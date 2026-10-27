//! Move only live, measured user-file allocations on the independent shadow.
//! The source device is not accepted by this interface. No raw writes exist.
use super::*;
use crate::{
    bitmap_observation::Observation,
    shadow_evacuation::{self, Extent, Plan},
};

#[derive(Debug, Serialize)]
pub struct Attempt {
    pub file_index: u32,
    pub file_id: Vec<u8>,
    pub mapping_before_sha256: String,
    pub mapping_after_sha256: String,
    pub before_page_proof: crate::retrieval_paging::Proof,
    pub after_page_proof: crate::retrieval_paging::Proof,
    pub destination_legacy_bitmap_sha256: String,
    pub destination_metadata_bitmap_sha256: String,
    pub moved_range_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub plan: Option<Plan>,
    pub not_submitted_reason: Option<String>,
    pub attempts: Vec<Attempt>,
    pub completed_bytes: u64,
    pub source_payload_writes: u64,
}

fn push_extent(
    out: &mut Vec<Extent>,
    file_index: usize,
    logical_offset: u64,
    physical_offset: u64,
    length: u64,
) -> io::Result<()> {
    if length == 0 {
        return Ok(());
    }
    if out.len() == shadow_evacuation::MAX_EXTENTS {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shadow evacuation extent budget exceeded",
        ));
    }
    out.push(Extent {
        file_index: u32::try_from(file_index).map_err(|_| invalid("evacuation file index"))?,
        logical_offset,
        physical_offset,
        length,
    });
    Ok(())
}

/// The caller has already bound this mounted volume as an independent ReFS
/// shadow, enabled volume-management privilege and initialized all file bytes.
struct Prepared {
    eligible: Vec<Extent>,
    files: Vec<Option<File>>,
    ids: Vec<Vec<u8>>,
    plan: Plan,
}

fn prepare(volume: &File, root: &str, input: &[Input<'_>], partition: u64) -> io::Result<Prepared> {
    let mut eligible = Vec::new();
    let mut owned = Vec::new();
    let mut files = Vec::new();
    let mut ids = Vec::new();
    let mut unique = std::collections::BTreeSet::new();
    for (index, object) in input.iter().enumerate() {
        if object.directory {
            files.push(None);
            ids.push(Vec::new());
            continue;
        }
        if let Some(offset) = object.source_offset {
            push_extent(
                &mut eligible,
                index,
                0,
                offset,
                object.logical_length() / 4096 * 4096,
            )?;
        }
        for run in &object.source_runs {
            if let Some(offset) = run.physical_offset {
                push_extent(
                    &mut eligible,
                    index,
                    run.logical_offset,
                    offset,
                    run.length / 4096 * 4096,
                )?;
            }
        }
        let file = open(
            &format!("{root}{}", object.components.join("\\")),
            false,
            true,
        )?;
        let standard = info(&file, 1, 24)?;
        let id = info(&file, 18, 24)?[8..24].to_vec();
        if id == [0; 16]
            || !unique.insert(id.clone())
            || layout::u32_at(&standard, 16)? != 1
            || standard[20] != 0
            || standard[21] != 0
            || layout::u64_at(&standard, 8)? != object.logical_length()
        {
            return Err(invalid(
                "evacuation requires unique ordinary shadow file identities",
            ));
        }
        if layout::u64_at(&standard, 0)? >= 4096 {
            let capture = crate::stream_native::retrieval_capture(&file)?;
            for run in stream_layout::parse_complete_retrieval(&capture.canonical)? {
                let lcn = run
                    .lcn
                    .ok_or_else(|| invalid("sparse shadow ownership is not evacuable"))?;
                push_extent(
                    &mut owned,
                    index,
                    run.vcn
                        .checked_mul(4096)
                        .ok_or_else(|| invalid("evacuation VCN overflow"))?,
                    lcn.checked_mul(4096)
                        .ok_or_else(|| invalid("evacuation LCN overflow"))?,
                    run.clusters
                        .checked_mul(4096)
                        .ok_or_else(|| invalid("evacuation run overflow"))?,
                )?;
            }
        }
        files.push(Some(file));
        ids.push(id);
    }
    let legacy =
        Observation::capture(volume, &[0; 8], partition, true)?.allocation_map(partition)?;
    let mut ex = [0; 16];
    ex[8] = 1;
    let metadata = Observation::capture(volume, &ex, partition, true)?.allocation_map(partition)?;
    let plan = shadow_evacuation::plan_ranges(&legacy, &metadata, &eligible, &owned, partition)?;
    Ok(Prepared {
        eligible,
        files,
        ids,
        plan,
    })
}

pub(super) fn run(
    volume: &File,
    root: &str,
    input: &[Input<'_>],
    partition: u64,
) -> io::Result<Report> {
    let Prepared {
        eligible,
        files,
        ids,
        plan,
    } = match prepare(volume, root, input, partition) {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::Unsupported | io::ErrorKind::StorageFull
            ) =>
        {
            // Preparation has not submitted any move. Preserve the reason and
            // continue the existing independently checked retention path.
            return Ok(Report {
                plan: None,
                not_submitted_reason: Some(error.to_string()),
                attempts: vec![],
                completed_bytes: 0,
                source_payload_writes: 0,
            });
        }
        Err(error) => return Err(error),
    };
    let mut ex = [0; 16];
    ex[8] = 1;
    let mut attempts = Vec::new();
    let mut completed_bytes = 0;
    for movement in &plan.moves {
        let index = movement.file_index as usize;
        let file = files
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| invalid("evacuation file handle missing"))?;
        if info(file, 18, 24)?[8..24] != ids[index] {
            return Err(invalid("evacuation file identity changed"));
        }
        let before = crate::stream_native::retrieval_capture(file)?;
        if !mapping_matches_run(
            &stream_layout::parse_complete_retrieval(&before.canonical)?,
            movement.starting_vcn,
            movement.source_offset / 4096,
            movement.clusters,
        )? {
            return Err(invalid("shadow evacuation source ownership changed"));
        }
        let live_legacy = Observation::capture(volume, &[0; 8], partition, true)?;
        let live_metadata = Observation::capture(volume, &ex, partition, true)?;
        for view in [&live_legacy, &live_metadata] {
            if view
                .view(partition)?
                .candidate(movement.destination_offset, movement.length)?
                .allocated_clusters
                != 0
            {
                return Err(invalid("shadow evacuation destination is no longer free"));
            }
        }
        if eligible.iter().any(|source| {
            movement.destination_offset < source.physical_offset + source.length
                && source.physical_offset < movement.destination_offset + movement.length
        }) {
            return Err(invalid(
                "evacuation destination overlaps a retained-source candidate",
            ));
        }
        let mut request = [0; 32];
        request[..8].copy_from_slice(&(file.as_raw_handle() as usize as u64).to_le_bytes());
        request[8..16].copy_from_slice(&movement.starting_vcn.to_le_bytes());
        request[16..24].copy_from_slice(&movement.destination_lcn.to_le_bytes());
        request[24..28].copy_from_slice(&movement.clusters.to_le_bytes());
        // A failure may have changed mapping; abort construction without retry.
        // The NTFS source remains untouched and cannot enter raw execution.
        ctl(volume, 0x00090074, &request, 0).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "shadow-only user evacuation failed at logical {}: {e}",
                    movement.logical_offset
                ),
            )
        })?;
        let after = crate::stream_native::retrieval_capture(file)?;
        if info(file, 18, 24)?[8..24] != ids[index]
            || !mapping_matches_run(
                &stream_layout::parse_complete_retrieval(&after.canonical)?,
                movement.starting_vcn,
                movement.destination_lcn,
                movement.clusters,
            )?
        {
            return Err(invalid(
                "native evacuation did not establish its exact destination mapping",
            ));
        }
        attempts.push(Attempt {
            file_index: movement.file_index,
            file_id: ids[index].clone(),
            mapping_before_sha256: hex::encode(Sha256::digest(&before.canonical)),
            mapping_after_sha256: hex::encode(Sha256::digest(&after.canonical)),
            before_page_proof: before.proof,
            after_page_proof: after.proof,
            destination_legacy_bitmap_sha256: live_legacy.proof().canonical_bitmap_sha256,
            destination_metadata_bitmap_sha256: live_metadata.proof().canonical_bitmap_sha256,
            moved_range_verified: true,
        });
        completed_bytes += movement.length;
    }
    volume.sync_all()?;
    Ok(Report {
        plan: Some(plan),
        not_submitted_reason: None,
        attempts,
        completed_bytes,
        source_payload_writes: 0,
    })
}
