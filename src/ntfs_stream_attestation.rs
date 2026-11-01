//! Native stream/extent and bitmap reconciliation, without adoption authority.
use crate::ntfs_inspect::{AllocationReconciliationStatus, Extent, FileInventory, NtfsInspection};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    attestation::{IoctlQuery, Report, StreamCapture},
    bitmap_paging, retrieval_paging, stream_layout as layout,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct Check {
    pub matched: bool,
    pub detail: String,
}
impl Check {
    pub(crate) fn from(result: Result<()>) -> Self {
        match result {
            Ok(()) => Self {
                matched: true,
                detail: "native observations match the supplied raw model".into(),
            },
            Err(e) => Self {
                matched: false,
                detail: format!("{e:#}"),
            },
        }
    }
}
#[derive(Debug, Serialize)]
pub struct FileCheck {
    pub record_number: u64,
    pub sequence_number: u16,
    pub streams: usize,
    pub check: Check,
}
#[derive(Debug, Serialize)]
pub struct Reconciliation {
    pub bitmap: Check,
    pub files: Vec<FileCheck>,
    pub matched_files: usize,
    pub matched_streams: usize,
    pub all_mappings_matched: bool,
    pub conversion_qualified: bool,
}
fn bytes<'a>(q: &'a IoctlQuery, code: u32, input: &[u8]) -> Result<&'a [u8]> {
    ensure!(
        q.code == code && q.input == input,
        "unexpected native extent query/input"
    );
    ensure!(
        q.native_error.is_none(),
        "native extent query {code:#x} refused with {:?}",
        q.native_error
    );
    Ok(&q.bytes)
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated native extent metadata")?
            .try_into()?,
    ))
}
pub fn base(q: &IoctlQuery) -> Result<u64> {
    let b = bytes(q, layout::GET_BASE, &[])?;
    ensure!(b.len() == 8, "native retrieval base length differs");
    let n = u64le(b, 0)?;
    ensure!(n <= i64::MAX as u64, "negative native retrieval base");
    Ok(n)
}
pub(crate) fn validate_paging_schema(native: &Report) -> Result<()> {
    native.validate_resources()?;
    ensure!(
        native.schema_version >= 6
            || native.allocation.as_ref().is_none_or(|a| {
                a.bitmap_before_continuation.is_empty() && a.bitmap_after_continuation.is_empty()
            }),
        "paged bitmap transcripts require native schema 6"
    );
    ensure!(
        native.schema_version >= 7
            || native
                .files
                .iter()
                .flat_map(|file| file.streams_before.iter().chain(file.streams_after.iter()))
                .flat_map(|capture| capture.streams.iter())
                .all(|stream| stream.retrieval_continuation.is_empty()),
        "paged retrieval transcripts require native schema 7"
    );
    Ok(())
}
pub fn check_bitmap(raw: &NtfsInspection, q: &IoctlQuery) -> Result<()> {
    check_bitmap_pages(raw, q, &[])
}
/// Reconstruct the complete bitmap from the recorded native queries. A supplied
/// canonical map or page-summary success flag is never allocation evidence.
pub fn check_bitmap_pages(
    raw: &NtfsInspection,
    first: &IoctlQuery,
    continuation: &[IoctlQuery],
) -> Result<()> {
    let capture = bitmap_paging::assemble_queries(first, continuation, &[0; 8])?;
    let b = &capture.bitmap;
    let count = raw.geometry.total_clusters;
    ensure!(
        count > 0 && count <= bitmap_paging::MAX_DATA_BYTES as u64 * 8,
        "bitmap domain exceeds profile"
    );
    ensure!(
        u64le(b, 0)? == 0,
        "native bitmap does not start at LCN zero"
    );
    let bits = u64le(b, 8)?;
    let need = count.div_ceil(8) as usize;
    ensure!(
        bits >= count
            && bits <= count.div_ceil(8) * 8
            && b.len() >= 16 + need
            && b.len() <= bitmap_paging::MAX_COMPLETE_BYTES,
        "native bitmap is incomplete or outside domain"
    );
    let source = raw
        .allocation_reconciliation
        .as_ref()
        .context("missing raw allocation reconciliation")?;
    ensure!(
        source.status == AllocationReconciliationStatus::ConsistentRawModel
            && source.domain_clusters == count,
        "raw allocation model is incomplete or inconsistent"
    );
    ensure!(
        hex::encode(Sha256::digest(&b[16..16 + need])) == source.bitmap_sha256,
        "native bitmap bytes differ from initialized NTFS bitmap"
    );
    Ok(())
}

fn check_streamed_bitmap(
    raw: &NtfsInspection,
    first: &IoctlQuery,
    summary: &n2r_win32::bitmap_streaming::Summary,
) -> Result<()> {
    summary.validate_source_first(first)?;
    let source = raw
        .allocation_reconciliation
        .as_ref()
        .context("missing raw allocation reconciliation")?;
    ensure!(
        source.status == AllocationReconciliationStatus::ConsistentRawModel
            && source.domain_clusters == raw.geometry.total_clusters
            && summary.cluster_count == raw.geometry.total_clusters
            && summary.bitmap_data_sha256 == source.bitmap_sha256
            && raw.allocated_clusters == Some(summary.allocated_clusters)
            && raw.free_clusters == Some(summary.free_clusters),
        "streamed native bitmap differs from the complete initialized frozen NTFS bitmap"
    );
    Ok(())
}
fn normalized(items: &[Extent], volume: u64, cluster: u64) -> Result<Vec<Extent>> {
    let mut out: Vec<Extent> = vec![];
    let mut next = 0;
    ensure!(
        items.len() <= retrieval_paging::MAX_COMPLETE_EXTENTS,
        "extent count exceeds profile"
    );
    for e in items {
        ensure!(
            e.logical_offset == next
                && e.length > 0
                && e.logical_offset % cluster == 0
                && e.length % cluster == 0,
            "extent VCN coverage/alignment differs"
        );
        next = next
            .checked_add(e.length)
            .context("logical extent overflow")?;
        if let Some(p) = e.physical_offset {
            ensure!(
                p % cluster == 0 && p.checked_add(e.length).is_some_and(|end| end <= volume),
                "physical extent outside source volume"
            );
        }
        if let Some(last) = out.last_mut() {
            let contiguous = match (last.physical_offset, e.physical_offset) {
                (None, None) => true,
                (Some(a), Some(b)) => a.checked_add(last.length) == Some(b),
                _ => false,
            };
            if contiguous {
                last.length = last
                    .length
                    .checked_add(e.length)
                    .context("merged extent overflow")?;
                continue;
            }
        }
        out.push(e.clone());
    }
    Ok(out)
}
fn identity(q: &n2r_win32::attestation::Query, file: &FileInventory, serial: u64) -> Result<()> {
    ensure!(
        q.class == 18 && q.native_error.is_none() && q.bytes.len() == 24,
        "native stream identity query refused"
    );
    ensure!(
        u64le(&q.bytes, 0)? == serial
            && u64le(&q.bytes, 8)?
                == (file.record_number | (u64::from(file.sequence_number) << 48))
            && u64le(&q.bytes, 16)? == 0,
        "named stream is bound to a different file or volume"
    );
    Ok(())
}
pub fn check_file(
    file: &FileInventory,
    native: &StreamCapture,
    base_sectors: u64,
    geometry: &crate::ntfs_inspect::NtfsGeometry,
) -> Result<()> {
    ensure!(
        file.base_file_reference == 0
            && !file
                .attributes
                .iter()
                .any(|a| a.type_code == 0x20 || a.lowest_vcn != 0),
        "attribute-list/extension assembly required"
    );
    ensure!(
        native.enumeration.class == 7 && native.parse_error.is_none(),
        "native stream enumeration parse refused: {:?}",
        native.parse_error
    );
    if let Some(e) = native.enumeration.native_error {
        ensure!(
            e == 38
                && native.enumeration.bytes.is_empty()
                && native.streams.is_empty()
                && file.streams.is_empty(),
            "native stream enumeration refused with {e}"
        );
        return Ok(());
    }
    let (entries, end) = layout::parse_streams(&native.enumeration.bytes)?;
    ensure!(
        end == native.enumeration.bytes.len()
            && entries.len() == file.streams.len()
            && entries.len() == native.streams.len(),
        "stream inventory coverage differs"
    );
    let parsed: BTreeMap<_, _> = entries.iter().map(|e| (&e.name, e)).collect();
    let source: BTreeSet<_> = file.streams.iter().map(|s| &s.name_utf16).collect();
    let observed: BTreeSet<_> = native.streams.iter().map(|s| &s.name_utf16).collect();
    ensure!(
        source.len() == file.streams.len()
            && observed.len() == native.streams.len()
            && source == observed
            && source == parsed.keys().copied().collect(),
        "missing, duplicate or unexpected stream name"
    );
    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        crate::ntfs_index::supports_cluster_size(geometry.cluster_size)
            && geometry.bytes_per_sector == 512,
        "unsupported native stream geometry"
    );
    let base_bytes = base_sectors
        .checked_mul(u64::from(geometry.bytes_per_sector))
        .context("retrieval base overflow")?;
    for s in &file.streams {
        let e = parsed.get(&s.name_utf16).unwrap();
        let q = native
            .streams
            .iter()
            .find(|q| q.name_utf16 == s.name_utf16)
            .unwrap();
        ensure!(
            q.logical_size == e.logical_size
                && q.allocated_size == e.allocated_size
                && q.logical_size == s.logical_size,
            "native stream length/enumeration differs"
        );
        ensure!(
            q.open_error.is_none() && q.binding_error.is_none(),
            "native stream open/binding refused: {:?}, {:?}",
            q.open_error,
            q.binding_error
        );
        identity(
            q.identity_before
                .as_ref()
                .context("missing stream identity before")?,
            file,
            geometry.serial_number,
        )?;
        identity(
            q.identity_after
                .as_ref()
                .context("missing stream identity after")?,
            file,
            geometry.serial_number,
        )?;
        ensure!(
            q.identity_before == q.identity_after,
            "native stream identity changed"
        );
        let r = q.retrieval.as_ref().context("missing retrieval query")?;
        ensure!(
            r.code == layout::GET_RETRIEVAL && r.input == [0; 8],
            "unexpected retrieval input"
        );
        let compressed = if s.flags == 1 {
            let mut attributes = file
                .attributes
                .iter()
                .filter(|a| a.type_code == 0x80 && a.name_utf16 == s.name_utf16);
            let attribute = attributes
                .next()
                .context("compressed DATA inventory absent")?;
            ensure!(
                attributes.next().is_none(),
                "duplicate compressed DATA inventory"
            );
            crate::ntfs_compression::supported(attribute, geometry)?;
            ensure!(
                attribute.flags == s.flags
                    && attribute.resident == s.resident
                    && attribute.logical_size == s.logical_size
                    && attribute.initialized_size == s.initialized_size
                    && attribute.allocated_size == s.allocated_size
                    && attribute.extents == s.extents,
                "compressed stream differs from its validated DATA attribute"
            );
            Some(attribute)
        } else {
            None
        };
        ensure!(
            s.flags & !0x8000 == 0 || compressed.is_some(),
            "unsupported encoded or encrypted stream"
        );
        if s.resident {
            ensure!(
                s.extents.is_empty()
                    && r.native_error == Some(38)
                    && r.bytes.is_empty()
                    && q.retrieval_continuation.is_empty(),
                "resident stream has unexpected physical retrieval evidence"
            );
            continue;
        }
        let runs = retrieval_paging::assemble_queries(r, &q.retrieval_continuation)?.runs;
        let mut extents = vec![];
        for run in runs {
            extents.push(Extent {
                logical_offset: run
                    .vcn
                    .checked_mul(cluster)
                    .context("native VCN byte overflow")?,
                length: run
                    .clusters
                    .checked_mul(cluster)
                    .context("native extent length overflow")?,
                physical_offset: run
                    .lcn
                    .map(|lcn| {
                        lcn.checked_mul(cluster)
                            .and_then(|n| n.checked_add(base_bytes))
                            .context("native physical offset overflow")
                    })
                    .transpose()?,
            });
        }
        ensure!(
            normalized(&extents, geometry.volume_size, cluster)?
                == normalized(&s.extents, geometry.volume_size, cluster)?,
            "native VCN/LCN mapping differs from NTFS runs"
        );
        let physical = s
            .extents
            .iter()
            .filter(|e| e.physical_offset.is_some())
            .try_fold(0u64, |sum, e| {
                sum.checked_add(e.length)
                    .context("allocated stream bytes overflow")
            })?;
        ensure!(
            q.allocated_size == physical,
            "native physical allocation differs from mapped NTFS data"
        );
        if let Some(attribute) = compressed {
            ensure!(
                attribute.total_allocated_size == Some(physical),
                "native compressed allocation differs from raw TotalAllocated"
            );
        }
    }
    Ok(())
}
pub fn reconcile(raw: &NtfsInspection, native: &Report) -> Result<Reconciliation> {
    if !raw.attribute_assemblies.is_empty() {
        crate::ntfs_inspect::validate_record_coverage(raw)?;
    }
    ensure!(
        matches!(native.schema_version, 3..=14),
        "native stream profile missing"
    );
    validate_paging_schema(native)?;
    let volume = native
        .allocation
        .as_ref()
        .context("missing native volume allocation observations")?;
    let bitmap = Check::from((|| {
        if matches!(native.schema_version, 9 | 10 | 11 | 12 | 14)
            || (native.schema_version == 13 && native.request.resource_profile.is_some())
        {
            let before = volume
                .streamed_before
                .as_ref()
                .context("missing streamed bitmap before observation")?;
            let after = volume
                .streamed_after
                .as_ref()
                .context("missing streamed bitmap after observation")?;
            check_streamed_bitmap(raw, &volume.bitmap_before, before)?;
            check_streamed_bitmap(raw, &volume.bitmap_after, after)?;
            ensure!(
                before == after && volume.bitmap_before == volume.bitmap_after,
                "streamed native bitmap changed across source observation"
            );
            return Ok(());
        }
        check_bitmap_pages(
            raw,
            &volume.bitmap_before,
            &volume.bitmap_before_continuation,
        )?;
        check_bitmap_pages(raw, &volume.bitmap_after, &volume.bitmap_after_continuation)?;
        ensure!(
            volume.bitmap_before == volume.bitmap_after
                && volume.bitmap_before_continuation == volume.bitmap_after_continuation,
            "native bitmap changed"
        );
        Ok(())
    })());
    let before_base = base(&volume.base_before);
    let after_base = base(&volume.base_after);
    ensure!(
        native.files.len() == raw.files.len(),
        "native stream identity coverage differs"
    );
    let mut seen = BTreeSet::new();
    let mut files = vec![];
    let mut matched_files = 0;
    let mut matched_streams = 0;
    for file in &raw.files {
        let obs: Vec<_> = native
            .files
            .iter()
            .filter(|o| {
                o.identity.record_number == file.record_number
                    && o.identity.sequence_number == file.sequence_number
            })
            .collect();
        ensure!(
            obs.len() == 1 && seen.insert((file.record_number, file.sequence_number)),
            "native stream identity missing or duplicate"
        );
        let obs = obs[0];
        let result = (|| {
            ensure!(
                obs.open_error.is_none(),
                "native file open refused: {:?}",
                obs.open_error
            );
            let base = *before_base
                .as_ref()
                .map_err(|e| anyhow::anyhow!("native retrieval base before: {e:#}"))?;
            ensure!(
                after_base.as_ref().is_ok_and(|n| *n == base)
                    && volume.base_before == volume.base_after,
                "native retrieval base changed or refused"
            );
            let a = obs
                .streams_before
                .as_ref()
                .context("missing native streams before")?;
            let b = obs
                .streams_after
                .as_ref()
                .context("missing native streams after")?;
            check_file(file, a, base, &raw.geometry)?;
            check_file(file, b, base, &raw.geometry)?;
            ensure!(a == b, "native stream snapshot changed");
            Ok(())
        })();
        let check = Check::from(result);
        if check.matched {
            matched_files += 1;
            matched_streams += file.streams.len();
        }
        files.push(FileCheck {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            streams: file.streams.len(),
            check,
        });
    }
    Ok(Reconciliation {
        all_mappings_matched: bitmap.matched && matched_files == files.len(),
        bitmap,
        files,
        matched_files,
        matched_streams,
        conversion_qualified: false,
    })
}
