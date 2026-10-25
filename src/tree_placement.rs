//! Exact stream dispositions for a measured shadow. Diagnostic only: admission,
//! frozen-shadow validation, capacity and recovery still precede execution.
use crate::{
    ntfs_inspect::Extent,
    shadow_tree::{Object, Tree},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};
pub struct Mapping {
    pub record_number: u64,
    pub sequence_number: u16,
    pub target_file_id: [u8; 16],
    pub logical_sha256: String,
    pub extents: Vec<Extent>,
}

/// Convert the actual native ReFS observation into stream mappings. This
/// rejects missing identities, holes and malformed retrieval extents before
/// any source/shadow comparison request is constructed.
#[cfg(windows)]
pub fn mappings_from_native(
    tree: &Tree,
    native: &n2r_win32::shadow_native::Report,
) -> Result<Vec<Mapping>> {
    ensure!(
        tree.objects.len() == native.objects.len(),
        "native tree coverage differs"
    );
    tree.objects
        .iter()
        .zip(&native.objects)
        .filter(|(object, _)| !object.directory)
        .map(|(object, measured)| -> Result<_> {
            ensure!(
                object.path == measured.components,
                "native stream identity order differs"
            );
            let id = measured
                .before
                .queries
                .iter()
                .find(|q| q.class == 18 && q.native_error.is_none() && q.bytes.len() == 24)
                .context("missing target file identity")?;
            let runs = if measured.resident_data {
                ensure!(
                    object.length <= 4096
                        && measured.retrieval.is_empty()
                        && measured.cached_validity.is_empty()
                        && measured.storage_validity.is_empty(),
                    "resident target unexpectedly carries physical data mappings"
                );
                vec![]
            } else if object.length == 0 && measured.retrieval.is_empty() {
                vec![]
            } else {
                n2r_win32::stream_layout::parse_retrieval(&measured.retrieval)?
            };
            let extents = runs
                .into_iter()
                .map(|run| -> Result<_> {
                    Ok(Extent {
                        logical_offset: run.vcn.checked_mul(4096).context("VCN overflow")?,
                        physical_offset: Some(
                            run.lcn
                                .context("target sparse mapping")?
                                .checked_mul(4096)
                                .context("LCN overflow")?,
                        ),
                        length: run
                            .clusters
                            .checked_mul(4096)
                            .context("run length overflow")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Mapping {
                record_number: object.record_number,
                sequence_number: object.sequence_number,
                target_file_id: id.bytes[8..24].try_into()?,
                logical_sha256: measured
                    .logical_sha256
                    .clone()
                    .context("missing target logical hash")?,
                extents,
            })
        })
        .collect()
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Retained,
    Relocated,
    Materialized,
}
#[derive(Debug, Serialize)]
pub struct Range {
    pub record_number: u64,
    pub sequence_number: u16,
    pub path: Vec<String>,
    pub stream_name: &'static str,
    pub target_file_id: [u8; 16],
    pub logical_offset: u64,
    pub source_offset: Option<u64>,
    pub destination_offset: Option<u64>,
    pub length: u64,
    pub sha256: Option<String>,
    pub disposition: Disposition,
    pub justification: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Plan {
    pub profile: &'static str,
    pub ranges: Vec<Range>,
    pub retained_bytes: u64,
    pub relocated_bytes: u64,
    pub materialized_bytes: u64,
    pub shadow_payload_initialization_bytes: u64,
    pub executable: bool,
    pub pending: Vec<&'static str>,
}
impl Plan {
    /// Convert measured dispositions into byte-comparison inputs. The request
    /// still requires complete input rehashing and grants no write authority.
    pub fn comparison_request(
        &self,
        partition_bytes: u64,
        source_sha256: &str,
        shadow_sha256: &str,
        max_change_bytes: u64,
    ) -> Result<crate::retained_compare::RetainedCompareRequest> {
        use crate::retained_compare::{RetainedCompareRequest, RetainedRangeRequest};
        let mut retained_ranges = vec![];
        let mut retained_bytes = 0u64;
        let mut relocated_bytes = 0u64;
        let mut materialized_bytes = 0u64;
        for range in &self.ranges {
            ensure!(range.length > 0, "empty stream disposition");
            match range.disposition {
                Disposition::Retained => {
                    ensure!(
                        range.source_offset == range.destination_offset
                            && range.destination_offset.is_some(),
                        "retained disposition changes physical placement"
                    );
                    retained_bytes = retained_bytes
                        .checked_add(range.length)
                        .context("retained byte count overflow")?;
                    retained_ranges.push(RetainedRangeRequest {
                        offset: range.source_offset.context("retained source absent")?,
                        length: range.length,
                        source_sha256: range
                            .sha256
                            .clone()
                            .context("retained range digest absent")?,
                        shadow_sha256: range
                            .sha256
                            .clone()
                            .context("retained range digest absent")?,
                    });
                }
                Disposition::Relocated => {
                    ensure!(
                        range.source_offset.is_some()
                            && range.destination_offset.is_some()
                            && range.source_offset != range.destination_offset,
                        "relocated disposition has unchanged placement"
                    );
                    relocated_bytes = relocated_bytes
                        .checked_add(range.length)
                        .context("relocated byte count overflow")?;
                }
                Disposition::Materialized => {
                    ensure!(
                        range.source_offset.is_none(),
                        "materialized range invents a source extent"
                    );
                    materialized_bytes = materialized_bytes
                        .checked_add(range.length)
                        .context("materialized byte count overflow")?;
                }
            }
        }
        ensure!(
            retained_bytes == self.retained_bytes
                && relocated_bytes == self.relocated_bytes
                && materialized_bytes == self.materialized_bytes,
            "disposition totals changed"
        );
        retained_ranges.sort_by_key(|range| range.offset);
        let request = RetainedCompareRequest {
            schema_version: 2,
            sector_size: 4096,
            expected_length: partition_bytes,
            source_sha256: source_sha256.into(),
            shadow_sha256: shadow_sha256.into(),
            retained_ranges,
            max_change_bytes,
            max_ranges: 65536,
        };
        crate::retained_compare::validate_request(&request)?;
        Ok(request)
    }
}
pub fn diagnose(
    tree: &Tree,
    mappings: &[Mapping],
    payloads: &[Vec<u8>],
    partition: u64,
) -> Result<Plan> {
    ensure!(
        payloads.len() == tree.objects.len(),
        "source payload coverage differs"
    );
    for (object, bytes) in tree.objects.iter().zip(payloads) {
        ensure!(
            if object.directory {
                bytes.is_empty()
            } else {
                bytes.len() as u64 == object.length
                    && object.sha256.as_deref() == Some(&hex::encode(Sha256::digest(bytes)))
            },
            "source payload or digest differs from the tree"
        );
    }
    diagnose_impl(
        tree,
        mappings,
        partition,
        "existing-tree-placement-v1",
        |index, _, start, end, _| {
            let bytes = &payloads[index];
            Ok(Some(hex::encode(Sha256::digest(
                &bytes[start as usize..end as usize],
            ))))
        },
    )
}

/// Use the already verified full logical source/target hashes while hashing
/// only physical ranges needed for retained-extent comparison pins. This path
/// supports bounded native shadow construction without retaining every file's
/// payload in memory. The caller supplies a checked logical-range digest for
/// materialized subranges; the whole-stream native digest remains mandatory.
pub fn diagnose_measured<R: Read + Seek>(
    tree: &Tree,
    mappings: &[Mapping],
    reader: &mut R,
    partition: u64,
    mut materialized_digest: impl FnMut(&mut R, &Object, u64, u64) -> Result<String>,
) -> Result<Plan> {
    diagnose_impl(
        tree,
        mappings,
        partition,
        "existing-tree-placement-streamed-v2",
        |_, object, start, end, physical| {
            if let Some(offset) = physical {
                Ok(Some(hex::encode(crate::lab_reconstruct::hash_range(
                    reader,
                    offset,
                    end - start,
                )?)))
            } else {
                let actual = materialized_digest(reader, object, start, end)?;
                if start == 0 && end == object.length {
                    ensure!(
                        Some(&actual) == object.sha256.as_ref(),
                        "materialized full-stream digest differs"
                    );
                }
                Ok(Some(actual))
            }
        },
    )
}

fn diagnose_impl(
    tree: &Tree,
    mappings: &[Mapping],
    partition: u64,
    profile: &'static str,
    mut digest: impl FnMut(usize, &Object, u64, u64, Option<u64>) -> Result<Option<String>>,
) -> Result<Plan> {
    let mut index = BTreeMap::new();
    let mut target_ids = BTreeSet::new();
    for m in mappings {
        ensure!(
            index
                .insert((m.record_number, m.sequence_number), m)
                .is_none()
                && m.target_file_id != [0; 16]
                && target_ids.insert(m.target_file_id),
            "duplicate source or target file identity"
        );
    }
    let mut p = Plan {
        profile,
        ranges: vec![],
        retained_bytes: 0,
        relocated_bytes: 0,
        materialized_bytes: 0,
        shadow_payload_initialization_bytes: 0,
        executable: false,
        pending: vec![
            "complete source admission",
            "frozen shadow and whole-image validation",
            "exact patch/journal capacity",
            "native interruption/recovery qualification",
        ],
    };
    let mut targets = vec![];
    let mut source_allocations = vec![];
    for (object_index, o) in tree.objects.iter().enumerate() {
        if o.directory {
            continue;
        }
        let m = index
            .remove(&(o.record_number, o.sequence_number))
            .context("missing target stream")?;
        let source = o.source_offset;
        ensure!(
            source.is_none() || o.source_extents.is_empty(),
            "mixed single and fragmented source mapping"
        );
        if let Some(offset) = source {
            ensure!(
                offset.is_multiple_of(4096)
                    && o.length.is_multiple_of(4096)
                    && offset
                        .checked_add(o.length)
                        .is_some_and(|end| end <= partition),
                "single source extent exceeds partition"
            );
            source_allocations.push((offset, o.length));
        }
        let mut source_covered = 0u64;
        if !o.source_extents.is_empty() {
            let mut covered = 0u64;
            for run in &o.source_extents {
                let offset = run.physical_offset.context("fragmented source hole")?;
                ensure!(
                    run.logical_offset == covered
                        && run.length > 0
                        && run.length.is_multiple_of(4096)
                        && offset.is_multiple_of(4096)
                        && offset
                            .checked_add(run.length)
                            .is_some_and(|end| end <= partition),
                    "fragmented source run differs"
                );
                covered = covered
                    .checked_add(run.length)
                    .context("source run overflow")?;
                source_allocations.push((offset, run.length));
            }
            ensure!(
                covered > 0 && covered <= o.length / 4096 * 4096,
                "source initialized-cluster prefix differs"
            );
            source_covered = covered;
        }
        ensure!(
            Some(&m.logical_sha256) == o.sha256.as_ref(),
            "source/target logical stream proof differs"
        );
        let mut cursor = 0u64;
        let mut physical_cursor = 0u64;
        ensure!(
            (!m.extents.is_empty() || o.length == 0 || (source.is_none() && o.length <= 4096))
                && m.extents.len() <= 1024,
            "target extent budget"
        );
        if m.extents.is_empty() && o.length > 0 {
            p.materialized_bytes += o.length;
            p.shadow_payload_initialization_bytes += o.length;
            p.ranges.push(Range {
                record_number: o.record_number,
                sequence_number: o.sequence_number,
                path: o.path.clone(),
                stream_name: "",
                target_file_id: m.target_file_id,
                logical_offset: 0,
                source_offset: None,
                destination_offset: None,
                length: o.length,
                sha256: Some(m.logical_sha256.clone()),
                disposition: Disposition::Materialized,
                justification: "logical source bytes stored inline in native ReFS metadata",
            });
            continue;
        }
        for e in &m.extents {
            let dest = e.physical_offset.context("target hole is unsupported")?;
            let physical_end = physical_cursor
                .checked_add(e.length)
                .context("logical extent overflow")?;
            let end = physical_end.min(o.length);
            ensure!(
                e.logical_offset == physical_cursor
                    && e.length > 0
                    && e.length.is_multiple_of(4096)
                    && dest.is_multiple_of(4096)
                    && physical_end <= o.length.next_multiple_of(65536)
                    && dest
                        .checked_add(e.length)
                        .is_some_and(|end| end <= partition)
                    && source
                        .is_none_or(|s| s.checked_add(end).is_some_and(|end| end <= partition)),
                "invalid target extent coverage or bounds"
            );
            targets.push((dest, e.length));
            physical_cursor = physical_end;
            if e.logical_offset >= o.length {
                continue;
            }
            while cursor < end {
                let (from, segment_end) = if let Some(start) = source {
                    (Some(start + cursor), end)
                } else if o.source_extents.is_empty() || cursor >= source_covered {
                    (None, end)
                } else {
                    let run = o
                        .source_extents
                        .iter()
                        .find(|run| {
                            run.logical_offset <= cursor
                                && run
                                    .logical_offset
                                    .checked_add(run.length)
                                    .is_some_and(|limit| cursor < limit)
                        })
                        .context("fragmented source has incomplete logical coverage")?;
                    let start = run.physical_offset.context("fragmented source hole")?;
                    (
                        Some(
                            start
                                .checked_add(cursor - run.logical_offset)
                                .context("source run overflow")?,
                        ),
                        end.min(run.logical_offset + run.length),
                    )
                };
                let length = segment_end - cursor;
                let destination = dest
                    .checked_add(cursor - e.logical_offset)
                    .context("target run overflow")?;
                ensure!(
                    length > 0
                        && from.is_none_or(|offset| {
                            offset
                                .checked_add(length)
                                .is_some_and(|limit| limit <= partition)
                        }),
                    "source run exceeds partition"
                );
                let retained = Some(destination) == from && length.is_multiple_of(4096);
                if retained {
                    p.retained_bytes += length;
                } else if from.is_none() {
                    p.materialized_bytes += length;
                } else {
                    p.relocated_bytes += length;
                }
                let range_sha = digest(object_index, o, cursor, segment_end, from)?;
                if retained && cursor == 0 && segment_end == o.length {
                    ensure!(
                        range_sha.as_ref() == o.sha256.as_ref(),
                        "retained full-stream digest differs"
                    );
                }
                p.ranges.push(Range{record_number:o.record_number,sequence_number:o.sequence_number,path:o.path.clone(),
                    stream_name:"",target_file_id:m.target_file_id,logical_offset:cursor,source_offset:from,
                    destination_offset:Some(destination),length,sha256:range_sha,
                    disposition:if retained {Disposition::Retained} else if from.is_none() {Disposition::Materialized} else {Disposition::Relocated},
                    justification:if retained {"native target mapping resolves to the original source bytes"}
                        else if from.is_none() {"logical source bytes materialized into native ReFS storage; no adoptable source range"}
                        else {"real source bytes initialized at an independent native ReFS allocation; journal must carry them to the original partition"}});
                cursor = segment_end;
            }
        }
        ensure!(
            cursor == o.length,
            "target stream has incomplete physical coverage"
        );
        p.shadow_payload_initialization_bytes += o.length;
    }
    ensure!(index.is_empty(), "unexpected target stream identity");
    source_allocations.sort_unstable();
    ensure!(
        source_allocations
            .windows(2)
            .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0),
        "source payload allocations overlap"
    );
    targets.sort_unstable();
    ensure!(
        targets
            .windows(2)
            .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0),
        "exclusive target allocations overlap"
    );
    ensure!(
        p.retained_bytes + p.relocated_bytes + p.materialized_bytes == tree.logical_bytes,
        "stream disposition coverage differs"
    );
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example(destination: u64) -> (Tree, Mapping, Vec<Vec<u8>>) {
        let bytes = vec![42; 8192];
        let sha = hex::encode(Sha256::digest(&bytes));
        (
            Tree {
                profile: "test",
                logical_bytes: 8192,
                internal_replacement_pending: vec![],
                objects: vec![crate::shadow_tree::Object {
                    record_number: 16,
                    sequence_number: 2,
                    path: vec!["file.bin".into()],
                    directory: false,
                    stored_times: [1; 4],
                    attributes: 32,
                    security: vec![],
                    api_security: None,
                    source_offset: Some(4096),
                    source_extents: vec![],
                    length: 8192,
                    sha256: Some(sha.clone()),
                }],
            },
            Mapping {
                record_number: 16,
                sequence_number: 2,
                target_file_id: [1; 16],
                logical_sha256: sha,
                extents: vec![Extent {
                    logical_offset: 0,
                    physical_offset: Some(destination),
                    length: 8192,
                }],
            },
            vec![bytes],
        )
    }
    #[test]
    fn relocation_only_has_no_dummy_retained_range() {
        let (t, m, b) = example(32768);
        let p = diagnose(&t, &[m], &b, 65536).unwrap();
        assert_eq!(p.retained_bytes, 0);
        assert_eq!(p.relocated_bytes, 8192);
        assert_eq!(p.ranges[0].disposition, Disposition::Relocated);
        assert!(!p.executable);
        let request = p
            .comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
            .unwrap();
        assert!(request.retained_ranges.is_empty());
    }
    #[test]
    fn split_stream_can_retain_one_range_and_relocate_another() {
        let (t, mut m, b) = example(4096);
        m.extents[0].length = 4096;
        m.extents.push(Extent {
            logical_offset: 4096,
            physical_offset: Some(32768),
            length: 4096,
        });
        let p = diagnose(&t, &[m], &b, 65536).unwrap();
        assert_eq!(p.retained_bytes, 4096);
        assert_eq!(p.relocated_bytes, 4096);
        assert_eq!(p.ranges[0].sha256, p.ranges[1].sha256);
        let request = p
            .comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
            .unwrap();
        assert_eq!(request.retained_ranges.len(), 1);
        assert_eq!(request.retained_ranges[0].offset, 4096);
        assert_eq!(request.retained_ranges[0].length, 4096);
        assert_eq!(
            request.retained_ranges[0].source_sha256,
            p.ranges[0].sha256.as_deref().unwrap()
        );
    }
    #[test]
    fn fragmented_ntfs_source_splits_a_single_target_run_at_source_boundaries() {
        let (mut tree, mapping, mut payloads) = example(4096);
        payloads[0][4096..].fill(43);
        let digest = hex::encode(Sha256::digest(&payloads[0]));
        tree.objects[0].sha256 = Some(digest.clone());
        tree.objects[0].source_offset = None;
        tree.objects[0].source_extents = vec![
            Extent {
                logical_offset: 0,
                physical_offset: Some(4096),
                length: 4096,
            },
            Extent {
                logical_offset: 4096,
                physical_offset: Some(16384),
                length: 4096,
            },
        ];
        let mut mapping = mapping;
        mapping.logical_sha256 = digest;
        let plan = diagnose(&tree, &[mapping], &payloads, 65536).unwrap();
        assert_eq!((plan.retained_bytes, plan.relocated_bytes), (4096, 4096));
        assert_eq!(plan.ranges.len(), 2);
        assert_eq!(plan.ranges[0].disposition, Disposition::Retained);
        assert_eq!(plan.ranges[1].disposition, Disposition::Relocated);
        assert_eq!(plan.ranges[1].source_offset, Some(16384));
        assert_eq!(plan.ranges[1].destination_offset, Some(8192));
        let comparison = plan
            .comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
            .unwrap();
        assert_eq!(comparison.retained_ranges.len(), 1);

        tree.objects[0].source_extents[1].logical_offset = 0;
        let (_, mut invalid_mapping, _) = example(4096);
        invalid_mapping.logical_sha256 = tree.objects[0].sha256.clone().unwrap();
        assert!(diagnose(&tree, &[invalid_mapping], &payloads, 65536).is_err());
    }
    #[test]
    fn partial_final_cluster_materializes_only_the_tail() {
        let (mut tree, mut mapping, mut payloads) = example(4096);
        payloads[0].truncate(4097);
        let digest = hex::encode(Sha256::digest(&payloads[0]));
        tree.objects[0].source_offset = None;
        tree.objects[0].source_extents = vec![Extent {
            logical_offset: 0,
            physical_offset: Some(4096),
            length: 4096,
        }];
        tree.objects[0].length = 4097;
        tree.objects[0].sha256 = Some(digest.clone());
        tree.logical_bytes = 4097;
        mapping.logical_sha256 = digest;
        let plan = diagnose(&tree, &[mapping], &payloads, 65536).unwrap();
        assert_eq!(
            (
                plan.retained_bytes,
                plan.relocated_bytes,
                plan.materialized_bytes
            ),
            (4096, 0, 1)
        );
        assert_eq!(plan.ranges.len(), 2);
        assert_eq!(plan.ranges[0].source_offset, Some(4096));
        assert_eq!(plan.ranges[0].disposition, Disposition::Retained);
        assert_eq!(plan.ranges[1].source_offset, None);
        assert_eq!(plan.ranges[1].destination_offset, Some(8192));
        assert_eq!(plan.ranges[1].disposition, Disposition::Materialized);
        assert_eq!(
            plan.comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
                .unwrap()
                .retained_ranges
                .len(),
            1
        );
    }
    #[test]
    fn initialized_prefix_retains_while_uninitialized_tail_materializes() {
        let (mut tree, mut mapping, mut payloads) = example(4096);
        payloads[0].resize(16384, 0);
        payloads[0][5000..].fill(0);
        let digest = hex::encode(Sha256::digest(&payloads[0]));
        tree.objects[0].source_offset = None;
        tree.objects[0].source_extents = vec![Extent {
            logical_offset: 0,
            physical_offset: Some(4096),
            length: 4096,
        }];
        tree.objects[0].length = 16384;
        tree.objects[0].sha256 = Some(digest.clone());
        tree.logical_bytes = 16384;
        mapping.logical_sha256 = digest;
        mapping.extents[0].length = 16384;
        let plan = diagnose(&tree, &[mapping], &payloads, 65536).unwrap();
        assert_eq!(
            (
                plan.retained_bytes,
                plan.relocated_bytes,
                plan.materialized_bytes
            ),
            (4096, 0, 12288)
        );
        assert_eq!(plan.ranges.len(), 2);
        assert_eq!(plan.ranges[1].logical_offset, 4096);
        assert_eq!(
            plan.ranges[1].sha256,
            Some(hex::encode(Sha256::digest(&payloads[0][4096..])))
        );
    }
    #[test]
    fn streamed_fragmented_source_hashes_each_original_physical_run() {
        let (mut tree, mut mapping, payloads) = example(4096);
        tree.objects[0].source_offset = None;
        tree.objects[0].source_extents = vec![
            Extent {
                logical_offset: 0,
                physical_offset: Some(4096),
                length: 4096,
            },
            Extent {
                logical_offset: 4096,
                physical_offset: Some(16384),
                length: 4096,
            },
        ];
        mapping.extents = vec![
            Extent {
                logical_offset: 0,
                physical_offset: Some(4096),
                length: 4096,
            },
            Extent {
                logical_offset: 4096,
                physical_offset: Some(32768),
                length: 4096,
            },
        ];
        let mut raw = vec![0u8; 65536];
        raw[4096..8192].copy_from_slice(&payloads[0][..4096]);
        raw[16384..20480].copy_from_slice(&payloads[0][4096..]);
        let plan = diagnose_measured(
            &tree,
            &[mapping],
            &mut std::io::Cursor::new(raw),
            65536,
            |_, _, _, _| anyhow::bail!("fragmented source must use physical evidence"),
        )
        .unwrap();
        assert_eq!((plan.retained_bytes, plan.relocated_bytes), (4096, 4096));
        assert_eq!(plan.ranges[0].sha256, plan.ranges[1].sha256);
        assert_eq!(plan.ranges[1].source_offset, Some(16384));
    }
    #[test]
    fn incomplete_sparse_overlapping_and_foreign_streams_are_refused() {
        for kind in 0..5 {
            let (t, mut m, b) = example(4096);
            match kind {
                0 => m.extents[0].length = 4096,
                1 => m.extents[0].physical_offset = None,
                2 => m.extents[0].logical_offset = 4096,
                3 => m.logical_sha256 = "0".repeat(64),
                _ => m.record_number = 17,
            }
            assert!(diagnose(&t, &[m], &b, 65536).is_err());
        }
    }
    #[test]
    fn materialized_inline_and_partial_cluster_streams_need_no_fake_source_extent() {
        let (mut tree, mut mapping, mut payloads) = example(32768);
        payloads[0].truncate(512);
        let sha = hex::encode(Sha256::digest(&payloads[0]));
        tree.objects[0].source_offset = None;
        tree.objects[0].length = 512;
        tree.objects[0].sha256 = Some(sha.clone());
        tree.logical_bytes = 512;
        mapping.logical_sha256 = sha;
        mapping.extents.clear();
        let inline = diagnose(&tree, &[mapping], &payloads, 65536).unwrap();
        assert_eq!(inline.materialized_bytes, 512);
        assert_eq!(inline.ranges[0].destination_offset, None);
        assert!(
            inline
                .comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
                .unwrap()
                .retained_ranges
                .is_empty()
        );

        let (mut tree, mut mapping, mut payloads) = example(32768);
        payloads[0].truncate(4097);
        let sha = hex::encode(Sha256::digest(&payloads[0]));
        tree.objects[0].source_offset = None;
        tree.objects[0].length = 4097;
        tree.objects[0].sha256 = Some(sha.clone());
        tree.logical_bytes = 4097;
        mapping.logical_sha256 = sha;
        let partial = diagnose(&tree, &[mapping], &payloads, 65536).unwrap();
        assert_eq!(partial.materialized_bytes, 4097);
        assert_eq!(partial.ranges[0].length, 4097);
        assert_eq!(partial.ranges[0].destination_offset, Some(32768));
    }

    #[test]
    fn streamed_placement_hashes_only_source_physical_ranges() {
        let (tree, mapping, payloads) = example(4096);
        let mut source = vec![0u8; 65536];
        source[4096..4096 + payloads[0].len()].copy_from_slice(&payloads[0]);
        let measured = diagnose_measured(
            &tree,
            &[mapping],
            &mut std::io::Cursor::new(source),
            65536,
            |_, _, _, _| anyhow::bail!("unexpected materialized range"),
        )
        .unwrap();
        assert_eq!(measured.retained_bytes, 8192);
        assert_eq!(measured.ranges[0].sha256, tree.objects[0].sha256);
        assert_eq!(
            measured
                .comparison_request(65536, &"1".repeat(64), &"2".repeat(64), 65536)
                .unwrap()
                .retained_ranges[0]
                .source_sha256,
            tree.objects[0].sha256.as_deref().unwrap()
        );
    }

    #[test]
    fn streamed_placement_hashes_materialized_fragments() {
        let (mut tree, mut mapping, payloads) = example(32768);
        tree.objects[0].source_offset = None;
        mapping.extents[0].length = 4096;
        mapping.extents.push(Extent {
            logical_offset: 4096,
            physical_offset: Some(36864),
            length: 4096,
        });
        let measured = diagnose_measured(
            &tree,
            &[mapping],
            &mut std::io::Cursor::new(vec![0u8; 65536]),
            65536,
            |_, _, start, end| {
                Ok(hex::encode(Sha256::digest(
                    &payloads[0][start as usize..end as usize],
                )))
            },
        )
        .unwrap();
        assert_eq!(measured.materialized_bytes, 8192);
        assert_eq!(measured.ranges.len(), 2);
        assert!(measured.ranges.iter().all(|r| r.sha256.is_some()));
    }
}
