//! Exact stream dispositions for a measured shadow. Diagnostic only: admission,
//! frozen-shadow validation, capacity and recovery still precede execution.
use crate::{ntfs_inspect::Extent, shadow_tree::Tree};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub struct Mapping {
    pub record_number: u64,
    pub sequence_number: u16,
    pub target_file_id: [u8; 16],
    pub logical_sha256: String,
    pub extents: Vec<Extent>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Retained,
    Relocated,
}
#[derive(Debug, Serialize)]
pub struct Range {
    pub record_number: u64,
    pub sequence_number: u16,
    pub path: Vec<String>,
    pub stream_name: &'static str,
    pub target_file_id: [u8; 16],
    pub logical_offset: u64,
    pub source_offset: u64,
    pub destination_offset: u64,
    pub length: u64,
    pub sha256: String,
    pub disposition: Disposition,
    pub justification: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Plan {
    pub profile: &'static str,
    pub ranges: Vec<Range>,
    pub retained_bytes: u64,
    pub relocated_bytes: u64,
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
        for range in &self.ranges {
            ensure!(range.length > 0, "empty stream disposition");
            match range.disposition {
                Disposition::Retained => {
                    ensure!(
                        range.source_offset == range.destination_offset,
                        "retained disposition changes physical placement"
                    );
                    retained_bytes = retained_bytes
                        .checked_add(range.length)
                        .context("retained byte count overflow")?;
                    retained_ranges.push(RetainedRangeRequest {
                        offset: range.source_offset,
                        length: range.length,
                        source_sha256: range.sha256.clone(),
                        shadow_sha256: range.sha256.clone(),
                    });
                }
                Disposition::Relocated => {
                    ensure!(
                        range.source_offset != range.destination_offset,
                        "relocated disposition has unchanged placement"
                    );
                    relocated_bytes = relocated_bytes
                        .checked_add(range.length)
                        .context("relocated byte count overflow")?;
                }
            }
        }
        ensure!(
            retained_bytes == self.retained_bytes && relocated_bytes == self.relocated_bytes,
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
        profile: "existing-tree-placement-v1",
        ranges: vec![],
        retained_bytes: 0,
        relocated_bytes: 0,
        shadow_payload_initialization_bytes: 0,
        executable: false,
        pending: vec![
            "complete source admission",
            "frozen shadow and whole-image validation",
            "exact patch/journal capacity",
            "native interruption/recovery qualification",
        ],
    };
    for (o, bytes) in tree.objects.iter().zip(payloads) {
        if o.directory {
            ensure!(bytes.is_empty(), "directory payload is unsupported");
            continue;
        }
        let m = index
            .remove(&(o.record_number, o.sequence_number))
            .context("missing target stream")?;
        let source = o.source_offset.context("missing source physical extent")?;
        ensure!(
            bytes.len() as u64 == o.length
                && Some(&m.logical_sha256) == o.sha256.as_ref()
                && hex::encode(Sha256::digest(bytes)) == m.logical_sha256,
            "source/target logical stream proof differs"
        );
        let mut cursor = 0u64;
        ensure!(
            !m.extents.is_empty() && m.extents.len() <= 1024,
            "target extent budget"
        );
        for e in &m.extents {
            let dest = e.physical_offset.context("target hole is unsupported")?;
            let end = cursor
                .checked_add(e.length)
                .context("logical extent overflow")?;
            ensure!(
                e.logical_offset == cursor
                    && e.length > 0
                    && e.length.is_multiple_of(4096)
                    && dest.is_multiple_of(4096)
                    && end <= o.length
                    && dest
                        .checked_add(e.length)
                        .is_some_and(|end| end <= partition)
                    && source.checked_add(end).is_some_and(|end| end <= partition),
                "invalid target extent coverage or bounds"
            );
            let from = source + cursor;
            let retained = dest == from;
            if retained {
                p.retained_bytes += e.length;
            } else {
                p.relocated_bytes += e.length;
            }
            p.ranges.push(Range{record_number:o.record_number,sequence_number:o.sequence_number,path:o.path.clone(),
                stream_name:"",target_file_id:m.target_file_id,logical_offset:cursor,source_offset:from,
                destination_offset:dest,length:e.length,sha256:hex::encode(Sha256::digest(&bytes[cursor as usize..end as usize])),
                disposition:if retained {Disposition::Retained} else {Disposition::Relocated},
                justification:if retained {"native target mapping resolves to the original source bytes"}
                    else {"real source bytes initialized at an independent native ReFS allocation; journal must carry them to the original partition"}});
            cursor = end;
        }
        ensure!(
            cursor == o.length,
            "target stream has incomplete physical coverage"
        );
        p.shadow_payload_initialization_bytes += o.length;
    }
    ensure!(index.is_empty(), "unexpected target stream identity");
    let mut targets: Vec<_> = p
        .ranges
        .iter()
        .map(|r| (r.destination_offset, r.length))
        .collect();
    targets.sort_unstable();
    ensure!(
        targets
            .windows(2)
            .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0),
        "exclusive target allocations overlap"
    );
    ensure!(
        p.retained_bytes + p.relocated_bytes == tree.logical_bytes,
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
                    source_offset: Some(4096),
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
        assert_eq!(request.retained_ranges[0].source_sha256, p.ranges[0].sha256);
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
}
