//! Explicitly scoped source fingerprints under the caller's frozen live lease.
//! Extent mode omits only validated ordinary initialized payload interiors from
//! fingerprint IO. It does not turn metadata into a logical-content digest or
//! issue source admission. The raw inspector still obtains full content hashes.
use crate::{
    lab_reconstruct,
    ntfs_inspect::{LogicalHashStatus, MetadataRole, NtfsInspection},
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::GeneralFrozenPartition;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const FULL_KIND: &str = "ntfs_allocated_ranges_xxh3_128_4mib_pieces";
pub const EXTENT_KIND: &str = "ntfs_metadata_and_extent_fingerprint_v1";
const DOMAIN: &[u8] = b"ntfs2refs/source/metadata-and-extents/v1\0";
const GRANULE: u64 = 4096;

#[derive(Debug)]
pub struct SourceFingerprint {
    partition_bytes: u64,
    inspection_sha256: [u8; 32],
    policy: VerificationPolicy,
    allocated: Vec<(u64, u64)>,
    covered: Vec<(u64, u64)>,
    omitted: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub kind: &'static str,
    pub partition_bytes: u64,
    pub allocated_ranges: usize,
    pub allocated_bytes: u64,
    pub fingerprint_ranges: usize,
    pub fingerprint_bytes: u64,
    pub omitted_initialized_payload_ranges: usize,
    pub omitted_initialized_payload_bytes: u64,
    pub whole_source_content_digest: bool,
    pub raw_inspector_content_hashes_preserved: bool,
    pub grants_source_admission: bool,
}

fn normalize(mut ranges: Vec<(u64, u64)>, limit: u64) -> Result<Vec<(u64, u64)>> {
    for &(start, length) in &ranges {
        ensure!(
            length != 0 && start.checked_add(length).is_some_and(|end| end <= limit),
            "source fingerprint interval escapes partition"
        );
    }
    ranges.sort_unstable();
    let mut output: Vec<(u64, u64)> = Vec::new();
    for (start, length) in ranges {
        if let Some(last) = output.last_mut()
            && start <= last.0 + last.1
        {
            last.1 = (last.0 + last.1).max(start + length) - last.0;
        } else {
            output.push((start, length));
        }
    }
    Ok(output)
}

fn subtract(outer: &[(u64, u64)], removed: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut output = Vec::new();
    let mut first = 0;
    for &(start, length) in outer {
        let end = start + length;
        let mut cursor = start;
        while removed
            .get(first)
            .is_some_and(|&(at, bytes)| at + bytes <= start)
        {
            first += 1;
        }
        for &(at, bytes) in removed[first..].iter().take_while(|&&(at, _)| at < end) {
            if at > cursor {
                output.push((cursor, at.min(end) - cursor));
            }
            cursor = cursor.max((at + bytes).min(end));
        }
        if cursor < end {
            output.push((cursor, end - cursor));
        }
    }
    output
}

impl SourceFingerprint {
    pub fn for_inspection(
        raw: &NtfsInspection,
        partition_bytes: u64,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        ensure!(
            raw.geometry.volume_size <= partition_bytes,
            "NTFS geometry exceeds source fingerprint partition"
        );
        let allocated = raw.allocated_byte_ranges(partition_bytes)?;
        let mut omitted = Vec::new();
        if policy.is_fast() {
            // Reconcile all physical owners independently before any exclusion,
            // including MFT/system/attribute-list storage and unused reservation.
            let list_storage = raw.attribute_assemblies.iter().filter_map(|assembly| {
                assembly
                    .base
                    .attributes
                    .iter()
                    .find(|a| a.type_code == 0x20 && !a.resident)
            });
            let mut owners = Vec::new();
            for attribute in raw
                .files
                .iter()
                .flat_map(|f| f.attributes.iter())
                .chain(list_storage)
            {
                if attribute.resident {
                    continue;
                }
                for extent in &attribute.extents {
                    if let Some(start) = extent.physical_offset {
                        let end = start
                            .checked_add(extent.length)
                            .context("fingerprint owner overflow")?;
                        ensure!(
                            extent.length > 0 && end <= partition_bytes,
                            "fingerprint owner escapes partition"
                        );
                        owners.push((start, end));
                    }
                }
            }
            owners.sort_unstable();
            ensure!(
                owners.windows(2).all(|pair| pair[0].1 <= pair[1].0),
                "source fingerprint physical ownership overlaps"
            );
            let tail = partition_bytes.saturating_sub(1) / GRANULE * GRANULE;
            for file in raw.files.iter().filter(|file| {
                !file.is_directory
                    && !file.is_metadata
                    && file.base_file_reference == 0
                    && file.record_number >= 16
                    && file.metadata_role == MetadataRole::OutsideExtendCandidate
                    && file.metadata_role_issue.is_none()
            }) {
                for stream in &file.streams {
                    if stream.resident
                        || stream.flags != 0
                        || stream.initialized_size != stream.logical_size
                        || stream.logical_hash_status != LogicalHashStatus::Complete
                        || !stream
                            .logical_sha256
                            .as_deref()
                            .is_some_and(n2r_win32::content_digest::is_hex)
                    {
                        continue;
                    }
                    let mut matches = file
                        .attributes
                        .iter()
                        .filter(|a| a.type_code == 0x80 && a.name_utf16 == stream.name_utf16);
                    let Some(attribute) = matches.next() else {
                        continue;
                    };
                    ensure!(
                        matches.next().is_none(),
                        "ambiguous fingerprint DATA attribute"
                    );
                    ensure!(
                        !attribute.resident
                            && attribute.flags == 0
                            && attribute.compression_unit == 0
                            && attribute.lowest_vcn == 0
                            && attribute.total_allocated_size.is_none()
                            && attribute.logical_size == stream.logical_size
                            && attribute.initialized_size == stream.initialized_size
                            && attribute.allocated_size == stream.allocated_size
                            && attribute.extents == stream.extents,
                        "fingerprint DATA differs from its stream inventory"
                    );
                    let prefix = stream.logical_size / GRANULE * GRANULE;
                    let mut coverage = 0u64;
                    for extent in &stream.extents {
                        ensure!(
                            extent.logical_offset == coverage
                                && extent.length != 0
                                && extent.length.is_multiple_of(GRANULE),
                            "invalid fingerprint DATA coverage"
                        );
                        coverage = coverage
                            .checked_add(extent.length)
                            .context("fingerprint DATA coverage overflow")?;
                        let start = extent
                            .physical_offset
                            .context("plain fingerprint DATA has a sparse run")?;
                        ensure!(
                            start.is_multiple_of(GRANULE),
                            "unaligned fingerprint DATA physical run"
                        );
                        if extent.logical_offset < prefix {
                            let length = extent.length.min(prefix - extent.logical_offset);
                            // Always retain both bootstrap granules even if a
                            // malformed ownership model labels them user DATA.
                            let end = start
                                .checked_add(length)
                                .context("fingerprint payload overflow")?
                                .min(tail);
                            let start = start.max(GRANULE);
                            if start < end {
                                omitted.push((start, end - start));
                            }
                        }
                    }
                    ensure!(
                        coverage == stream.allocated_size && coverage >= stream.logical_size,
                        "fingerprint DATA allocation differs from complete mapping"
                    );
                }
            }
            omitted = normalize(omitted, partition_bytes)?;
            ensure!(
                crate::ntfs_inspect::ranges_cover(&allocated, &omitted),
                "fingerprint payload exclusions leave NTFS allocation"
            );
        }
        let covered = subtract(&allocated, &omitted);
        Ok(Self {
            partition_bytes,
            inspection_sha256: if policy.is_fast() {
                Sha256::digest(serde_json::to_vec(raw)?).into()
            } else {
                // The historical allocated-range digest has no inspection
                // frame. Avoid adding serialization work to full mode.
                [0; 32]
            },
            policy,
            allocated,
            covered,
            omitted,
        })
    }

    pub fn kind(&self) -> &'static str {
        if self.policy.is_fast() {
            EXTENT_KIND
        } else {
            FULL_KIND
        }
    }

    pub fn report(&self) -> Report {
        Report {
            kind: self.kind(),
            partition_bytes: self.partition_bytes,
            allocated_ranges: self.allocated.len(),
            allocated_bytes: self.allocated.iter().map(|r| r.1).sum(),
            fingerprint_ranges: self.covered.len(),
            fingerprint_bytes: self.covered.iter().map(|r| r.1).sum(),
            omitted_initialized_payload_ranges: self.omitted.len(),
            omitted_initialized_payload_bytes: self.omitted.iter().map(|r| r.1).sum(),
            whole_source_content_digest: false,
            raw_inspector_content_hashes_preserved: true,
            grants_source_admission: false,
        }
    }

    pub fn validate_inspection_reads(&self, reads: &[(u64, u64)]) -> Result<()> {
        let reads = normalize(reads.to_vec(), self.partition_bytes)?;
        ensure!(
            crate::ntfs_inspect::ranges_cover(&self.allocated, &reads),
            "inspection reads outside the reconciled NTFS allocation"
        );
        let outside = subtract(&reads, &self.covered);
        ensure!(
            crate::ntfs_inspect::ranges_cover(&self.omitted, &outside),
            "inspection bytes outside fingerprint are not explicitly eligible payload"
        );
        Ok(())
    }

    pub fn validate_reads(&self, reads: &[(u64, u64)]) -> Result<()> {
        self.validate_inspection_reads(reads)
    }

    pub fn hash(&self, source: &mut GeneralFrozenPartition) -> Result<String> {
        ensure!(
            source.byte_len() == self.partition_bytes,
            "fingerprint source length differs"
        );
        let digest = lab_reconstruct::hash_ranges_xxh3(source, &self.covered)?;
        if self.policy.is_full_content() {
            return Ok(hex::encode(digest));
        }
        let mut scoped = Sha256::new();
        scoped.update(DOMAIN);
        scoped.update(self.partition_bytes.to_le_bytes());
        scoped.update(self.inspection_sha256);
        for ranges in [&self.covered, &self.omitted] {
            scoped.update((ranges.len() as u64).to_le_bytes());
            for &(offset, length) in ranges {
                scoped.update(offset.to_le_bytes());
                scoped.update(length.to_le_bytes());
            }
        }
        scoped.update(digest);
        Ok(hex::encode(scoped.finalize()))
    }
}
