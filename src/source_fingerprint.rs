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
use std::io::{Read, Seek, SeekFrom};

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
    raw_extent_identity_streams: usize,
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
    pub raw_extent_identity_streams: usize,
    pub grants_source_admission: bool,
}

/// Accounting for one complete closing fingerprint. These are logical bytes
/// actually supplied to its digest, not physical-device IO measurements.
#[derive(Debug, Serialize)]
pub(crate) struct ClosingReuseReport {
    scope: &'static str,
    fingerprint_kind: &'static str,
    fingerprint_ranges: usize,
    fingerprint_bytes: u64,
    reused_capture_source_bytes: u64,
    additional_source_bytes_read: u64,
    observed_capture_source_bytes: u64,
    observed_capture_source_buffers: u64,
    maximum_gap_read_buffer_bytes: usize,
    exact_range_and_piece_framing_verified: bool,
    same_frozen_source_owner: bool,
    grants_source_admission: bool,
}

/// A single in-order fingerprint pass, consuming actual original capture
/// buffers before they are recycled. Only its next canonical piece is hashed;
/// no old-source payload or table of per-piece digests is retained. Missing
/// coverage is read through the same frozen owner, not inferred from ownership.
pub(crate) struct ClosingSourceFingerprint<'a> {
    fingerprint: &'a SourceFingerprint,
    // Identity only: this pointer is never dereferenced. The capture must pass
    // back the actual frozen owner that created its original-read lanes.
    owner: *const GeneralFrozenPartition,
    binding: n2r_win32::general_layout::GeneralDiskBinding,
    summary: n2r_win32::sha256_native::Sha256,
    piece: xxhash_rust::xxh3::Xxh3,
    range_index: usize,
    range_done: u64,
    piece_done: usize,
    observed_end: u64,
    observed_buffers: u64,
    observed_bytes: u64,
    reused_bytes: u64,
    read_bytes: u64,
    gap_buffer: Vec<u8>,
}

impl ClosingSourceFingerprint<'_> {
    fn validate_owner(&self, source: &GeneralFrozenPartition) -> Result<()> {
        ensure!(
            std::ptr::eq(self.owner, source)
                && source.binding() == &self.binding
                && source.byte_len() == self.fingerprint.partition_bytes,
            "closing fingerprint requires its original frozen source owner"
        );
        Ok(())
    }

    fn next_offset(&self) -> Option<u64> {
        self.fingerprint
            .covered
            .get(self.range_index)
            .map(|&(offset, _)| offset + self.range_done)
    }

    /// Feed bytes at exactly the next covered address. The XXH3 piece size and
    /// range framing equal hash_ranges_xxh3 even when capture/gap boundaries
    /// split a piece, or one capture buffer spans several fingerprint ranges.
    fn consume(&mut self, mut bytes: &[u8]) -> Result<()> {
        use crate::parallel_digest::MAX_CHUNK_BYTES;
        let &(offset, length) = self
            .fingerprint
            .covered
            .get(self.range_index)
            .context("closing fingerprint has no remaining range")?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= length - self.range_done,
            "closing fingerprint bytes escape the next covered range"
        );
        if self.range_done == 0 {
            self.summary.update(&offset.to_le_bytes())?;
            self.summary.update(&length.to_le_bytes())?;
        }
        while !bytes.is_empty() {
            let count = bytes.len().min(MAX_CHUNK_BYTES - self.piece_done);
            self.piece.update(&bytes[..count]);
            self.piece_done += count;
            self.range_done += count as u64;
            bytes = &bytes[count..];
            if self.piece_done == MAX_CHUNK_BYTES || self.range_done == length {
                self.summary.update(&self.piece.digest128().to_be_bytes())?;
                self.piece = xxhash_rust::xxh3::Xxh3::new();
                self.piece_done = 0;
            }
        }
        if self.range_done == length {
            self.range_index += 1;
            self.range_done = 0;
        }
        Ok(())
    }

    fn read_before(&mut self, source: &mut GeneralFrozenPartition, limit: u64) -> Result<()> {
        self.validate_owner(source)?;
        if self.next_offset().is_none_or(|offset| offset >= limit) {
            return Ok(());
        }
        let original_position = source.stream_position()?;
        // Temporarily separate scratch storage from the digest state so no
        // source bytes are copied or cached while consume mutates its cursor.
        let mut buffer = std::mem::take(&mut self.gap_buffer);
        let result = (|| -> Result<()> {
            while let Some(offset) = self.next_offset().filter(|&offset| offset < limit) {
                let (range_offset, range_length) = self.fingerprint.covered[self.range_index];
                let count = usize::try_from(
                    (range_offset + range_length - offset)
                        .min(limit - offset)
                        .min(buffer.len() as u64),
                )?;
                ensure!(count > 0, "closing fingerprint gap read made no progress");
                source.seek(SeekFrom::Start(offset))?;
                source.read_exact(&mut buffer[..count])?;
                self.consume(&buffer[..count])?;
                self.read_bytes = self
                    .read_bytes
                    .checked_add(count as u64)
                    .context("closing fingerprint gap byte count overflow")?;
            }
            Ok(())
        })();
        self.gap_buffer = buffer;
        // The capture's source and logical readers retain their original seek
        // contract even on refusal; the independent prefetch lane is untouched.
        let restored = source.seek(SeekFrom::Start(original_position));
        result?;
        restored?;
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        source: &mut GeneralFrozenPartition,
    ) -> Result<(String, ClosingReuseReport)> {
        self.read_before(source, self.fingerprint.partition_bytes)?;
        let fingerprint_bytes = self.fingerprint.covered.iter().map(|range| range.1).sum();
        ensure!(
            self.range_index == self.fingerprint.covered.len()
                && self.range_done == 0
                && self.piece_done == 0
                && self.reused_bytes.checked_add(self.read_bytes) == Some(fingerprint_bytes),
            "closing fingerprint did not consume every covered byte exactly once"
        );
        let digest = self.fingerprint.wrap_digest(self.summary.finish()?);
        Ok((
            digest,
            ClosingReuseReport {
                scope: "actual-closing-source-buffers-and-gap-reads-v1",
                fingerprint_kind: self.fingerprint.kind(),
                fingerprint_ranges: self.fingerprint.covered.len(),
                fingerprint_bytes,
                reused_capture_source_bytes: self.reused_bytes,
                additional_source_bytes_read: self.read_bytes,
                observed_capture_source_bytes: self.observed_bytes,
                observed_capture_source_buffers: self.observed_buffers,
                maximum_gap_read_buffer_bytes: self.gap_buffer.len(),
                exact_range_and_piece_framing_verified: true,
                same_frozen_source_owner: true,
                grants_source_admission: false,
            },
        ))
    }
}

impl crate::general_shadow::source_backed::ClosingSourceBytes for ClosingSourceFingerprint<'_> {
    fn observe_original(
        &mut self,
        source: &mut GeneralFrozenPartition,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        self.validate_owner(source)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .context("closing fingerprint observed source range overflow")?;
        ensure!(
            !bytes.is_empty()
                && offset >= self.observed_end
                && end <= self.fingerprint.partition_bytes,
            "closing fingerprint original buffers overlap, regress or escape the source"
        );
        self.read_before(source, offset)?;
        while let Some(at) = self.next_offset().filter(|&at| at < end) {
            ensure!(
                at >= offset,
                "closing fingerprint missed preceding coverage"
            );
            let (range_offset, range_length) = self.fingerprint.covered[self.range_index];
            let count = usize::try_from((range_offset + range_length).min(end) - at)?;
            let start = usize::try_from(at - offset)?;
            self.consume(&bytes[start..start + count])?;
            self.reused_bytes = self
                .reused_bytes
                .checked_add(count as u64)
                .context("closing fingerprint reused byte count overflow")?;
        }
        self.observed_end = end;
        self.observed_buffers = self
            .observed_buffers
            .checked_add(1)
            .context("closing fingerprint observed buffer count overflow")?;
        self.observed_bytes = self
            .observed_bytes
            .checked_add(bytes.len() as u64)
            .context("closing fingerprint observed byte count overflow")?;
        Ok(())
    }
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
                    let explicit_extent = stream.logical_hash_status
                        == LogicalHashStatus::NotReadExtentIdentityV1
                        && stream.logical_sha256.is_none()
                        && crate::ntfs_attestation::extent_identity_stream_request(
                            raw, file, stream,
                        )?
                        .is_some();
                    if stream.resident
                        || stream.flags != 0
                        || stream.initialized_size != stream.logical_size
                        || (!explicit_extent
                            && (stream.logical_hash_status != LogicalHashStatus::Complete
                                || !stream
                                    .logical_sha256
                                    .as_deref()
                                    .is_some_and(n2r_win32::content_digest::is_hex)))
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
            raw_extent_identity_streams: raw
                .files
                .iter()
                .flat_map(|f| &f.streams)
                .filter(|s| s.logical_hash_status == LogicalHashStatus::NotReadExtentIdentityV1)
                .count(),
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
            raw_inspector_content_hashes_preserved: self.raw_extent_identity_streams == 0,
            raw_extent_identity_streams: self.raw_extent_identity_streams,
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
        Ok(self.wrap_digest(digest))
    }

    pub(crate) fn closing_reuse<'a>(
        &'a self,
        source: &GeneralFrozenPartition,
    ) -> Result<ClosingSourceFingerprint<'a>> {
        ensure!(
            self.policy.is_fast() && source.byte_len() == self.partition_bytes,
            "closing source reuse requires the complete fast fingerprint on this source"
        );
        Ok(ClosingSourceFingerprint {
            fingerprint: self,
            owner: source,
            binding: source.binding().clone(),
            summary: n2r_win32::sha256_native::Sha256::new()?,
            piece: xxhash_rust::xxh3::Xxh3::new(),
            range_index: 0,
            range_done: 0,
            piece_done: 0,
            observed_end: 0,
            observed_buffers: 0,
            observed_bytes: 0,
            reused_bytes: 0,
            read_bytes: 0,
            gap_buffer: vec![0; crate::parallel_digest::MAX_CHUNK_BYTES],
        })
    }

    fn wrap_digest(&self, digest: [u8; 32]) -> String {
        if self.policy.is_full_content() {
            return hex::encode(digest);
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
        hex::encode(scoped.finalize())
    }
}
