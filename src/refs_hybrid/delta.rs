//! Read-only target view backed only by changed clusters. Equal candidate bytes
//! use the frozen original; no allocator reservation is omitted by inference.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

mod artifact;
pub use artifact::{DeltaArtifactPins, VerifiedDeltaArtifact};

#[derive(Debug, Serialize)]
pub struct ChangedRange {
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) packed_offset: u64,
    /// Version-two backing omits these bytes; the captured candidate was all
    /// zero throughout this interval. The interval remains in the write set.
    #[serde(skip_serializing_if = "is_false")]
    pub(crate) new_is_zero: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Debug, Serialize)]
pub struct DeltaLayout {
    partition_bytes: u64,
    changed_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packed_bytes: Option<u64>,
    ranges: Vec<ChangedRange>,
}
impl DeltaLayout {
    pub(crate) fn new(
        partition_bytes: u64,
        changed_bytes: u64,
        ranges: Vec<ChangedRange>,
    ) -> Result<Self> {
        ensure!(
            ranges.iter().all(|range| !range.new_is_zero),
            "legacy delta cannot omit zero payloads"
        );
        Self::checked(partition_bytes, changed_bytes, None, ranges)
    }

    pub(crate) fn new_zero_aware(
        partition_bytes: u64,
        changed_bytes: u64,
        packed_bytes: u64,
        ranges: Vec<ChangedRange>,
    ) -> Result<Self> {
        Self::checked(partition_bytes, changed_bytes, Some(packed_bytes), ranges)
    }

    fn checked(
        partition_bytes: u64,
        changed_bytes: u64,
        packed_bytes: Option<u64>,
        ranges: Vec<ChangedRange>,
    ) -> Result<Self> {
        ensure!(
            partition_bytes > 0 && partition_bytes.is_multiple_of(4096) && ranges.len() <= 65536,
            "delta geometry/range budget differs"
        );
        let mut end = 0;
        let mut packed = 0u64;
        let mut logical = 0u64;
        for r in &ranges {
            let next = r
                .offset
                .checked_add(r.length)
                .context("delta interval overflow")?;
            ensure!(
                r.length > 0
                    && r.length.is_multiple_of(4096)
                    && r.offset.is_multiple_of(4096)
                    && r.offset >= end
                    && next <= partition_bytes
                    && r.packed_offset == packed,
                "delta ranges overlap, escape or lack dense backing"
            );
            end = next;
            logical = logical
                .checked_add(r.length)
                .context("delta logical byte overflow")?;
            if !r.new_is_zero {
                packed = packed
                    .checked_add(r.length)
                    .context("delta backing overflow")?;
            }
        }
        ensure!(
            logical == changed_bytes && packed == packed_bytes.unwrap_or(changed_bytes),
            "delta logical or backing byte total differs"
        );
        Ok(Self {
            partition_bytes,
            changed_bytes,
            encoding_version: packed_bytes.map(|_| 2),
            packed_bytes,
            ranges,
        })
    }
    pub fn changed_bytes(&self) -> u64 {
        self.changed_bytes
    }
    pub fn changed_ranges(&self) -> usize {
        self.ranges.len()
    }

    pub fn packed_bytes(&self) -> u64 {
        self.packed_bytes.unwrap_or(self.changed_bytes)
    }

    pub fn new_zero_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .filter(|range| range.new_is_zero)
            .map(|range| (range.offset, range.length))
            .collect()
    }

    pub(crate) fn intervals(&self) -> &[ChangedRange] {
        &self.ranges
    }

    /// Journal patch splitting may differ, but its write set must cover exactly
    /// these changed bytes. No source-backed complement byte may be armed.
    pub fn require_exact_write_ranges(&self, patches: &[(u64, u64)]) -> Result<()> {
        ensure!(
            patches.len() <= 65536,
            "delta journal range budget exceeded"
        );
        let mut index = 0usize;
        let mut cursor = self.ranges.first().map_or(0, |r| r.offset);
        for &(offset, length) in patches {
            let range = self
                .ranges
                .get(index)
                .context("journal writes beyond delta set")?;
            let end = offset
                .checked_add(length)
                .context("journal range overflow")?;
            ensure!(
                length > 0 && offset == cursor && end <= range.offset + range.length,
                "journal patch escapes or skips delta bytes"
            );
            cursor = end;
            if cursor == range.offset + range.length {
                index += 1;
                cursor = self.ranges.get(index).map_or(0, |r| r.offset);
            }
        }
        ensure!(
            index == self.ranges.len(),
            "journal does not cover all delta bytes"
        );
        Ok(())
    }
    pub fn partition_bytes(&self) -> u64 {
        self.partition_bytes
    }
}

/// The constructor checks layout, not capture provenance. A candidate remains
/// non-executable until the required-byte graph and recovery plan are qualified.
pub struct DifferenceImage<'a, R, S> {
    original: &'a mut R,
    packed: &'a mut S,
    layout: &'a DeltaLayout,
    position: u64,
}
impl<'a, R: Read + Seek, S: Read + Seek> DifferenceImage<'a, R, S> {
    pub fn new(original: &'a mut R, packed: &'a mut S, layout: &'a DeltaLayout) -> Result<Self> {
        ensure!(
            original.seek(SeekFrom::End(0))? == layout.partition_bytes
                && packed.seek(SeekFrom::End(0))? == layout.packed_bytes(),
            "delta backing lengths differ"
        );
        Ok(Self {
            original,
            packed,
            layout,
            position: 0,
        })
    }

    /// Replace only changed-range intersections in an already-read source
    /// chunk. This shares byte mechanics, not an admission or digest proof.
    #[cfg(windows)]
    fn overlay_packed_chunk(&mut self, offset: u64, candidate: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(candidate.len() as u64)
            .context("paired compact chunk overflow")?;
        ensure!(
            !candidate.is_empty() && end <= self.layout.partition_bytes,
            "paired compact chunk escapes partition"
        );
        let first = self
            .layout
            .ranges
            .partition_point(|range| range.offset + range.length <= offset);
        for range in self.layout.ranges[first..]
            .iter()
            .take_while(|range| range.offset < end)
        {
            let start = offset.max(range.offset);
            let stop = end.min(range.offset + range.length);
            let local = usize::try_from(start - offset)?;
            let length = usize::try_from(stop - start)?;
            if range.new_is_zero {
                candidate[local..local + length].fill(0);
                continue;
            }
            let packed_offset = range
                .packed_offset
                .checked_add(start - range.offset)
                .context("paired compact packed offset overflow")?;
            self.packed.seek(SeekFrom::Start(packed_offset))?;
            self.packed
                .read_exact(&mut candidate[local..local + length])?;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) struct FrozenPairDigests {
    pub(crate) source_raw: String,
    pub(crate) source_framed: String,
    pub(crate) candidate_raw: String,
    pub(crate) candidate_framed: String,
}

#[cfg(windows)]
impl<S: Read + Seek> DifferenceImage<'_, n2r_win32::GeneralFrozenPartition, S> {
    pub(crate) fn paired_source_state(
        &mut self,
        source: &n2r_win32::GeneralFrozenPartition,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<n2r_win32::GeneralDiskState> {
        ensure!(
            source.binding() == self.original.binding()
                && source.byte_len() == self.layout.partition_bytes
                && self.original.byte_len() == self.layout.partition_bytes
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired preparation does not share the exact frozen source"
        );
        let state = source.state(events)?;
        ensure!(
            state.disk_attributes == 3 && self.original.state(events)? == state,
            "paired preparation source/complement exclusion differs"
        );
        Ok(state)
    }

    pub(crate) fn read_pair_from_frozen_source(
        &mut self,
        source: &mut n2r_win32::GeneralFrozenPartition,
        offset: u64,
        original: &mut [u8],
        candidate: &mut [u8],
    ) -> Result<u64> {
        ensure!(
            source.binding() == self.original.binding()
                && offset == self.position
                && !original.is_empty()
                && original.len() <= 1024 * 1024
                && original.len() == candidate.len(),
            "invalid typed paired preparation chunk"
        );
        let end = offset
            .checked_add(original.len() as u64)
            .context("paired preparation overflow")?;
        ensure!(
            end <= self.layout.partition_bytes,
            "paired preparation escapes source"
        );
        source.seek(SeekFrom::Start(offset))?;
        source.read_exact(original)?;
        candidate.copy_from_slice(original);
        self.overlay_packed_chunk(offset, candidate)?;
        self.position = end;
        let first = self
            .layout
            .ranges
            .partition_point(|r| r.offset + r.length <= offset);
        let changed = self.layout.ranges[first..]
            .iter()
            .take_while(|r| r.offset < end)
            .map(|r| (r.offset + r.length).min(end) - r.offset.max(offset))
            .sum::<u64>();
        (original.len() as u64)
            .checked_sub(changed)
            .context("paired preparation read accounting overflow")
    }

    /// Fresh final source/candidate scan. Both raw and complete-range-framed
    /// digests consume identical logical bytes to independent hash_image scans.
    pub(crate) fn hash_pair_for_frozen_source(
        &mut self,
        source_binding: &n2r_win32::general_layout::GeneralDiskBinding,
        expected_length: u64,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<FrozenPairDigests> {
        ensure!(
            self.original.binding() == source_binding
                && self.original.byte_len() == expected_length
                && self.layout.partition_bytes == expected_length
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired frozen hash differs from actual source binding or backing"
        );
        let source_before = self.original.state(events)?;
        ensure!(
            source_before.disk_attributes == 3,
            "paired frozen hash requires persistently excluded read-only source"
        );
        self.original.seek(SeekFrom::Start(0))?;
        let mut source = vec![0u8; 1024 * 1024];
        let mut candidate = vec![0u8; 1024 * 1024];
        let mut hashes = crate::retained_compare::paired_digest::PairHasher::new(expected_length)?;
        let mut offset = 0u64;
        while offset < expected_length {
            let count = (expected_length - offset).min(source.len() as u64) as usize;
            self.original.read_exact(&mut source[..count])?;
            candidate[..count].copy_from_slice(&source[..count]);
            self.overlay_packed_chunk(offset, &mut candidate[..count])?;
            hashes.update_pair(&source[..count], &candidate[..count])?;
            offset += count as u64;
        }
        ensure!(
            self.original.state(events)? == source_before
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired frozen inputs changed around the complete scan"
        );
        self.position = expected_length;
        let hashes = hashes.finish()?;
        Ok(FrozenPairDigests {
            source_raw: hex::encode(hashes.source_raw),
            source_framed: hex::encode(hashes.source_framed),
            candidate_raw: hex::encode(hashes.candidate_raw),
            candidate_framed: hex::encode(hashes.candidate_framed),
        })
    }
}

#[cfg(windows)]
impl<S: Read + Seek> DifferenceImage<'_, n2r_win32::GeneralJournalReadView, S> {
    /// Bind a shared target read to this exact protected complement and packed
    /// layout. The caller must verify the returned state again after the scan.
    pub(crate) fn paired_target_state(
        &mut self,
        target: &n2r_win32::GeneralJournaledPartition,
        expected_length: u64,
        journal_ranges: &[(u64, u64)],
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<n2r_win32::GeneralDiskState> {
        ensure!(
            self.original.binding() == target.binding()
                && self.original.byte_len() == expected_length
                && target.byte_len() == expected_length
                && self.layout.partition_bytes == expected_length
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired compact hash is not the exact target read view and backing"
        );
        self.layout.require_exact_write_ranges(journal_ranges)?;
        let target_state = target.state(events)?;
        ensure!(
            self.original.state(events)? == target_state && target_state.disk_attributes == 1,
            "paired compact hash requires the same excluded activated target"
        );
        Ok(target_state)
    }

    /// Overlay the packed candidate on bytes just read from the paired target.
    pub(crate) fn overlay_target_chunk(&mut self, offset: u64, candidate: &mut [u8]) -> Result<()> {
        self.overlay_packed_chunk(offset, candidate)
    }

    /// Hash a fresh target read view and its complete candidate in one physical
    /// scan. The native view must be the exact target; callers cannot supply
    /// cached bytes or precomputed hashes. Packed overlays are still read in full.
    pub(crate) fn hash_pair_for_target(
        &mut self,
        target: &n2r_win32::GeneralJournaledPartition,
        expected_length: u64,
        journal_ranges: &[(u64, u64)],
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<(String, String)> {
        ensure!(
            self.original.binding() == target.binding()
                && self.original.byte_len() == expected_length
                && target.byte_len() == expected_length
                && self.layout.partition_bytes == expected_length
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired compact hash is not the exact target read view and backing"
        );
        self.layout.require_exact_write_ranges(journal_ranges)?;
        let target_before = target.state(events)?;
        let view_before = self.original.state(events)?;
        ensure!(
            target_before == view_before && target_before.disk_attributes == 1,
            "paired compact hash requires the same excluded activated target"
        );
        self.original.seek(SeekFrom::Start(0))?;
        let mut actual = vec![0u8; 1024 * 1024];
        let mut candidate = vec![0u8; 1024 * 1024];
        let mut actual_hash = n2r_win32::sha256_native::Sha256::new()?;
        let mut candidate_hash = n2r_win32::sha256_native::Sha256::new()?;
        let mut offset = 0u64;
        while offset < expected_length {
            let count = (expected_length - offset).min(actual.len() as u64) as usize;
            let end = offset + count as u64;
            // These are the only fresh native bytes for this chunk. The second
            // digest uses the same complement that DifferenceImage::read would
            // otherwise reread from this exact view.
            self.original.read_exact(&mut actual[..count])?;
            actual_hash.update(&actual[..count])?;
            candidate[..count].copy_from_slice(&actual[..count]);
            self.overlay_packed_chunk(offset, &mut candidate[..count])?;
            candidate_hash.update(&candidate[..count])?;
            offset = end;
        }
        ensure!(
            self.original.state(events)? == view_before
                && target.state(events)? == target_before
                && self.packed.seek(SeekFrom::End(0))? == self.layout.packed_bytes(),
            "paired compact inputs changed around the complete hash scan"
        );
        self.position = expected_length;
        Ok((
            hex::encode(actual_hash.finish()?),
            hex::encode(candidate_hash.finish()?),
        ))
    }
}

impl<R: Read + Seek, S: Read + Seek> Read for DifferenceImage<'_, R, S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.layout.partition_bytes {
            return Ok(0);
        }
        let index = self
            .layout
            .ranges
            .partition_point(|r| r.offset + r.length <= self.position);
        let range = self.layout.ranges.get(index);
        let changed = range.is_some_and(|r| r.offset <= self.position);
        let end = match range {
            Some(r) if changed => r.offset + r.length,
            Some(r) => r.offset,
            None => self.layout.partition_bytes,
        };
        let count = (end - self.position).min(output.len() as u64) as usize;
        let read = if changed {
            let r = range.unwrap();
            if r.new_is_zero {
                output[..count].fill(0);
                count
            } else {
                self.packed
                    .seek(SeekFrom::Start(r.packed_offset + self.position - r.offset))?;
                self.packed.read(&mut output[..count])?
            }
        } else {
            self.original.seek(SeekFrom::Start(self.position))?;
            self.original.read(&mut output[..count])?
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "delta backing ended",
            ));
        }
        self.position += read as u64;
        Ok(read)
    }
}
impl<R: Read + Seek, S: Read + Seek> Seek for DifferenceImage<'_, R, S> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.layout.partition_bytes) + i128::from(v),
        };
        if next < 0 || next > i128::from(self.layout.partition_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "delta seek escapes partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

impl<R: Read + Seek, S: Read + Seek> crate::lab_reconstruct::ReadSeek
    for DifferenceImage<'_, R, S>
{
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.layout.partition_bytes)
    }
}
