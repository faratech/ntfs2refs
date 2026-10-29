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
}

#[derive(Debug, Serialize)]
pub struct DeltaLayout {
    partition_bytes: u64,
    changed_bytes: u64,
    ranges: Vec<ChangedRange>,
}
impl DeltaLayout {
    pub(crate) fn new(
        partition_bytes: u64,
        changed_bytes: u64,
        ranges: Vec<ChangedRange>,
    ) -> Result<Self> {
        ensure!(
            partition_bytes > 0 && partition_bytes.is_multiple_of(4096) && ranges.len() <= 65536,
            "delta geometry/range budget differs"
        );
        let mut end = 0;
        let mut packed = 0u64;
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
            packed = packed
                .checked_add(r.length)
                .context("delta backing overflow")?;
        }
        ensure!(packed == changed_bytes, "delta byte total differs");
        Ok(Self {
            partition_bytes,
            changed_bytes,
            ranges,
        })
    }
    pub fn changed_bytes(&self) -> u64 {
        self.changed_bytes
    }
    pub fn changed_ranges(&self) -> usize {
        self.ranges.len()
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
                && packed.seek(SeekFrom::End(0))? == layout.changed_bytes,
            "delta backing lengths differ"
        );
        Ok(Self {
            original,
            packed,
            layout,
            position: 0,
        })
    }
}

#[cfg(windows)]
impl<S: Read + Seek> DifferenceImage<'_, n2r_win32::GeneralJournalReadView, S> {
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
                && self.packed.seek(SeekFrom::End(0))? == self.layout.changed_bytes,
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
        let mut first_range = 0usize;
        while offset < expected_length {
            let count = (expected_length - offset).min(actual.len() as u64) as usize;
            let end = offset + count as u64;
            // These are the only fresh native bytes for this chunk. The second
            // digest uses the same complement that DifferenceImage::read would
            // otherwise reread from this exact view.
            self.original.read_exact(&mut actual[..count])?;
            actual_hash.update(&actual[..count])?;
            candidate[..count].copy_from_slice(&actual[..count]);
            while first_range < self.layout.ranges.len()
                && self.layout.ranges[first_range].offset + self.layout.ranges[first_range].length
                    <= offset
            {
                first_range += 1;
            }
            for range in self.layout.ranges[first_range..]
                .iter()
                .take_while(|range| range.offset < end)
            {
                let start = offset.max(range.offset);
                let stop = end.min(range.offset + range.length);
                let local = usize::try_from(start - offset)?;
                let length = usize::try_from(stop - start)?;
                let packed_offset = range
                    .packed_offset
                    .checked_add(start - range.offset)
                    .context("paired compact packed offset overflow")?;
                self.packed.seek(SeekFrom::Start(packed_offset))?;
                self.packed
                    .read_exact(&mut candidate[local..local + length])?;
            }
            candidate_hash.update(&candidate[..count])?;
            offset = end;
        }
        ensure!(
            self.original.state(events)? == view_before
                && target.state(events)? == target_before
                && self.packed.seek(SeekFrom::End(0))? == self.layout.changed_bytes,
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
            self.packed
                .seek(SeekFrom::Start(r.packed_offset + self.position - r.offset))?;
            self.packed.read(&mut output[..count])?
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
