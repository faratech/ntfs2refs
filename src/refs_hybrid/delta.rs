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
