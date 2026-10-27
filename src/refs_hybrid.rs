//! Read-only candidate hybrid: retain original bytes outside the proposed ReFS
//! write set. No image allocation, native mount or execution authority exists
//! here. A caller must independently establish complete required-byte coverage
//! before this candidate can become a reconstruction target.
use crate::refs_write_set::{ByteRange, WriteSetPlan};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ReadCounts {
    pub original_bytes: u64,
    pub shadow_bytes: u64,
}

/// Bounded seekable view over two equally sized partition readers. Borrowed
/// interval metadata and caller-supplied read buffers are the only storage.
/// It deliberately implements no Write and exposes no source mutation route.
pub struct CandidateHybrid<'a, R, S> {
    original: &'a mut R,
    shadow: &'a mut S,
    owned: &'a [ByteRange],
    length: u64,
    position: u64,
    counts: ReadCounts,
}

impl<'a, R: Read + Seek, S: Read + Seek> CandidateHybrid<'a, R, S> {
    pub fn new(original: &'a mut R, shadow: &'a mut S, plan: &'a WriteSetPlan) -> Result<Self> {
        ensure!(
            plan.cluster_bytes == 4096
                && plan.partition_bytes >= 64 * 4096
                && plan.partition_bytes.is_multiple_of(4096)
                && plan.target_owned_ranges.len() <= 65536
                && plan.preserve_source_ranges.len() <= 65537,
            "hybrid candidate geometry or interval budget differs"
        );
        let mut cursor = 0u64;
        let mut owned_bytes = 0u64;
        let mut complement = Vec::new();
        for range in &plan.target_owned_ranges {
            let end = range
                .offset
                .checked_add(range.length)
                .context("hybrid interval overflow")?;
            ensure!(
                range.length > 0
                    && range.offset >= cursor
                    && range.offset.is_multiple_of(4096)
                    && range.length.is_multiple_of(4096)
                    && end <= plan.partition_bytes,
                "hybrid intervals overlap, are unaligned or leave the partition"
            );
            if cursor < range.offset {
                complement.push(ByteRange {
                    offset: cursor,
                    length: range.offset - cursor,
                });
            }
            cursor = end;
            owned_bytes = owned_bytes
                .checked_add(range.length)
                .context("hybrid owned-byte overflow")?;
        }
        if cursor < plan.partition_bytes {
            complement.push(ByteRange {
                offset: cursor,
                length: plan.partition_bytes - cursor,
            });
        }
        ensure!(
            complement == plan.preserve_source_ranges
                && owned_bytes == plan.target_owned_bytes
                && plan.preserve_source_bytes == plan.partition_bytes - owned_bytes,
            "hybrid plan does not exactly partition the volume"
        );
        ensure!(
            original.seek(SeekFrom::End(0))? == plan.partition_bytes
                && shadow.seek(SeekFrom::End(0))? == plan.partition_bytes,
            "hybrid input length differs from the candidate"
        );
        Ok(Self {
            original,
            shadow,
            owned: &plan.target_owned_ranges,
            length: plan.partition_bytes,
            position: 0,
            counts: ReadCounts::default(),
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.length
    }
    pub fn read_counts(&self) -> ReadCounts {
        self.counts
    }
}

impl<R: Read + Seek, S: Read + Seek> Read for CandidateHybrid<'_, R, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position == self.length {
            return Ok(0);
        }
        // Construction validated every sum used by this binary search.
        let index = self
            .owned
            .partition_point(|range| range.offset + range.length <= self.position);
        let range = self.owned.get(index);
        let from_shadow = range.is_some_and(|range| self.position >= range.offset);
        let boundary = match range {
            Some(range) if from_shadow => range.offset + range.length,
            Some(range) => range.offset,
            None => self.length,
        };
        let count = (boundary - self.position).min(buffer.len() as u64) as usize;
        let read = if from_shadow {
            self.shadow.seek(SeekFrom::Start(self.position))?;
            self.shadow.read(&mut buffer[..count])?
        } else {
            self.original.seek(SeekFrom::Start(self.position))?;
            self.original.read(&mut buffer[..count])?
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hybrid backing ended inside the partition",
            ));
        }
        self.position += read as u64;
        let counter = if from_shadow {
            &mut self.counts.shadow_bytes
        } else {
            &mut self.counts.original_bytes
        };
        *counter = counter
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("hybrid read counter overflow"))?;
        Ok(read)
    }
}

impl<R: Read + Seek, S: Read + Seek> Seek for CandidateHybrid<'_, R, S> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hybrid seek leaves partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
