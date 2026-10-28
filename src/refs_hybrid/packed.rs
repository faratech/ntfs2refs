//! Compact backing for a candidate hybrid. Only selected shadow ranges are
//! stored; holes are deliberately unreadable rather than fabricated as zeros.
//! This changes storage representation, not the candidate's write authority.
use crate::refs_write_set::{ByteRange, WriteSetPlan};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};

#[derive(Debug, serde::Serialize)]
pub struct PackReceipt {
    pub partition_bytes: u64,
    pub packed_bytes: u64,
    pub ranges: usize,
    pub sha256: String,
    pub buffer_bytes: usize,
    pub executable: bool,
}

/// A partition-sized address space backed by a densely packed sequence of
/// selected ranges. Use behind CandidateHybrid, which supplies original bytes
/// for the complement. No allocation proportional to partition size occurs.
pub struct PackedShadow<'a, R> {
    backing: &'a mut R,
    ranges: &'a [ByteRange],
    starts: Vec<u64>,
    length: u64,
    position: u64,
}

fn layout(plan: &WriteSetPlan) -> Result<Vec<u64>> {
    ensure!(
        plan.cluster_bytes == 4096
            && plan.partition_bytes >= 64 * 4096
            && plan.partition_bytes.is_multiple_of(4096)
            && plan.target_owned_ranges.len() <= 65536,
        "packed candidate geometry or range budget differs"
    );
    let mut starts = Vec::with_capacity(plan.target_owned_ranges.len());
    let (mut end, mut total) = (0u64, 0u64);
    let mut complement = Vec::new();
    for range in &plan.target_owned_ranges {
        let next = range
            .offset
            .checked_add(range.length)
            .context("packed range overflow")?;
        ensure!(
            range.length > 0
                && range.offset >= end
                && range.offset.is_multiple_of(4096)
                && range.length.is_multiple_of(4096)
                && next <= plan.partition_bytes,
            "invalid packed candidate range"
        );
        if range.offset > end {
            complement.push(ByteRange {
                offset: end,
                length: range.offset - end,
            });
        }
        starts.push(total);
        total = total
            .checked_add(range.length)
            .context("packed length overflow")?;
        end = next;
    }
    if end < plan.partition_bytes {
        complement.push(ByteRange {
            offset: end,
            length: plan.partition_bytes - end,
        });
    }
    ensure!(
        total == plan.target_owned_bytes
            && complement == plan.preserve_source_ranges
            && plan.preserve_source_bytes == plan.partition_bytes - total,
        "packed candidate totals or complement differ"
    );
    Ok(starts)
}

/// Stream selected shadow bytes into a fresh, caller-owned scratch sink. The
/// caller must flush it durably and bind this receipt to the exact plan before
/// reuse. Failure leaves an incomplete artifact, never a completion receipt.
pub fn pack<R: Read + Seek, W: Write>(
    shadow: &mut R,
    output: &mut W,
    plan: &WriteSetPlan,
) -> Result<PackReceipt> {
    layout(plan)?;
    ensure!(
        shadow.seek(SeekFrom::End(0))? == plan.partition_bytes,
        "shadow length differs from candidate"
    );
    let mut buffer = [0u8; 65536];
    let mut digest = Sha256::new();
    for range in &plan.target_owned_ranges {
        shadow.seek(SeekFrom::Start(range.offset))?;
        let mut left = range.length;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            shadow.read_exact(&mut buffer[..count])?;
            output.write_all(&buffer[..count])?;
            digest.update(&buffer[..count]);
            left -= count as u64;
        }
    }
    Ok(PackReceipt {
        partition_bytes: plan.partition_bytes,
        packed_bytes: plan.target_owned_bytes,
        ranges: plan.target_owned_ranges.len(),
        sha256: hex::encode(digest.finalize()),
        buffer_bytes: buffer.len(),
        executable: false,
    })
}

impl<'a, R: Read + Seek> PackedShadow<'a, R> {
    /// Length/geometry validation only. Authenticating bytes and the plan is
    /// the caller's responsibility; neither JSON nor this view grants writes.
    pub fn new(backing: &'a mut R, plan: &'a WriteSetPlan) -> Result<Self> {
        let starts = layout(plan)?;
        ensure!(
            backing.seek(SeekFrom::End(0))? == plan.target_owned_bytes,
            "compact backing length differs from candidate"
        );
        Ok(Self {
            backing,
            ranges: &plan.target_owned_ranges,
            starts,
            length: plan.partition_bytes,
            position: 0,
        })
    }
}

impl<R: Read + Seek> Read for PackedShadow<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position == self.length {
            return Ok(0);
        }
        let index = self
            .ranges
            .partition_point(|r| r.offset + r.length <= self.position);
        let range = self
            .ranges
            .get(index)
            .filter(|r| self.position >= r.offset)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unselected bytes must be read from the original source",
                )
            })?;
        let within = self.position - range.offset;
        let count = (range.length - within).min(buffer.len() as u64) as usize;
        self.backing
            .seek(SeekFrom::Start(self.starts[index] + within))?;
        let read = self.backing.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "compact backing ended inside a selected range",
            ));
        }
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for PackedShadow<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.length) + i128::from(v),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packed seek leaves partition",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
