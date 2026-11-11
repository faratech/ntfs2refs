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
    pub retained_source_bytes: u64,
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A partition-sized address space backed by a densely packed sequence of
/// selected ranges. Use behind CandidateHybrid, which supplies original bytes
/// for the complement. No allocation proportional to partition size occurs.
pub struct PackedShadow<'a, R> {
    backing: &'a mut R,
    ranges: Vec<ByteRange>,
    starts: Vec<u64>,
    original: Option<&'a mut dyn ReadSeek>,
    retained: Vec<ByteRange>,
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

/// Derive storage selection without changing the filesystem allocation plan.
/// Supplied retained ranges are only a diagnostic claim until independently
/// bound to file identity, source bytes and target metadata ownership.
fn storage_ranges(plan: &WriteSetPlan, retained: &[ByteRange]) -> Result<Vec<ByteRange>> {
    layout(plan)?;
    let coverage = crate::refs_write_set::payload_coverage(plan, retained)?;
    ensure!(
        coverage.all_supplied_payloads_covered,
        "retained range leaves target allocation"
    );
    let mut retained = retained.to_vec();
    retained.sort_by_key(|r| r.offset);
    let mut result = Vec::new();
    let mut index = 0;
    for owned in &plan.target_owned_ranges {
        let end = owned.offset + owned.length;
        let mut cursor = owned.offset;
        while index < retained.len() && retained[index].offset + retained[index].length <= cursor {
            index += 1;
        }
        for r in &retained[index..] {
            if r.offset >= end {
                break;
            }
            if r.offset > cursor {
                result.push(ByteRange {
                    offset: cursor,
                    length: r.offset - cursor,
                });
            }
            cursor = end.min(r.offset + r.length);
        }
        if cursor < end {
            result.push(ByteRange {
                offset: cursor,
                length: end - cursor,
            });
        }
    }
    ensure!(
        result.len() <= 131072,
        "compact storage range budget exceeded"
    );
    Ok(result)
}

pub fn required_bytes(plan: &WriteSetPlan, retained: &[ByteRange]) -> Result<u64> {
    Ok(storage_ranges(plan, retained)?
        .iter()
        .map(|r| r.length)
        .sum())
}

/// Stream selected shadow bytes into a fresh, caller-owned scratch sink. The
/// caller must flush it durably and bind this receipt to the exact plan before
/// reuse. Failure leaves an incomplete artifact, never a completion receipt.
pub fn pack<R: Read + Seek, W: Write>(
    shadow: &mut R,
    output: &mut W,
    plan: &WriteSetPlan,
) -> Result<PackReceipt> {
    pack_with_retained(shadow, output, plan, &[])
}

pub fn pack_with_retained<R: Read + Seek, W: Write>(
    shadow: &mut R,
    output: &mut W,
    plan: &WriteSetPlan,
    retained: &[ByteRange],
) -> Result<PackReceipt> {
    let selected = storage_ranges(plan, retained)?;
    let packed_bytes: u64 = selected.iter().map(|r| r.length).sum();
    ensure!(
        shadow.seek(SeekFrom::End(0))? == plan.partition_bytes,
        "shadow length differs from candidate"
    );
    let mut buffer = [0u8; 65536];
    let mut digest = Sha256::new();
    for range in &selected {
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
        packed_bytes,
        ranges: selected.len(),
        sha256: hex::encode(digest.finalize()),
        buffer_bytes: buffer.len(),
        executable: false,
        retained_source_bytes: plan.target_owned_bytes - packed_bytes,
    })
}

impl<'a, R: Read + Seek> PackedShadow<'a, R> {
    /// Length/geometry validation only. Authenticating bytes and the plan is
    /// the caller's responsibility; neither JSON nor this view grants writes.
    pub fn new(backing: &'a mut R, plan: &'a WriteSetPlan) -> Result<Self> {
        Self::open(backing, None, plan, &[])
    }

    pub fn with_retained<S: Read + Seek + 'a>(
        backing: &'a mut R,
        original: &'a mut S,
        plan: &WriteSetPlan,
        retained: &[ByteRange],
    ) -> Result<Self> {
        ensure!(
            original.seek(SeekFrom::End(0))? == plan.partition_bytes,
            "retained source length differs from candidate"
        );
        Self::open(backing, Some(original), plan, retained)
    }

    fn open(
        backing: &'a mut R,
        original: Option<&'a mut dyn ReadSeek>,
        plan: &WriteSetPlan,
        retained: &[ByteRange],
    ) -> Result<Self> {
        let ranges = storage_ranges(plan, retained)?;
        let mut starts = Vec::with_capacity(ranges.len());
        let mut bytes = 0;
        for range in &ranges {
            starts.push(bytes);
            bytes += range.length;
        }
        ensure!(
            backing.seek(SeekFrom::End(0))? == bytes,
            "compact backing length differs from candidate"
        );
        Ok(Self {
            backing,
            ranges,
            starts,
            original,
            retained: {
                let mut r = retained.to_vec();
                r.sort_by_key(|r| r.offset);
                r
            },
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
            .retained
            .partition_point(|r| r.offset + r.length <= self.position);
        if let Some(range) = self
            .retained
            .get(index)
            .filter(|r| self.position >= r.offset)
        {
            let count =
                (range.offset + range.length - self.position).min(buffer.len() as u64) as usize;
            let original = self.original.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "retained source absent")
            })?;
            original.seek(SeekFrom::Start(self.position))?;
            let read = original.read(&mut buffer[..count])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "retained source ended",
                ));
            }
            self.position += read as u64;
            return Ok(read);
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
