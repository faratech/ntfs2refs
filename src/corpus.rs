//! Streaming raw-image comparison for controlled native-format experiments.
use crate::block_io::{self, SourceIdentity};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{io::Read, path::Path};

#[derive(Debug, Serialize)]
pub struct ChangedRange {
    pub offset: u64,
    pub length: u64,
}
#[derive(Debug, Serialize)]
pub struct ImageDiff {
    pub schema_version: u32,
    pub before: SourceIdentity,
    pub after: SourceIdentity,
    pub block_size: usize,
    pub changed_blocks: u64,
    pub changed_bytes: u64,
    pub ranges: Vec<ChangedRange>,
    pub ranges_truncated: bool,
}
pub fn diff(before: &Path, after: &Path, block_size: usize) -> Result<ImageDiff> {
    ensure!(
        (512..=1024 * 1024).contains(&block_size) && block_size.is_power_of_two(),
        "block size must be a power of two from 512 to 1048576"
    );
    let mut a = block_io::open_image(before)?;
    let mut b = block_io::open_image(after)?;
    let before_id = block_io::identity(&mut a, before)?;
    let after_id = block_io::identity(&mut b, after)?;
    ensure!(
        before_id.length == after_id.length,
        "corpus images must have equal length"
    );
    let mut result = ImageDiff {
        schema_version: 1,
        before: before_id,
        after: after_id,
        block_size,
        changed_blocks: 0,
        changed_bytes: 0,
        ranges: Vec::new(),
        ranges_truncated: false,
    };
    let mut left = vec![0; block_size];
    let mut right = vec![0; block_size];
    let mut offset = 0;
    while offset < result.before.length {
        let n = (result.before.length - offset).min(block_size as u64) as usize;
        a.read_exact(&mut left[..n])?;
        b.read_exact(&mut right[..n])?;
        let changed = left[..n]
            .iter()
            .zip(&right[..n])
            .filter(|(x, y)| x != y)
            .count() as u64;
        if changed != 0 {
            result.changed_bytes += changed;
            result.changed_blocks += 1;
            if let Some(last) = result
                .ranges
                .last_mut()
                .filter(|r| r.offset + r.length == offset)
            {
                last.length += n as u64;
            } else if result.ranges.len() < 4096 {
                result.ranges.push(ChangedRange {
                    offset,
                    length: n as u64,
                });
            } else {
                result.ranges_truncated = true;
            }
        }
        offset += n as u64;
    }
    ensure!(
        block_io::identity(&mut a, before)?.sha256 == result.before.sha256
            && block_io::identity(&mut b, after)?.sha256 == result.after.sha256,
        "images changed during comparison"
    );
    Ok(result)
}
