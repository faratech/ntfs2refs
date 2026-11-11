//! Narrow decoding of ReFS 3.14 extent records from authenticated leaf data.
//! The caller must find records through the actual node index, resolve virtual
//! addresses through the container table and check physical bounds/ownership.
//! This decoder performs no reads and grants no conversion authority.
use anyhow::{Result, ensure};
use serde::Serialize;

const MAX_RECORD_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExtentKind {
    AllocatedUnwritten,
    AllocatedWritten,
    SparseHole,
    ChecksummedWritten,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtentRecord {
    pub kind: ExtentKind,
    pub flags: u16,
    pub virtual_lcn: u64,
    pub file_vcn: u32,
    pub clusters: u32,
    pub checksums_crc32c: Vec<u32>,
    pub physical_mapping_verified: bool,
    pub allocation_ownership_verified: bool,
    pub raw_write_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtentIndexReference {
    pub virtual_lcn_slots: [u64; 4],
    pub crc64_nvme: u64,
    pub expected_child_level: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ExtentNodeRows {
    Leaf(Vec<ExtentRecord>),
    Index(Vec<ExtentIndexReference>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtentNode {
    pub level: u8,
    pub flags: u8,
    pub rows: ExtentNodeRows,
    pub child_pages_verified: bool,
    pub stream_complete: bool,
    pub raw_write_authority: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded field"))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded field"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

fn intersects(a: &std::ops::Range<usize>, b: &std::ops::Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Decode only records named by an embedded extent node's index. The caller
/// must authenticate the enclosing page and independently follow each child.
pub fn inspect_extent_node(bytes: &[u8], node_offset: usize) -> Result<ExtentNode> {
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "extent node exceeds bounded page"
    );
    let header_end = node_offset
        .checked_add(40)
        .ok_or_else(|| anyhow::anyhow!("extent node header overflow"))?;
    let header = bytes
        .get(node_offset..header_end)
        .ok_or_else(|| anyhow::anyhow!("extent node header is truncated"))?;
    let level = header[0x0c];
    let flags = header[0x0d];
    let count = usize::try_from(u32_at(header, 0x14))?;
    let start = usize::try_from(u32_at(header, 0x10))?;
    let end = usize::try_from(u32_at(header, 0x20))?;
    ensure!(
        u32_at(header, 0) == 40
            && (level != 0) == (flags & 1 != 0)
            && level <= 8
            && count <= 256
            && (level == 0 || count != 0)
            && start >= 40
            && end.checked_sub(start) == count.checked_mul(4),
        "extent node header, index or level is unsupported"
    );
    let index_start = node_offset
        .checked_add(start)
        .ok_or_else(|| anyhow::anyhow!("extent index overflow"))?;
    let index_end = node_offset
        .checked_add(end)
        .ok_or_else(|| anyhow::anyhow!("extent index overflow"))?;
    ensure!(
        index_end <= bytes.len(),
        "extent index escapes containing value"
    );
    let index_span = index_start..index_end;
    let mut spans = Vec::with_capacity(count);
    let mut extents = Vec::new();
    let mut children = Vec::new();
    for index in 0..count {
        let entry = index_start + 4 * index;
        let relative = usize::from(u16_at(bytes, entry));
        ensure!(
            relative >= 40 && relative.is_multiple_of(8),
            "extent row alignment differs"
        );
        let row_start = node_offset
            .checked_add(relative)
            .ok_or_else(|| anyhow::anyhow!("extent row offset overflow"))?;
        let minimum = if level == 0 { 24 } else { 16 };
        let minimum_end = row_start
            .checked_add(minimum)
            .ok_or_else(|| anyhow::anyhow!("extent row overflow"))?;
        let head = bytes
            .get(row_start..minimum_end)
            .ok_or_else(|| anyhow::anyhow!("extent row header is truncated"))?;
        let size = if level == 0 {
            usize::from(u16_at(head, 0x0a))
        } else {
            usize::try_from(u32_at(head, 0))?
        };
        ensure!(size >= minimum, "extent row is smaller than its header");
        let row_end = row_start
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("extent row size overflow"))?;
        let padded = size
            .checked_add(7)
            .ok_or_else(|| anyhow::anyhow!("extent row alignment overflow"))?
            & !7;
        let padded_end = row_start
            .checked_add(padded)
            .ok_or_else(|| anyhow::anyhow!("extent row bounds overflow"))?;
        ensure!(
            padded_end <= bytes.len(),
            "extent row exceeds containing value"
        );
        let span = row_start..padded_end;
        ensure!(
            !intersects(&span, &index_span) && !spans.iter().any(|prior| intersects(&span, prior)),
            "extent rows overlap each other or the index"
        );
        spans.push(span);
        let row = &bytes[row_start..row_end];
        if level == 0 {
            extents.push(decode_extent_record(row)?);
        } else {
            let value_start = usize::from(u16_at(row, 10));
            let value_end = value_start
                .checked_add(usize::from(u16_at(row, 12)))
                .ok_or_else(|| anyhow::anyhow!("extent child value overflow"))?;
            ensure!(
                u16_at(row, 4) == 16
                    && u16_at(row, 6) == 0
                    && u16_at(row, 8) == 0
                    && u16_at(row, 14) == 0
                    && value_start >= 16
                    && u16_at(row, 12) == 48
                    && value_end <= row.len(),
                "extent index row is not the supported child reference"
            );
            let value = &row[value_start..value_end];
            ensure!(
                value[0x20..0x28] == [0, 0, 2, 8, 8, 0, 0, 0],
                "extent child checksum descriptor differs"
            );
            let slots = std::array::from_fn(|i| u64_at(value, i * 8));
            for (i, &slot) in slots.iter().enumerate() {
                ensure!(
                    slot != 0 && slot & 0x4000 == 0 && !slots[..i].contains(&slot),
                    "extent child slots are invalid"
                );
            }
            children.push(ExtentIndexReference {
                virtual_lcn_slots: slots,
                crc64_nvme: u64_at(value, 0x28),
                expected_child_level: level - 1,
            });
        }
    }
    Ok(ExtentNode {
        level,
        flags,
        rows: if level == 0 {
            ExtentNodeRows::Leaf(extents)
        } else {
            ExtentNodeRows::Index(children)
        },
        child_pages_verified: false,
        stream_complete: false,
        raw_write_authority: false,
    })
}

/// Decode exactly one indexed extent record, excluding any alignment padding.
/// This does not establish that the enclosing node or stream is complete.
pub fn decode_extent_record(bytes: &[u8]) -> Result<ExtentRecord> {
    ensure!(
        (24..=MAX_RECORD_BYTES).contains(&bytes.len()),
        "extent record is outside the bounded profile"
    );
    let flags = u16_at(bytes, 8);
    let kind = match flags {
        0x0040 => ExtentKind::AllocatedUnwritten,
        0x0050 => ExtentKind::AllocatedWritten,
        0x0060 | 0x0064 => ExtentKind::SparseHole,
        0x00d0 => ExtentKind::ChecksummedWritten,
        _ => anyhow::bail!("unsupported extent flags"),
    };
    let clusters = u32_at(bytes, 0x14);
    let expected_size = if kind == ExtentKind::ChecksummedWritten {
        24usize.checked_add(
            usize::try_from(clusters)?
                .checked_mul(4)
                .ok_or_else(|| anyhow::anyhow!("extent checksum length overflow"))?,
        )
    } else {
        Some(24)
    };
    ensure!(
        clusters > 0
            && expected_size == Some(bytes.len())
            && usize::from(u16_at(bytes, 0x0a)) == bytes.len()
            && u32_at(bytes, 0x10) == 0
            && u64::from(u32_at(bytes, 0x0c)) + u64::from(clusters) <= (1u64 << 32),
        "extent size, count, padding or logical range differs"
    );
    let virtual_lcn = u64_at(bytes, 0);
    if kind != ExtentKind::SparseHole {
        ensure!(
            virtual_lcn != 0
                && virtual_lcn & 0x4000 == 0
                && virtual_lcn.checked_add(u64::from(clusters) - 1).is_some(),
            "allocated extent virtual address is invalid"
        );
    }
    let checksums_crc32c = bytes[24..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("checksum word")))
        .collect();
    Ok(ExtentRecord {
        kind,
        flags,
        virtual_lcn,
        file_vcn: u32_at(bytes, 0x0c),
        clusters,
        checksums_crc32c,
        physical_mapping_verified: false,
        allocation_ownership_verified: false,
        raw_write_authority: false,
    })
}
