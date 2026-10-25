//! Bounded observations of researched ReFS 3.14 / 4 KiB root-node types.
//! The caller supplies one assembled 16 KiB page. No address is followed and no
//! checksum, table completeness, key ordering or filesystem health is certified.
//! Format observations: https://xbpt.gitlab.io/forefst/structures/btree_node/
//! and https://xbpt.gitlab.io/forefst/structures/container_table/ .

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;

const PAGE_BYTES: usize = 16384;
const ROOT_OFFSET: usize = 0x50;
const ROOT_DESCRIPTOR_BYTES: usize = 0x28;
// Initial observed profile: retain the complete 40-byte node-header region.
const NODE_HEADER_BYTES: usize = 0x28;
const ROW_HEADER_BYTES: usize = 16;
const MAX_ROW_INDEX_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootNodeObservation {
    pub page_bytes: usize,
    pub page_sha256: String,
    pub page_header_bytes_hex: String,
    pub table_id_low: u64,
    pub root_descriptor_size: u16,
    /// Distinct from descriptor size: native allocator roots carry 0xe010 here.
    pub root_descriptor_auxiliary: u16,
    pub schema_id: u32,
    pub whole_table_row_count: u64,
    pub leaf_extent_count_observed: u64,
    /// Includes all descriptor fields and the uninterpreted extension to the node.
    pub root_region_bytes_hex: String,
    pub node_offset: usize,
    pub node_header_bytes_hex: String,
    pub node_level: u8,
    pub node_flags: u8,
    pub index_node: bool,
    pub row_index_start_relative: u32,
    pub row_index_end_relative: u32,
    pub node_row_count: u32,
    /// In row-index order; physical row order need not match this order.
    pub rows: Vec<NodeRowObservation>,
    pub children_traversed: bool,
    pub metadata_verified: bool,
    pub checksum_verified: bool,
    pub conversion_profile_qualified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRowObservation {
    pub index: usize,
    pub index_entry_offset: usize,
    pub relative_offset: u16,
    pub page_offset: usize,
    /// Uninterpreted: marker 0 does not establish rightmost-child semantics.
    pub marker: u16,
    pub size: u32,
    pub key_offset: u16,
    pub key_length: u16,
    pub reserved_at_8: u16,
    pub value_offset: u16,
    pub value_length: u16,
    pub reserved_at_14: u16,
    /// Legal for observed container/allocator rows whose key prefixes the value.
    pub key_value_overlap: bool,
    /// Entire bounded row, including its header, key, value and internal padding.
    pub row_bytes_hex: String,
    pub row_sha256: String,
    pub key_sha256: String,
    pub value_sha256: String,
}

/// Structure of one page's node, without inventing a table-wide row count for
/// non-root pages. Its rows are observations, not validated child semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBodyObservation {
    pub node_offset: usize,
    pub node_prefix_bytes_hex: String,
    pub node_header_bytes_hex: String,
    pub node_level: u8,
    pub node_flags: u8,
    pub index_node: bool,
    pub row_index_start_relative: u32,
    pub row_index_end_relative: u32,
    pub node_row_count: u32,
    pub rows: Vec<NodeRowObservation>,
}

fn u16le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("bounded field"))
}
fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded field"))
}
fn u64le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("bounded field"))
}
fn range(offset: usize, size: usize, bound: usize) -> Result<Range<usize>> {
    let end = offset.checked_add(size).context("node range overflow")?;
    ensure!(end <= bound, "node range exceeds bounded page or row");
    Ok(offset..end)
}
fn overlaps(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < left.end
        && right.start < right.end
        && left.start < right.end
        && right.start < left.end
}
fn row_field(offset: u16, size: u16, row_size: usize) -> Result<Range<usize>> {
    ensure!(
        size == 0 || usize::from(offset) >= ROW_HEADER_BYTES,
        "nonempty key/value overlaps row header"
    );
    range(usize::from(offset), usize::from(size), row_size)
}

/// Observe a single root page of container tables 11/12 or allocator tables
/// 33/34. Allocator rows remain uninterpreted here.
/// Refuses unsupported profiles or malformed structure without returning partial
/// rows. At most 1024 index bytes (256 rows) are accepted. Row spans are disjoint,
/// so retained row hex is bounded by twice the 16 KiB input length.
pub fn inspect_root_node(bytes: &[u8]) -> Result<RootNodeObservation> {
    ensure!(
        bytes.len() == PAGE_BYTES,
        "root node requires exactly 16 KiB"
    );
    ensure!(&bytes[..4] == b"MSB+", "root node requires MSB+ signature");
    ensure!(u32le(bytes, 4) == 2, "unsupported root page header version");
    ensure!(u64le(bytes, 0x40) == 0, "unsupported table ID high half");
    let table_id_low = u64le(bytes, 0x48);
    let expected_schema = match table_id_low {
        11 | 12 => 0xe0c0,
        33 | 34 => 0xe010,
        _ => anyhow::bail!("root table is outside the bounded observed types"),
    };
    let descriptor_size = u16le(bytes, ROOT_OFFSET + 4);
    ensure!(
        usize::from(descriptor_size) == ROOT_DESCRIPTOR_BYTES,
        "unsupported root descriptor size"
    );
    let schema_id = u32le(bytes, ROOT_OFFSET + 0xc);
    ensure!(
        schema_id == expected_schema,
        "table/schema identity mismatch"
    );
    let node_offset = ROOT_OFFSET
        .checked_add(u32le(bytes, ROOT_OFFSET) as usize)
        .context("node header offset overflow")?;
    ensure!(
        node_offset >= ROOT_OFFSET + ROOT_DESCRIPTOR_BYTES,
        "node header overlaps page/root descriptor"
    );
    let node = inspect_node_body(bytes, node_offset)?;
    Ok(RootNodeObservation {
        page_bytes: bytes.len(),
        page_sha256: hex::encode(Sha256::digest(bytes)),
        page_header_bytes_hex: hex::encode(&bytes[..ROOT_OFFSET]),
        table_id_low,
        root_descriptor_size: descriptor_size,
        root_descriptor_auxiliary: u16le(bytes, ROOT_OFFSET + 6),
        schema_id,
        whole_table_row_count: u64le(bytes, ROOT_OFFSET + 0x20),
        leaf_extent_count_observed: u64le(bytes, ROOT_OFFSET + 0x18),
        root_region_bytes_hex: node.node_prefix_bytes_hex,
        node_offset: node.node_offset,
        node_header_bytes_hex: node.node_header_bytes_hex,
        node_level: node.node_level,
        node_flags: node.node_flags,
        index_node: node.index_node,
        row_index_start_relative: node.row_index_start_relative,
        row_index_end_relative: node.row_index_end_relative,
        node_row_count: node.node_row_count,
        rows: node.rows,
        children_traversed: false,
        metadata_verified: false,
        checksum_verified: false,
        conversion_profile_qualified: false,
    })
}

/// Initial native container-child profile: an eight-byte prefix at 0x50, then
/// the node header at 0x58. The caller must independently validate CRC, page
/// self-locations, volume signature and the expected table ID before traversal.
pub fn inspect_child_node(bytes: &[u8]) -> Result<NodeBodyObservation> {
    ensure!(
        bytes.len() == PAGE_BYTES,
        "container child requires exactly 16 KiB"
    );
    ensure!(
        &bytes[..4] == b"MSB+" && u32le(bytes, 4) == 2,
        "unsupported metadata child header"
    );
    ensure!(
        u64le(bytes, 0x40) == 0 && matches!(u64le(bytes, 0x48), 11 | 12 | 33 | 34),
        "unsupported metadata child table"
    );
    ensure!(
        u32le(bytes, ROOT_OFFSET) == 8,
        "unsupported non-root node prefix"
    );
    inspect_node_body(bytes, ROOT_OFFSET + 8)
}

pub fn inspect_container_child_node(bytes: &[u8]) -> Result<NodeBodyObservation> {
    inspect_child_node(bytes)
}

fn inspect_node_body(bytes: &[u8], node_offset: usize) -> Result<NodeBodyObservation> {
    let node_header_range = range(node_offset, NODE_HEADER_BYTES, bytes.len())?;
    let header = &bytes[node_header_range.clone()];
    let level = header[0xc];
    let flags = header[0xd];
    ensure!(
        (level != 0) == (flags & 1 != 0),
        "node level and index flag disagree"
    );
    let index_start = u32le(header, 0x10);
    let row_count = u32le(header, 0x14);
    let index_end = u32le(header, 0x20);
    let index_length = index_end
        .checked_sub(index_start)
        .context("reversed row-index bounds")?;
    ensure!(
        index_length as usize <= MAX_ROW_INDEX_BYTES
            && row_count.checked_mul(4) == Some(index_length),
        "row-index length/count mismatch or bounded row limit exceeded"
    );
    ensure!(
        index_start as usize >= NODE_HEADER_BYTES,
        "row index overlaps node header"
    );
    let index_page_start = node_offset
        .checked_add(index_start as usize)
        .context("row-index page offset overflow")?;
    let index_range = range(index_page_start, index_length as usize, bytes.len())?;
    let mut rows = Vec::with_capacity(row_count as usize);
    let mut spans: Vec<Range<usize>> = Vec::with_capacity(row_count as usize);
    for index in 0..row_count as usize {
        let entry = index_range.start + index * 4;
        let relative_offset = u16le(bytes, entry);
        let row_offset = node_offset
            .checked_add(usize::from(relative_offset))
            .context("row offset overflow")?;
        ensure!(
            row_offset >= node_header_range.end,
            "row overlaps node header or root prefix"
        );
        let row_header = range(row_offset, ROW_HEADER_BYTES, bytes.len())?;
        let size = u32le(bytes, row_header.start);
        ensure!(
            size as usize >= ROW_HEADER_BYTES,
            "row smaller than its header"
        );
        let row_range = range(row_offset, size as usize, bytes.len())?;
        ensure!(
            !overlaps(&row_range, &index_range),
            "row overlaps row-index array"
        );
        ensure!(
            !spans.iter().any(|other| other.start == row_range.start),
            "duplicate row offset"
        );
        ensure!(
            !spans.iter().any(|other| overlaps(other, &row_range)),
            "row spans overlap"
        );
        let row = &bytes[row_range.clone()];
        let key_offset = u16le(row, 4);
        let key_length = u16le(row, 6);
        let value_offset = u16le(row, 10);
        let value_length = u16le(row, 12);
        let key = row_field(key_offset, key_length, row.len())?;
        let value = row_field(value_offset, value_length, row.len())?;
        rows.push(NodeRowObservation {
            index,
            index_entry_offset: entry,
            relative_offset,
            page_offset: row_offset,
            marker: u16le(bytes, entry + 2),
            size,
            key_offset,
            key_length,
            reserved_at_8: u16le(row, 8),
            value_offset,
            value_length,
            reserved_at_14: u16le(row, 14),
            key_value_overlap: overlaps(&key, &value),
            row_bytes_hex: hex::encode(row),
            row_sha256: hex::encode(Sha256::digest(row)),
            key_sha256: hex::encode(Sha256::digest(&row[key])),
            value_sha256: hex::encode(Sha256::digest(&row[value])),
        });
        spans.push(row_range);
    }
    Ok(NodeBodyObservation {
        node_offset,
        node_prefix_bytes_hex: hex::encode(&bytes[ROOT_OFFSET..node_offset]),
        node_header_bytes_hex: hex::encode(header),
        node_level: level,
        node_flags: flags,
        index_node: flags & 1 != 0,
        row_index_start_relative: index_start,
        row_index_end_relative: index_end,
        node_row_count: row_count,
        rows,
    })
}
