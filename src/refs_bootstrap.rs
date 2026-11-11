//! Bounded, read-only observations of the researched ReFS 3.14/4 KiB bootstrap.
//! No checkpoint is selected; only three physical bootstrap root types are read.
//! Bounded physical container-tree children and translated checkpoint roots may
//! be followed; virtual-root children are never followed. Algorithm
//! matches do not establish filesystem health, mount behavior, or authenticity.
//! Field observations: https://xbpt.gitlab.io/forefst/structures/{vbr,supb,chkp}/
//! and https://xbpt.gitlab.io/forefst/concepts/checksum_architecture/ .

use crate::refs_inspect::RefsGeometry;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
};

const CLUSTER_BYTES: usize = 4096;
const CHECKPOINT_BYTES: usize = 16384;
const REFERENCE_BYTES: usize = 48;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapProbe {
    pub profile: String,
    pub vbr_stored_checksum: u16,
    pub vbr_computed_checksum: u16,
    pub vbr_checksum_matches: bool,
    pub superblocks: Vec<AnchorProbe>,
    pub checkpoints: Vec<AnchorProbe>,
    #[serde(default)]
    pub physical_root_pages: Vec<PhysicalRootPage>,
    #[serde(default)]
    pub physical_root_references: Vec<PhysicalRootProbe>,
    #[serde(default)]
    pub physical_root_probe_skipped_reason: Option<String>,
    #[serde(default)]
    pub container_tables: Option<crate::refs_containers::ContainerTablesProbe>,
    #[serde(default)]
    pub virtual_roots: Option<Box<crate::refs_virtual_roots::VirtualRootsProbe>>,
    pub authoritative_checkpoint_selected: bool,
    pub metadata_verified: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProbe {
    pub kind: String,
    pub lcn: u64,
    pub byte_offset: u64,
    pub bytes_read: usize,
    pub sha256: String,
    pub referenced_by_superblock_lcns: Vec<u64>,
    pub header: Option<AnchorHeader>,
    pub self_checksum: Option<SelfChecksum>,
    pub superblock: Option<SuperblockFields>,
    pub checkpoint: Option<CheckpointFields>,
    pub rejection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorHeader {
    pub signature: String,
    pub version: u32,
    pub volume_signature: u32,
    pub virtual_clock: u64,
    pub tree_update_clock: u64,
    pub lcn_slots: [u64; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfChecksum {
    pub descriptor_offset: usize,
    pub descriptor_length: usize,
    pub algorithm: String,
    pub coverage_bytes: usize,
    pub stored: u32,
    pub computed: u32,
    pub matches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperblockFields {
    pub volume_guid_bytes_hex: String,
    pub generation: u64,
    pub checkpoint_lcns: [u64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointFields {
    pub version_echo: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub virtual_clock: u64,
    pub allocator_clock: u64,
    pub header_clock_matches: bool,
    pub flags: u32,
    pub indirect_root_list: bool,
    pub reference_size: u32,
    pub roots: Vec<RootReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootReference {
    pub index: usize,
    pub descriptor_offset: usize,
    pub lcn_slots: [u64; 4],
    pub flags: u16,
    pub checksum_type: u8,
    pub checksum_data_offset: u8,
    pub checksum_data_length: u32,
    pub stored_checksum_bytes_hex: String,
    pub descriptor_sha256: String,
    pub addressed_page_read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalRootPage {
    pub lcn_slots: [u64; 4],
    pub byte_offsets: [u64; 4],
    pub bytes_read: usize,
    pub sha256: String,
    pub crc64_nvme: String,
    pub signature_bytes_hex: String,
    pub header_version: u32,
    pub reserved_header: u32,
    pub volume_signature: u32,
    pub self_lcn_slots: [u64; 4],
    pub table_id_high: u64,
    pub table_id_low: u64,
    /// Bounded structural observation, independent of the reference CRC result.
    #[serde(default)]
    pub node: Option<crate::refs_node::RootNodeObservation>,
    #[serde(default)]
    pub node_rejection: Option<String>,
    pub children_traversed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalRootProbe {
    pub checkpoint_lcn: u64,
    pub root_index: usize,
    pub lcn_slots: [u64; 4],
    pub page_index: Option<usize>,
    pub stored_crc64_nvme: Option<String>,
    pub checksum_matches: Option<bool>,
    pub header_matches: Option<bool>,
    pub table_id_matches: Option<bool>,
    pub rejection: Option<String>,
}

fn u16le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked structure bounds"),
    )
}
fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked structure bounds"),
    )
}
fn u64le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked structure bounds"),
    )
}
fn slots(bytes: &[u8], offset: usize) -> [u64; 4] {
    [
        u64le(bytes, offset),
        u64le(bytes, offset + 8),
        u64le(bytes, offset + 16),
        u64le(bytes, offset + 24),
    ]
}

/// Recognition checksum skips bytes 0..2 and 0x16..0x17; it is not a CRC.
pub fn vbr_checksum(bytes: &[u8]) -> Result<u16> {
    ensure!(
        bytes.len() == 512,
        "VBR checksum requires exactly 512 bytes"
    );
    let mut checksum = 0_u16;
    for (offset, byte) in bytes.iter().enumerate().skip(3) {
        if !(0x16..0x18).contains(&offset) {
            checksum = checksum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
    }
    Ok(checksum)
}

/// Standard reflected CRC32-C, checked against its public check vector.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78_u32 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// Reflected CRC64/NVME with the observed ReFS collision-sentinel encoding.
pub fn crc64_nvme(bytes: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for byte in bytes {
        crc ^= u64::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x9a6c_9329_ac4b_c9b5_u64 & (0_u64.wrapping_sub(crc & 1)));
        }
    }
    encode_crc64_sentinel(!crc)
}

pub fn encode_crc64_sentinel(checksum: u64) -> u64 {
    if checksum == 0xabba_ffff_abba_fffe {
        0xabba_ffff_abba_ffff
    } else {
        checksum
    }
}

fn bounded_range(offset: usize, length: usize, bound: usize) -> Result<std::ops::Range<usize>> {
    let end = offset
        .checked_add(length)
        .context("structure offset overflow")?;
    ensure!(end <= bound, "structure exceeds bounded page");
    Ok(offset..end)
}

fn read_candidate<R: Read + Seek>(
    reader: &mut R,
    lcn: u64,
    bytes: usize,
    volume_bytes: u64,
) -> Result<Vec<u8>> {
    let offset = lcn
        .checked_mul(CLUSTER_BYTES as u64)
        .context("candidate offset overflow")?;
    let end = offset
        .checked_add(bytes as u64)
        .context("candidate range overflow")?;
    ensure!(
        end <= volume_bytes,
        "candidate page outside declared volume"
    );
    reader.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0_u8; bytes];
    reader
        .read_exact(&mut data)
        .context("read bounded bootstrap candidate")?;
    Ok(data)
}

fn header(bytes: &[u8], expected: &[u8; 4], lcn: u64) -> Result<AnchorHeader> {
    ensure!(bytes.len() >= 0x98, "anchor is shorter than bounded header");
    ensure!(
        &bytes[..4] == expected,
        "anchor signature is not {}",
        String::from_utf8_lossy(expected)
    );
    ensure!(u32le(bytes, 4) == 2, "unknown anchor header version");
    ensure!(
        u32le(bytes, 8) == 0,
        "anchor reserved header field is nonzero"
    );
    ensure!(
        u64le(bytes, 0x20) == lcn,
        "anchor self LCN disagrees with read location"
    );
    Ok(AnchorHeader {
        signature: String::from_utf8_lossy(expected).into_owned(),
        version: u32le(bytes, 4),
        volume_signature: u32le(bytes, 0x0c),
        virtual_clock: u64le(bytes, 0x10),
        tree_update_clock: u64le(bytes, 0x18),
        lcn_slots: slots(bytes, 0x20),
    })
}

fn self_checksum(bytes: &[u8], offset: usize, length: usize, lcn: u64) -> Result<SelfChecksum> {
    ensure!(
        bytes.len() >= CLUSTER_BYTES && offset >= 0x80 && length == REFERENCE_BYTES,
        "unsupported bootstrap self-descriptor layout"
    );
    let range = bounded_range(offset, length, CLUSTER_BYTES)?;
    let descriptor = &bytes[range.clone()];
    ensure!(
        u64le(descriptor, 0) == lcn,
        "self-descriptor LCN disagrees with anchor location"
    );
    ensure!(
        u16le(descriptor, 0x20) == 0
            && descriptor[0x22] == 1
            && descriptor[0x23] == 8
            && u32le(descriptor, 0x24) == 4,
        "self-descriptor is not the bounded CRC32-C profile"
    );
    let stored = u32le(descriptor, 0x28);
    let mut covered = bytes[..CLUSTER_BYTES].to_vec();
    covered[range].fill(0);
    let computed = crc32c(&covered);
    Ok(SelfChecksum {
        descriptor_offset: offset,
        descriptor_length: length,
        algorithm: "CRC32-C; descriptor zeroed".into(),
        coverage_bytes: CLUSTER_BYTES,
        stored,
        computed,
        matches: stored == computed,
    })
}

fn candidate(kind: &str, lcn: u64, bytes: &[u8], referrers: Vec<u64>) -> AnchorProbe {
    AnchorProbe {
        kind: kind.into(),
        lcn,
        byte_offset: lcn * CLUSTER_BYTES as u64,
        bytes_read: bytes.len(),
        sha256: hex::encode(Sha256::digest(bytes)),
        referenced_by_superblock_lcns: referrers,
        header: None,
        self_checksum: None,
        superblock: None,
        checkpoint: None,
        rejection: None,
    }
}

fn parse_superblock(probe: &mut AnchorProbe, bytes: &[u8], volume_bytes: u64) -> Result<()> {
    let parsed_header = header(bytes, b"SUPB", probe.lcn)?;
    let derived_signature = (0x50..0x60)
        .step_by(4)
        .map(|offset| u32le(bytes, offset))
        .fold(0, |a, b| a ^ b);
    ensure!(
        parsed_header.volume_signature == derived_signature,
        "SUPB volume signature differs from its GUID"
    );
    probe.header = Some(parsed_header);
    let descriptor_offset = u32le(bytes, 0x78) as usize;
    let descriptor_length = u32le(bytes, 0x7c) as usize;
    probe.self_checksum = Some(self_checksum(
        bytes,
        descriptor_offset,
        descriptor_length,
        probe.lcn,
    )?);
    ensure!(
        u32le(bytes, 0x74) == 2,
        "SUPB checkpoint count differs from bounded two-copy profile"
    );
    let offset = u32le(bytes, 0x70) as usize;
    ensure!(offset >= 0x80, "SUPB checkpoint list overlaps fixed fields");
    let range = bounded_range(offset, 16, bytes.len())?;
    ensure!(
        range.end <= descriptor_offset || range.start >= descriptor_offset + descriptor_length,
        "SUPB checkpoint list overlaps self descriptor"
    );
    let lcns = [u64le(bytes, offset), u64le(bytes, offset + 8)];
    ensure!(
        lcns[0] != lcns[1]
            && lcns.iter().all(|lcn| *lcn > 0
                && lcn
                    .checked_mul(CLUSTER_BYTES as u64)
                    .and_then(|start| start.checked_add(CHECKPOINT_BYTES as u64))
                    .is_some_and(|end| end <= volume_bytes)),
        "SUPB checkpoint locations are duplicate or out of bounds"
    );
    probe.superblock = Some(SuperblockFields {
        volume_guid_bytes_hex: hex::encode(&bytes[0x50..0x60]),
        generation: u64le(bytes, 0x68),
        checkpoint_lcns: lcns,
    });
    Ok(())
}

fn parse_checkpoint(
    probe: &mut AnchorProbe,
    bytes: &[u8],
    expected_signatures: &[u32],
) -> Result<()> {
    let parsed_header = header(bytes, b"CHKP", probe.lcn)?;
    ensure!(
        expected_signatures.contains(&parsed_header.volume_signature),
        "CHKP volume signature differs from referring SUPB"
    );
    let header_clock = parsed_header.virtual_clock;
    probe.header = Some(parsed_header);
    ensure!(
        u16le(bytes, 0x54) == 3 && u16le(bytes, 0x56) == 14,
        "CHKP version differs from researched 3.14 profile"
    );
    let descriptor_offset = u32le(bytes, 0x58) as usize;
    let descriptor_length = u32le(bytes, 0x5c) as usize;
    probe.self_checksum = Some(self_checksum(
        bytes,
        descriptor_offset,
        descriptor_length,
        probe.lcn,
    )?);
    ensure!(
        u32le(bytes, 0x90) == 13,
        "CHKP root count differs from bounded thirteen-root profile"
    );
    let flags = u32le(bytes, 0x78);
    let indirect = flags & 0x200 != 0;
    let list_offset = if indirect {
        u32le(bytes, 0x94) as usize
    } else {
        0x94
    };
    let fixed_end = if indirect { 0x98 } else { 0x94 };
    ensure!(
        list_offset >= fixed_end,
        "CHKP root list overlaps fixed fields"
    );
    let list_span = bounded_range(list_offset, 13 * 4, bytes.len())?;
    let self_span = bounded_range(descriptor_offset, descriptor_length, bytes.len())?;
    ensure!(
        self_span.start >= fixed_end
            && (self_span.end <= list_span.start || self_span.start >= list_span.end),
        "CHKP self descriptor overlaps fixed fields or root list"
    );
    let mut roots = Vec::with_capacity(13);
    let mut spans = vec![0..fixed_end, list_span, self_span];
    for index in 0..13 {
        let offset = u32le(bytes, list_offset + index * 4) as usize;
        ensure!(offset >= 0x98, "root descriptor overlaps fixed fields");
        let span = bounded_range(offset, REFERENCE_BYTES, bytes.len())?;
        ensure!(
            spans
                .iter()
                .all(|other| span.end <= other.start || span.start >= other.end),
            "root descriptors overlap"
        );
        let descriptor = &bytes[span.clone()];
        roots.push(RootReference {
            index,
            descriptor_offset: offset,
            lcn_slots: slots(descriptor, 0),
            flags: u16le(descriptor, 0x20),
            checksum_type: descriptor[0x22],
            checksum_data_offset: descriptor[0x23],
            checksum_data_length: u32le(descriptor, 0x24),
            stored_checksum_bytes_hex: hex::encode(&descriptor[0x28..]),
            descriptor_sha256: hex::encode(Sha256::digest(descriptor)),
            addressed_page_read: false,
        });
        spans.push(span);
    }
    probe.checkpoint = Some(CheckpointFields {
        version_echo: u32le(bytes, 0x50),
        major_version: u16le(bytes, 0x54),
        minor_version: u16le(bytes, 0x56),
        virtual_clock: u64le(bytes, 0x60),
        allocator_clock: u64le(bytes, 0x68),
        header_clock_matches: header_clock == u64le(bytes, 0x60),
        flags,
        indirect_root_list: indirect,
        reference_size: descriptor_length as u32,
        roots,
    });
    Ok(())
}

fn inspect_physical_roots<R: Read + Seek>(
    reader: &mut R,
    report: &mut BootstrapProbe,
    volume_bytes: u64,
) -> Result<()> {
    // More than two distinct checkpoint addresses indicates divergent SUPB
    // candidates. Do not invent a winner to stay within the root-read budget.
    if report.checkpoints.len() > 2 {
        report.physical_root_probe_skipped_reason = Some(
            "More than two distinct checkpoint candidates; no authoritative pair selected.".into(),
        );
        return Ok(());
    }
    let mut requests = Vec::new();
    for (checkpoint_index, probe) in report.checkpoints.iter().enumerate() {
        if probe.rejection.is_none()
            && probe
                .self_checksum
                .as_ref()
                .is_some_and(|checksum| checksum.matches)
            && let (Some(fields), Some(header)) = (&probe.checkpoint, &probe.header)
            && fields.header_clock_matches
        {
            for index in [7, 8, 12] {
                requests.push((
                    checkpoint_index,
                    probe.lcn,
                    fields.roots[index].clone(),
                    header.volume_signature,
                ));
            }
        }
    }
    ensure!(
        requests.len() <= 6,
        "physical bootstrap root budget exceeded"
    );
    if requests.is_empty() {
        report.physical_root_probe_skipped_reason = Some("No checksum-consistent, structurally accepted checkpoint is available for root probes.".into());
        return Ok(());
    }
    let mut cache: BTreeMap<[u64; 4], usize> = BTreeMap::new();
    for (checkpoint_index, checkpoint_lcn, reference, volume_signature) in &requests {
        let mut probe = PhysicalRootProbe {
            checkpoint_lcn: *checkpoint_lcn,
            root_index: reference.index,
            lcn_slots: reference.lcn_slots,
            page_index: None,
            stored_crc64_nvme: None,
            checksum_matches: None,
            header_matches: None,
            table_id_matches: None,
            rejection: None,
        };
        let validated = (|| -> Result<u64> {
            ensure!(
                reference.flags == 0
                    && reference.checksum_type == 2
                    && reference.checksum_data_offset == 8
                    && reference.checksum_data_length == 8,
                "physical root reference is not the bounded CRC64/NVME profile"
            );
            let checksum = hex::decode(&reference.stored_checksum_bytes_hex)?;
            ensure!(
                checksum.len() == 8,
                "root checksum is not exactly eight bytes"
            );
            for (slot, lcn) in reference.lcn_slots.iter().enumerate() {
                ensure!(
                    *lcn > 0 && !reference.lcn_slots[..slot].contains(lcn),
                    "root page has empty or duplicate LCN slots"
                );
                let offset = lcn
                    .checked_mul(CLUSTER_BYTES as u64)
                    .context("root LCN byte-offset overflow")?;
                let end = offset
                    .checked_add(CLUSTER_BYTES as u64)
                    .context("root cluster end overflow")?;
                ensure!(
                    end <= volume_bytes,
                    "root cluster lies outside the declared volume"
                );
                ensure!(
                    report
                        .superblocks
                        .iter()
                        .chain(report.checkpoints.iter())
                        .all(|anchor| end <= anchor.byte_offset
                            || offset >= anchor.byte_offset + anchor.bytes_read as u64),
                    "root cluster overlaps an observed bootstrap anchor"
                );
                ensure!(
                    requests
                        .iter()
                        .all(|(_, _, other, _)| other.index == reference.index
                            || !other.lcn_slots.contains(lcn)),
                    "different physical bootstrap roots share a cluster"
                );
            }
            Ok(u64::from_le_bytes(
                checksum.try_into().expect("eight checksum bytes"),
            ))
        })();
        let stored = match validated {
            Ok(stored) => stored,
            Err(error) => {
                probe.rejection = Some(error.to_string());
                report.physical_root_references.push(probe);
                continue;
            }
        };
        probe.stored_crc64_nvme = Some(format!("{stored:016x}"));
        let page_index = if let Some(index) = cache.get(&reference.lcn_slots) {
            *index
        } else {
            let mut bytes = Vec::with_capacity(CHECKPOINT_BYTES);
            for lcn in reference.lcn_slots {
                bytes.extend(read_candidate(reader, lcn, CLUSTER_BYTES, volume_bytes)?);
            }
            ensure!(
                bytes.len() == CHECKPOINT_BYTES,
                "physical bootstrap page length differs from four clusters"
            );
            let (node, node_rejection) = match crate::refs_node::inspect_root_node(&bytes) {
                Ok(node) => (Some(node), None),
                Err(error) => (None, Some(error.to_string())),
            };
            let page = PhysicalRootPage {
                lcn_slots: reference.lcn_slots,
                byte_offsets: reference.lcn_slots.map(|lcn| lcn * CLUSTER_BYTES as u64),
                bytes_read: bytes.len(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                crc64_nvme: format!("{:016x}", crc64_nvme(&bytes)),
                signature_bytes_hex: hex::encode(&bytes[..4]),
                header_version: u32le(&bytes, 4),
                reserved_header: u32le(&bytes, 8),
                volume_signature: u32le(&bytes, 0xc),
                self_lcn_slots: slots(&bytes, 0x20),
                table_id_high: u64le(&bytes, 0x40),
                table_id_low: u64le(&bytes, 0x48),
                node,
                node_rejection,
                children_traversed: false,
            };
            let index = report.physical_root_pages.len();
            report.physical_root_pages.push(page);
            cache.insert(reference.lcn_slots, index);
            index
        };
        let page = &report.physical_root_pages[page_index];
        probe.page_index = Some(page_index);
        probe.checksum_matches = Some(page.crc64_nvme == format!("{stored:016x}"));
        probe.header_matches = Some(
            page.signature_bytes_hex == "4d53422b"
                && page.header_version == 2
                && page.reserved_header == 0
                && page.volume_signature == *volume_signature
                && page.self_lcn_slots == reference.lcn_slots,
        );
        probe.table_id_matches = Some(
            page.table_id_high == 0
                && if reference.index == 12 {
                    page.table_id_low == 0x22
                } else {
                    matches!(page.table_id_low, 0xb | 0xc)
                },
        );
        if probe.checksum_matches != Some(true)
            || probe.header_matches != Some(true)
            || probe.table_id_matches != Some(true)
        {
            probe.rejection = Some("Physical root bytes disagree with the reference checksum, header, or expected table identity.".into());
        }
        report.checkpoints[*checkpoint_index]
            .checkpoint
            .as_mut()
            .expect("validated parent")
            .roots[reference.index]
            .addressed_page_read = true;
        report.physical_root_references.push(probe);
    }
    // The container pair may be swapped, but two copies with the same table ID
    // do not satisfy the documented {0x0B,0x0C} pair.
    for checkpoint in &report.checkpoints {
        let pair: Vec<_> = report
            .physical_root_references
            .iter()
            .enumerate()
            .filter(|(_, root)| {
                root.checkpoint_lcn == checkpoint.lcn && matches!(root.root_index, 7 | 8)
            })
            .collect();
        if pair.len() == 2
            && let (Some(first), Some(second)) = (pair[0].1.page_index, pair[1].1.page_index)
            && report.physical_root_pages[first].table_id_low
                == report.physical_root_pages[second].table_id_low
        {
            let indices = [pair[0].0, pair[1].0];
            for index in indices {
                report.physical_root_references[index].table_id_matches = Some(false);
                report.physical_root_references[index].rejection = Some(
                    "Container bootstrap pair does not contain distinct table IDs 0x0B and 0x0C."
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// At most three 4 KiB SUPB and six 16 KiB CHKP candidates are read. With at
/// most two CHKP candidates, up to six physical-root references are examined
/// (deduplicated by four LCN slots). Eligible container trees add a bounded
/// physical walk of at most 128 16 KiB reads; no virtual address is followed.
/// Unsupported profiles return None. I/O errors propagate; malformed candidates
/// retain their exact range hash and rejection without following their pointers.
pub fn inspect<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    vbr: &[u8],
) -> Result<Option<BootstrapProbe>> {
    inspect_profile(reader, geometry, vbr, true, false)
}

/// Physical bootstrap only; container descendants and virtual roots remain
/// absent rather than being reported as inspected.
pub fn inspect_physical<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    vbr: &[u8],
) -> Result<Option<BootstrapProbe>> {
    inspect_profile(reader, geometry, vbr, false, false)
}

/// Experimental container lookup with compact live index storage.
pub fn inspect_compact<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    vbr: &[u8],
) -> Result<Option<BootstrapProbe>> {
    inspect_profile(reader, geometry, vbr, true, true)
}

fn inspect_profile<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    vbr: &[u8],
    include_virtual: bool,
    compact_containers: bool,
) -> Result<Option<BootstrapProbe>> {
    if geometry.major_version != 3
        || geometry.minor_version != 14
        || geometry.bytes_per_cluster != CLUSTER_BYTES as u32
    {
        return Ok(None);
    }
    let computed = vbr_checksum(vbr)?;
    let mut report = BootstrapProbe { profile: "candidate ReFS 3.14, 4 KiB cluster, 48-byte CRC descriptors".into(), vbr_stored_checksum: geometry.recognition_checksum, vbr_computed_checksum: computed, vbr_checksum_matches: geometry.recognition_checksum == computed, superblocks: Vec::new(), checkpoints: Vec::new(), physical_root_pages: Vec::new(), physical_root_references: Vec::new(), physical_root_probe_skipped_reason: None, container_tables: None, virtual_roots: None, authoritative_checkpoint_selected: false, metadata_verified: false, warnings: vec!["Research-derived candidate parser only; no mount, driver acceptance, current checkpoint, or filesystem health is established.".into(), "Physical bootstrap roots, bounded container-tree children and checksum-bound virtual checkpoint roots are probed; virtual descendants and allocation ownership remain unverified.".into()] };
    if !include_virtual {
        report.profile.push_str("; physical bootstrap only");
        report.warnings[1] = "Only anchors, checkpoints and physical root pages are probed; container descendants and virtual roots are not traversed.".into();
    }
    if compact_containers {
        report.profile.push_str("; compact container index v1");
        report.warnings[1] = "Container pages and values are digest-covered with compact live address indexes; diagnostics omit lookup data and are not replay authority.".into();
    }
    let clusters = geometry.volume_bytes / CLUSTER_BYTES as u64;
    if clusters < 34 || !geometry.volume_bytes.is_multiple_of(CLUSTER_BYTES as u64) {
        report
            .warnings
            .push("Volume is too small or not cluster-aligned for bounded anchor probes.".into());
        return Ok(Some(report));
    }
    if !report.vbr_checksum_matches {
        report
            .warnings
            .push("Recognition checksum mismatch; bootstrap locations are not followed.".into());
        return Ok(Some(report));
    }
    let mut checkpoint_references: BTreeMap<u64, (Vec<u64>, Vec<u32>)> = BTreeMap::new();
    for lcn in [30, clusters - 2, clusters - 3] {
        let bytes = read_candidate(reader, lcn, CLUSTER_BYTES, geometry.volume_bytes)?;
        let mut probe = candidate("SUPB", lcn, &bytes, Vec::new());
        if let Err(error) = parse_superblock(&mut probe, &bytes, geometry.volume_bytes) {
            probe.rejection = Some(error.to_string());
        }
        if probe.rejection.is_none()
            && probe
                .self_checksum
                .as_ref()
                .is_some_and(|checksum| checksum.matches)
            && let (Some(fields), Some(header)) = (&probe.superblock, &probe.header)
        {
            for lcn in fields.checkpoint_lcns {
                let entry = checkpoint_references.entry(lcn).or_default();
                entry.0.push(probe.lcn);
                entry.1.push(header.volume_signature);
            }
        }
        report.superblocks.push(probe);
    }
    for (lcn, (referrers, signatures)) in checkpoint_references {
        let bytes = read_candidate(reader, lcn, CHECKPOINT_BYTES, geometry.volume_bytes)?;
        let mut probe = candidate("CHKP", lcn, &bytes, referrers);
        if let Err(error) = parse_checkpoint(&mut probe, &bytes, &signatures) {
            probe.rejection = Some(error.to_string());
        }
        report.checkpoints.push(probe);
    }
    inspect_physical_roots(reader, &mut report, geometry.volume_bytes)?;
    let mut roots = Vec::new();
    let mut protected = std::collections::BTreeSet::new();
    for anchor in &report.superblocks {
        protected.insert(anchor.lcn);
    }
    for anchor in &report.checkpoints {
        for offset in 0..4 {
            protected.insert(anchor.lcn + offset);
        }
    }
    for page in &report.physical_root_pages {
        protected.extend(page.lcn_slots);
    }
    for reference in &report.physical_root_references {
        if !matches!(reference.root_index, 7 | 8)
            || reference.rejection.is_some()
            || reference.checksum_matches != Some(true)
            || reference.header_matches != Some(true)
            || reference.table_id_matches != Some(true)
        {
            continue;
        }
        if let Some(index) = reference.page_index {
            let page = &report.physical_root_pages[index];
            if page.node.is_none() || page.node_rejection.is_some() {
                continue;
            }
            roots.push(crate::refs_containers::ContainerRootTarget {
                checkpoint_lcn: reference.checkpoint_lcn,
                root_index: reference.root_index,
                table_id: page.table_id_low,
                volume_signature: page.volume_signature,
                lcn_slots: reference.lcn_slots,
                expected_crc64: u64::from_str_radix(
                    reference
                        .stored_crc64_nvme
                        .as_ref()
                        .context("missing accepted root checksum")?,
                    16,
                )?,
                expected_sha256: page.sha256.clone(),
            });
        }
    }
    if include_virtual && !roots.is_empty() {
        let containers = if compact_containers {
            crate::refs_containers::inspect_container_tables_compact(
                reader, geometry, &roots, &protected,
            )?
        } else {
            crate::refs_containers::inspect_container_tables(
                reader,
                geometry,
                &roots,
                &protected,
                crate::refs_containers::ContainerLimits::default(),
            )?
        };
        for page in &mut report.physical_root_pages {
            page.children_traversed = containers.trees.iter().any(|tree| {
                tree.root_lcn_slots == page.lcn_slots
                    && (tree.pages.iter().any(|child| child.depth != 0)
                        || tree
                            .compact
                            .as_ref()
                            .is_some_and(|index| index.pages_read > 1))
            });
        }
        let virtual_roots = crate::refs_virtual_roots::inspect_virtual_roots(
            reader,
            geometry,
            &report.checkpoints,
            &containers,
            &protected,
            crate::refs_virtual_roots::VirtualRootLimits::default(),
        )?;
        for checkpoint in &mut report.checkpoints {
            if let Some(fields) = &mut checkpoint.checkpoint {
                for reference in &mut fields.roots {
                    reference.addressed_page_read |= virtual_roots.roots.iter().any(|root| {
                        root.checkpoint_lcn == checkpoint.lcn
                            && root.root_index == reference.index
                            && root.bytes_read != 0
                    });
                }
            }
        }
        report.virtual_roots = Some(Box::new(virtual_roots));
        report.container_tables = Some(containers);
    }
    Ok(Some(report))
}
