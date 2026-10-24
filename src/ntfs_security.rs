//! Raw NTFS security data, index and relative-descriptor reconciliation.
//! No access check, native security attestation or write authority is implied.
use crate::{
    ntfs_index::{self, Input, Profile},
    ntfs_inspect::FileInventory,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DESCRIPTOR_BYTES: usize = 0x40000 - 20;
pub const MAX_TOTAL_DESCRIPTOR_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DESCRIPTORS: usize = 16_384;
pub const MAX_TOTAL_ACES: usize = 65_536;
const HALF: usize = 0x40000;
const PAIR: usize = 0x80000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    ConsistentRawModel,
    Rejected,
    IncompleteAttributeInventory,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reconciliation {
    pub status: Status,
    pub metadata_bytes_read: usize,
    pub central_descriptors: usize,
    pub legacy_descriptors: usize,
    pub sii_entries: usize,
    pub sdh_entries: usize,
    pub index_blocks: usize,
    pub bound_files: usize,
    pub evidence_sha256: String,
    pub detail: String,
    pub descriptors: Vec<DescriptorRecord>,
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub record_number: u64,
    pub sequence_number: u16,
    pub security_id: Option<u32>,
    pub descriptor_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DescriptorRecord {
    pub security_id: Option<u32>,
    pub legacy_record: Option<u64>,
    pub sds_offset: Option<u64>,
    pub ntfs_hash: Option<u32>,
    pub descriptor: Descriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub sha256: String,
    pub relative_hex: String,
    pub control: u16,
    pub rm_control: u8,
    pub minimum_length: usize,
    pub owner_sid: Option<String>,
    pub group_sid: Option<String>,
    pub dacl: Acl,
    pub sacl: Acl,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclState {
    Absent,
    Null,
    Present,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acl {
    pub state: AclState,
    pub offset: usize,
    pub length: usize,
    pub revision: Option<u8>,
    pub aces: Vec<Ace>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub offset: usize,
    pub length: usize,
    pub mask: u32,
    pub trustee_sid: String,
    pub object_flags: Option<u32>,
    pub object_type: Option<String>,
    pub inherited_object_type: Option<String>,
    pub application_data_offset: Option<usize>,
    pub application_data_length: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub hash: u32,
    pub id: u32,
    pub offset: u64,
    pub length: u32,
}
#[derive(Clone, Copy)]
pub enum IndexKind {
    Id,
    Hash,
}
pub struct SecurityIndex {
    pub entries: Vec<Header>,
    pub index_blocks: usize,
}
pub struct Table {
    pub records: Vec<DescriptorRecord>,
    pub index_blocks: usize,
}

fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .context("truncated security u16")?
            .try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated security u32")?
            .try_into()?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated security u64")?
            .try_into()?,
    ))
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn ntfs_hash(bytes: &[u8]) -> Result<u32> {
    ensure!(
        bytes.len().is_multiple_of(4),
        "unaligned NTFS security hash input"
    );
    Ok(bytes.as_chunks::<4>().0.iter().fold(0u32, |h, w| {
        h.rotate_left(3).wrapping_add(u32::from_le_bytes(*w))
    }))
}
fn header(bytes: &[u8]) -> Result<Header> {
    ensure!(bytes.len() == 20, "exact 20-byte security header required");
    let h = Header {
        hash: u32le(bytes, 0)?,
        id: u32le(bytes, 4)?,
        offset: u64le(bytes, 8)?,
        length: u32le(bytes, 16)?,
    };
    ensure!(
        h.id >= 256 && h.offset.is_multiple_of(16) && h.length >= 40 && h.length <= HALF as u32,
        "invalid security header identity/offset/length"
    );
    Ok(h)
}
pub fn parse_index(input: Input<'_>, kind: IndexKind) -> Result<SecurityIndex> {
    let profile = match kind {
        IndexKind::Id => Profile::SECURITY_ID,
        IndexKind::Hash => Profile::SECURITY_HASH,
    };
    let index = ntfs_index::parse(input, profile, |_entry, key, value| {
        let h = header(value)?;
        match kind {
            IndexKind::Id => ensure!(
                key.len() == 4 && u32le(key, 0)? == h.id,
                "SII key/value identity mismatch"
            ),
            IndexKind::Hash => ensure!(
                key.len() == 8 && u32le(key, 0)? == h.hash && u32le(key, 4)? == h.id,
                "SDH key/value mismatch"
            ),
        }
        Ok(h)
    })?;
    for pair in index.entries.windows(2) {
        let ordered = match kind {
            IndexKind::Id => pair[0].id < pair[1].id,
            IndexKind::Hash => (pair[0].hash, pair[0].id) < (pair[1].hash, pair[1].id),
        };
        ensure!(ordered, "security index keys unordered or duplicated");
    }
    Ok(SecurityIndex {
        entries: index.entries,
        index_blocks: index.index_blocks,
    })
}

fn sid(bytes: &[u8], offset: usize) -> Result<(String, usize)> {
    let prefix = bytes
        .get(offset..offset + 8)
        .context("truncated SID header")?;
    ensure!(
        prefix[0] == 1 && prefix[1] <= 15,
        "unsupported SID revision/subauthority count"
    );
    let length = 8 + 4 * usize::from(prefix[1]);
    let data = bytes
        .get(offset..offset + length)
        .context("SID exceeds descriptor/ACE")?;
    let authority = prefix[2..8]
        .iter()
        .fold(0u64, |a, v| (a << 8) | u64::from(*v));
    let mut text = if authority <= u64::from(u32::MAX) {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012x}")
    };
    for w in data[8..].as_chunks::<4>().0 {
        text.push_str(&format!("-{}", u32::from_le_bytes(*w)));
    }
    Ok((text, length))
}
fn guid(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() == 16, "GUID length differs");
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32le(bytes, 0)?,
        u16le(bytes, 4)?,
        u16le(bytes, 6)?,
        bytes[8],
        bytes[9],
        hex::encode(&bytes[10..])
    ))
}
fn acl(bytes: &[u8], offset: usize, present: bool) -> Result<Acl> {
    if !present {
        ensure!(offset == 0, "absent ACL has a nonzero offset");
        return Ok(Acl {
            state: AclState::Absent,
            offset: 0,
            length: 0,
            revision: None,
            aces: Vec::new(),
        });
    }
    if offset == 0 {
        return Ok(Acl {
            state: AclState::Null,
            offset: 0,
            length: 0,
            revision: None,
            aces: Vec::new(),
        });
    }
    ensure!(
        offset >= 20 && offset.is_multiple_of(4),
        "invalid ACL relative offset"
    );
    let revision = *bytes.get(offset).context("ACL header outside descriptor")?;
    ensure!(
        [2, 4].contains(&revision)
            && bytes.get(offset + 1) == Some(&0)
            && u16le(bytes, offset + 6)? == 0,
        "invalid ACL revision/reserved fields"
    );
    let length = usize::from(u16le(bytes, offset + 2)?);
    let count = usize::from(u16le(bytes, offset + 4)?);
    ensure!(
        length >= 8 && length.is_multiple_of(4) && count <= 8192,
        "invalid ACL size/ACE count"
    );
    let data = bytes
        .get(offset..offset + length)
        .context("ACL exceeds descriptor")?;
    let mut at = 8;
    let mut aces = Vec::new();
    for _ in 0..count {
        let prefix = data.get(at..at + 8).context("short ACE header/mask")?;
        let n = usize::from(u16le(prefix, 2)?);
        ensure!(n >= 16 && n.is_multiple_of(4), "invalid ACE length");
        let entry = data.get(at..at + n).context("ACE exceeds ACL")?;
        let ty = entry[0];
        let object = matches!(ty, 5..=8 | 11 | 12 | 15 | 16);
        let application = matches!(ty, 9..=16 | 18 | 21);
        ensure!(matches!(ty,0..=3|5..=21), "unsupported ACE type {ty}");
        let mut sid_at = 8;
        let mut object_flags = None;
        let mut object_type = None;
        let mut inherited_object_type = None;
        if object {
            ensure!(revision == 4, "object ACE requires ACL revision 4");
            let flags = u32le(entry, 8)?;
            ensure!(flags & !3 == 0, "unknown object ACE flags");
            object_flags = Some(flags);
            sid_at = 12;
            if flags & 1 != 0 {
                object_type = Some(guid(
                    entry
                        .get(sid_at..sid_at + 16)
                        .context("truncated object GUID")?,
                )?);
                sid_at += 16;
            }
            if flags & 2 != 0 {
                inherited_object_type = Some(guid(
                    entry
                        .get(sid_at..sid_at + 16)
                        .context("truncated inherited GUID")?,
                )?);
                sid_at += 16;
            }
        }
        let (trustee_sid, sid_length) = sid(entry, sid_at)?;
        let end = sid_at + sid_length;
        ensure!(
            application || end == entry.len(),
            "ordinary ACE has trailing data"
        );
        let application_data_length = entry.len() - end;
        aces.push(Ace {
            ace_type: ty,
            flags: entry[1],
            offset: offset + at,
            length: n,
            mask: u32le(entry, 4)?,
            trustee_sid,
            object_flags,
            object_type,
            inherited_object_type,
            application_data_offset: if application_data_length > 0 {
                Some(offset + at + end)
            } else {
                None
            },
            application_data_length,
        });
        at += n;
    }
    Ok(Acl {
        state: AclState::Present,
        offset,
        length,
        revision: Some(revision),
        aces,
    })
}

/// Preserves all relative bytes and ordered ACEs. Conditional/resource ACE
/// application data is retained by offset, not evaluated or normalized.
pub fn parse_descriptor(bytes: &[u8]) -> Result<Descriptor> {
    ensure!(
        bytes.len() >= 20 && bytes.len() <= MAX_DESCRIPTOR_BYTES && bytes.len().is_multiple_of(4),
        "security descriptor size bound differs"
    );
    ensure!(bytes[0] == 1, "unsupported security descriptor revision");
    let control = u16le(bytes, 2)?;
    ensure!(
        control & 0x8000 != 0 && (control & 0x4000 != 0 || bytes[1] == 0),
        "descriptor is not valid relative form/RM control"
    );
    let mut minimum_length = 20;
    let mut read_sid = |at: usize| -> Result<Option<String>> {
        let offset = u32le(bytes, at)? as usize;
        if offset == 0 {
            return Ok(None);
        }
        ensure!(
            offset >= 20 && offset.is_multiple_of(4),
            "invalid SID relative offset"
        );
        let (text, n) = sid(bytes, offset)?;
        minimum_length = minimum_length.max(offset + n);
        Ok(Some(text))
    };
    let owner_sid = read_sid(4)?;
    let group_sid = read_sid(8)?;
    let sacl = acl(bytes, u32le(bytes, 12)? as usize, control & 0x10 != 0)?;
    let dacl = acl(bytes, u32le(bytes, 16)? as usize, control & 4 != 0)?;
    minimum_length = minimum_length
        .max(sacl.offset + sacl.length)
        .max(dacl.offset + dacl.length);
    Ok(Descriptor {
        sha256: hash(bytes),
        relative_hex: hex::encode(bytes),
        control,
        rm_control: bytes[1],
        minimum_length,
        owner_sid,
        group_sid,
        dacl,
        sacl,
    })
}

fn sds_records(bytes: &[u8]) -> Result<BTreeMap<u32, (Header, &[u8])>> {
    ensure!(bytes.len() <= MAX_METADATA_BYTES, "SDS read limit exceeded");
    let mut records = BTreeMap::new();
    let mut descriptor_bytes = 0usize;
    for base in (0..bytes.len()).step_by(PAIR) {
        let end = (base + HALF).min(bytes.len());
        let mut at = base;
        while at + 20 <= end {
            if bytes[at..at + 20].iter().all(|v| *v == 0) {
                break;
            }
            let h = header(&bytes[at..at + 20])?;
            let n = h.length as usize;
            ensure!(
                h.offset == at as u64 && n <= end - at,
                "SDS header position/record boundary differs"
            );
            let duplicate = at + HALF;
            ensure!(duplicate + n <= bytes.len(), "missing SDS mirror record");
            ensure!(
                bytes[at..at + n] == bytes[duplicate..duplicate + n],
                "SDS primary/mirror mismatch"
            );
            let data = &bytes[at + 20..at + n];
            ensure!(ntfs_hash(data)? == h.hash, "SDS descriptor hash mismatch");
            descriptor_bytes += data.len();
            ensure!(
                descriptor_bytes <= MAX_TOTAL_DESCRIPTOR_BYTES && records.len() < MAX_DESCRIPTORS,
                "security descriptor count/byte budget exceeded"
            );
            ensure!(
                records.insert(h.id, (h, data)).is_none(),
                "duplicate primary SDS security ID"
            );
            at = (at + n + 15) & !15;
        }
        ensure!(
            bytes[at.min(end)..end].iter().all(|v| *v == 0),
            "unparsed nonzero SDS primary tail"
        );
        let backup_tail = (at + HALF).min(bytes.len());
        let backup_end = (base + PAIR).min(bytes.len());
        ensure!(
            bytes[backup_tail.min(backup_end)..backup_end]
                .iter()
                .all(|v| *v == 0),
            "unparsed nonzero SDS mirror tail"
        );
    }
    Ok(records)
}

pub fn reconcile_table(sds: &[u8], sii: &SecurityIndex, sdh: &SecurityIndex) -> Result<Table> {
    let records = sds_records(sds)?;
    ensure!(
        sii.entries.len() == records.len() && sdh.entries.len() == records.len(),
        "SDS/SII/SDH descriptor counts differ"
    );
    for index in [sii, sdh] {
        let mut ids = BTreeSet::new();
        for h in &index.entries {
            ensure!(ids.insert(h.id), "security index repeats a descriptor ID");
            ensure!(
                records.get(&h.id).is_some_and(|r| r.0 == *h),
                "SDS/index security header mismatch"
            );
        }
    }
    let mut result = Vec::new();
    let mut aces = 0usize;
    for (id, (h, data)) in records {
        let descriptor = parse_descriptor(data)?;
        aces += descriptor.dacl.aces.len() + descriptor.sacl.aces.len();
        ensure!(aces <= MAX_TOTAL_ACES, "aggregate ACE limit exceeded");
        result.push(DescriptorRecord {
            security_id: Some(id),
            legacy_record: None,
            sds_offset: Some(h.offset),
            ntfs_hash: Some(h.hash),
            descriptor,
        });
    }
    Ok(Table {
        records: result,
        index_blocks: sii.index_blocks + sdh.index_blocks,
    })
}

pub fn bind_files(files: &[FileInventory], records: &[DescriptorRecord]) -> Result<Vec<Binding>> {
    ensure!(
        files.len() <= MAX_DESCRIPTORS && records.len() <= MAX_DESCRIPTORS,
        "security binding count limit exceeded"
    );
    let mut central = BTreeMap::new();
    let mut legacy = BTreeMap::new();
    for r in records {
        match (r.security_id, r.legacy_record) {
            (Some(id), None) => ensure!(
                central.insert(id, r).is_none(),
                "duplicate central descriptor identity"
            ),
            (None, Some(record)) => ensure!(
                legacy.insert(record, r).is_none(),
                "duplicate legacy descriptor identity"
            ),
            _ => bail!("ambiguous descriptor source identity"),
        }
    }
    let mut bindings = Vec::new();
    let mut used_legacy = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for f in files {
        ensure!(
            f.base_file_reference == 0 && !f.attributes.iter().any(|a| a.type_code == 0x20),
            "unassembled security attributes"
        );
        ensure!(
            seen.insert(f.record_number) && f.sequence_number != 0,
            "invalid security binding file identity"
        );
        if (12..16).contains(&f.record_number)
            && f.names.is_empty()
            && f.attributes.is_empty()
            && !f.is_directory
            && f.hard_link_count == 0
        {
            continue;
        }
        let id = f
            .standard_information
            .as_ref()
            .and_then(|s| s.security_id)
            .filter(|id| *id != 0);
        let record = if let Some(id) = id {
            ensure!(
                !legacy.contains_key(&f.record_number)
                    && !f.attributes.iter().any(|a| a.type_code == 0x50),
                "file has both legacy and central security"
            );
            central
                .get(&id)
                .context("MFT security ID is absent from validated SDS/index table")?
        } else {
            used_legacy.insert(f.record_number);
            let source = legacy
                .get(&f.record_number)
                .context("allocated file lacks a resolvable security descriptor")?;
            let mut attributes = f.attributes.iter().filter(|a| a.type_code == 0x50);
            let a = attributes
                .next()
                .context("legacy descriptor lacks its source attribute")?;
            ensure!(
                attributes.next().is_none()
                    && a.name_utf16.is_empty()
                    && a.flags == 0
                    && a.lowest_vcn == 0
                    && a.initialized_size == a.logical_size
                    && a.logical_size as usize == source.descriptor.relative_hex.len() / 2,
                "legacy descriptor/source attribute mismatch"
            );
            if a.resident {
                ensure!(
                    a.resident_sha256.as_deref() == Some(source.descriptor.sha256.as_str()),
                    "legacy resident descriptor hash mismatch"
                );
            }
            source
        };
        bindings.push(Binding {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            security_id: id,
            descriptor_sha256: record.descriptor.sha256.clone(),
        });
    }
    ensure!(
        used_legacy.len() == legacy.len(),
        "legacy descriptor has no binding"
    );
    Ok(bindings)
}

/// Actual retained heap capacities for the inspector's shared report budget.
pub fn heap_bytes(report: &Reconciliation) -> usize {
    let mut n = report.evidence_sha256.capacity()
        + report.detail.capacity()
        + report.descriptors.capacity() * std::mem::size_of::<DescriptorRecord>()
        + report.bindings.capacity() * std::mem::size_of::<Binding>();
    for b in &report.bindings {
        n += b.descriptor_sha256.capacity();
    }
    for r in &report.descriptors {
        let d = &r.descriptor;
        n += d.sha256.capacity()
            + d.relative_hex.capacity()
            + d.owner_sid.as_ref().map_or(0, String::capacity)
            + d.group_sid.as_ref().map_or(0, String::capacity);
        for acl in [&d.dacl, &d.sacl] {
            n += acl.aces.capacity() * std::mem::size_of::<Ace>();
            for ace in &acl.aces {
                n += ace.trustee_sid.capacity()
                    + ace.object_type.as_ref().map_or(0, String::capacity)
                    + ace
                        .inherited_object_type
                        .as_ref()
                        .map_or(0, String::capacity);
            }
        }
    }
    n
}
