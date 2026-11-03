//! Narrow frozen-source checks for indexes that role recognition cannot
//! authorize dropping. User object IDs and nondefault quota state stay refused;
//! supported reparse entries must cross-match every actual point, while the
//! sole cross-bound $Volume identity has an explicit audit
//! and replacement disposition, and default quotas require a live witness.
use crate::{
    ntfs_admission,
    ntfs_index::{self, Input, Profile},
    ntfs_inspect::{self, NtfsInspection},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

#[cfg(windows)]
#[path = "ntfs_internal_paged.rs"]
mod paged;
#[cfg(windows)]
pub use paged::{PagedVerifiedIndexes, verify_domain};

#[derive(Debug, Serialize)]
pub struct IndexState {
    pub role: String,
    pub name: String,
    pub record_number: u64,
    pub root_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_allocation_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitmap_sha256: Option<String>,
    pub index_blocks: usize,
    pub entries: usize,
    pub entry_evidence: Vec<IndexEntry>,
    pub replacement_supported: bool,
    pub detail: String,
}
#[derive(Debug, Serialize)]
pub struct IndexEntry {
    pub key_hex: String,
    pub value_hex: String,
}
/// No deserializer: this evidence is constructed from source reads only.
#[derive(Debug, Serialize)]
pub struct VerifiedIndexes {
    inspection_sha256: String,
    internal_volume_object_id: Option<InternalVolumeObjectId>,
    pub indexes: Vec<IndexState>,
    pub default_quotas_only: bool,
    pub native_quota_policy_bound: bool,
    pub replacement_supported: bool,
}

/// Exact NTFS filesystem-internal identity recorded for replacement, not a
/// claim that ReFS preserves the same NTFS object-ID semantics. Created only
/// from a fresh resident-value read and its sole cross-matched index entry.
#[derive(Debug, Serialize)]
pub struct InternalVolumeObjectId {
    inspection_sha256: String,
    record_number: u64,
    sequence_number: u16,
    attribute_instance: u16,
    object_id_hex: String,
    object_id_sha256: String,
    object_index_record_number: u64,
    object_index_sequence_number: u16,
    object_index_name: &'static str,
    object_index_root_sha256: String,
    object_index_value_sha256: String,
    file_reference: u64,
    disposition: &'static str,
    same_refs_object_id_preserved: bool,
}
impl InternalVolumeObjectId {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    #[cfg(windows)]
    pub fn binds_domain(&self, source: &ntfs_inspect::PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|hash| hash == self.inspection_sha256)
    }
    pub fn record_number(&self) -> u64 {
        self.record_number
    }
    pub fn sequence_number(&self) -> u16 {
        self.sequence_number
    }
    pub fn object_id_hex(&self) -> &str {
        &self.object_id_hex
    }
    pub fn disposition(&self) -> &'static str {
        self.disposition
    }
}

impl VerifiedIndexes {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
    pub fn internal_volume_object_id(&self) -> Option<&InternalVolumeObjectId> {
        self.internal_volume_object_id.as_ref()
    }
    pub fn covers_volume_object_id(&self, raw: &NtfsInspection, record_number: u64) -> bool {
        record_number == 3
            && self.binds(raw)
            && self
                .internal_volume_object_id
                .as_ref()
                .is_some_and(|id| id.record_number == record_number && id.binds(raw))
    }
    #[cfg(windows)]
    pub fn bind_native_quota(&mut self, observed: &n2r_win32::GeneralLiveNtfsObservation) -> bool {
        let Some(native) = observed.txf() else {
            return false;
        };
        let native = &native.observation;
        if observed.report().request.source_inspection_sha256 != self.inspection_sha256
            || !self.default_quotas_only
            || native.windows_version != [10, 0, 26300]
            || native.rm_handle_profile != "volume-root-directory-physical-disk-read-only"
            || !native
                .quota_before
                .as_ref()
                .zip(native.quota_after.as_ref())
                .is_some_and(|(a, b)| {
                    a == b
                        && a.control_flags == 0
                        && a.default_threshold == -1
                        && a.default_limit == -1
                        && a.free_space_start_filtering == 0
                        && a.free_space_threshold == 0
                        && a.free_space_stop_filtering == 0
                })
        {
            return false;
        }
        self.native_quota_policy_bound = true;
        for index in &mut self.indexes {
            if index.role == "$Extend\\$Quota" {
                index.replacement_supported = true;
                index.detail =
                    "cross-matched unlimited defaults; native quotas disabled with zero accounting"
                        .into();
            }
        }
        self.replacement_supported = self.indexes.iter().all(|i| i.replacement_supported);
        true
    }
}

fn internal_volume_object_id<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    index_file: &ntfs_inspect::FileInventory,
    index_root: &[u8],
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<Option<InternalVolumeObjectId>> {
    let mut ids = raw.files.iter().flat_map(|file| {
        file.attributes
            .iter()
            .filter(|attribute| attribute.type_code == 0x40)
            .map(move |attribute| (file, attribute))
    });
    let Some((volume, attribute)) = ids.next() else {
        return Ok(None);
    };
    if ids.next().is_some() || entries.len() != 1 {
        return Ok(None);
    }
    let name: Vec<_> = "$O".encode_utf16().collect();
    if volume.record_number != 3
        || volume.sequence_number == 0
        || volume.base_file_reference != 0
        || volume.is_directory
        || volume.hard_link_count != 1
        || volume.metadata_role != ntfs_inspect::MetadataRole::ReservedSystemRecord
        || volume.metadata_role_issue.is_some()
        || ntfs_admission::internal_role(raw, volume).as_deref() != Some("$Volume")
        || !attribute.resident
        || !attribute.name_utf16.is_empty()
        || attribute.flags != 0
        || attribute.compression_unit != 0
        || attribute.lowest_vcn != 0
        || attribute.logical_size != 16
        || attribute.initialized_size != 16
        || attribute.allocated_size != 16
        || !attribute.extents.is_empty()
        || index_file.base_file_reference != 0
        || index_file.sequence_number == 0
        || index_file.metadata_role_issue.is_some()
        || index_file.attributes.iter().any(|attribute| {
            matches!(attribute.type_code, 0x20 | 0xa0 | 0xb0)
                || (attribute.type_code == 0x90 && attribute.name_utf16 != name)
        })
    {
        return Ok(None);
    }
    // The helper parses the actual FILE record, applies USA fixups, checks
    // file sequence/base identity and compares the complete attribute report.
    let value = ntfs_inspect::read_resident_inventory_attribute(reader, raw, volume, attribute)?;
    let reference = (u64::from(volume.sequence_number) << 48) | volume.record_number;
    let (key, indexed) = &entries[0];
    if value.len() != 16
        || value.iter().all(|byte| *byte == 0)
        || key.as_slice() != value
        || indexed.len() != 56
        || indexed[..8] != reference.to_le_bytes()
        || indexed[8..] != [0; 48]
    {
        return Ok(None);
    }
    Ok(Some(InternalVolumeObjectId {
        inspection_sha256: hex::encode(Sha256::digest(serde_json::to_vec(raw)?)),
        record_number: volume.record_number,
        sequence_number: volume.sequence_number,
        attribute_instance: attribute.instance,
        object_id_hex: hex::encode(&value),
        object_id_sha256: hex::encode(Sha256::digest(&value)),
        object_index_record_number: index_file.record_number,
        object_index_sequence_number: index_file.sequence_number,
        object_index_name: "$O",
        object_index_root_sha256: hex::encode(Sha256::digest(index_root)),
        object_index_value_sha256: hex::encode(Sha256::digest(indexed)),
        file_reference: reference,
        disposition: "replace-filesystem-internal-volume-identity",
        same_refs_object_id_preserved: false,
    }))
}

fn supported_quota(entries: &[(Vec<u8>, Vec<u8>)]) -> bool {
    // DEFAULT_LIMITS, unlimited, no accounting or exceeded-limit state. Native
    // disabled policy is still required, even for this exact stored form.
    !entries.is_empty()
        && entries.len() <= 128
        && entries[0].0 == 1u32.to_le_bytes()
        && entries[0].1.len() == 48
        && entries.windows(2).all(|w| {
            w[0].0.len() == 4
                && w[1].0.len() == 4
                && u32::from_le_bytes(w[0].0[..].try_into().unwrap())
                    < u32::from_le_bytes(w[1].0[..].try_into().unwrap())
        })
        && entries.iter().enumerate().all(|(i, (key, value))| {
            key.len() == 4
                && value.len() >= 48
                && value[..4] == 2u32.to_le_bytes()
                && value[4..8] == 1u32.to_le_bytes()
                && value[8..16] == [0; 8]
                && value[24..40] == [0xff; 16]
                && value[40..48] == [0; 8]
                && (i == 0
                    || (u32::from_le_bytes(key[..].try_into().unwrap()) >= 256
                        && valid_sid(&value[48..])))
        })
}

fn valid_sid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * usize::from(sid[1])
}
fn quota_indexes_match(owners: &[(Vec<u8>, Vec<u8>)], quotas: &[(Vec<u8>, Vec<u8>)]) -> bool {
    use std::collections::BTreeSet;
    supported_quota(quotas)
        && owners.len() + 1 == quotas.len()
        && owners.iter().all(|(sid, id)| {
            valid_sid(sid)
                && id.len() == 4
                && quotas
                    .iter()
                    .skip(1)
                    .filter(|(key, value)| key == id && &value[48..] == sid)
                    .count()
                    == 1
        })
        && owners
            .iter()
            .map(|(sid, _)| sid)
            .collect::<BTreeSet<_>>()
            .len()
            == owners.len()
        && owners
            .iter()
            .map(|(_, id)| id)
            .collect::<BTreeSet<_>>()
            .len()
            == owners.len()
}

fn reparse_index_matches(raw: &NtfsInspection, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<bool> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut expected = BTreeMap::new();
    for file in &raw.files {
        let point = match crate::ntfs_reparse::file_point(file) {
            Ok(point) => point,
            Err(_) => return Ok(false),
        };
        let Some(point) = point else { continue };
        if file.sequence_number == 0 || file.record_number > 0x0000_ffff_ffff_ffff {
            return Ok(false);
        }
        let reference = file.record_number | (u64::from(file.sequence_number) << 48);
        if expected.insert(reference, point.tag()).is_some() {
            return Ok(false);
        }
    }
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for (key, value) in entries {
        if key.len() != 12 || !value.is_empty() {
            return Ok(false);
        }
        let tag = u32::from_le_bytes(key[..4].try_into()?);
        let low = u32::from_le_bytes(key[4..8].try_into()?);
        let high = u32::from_le_bytes(key[8..12].try_into()?);
        // COLLATION_NTOFS_ULONGS compares successive little-endian ULONGs,
        // rather than UTF-8 bytes or an ordinary 64-bit file-reference order.
        let ordering = (tag, low, high);
        if previous.is_some_and(|prior| prior >= ordering) {
            return Ok(false);
        }
        previous = Some(ordering);
        let reference = u64::from(low) | (u64::from(high) << 32);
        if reference >> 48 == 0 || expected.get(&reference) != Some(&tag) || !seen.insert(reference)
        {
            return Ok(false);
        }
    }
    Ok(seen.len() == expected.len())
}

struct ReparseIndexStorage {
    root: Vec<u8>,
    allocation: Vec<u8>,
    initialized: u64,
    bitmap: Vec<u8>,
}

fn reparse_index_storage<R: Read + Seek>(
    reader: &mut R,
    raw: &NtfsInspection,
    file: &ntfs_inspect::FileInventory,
    name: &[u16],
) -> Result<ReparseIndexStorage> {
    let mut root = None;
    let mut allocation = None;
    let mut bitmap = None;
    ensure!(
        file.base_file_reference == 0 && file.sequence_number != 0,
        "reparse index file identity is invalid"
    );
    for attribute in &file.attributes {
        if matches!(attribute.type_code, 0x90 | 0xa0 | 0xb0) {
            ensure!(
                attribute.name_utf16 == name
                    && attribute.flags == 0
                    && attribute.lowest_vcn == 0
                    && attribute.compression_unit == 0,
                "reparse index contains an unknown, encoded or continued index"
            );
            let target = match attribute.type_code {
                0x90 => &mut root,
                0xa0 => &mut allocation,
                0xb0 => &mut bitmap,
                _ => unreachable!(),
            };
            ensure!(
                target.replace(attribute).is_none(),
                "duplicate reparse index stream"
            );
        } else {
            let metadata = matches!(attribute.type_code, 0x10 | 0x30 | 0x50)
                && attribute.resident
                && attribute.name_utf16.is_empty()
                && attribute.flags == 0;
            let empty_data = attribute.type_code == 0x80
                && attribute.name_utf16.is_empty()
                && attribute.flags == 0
                && attribute.logical_size == 0
                && attribute.initialized_size == 0
                && attribute.allocated_size == 0
                && attribute.extents.is_empty();
            ensure!(
                metadata || empty_data,
                "unexplained reparse-index file metadata"
            );
        }
    }
    let root = root.context("reparse index root absent")?;
    ensure!(root.resident, "reparse index root must be resident");
    let root = ntfs_inspect::read_resident_inventory_attribute(reader, raw, file, root)?;
    let (allocation, initialized, bitmap) = match (allocation, bitmap) {
        (None, None) => (Vec::new(), 0, Vec::new()),
        (Some(allocation), Some(bitmap)) => {
            ensure!(
                !allocation.resident
                    && allocation.logical_size > 0
                    && allocation.logical_size <= ntfs_index::MAX_INDEX_BYTES as u64
                    && allocation.logical_size.is_multiple_of(4096)
                    && allocation.initialized_size <= allocation.logical_size
                    && bitmap.logical_size <= 4096
                    && bitmap.initialized_size == bitmap.logical_size,
                "reparse index allocation/bitmap exceeds the complete walker profile"
            );
            // Every initialized byte is reread. Uninitialized free slots stay
            // zero in this temporary input and can never be followed by the
            // bitmap-complete index walker.
            let mut bytes = vec![0; allocation.logical_size as usize];
            ntfs_inspect::read_nonresident_inventory_range(
                reader,
                allocation,
                0,
                &mut bytes[..allocation.initialized_size as usize],
                &raw.geometry,
            )?;
            let bitmap_bytes = if bitmap.resident {
                ntfs_inspect::read_resident_inventory_attribute(reader, raw, file, bitmap)?
            } else {
                let mut bytes = vec![0; bitmap.logical_size as usize];
                ntfs_inspect::read_nonresident_inventory_range(
                    reader,
                    bitmap,
                    0,
                    &mut bytes,
                    &raw.geometry,
                )?;
                bytes
            };
            (bytes, allocation.initialized_size, bitmap_bytes)
        }
        _ => anyhow::bail!("reparse index allocation/bitmap pair is incomplete"),
    };
    Ok(ReparseIndexStorage {
        root,
        allocation,
        initialized,
        bitmap,
    })
}

pub fn verify<R: Read + Seek>(reader: &mut R, raw: &NtfsInspection) -> Result<VerifiedIndexes> {
    crate::ntfs_inspect::revalidate_mft_mapping(reader, raw)?;
    crate::ntfs_inspect::validate_record_coverage(raw)?;
    ensure!(
        ntfs_index::supports_cluster_size(raw.geometry.cluster_size)
            && raw.geometry.bytes_per_sector == 512
            && raw.geometry.file_record_size == 1024
            && raw.geometry.index_record_size == 4096,
        "bounded supported-cluster MFT scan with 512-byte sectors and 4 KiB indexes required"
    );
    let mut indexes = Vec::new();
    let mut quota_owners = Vec::new();
    let mut quota_ids = Vec::new();
    let mut volume_object_id = None;
    for (role, name, profile) in [
        ("$Extend\\$ObjId", "$O", Profile::OBJECT_ID),
        ("$Extend\\$Reparse", "$R", Profile::REPARSE),
        ("$Extend\\$Quota", "$O", Profile::QUOTA_OWNER),
        ("$Extend\\$Quota", "$Q", Profile::QUOTA_ID),
    ] {
        let files: Vec<_> = raw
            .files
            .iter()
            .filter(|f| ntfs_admission::internal_role(raw, f).as_deref() == Some(role))
            .collect();
        ensure!(files.len() == 1, "missing/duplicate internal object {role}");
        let file = files[0];
        let name_utf16: Vec<_> = name.encode_utf16().collect();
        let attrs: Vec<_> = file
            .attributes
            .iter()
            .filter(|a| a.name_utf16 == name_utf16)
            .collect();
        let storage = if role == "$Extend\\$Reparse" {
            reparse_index_storage(reader, raw, file, &name_utf16)?
        } else {
            ensure!(
                attrs.len() == 1
                    && attrs[0].type_code == 0x90
                    && attrs[0].flags == 0
                    && attrs[0].lowest_vcn == 0
                    && attrs[0].compression_unit == 0,
                "internal index {role}/{name} exceeds resident-only replacement profile"
            );
            ReparseIndexStorage {
                root: ntfs_inspect::read_resident_inventory_attribute(reader, raw, file, attrs[0])?,
                allocation: Vec::new(),
                initialized: 0,
                bitmap: Vec::new(),
            }
        };
        let root = &storage.root;
        let parsed = ntfs_index::parse_with_cluster_size(
            Input {
                root,
                allocation: &storage.allocation,
                initialized: storage.initialized,
                bitmap: &storage.bitmap,
            },
            profile,
            raw.geometry.cluster_size,
            |_, key, value| Ok((key.to_vec(), value.to_vec())),
        )
        .with_context(|| format!("internal index {role}/{name}"))?;
        let supported = if role == "$Extend\\$ObjId" {
            volume_object_id = internal_volume_object_id(reader, raw, file, root, &parsed.entries)?;
            volume_object_id.is_some()
                || (parsed.entries.is_empty()
                    && raw.files.iter().all(|file| {
                        file.attributes
                            .iter()
                            .all(|attribute| attribute.type_code != 0x40)
                    }))
        } else if role == "$Extend\\$Reparse" {
            reparse_index_matches(raw, &parsed.entries)?
        } else {
            role != "$Extend\\$Quota" && parsed.entries.is_empty()
        };
        if role == "$Extend\\$Quota" {
            if name == "$Q" {
                quota_ids = parsed.entries.clone();
            } else {
                quota_owners = parsed.entries.clone();
            }
        }
        indexes.push(IndexState {
            role: role.into(),
            name: name.into(),
            record_number: file.record_number,
            root_sha256: hex::encode(Sha256::digest(root)),
            initialized_allocation_sha256: (!storage.allocation.is_empty()).then(|| {
                hex::encode(Sha256::digest(&storage.allocation[..storage.initialized as usize]))
            }),
            bitmap_sha256: (!storage.bitmap.is_empty())
                .then(|| hex::encode(Sha256::digest(&storage.bitmap))),
            index_blocks: parsed.index_blocks,
            entries: parsed.entries.len(),
            entry_evidence: parsed
                .entries
                .iter()
                .map(|(key, value)| IndexEntry {
                    key_hex: hex::encode(key),
                    value_hex: hex::encode(value),
                })
                .collect(),
            replacement_supported: supported,
            detail: if role == "$Extend\\$ObjId" && volume_object_id.is_some() {
                "sole $Volume identity cross-matches its current file reference; recorded for explicit filesystem-internal replacement, not same-ID preservation"
            } else if supported && role == "$Extend\\$Reparse" {
                "complete reparse index cross-matches every supported file reference, sequence and tag; target reconstruction still required"
            } else if supported {
                "empty index or unlimited format defaults"
            } else {
                "nonempty or unrecognized internal state requires preservation"
            }
            .into(),
        });
    }
    Ok(VerifiedIndexes {
        inspection_sha256: hex::encode(Sha256::digest(serde_json::to_vec(raw)?)),
        internal_volume_object_id: volume_object_id,
        replacement_supported: indexes.iter().all(|i| i.replacement_supported),
        default_quotas_only: quota_indexes_match(&quota_owners, &quota_ids),
        native_quota_policy_bound: false,
        indexes,
    })
}

#[cfg(test)]
#[path = "../tests/support/volume_object_id.rs"]
mod volume_identity_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    fn diagnostic_assessment(raw: &NtfsInspection) -> ntfs_admission::Assessment {
        let comparison = crate::ntfs_attestation::Comparison {
            schema_version: 1,
            source_inspection_sha256: hex::encode(Sha256::digest(serde_json::to_vec(raw).unwrap())),
            requested_files: raw.files.len(),
            opened_files: 0,
            matched_files: 0,
            files: vec![],
            all_requested_metadata_matched: false,
            conversion_qualified: false,
            native_streams: None,
            native_logical_data: None,
            native_namespace: None,
        };
        ntfs_admission::assess_ordinary_with_backups(raw, &comparison, 5, None)
    }

    #[test]
    fn volume_identity_binder_clears_only_its_blocker_without_admitting_source() {
        use std::io::Cursor;
        use volume_identity_fixture::{ID, fixture, index_value};
        let bytes = fixture(Some(&ID), &[(ID.to_vec(), index_value(3, 3))], false);
        let mut raw = ntfs_inspect::inspect(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
        raw.blockers.push(ntfs_inspect::InspectionBlocker {
            code: "unimplemented_future_feature".into(),
            message: "unrelated source requirement must survive identity classification".into(),
            file_record_number: Some(16),
        });
        let proof = verify(&mut Cursor::new(&bytes), &raw).unwrap();
        let mut assessment = diagnostic_assessment(&raw);
        let other_gates = |assessment: &ntfs_admission::Assessment| {
            assessment
                .gates
                .iter()
                .filter(|gate| gate.code != "remaining_inspection_refusals")
                .map(|gate| (gate.code.clone(), gate.satisfied))
                .collect::<Vec<_>>()
        };
        let before = other_gates(&assessment);
        assert!(assessment.gates.iter().any(|gate| {
            gate.code == "remaining_inspection_refusals" && gate.detail.contains("\"object_id\"")
        }));
        assert!(ntfs_admission::bind_internal_volume_identity(
            &mut assessment,
            &raw,
            &proof
        ));
        let remaining = assessment
            .gates
            .iter()
            .find(|gate| gate.code == "remaining_inspection_refusals")
            .unwrap();
        assert!(!remaining.satisfied);
        assert!(!remaining.detail.contains("\"object_id\""));
        assert!(remaining.detail.contains("unimplemented_future_feature"));
        assert_eq!(other_gates(&assessment), before);
        assert!(!assessment.source_admitted);
        assert!(!assessment.certificate_issued);
        assert!(!assessment.execution_authorized);
        let user_ids = fixture(Some(&ID), &[(ID.to_vec(), index_value(3, 3))], true);
        let raw =
            ntfs_inspect::inspect(&mut Cursor::new(&user_ids), user_ids.len() as u64).unwrap();
        let proof = verify(&mut Cursor::new(&user_ids), &raw).unwrap();
        let mut assessment = diagnostic_assessment(&raw);
        let before = serde_json::to_vec(&assessment).unwrap();
        assert!(!ntfs_admission::bind_internal_volume_identity(
            &mut assessment,
            &raw,
            &proof
        ));
        assert_eq!(serde_json::to_vec(&assessment).unwrap(), before);
    }

    #[test]
    fn quota_policy_rejects_users_limits_tracking_and_truncation() {
        let mut value = vec![0; 48];
        value[..4].copy_from_slice(&2u32.to_le_bytes());
        value[4..8].copy_from_slice(&1u32.to_le_bytes());
        value[24..40].fill(0xff);
        let baseline = vec![(1u32.to_le_bytes().to_vec(), value)];
        assert!(supported_quota(&baseline));
        for offset in [0, 4, 8, 24, 32, 40] {
            let mut bad = baseline.clone();
            bad[0].1[offset] ^= 1;
            assert!(!supported_quota(&bad));
        }
        let mut bad = baseline.clone();
        bad[0].0[0] = 2;
        assert!(!supported_quota(&bad));
        let mut bad = baseline.clone();
        bad.push(baseline[0].clone());
        assert!(!supported_quota(&bad));
        let mut bad = baseline;
        bad[0].1.pop();
        assert!(!supported_quota(&bad));
        assert!(!supported_quota(&[]));
    }
    #[test]
    fn default_user_quotas_require_exact_sid_owner_cross_membership() {
        let sid = hex::decode("01020000000000052000000020020000").unwrap();
        let mut defaults = vec![0; 48];
        defaults[..4].copy_from_slice(&2u32.to_le_bytes());
        defaults[4..8].copy_from_slice(&1u32.to_le_bytes());
        defaults[24..40].fill(0xff);
        let mut user = defaults.clone();
        user.extend(&sid);
        let quotas = vec![
            (1u32.to_le_bytes().to_vec(), defaults),
            (256u32.to_le_bytes().to_vec(), user),
        ];
        let owners = vec![(sid, 256u32.to_le_bytes().to_vec())];
        assert!(quota_indexes_match(&owners, &quotas));
        assert!(!quota_indexes_match(&[], &quotas));
        let mut bad = owners.clone();
        bad[0].1[0] ^= 1;
        assert!(!quota_indexes_match(&bad, &quotas));
        let mut bad = owners.clone();
        bad[0].0[8] ^= 1;
        assert!(!quota_indexes_match(&bad, &quotas));
        let mut bad = owners.clone();
        bad.push(bad[0].clone());
        assert!(!quota_indexes_match(&bad, &quotas));
        let mut bad = quotas.clone();
        bad[1].1[32] = 0;
        assert!(!quota_indexes_match(&owners, &bad));
        let mut bad = quotas;
        bad[1].1[49] = 15;
        assert!(!quota_indexes_match(&owners, &bad));
    }
}
