//! Narrow frozen-source checks for indexes that role recognition cannot
//! authorize dropping. Object/reparse entries and nondefault quota state stay
//! refused; default quota entries also require a live disabled-policy witness.
use crate::{
    ntfs_admission,
    ntfs_index::{self, Input, Profile},
    ntfs_inspect::{self, NtfsInspection},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

#[derive(Debug, Serialize)]
pub struct IndexState {
    pub role: String,
    pub name: String,
    pub record_number: u64,
    pub root_sha256: String,
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
    pub indexes: Vec<IndexState>,
    pub default_quotas_only: bool,
    pub native_quota_policy_bound: bool,
    pub replacement_supported: bool,
}
impl VerifiedIndexes {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
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

pub fn verify<R: Read + Seek>(reader: &mut R, raw: &NtfsInspection) -> Result<VerifiedIndexes> {
    ensure!(
        raw.records_scanned == raw.files.len() as u64
            && raw.geometry.cluster_size == 4096
            && raw.geometry.bytes_per_sector == 512
            && raw.geometry.file_record_size == 1024,
        "bounded initial-profile MFT scan required"
    );
    let mut indexes = Vec::new();
    let mut quota_owners = Vec::new();
    let mut quota_ids = Vec::new();
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
        ensure!(
            attrs.len() == 1
                && attrs[0].type_code == 0x90
                && attrs[0].flags == 0
                && attrs[0].lowest_vcn == 0
                && attrs[0].compression_unit == 0,
            "internal index {role}/{name} exceeds resident-only replacement profile"
        );
        let root = ntfs_inspect::read_resident_inventory_attribute(reader, raw, file, attrs[0])?;
        let parsed = ntfs_index::parse(
            Input {
                root: &root,
                allocation: &[],
                initialized: 0,
                bitmap: &[],
            },
            profile,
            |_, key, value| Ok((key.to_vec(), value.to_vec())),
        )
        .with_context(|| format!("internal index {role}/{name}"))?;
        let supported = role != "$Extend\\$Quota" && parsed.entries.is_empty();
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
            root_sha256: hex::encode(Sha256::digest(&root)),
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
            detail: if supported {
                "empty index or unlimited format defaults"
            } else {
                "nonempty or unrecognized internal state requires preservation"
            }
            .into(),
        });
    }
    Ok(VerifiedIndexes {
        inspection_sha256: hex::encode(Sha256::digest(serde_json::to_vec(raw)?)),
        replacement_supported: indexes.iter().all(|i| i.replacement_supported),
        default_quotas_only: quota_indexes_match(&quota_owners, &quota_ids),
        native_quota_policy_bound: false,
        indexes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
