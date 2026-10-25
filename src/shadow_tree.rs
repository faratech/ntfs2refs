//! Semantic input for an independent, native-created ReFS shadow. This is not
//! source admission, a conversion plan or authority to modify the NTFS source.
use crate::{ntfs_admission, ntfs_inspect as ntfs, ntfs_security, ntfs_stream_plan};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub record_number: u64,
    pub sequence_number: u16,
    pub path: Vec<String>,
    pub directory: bool,
    /// FILE_BASIC_INFO order: creation, access, write, change.
    pub stored_times: [u64; 4],
    pub attributes: u32,
    pub security: Vec<u8>,
    pub source_offset: Option<u64>,
    /// Fragmented, aligned NTFS payload runs. Mutually exclusive with the
    /// single-run source_offset; absent in older frozen tree requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_extents: Vec<ntfs::Extent>,
    pub length: u64,
    pub sha256: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Tree {
    pub profile: &'static str,
    pub objects: Vec<Object>,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTree {
    pub profile: String,
    pub objects: Vec<Object>,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
}
impl From<&Tree> for ExpectedTree {
    fn from(tree: &Tree) -> Self {
        Self {
            profile: tree.profile.into(),
            objects: tree.objects.clone(),
            logical_bytes: tree.logical_bytes,
            internal_replacement_pending: tree.internal_replacement_pending.clone(),
        }
    }
}
impl ExpectedTree {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.profile == "native-ordinary-tree-shadow-v2"
                && !self.objects.is_empty()
                && self.objects.len() <= 160
                && self.objects[0].directory
                && self.objects[0].path.is_empty()
                && self
                    .objects
                    .iter()
                    .filter(|object| object.path.is_empty())
                    .count()
                    == 1,
            "expected general tree profile or root differs"
        );
        let mut paths = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut bytes = 0u64;
        for object in &self.objects {
            let path_key = object.path.join("\\").to_ascii_uppercase();
            ensure!(
                object.path.len() <= 16
                    && object.path.iter().all(|part| valid_component(part))
                    && object
                        .stored_times
                        .iter()
                        .all(|time| *time > 0 && *time < i64::MAX as u64)
                    && object.attributes & !0x2037 == 0
                    && (object.attributes & 16 != 0) == object.directory
                    && identities.insert((object.record_number, object.sequence_number))
                    && !paths.contains_key(&path_key),
                "expected general tree object is invalid or duplicated"
            );
            if !object.path.is_empty() {
                let parent = object.path[..object.path.len() - 1]
                    .join("\\")
                    .to_ascii_uppercase();
                ensure!(
                    paths.get(&parent) == Some(&true),
                    "expected tree parent is missing, is not a directory, or follows its child"
                );
            }
            paths.insert(path_key, object.directory);
            if !object.directory {
                let digest = object.sha256.as_deref().unwrap_or("");
                ensure!(
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "expected stream digest differs"
                );
                bytes = bytes
                    .checked_add(object.length)
                    .context("expected byte overflow")?;
            } else {
                ensure!(
                    object.length == 0
                        && object.sha256.is_none()
                        && object.source_offset.is_none()
                        && object.source_extents.is_empty(),
                    "expected directory carries stream data"
                );
            }
            ensure!(
                object.source_offset.is_none() || object.source_extents.is_empty(),
                "expected tree mixes single and fragmented source runs"
            );
            if !object.source_extents.is_empty() {
                let mut covered = 0u64;
                for extent in &object.source_extents {
                    ensure!(
                        extent.logical_offset == covered
                            && extent.length > 0
                            && extent.length.is_multiple_of(4096)
                            && extent.physical_offset.is_some_and(|offset| {
                                offset.is_multiple_of(4096)
                                    && offset.checked_add(extent.length).is_some()
                            }),
                        "expected fragmented source run differs"
                    );
                    covered = covered
                        .checked_add(extent.length)
                        .context("source run overflow")?;
                }
                ensure!(
                    covered > 0 && covered <= object.length / 4096 * 4096,
                    "source initialized-cluster prefix differs"
                );
            }
        }
        ensure!(
            bytes == self.logical_bytes && bytes <= ntfs_admission::MAX_LOGICAL_BYTES,
            "expected logical byte total differs"
        );
        Ok(())
    }
}
pub fn derive(raw: &ntfs::NtfsInspection) -> Result<Tree> {
    derive_profile(raw, false)
}
/// Additional ordinary stream forms are materialized from logical bytes. This
/// constructs an independent shadow; it does not admit source-device writes.
pub fn derive_ordinary(raw: &ntfs::NtfsInspection) -> Result<Tree> {
    derive_profile(raw, true)
}
fn derive_profile(raw: &ntfs::NtfsInspection, ordinary: bool) -> Result<Tree> {
    ensure!(
        raw.schema_version == 1
            && raw.records_scanned == raw.files.len() as u64
            && raw.geometry.cluster_size == 4096
            && raw.geometry.bytes_per_sector == 512,
        "incomplete record scan or unsupported source geometry"
    );
    ensure!(
        matches!(
            raw.allocation_reconciliation.as_ref().map(|a| &a.status),
            Some(ntfs::AllocationReconciliationStatus::ConsistentRawModel)
        ) && matches!(
            raw.namespace_reconciliation.as_ref().map(|n| &n.status),
            Some(crate::ntfs_namespace::Status::ConsistentRawModel)
        ),
        "raw ownership or namespace is unresolved"
    );
    let sd = raw
        .security_reconciliation
        .as_ref()
        .context("no raw security model")?;
    ensure!(
        sd.status == ntfs_security::Status::ConsistentRawModel,
        "raw security unresolved"
    );
    let mut tree = Tree {
        profile: if ordinary {
            "native-ordinary-tree-shadow-v2"
        } else {
            "native-existing-tree-shadow-v1"
        },
        objects: vec![],
        logical_bytes: 0,
        internal_replacement_pending: vec![],
    };
    let mut paths = BTreeSet::new();
    let mut source_ranges = vec![];
    let source_plan = ntfs_stream_plan::classify(raw);
    for f in &raw.files {
        if let Some(role) = ntfs_admission::internal_role(raw, f) {
            tree.internal_replacement_pending.push(role);
            continue;
        }
        let p = ntfs_admission::path(raw, f).context("unresolved source path")?;
        ensure!(
            p.len() <= 16 && p.iter().all(|c| valid_component(c)),
            "unsupported Windows path"
        );
        ensure!(
            paths.insert(p.join("\\").to_ascii_uppercase()),
            "colliding destination name"
        );
        if f.record_number == 5 {
            // Root is reconstructed only as a shadow experiment. Its NTFS
            // transactional attribute is explicitly unresolved for admission.
            ensure!(
                p.is_empty() && f.is_directory && f.streams.is_empty(),
                "invalid root"
            );
            ensure!(
                f.attributes.iter().all(|a| a.flags == 0
                    && a.lowest_vcn == 0
                    && ((matches!(a.type_code, 0x10 | 0x30 | 0x50)
                        && a.resident
                        && a.name_utf16.is_empty())
                        || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                            && crate::ntfs_namespace::is_i30(&a.name_utf16))
                        || ntfs_admission::recognized_root_txf(a))),
                "unknown root attributes"
            );
            if f.attributes.iter().any(|a| a.type_code == 0x100) {
                tree.internal_replacement_pending
                    .push("root:$TXF_DATA (not yet admitted for replacement)".into());
            }
        } else {
            let issues = if ordinary {
                ntfs_admission::ordinary_user_issues(raw, f)
            } else {
                ntfs_admission::user_issues(raw, f)
            };
            ensure!(
                issues.is_empty(),
                "record {} exceeds shadow profile: {issues:?}",
                f.record_number
            );
        }
        let binding = sd
            .bindings
            .iter()
            .find(|b| b.record_number == f.record_number && b.sequence_number == f.sequence_number)
            .context("missing descriptor binding")?;
        let descriptor = &sd
            .descriptors
            .iter()
            .find(|d| d.descriptor.sha256 == binding.descriptor_sha256)
            .context("missing descriptor bytes")?
            .descriptor;
        ensure!(
            descriptor.sacl.state == ntfs_security::AclState::Absent
                && descriptor.dacl.state == ntfs_security::AclState::Present,
            "initial shadow requires present DACL and absent SACL"
        );
        ensure!(
            ordinary || f.record_number == 5 || descriptor.control & 0x1000 != 0,
            "initial shadow profile requires protected child DACLs"
        );
        let si = f
            .standard_information
            .as_ref()
            .context("missing stored timestamps")?;
        let times = [
            si.creation_time,
            si.access_time,
            si.modification_time,
            si.mft_change_time,
        ];
        ensure!(
            times.iter().all(|t| *t > 0 && *t < i64::MAX as u64)
                && si.file_attributes & !0x2027 == 0,
            "unsupported basic metadata"
        );
        let (source_offset, source_extents, length, sha256) = match f.streams.first() {
            Some(s) => {
                let candidate = source_plan.streams.iter().find(|decision| {
                    decision.record_number == f.record_number
                        && decision.sequence_number == f.sequence_number
                        && decision.name_utf16.is_empty()
                });
                let offset = candidate
                    .filter(|decision| {
                        decision.disposition == ntfs_stream_plan::Disposition::RetainCandidate
                    })
                    .and_then(|decision| decision.source_offset);
                let extents = candidate
                    .filter(|decision| {
                        matches!(
                            decision.disposition,
                            ntfs_stream_plan::Disposition::RetainCandidate
                                | ntfs_stream_plan::Disposition::MixedCandidate
                        )
                    })
                    .map(|decision| decision.source_extents.clone())
                    .unwrap_or_default();
                if let Some(offset) = offset {
                    source_ranges.push((offset, s.logical_size));
                }
                for extent in &extents {
                    source_ranges.push((
                        extent.physical_offset.context("missing source run")?,
                        extent.length,
                    ));
                }
                (
                    offset,
                    extents,
                    s.logical_size,
                    Some(s.logical_sha256.clone().context("missing logical digest")?),
                )
            }
            None => (None, Vec::new(), 0, None),
        };
        tree.logical_bytes = tree
            .logical_bytes
            .checked_add(length)
            .context("logical size overflow")?;
        tree.objects.push(Object {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            path: p,
            directory: f.is_directory,
            stored_times: times,
            attributes: si.file_attributes | if f.is_directory { 16 } else { 0 },
            security: hex::decode(&descriptor.relative_hex)?,
            source_offset,
            source_extents,
            length,
            sha256,
        });
    }
    source_ranges.sort_unstable();
    ensure!(
        source_ranges.windows(2).all(|p| p[0].0 + p[0].1 <= p[1].0),
        "overlapping user payloads"
    );
    let directories = tree.objects.iter().filter(|o| o.directory).count();
    ensure!(
        directories > 0
            && directories <= ntfs_admission::MAX_DIRECTORIES
            && tree.objects.len() - directories <= ntfs_admission::MAX_FILES
            && tree.logical_bytes <= ntfs_admission::MAX_LOGICAL_BYTES
            && tree.objects.iter().filter(|o| o.path.is_empty()).count() == 1,
        "tree budget or root differs"
    );
    tree.objects.sort_by_key(|o| (o.path.len(), o.path.clone()));
    Ok(tree)
}
pub(crate) fn valid_component(s: &str) -> bool {
    let upper = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !s.is_empty()
        && s.len() <= 100
        && !s.ends_with([' ', '.'])
        && s.bytes()
            .all(|c| (c == b' ' || c.is_ascii_graphic()) && !b"<>:\"/\\|?*".contains(&c))
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(&upper.as_str())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_alias_traversal_devices_and_ambiguous_components() {
        for s in [
            "", ".", "..", "a.", "a ", "CON.txt", "CON .txt", "lpt9.bin", "a:b", "a\\b", "a/b",
            "a?b", "a*b", "a\0b", "é",
        ] {
            assert!(!valid_component(s), "{s:?}");
        }
        assert!(valid_component("doc1.bin"));
        assert!(valid_component("Quarterly Report 1.txt"));
        assert!(valid_component("Q4 (final) #1 & notes.txt"));
    }
}
