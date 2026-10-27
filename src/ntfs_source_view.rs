//! Explicit persisted-source policy over native observations. Strict raw/native
//! discrepancies remain available separately. A replay is conditional evidence;
//! only the actual frozen-device observer can bind it to an unchanged source.
use crate::{
    ntfs_attestation,
    ntfs_inspect::{FileInventory, NtfsInspection},
    ntfs_namespace_attestation::{self, ProjectedDirectory},
    ntfs_stream_attestation::Check,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::attestation::{Report, Snapshot};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct TimestampView {
    /// Creation, access, modification and metadata-change FILETIMEs, unchanged.
    pub stored: [u64; 4],
    pub native_before: [u64; 4],
    pub native_after: [u64; 4],
    pub cached_access_differs: bool,
    pub preservation_authority: &'static str,
}
#[derive(Debug, Serialize)]
pub struct DirectoryView {
    pub check: Check,
    pub projection: Option<ProjectedDirectory>,
}
#[derive(Debug, Serialize)]
pub struct ObjectView {
    pub record_number: u64,
    pub sequence_number: u16,
    pub metadata: Check,
    pub timestamps: Option<TimestampView>,
    pub directory: Option<DirectoryView>,
    pub security: Option<SecurityView>,
}

#[derive(Debug, Serialize)]
pub struct SecurityView {
    pub stored_sha256: String,
    pub api_descriptor_hex: String,
    pub api_matches_stored: bool,
    pub api_stable: bool,
    pub target_must_reproduce_both_views: bool,
}

pub fn check_security_views(
    sd: &[u8],
    before: &Snapshot,
    after: &Snapshot,
) -> Result<SecurityView> {
    for snapshot in [before, after] {
        let kernel = snapshot
            .kernel_security
            .as_ref()
            .context("kernel security view absent")?;
        ensure!(
            kernel.native_error.is_none() && ntfs_attestation::same_security(sd, &kernel.bytes)?,
            "stored/kernel security semantics differ"
        );
        ensure!(
            snapshot.security_error.is_none(),
            "API security query failed"
        );
        crate::ntfs_security::parse_descriptor(&snapshot.security)?;
    }
    ensure!(
        ntfs_attestation::same_security(&before.security, &after.security)?,
        "API security projection changed"
    );
    Ok(SecurityView {
        stored_sha256: hex::encode(Sha256::digest(sd)),
        api_descriptor_hex: hex::encode(&before.security),
        api_matches_stored: ntfs_attestation::same_security(sd, &before.security)?,
        api_stable: true,
        target_must_reproduce_both_views: true,
    })
}
#[derive(Debug, Serialize)]
pub struct Analysis {
    profile: &'static str,
    source_inspection_sha256: String,
    canonical_native_sha256: String,
    /// Only filled by the live observer after its actual-device/hash checks.
    frozen_source_sha256: Option<String>,
    pub objects: Vec<ObjectView>,
    pub all_user_views_compatible: bool,
    source_admitted: bool,
    execution_authorized: bool,
}
impl Analysis {
    pub(crate) fn bind_frozen_source(&mut self, hash: &str) {
        self.frozen_source_sha256 = Some(hash.into());
    }
    pub(crate) fn binds_live(&self, inspection: &str) -> bool {
        self.source_inspection_sha256 == inspection && self.frozen_source_sha256.is_some()
    }
    pub(crate) fn binds_live_source(&self, inspection: &str, source: &str) -> bool {
        self.source_inspection_sha256 == inspection
            && self.frozen_source_sha256.as_deref() == Some(source)
    }
}
fn query(s: &Snapshot, class: i32) -> Result<&[u8]> {
    let mut found = s.queries.iter().filter(|q| q.class == class);
    let q = found.next().context("missing source-view metadata query")?;
    ensure!(
        found.next().is_none() && q.native_error.is_none(),
        "duplicate/refused source-view query"
    );
    Ok(&q.bytes)
}
/// Validate both complete metadata views. Access time is not rewritten or
/// compared to a substitute value: all three observed/persisted values are
/// recorded and all other metadata must remain stable and match the raw model.
pub fn check_metadata(
    f: &FileInventory,
    serial: u64,
    sd: &[u8],
    before: &Snapshot,
    after: &Snapshot,
) -> Result<TimestampView> {
    let a = ntfs_attestation::check_non_security_snapshot(f, serial, before)?;
    let b = ntfs_attestation::check_non_security_snapshot(f, serial, after)?;
    check_security_views(sd, before, after)?;
    let si = f
        .standard_information
        .as_ref()
        .context("stored timestamps absent")?;
    let stored = [
        si.creation_time,
        si.access_time,
        si.modification_time,
        si.mft_change_time,
    ];
    for times in [a, b] {
        ensure!(
            [times[0], times[2], times[3]] == [stored[0], stored[2], stored[3]],
            "creation, modification or metadata-change time differs"
        );
    }
    for s in [before, after] {
        let k = s
            .kernel_security
            .as_ref()
            .context("kernel security view absent")?;
        ensure!(
            k.native_error.is_none() && ntfs_attestation::same_security(sd, &k.bytes)?,
            "stored/kernel security semantics differ"
        );
        let tag = query(s, 9)?;
        ensure!(
            tag[4..8] == [0; 4],
            "source-view profile refuses reparse tags"
        );
        if !f.is_directory {
            let stream = f
                .streams
                .iter()
                .find(|s| s.name_utf16.is_empty())
                .context("default stream absent")?;
            if !stream.resident {
                ensure!(
                    u64::from_le_bytes(query(s, 1)?[..8].try_into().unwrap())
                        == stream.allocated_size,
                    "native allocation size differs"
                );
            }
        }
    }
    for class in [0, 1, 9, 18] {
        let x = query(before, class)?;
        let y = query(after, class)?;
        let stable = if class == 0 {
            x[..8] == y[..8] && x[16..] == y[16..]
        } else {
            x == y
        };
        ensure!(
            stable,
            "metadata changed beyond cached access time (class {class})"
        );
    }
    Ok(TimestampView {
        stored,
        native_before: a,
        native_after: b,
        cached_access_differs: a[1] != stored[1] || b[1] != stored[1],
        preservation_authority: "persisted STANDARD_INFORMATION after freeze; requires actual unchanged read-only source",
    })
}

/// Replay-compatible diagnostic. This constructor never establishes an actual
/// device freeze and its result alone cannot satisfy an admission gate.
pub fn diagnose(raw: &NtfsInspection, inspection_pin: &str, native: &Report) -> Result<Analysis> {
    // Validate the entire request, native route/protection and identity set.
    // Per-object strict failures remain in this independent comparison.
    let _strict = ntfs_attestation::compare(raw, inspection_pin, native)?;
    ensure!(
        matches!(native.schema_version, 5..=8),
        "source-view policy requires native schema 5 through 8"
    );
    let security = raw
        .security_reconciliation
        .as_ref()
        .context("stored security absent")?;
    let namespace = native
        .namespace
        .as_ref()
        .context("native namespace absent")?;
    let mut objects = vec![];
    for f in &raw.files {
        if crate::ntfs_admission::internal_role(raw, f).is_some() {
            continue;
        }
        let mut timestamps = None;
        let mut security_view = None;
        let mut metadata = Check::from((|| {
            let observed = native
                .files
                .iter()
                .find(|o| {
                    o.identity.record_number == f.record_number
                        && o.identity.sequence_number == f.sequence_number
                })
                .context("native identity missing")?;
            ensure!(
                observed.open_error.is_none(),
                "native object open refused: {:?}",
                observed.open_error
            );
            let binding = security
                .bindings
                .iter()
                .find(|b| {
                    b.record_number == f.record_number && b.sequence_number == f.sequence_number
                })
                .context("stored descriptor binding missing")?;
            let sd = security
                .descriptors
                .iter()
                .find(|d| d.descriptor.sha256 == binding.descriptor_sha256)
                .context("stored descriptor missing")?;
            timestamps = Some(check_metadata(
                f,
                raw.geometry.serial_number,
                &hex::decode(&sd.descriptor.relative_hex)?,
                observed
                    .before
                    .as_ref()
                    .context("native before snapshot absent")?,
                observed
                    .after
                    .as_ref()
                    .context("native after snapshot absent")?,
            )?);
            security_view = Some(check_security_views(
                &hex::decode(&sd.descriptor.relative_hex)?,
                observed
                    .before
                    .as_ref()
                    .context("native before snapshot absent")?,
                observed
                    .after
                    .as_ref()
                    .context("native after snapshot absent")?,
            )?);
            Ok(())
        })());
        if metadata.matched {
            metadata.detail = "stored/kernel metadata matches and the API projection is stable; target must preserve both descriptor views and the recorded stored FILETIMEs".into();
        }
        let directory = if f.is_directory {
            let mut projection = None;
            let mut check = Check::from((|| {
                ensure!(
                    raw.namespace_reconciliation.as_ref().is_some_and(
                        |n| n.status == crate::ntfs_namespace::Status::ConsistentRawModel
                    ),
                    "raw namespace inconsistent"
                );
                let n = namespace
                    .files
                    .iter()
                    .find(|n| {
                        n.identity.record_number == f.record_number
                            && n.identity.sequence_number == f.sequence_number
                    })
                    .context("native directory identity missing")?;
                projection = Some(ntfs_namespace_attestation::check_projected_directory(
                    raw, f, n,
                )?);
                Ok(())
            })());
            if check.matched {
                check.detail = "native names and identities match with explicitly recorded reserved-object visibility".into();
            }
            Some(DirectoryView { check, projection })
        } else {
            None
        };
        objects.push(ObjectView {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            metadata,
            timestamps,
            directory,
            security: security_view,
        });
    }
    Ok(Analysis {
        profile: "frozen-ntfs-persisted-view-v2",
        source_inspection_sha256: inspection_pin.into(),
        canonical_native_sha256: hex::encode(Sha256::digest(serde_json::to_vec(native)?)),
        frozen_source_sha256: None,
        all_user_views_compatible: !objects.is_empty()
            && objects.iter().all(|o| {
                o.metadata.matched && o.directory.as_ref().is_none_or(|d| d.check.matched)
            }),
        objects,
        source_admitted: false,
        execution_authorized: false,
    })
}
