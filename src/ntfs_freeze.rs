//! Source basis captured after native lock/dismount and persistent exclusion.
//! A frozen basis is not source admission or authority to arm writes.
use crate::{
    block_io::SourceIdentity,
    ntfs_backup, ntfs_inspect,
    planner::{Filesystem, Inspection},
};
use anyhow::{Result, ensure};
use n2r_win32::{NativeEvent, OfflinePartition, PartitionSnapshot};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct Evidence {
    schema_version: u32,
    kind: &'static str,
    partition_length: u64,
    source_sha256: String,
    canonical_inspection_sha256: String,
    before: PartitionSnapshot,
    after: PartitionSnapshot,
    backups: ntfs_backup::VerifiedBackups,
    raw_bytes_read: u64,
    raw_bytes_written: u64,
    source_admitted: bool,
}
/// Private construction; serialized evidence cannot recreate this value.
pub struct FrozenBasis {
    inspection: Inspection,
    evidence: Evidence,
}
/// Actual native collection over the same protected source, bracketed by full
/// frozen-image revalidation. A report file cannot reconstruct this witness.
#[derive(Debug, Serialize)]
pub struct ObservedFrozenSource {
    source_sha256: String,
    canonical_inspection_sha256: String,
    native: n2r_win32::LiveNtfsObservation,
    comparison: crate::ntfs_attestation::Comparison,
}
impl ObservedFrozenSource {
    pub fn assessment(&self, basis: &FrozenBasis) -> Result<crate::ntfs_admission::Assessment> {
        self.assessment_profile(basis, false)
    }
    pub fn assessment_ordinary(
        &self,
        basis: &FrozenBasis,
    ) -> Result<crate::ntfs_admission::Assessment> {
        self.assessment_profile(basis, true)
    }
    fn assessment_profile(
        &self,
        basis: &FrozenBasis,
        ordinary: bool,
    ) -> Result<crate::ntfs_admission::Assessment> {
        ensure!(
            self.source_sha256 == basis.evidence.source_sha256
                && self.canonical_inspection_sha256 == basis.evidence.canonical_inspection_sha256,
            "live observation and frozen basis differ"
        );
        let Filesystem::Ntfs(raw) = &basis.inspection.filesystem else {
            anyhow::bail!("source is not NTFS")
        };
        let mut view = crate::ntfs_source_view::diagnose(
            raw,
            &self.canonical_inspection_sha256,
            self.native.report(),
        )?;
        view.bind_frozen_source(&self.source_sha256);
        let mut assessment = if ordinary {
            crate::ntfs_admission::assess_ordinary_source_view(
                raw,
                &self.comparison,
                self.native.report().schema_version,
                Some(&basis.evidence.backups),
                Some(view),
            )
        } else {
            crate::ntfs_admission::assess_source_view(
                raw,
                &self.comparison,
                self.native.report().schema_version,
                Some(&basis.evidence.backups),
                Some(view),
            )
        };
        for gate in &mut assessment.gates {
            if gate.code == "frozen_device_basis" {
                gate.satisfied = true;
                gate.detail="actual excluded device and complete source hash revalidated before and after a live physically read-only native observation".into();
            }
        }
        Ok(assessment)
    }
    pub fn native(&self) -> &n2r_win32::attestation::Report {
        self.native.report()
    }
}
/// A fresh full-device hash check, constructed only from native reads.
#[derive(Debug, Serialize)]
pub struct Revalidation {
    before: PartitionSnapshot,
    after: PartitionSnapshot,
    source_sha256: String,
    bytes_read: u64,
}
pub fn revalidate_pin(
    source: &mut OfflinePartition,
    expected: &str,
    events: &mut Vec<NativeEvent>,
) -> Result<Revalidation> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid frozen source SHA-256 pin"
    );
    let before = source.inspect(events)?;
    ensure!(
        before.disk_attributes == 3
            && source.native_bytes_written == 0
            && source.native_write_bytes_requested == 0,
        "source must remain excluded, read-only and unwritten"
    );
    let start = source.native_bytes_read;
    let actual = hex::encode(crate::lab_reconstruct::hash_range(
        source,
        0,
        source.byte_len(),
    )?);
    ensure!(
        actual == expected,
        "frozen source content no longer matches"
    );
    let after = source.inspect(events)?;
    snapshot_matches(&before, &after)?;
    Ok(Revalidation {
        before,
        after,
        source_sha256: actual,
        bytes_read: source.native_bytes_read - start,
    })
}
fn snapshot_matches(a: &PartitionSnapshot, b: &PartitionSnapshot) -> Result<()> {
    ensure!(
        a.disk_attributes == 3
            && b.disk_attributes == 3
            && a.binding == b.binding
            && a.device == b.device
            && a.layout == b.layout
            && a.alignment == b.alignment
            && a.length == b.length,
        "frozen source identity, geometry or persistent exclusion changed"
    );
    Ok(())
}
impl FrozenBasis {
    pub fn observe_native(
        &self,
        source: &mut OfflinePartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<ObservedFrozenSource> {
        self.revalidate(source, events)?;
        let request = crate::ntfs_attestation::request_for_inspection(
            &self.inspection,
            &self.evidence.canonical_inspection_sha256,
            source.binding(),
        )?;
        let observed = source.observe_ntfs_files(&request, events);
        // Revalidate even after a collector refusal. If exclusion was not
        // restored this refuses before reading, and no witness is returned.
        self.revalidate(source, events)?;
        let native = observed?;
        let Filesystem::Ntfs(raw) = &self.inspection.filesystem else {
            anyhow::bail!("source is not NTFS")
        };
        let comparison = crate::ntfs_attestation::compare(
            raw,
            &self.evidence.canonical_inspection_sha256,
            native.report(),
        )?;
        Ok(ObservedFrozenSource {
            source_sha256: self.evidence.source_sha256.clone(),
            canonical_inspection_sha256: self.evidence.canonical_inspection_sha256.clone(),
            native,
            comparison,
        })
    }
    /// Caller supplies the actual native partition, already excluded. The
    /// constructor cannot be satisfied with an evidence JSON or boolean.
    pub fn capture(source: &mut OfflinePartition, events: &mut Vec<NativeEvent>) -> Result<Self> {
        let before = source.inspect(events)?;
        ensure!(
            before.disk_attributes == 3,
            "source requires persistent offline AND read-only attributes"
        );
        let written = source.native_bytes_written;
        let requested = source.native_write_bytes_requested;
        ensure!(
            written == 0 && requested == 0,
            "source handle has issued payload writes"
        );
        let read_start = source.native_bytes_read;
        let length = source.byte_len();
        let hash = crate::lab_reconstruct::hash_range(source, 0, length)?;
        let raw = ntfs_inspect::inspect(source, length)?;
        let backups = ntfs_backup::verify(source, length, &raw)?;
        let inspection = Inspection {
            schema_version: 1,
            source: SourceIdentity {
                path: PathBuf::from(source.binding().volume_path()?),
                length,
                sha256: hex::encode(hash),
            },
            filesystem: Filesystem::Ntfs(raw),
        };
        let manifest = hex::encode(Sha256::digest(serde_json::to_vec(&inspection)?));
        let after_hash = crate::lab_reconstruct::hash_range(source, 0, length)?;
        ensure!(
            hash == after_hash,
            "source bytes changed during frozen inspection"
        );
        let after = source.inspect(events)?;
        snapshot_matches(&before, &after)?;
        ensure!(
            source.native_bytes_written == written
                && source.native_write_bytes_requested == requested,
            "frozen inspection issued source payload writes"
        );
        let evidence = Evidence {
            schema_version: 1,
            kind: "post-exclusion-ntfs-source-basis-v1",
            partition_length: length,
            source_sha256: hex::encode(hash),
            canonical_inspection_sha256: manifest,
            before,
            after,
            backups,
            raw_bytes_read: source.native_bytes_read - read_start,
            raw_bytes_written: 0,
            source_admitted: false,
        };
        Ok(Self {
            inspection,
            evidence,
        })
    }
    pub fn inspection(&self) -> &Inspection {
        &self.inspection
    }
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Revalidate the device itself immediately before consuming a basis. This
    /// intentionally costs another complete read; a stored success flag is not
    /// a substitute for exclusion, identity and content checks.
    pub fn revalidate(
        &self,
        source: &mut OfflinePartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        let before = source.inspect(events)?;
        snapshot_matches(&self.evidence.after, &before)?;
        ensure!(
            source.native_write_bytes_requested == 0 && source.native_bytes_written == 0,
            "source has issued payload writes since freeze"
        );
        let hash = crate::lab_reconstruct::hash_range(source, 0, self.evidence.partition_length)?;
        ensure!(
            hex::encode(hash) == self.evidence.source_sha256,
            "frozen source content no longer matches"
        );
        let after = source.inspect(events)?;
        snapshot_matches(&before, &after)?;
        Ok(())
    }
}
