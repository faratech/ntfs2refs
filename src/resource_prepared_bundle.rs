//! Cold opening of a Windows-produced preparation bundle. This authenticates
//! held metadata and the original source fingerprint; it exposes no writer.
use crate::{
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
    selected_journal::{
        SelectedTicket,
        resource_domain::source_scope::{GuardFilePin, PartitionPreparationGuardPin},
    },
    source_fingerprint::resource::{PagedSourceFingerprint, ReopenedFingerprintPins},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent,
    general_layout::GeneralDiskBinding,
    journal_file::{GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile},
    offline_environment::{OfflineOwningEnvironment, OfflinePreparedSource},
    reference_file::ReferenceFileSnapshot,
    tree_resources::SourceResourceAdmission,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedArtifact {
    pub role: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub snapshot: Option<GuardFilePin>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedCore {
    pub schema_version: u32,
    pub kind: String,
    pub source: GeneralDiskBinding,
    pub shadow: GeneralDiskBinding,
    pub source_preparation: PartitionPreparationGuardPin,
    pub source_readonly_gpt_sha256: String,
    pub journal_binding: GeneralJournalStorageBinding,
    pub journal_identity: JournalFileIdentity,
    pub journal_path: PathBuf,
    pub journal_profile_version: u32,
    pub journal_profile_max_bytes: u64,
    pub ticket: SelectedTicket,
    pub publication_path: PathBuf,
    pub publication_sha256: String,
    pub locator_path: String,
    pub locator_sha256: [u8; 32],
    pub artifacts: Vec<PreparedArtifact>,
    pub source_resource_admission: SourceResourceAdmission,
    pub source_sha256: String,
    pub source_inspection_sha256: String,
    pub source_views_sha256: String,
    pub source_fingerprint: ReopenedFingerprintPins,
    pub journal_contains_source_free_rows: bool,
    pub native_journal_body_sealed: bool,
    pub journal_prepared_clear: bool,
    pub source_payload_write_calls: u64,
    pub source_apply_intent_attempted: bool,
    pub source_certificate_issued: bool,
    pub sealed_bundle_grants_writer_permission: bool,
    pub requires_new_pe_bootguard_and_actual_apply_gate: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u32,
    kind: String,
    core: PreparedCore,
    producer_handles_closed: bool,
    #[serde(rename = "postclose_source_BasicReadonly_native19_verified")]
    postclose_readonly19: bool,
    postclose_source_ntfs_primary_sha256: String,
    postclose_prepared_journal_prefix_bytes: u64,
    postclose_prepared_journal_prefix_sha256: String,
    full_journal_body_not_rescanned_at_close: bool,
    historical_run_artifacts_preserved: bool,
    source_payload_write_calls: u64,
    source_apply_intent_attempted: bool,
    source_write_or_replay_authority: bool,
    #[serde(rename = "requires_new_PE_guarded_prepared_consumer")]
    requires_guarded_consumer: bool,
    #[serde(rename = "legacy_C_only_Origin_route_allowed")]
    legacy_origin_allowed: bool,
}
fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical prepared-artifact SHA256 required"
    );
    Ok(hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256 length differs"))?)
}
fn ordinary(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
        "absolute prepared-artifact path without traversal required"
    );
    Ok(())
}
struct HeldMetadata {
    file: File,
    snapshot: ReferenceFileSnapshot,
    sha256: [u8; 32],
}
impl HeldMetadata {
    fn open(path: &Path, expected: [u8; 32], maximum: u64) -> Result<Self> {
        ordinary(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        ensure!(
            snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
            "ordinary nonempty prepared metadata required"
        );
        ensure!(
            n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == expected,
            "actual prepared-artifact content differs"
        );
        let value = Self {
            file,
            snapshot,
            sha256: expected,
        };
        value.revalidate()?;
        Ok(value)
    }
    fn revalidate(&self) -> Result<()> {
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes
            )? == self.snapshot,
            "same held prepared-artifact identity changed"
        );
        Ok(())
    }
    fn require_volume(&self, journal: &GeneralJournalStorageBinding) -> Result<()> {
        let prefix = format!("{}\\", journal.disk.volume_path()?);
        ensure!(
            self.snapshot
                .final_path
                .get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(&prefix)),
            "prepared artifact is not on the actual independently bound journal volume"
        );
        Ok(())
    }
}
pub(crate) struct HeldWindowsPreparedBundle {
    bundle: Bundle,
    outer: HeldMetadata,
    artifacts: Vec<HeldMetadata>,
    _decode_memory: SourceRamLease,
}
impl HeldWindowsPreparedBundle {
    pub(crate) fn open(
        path: &Path,
        independently_expected_sha256: &str,
        maximum_bytes: u64,
        environment: &mut OfflineOwningEnvironment,
        actual_journal_volume: &File,
        scratch: &SourceScratch,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        // Reserve the actual bounded decoder/DTO representation before parsing;
        // the reservation lives as long as the decoded bundle and its paths.
        let _io_memory = scratch.lease_ram(5 * 1024 * 1024)?;
        let mut outer =
            HeldMetadata::open(path, digest(independently_expected_sha256)?, maximum_bytes)?;
        let memory = outer
            .snapshot
            .file_bytes
            .checked_mul(32)
            .and_then(|v| v.checked_add(65536))
            .context("prepared bundle decoder reservation overflow")?;
        let decode_memory = scratch.lease_ram(memory)?;
        outer.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::try_from(outer.snapshot.file_bytes)?)?;
        (&mut outer.file)
            .take(
                outer
                    .snapshot
                    .file_bytes
                    .checked_add(1)
                    .context("bundle length overflow")?,
            )
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == outer.snapshot.file_bytes
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == outer.sha256,
            "held outer bundle changed during decoding"
        );
        let bundle: Bundle = serde_json::from_slice(&bytes)?;
        drop(bytes);
        let c = &bundle.core;
        c.source.validate()?;
        c.shadow.validate()?;
        c.journal_binding.validate()?;
        c.source_preparation.validate()?;
        environment.require_journal_disjoint(&c.journal_binding, actual_journal_volume, events)?;
        outer.require_volume(&c.journal_binding)?;
        ensure!(
            bundle.schema_version == 1
                && bundle.kind == "windows-prepared-offline-apply-bundle-v1"
                && c.schema_version == 1
                && c.kind == "windows-native-prepared-offline-apply-core-v1"
                && bundle.producer_handles_closed
                && bundle.postclose_readonly19
                && !bundle.source_write_or_replay_authority
                && !bundle.source_apply_intent_attempted
                && bundle.source_payload_write_calls == 0
                && bundle.requires_guarded_consumer
                && !bundle.legacy_origin_allowed
                && c.native_journal_body_sealed
                && c.journal_prepared_clear
                && c.source_payload_write_calls == 0
                && !c.source_apply_intent_attempted
                && !c.source_certificate_issued
                && !c.sealed_bundle_grants_writer_permission
                && c.requires_new_pe_bootguard_and_actual_apply_gate,
            "bundle is not an unactivated Windows preparation result"
        );
        ensure!(
            c.source.disk_number != c.journal_binding.disk.disk_number
                && n2r_win32::layout::guid_bytes(&c.source.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&c.journal_binding.disk.identity.disk_guid)?
                && c.source_preparation.binding.storage == c.source
                && environment.facts().source.storage == c.source
                && c.ticket.image_length == c.source.identity.partition_bytes
                && c.ticket.marker_profile.is_none()
                && bundle.postclose_prepared_journal_prefix_bytes == 8192
                && digest(&bundle.postclose_prepared_journal_prefix_sha256)?
                    == <[u8; 32]>::from(Sha256::digest([0u8; 8192]))
                && bundle.postclose_source_ntfs_primary_sha256
                    == c.source_preparation.ntfs_primary_sha256,
            "prepared source/journal/discovery bindings differ"
        );
        ensure!(
            c.source_fingerprint.partition_bytes == c.source.identity.partition_bytes
                && c.source_fingerprint.source_inspection_sha256 == c.source_inspection_sha256,
            "prepared fingerprint belongs to another source model"
        );
        for pin in [
            &c.source_readonly_gpt_sha256,
            &c.source_sha256,
            &c.source_inspection_sha256,
            &c.source_views_sha256,
            &c.publication_sha256,
        ] {
            digest(pin)?;
        }
        JournalProfile::from_schema_and_capacity(
            c.journal_profile_version,
            Some(c.journal_profile_max_bytes),
        )?;
        let mut artifacts = Vec::new();
        let mut roles = std::collections::BTreeSet::new();
        for artifact in &c.artifacts {
            ensure!(
                roles.insert(artifact.role.as_str()),
                "duplicate prepared artifact role"
            );
            let path = artifact
                .snapshot
                .as_ref()
                .map(|s| Path::new(&s.final_path))
                .unwrap_or(&artifact.path);
            let held = HeldMetadata::open(path, digest(&artifact.sha256)?, artifact.bytes)?;
            held.require_volume(&c.journal_binding)?;
            ensure!(
                held.snapshot.file_bytes == artifact.bytes
                    && held.snapshot.volume_serial_number
                        == c.journal_identity.volume_serial_number,
                "actual prepared artifact length or journal-volume serial differs"
            );
            if let Some(expected) = &artifact.snapshot {
                let a = &held.snapshot;
                ensure!(
                    a.file_id_128 == expected.file_id_128
                        && a.volume_serial_number == expected.volume_serial_number
                        && a.file_bytes == expected.file_bytes
                        && a.file_attributes == expected.file_attributes
                        && a.number_of_links == expected.number_of_links
                        && a.final_path.eq_ignore_ascii_case(&expected.final_path)
                        && a.allocation_bytes <= expected.allocation_bytes
                        && a.allocation_bytes >= a.file_bytes,
                    "actual prepared artifact differs from its original native identity"
                );
            }
            if artifact.role == "publication" {
                ensure!(
                    artifact.sha256 == c.publication_sha256,
                    "publisher SHA differs"
                );
            }
            if artifact.role == "recovery-locator" {
                ensure!(
                    digest(&artifact.sha256)? == c.locator_sha256,
                    "locator SHA differs"
                );
            }
            artifacts.push(held);
        }
        for role in [
            "publication",
            "publication-checksum",
            "native-write-index",
            "expected-tree",
            "recovery-locator",
            "source-native-pages",
            "source-preparation-intent",
            "fingerprint-allocated-data",
            "fingerprint-allocated-directory",
            "fingerprint-covered-data",
            "fingerprint-covered-directory",
            "fingerprint-omitted-data",
            "fingerprint-omitted-directory",
        ] {
            ensure!(roles.contains(role), "missing prepared artifact {role}");
        }
        for (data_role, directory_role, store) in [
            (
                "fingerprint-allocated-data",
                "fingerprint-allocated-directory",
                &c.source_fingerprint.allocated,
            ),
            (
                "fingerprint-covered-data",
                "fingerprint-covered-directory",
                &c.source_fingerprint.covered,
            ),
            (
                "fingerprint-omitted-data",
                "fingerprint-omitted-directory",
                &c.source_fingerprint.omitted,
            ),
        ] {
            for (role, page) in [(data_role, &store.data), (directory_role, &store.directory)] {
                let artifact = c
                    .artifacts
                    .iter()
                    .find(|a| a.role == role)
                    .context("fingerprint artifact absent")?;
                let native = artifact
                    .snapshot
                    .as_ref()
                    .context("fingerprint native route snapshot absent")?;
                ensure!(
                    page.path == PathBuf::from(&native.final_path)
                        && page.wire_bytes == artifact.bytes
                        && page.file_sha256 == artifact.sha256,
                    "fingerprint range pin is not the same authenticated, journal-bound native artifact"
                );
            }
        }
        outer.revalidate()?;
        Ok(Self {
            bundle,
            outer,
            artifacts,
            _decode_memory: decode_memory,
        })
    }
    pub(crate) fn core(&self) -> &PreparedCore {
        &self.bundle.core
    }
    pub(crate) fn outer_file(&mut self) -> &mut File {
        &mut self.outer.file
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.outer.revalidate()?;
        for file in &self.artifacts {
            file.revalidate()?;
        }
        Ok(())
    }
    pub(crate) fn verify_original_source(
        &self,
        owner: &mut OfflinePreparedSource,
        scratch: &SourceScratch,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PagedSourceFingerprint> {
        self.revalidate()?;
        let token = owner.owner_token();
        let before = owner.state(events)?;
        ensure!(
            owner.binding().storage == self.bundle.core.source,
            "actual prepared source differs from bundle"
        );
        let operation = (|| -> Result<PagedSourceFingerprint> {
            let fingerprint = self.bundle.core.source_fingerprint.clone().open(scratch)?;
            let length = owner.byte_len();
            ensure!(
                fingerprint.hash_partition_reader(owner, length)? == self.bundle.core.source_sha256,
                "current source metadata/extent fingerprint differs from the Windows-prepared source"
            );
            Ok(fingerprint)
        })();
        // Both closing checks execute even when opening/hashing a fingerprint
        // fails. An error cannot silently skip the held metadata/source bookend.
        let source_closing = owner.state(events);
        let metadata_closing = self.revalidate();
        let closing = (|| -> Result<()> {
            let source = source_closing?;
            metadata_closing?;
            ensure!(
                token.same_owner(&owner.owner_token()) && source.actual == before.actual,
                "actual prepared source changed across fingerprint verification"
            );
            Ok(())
        })();
        match (operation, closing) {
            (Ok(fingerprint), Ok(())) => Ok(fingerprint),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(closing)) => Err(closing),
            (Err(primary), Err(closing)) => Err(primary.context(format!(
                "closing source/artifact verification also failed: {closing:#}"
            ))),
        }
    }
}
