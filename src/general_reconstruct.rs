//! Read-only general source/shadow preparation using the existing durable
//! old/new journal. This module cannot activate or write a target partition.
use crate::{
    lab_native_reconstruct::{identity_hash, partition_hash},
    lab_reconstruct::{self, JournalBinding, JournalSummary},
    ntfs_inspect, refs_inspect,
    retained_compare::{self, RetainedCompareRequest},
};
use anyhow::{Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
    journal_file::{JournalStorageBinding, MAX_JOURNAL_BYTES, observe_journal_file},
    layout::guid_bytes,
};
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub experiment_id: String,
    pub pair: GeneralSourceShadowBinding,
    pub comparison: RetainedCompareRequest,
    pub journal: JournalStorageBinding,
    pub max_journal_bytes: u64,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid general preparation experiment identity"
        );
        self.pair.validate()?;
        self.journal.validate()?;
        retained_compare::validate_request(&self.comparison)?;
        ensure!(
            self.comparison.schema_version == 2
                && self.comparison.sector_size == 4096
                && self.comparison.expected_length == self.pair.source.identity.partition_bytes
                && self.comparison.max_change_bytes <= 256 * 1024 * 1024
                && (1..=MAX_JOURNAL_BYTES).contains(&self.max_journal_bytes),
            "general comparison or journal budget differs"
        );
        for data in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                data.disk_number != self.journal.disk_number
                    && guid_bytes(&data.identity.disk_guid)?
                        != guid_bytes(&self.journal.identity.disk_guid)?
                    && guid_bytes(&data.identity.partition_guid)?
                        != guid_bytes(&self.journal.identity.partition_guid)?
                    && guid_bytes(&data.volume_guid)? != guid_bytes(&self.journal.volume_guid)?,
                "external journal overlaps a data disk"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Preparation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub request: Request,
    pub observed_binding: JournalBinding,
    pub source_before: GeneralDiskState,
    pub source_after: GeneralDiskState,
    pub shadow_before: GeneralDiskState,
    pub shadow_after: GeneralDiskState,
    pub source_ntfs_dirty: Option<bool>,
    pub source_ntfs_volume_flags: Option<u16>,
    pub shadow_refs_version: String,
    pub journal: JournalSummary,
    pub events: Vec<NativeEvent>,
    pub source_admitted: bool,
    pub target_profile_qualified: bool,
    pub execution_authorized: bool,
}

/// The caller owns a fresh exclusive journal file and separately frozen data
/// disks. Successful return supplies a ticket to persist outside the journal;
/// it does not grant authority to activate the target.
pub fn prepare(
    request: &Request,
    source: &mut GeneralFrozenPartition,
    shadow: &mut GeneralFrozenPartition,
    journal: &mut File,
) -> Result<Preparation> {
    request.validate()?;
    ensure!(
        source.binding() == &request.pair.source && shadow.binding() == &request.pair.shadow,
        "actual frozen source/shadow bindings differ"
    );
    let mut events = Vec::new();
    let source_before = source.state(&mut events)?;
    let shadow_before = shadow.state(&mut events)?;
    let journal_before = observe_journal_file(journal, &request.journal)?;
    ensure!(
        journal_before.file_bytes == 0,
        "journal is not a fresh empty file"
    );
    let ntfs = ntfs_inspect::inspect(source, source.byte_len())?;
    let refs = refs_inspect::inspect(shadow, shadow.byte_len())?;
    ensure!(
        ntfs.geometry.cluster_size == 4096
            && refs.geometry.major_version == 3
            && refs.geometry.minor_version == 14
            && refs.geometry.bytes_per_cluster == 4096
            && refs.geometry.volume_bytes == shadow.byte_len(),
        "initial NTFS/ReFS format geometry differs"
    );
    let observed_binding = JournalBinding {
        experiment_id: request.experiment_id.clone(),
        target_identity_sha256: partition_hash(&request.pair.source.identity)?,
        shadow_identity_sha256: partition_hash(&request.pair.shadow.identity)?,
        journal_identity_sha256: identity_hash(
            b"ntfs2refs/general/journal-file-identity/v1",
            &journal_before.identity,
        )?,
    };
    let summary = lab_reconstruct::prepare_journal(
        source,
        shadow,
        journal,
        &request.comparison,
        &observed_binding,
        request.max_journal_bytes,
    )?;
    ensure!(
        summary.expected_postimage_sha256 == request.comparison.shadow_sha256,
        "general prepared postimage differs from frozen ReFS shadow"
    );
    let source_after = source.state(&mut events)?;
    let shadow_after = shadow.state(&mut events)?;
    let journal_after = observe_journal_file(journal, &request.journal)?;
    ensure!(
        source_before == source_after
            && shadow_before == shadow_after
            && journal_before.identity == journal_after.identity
            && journal_after.file_bytes == summary.ticket.journal_length,
        "general data or journal binding changed during preparation"
    );
    Ok(Preparation {
        schema_version: 1,
        kind: "general-frozen-ntfs-refs-journal-preparation",
        request: request.clone(),
        observed_binding,
        source_before,
        source_after,
        shadow_before,
        shadow_after,
        source_ntfs_dirty: ntfs.dirty,
        source_ntfs_volume_flags: ntfs.volume_flags,
        shadow_refs_version: format!(
            "{}.{}",
            refs.geometry.major_version, refs.geometry.minor_version
        ),
        journal: summary,
        events,
        source_admitted: false,
        target_profile_qualified: false,
        execution_authorized: false,
    })
}
