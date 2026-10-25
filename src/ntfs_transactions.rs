//! Initial default-RM freeze policy. A protected mount's inactive RM alone
//! does not prove recovery: require its live pre-freeze state, an actual
//! lock/dismount witness, clean restart pages and a complete bounded scope.
use crate::{
    ntfs_admission,
    ntfs_inspect::{self as ntfs, NtfsInspection},
    ntfs_log,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct Scope {
    pub transactional_records: Vec<u64>,
    pub default_log_records: Vec<u64>,
    pub deferred_directories: Vec<u64>,
    pub default_log_stream_sha256: Vec<String>,
}

/// Diagnostics only. User TxF attributes, secondary RM namespaces, extension
/// records and deferred transaction/deletion objects exceed this profile.
pub fn inspect_scope(raw: &NtfsInspection) -> Result<Scope> {
    let mut transactional_records = Vec::new();
    for file in &raw.files {
        let txf: Vec<_> = file
            .attributes
            .iter()
            .filter(|a| a.type_code == 0x100)
            .collect();
        if txf.is_empty() {
            continue;
        }
        ensure!(
            txf.len() == 1
                && ntfs_admission::recognized_root_txf(txf[0])
                && (file.record_number == 5
                    || ntfs_admission::internal_role(raw, file).as_deref()
                        == Some("$Extend\\$RmMetadata\\$Txf"))
                && file.is_directory
                && file.base_file_reference == 0
                && file.hard_link_count == 1
                && txf[0]
                    .resident_sha256
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 64),
            "user, secondary-RM or unknown transactional metadata at record {}",
            file.record_number
        );
        transactional_records.push(file.record_number);
    }
    ensure!(
        transactional_records.len() == 2 && transactional_records.contains(&5),
        "initial default-RM metadata pair is incomplete"
    );
    let mut deferred_directories = Vec::new();
    for role in ["$Extend\\$RmMetadata\\$Txf", "$Extend\\$Deleted"] {
        let directories: Vec<_> = raw
            .files
            .iter()
            .filter(|f| ntfs_admission::internal_role(raw, f).as_deref() == Some(role))
            .collect();
        ensure!(
            directories.len() == 1 && directories[0].is_directory,
            "missing default transaction namespace {role}"
        );
        let directory = directories[0];
        ensure!(
            raw.files.iter().all(|f| f
                .names
                .iter()
                .all(|name| name.parent_record_number != directory.record_number)),
            "deferred transaction/deletion namespace is not empty: {role}"
        );
        deferred_directories.push(directory.record_number);
    }
    let mut default_log_records = Vec::new();
    let mut default_log_stream_sha256 = Vec::new();
    for (role, expected_names) in [
        ("$Extend\\$RmMetadata\\$TxfLog\\$Tops", vec!["", "$T"]),
        ("$Extend\\$RmMetadata\\$TxfLog\\$TxfLog.blf", vec![""]),
        (
            "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000001",
            vec![""],
        ),
        (
            "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000002",
            vec![""],
        ),
    ] {
        let files: Vec<_> = raw
            .files
            .iter()
            .filter(|f| ntfs_admission::internal_role(raw, f).as_deref() == Some(role))
            .collect();
        ensure!(
            files.len() == 1,
            "missing/duplicate default transaction log {role}"
        );
        let file = files[0];
        ensure!(
            !file.is_directory
                && file.hard_link_count == 1
                && file.base_file_reference == 0
                && file.streams.len() == expected_names.len()
                && file
                    .attributes
                    .iter()
                    .all(|a| matches!(a.type_code, 0x10 | 0x30 | 0x50 | 0x80)
                        && a.flags == 0
                        && a.lowest_vcn == 0),
            "default transaction log metadata exceeds profile: {role}"
        );
        for name in expected_names {
            let units: Vec<_> = name.encode_utf16().collect();
            let streams: Vec<_> = file
                .streams
                .iter()
                .filter(|s| s.name_utf16 == units)
                .collect();
            ensure!(
                streams.len() == 1,
                "default transaction log stream is missing/duplicated: {role}:{name}"
            );
            let stream = streams[0];
            ensure!(
                stream.flags == 0
                    && stream.initialized_size == stream.logical_size
                    && stream.logical_hash_status == ntfs::LogicalHashStatus::Complete,
                "default transaction log stream is incomplete: {role}:{name}"
            );
            default_log_stream_sha256.push(
                stream
                    .logical_sha256
                    .clone()
                    .context("default transaction log stream hash absent")?,
            );
        }
        default_log_records.push(file.record_number);
    }
    Ok(Scope {
        transactional_records,
        default_log_records,
        deferred_directories,
        default_log_stream_sha256,
    })
}

#[derive(Debug, Serialize)]
pub struct VerifiedTransactions {
    inspection_sha256: String,
    pub scope: Scope,
    pub default_rm_before: String,
    pub default_rm_after: String,
    pub lock_dismount_exclusion_observed: bool,
    pub clean_restart_bound: bool,
}
impl VerifiedTransactions {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_sha256)
    }
}

#[cfg(windows)]
pub(crate) fn verify(
    raw: &NtfsInspection,
    log: &ntfs_log::VerifiedRestart,
    freeze: &n2r_win32::GeneralFreezeObservation,
    observed: &n2r_win32::GeneralLiveNtfsObservation,
) -> Result<VerifiedTransactions> {
    use n2r_win32::txf_native::DefaultRmState;
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(raw)?));
    ensure!(
        log.binds(raw) && log.restart.candidate_clean_dismount && raw.dirty == Some(false),
        "clean frozen NTFS restart proof required"
    );
    let before = freeze.mounted_ntfs();
    let after = observed
        .txf()
        .context("protected native transaction observation absent")?;
    ensure!(
        before.binding == after.binding
            && observed.report().request.source_inspection_sha256 == pin,
        "transaction observations are not bound to the same frozen source"
    );
    let before = &before.observation;
    let after = &after.observation;
    ensure!(
        before.windows_version == [10, 0, 26300]
            && after.windows_version == before.windows_version
            && before.rm_handle_profile == "volume-root-directory-access-time-suppressed"
            && before.native_volume_state_stably_clear
            && after.native_volume_state_stably_clear
            && before.default_rm_state() != DefaultRmState::Unresolved
            && after.rm_handle_profile == "volume-root-directory-physical-disk-read-only"
            && after.default_rm_state() == DefaultRmState::Inactive,
        "default RM did not transition from verified idle/inactive through the actual freeze to protected inactive state"
    );
    Ok(VerifiedTransactions {
        inspection_sha256: pin,
        scope: inspect_scope(raw)?,
        default_rm_before: format!("{:?}", before.default_rm_state()),
        default_rm_after: "Inactive".into(),
        lock_dismount_exclusion_observed: true,
        clean_restart_bound: true,
    })
}
