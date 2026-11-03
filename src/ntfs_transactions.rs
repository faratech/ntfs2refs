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
    inspect_scope_with(
        raw.files.len() as u64,
        |i| Ok(std::borrow::Cow::Borrowed(&raw.files[usize::try_from(i)?])),
        |file| Ok(ntfs_admission::internal_role(raw, file)),
    )
}

fn scope_role_file<'a>(
    count: u64,
    get: &mut impl FnMut(u64) -> Result<std::borrow::Cow<'a, ntfs::FileInventory>>,
    role: &mut impl FnMut(&ntfs::FileInventory) -> Result<Option<String>>,
    wanted: &str,
) -> Result<std::borrow::Cow<'a, ntfs::FileInventory>> {
    let mut found = None;
    for ordinal in 0..count {
        let file = get(ordinal)?;
        if role(&file)?.as_deref() == Some(wanted) {
            ensure!(
                found.is_none(),
                "missing/duplicate default transaction namespace {wanted}"
            );
            found = Some(file);
        }
    }
    found.with_context(|| format!("missing/duplicate default transaction namespace {wanted}"))
}
fn inspect_scope_with<'a>(
    count: u64,
    mut get: impl FnMut(u64) -> Result<std::borrow::Cow<'a, ntfs::FileInventory>>,
    mut role: impl FnMut(&ntfs::FileInventory) -> Result<Option<String>>,
) -> Result<Scope> {
    let mut transactional_records = Vec::new();
    for ordinal in 0..count {
        let file = get(ordinal)?;
        let mut attrs = file.attributes.iter().filter(|a| a.type_code == 0x100);
        let Some(txf) = attrs.next() else { continue };
        ensure!(
            attrs.next().is_none()
                && ntfs_admission::recognized_root_txf(txf)
                && (file.record_number == 5
                    || role(&file)?.as_deref() == Some("$Extend\\$RmMetadata\\$Txf"))
                && file.is_directory
                && file.base_file_reference == 0
                && file.hard_link_count == 1
                && txf
                    .resident_sha256
                    .as_ref()
                    .is_some_and(|hash| n2r_win32::content_digest::is_hex(hash)),
            "user, secondary-RM or unknown transactional metadata at record {}",
            file.record_number
        );
        ensure!(
            transactional_records.len() < 2,
            "initial default-RM metadata pair is incomplete"
        );
        transactional_records.push(file.record_number);
    }
    ensure!(
        transactional_records.len() == 2 && transactional_records.contains(&5),
        "initial default-RM metadata pair is incomplete"
    );
    let mut deferred_directories = Vec::new();
    for wanted in ["$Extend\\$RmMetadata\\$Txf", "$Extend\\$Deleted"] {
        let directory = scope_role_file(count, &mut get, &mut role, wanted)?;
        ensure!(
            directory.is_directory,
            "missing default transaction namespace {wanted}"
        );
        for ordinal in 0..count {
            let child = get(ordinal)?;
            ensure!(
                child
                    .names
                    .iter()
                    .all(|name| name.parent_record_number != directory.record_number),
                "deferred transaction/deletion namespace is not empty: {wanted}"
            );
        }
        deferred_directories.push(directory.record_number);
    }
    let mut default_log_records = Vec::new();
    let mut default_log_stream_sha256 = Vec::new();
    for (wanted, names) in [
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
        let file = scope_role_file(count, &mut get, &mut role, wanted)?;
        ensure!(
            !file.is_directory
                && file.hard_link_count == 1
                && file.base_file_reference == 0
                && file.streams.len() == names.len()
                && file
                    .attributes
                    .iter()
                    .all(|a| matches!(a.type_code, 0x10 | 0x30 | 0x50 | 0x80)
                        && a.flags == 0
                        && a.lowest_vcn == 0),
            "default transaction log metadata exceeds profile: {wanted}"
        );
        for name in names {
            let units: Vec<_> = name.encode_utf16().collect();
            let mut streams = file
                .streams
                .iter()
                .filter(|stream| stream.name_utf16 == units);
            let stream = streams
                .next()
                .context("default transaction log stream absent")?;
            ensure!(
                streams.next().is_none(),
                "default transaction log stream is missing/duplicated: {wanted}:{name}"
            );
            ensure!(
                stream.flags == 0
                    && stream.initialized_size == stream.logical_size
                    && stream.logical_hash_status == ntfs::LogicalHashStatus::Complete,
                "default transaction log stream is incomplete: {wanted}:{name}"
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

#[cfg(windows)]
pub fn inspect_scope_domain(source: &ntfs::PagedInspection) -> Result<Scope> {
    use ntfs::RootFileDomain;
    source.revalidate()?;
    let scope = inspect_scope_with(
        source.file_count(),
        |i| source.file(i).map(std::borrow::Cow::Owned),
        |file| ntfs_admission::paged::internal_role(source, file),
    )?;
    source.revalidate()?;
    Ok(scope)
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
    #[cfg(windows)]
    pub fn binds_domain(&self, source: &ntfs::PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|hash| hash == self.inspection_sha256)
    }
}

#[cfg(windows)]
pub(crate) fn verify(
    raw: &NtfsInspection,
    log: &ntfs_log::VerifiedRestart,
    freeze: &n2r_win32::GeneralFreezeObservation,
    observed: &n2r_win32::GeneralLiveNtfsObservation,
) -> Result<VerifiedTransactions> {
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
    verify_observations(pin, inspect_scope(raw)?, before, after)
}

#[cfg(windows)]
fn verify_observations(
    pin: String,
    scope: Scope,
    before: &n2r_win32::txf_native::GeneralObservation,
    after: &n2r_win32::txf_native::GeneralObservation,
) -> Result<VerifiedTransactions> {
    use n2r_win32::txf_native::DefaultRmState;
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
        scope,
        default_rm_before: format!("{:?}", before.default_rm_state()),
        default_rm_after: "Inactive".into(),
        lock_dismount_exclusion_observed: true,
        clean_restart_bound: true,
    })
}

#[cfg(windows)]
pub(crate) fn verify_domain(
    source: &ntfs::PagedInspection,
    log: &ntfs_log::VerifiedRestart,
    freeze: &n2r_win32::GeneralFreezeObservation,
    observed: &n2r_win32::GeneralLivePagedNtfsObservation,
) -> Result<VerifiedTransactions> {
    use n2r_win32::attestation::NativeObservationDomain;
    use ntfs::RootFileDomain;
    source.revalidate()?;
    let pin = source.canonical_sha256()?;
    ensure!(
        log.binds_domain(source)
            && log.restart.candidate_clean_dismount
            && source.header().dirty == Some(false),
        "clean frozen NTFS restart proof required"
    );
    let before = freeze.mounted_ntfs();
    let after = observed
        .txf()
        .context("protected native transaction observation absent")?;
    ensure!(
        before.binding == after.binding
            && observed.domain().header().request.source_inspection_sha256 == pin
            && observed.before() == observed.after()
            && observed.before().disk_attributes == 3,
        "transaction observations are not bound to the same frozen source"
    );
    let result = verify_observations(pin, inspect_scope_domain(source)?, before, after)?;
    observed.domain().revalidate()?;
    source.revalidate()?;
    Ok(result)
}
