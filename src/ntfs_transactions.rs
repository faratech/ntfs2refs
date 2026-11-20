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
    pub windows_user_marker_records: u64,
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
        |_| Ok(false),
    )
}

fn scope_role_file<F: std::ops::Deref<Target = ntfs::FileInventory>>(
    count: u64,
    get: &mut impl FnMut(u64) -> Result<F>,
    role: &mut impl FnMut(&ntfs::FileInventory) -> Result<Option<String>>,
    wanted: &str,
) -> Result<F> {
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
fn inspect_scope_with<F: std::ops::Deref<Target = ntfs::FileInventory>>(
    count: u64,
    // The row as its owner hands it out: borrowed, its own, or the one a
    // paged source holds shared.
    mut get: impl FnMut(u64) -> Result<F>,
    mut role: impl FnMut(&ntfs::FileInventory) -> Result<Option<String>>,
    mut windows_user: impl FnMut(&ntfs::FileInventory) -> Result<bool>,
) -> Result<Scope> {
    let mut transactional_records = Vec::new();
    let mut windows_user_marker_records = 0u64;
    for ordinal in 0..count {
        let file = get(ordinal)?;
        // LOGGED_UTILITY_STREAM also carries nontransactional metadata such as
        // $DSC storage-class information. Its separate preservation policy must
        // not be confused with a user TxF transaction. Unknown utility streams
        // remain refused by the enclosing source attribute policy.
        let mut attrs = file.attributes.iter().filter(|a| {
            a.type_code == 0x100 && a.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
        });
        let Some(txf) = attrs.next() else { continue };
        if windows_user(&file)? {
            windows_user_marker_records = windows_user_marker_records
                .checked_add(1)
                .context("Windows user TxF marker count overflow")?;
            continue;
        }
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
        windows_user_marker_records,
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
        |i| source.file_shared(i),
        |file| ntfs_admission::paged::internal_role(source, file),
        |_| Ok(false),
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
    #[cfg(windows)]
    #[serde(skip)]
    windows_txf_markers: Option<std::sync::Arc<n2r_win32::windows_txf::VerifiedWindowsTxfMarkers>>,
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
    #[cfg(windows)]
    pub(crate) fn windows_txf_markers_owned(
        &self,
    ) -> Option<std::sync::Arc<n2r_win32::windows_txf::VerifiedWindowsTxfMarkers>> {
        self.windows_txf_markers.clone()
    }
}

#[cfg(windows)]
fn windows_marker_bytes(attribute: &ntfs::AttributeInventory) -> Result<[u8; 56]> {
    ensure!(
        ntfs_admission::recognized_root_txf(attribute) && attribute.total_allocated_size.is_none(),
        "Windows TxF marker storage differs"
    );
    let encoded = attribute
        .resident_metadata_hex
        .as_deref()
        .context("Windows TxF marker resident bytes absent")?;
    ensure!(
        encoded.len() == 112
            && encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Windows TxF marker resident bytes are not exact canonical56-byte evidence"
    );
    let mut bytes = [0u8; 56];
    hex::decode_to_slice(encoded, &mut bytes)?;
    ensure!(
        attribute.resident_sha256.as_deref().is_some_and(|digest| {
            crate::ntfs_attribute_list::resident_digest_matches(digest, &bytes)
        }),
        "Windows TxF marker resident digest differs"
    );
    Ok(bytes)
}

#[cfg(windows)]
fn windows_marker_attribute(
    file: &ntfs::FileInventory,
) -> Result<Option<&ntfs::AttributeInventory>> {
    let mut attributes = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x100 && a.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]);
    let Some(attribute) = attributes.next() else {
        return Ok(None);
    };
    ensure!(
        attributes.next().is_none(),
        "multiple Windows TxF markers at record {}",
        file.record_number
    );
    Ok(Some(attribute))
}

#[cfg(windows)]
fn require_windows_marker_identity(
    source: &ntfs::PagedInspection,
    file: &ntfs::FileInventory,
    bytes: &[u8; 56],
    proof: &n2r_win32::windows_txf::VerifiedWindowsTxfMarkers,
) -> Result<()> {
    ensure!(
        source.is_windows_conversion() && file.sequence_number != 0 && file.record_number < 1 << 48,
        "Windows TxF marker requires actual Windows inspection and exact identity"
    );
    let digest = source.canonical_sha256()?;
    let mut pin = [0u8; 32];
    hex::decode_to_slice(digest, &mut pin)?;
    proof.require_raw_marker_scope(
        proof.binding(),
        pin,
        &n2r_win32::attestation::FileIdentity {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
        },
        bytes,
    )?;
    Ok(())
}

/// Live SDK membership and the held raw56-byte marker must agree. Serialized
/// inventories alone cannot admit a Windows user transaction marker.
#[cfg(windows)]
pub(crate) fn windows_user_marker(
    source: &ntfs::PagedInspection,
    file: &ntfs::FileInventory,
    proof: &n2r_win32::windows_txf::VerifiedWindowsTxfMarkers,
) -> Result<bool> {
    use ntfs::RootFileDomain;
    let Some(attribute) = windows_marker_attribute(file)? else {
        return Ok(false);
    };
    if matches!(
        file.metadata_role,
        ntfs::MetadataRole::ReservedSystemRecord | ntfs::MetadataRole::ExtendDescendantCandidate
    ) {
        return Ok(false);
    }
    ensure!(
        source.is_windows_conversion()
            && file.record_number >= 16
            && file.base_file_reference == 0
            && file.metadata_role == ntfs::MetadataRole::OutsideExtendCandidate
            && file.metadata_role_issue.is_none()
            && !file.is_metadata,
        "unknown Windows user TxF marker scope at record {}",
        file.record_number
    );
    let bytes = windows_marker_bytes(attribute)?;
    let root = source
        .find_record(5, None)?
        .context("Windows TxF root record absent")?;
    ensure!(
        root.is_directory && root.base_file_reference == 0 && root.hard_link_count == 1,
        "Windows TxF root identity/storage differs"
    );
    let root_attribute =
        windows_marker_attribute(&root)?.context("Windows TxF root marker absent")?;
    let root_bytes = windows_marker_bytes(root_attribute)?;
    ensure!(
        bytes[..16] == root_bytes[..16],
        "Windows user TxF marker root/version prefix differs at record {}",
        file.record_number
    );
    require_windows_marker_identity(source, &root, &root_bytes, proof)?;
    require_windows_marker_identity(source, file, &bytes, proof)?;
    Ok(true)
}

#[cfg(windows)]
fn inspect_windows_scope_domain(
    source: &ntfs::PagedInspection,
    proof: &n2r_win32::windows_txf::VerifiedWindowsTxfMarkers,
) -> Result<Scope> {
    use ntfs::RootFileDomain;
    ensure!(
        source.is_windows_conversion(),
        "Windows TxF scope requires actual Windows inspection"
    );
    let scope = inspect_scope_with(
        source.file_count(),
        |i| source.file_shared(i),
        |file| ntfs_admission::paged::internal_role(source, file),
        |file| {
            if file.record_number == 5 {
                let attribute =
                    windows_marker_attribute(file)?.context("Windows TxF root marker absent")?;
                let bytes = windows_marker_bytes(attribute)?;
                require_windows_marker_identity(source, file, &bytes, proof)?;
                Ok(false)
            } else {
                windows_user_marker(source, file, proof)
            }
        },
    )?;
    ensure!(
        u64::try_from(proof.len())?
            == scope
                .windows_user_marker_records
                .checked_add(1)
                .context("Windows TxF native membership count overflow")?,
        "Windows TxF native membership does not cover exact root/user marker domain"
    );
    Ok(scope)
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
        n2r_win32::windows_build::supported(before.windows_version),
        "Windows {} is older than build {}, the first from which this converter accepts its observations of a source",
        n2r_win32::windows_build::describe(before.windows_version),
        n2r_win32::windows_build::MINIMUM_BUILD
    );
    ensure!(
        after.windows_version == before.windows_version
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
        windows_txf_markers: None,
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
    let windows_txf_markers = if source.is_windows_conversion() {
        let proof = observed
            .windows_txf_markers_owned()
            .context("live protected Windows TxF marker witness absent")?;
        ensure!(
            proof.binding() == &before.binding,
            "Windows TxF marker source binding differs"
        );
        Some(proof)
    } else {
        None
    };
    let scope = if let Some(proof) = windows_txf_markers.as_deref() {
        inspect_windows_scope_domain(source, proof)?
    } else {
        inspect_scope_domain(source)?
    };
    let mut result = verify_observations(pin, scope, before, after)?;
    result.windows_txf_markers = windows_txf_markers;
    observed.domain().revalidate()?;
    source.revalidate()?;
    Ok(result)
}

/// Bind the actual offline owner's pre-lock and protected native transaction
/// observations to the complete frozen NTFS model.
#[cfg(windows)]
pub(crate) fn verify_offline_domain(
    source: &ntfs::PagedInspection,
    log: &ntfs_log::VerifiedRestart,
    owner: &mut n2r_win32::offline_environment::OfflineFrozenSource,
    observed: &n2r_win32::offline_environment::OfflinePagedNtfsObservation,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<VerifiedTransactions> {
    use n2r_win32::{attestation::NativeObservationDomain, txf_native::DefaultRmState};
    use ntfs::RootFileDomain;
    let token = owner.owner_token();
    observed.require_owner(&token)?;
    observed.require_admission_evidence()?;
    let opening = owner.state(events)?;
    source.revalidate()?;
    let pin = source.canonical_sha256()?;
    ensure!(
        opening.actual.disk_attributes == 3
            && !opening.source_writer_issued
            && log.binds_domain(source)
            && log.restart.candidate_clean_dismount
            && source.header().dirty == Some(false)
            && observed.domain().header().request.source_inspection_sha256 == pin
            && observed.before().actual == observed.after().actual
            && observed.after().actual == opening.actual,
        "offline transaction evidence does not bind the clean, unchanged frozen source"
    );
    let witness = owner
        .fresh_witness()
        .context("actual pre-lock offline witness absent")?;
    let before = witness
        .before_freeze_txf()
        .context("actual pre-lock TxF facts absent")?;
    let after = observed
        .txf()
        .context("actual protected offline TxF facts absent")?;
    ensure!(
        before.windows_version == [10, 0, 26100]
            && after.windows_version == before.windows_version
            && before.rm_handle_profile == "volume-root-directory-access-time-suppressed"
            && after.rm_handle_profile == "volume-root-directory-physical-disk-read-only"
            && before.native_volume_state_stably_clear
            && after.native_volume_state_stably_clear
            && matches!(
                before.default_rm_state(),
                DefaultRmState::QueriedEmpty | DefaultRmState::Inactive
            )
            && after.default_rm_state() == DefaultRmState::Inactive,
        "offline default RM lacks the actual idle/lock/protected-inactive transition"
    );
    let result = VerifiedTransactions {
        inspection_sha256: pin,
        scope: inspect_scope_domain(source)?,
        default_rm_before: format!("{:?}", before.default_rm_state()),
        default_rm_after: "Inactive".into(),
        lock_dismount_exclusion_observed: opening.original_live_volume_locks_acquired,
        clean_restart_bound: true,
        windows_txf_markers: None,
    };
    ensure!(
        result.lock_dismount_exclusion_observed,
        "actual source locks absent"
    );
    observed.revalidate()?;
    source.revalidate()?;
    ensure!(
        token.same_owner(&owner.owner_token()) && owner.state(events)?.actual == opening.actual,
        "offline source owner changed across transaction reconciliation"
    );
    Ok(result)
}

/// Same default-RM/raw-log reconciliation with an actual selected-partition
/// lifecycle phase, never a fabricated GeneralFreezeObservation.
#[cfg(windows)]
pub(crate) fn verify_partition_domain(
    source: &ntfs::PagedInspection,
    log: &ntfs_log::VerifiedRestart,
    phase: &mut n2r_win32::partition_lifecycle::PartitionReadonlyPhase<'_>,
    observed: &n2r_win32::attestation_partition::PartitionPagedNtfsObservation,
    events: &mut Vec<n2r_win32::NativeEvent>,
) -> Result<VerifiedTransactions> {
    use n2r_win32::{attestation::NativeObservationDomain, txf_native::DefaultRmState};
    use ntfs::RootFileDomain;
    observed.require_phase(phase, events)?;
    source.revalidate()?;
    let pin = source.canonical_sha256()?;
    ensure!(
        log.binds_domain(source)
            && log.restart.candidate_clean_dismount
            && source.header().dirty == Some(false),
        "clean selected-partition restart proof required"
    );
    let before = phase.mounted_ntfs_before_freeze();
    let after = observed.txf().observation();
    ensure!(
        before.binding() == phase.binding()
            && observed.domain().header().request.source_inspection_sha256 == pin,
        "partition transaction observations differ from actual lifecycle source"
    );
    let before = before.observation();
    ensure!(
        n2r_win32::windows_build::supported(before.windows_version),
        "Windows {} is older than build {}, the first from which this converter accepts its observations of a source",
        n2r_win32::windows_build::describe(before.windows_version),
        n2r_win32::windows_build::MINIMUM_BUILD
    );
    ensure!(
        after.windows_version == before.windows_version
            && before.rm_handle_profile == "volume-root-directory-access-time-suppressed"
            && before.native_volume_state_stably_clear
            && after.native_volume_state_stably_clear
            && before.default_rm_state() != DefaultRmState::Unresolved
            && after.rm_handle_profile == "volume-root-directory-selected-partition-read-only"
            && after.default_rm_state() == DefaultRmState::Inactive,
        "partition default RM did not transition through actual lock/dismount to protected inactive state"
    );
    let result = VerifiedTransactions {
        inspection_sha256: pin,
        scope: inspect_scope_domain(source)?,
        default_rm_before: format!("{:?}", before.default_rm_state()),
        default_rm_after: "Inactive".into(),
        lock_dismount_exclusion_observed: true,
        clean_restart_bound: true,
        windows_txf_markers: None,
    };
    observed.require_phase(phase, events)?;
    source.revalidate()?;
    Ok(result)
}
