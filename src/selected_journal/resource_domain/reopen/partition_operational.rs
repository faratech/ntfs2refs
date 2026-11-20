//! Metadata/J-only idempotent reconciliation after actual Basic0 publication.
//! Current source files never enter an OLD/NEW/image/map comparison.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_operational_partition(
    mut source: n2r_win32::partition_restoration::PartitionOperationalTerminal,
    path: &Path,
    publication_sha: [u8; 32],
    maximum_publication_bytes: u64,
    expected_shadow: &GeneralDiskBinding,
    expected_journal: &GeneralJournalStorageBinding,
    group: &ArtifactGroupPermit,
    scratch: &SourceScratch,
    index_path: &Path,
    maximum_index_bytes: u64,
    requested_kind: n2r_win32::PartitionTerminalKind,
    observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> Result<serde_json::Value> {
    ensure!(
        group.group() == ArtifactGroup::RecoveryCopy
            && maximum_publication_bytes > 0
            && maximum_publication_bytes <= scratch.budget().record_bytes,
        "operational reconciliation requires bounded actual recovery scratch"
    );
    let actual_group = scratch
        .artifact_group()
        .context("operational recovery arena absent")?;
    ensure!(
        actual_group.group() == group.group() && actual_group.arena().same_arena(group.arena()),
        "operational recovery scratch/group differs"
    );
    source.revalidate(observer, events)?;
    let size = std::fs::symlink_metadata(path)?.len();
    ensure!(
        size > 0 && size <= maximum_publication_bytes,
        "operational publication exceeds its actual read bound"
    );
    let _memory = scratch.lease_ram(
        size.checked_mul(4)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .context("operational publication RAM overflow")?,
    )?;
    let mut publication_file = HeldFile::open(
        path,
        publication_sha,
        Some(size),
        maximum_publication_bytes,
        scratch,
    )?;
    publication_file.file.seek(SeekFrom::Start(0))?;
    let publication: Publication = serde_json::from_reader(&mut publication_file.file)?;
    adopt_review(publication.review_before_handoff, false)?;
    let mut canonical = HashSink {
        bytes: 0,
        maximum: size,
        hash: Sha256::new(),
    };
    serde_json::to_writer(&mut canonical, &publication)?;
    ensure!(
        canonical.bytes == size && <[u8; 32]>::from(canonical.hash.finalize()) == publication_sha,
        "operational publication is not exact canonical independently pinned bytes"
    );
    publication
        .source_scope
        .require_envelope_version(publication.schema_version, &publication.kind)?;
    let explicit = match &publication.source_scope {
        super::super::source_scope::ResourceRecoverySourceScope::Partition(scope) => scope,
        _ => anyhow::bail!("operational reconciliation requires explicit partition-v2 publication"),
    };
    ensure!(
        explicit.binding == *source.binding()
            && publication.source == source.binding().storage
            && &publication.shadow == expected_shadow
            && !publication.serialized_publication_grants_authority
            && publication.early_preparation_guard.is_none()
            && explicit.original_attributes == 0,
        "operational publication does not name this actual Basic0 source"
    );
    let original = &explicit.complete_preparation_guard.original_partition_info;
    let current = source.native_partition_info();
    ensure!(
        original.len() == 144 && current.len() == 144 && current[32..64] == original[32..64],
        "operational native target type/partition identity differs from original publication"
    );
    publication.resource_admission.validate()?;
    expected_shadow.validate()?;
    ensure!(
        expected_shadow.disk_number != source.binding().storage.disk_number
            && n2r_win32::layout::guid_bytes(&expected_shadow.identity.disk_guid)?
                != n2r_win32::layout::guid_bytes(&source.binding().storage.identity.disk_guid)?,
        "original shadow routing aliases actual operational source"
    );
    let mut locator = DurableRecoveryLocator::open_observed(
        Path::new(&publication.locator.path),
        digest(&publication.locator.sha256)?,
        scratch,
        publication.locator.bytes,
    )?;
    ensure!(
        locator.source_scope() == &publication.source_scope
            && locator.source() == &publication.source
            && locator.journal_binding() == expected_journal
            && locator.snapshot().file_bytes == publication.locator.bytes
            && hex::encode(Sha256::digest(serde_json::to_vec(locator.ticket())?))
                == publication.ticket_sha256
            && locator.ticket().marker_profile.is_none()
            && locator.marker_use()
                == n2r_win32::journal_file::MarkerStorageUse::QualifiedProduction,
        "operational publication/locator/ticket identity differs"
    );
    publication
        .source_scope
        .require_journal_route(&publication.source, expected_journal)?;
    let (mut journal, _) = BoundNativeRecoveryJournal::open(
        locator.journal_path(),
        expected_journal,
        locator.journal_profile()?,
        locator.ticket(),
        None,
        locator.marker_use(),
    )?;
    {
        let (_, facts) = journal.split_for_observation()?;
        ensure!(
            facts.binding == locator.journal_binding()
                && *facts.identity == locator.journal_identity()
                && facts.path == locator.journal_path()
                && facts.profile == locator.journal_profile()?
                && facts.marker_use == locator.marker_use()
                && facts.marker_native_qualified.is_none(),
            "operational actual held journal differs from original pinned locator"
        );
    }
    require_operational_artifacts(
        &source,
        &publication.source_scope,
        &mut journal,
        &[&publication_file.snapshot, locator.snapshot()],
        observer,
        events,
    )?;
    // This scanner authenticates the complete immutable J/header/descriptor/
    // payload/index wire bytes. It takes NO source reader or image argument.
    let mut observed = BoundJournalObservation::open(
        &mut journal,
        locator.ticket(),
        group,
        scratch,
        index_path,
        maximum_index_bytes,
    )?;
    let lifecycle = observed.lifecycle()?;
    let kind = match lifecycle {
        SelectedLifecycle::Handoff => n2r_win32::PartitionTerminalKind::Handoff,
        SelectedLifecycle::Aborted => n2r_win32::PartitionTerminalKind::Aborted,
        _ => anyhow::bail!(
            "operational Basic0 admits canonical closed HND/ABT only; AP/RB/clear cannot reconcile or replay here"
        ),
    };
    ensure!(
        kind == requested_kind,
        "requested direction conflicts with actual terminal state; raw replay is permanently closed"
    );
    source.require_closed_kind(kind)?;
    let first = observed.observation.record(0)?;
    ensure!(
        first.offset == 0 && first.length >= 512,
        "closed journal lacks authenticated discovery0 epoch contract"
    );
    let payload = if kind == n2r_win32::PartitionTerminalKind::Handoff {
        ensure!(
            first.new_kind == 0,
            "HND target epoch contract unavailable: authenticated discovery NEW is not literal; refusing operational reconciliation"
        );
        first.new_payload
    } else {
        ensure!(
            first.old_kind == 0,
            "ABT original epoch contract unavailable: authenticated discovery OLD is not literal; refusing operational reconciliation"
        );
        first.old_payload
    };
    let mut saved_boot = [0u8; 512];
    crate::selected_journal::at(observed.observation.journal, payload, &mut saved_boot)?;
    let expected_epoch = epoch(&saved_boot, locator.ticket().image_length, kind)?;
    let current_epoch = epoch(
        &source.discovery_metadata()?,
        locator.ticket().image_length,
        kind,
    )?;
    ensure!(
        current_epoch == expected_epoch,
        "current filesystem epoch/geometry differs from authenticated journal discovery metadata; refusing a reformatted or unsupported volume"
    );
    source.revalidate(observer, events)?;
    let metadata = source.current_metadata()?;
    ensure!(
        observed.lifecycle()? == lifecycle,
        "actual closed lifecycle changed during operational observation"
    );
    // No SDK ClosedJournalObservation is fabricated: that separate capability
    // proves historical source OLD/NEW and must never authorize this lane.
    drop(observed);
    publication_file.revalidate(scratch)?;
    locator.revalidate()?;
    journal.revalidate()?;
    require_operational_artifacts(
        &source,
        &publication.source_scope,
        &mut journal,
        &[&publication_file.snapshot, locator.snapshot()],
        observer,
        events,
    )?;
    source.revalidate(observer, events)?;
    let closing_epoch = epoch(
        &source.discovery_metadata()?,
        locator.ticket().image_length,
        kind,
    )?;
    ensure!(
        closing_epoch == expected_epoch,
        "operational filesystem epoch/geometry changed during reconciliation"
    );
    let after = source.current_metadata()?;
    observer.checkpoint_native_events("partition-operational-closed-no-replay-verified", events)?;
    ensure!(
        events.is_empty(),
        "operational observer did not preserve/drain actual native events"
    );
    Ok(
        serde_json::json!({"kind":"partition-operational-closed-reconciliation-v1","success":true,
        "terminal":if kind==n2r_win32::PartitionTerminalKind::Handoff{"HND"}else{"ABT"},
        "raw_replay_performed":false,"source_writer_issued":false,"lifecycle_marker_written":false,
        "partition_or_label_or_mount_setters_issued":false,"current_contents_reverified":false,
        "conversion_time_expected_or_maps_compared":false,"original_conversion_contents_proved":false,
        "current_contents_preserved_by_no_source_writes":true,
        "before_metadata":metadata,"after_metadata":after,
            "filesystem_epoch":expected_epoch,"filesystem_epoch_from_authenticated_literal_discovery":true,
            "source_binding":source.binding(),"recovery_files_retired":false,"stable_release_qualification":false}),
    )
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct FilesystemEpoch {
    filesystem: &'static str,
    serial_u64_hex: String,
    bytes_per_sector: u32,
    bytes_per_cluster: u32,
    total_sectors: u64,
    refs_version: Option<[u8; 2]>,
}
fn epoch(
    bytes: &[u8],
    partition_bytes: u64,
    kind: n2r_win32::PartitionTerminalKind,
) -> Result<FilesystemEpoch> {
    if kind == n2r_win32::PartitionTerminalKind::Handoff {
        let geometry = crate::refs_inspect::inspect_boot_sector(bytes, partition_bytes)?;
        ensure!(
            geometry.recognition_checksum == crate::refs_bootstrap::vbr_checksum(bytes)?,
            "ReFS discovery metadata checksum differs"
        );
        Ok(FilesystemEpoch {
            filesystem: "ReFS",
            serial_u64_hex: format!("{:016x}", geometry.volume_serial),
            bytes_per_sector: geometry.bytes_per_sector,
            bytes_per_cluster: geometry.bytes_per_cluster,
            total_sectors: geometry.total_sectors,
            refs_version: Some([geometry.major_version, geometry.minor_version]),
        })
    } else {
        let geometry = crate::ntfs_inspect::inspect_boot_sector(bytes, partition_bytes)?;
        Ok(FilesystemEpoch {
            filesystem: "NTFS",
            serial_u64_hex: format!("{:016x}", geometry.serial_number),
            bytes_per_sector: u32::from(geometry.bytes_per_sector),
            bytes_per_cluster: geometry.cluster_size,
            total_sectors: geometry.total_sectors,
            refs_version: None,
        })
    }
}

fn require_operational_artifacts(
    source: &n2r_win32::partition_restoration::PartitionOperationalTerminal,
    scope: &super::super::source_scope::ResourceRecoverySourceScope,
    journal: &mut BoundNativeRecoveryJournal,
    artifacts: &[&ReferenceFileSnapshot],
    observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> Result<()> {
    source.revalidate(observer, events)?;
    let (actual, facts) = journal.split_for_observation()?;
    scope.require_journal_route(&source.binding().storage, facts.binding)?;
    let observed = n2r_win32::journal_file::observe_general_journal_file_with_profile(
        actual.markerless_recovery_file()?,
        facts.binding,
        facts.profile,
    )?;
    let windows = source.windows_volume();
    ensure!(
        observed.identity == *facts.identity
            && observed.file_bytes == facts.journal_length
            && observed.disk_number == windows.disk_number
            && observed.identity.partition_offset == windows.offset
            && observed.identity.partition_bytes == windows.length,
        "operational actual journal is not on current native Windows sibling volume"
    );
    let volume = facts.binding.disk.volume_path()?;
    for artifact in artifacts {
        ensure!(
            on_volume(&artifact.final_path, &volume)
                && artifact.volume_serial_number == observed.identity.volume_serial_number
                && artifact.number_of_links == 1,
            "operational publication/locator is not an actual held ordinary journal-volume artifact"
        );
    }
    source.revalidate(observer, events)?;
    Ok(())
}
