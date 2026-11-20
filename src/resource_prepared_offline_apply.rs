//! Owning cold consumer for the new Windows-prepared bundle protocol.
//! No live Windows NTFS admission is recreated in PE. Authenticated historical
//! READY metadata, current physical source fingerprint, self-contained J and
//! native persistent boot protection remain separate actual capabilities.
use crate::{
    artifact_arena::{ArtifactGroupPermit, ArtifactLease},
    general_reconstruct::selected_native_journal::BoundNativeRecoveryJournal,
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
    resource_prepared_bundle::HeldWindowsPreparedBundle,
    selected_journal::{
        SelectedResult, SelectedTicket,
        resource_domain::reopen::{BoundJournalObservation, PreparedOfflineRun},
    },
    source_fingerprint::resource::PagedSourceFingerprint,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    HeldPagedWritePolicy, NativeEvent, PagedRecoveryPins,
    offline_environment::{
        OfflinePreparedAvailableSource, OfflinePreparedClosedQualification,
        OfflinePreparedJournalQualification, OfflinePreparedReplayQualification,
        OfflinePreparedSource, OfflinePreparedTerminalSource, OfflineSourceOwnerToken,
    },
    recovery_boot::{RecoveryBootBudget, RecoveryBootGuard},
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[path = "resource_prepared_pause.rs"]
mod controlled_pause;
pub(crate) use controlled_pause::{PreparedPostFlushReceipt, wait as wait_postflush_pause};
pub(crate) const CONTROLLED_PAUSE_RAM_BYTES: u64 = 512 * 1024;
pub(crate) const CONTROLLED_PAUSE_EVIDENCE_BYTES: u64 = 1024 * 1024;
pub(crate) struct PreparedOfflineBootRequest {
    /// Explicit metadata-only repair after authenticated HND/allNEW or
    /// ABT/restoredOLD. This mode can never enter apply or mixed replay.
    pub(crate) closed_only_boot_repair: bool,
    /// Updated helper may recover only an actually classified current AP/RB.
    pub(crate) interrupted_recovery_boot_repair: bool,
    pub(crate) postflush_pause_nonce: Option<String>,
    pub(crate) intent_path: PathBuf,
    pub(crate) intent_sha256: [u8; 32],
    pub(crate) output: PathBuf,
    pub(crate) budget: RecoveryBootBudget,
}
impl PreparedOfflineBootRequest {
    pub(crate) fn validate_control(&self) -> Result<()> {
        ensure!(
            !(self.closed_only_boot_repair && self.interrupted_recovery_boot_repair),
            "closed-only and interrupted-recovery helper modes are exclusive"
        );
        ensure!(
            !self.closed_only_boot_repair || self.postflush_pause_nonce.is_none(),
            "closed-only boot repair cannot request a data-writer pause"
        );
        if let Some(nonce) = &self.postflush_pause_nonce {
            controlled_pause::require_nonce(nonce)?;
        }
        Ok(())
    }
}
/// Current proof is issued from actual held bundle + current raw fingerprint,
/// never from a decoded READY flag or a fabricated preboot native witness.
/// Windows readiness is authenticated producer evidence, not fresh PE NTFS.
pub(crate) struct PreparedReadinessCertificate {
    owner: OfflineSourceOwnerToken,
    outer_sha256: [u8; 32],
    outer_identity: n2r_win32::reference_file::ReferenceFileSnapshot,
    ticket_sha256: [u8; 32],
    index_sha256: [u8; 32],
    fingerprint: PagedSourceFingerprint,
}
fn ticket_pin(ticket: &SelectedTicket) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(ticket)?;
    ensure!(bytes.len() <= 4096, "prepared ticket exceeds bound");
    Ok(Sha256::digest(bytes).into())
}
impl PreparedReadinessCertificate {
    pub(crate) fn qualify(
        bundle: &HeldWindowsPreparedBundle,
        source: &mut OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        ticket: &SelectedTicket,
        scratch: &SourceScratch,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        bundle.require_ready_artifacts()?;
        let facts = policy.facts()?;
        let core = bundle.core();
        let original_index = core
            .artifacts
            .iter()
            .find(|p| p.role == "native-write-index")
            .context("actual Windows index pin absent")?;
        ensure!(
            original_index.sha256 == hex::encode(facts.index_sha256),
            "actual reopened J index differs from the exact Windows semantic-ready index"
        );
        ensure!(
            source.binding().storage == core.source
                && ticket_pin(ticket)? == ticket_pin(&core.ticket)?
                && ticket.marker_profile.is_none()
                && facts.image_length == ticket.image_length
                && facts.selected_bytes == ticket.selected_bytes
                && facts.range_count == ticket.range_count
                && facts.journal_length == ticket.journal_length
                && facts.journal_immutable_sha256 == ticket.immutable_sha256
                && (1..=5).contains(&facts.format_version),
            "actual prepared source/scanned J/index does not match the authenticated Windows readiness domain"
        );
        // This method checks current source metadata/covered extents only;
        // complete selected OLD and source-free digests are independently
        // checked by the actual SDK qualification immediately before AP.
        let fingerprint = bundle.verify_original_source(source, scratch, events)?;
        let proof = Self {
            owner: source.owner_token(),
            outer_sha256: bundle.outer_sha256(),
            outer_identity: bundle.outer_snapshot().clone(),
            ticket_sha256: ticket_pin(ticket)?,
            index_sha256: facts.index_sha256,
            fingerprint,
        };
        proof.require_binding(bundle, source, policy, ticket)?;
        Ok(proof)
    }
    pub(crate) fn require_binding(
        &self,
        bundle: &HeldWindowsPreparedBundle,
        source: &OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        bundle.require_ready_artifacts()?;
        self.fingerprint.revalidate()?;
        policy.revalidate()?;
        ensure!(
            self.owner.same_owner(&source.owner_token())
                && source.binding().storage == bundle.core().source
                && bundle.outer_sha256() == self.outer_sha256
                && bundle.outer_snapshot() == &self.outer_identity
                && self.ticket_sha256 == ticket_pin(ticket)?
                && policy.facts()?.index_sha256 == self.index_sha256,
            "cold readiness lost actual source/bundle/fingerprint/index owners"
        );
        Ok(())
    }
}
/// Actual new-protocol recovery readiness: authenticated Windows READY plus
/// current opaque SDK mixed/J qualification. Never the stale NTFS fingerprint.
pub(crate) struct PreparedRecoveryReadiness {
    owner: OfflineSourceOwnerToken,
    outer_sha256: [u8; 32],
    outer_identity: n2r_win32::reference_file::ReferenceFileSnapshot,
    ticket_sha256: [u8; 32],
    index_sha256: [u8; 32],
}
impl PreparedRecoveryReadiness {
    pub(crate) fn qualify(
        bundle: &HeldWindowsPreparedBundle,
        source: &OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        ticket: &SelectedTicket,
        qualification: &OfflinePreparedReplayQualification,
    ) -> Result<Self> {
        bundle.require_ready_artifacts()?;
        qualification.require_owner(&source.owner_token())?;
        let facts = policy.facts()?;
        let requirements = qualification.boot_guard_requirements();
        let old_index = bundle
            .core()
            .artifacts
            .iter()
            .find(|p| p.role == "native-write-index")
            .context("Windows prepared index absent")?;
        ensure!(
            requirements.source == *source.binding()
                && source.binding().storage == bundle.core().source
                && requirements.sealed_publication_sha256 == bundle.outer_sha256()
                && (requirements.source_was_already_offline_on_enrollment
                    || requirements.actual_current_boot_volume_locks_acquired)
                && requirements.actual_excluded_disk_attributes == 3
                && facts.index_sha256 == requirements.index_sha256
                && old_index.sha256 == hex::encode(facts.index_sha256)
                && ticket_pin(ticket)? == ticket_pin(&bundle.core().ticket)?,
            "actual CURRENT recovery scope differs from authenticated Windows/J owners"
        );
        Ok(Self {
            owner: source.owner_token(),
            outer_sha256: bundle.outer_sha256(),
            outer_identity: bundle.outer_snapshot().clone(),
            ticket_sha256: ticket_pin(ticket)?,
            index_sha256: facts.index_sha256,
        })
    }
    pub(crate) fn qualify_closed(
        bundle: &HeldWindowsPreparedBundle,
        source: &OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        ticket: &SelectedTicket,
        qualification: &OfflinePreparedClosedQualification,
    ) -> Result<Self> {
        bundle.require_ready_artifacts()?;
        qualification.require_owner(&source.owner_token())?;
        let facts = policy.facts()?;
        let requirements = qualification.boot_guard_requirements();
        let old_index = bundle
            .core()
            .artifacts
            .iter()
            .find(|p| p.role == "native-write-index")
            .context("Windows prepared index absent")?;
        ensure!(
            requirements.source == *source.binding()
                && source.binding().storage == bundle.core().source
                && requirements.sealed_publication_sha256 == bundle.outer_sha256()
                && (requirements.source_was_already_offline_on_enrollment
                    || requirements.actual_current_boot_volume_locks_acquired)
                && requirements.actual_excluded_disk_attributes == 3
                && facts.index_sha256 == requirements.index_sha256
                && old_index.sha256 == hex::encode(facts.index_sha256)
                && ticket_pin(ticket)? == ticket_pin(&bundle.core().ticket)?,
            "actual CURRENT recovery scope differs from authenticated Windows/J owners"
        );
        Ok(Self {
            owner: source.owner_token(),
            outer_sha256: bundle.outer_sha256(),
            outer_identity: bundle.outer_snapshot().clone(),
            ticket_sha256: ticket_pin(ticket)?,
            index_sha256: facts.index_sha256,
        })
    }
    pub(crate) fn require_binding(
        &self,
        bundle: &HeldWindowsPreparedBundle,
        source: &OfflinePreparedSource,
        policy: &HeldPagedWritePolicy,
        ticket: &SelectedTicket,
    ) -> Result<()> {
        bundle.require_ready_artifacts()?;
        policy.revalidate()?;
        ensure!(
            self.owner.same_owner(&source.owner_token())
                && source.binding().storage == bundle.core().source
                && self.outer_sha256 == bundle.outer_sha256()
                && &self.outer_identity == bundle.outer_snapshot()
                && self.ticket_sha256 == ticket_pin(ticket)?
                && self.index_sha256 == policy.facts()?.index_sha256,
            "CURRENT recovery readiness lost actual bundle/source/index owners"
        );
        Ok(())
    }
}
enum PreparedTerminalQualification {
    Fresh(OfflinePreparedJournalQualification),
    Replay(OfflinePreparedReplayQualification),
    Closed,
}
enum PreparedTerminalReadiness {
    Fresh(PreparedReadinessCertificate),
    Replay(PreparedRecoveryReadiness),
    Closed(PreparedRecoveryReadiness),
}
/// HND/ABT is closed. Actual J/expected/maps/bundle/index/boot owners all remain
/// retained. Source has no writer, replay, File or raw-handle interface.
pub(crate) struct PreparedOfflineHandoff {
    pub(crate) bundle: HeldWindowsPreparedBundle,
    pub(crate) source: OfflinePreparedTerminalSource,
    pub(crate) journal: BoundNativeRecoveryJournal,
    pub(crate) boot: RecoveryBootGuard,
    pub(crate) policy: HeldPagedWritePolicy,
    pub(crate) index_owner: ArtifactLease,
    pub(crate) selected: SelectedResult,
    pub(crate) native_bytes_written: u64,
    qualification: PreparedTerminalQualification,
    _readiness: PreparedTerminalReadiness,
    _memory: SourceRamLease,
}
/// Positive closed-only availability, still source BASIC+READONLY. Native
/// metadata verification/BCD restoration must use this actual owner, not DTOs.
pub(crate) struct PreparedOfflineAvailable {
    pub(crate) bundle: HeldWindowsPreparedBundle,
    pub(crate) source: OfflinePreparedAvailableSource,
    pub(crate) journal: BoundNativeRecoveryJournal,
    pub(crate) boot: RecoveryBootGuard,
    pub(crate) policy: HeldPagedWritePolicy,
    pub(crate) index_owner: ArtifactLease,
    pub(crate) selected: SelectedResult,
    pub(crate) native_bytes_written: u64,
    _qualification: PreparedTerminalQualification,
    _readiness: PreparedTerminalReadiness,
    _memory: SourceRamLease,
}
impl PreparedOfflineHandoff {
    /// No boot selection or source GPT changes here. SDK proves closed HND,
    /// removes every source writer and only then makes the physical disk
    /// available with target BASIC+READONLY unchanged for metadata operations.
    pub(crate) fn into_available(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<PreparedOfflineAvailable> {
        self.bundle.revalidate()?;
        self.index_owner.revalidate()?;
        self.policy.revalidate()?;
        self.journal.revalidate()?;
        let ticket = self.bundle.core().ticket.clone();
        let (native, facts) = self.journal.split_for_observation()?;
        let pins = PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        let source = native.make_offline_prepared_available(
            self.source,
            &self.policy,
            &pins,
            &mut self.boot,
            events,
        )?;
        self.bundle.revalidate()?;
        Ok(PreparedOfflineAvailable {
            bundle: self.bundle,
            source,
            journal: self.journal,
            boot: self.boot,
            policy: self.policy,
            index_owner: self.index_owner,
            selected: self.selected,
            native_bytes_written: self.native_bytes_written,
            _qualification: self.qualification,
            _readiness: self._readiness,
            _memory: self._memory,
        })
    }
}
/// Actual owners enter together. No request path, JSON flag or publication
/// alone can invoke a source write. Caller owns independent-J output admission
/// and durably drains native events. Failure preserves all durable artifacts,
/// persistent recovery selection and source exclusion; no automatic retry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_prepared(
    mut bundle: HeldWindowsPreparedBundle,
    mut source: OfflinePreparedSource,
    mut journal: BoundNativeRecoveryJournal,
    group: &ArtifactGroupPermit,
    scratch: &SourceScratch,
    index_path: &Path,
    max_index_bytes: u64,
    boot_request: &PreparedOfflineBootRequest,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PreparedOfflineHandoff> {
    ensure!(
        !boot_request.closed_only_boot_repair && !boot_request.interrupted_recovery_boot_repair,
        "closed-only boot repair cannot apply source patches or activate a journal"
    );
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "opening prepared checkpoint did not drain"
    );
    bundle.require_ready_artifacts()?;
    journal.revalidate()?;
    let ticket = bundle.core().ticket.clone();
    {
        let (_native, facts) = journal.split_for_observation()?;
        let core = bundle.core();
        ensure!(
            facts.binding == &core.journal_binding
                && facts.identity == &core.journal_identity
                && facts.path == core.journal_path.as_path()
                && facts.journal_length == ticket.journal_length
                && facts.profile.version() == core.journal_profile_version
                && facts.profile.max_journal_bytes() == core.journal_profile_max_bytes
                && facts.marker_native_qualified.is_none(),
            "actual exclusively held J differs from Windows sealed bundle"
        );
    }
    let observation = BoundJournalObservation::open(
        &mut journal,
        &ticket,
        group,
        scratch,
        index_path,
        max_index_bytes,
    )?;
    let PreparedOfflineRun {
        selected,
        qualification,
        mut boot,
        closed,
        policy,
        index_owner,
        readiness,
        memory,
        native_bytes_written,
    } = observation.execute_windows_prepared(
        &mut bundle,
        &mut source,
        scratch,
        boot_request,
        events,
        |events| checkpoint(events),
    )?;
    // HND/current NEW has already been authenticated. Never run original
    // NTFS/fingerprint/allOLD checks when consuming the terminal source.
    let terminal = {
        let (native, facts) = journal.split_for_observation()?;
        let pins = PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        native.into_offline_prepared_terminal(
            source,
            closed,
            &policy,
            &pins,
            &mut boot,
            bundle.outer_file(),
            &qualification,
            events,
        )?
    };
    bundle.revalidate()?;
    index_owner.revalidate()?;
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "terminal prepared checkpoint did not drain"
    );
    Ok(PreparedOfflineHandoff {
        bundle,
        source: terminal,
        journal,
        boot,
        policy,
        index_owner,
        selected,
        native_bytes_written,
        qualification: PreparedTerminalQualification::Fresh(qualification),
        _readiness: PreparedTerminalReadiness::Fresh(readiness),
        _memory: memory,
    })
}

/// New-protocol CURRENT AP/RB resume or rollback. This entry never calls
/// verify_original_source and never interprets a missing artifact as no AP.
#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_prepared(
    mut bundle: HeldWindowsPreparedBundle,
    mut source: OfflinePreparedSource,
    mut journal: BoundNativeRecoveryJournal,
    group: &ArtifactGroupPermit,
    scratch: &SourceScratch,
    index_path: &Path,
    max_index_bytes: u64,
    direction: n2r_win32::PagedRecoveryDirection,
    boot_request: &PreparedOfflineBootRequest,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PreparedOfflineHandoff> {
    boot_request.validate_control()?;
    ensure!(
        !boot_request.closed_only_boot_repair,
        "closed-only boot repair cannot resume or roll back source patches"
    );
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "opening prepared checkpoint did not drain"
    );
    bundle.require_ready_artifacts()?;
    journal.revalidate()?;
    let ticket = bundle.core().ticket.clone();
    {
        let (_native, facts) = journal.split_for_observation()?;
        let core = bundle.core();
        ensure!(
            facts.binding == &core.journal_binding
                && facts.identity == &core.journal_identity
                && facts.path == core.journal_path.as_path()
                && facts.journal_length == ticket.journal_length
                && facts.profile.version() == core.journal_profile_version
                && facts.profile.max_journal_bytes() == core.journal_profile_max_bytes
                && facts.marker_native_qualified.is_none(),
            "actual exclusively held J differs from Windows sealed bundle"
        );
    }
    let observation = BoundJournalObservation::open(
        &mut journal,
        &ticket,
        group,
        scratch,
        index_path,
        max_index_bytes,
    )?;
    let crate::selected_journal::resource_domain::reopen::PreparedOfflineReplayRun {
        selected,
        qualification,
        mut boot,
        closed,
        policy,
        index_owner,
        readiness,
        memory,
        native_bytes_written,
    } = observation.replay_windows_prepared(
        &mut bundle,
        &mut source,
        direction,
        boot_request,
        events,
        |events| checkpoint(events),
    )?;
    // Actual HND/NEW or ABT/restoredOLD has been authenticated. Never run original
    // NTFS/fingerprint/allOLD checks when consuming the terminal source.
    let terminal = {
        let (native, facts) = journal.split_for_observation()?;
        let pins = PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        native.into_offline_prepared_replay_terminal(
            source,
            closed,
            &policy,
            &pins,
            &mut boot,
            bundle.outer_file(),
            &qualification,
            events,
        )?
    };
    bundle.revalidate()?;
    index_owner.revalidate()?;
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "terminal prepared checkpoint did not drain"
    );
    Ok(PreparedOfflineHandoff {
        bundle,
        source: terminal,
        journal,
        boot,
        policy,
        index_owner,
        selected,
        native_bytes_written,
        qualification: PreparedTerminalQualification::Replay(qualification),
        _readiness: PreparedTerminalReadiness::Replay(readiness),
        _memory: memory,
    })
}

/// Reopen actual closed HND/ABT before final writable restoration. No source
/// writes, marker mutation or replay occurs; data still BASIC+READONLY.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_prepared_closed(
    mut bundle: HeldWindowsPreparedBundle,
    mut source: OfflinePreparedSource,
    mut journal: BoundNativeRecoveryJournal,
    group: &ArtifactGroupPermit,
    scratch: &SourceScratch,
    index_path: &Path,
    max_index_bytes: u64,
    boot_request: &PreparedOfflineBootRequest,
    events: &mut Vec<NativeEvent>,
    mut checkpoint: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
) -> Result<PreparedOfflineHandoff> {
    boot_request.validate_control()?;
    ensure!(
        !boot_request.interrupted_recovery_boot_repair,
        "interrupted recovery helper cannot adopt an already closed journal"
    );
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "opening prepared checkpoint did not drain"
    );
    bundle.require_ready_artifacts()?;
    journal.revalidate()?;
    let ticket = bundle.core().ticket.clone();
    {
        let (_native, facts) = journal.split_for_observation()?;
        let core = bundle.core();
        ensure!(
            facts.binding == &core.journal_binding
                && facts.identity == &core.journal_identity
                && facts.path == core.journal_path.as_path()
                && facts.journal_length == ticket.journal_length
                && facts.profile.version() == core.journal_profile_version
                && facts.profile.max_journal_bytes() == core.journal_profile_max_bytes
                && facts.marker_native_qualified.is_none(),
            "actual exclusively held J differs from Windows sealed bundle"
        );
    }
    let observation = BoundJournalObservation::open(
        &mut journal,
        &ticket,
        group,
        scratch,
        index_path,
        max_index_bytes,
    )?;
    let crate::selected_journal::resource_domain::reopen::PreparedOfflineClosedRun {
        selected,
        qualification,
        mut boot,
        policy,
        index_owner,
        readiness,
        memory,
    } = observation.observe_windows_prepared_closed(
        &mut bundle,
        &mut source,
        boot_request,
        events,
        |events| checkpoint(events),
    )?;
    // HND/current NEW has already been authenticated. Never run original
    // NTFS/fingerprint/allOLD checks when consuming the terminal source.
    let terminal = {
        let (native, facts) = journal.split_for_observation()?;
        let pins = PagedRecoveryPins {
            journal_binding: facts.binding,
            journal_identity: facts.identity,
            journal_path: facts.path,
            journal_profile: facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        native.into_offline_prepared_closed_terminal(
            source,
            &policy,
            &pins,
            &mut boot,
            bundle.outer_file(),
            qualification,
            events,
        )?
    };
    bundle.revalidate()?;
    index_owner.revalidate()?;
    checkpoint(events)?;
    ensure!(
        events.is_empty(),
        "terminal prepared checkpoint did not drain"
    );
    Ok(PreparedOfflineHandoff {
        bundle,
        source: terminal,
        journal,
        boot,
        policy,
        index_owner,
        selected,
        native_bytes_written: 0,
        qualification: PreparedTerminalQualification::Closed,
        _readiness: PreparedTerminalReadiness::Closed(readiness),
        _memory: memory,
    })
}
