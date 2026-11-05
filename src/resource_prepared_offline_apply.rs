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
        OfflinePreparedAvailableSource, OfflinePreparedJournalQualification, OfflinePreparedSource,
        OfflinePreparedTerminalSource, OfflineSourceOwnerToken,
    },
    recovery_boot::{RecoveryBootBudget, RecoveryBootGuard},
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) struct PreparedOfflineBootRequest {
    pub(crate) intent_path: PathBuf,
    pub(crate) intent_sha256: [u8; 32],
    pub(crate) output: PathBuf,
    pub(crate) budget: RecoveryBootBudget,
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
/// HND is closed. Actual J/expected/maps/bundle/index/boot owners all remain
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
    qualification: OfflinePreparedJournalQualification,
    _readiness: PreparedReadinessCertificate,
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
    _qualification: OfflinePreparedJournalQualification,
    _readiness: PreparedReadinessCertificate,
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
        qualification,
        _readiness: readiness,
        _memory: memory,
    })
}
