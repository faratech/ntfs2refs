//! CLOSED-only private-source finalization. No replay gate, marker write,
//! fabricated replay outcome or spent fresh/replay witness is constructed.
use super::*;
use crate::{
    artifact_arena::ArtifactLease,
    general_reconstruct::fast_verification::v4_maps::reopened::ReopenedVerificationMetadata,
};
pub(crate) enum ReopenedPartitionRestart {
    Replay(ReopenedPartitionResourceRecovery),
    Closed(PartitionClosedTerminal),
}
pub(crate) struct PartitionClosedTerminal {
    recovery: ReopenedPartitionResourceRecovery,
    closed: n2r_win32::PartitionClosedJournalObservation,
    policy: n2r_win32::HeldPagedWritePolicy,
    _index: ArtifactLease,
}
impl PartitionClosedTerminal {
    pub(super) fn from_actual(
        recovery: ReopenedPartitionResourceRecovery,
        closed: n2r_win32::PartitionClosedJournalObservation,
        policy: n2r_win32::HeldPagedWritePolicy,
        index: ArtifactLease,
    ) -> Self {
        Self {
            recovery,
            closed,
            policy,
            _index: index,
        }
    }
    pub(crate) fn kind(&self) -> n2r_win32::PartitionTerminalKind {
        self.closed.kind()
    }
    pub(crate) fn finalize(
        mut self,
        mut owner: n2r_win32::PartitionScopedOwner,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
        mut checkpoint: impl FnMut(&'static str, &mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<serde_json::Value> {
        let stable = owner.owner_token();
        let kind = self.closed.kind();
        self.closed.require_owner(&stable)?;
        checkpoint("partition-closed-private-opening", events)?;
        self.recovery
            .publication_file
            .revalidate(&self.recovery.scratch)?;
        self.recovery.expected.revalidate(&self.recovery.scratch)?;
        if let Some(maps) = &mut self.recovery.maps {
            maps.revalidate(&self.recovery.scratch)?;
        }
        self.recovery.locator.revalidate()?;
        self.recovery.journal.revalidate()?;
        let ticket = self.recovery.locator.ticket().clone();
        {
            let (journal, facts) = self.recovery.journal.split_for_observation()?;
            let pins = n2r_win32::PagedRecoveryPins {
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
            self.closed.revalidate(
                &mut owner,
                &self.policy,
                journal.markerless_recovery_file()?,
                &pins,
                events,
            )?;
        }
        let metadata = if kind == n2r_win32::PartitionTerminalKind::Handoff {
            Some(ReopenedVerificationMetadata::open_closed_partition(
                &self.recovery,
                &self.closed,
                &stable,
            )?)
        } else {
            None
        };
        let origin = self
            .recovery
            .restarted_origin
            .take()
            .context("actual authenticated closed origin absent")?;
        let shadow = self.recovery.publication.shadow.clone();
        let admission = self.recovery.publication.resource_admission;
        let arena = self
            .recovery
            .scratch
            .artifact_group()
            .context("actual closed recovery arena absent")?
            .arena()
            .clone();
        let (journal, facts) = self.recovery.journal.split_for_observation()?;
        let pins = n2r_win32::PagedRecoveryPins {
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
        origin.require_journal_pins(&pins)?;
        checkpoint("partition-closed-private-authenticated", events)?;
        let mut guard = origin.into_terminal(
            owner,
            &self.policy,
            journal.markerless_recovery_file()?,
            pins,
            kind,
            events,
        )?;
        checkpoint("partition-closed-before-readonly", events)?;
        guard.enter_readonly(observer, events)?;
        checkpoint("partition-closed-readonly-native", events)?;
        let mut bindings = 0;
        let mut known_streams = 0;
        let mut extent_streams = 0;
        let restored = if let Some(metadata) = metadata.as_ref() {
            let native = {
                let readonly = guard.readonly_volume()?;
                ensure!(
                    readonly.owner_token().same_owner(&stable),
                    "actual closed terminal readonly owner changed"
                );
                let pair = GeneralSourceShadowBinding {
                    source: readonly.binding().clone(),
                    shadow,
                };
                let native = readonly.observe_converted_metadata_with_memory(
                    pair,
                    &crate::general_shadow::PagedInputs(metadata.expected()),
                    None,
                    |a, b| crate::ntfs_attestation::same_security(a, b).map_err(io::Error::other),
                    ResourceProfile::ResourceBoundedV4(Some(admission)),
                    &crate::general_composite_target::paged_memory::ArenaReportMemory(
                        arena.clone(),
                    ),
                    true,
                    events,
                )?;
                bindings = metadata.compare_partition(&stable, &native)?;
                let known = native
                    .report()
                    .content_observation
                    .as_ref()
                    .and_then(|c| c.known_content.as_ref())
                    .context("actual closed HND known-content observation absent")?;
                known_streams = known.streams_hashed;
                extent_streams = known.streams_without_content_baseline;
                native
            };
            checkpoint("partition-closed-hnd-verified-before-rw", events)?;
            guard.finish(native, observer, events)?
        } else {
            ensure!(
                kind == n2r_win32::PartitionTerminalKind::Aborted,
                "closed HND lacks actual expected/maps capability"
            );
            checkpoint("partition-closed-abt-old-before-rw", events)?;
            guard.finish_aborted(observer, events)?
        };
        checkpoint("partition-closed-original-mounts-restored", events)?;
        // After RW publication authenticate only held metadata/J facts, never stale
        // conversion-time source bytes or an operational filesystem's contents.
        self.recovery
            .publication_file
            .revalidate(&self.recovery.scratch)?;
        self.recovery.expected.revalidate(&self.recovery.scratch)?;
        if let Some(maps) = &mut self.recovery.maps {
            maps.revalidate(&self.recovery.scratch)?;
        }
        self.recovery.locator.revalidate()?;
        self.recovery.journal.revalidate()?;
        Ok(
            serde_json::json!({"kind":"partition-private-closed-terminal-finalization-v1","success":true,
   "terminal":if kind==n2r_win32::PartitionTerminalKind::Handoff{"HND"}else{"ABT"},
   "restoration":restored,"raw_replay_performed":false,"source_replay_gate_issued":false,"lifecycle_marker_written":false,
   "native_terminal_verified_before_writable":true,"matching_map_bindings":bindings,
   "known_streams_hashed":known_streams,"extent_only_streams":extent_streams,
   "recovery_files_retired":false,"operational_basic0_reconciliation_supported":false,"stable_release_qualification":false}),
        )
    }
}
