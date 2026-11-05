//! Existing HND/ABT source proof; no writer, replay, marker write or repair.
use super::*;
use crate::{
    artifact_arena::ArtifactLease,
    ntfs_inspect::paged_storage::SourceRamLease,
    resource_prepared_bundle::HeldWindowsPreparedBundle,
    resource_prepared_offline_apply::{PreparedOfflineBootRequest, PreparedRecoveryReadiness},
};
use n2r_win32::{
    offline_environment::{
        OfflinePreparedClosedQualification, OfflinePreparedSource, OfflineTerminalKind,
    },
    recovery_boot::RecoveryBootGuard,
};
pub(crate) struct PreparedOfflineClosedRun {
    pub(crate) selected: SelectedResult,
    pub(crate) qualification: OfflinePreparedClosedQualification,
    pub(crate) boot: RecoveryBootGuard,
    pub(crate) policy: n2r_win32::HeldPagedWritePolicy,
    pub(crate) index_owner: ArtifactLease,
    pub(crate) readiness: PreparedRecoveryReadiness,
    pub(crate) memory: SourceRamLease,
}
impl BoundJournalObservation<'_> {
    pub(crate) fn observe_windows_prepared_closed(
        mut self,
        bundle: &mut HeldWindowsPreparedBundle,
        source: &mut OfflinePreparedSource,
        request: &PreparedOfflineBootRequest,
        events: &mut Vec<NativeEvent>,
        mut drain: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<PreparedOfflineClosedRun> {
        drain(events)?;
        ensure!(
            events.is_empty(),
            "closed prepared opening checkpoint did not drain"
        );
        self.observation.revalidate_index()?;
        let lifecycle = self.observation.lifecycle()?;
        let kind = match lifecycle {
            SelectedLifecycle::Handoff => OfflineTerminalKind::Handoff,
            SelectedLifecycle::Aborted => OfflineTerminalKind::Aborted,
            _ => {
                anyhow::bail!("closed prepared reopen requires actual HND/ABT; no replay fallback")
            }
        };
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none()
                && (1..=5).contains(&self.observation.format.version),
            "new prepared closed protocol requires markerless self-contained J"
        );
        let ticket = self.observation.ticket;
        let policy = self.observation.index.clone();
        let length = source.byte_len();
        let digest = if kind == OfflineTerminalKind::Handoff {
            self.observation.check_target_reader(
                source,
                length,
                Some(ticket.new_selected_sha256),
                false,
            )?
        } else {
            self.observation.check_restored_reader(source, length)?
        };
        let restored = if kind == OfflineTerminalKind::Aborted {
            self.observation.restored_bytes()?
        } else {
            None
        };
        let pins = PagedRecoveryPins {
            journal_binding: self.facts.binding,
            journal_identity: self.facts.identity,
            journal_path: self.facts.path,
            journal_profile: self.facts.profile,
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        self.observation
            .journal
            .seal_reopened_prepared_closed_body(ticket)?;
        let outer_sha = bundle.outer_sha256();
        let qualification = self
            .observation
            .journal
            .qualify_offline_prepared_closed_journal(
                source,
                &policy,
                &pins,
                bundle.outer_file(),
                outer_sha,
                kind,
                events,
            )?;
        let readiness = PreparedRecoveryReadiness::qualify_closed(
            bundle,
            source,
            &policy,
            ticket,
            &qualification,
        )?;
        let mut boot = self.observation.journal.observe_prepared_closed_boot(
            source,
            &qualification,
            &policy,
            &pins,
            bundle.outer_file(),
            &request.intent_path,
            request.intent_sha256,
            &request.output,
            request.budget,
            events,
        )?;
        readiness.require_binding(bundle, source, &policy, ticket)?;
        boot.require_current_boot(&source.owner_token(), events)?;
        ensure!(
            self.observation.lifecycle()? == lifecycle,
            "closed prepared lifecycle changed during observation"
        );
        bundle.revalidate()?;
        drain(events)?;
        ensure!(
            events.is_empty(),
            "closed prepared final checkpoint did not drain"
        );
        let selected = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: restored,
        };
        let JournalObservation {
            index_lease,
            _memory,
            ..
        } = self.observation;
        Ok(PreparedOfflineClosedRun {
            selected,
            qualification,
            boot,
            policy,
            index_owner: index_lease,
            readiness,
            memory: _memory,
        })
    }
}
