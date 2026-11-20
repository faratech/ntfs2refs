//! Actual cold AP/RB recovery for new Windows prepared bundles only.
use super::*;
use crate::{
    artifact_arena::ArtifactLease,
    ntfs_inspect::paged_storage::SourceRamLease,
    resource_prepared_bundle::HeldWindowsPreparedBundle,
    resource_prepared_offline_apply::{PreparedOfflineBootRequest, PreparedRecoveryReadiness},
};
use n2r_win32::{
    offline_environment::{
        OfflineClosedJournalObservation, OfflinePreparedReplayQualification, OfflinePreparedSource,
    },
    recovery_boot::RecoveryBootGuard,
};
pub(crate) struct PreparedOfflineReplayRun {
    pub(crate) selected: SelectedResult,
    pub(crate) qualification: OfflinePreparedReplayQualification,
    pub(crate) boot: RecoveryBootGuard,
    pub(crate) closed: OfflineClosedJournalObservation,
    pub(crate) policy: n2r_win32::HeldPagedWritePolicy,
    pub(crate) index_owner: ArtifactLease,
    pub(crate) readiness: PreparedRecoveryReadiness,
    pub(crate) memory: SourceRamLease,
    pub(crate) native_bytes_written: u64,
}
fn checkpoint(
    events: &mut Vec<NativeEvent>,
    drain: &mut impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
) -> Result<()> {
    drain(events)?;
    ensure!(
        events.is_empty(),
        "CURRENT prepared recovery checkpoint did not drain"
    );
    Ok(())
}
impl BoundJournalObservation<'_> {
    pub(crate) fn replay_windows_prepared(
        mut self,
        bundle: &mut HeldWindowsPreparedBundle,
        source: &mut OfflinePreparedSource,
        direction: PagedRecoveryDirection,
        request: &PreparedOfflineBootRequest,
        events: &mut Vec<NativeEvent>,
        mut drain: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<PreparedOfflineReplayRun> {
        checkpoint(events, &mut drain)?;
        self.observation.revalidate_index()?;
        let lifecycle = self.observation.lifecycle()?;
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none()
                && (1..=5).contains(&self.observation.format.version)
                && match direction {
                    PagedRecoveryDirection::Resume => lifecycle == SelectedLifecycle::ApplyIntent,
                    PagedRecoveryDirection::Rollback => matches!(
                        lifecycle,
                        SelectedLifecycle::ApplyIntent | SelectedLifecycle::RollbackIntent
                    ),
                },
            "new prepared recovery requires actual AP/RB; clear/HND/ABT never raw replay"
        );
        let ticket = self.observation.ticket;
        let policy = self.observation.index.clone();
        let length = source.byte_len();
        // Existing complete Root checker, not the original metadata hash.
        let current = self
            .observation
            .check_target_reader(source, length, None, false)?;
        let pins = PagedRecoveryPins {
            journal_binding: self.facts.binding,
            journal_identity: self.facts.identity,
            journal_path: self.facts.path,
            journal_profile: self.facts.profile,
            digest: ticket.digest_algorithm(),
            immutable_sha256: ticket.immutable_sha256,
            old_selected_sha256: ticket.old_selected_sha256,
            old_restored_selected_sha256: ticket.old_restored_selected_sha256,
            new_selected_sha256: ticket.new_selected_sha256,
        };
        self.observation
            .journal
            .seal_reopened_prepared_replay_body(ticket, direction)?;
        let outer_sha = bundle.outer_sha256();
        let qualification = self
            .observation
            .journal
            .qualify_offline_prepared_replay_journal(
                source,
                &policy,
                &pins,
                bundle.outer_file(),
                outer_sha,
                direction,
                events,
            )?;
        let readiness =
            PreparedRecoveryReadiness::qualify(bundle, source, &policy, ticket, &qualification)?;
        let mut boot = self.observation.journal.observe_prepared_recovery_boot(
            source,
            &qualification,
            &policy,
            &pins,
            bundle.outer_file(),
            &request.intent_path,
            request.intent_sha256,
            &request.output,
            request.budget,
            request.interrupted_recovery_boot_repair,
            events,
        )?;
        readiness.require_binding(bundle, source, &policy, ticket)?;
        ensure!(
            self.observation.lifecycle()? == lifecycle
                && self
                    .observation
                    .check_target_reader(source, length, None, false)?
                    == current,
            "CURRENT complete mixed source/lifecycle changed before consuming Root recovery observation"
        );
        checkpoint(events, &mut drain)?;
        let mut gate = self.observation.journal.qualify_offline_prepared_replay(
            source,
            &qualification,
            &mut boot,
            &policy,
            &pins,
            bundle.outer_file(),
            events,
        )?;
        let mut writer = self.observation.journal.begin_offline_prepared_replay(
            source,
            &mut gate,
            &qualification,
            &mut boot,
            policy.clone(),
            &pins,
            bundle.outer_file(),
            events,
        )?;
        let format = self.observation.format;
        let forward = direction == PagedRecoveryDirection::Resume;
        let mut buffers = Buffers::new();
        for ordinal in 0..u64::from(ticket.range_count) {
            let row = {
                let mut view = writer.journal_read_view()?;
                partition_record(&policy, &mut view, format, ticket, ordinal)?
            };
            let delayed = if row.offset == 0 { GRANULE } else { 0 };
            partition_write_span(
                &mut writer,
                &policy,
                format,
                ticket,
                row,
                ordinal,
                delayed,
                row.length - delayed,
                forward,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("prepared recovery non-discovery flush/readback")?;
        writer.revalidate(events)?;
        checkpoint(events, &mut drain)?;
        let first = {
            let mut view = writer.journal_read_view()?;
            partition_record(&policy, &mut view, format, ticket, 0)?
        };
        if first.offset == 0 {
            partition_write_span(
                &mut writer,
                &policy,
                format,
                ticket,
                first,
                0,
                0,
                GRANULE,
                forward,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("prepared recovery discovery-last flush/readback")?;
        let native_bytes_written = writer.native_bytes_written();
        if forward {
            writer.finish_new(events)?;
        } else {
            writer.finish_old(events)?;
        }
        drop(buffers);
        checkpoint(events, &mut drain)?;
        boot.require_current_boot(&source.owner_token(), events)?;
        let selected_sha256 = if forward {
            self.observation.check_target_reader(
                source,
                length,
                Some(ticket.new_selected_sha256),
                false,
            )?
        } else {
            self.observation.check_restored_reader(source, length)?
        };
        let restored = if forward {
            None
        } else {
            self.observation.restored_bytes()?
        };
        ensure!(
            self.observation.lifecycle()?
                == if forward {
                    SelectedLifecycle::ApplyIntent
                } else {
                    SelectedLifecycle::RollbackIntent
                },
            "actual AP/RB changed before prepared recovery terminal marker"
        );
        sj::write_lifecycle_marker(
            self.observation.journal,
            ticket,
            if forward {
                MarkerKind::Handoff
            } else {
                MarkerKind::Aborted
            },
        )?;
        self.observation
            .journal
            .require_native_mount_barriers(ticket)?;
        let closed = self
            .observation
            .journal
            .close_offline_prepared_replay(source, &policy, &pins, direction, events)?;
        boot.require_current_boot(&source.owner_token(), events)?;
        bundle.revalidate()?;
        checkpoint(events, &mut drain)?;
        let selected = SelectedResult {
            selected_sha256,
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
        Ok(PreparedOfflineReplayRun {
            selected,
            qualification,
            boot,
            closed,
            policy,
            index_owner: index_lease,
            readiness,
            memory: _memory,
            native_bytes_written,
        })
    }
}
