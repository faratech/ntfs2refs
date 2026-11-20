//! New sealed Windows-prepared protocol only. Actual scanner and all NEW bytes
//! are self-contained in J: COPY resolves prior complete OLD records, never a
//! shadow filesystem, a current-source alias or source-free digest table.
use super::*;
use crate::{
    artifact_arena::ArtifactLease,
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
    resource_prepared_bundle::HeldWindowsPreparedBundle,
    resource_prepared_offline_apply::{PreparedOfflineBootRequest, PreparedReadinessCertificate},
};
use n2r_win32::{
    offline_environment::{
        OfflineClosedJournalObservation, OfflinePreparedJournalQualification, OfflinePreparedSource,
    },
    recovery_boot::RecoveryBootGuard,
};

pub(crate) struct PreparedOfflineRun {
    pub(crate) selected: SelectedResult,
    pub(crate) qualification: OfflinePreparedJournalQualification,
    pub(crate) boot: RecoveryBootGuard,
    pub(crate) closed: OfflineClosedJournalObservation,
    pub(crate) policy: n2r_win32::HeldPagedWritePolicy,
    pub(crate) index_owner: ArtifactLease,
    pub(crate) readiness: PreparedReadinessCertificate,
    pub(crate) memory: SourceRamLease,
    pub(crate) native_bytes_written: u64,
}
fn checkpoint(
    events: &mut Vec<NativeEvent>,
    action: &mut impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
) -> Result<()> {
    action(events)?;
    ensure!(
        events.is_empty(),
        "prepared offline checkpoint did not durably drain native events"
    );
    Ok(())
}
impl BoundJournalObservation<'_> {
    /// Consumes a completed scanner that already authenticated both immutable
    /// payloads/aggregates and every resolved COPY row. No new checker exists.
    pub(crate) fn execute_windows_prepared(
        mut self,
        bundle: &mut HeldWindowsPreparedBundle,
        source: &mut OfflinePreparedSource,
        scratch: &SourceScratch,
        boot_request: &PreparedOfflineBootRequest,
        events: &mut Vec<NativeEvent>,
        mut drain: impl FnMut(&mut Vec<NativeEvent>) -> Result<()>,
    ) -> Result<PreparedOfflineRun> {
        checkpoint(events, &mut drain)?;
        self.observation.revalidate_index()?;
        boot_request.validate_control()?;
        ensure!(
            self.observation.ticket.marker_profile.is_none()
                && self.facts.marker_native_qualified.is_none()
                && (1..=5).contains(&self.observation.format.version)
                && self.observation.lifecycle()? == SelectedLifecycle::PreparedClear,
            "only the new markerless Windows-prepared clear protocol can activate this path"
        );
        let ticket = self.observation.ticket;
        let policy = self.observation.index.clone();
        let readiness = PreparedReadinessCertificate::qualify(
            bundle, source, &policy, ticket, scratch, events,
        )?;
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
        // The same actual native body becomes marker-only before any AP attempt.
        self.observation
            .journal
            .seal_reopened_prepared_body(ticket)?;
        let outer_sha = bundle.outer_sha256();
        let qualification = self.observation.journal.qualify_guarded_offline_prepared(
            source,
            &policy,
            &pins,
            bundle.outer_file(),
            outer_sha,
            events,
        )?;
        let mut boot = self.observation.journal.observe_prepared_boot(
            source,
            &qualification,
            &policy,
            &pins,
            bundle.outer_file(),
            &boot_request.intent_path,
            boot_request.intent_sha256,
            &boot_request.output,
            boot_request.budget,
            events,
        )?;
        readiness.require_binding(bundle, source, &policy, ticket)?;
        self.observation.revalidate_index()?;
        checkpoint(events, &mut drain)?;
        let mut gate = self.observation.journal.qualify_offline_prepared_apply(
            source,
            &qualification,
            &mut boot,
            &policy,
            &pins,
            bundle.outer_file(),
            events,
        )?;
        let pause_context = boot_request.postflush_pause_nonce.as_ref().map(|_| {
            (
                source.offline_environment_facts().boot.clone(),
                source.binding().clone(),
                bundle.outer_sha256(),
            )
        });
        let mut writer = self.observation.journal.begin_offline_prepared_apply(
            source,
            &mut gate,
            &qualification,
            &mut boot,
            policy.clone(),
            &pins,
            bundle.outer_file(),
            events,
        )?;
        let mut buffers = Buffers::new();
        let format = self.observation.format;
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
                true,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("offline prepared non-discovery flush/readback")?;
        writer.revalidate(events)?;
        checkpoint(events, &mut drain)?;
        let first = {
            let mut view = writer.journal_read_view()?;
            partition_record(&policy, &mut view, format, ticket, 0)?
        };
        if let Some((actual_boot, source_binding, outer_bundle_sha256)) = pause_context {
            ensure!(
                first.offset == 0 && first.length >= GRANULE,
                "controlled cut requires an actual deferred discovery granule"
            );
            let actual = crate::resource_prepared_offline_apply::PreparedPostFlushReceipt {
                kind: "offline-prepared-actual-nondiscovery-postflush-v1",
                actual_pid: actual_boot.process_id,
                actual_process_creation_100ns: actual_boot.process_creation_100ns,
                actual_boot_identifier: &actual_boot.boot_identifier,
                source: &source_binding,
                outer_bundle_sha256,
                immutable_journal_sha256: ticket.immutable_sha256,
                index_sha256: policy.facts()?.index_sha256,
                journal_binding: pins.journal_binding,
                journal_identity: pins.journal_identity,
                image_bytes: ticket.image_length,
                selected_bytes: ticket.selected_bytes,
                range_count: ticket.range_count,
                native_bytes_written: writer.native_bytes_written(),
                native_write_bytes_requested: writer.native_write_bytes_requested(),
                delayed_discovery_bytes: GRANULE,
                flush_and_pending_readback_succeeded: true,
                native_writer_revalidation_succeeded: true,
                discovery_write_not_requested: true,
                first_write_qualified: false,
            };
            crate::resource_prepared_offline_apply::wait_postflush_pause(boot_request, &actual)?;
            writer.revalidate(events)?;
            checkpoint(events, &mut drain)?;
        }
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
                true,
                &mut buffers,
            )?;
        }
        writer
            .sync_all()
            .context("offline prepared discovery-last flush/readback")?;
        let native_bytes_written = writer.native_bytes_written();
        writer.finish_new(events)?;
        drop(buffers);
        checkpoint(events, &mut drain)?;
        // No stale original fingerprint or fresh NTFS validation after AP.
        boot.require_current_boot(&source.owner_token(), events)?;
        let length = source.byte_len();
        let digest = self.observation.check_target_reader(
            source,
            length,
            Some(ticket.new_selected_sha256),
            false,
        )?;
        ensure!(
            self.observation.lifecycle()? == SelectedLifecycle::ApplyIntent,
            "actual prepared AP changed before HND"
        );
        sj::write_lifecycle_marker(self.observation.journal, ticket, MarkerKind::Handoff)?;
        self.observation
            .journal
            .require_native_mount_barriers(ticket)?;
        let closed = self
            .observation
            .journal
            .close_offline_prepared_handoff(source, &policy, &pins, events)?;
        boot.require_current_boot(&source.owner_token(), events)?;
        bundle.revalidate()?;
        checkpoint(events, &mut drain)?;
        let selected = SelectedResult {
            selected_sha256: digest,
            selected_bytes: ticket.selected_bytes,
            range_count: ticket.range_count,
            replay_closed: true,
            whole_image_verified: false,
            conversion_qualified: false,
            old_restoration_bytes: None,
        };
        let JournalObservation {
            index_lease,
            _memory,
            ..
        } = self.observation;
        Ok(PreparedOfflineRun {
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
