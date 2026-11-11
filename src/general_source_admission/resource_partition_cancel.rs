//! Consuming live-only cancellation using the original scoped fingerprint and
//! actual source/admission owners. No saved intent or missing-J inference.
use super::*;
use n2r_win32::partition_restoration::PartitionRestorationObserver;
impl PartitionResourceSourceContext {
    pub(crate) fn cancel_unactivated(
        self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        observer.checkpoint_native_events("partition-live-cancel-request", events)?;
        let receipt = self.cancel_with_original_sink(events)?;
        observer.checkpoint_native_events("partition-live-cancel-restored", events)?;
        Ok(receipt)
    }
    pub(super) fn cancel_with_original_sink(
        self,
        events: &mut Vec<NativeEvent>,
    ) -> Result<serde_json::Value> {
        ensure!(
            !self.source.state().source_admission_issued,
            "source gate already issued; preserve AP/RB recovery state"
        );
        let mut context = self;
        // Cancellation proves original bytes/lineage, not convertibility. A
        // failed conversion-policy gate must not prevent safe NTFS retention.
        context.source.revalidate(events)?;
        let journal = match &mut context.cancel_journal {
            cancel_journal::LiveCancellationJournal::NotStarted => {
                serde_json::json!({"kind":"actual-live-native-journal-creation-not-started"})
            }
            cancel_journal::LiveCancellationJournal::Attempting => anyhow::bail!(
                "actual native J creation was attempted but its held clear witness is unavailable; preserve private source"
            ),
            cancel_journal::LiveCancellationJournal::Owned(journal) => {
                journal.require_clear(&context.source, events)?
            }
        };
        context
            .native_admission
            .checkpoint_native_events("partition-live-cancel-original-basis-and-J", events)?;
        let PartitionResourceSourceContext {
            source,
            native_admission,
            collected,
            binding,
            cancel_journal: held_journal,
            cancel_journal_memory: held_journal_memory,
            ..
        } = context;
        let expected_binding = binding.clone();
        let receipt = cancel_collected(
            source,
            native_admission,
            collected,
            &expected_binding,
            events,
        )?;
        // Retain the exact same J FileObject/share exclusion until NTFS is restored.
        drop(held_journal);
        drop(held_journal_memory);
        Ok(
            serde_json::json!({"kind":"actual-live-private-preparation-cancellation","sdk":receipt,
   "actual_original_scoped_fingerprint_verified":true,"journal":journal,"pre_ap_process_death_cancel":false}),
        )
    }
    pub(crate) fn note_native_journal_attempt(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.cancel_journal,
                cancel_journal::LiveCancellationJournal::NotStarted
            ) && !self.source.state().source_admission_issued,
            "native journal creation already attempted/source gate issued"
        );
        let memory = self
            .arena
            .reserve_ram(cancel_journal::WORKING_MEMORY_BYTES)?;
        self.cancel_journal_memory = Some(memory);
        self.cancel_journal = cancel_journal::LiveCancellationJournal::Attempting;
        Ok(())
    }
    pub(crate) fn remember_unactivated_journal_owner(
        &mut self,
        proof: cancel_journal::LiveClearJournal,
    ) -> Result<()> {
        ensure!(
            matches!(
                self.cancel_journal,
                cancel_journal::LiveCancellationJournal::Attempting
            ) && !self.source.state().source_admission_issued,
            "native journal witness is not this live creation attempt"
        );
        let memory = self
            .cancel_journal_memory
            .take()
            .context("prepaid live J observation memory absent")?;
        self.cancel_journal =
            cancel_journal::LiveCancellationJournal::Owned(proof.retain_memory(memory)?);
        Ok(())
    }
}
pub(super) fn cancel_collected(
    mut source: PartitionScopedOwner,
    admission: PartitionNtfsAdmission,
    collected: CollectedPartitionSource,
    binding: &PartitionSourceBinding,
    events: &mut Vec<NativeEvent>,
) -> Result<n2r_win32::partition_lifecycle::PartitionLiveCancellationReceipt> {
    ensure!(
        !source.state().source_admission_issued && source.binding() == binding,
        "actual live unactivated source owner differs"
    );
    n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(&source, &admission)?;
    admission.native().domain().revalidate()?;
    ensure!(
        admission
            .native()
            .domain()
            .header()
            .request
            .source_inspection_sha256
            == collected.inspection_sha,
        "actual native admission does not bind the original scoped raw basis"
    );
    collected.raw.revalidate()?;
    collected.fingerprint.revalidate()?;
    collected
        .fingerprint
        .validate_reads(&collected.read_coverage)?;
    ensure!(
        collected.fingerprint.pins().source_inspection_sha256 == collected.inspection_sha
            && collected.raw.canonical_sha256()? == collected.inspection_sha,
        "original scoped fingerprint/raw owner binding differs"
    );
    source.revalidate(events)?;
    ensure!(
        collected
            .fingerprint
            .hash_partition_reader(&mut source, binding.storage.identity.partition_bytes)?
            == collected.source_sha,
        "original NTFS scoped bytes changed; live cancellation refused"
    );
    source.revalidate(events)?;
    // Only original source metadata/fingerprint artifact owners remain. Root's
    // consuming resources/error wrapper dropped all target/query witnesses first.
    let expected = binding.clone();
    Ok(
        admission.cancel_live_unactivated(source, events, |phase, events| {
            let verify = (|| -> Result<()> {
                ensure!(
                    phase.binding() == &expected,
                    "actual BasicRO cancellation phase names another original source"
                );
                phase.revalidate(events)?;
                let mut reader = phase.read_source(events)?;
                ensure!(
                    collected.fingerprint.hash_partition_reader(
                        &mut reader,
                        expected.storage.identity.partition_bytes
                    )? == collected.source_sha,
                    "original scoped fingerprint differs on actual restored readonly NTFS"
                );
                drop(reader);
                phase.revalidate(events)?;
                Ok(())
            })();
            verify.map_err(io::Error::other)
        })?,
    )
}
