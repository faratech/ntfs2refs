//! Only the actual ordinary held J FileObject enters the closed SDK terminal.
use super::*;
impl NativeSelectedJournal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_offline_terminal_guard<'j, 'p>(
        &'j mut self,
        source: n2r_win32::offline_environment::OfflinePreparedAvailableSource,
        boot: n2r_win32::recovery_boot::RecoveryBootGuard,
        policy: &'j n2r_win32::HeldPagedWritePolicy,
        pins: n2r_win32::PagedRecoveryPins<'p>,
        outer: File,
        publication: File,
        intent: File,
        budget: n2r_win32::partition_isolation::PartitionObservationBudget,
        observer: &mut impl n2r_win32::partition_restoration::PartitionRestorationObserver,
        events: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<n2r_win32::offline_environment::OfflinePreparedTerminalGuard<'j, 'p>> {
        let Storage::Buffered(file) = &mut self.storage else {
            anyhow::bail!("cold terminal requires the actual markerless buffered J owner")
        };
        Ok(
            n2r_win32::offline_environment::OfflinePreparedTerminalGuard::open(
                source,
                boot,
                policy,
                file,
                pins,
                outer,
                publication,
                intent,
                budget,
                observer,
                events,
            )?,
        )
    }
}
