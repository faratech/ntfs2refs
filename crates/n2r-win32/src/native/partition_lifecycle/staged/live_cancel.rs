//! Actual original live guard cancellation after PRIVATE but before ANY source
//! admission gate. Saved intents and reopened owners cannot construct this lane.
use super::*;
use crate::attestation::NativeObservationDomain;
use crate::native::partition_restoration as terminal;
use std::time::{Duration, Instant};
#[derive(Debug, Serialize)]
pub struct PartitionLiveCancellationReceipt {
    pub kind: &'static str,
    pub binding: PartitionSourceBinding,
    pub original_type_attributes_restored: bool,
    pub original_label_mounts_restored: bool,
    pub native_ntfs_readonly_verified: bool,
    pub actual_source_gate_ever_issued: bool,
    pub source_payload_write_calls: u64,
    pub process_death_recovery_supported: bool,
}
struct CancelObserver(PartitionNativeEventSink);
impl terminal::PartitionRestorationObserver for CancelObserver {
    fn checkpoint_native_events(
        &mut self,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.0.checkpoint(phase, events)
    }
    fn before_partition_change(
        &mut self,
        _kind: crate::native::PartitionTerminalKind,
        _current: &[u8],
        _desired: &[u8],
    ) -> io::Result<()> {
        // This adapter is used only by readonly volume-publication queries.
        // Actual changes must pass through the live guard's durable intent
        // and native setter; never synthesize a successful native I/O event.
        Err(invalid(
            "live cancellation partition changes require the owning guard",
        ))
    }
}
fn wait_volume(
    guard: &mut PartitionPreparationGuard,
    events: &mut Vec<NativeEvent>,
) -> io::Result<(crate::general_layout::GeneralDiskBinding, File)> {
    let mut observer = CancelObserver(guard.observer.clone());
    let started = Instant::now();
    for attempt in 0..60 {
        guard.revalidate_current_metadata(events)?;
        guard.checkpoint("live-unactivated-publication-before", events)?;
        let found = terminal::find_terminal_volume(
            &guard.binding,
            &guard.current_info,
            guard.budget,
            &mut observer,
            events,
        );
        match found {
            Ok((binding, file)) => {
                guard.revalidate_current_with_volume(Some(&file), events)?;
                guard.checkpoint("live-unactivated-publication-matched", events)?;
                require(
                    binding == guard.binding.storage,
                    "unchanged NTFS volume route differs from original live guard",
                )?;
                return Ok((binding, file));
            }
            Err(error) if terminal::terminal_publication_pending(&error) => {
                guard.revalidate_current_metadata(events)?;
                guard.checkpoint("live-unactivated-publication-pending", events)?;
                if attempt == 59 || started.elapsed() >= Duration::from_secs(15) {
                    return Err(error);
                }
                std::thread::sleep(
                    Duration::from_millis(250)
                        .min(Duration::from_secs(15).saturating_sub(started.elapsed())),
                );
            }
            Err(error) => {
                let drained = guard.checkpoint("live-unactivated-publication-failed", events);
                return match drained {
                    Ok(()) => Err(error),
                    Err(checkpoint) => Err(io::Error::new(
                        error.kind(),
                        format!("{error}; durable checkpoint also failed: {checkpoint}"),
                    )),
                };
            }
        }
    }
    Err(invalid("live NTFS publication attempt bound exhausted"))
}
impl PartitionNtfsAdmission {
    /// Root must drop every source query/target proof before consuming this
    /// actual owner. The verifier receives only an actual borrowed BasicRO phase;
    /// Root's original scoped fingerprint is checked there before RW restoration.
    pub fn cancel_live_unactivated(
        mut self,
        mut owner: PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
        verify_original: impl FnOnce(
            &mut PartitionReadonlyPhase<'_>,
            &mut Vec<NativeEvent>,
        ) -> io::Result<()>,
    ) -> io::Result<PartitionLiveCancellationReceipt> {
        require_complete_fresh_ntfs_admission(&owner, &self)?;
        require(
            !owner.state().source_admission_issued,
            "source gate already issued; use authenticated AP/RB recovery",
        )?;
        let token = owner.owner_token();
        let preparation = self.guard.token.clone();
        let pin = self.durable_preparation_pin()?;
        self.revalidate_publication_handoff(&mut owner, &pin, events)?;
        self.native.domain().revalidate()?;
        let ntfs_serial = self.native.domain().header().request.ntfs_serial;
        let parts = owner.into_unactivated_cancellation_parts(&mut self, events)?;
        require(
            parts.token.same_owner(&token)
                && self.owner.same_owner(&token)
                && self.guard.token.same_owner(&preparation)
                && parts.binding == self.guard.binding
                && parts.budget == self.guard.budget
                && !parts.state.source_admission_issued
                && self.guard.volume.is_none()
                && self.guard.physical.is_none(),
            "live cancellation original owner/guard transfer differs",
        )?;
        self.guard.volume = Some(parts.file);
        self.guard.physical = Some(parts.physical_readonly);
        self.guard.locked = true;
        self.guard
            .checkpoint("live-unactivated-original-owner-returned", events)?;
        self.guard.change(BASIC, READONLY, events)?;
        self.guard.stage = PartitionPreparationStage::BasicReadonly;
        // Persistent BasicRO precedes releasing ALL original NTFS FileObjects. Root
        // already dropped read lanes/target witnesses; this closes the actual owner.
        drop(self.guard.volume.take());
        self.guard.locked = false;
        let (_, volume) = wait_volume(&mut self.guard, events)?;
        self.guard.volume = Some(volume);
        self.guard.observe_readonly(events)?;
        let facts = terminal::terminal_volume_info(self.guard.volume.as_ref().unwrap())?;
        let ntfs = &self
            .guard
            .protection
            .as_ref()
            .ok_or_else(|| invalid("actual cancellation BasicRO proof absent"))?
            .ntfs_volume_data;
        require(
            facts.filesystem == "NTFS"
                && facts.flags & 0x80000 != 0
                && facts.label == self.guard.source_label
                && ntfs.len() >= 96
                && crate::layout::u64_at(ntfs, 0)? == ntfs_serial,
            "live cancellation readonly NTFS identity/label differs from original actual admission",
        )?;
        self.guard
            .checkpoint("live-unactivated-original-ntfs-readonly", events)?;
        {
            let mut phase = PartitionReadonlyPhase {
                guard: &mut self.guard,
            };
            verify_original(&mut phase, events)?;
            phase.revalidate(events)?;
        }
        require(
            self.guard.token.same_owner(&preparation),
            "live cancellation preparation owner changed",
        )?;
        self.guard
            .checkpoint("live-unactivated-original-fingerprint-verified", events)?;
        self.guard.cancel_before_private(events)?;
        let binding = self.guard.binding.clone();
        let original = self.guard.original_info.clone();
        let mounts = self.guard.mount_paths.paths.clone();
        let label = self.guard.source_label.clone();
        // cancel_before_private still owns its new locking FileObject. Close it
        // before ordinary RW publication and nonstealing mount readback.
        drop(self.guard.volume.take());
        self.guard.locked = false;
        let (actual, file) = wait_volume(&mut self.guard, events)?;
        let facts = terminal::terminal_volume_info(&file)?;
        require(
            self.guard.current_info == original
                && facts.filesystem == "NTFS"
                && facts.flags & 0x80000 == 0
                && facts.label == label,
            "live cancellation final original Basic0/NTFS/label differs",
        )?;
        terminal::restore_terminal_mounts(&mounts, &actual, &original)?;
        self.guard
            .revalidate_current_with_volume(Some(&file), events)?;
        self.guard
            .checkpoint("live-unactivated-original-restored", events)?;
        drop(file);
        Ok(PartitionLiveCancellationReceipt {
            kind: "actual-live-unactivated-partition-cancellation",
            binding,
            original_type_attributes_restored: true,
            original_label_mounts_restored: true,
            native_ntfs_readonly_verified: true,
            actual_source_gate_ever_issued: false,
            source_payload_write_calls: 0,
            process_death_recovery_supported: false,
        })
    }
}
