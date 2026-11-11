//! Cold source-I/O ownership for profile3. GPT BASIC+RO is physically observed
//! BEFORE any selected volume open. A NEW actual LOCK, not its historical pin,
//! must succeed before an owner can later qualify the existing J/AP writer.
use super::*;
struct EventObserver(super::super::partition_lifecycle::PartitionNativeEventSink);
impl PartitionRestorationObserver for EventObserver {
    fn checkpoint_native_events(
        &mut self,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.0.checkpoint(phase, events)
    }
    fn before_partition_change(
        &mut self,
        _kind: PartitionTerminalKind,
        _current: &[u8],
        _desired: &[u8],
    ) -> io::Result<()> {
        Err(bad(
            "cold physical source opener cannot change partition metadata",
        ))
    }
}
pub fn open_readonly_physical_recovery(
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    observer: Box<dyn super::super::partition_lifecycle::PartitionPreparationObserver>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionScopedOwner> {
    binding.validate()?;
    budget.validate()?;
    let sink = super::super::partition_lifecycle::PartitionNativeEventSink::new(observer);
    sink.checkpoint("physical-recovery-before-source-volume-open", events)?;
    let mut physical = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
        false,
        false,
    )?;
    let before = partition_isolation::observe_physical_only(
        &mut physical,
        &binding,
        budget,
        events,
        crate::layout::guid_bytes(BASIC)?,
    )?;
    need(
        before.gpt.target_attributes == RO
            && before.disk_attributes == 0
            && before.paging.all_locations_resolved
            && !before.paging.source_hosts_active_pagefile,
        "cold physical source is not actual BASIC+RO/current noncritical data",
    )?;
    sink.checkpoint("physical-recovery-positive-persistent-basic-ro", events)?;
    let target = crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?;
    let expected = before.gpt.native_layout[48..]
        .chunks_exact(144)
        .find(|row| row[48..64] == target)
        .ok_or_else(|| bad("cold physical source native target row absent"))?
        .to_vec();
    // A partition PDO or stale pre-type-change VPB does not prove a lock on
    // the mounted current volume. Resolve its actual full native extents/144B
    // identity first, then close the query object before obtaining the RW lock.
    let (current_binding, query) = find_terminal_volume(
        &binding,
        &expected,
        budget,
        &mut EventObserver(sink.clone()),
        events,
    )?;
    drop(query);
    let route = current_binding.volume_path()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0xa000_0000)
        .open(&route)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "opening protected source metadata/LOCK owner {route}: {e}; native_error={:?}",
                    e.raw_os_error()
                ),
            )
        })?;
    let device = control(
        &file,
        "physical-recovery-source-device",
        super::super::DEVICE,
        &[],
        12,
        events,
    )?;
    let info = control(
        &file,
        "physical-recovery-source-native-info",
        0x0007_0048,
        &[],
        144,
        events,
    )?;
    need(
        device.len() == 12
            && crate::layout::u32_at(&device, 0)? == 7
            && crate::layout::u32_at(&device, 4)? == binding.storage.disk_number
            && crate::layout::u32_at(&device, 8)? == binding.storage.identity.partition_number
            && info == expected,
        "cold physical source metadata handle is another actual partition",
    )?;
    let ext = control(
        &file,
        "physical-recovery-current-volume-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        events,
    )?;
    current_binding.validate_volume_extent(&ext)?;
    let at = events.len();
    let writable = control(
        &file,
        "physical-recovery-source-READONLY19",
        0x0007_0024,
        &[],
        0,
        events,
    );
    need(
        writable.is_err()
            && events
                .get(at)
                .is_some_and(|e| !e.succeeded && e.native_error == Some(19)),
        "cold BASIC+RO source must enforce actual native19",
    )?;
    for (code, label) in [
        (super::super::LOCK, "physical-recovery-NEW-real-volume-LOCK"),
        (
            super::super::DISMOUNT,
            "physical-recovery-real-volume-DISMOUNT",
        ),
        (0x0009_0083, "physical-recovery-extended-DASD"),
    ] {
        need(
            control(&file, label, code, &[], 0, events)?.is_empty(),
            "cold physical protection control reply differs",
        )?;
    }
    // No flush through the readonly filesystem, source data read, fake lock,
    // snapshot construction or writer gate is performed here.
    sink.checkpoint("physical-recovery-new-real-lock-completed", events)?;
    let after = partition_isolation::observe_physical_only(
        &mut physical,
        &binding,
        budget,
        events,
        crate::layout::guid_bytes(BASIC)?,
    )?;
    need(
        partition_isolation::same_private_identity(&before, &after),
        "cold physical source/GPT/C/critical identity changed across new lock",
    )?;
    sink.checkpoint("physical-recovery-identity-bookend", events)?;
    PartitionScopedOwner::adopt_readonly_physical_owner(
        binding, budget, file, physical, sink, events,
    )
}
