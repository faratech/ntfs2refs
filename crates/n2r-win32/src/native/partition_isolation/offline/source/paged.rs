//! Same-owner current-PE-session paged activation. No JSON/marker/token alone
//! opens a source writer; complete actual J/index/source/native gates precede AP.
use super::native_observation::OfflinePagedNtfsObservation;
use super::*;
use crate::native::{
    HeldPagedWritePolicy,
    paged_recovery::{
        self, OwnedPartitionJournalPins, PagedRecoveryDirection, PagedRecoveryPins,
        PartitionJournalPhase,
    },
};
use std::os::windows::io::AsRawHandle;
#[derive(Debug)]
struct OfflineIoError {
    operation: &'static str,
    relative: u64,
    bytes: usize,
    source: io::Error,
}
impl std::fmt::Display for OfflineIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at source-relative{} /{}bytes: {}; native_error={:?}",
            self.operation,
            self.relative,
            self.bytes,
            self.source,
            self.source.raw_os_error()
        )
    }
}
impl std::error::Error for OfflineIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
fn source_io<T>(
    result: io::Result<T>,
    operation: &'static str,
    relative: u64,
    bytes: usize,
) -> io::Result<T> {
    result.map_err(|source| {
        io::Error::new(
            source.kind(),
            OfflineIoError {
                operation,
                relative,
                bytes,
                source,
            },
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Activation {
    Fresh,
    Prepared,
    PreparedReplay(PagedRecoveryDirection),
    Replay(PagedRecoveryDirection),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OfflineTerminalKind {
    Handoff,
    Aborted,
}
pub struct OfflineSourceApplyGate {
    owner: OfflineSourceOwnerToken,
    binding: PartitionSourceBinding,
    boot: OfflineBootIdentity,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    journal_handle: usize,
    current_mixed_sha256: Option<[u8; 32]>,
    lifecycle_sha256: [u8; 32],
    native_pin: Option<(String, String, u64)>,
    prepared_pin: Option<super::prepared_apply::PreparedPublicationPin>,
    activation: Activation,
    used: bool,
}
impl OfflineSourceApplyGate {
    fn require_bound(
        &self,
        core: &Core,
        policy: &HeldPagedWritePolicy,
        journal: &File,
        pins: &PagedRecoveryPins<'_>,
    ) -> io::Result<()> {
        require(
            self.owner.same_owner(&core.token)
                && self.binding == core.env.source
                && self.boot == core.env.facts.boot
                && self.journal_handle == journal.as_raw_handle() as usize
                && self.index_sha256 == policy.facts()?.index_sha256
                && core.gate_ever_issued
                && !core.poisoned,
            "actual offline gate source/epoch/J/index owner changed",
        )?;
        self.pins.require(pins)
    }
}
struct Reader<'a>(&'a mut Core);
impl Read for Reader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.0.read(out)
    }
}
impl Seek for Reader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.0.seek(from)
    }
}
fn phase(activation: Activation, initial: bool) -> PartitionJournalPhase {
    match (activation, initial) {
        (Activation::Fresh | Activation::Prepared, true) => PartitionJournalPhase::FreshOld,
        (Activation::Fresh | Activation::Prepared, false) => PartitionJournalPhase::Applying,
        (Activation::Replay(d) | Activation::PreparedReplay(d), true) => PartitionJournalPhase::Mixed(d),
        (Activation::Replay(d) | Activation::PreparedReplay(d), false) => PartitionJournalPhase::Replaying(d),
    }
}
fn independent_journal(core: &Core, pins: &PagedRecoveryPins<'_>) -> io::Result<()> {
    pins.journal_binding.validate()?;
    require(
        core.env.source.storage.disk_number != pins.journal_binding.disk.disk_number
            && layout::guid_bytes(&core.env.source.storage.identity.disk_guid)?
                != layout::guid_bytes(&pins.journal_binding.disk.identity.disk_guid)?,
        "offline whole source disk requires native J on another physical disk",
    )
}
fn native_pin(
    core: &Core,
    native: Option<&OfflinePagedNtfsObservation>,
) -> io::Result<Option<(String, String, u64)>> {
    if let Some(native) = native {
        native.require_owner(&core.token)?;
        require(
            native.binding() == &core.env.source,
            "actual offline native observation names another source",
        )?;
        native.revalidate()?;
        native.require_admission_evidence()?;
        let domain = native.domain();
        Ok(Some((
            domain.final_path(),
            domain.sha256().into(),
            domain.byte_len(),
        )))
    } else {
        Ok(None)
    }
}
fn require_native(
    gate: &OfflineSourceApplyGate,
    core: &Core,
    native: Option<&OfflinePagedNtfsObservation>,
) -> io::Result<()> {
    require(
        (gate.activation == Activation::Fresh) == native.is_some()
            && native_pin(core, native)? == gate.native_pin,
        "actual fresh native owner/domain differs from source gate",
    )
}
pub(super) fn authenticate(
    core: &mut Core,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    phase: PartitionJournalPhase,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Option<[u8; 32]>> {
    core.state(events)?;
    independent_journal(core, pins)?;
    let binding = core.env.source.clone();
    let length = binding.storage.identity.partition_bytes;
    let result = paged_recovery::authenticate_scoped_partition_reader(
        &mut Reader(core),
        length,
        &binding,
        policy,
        journal,
        pins,
        phase,
    );
    let closing = core.state(events);
    match (result, closing) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}
pub(super) fn lifecycle_digest(journal: &mut File) -> io::Result<[u8; 32]> {
    let before = journal.stream_position()?;
    let mut bytes = [0; 8192];
    journal.seek(SeekFrom::Start(0))?;
    let result = journal.read_exact(&mut bytes);
    let restored = journal.seek(SeekFrom::Start(before));
    result?;
    restored?;
    Ok(Sha256::digest(bytes).into())
}
fn qualify(
    core: &mut Core,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    activation: Activation,
    native: Option<&OfflinePagedNtfsObservation>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineSourceApplyGate> {
    require(
        !core.poisoned && !core.gate_ever_issued,
        "offline source has already issued a gate or is poisoned",
    )?;
    require(
        (activation == Activation::Fresh && core.fresh && core.expected_attributes == 3)
            || (matches!(activation, Activation::Replay(_))
                && !core.fresh
                && matches!(core.expected_attributes, 1 | 3)),
        "fresh/recovery owner and actual offline source mode differ",
    )?;
    require(
        (activation == Activation::Fresh) == native.is_some(),
        "fresh writer requires actual native proof; replay forbids fresh admission",
    )?;
    if activation == Activation::Fresh {
        core.state(events)?;
        core.fresh_witness
            .as_ref()
            .ok_or_else(|| invalid("actual pre-freeze offline NTFS witness absent"))?
            .require_environment(&mut core.env, events)?;
        core.state(events)?;
    }
    let native_pin = native_pin(core, native)?;
    let current = authenticate(core, policy, journal, pins, phase(activation, true), events)?;
    let lifecycle_sha256 = lifecycle_digest(journal)?;
    let gate = OfflineSourceApplyGate {
        owner: core.token.clone(),
        binding: core.env.source.clone(),
        boot: core.env.facts.boot.clone(),
        pins: OwnedPartitionJournalPins::capture(pins),
        index_sha256: policy.facts()?.index_sha256,
        journal_handle: journal.as_raw_handle() as usize,
        current_mixed_sha256: current,
        lifecycle_sha256,
        native_pin,
        prepared_pin: None,
        activation,
        used: false,
    };
    core.gate_ever_issued = true;
    Ok(gate)
}
pub(super) fn gate_file_state(
    file: &File,
    core: &Core,
    expected: u64,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    require_physical_handle(file, &core.env.facts.source_physical, expected, events)
}
pub(super) fn begin<'a, 'p>(
    core: &'a mut Core,
    gate: &'a mut OfflineSourceApplyGate,
    policy: HeldPagedWritePolicy,
    journal: &'a mut File,
    pins: &'a PagedRecoveryPins<'p>,
    native: Option<&'a OfflinePagedNtfsObservation>,
    mut prepared: Option<super::prepared_apply::PreparedWriteProtection<'a>>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflinePagedWriter<'a, 'p>> {
    require(!gate.used, "offline paged gate is single use")?;
    gate.require_bound(core, &policy, journal, pins)?;
    require_native(gate, core, native)?;
    require(
        matches!(gate.activation, Activation::Prepared | Activation::PreparedReplay(_)) == prepared.is_some(),
        "prepared activation needs the actual retained boot guard and outer file",
    )?;
    if let Some(protection) = prepared.as_mut() {
        protection.revalidate(
            &core.token,
            gate.prepared_pin
                .as_ref()
                .ok_or_else(|| invalid("prepared publication pin absent"))?,
            pins,
            core.env.budget.ram_bytes / 8,
            events,
        )?;
    }
    let current = authenticate(
        core,
        &policy,
        journal,
        pins,
        phase(gate.activation, true),
        events,
    )?;
    require(
        current == gate.current_mixed_sha256 && lifecycle_digest(journal)? == gate.lifecycle_sha256,
        "CURRENT source mixed digest or actual lifecycle changed after qualification",
    )?;
    checkpoint(
        &core.sink,
        "offline-source-paged-before-exclusive-RW-gate",
        events,
    )?;
    let path = format!(
        "\\\\.\\PhysicalDrive{}",
        core.env.source.storage.disk_number
    );
    let retained = core.prepared_exclusion.as_ref().and_then(|v| v.management.as_ref())
        .map(File::try_clone).transpose()?;
    let file = match retained {
        Some(file) => file,
        None => OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1)
        .custom_flags(0xa000_0000)
        .open(&path)?,
    };
    gate_file_state(&file, core, core.expected_attributes, events)?;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0xa000_0000)
        .open(&path)
    {
        Err(error) if error.raw_os_error() == Some(32) => (),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("actual source sharing exclusion unknown: {error}"),
            ));
        }
        Ok(other) => {
            close_file(other, "offline-close-unexpected-second-RW-source", events)?;
            return Err(invalid(
                "offline source gate permitted another ordinary raw writer",
            ));
        }
    }
    // Spent BEFORE any intent attempt. A failed AP/RB can be durable or torn;
    // neither old native admission nor a clear-marker guess is reusable.
    gate.used = true;
    let activated = (|| {
        match gate.activation {
            Activation::Fresh | Activation::Prepared => {
                paged_recovery::publish_partition_apply_marker(journal, pins, events)?
            }
            Activation::Replay(PagedRecoveryDirection::Rollback) | Activation::PreparedReplay(PagedRecoveryDirection::Rollback) => {
                paged_recovery::publish_partition_rollback_marker(journal, pins, events)?
            }
            Activation::Replay(PagedRecoveryDirection::Resume) | Activation::PreparedReplay(PagedRecoveryDirection::Resume) => (),
        }
        gate_file_state(&file, core, core.expected_attributes, events)?;
        // OFFLINE stays set; only physical READ_ONLY is cleared after durable
        // AP/RB. This is NOT a cross-environment cold-exclusion assertion.
        if core.expected_attributes == 3 {
            set_attributes(&file, DISK_OFFLINE, events)?;
        }
        core.env
            .require_current_at_attributes(DISK_OFFLINE, events)?;
        gate_file_state(&file, core, DISK_OFFLINE, events)?;
        let old = std::mem::replace(&mut core.file, file);
        core.expected_attributes = DISK_OFFLINE;
        close_file(
            old,
            "offline-source-original-RO-data-close-after-activation",
            events,
        )?;
        authenticate(
            core,
            &policy,
            journal,
            pins,
            phase(gate.activation, false),
            events,
        )?;
        if let Some(protection) = prepared.as_mut() {
            protection.revalidate(
                &core.token,
                gate.prepared_pin
                    .as_ref()
                    .ok_or_else(|| invalid("prepared publication pin absent"))?,
                pins,
                core.env.budget.ram_bytes / 8,
                events,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = activated {
        core.poisoned = true;
        return Err(error);
    }
    core.writer_ever_issued = true;
    Ok(OfflinePagedWriter {
        core,
        gate,
        policy,
        journal,
        pins,
        native,
        prepared,
        requested: 0,
        written: 0,
        pending: None,
        poisoned: false,
    })
}
impl OfflineFrozenSource {
    /// ROOT must still hold its actual prepared-target/capture/publication
    /// certificate. This SDK gate independently proves source/J/index/OLD.
    pub fn qualify_fresh_paged_apply(
        &mut self,
        native: &OfflinePagedNtfsObservation,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflineSourceApplyGate> {
        qualify(
            &mut self.core,
            policy,
            journal,
            pins,
            Activation::Fresh,
            Some(native),
            events,
        )
    }
    pub fn begin_fresh_paged_apply<'a, 'p>(
        &'a mut self,
        gate: &'a mut OfflineSourceApplyGate,
        native: &'a OfflinePagedNtfsObservation,
        policy: HeldPagedWritePolicy,
        journal: &'a mut File,
        pins: &'a PagedRecoveryPins<'p>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePagedWriter<'a, 'p>> {
        require(
            gate.activation == Activation::Fresh,
            "replay gate cannot enter fresh owner",
        )?;
        begin(
            &mut self.core,
            gate,
            policy,
            journal,
            pins,
            Some(native),
            None,
            events,
        )
    }
}
impl OfflineRecoverySource {
    /// ROOT must separately consume its authenticated actual publication and
    /// MIXED observation. No original live NTFS admission is fabricated here.
    pub fn qualify_paged_replay(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        direction: PagedRecoveryDirection,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflineSourceApplyGate> {
        qualify(
            &mut self.core,
            policy,
            journal,
            pins,
            Activation::Replay(direction),
            None,
            events,
        )
    }
    pub fn begin_paged_replay<'a, 'p>(
        &'a mut self,
        gate: &'a mut OfflineSourceApplyGate,
        policy: HeldPagedWritePolicy,
        journal: &'a mut File,
        pins: &'a PagedRecoveryPins<'p>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflinePagedWriter<'a, 'p>> {
        require(
            matches!(gate.activation, Activation::Replay(_)),
            "fresh gate cannot enter recovery owner",
        )?;
        begin(
            &mut self.core,
            gate,
            policy,
            journal,
            pins,
            None,
            None,
            events,
        )
    }
}
pub struct OfflinePagedWriter<'a, 'p> {
    core: &'a mut Core,
    gate: &'a mut OfflineSourceApplyGate,
    policy: HeldPagedWritePolicy,
    journal: &'a mut File,
    pins: &'a PagedRecoveryPins<'p>,
    native: Option<&'a OfflinePagedNtfsObservation>,
    prepared: Option<super::prepared_apply::PreparedWriteProtection<'a>>,
    requested: u64,
    written: u64,
    pending: Option<(u64, usize, [u8; 32])>,
    poisoned: bool,
}
impl OfflinePagedWriter<'_, '_> {
    fn poison(&mut self, error: io::Error) -> io::Error {
        self.poisoned = true;
        self.core.poisoned = true;
        error
    }
    fn prepared_protection(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        match self.prepared.as_mut() {
            Some(protection) => protection.revalidate(
                &self.core.token,
                self.gate
                    .prepared_pin
                    .as_ref()
                    .ok_or_else(|| invalid("prepared publication pin absent"))?,
                self.pins,
                self.core.env.budget.ram_bytes / 8,
                events,
            ),
            None => require(
                !matches!(self.gate.activation, Activation::Prepared | Activation::PreparedReplay(_)),
                "prepared writer lost boot/outer owners",
            ),
        }
    }
    fn prepared_write_checkpoint(&mut self) -> io::Result<()> {
        if !matches!(self.gate.activation, Activation::Prepared | Activation::PreparedReplay(_)) {
            return Ok(());
        }
        let mut events = Vec::new();
        checkpoint(
            &self.core.sink,
            "offline-PREPARED-before-source-write-boot-opening",
            &mut events,
        )?;
        let checked = self.prepared_protection(&mut events);
        let drained = checkpoint(
            &self.core.sink,
            "offline-PREPARED-before-source-write-boot-closed",
            &mut events,
        );
        match (checked, drained) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(a), Err(b)) => Err(invalid(&format!(
                "prepared boot protection failed:{a}; durable checkpoint also failed:{b}"
            ))),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
    fn live(&self) -> io::Result<()> {
        require(
            !self.poisoned
                && !self.core.poisoned
                && self.gate.used
                && self.core.gate_ever_issued
                && self.core.expected_attributes == DISK_OFFLINE
                && self.gate.owner.same_owner(&self.core.token),
            "offline writer lost actual used gate/current source owner",
        )
    }
    pub fn byte_len(&self) -> u64 {
        self.core.env.source.storage.identity.partition_bytes
    }
    pub fn native_bytes_written(&self) -> u64 {
        self.written
    }
    pub fn native_write_bytes_requested(&self) -> u64 {
        self.requested
    }
    /// Owner-lifetime aligned payload-reader counters; not total device I/O.
    pub fn native_read_bytes_requested(&self) -> u64 {
        self.core.native_read_bytes_requested
    }
    pub fn native_read_bytes_succeeded(&self) -> u64 {
        self.core.native_read_bytes_succeeded
    }
    pub fn native_read_error_count(&self) -> u64 {
        self.core.native_read_error_count
    }
    pub fn native_read_short_count(&self) -> u64 {
        self.core.native_read_short_count
    }
    pub fn sync_all(&mut self) -> io::Result<()> {
        let result = (|| {
            self.live()?;
            if let Some((at, bytes, expected)) = self.pending {
                source_io(
                    self.core.file.sync_all(),
                    "offline physical FlushFileBuffers after actual write",
                    at,
                    bytes,
                )?;
                let absolute = self
                    .core
                    .env
                    .source
                    .storage
                    .identity
                    .partition_offset
                    .checked_add(at)
                    .ok_or_else(|| invalid("offline readback base overflow"))?;
                require(
                    source_io(
                        self.core.file.seek(SeekFrom::Start(absolute)),
                        "offline physical readback seek",
                        at,
                        bytes,
                    )? == absolute,
                    "offline source readback seek differs",
                )?;
                let got = source_io(
                    self.core
                        .file
                        .read(&mut self.core.buffer.bytes_mut()[..bytes]),
                    "offline physical readback ReadFile",
                    at,
                    bytes,
                )?;
                require(
                    got == bytes
                        && <[u8; 32]>::from(Sha256::digest(&self.core.buffer.bytes_mut()[..bytes]))
                            == expected,
                    "offline source write flush/readback differs",
                )?;
                self.pending = None;
            }
            Ok(())
        })();
        result.map_err(|e| self.poison(e))
    }
    pub fn journal_read_view(&mut self) -> io::Result<OfflineJournalReadView<'_>> {
        self.sync_all()?;
        let result = (|| {
            let length = self.policy.facts()?.journal_length;
            let position = self.journal.stream_position()?;
            require(
                position <= length,
                "actual J position outside authenticated length",
            )?;
            Ok((length, position))
        })();
        let (length, position) = result.map_err(|e| self.poison(e))?;
        Ok(OfflineJournalReadView {
            file: self.journal,
            length,
            position,
            writer_poison: &mut self.poisoned,
            owner_poison: &mut self.core.poisoned,
        })
    }
    pub fn revalidate(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            self.sync_all()?;
            self.gate
                .require_bound(self.core, &self.policy, self.journal, self.pins)?;
            require_native(self.gate, self.core, self.native)?;
            self.prepared_protection(events)?;
            authenticate(
                self.core,
                &self.policy,
                self.journal,
                self.pins,
                phase(self.gate.activation, false),
                events,
            )
            .map(|_| ())
        })();
        result.map_err(|e| self.poison(e))
    }
    pub fn finish_new(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            require(
                !matches!(self.gate.activation, Activation::Replay(PagedRecoveryDirection::Rollback) | Activation::PreparedReplay(PagedRecoveryDirection::Rollback)),
                "rollback writer cannot finish NEW",
            )?;
            self.revalidate(events)?;
            authenticate(
                self.core,
                &self.policy,
                self.journal,
                self.pins,
                PartitionJournalPhase::New,
                events,
            )?;
            self.revalidate(events)
        })();
        result.map_err(|e| self.poison(e))
    }
    pub fn finish_old(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        let result = (|| {
            require(
                matches!(self.gate.activation, Activation::Replay(PagedRecoveryDirection::Rollback) | Activation::PreparedReplay(PagedRecoveryDirection::Rollback)),
                "finish OLD requires actual Rollback writer",
            )?;
            self.revalidate(events)?;
            authenticate(
                self.core,
                &self.policy,
                self.journal,
                self.pins,
                PartitionJournalPhase::Restored,
                events,
            )?;
            self.revalidate(events)
        })();
        result.map_err(|e| self.poison(e))
    }
}
impl Read for OfflinePagedWriter<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.sync_all()?;
        self.core.read(out).map_err(|e| self.poison(e))
    }
}
impl Seek for OfflinePagedWriter<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.sync_all()?;
        self.core.seek(from).map_err(|e| self.poison(e))
    }
}
impl Write for OfflinePagedWriter<'_, '_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let result = (|| {
            self.sync_all()?;
            require(
                input.len() <= MAX_IO
                    && input.len().is_multiple_of(4096)
                    && self.core.position.is_multiple_of(4096),
                "offline paged write geometry invalid",
            )?;
            let attempted = self
                .requested
                .checked_add(input.len() as u64)
                .ok_or_else(|| invalid("offline source write counter overflow"))?;
            let facts = self.policy.facts()?;
            require(
                attempted <= facts.selected_bytes
                    && self
                        .policy
                        .permits(self.core.position, input.len() as u64)?
                    && self
                        .core
                        .position
                        .checked_add(input.len() as u64)
                        .is_some_and(|end| end <= self.byte_len()),
                "offline write escapes authenticated selected source ranges",
            )?;
            let relative = self.core.position;
            let absolute = self
                .core
                .env
                .source
                .storage
                .identity
                .partition_offset
                .checked_add(relative)
                .ok_or_else(|| invalid("offline source write base overflow"))?;
            require(
                absolute.checked_add(input.len() as u64).is_some_and(|end| {
                    end <= self.core.env.source.storage.identity.disk_bytes
                        && end <= i64::MAX as u64
                }),
                "offline write crosses physical disk bound",
            )?;
            require(
                source_io(
                    self.core.file.seek(SeekFrom::Start(absolute)),
                    "offline physical prewrite seek",
                    relative,
                    input.len(),
                )? == absolute,
                "offline physical write seek differs",
            )?;
            self.prepared_write_checkpoint()?;
            self.core.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
            self.requested = attempted;
            let count = source_io(
                self.core
                    .file
                    .write(&self.core.buffer.bytes_mut()[..input.len()]),
                "offline physical WriteFile",
                relative,
                input.len(),
            )?;
            require(
                count == input.len(),
                "short offline physical source write; reopen actual recovery",
            )?;
            self.written = self
                .written
                .checked_add(count as u64)
                .ok_or_else(|| invalid("offline completed write counter overflow"))?;
            self.core.position += count as u64;
            self.pending = Some((relative, count, Sha256::digest(input).into()));
            Ok(count)
        })();
        result.map_err(|e| self.poison(e))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
pub struct OfflineJournalReadView<'a> {
    file: &'a mut File,
    length: u64,
    position: u64,
    writer_poison: &'a mut bool,
    owner_poison: &'a mut bool,
}
impl OfflineJournalReadView<'_> {
    fn checked<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            *self.writer_poison = true;
            *self.owner_poison = true;
        }
        result
    }
}
impl Read for OfflineJournalReadView<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let result = (|| {
            require(
                !*self.writer_poison && !*self.owner_poison,
                "poisoned offline J view",
            )?;
            let n = (out.len().min(MAX_IO) as u64).min(self.length - self.position) as usize;
            if n == 0 {
                return Ok(0);
            }
            require(
                self.file.seek(SeekFrom::Start(self.position))? == self.position,
                "offline J view seek differs",
            )?;
            let got = self.file.read(&mut out[..n])?;
            require(
                got > 0 && got <= n,
                "short/invalid offline J read before authenticated EOF",
            )?;
            self.position += got as u64;
            Ok(got)
        })();
        self.checked(result)
    }
}
impl Seek for OfflineJournalReadView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let result = (|| {
            require(
                !*self.writer_poison && !*self.owner_poison,
                "poisoned offline J view",
            )?;
            let at = match from {
                SeekFrom::Start(n) => i128::from(n),
                SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
                SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
            };
            require(
                at >= 0 && at <= i128::from(self.length),
                "offline J view leaves actual journal length",
            )?;
            self.position = at as u64;
            Ok(self.position)
        })();
        self.checked(result)
    }
}
pub struct OfflineClosedJournalObservation {
    owner: OfflineSourceOwnerToken,
    binding: PartitionSourceBinding,
    boot: OfflineBootIdentity,
    pins: OwnedPartitionJournalPins,
    index_sha256: [u8; 32],
    kind: OfflineTerminalKind,
}
pub(super) fn closed(
    core: &mut Core,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    kind: OfflineTerminalKind,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineClosedJournalObservation> {
    authenticate(
        core,
        policy,
        journal,
        pins,
        match kind {
            OfflineTerminalKind::Handoff => PartitionJournalPhase::Handoff,
            OfflineTerminalKind::Aborted => PartitionJournalPhase::Aborted,
        },
        events,
    )?;
    Ok(OfflineClosedJournalObservation {
        owner: core.token.clone(),
        binding: core.env.source.clone(),
        boot: core.env.facts.boot.clone(),
        pins: OwnedPartitionJournalPins::capture(pins),
        index_sha256: policy.facts()?.index_sha256,
        kind,
    })
}
impl OfflineClosedJournalObservation {
    pub fn kind(&self) -> OfflineTerminalKind {
        self.kind
    }
    pub fn require_owner(&self, owner: &OfflineSourceOwnerToken) -> io::Result<()> {
        require(
            self.owner.same_owner(owner),
            "offline closed-J observation belongs to another actual source",
        )
    }
    pub(super) fn revalidate(
        &self,
        core: &mut Core,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_owner(&core.token)?;
        self.pins.require(pins)?;
        require(
            self.binding == core.env.source
                && self.boot == core.env.facts.boot
                && self.index_sha256 == policy.facts()?.index_sha256,
            "offline closed-J source/epoch/index changed",
        )?;
        authenticate(
            core,
            policy,
            journal,
            pins,
            match self.kind {
                OfflineTerminalKind::Handoff => PartitionJournalPhase::Handoff,
                OfflineTerminalKind::Aborted => PartitionJournalPhase::Aborted,
            },
            events,
        )
        .map(|_| ())
    }
    pub fn revalidate_frozen(
        &self,
        source: &mut OfflineFrozenSource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.revalidate(&mut source.core, policy, journal, pins, events)
    }
    pub fn revalidate_recovery(
        &self,
        source: &mut OfflineRecoverySource,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.revalidate(&mut source.core, policy, journal, pins, events)
    }
}
macro_rules! closed_owner {
    ($type:ty) => {
        impl $type {
            /// Complete actual HND/ABT source/J evidence, not a mount/repair/replay grant.
            pub fn authenticate_closed(
                &mut self,
                policy: &HeldPagedWritePolicy,
                journal: &mut File,
                pins: &PagedRecoveryPins<'_>,
                kind: OfflineTerminalKind,
                events: &mut Vec<NativeEvent>,
            ) -> io::Result<OfflineClosedJournalObservation> {
                closed(&mut self.core, policy, journal, pins, kind, events)
            }
        }
    };
}
closed_owner!(OfflineFrozenSource);
closed_owner!(OfflineRecoverySource);

// Only the opaque prepared-source/boot-guard entry calls this factory.
pub(super) fn qualify_prepared(
    core: &mut Core,
    policy: &HeldPagedWritePolicy,
    journal: &mut File,
    pins: &PagedRecoveryPins<'_>,
    publication: super::prepared_apply::PreparedPublicationPin,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineSourceApplyGate> {
    require(
        !core.poisoned
            && !core.fresh
            && !core.gate_ever_issued
            && !core.writer_ever_issued
            && core.expected_attributes == 3,
        "prepared activation needs a new excluded cold owner",
    )?;
    let current = authenticate(
        core,
        policy,
        journal,
        pins,
        PartitionJournalPhase::FreshOld,
        events,
    )?;
    require(
        current.is_none(),
        "prepared clear OLD checker returned mixed state",
    )?;
    let gate = OfflineSourceApplyGate {
        owner: core.token.clone(),
        binding: core.env.source.clone(),
        boot: core.env.facts.boot.clone(),
        pins: OwnedPartitionJournalPins::capture(pins),
        index_sha256: policy.facts()?.index_sha256,
        journal_handle: journal.as_raw_handle() as usize,
        current_mixed_sha256: None,
        lifecycle_sha256: lifecycle_digest(journal)?,
        native_pin: None,
        prepared_pin: Some(publication),
        activation: Activation::Prepared,
        used: false,
    };
    core.gate_ever_issued = true;
    Ok(gate)
}
pub(super) fn require_prepared_gate(gate: &OfflineSourceApplyGate) -> io::Result<()> {
    require(
        gate.activation == Activation::Prepared && gate.prepared_pin.is_some(),
        "actual prepared activation gate required",
    )
}

// Distinct cold-prepared recovery factory: legacy PE-fresh and standalone
// recovery entrypoints keep their original activation/protection contract.
pub(super) fn qualify_prepared_replay(core:&mut Core,policy:&HeldPagedWritePolicy,journal:&mut File,
    pins:&PagedRecoveryPins<'_>,publication:super::prepared_apply::PreparedPublicationPin,direction:PagedRecoveryDirection,
    events:&mut Vec<NativeEvent>)->io::Result<OfflineSourceApplyGate>{
    require(!core.poisoned&&!core.fresh&&core.fresh_witness.is_none()&&!core.gate_ever_issued&&!core.writer_ever_issued
        &&core.expected_attributes==3,"prepared replay needs new actual excluded cold owner")?;
    let current=authenticate(core,policy,journal,pins,PartitionJournalPhase::Mixed(direction),events)?;
    require(current.is_some(),"prepared replay CURRENT mixed digest absent")?;
    let gate=OfflineSourceApplyGate{owner:core.token.clone(),binding:core.env.source.clone(),boot:core.env.facts.boot.clone(),
        pins:OwnedPartitionJournalPins::capture(pins),index_sha256:policy.facts()?.index_sha256,journal_handle:journal.as_raw_handle()as usize,
        current_mixed_sha256:current,lifecycle_sha256:lifecycle_digest(journal)?,native_pin:None,prepared_pin:Some(publication),
        activation:Activation::PreparedReplay(direction),used:false};
    core.gate_ever_issued=true;Ok(gate)
}
pub(super) fn require_prepared_replay_gate(gate:&OfflineSourceApplyGate,direction:PagedRecoveryDirection)->io::Result<()> {
    require(gate.activation==Activation::PreparedReplay(direction)&&gate.prepared_pin.is_some(),"actual guarded prepared replay gate/direction required")
}
