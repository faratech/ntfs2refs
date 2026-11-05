//! Actual offline-machine source ownership. No legacy Windows-C/layout guard
//! changes and no source writer or online/repair operation is exposed here.
mod native_observation;
mod paged;
mod prepared;
mod prepared_apply;
pub use prepared_apply::{OfflinePreparedTerminalSource,OfflinePreparedAvailableSource};
pub use prepared::{OfflinePreparedSource, OfflinePreparedJournalQualification, OfflinePreparedBootGuardRequirements};
use super::*;
use crate::native::{
    AlignedBuffer, MAX_IO, close_file,
    partition_lifecycle::{PartitionNativeEventSink, PartitionPreparationObserver},
    set_attributes,
};
pub use native_observation::{
    OfflineFreshWitness, OfflinePagedNtfsObservation, OfflineReadonlyNtfsPhase,
};
pub use paged::{
    OfflineClosedJournalObservation, OfflineJournalReadView, OfflinePagedWriter,
    OfflineSourceApplyGate, OfflineTerminalKind,
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    sync::Arc,
};
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};
const DISK_OFFLINE: u64 = 1;
const DISK_READONLY: u64 = 2;
const BASIC: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";

#[derive(Clone)]
pub struct OfflineSourceOwnerToken(Arc<()>);
impl OfflineSourceOwnerToken {
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct OfflineSourceState {
    pub binding: PartitionSourceBinding,
    pub actual: OfflineSourcePhysicalFacts,
    pub mode: &'static str,
    pub original_live_volume_locks_acquired: bool,
    pub current_filesystem_lock_claimed: bool,
    pub disk_offline_in_current_environment: bool,
    pub cross_environment_restart_exclusion_qualified: bool,
    pub source_gate_ever_issued: bool,
    pub source_writer_issued: bool,
    pub serialized_state_grants_authority: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct OfflineSourceIntentPin {
    pub kind: &'static str,
    pub binding: PartitionSourceBinding,
    pub intent_file: crate::reference_file::ReferenceFileSnapshot,
    pub intent_sha256: String,
    pub original_disk_attributes: u64,
    pub desired_disk_attributes: u64,
    pub actual_source_metadata_sha256: String,
    pub actual_boot: OfflineBootIdentity,
    pub serialized_pin_grants_authority: bool,
}
struct HeldIntent {
    file: File,
    pin: OfflineSourceIntentPin,
}
impl HeldIntent {
    fn persist(
        mut file: File,
        env: &OfflineOwningEnvironment,
        journal: &GeneralJournalStorageBinding,
        desired: u64,
    ) -> io::Result<Self> {
        let maximum = env.budget.ram_bytes / 8;
        let before =
            crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        require(
            before.file_bytes == 0
                && before.number_of_links == 1
                && before.file_attributes & 0x0e00 == 0,
            "fresh ordinary nonsparse/uncompressed external intent file required",
        )?;
        let route = journal.disk.volume_path()?;
        require(
            before
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(route.to_ascii_lowercase() + "\\")),
            "actual intent file is not on the independently native-bound journal volume",
        )?;
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(&before.final_path)
        {
            Err(e) if e.raw_os_error() == Some(32) => (),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("intent exclusive ownership unproved: {e}"),
                ));
            }
            Ok(_) => return Err(invalid("offline intent permits another ordinary writer")),
        }
        let actual_source_metadata_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&env.facts.source_physical).map_err(io::Error::other)?,
        ));
        let body=serde_json::to_vec(&serde_json::json!({"version":1,"kind":"offline-whole-source-disk-preparation-intent-v1",
            "source":env.source,"original_disk_attributes":env.facts.source_physical.disk_attributes,
            "desired_disk_attributes":desired,"actual_source_metadata_sha256":actual_source_metadata_sha256,
            "actual_boot":env.facts.boot,"source_write_gate_issued":false,"process_death_writer_authority":false})).map_err(io::Error::other)?;
        require(
            body.len() as u64 <= maximum,
            "offline durable intent exceeds prepaid metadata budget",
        )?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&body)?;
        file.sync_all()?;
        let mut readback = vec![0; body.len()];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut readback)?;
        require(readback == body, "offline intent flush/readback differs")?;
        let slack = crate::file_storage::artifact_allocation_slack(&file)?;
        let normalized = crate::file_storage::normalize_allocation_at_eof(
            &file,
            body.len() as u64,
            maximum,
            slack,
        )?;
        let snapshot =
            crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        require(
            snapshot.file_id_128 == before.file_id_128
                && snapshot.volume_serial_number == before.volume_serial_number
                && snapshot.final_path == before.final_path
                && snapshot.file_bytes == body.len() as u64
                && snapshot.number_of_links == 1
                && snapshot == normalized.after,
            "actual intent identity/EOF changed across durable write",
        )?;
        let pin = OfflineSourceIntentPin {
            kind: "offline-whole-source-disk-preparation-v1",
            binding: env.source.clone(),
            intent_file: snapshot,
            intent_sha256: hex::encode(Sha256::digest(&body)),
            original_disk_attributes: env.facts.source_physical.disk_attributes,
            desired_disk_attributes: desired,
            actual_source_metadata_sha256,
            actual_boot: env.facts.boot.clone(),
            serialized_pin_grants_authority: false,
        };
        Ok(Self { file, pin })
    }
    fn revalidate(&mut self) -> io::Result<()> {
        let before = crate::reference_file::observe_reference_file_handle_with_limit(
            &self.file,
            self.pin.intent_file.file_bytes,
        )?;
        require(
            before == self.pin.intent_file,
            "held offline intent identity changed",
        )?;
        require(
            hex::encode(crate::sha256_native::hash_range(
                &mut self.file,
                0,
                before.file_bytes,
            )?) == self.pin.intent_sha256,
            "held offline intent SHA256 changed",
        )?;
        require(
            crate::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                before.file_bytes,
            )? == before,
            "held offline intent changed during hash",
        )
    }
}
struct Volumes(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Volumes {
    fn drop(&mut self) {
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
fn checkpoint(
    sink: &PartitionNativeEventSink,
    phase: &'static str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    sink.checkpoint(phase, events)
}
fn catalog_names(maximum: u64) -> io::Result<Vec<String>> {
    let mut out = [0u16; 1024];
    let handle = unsafe { FindFirstVolumeW(out.as_mut_ptr(), out.len() as u32) };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let enumeration = Volumes(handle);
    let mut names = Vec::new();
    let mut complete = false;
    for _ in 0..maximum {
        let n = out
            .iter()
            .position(|u| *u == 0)
            .ok_or_else(|| invalid("closing volume catalog name unterminated"))?;
        let name = text(&out[..n])?;
        require(
            name.len() == 49 && name.starts_with(r"\\?\Volume{") && name.ends_with("}\\"),
            "closing catalog contains malformed volume GUID",
        )?;
        names.push(name);
        out.fill(0);
        if unsafe { FindNextVolumeW(enumeration.0, out.as_mut_ptr(), out.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(18) {
                complete = true;
                break;
            }
            return Err(error);
        }
    }
    require(complete, "closing native volume catalog incomplete")?;
    names.sort();
    require(
        !names.windows(2).any(|v| v[0] == v[1]),
        "duplicate native volume GUID catalog",
    )?;
    Ok(names)
}
fn lock_source_volumes(
    env: &mut OfflineOwningEnvironment,
    sink: &PartitionNativeEventSink,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<File>> {
    checkpoint(sink, "offline-source-volume-inventory-opening", events)?;
    let mut name = [0u16; 1024];
    let handle = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let enumeration = Volumes(handle);
    let maximum = env.budget.ram_bytes / 4096;
    let mut locked = Vec::new();
    let mut selected_seen = false;
    let mut complete = false;
    let mut identities = Vec::<Vec<u8>>::new();
    let mut names = Vec::new();
    for _ in 0..maximum {
        let n = name
            .iter()
            .position(|u| *u == 0)
            .ok_or_else(|| invalid("source volume inventory name unterminated"))?;
        let path = text(&name[..n])?;
        require(
            path.starts_with(r"\\?\Volume{") && path.ends_with("}\\") && path.len() == 49,
            "source volume inventory returned non-GUID path",
        )?;
        names.push(path.clone());
        if unsafe { GetDriveTypeW(wide(&path).as_ptr()) } != 6 {
            // Metadata only; no source file enumeration/payload read.
            let query = OpenOptions::new()
                .access_mode(0x0010_0080)
                .share_mode(3)
                .open(path.trim_end_matches('\\'))?;
            let device = control(
                &query,
                "offline-volume-inventory-device",
                DEVICE,
                &[],
                12,
                events,
            )?;
            require(
                device.len() == 12,
                "source volume inventory device reply incomplete",
            )?;
            if layout::u32_at(&device, 0)? == 7
                && layout::u32_at(&device, 4)? == env.source.storage.disk_number
            {
                let ext = control(
                    &query,
                    "offline-volume-inventory-extents",
                    VOLUME_EXTENTS,
                    &[],
                    32,
                    events,
                )?;
                let info = control(
                    &query,
                    "offline-volume-inventory-native-info",
                    0x0007_0048,
                    &[],
                    144,
                    events,
                )?;
                require(
                    ext.len() == 32
                        && layout::u32_at(&ext, 0)? == 1
                        && layout::u32_at(&ext, 8)? == env.source.storage.disk_number
                        && info.len() == 144
                        && layout::u32_at(&info, 0)? == 1
                        && layout::u64_at(&ext, 16)? == layout::u64_at(&info, 8)?
                        && layout::u64_at(&ext, 24)? == layout::u64_at(&info, 16)?,
                    "source disk has unsupported/ambiguous mounted extent",
                )?;
                let matches = env.facts.source_physical.gpt.native_layout[48..]
                    .chunks_exact(144)
                    .filter(|r| *r == info.as_slice())
                    .count();
                require(
                    matches == 1 && !identities.iter().any(|old| *old == info),
                    "mounted source-disk volume is duplicate or absent from full GPT",
                )?;
                identities.push(info.clone());
                selected_seen |= info[48..64]
                    == layout::guid_bytes(&env.source.storage.identity.partition_guid)?;
                close_file(
                    query,
                    "offline-source-volume-query-close-before-real-lock",
                    events,
                )?;
                let volume = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(3)
                    .custom_flags(0xa000_0000)
                    .open(path.trim_end_matches('\\'))?;
                require(
                    control(
                        &volume,
                        "offline-real-lock-current-volume-info",
                        0x0007_0048,
                        &[],
                        144,
                        events,
                    )? == info,
                    "new locking FileObject names another actual source-disk volume",
                )?;
                for (code, phase) in [
                    (crate::native::LOCK, "offline-source-volume-actual-LOCK"),
                    (
                        crate::native::DISMOUNT,
                        "offline-source-volume-actual-DISMOUNT",
                    ),
                    (0x0009_0083, "offline-source-volume-extended-DASD"),
                ] {
                    require(
                        control(&volume, phase, code, &[], 0, events)?.is_empty(),
                        "source-volume lock/dismount control reply differs",
                    )?;
                }
                // Real LOCK flushes cached data. Do not drop this FileObject
                // until actual persistent whole-disk OFFLINE|READONLY is proved.
                require(
                    control(
                        &volume,
                        "offline-locked-source-volume-closing-info",
                        0x0007_0048,
                        &[],
                        144,
                        events,
                    )? == info,
                    "locked source volume identity changed",
                )?;
                locked.push(volume);
            } else {
                close_file(query, "offline-nonsource-volume-query-close", events)?;
            }
        }
        checkpoint(sink, "offline-source-volume-inventory-row-closed", events)?;
        name.fill(0);
        if unsafe { FindNextVolumeW(enumeration.0, name.as_mut_ptr(), name.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(18) {
                complete = true;
                break;
            }
            return Err(error);
        }
    }
    require(
        complete && selected_seen && !locked.is_empty(),
        "complete source-disk mounted inventory and actual selected-volume lock required",
    )?;
    names.sort();
    require(
        catalog_names(maximum)? == names,
        "native volume catalog changed while real source locks were acquired",
    )?;
    for (volume, expected) in locked.iter().zip(&identities) {
        require(
            control(
                volume,
                "offline-source-real-lock-closing-native-info",
                0x0007_0048,
                &[],
                144,
                events,
            )? == *expected,
            "original locking source FileObject changed before persistent exclusion",
        )?;
        checkpoint(sink, "offline-source-all-locks-closing-native-info", events)?;
    }
    Ok(locked)
}
struct Core {
    env: OfflineOwningEnvironment,
    file: File,
    expected_attributes: u64,
    position: u64,
    buffer: AlignedBuffer,
    token: OfflineSourceOwnerToken,
    poisoned: bool,
    fresh: bool,
    gate_ever_issued: bool,
    writer_ever_issued: bool,
    fresh_witness: Option<native_observation::OfflineFreshWitness>,
    native_read_bytes_requested: u64,
    native_read_bytes_succeeded: u64,
    native_read_error_count: u64,
    native_read_short_count: u64,
    intent: Option<HeldIntent>,
    sink: PartitionNativeEventSink,
}
impl Core {
    fn state(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<OfflineSourceState> {
        checkpoint(&self.sink, "offline-owned-source-state-opening", events)?;
        let result = (|| {
            require(!self.poisoned, "offline source owner poisoned")?;
            self.env
                .require_current_at_attributes(self.expected_attributes, events)?;
            // Raw GPT metadata reads need a separate buffered readonly object;
            // the source data object is NO_BUFFERING and its aligned window
            // never becomes a general metadata/file/raw-handle API.
            let mut metadata = device_file(
                &format!(
                    "\\\\.\\PhysicalDrive{}",
                    self.env.source.storage.disk_number
                ),
                false,
                false,
            )?;
            let actual = source_facts(&mut metadata, &self.env.source, self.env.budget, events)?;
            let device = control(
                &self.file,
                "offline-source-data-device",
                DEVICE,
                &[],
                12,
                events,
            )?;
            let length = control(
                &self.file,
                "offline-source-data-length",
                LENGTH,
                &[],
                8,
                events,
            )?;
            let layout = control(
                &self.file,
                "offline-source-data-full-native-layout",
                LAYOUT,
                &[],
                65536,
                events,
            )?;
            require(
                device == actual.device
                    && length == actual.length
                    && layout == actual.gpt.native_layout,
                "actual data FileObject differs from complete metadata source",
            )?;
            close_file(
                metadata,
                "offline-source-state-readonly-metadata-close",
                events,
            )?;
            require(
                actual.disk_attributes == self.expected_attributes,
                "held offline source data FileObject lost disk protection",
            )?;
            let mut expected = self.env.facts.source_physical.clone();
            expected.disk_attributes = self.expected_attributes;
            require(
                actual == expected,
                "same held physical source file lost actual full GPT/native identity",
            )?;
            if let Some(intent) = self.intent.as_mut() {
                intent.revalidate()?;
            }
            Ok(OfflineSourceState {
                binding: self.env.source.clone(),
                actual,
                mode: if self.fresh {
                    "fresh-whole-disk-frozen"
                } else {
                    "reopened-whole-disk-excluded"
                },
                original_live_volume_locks_acquired: self.fresh,
                current_filesystem_lock_claimed: false,
                disk_offline_in_current_environment: self.expected_attributes & DISK_OFFLINE != 0,
                cross_environment_restart_exclusion_qualified: false,
                source_gate_ever_issued: self.gate_ever_issued,
                source_writer_issued: self.writer_ever_issued,
                serialized_state_grants_authority: false,
            })
        })();
        let closed = checkpoint(&self.sink, "offline-owned-source-state-closed", events);
        match (result, closed) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let length = self.env.source.storage.identity.partition_bytes;
        let pos = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(length) + i128::from(n),
        };
        if self.poisoned || pos < 0 || pos > i128::from(length) {
            self.poisoned = true;
            return Err(invalid("offline source seek leaves selected partition"));
        }
        self.position = pos as u64;
        Ok(self.position)
    }
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        require(!self.poisoned, "offline source is poisoned")?;
        let length = self.env.source.storage.identity.partition_bytes;
        if out.is_empty() || self.position == length {
            return Ok(0);
        }
        let lead = (self.position % 4096) as usize;
        let count = (out.len().min(MAX_IO - lead) as u64).min(length - self.position) as usize;
        let sector = self.env.source.storage.identity.logical_sector_bytes as usize;
        let bytes = (lead + count).div_ceil(sector) * sector;
        let relative = self.position - lead as u64;
        let result = (|| {
            require(
                relative
                    .checked_add(bytes as u64)
                    .is_some_and(|e| e <= length),
                "aligned offline read escapes selected partition",
            )?;
            let absolute = self
                .env
                .source
                .storage
                .identity
                .partition_offset
                .checked_add(relative)
                .ok_or_else(|| invalid("offline source read base overflow"))?;
            require(
                absolute.checked_add(bytes as u64).is_some_and(|e| {
                    e <= self.env.source.storage.identity.disk_bytes && e <= i64::MAX as u64
                }),
                "offline source read escapes disk",
            )?;
            require(
                self.file.seek(SeekFrom::Start(absolute))? == absolute,
                "offline source physical seek differs",
            )?;
            self.native_read_bytes_requested = self
                .native_read_bytes_requested
                .checked_add(bytes as u64)
                .ok_or_else(|| invalid("offline physical read request counter overflow"))?;
            let n = match self.file.read(&mut self.buffer.bytes_mut()[..bytes]) {
                Ok(n) => {
                    self.native_read_bytes_succeeded = self
                        .native_read_bytes_succeeded
                        .checked_add(n as u64)
                        .ok_or_else(|| invalid("offline physical read success counter overflow"))?;
                    n
                }
                Err(error) => {
                    self.native_read_error_count = self
                        .native_read_error_count
                        .checked_add(1)
                        .ok_or_else(|| invalid("offline physical read error counter overflow"))?;
                    return Err(error);
                }
            };
            if n < lead + count {
                self.native_read_short_count = self
                    .native_read_short_count
                    .checked_add(1)
                    .ok_or_else(|| invalid("offline short-read counter overflow"))?;
                return Err(invalid("offline source physical read short"));
            }
            out[..count].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + count]);
            self.position += count as u64;
            Ok(count)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
/// Actual fresh all-volume freeze; no Write/raw-handle/JSON constructor.
pub struct OfflineFrozenSource {
    core: Core,
}
/// Actual current already-excluded disk, never a fresh NTFS admission.
pub struct OfflineRecoverySource {
    core: Core,
}
fn require_owner_budget(budget: PartitionObservationBudget) -> io::Result<()> {
    let metadata = add(
        add(
            mul(budget.gpt_entry_bytes, 8)?,
            mul(u64::from(budget.native_layout_bytes), 8)?,
        )?,
        add(
            mul(u64::from(budget.read_buffer_bytes), 2)?,
            2 * 1024 * 1024,
        )?,
    )?;
    require(
        add(metadata, MAX_IO as u64 + 4096)? <= budget.ram_bytes,
        "actual source owner aligned buffer exceeds independent SDK RAM budget",
    )
}
impl OfflineFrozenSource {
    pub fn fresh_witness(&self) -> Option<&native_observation::OfflineFreshWitness> {
        self.core.fresh_witness.as_ref()
    }
    /// Caller reserves this PLUS actual artifact_allocation_slack before entry.
    pub fn maximum_intent_file_bytes(budget: PartitionObservationBudget) -> io::Result<u64> {
        budget.validate()?;
        Ok(budget.ram_bytes / 8)
    }
    pub fn freeze(
        mut env: OfflineOwningEnvironment,
        journal: &GeneralJournalStorageBinding,
        journal_volume: &File,
        intent: File,
        observer: Box<dyn PartitionPreparationObserver>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        require_owner_budget(env.budget)?;
        let sink = PartitionNativeEventSink::new(observer);
        checkpoint(&sink, "offline-fresh-source-freeze-opening", events)?;
        require(
            journal.disk.disk_number != env.source.storage.disk_number
                && layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != layout::guid_bytes(&env.source.storage.identity.disk_guid)?,
            "whole-source-disk freeze requires an independent journal disk",
        )?;
        env.require_journal_disjoint(journal, journal_volume, events)?;
        require(
            env.facts.source_physical.disk_attributes == 0
                && env.facts.source_physical.gpt.target_attributes == 0,
            "fresh offline source must start at actual online writable disk and original target attrs0",
        )?;
        let guid = layout::guid_bytes(&env.source.storage.identity.partition_guid)?;
        let row = env.facts.source_physical.gpt.native_layout[48..]
            .chunks_exact(144)
            .find(|r| r[48..64] == guid)
            .ok_or_else(|| invalid("fresh selected source native row missing"))?;
        require(
            row[32..48] == layout::guid_bytes(BASIC)?,
            "fresh offline owner cannot reinterpret legacy/private AP source",
        )?;
        checkpoint(&sink, "offline-fresh-source-journal-native-bound", events)?;
        let fresh_witness =
            native_observation::capture_offline_fresh_witness(&mut env, &sink, events)?;
        fresh_witness.require_environment(&mut env, events)?;
        checkpoint(
            &sink,
            "offline-actual-prelock-NTFS-witness-captured",
            events,
        )?;
        let locked = lock_source_volumes(&mut env, &sink, events)?;
        env.require_current(events)?;
        checkpoint(&sink, "offline-all-source-volume-locks-held", events)?;
        let held_intent = HeldIntent::persist(intent, &env, journal, DISK_OFFLINE | DISK_READONLY)?;
        checkpoint(
            &sink,
            "offline-source-intent-durable-before-disk-setter",
            events,
        )?;
        let management = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                env.source.storage.disk_number
            ))?;
        require(
            source_facts(
                &mut management.try_clone()?,
                &env.source,
                env.budget,
                events,
            )? == env.facts.source_physical,
            "actual source management FileObject changed before whole-disk freeze",
        )?;
        set_attributes(&management, DISK_OFFLINE | DISK_READONLY, events)?;
        env.require_current_at_attributes(DISK_OFFLINE | DISK_READONLY, events)?;
        checkpoint(&sink, "offline-source-actual-persistent-disk3", events)?;
        for volume in locked {
            close_file(
                volume,
                "offline-original-volume-lock-close-AFTER-disk3",
                events,
            )?;
        }
        close_file(management, "offline-source-freeze-management-close", events)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                env.source.storage.disk_number
            ))?;
        let mut result = Self {
            core: Core {
                env,
                file,
                expected_attributes: DISK_OFFLINE | DISK_READONLY,
                position: 0,
                buffer: AlignedBuffer::new()?,
                token: OfflineSourceOwnerToken(Arc::new(())),
                poisoned: false,
                fresh: true,
                gate_ever_issued: false,
                writer_ever_issued: false,
                native_read_bytes_requested: 0,
                native_read_bytes_succeeded: 0,
                native_read_error_count: 0,
                native_read_short_count: 0,
                fresh_witness: Some(fresh_witness),
                intent: Some(held_intent),
                sink,
            },
        };
        result.state(events)?;
        Ok(result)
    }
    pub fn preparation_pin(&self) -> &OfflineSourceIntentPin {
        &self
            .core
            .intent
            .as_ref()
            .expect("fresh owner holds actual intent")
            .pin
    }
}
impl OfflineRecoverySource {
    pub fn open_recovery(
        mut env: OfflineOwningEnvironment,
        observer: Box<dyn PartitionPreparationObserver>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        require_owner_budget(env.budget)?;
        let sink = PartitionNativeEventSink::new(observer);
        checkpoint(&sink, "offline-reopened-source-opening", events)?;
        env.require_current(events)?;
        let expected = env.facts.source_physical.disk_attributes;
        require(
            matches!(expected, 1 | 3),
            "recovery source must ALREADY be actual persistently offline disk1/3",
        )?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                env.source.storage.disk_number
            ))?;
        let mut result = Self {
            core: Core {
                env,
                file,
                expected_attributes: expected,
                position: 0,
                buffer: AlignedBuffer::new()?,
                token: OfflineSourceOwnerToken(Arc::new(())),
                poisoned: false,
                fresh: false,
                gate_ever_issued: false,
                writer_ever_issued: false,
                native_read_bytes_requested: 0,
                native_read_bytes_succeeded: 0,
                native_read_error_count: 0,
                native_read_short_count: 0,
                fresh_witness: None,
                intent: None,
                sink,
            },
        };
        result.state(events)?;
        Ok(result)
    }
}
macro_rules! readonly_owner {
    ($type:ty) => {
        impl $type {
            /// These count this aligned physical source-data reader only;
            /// GPT/native metadata, filesystem collectors and J I/O are separate.
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
            pub fn read_buffer_memory_bytes() -> u64 {
                MAX_IO as u64 + 4096
            }
            pub fn binding(&self) -> &PartitionSourceBinding {
                &self.core.env.source
            }
            pub fn byte_len(&self) -> u64 {
                self.core.env.source.storage.identity.partition_bytes
            }
            pub fn owner_token(&self) -> OfflineSourceOwnerToken {
                self.core.token.clone()
            }
            pub fn state(
                &mut self,
                events: &mut Vec<NativeEvent>,
            ) -> io::Result<OfflineSourceState> {
                self.core.state(events)
            }
        }
        impl Read for $type {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.core.read(out)
            }
        }
        impl Seek for $type {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                self.core.seek(from)
            }
        }
    };
}
readonly_owner!(OfflineFrozenSource);
readonly_owner!(OfflineRecoverySource);
