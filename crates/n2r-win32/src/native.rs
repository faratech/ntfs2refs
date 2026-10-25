use crate::layout::{self, DiskBinding, GRANULE, invalid};
use serde::Serialize;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, IntoRawHandle},
    },
    ptr::{self, NonNull},
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::{IO::DeviceIoControl, SystemInformation::GetWindowsDirectoryW};

const DEVICE: u32 = 0x002d1080;
const LENGTH: u32 = 0x0007405c;
const ALIGNMENT: u32 = 0x002d1400;
const LAYOUT: u32 = 0x00070050;
const GET_ATTRIBUTES: u32 = 0x000700f0;
const SET_ATTRIBUTES: u32 = 0x0007c0f4;
const UPDATE_PROPERTIES: u32 = 0x00070140;
const VOLUME_EXTENTS: u32 = 0x00560000;
const LOCK: u32 = 0x00090018;
const DISMOUNT: u32 = 0x00090020;
const OFFLINE: u64 = 1;
const READ_ONLY: u64 = 2;
const MAX_IO: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct NativeEvent {
    pub operation: String,
    pub control_code: u32,
    pub input: Vec<u8>,
    pub succeeded: bool,
    pub native_error: Option<i32>,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PartitionSnapshot {
    pub binding: DiskBinding,
    pub disk_attributes: u64,
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub layout: Vec<u8>,
}
/// Created only by a physically read-only native observation bracketed by
/// actual excluded-device snapshots. Exporting it cannot recreate a lease.
#[derive(Debug, Serialize)]
pub struct LiveNtfsObservation {
    report: crate::attestation::Report,
    before: PartitionSnapshot,
    after: PartitionSnapshot,
}
impl LiveNtfsObservation {
    pub fn report(&self) -> &crate::attestation::Report {
        &self.report
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.after.binding
    }
}
struct ReadonlyObservationLease<'a> {
    file: &'a File,
    events: &'a mut Vec<NativeEvent>,
    restoration_attempted: bool,
}
impl ReadonlyObservationLease<'_> {
    fn finish(&mut self) -> io::Result<()> {
        self.restoration_attempted = true;
        set_attributes(self.file, OFFLINE | READ_ONLY, self.events)?;
        control(
            self.file,
            "refresh-excluded-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            self.events,
        )?;
        Ok(())
    }
}
impl Drop for ReadonlyObservationLease<'_> {
    fn drop(&mut self) {
        if !self.restoration_attempted {
            let _ = self.finish();
        }
    }
}

#[derive(Clone, Debug)]
pub struct WritePolicy {
    pub allowed: Vec<(u64, u64)>,
    pub retained: Vec<(u64, u64)>,
    pub maximum_bytes: u64,
}

impl WritePolicy {
    pub fn validate(&self, length: u64) -> io::Result<()> {
        layout::validate_ranges(&self.allowed, length)?;
        layout::validate_ranges(&self.retained, length)?;
        let mut bytes = 0_u64;
        for &(offset, count) in &self.allowed {
            bytes = bytes
                .checked_add(count)
                .ok_or_else(|| invalid("write budget overflow"))?;
            for &(keep, keep_count) in &self.retained {
                if offset < keep + keep_count && keep < offset + count {
                    return Err(invalid("write policy overlaps retained data"));
                }
            }
        }
        if bytes > self.maximum_bytes || self.maximum_bytes > 256 * 1024 * 1024 {
            return Err(invalid(
                "native write policy exceeds the explicit 256 MiB profile",
            ));
        }
        Ok(())
    }

    fn permits(&self, offset: u64, count: u64) -> bool {
        if !offset.is_multiple_of(GRANULE) || !count.is_multiple_of(GRANULE) || count == 0 {
            return false;
        }
        offset.checked_add(count).is_some_and(|end| {
            self.allowed
                .iter()
                .any(|&(at, len)| at <= offset && end <= at + len)
        })
    }
}

fn control(
    file: &File,
    name: &str,
    code: u32,
    input: &[u8],
    capacity: usize,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    if input.len() > 64 || capacity > 65536 || events.len() >= 128 {
        return Err(invalid("native control budget exceeded"));
    }
    let mut output = vec![0; capacity];
    let mut returned = 0_u32;
    // SAFETY: File owns a live Windows handle; input/output are separately owned
    // buffers of the declared sizes. Synchronous I/O retains neither pointer.
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    if returned as usize > capacity {
        return Err(invalid(
            "native control returned more bytes than its buffer",
        ));
    }
    output.truncate(returned as usize);
    events.push(NativeEvent {
        operation: name.into(),
        control_code: code,
        input: input.to_vec(),
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: output.clone(),
    });
    if let Some(error) = error {
        return Err(io::Error::new(error.kind(), format!("{name}: {error}")));
    }
    Ok(output)
}

fn device_file(path: &str, writable: bool, unbuffered: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable).share_mode(3);
    if unbuffered {
        options.custom_flags(0xa000_0000);
    } // NO_BUFFERING | WRITE_THROUGH
    options.open(path)
}

fn attributes(file: &File, events: &mut Vec<NativeEvent>) -> io::Result<u64> {
    let bytes = control(file, "get-disk-attributes", GET_ATTRIBUTES, &[], 16, events)?;
    if bytes.len() != 16 || layout::u32_at(&bytes, 0)? != 16 {
        return Err(invalid("disk attributes response differs"));
    }
    let attributes = layout::u64_at(&bytes, 8)?;
    if attributes & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown disk attributes"));
    }
    Ok(attributes)
}

fn set_attributes(file: &File, value: u64, events: &mut Vec<NativeEvent>) -> io::Result<()> {
    if value & !(OFFLINE | READ_ONLY) != 0 {
        return Err(invalid("unknown requested attributes"));
    }
    let mut bytes = [0_u8; 40];
    bytes[..4].copy_from_slice(&40_u32.to_le_bytes());
    bytes[4] = 1; // Persist: the exclusion must survive a restart.
    bytes[8..16].copy_from_slice(&value.to_le_bytes());
    bytes[16..24].copy_from_slice(&(OFFLINE | READ_ONLY).to_le_bytes());
    control(
        file,
        "set-persistent-disk-attributes",
        SET_ATTRIBUTES,
        &bytes,
        0,
        events,
    )?;
    if attributes(file, events)? != value {
        return Err(invalid("disk attribute transition did not take effect"));
    }
    Ok(())
}

pub(crate) fn current_windows_disk(events: &mut Vec<NativeEvent>) -> io::Result<u32> {
    let mut name = vec![0_u16; 512];
    // SAFETY: the output buffer contains 512 writable UTF-16 elements.
    let count = unsafe { GetWindowsDirectoryW(name.as_mut_ptr(), name.len() as u32) } as usize;
    if count < 3 || count >= name.len() || name[1] != b':' as u16 || name[2] != b'\\' as u16 {
        return Err(invalid(
            "current Windows volume cannot be safely identified",
        ));
    }
    let letter =
        char::from_u32(u32::from(name[0])).ok_or_else(|| invalid("invalid system drive"))?;
    if !letter.is_ascii_alphabetic() {
        return Err(invalid("current Windows path is not a drive path"));
    }
    let volume = device_file(&format!("\\\\.\\{letter}:"), false, false)?;
    let bytes = control(
        &volume,
        "current-windows-extents",
        VOLUME_EXTENTS,
        &[],
        1024,
        events,
    )?;
    if bytes.len() != 32 || layout::u32_at(&bytes, 0)? != 1 {
        return Err(invalid("current Windows disk is not a simple volume"));
    }
    layout::u32_at(&bytes, 8)
}

pub(crate) fn snapshot(
    file: &File,
    binding: &DiskBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionSnapshot> {
    binding.validate()?;
    let device = control(file, "storage-device-number", DEVICE, &[], 12, events)?;
    layout::validate_device(&device, binding.disk_number)?;
    let length = control(file, "disk-length", LENGTH, &[], 8, events)?;
    if length.len() != 8 || layout::u64_at(&length, 0)? != binding.identity.disk_bytes {
        return Err(invalid("physical disk length differs"));
    }
    let mut property = [0_u8; 12];
    property[0] = 6;
    let alignment = control(file, "storage-alignment", ALIGNMENT, &property, 28, events)?;
    layout::validate_alignment(&alignment)?;
    let layout_bytes = control(file, "gpt-layout", LAYOUT, &[], 65536, events)?;
    layout::validate_layout(&layout_bytes, binding)?;
    let disk_attributes = attributes(file, events)?;
    Ok(PartitionSnapshot {
        binding: binding.clone(),
        disk_attributes,
        device,
        length,
        alignment,
        layout: layout_bytes,
    })
}

struct AlignedBuffer {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl AlignedBuffer {
    fn new() -> io::Result<Self> {
        let layout = Layout::from_size_align(MAX_IO, GRANULE as usize)
            .map_err(|_| invalid("alignment layout"))?;
        // SAFETY: layout is nonzero and valid. The allocation is owned here and
        // freed once in Drop with the identical layout; every byte is initialized.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| io::Error::other("aligned allocation failed"))?;
        Ok(Self { pointer, layout })
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: self uniquely owns MAX_IO initialized bytes at pointer.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), MAX_IO) }
    }
}
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: pointer/layout came from alloc_zeroed and are released once.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}

/// Partition-relative stream whose raw file never escapes. Drop does not clear
/// persistent offline/read-only attributes and therefore cannot mount partial data.
pub struct OfflinePartition {
    file: File,
    binding: DiskBinding,
    read_only: bool,
    position: u64,
    buffer: AlignedBuffer,
    policy: Option<WritePolicy>,
    write_poisoned: bool,
    pub native_bytes_read: u64,
    pub native_bytes_written: u64,
    pub native_write_bytes_requested: u64,
}

fn close_file(file: File, name: &str, events: &mut Vec<NativeEvent>) -> io::Result<()> {
    let raw = file.into_raw_handle();
    // SAFETY: into_raw_handle transferred sole ownership; this is the only close.
    // On failure, do not blindly close again: the handle value could be reused.
    let success = unsafe { CloseHandle(raw) } != 0;
    let error = if success {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    events.push(NativeEvent {
        operation: name.into(),
        control_code: 0,
        input: vec![],
        succeeded: success,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: vec![],
    });
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

impl OfflinePartition {
    /// Lock/dismount the bound volume, then persist physical disk exclusion.
    /// No raw payload write is issued. Failure does not bring anything online.
    pub fn isolate(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            true,
            true,
        )?;
        let before = snapshot(&file, &binding, events)?;
        if before.disk_attributes != 0 {
            return Err(invalid("initial disk must be online and writable"));
        }
        let volume = device_file(&binding.volume_path()?, true, false)?;
        let extents = control(
            &volume,
            "bound-volume-extents",
            VOLUME_EXTENTS,
            &[],
            1024,
            events,
        )?;
        layout::validate_volume_extent(&extents, &binding)?;
        // Allocate before any device mutation.
        let buffer = AlignedBuffer::new()?;
        control(&volume, "lock-volume", LOCK, &[], 0, events)?;
        control(&volume, "dismount-volume", DISMOUNT, &[], 0, events)?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        set_attributes(&file, expected, events)?;
        // Persistent exclusion is proven before closing the lock owner. Close
        // releases the volume lock; no online/unlock fallback is attempted.
        close_file(volume, "close-isolated-volume", events)?;
        let after = snapshot(&file, &binding, events)?;
        if after.disk_attributes != expected {
            return Err(invalid("disk isolation was lost"));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    /// Reopen an already excluded device after interruption. Never changes
    /// attributes as a fallback and never selects a disk by number alone.
    pub fn reopen(
        binding: DiskBinding,
        read_only: bool,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if current_windows_disk(events)? == binding.disk_number {
            return Err(invalid("current Windows disk is excluded"));
        }
        let file = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.disk_number),
            !read_only,
            true,
        )?;
        let expected = OFFLINE | if read_only { READ_ONLY } else { 0 };
        let found = snapshot(&file, &binding, events)?;
        if found.disk_attributes != expected {
            return Err(invalid(
                "persistent offline state differs; no automatic repair",
            ));
        }
        Ok(Self {
            file,
            binding,
            read_only,
            position: 0,
            buffer: AlignedBuffer::new()?,
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.binding.identity.partition_bytes
    }
    pub fn binding(&self) -> &DiskBinding {
        &self.binding
    }
    pub fn inspect(&self, events: &mut Vec<NativeEvent>) -> io::Result<PartitionSnapshot> {
        snapshot(&self.file, &self.binding, events)
    }
    /// Mount only an already frozen source read-only for supported NTFS API
    /// queries, then persist exclusion again. READ_ONLY is never cleared.
    /// A killed observer can leave a valid, write-protected NTFS mount; this
    /// operation is forbidden after reconstruction has begun.
    pub fn observe_ntfs_files(
        &mut self,
        request: &crate::attestation::Request,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<LiveNtfsObservation> {
        request.validate()?;
        if !self.read_only
            || self.policy.is_some()
            || self.native_write_bytes_requested != 0
            || self.native_bytes_written != 0
            || request.disk_number != self.binding.disk_number
            || request.volume.trim_end_matches('\\') != self.binding.volume_path()?
            || request.partition_offset != self.binding.identity.partition_offset
            || request.partition_length != self.byte_len()
        {
            return Err(invalid("read-only source observation binding differs"));
        }
        let before = self.inspect(events)?;
        if before.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("source must already be excluded and read-only"));
        }
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.disk_number),
            true,
            false,
        )?;
        let actual = snapshot(&management, &self.binding, events)?;
        if actual.disk_attributes != OFFLINE | READ_ONLY {
            return Err(invalid("control handle source state differs"));
        }
        let mut lease = ReadonlyObservationLease {
            file: &management,
            events,
            restoration_attempted: false,
        };
        set_attributes(lease.file, READ_ONLY, lease.events)?;
        control(
            lease.file,
            "refresh-readonly-source-properties",
            UPDATE_PROPERTIES,
            &[],
            0,
            lease.events,
        )?;
        // Disk attributes and volume-interface publication are distinct. Poll
        // only harmless opens, never repeat a management mutation or drop RO.
        let mut ready = false;
        for _ in 0..60 {
            if attributes(lease.file, lease.events)? != READ_ONLY {
                return Err(invalid("source read-only observation state changed"));
            }
            match device_file(&self.binding.volume_path()?, false, false) {
                Ok(volume) => {
                    drop(volume);
                    ready = true;
                    break;
                }
                Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Err(e) => return Err(e),
            }
        }
        if !ready {
            return Err(invalid(
                "read-only source volume interface was not published within 15 seconds",
            ));
        }
        let collected = crate::attestation_native::collect_file_metadata(request);
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.inspect(events)?;
        if after.disk_attributes != OFFLINE | READ_ONLY
            || before.binding != after.binding
            || before.device != after.device
            || before.layout != after.layout
            || before.length != after.length
            || before.alignment != after.alignment
        {
            return Err(invalid(
                "source identity or exclusion changed during observation",
            ));
        }
        Ok(LiveNtfsObservation {
            report: collected?,
            before,
            after,
        })
    }

    /// Caller must finish and flush its complete journal and independently
    /// validate the journal ticket before supplying this explicit write set.
    pub fn arm_writes(
        &mut self,
        policy: WritePolicy,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if self.read_only || self.policy.is_some() || self.write_poisoned {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write arming is unavailable in this state",
            ));
        }
        policy.validate(self.byte_len())?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target is not excluded from mounting"));
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        if let Err(error) = self.file.sync_all() {
            self.write_poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    /// Explicit native mount boundary. Journal handoff (or verified rollback
    /// completion) must be durable before this is called. Consumes the stream.
    pub fn bring_online(mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        if self.read_only || self.write_poisoned {
            return Err(invalid("cannot expose a read-only or failed target"));
        }
        self.policy = None;
        self.sync_all()?;
        if snapshot(&self.file, &self.binding, events)?.disk_attributes != OFFLINE {
            return Err(invalid("target isolation changed before handoff"));
        }
        set_attributes(&self.file, 0, events)?;
        close_file(self.file, "close-online-target", events)
    }
}

impl Read for OfflinePartition {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.byte_len() {
            return Ok(0);
        }
        let aligned = self.position / GRANULE * GRANULE;
        let prefix = (self.position - aligned) as usize;
        let wanted = output
            .len()
            .min(MAX_IO - prefix)
            .min((self.byte_len() - self.position) as usize);
        let count = (prefix + wanted).div_ceil(GRANULE as usize) * GRANULE as usize;
        if aligned + count as u64 > self.byte_len() {
            return Err(invalid("aligned read escapes partition"));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + aligned,
        ))?;
        let read = self.file.read(&mut self.buffer.bytes_mut()[..count])?;
        self.native_bytes_read += read as u64;
        if read != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short native aligned read",
            ));
        }
        output[..wanted].copy_from_slice(&self.buffer.bytes_mut()[prefix..prefix + wanted]);
        self.position += wanted as u64;
        Ok(wanted)
    }
}

impl Write for OfflinePartition {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let policy = self.policy.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "raw writes are not armed")
        })?;
        let attempted = self
            .native_write_bytes_requested
            .checked_add(input.len() as u64)
            .ok_or_else(|| invalid("native write accounting overflow"))?;
        if self.read_only
            || self.write_poisoned
            || input.len() > MAX_IO
            || !policy.permits(self.position, input.len() as u64)
            || attempted > policy.maximum_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native write violates bounded policy",
            ));
        }
        self.file.seek(SeekFrom::Start(
            self.binding.identity.partition_offset + self.position,
        ))?;
        self.buffer.bytes_mut()[..input.len()].copy_from_slice(input);
        // A failed/short dispatch has unknown completion. Never retry it through
        // this handle, including through Write::write_all.
        self.native_write_bytes_requested = attempted;
        let result = self.file.write(&self.buffer.bytes_mut()[..input.len()]);
        match result {
            Ok(count) => {
                self.native_bytes_written += count as u64;
                if count != input.len() {
                    self.write_poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short native write; reopen through recovery",
                    ));
                }
                self.position += count as u64;
                Ok(count)
            }
            Err(error) => {
                self.write_poisoned = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl Seek for OfflinePartition {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.byte_len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.byte_len()) {
            return Err(invalid("seek escapes partition"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PartitionIdentity;

    fn ordinary_stream() -> OfflinePartition {
        let mut file = tempfile::tempfile().unwrap();
        let bytes: Vec<u8> = (0..73728).map(|n| (n % 251) as u8).collect();
        file.write_all(&bytes).unwrap();
        OfflinePartition {
            file,
            binding: DiskBinding {
                disk_number: 1,
                volume_guid: String::new(),
                identity: PartitionIdentity {
                    disk_guid: String::new(),
                    partition_guid: String::new(),
                    partition_number: 2,
                    disk_bytes: 73728,
                    partition_offset: 4096,
                    partition_bytes: 65536,
                    logical_sector_bytes: 512,
                    physical_sector_bytes: 4096,
                },
            },
            read_only: false,
            position: 0,
            buffer: AlignedBuffer::new().unwrap(),
            policy: None,
            write_poisoned: false,
            native_bytes_read: 0,
            native_bytes_written: 0,
            native_write_bytes_requested: 0,
        }
    }

    #[test]
    fn arbitrary_reads_remain_inside_the_partition_and_match_bytes() {
        let mut stream = ordinary_stream();
        assert_eq!(stream.buffer.pointer.as_ptr() as usize % 4096, 0);
        for (at, count) in [(0, 1), (3, 5000), (4095, 4098), (65535, 10), (65536, 1)] {
            stream.seek(SeekFrom::Start(at)).unwrap();
            let mut bytes = vec![0; count];
            let read = stream.read(&mut bytes).unwrap();
            assert_eq!(read, count.min((65536 - at) as usize));
            for (index, &byte) in bytes[..read].iter().enumerate() {
                assert_eq!(byte, ((4096 + at + index as u64) % 251) as u8);
            }
        }
        assert!(stream.seek(SeekFrom::End(1)).is_err());
        assert!(stream.seek(SeekFrom::Start(u64::MAX)).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.seek(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn explicit_write_set_retained_exclusion_and_attempt_budget_are_enforced() {
        let mut stream = ordinary_stream();
        let block = vec![0xa7; 4096];
        assert!(stream.write(&block).is_err());
        let policy = WritePolicy {
            allowed: vec![(0, 4096), (8192, 4096)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
        };
        policy.validate(stream.byte_len()).unwrap();
        let bad = WritePolicy {
            allowed: vec![(0, 8192)],
            retained: vec![(4096, 4096)],
            maximum_bytes: 8192,
        };
        assert!(bad.validate(stream.byte_len()).is_err());
        stream.policy = Some(policy);
        assert!(stream.write(&block[..1]).is_err());
        stream.seek(SeekFrom::Start(4096)).unwrap();
        assert!(stream.write(&block).is_err());
        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.write_all(&block).unwrap();
        stream.seek(SeekFrom::Start(8192)).unwrap();
        stream.write_all(&block).unwrap();
        stream.sync_all().unwrap();
        stream.seek(SeekFrom::Start(0)).unwrap();
        assert!(stream.write(&block).is_err());
        assert_eq!(stream.native_bytes_written, 8192);
        assert_eq!(stream.native_write_bytes_requested, 8192);
        let mut raw = vec![0; 73728];
        stream.file.seek(SeekFrom::Start(0)).unwrap();
        stream.file.read_exact(&mut raw).unwrap();
        for (n, byte) in raw.into_iter().enumerate() {
            let changed = (4096..8192).contains(&n) || (12288..16384).contains(&n);
            assert_eq!(
                byte,
                if changed { 0xa7 } else { (n % 251) as u8 },
                "byte {n}"
            );
        }
    }
}
