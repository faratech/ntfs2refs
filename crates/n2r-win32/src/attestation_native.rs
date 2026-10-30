//! Queries only. No device/file setters or payload writes are exposed here.
use crate::attestation::*;
use std::{
    fs::File,
    io, mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree, SetLastError},
    Security::{
        AdjustTokenPrivileges, Authorization::GetSecurityInfo, GetKernelObjectSecurity,
        GetSecurityDescriptorLength, GetTokenInformation, IsValidSecurityDescriptor,
        LookupPrivilegeValueW, TOKEN_PRIVILEGES, TokenPrivileges,
    },
    Storage::FileSystem::{
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx,
        OpenFileById,
    },
    System::{
        IO::DeviceIoControl,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn raw(file: &File) -> HANDLE {
    file.as_raw_handle()
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn open(path: &str) -> io::Result<File> {
    File::options()
        .read(true)
        .share_mode(7)
        .custom_flags(0x02000000)
        .open(path)
}
fn control(file: &File, code: u32, capacity: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0; capacity];
    let mut used = 0;
    // SAFETY: live borrowed handle and writable output of the declared size;
    // synchronous IOCTL, no input or overlapped pointer.
    if unsafe {
        DeviceIoControl(
            raw(file),
            code,
            ptr::null(),
            0,
            b.as_mut_ptr().cast(),
            capacity as u32,
            &mut used,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if used as usize > capacity {
        return Err(invalid("oversized native IOCTL response"));
    }
    b.truncate(used as usize);
    Ok(b)
}
fn u64le(b: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or_else(|| invalid("short native response"))?
            .try_into()
            .unwrap(),
    ))
}
fn u32le(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(|| invalid("short native response"))?
            .try_into()
            .unwrap(),
    ))
}
type Route = (Vec<u8>, Vec<u8>, Vec<u8>, i32);
fn route(volume: &File, disk: &File, r: &Request) -> io::Result<Route> {
    let ext = control(volume, 0x00560000, 32)?;
    let data = control(volume, 0x00090064, 128)?;
    let attrs = control(disk, 0x000700f0, 16)?;
    let e = match control(disk, 0x00070024, 0) {
        Ok(_) => return Err(invalid("disk reports writable")),
        Err(e) => e.raw_os_error().ok_or(e)?,
    };
    let cluster_bytes = u32le(&data, 44)?;
    let supported_clusters = if r.resource_profile.is_some() {
        cluster_bytes.is_power_of_two() && (4096..=2 * 1024 * 1024).contains(&cluster_bytes)
    } else {
        cluster_bytes == 4096
    };
    if ext.len() != 32
        || u32le(&ext, 0)? != 1
        || u32le(&ext, 8)? != r.disk_number
        || u64le(&ext, 16)? != r.partition_offset
        || u64le(&ext, 24)? != r.partition_length
        || data.len() < 96
        || u64le(&data, 0)? != r.ntfs_serial
        || u32le(&data, 40)? != 512
        || !supported_clusters
        || attrs.len() != 16
        || u32le(&attrs, 0)? != 16
        || u64le(&attrs, 8)? & 3 != 2
        || e != 19
    {
        return Err(invalid(
            "native volume route, NTFS geometry or read-only disk evidence differs",
        ));
    }
    Ok((ext, data, attrs, e))
}
fn query(file: &File, class: i32, count: usize) -> Query {
    let mut bytes = vec![0; count];
    // SAFETY: exact class-specific fixed buffer, synchronous query, live handle.
    let ok = unsafe {
        GetFileInformationByHandleEx(raw(file), class, bytes.as_mut_ptr().cast(), count as u32)
    };
    let native_error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    if native_error.is_some() {
        bytes.clear();
    }
    Query {
        class,
        bytes,
        native_error,
    }
}
fn security(file: &File) -> (Vec<u8>, Option<i32>) {
    let mut sd = ptr::null_mut();
    // SAFETY: borrowed file handle; all optional component pointers are null.
    // The returned descriptor is owned by LocalFree, including error paths.
    let error = unsafe {
        GetSecurityInfo(
            raw(file),
            1,
            0x1f,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    let result = if error != 0 {
        (vec![], Some(error as i32))
    } else if sd.is_null() {
        (vec![], Some(1338))
    } else {
        // SAFETY: successful GetSecurityInfo returned an allocated descriptor.
        let valid = unsafe { IsValidSecurityDescriptor(sd) } != 0;
        let length = if valid {
            (unsafe { GetSecurityDescriptorLength(sd) }) as usize
        } else {
            0
        };
        if !(20..=MAX_SECURITY_BYTES).contains(&length) {
            (vec![], Some(1338))
        } else {
            (
                unsafe { std::slice::from_raw_parts(sd.cast::<u8>(), length) }.to_vec(),
                None,
            )
        }
    };
    if !sd.is_null() {
        unsafe {
            LocalFree(sd);
        }
    }
    result
}
pub(crate) fn snapshot(file: &File) -> Snapshot {
    let queries = [(0, 40), (1, 24), (18, 24), (9, 8)]
        .into_iter()
        .map(|(c, n)| query(file, c, n))
        .collect();
    let (security, security_error) = security(file);
    let mut storage = vec![0u64; MAX_SECURITY_BYTES / 8];
    let mut used = 0;
    // SAFETY: live handle, aligned caller-owned descriptor output; synchronous
    // query with an explicit 64 KiB bound and returned required byte count.
    let ok = unsafe {
        GetKernelObjectSecurity(
            raw(file),
            0x1f,
            storage.as_mut_ptr().cast(),
            MAX_SECURITY_BYTES as u32,
            &mut used,
        )
    };
    let error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    let kernel_security = if error.is_none() && (20..=MAX_SECURITY_BYTES).contains(&(used as usize))
    {
        SecurityQuery {
            bytes: unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), used as usize)
            }
            .to_vec(),
            native_error: None,
        }
    } else {
        SecurityQuery {
            bytes: vec![],
            native_error: Some(error.unwrap_or(13)),
        }
    };
    Snapshot {
        queries,
        security,
        security_error,
        kernel_security: Some(kernel_security),
        extended_attributes: None,
        extended_attributes_error: None,
    }
}

/// File/directory metadata handles only. EA enumeration belongs to the file
/// identity and must not be repeated on named stream payload handles.
pub(crate) fn snapshot_with_ea(file: &File) -> Snapshot {
    let mut observation = snapshot(file);
    match crate::extended_attributes_native::capture(file) {
        Ok(set) => observation.extended_attributes = Some(set),
        Err(error) => observation.extended_attributes_error = Some(error.to_string()),
    }
    observation
}

pub(crate) struct Privileges {
    token: HANDLE,
    previous: Vec<(LUID, u32)>,
    restoration_attempted: bool,
    audit: Vec<PrivilegeState>,
}
impl Privileges {
    fn attributes(token: HANDLE, luid: LUID) -> io::Result<u32> {
        let mut b = vec![0u64; 8192];
        let mut used = 0;
        // SAFETY: aligned, initialized output storage and a live token handle.
        if unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                b.as_mut_ptr().cast(),
                (b.len() * 8) as u32,
                &mut used,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if used as usize > b.len() * 8 {
            return Err(invalid("oversized token privileges"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<u8>(), used as usize) };
        let count = u32le(bytes, 0)? as usize;
        if bytes.len() != 4 + 12 * count {
            return Err(invalid("invalid TOKEN_PRIVILEGES length"));
        }
        let found: Vec<_> = (0..count)
            .filter(|i| {
                u64le(bytes, 4 + 12 * i).ok()
                    == Some((u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart))
            })
            .collect();
        if found.len() != 1 {
            return Err(invalid("required privilege absent or duplicated"));
        }
        u32le(bytes, 12 + 12 * found[0])
    }
    fn enable() -> io::Result<Self> {
        Self::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])
    }
    pub(crate) fn enable_for(names: &[&str]) -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: current process pseudo handle, one output token handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), 0x28, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut p = Self {
            token,
            previous: vec![],
            restoration_attempted: false,
            audit: vec![],
        };
        for &name in names {
            let mut luid = LUID::default();
            if unsafe { LookupPrivilegeValueW(ptr::null(), wide(name).as_ptr(), &mut luid) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let previous = Self::attributes(token, luid)?;
            p.previous.push((luid, previous));
            Self::adjust(token, luid, previous | 2)?;
            let enabled = Self::attributes(token, luid)?;
            if enabled != previous | 2 {
                return Err(invalid("privilege enable verification differs"));
            }
            p.audit.push(PrivilegeState {
                name: name.into(),
                before: previous,
                enabled,
                restored: 0,
            });
        }
        Ok(p)
    }
    fn adjust(token: HANDLE, luid: LUID, attributes: u32) -> io::Result<()> {
        let mut p = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        p.Privileges[0].Luid = luid;
        p.Privileges[0].Attributes = attributes;
        unsafe {
            SetLastError(0);
        }
        let ok =
            unsafe { AdjustTokenPrivileges(token, 0, &p, 0, ptr::null_mut(), ptr::null_mut()) };
        let e = io::Error::last_os_error();
        if ok == 0 || e.raw_os_error() != Some(0) {
            return Err(e);
        }
        Ok(())
    }
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        self.restoration_attempted = true;
        let mut failure = None;
        for (i, &(luid, attributes)) in self.previous.iter().enumerate().rev() {
            if let Err(e) = Self::adjust(self.token, luid, attributes) {
                failure = Some(e);
                continue;
            }
            match Self::attributes(self.token, luid) {
                Ok(observed) if (observed & !0x8000_0000) == (attributes & !0x8000_0000) => {
                    if let Some(audit) = self.audit.get_mut(i) {
                        audit.restored = observed;
                    }
                }
                Ok(_) => failure = Some(invalid("privilege restoration verification differs")),
                Err(e) => failure = Some(e),
            }
        }
        if let Some(e) = failure {
            Err(e)
        } else {
            Ok(())
        }
    }
    pub(crate) fn audit(&self) -> &[PrivilegeState] {
        &self.audit
    }
}
impl Drop for Privileges {
    fn drop(&mut self) {
        if !self.restoration_attempted {
            let _ = self.restore();
        }
        unsafe {
            CloseHandle(self.token);
        }
    }
}

pub fn collect_file_metadata(request: &Request) -> io::Result<Report> {
    collect_file_metadata_with_passes(request, false)
}

/// Read each stream's content once and mirror it as the second capture. Only
/// for callers that bracket the whole observation over the frozen source.
pub fn collect_file_metadata_single_content_pass(request: &Request) -> io::Result<Report> {
    collect_file_metadata_with_passes(request, true)
}

fn collect_file_metadata_with_passes(
    request: &Request,
    single_content_pass: bool,
) -> io::Result<Report> {
    request.validate()?;
    let limits = request.limits();
    let volume = open(request.volume.trim_end_matches('\\'))?;
    let disk = open(&format!(r"\\.\PhysicalDrive{}", request.disk_number))?;
    let before = route(&volume, &disk, request)?;
    let mut privileges = Privileges::enable()?;
    let base_before = crate::stream_native::base(&volume);
    let clusters = u64le(&before.1, 16)?;
    let (bitmap_before, bitmap_before_continuation, streamed_before) =
        if request.resource_profile.is_some() {
            let (first, summary) = crate::stream_native::bitmap_streamed(&volume, clusters)?;
            (first, Vec::new(), Some(summary))
        } else {
            let (first, continuation) = crate::stream_native::bitmap(&volume)?;
            (first, continuation, None)
        };
    let bitmap_bytes = |first: &IoctlQuery, continuation: &Vec<IoctlQuery>| {
        std::iter::once(first).chain(continuation).fold(
            continuation.capacity() * std::mem::size_of::<IoctlQuery>(),
            |sum, q| sum.saturating_add(q.bytes.capacity() + q.input.capacity()),
        )
    };
    let bitmap_before_bytes = bitmap_bytes(&bitmap_before, &bitmap_before_continuation);
    let mut stream_bytes = base_before.bytes.capacity();
    let mut files = vec![];
    let mut logical_files = vec![];
    let mut read_budget = if request.resource_profile.is_some() {
        crate::logical_hash::Budget::with_limits(
            limits.logical_read_bytes,
            limits.maximum_stream_bytes,
            limits.logical_read_calls,
        )?
    } else {
        crate::logical_hash::Budget::new(crate::logical_hash::DEFAULT_LIMIT)
    };
    let mut security_bytes = 0;
    for identity in &request.files {
        let mut logical = LogicalFile {
            identity: identity.clone(),
            before: vec![],
            after: vec![],
        };
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: identity.reference() as i64,
            },
        };
        // SAFETY: descriptor is initialized, valid volume hint remains open.
        // READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA | ACCESS_SYSTEM_SECURITY;
        // BACKUP_SEMANTICS | OPEN_REPARSE_POINT avoids following reparse targets.
        let handle = unsafe {
            OpenFileById(
                raw(&volume),
                &descriptor,
                0x01020088,
                7,
                ptr::null(),
                0x02200000,
            )
        };
        let mut obs = Observation {
            identity: identity.clone(),
            open_error: None,
            before: None,
            after: None,
            streams_before: None,
            streams_after: None,
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            obs.open_error = Some(io::Error::last_os_error().raw_os_error().unwrap_or(31));
        } else {
            // SAFETY: transfer the newly acquired unique file-handle ownership.
            let file = unsafe { File::from_raw_handle(handle) };
            obs.before = Some(snapshot_with_ea(&file));
            let (capture, hashes) = crate::stream_native::capture(
                &file,
                request,
                identity,
                &mut read_budget,
                limits.stream_evidence_bytes.saturating_sub(stream_bytes),
            );
            obs.streams_before = Some(capture);
            logical.before = hashes;
            if single_content_pass {
                obs.streams_after = obs.streams_before.clone();
                logical.after = logical.before.clone();
            } else {
                let (capture, hashes) = crate::stream_native::capture(
                    &file,
                    request,
                    identity,
                    &mut read_budget,
                    limits
                        .stream_evidence_bytes
                        .saturating_sub(stream_bytes)
                        .saturating_sub(
                            obs.streams_before
                                .as_ref()
                                .map_or(0, StreamCapture::retained_bytes),
                        )
                        .saturating_sub(hash_retained_bytes(&logical.before)),
                );
                obs.streams_after = Some(capture);
                logical.after = hashes;
            }
            obs.after = Some(snapshot_with_ea(&file));
            for s in [&obs.before, &obs.after].into_iter().flatten() {
                security_bytes +=
                    s.security.len() + s.kernel_security.as_ref().map_or(0, |q| q.bytes.len());
                stream_bytes = stream_bytes
                    .checked_add(s.extended_attribute_bytes()?)
                    .ok_or_else(|| invalid("native EA evidence budget overflow"))?;
            }
            if security_bytes > limits.security_bytes {
                return Err(invalid("native descriptor budget exhausted"));
            }
            for s in [&obs.streams_before, &obs.streams_after]
                .into_iter()
                .flatten()
            {
                stream_bytes = stream_bytes.saturating_add(s.retained_bytes());
            }
            stream_bytes = stream_bytes.saturating_add(
                hash_retained_bytes(&logical.before) + hash_retained_bytes(&logical.after),
            );
            if stream_bytes > limits.stream_evidence_bytes {
                return Err(invalid("native stream evidence budget exhausted"));
            }
        }
        files.push(obs);
        logical_files.push(logical);
    }
    let base_after = crate::stream_native::base(&volume);
    let (bitmap_after, bitmap_after_continuation, streamed_after) =
        if request.resource_profile.is_some() {
            let (first, summary) = crate::stream_native::bitmap_streamed(&volume, clusters)?;
            (first, Vec::new(), Some(summary))
        } else {
            let (first, continuation) = crate::stream_native::bitmap(&volume)?;
            (first, continuation, None)
        };
    if bitmap_before_bytes.saturating_add(bitmap_bytes(&bitmap_after, &bitmap_after_continuation))
        > MAX_TOTAL_BITMAP_BYTES
    {
        return Err(invalid("native bitmap page evidence budget exhausted"));
    }
    stream_bytes = stream_bytes.saturating_add(base_after.bytes.capacity());
    if stream_bytes > limits.stream_evidence_bytes {
        return Err(invalid("native allocation evidence budget exhausted"));
    }
    let namespace = crate::namespace_native::collect(&volume, request);
    privileges.restore()?;
    let after = route(&volume, &disk, request)?;
    let mut report = Report {
        schema_version: if request.resource_profile.is_some() {
            10
        } else {
            7
        },
        resources: None,
        request: request.clone(),
        volume_extents_before: before.0,
        volume_extents_after: after.0,
        ntfs_data_before: before.1,
        ntfs_data_after: after.1,
        disk_attributes_before: before.2,
        disk_attributes_after: after.2,
        write_protect_error_before: before.3,
        write_protect_error_after: after.3,
        privileges_restored: true,
        privilege_states: privileges.audit.clone(),
        files,
        conversion_qualified: false,
        allocation: Some(VolumeAllocation {
            base_before,
            base_after,
            bitmap_before,
            bitmap_after,
            bitmap_before_continuation,
            bitmap_after_continuation,
            streamed_before,
            streamed_after,
        }),
        logical_data: Some(LogicalData {
            audit: read_budget.audit(),
            files: logical_files,
        }),
        namespace: Some(namespace),
        content_passes: if single_content_pass { 1 } else { 2 },
    };
    if let Some(profile) = request.resource_profile {
        report.resources = Some(report.measured_resources(profile)?);
        report.validate_resources()?;
    }
    Ok(report)
}
