//! Owned, unbuffered journal I/O for native qualification of eight 4 KiB slots.
//!
//! This is a storage-interface contract, not a power-loss qualification. Only
//! ordinary NTFS unnamed data is admitted. NTFS's exclusive cluster allocation,
//! absence of block-refcounting support, ordinary attributes and native retrieval
//! pointers are the no-shared-allocation contract; no claim is made about a
//! controller, virtual disk, storage filter or flash translation layer.
//!
//! There is deliberately no File/handle constructor, handle accessor, clone or
//! deserializable capability. The same share-zero handle survives construction,
//! the complete journal readback, sealing and marker writes; recovery obtains a
//! newly bound share-zero owner. Callers must still exclude raw/admin aliases
//! and surviving memory mappings. Production admission remains disabled until
//! the native qualification is completed.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, size_of_val},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INVALID_FUNCTION, ERROR_MORE_DATA, ERROR_NOT_A_REPARSE_POINT,
        ERROR_OBJECT_NOT_EXTERNALLY_BACKED,
    },
    Storage::FileSystem::{
        FILE_BEGIN, FILE_END_OF_FILE_INFO, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_STORAGE_INFO, FileAlignmentInfo, FileEndOfFileInfo,
        FileStorageInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW, ReadFile,
        SetFileInformationByHandle, SetFilePointerEx, WriteFile,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            FSCTL_GET_COMPRESSION, FSCTL_GET_EXTERNAL_BACKING, FSCTL_GET_REPARSE_POINT,
            FSCTL_MARK_HANDLE, MARK_HANDLE_INFO, MARK_HANDLE_PROTECT_CLUSTERS,
        },
    },
};

pub const MARKER_STORAGE_NATIVE_QUALIFIED: bool = false;
const GRANULE: usize = 4096;
const SLOTS: usize = 8;
const MARKER_BYTES: u64 = (SLOTS * GRANULE) as u64;
const BLOCK: usize = 64 * 1024;
const NTFS_DATA: u32 = 0x00090064;
const BLOCK_REFCOUNTING: u32 = 0x08000000;
const MAX_PREFIX_EXTENTS: usize = 64; // 32 KiB / the minimum 512-byte cluster.

#[derive(Debug)]
struct OperationError {
    operation: &'static str,
    source: io::Error,
}

impl std::fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.source)
    }
}

impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

// Retain the original OS error as a source rather than flattening it into a
// string. Callers still receive its ErrorKind, and diagnostics can traverse to
// the original raw_os_error even when an API returns an otherwise vague code.
fn operation(operation: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), OperationError { operation, source })
}

#[repr(C, align(4096))]
struct AlignedBlock([u8; BLOCK]);

/// Descriptive same-handle exclusion of reparse-backed NTFS storage, including
/// IO_REPARSE_TAG_WOF and dedup tags. An unavailable WOF service is not evidence
/// of an unbacked file: explicit reparse absence supplies the equivalent direct
/// exclusion while supported external backing and every other error refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrdinaryStorageObservation {
    pub file_attribute_tag_info_before: [u8; 8],
    pub file_attribute_tag_info_after: [u8; 8],
    pub reparse_query_error: u32,
    pub explicit_no_reparse_point: bool,
    /// The actual WOF query status, including ERROR_INVALID_FUNCTION when the
    /// backing service is absent. That status is never a negative WOF answer.
    pub external_backing_query_error: u32,
    pub external_backing_absence_reported: bool,
    pub external_backing_query_unsupported: bool,
}

/// Descriptive native observations only. This value cannot authorize markers.
/// `MarkerJournalFile`, which retains its original handle, is the capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MarkerStorageObservation {
    pub identity: JournalFileIdentity,
    pub journal_length: u64,
    pub logical_sector_bytes: u32,
    pub physical_sector_bytes: u32,
    pub cluster_bytes: u32,
    pub retrieval_base_bytes: u64,
    /// Exact FileStorageInfo fields, including filesystem atomicity and offsets.
    pub file_storage_info: [u32; 7],
    pub ordinary_storage: OrdinaryStorageObservation,
    /// Offsets on the one bound disk, not merely offsets within the file.
    pub marker_device_offsets: [u64; SLOTS],
    pub native_qualified: bool,
}

/// Construction I/O, with a bounded 64 KiB aligned bounce cache. This owns the
/// handle but has no marker capability. Logical seek/EOF remain byte precise.
/// A final padded write may temporarily extend EOF by at most 4095 bytes, always
/// inside the admitted capacity, then FileEndOfFileInfo restores the exact EOF.
pub struct UnbufferedJournalFile {
    file: File,
    volume: File,
    disk: File,
    binding: GeneralJournalStorageBinding,
    profile: JournalProfile,
    identity: JournalFileIdentity,
    final_path: String,
    logical_length: u64,
    disk_length: u64,
    position: u64,
    cache: Box<AlignedBlock>,
    cache_at: Option<u64>,
    dirty: bool,
    poisoned: bool,
    ordinary_storage: Option<OrdinaryStorageObservation>,
    // Fields drop in declaration order: the owned file (and its cluster
    // protection), volume and disk close before restoring this token state.
    // Keeping the guard here also preserves that order on every sealing error.
    privileges: Option<crate::attestation_native::Privileges>,
}

/// Sealed storage capability, retaining the original exclusive unbuffered
/// handle. Its immutable body cannot be written through this type. Only full
/// aligned marker-slot writes are accepted, with flush and uncached readback.
pub struct MarkerJournalFile {
    io: UnbufferedJournalFile,
    observation: MarkerStorageObservation,
}

fn profile_capacity(profile: JournalProfile) -> io::Result<u64> {
    let capacity = match profile {
        JournalProfile::CapacityPinnedV3 { max_journal_bytes } => Some(max_journal_bytes),
        _ => None,
    };
    JournalProfile::from_schema_and_capacity(profile.version(), capacity)?;
    Ok(profile.max_journal_bytes())
}

fn round_up(value: u64) -> io::Result<u64> {
    value
        .checked_add(GRANULE as u64 - 1)
        .map(|v| v / GRANULE as u64 * GRANULE as u64)
        .ok_or_else(|| invalid("unbuffered journal rounding overflow"))
}

impl UnbufferedJournalFile {
    /// Create only a new file. Existing journals are never truncated/replaced.
    /// No privileges, disk attributes, drive routes or filesystem flags change.
    pub fn create_new(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
    ) -> io::Result<Self> {
        Self::open_owned(path, binding, profile, None)
    }

    fn open_owned(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        recovery: Option<(&JournalFileIdentity, u64)>,
    ) -> io::Result<Self> {
        binding
            .validate()
            .map_err(|error| operation("open_owned.binding.validate", error))?;
        let capacity = profile_capacity(profile)
            .map_err(|error| operation("open_owned.profile_capacity", error))?;
        let path_units: Vec<u16> = path.as_os_str().encode_wide().collect();
        let drive_colon = if path_units.get(1) == Some(&58)
            && path_units[0] <= 127
            && (path_units[0] as u8).is_ascii_alphabetic()
        {
            Some(1)
        } else if path_units.starts_with(&[92, 92, 63, 92])
            && path_units.get(5) == Some(&58)
            && path_units[4] <= 127
            && (path_units[4] as u8).is_ascii_alphabetic()
        {
            Some(5)
        } else {
            None
        };
        require(
            path.is_absolute()
                && path_units.len() < MAX_PATH_UNITS
                && !path_units.contains(&0)
                && !path_units
                    .iter()
                    .enumerate()
                    .any(|(at, unit)| *unit == 58 && Some(at) != drive_colon),
            "marker journal requires a bounded absolute path without stream aliases",
        )?;
        require(
            capacity >= MARKER_BYTES + 160,
            "unbuffered journal capacity cannot contain markers and body",
        )?;
        if let Some((identity, length)) = recovery {
            require(
                length >= MARKER_BYTES + 160 && round_up(length)? <= capacity,
                "recovery journal length exceeds aligned I/O capacity",
            )?;
            require(
                identity.volume_guid == guid_bytes(&binding.disk.volume_guid)?,
                "recovery journal identity has another volume",
            )?;
        }
        // The private constructor is the only source of these flags and this
        // ownership. A buffered File or serialized observation cannot enter it.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .create_new(recovery.is_none())
            .open(path)
            .map_err(|error| operation("open_owned.OpenOptions journal", error))?;
        let snapshot = native::observe_general_journal_file_with_profile(&file, binding, profile)
            .map_err(|error| {
            operation(
                "open_owned.native::observe_general_journal_file_with_profile",
                error,
            )
        })?;
        require(
            recovery.is_some() || snapshot.file_bytes == 0,
            "new unbuffered journal is not empty",
        )?;
        if let Some((identity, length)) = recovery {
            require(
                snapshot.identity == *identity && snapshot.file_bytes == length,
                "actual recovery journal identity or exact length differs",
            )?;
        }
        let volume_path = final_volume_path(
            &snapshot.final_path,
            &guid_bytes(&binding.disk.volume_guid)?,
        )
        .map_err(|error| operation("open_owned.final_volume_path", error))?;
        let volume = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(volume_path)
            .map_err(|error| operation("open_owned.OpenOptions volume", error))?;
        let disk = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(format!("\\\\.\\PhysicalDrive{}", binding.disk.disk_number))
            .map_err(|error| operation("open_owned.OpenOptions disk", error))?;
        let mut result = Self {
            file,
            volume,
            disk,
            binding: binding.clone(),
            profile,
            identity: snapshot.identity,
            final_path: snapshot.final_path,
            logical_length: snapshot.file_bytes,
            disk_length: snapshot.file_bytes,
            position: 0,
            cache: Box::new(AlignedBlock([0; BLOCK])),
            cache_at: None,
            dirty: false,
            poisoned: false,
            ordinary_storage: None,
            privileges: None,
        };
        result
            .observe_owned()
            .map_err(|error| operation("open_owned.observe_owned", error))?;
        let geometry = result
            .ntfs_geometry()
            .map_err(|error| operation("open_owned.ntfs_geometry", error))?;
        let (_, ordinary) = result
            .require_plain_storage(&geometry)
            .map_err(|error| operation("open_owned.require_plain_storage", error))?;
        result.ordinary_storage = Some(ordinary);
        Ok(result)
    }

    fn usable(&self) -> io::Result<()> {
        require(
            !self.poisoned,
            "unbuffered journal was poisoned by failed native I/O",
        )
    }

    /// Byte length seen by ordinary construction I/O, including pending cache.
    pub fn byte_len(&self) -> io::Result<u64> {
        self.usable()?;
        Ok(self.logical_length)
    }

    /// Actual constructor observation, retained privately for this handle.
    pub fn identity(&self) -> &JournalFileIdentity {
        &self.identity
    }

    /// Facts from this constructor's actual same-handle metadata checks. No
    /// handle, sealing capability, privilege or source authority is exposed.
    pub fn ordinary_storage_observation(&self) -> &OrdinaryStorageObservation {
        self.ordinary_storage
            .as_ref()
            .expect("only the checked constructor publishes an unbuffered journal")
    }

    fn observe_owned(&self) -> io::Result<JournalFileSnapshot> {
        self.usable()?;
        let (path, mut before) = native::file_observation_with_profile(&self.file, self.profile)
            .map_err(|error| operation("observe_owned.native::file_observation before", error))?;
        native::storage_observation(&self.volume, &self.disk, &mut before).map_err(|error| {
            operation("observe_owned.native::storage_observation before", error)
        })?;
        let snapshot =
            validate_general_evidence_for_profile(&self.binding, &path, before, self.profile)
                .map_err(|error| operation("observe_owned.validate_general_evidence", error))?;
        require(
            snapshot.identity == self.identity
                && path == self.final_path
                && snapshot.file_bytes == self.disk_length,
            "owned journal file identity, route or actual EOF changed",
        )?;
        let (after_path, mut after) =
            native::file_observation_with_profile(&self.file, self.profile).map_err(|error| {
                operation("observe_owned.native::file_observation after", error)
            })?;
        native::storage_observation(&self.volume, &self.disk, &mut after)
            .map_err(|error| operation("observe_owned.native::storage_observation after", error))?;
        finish_observation(snapshot, &after_path, &after)
            .map_err(|error| operation("observe_owned.finish_observation", error))
    }

    fn require_plain_storage(
        &self,
        // Both private callers must first check NTFS/no shared blocks and the
        // complete native geometry through these same retained handles.
        _ntfs_geometry: &(u32, u64),
    ) -> io::Result<([u32; 7], OrdinaryStorageObservation)> {
        let (_, evidence) = native::file_observation_with_profile(&self.file, self.profile)
            .map_err(|error| operation("require_plain_storage.native::file_observation", error))?;
        // Reparse includes dedup/WOF. Also reject recall/offline/virtual and
        // integrity streams; no provider or filesystem transform is admitted.
        const EXTRA_FORBIDDEN: u32 =
            0x200 | 0x800 | 0x1000 | 0x4000 | 0x8000 | 0x10000 | 0x40000 | 0x400000;
        require(
            u32_at(&evidence.file_attribute_tag_info, 0)? & (EXTRA_FORBIDDEN | 0x400) == 0
                && u32_at(&evidence.file_attribute_tag_info, 4)? == 0,
            "marker journal has sparse, compressed, encrypted, offline, recall, virtual, integrity or reparse storage/tag",
        )?;
        require(
            native::query(&self.file, FSCTL_GET_COMPRESSION, &[], 2)
                .map_err(|error| operation("require_plain_storage.FSCTL_GET_COMPRESSION", error))?
                == [0, 0],
            "marker journal has native file compression",
        )?;
        // On the already verified NTFS volume, require a direct answer from
        // the file opened with OPEN_REPARSE_POINT, irrespective of whether a
        // WOF/dedup filter service is installed. Any returned reparse data or
        // any error other than explicit NOT_A_REPARSE_POINT refuses.
        // https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d86a4c4d-a996-403a-8b92-9c0e1a300e22
        match native::query(&self.file, FSCTL_GET_REPARSE_POINT, &[], 16 * 1024) {
            Err(error) if error.raw_os_error() == Some(ERROR_NOT_A_REPARSE_POINT as i32) => {}
            Err(error) => {
                return Err(operation(
                    "require_plain_storage.FSCTL_GET_REPARSE_POINT",
                    error,
                ));
            }
            Ok(_) => return Err(invalid("marker journal has a reparse point")),
        }
        // INVALID_FUNCTION describes an absent/not-started backing service,
        // not an unbacked file. Only the independent direct no-reparse proof
        // above excludes WOF/dedup storage in that case; retain the actual WOF
        // status rather than manufacturing a negative provider observation.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-get-external-backing
        let external_backing_query_error =
            match native::query(&self.file, FSCTL_GET_EXTERNAL_BACKING, &[], 4096) {
                Err(error)
                    if error.raw_os_error() == Some(ERROR_OBJECT_NOT_EXTERNALLY_BACKED as i32) =>
                {
                    ERROR_OBJECT_NOT_EXTERNALLY_BACKED
                }
                Err(error) if error.raw_os_error() == Some(ERROR_INVALID_FUNCTION as i32) => {
                    ERROR_INVALID_FUNCTION
                }
                Err(error) => {
                    return Err(operation(
                        "require_plain_storage.FSCTL_GET_EXTERNAL_BACKING",
                        error,
                    ));
                }
                Ok(_) => return Err(invalid("marker journal has external backing")),
            };
        let alignment = native::information::<4>(&self.file, FileAlignmentInfo)
            .map_err(|error| operation("require_plain_storage.FileAlignmentInfo", error))?;
        let mask = u32_at(&alignment, 0)?;
        require(
            mask < GRANULE as u32 && (mask + 1).is_power_of_two(),
            "marker journal needs alignment above its 4 KiB buffer",
        )?;
        let mut info = FILE_STORAGE_INFO::default();
        // SAFETY: the typed storage-info struct has no Rust boolean fields,
        // has the native size/alignment, and is initialized before the call.
        if unsafe {
            GetFileInformationByHandleEx(
                self.file.as_raw_handle(),
                FileStorageInfo,
                (&mut info as *mut FILE_STORAGE_INFO).cast(),
                size_of::<FILE_STORAGE_INFO>() as u32,
            )
        } == 0
        {
            return Err(operation(
                "require_plain_storage.GetFileInformationByHandleEx(FileStorageInfo)",
                io::Error::last_os_error(),
            ));
        }
        let values = [
            info.LogicalBytesPerSector,
            info.PhysicalBytesPerSectorForAtomicity,
            info.PhysicalBytesPerSectorForPerformance,
            info.FileSystemEffectivePhysicalBytesPerSectorForAtomicity,
            info.Flags,
            info.ByteOffsetForSectorAlignment,
            info.ByteOffsetForPartitionAlignment,
        ];
        require(
            values[0] == self.identity.logical_sector_bytes
                && values[1] == self.identity.physical_sector_bytes
                && values[1..4]
                    .iter()
                    .all(|size| matches!(*size, 512 | 4096) && *size >= values[0])
                && values[4] & 3 == 3
                && values[5] == 0
                && values[6] == 0,
            "marker file storage atomicity, performance or sector alignment exceeds its contract",
        )?;
        let (_, after) =
            native::file_observation_with_profile(&self.file, self.profile).map_err(|error| {
                operation(
                    "require_plain_storage.native::file_observation after",
                    error,
                )
            })?;
        require(
            evidence.file_attribute_tag_info == after.file_attribute_tag_info
                && u32_at(&after.file_attribute_tag_info, 0)? & 0x400 == 0
                && u32_at(&after.file_attribute_tag_info, 4)? == 0,
            "marker journal attributes or reparse tag changed during ordinary-storage checks",
        )?;
        Ok((
            values,
            OrdinaryStorageObservation {
                file_attribute_tag_info_before: evidence.file_attribute_tag_info,
                file_attribute_tag_info_after: after.file_attribute_tag_info,
                reparse_query_error: ERROR_NOT_A_REPARSE_POINT,
                explicit_no_reparse_point: true,
                external_backing_query_error,
                external_backing_absence_reported: external_backing_query_error
                    == ERROR_OBJECT_NOT_EXTERNALLY_BACKED,
                external_backing_query_unsupported: external_backing_query_error
                    == ERROR_INVALID_FUNCTION,
            },
        ))
    }

    fn ntfs_geometry(&self) -> io::Result<(u32, u64)> {
        let mut name = [0u16; 16];
        let mut flags = 0u32;
        // SAFETY: a retained volume handle and bounded initialized outputs.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                self.volume.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                name.as_mut_ptr(),
                name.len() as u32,
            )
        };
        if ok == 0 {
            return Err(operation(
                "ntfs_geometry.GetVolumeInformationByHandleW",
                io::Error::last_os_error(),
            ));
        }
        require(
            name[..5] == [78, 84, 70, 83, 0] && flags & BLOCK_REFCOUNTING == 0,
            "marker storage requires NTFS without block refcounting",
        )?;
        let data = native::query(&self.volume, NTFS_DATA, &[], 96)
            .map_err(|error| operation("ntfs_geometry.FSCTL_GET_NTFS_VOLUME_DATA", error))?;
        let logical = self.identity.logical_sector_bytes;
        let physical = self.identity.physical_sector_bytes;
        let cluster = u32_at(&data, 44)?;
        require(
            data.len() == 96
                && u64_at(&data, 0)? == self.identity.volume_serial_number
                && u32_at(&data, 40)? == logical
                && matches!(logical, 512 | 4096)
                && matches!(physical, 512 | 4096)
                && physical >= logical
                && (512..=65536).contains(&cluster)
                && cluster.is_power_of_two()
                && cluster.is_multiple_of(logical),
            "marker journal NTFS or reported sector geometry differs",
        )?;
        let base = native::query(&self.volume, crate::stream_layout::GET_BASE, &[], 8)
            .map_err(|error| operation("ntfs_geometry.FSCTL_GET_RETRIEVAL_POINTER_BASE", error))?;
        require(base.len() == 8, "marker retrieval base is incomplete")?;
        let base = u64_at(&base, 0)?
            .checked_mul(u64::from(logical))
            .ok_or_else(|| invalid("marker retrieval base overflow"))?;
        require(
            base < self.identity.partition_bytes && base.is_multiple_of(u64::from(physical)),
            "marker retrieval base is outside or unaligned on the partition",
        )?;
        Ok((cluster, base))
    }

    fn seek_native(&self, offset: u64) -> io::Result<()> {
        require(
            offset <= i64::MAX as u64 && offset.is_multiple_of(GRANULE as u64),
            "unbuffered journal native seek is unaligned or oversized",
        )?;
        // SAFETY: only this owner operates on its live synchronous file handle.
        if unsafe {
            SetFilePointerEx(
                self.file.as_raw_handle(),
                offset as i64,
                ptr::null_mut(),
                FILE_BEGIN,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_block(&mut self, offset: u64, count: usize) -> io::Result<usize> {
        require(
            offset < self.disk_length
                && (1..=BLOCK).contains(&count)
                && count.is_multiple_of(GRANULE),
            "unbuffered journal native read is outside EOF or its buffer",
        )?;
        self.seek_native(offset)?;
        self.cache.0.fill(0);
        let mut returned = 0u32;
        // SAFETY: cache is 4096-byte aligned and its initialized writable
        // prefix has the declared sector-multiple length. No pointer escapes.
        if unsafe {
            ReadFile(
                self.file.as_raw_handle(),
                self.cache.0.as_mut_ptr(),
                count as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        require(
            returned as usize == (self.disk_length - offset).min(count as u64) as usize,
            "short or oversized unbuffered journal read",
        )?;
        Ok(returned as usize)
    }

    fn write_block(&mut self, offset: u64, count: usize) -> io::Result<()> {
        require(
            offset
                .checked_add(count as u64)
                .is_some_and(|end| end <= self.profile.max_journal_bytes())
                && (1..=BLOCK).contains(&count)
                && count.is_multiple_of(GRANULE),
            "aligned journal write exceeds admitted capacity",
        )?;
        self.seek_native(offset)?;
        let mut returned = 0u32;
        // SAFETY: bounded, initialized, 4096-byte aligned sector-multiple input;
        // the synchronous API cannot retain a borrow of the private cache.
        if unsafe {
            WriteFile(
                self.file.as_raw_handle(),
                self.cache.0.as_ptr(),
                count as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        require(returned as usize == count, "short unbuffered journal write")?;
        self.disk_length = self.disk_length.max(offset + count as u64);
        Ok(())
    }

    fn flush_cache(&mut self) -> io::Result<()> {
        self.usable()?;
        if !self.dirty {
            return Ok(());
        }
        let result = self.flush_cache_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn flush_cache_inner(&mut self) -> io::Result<()> {
        let offset = self
            .cache_at
            .ok_or_else(|| invalid("dirty journal cache has no offset"))?;
        let available = self
            .logical_length
            .checked_sub(offset)
            .ok_or_else(|| invalid("journal cache exceeds logical EOF"))?;
        let count = round_up(available.min(BLOCK as u64))? as usize;
        self.write_block(offset, count)?;
        if self.disk_length != self.logical_length {
            let info = FILE_END_OF_FILE_INFO {
                EndOfFile: self.logical_length as i64,
            };
            // SAFETY: live write handle and initialized, aligned native struct.
            // FileEndOfFileInfo avoids an unaligned native file-pointer seek.
            if unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle(),
                    FileEndOfFileInfo,
                    (&info as *const FILE_END_OF_FILE_INFO).cast(),
                    size_of::<FILE_END_OF_FILE_INFO>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            self.disk_length = self.logical_length;
        }
        self.dirty = false;
        Ok(())
    }

    fn load_cache(&mut self, offset: u64) -> io::Result<()> {
        if self.cache_at == Some(offset) {
            return Ok(());
        }
        self.flush_cache()?;
        self.cache_at = None;
        if offset < self.disk_length {
            self.read_block(offset, BLOCK)?;
        } else {
            self.cache.0.fill(0);
        }
        self.cache_at = Some(offset);
        Ok(())
    }

    /// Flush dirty bytes, restore exact EOF, issue FlushFileBuffers, and discard
    /// all body cache entries. The next read therefore uses actual native I/O.
    pub fn sync_all(&mut self) -> io::Result<()> {
        self.flush_cache()?;
        self.cache_at = None;
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(error);
        }
        let result = self.observe_owned().map(|_| ());
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Consume construction ownership only after exact final EOF and a stable
    /// native map. This authenticates storage; the caller must still perform
    /// the full journal/ticket authentication before Apply or recovery.
    pub fn seal_marker_storage(mut self, expected_length: u64) -> io::Result<MarkerJournalFile> {
        require(
            expected_length >= MARKER_BYTES + 160 && self.logical_length == expected_length,
            "marker capability requires the exact complete journal length",
        )?;
        self.sync_all()?;
        self.privileges = Some(crate::attestation_native::Privileges::enable_for(&[
            "SeManageVolumePrivilege",
        ])?);
        protect_clusters(&self.file, &self.volume)?;
        let before = self.marker_observation()?;
        let after = self.marker_observation()?;
        require(before == after, "marker allocation changed during sealing")?;
        Ok(MarkerJournalFile {
            io: self,
            observation: before,
        })
    }

    fn marker_observation(&self) -> io::Result<MarkerStorageObservation> {
        let snapshot = self.observe_owned()?;
        require(
            snapshot.file_bytes == self.logical_length && snapshot.file_bytes >= MARKER_BYTES + 160,
            "marker file body or exact EOF is incomplete",
        )?;
        let (cluster, base) = self.ntfs_geometry()?;
        let (file_storage_info, ordinary_storage) = self.require_plain_storage(&(cluster, base))?;
        let offsets = marker_offsets(&self.file, &self.identity, cluster, base)?;
        Ok(MarkerStorageObservation {
            identity: self.identity.clone(),
            journal_length: self.logical_length,
            logical_sector_bytes: self.identity.logical_sector_bytes,
            physical_sector_bytes: self.identity.physical_sector_bytes,
            cluster_bytes: cluster,
            retrieval_base_bytes: base,
            file_storage_info,
            ordinary_storage,
            marker_device_offsets: offsets,
            native_qualified: MARKER_STORAGE_NATIVE_QUALIFIED,
        })
    }
}

impl Read for UnbufferedJournalFile {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.usable()?;
        if output.is_empty() || self.position >= self.logical_length {
            return Ok(0);
        }
        // Marker reads never reuse even the private body cache. This also
        // drains construction writes before its post-flush validating readback.
        if self.position < MARKER_BYTES {
            self.flush_cache()?;
            self.cache_at = None;
            let offset = self.position / GRANULE as u64 * GRANULE as u64;
            self.read_block(offset, GRANULE)?;
            let within = (self.position - offset) as usize;
            let count = output
                .len()
                .min(GRANULE - within)
                .min((self.logical_length - self.position).min(BLOCK as u64) as usize);
            output[..count].copy_from_slice(&self.cache.0[within..within + count]);
            self.position += count as u64;
            return Ok(count);
        }
        let offset = self.position / BLOCK as u64 * BLOCK as u64;
        self.load_cache(offset)?;
        let within = (self.position - offset) as usize;
        let count = output
            .len()
            .min(BLOCK - within)
            .min((self.logical_length - self.position).min(BLOCK as u64) as usize);
        output[..count].copy_from_slice(&self.cache.0[within..within + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Write for UnbufferedJournalFile {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.usable()?;
        if input.is_empty() {
            return Ok(0);
        }
        let offset = self.position / BLOCK as u64 * BLOCK as u64;
        let within = (self.position - offset) as usize;
        let count = input.len().min(BLOCK - within);
        let end = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| invalid("unbuffered journal write overflow"))?;
        require(
            round_up(end)? <= self.profile.max_journal_bytes(),
            "journal byte write would exceed aligned native capacity",
        )?;
        self.load_cache(offset)?;
        self.cache.0[within..within + count].copy_from_slice(&input[..count]);
        self.dirty = true;
        self.logical_length = self.logical_length.max(end);
        self.position = end;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl Seek for UnbufferedJournalFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.usable()?;
        let next = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.logical_length) + i128::from(delta),
        };
        require(
            (0..=i128::from(self.profile.max_journal_bytes())).contains(&next),
            "journal logical seek exceeds admitted capacity",
        )?;
        self.position = next as u64;
        Ok(self.position)
    }
}

impl MarkerJournalFile {
    /// Recovery requires the independently pinned file identity and exact
    /// ticket length, plus fresh observations through the newly owned handle.
    /// Descriptive saved slot addresses never grant this capability.
    pub fn open_recovery(
        path: &Path,
        binding: &GeneralJournalStorageBinding,
        profile: JournalProfile,
        identity: &JournalFileIdentity,
        expected_length: u64,
    ) -> io::Result<Self> {
        UnbufferedJournalFile::open_owned(
            path,
            binding,
            profile,
            Some((identity, expected_length)),
        )?
        .seal_marker_storage(expected_length)
    }

    pub fn observation(&self) -> &MarkerStorageObservation {
        &self.observation
    }

    /// Actual scoped token observations; no assertion of process-wide or
    /// device-wide exclusivity is derived from holding this privilege.
    pub fn privilege_audit(&self) -> &[crate::attestation::PrivilegeState] {
        self.io
            .privileges
            .as_ref()
            .expect("only sealing constructs a marker journal")
            .audit()
    }

    /// Close native handles before explicitly restoring the scoped privilege
    /// and returning its actual audit. This issues no journal writes. Drop
    /// retains the same order when the caller exits early instead.
    pub fn close(self) -> io::Result<Vec<crate::attestation::PrivilegeState>> {
        let Self { mut io, .. } = self;
        let mut privileges = io
            .privileges
            .take()
            .expect("only sealing constructs a marker journal");
        drop(io);
        privileges.restore()?;
        Ok(privileges.audit().to_vec())
    }

    pub fn byte_len(&self) -> io::Result<u64> {
        self.io.usable()?;
        require(
            self.io.file.metadata()?.len() == self.observation.journal_length,
            "sealed marker journal actual EOF changed",
        )?;
        Ok(self.observation.journal_length)
    }

    pub fn revalidate_storage(&mut self) -> io::Result<()> {
        let result = self.io.marker_observation().and_then(|actual| {
            require(
                actual == self.observation,
                "sealed marker storage map or identity changed",
            )
        });
        if result.is_err() {
            self.io.poisoned = true;
        }
        result
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        self.io.sync_all()?;
        self.revalidate_storage()
    }
}

impl Read for MarkerJournalFile {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !output.is_empty() && self.io.position < MARKER_BYTES {
            self.revalidate_storage()?;
        }
        self.io.read(output)
    }
}
impl Seek for MarkerJournalFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.io.seek(from)
    }
}
impl Write for MarkerJournalFile {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.io.usable()?;
        if input.is_empty() {
            return Ok(0);
        }
        let offset = self.io.position;
        require(
            input.len() == GRANULE
                && offset < MARKER_BYTES
                && offset.is_multiple_of(GRANULE as u64),
            "sealed journal accepts only one complete 4 KiB marker slot",
        )?;
        self.revalidate_storage()?;
        self.io.cache_at = None;
        self.io.cache.0[..GRANULE].copy_from_slice(input);
        let result = (|| {
            self.io.write_block(offset, GRANULE)?;
            self.io.file.sync_all()?;
            self.revalidate_storage()?;
            self.io.read_block(offset, GRANULE)?;
            require(
                self.io.cache.0[..GRANULE] == *input,
                "uncached post-flush marker readback differs",
            )?;
            self.revalidate_storage()
        })();
        if let Err(error) = result {
            self.io.poisoned = true;
            return Err(error);
        }
        self.io.position += GRANULE as u64;
        Ok(GRANULE)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

fn protect_clusters(file: &File, volume: &File) -> io::Result<()> {
    let mut info = MARK_HANDLE_INFO::default();
    info.VolumeHandle = volume.as_raw_handle();
    info.HandleInfo = MARK_HANDLE_PROTECT_CLUSTERS;
    let mut returned = 0u32;
    // SAFETY: native initialized input and live retained file/volume handles.
    // Protection is local to this file handle and expires when it closes.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_MARK_HANDLE,
            (&info as *const MARK_HANDLE_INFO).cast(),
            size_of::<MARK_HANDLE_INFO>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn marker_offsets(
    file: &File,
    identity: &JournalFileIdentity,
    cluster: u32,
    base: u64,
) -> io::Result<[u64; SLOTS]> {
    let input = 0i64;
    let mut output = [0u64; 2 + 2 * MAX_PREFIX_EXTENTS];
    let mut returned = 0u32;
    // SAFETY: aligned initialized native input/output with fixed independent
    // budgets. ERROR_MORE_DATA is accepted only with complete prefix coverage.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            crate::stream_layout::GET_RETRIEVAL,
            (&input as *const i64).cast(),
            8,
            output.as_mut_ptr().cast(),
            size_of_val(&output) as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(error);
        }
    }
    require(
        returned as usize <= size_of_val(&output),
        "marker retrieval output exceeds budget",
    )?;
    // SAFETY: output is initialized, and only the bounded native returned
    // prefix is viewed as bytes. Integer parsing never creates native bools.
    let bytes =
        unsafe { std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), returned as usize) };
    let count = u32_at(bytes, 0)? as usize;
    require(
        (1..=MAX_PREFIX_EXTENTS).contains(&count)
            && bytes.len() == 16 + 16 * count
            && u64_at(bytes, 8)? == 0,
        "marker retrieval prefix is incomplete or malformed",
    )?;
    let mut runs = Vec::with_capacity(count);
    let mut vcn = 0u64;
    for index in 0..count {
        let next = u64_at(bytes, 16 + 16 * index)?;
        let lcn = u64_at(bytes, 24 + 16 * index)?;
        require(
            next > vcn && next <= i64::MAX as u64 && lcn <= i64::MAX as u64,
            "marker retrieval has a sparse or invalid extent",
        )?;
        let start = vcn
            .checked_mul(u64::from(cluster))
            .ok_or_else(|| invalid("marker VCN overflow"))?;
        let end = next
            .checked_mul(u64::from(cluster))
            .ok_or_else(|| invalid("marker next VCN overflow"))?;
        let physical = lcn
            .checked_mul(u64::from(cluster))
            .and_then(|n| n.checked_add(base))
            .and_then(|n| n.checked_add(identity.partition_offset))
            .ok_or_else(|| invalid("marker LCN/base offset overflow"))?;
        runs.push((start, end, physical));
        vcn = next;
    }
    require(
        runs.last().is_some_and(|(_, end, _)| *end >= MARKER_BYTES),
        "retrieval prefix does not cover all eight marker slots",
    )?;
    let partition_end = identity
        .partition_offset
        .checked_add(identity.partition_bytes)
        .ok_or_else(|| invalid("marker partition overflow"))?;
    let mut offsets = [0u64; SLOTS];
    for (slot, device_offset) in offsets.iter_mut().enumerate() {
        let start = (slot * GRANULE) as u64;
        let stop = start + GRANULE as u64;
        let mut covered = start;
        let mut first = None;
        for &(vstart, vend, physical) in &runs {
            let lo = start.max(vstart);
            let hi = stop.min(vend);
            if lo >= hi {
                continue;
            }
            let at = physical
                .checked_add(lo - vstart)
                .ok_or_else(|| invalid("marker physical range overflow"))?;
            let first = *first.get_or_insert(at);
            require(
                lo == covered && first.checked_add(lo - start) == Some(at),
                "marker slot is incomplete or physically fragmented",
            )?;
            covered = hi;
        }
        let at = first.ok_or_else(|| invalid("marker slot is unallocated"))?;
        let end = at
            .checked_add(GRANULE as u64)
            .ok_or_else(|| invalid("marker slot disk range overflow"))?;
        require(
            covered == stop
                && at.is_multiple_of(GRANULE as u64)
                && at >= identity.partition_offset
                && end <= partition_end
                && end <= identity.disk_bytes,
            "marker slot is not aligned and wholly inside its bound partition",
        )?;
        *device_offset = at;
    }
    for left in 0..SLOTS {
        for right in left + 1..SLOTS {
            require(
                offsets[left].abs_diff(offsets[right]) >= GRANULE as u64,
                "marker slots share a reported device sector",
            )?;
        }
    }
    Ok(offsets)
}
