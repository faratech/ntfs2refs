//! Private allocation-only construction primitive. No payload Read/Write or
//! raw handle is exposed outside the native shadow module. Failed operations
//! leave the private file for diagnosis; they never authorize target writes.
use super::{ctl, invalid, mapping_matches_run, wide};
use crate::{bitmap_layout::Candidate, bitmap_observation::Observation};
use serde::Serialize;
use std::{
    fs::File,
    io, mem,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, SetFileInformationByHandle, SetFileValidData},
};

#[derive(Serialize)]
pub(super) struct Placement {
    pub destination_lcn: u64,
    pub starting_vcn: u64,
    pub clusters: u32,
    pub submitted_once: bool,
    pub before_valid_data_advance: bool,
    pub native_error: Option<i32>,
    pub mapping_matches: bool,
    pub mapping_after: Vec<u8>,
    pub mapping_page_proof: crate::retrieval_paging::Proof,
    pub legacy_candidate: Candidate,
    pub metadata_candidate: Candidate,
}

pub(super) struct PrivatePlaceholder {
    file: File,
    pub path: String,
    bytes: u64,
    partition: u64,
    placed: Vec<(u64, u64, u32)>,
    valid_data_submitted: bool,
    poisoned: bool,
}

impl PrivatePlaceholder {
    /// Caller binds the independent writable ReFS shadow and enables volume
    /// privilege before this call. Security is applied atomically at creation.
    pub fn allocate(root: &str, experiment: &str, bytes: u64, partition: u64) -> io::Result<Self> {
        if experiment.len() != 32
            || !experiment.bytes().all(|b| b.is_ascii_hexdigit())
            || bytes < 4096
            || !bytes.is_multiple_of(4096)
        {
            return Err(invalid("private allocation geometry or identity differs"));
        }
        Self::allocate_named(
            root,
            &[format!("n2r-valid-data-{experiment}.bin")],
            bytes,
            partition,
        )
    }

    /// Preserve source names while retaining private permissions. No source
    /// security descriptor is restored over an uninitialized placeholder.
    pub fn allocate_named(
        root: &str,
        components: &[String],
        bytes: u64,
        partition: u64,
    ) -> io::Result<Self> {
        if components.is_empty()
            || components.len() > 16
            || components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
            || bytes > partition
            || partition > crate::general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES
            || i64::try_from(bytes).is_err()
        {
            return Err(invalid("private named allocation geometry or path differs"));
        }
        let sddl = wide("O:SYG:SYD:P(A;;FA;;;SY)");
        let mut descriptor = ptr::null_mut();
        // SAFETY: constant NUL-terminated SDDL, allocated output freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let path = format!("{}\\{}", root.trim_end_matches('\\'), components.join("\\"));
        let name = wide(&path);
        // SAFETY: caller-bound volume root, validated components, CREATE_NEW,
        // sharing disabled and SYSTEM-only protected security descriptor.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0xc0020000,
                0,
                &sa,
                1,
                0x80200080,
                ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        unsafe {
            LocalFree(descriptor);
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: unique ownership of the successfully created native handle.
        let file = unsafe { File::from_raw_handle(handle) };
        ctl(&file, 0x9c280, &[0; 8], 0)?;
        if bytes >= 4096 {
            let allocation = bytes
                .checked_add(4095)
                .ok_or_else(|| invalid("private allocation overflow"))?
                / 4096
                * 4096;
            // SAFETY: aligned FILE_ALLOCATION_INFO and synchronous live handle.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    5,
                    (&allocation as *const u64).cast(),
                    8,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        file.set_len(bytes)?;
        Ok(Self {
            file,
            path,
            bytes,
            partition,
            placed: vec![],
            valid_data_submitted: false,
            poisoned: false,
        })
    }

    /// Metadata-only access for the enclosing native module's existing query
    /// functions. The constructor exposes no payload interface to callers.
    pub fn metadata_handle(&self) -> &File {
        &self.file
    }

    /// Place one unwritten logical range. A native refusal/partial completion
    /// poisons the placeholder; no retry or later VDL advancement is accepted.
    pub fn place(
        &mut self,
        volume: &File,
        starting_vcn: u64,
        destination_lcn: u64,
        clusters: u32,
    ) -> io::Result<Placement> {
        let logical_end = starting_vcn.checked_add(u64::from(clusters));
        let physical_end = destination_lcn.checked_add(u64::from(clusters));
        if self.poisoned
            || self.valid_data_submitted
            || self.placed.len() >= 1024
            || clusters == 0
            || destination_lcn < 256
            || logical_end.is_none_or(|v| v > self.bytes / 4096)
            || physical_end.is_none_or(|v| v > self.partition / 4096)
            || self.placed.iter().any(|(v, l, n)| {
                starting_vcn < *v + u64::from(*n) && *v < logical_end.unwrap_or(0)
                    || destination_lcn < *l + u64::from(*n) && *l < physical_end.unwrap_or(0)
            })
        {
            return Err(invalid(
                "private unwritten placement state, overlap or bounds differ",
            ));
        }
        let legacy = Observation::capture(volume, &[0; 8], self.partition, true)?;
        let mut ex = [0u8; 16];
        ex[8] = 1;
        let metadata = Observation::capture(volume, &ex, self.partition, true)?;
        let length = u64::from(clusters) * 4096;
        let old = legacy
            .view(self.partition)?
            .candidate(destination_lcn * 4096, length)?;
        let all = metadata
            .view(self.partition)?
            .candidate(destination_lcn * 4096, length)?;
        if old.declared_clusters != self.partition / 4096
            || all.declared_clusters != self.partition / 4096
            || old.allocated_clusters != 0
            || all.allocated_clusters != 0
        {
            return Err(invalid(
                "private placement requires both current bitmap views free",
            ));
        }
        let mut input = [0u8; 32];
        input[..8].copy_from_slice(&(self.file.as_raw_handle() as usize as u64).to_le_bytes());
        input[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
        input[16..24].copy_from_slice(&destination_lcn.to_le_bytes());
        input[24..28].copy_from_slice(&clusters.to_le_bytes());
        self.poisoned = true; // Any missing post-I/O evidence must fail closed.
        let moved = ctl(volume, 0x90074, &input, 0);
        let capture = crate::stream_native::retrieval_capture(&self.file)?;
        let mapped = mapping_matches_run(
            &crate::stream_layout::parse_complete_retrieval(&capture.canonical)?,
            starting_vcn,
            destination_lcn,
            clusters,
        )?;
        let native_error = moved.err().map(|e| e.raw_os_error().unwrap_or(31));
        if native_error.is_none() && mapped {
            self.placed.push((starting_vcn, destination_lcn, clusters));
            self.poisoned = false;
        }
        Ok(Placement {
            destination_lcn,
            starting_vcn,
            clusters,
            submitted_once: true,
            before_valid_data_advance: true,
            native_error,
            mapping_matches: mapped,
            mapping_after: capture.canonical,
            mapping_page_proof: capture.proof,
            legacy_candidate: old,
            metadata_candidate: all,
        })
    }

    /// Advance once. Construction requires complete placed-prefix coverage;
    /// the old standalone allocation probe can explicitly omit that policy.
    pub fn advance_valid_data(&mut self, bytes: u64, require_placed: bool) -> io::Result<()> {
        if self.poisoned
            || self.valid_data_submitted
            || bytes == 0
            || bytes > self.bytes
            || !bytes.is_multiple_of(4096)
        {
            return Err(invalid("private validity state or length differs"));
        }
        if require_placed {
            let mut runs = self.placed.clone();
            runs.sort_by_key(|r| r.0);
            let mut cursor = 0;
            for (vcn, _, clusters) in runs {
                if vcn >= bytes / 4096 {
                    break;
                }
                if vcn != cursor {
                    return Err(invalid("private placed prefix has a gap"));
                }
                cursor += u64::from(clusters);
            }
            if cursor < bytes / 4096 {
                return Err(invalid("private placed prefix is incomplete"));
            }
        }
        self.valid_data_submitted = true;
        self.poisoned = true;
        // SAFETY: caller enabled manage-volume privilege before creating this
        // private file; aligned positive VDL is no greater than admitted EOF.
        if unsafe { SetFileValidData(self.file.as_raw_handle(), bytes as i64) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.file.sync_all()?;
        let capture = crate::stream_native::retrieval_capture(&self.file)?;
        let runs = crate::stream_layout::parse_complete_retrieval(&capture.canonical)?;
        for &(vcn, lcn, clusters) in &self.placed {
            if !mapping_matches_run(&runs, vcn, lcn, clusters)? {
                return Err(invalid("private mapping changed after valid-data flush"));
            }
        }
        self.poisoned = false;
        Ok(())
    }
}
