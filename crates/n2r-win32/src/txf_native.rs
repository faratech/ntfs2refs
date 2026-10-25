//! Read-only TxF resource-manager observations while NTFS is still mounted.
//! A pair of zero-count queries is diagnostic; source freeze and log recovery
//! still have to be proven separately before conversion.
use crate::layout::DiskBinding;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io, mem,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_IS_VOLUME_DIRTY,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE, FSCTL_TXFS_LIST_TRANSACTIONS,
            FSCTL_TXFS_QUERY_RM_INFORMATION, TXFS_QUERY_RM_INFORMATION,
        },
    },
};

const MAX_REPLY: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct RmQuery {
    pub rm_state: u32,
    pub transaction_count: u64,
    pub tail_lsn: u64,
    pub current_lsn: u64,
    pub tops_used: u64,
    pub bytes_returned: u32,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionList {
    pub number_of_transactions: u64,
    pub buffer_size_required: u64,
    pub bytes_returned: u32,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct PersistentState {
    pub volume_flags: u32,
    pub flag_mask: u32,
    pub version: u32,
    pub short_name_creation_disabled: bool,
    pub reply_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub binding: DiskBinding,
    pub native_dirty_before: Option<u32>,
    pub native_dirty_before_error: Option<u32>,
    pub persistent_state_before: Option<PersistentState>,
    pub persistent_state_before_error: Option<u32>,
    pub query_before: Option<RmQuery>,
    pub query_before_error: Option<u32>,
    pub transaction_list: Option<TransactionList>,
    pub transaction_list_error: Option<u32>,
    pub query_after: Option<RmQuery>,
    pub query_after_error: Option<u32>,
    pub native_dirty_after: Option<u32>,
    pub native_dirty_after_error: Option<u32>,
    pub persistent_state_after: Option<PersistentState>,
    pub persistent_state_after_error: Option<u32>,
    pub native_volume_state_stably_clear: bool,
    pub short_name_state_stable: bool,
    pub queried_rm_stably_empty: bool,
    pub all_resource_managers_checked: bool,
    pub source_frozen: bool,
    pub execution_authorized: bool,
}

fn control(file: &File, code: u32) -> Result<Vec<u8>, u32> {
    let mut aligned = vec![0u64; MAX_REPLY / 8];
    let mut returned = 0u32;
    // SAFETY: the borrowed handle and initialized u64-aligned output buffer
    // remain alive for this bounded synchronous FSCTL.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            ptr::null(),
            0,
            aligned.as_mut_ptr().cast(),
            MAX_REPLY as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: this is the error from the immediately preceding Win32 call.
        return Err(unsafe { GetLastError() });
    }
    if returned as usize > MAX_REPLY {
        return Err(13); // ERROR_INVALID_DATA
    }
    // SAFETY: returned is bounded by the allocated 64 KiB above; the aligned
    // storage remains alive while copying the exact initialized reply bytes.
    Ok(unsafe {
        std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), returned as usize).to_vec()
    })
}

fn query(file: &File) -> (Option<RmQuery>, Option<u32>) {
    match control(file, FSCTL_TXFS_QUERY_RM_INFORMATION) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() < mem::size_of::<TXFS_QUERY_RM_INFORMATION>() => (None, Some(13)),
        Ok(bytes) => {
            // SAFETY: the complete repr(C) structure is present; read_unaligned
            // handles Vec<u8>'s byte alignment without casting it to a reference.
            let info =
                unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<TXFS_QUERY_RM_INFORMATION>()) };
            (
                Some(RmQuery {
                    rm_state: info.RmState,
                    transaction_count: info.TransactionCount,
                    tail_lsn: info.TailLsn,
                    current_lsn: info.CurrentLsn,
                    tops_used: info.TopsUsed,
                    bytes_returned: bytes.len() as u32,
                    reply_sha256: hex::encode(Sha256::digest(&bytes)),
                }),
                None,
            )
        }
    }
}

fn list(file: &File) -> (Option<TransactionList>, Option<u32>) {
    match control(file, FSCTL_TXFS_LIST_TRANSACTIONS) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() < 16 => (None, Some(13)),
        Ok(bytes) => (
            Some(TransactionList {
                number_of_transactions: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                buffer_size_required: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                bytes_returned: bytes.len() as u32,
                reply_sha256: hex::encode(Sha256::digest(&bytes)),
            }),
            None,
        ),
    }
}

fn dirty(file: &File) -> (Option<u32>, Option<u32>) {
    match control(file, FSCTL_IS_VOLUME_DIRTY) {
        Err(code) => (None, Some(code)),
        Ok(bytes) if bytes.len() != 4 => (None, Some(13)),
        Ok(bytes) => (Some(u32::from_le_bytes(bytes.try_into().unwrap())), None),
    }
}

fn persistent(file: &File) -> (Option<PersistentState>, Option<u32>) {
    let input = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        FlagMask: 1,
        Version: 1,
        ..Default::default()
    };
    let mut output = FILE_FS_PERSISTENT_VOLUME_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: both repr(C) structures are initialized, aligned and live for
    // this synchronous read-only volume query.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            mem::size_of_val(&input) as u32,
            (&mut output as *mut FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            mem::size_of_val(&output) as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: direct error from the preceding Win32 call.
        return (None, Some(unsafe { GetLastError() }));
    }
    if returned as usize != mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>()
        || output.Version != 1
        || output.FlagMask & 1 == 0
        || output.Reserved != 0
    {
        return (None, Some(13));
    }
    let bytes = [
        output.VolumeFlags.to_le_bytes(),
        output.FlagMask.to_le_bytes(),
        output.Version.to_le_bytes(),
        output.Reserved.to_le_bytes(),
    ]
    .concat();
    (
        Some(PersistentState {
            volume_flags: output.VolumeFlags,
            flag_mask: output.FlagMask,
            version: output.Version,
            short_name_creation_disabled: output.VolumeFlags & 1 != 0,
            reply_sha256: hex::encode(Sha256::digest(bytes)),
        }),
        None,
    )
}

pub fn observe(binding: DiskBinding) -> io::Result<Observation> {
    binding.validate()?;
    if binding.disk_number != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lab TxF query requires disk 1",
        ));
    }
    if crate::native::current_windows_disk(&mut Vec::new())? == binding.disk_number {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows disk cannot be queried by the lab tool",
        ));
    }
    let volume = File::options()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    let (native_dirty_before, native_dirty_before_error) = dirty(&volume);
    let (persistent_state_before, persistent_state_before_error) = persistent(&volume);
    let (before, before_error) = query(&volume);
    let (transactions, list_error) = list(&volume);
    let (after, after_error) = query(&volume);
    let (native_dirty_after, native_dirty_after_error) = dirty(&volume);
    let (persistent_state_after, persistent_state_after_error) = persistent(&volume);
    let native_volume_state_stably_clear =
        native_dirty_before == Some(0) && native_dirty_after == Some(0);
    let short_name_state_stable = persistent_state_before
        .as_ref()
        .zip(persistent_state_after.as_ref())
        .is_some_and(|(before, after)| {
            before.short_name_creation_disabled == after.short_name_creation_disabled
                && before.volume_flags & 1 == after.volume_flags & 1
        });
    let queried_rm_stably_empty = before.as_ref().is_some_and(|q| q.transaction_count == 0)
        && after.as_ref().is_some_and(|q| q.transaction_count == 0)
        && transactions.as_ref().is_some_and(|l| {
            l.number_of_transactions == 0 && l.buffer_size_required <= MAX_REPLY as u64
        })
        && before
            .as_ref()
            .zip(after.as_ref())
            .is_some_and(|(a, b)| a.rm_state == b.rm_state && matches!(a.rm_state, 0 | 2));
    Ok(Observation {
        schema_version: 1,
        kind: "mounted-ntfs-txf-resource-manager-observation",
        binding,
        native_dirty_before,
        native_dirty_before_error,
        persistent_state_before,
        persistent_state_before_error,
        query_before: before,
        query_before_error: before_error,
        transaction_list: transactions,
        transaction_list_error: list_error,
        query_after: after,
        query_after_error: after_error,
        native_dirty_after,
        native_dirty_after_error,
        persistent_state_after,
        persistent_state_after_error,
        native_volume_state_stably_clear,
        short_name_state_stable,
        queried_rm_stably_empty,
        all_resource_managers_checked: false,
        source_frozen: false,
        execution_authorized: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_volume_state_uses_the_documented_aligned_wire_shape() {
        assert_eq!(mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>(), 16);
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, VolumeFlags),
            0
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, FlagMask),
            4
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, Version),
            8
        );
        assert_eq!(
            mem::offset_of!(FILE_FS_PERSISTENT_VOLUME_INFORMATION, Reserved),
            12
        );
    }
}
