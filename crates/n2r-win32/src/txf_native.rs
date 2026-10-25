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
            FSCTL_TXFS_LIST_TRANSACTIONS, FSCTL_TXFS_QUERY_RM_INFORMATION,
            TXFS_QUERY_RM_INFORMATION,
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
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub binding: DiskBinding,
    pub query_before: Option<RmQuery>,
    pub query_before_error: Option<u32>,
    pub transaction_list: Option<TransactionList>,
    pub transaction_list_error: Option<u32>,
    pub query_after: Option<RmQuery>,
    pub query_after_error: Option<u32>,
    pub queried_rm_stably_empty: bool,
    pub all_resource_managers_checked: bool,
    pub source_frozen: bool,
    pub execution_authorized: bool,
}

fn control(file: &File, code: u32) -> Result<Vec<u8>, u32> {
    let mut bytes = vec![0; MAX_REPLY];
    let mut returned = 0u32;
    // SAFETY: the file handle is borrowed; the output buffer is initialized,
    // bounded, exclusively owned and kept alive for this synchronous FSCTL.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            ptr::null(),
            0,
            bytes.as_mut_ptr().cast(),
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
    bytes.truncate(returned as usize);
    Ok(bytes)
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
    let (before, before_error) = query(&volume);
    let (transactions, list_error) = list(&volume);
    let (after, after_error) = query(&volume);
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
        query_before: before,
        query_before_error: before_error,
        transaction_list: transactions,
        transaction_list_error: list_error,
        query_after: after,
        query_after_error: after_error,
        queried_rm_stably_empty,
        all_resource_managers_checked: false,
        source_frozen: false,
        execution_authorized: false,
    })
}
