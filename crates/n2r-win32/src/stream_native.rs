//! Native stream metadata queries only. No payload reads or setters.
use crate::{attestation::*, stream_layout as layout};
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{CreateFileW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW},
    System::IO::DeviceIoControl,
};

pub(crate) fn ioctl(file: &File, code: u32, input: &[u8], capacity: usize) -> IoctlQuery {
    let mut bytes = vec![0; capacity];
    let mut used = 0;
    // SAFETY: live handle and initialized buffers of their declared lengths.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            bytes.as_mut_ptr().cast(),
            capacity as u32,
            &mut used,
            ptr::null_mut(),
        )
    };
    let mut native_error =
        (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    if used as usize > capacity {
        bytes.clear();
        native_error = Some(13);
    } else {
        bytes.truncate(used as usize);
        bytes.shrink_to_fit();
    }
    IoctlQuery {
        code,
        input: input.to_vec(),
        bytes,
        native_error,
    }
}
pub(crate) fn base(file: &File) -> IoctlQuery {
    ioctl(file, layout::GET_BASE, &[], 8)
}
pub(crate) fn bitmap(file: &File) -> IoctlQuery {
    ioctl(
        file,
        layout::GET_BITMAP,
        &[0; 8],
        16 + layout::MAX_BITMAP_BYTES,
    )
}
fn info(file: &File, class: i32, length: usize) -> Query {
    let mut storage = vec![0u64; length.div_ceil(8)];
    // SAFETY: aligned fixed-size output and a live borrowed handle.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            length as u32,
        )
    };
    let error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    let bytes = if error.is_some() {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) }.to_vec()
    };
    Query {
        class,
        bytes,
        native_error: error,
    }
}
fn binding(q: &Query, r: &Request, id: &FileIdentity) -> io::Result<()> {
    if q.native_error.is_some() || q.bytes.len() != 24 {
        return Err(io::Error::other("stream file identity query refused"));
    }
    let b = &q.bytes;
    if u64::from_le_bytes(b[0..8].try_into().unwrap()) != r.ntfs_serial
        || u64::from_le_bytes(b[8..16].try_into().unwrap()) != id.reference()
        || b[16..].iter().any(|x| *x != 0)
    {
        return Err(io::Error::other("stream file/volume identity differs"));
    }
    Ok(())
}
fn named(file: &File, r: &Request, name: &[u16]) -> io::Result<File> {
    let mut path = vec![0u16; 32768];
    // SAFETY: live source handle and caller-owned UTF-16 output buffer.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            1,
        )
    } as usize;
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    if n >= path.len() {
        return Err(io::Error::other("source path exceeds bound"));
    }
    path.truncate(n);
    let prefix: Vec<u16> = r.volume.encode_utf16().collect();
    if path.len() < prefix.len()
        || !path[..prefix.len()].iter().zip(&prefix).all(|(a, b)| {
            a == b || (*a < 128 && *b < 128 && (*a as u8).eq_ignore_ascii_case(&(*b as u8)))
        })
        || path.contains(&0)
    {
        return Err(io::Error::other("source path is outside pinned volume"));
    }
    path.push(58);
    path.extend_from_slice(name);
    path.extend(":$DATA".encode_utf16());
    if path.len() >= 32767 {
        return Err(io::Error::other("named stream path exceeds bound"));
    }
    path.push(0);
    // SAFETY: terminated bounded path; read attributes only, share all and
    // open reparse points themselves. The new handle's identity is verified
    // before issuing any retrieval query.
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            0x80,
            7,
            ptr::null(),
            3,
            0x02200000,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(h) })
}
pub(crate) fn capture(file: &File, r: &Request, id: &FileIdentity) -> StreamCapture {
    let mut enumeration = info(file, 7, layout::MAX_STREAM_BUFFER);
    let mut result = StreamCapture {
        enumeration: enumeration.clone(),
        parse_error: None,
        streams: vec![],
    };
    if enumeration.native_error.is_some() {
        return result;
    }
    let entries = match layout::parse_streams(&enumeration.bytes) {
        Ok((entries, end)) => {
            enumeration.bytes.truncate(end);
            enumeration.bytes.shrink_to_fit();
            result.enumeration = enumeration;
            entries
        }
        Err(e) => {
            result.parse_error = Some(e.to_string());
            return result;
        }
    };
    for entry in entries {
        let mut q = StreamQuery {
            name_utf16: entry.name.clone(),
            logical_size: entry.logical_size,
            allocated_size: entry.allocated_size,
            open_error: None,
            binding_error: None,
            identity_before: None,
            identity_after: None,
            retrieval: None,
        };
        let owned = if entry.name.is_empty() {
            None
        } else {
            match named(file, r, &entry.name) {
                Ok(f) => Some(f),
                Err(e) => {
                    q.open_error = Some(e.raw_os_error().unwrap_or(13));
                    q.binding_error = Some(e.to_string());
                    result.streams.push(q);
                    continue;
                }
            }
        };
        let f = owned.as_ref().unwrap_or(file);
        let before = info(f, 18, 24);
        if let Err(e) = binding(&before, r, id) {
            q.binding_error = Some(e.to_string());
            q.identity_before = Some(before);
            result.streams.push(q);
            continue;
        }
        q.identity_before = Some(before);
        q.retrieval = Some(ioctl(
            f,
            layout::GET_RETRIEVAL,
            &[0; 8],
            layout::RETRIEVAL_CAPACITY,
        ));
        let after = info(f, 18, 24);
        if let Err(e) = binding(&after, r, id) {
            q.binding_error = Some(e.to_string());
        }
        q.identity_after = Some(after);
        result.streams.push(q);
    }
    result
}
