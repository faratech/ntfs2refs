//! Native stream observations and bounded logical reads. No on-disk setters.
use crate::{attestation::*, stream_layout as layout};
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OpenFileById, ReOpenFile,
    },
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
pub(crate) fn bitmap(file: &File) -> io::Result<(IoctlQuery, Vec<IoctlQuery>)> {
    bitmap_queries(file, &[0; 8])
}

/// Retain the actual first call for diagnostics; later bitmap pages feed the
/// bounded collector and transcript rather than an image-sized response list.
pub(crate) fn bitmap_streamed(
    file: &File,
    clusters: u64,
) -> io::Result<(IoctlQuery, crate::bitmap_streaming::Summary)> {
    bitmap_streamed_with_input(file, clusters, &[0; 8])
}

pub(crate) fn bitmap_streamed_with_input(
    file: &File,
    clusters: u64,
    template: &[u8],
) -> io::Result<(IoctlQuery, crate::bitmap_streaming::Summary)> {
    crate::bitmap_paging::page_input(template, 0)?;
    let mut collector = crate::bitmap_streaming::Collector::new(
        clusters,
        crate::bitmap_streaming::source_limits(clusters)?,
    )?;
    let mut first = None;
    while collector.response_capacity() != 0 {
        let input = crate::bitmap_paging::page_input(template, collector.next_lcn())?;
        let query = ioctl(
            file,
            layout::GET_BITMAP,
            &input,
            collector.response_capacity(),
        );
        if let Some(error) = query
            .native_error
            .filter(|error| *error != crate::bitmap_paging::MORE_DATA)
        {
            return Err(io::Error::from_raw_os_error(error));
        }
        let complete = collector.push(&query, template, &mut |_| Ok(()))?;
        if first.is_none() {
            first = Some(query);
        }
        if complete {
            break;
        }
    }
    Ok((
        first.ok_or_else(|| io::Error::other("source bitmap returned no pages"))?,
        collector.finish()?,
    ))
}
pub(crate) fn bitmap_queries(
    file: &File,
    template: &[u8],
) -> io::Result<(IoctlQuery, Vec<IoctlQuery>)> {
    crate::bitmap_paging::page_input(template, 0)?;
    let mut assembler = crate::bitmap_paging::Assembler::default();
    let mut queries = Vec::new();
    while assembler.response_capacity() != 0 {
        let input = crate::bitmap_paging::page_input(template, assembler.next_lcn())?;
        let query = ioctl(
            file,
            layout::GET_BITMAP,
            &input,
            assembler.response_capacity(),
        );
        let result = assembler.push(&query, template);
        queries.push(query);
        if !matches!(result, Ok(false)) {
            break;
        }
    }
    // Keep refused/truncated responses for diagnostic replay. Only the shared
    // assembler, not this tuple, can establish complete bitmap coverage.
    let first = queries.remove(0);
    Ok((first, queries))
}
pub(crate) fn bitmap_capture(
    file: &File,
    template: &[u8],
) -> io::Result<crate::bitmap_paging::Capture> {
    let (first, continuation) = bitmap_queries(file, template)?;
    crate::bitmap_paging::assemble_queries(&first, &continuation, template)
}
pub(crate) fn retrieval_queries(file: &File) -> (IoctlQuery, Vec<IoctlQuery>) {
    let mut assembler = crate::retrieval_paging::Assembler::default();
    let mut queries = Vec::new();
    while assembler.response_capacity() != 0 {
        let query = ioctl(
            file,
            layout::GET_RETRIEVAL,
            &assembler.next_vcn().to_le_bytes(),
            assembler.response_capacity(),
        );
        let result = assembler.push(&query);
        queries.push(query);
        if !matches!(result, Ok(false)) {
            break;
        };
    }
    let first = queries.remove(0);
    (first, queries)
}
pub(crate) fn retrieval_capture(file: &File) -> io::Result<crate::retrieval_paging::Capture> {
    let (first, continuation) = retrieval_queries(file);
    crate::retrieval_paging::assemble_queries(&first, &continuation)
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
fn read_handle(file: &File, id: &FileIdentity, named_stream: bool) -> io::Result<File> {
    // Named streams originated from CreateFileW, so ReOpenFile retains their
    // stream. Default streams reopen by ID using the existing volume hint.
    let h = if named_stream {
        unsafe { ReOpenFile(file.as_raw_handle(), 0x80000080, 7, 0x02200000) }
    } else {
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: id.reference() as i64,
            },
        };
        unsafe {
            OpenFileById(
                file.as_raw_handle(),
                &descriptor,
                0x80000080,
                7,
                ptr::null(),
                0x02200000,
            )
        }
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: transfer the newly returned, uniquely owned native handle.
    Ok(unsafe { File::from_raw_handle(h) })
}
fn hash_stream(
    file: &File,
    r: &Request,
    id: &FileIdentity,
    name: &[u16],
    expected: u64,
    budget: &mut crate::logical_hash::Budget,
) -> StreamHash {
    let mut out = StreamHash {
        name_utf16: name.to_vec(),
        logical_size: expected,
        identity_before: None,
        identity_after: None,
        standard_before: None,
        standard_after: None,
        outcome: crate::logical_hash::Outcome::refused(io::Error::other(
            "data read was not started",
        )),
    };
    let mut data = match read_handle(file, id, !name.is_empty()) {
        Ok(f) => f,
        Err(e) => {
            out.outcome = crate::logical_hash::Outcome::refused(e);
            return out;
        }
    };
    let before = info(&data, 18, 24);
    let valid = binding(&before, r, id);
    out.identity_before = Some(before);
    if let Err(e) = valid {
        out.outcome = crate::logical_hash::Outcome::refused(e);
        return out;
    }
    let standard = info(&data, 1, 24);
    let correct = standard.native_error.is_none()
        && standard.bytes.len() == 24
        && u64::from_le_bytes(standard.bytes[8..16].try_into().unwrap()) == expected;
    out.standard_before = Some(standard);
    if !correct {
        out.outcome = crate::logical_hash::Outcome::refused(io::Error::other(
            "data stream length query differs",
        ));
        return out;
    }
    out.outcome = crate::logical_hash::read(&mut data, expected, budget);
    let after = info(&data, 18, 24);
    let valid = binding(&after, r, id);
    out.identity_after = Some(after);
    out.standard_after = Some(info(&data, 1, 24));
    if valid.is_err()
        || out.identity_before != out.identity_after
        || out.standard_before != out.standard_after
    {
        let consumed = out.outcome.bytes_read;
        out.outcome = crate::logical_hash::Outcome::refused(io::Error::other(
            "data stream identity or length changed during read",
        ));
        out.outcome.bytes_read = consumed;
    }
    out
}
pub(crate) fn capture(
    file: &File,
    r: &Request,
    id: &FileIdentity,
    budget: &mut crate::logical_hash::Budget,
    evidence_limit: usize,
) -> (StreamCapture, Vec<StreamHash>) {
    let mut hashes = vec![];
    let mut enumeration = info(file, 7, layout::MAX_STREAM_BUFFER);
    let mut result = StreamCapture {
        enumeration: enumeration.clone(),
        parse_error: None,
        streams: vec![],
    };
    if enumeration.native_error.is_some() {
        return (result, hashes);
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
            return (result, hashes);
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
            retrieval_continuation: vec![],
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
        let (first, continuation) = retrieval_queries(f);
        q.retrieval = Some(first);
        q.retrieval_continuation = continuation;
        hashes.push(hash_stream(
            f,
            r,
            id,
            &entry.name,
            entry.logical_size,
            budget,
        ));
        let after = info(f, 18, 24);
        if let Err(e) = binding(&after, r, id) {
            q.binding_error = Some(e.to_string());
        }
        q.identity_after = Some(after);
        result.streams.push(q);
        if result
            .retained_bytes()
            .saturating_add(hash_retained_bytes(&hashes))
            > evidence_limit
        {
            result.parse_error = Some("native stream page evidence budget exhausted".into());
            break;
        }
    }
    (result, hashes)
}
