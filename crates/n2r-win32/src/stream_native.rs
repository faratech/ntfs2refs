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
    Ok(bitmap_streamed_collected_with_input(file, clusters, template)?.into_legacy_parts())
}

/// Retain the original collector's first-page proof and validated prefix in an
/// opaque value, so native consumers do not replay/hash that response again.
pub(crate) fn bitmap_streamed_collected_with_input(
    file: &File,
    clusters: u64,
    template: &[u8],
) -> io::Result<crate::bitmap_streaming::CollectedBitmap> {
    bitmap_streamed_with_limits(
        file,
        clusters,
        template,
        crate::bitmap_streaming::source_limits(clusters)?,
    )
}
pub(crate) fn bitmap_streamed_with_limits(
    file: &File,
    clusters: u64,
    template: &[u8],
    limits: crate::bitmap_streaming::Limits,
) -> io::Result<crate::bitmap_streaming::CollectedBitmap> {
    bitmap_streamed_collector(
        file,
        template,
        crate::bitmap_streaming::Collector::new(clusters, limits)?,
    )
}
pub(crate) fn bitmap_streamed_with_bounded_ranges(
    file: &File,
    clusters: u64,
    template: &[u8],
    limits: crate::bitmap_streaming::Limits,
) -> io::Result<crate::bitmap_streaming::CollectedBitmap> {
    bitmap_streamed_collector(
        file,
        template,
        crate::bitmap_streaming::Collector::new_with_bounded_ranges(clusters, limits)?,
    )
}
fn bitmap_streamed_collector(
    file: &File,
    template: &[u8],
    mut collector: crate::bitmap_streaming::Collector,
) -> io::Result<crate::bitmap_streaming::CollectedBitmap> {
    crate::bitmap_paging::page_input(template, 0)?;
    let mut first = true;
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
        let complete = if first {
            first = false;
            collector.push_first_owned(query, template)?
        } else {
            collector.push(&query, template, &mut |_| Ok(()))?
        };
        if complete {
            break;
        }
    }
    collector.finish_collected()
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
    retrieval_queries_assembled(file, crate::retrieval_paging::Assembler::default())
}
pub(crate) fn retrieval_queries_resource(
    file: &File,
    evidence_bytes: usize,
) -> io::Result<(IoctlQuery, Vec<IoctlQuery>)> {
    let limits = crate::retrieval_paging::Limits::for_resource_bytes(evidence_bytes)?;
    Ok(retrieval_queries_assembled(
        file,
        crate::retrieval_paging::Assembler::with_limits(limits)?,
    ))
}
fn retrieval_queries_assembled(
    file: &File,
    mut assembler: crate::retrieval_paging::Assembler,
) -> (IoctlQuery, Vec<IoctlQuery>) {
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
#[derive(Clone, Copy)]
pub(crate) struct ExtentContext {
    pub cluster_bytes: u32,
    pub retrieval_base_bytes: u64,
}
fn request_resource_bytes(request: &Request) -> io::Result<Option<usize>> {
    request
        .resource_profile
        .map(|p| p.resource_admission())
        .transpose()?
        .flatten()
        .map(|a| usize::try_from(a.budget.max_row_bytes).map_err(io::Error::other))
        .transpose()
}

fn extent_map_matches(
    expected: &ExtentIdentityStream,
    context: ExtentContext,
    first: &IoctlQuery,
    continuation: &[IoctlQuery],
    resource_bytes: Option<usize>,
) -> io::Result<()> {
    if expected.cluster_bytes != context.cluster_bytes {
        return Err(io::Error::other(
            "extent-identity native cluster geometry differs",
        ));
    }
    let runs = if let Some(bytes) = resource_bytes {
        crate::retrieval_paging::assemble_queries_with_limits(
            first,
            continuation,
            crate::retrieval_paging::Limits::for_resource_bytes(bytes)?,
        )?
        .runs
    } else {
        crate::retrieval_paging::assemble_queries(first, continuation)?.runs
    };
    let cluster = u64::from(context.cluster_bytes);
    let mut extents: Vec<ExtentIdentityExtent> = Vec::new();
    for run in runs {
        let offset = run
            .vcn
            .checked_mul(cluster)
            .ok_or_else(|| io::Error::other("native extent VCN overflow"))?;
        let physical = run
            .lcn
            .and_then(|lcn| lcn.checked_mul(cluster))
            .and_then(|n| n.checked_add(context.retrieval_base_bytes))
            .ok_or_else(|| io::Error::other("extent-identity native hole or LCN overflow"))?;
        let length = run
            .clusters
            .checked_mul(cluster)
            .ok_or_else(|| io::Error::other("native extent size overflow"))?;
        if let Some(last) = extents.last_mut()
            && last.logical_offset.checked_add(last.length) == Some(offset)
            && last.physical_offset.checked_add(last.length) == Some(physical)
        {
            last.length = last
                .length
                .checked_add(length)
                .ok_or_else(|| io::Error::other("native extent merge overflow"))?;
        } else {
            extents.push(ExtentIdentityExtent {
                logical_offset: offset,
                physical_offset: physical,
                length,
            });
        }
    }
    if extents != expected.extents {
        return Err(io::Error::other(
            "extent-identity complete native mapping differs",
        ));
    }
    Ok(())
}

fn hash_stream(
    file: &File,
    r: &Request,
    id: &FileIdentity,
    name: &[u16],
    expected: u64,
    budget: &mut crate::logical_hash::Budget,
    extent_identity: Option<(
        &ExtentIdentityStream,
        ExtentContext,
        &IoctlQuery,
        &[IoctlQuery],
    )>,
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
    out.outcome = if let Some((wanted, context, first, continuation)) = extent_identity {
        let allocated = out
            .standard_before
            .as_ref()
            .map(|q| u64::from_le_bytes(q.bytes[..8].try_into().unwrap()));
        match (allocated == Some(wanted.allocated_size) && wanted.logical_size == expected)
            .then(|| {
                extent_map_matches(
                    wanted,
                    context,
                    first,
                    continuation,
                    request_resource_bytes(r)?,
                )
            })
            .unwrap_or_else(|| {
                Err(io::Error::other(
                    "extent-identity stream allocation or EOF differs",
                ))
            }) {
            Ok(()) => crate::logical_hash::Outcome {
                status: crate::logical_hash::Status::NotReadExtentIdentityV1,
                bytes_read: 0,
                eof_confirmed: false,
                sha256: None,
                native_error: None,
                detail: None,
            },
            Err(e) => crate::logical_hash::Outcome::refused(e),
        }
    } else {
        crate::logical_hash::read(&mut data, expected, budget)
    };
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
    extent_context: Option<ExtentContext>,
) -> (StreamCapture, Vec<StreamHash>) {
    let mut hashes = vec![];
    let resource = match request_resource_bytes(r) {
        Ok(resource) => resource,
        Err(error) => {
            return (
                StreamCapture {
                    enumeration: info(file, 7, layout::MAX_STREAM_BUFFER),
                    parse_error: Some(error.to_string()),
                    streams: Vec::new(),
                },
                hashes,
            );
        }
    };
    let mut enumeration = info(file, 7, layout::MAX_STREAM_BUFFER);
    if resource.is_some() {
        let mut capacity = layout::MAX_STREAM_BUFFER;
        let maximum = evidence_limit.min(u32::MAX as usize);
        while matches!(enumeration.native_error, Some(122 | 234)) && capacity < maximum {
            capacity = capacity.saturating_mul(2).min(maximum);
            enumeration = info(file, 7, capacity);
        }
    }
    let mut result = StreamCapture {
        enumeration: enumeration.clone(),
        parse_error: None,
        streams: vec![],
    };
    if enumeration.native_error.is_some() {
        return (result, hashes);
    }
    let parsed = if resource.is_some() {
        layout::parse_streams_with_limits(
            &enumeration.bytes,
            enumeration.bytes.len(),
            evidence_limit / std::mem::size_of::<layout::Entry>(),
        )
    } else {
        layout::parse_streams(&enumeration.bytes)
    };
    let entries = match parsed {
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
        let retrieval = if resource.is_some() {
            let remaining = evidence_limit
                .saturating_sub(result.retained_bytes())
                .saturating_sub(hash_retained_bytes(&hashes));
            retrieval_queries_resource(f, remaining)
        } else {
            Ok(retrieval_queries(f))
        };
        let (first, continuation) = match retrieval {
            Ok(q) => q,
            Err(error) => {
                q.binding_error = Some(error.to_string());
                q.identity_after = Some(info(f, 18, 24));
                result.streams.push(q);
                result.parse_error = Some("native retrieval resource budget exhausted".into());
                break;
            }
        };
        q.retrieval = Some(first);
        q.retrieval_continuation = continuation;
        let wanted = r
            .extent_identity_streams
            .iter()
            .find(|wanted| wanted.identity == *id && wanted.name_utf16 == entry.name);
        let omission = wanted.and_then(|wanted| {
            extent_context.map(|context| {
                (
                    wanted,
                    context,
                    q.retrieval.as_ref().unwrap(),
                    q.retrieval_continuation.as_slice(),
                )
            })
        });
        let hash = if wanted.is_some() && extent_context.is_none() {
            StreamHash {
                name_utf16: entry.name.clone(),
                logical_size: entry.logical_size,
                identity_before: None,
                identity_after: None,
                standard_before: None,
                standard_after: None,
                outcome: crate::logical_hash::Outcome::refused(io::Error::other(
                    "extent-identity native volume context missing",
                )),
            }
        } else {
            hash_stream(f, r, id, &entry.name, entry.logical_size, budget, omission)
        };
        hashes.push(hash);
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
