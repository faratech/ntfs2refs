//! Native namespace reads, separately opened without security-query rights.
use crate::{attestation::*, namespace_layout as layout};
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx,
        OpenFileById,
    },
};

fn info(file: &File, class: i32, capacity: usize) -> Query {
    let mut storage = vec![0u64; capacity.div_ceil(8)];
    // SAFETY: owned, initialized and 8-byte-aligned output; synchronous query
    // against a borrowed live handle. Failed buffers are never parsed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            capacity as u32,
        )
    };
    let error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    let mut q = Query {
        class,
        bytes: vec![],
        native_error: error,
    };
    if error.is_none() {
        // SAFETY: initialized storage covers the requested capacity.
        q.bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast(), capacity) }.to_vec();
    }
    q
}
fn open(volume: &File, id: &FileIdentity) -> io::Result<File> {
    let d = FILE_ID_DESCRIPTOR {
        dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            FileId: id.reference() as i64,
        },
    };
    // SAFETY: initialized descriptor, live pinned volume hint. Read/list only;
    // backup semantics and OPEN_REPARSE_POINT avoid traversal through links.
    let h = unsafe { OpenFileById(volume.as_raw_handle(), &d, 0x81, 7, ptr::null(), 0x02200000) };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: transfer the newly acquired unique handle.
    Ok(unsafe { File::from_raw_handle(h) })
}
fn pass(file: &File, budget: &mut usize) -> DirectoryCapture {
    pass_with_budget(file, budget, false)
}
fn pass_with_budget(file: &File, budget: &mut usize, paged: bool) -> DirectoryCapture {
    let mut out = DirectoryCapture {
        calls: vec![],
        refusal: None,
    };
    let mut i = 0usize;
    loop {
        if !paged && i == layout::MAX_CALLS {
            out.refusal = Some("directory call budget exhausted".into());
            return out;
        }
        if !paged && *budget < layout::CAPACITY {
            out.refusal = Some("directory evidence budget exhausted".into());
            return out;
        }
        let mut q = info(
            file,
            if i == 0 {
                layout::RESTART
            } else {
                layout::CONTINUE
            },
            layout::CAPACITY,
        );
        let end = q.native_error.is_some();
        let confirm_empty = i == 0 && q.native_error == Some(layout::FIRST_EMPTY);
        if !end {
            let parsed = if paged {
                layout::parse_with_limits(
                    &q.bytes,
                    layout::CAPACITY,
                    (*budget / std::mem::size_of::<layout::Entry>()).max(1),
                )
            } else {
                layout::parse(&q.bytes)
            };
            match parsed {
                Ok((_, used)) => q.bytes.truncate(used),
                Err(e) => {
                    out.refusal = Some(e.to_string());
                    return out;
                }
            }
        }
        q.bytes.shrink_to_fit();
        let Some(remaining) = budget.checked_sub(q.bytes.len()) else {
            out.refusal = Some("directory evidence budget exhausted".into());
            return out;
        };
        *budget = remaining;
        out.calls.push(q);
        if end && !confirm_empty {
            return out;
        }
        let Some(next) = i.checked_add(1) else {
            out.refusal = Some("directory call count overflow".into());
            return out;
        };
        i = next;
    }
}
pub(crate) fn collect(volume: &File, request: &Request) -> NamespaceData {
    let mut files = vec![];
    // This in-memory sink cannot fail. Keep the historical Report interface.
    collect_rows(volume, request, false, |row| {
        files.push(row);
        Ok(())
    })
    .expect("infallible namespace sink");
    NamespaceData { files }
}
pub(crate) fn collect_rows(
    volume: &File,
    request: &Request,
    paged: bool,
    mut sink: impl FnMut(NamespaceFile) -> io::Result<()>,
) -> io::Result<()> {
    collect_rows_domain(volume, request, request, paged, None, sink)
}
pub(crate) fn collect_rows_domain(
    volume: &File,
    request: &Request,
    selectors: &impl crate::attestation::NativeRequestDomain,
    paged: bool,
    row_limit: Option<usize>,
    mut sink: impl FnMut(NamespaceFile) -> io::Result<()>,
) -> io::Result<()> {
    let mut budget = request.limits().namespace_evidence_bytes;
    for index in 0..selectors.len() {
        let id = selectors.identity(index)?;
        let mut row_budget = budget.min(row_limit.unwrap_or(budget));
        let row_start = row_budget;
        let mut out = NamespaceFile {
            identity: id.clone(),
            open_error: None,
            identity_before: None,
            identity_after: None,
            standard: None,
            before: None,
            after: None,
        };
        match open(volume, &id) {
            Err(e) => out.open_error = Some(e.raw_os_error().unwrap_or(31)),
            Ok(file) => {
                out.identity_before = Some(info(&file, 18, 24));
                let standard = info(&file, 1, 24);
                if standard.native_error.is_none() && standard.bytes[21] == 1 {
                    out.before = Some(if paged {
                        pass_with_budget(&file, &mut row_budget, true)
                    } else {
                        pass(&file, &mut row_budget)
                    });
                    out.after = Some(if paged {
                        pass_with_budget(&file, &mut row_budget, true)
                    } else {
                        pass(&file, &mut row_budget)
                    });
                }
                out.standard = Some(standard);
                out.identity_after = Some(info(&file, 18, 24));
            }
        }
        budget -= row_start - row_budget;
        sink(out)?;
    }
    Ok(())
}
