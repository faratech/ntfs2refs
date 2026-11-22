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
    match info_measured(file, class, capacity, |response| Ok(response.len())) {
        Ok(query) => query,
        Err(_) => unreachable!("a whole response has a length"),
    }
}
/// One query answered into this thread's query buffer. `measure` says how
/// many of the bytes are the answer, and those are copied out; when it
/// refuses the answer, its refusal is returned and nothing is copied.
fn info_measured(
    file: &File,
    class: i32,
    capacity: usize,
    measure: impl FnOnce(&[u8]) -> io::Result<usize>,
) -> io::Result<Query> {
    crate::query_scratch::with(capacity, |response| {
        // SAFETY: initialized and 8-byte-aligned output of the stated
        // capacity; synchronous query against a borrowed live handle. Failed
        // buffers are never parsed.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                response.as_mut_ptr().cast(),
                capacity as u32,
            )
        };
        let error = (ok == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
        let bytes = if error.is_none() {
            let used = measure(response)?.min(capacity);
            response[..used].to_vec()
        } else {
            vec![]
        };
        Ok(Query {
            class,
            bytes,
            native_error: error,
        })
    })
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
        // The page is parsed where Windows wrote it and only its entries
        // are copied out, not the 64 KiB they were written into.
        let entries = *budget / std::mem::size_of::<layout::Entry>();
        let q = match info_measured(
            file,
            if i == 0 {
                layout::RESTART
            } else {
                layout::CONTINUE
            },
            layout::CAPACITY,
            |page| {
                let parsed = if paged {
                    layout::parse_with_limits(page, layout::CAPACITY, entries.max(1))
                } else {
                    layout::parse(page)
                };
                parsed.map(|(_, used)| used)
            },
        ) {
            Ok(q) => q,
            Err(e) => {
                out.refusal = Some(e.to_string());
                return out;
            }
        };
        let end = q.native_error.is_some();
        let confirm_empty = i == 0 && q.native_error == Some(layout::FIRST_EMPTY);
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
    sink: impl FnMut(NamespaceFile) -> io::Result<()>,
) -> io::Result<()> {
    collect_rows_domain_with_helpers(
        volume,
        request,
        selectors,
        paged,
        row_limit,
        None,
        Vec::new(),
        sink,
    )
}

/// One object's namespace row as Windows shows it, its directory listed
/// twice, with `row_budget` bytes of listing evidence. Returns the row and
/// the evidence bytes it used. The same object observed with the same budget
/// on any thread is the same row: nothing here depends on other objects.
fn observe_object(
    volume: &File,
    id: &FileIdentity,
    paged: bool,
    row_budget: usize,
) -> (NamespaceFile, usize) {
    let mut remaining = row_budget;
    let mut out = NamespaceFile {
        identity: id.clone(),
        open_error: None,
        identity_before: None,
        identity_after: None,
        standard: None,
        before: None,
        after: None,
    };
    match open(volume, id) {
        Err(e) => out.open_error = Some(e.raw_os_error().unwrap_or(31)),
        Ok(file) => {
            out.identity_before = Some(info(&file, 18, 24));
            let standard = info(&file, 1, 24);
            if standard.native_error.is_none() && standard.bytes[21] == 1 {
                let first = if paged {
                    pass_with_budget(&file, &mut remaining, true)
                } else {
                    pass(&file, &mut remaining)
                };
                out.after = Some(if crate::verify_policy::checks_once() {
                    first.clone()
                } else if paged {
                    pass_with_budget(&file, &mut remaining, true)
                } else {
                    pass(&file, &mut remaining)
                });
                out.before = Some(first);
            }
            out.standard = Some(standard);
            out.identity_after = if crate::verify_policy::checks_once() {
                out.identity_before.clone()
            } else {
                Some(info(&file, 18, 24))
            };
        }
    }
    (out, row_budget - remaining)
}

/// The memory a namespace row holds until it is taken.
fn held_bytes(row: &NamespaceFile) -> u64 {
    let mut bytes = std::mem::size_of::<NamespaceFile>();
    for q in [&row.identity_before, &row.identity_after, &row.standard]
        .into_iter()
        .flatten()
    {
        bytes = bytes.saturating_add(q.bytes.capacity());
    }
    for capture in [&row.before, &row.after].into_iter().flatten() {
        bytes = bytes
            .saturating_add(
                capture
                    .calls
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Query>()),
            )
            .saturating_add(capture.refusal.as_ref().map_or(0, String::capacity));
        for q in &capture.calls {
            bytes = bytes.saturating_add(q.bytes.capacity());
        }
    }
    bytes as u64
}

/// An object gathered for the namespace pass: its identity, the listing
/// evidence it may hold if taken after the objects gathered before it, and
/// whether a helper lists it ahead of its turn.
struct Gathered {
    id: FileIdentity,
    row_budget: usize,
    ahead: bool,
}
/// What a helper saw of one object and the memory it is held with.
struct Listed {
    row: NamespaceFile,
    used: usize,
    _paid: Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>,
}

/// [`collect_rows_domain`], with objects observed ahead of their turn on
/// helper threads where `payer` pays for each result as spare memory and
/// `workspaces` (one per helper, paid by the caller) number two or more.
/// Objects are still gathered, counted against the run's listing budget and
/// handed to `sink` one after another, in order: an object is listed ahead
/// only while the row limit, not the run's remaining total, bounds its
/// evidence, and a helper's row is used only where taking the object in its
/// turn gives it that same budget. Otherwise (or where its result could not
/// be paid for) the object is observed again in its turn, as without helpers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_rows_domain_with_helpers(
    volume: &File,
    request: &Request,
    selectors: &impl crate::attestation::NativeRequestDomain,
    paged: bool,
    row_limit: Option<usize>,
    payer: Option<&std::sync::Arc<dyn crate::shadow_native::report_memory::ReportMemoryAccountant>>,
    mut workspaces: Vec<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
    mut sink: impl FnMut(NamespaceFile) -> io::Result<()>,
) -> io::Result<()> {
    struct Pass<'w, S> {
        budget: usize,
        sink: S,
        workspaces: &'w mut Vec<Box<dyn crate::shadow_native::report_memory::ReportMemoryLease>>,
    }
    let payer = payer.filter(|_| workspaces.len() >= 2);
    let helpers = if payer.is_some() { workspaces.len() } else { 0 };
    let mut pass = Pass {
        budget: request.limits().namespace_evidence_bytes,
        sink: &mut sink,
        workspaces: &mut workspaces,
    };
    let budget_for = |budget: usize| budget.min(row_limit.unwrap_or(budget));
    crate::ordered_observation::in_order(
        selectors.len(),
        helpers,
        crate::perf::Point::SourceNamespace,
        &mut pass,
        |pass, index, _| {
            let id = selectors.identity(index)?;
            let row_budget = budget_for(pass.budget);
            // Where the run's remaining total bounds the row, every object
            // taken before it changes it: such an object waits for its turn.
            let ahead =
                !pass.workspaces.is_empty() && row_limit.is_some_and(|limit| row_budget == limit);
            Ok(Some(Gathered {
                id,
                row_budget,
                ahead,
            }))
        },
        |gathered| {
            let payer = payer.filter(|_| gathered.ahead)?;
            let (row, used) = observe_object(volume, &gathered.id, paged, gathered.row_budget);
            let paid = payer.reserve_spare(held_bytes(&row)).ok()?;
            Some(Listed {
                row,
                used,
                _paid: paid,
            })
        },
        |pass, _, gathered, listed| {
            let row_budget = budget_for(pass.budget);
            let (row, used) = match listed.filter(|_| gathered.row_budget == row_budget) {
                Some(listed) => (listed.row, listed.used),
                None => {
                    let _in_turn =
                        (helpers >= 2).then(|| crate::perf::scope(crate::perf::Point::InTurn));
                    observe_object(volume, &gathered.id, paged, row_budget)
                }
            };
            pass.budget -= used;
            (pass.sink)(row)
        },
        |pass| pass.workspaces.clear(),
    )
}
