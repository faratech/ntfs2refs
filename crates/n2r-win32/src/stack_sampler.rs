//! A sampling profiler for the converter's worker thread, for laboratory runs.
//!
//! Off unless [`start`] is called. A helper thread then stops the thread that
//! last announced a phase or step a hundred times a second, records its call
//! stack and lets it continue. [`finish`] resolves the addresses to names and
//! writes one line per distinct stack:
//!
//! ```text
//! L <label id> <phase>;<step>
//! S <symbol id> <function name, or file:line>
//! K <label id> <samples> <symbol id of the innermost file:line> <symbol ids, outermost first>
//! ```
//!
//! Names come from the `.pdb` beside the executable. It only observes: nothing
//! the converter decides depends on it.

use std::path::PathBuf;

/// Starts sampling. The thread sampled is the one that next calls
/// [`note_phase`] or [`note_step`]. Does nothing where sampling is unsupported.
pub fn start(output: PathBuf) {
    imp::start(output);
}

/// The sampled thread entered a phase. Cheap when sampling is off.
pub fn note_phase(name: &str) {
    imp::note(Some(name), None);
}

/// The sampled thread entered a step of the current phase.
pub fn note_step(name: &str) {
    imp::note(None, Some(name));
}

/// Stops sampling and writes the profile. Safe to call when never started.
pub fn finish() {
    imp::finish();
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod imp {
    use std::path::PathBuf;
    pub fn start(_output: PathBuf) {}
    pub fn note(_phase: Option<&str>, _step: Option<&str>) {}
    pub fn finish() {}
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod imp {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::Relaxed};
    use std::thread::JoinHandle;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, IMAGEHLP_LINEW64, ReadProcessMemory,
        RtlLookupFunctionEntry, RtlVirtualUnwind, SYMBOL_INFOW, SYMOPT_DEFERRED_LOADS,
        SYMOPT_FAIL_CRITICAL_ERRORS, SYMOPT_IGNORE_CVREC, SYMOPT_LOAD_LINES, SYMOPT_NO_PROMPTS,
        SYMOPT_UNDNAME, SymCleanup, SymFromAddrW, SymGetLineFromAddrW64, SymInitializeW,
        SymSetOptions, UNW_FLAG_NHANDLER,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
        THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    const MAX_FRAMES: usize = 96;
    const MAX_NAME: usize = 512;
    const INTERVAL: Duration = Duration::from_millis(10);

    type Samples = HashMap<(usize, Box<[u64]>), u64>;

    struct State {
        output: PathBuf,
        labels: Vec<String>,
        phase: String,
        sampler: Option<JoinHandle<Samples>>,
    }
    static STATE: Mutex<Option<State>> = Mutex::new(None);
    static ENABLED: AtomicBool = AtomicBool::new(false);
    static STOP: AtomicBool = AtomicBool::new(false);
    static TARGET_THREAD: AtomicU32 = AtomicU32::new(0);
    static LABEL: AtomicUsize = AtomicUsize::new(0);

    pub fn start(output: PathBuf) {
        let mut state = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.is_some() {
            return;
        }
        STOP.store(false, Relaxed);
        TARGET_THREAD.store(0, Relaxed);
        LABEL.store(0, Relaxed);
        let sampler = std::thread::Builder::new()
            .name("ntfs2refs-stack-sampler".to_owned())
            .spawn(sample_until_stopped)
            .ok();
        *state = Some(State {
            output,
            labels: vec!["(before the first phase);".to_owned()],
            phase: String::new(),
            sampler,
        });
        ENABLED.store(true, Relaxed);
    }

    pub fn note(phase: Option<&str>, step: Option<&str>) {
        if !ENABLED.load(Relaxed) {
            return;
        }
        let mut state = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = state.as_mut() else { return };
        if let Some(phase) = phase {
            state.phase = phase.to_owned();
        }
        let label = format!("{};{}", state.phase, step.unwrap_or(""));
        let index = match state.labels.iter().position(|known| *known == label) {
            Some(index) => index,
            None => {
                state.labels.push(label);
                state.labels.len() - 1
            }
        };
        LABEL.store(index, Relaxed);
        // SAFETY: no preconditions; returns the calling thread's identifier.
        TARGET_THREAD.store(unsafe { GetCurrentThreadId() }, Relaxed);
    }

    pub fn finish() {
        if !ENABLED.swap(false, Relaxed) {
            return;
        }
        STOP.store(true, Relaxed);
        let state = STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(mut state) = state else { return };
        let Some(samples) = state.sampler.take().and_then(|sampler| sampler.join().ok()) else {
            eprintln!("stack samples: the sampler did not finish; no profile written");
            return;
        };
        let total: u64 = samples.values().sum();
        match write_profile(&samples, &state.labels, &state.output) {
            Ok(()) => eprintln!(
                "stack samples: {total} samples in {} distinct stacks written to {}",
                samples.len(),
                state.output.display()
            ),
            Err(error) => eprintln!("stack samples: profile not written: {error}"),
        }
    }

    // GetThreadContext requires a 16-byte aligned CONTEXT.
    #[repr(C, align(16))]
    struct AlignedContext(CONTEXT);

    fn sample_until_stopped() -> Samples {
        let mut samples = Samples::new();
        let mut handle: HANDLE = std::ptr::null_mut();
        let mut handle_thread = 0u32;
        while !STOP.load(Relaxed) {
            std::thread::sleep(INTERVAL);
            let thread = TARGET_THREAD.load(Relaxed);
            if thread == 0 {
                continue;
            }
            if thread != handle_thread {
                if !handle.is_null() {
                    // SAFETY: `handle` is a thread handle this function opened.
                    unsafe { CloseHandle(handle) };
                }
                // SAFETY: plain call; a null result is handled below.
                handle = unsafe {
                    OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        0,
                        thread,
                    )
                };
                handle_thread = thread;
            }
            if handle.is_null() {
                continue;
            }
            let mut frames = [0u64; MAX_FRAMES];
            // SAFETY: `handle` is an open handle to another thread of this
            // process with suspend and get-context access.
            let count = unsafe { capture(handle, &mut frames) };
            if count > 0 {
                let label = LABEL.load(Relaxed);
                *samples.entry((label, frames[..count].into())).or_default() += 1;
            }
        }
        if !handle.is_null() {
            // SAFETY: `handle` is a thread handle this function opened.
            unsafe { CloseHandle(handle) };
        }
        samples
    }

    /// Records the return addresses of `thread`, innermost first.
    ///
    /// Between suspend and resume this must not allocate, print or take any
    /// lock the suspended thread could hold.
    ///
    /// # Safety
    /// `thread` must be an open handle to a different thread of this process
    /// with `THREAD_SUSPEND_RESUME` and `THREAD_GET_CONTEXT` access.
    unsafe fn capture(thread: HANDLE, frames: &mut [u64; MAX_FRAMES]) -> usize {
        // SAFETY: per this function's contract.
        if unsafe { SuspendThread(thread) } == u32::MAX {
            return 0;
        }
        // SAFETY: CONTEXT is plain data for which all-zero is a valid value.
        let mut context = AlignedContext(unsafe { std::mem::zeroed() });
        context.0.ContextFlags = CONTEXT_FULL_AMD64;
        let mut count = 0;
        // SAFETY: the thread is suspended and `context` is aligned and writable.
        if unsafe { GetThreadContext(thread, &mut context.0) } != 0 {
            while count < MAX_FRAMES {
                let rip = context.0.Rip;
                if rip == 0 {
                    break;
                }
                frames[count] = rip;
                count += 1;
                let mut image_base = 0u64;
                // SAFETY: looks up static unwind data for an address; null is handled.
                let entry =
                    unsafe { RtlLookupFunctionEntry(rip, &mut image_base, std::ptr::null_mut()) };
                if entry.is_null() {
                    // A leaf function: the return address is at the stack pointer.
                    let mut value = 0u64;
                    let mut read = 0usize;
                    // SAFETY: copies eight bytes of this process's memory and
                    // fails cleanly if the address is not readable.
                    let ok = unsafe {
                        ReadProcessMemory(
                            GetCurrentProcess(),
                            context.0.Rsp as *const c_void,
                            (&mut value as *mut u64).cast(),
                            8,
                            &mut read,
                        )
                    };
                    if ok == 0 || read != 8 {
                        break;
                    }
                    context.0.Rip = value;
                    context.0.Rsp = context.0.Rsp.wrapping_add(8);
                } else {
                    let mut handler_data: *mut c_void = std::ptr::null_mut();
                    let mut establisher_frame = 0u64;
                    // SAFETY: `entry` and `image_base` describe `rip`, and the
                    // context is the suspended thread's own register state.
                    unsafe {
                        RtlVirtualUnwind(
                            UNW_FLAG_NHANDLER,
                            image_base,
                            rip,
                            entry,
                            &mut context.0,
                            &mut handler_data,
                            &mut establisher_frame,
                            std::ptr::null_mut(),
                        )
                    };
                }
            }
        }
        // SAFETY: resumes the thread suspended above.
        unsafe { ResumeThread(thread) };
        count
    }

    struct Symbols {
        process: HANDLE,
        ids: HashMap<String, usize>,
        texts: Vec<String>,
        by_address: HashMap<u64, (usize, usize)>,
    }
    impl Symbols {
        fn id(&mut self, text: String) -> usize {
            if let Some(id) = self.ids.get(&text) {
                return *id;
            }
            self.texts.push(text.clone());
            self.ids.insert(text, self.texts.len() - 1);
            self.texts.len() - 1
        }

        /// The function and the `file:line` holding `address`.
        fn resolve(&mut self, address: u64) -> (usize, usize) {
            if let Some(known) = self.by_address.get(&address) {
                return *known;
            }
            // A u64 buffer keeps SYMBOL_INFOW aligned; the name follows it.
            let mut buffer = [0u64; (std::mem::size_of::<SYMBOL_INFOW>() + 2 * MAX_NAME) / 8 + 1];
            let symbol = buffer.as_mut_ptr().cast::<SYMBOL_INFOW>();
            let mut displacement = 0u64;
            // SAFETY: `symbol` points to a zeroed, aligned buffer with room
            // for the structure and `MAX_NAME` UTF-16 units, as declared.
            let function = unsafe {
                (*symbol).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
                (*symbol).MaxNameLen = MAX_NAME as u32;
                if SymFromAddrW(self.process, address, &mut displacement, symbol) != 0 {
                    let length = ((*symbol).NameLen as usize).min(MAX_NAME - 1);
                    let name = std::ptr::addr_of!((*symbol).Name).cast::<u16>();
                    String::from_utf16_lossy(std::slice::from_raw_parts(name, length))
                } else {
                    format!("0x{address:x}")
                }
            };
            // SAFETY: IMAGEHLP_LINEW64 is plain data for which all-zero is valid.
            let mut line: IMAGEHLP_LINEW64 = unsafe { std::mem::zeroed() };
            line.SizeOfStruct = std::mem::size_of::<IMAGEHLP_LINEW64>() as u32;
            let mut line_displacement = 0u32;
            // SAFETY: `line` is initialized as the API requires; on success
            // FileName is a NUL-terminated string owned by the symbol handler.
            let place = unsafe {
                if SymGetLineFromAddrW64(self.process, address, &mut line_displacement, &mut line)
                    != 0
                    && !line.FileName.is_null()
                {
                    let mut length = 0;
                    while *line.FileName.add(length) != 0 {
                        length += 1;
                    }
                    let file = String::from_utf16_lossy(std::slice::from_raw_parts(
                        line.FileName,
                        length,
                    ));
                    let parts: Vec<&str> = file.split(['\\', '/']).collect();
                    let tail = parts[parts.len().saturating_sub(3)..].join("/");
                    format!("{tail}:{}", line.LineNumber)
                } else {
                    function.clone()
                }
            };
            let resolved = (self.id(function), self.id(place));
            self.by_address.insert(address, resolved);
            resolved
        }
    }

    fn write_profile(samples: &Samples, labels: &[String], output: &Path) -> std::io::Result<()> {
        let directory = std::env::current_exe()?
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let search: Vec<u16> = directory
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: returns a pseudo-handle; no preconditions.
        let process = unsafe { GetCurrentProcess() };
        // Symbols are looked for beside the executable only, never at the
        // build path recorded in it (which may name a volume being converted).
        // SAFETY: `search` is NUL-terminated and outlives the call.
        let initialized = unsafe {
            SymSetOptions(
                SYMOPT_UNDNAME
                    | SYMOPT_DEFERRED_LOADS
                    | SYMOPT_LOAD_LINES
                    | SYMOPT_IGNORE_CVREC
                    | SYMOPT_FAIL_CRITICAL_ERRORS
                    | SYMOPT_NO_PROMPTS,
            );
            SymInitializeW(process, search.as_ptr(), 1)
        };
        if initialized == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut symbols = Symbols {
            process,
            ids: HashMap::new(),
            texts: Vec::new(),
            by_address: HashMap::new(),
        };
        // Stacks that differ only in addresses inside the same functions merge.
        let mut merged: HashMap<(usize, usize, Vec<usize>), u64> = HashMap::new();
        for ((label, frames), count) in samples {
            let mut functions = Vec::with_capacity(frames.len());
            let mut innermost_place = 0;
            for (depth, address) in frames.iter().enumerate() {
                // Every frame but the innermost holds a return address, which
                // can lie just past the end of the calling function.
                let (function, place) =
                    symbols.resolve(if depth == 0 { *address } else { address - 1 });
                if depth == 0 {
                    innermost_place = place;
                }
                functions.push(function);
            }
            functions.reverse();
            *merged.entry((*label, innermost_place, functions)).or_default() += count;
        }
        // SAFETY: releases the symbol handler initialized above.
        unsafe { SymCleanup(process) };
        let mut file = std::io::BufWriter::new(std::fs::File::create(output)?);
        writeln!(
            file,
            "# ntfs2refs stack samples, one every {} ms of the worker thread",
            INTERVAL.as_millis()
        )?;
        for (id, label) in labels.iter().enumerate() {
            writeln!(file, "L {id} {label}")?;
        }
        for (id, text) in symbols.texts.iter().enumerate() {
            writeln!(file, "S {id} {text}")?;
        }
        for ((label, place, functions), count) in &merged {
            write!(file, "K {label} {count} {place}")?;
            for function in functions {
                write!(file, " {function}")?;
            }
            writeln!(file)?;
        }
        file.flush()
    }

    #[cfg(test)]
    mod tests {
        use std::time::{Duration, Instant};

        #[test]
        fn a_busy_thread_is_sampled_and_its_frames_are_named() {
            let directory = tempfile::tempdir().unwrap();
            let output = directory.path().join("stacks.txt");
            super::start(output.clone());
            super::note(Some("sampler-test"), None);
            let started = Instant::now();
            let mut value = 1u64;
            while started.elapsed() < Duration::from_millis(500) {
                value = std::hint::black_box(value.wrapping_mul(31).wrapping_add(7));
            }
            super::finish();
            let text = std::fs::read_to_string(&output).unwrap();
            assert!(text.lines().any(|line| line.starts_with("K ")), "{text}");
            assert!(text.contains("sampler-test;"), "{text}");
            assert!(text.contains("a_busy_thread_is_sampled"), "{text}");
        }
    }
}
