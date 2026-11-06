//! Documented in-memory registry reader. No active-registry or save/set API.
//! Caller authenticates the DLL's sealed RAM origin and both input files.
use std::{ffi::c_void, fs::File, io, path::Path, ptr};

type Handle = *mut c_void;
type OpenHive = unsafe extern "system" fn(*const u16, *mut Handle) -> u32;
type GetValue = unsafe extern "system" fn(
    Handle, *const u16, *const u16, *mut u32, *mut c_void, *mut u32,
) -> u32;
type CloseHive = unsafe extern "system" fn(Handle) -> u32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(path: *const u16, reserved: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;
    fn FreeLibrary(module: Handle) -> i32;
}
fn wide(value: &str) -> Vec<u16> { value.encode_utf16().chain([0]).collect() }
fn invalid(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn status(value: u32) -> io::Result<()> {
    if value == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(value as i32)) }
}

/// Owns only the read/query/close exports and the caller's real readonly DLL
/// FileObject. This type cannot be cloned/deserialized or grant source rights.
pub(super) struct OfflineRegistry {
    module: Handle,
    open: OpenHive,
    get: GetValue,
    close: CloseHive,
    file: File,
}
impl OfflineRegistry {
    /// The caller has already proved that path names THIS held readonly DLL,
    /// that its entire SHA matches the sealed image dependency, and that its
    /// native backing is the actual current kernel RAM device.
    pub(super) fn load(path: &Path, held_readonly_library: File) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("explicit absolute authenticated OFFREG path required"));
        }
        crate::file_storage::require_readonly_access(&held_readonly_library)?;
        if !held_readonly_library.metadata()?.is_file() {
            return Err(invalid("held OFFREG dependency is not an ordinary file"));
        }
        let path = path.to_str().ok_or_else(|| invalid("Unicode authenticated OFFREG path required"))?;
        // Search dependencies only alongside this explicit DLL and in the
        // actual System32; never the current directory or ambient PATH.
        // SAFETY: terminated input, no reserved handle, synchronous loader.
        let module = unsafe { LoadLibraryExW(wide(path).as_ptr(), ptr::null_mut(), 0x900) };
        if module.is_null() { return Err(io::Error::last_os_error()); }
        // SAFETY: the module remains loaded throughout export lookup and use;
        // all names are fixed NUL-terminated documented exports.
        let (open, get, close) = unsafe {
            (
                GetProcAddress(module, b"OROpenHive\0".as_ptr()),
                GetProcAddress(module, b"ORGetValue\0".as_ptr()),
                GetProcAddress(module, b"ORCloseHive\0".as_ptr()),
            )
        };
        if open.is_null() || get.is_null() || close.is_null() {
            // SAFETY: this uniquely owned module has not escaped.
            unsafe { FreeLibrary(module); }
            return Err(invalid("authenticated OFFREG lacks required readonly exports"));
        }
        // SAFETY: these are the three exact documented OFFREG ABIs on Windows.
        // No save, set, create, delete, mount or active-registry export is kept.
        Ok(Self {
            module,
            open: unsafe { std::mem::transmute::<*const c_void, OpenHive>(open) },
            get: unsafe { std::mem::transmute::<*const c_void, GetValue>(get) },
            close: unsafe { std::mem::transmute::<*const c_void, CloseHive>(close) },
            file: held_readonly_library,
        })
    }
    pub(super) fn held_file(&self) -> &File { &self.file }

    /// The caller retains the exact authenticated readonly input FileObject
    /// and performs its complete identity/length/hash bookends. OROpenHive
    /// validates and reads the file into memory; ORSaveHive is never resolved.
    pub(super) fn read_device(&self, path: &Path, maximum: u32) -> io::Result<Vec<u8>> {
        if maximum == 0 || !path.is_absolute() {
            return Err(invalid("bounded absolute readonly BCD input required"));
        }
        let path = path.to_str().ok_or_else(|| invalid("Unicode readonly BCD input required"))?;
        let mut root = ptr::null_mut();
        // SAFETY: a live pinned library, terminated path, and writable output.
        status(unsafe { (self.open)(wide(path).as_ptr(), &mut root) })?;
        if root.is_null() { return Err(invalid("OFFREG returned a null hive after success")); }
        let hive = OfflineHive { root, library: self };
        let result = (|| {
            let key = wide(r"Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\11000001");
            let name = wide("Element");
            let (mut kind, mut length) = (0u32, 0u32);
            // SAFETY: query only the type/size under the live private memory hive.
            status(unsafe {
                (self.get)(hive.root, key.as_ptr(), name.as_ptr(),
                    &mut kind, ptr::null_mut(), &mut length)
            })?;
            if kind != 3 || length == 0 || length > maximum {
                return Err(invalid("OFFREG device element exceeds admitted REG_BINARY workspace"));
            }
            let expected = length;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length as usize).map_err(io::Error::other)?;
            bytes.resize(length as usize, 0);
            // SAFETY: complete initialized output of the just-observed length.
            status(unsafe {
                (self.get)(hive.root, key.as_ptr(), name.as_ptr(),
                    &mut kind, bytes.as_mut_ptr().cast(), &mut length)
            })?;
            if kind != 3 || length != expected {
                return Err(invalid("OFFREG device element changed size/type during query"));
            }
            Ok(bytes)
        })();
        let closed = hive.close();
        match (result, closed) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}
impl Drop for OfflineRegistry {
    fn drop(&mut self) {
        // SAFETY: no memory-hive owner can outlive its borrowed library.
        // Unload code before Rust releases the retained readonly DLL FileObject.
        unsafe { FreeLibrary(self.module); }
    }
}
struct OfflineHive<'a> { root: Handle, library: &'a OfflineRegistry }
impl OfflineHive<'_> {
    fn close(mut self) -> io::Result<()> {
        // SAFETY: this live root uniquely owns the documented memory hive.
        let result = status(unsafe { (self.library.close)(self.root) });
        self.root = ptr::null_mut();
        result
    }
}
impl Drop for OfflineHive<'_> {
    fn drop(&mut self) {
        if !self.root.is_null() {
            // SAFETY: failure paths still close the unique memory-hive root.
            unsafe { (self.library.close)(self.root); }
        }
    }
}
