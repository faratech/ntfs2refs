//! Documented in-memory registry reader. No active-registry or save/set API.
//! Caller authenticates the DLL's sealed RAM origin and both input files.
use std::{collections::BTreeMap, ffi::c_void, fs::File, io, path::Path, ptr};
use windows_sys::Win32::Foundation::FILETIME;

type Handle = *mut c_void;
type OpenHive = unsafe extern "system" fn(*const u16, *mut Handle) -> u32;
type GetValue = unsafe extern "system" fn(
    Handle,
    *const u16,
    *const u16,
    *mut u32,
    *mut c_void,
    *mut u32,
) -> u32;
type CloseHive = unsafe extern "system" fn(Handle) -> u32;
type OpenKey = unsafe extern "system" fn(Handle, *const u16, *mut Handle) -> u32;
type EnumKey = unsafe extern "system" fn(
    Handle,
    u32,
    *mut u16,
    *mut u32,
    *mut u16,
    *mut u32,
    *mut FILETIME,
) -> u32;
type CloseKey = unsafe extern "system" fn(Handle) -> u32;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct OfflineBcdObject {
    pub(super) object_type: u32,
    pub(super) elements: BTreeMap<u32, OfflineBcdElement>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct OfflineBcdElement {
    pub(super) registry_type: u32,
    pub(super) bytes: Vec<u8>,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(path: *const u16, reserved: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;
    fn FreeLibrary(module: Handle) -> i32;
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn status(value: u32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(value as i32))
    }
}

/// Owns only the read/query/close exports and the caller's real readonly DLL
/// FileObject. This type cannot be cloned/deserialized or grant source rights.
pub(super) struct OfflineRegistry {
    module: Handle,
    open: OpenHive,
    get: GetValue,
    close: CloseHive,
    open_key: OpenKey,
    enum_key: EnumKey,
    close_key: CloseKey,
    file: File,
}
impl OfflineRegistry {
    /// The caller has already proved that path names THIS held readonly DLL,
    /// that its entire SHA matches the sealed image dependency, and that its
    /// native backing is the actual current kernel RAM device.
    pub(super) fn load(path: &Path, held_readonly_library: File) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid(
                "explicit absolute authenticated OFFREG path required",
            ));
        }
        crate::file_storage::require_readonly_access(&held_readonly_library)?;
        if !held_readonly_library.metadata()?.is_file() {
            return Err(invalid("held OFFREG dependency is not an ordinary file"));
        }
        let path = path
            .to_str()
            .ok_or_else(|| invalid("Unicode authenticated OFFREG path required"))?;
        // Search dependencies only alongside this explicit DLL and in the
        // actual System32; never the current directory or ambient PATH.
        // SAFETY: terminated input, no reserved handle, synchronous loader.
        let module = unsafe { LoadLibraryExW(wide(path).as_ptr(), ptr::null_mut(), 0x900) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the module remains loaded throughout export lookup and use;
        // all names are fixed NUL-terminated documented exports.
        let (open, get, close, open_key, enum_key, close_key) = unsafe {
            (
                GetProcAddress(module, b"OROpenHive\0".as_ptr()),
                GetProcAddress(module, b"ORGetValue\0".as_ptr()),
                GetProcAddress(module, b"ORCloseHive\0".as_ptr()),
                GetProcAddress(module, b"OROpenKey\0".as_ptr()),
                GetProcAddress(module, b"OREnumKey\0".as_ptr()),
                GetProcAddress(module, b"ORCloseKey\0".as_ptr()),
            )
        };
        if open.is_null()
            || get.is_null()
            || close.is_null()
            || open_key.is_null()
            || enum_key.is_null()
            || close_key.is_null()
        {
            // SAFETY: this uniquely owned module has not escaped.
            unsafe {
                FreeLibrary(module);
            }
            return Err(invalid(
                "authenticated OFFREG lacks required readonly exports",
            ));
        }
        // SAFETY: these are the exact documented OFFREG ABIs on Windows.
        // No save, set, create, delete, mount or active-registry export is kept.
        Ok(Self {
            module,
            open: unsafe { std::mem::transmute::<*const c_void, OpenHive>(open) },
            get: unsafe { std::mem::transmute::<*const c_void, GetValue>(get) },
            close: unsafe { std::mem::transmute::<*const c_void, CloseHive>(close) },
            open_key: unsafe { std::mem::transmute::<*const c_void, OpenKey>(open_key) },
            enum_key: unsafe { std::mem::transmute::<*const c_void, EnumKey>(enum_key) },
            close_key: unsafe { std::mem::transmute::<*const c_void, CloseKey>(close_key) },
            file: held_readonly_library,
        })
    }
    pub(super) fn held_file(&self) -> &File {
        &self.file
    }

    fn subkey(&self, parent: Handle, name: &[u16]) -> io::Result<OfflineKey<'_>> {
        if name.len() < 2 || name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
            return Err(invalid("exact terminated nonempty OFFREG subkey required"));
        }
        let mut handle = ptr::null_mut();
        // SAFETY: live memory hive/key, complete terminated name and output.
        status(unsafe { (self.open_key)(parent, name.as_ptr(), &mut handle) })?;
        if handle.is_null() {
            return Err(invalid("OFFREG returned a null subkey after success"));
        }
        Ok(OfflineKey {
            handle,
            library: self,
        })
    }

    fn enum_name(&self, key: Handle, index: u32) -> io::Result<Option<([u16; 32], usize)>> {
        let mut name = [u16::MAX; 32];
        let mut length = name.len() as u32;
        // https://learn.microsoft.com/en-us/windows/win32/devnotes/orenumkey
        // SAFETY: exact initialized WCHAR buffer; class and FILETIME are optional.
        let result = unsafe {
            (self.enum_key)(
                key,
                index,
                name.as_mut_ptr(),
                &mut length,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if result == 259 {
            return Ok(None);
        }
        status(result)?; // Includes ERROR_MORE_DATA: oversized names fail closed.
        let length = usize::try_from(length).map_err(io::Error::other)?;
        if length == 0 || length >= name.len() || name[length] != 0 || name[..length].contains(&0) {
            return Err(invalid("OFFREG subkey name is incomplete or unterminated"));
        }
        Ok(Some((name, length)))
    }

    /// Complete bounded object observation in a private in-memory hive. The
    /// caller owns raw-file/native-identity/SHA bookends and sealed-map policy.
    pub(super) fn read_object(
        &self,
        path: &Path,
        object_guid: &str,
        max_value_bytes: u32,
        max_total_bytes: u64,
        max_elements: u32,
    ) -> io::Result<OfflineBcdObject> {
        // Charge fixed observation storage plus a deliberately conservative
        // BTree node/Vec/allocator allowance before every entry allocation.
        const OBJECT_HEAP_CHARGE: u64 = 256;
        const ENTRY_HEAP_CHARGE: u64 = 1024;
        if max_value_bytes == 0
            || max_elements == 0
            || max_total_bytes < OBJECT_HEAP_CHARGE + 4
            || !path.is_absolute()
            || super::canonical_guid(object_guid)? != object_guid
        {
            return Err(invalid(
                "canonical object GUID and explicit bounded BCD workspace required",
            ));
        }
        let path = path
            .to_str()
            .ok_or_else(|| invalid("Unicode readonly BCD input required"))?;
        if path.contains('\0') {
            return Err(invalid("embedded NUL in readonly BCD input"));
        }
        let units = path.encode_utf16().count();
        if units > 32767 {
            return Err(invalid(
                "readonly BCD path exceeds native bounded path size",
            ));
        }
        let mut path_wide = Vec::new();
        path_wide
            .try_reserve_exact(units + 1)
            .map_err(io::Error::other)?;
        path_wide.extend(path.encode_utf16());
        path_wide.push(0);
        let mut root = ptr::null_mut();
        // SAFETY: readonly parser, complete terminated path and hive output.
        status(unsafe { (self.open)(path_wide.as_ptr(), &mut root) })?;
        if root.is_null() {
            return Err(invalid("OFFREG returned a null hive after success"));
        }
        let hive = OfflineHive {
            root,
            library: self,
        };
        let result = (|| {
            let object = self.subkey(hive.root, &wide(&format!("Objects\\{object_guid}")))?;
            let mut description_seen = false;
            let mut elements_seen = false;
            let mut ordinal = 0;
            while let Some((name, length)) = self.enum_name(object.handle, ordinal)? {
                let matches = |expected: &str| {
                    name[..length]
                        .iter()
                        .zip(expected.bytes())
                        .all(|(unit, byte)| {
                            *unit <= 127 && (*unit as u8).eq_ignore_ascii_case(&byte)
                        })
                        && length == expected.len()
                };
                if matches("Description") && !description_seen {
                    description_seen = true;
                } else if matches("Elements") && !elements_seen {
                    elements_seen = true;
                } else {
                    return Err(invalid("BCD object has duplicate or untracked child keys"));
                }
                ordinal += 1;
            }
            if !description_seen || !elements_seen {
                return Err(invalid(
                    "complete BCD Description and Elements keys required",
                ));
            }
            let description = self.subkey(object.handle, &wide("Description"))?;
            if self.enum_name(description.handle, 0)?.is_some() {
                return Err(invalid("BCD Description contains untracked child keys"));
            }
            let mut object_type = [0u8; 4];
            let (mut kind, mut length) = (0u32, 4u32);
            // SAFETY: exact DWORD-sized output under the live Description key.
            status(unsafe {
                (self.get)(
                    description.handle,
                    ptr::null(),
                    wide("Type").as_ptr(),
                    &mut kind,
                    object_type.as_mut_ptr().cast(),
                    &mut length,
                )
            })?;
            if kind != 4 || length != 4 {
                return Err(invalid("BCD Description Type must be exact REG_DWORD4"));
            }
            description.close()?;
            let elements_key = self.subkey(object.handle, &wide("Elements"))?;
            let mut elements = BTreeMap::new();
            let mut used = OBJECT_HEAP_CHARGE + 4;
            let mut index = 0u32;
            while let Some((name, length)) = self.enum_name(elements_key.handle, index)? {
                if index >= max_elements || length != 8 {
                    return Err(invalid(
                        "BCD element count or exact eight-hex name bound exceeded",
                    ));
                }
                let mut element_type = 0u32;
                for unit in &name[..8] {
                    let digit = match *unit {
                        0x30..=0x39 => u32::from(*unit - 0x30),
                        0x61..=0x66 => u32::from(*unit - 0x61 + 10),
                        0x41..=0x46 => u32::from(*unit - 0x41 + 10),
                        _ => {
                            return Err(invalid(
                                "BCD element name is not exactly ASCII hexadecimal",
                            ));
                        }
                    };
                    element_type = (element_type << 4) | digit;
                }
                if elements.contains_key(&element_type) {
                    return Err(invalid("duplicate BCD element type"));
                }
                let element = self.subkey(elements_key.handle, &name[..9])?;
                if self.enum_name(element.handle, 0)?.is_some() {
                    return Err(invalid("BCD Element contains untracked child keys"));
                }
                let (mut kind, mut length) = (0u32, 0u32);
                // SAFETY: size/type query only under the exact element key.
                status(unsafe {
                    (self.get)(
                        element.handle,
                        ptr::null(),
                        wide("Element").as_ptr(),
                        &mut kind,
                        ptr::null_mut(),
                        &mut length,
                    )
                })?;
                if length > max_value_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "BCD Element exceeds admitted raw value workspace: element=0x{element_type:08x}, type={kind}, bytes={length}, maximum={max_value_bytes}"
                        ),
                    ));
                }
                used = used
                    .checked_add(ENTRY_HEAP_CHARGE)
                    .and_then(|n| n.checked_add(u64::from(length)))
                    .ok_or_else(|| invalid("BCD object workspace accounting overflow"))?;
                if used > max_total_bytes {
                    return Err(invalid(
                        "complete BCD object exceeds admitted heap/data workspace",
                    ));
                }
                let expected = length;
                let registry_type = kind;
                let mut bytes = Vec::new();
                let count = usize::try_from(length).map_err(io::Error::other)?;
                bytes.try_reserve_exact(count).map_err(io::Error::other)?;
                bytes.resize(count, 0);
                // SAFETY: initialized complete bounded output (null for zero bytes).
                status(unsafe {
                    (self.get)(
                        element.handle,
                        ptr::null(),
                        wide("Element").as_ptr(),
                        &mut kind,
                        if bytes.is_empty() {
                            ptr::null_mut()
                        } else {
                            bytes.as_mut_ptr().cast()
                        },
                        &mut length,
                    )
                })?;
                if kind != registry_type || length != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "BCD Element changed size/type during complete query: element=0x{element_type:08x}, type={kind}, expected_type={registry_type}, bytes={length}, expected_bytes={expected}, maximum={max_value_bytes}"
                        ),
                    ));
                }
                element.close()?;
                // Preserve the native type and exact bytes. String/GUID/list
                // semantics belong to the caller; no registry data is coerced.
                elements.insert(
                    element_type,
                    OfflineBcdElement {
                        registry_type,
                        bytes,
                    },
                );
                index = index
                    .checked_add(1)
                    .ok_or_else(|| invalid("BCD element enumeration index overflow"))?;
            }
            elements_key.close()?;
            object.close()?;
            Ok(OfflineBcdObject {
                object_type: u32::from_le_bytes(object_type),
                elements,
            })
        })();
        let closed = hive.close();
        match (result, closed) {
            (Ok(object), Ok(())) => Ok(object),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    /// The caller retains the exact authenticated readonly input FileObject
    /// and performs its complete identity/length/hash bookends. OROpenHive
    /// validates and reads the file into memory; ORSaveHive is never resolved.
    pub(super) fn read_device(&self, path: &Path, maximum: u32) -> io::Result<Vec<u8>> {
        if maximum == 0 || !path.is_absolute() {
            return Err(invalid("bounded absolute readonly BCD input required"));
        }
        let path = path
            .to_str()
            .ok_or_else(|| invalid("Unicode readonly BCD input required"))?;
        let mut root = ptr::null_mut();
        // SAFETY: a live pinned library, terminated path, and writable output.
        status(unsafe { (self.open)(wide(path).as_ptr(), &mut root) })?;
        if root.is_null() {
            return Err(invalid("OFFREG returned a null hive after success"));
        }
        let hive = OfflineHive {
            root,
            library: self,
        };
        let result = (|| {
            let key = wide(r"Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\11000001");
            let name = wide("Element");
            let (mut kind, mut length) = (0u32, 0u32);
            // SAFETY: query only the type/size under the live private memory hive.
            status(unsafe {
                (self.get)(
                    hive.root,
                    key.as_ptr(),
                    name.as_ptr(),
                    &mut kind,
                    ptr::null_mut(),
                    &mut length,
                )
            })?;
            if kind != 3 || length == 0 || length > maximum {
                return Err(invalid(
                    "OFFREG device element exceeds admitted REG_BINARY workspace",
                ));
            }
            let expected = length;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length as usize)
                .map_err(io::Error::other)?;
            bytes.resize(length as usize, 0);
            // SAFETY: complete initialized output of the just-observed length.
            status(unsafe {
                (self.get)(
                    hive.root,
                    key.as_ptr(),
                    name.as_ptr(),
                    &mut kind,
                    bytes.as_mut_ptr().cast(),
                    &mut length,
                )
            })?;
            if kind != 3 || length != expected {
                return Err(invalid(
                    "OFFREG device element changed size/type during query",
                ));
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
        unsafe {
            FreeLibrary(self.module);
        }
    }
}
struct OfflineKey<'a> {
    handle: Handle,
    library: &'a OfflineRegistry,
}
impl OfflineKey<'_> {
    fn close(mut self) -> io::Result<()> {
        // https://learn.microsoft.com/en-us/windows/win32/devnotes/orclosekey
        // SAFETY: unique non-root key; close before its memory hive/library.
        let result = status(unsafe { (self.library.close_key)(self.handle) });
        self.handle = ptr::null_mut();
        result
    }
}
impl Drop for OfflineKey<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: early-return paths release the unique borrowed-library key.
            unsafe {
                (self.library.close_key)(self.handle);
            }
        }
    }
}
struct OfflineHive<'a> {
    root: Handle,
    library: &'a OfflineRegistry,
}
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
            unsafe {
                (self.library.close)(self.root);
            }
        }
    }
}
