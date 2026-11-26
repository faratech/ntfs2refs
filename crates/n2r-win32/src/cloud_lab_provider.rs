//! A minimal Cloud Files API provider, for the laboratory only.
//!
//! It registers a sync root on a folder, makes a placeholder there for
//! every file and folder of a backing folder (on another volume), and,
//! while it is connected, serves each placeholder's data from the backing
//! file of the same relative path. With it the lab makes placeholders that
//! are fully present, partly present, not present and pinned, and runs a
//! conversion with the provider running or stopped. Nothing of the
//! converter uses it.
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use windows_sys::Win32::Storage::CloudFilters::{
    CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS, CF_CALLBACK_REGISTRATION,
    CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE, CF_CONNECT_FLAG_NONE, CF_CREATE_FLAG_NONE,
    CF_DEHYDRATE_FLAG_NONE, CF_FS_METADATA, CF_HARDLINK_POLICY_NONE, CF_HYDRATE_FLAG_NONE,
    CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_MODIFIER_NONE, CF_HYDRATION_POLICY_PARTIAL,
    CF_INSYNC_POLICY_NONE, CF_OPERATION_INFO, CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0,
    CF_OPERATION_PARAMETERS_0_0, CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
    CF_OPERATION_TYPE_TRANSFER_DATA, CF_PIN_STATE_PINNED,
    CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION,
    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, CF_PLACEHOLDER_CREATE_INFO,
    CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_POPULATION_POLICY,
    CF_POPULATION_POLICY_ALWAYS_FULL, CF_POPULATION_POLICY_MODIFIER_NONE, CF_PROVIDER_STATUS_IDLE,
    CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT, CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT,
    CF_SET_PIN_FLAG_NONE, CF_SYNC_POLICIES, CF_SYNC_REGISTRATION, CfConnectSyncRoot,
    CfCreatePlaceholders, CfDehydratePlaceholder, CfDisconnectSyncRoot, CfExecute,
    CfHydratePlaceholder, CfRegisterSyncRoot, CfSetPinState, CfUnregisterSyncRoot,
    CfUpdateSyncProviderStatus,
};
use windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO;

/// The name the provider registers.
pub const PROVIDER_NAME: &str = "ntfs2refs lab provider";
/// What it reads at most in one transfer.
const CHUNK: usize = 1 << 20;
/// STATUS_UNSUCCESSFUL, for a transfer that cannot be served.
const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32 as i32;

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn hresult(what: &str, code: i32) -> io::Error {
    io::Error::other(format!(
        "{what}: {}",
        crate::cloud_native::describe_error(code)
    ))
}

/// Registers `root` (an existing, empty folder) as a sync root of this
/// provider: data is fetched on demand and may be partly present, and
/// every folder is listed in full when it is made.
pub fn register(root: &Path) -> io::Result<()> {
    let name = wide(PROVIDER_NAME.as_ref());
    let version = wide("1".as_ref());
    let identity = b"ntfs2refs-lab";
    let registration = CF_SYNC_REGISTRATION {
        StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: name.as_ptr(),
        ProviderVersion: version.as_ptr(),
        SyncRootIdentity: identity.as_ptr().cast(),
        SyncRootIdentityLength: identity.len() as u32,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        // {6e2b5d0a-6b5f-4d37-9c1a-2e3b4f5a6b7c}
        ProviderId: windows_sys::core::GUID::from_u128(0x6e2b5d0a_6b5f_4d37_9c1a_2e3b4f5a6b7c),
    };
    let policies = CF_SYNC_POLICIES {
        StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_PARTIAL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_ALWAYS_FULL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_NONE,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };
    let path = wide(root.as_os_str());
    // SAFETY: terminated strings and complete structures that outlive the call.
    let result = unsafe {
        CfRegisterSyncRoot(
            path.as_ptr(),
            &registration,
            &policies,
            CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT
                | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT,
        )
    };
    if result < 0 {
        return Err(hresult(&format!("registering {}", root.display()), result));
    }
    Ok(())
}

/// Removes the sync root registration of `root`.
pub fn unregister(root: &Path) -> io::Result<()> {
    let path = wide(root.as_os_str());
    // SAFETY: a terminated string.
    let result = unsafe { CfUnregisterSyncRoot(path.as_ptr()) };
    if result < 0 {
        return Err(hresult(
            &format!("unregistering {}", root.display()),
            result,
        ));
    }
    Ok(())
}

/// Makes, under `root`, a placeholder for each file and folder under
/// `backing`, none of it present, each identified by its relative path.
/// How many it made.
pub fn create_placeholders(root: &Path, backing: &Path) -> io::Result<usize> {
    create_in(root, backing, Path::new(""))
}

fn create_in(root: &Path, backing: &Path, relative: &Path) -> io::Result<usize> {
    let mut made = 0;
    let mut entries: Vec<_> =
        std::fs::read_dir(backing.join(relative))?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let metadata = entry.metadata()?;
        let child = relative.join(entry.file_name());
        let name = wide(&entry.file_name());
        let identity: Vec<u8> = child
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
        let directory = metadata.is_dir();
        let mut info = CF_PLACEHOLDER_CREATE_INFO {
            RelativeFileName: name.as_ptr(),
            FsMetadata: CF_FS_METADATA {
                BasicInfo: FILE_BASIC_INFO {
                    CreationTime: 0,
                    LastAccessTime: 0,
                    LastWriteTime: 0,
                    ChangeTime: 0,
                    FileAttributes: if directory { 0x10 } else { 0x80 },
                },
                FileSize: if directory { 0 } else { metadata.len() as i64 },
            },
            FileIdentity: identity.as_ptr().cast(),
            FileIdentityLength: identity.len() as u32,
            Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                | if directory {
                    CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION
                } else {
                    0
                },
            Result: 0,
            CreateUsn: 0,
        };
        let base = wide(root.join(relative).as_os_str());
        let mut processed = 0u32;
        // SAFETY: one complete entry whose strings and identity outlive the call.
        let result = unsafe {
            CfCreatePlaceholders(
                base.as_ptr(),
                &mut info,
                1,
                CF_CREATE_FLAG_NONE,
                &mut processed,
            )
        };
        if result < 0 || info.Result < 0 {
            return Err(hresult(
                &format!("making the placeholder {}", root.join(&child).display()),
                if result < 0 { result } else { info.Result },
            ));
        }
        made += 1;
        if directory {
            made += create_in(root, backing, &child)?;
        }
    }
    Ok(made)
}

static BACKING: OnceLock<PathBuf> = OnceLock::new();

/// A connection of this process to a sync root: while it is held, the
/// provider runs and serves data.
pub struct Connection {
    key: i64,
}

impl Connection {
    /// Connects to `root`, serving each placeholder from `backing`.
    pub fn connect(root: &Path, backing: &Path) -> io::Result<Self> {
        BACKING
            .set(backing.to_owned())
            .map_err(|_| io::Error::other("this process already serves a backing folder"))?;
        let table = [
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch_data),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ];
        let path = wide(root.as_os_str());
        let mut key = 0i64;
        // SAFETY: a terminated path and a callback table ended by NONE.
        let result = unsafe {
            CfConnectSyncRoot(
                path.as_ptr(),
                table.as_ptr(),
                std::ptr::null(),
                CF_CONNECT_FLAG_NONE,
                &mut key,
            )
        };
        if result < 0 {
            return Err(hresult(
                &format!("connecting to {}", root.display()),
                result,
            ));
        }
        // Says it is running, as a provider does: CF_PROVIDER_STATUS_IDLE,
        // which CfGetSyncRootInfo then reports to every reader (how a
        // conversion tells a provider that runs from one that does not).
        // SAFETY: the key this connection was just given.
        let status = unsafe { CfUpdateSyncProviderStatus(key, CF_PROVIDER_STATUS_IDLE) };
        if status < 0 {
            // SAFETY: as above, once.
            unsafe { CfDisconnectSyncRoot(key) };
            return Err(hresult(
                &format!("reporting the provider of {} as running", root.display()),
                status,
            ));
        }
        Ok(Self { key })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the key this connection was given.
        unsafe { CfDisconnectSyncRoot(self.key) };
    }
}

fn identity_path(info: &CF_CALLBACK_INFO) -> Option<PathBuf> {
    if info.FileIdentity.is_null() || !info.FileIdentityLength.is_multiple_of(2) {
        return None;
    }
    // SAFETY: the filter hands FileIdentityLength readable bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            info.FileIdentity as *const u8,
            info.FileIdentityLength as usize,
        )
    };
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(BACKING.get()?.join(String::from_utf16(&units).ok()?))
}

fn transfer(info: &CF_CALLBACK_INFO, status: i32, buffer: *const c_void, offset: i64, length: i64) {
    let operation = CF_OPERATION_INFO {
        StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: info.ConnectionKey,
        TransferKey: info.TransferKey,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: info.RequestKey,
    };
    let mut parameters = CF_OPERATION_PARAMETERS {
        ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_0 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: status,
                Buffer: buffer,
                Offset: offset,
                Length: length,
            },
        },
    };
    // SAFETY: complete structures, and a buffer of `length` bytes or none.
    unsafe { CfExecute(&operation, &mut parameters) };
}

fn serve(info: &CF_CALLBACK_INFO, offset: i64, length: i64) -> io::Result<()> {
    let path = identity_path(info).ok_or_else(|| io::Error::other("no identity"))?;
    let mut file = File::open(path)?;
    let size = file.metadata()?.len() as i64;
    let end = offset.saturating_add(length).min(size);
    let mut at = offset;
    let mut buffer = vec![0u8; CHUNK];
    file.seek(SeekFrom::Start(at as u64))?;
    while at < end {
        let take = ((end - at) as usize).min(CHUNK);
        file.read_exact(&mut buffer[..take])?;
        transfer(info, 0, buffer.as_ptr().cast(), at, take as i64);
        at += take as i64;
    }
    Ok(())
}

unsafe extern "system" fn fetch_data(
    info: *const CF_CALLBACK_INFO,
    parameters: *const CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: the filter hands both, valid for the callback.
    let (info, fetch) = unsafe { (&*info, (*parameters).Anonymous.FetchData) };
    if serve(info, fetch.RequiredFileOffset, fetch.RequiredLength).is_err() {
        transfer(
            info,
            STATUS_UNSUCCESSFUL,
            std::ptr::null(),
            fetch.RequiredFileOffset,
            fetch.RequiredLength,
        );
    }
}

fn open_for_data(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        // FILE_READ_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        .access_mode(0x0010_0181)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
}

/// Brings `length` bytes of the placeholder at `path` from `offset` onto
/// the volume (the provider has to be connected).
pub fn hydrate_range(path: &Path, offset: u64, length: u64) -> io::Result<()> {
    let file = open_for_data(path)?;
    // SAFETY: a live handle, no overlapped I/O.
    let result = unsafe {
        CfHydratePlaceholder(
            file.as_raw_handle(),
            offset as i64,
            length as i64,
            CF_HYDRATE_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(hresult(&format!("hydrating {}", path.display()), result));
    }
    Ok(())
}

/// Takes the bytes of the placeholder at `path` from `offset` to its end
/// off the volume again: a file partly present. (A hydration of a range
/// alone brings the whole file, as the filter asks the provider for it.)
pub fn dehydrate_from(path: &Path, offset: u64) -> io::Result<()> {
    let file = std::fs::OpenOptions::new()
        // FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
        // FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
        .access_mode(0x0010_0183)
        .share_mode(0)
        .custom_flags(0x0200_0000)
        .open(path)?;
    // SAFETY: a live handle, no overlapped I/O.
    let result = unsafe {
        CfDehydratePlaceholder(
            file.as_raw_handle(),
            offset as i64,
            -1,
            CF_DEHYDRATE_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(hresult(&format!("dehydrating {}", path.display()), result));
    }
    Ok(())
}

/// Pins the placeholder at `path`: always kept on this device.
pub fn pin(path: &Path) -> io::Result<()> {
    let file = open_for_data(path)?;
    // SAFETY: a live handle, no overlapped I/O.
    let result = unsafe {
        CfSetPinState(
            file.as_raw_handle(),
            CF_PIN_STATE_PINNED,
            CF_SET_PIN_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(hresult(&format!("pinning {}", path.display()), result));
    }
    Ok(())
}
