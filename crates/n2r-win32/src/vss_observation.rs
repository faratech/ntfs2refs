//! Read-only, bounded VSS catalog observation. This does not exclude in-flight
//! snapshot operations, freeze a volume, or authorize conversion/recovery.
//!
//! ABI declarations follow Windows SDK 10.0.26100.0 `vsbackup.h`, `vss.h`, and
//! `vsmgmt.h`. The VSS_CTX_ALL provider inventory is read completely. Windows'
//! own providers are known by identity. Any other, usually part of backup
//! software, is asked whether it can make shadow copies of a volume, once
//! before and once after the machine's shadow copies are listed: it is passed
//! over only if it answered both times and none of those copies is its own.
//! The supported requester IsVolumeSnapshotted API
//! checks the source, and management enumerates differential storage hosted on it.
//! No services, COM process security defaults, snapshots, or disk flags change.
//! COM calls are synchronous: enumeration/storage bounds are not a wall timeout.
//!
//! Contracts: https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-ivssbackupcomponents-query
//! https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-ivssbackupcomponents-isvolumesupported
//! https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-isvolumesnapshotted
//! https://learn.microsoft.com/windows/win32/api/vsmgmt/nf-vsmgmt-ivssdifferentialsoftwaresnapshotmgmt-querydiffareasonvolume
use serde::Serialize;
use std::{ffi::c_void, io, marker::PhantomData, mem, ptr, rc::Rc};

/// A guard against a provider whose enumeration never ends, not a limit
/// on what a machine may hold: Windows keeps at most 512 shadow copies of a
/// volume, so this is the full set of two thousand volumes.
const MAX_OBJECTS: usize = 1 << 20;
const MAX_STRING_UNITS: usize = 1024;
const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const E_UNEXPECTED: i32 = 0x8000_ffffu32 as i32;
const SNAPSHOT: i32 = 3;
const PROVIDER: i32 = 4;
const DIFF_AREA: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
const NULL_GUID: Guid = Guid {
    a: 0,
    b: 0,
    c: 0,
    d: [0; 8],
};
const SNAPSHOT_MGMT: Guid = Guid {
    a: 0x0b5a2c52,
    b: 0x3eb9,
    c: 0x470a,
    d: [0x96, 0xe2, 0x6c, 0x6d, 0x45, 0x70, 0xe4, 0x0f],
};
const IID_SNAPSHOT_MGMT: Guid = Guid {
    a: 0xfa7df749,
    b: 0x66e7,
    c: 0x4986,
    d: [0xa2, 0x7f, 0xe2, 0xf0, 0x4a, 0xe5, 0x37, 0x72],
};
const IID_DIFF_MGMT: Guid = Guid {
    a: 0x214a0f28,
    b: 0xb737,
    c: 0x4026,
    d: [0xb8, 0x47, 0x4f, 0x9e, 0x37, 0xd7, 0x95, 0x29],
};
const SOFTWARE_PROVIDER: Guid = Guid {
    a: 0xb5946137,
    b: 0x7b9f,
    c: 0x4925,
    d: [0xaf, 0x80, 0x51, 0xab, 0xd6, 0x0b, 0x20, 0xd5],
};
// Observed Windows Hyper-V integration provider. Its backup coordinates the
// host's VM image; it is not a second guest differential-storage catalog.
// Source presence is still checked through the requester API across providers.
// https://learn.microsoft.com/windows-server/virtualization/hyper-v/integration-services
const HYPERV_PROVIDER: Guid = Guid {
    a: 0x74600e39,
    b: 0x7dc5,
    c: 0x4567,
    d: [0xa0, 0x3b, 0xf0, 0x91, 0xd6, 0xc7, 0xb0, 0x92],
};
const HYPERV_CLASS: Guid = Guid {
    a: 0x3e02620c,
    b: 0xe180,
    c: 0x44f3,
    d: [0xb1, 0x54, 0x24, 0x73, 0x64, 0x6e, 0x4c, 0xb8],
};
// The Microsoft File Share Shadow Copy provider, which every Windows Server
// has (observed on Server 2025, build 26100). It relays a shadow-copy request
// for a remote SMB share to the file server that holds the share; the copy and
// its storage are on that server. It makes no shadow copy of a local volume
// and keeps nothing on one, so it is not a place where storage the converter
// cannot see could be: its interface takes UNC paths only. VSS_PROV_FILESHARE
// is 4.
// https://learn.microsoft.com/windows/win32/api/vsprov/nn-vsprov-ivssfilesharesnapshotprovider
const FILESHARE_PROVIDER: Guid = Guid {
    a: 0x89300202,
    b: 0x3cec,
    c: 0x4981,
    d: [0x91, 0x71, 0x19, 0xf5, 0x95, 0x59, 0xe0, 0xf2],
};
const FILESHARE_CLASS: Guid = Guid {
    a: 0xfce59da7,
    b: 0x7bac,
    c: 0x40da,
    d: [0x8d, 0x21, 0x3e, 0x73, 0x11, 0xba, 0x51, 0xcd],
};
/// Windows' own, Hyper-V's and the file-share provider: no machine has more
/// known providers than these.
const MAX_KNOWN_PROVIDERS: usize = 3;

/// What a provider the converter knows keeps, and where: `None` for any
/// other. A provider is known by its identity, its class and its kind
/// together, as they were observed.
fn known_storage_role(id: Guid, class: Guid, kind: i32) -> Option<&'static str> {
    if id == SOFTWARE_PROVIDER && kind == 1 {
        Some("guest_local_differential_storage")
    } else if id == HYPERV_PROVIDER && class == HYPERV_CLASS && kind == 2 {
        Some("hyperv_host_vm_image")
    } else if id == FILESHARE_PROVIDER && class == FILESHARE_CLASS && kind == 4 {
        Some("remote_file_share_no_local_storage")
    } else {
        None
    }
}

/// The role recorded for a provider the converter does not know.
const UNKNOWN_ROLE: &str = "unknown";

/// A provider the converter does not know, as a refusal or a note names it.
fn unknown_provider(provider: &Provider) -> String {
    format!(
        "a shadow-copy (VSS) provider that the converter does not know is installed, usually part of backup software: \"{}\" version {} ({{{}}}, class {{{}}}, kind {})",
        provider.name, provider.version, provider.id, provider.class_id, provider.kind
    )
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, model: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        class: *const Guid,
        outer: *mut c_void,
        context: u32,
        iid: *const Guid,
        result: *mut *mut c_void,
    ) -> i32;
    fn CoTaskMemFree(memory: *mut c_void);
}
// VSS is optional in WinPE. Do not make every SDK executable depend on
// VSSAPI.DLL at process startup: only an actual VSS query loads the system DLL.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, characters: u32) -> u32;
    fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}
type CreateBackup = unsafe extern "system" fn(*mut *mut Backup) -> i32;
type FreeSnapshot = unsafe extern "system" fn(*mut SnapshotRaw);
type IsSnapshotted = unsafe extern "system" fn(*const u16, *mut i32, *mut i32) -> i32;
struct VssModule(*mut c_void);
impl Drop for VssModule {
    fn drop(&mut self) {
        // SAFETY: exactly the successful LoadLibraryExW reference owned here.
        // VssApi and every returned object borrow outlive this release.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct VssApi {
    _module: VssModule,
    create_backup: CreateBackup,
    free_snapshot: FreeSnapshot,
    is_snapshotted: IsSnapshotted,
}
impl VssApi {
    fn load() -> io::Result<Self> {
        let mut directory = vec![0u16; 32768];
        // SAFETY: initialized bounded WCHAR buffer, no environment path input.
        let n =
            unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n >= directory.len() {
            return Err(invalid("VSS system directory exceeds bounded path"));
        }
        directory.truncate(n);
        directory.extend("\\vssapi.dll".encode_utf16());
        directory.push(0);
        // Full native system path and LOAD_LIBRARY_SEARCH_SYSTEM32 prevent
        // caller/current-directory DLL search or an installed-image transplant.
        let raw = unsafe { LoadLibraryExW(directory.as_ptr(), ptr::null_mut(), 0x0000_0800) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "VSS unavailable: LoadLibraryExW(system32/vssapi.dll) failed: {error}; native_error={:?}",
                    error.raw_os_error()
                ),
            ));
        }
        let module = VssModule(raw);
        let address = |name: &'static [u8]| -> io::Result<*mut c_void> {
            // SAFETY: live module and fixed NUL-terminated SDK export names.
            let raw = unsafe { GetProcAddress(module.0, name.as_ptr()) };
            if raw.is_null() {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "VSS unavailable: required export {} missing: {error}; native_error={:?}",
                        String::from_utf8_lossy(&name[..name.len() - 1]),
                        error.raw_os_error()
                    ),
                ));
            }
            Ok(raw)
        };
        // SAFETY: these exact exports/signatures are the same SDK entry points
        // previously imported statically; no guessed alternate API is used.
        let create_backup = unsafe {
            mem::transmute::<*mut c_void, CreateBackup>(address(
                b"CreateVssBackupComponentsInternal\0",
            )?)
        };
        let free_snapshot = unsafe {
            mem::transmute::<*mut c_void, FreeSnapshot>(address(
                b"VssFreeSnapshotPropertiesInternal\0",
            )?)
        };
        let is_snapshotted = unsafe {
            mem::transmute::<*mut c_void, IsSnapshotted>(address(b"IsVolumeSnapshottedInternal\0")?)
        };
        Ok(Self {
            _module: module,
            create_backup,
            free_snapshot,
            is_snapshotted,
        })
    }
}

#[repr(C)]
struct UnknownVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
struct Backup {
    vtable: *const BackupVtable,
}
#[repr(C)]
struct BackupVtable {
    unknown: UnknownVtable,
    // SDK IVssBackupComponents slots 3..4.
    writer_component_methods: [usize; 2],
    initialize_for_backup: unsafe extern "system" fn(*mut Backup, *const u16) -> i32,
    // Slots 6..34; no mutation/backup methods are invoked.
    unused_before_context: [usize; 29],
    set_context: unsafe extern "system" fn(*mut Backup, i32) -> i32,
    unused_before_query: [usize; 7],
    query: unsafe extern "system" fn(*mut Backup, Guid, i32, i32, *mut *mut ObjectEnum) -> i32,
    is_volume_supported: unsafe extern "system" fn(*mut Backup, Guid, *const u16, *mut i32) -> i32,
}
#[repr(C)]
struct ObjectEnum {
    vtable: *const ObjectEnumVtable,
}
#[repr(C)]
struct ObjectEnumVtable {
    unknown: UnknownVtable,
    next: unsafe extern "system" fn(*mut ObjectEnum, u32, *mut ObjectRaw, *mut u32) -> i32,
}
#[repr(C)]
struct Management {
    vtable: *const ManagementVtable,
}
#[repr(C)]
struct ManagementVtable {
    unknown: UnknownVtable,
    provider_management:
        unsafe extern "system" fn(*mut Management, Guid, *const Guid, *mut *mut c_void) -> i32,
}
#[repr(C)]
struct Differential {
    vtable: *const DifferentialVtable,
}
#[repr(C)]
struct DifferentialVtable {
    unknown: UnknownVtable,
    unused_before_query_on_volume: [usize; 4],
    query_on_volume:
        unsafe extern "system" fn(*mut Differential, *const u16, *mut *mut ManagementEnum) -> i32,
}
#[repr(C)]
struct ManagementEnum {
    vtable: *const ManagementEnumVtable,
}
#[repr(C)]
struct ManagementEnumVtable {
    unknown: UnknownVtable,
    next: unsafe extern "system" fn(*mut ManagementEnum, u32, *mut ManagementRaw, *mut u32) -> i32,
}
// Keep the used slots tied to the SDK ordering even if a declaration is edited.
const _: () = {
    let pointer = mem::size_of::<usize>();
    assert!(mem::size_of::<Guid>() == 16);
    assert!(mem::offset_of!(BackupVtable, initialize_for_backup) == 5 * pointer);
    assert!(mem::offset_of!(BackupVtable, set_context) == 35 * pointer);
    assert!(mem::offset_of!(BackupVtable, query) == 43 * pointer);
    assert!(mem::offset_of!(BackupVtable, is_volume_supported) == 44 * pointer);
    assert!(mem::offset_of!(DifferentialVtable, query_on_volume) == 7 * pointer);
    assert!(mem::offset_of!(ObjectEnumVtable, next) == 3 * pointer);
    assert!(mem::offset_of!(ManagementEnumVtable, next) == 3 * pointer);
};
#[repr(C)]
#[derive(Clone, Copy)]
struct SnapshotRaw {
    id: Guid,
    set: Guid,
    count: i32,
    device: *mut u16,
    original: *mut u16,
    originating_machine: *mut u16,
    service_machine: *mut u16,
    exposed_name: *mut u16,
    exposed_path: *mut u16,
    provider: Guid,
    attributes: i32,
    created: i64,
    state: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct ProviderRaw {
    id: Guid,
    name: *mut u16,
    kind: i32,
    version: *mut u16,
    version_id: Guid,
    class: Guid,
}
#[repr(C)]
union ObjectUnion {
    snapshot: SnapshotRaw,
    provider: ProviderRaw,
}
#[repr(C)]
struct ObjectRaw {
    kind: i32,
    object: ObjectUnion,
}
struct OwnedObject<'api> {
    raw: ObjectRaw,
    api: &'api VssApi,
}
impl std::ops::Deref for OwnedObject<'_> {
    type Target = ObjectRaw;
    fn deref(&self) -> &ObjectRaw {
        &self.raw
    }
}
impl Drop for OwnedObject<'_> {
    fn drop(&mut self) {
        // SAFETY: only an SDK-discriminated returned arm is released. Zeroed
        // initial storage has kind 0, so failed/unfilled queries release none.
        unsafe {
            match self.raw.kind {
                SNAPSHOT => (self.api.free_snapshot)(&mut self.raw.object.snapshot),
                PROVIDER => {
                    CoTaskMemFree(self.raw.object.provider.name.cast());
                    CoTaskMemFree(self.raw.object.provider.version.cast());
                }
                _ => {}
            }
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct DiffAreaRaw {
    original: *mut u16,
    host: *mut u16,
    maximum: i64,
    allocated: i64,
    used: i64,
}
#[repr(C)]
union ManagementUnion {
    area: DiffAreaRaw,
}
#[repr(C)]
struct ManagementRaw {
    kind: i32,
    object: ManagementUnion,
}
impl Drop for ManagementRaw {
    fn drop(&mut self) {
        if self.kind == DIFF_AREA {
            // SAFETY: this arm is two CoTaskMem-allocated strings per vsmgmt.h.
            unsafe {
                CoTaskMemFree(self.object.area.original.cast());
                CoTaskMemFree(self.object.area.host.cast());
            }
        }
    }
}

struct Apartment;
impl Apartment {
    fn initialize() -> io::Result<Self> {
        // SAFETY: reserved is null; COINIT_MULTITHREADED is 0. A conflicting
        // existing apartment is an error, not assumed usable initialization.
        let hr = unsafe { CoInitializeEx(ptr::null_mut(), 0) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self)
        } else {
            Err(hresult("CoInitializeEx", hr))
        }
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: balances this thread's successful CoInitializeEx only.
        unsafe { CoUninitialize() };
    }
}
struct Com<T> {
    raw: *mut T,
    not_send: PhantomData<Rc<()>>,
}
impl<T> Com<T> {
    fn returned(raw: *mut T, hr: i32, operation: &str) -> io::Result<Self> {
        let owned = (!raw.is_null()).then(|| Self {
            raw,
            not_send: PhantomData,
        });
        if hr != S_OK {
            return Err(hresult(operation, hr));
        }
        owned.ok_or_else(|| invalid(format!("{operation} returned a null interface")))
    }
}
impl<T> Drop for Com<T> {
    fn drop(&mut self) {
        // SAFETY: every owned interface starts with an IUnknown-compatible
        // vtable and was returned with one reference, released on this thread.
        unsafe {
            let vtable = *(self.raw.cast::<*const UnknownVtable>());
            ((*vtable).release)(self.raw.cast());
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Provider {
    pub id: String,
    pub class_id: String,
    pub name: String,
    pub kind: i32,
    pub version: String,
    pub hosted_diff_areas_query_completed: bool,
    pub storage_role: &'static str,
    /// What a provider the converter does not know answered when asked;
    /// nothing for one it knows, which is not asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked: Option<ProviderAnswers>,
}
/// A provider the converter does not know is asked, through Windows, whether
/// it can make shadow copies of the volume Windows runs from: once before
/// the machine's shadow copies are listed and once after. What it says does
/// not matter; that it answered both times shows it was there to be asked
/// for its shadow copies in between.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderAnswers {
    pub api: &'static str,
    pub volume: String,
    pub before_hresult: i32,
    pub after_hresult: i32,
}
impl ProviderAnswers {
    fn both(&self) -> bool {
        self.before_hresult == S_OK && self.after_hresult == S_OK
    }
}
/// A completed shadow copy on the machine, of any provider and any volume.
#[derive(Clone, Debug, Serialize)]
pub struct ShadowCopy {
    pub id: String,
    pub provider_id: String,
    pub original_volume: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct SourceSnapshotPresence {
    pub api: &'static str,
    pub scope: &'static str,
    pub hresult: i32,
    pub snapshots_present: bool,
    pub compatibility_flags: i32,
}
#[derive(Clone, Debug, Serialize)]
pub struct HostedDiffArea {
    pub provider_id: String,
    pub original_volume: String,
    pub storage_volume: String,
    pub maximum_bytes: i64,
    pub allocated_bytes: i64,
    pub used_bytes: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub source_volume_guid: String,
    pub snapshot_context: i32,
    pub completed_snapshot_count_all_volumes: Option<usize>,
    pub source_snapshot_presence: SourceSnapshotPresence,
    pub providers: Vec<Provider>,
    pub hosted_diff_areas: Vec<HostedDiffArea>,
    pub hosted_diff_area_query_hresult: Option<i32>,
    pub hosted_storage_enumerated: bool,
    pub completed_catalog_enumeration: bool,
    pub provider_inventory_completed: bool,
    /// The machine's completed shadow copies and the result of asking for
    /// them. They are asked for only where a provider is installed that the
    /// converter does not know: `None` where every provider is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow_copy_query_hresult: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shadow_copies: Vec<ShadowCopy>,
    pub inflight_snapshot_operations_excluded: bool,
    pub source_exclusion_proven: bool,
    pub execution_authorized: bool,
}
impl Observation {
    /// A source-presence/storage observation only. Callers must separately own and
    /// bind source freeze/exclusion; this is not a global VSS serialization lease.
    pub fn require_observed_catalog_clear(&self) -> io::Result<()> {
        self.require_observed_snapshot_absence()?;
        if let Some(area) = self.hosted_diff_areas.first() {
            return Err(invalid(format!(
                "this volume stores shadow copies of {} ({} bytes of snapshot storage in use, {} area(s) in all): a conversion in place would destroy them. Delete those shadow copies or move their storage to another volume (`vssadmin list shadowstorage`), then convert",
                area.original_volume,
                area.used_bytes,
                self.hosted_diff_areas.len()
            )));
        }
        if !self.hosted_storage_enumerated
            || !matches!(self.hosted_diff_area_query_hresult, Some(S_OK | S_FALSE))
            || self
                .providers
                .iter()
                .any(|p| p.id == guid(SOFTWARE_PROVIDER) && !p.hosted_diff_areas_query_completed)
        {
            return Err(invalid(format!(
                "Windows did not answer completely whether this volume stores shadow copies of any volume (query result {:?}); without that answer the volume is not converted",
                self.hosted_diff_area_query_hresult
            )));
        }
        Ok(())
    }

    /// The same conditions as ever, each with its own words: a refusal
    /// used to be one sentence that named none of them.
    pub fn require_observed_snapshot_absence(&self) -> io::Result<()> {
        let presence = &self.source_snapshot_presence;
        if presence.hresult == S_OK && presence.snapshots_present {
            return Err(invalid(
                "the volume has shadow copies (snapshots: restore points, previous versions, or a backup's). A conversion in place would destroy them: delete them first (`vssadmin delete shadows /for=<drive>:`), then convert",
            ));
        }
        if presence.hresult != S_OK || presence.compatibility_flags != 0 {
            return Err(invalid(format!(
                "Windows did not say plainly whether the volume has shadow copies (result {:#x}, compatibility flags {:#x}); without that answer the volume is not converted",
                presence.hresult, presence.compatibility_flags
            )));
        }
        if !self.provider_inventory_completed {
            return Err(invalid(
                "the list of installed shadow-copy (VSS) providers could not be read completely; without it the volume is not converted",
            ));
        }
        // What Windows said of the volume is held against the machine's own
        // list, where that was read.
        if let Some(copy) = self.shadow_copies.iter().find(|copy| {
            copy.original_volume
                .eq_ignore_ascii_case(&self.source_volume_guid)
        }) {
            return Err(invalid(format!(
                "the volume has a shadow copy ({{{}}}, of provider {{{}}}) that Windows did not report when asked about the volume. A conversion in place would destroy it: delete it first (`vssadmin delete shadows /for=<drive>:`), then convert",
                copy.id, copy.provider_id
            )));
        }
        for provider in self.providers.iter().filter(|p| !Self::known(p)) {
            if let Some(reason) = self.unknown_provider_refusal(provider) {
                return Err(invalid(format!(
                    "{}. {reason}. The volume itself has no shadow copies",
                    unknown_provider(provider)
                )));
            }
        }
        let known = self.providers.iter().filter(|p| Self::known(p)).count();
        if !(1..=MAX_KNOWN_PROVIDERS).contains(&known)
            || self
                .providers
                .iter()
                .filter(|p| p.id == guid(SOFTWARE_PROVIDER))
                .map(Self::known)
                .ne([true])
        {
            return Err(invalid(format!(
                "Windows' own shadow-copy provider is missing or listed more than once among the {} installed provider(s); the volume is not converted",
                self.providers.len()
            )));
        }
        Ok(())
    }

    /// Windows' own providers, each by its identity, class, kind and the
    /// role recorded for it together.
    fn known(p: &Provider) -> bool {
        if p.id == guid(SOFTWARE_PROVIDER) {
            p.kind == 1 && p.storage_role == "guest_local_differential_storage"
        } else if p.id == guid(HYPERV_PROVIDER) {
            p.class_id == guid(HYPERV_CLASS)
                && p.kind == 2
                && p.storage_role == "hyperv_host_vm_image"
        } else {
            p.id == guid(FILESHARE_PROVIDER)
                && p.class_id == guid(FILESHARE_CLASS)
                && p.kind == 4
                && p.storage_role == "remote_file_share_no_local_storage"
        }
    }

    /// Why a provider the converter does not know stops the conversion, or
    /// `None` where it holds nothing a conversion could destroy: it answered
    /// when asked, before and after the machine's shadow copies were listed,
    /// and none of those is its own. Whether the volume itself has shadow
    /// copies is asked of Windows and decided before this.
    fn unknown_provider_refusal(&self, provider: &Provider) -> Option<String> {
        const UNSEEN: &str = "Such a provider may keep snapshot storage the converter cannot see, so the volume is not converted";
        let Some(asked) = provider
            .asked
            .as_ref()
            .filter(|_| provider.storage_role == UNKNOWN_ROLE)
        else {
            return Some(format!(
                "It was not asked whether it holds shadow copies. {UNSEEN}"
            ));
        };
        if !asked.both() {
            return Some(format!(
                "It did not answer when Windows asked it about a volume (results {:#010x} and {:#010x}), so whether it holds shadow copies is not known. {UNSEEN} until it answers or is removed",
                asked.before_hresult as u32, asked.after_hresult as u32
            ));
        }
        if !matches!(self.shadow_copy_query_hresult, Some(S_OK | S_FALSE)) {
            return Some(format!(
                "Windows did not list the machine's shadow copies (result {}), so whether this provider holds any is not known. {UNSEEN} without that list",
                self.shadow_copy_query_hresult
                    .map_or("none".to_owned(), |hr| format!("{:#010x}", hr as u32))
            ));
        }
        let own: Vec<&ShadowCopy> = self
            .shadow_copies
            .iter()
            .filter(|copy| copy.provider_id == provider.id)
            .collect();
        let first = own.first()?;
        Some(format!(
            "It holds {} shadow cop{} on this machine (for example {{{}}} of {}), and where it keeps their storage the converter cannot see. Delete them, or let the backup that made them finish, then convert",
            own.len(),
            if own.len() == 1 { "y" } else { "ies" },
            first.id,
            first.original_volume
        ))
    }

    /// What a run says of the providers it does not know and passes over:
    /// one note each. Nothing where the observation refuses.
    pub fn provider_notes(&self) -> Vec<String> {
        if self.require_observed_snapshot_absence().is_err() {
            return Vec::new();
        }
        self.providers
            .iter()
            .filter(|p| !Self::known(p))
            .map(|provider| {
                let named = unknown_provider(provider);
                format!(
                    "A{}. It answered when asked and holds no shadow copy on this machine, so the conversion goes ahead. If that software keeps track of what changed on the volume since its last backup, it will not recognise the converted volume: make a full backup afterwards.",
                    &named[1..]
                )
            })
            .collect()
    }

    pub fn same_source_and_provider_inventory(&self, other: &Self) -> bool {
        self.source_volume_guid == other.source_volume_guid
            && self.provider_inventory_completed
            && other.provider_inventory_completed
            && self.providers.len() == other.providers.len()
            && self.providers.iter().all(|p| {
                other.providers.iter().any(|q| {
                    p.id == q.id
                        && p.class_id == q.class_id
                        && p.kind == q.kind
                        && p.storage_role == q.storage_role
                })
            })
    }
}

/// Query source snapshot presence and hosted storage without mutation. The
/// Microsoft system provider must be there and fully enumerated; the known
/// Hyper-V host-integration provider and Windows Server's provider for remote
/// file shares may accompany it. Any other provider is asked and the
/// machine's shadow copies are listed (see `ProviderAnswers`); what comes of
/// that the requirements below decide, naming the provider.
/// The source's own absence of shadow copies is never read off that list: it
/// is what IsVolumeSnapshotted says. All enumerators must terminate with the
/// exact SDK S_FALSE/zero-fetched completion result.
pub fn observe_catalog(source_volume_guid: &str) -> io::Result<Observation> {
    observe(source_volume_guid, true)
}

/// The presence API works under the existing physically read-only NTFS lease;
/// the differential-storage query does not on the qualified Windows build.
/// This scope cannot substitute for the pre-freeze hosted-storage observation.
pub fn observe_snapshot_presence(source_volume_guid: &str) -> io::Result<Observation> {
    observe(source_volume_guid, false)
}

fn observe(source_volume_guid: &str, include_storage: bool) -> io::Result<Observation> {
    let source = volume_guid(source_volume_guid)?;
    // Declare the module before all COM owners; they release before unload.
    let api = VssApi::load()?;
    let _apartment = Apartment::initialize()?;
    let mut backup = ptr::null_mut();
    // SAFETY: initialized output pointer, owned reference checked below.
    let hr = unsafe { (api.create_backup)(&mut backup) };
    let backup = Com::returned(backup, hr, "CreateVssBackupComponents")?;
    // SAFETY: SDK-typed vtable slots on the live interface, null BSTR means a
    // new query context; no StartSnapshotSet/DoSnapshotSet or writers are called.
    let hr = unsafe { ((*(*backup.raw).vtable).initialize_for_backup)(backup.raw, ptr::null()) };
    exact_ok("IVssBackupComponents::InitializeForBackup", hr)?;
    let hr = unsafe { ((*(*backup.raw).vtable).set_context)(backup.raw, -1) };
    exact_ok("IVssBackupComponents::SetContext(VSS_CTX_ALL)", hr)?;
    let mut total = 0usize;
    let mut mgmt = ptr::null_mut();
    // SAFETY: valid GUIDs; local in-process/local-server activation only, with
    // no remote server or aggregation requested.
    let hr = unsafe {
        CoCreateInstance(
            &SNAPSHOT_MGMT,
            ptr::null_mut(),
            5,
            &IID_SNAPSHOT_MGMT,
            &mut mgmt,
        )
    };
    let management = Com::returned(
        mgmt.cast::<Management>(),
        hr,
        "CoCreateInstance(VssSnapshotMgmt)",
    )?;
    let provider_enum = query(&backup, PROVIDER)?;
    let mut providers = Vec::new();
    // The providers the converter does not know: position and identity.
    let mut unknown: Vec<(usize, Guid)> = Vec::new();
    let mut areas = Vec::new();
    while let Some(item) = next_object(&provider_enum, PROVIDER, &api)? {
        count(&mut total)?;
        // SAFETY: next_object checked the union discriminator.
        let provider = unsafe { item.object.provider };
        let provider_id = guid(provider.id);
        let name = wide_string(provider.name)?;
        let version = wide_string(provider.version)?;
        let storage_role =
            known_storage_role(provider.id, provider.class, provider.kind).unwrap_or(UNKNOWN_ROLE);
        if provider.class == NULL_GUID || providers.iter().any(|p: &Provider| p.id == provider_id) {
            return Err(invalid(format!(
                "the list of shadow-copy (VSS) providers is not one the converter can read: \"{name}\" ({{{provider_id}}}) is listed twice or has no class; the volume is not converted"
            )));
        }
        if storage_role == UNKNOWN_ROLE {
            unknown.push((providers.len(), provider.id));
        }
        providers.push(Provider {
            id: provider_id,
            class_id: guid(provider.class),
            name,
            kind: provider.kind,
            version,
            hosted_diff_areas_query_completed: false,
            storage_role,
            asked: None,
        });
    }
    if providers
        .iter()
        .filter(|p| p.id == guid(SOFTWARE_PROVIDER))
        .count()
        != 1
    {
        return Err(invalid(
            "Microsoft software VSS provider was not completely observed",
        ));
    }
    // A provider the converter does not know is asked about a volume, the
    // machine's shadow copies are listed, and it is asked again. Nothing
    // here refuses for what it finds: the requirements do, and name the
    // provider. Where every provider is known, none of this is done.
    let mut shadow_copy_query_hresult = None;
    let mut shadow_copies = Vec::new();
    if !unknown.is_empty() {
        let (asked_volume, asked_wide) = windows_volume()?;
        let ask = |provider: Guid| -> i32 {
            let mut supported = -1i32;
            // SAFETY: SDK-typed slot on the live interface, a live
            // NUL-terminated volume path and an initialized BOOL output.
            let hr = unsafe {
                ((*(*backup.raw).vtable).is_volume_supported)(
                    backup.raw,
                    provider,
                    asked_wide.as_ptr(),
                    &mut supported,
                )
            };
            // An answer that left its output unset is not an answer.
            if hr == S_OK && !matches!(supported, 0 | 1) {
                E_UNEXPECTED
            } else {
                hr
            }
        };
        let before: Vec<i32> = unknown.iter().map(|(_, id)| ask(*id)).collect();
        let mut enumeration = ptr::null_mut();
        // SAFETY: the exact SDK Query signature, as in `query`.
        let hr = unsafe {
            ((*(*backup.raw).vtable).query)(backup.raw, NULL_GUID, 1, SNAPSHOT, &mut enumeration)
        };
        // Owned whatever the result, so that it is released.
        let enumeration = (!enumeration.is_null()).then(|| Com {
            raw: enumeration,
            not_send: PhantomData,
        });
        shadow_copy_query_hresult = Some(hr);
        match (hr, enumeration) {
            (S_OK, Some(enumeration)) => {
                while let Some(item) = next_object(&enumeration, SNAPSHOT, &api)? {
                    count(&mut total)?;
                    // SAFETY: next_object checked the union discriminator.
                    let snapshot = unsafe { item.object.snapshot };
                    shadow_copies.push(ShadowCopy {
                        id: guid(snapshot.id),
                        provider_id: guid(snapshot.provider),
                        original_volume: optional_wide_string(snapshot.original)?,
                    });
                }
            }
            // Windows answers a machine without shadow copies with S_FALSE
            // and no list. A list that then holds something is no answer.
            (S_FALSE, None) => (),
            (S_FALSE, Some(enumeration)) => {
                if next_object(&enumeration, SNAPSHOT, &api)?.is_some() {
                    return Err(invalid(
                        "the list of shadow copies was returned as empty and holds one",
                    ));
                }
            }
            (S_OK, None) => {
                return Err(invalid(
                    "IVssBackupComponents::Query returned no list of shadow copies",
                ));
            }
            // Any other result is recorded; the requirement refuses with it.
            _ => (),
        }
        shadow_copies.sort_by(|a, b| {
            (&a.provider_id, &a.original_volume, &a.id).cmp(&(
                &b.provider_id,
                &b.original_volume,
                &b.id,
            ))
        });
        for ((position, id), before_hresult) in unknown.iter().zip(before) {
            providers[*position].asked = Some(ProviderAnswers {
                api: "IVssBackupComponents::IsVolumeSupported",
                volume: asked_volume.clone(),
                before_hresult,
                after_hresult: ask(*id),
            });
        }
    }
    let completed_snapshot_count_all_volumes =
        matches!(shadow_copy_query_hresult, Some(S_OK | S_FALSE)).then_some(shadow_copies.len());
    let source_wide: Vec<u16> = source.encode_utf16().chain(Some(0)).collect();
    // Sentinel outputs ensure a provider cannot leave a successful result
    // uninitialized and have that accidentally interpreted as false/zero.
    let mut present = -1i32;
    let mut compatibility = -1i32;
    // SAFETY: live NUL-terminated volume GUID and exact SDK BOOL/LONG outputs;
    // this is the public IsVolumeSnapshotted inline's exported entry point.
    let hr =
        unsafe { (api.is_snapshotted)(source_wide.as_ptr(), &mut present, &mut compatibility) };
    exact_ok("IsVolumeSnapshotted", hr)?;
    if !matches!(present, 0 | 1) || compatibility < 0 {
        return Err(invalid(
            "IsVolumeSnapshotted returned malformed/unset output",
        ));
    }
    let source_snapshot_presence = SourceSnapshotPresence {
        api: "IsVolumeSnapshotted",
        scope: "source-volume-snapshot-presence-requester-api-v1",
        hresult: hr,
        snapshots_present: present != 0,
        compatibility_flags: compatibility,
    };
    if !include_storage {
        return Ok(Observation {
            schema_version: 4,
            kind: "vss-source-presence-observation-v4",
            source_volume_guid: source,
            snapshot_context: -1,
            completed_snapshot_count_all_volumes,
            source_snapshot_presence,
            providers,
            hosted_diff_areas: Vec::new(),
            hosted_diff_area_query_hresult: None,
            hosted_storage_enumerated: false,
            completed_catalog_enumeration: false,
            provider_inventory_completed: true,
            shadow_copy_query_hresult,
            shadow_copies,
            inflight_snapshot_operations_excluded: false,
            source_exclusion_proven: false,
            execution_authorized: false,
        });
    }
    let mut differential = ptr::null_mut();
    // SAFETY: supported system provider ID and the only documented management
    // IID. No request to activate the provider implementation class is made.
    let hr = unsafe {
        ((*(*management.raw).vtable).provider_management)(
            management.raw,
            SOFTWARE_PROVIDER,
            &IID_DIFF_MGMT,
            &mut differential,
        )
    };
    let differential = Com::returned(
        differential.cast::<Differential>(),
        hr,
        "IVssSnapshotMgmt::GetProviderMgmtInterface(system differential)",
    )?;
    let mut enumeration = ptr::null_mut();
    // SAFETY: source string remains alive for the synchronous query.
    let hr = unsafe {
        ((*(*differential.raw).vtable).query_on_volume)(
            differential.raw,
            source_wide.as_ptr(),
            &mut enumeration,
        )
    };
    // This is the single Microsoft differential-management interface, not
    // IVssBackupComponents::Query's aggregation over snapshot providers. A
    // positive S_FALSE is accepted only with a real enumerator that proves
    // an empty collection. Never infer absence from S_FALSE plus null output,
    // a partial collection, or any failing HRESULT.
    let empty_query = hr == S_FALSE;
    let enumeration = Com::returned(
        enumeration,
        if empty_query { S_OK } else { hr },
        "QueryDiffAreasOnVolume",
    )?;
    while let Some(item) = next_area(&enumeration)? {
        if empty_query {
            return Err(invalid(
                "empty diff-area query returned a nonempty collection",
            ));
        }
        count(&mut total)?;
        // SAFETY: next_area checked the SDK union discriminator.
        let area = unsafe { item.object.area };
        let host = volume_guid(&wide_string(area.host)?)?;
        let original = volume_guid(&wide_string(area.original)?)?;
        if host != source || area.maximum < -1 || area.allocated < 0 || area.used < 0 {
            return Err(invalid(
                "VSS returned an invalid or foreign hosted diff area",
            ));
        }
        areas.push(HostedDiffArea {
            provider_id: guid(SOFTWARE_PROVIDER),
            original_volume: original,
            storage_volume: host,
            maximum_bytes: area.maximum,
            allocated_bytes: area.allocated,
            used_bytes: area.used,
        });
    }
    providers
        .iter_mut()
        .find(|p| p.id == guid(SOFTWARE_PROVIDER))
        .expect("system provider inventory checked")
        .hosted_diff_areas_query_completed = true;
    areas.sort_by(|a, b| {
        (&a.provider_id, &a.original_volume).cmp(&(&b.provider_id, &b.original_volume))
    });
    Ok(Observation {
        schema_version: 3,
        kind: "vss-source-presence-and-hosted-storage-observation-v3",
        source_volume_guid: source,
        snapshot_context: -1,
        completed_snapshot_count_all_volumes,
        source_snapshot_presence,
        providers,
        hosted_diff_areas: areas,
        hosted_diff_area_query_hresult: Some(hr),
        hosted_storage_enumerated: true,
        completed_catalog_enumeration: false,
        provider_inventory_completed: true,
        shadow_copy_query_hresult,
        shadow_copies,
        inflight_snapshot_operations_excluded: false,
        source_exclusion_proven: false,
        execution_authorized: false,
    })
}

fn query(backup: &Com<Backup>, kind: i32) -> io::Result<Com<ObjectEnum>> {
    let mut result = ptr::null_mut();
    // SAFETY: exact SDK Query signature; VSS_OBJECT_NONE=1 and GUID_NULL request
    // all objects of the requested type, under the already-set VSS_CTX_ALL.
    let hr =
        unsafe { ((*(*backup.raw).vtable).query)(backup.raw, NULL_GUID, 1, kind, &mut result) };
    Com::returned(result, hr, "IVssBackupComponents::Query")
}
fn next_object<'api>(
    enumeration: &Com<ObjectEnum>,
    expected: i32,
    api: &'api VssApi,
) -> io::Result<Option<OwnedObject<'api>>> {
    // SAFETY: zeroed C POD/union has no references or Rust invariants. The
    // wrapper retains a live free function even if Next fails/misbehaves.
    let mut item = OwnedObject {
        raw: unsafe { mem::zeroed() },
        api,
    };
    let mut fetched = 0;
    let hr = unsafe {
        ((*(*enumeration.raw).vtable).next)(enumeration.raw, 1, &mut item.raw, &mut fetched)
    };
    if hr == S_FALSE && fetched == 0 && item.kind == 0 {
        return Ok(None);
    }
    exact_ok("IVssEnumObject::Next", hr)?;
    if fetched != 1 || item.kind != expected {
        return Err(invalid(
            "VSS object enumeration returned an incomplete or unexpected object",
        ));
    }
    Ok(Some(item))
}
fn next_area(enumeration: &Com<ManagementEnum>) -> io::Result<Option<ManagementRaw>> {
    // SAFETY: zero-initialized output POD; Next receives storage for one item.
    let mut item: ManagementRaw = unsafe { mem::zeroed() };
    let mut fetched = 0;
    let hr =
        unsafe { ((*(*enumeration.raw).vtable).next)(enumeration.raw, 1, &mut item, &mut fetched) };
    if hr == S_FALSE && fetched == 0 && item.kind == 0 {
        return Ok(None);
    }
    exact_ok("IVssEnumMgmtObject::Next", hr)?;
    if fetched != 1 || item.kind != DIFF_AREA {
        return Err(invalid(
            "VSS diff-area enumeration returned an incomplete or unexpected object",
        ));
    }
    Ok(Some(item))
}
fn count(total: &mut usize) -> io::Result<()> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| invalid("VSS object count overflow"))?;
    if *total > MAX_OBJECTS {
        return Err(invalid(&format!(
            "the VSS provider listed more than {MAX_OBJECTS} objects; its enumeration is taken not to end"
        )));
    }
    Ok(())
}
fn wide_string(value: *const u16) -> io::Result<String> {
    if value.is_null() {
        return Err(invalid("VSS required string is null"));
    }
    for length in 0..MAX_STRING_UNITS {
        // SAFETY: SDK output strings are readable nul-terminated UTF-16; bounded
        // scanning limits retained data and refuses over-budget provider output.
        if unsafe { *value.add(length) } == 0 {
            let units = unsafe { std::slice::from_raw_parts(value, length) };
            return String::from_utf16(units)
                .map_err(|_| invalid("VSS string is not valid UTF-16"));
        }
    }
    Err(invalid("VSS string exceeds the bounded string budget"))
}
/// A string VSS may leave out: empty then.
fn optional_wide_string(value: *const u16) -> io::Result<String> {
    if value.is_null() {
        Ok(String::new())
    } else {
        wide_string(value)
    }
}
/// The volume Windows runs from, as a root path ("C:\\") and as the
/// NUL-terminated string VSS takes. It is online and writable for as long
/// as the run lasts, whatever state the run puts its source in.
fn windows_volume() -> io::Result<(String, Vec<u16>)> {
    let mut directory = vec![0u16; 32768];
    // SAFETY: initialized bounded WCHAR buffer, no environment path input.
    let length =
        unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length < 3
        || length >= directory.len()
        || !u8::try_from(directory[0]).is_ok_and(|unit| unit.is_ascii_alphabetic())
        || directory[1] != u16::from(b':')
        || directory[2] != u16::from(b'\\')
    {
        return Err(invalid(
            "Windows' own directory is not on a volume with a drive letter",
        ));
    }
    let root = String::from_utf16_lossy(&directory[..3]);
    let wide = directory[..3].iter().copied().chain(Some(0)).collect();
    Ok((root, wide))
}
fn volume_guid(value: &str) -> io::Result<String> {
    if value.len() != 49 {
        return Err(invalid(
            "VSS volume identity is not an exact GUID volume path",
        ));
    }
    let lower = value.to_ascii_lowercase();
    let inside = lower
        .strip_prefix(r"\\?\volume{")
        .and_then(|s| s.strip_suffix("}\\"))
        .ok_or_else(|| invalid("VSS volume identity is not an exact GUID volume path"))?;
    if inside.len() != 36
        || !inside.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        || inside.bytes().filter(|b| *b != b'-').all(|b| b == b'0')
    {
        return Err(invalid("VSS volume GUID is malformed or null"));
    }
    Ok(lower)
}
fn guid(g: Guid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.a, g.b, g.c, g.d[0], g.d[1], g.d[2], g.d[3], g.d[4], g.d[5], g.d[6], g.d[7]
    )
}
fn exact_ok(operation: &str, hr: i32) -> io::Result<()> {
    if hr == S_OK {
        Ok(())
    } else {
        Err(hresult(operation, hr))
    }
}
fn hresult(operation: &str, hr: i32) -> io::Error {
    io::Error::other(format!(
        "{operation} failed or was incomplete: HRESULT {:#010x}",
        hr as u32
    ))
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    const BACKUP_PROVIDER: &str = "11111111-2222-3333-4444-555555555555";
    const OTHER_VOLUME: &str = "\\\\?\\Volume{other}\\";

    /// A provider of a backup product, with what it answered when asked.
    fn backup_provider(asked: Option<(i32, i32)>) -> Provider {
        Provider {
            id: BACKUP_PROVIDER.into(),
            class_id: "66666666-7777-8888-9999-000000000000".into(),
            name: "Some Backup VSS Provider".into(),
            kind: 2,
            version: "9.1".into(),
            hosted_diff_areas_query_completed: false,
            storage_role: UNKNOWN_ROLE,
            asked: asked.map(|(before_hresult, after_hresult)| ProviderAnswers {
                api: "IVssBackupComponents::IsVolumeSupported",
                volume: "C:\\".into(),
                before_hresult,
                after_hresult,
            }),
        }
    }

    fn refusal(observation: &Observation) -> String {
        assert!(observation.provider_notes().is_empty());
        observation
            .require_observed_catalog_clear()
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn a_provider_the_converter_does_not_know_is_passed_over_only_when_it_holds_nothing() {
        // Where every provider is known there is nothing to say.
        assert!(clear().provider_notes().is_empty());

        // It answered before and after the list was read, and the machine
        // has no shadow copy: the volume converts, with a note naming it.
        let mut admitted = clear();
        admitted.providers.push(backup_provider(Some((S_OK, S_OK))));
        admitted.shadow_copy_query_hresult = Some(S_FALSE);
        admitted.require_observed_catalog_clear().unwrap();
        let notes = admitted.provider_notes();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("A shadow-copy (VSS) provider")
                && notes[0].contains("\"Some Backup VSS Provider\" version 9.1")
                && notes[0].contains("full backup"),
            "{}",
            notes[0]
        );
        // Shadow copies of another provider, of another volume, change nothing.
        admitted.shadow_copy_query_hresult = Some(S_OK);
        admitted.shadow_copies.push(ShadowCopy {
            id: "aaaaaaaa".into(),
            provider_id: guid(SOFTWARE_PROVIDER),
            original_volume: OTHER_VOLUME.into(),
        });
        admitted.require_observed_catalog_clear().unwrap();
        assert_eq!(admitted.provider_notes().len(), 1);
        // The inventory is the same one when the provider is there both times.
        assert!(admitted.same_source_and_provider_inventory(&admitted.clone()));
        assert!(!admitted.same_source_and_provider_inventory(&clear()));

        // A shadow copy of its own, of whatever volume: refused, and the
        // refusal names the provider and the copy.
        let mut holds = admitted.clone();
        holds.shadow_copies.push(ShadowCopy {
            id: "bbbbbbbb".into(),
            provider_id: BACKUP_PROVIDER.into(),
            original_volume: OTHER_VOLUME.into(),
        });
        let said = refusal(&holds);
        assert!(
            said.contains("Some Backup VSS Provider")
                && said.contains("It holds 1 shadow copy on this machine")
                && said.contains("{bbbbbbbb}")
                && said.contains(OTHER_VOLUME),
            "{said}"
        );
        holds.shadow_copies.push(ShadowCopy {
            id: "cccccccc".into(),
            provider_id: BACKUP_PROVIDER.into(),
            original_volume: OTHER_VOLUME.into(),
        });
        assert!(refusal(&holds).contains("It holds 2 shadow copies"));

        // No answer, the first time or the second.
        let veto = 0x8004_230fu32 as i32;
        for answers in [(veto, S_OK), (S_OK, veto), (E_UNEXPECTED, E_UNEXPECTED)] {
            let mut silent = clear();
            silent.providers.push(backup_provider(Some(answers)));
            silent.shadow_copy_query_hresult = Some(S_FALSE);
            let said = refusal(&silent);
            assert!(
                said.contains("Some Backup VSS Provider") && said.contains("did not answer"),
                "{said}"
            );
        }
        let said = {
            let mut silent = clear();
            silent.providers.push(backup_provider(Some((veto, S_OK))));
            silent.shadow_copy_query_hresult = Some(S_FALSE);
            refusal(&silent)
        };
        assert!(said.contains("0x8004230f and 0x00000000"), "{said}");

        // The machine's shadow copies were not listed, or not asked for.
        for listed in [Some(0x8004_2302u32 as i32), None] {
            let mut unlisted = clear();
            unlisted.providers.push(backup_provider(Some((S_OK, S_OK))));
            unlisted.shadow_copy_query_hresult = listed;
            let said = refusal(&unlisted);
            assert!(
                said.contains("did not list the machine's shadow copies")
                    && said.contains(if listed.is_some() {
                        "0x80042302"
                    } else {
                        "none"
                    }),
                "{said}"
            );
        }

        // A shadow copy of the volume itself on the list, which Windows did
        // not report when asked about the volume.
        let mut unreported = admitted.clone();
        unreported.shadow_copies.push(ShadowCopy {
            id: "dddddddd".into(),
            provider_id: BACKUP_PROVIDER.into(),
            original_volume: "VOLUME".into(),
        });
        let said = refusal(&unreported);
        assert!(
            said.contains("{dddddddd}") && said.contains("did not report"),
            "{said}"
        );

        // Windows' own provider under another kind is not the one known,
        // and no other may stand in for it.
        let mut odd = clear();
        odd.providers[0].kind = 2;
        odd.providers[0].storage_role = UNKNOWN_ROLE;
        odd.providers[0].asked = backup_provider(Some((S_OK, S_OK))).asked;
        odd.shadow_copy_query_hresult = Some(S_FALSE);
        let said = refusal(&odd);
        assert!(
            said.contains("Windows' own shadow-copy provider is missing"),
            "{said}"
        );
        // A role of a known provider on one that is not it does not pass.
        let mut posing = clear();
        posing.providers.push(Provider {
            storage_role: "hyperv_host_vm_image",
            ..backup_provider(Some((S_OK, S_OK)))
        });
        posing.shadow_copy_query_hresult = Some(S_FALSE);
        assert!(refusal(&posing).contains("was not asked"));
    }

    fn clear() -> Observation {
        Observation {
            schema_version: 1,
            kind: "test",
            source_volume_guid: "volume".into(),
            snapshot_context: 0,
            completed_snapshot_count_all_volumes: Some(0),
            source_snapshot_presence: SourceSnapshotPresence {
                api: "IsVolumeSnapshotted",
                scope: "source",
                hresult: S_OK,
                snapshots_present: false,
                compatibility_flags: 0,
            },
            providers: vec![Provider {
                id: guid(SOFTWARE_PROVIDER),
                class_id: String::new(),
                name: "Microsoft Software Shadow Copy provider 1.0".into(),
                kind: 1,
                version: "1.0.0.7".into(),
                hosted_diff_areas_query_completed: true,
                storage_role: "guest_local_differential_storage",
                asked: None,
            }],
            hosted_diff_areas: Vec::new(),
            hosted_diff_area_query_hresult: Some(S_OK),
            hosted_storage_enumerated: true,
            completed_catalog_enumeration: true,
            provider_inventory_completed: true,
            shadow_copy_query_hresult: None,
            shadow_copies: Vec::new(),
            inflight_snapshot_operations_excluded: false,
            source_exclusion_proven: false,
            execution_authorized: false,
        }
    }

    #[test]
    fn a_shadow_copy_refusal_says_which_condition_it_met() {
        clear().require_observed_catalog_clear().unwrap();

        let mut snapshots = clear();
        snapshots.source_snapshot_presence.snapshots_present = true;
        let refusal = snapshots
            .require_observed_catalog_clear()
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("has shadow copies") && refusal.contains("vssadmin delete shadows"),
            "{refusal}"
        );

        // A provider of a backup product that was not asked anything:
        // named, and the volume is said to be clear.
        let mut provider = clear();
        provider.providers.push(backup_provider(None));
        let refusal = provider
            .require_observed_catalog_clear()
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("Some Backup VSS Provider")
                && refusal.contains("11111111-2222-3333-4444-555555555555")
                && refusal.contains("was not asked")
                && refusal.contains("The volume itself has no shadow copies"),
            "{refusal}"
        );

        // What every Windows Server has beside Windows' own: the provider for
        // remote file shares, which keeps nothing on a local volume.
        let mut server = clear();
        server.providers.push(Provider {
            id: guid(FILESHARE_PROVIDER),
            class_id: guid(FILESHARE_CLASS),
            name: "Microsoft File Share Shadow Copy provider".into(),
            kind: 4,
            version: "1.0.0.1".into(),
            hosted_diff_areas_query_completed: false,
            storage_role: "remote_file_share_no_local_storage",
            asked: None,
        });
        server.require_observed_catalog_clear().unwrap();
        // Known by identity, class and kind together.
        assert_eq!(
            known_storage_role(FILESHARE_PROVIDER, FILESHARE_CLASS, 4),
            Some("remote_file_share_no_local_storage")
        );
        assert_eq!(
            guid(FILESHARE_PROVIDER),
            "89300202-3cec-4981-9171-19f59559e0f2"
        );
        assert_eq!(
            known_storage_role(FILESHARE_PROVIDER, FILESHARE_CLASS, 2),
            None
        );
        assert_eq!(
            known_storage_role(FILESHARE_PROVIDER, HYPERV_CLASS, 4),
            None
        );
        assert_eq!(known_storage_role(NULL_GUID, FILESHARE_CLASS, 4), None);

        // Snapshot storage of another volume kept on this one.
        let mut storage = clear();
        storage.hosted_diff_areas.push(HostedDiffArea {
            provider_id: guid(SOFTWARE_PROVIDER),
            original_volume: "\\\\?\\Volume{other}\\".into(),
            storage_volume: "volume".into(),
            maximum_bytes: 1 << 30,
            allocated_bytes: 1 << 20,
            used_bytes: 4096,
        });
        let refusal = storage
            .require_observed_catalog_clear()
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("stores shadow copies of"), "{refusal}");

        let mut unanswered = clear();
        unanswered.source_snapshot_presence.hresult = 0x8004_2301u32 as i32;
        let refusal = unanswered
            .require_observed_catalog_clear()
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("did not say plainly"), "{refusal}");
    }
}
