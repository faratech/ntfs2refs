//! Read-only, bounded VSS catalog observation. This does not exclude in-flight
//! snapshot operations, freeze a volume, or authorize conversion/recovery.
//!
//! ABI declarations follow Windows SDK 10.0.26100.0 `vsbackup.h`, `vss.h`, and
//! `vsmgmt.h`. A complete VSS_CTX_ALL provider inventory must contain only the
//! Microsoft system provider and optional known Hyper-V host integration. The
//! supported requester IsVolumeSnapshotted API
//! checks the source, and management enumerates differential storage hosted on it.
//! No services, COM process security defaults, snapshots, or disk flags change.
//! COM calls are synchronous: enumeration/storage bounds are not a wall timeout.
//!
//! Contracts: https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-ivssbackupcomponents-query
//! https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-isvolumesnapshotted
//! https://learn.microsoft.com/windows/win32/api/vsmgmt/nf-vsmgmt-ivssdifferentialsoftwaresnapshotmgmt-querydiffareasonvolume
use serde::Serialize;
use std::{ffi::c_void, io, marker::PhantomData, mem, ptr, rc::Rc};

const MAX_OBJECTS: usize = 4096;
const MAX_STRING_UNITS: usize = 1024;
const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
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
    pub inflight_snapshot_operations_excluded: bool,
    pub source_exclusion_proven: bool,
    pub execution_authorized: bool,
}
impl Observation {
    /// A source-presence/storage observation only. Callers must separately own and
    /// bind source freeze/exclusion; this is not a global VSS serialization lease.
    pub fn require_observed_catalog_clear(&self) -> io::Result<()> {
        self.require_observed_snapshot_absence()?;
        if !self.hosted_storage_enumerated
            || !matches!(self.hosted_diff_area_query_hresult, Some(S_OK | S_FALSE))
            || self
                .providers
                .iter()
                .any(|p| p.id == guid(SOFTWARE_PROVIDER) && !p.hosted_diff_areas_query_completed)
            || !self.hosted_diff_areas.is_empty()
        {
            return Err(invalid(
                "VSS hosted differential storage is not completely observed and clear",
            ));
        }
        Ok(())
    }

    pub fn require_observed_snapshot_absence(&self) -> io::Result<()> {
        if !self.provider_inventory_completed
            || !(1..=2).contains(&self.providers.len())
            || self
                .providers
                .iter()
                .filter(|p| p.id == guid(SOFTWARE_PROVIDER))
                .count()
                != 1
            || self.providers.iter().any(|p| {
                if p.id == guid(SOFTWARE_PROVIDER) {
                    p.kind != 1 || p.storage_role != "guest_local_differential_storage"
                } else {
                    p.id != guid(HYPERV_PROVIDER)
                        || p.class_id != guid(HYPERV_CLASS)
                        || p.kind != 2
                        || p.storage_role != "hyperv_host_vm_image"
                }
            })
            || self.source_snapshot_presence.hresult != S_OK
            || self.source_snapshot_presence.snapshots_present
            || self.source_snapshot_presence.compatibility_flags != 0
        {
            return Err(invalid(
                "VSS source-presence/storage observation is not clear for the source volume",
            ));
        }
        Ok(())
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

/// Query source snapshot presence and hosted storage without mutation. Only a
/// fully enumerated Microsoft system provider, optionally accompanied by the
/// known Hyper-V host-integration provider, is supported. Other providers refuse.
/// No aggregate snapshot Query S_FALSE is translated to absence. All enumerators
/// must terminate with the exact SDK S_FALSE/zero-fetched completion result.
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
    let mut areas = Vec::new();
    while let Some(item) = next_object(&provider_enum, PROVIDER, &api)? {
        count(&mut total)?;
        // SAFETY: next_object checked the union discriminator.
        let provider = unsafe { item.object.provider };
        let provider_id = guid(provider.id);
        let name = wide_string(provider.name)?;
        let version = wide_string(provider.version)?;
        let system = provider.id == SOFTWARE_PROVIDER && provider.kind == 1;
        let hyperv =
            provider.id == HYPERV_PROVIDER && provider.class == HYPERV_CLASS && provider.kind == 2;
        if !(system || hyperv)
            || provider.class == NULL_GUID
            || providers.iter().any(|p: &Provider| p.id == provider_id)
            || providers.len() >= 2
        {
            return Err(invalid(format!(
                "unsupported VSS provider inventory: provider={provider_id}, class={}, kind={}; unknown provider coverage is refused",
                guid(provider.class),
                provider.kind,
            )));
        }
        providers.push(Provider {
            id: provider_id,
            class_id: guid(provider.class),
            name,
            kind: provider.kind,
            version,
            hosted_diff_areas_query_completed: false,
            storage_role: if system {
                "guest_local_differential_storage"
            } else {
                "hyperv_host_vm_image"
            },
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
            completed_snapshot_count_all_volumes: None,
            source_snapshot_presence,
            providers,
            hosted_diff_areas: Vec::new(),
            hosted_diff_area_query_hresult: None,
            hosted_storage_enumerated: false,
            completed_catalog_enumeration: false,
            provider_inventory_completed: true,
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
        completed_snapshot_count_all_volumes: None,
        source_snapshot_presence,
        providers,
        hosted_diff_areas: areas,
        hosted_diff_area_query_hresult: Some(hr),
        hosted_storage_enumerated: true,
        completed_catalog_enumeration: false,
        provider_inventory_completed: true,
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
        return Err(invalid("VSS catalog exceeds bounded object budget"));
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
