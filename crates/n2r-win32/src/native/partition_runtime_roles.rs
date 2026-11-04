//! Fresh readonly VDS software-provider volume-role facts. Not an issuer.
//! ABI: SDK10.0.26100.0 um/vds.h. Existing dependencies have no VDS binding;
//! use the same small ole32/IUnknown ownership pattern as vss_observation.rs.
//! No refresh, disk/volume lifecycle method, data read/write or setter is called.
//! COM activation may load local VDS/providers; synchronous COM has no wall bound.
//! Returned-object/count/string bounds are not a quota on COM/server allocations.
//!
//! VDS flags describe VDS volume properties, not undocumented dump-driver state:
//! https://learn.microsoft.com/windows/win32/api/vds/ne-vds-vds_volume_flag
//! https://learn.microsoft.com/windows/win32/api/vds/ns-vds-vds_volume_prop
//! https://learn.microsoft.com/windows/win32/vds/loading-vds
//! https://learn.microsoft.com/windows/win32/vds/vds-object-model
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::{NativeEvent, VOLUME_EXTENTS, control, device_file};
use serde::Serialize;
use std::{ffi::c_void, io, marker::PhantomData, mem, ptr, rc::Rc};

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const VDS_S_PROPERTIES_INCOMPLETE: i32 = 0x0004_2715;
const KNOWN_FLAGS: u32 = 0x03ff_ffff;
const CRITICAL_FLAGS: u32 = 0x1 | 0x2 | 0x80 | 0x100 | 0x200 | 0x0100_0000;
const MAX_EXTENTS: usize = 16;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}
fn hr(operation: &str, value: i32) -> io::Error {
    io::Error::other(format!(
        "{operation} returned HRESULT0x{:08x}",
        value as u32
    ))
}
fn exact(operation: &str, value: i32) -> io::Result<()> {
    if value == S_OK {
        Ok(())
    } else {
        Err(hr(operation, value))
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
impl Guid {
    fn bytes(self) -> [u8; 16] {
        let mut out = [0; 16];
        out[..4].copy_from_slice(&self.a.to_le_bytes());
        out[4..6].copy_from_slice(&self.b.to_le_bytes());
        out[6..8].copy_from_slice(&self.c.to_le_bytes());
        out[8..].copy_from_slice(&self.d);
        out
    }
}
const LOADER_CLASS: Guid = Guid {
    a: 0x9c38ed61,
    b: 0xd565,
    c: 0x4728,
    d: [0xae, 0xee, 0xc8, 0x09, 0x52, 0xf0, 0xec, 0xde],
};
const LOADER_IID: Guid = Guid {
    a: 0xe0393303,
    b: 0x90d4,
    c: 0x4a97,
    d: [0xab, 0x71, 0xe9, 0xb6, 0x71, 0xee, 0x27, 0x29],
};
const PROVIDER_IID: Guid = Guid {
    a: 0x10c5e575,
    b: 0x7984,
    c: 0x4e81,
    d: [0xa5, 0x6b, 0x43, 0x1f, 0x5f, 0x92, 0xae, 0x42],
};
const SOFTWARE_IID: Guid = Guid {
    a: 0x9aa58360,
    b: 0xce33,
    c: 0x4f92,
    d: [0xb6, 0x58, 0xed, 0x24, 0xb1, 0x44, 0x25, 0xb8],
};
const PACK_IID: Guid = Guid {
    a: 0x3b69d7f5,
    b: 0x9d94,
    c: 0x4648,
    d: [0x91, 0xca, 0x79, 0x93, 0x9b, 0xa2, 0x63, 0xbf],
};
const VOLUME_IID: Guid = Guid {
    a: 0x88306bb2,
    b: 0xe71f,
    c: 0x478c,
    d: [0x86, 0xa2, 0x79, 0xda, 0x20, 0x0a, 0x0f, 0x11],
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
#[repr(C)]
struct UnknownVtable {
    query: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
    _add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
struct Unknown {
    vtable: *const UnknownVtable,
}
#[repr(C)]
struct Loader {
    vtable: *const LoaderVtable,
}
#[repr(C)]
struct LoaderVtable {
    unknown: UnknownVtable,
    load: unsafe extern "system" fn(*mut Loader, *mut u16, *mut *mut Service) -> i32,
}
#[repr(C)]
struct Service {
    vtable: *const ServiceVtable,
}
#[repr(C)]
struct ServiceVtable {
    unknown: UnknownVtable,
    is_ready: unsafe extern "system" fn(*mut Service) -> i32,
    wait_ready: unsafe extern "system" fn(*mut Service) -> i32,
    _get_properties: usize,
    query_providers: unsafe extern "system" fn(*mut Service, u32, *mut *mut Enumeration) -> i32,
}
#[repr(C)]
struct Enumeration {
    vtable: *const EnumerationVtable,
}
#[repr(C)]
struct EnumerationVtable {
    unknown: UnknownVtable,
    next: unsafe extern "system" fn(*mut Enumeration, u32, *mut *mut Unknown, *mut u32) -> i32,
}
#[repr(C)]
struct Provider {
    vtable: *const ProviderVtable,
}
#[repr(C)]
struct ProviderVtable {
    unknown: UnknownVtable,
    properties: unsafe extern "system" fn(*mut Provider, *mut ProviderRaw) -> i32,
}
#[repr(C)]
struct Software {
    vtable: *const SoftwareVtable,
}
#[repr(C)]
struct SoftwareVtable {
    unknown: UnknownVtable,
    packs: unsafe extern "system" fn(*mut Software, *mut *mut Enumeration) -> i32,
}
#[repr(C)]
struct Pack {
    vtable: *const PackVtable,
}
#[repr(C)]
struct PackVtable {
    unknown: UnknownVtable,
    properties: unsafe extern "system" fn(*mut Pack, *mut PackRaw) -> i32,
    _get_provider: usize,
    volumes: unsafe extern "system" fn(*mut Pack, *mut *mut Enumeration) -> i32,
}
#[repr(C)]
struct Volume {
    vtable: *const VolumeVtable,
}
#[repr(C)]
struct VolumeVtable {
    unknown: UnknownVtable,
    properties: unsafe extern "system" fn(*mut Volume, *mut VolumeRaw) -> i32,
}
#[repr(C)]
struct ProviderRaw {
    id: Guid,
    name: *mut u16,
    version_id: Guid,
    version: *mut u16,
    kind: i32,
    flags: u32,
    stripe_flags: u32,
    rebuild_priority: i16,
}
#[repr(C)]
struct PackRaw {
    id: Guid,
    name: *mut u16,
    status: i32,
    flags: u32,
}
#[repr(C)]
struct VolumeRaw {
    id: Guid,
    kind: i32,
    status: i32,
    health: i32,
    transition: i32,
    size: u64,
    flags: u32,
    recommended_fs: i32,
    name: *mut u16,
}
impl Drop for ProviderRaw {
    fn drop(&mut self) {
        // SAFETY: only VDS GetProperties writes these CoTaskMem-owned pointers.
        unsafe {
            CoTaskMemFree(self.name.cast());
            CoTaskMemFree(self.version.cast());
        }
    }
}
impl Drop for PackRaw {
    fn drop(&mut self) {
        // SAFETY: only VDS GetProperties writes this CoTaskMem-owned pointer.
        unsafe {
            CoTaskMemFree(self.name.cast());
        }
    }
}
impl Drop for VolumeRaw {
    fn drop(&mut self) {
        // SAFETY: only VDS GetProperties writes this CoTaskMem-owned pointer.
        unsafe {
            CoTaskMemFree(self.name.cast());
        }
    }
}
// Exact SDK x64 ABI. This experimental owner is not an x86 implementation.
const _: () = assert!(
    mem::size_of::<ProviderRaw>() == 64
        && mem::size_of::<PackRaw>() == 32
        && mem::size_of::<VolumeRaw>() == 56
        && mem::offset_of!(VolumeRaw, name) == 48
);
struct Apartment {
    _thread: PhantomData<Rc<()>>,
}
impl Apartment {
    fn new() -> io::Result<Self> {
        // SAFETY: this thread initializes only its own MTA; no COM security defaults change.
        let value = unsafe { CoInitializeEx(ptr::null_mut(), 0) };
        if value == S_OK || value == S_FALSE {
            Ok(Self {
                _thread: PhantomData,
            })
        } else {
            Err(hr("CoInitializeEx", value))
        }
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: balances the successful initialization on this same thread.
        unsafe {
            CoUninitialize();
        }
    }
}
struct Com<T> {
    raw: *mut T,
    _thread: PhantomData<Rc<()>>,
}
impl<T> Com<T> {
    fn returned(raw: *mut T, value: i32, operation: &str) -> io::Result<Self> {
        let owner = (!raw.is_null()).then(|| Self {
            raw,
            _thread: PhantomData,
        });
        exact(operation, value)?;
        owner.ok_or_else(|| invalid("VDS returned a null successful interface"))
    }
    fn query<U>(&self, iid: &Guid) -> io::Result<Com<U>> {
        let mut raw = ptr::null_mut();
        // SAFETY: all private interface types start with the SDK IUnknown prefix;
        // iid is the fixed documented IID corresponding to U at each call site.
        let value = unsafe {
            let vtable = *(self.raw.cast::<*const UnknownVtable>());
            ((*vtable).query)(self.raw.cast(), iid, &mut raw)
        };
        Com::returned(raw.cast(), value, "VDS QueryInterface")
    }
}
impl<T> Drop for Com<T> {
    fn drop(&mut self) {
        // SAFETY: one owned reference from COM; prefix ABI is IUnknown on this thread.
        unsafe {
            let vtable = *(self.raw.cast::<*const UnknownVtable>());
            ((*vtable).release)(self.raw.cast());
        }
    }
}
struct Limits {
    objects: usize,
    maximum_objects: usize,
    retained_bytes: u64,
    maximum_bytes: u64,
    maximum_units: usize,
}
impl Limits {
    fn object(&mut self) -> io::Result<()> {
        self.objects = self
            .objects
            .checked_add(1)
            .ok_or_else(|| invalid("VDS object count overflow"))?;
        require(
            self.objects <= self.maximum_objects,
            "VDS provider/pack/volume enumeration exceeds admitted object budget",
        )?;
        self.charge(1024)
    }
    fn charge(&mut self, bytes: u64) -> io::Result<()> {
        self.retained_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("VDS metadata accounting overflow"))?;
        require(
            self.retained_bytes <= self.maximum_bytes,
            "VDS returned metadata exceeds admitted RAM share",
        )
    }
    fn string(&mut self, pointer: *const u16, optional: bool) -> io::Result<String> {
        if pointer.is_null() {
            return if optional {
                Ok(String::new())
            } else {
                Err(invalid("VDS volume/provider name is missing"))
            };
        }
        let mut count = 0;
        while count < self.maximum_units {
            // SAFETY: SDK GetProperties returns an allocated NUL-terminated string;
            // scan is bounded and ends before freeing its owning Raw structure.
            if unsafe { *pointer.add(count) } == 0 {
                break;
            }
            count += 1;
        }
        require(
            count < self.maximum_units,
            "VDS string exceeds the admitted UTF-16 bound",
        )?;
        self.charge(
            (count as u64)
                .checked_mul(8)
                .ok_or_else(|| invalid("VDS string accounting overflow"))?,
        )?;
        // SAFETY: the bounded scan established this initialized string prefix.
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, count) })
            .map_err(|_| invalid("VDS property contains invalid UTF-16"))?;
        require(
            optional || !value.is_empty(),
            "VDS required string is empty",
        )?;
        Ok(value)
    }
}
fn next(enumeration: &Com<Enumeration>, limits: &mut Limits) -> io::Result<Option<Com<Unknown>>> {
    let mut object = ptr::null_mut();
    let mut fetched = 0;
    // SAFETY: exactly one initialized output slot; synchronous enumerator call.
    let value = unsafe {
        ((*(*enumeration.raw).vtable).next)(enumeration.raw, 1, &mut object, &mut fetched)
    };
    let owner = (!object.is_null()).then(|| Com {
        raw: object,
        _thread: PhantomData,
    });
    if value == S_FALSE && fetched == 0 && owner.is_none() {
        return Ok(None);
    }
    exact("IEnumVdsObject::Next", value)?;
    require(
        fetched == 1 && owner.is_some(),
        "VDS enumeration returned an ambiguous object count",
    )?;
    limits.object()?;
    Ok(owner)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct VdsExtent {
    pub disk_number: u32,
    pub offset: u64,
    pub length: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct VdsVolumeRoles {
    pub provider_id: [u8; 16],
    pub pack_id: [u8; 16],
    pub volume_id: [u8; 16],
    pub volume_name: Option<String>,
    pub volume_type: i32,
    pub status: i32,
    pub health: i32,
    pub transition: i32,
    pub size_bytes: u64,
    pub vds_flags: u32,
    pub critical_flags: u32,
    pub properties_hresult: i32,
    pub closing_properties_hresult: i32,
    pub role_classification_qualified: bool,
    pub reported_online_healthy_stable: bool,
    pub extents: Option<Vec<VdsExtent>>,
    pub extent_observation_note: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct VdsProviderFacts {
    pub id: [u8; 16],
    pub name: String,
    pub version_id: [u8; 16],
    pub version: String,
    pub flags: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct VdsPackFacts {
    pub provider_id: [u8; 16],
    pub id: [u8; 16],
    pub name: String,
    pub status: i32,
    pub flags: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct RuntimeVolumeRoleObservation {
    pub software_providers: Vec<VdsProviderFacts>,
    pub packs: Vec<VdsPackFacts>,
    pub volumes: Vec<VdsVolumeRoles>,
    pub vds_enumeration_completed: bool,
    pub vds_critical_role_extents_outside_target: bool,
    pub vds_system_volume_count: u64,
    pub vds_boot_volume_count: u64,
    pub accounted_metadata_bytes: u64,
    pub vds_flags_are_not_undocumented_loaded_driver_state: bool,
    pub serialized_observation_grants_authority: bool,
}
impl RuntimeVolumeRoleObservation {
    /// Compare the security-relevant role binding, not full telemetry equality.
    /// All provider/pack/volume identities and critical classifications must
    /// persist; critical volumes and their packs retain exact properties/maps.
    /// Noncritical volume availability, names, size/type and noncritical flag
    /// changes, noncritical-pack availability, and accounting samples are
    /// deliberately ignored. Raw observations retain their derived full Eq.
    pub(super) fn same_critical_roles(&self, other: &Self) -> bool {
        self.vds_enumeration_completed
            && other.vds_enumeration_completed
            && self.vds_critical_role_extents_outside_target
            && other.vds_critical_role_extents_outside_target
            && self.software_providers == other.software_providers
            && self.vds_system_volume_count == other.vds_system_volume_count
            && self.vds_boot_volume_count == other.vds_boot_volume_count
            && self.packs.len() == other.packs.len()
            && self.volumes.len() == other.volumes.len()
            && self.packs.iter().zip(&other.packs).all(|(a, b)| {
                a.id == b.id
                    && a.provider_id == b.provider_id
                    && (!self
                        .volumes
                        .iter()
                        .any(|volume| volume.pack_id == a.id && volume.critical_flags != 0)
                        || a == b)
            })
            && self.volumes.iter().zip(&other.volumes).all(|(a, b)| {
                a.provider_id == b.provider_id
                    && a.pack_id == b.pack_id
                    && a.volume_id == b.volume_id
                    && a.critical_flags == b.critical_flags
                    && (a.critical_flags == 0 || a == b)
            })
    }
}
fn volume_path(name: &str) -> io::Result<String> {
    require(
        !name.contains('\0') && !name.ends_with(' '),
        "VDS volume name is malformed",
    )?;
    if name.starts_with(r"\\?\GLOBALROOT\Device\HarddiskVolume") {
        let suffix = &name[r"\\?\GLOBALROOT\Device\HarddiskVolume".len()..];
        require(
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()),
            "Unsupported VDS device-name suffix",
        )?;
        Ok(name.into())
    } else if name.starts_with(r"\\?\Volume{") {
        let value = name.trim_end_matches('\\');
        require(
            value.ends_with('}')
                && crate::layout::guid_bytes(&value[11..value.len() - 1])? != [0; 16],
            "Invalid VDS volume GUID",
        )?;
        Ok(value.into())
    } else {
        Err(invalid(
            "VDS volume has no supported exact local device/GUID route",
        ))
    }
}
fn extents(
    name: &str,
    flags: u32,
    binding: &PartitionSourceBinding,
    events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<VdsExtent>> {
    let file = device_file(&volume_path(name)?, false, false)?;
    let raw = control(
        &file,
        "partition-vds-volume-role-extents",
        VOLUME_EXTENTS,
        &[],
        8 + 24 * MAX_EXTENTS,
        events,
    )?;
    require(raw.len() >= 8, "VDS volume extent response incomplete")?;
    let count = crate::layout::u32_at(&raw, 0)? as usize;
    require(
        count > 0 && count <= MAX_EXTENTS && raw.len() == 8 + count * 24,
        "VDS volume extents incomplete or unbounded",
    )?;
    let target = &binding.storage.identity;
    let target_end = target
        .partition_offset
        .checked_add(target.partition_bytes)
        .ok_or_else(|| invalid("Selected extent overflow"))?;
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(io::Error::other)?;
    for i in 0..count {
        let at = 8 + i * 24;
        let value = VdsExtent {
            disk_number: crate::layout::u32_at(&raw, at)?,
            offset: crate::layout::u64_at(&raw, at + 8)?,
            length: crate::layout::u64_at(&raw, at + 16)?,
        };
        let end = value
            .offset
            .checked_add(value.length)
            .ok_or_else(|| invalid("VDS volume extent overflow"))?;
        require(
            value.length > 0
                && end <= i64::MAX as u64
                && value.offset.is_multiple_of(512)
                && value.length.is_multiple_of(512),
            "VDS volume has invalid physical extent",
        )?;
        require(
            flags & CRITICAL_FLAGS == 0
                || value.disk_number != binding.storage.disk_number
                || value.offset >= target_end
                || end <= target.partition_offset,
            "A VDS boot/system/pagefile/hibernation/crashdump role overlaps selected partition",
        )?;
        result.push(value);
    }
    result.sort_by_key(|value| (value.disk_number, value.offset, value.length));
    require(
        !result.windows(2).any(|pair| {
            pair[0].disk_number == pair[1].disk_number
                && pair[0].offset + pair[0].length > pair[1].offset
        }),
        "Ambiguous overlapping VDS volume extents",
    )?;
    Ok(result)
}

pub(super) fn observe_runtime_volume_roles(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<RuntimeVolumeRoleObservation> {
    binding.validate()?;
    budget.validate()?;
    require(
        mem::size_of::<usize>() == 8 && events.len() < 126,
        "VDS role collector requires x64 and native event capacity",
    )?;
    let share = budget.ram_bytes / 4;
    let maximum_objects =
        usize::try_from(share / 8192).map_err(|_| invalid("VDS object budget overflow"))?;
    require(maximum_objects > 0, "VDS has no admitted object workspace")?;
    let mut limits = Limits {
        objects: 0,
        maximum_objects,
        retained_bytes: 0,
        maximum_bytes: share,
        maximum_units: usize::try_from((share / 32).min(32768))
            .map_err(|_| invalid("VDS string bound overflow"))?,
    };
    let _apartment = Apartment::new()?;
    let mut loader = ptr::null_mut();
    // SAFETY: fixed documented local VDS loader CLSID/IID, no remote host or aggregation.
    let value =
        unsafe { CoCreateInstance(&LOADER_CLASS, ptr::null_mut(), 4, &LOADER_IID, &mut loader) };
    let loader: Com<Loader> = Com::returned(loader.cast(), value, "CoCreateInstance(VdsLoader)")?;
    let mut service = ptr::null_mut();
    // SAFETY: live loader and local-host(NULL) synchronous output interface slot.
    let value =
        unsafe { ((*(*loader.raw).vtable).load)(loader.raw, ptr::null_mut(), &mut service) };
    let service = Com::returned(service, value, "IVdsServiceLoader::LoadService(local)")?;
    // SAFETY: documented readiness queries only; no Refresh/Reenumerate is invoked.
    exact("IVdsService::WaitForServiceReady", unsafe {
        ((*(*service.raw).vtable).wait_ready)(service.raw)
    })?;
    exact("IVdsService::IsServiceReady", unsafe {
        ((*(*service.raw).vtable).is_ready)(service.raw)
    })?;
    let mut providers = ptr::null_mut();
    // SAFETY: software providers own the VDS pack/volume hierarchy; mask1 is SDK VDS_QUERY_SOFTWARE_PROVIDERS.
    let value =
        unsafe { ((*(*service.raw).vtable).query_providers)(service.raw, 1, &mut providers) };
    let providers = Com::returned(providers, value, "IVdsService::QueryProviders(software)")?;
    let mut result = RuntimeVolumeRoleObservation {
        software_providers: Vec::new(),
        packs: Vec::new(),
        volumes: Vec::new(),
        vds_enumeration_completed: false,
        vds_critical_role_extents_outside_target: false,
        vds_system_volume_count: 0,
        vds_boot_volume_count: 0,
        accounted_metadata_bytes: 0,
        vds_flags_are_not_undocumented_loaded_driver_state: true,
        serialized_observation_grants_authority: false,
    };
    while let Some(provider) = next(&providers, &mut limits)? {
        let properties: Com<Provider> = provider.query(&PROVIDER_IID)?;
        // SAFETY: these repr(C) structs contain only integers/GUIDs/null pointers;
        // zero is valid and Drop frees even partially returned property strings.
        let mut raw: ProviderRaw = unsafe { mem::zeroed() };
        exact("IVdsProvider::GetProperties", unsafe {
            ((*(*properties.raw).vtable).properties)(properties.raw, &mut raw)
        })?;
        require(
            raw.kind == 1 && raw.id.bytes() != [0; 16],
            "VDS provider is not a complete software provider",
        )?;
        let provider_id = raw.id.bytes();
        let provider_fact = VdsProviderFacts {
            id: provider_id,
            name: limits.string(raw.name, false)?,
            version_id: raw.version_id.bytes(),
            version: limits.string(raw.version, false)?,
            flags: raw.flags,
        };
        require(
            !result
                .software_providers
                .iter()
                .any(|value| value.id == provider_id),
            "Duplicate VDS provider identity",
        )?;
        result.software_providers.push(provider_fact);
        let software: Com<Software> = provider.query(&SOFTWARE_IID)?;
        let mut packs = ptr::null_mut();
        // SAFETY: live software provider, initialized enum output slot.
        let value = unsafe { ((*(*software.raw).vtable).packs)(software.raw, &mut packs) };
        let packs = Com::returned(packs, value, "IVdsSwProvider::QueryPacks")?;
        while let Some(pack) = next(&packs, &mut limits)? {
            let pack: Com<Pack> = pack.query(&PACK_IID)?;
            // SAFETY: valid zero initialization of this C output/ownership struct.
            let mut raw: PackRaw = unsafe { mem::zeroed() };
            exact("IVdsPack::GetProperties", unsafe {
                ((*(*pack.raw).vtable).properties)(pack.raw, &mut raw)
            })?;
            require(
                raw.id.bytes() != [0; 16] && matches!(raw.status, 1 | 4) && raw.flags & !0x1f == 0,
                "Unknown/incomplete VDS pack properties",
            )?;
            let pack_id = raw.id.bytes();
            require(
                !result.packs.iter().any(|value| value.id == pack_id),
                "Duplicate VDS pack identity",
            )?;
            result.packs.push(VdsPackFacts {
                provider_id,
                id: pack_id,
                name: limits.string(raw.name, true)?,
                status: raw.status,
                flags: raw.flags,
            });
            let mut volumes = ptr::null_mut();
            // SAFETY: live pack, initialized enum output slot.
            let value = unsafe { ((*(*pack.raw).vtable).volumes)(pack.raw, &mut volumes) };
            let volumes = Com::returned(volumes, value, "IVdsPack::QueryVolumes")?;
            while let Some(volume) = next(&volumes, &mut limits)? {
                let volume: Com<Volume> = volume.query(&VOLUME_IID)?;
                // SAFETY: valid zero initialization; returned pwszName always has a Drop owner.
                let mut raw: VolumeRaw = unsafe { mem::zeroed() };
                let properties_hr =
                    unsafe { ((*(*volume.raw).vtable).properties)(volume.raw, &mut raw) };
                require(
                    matches!(properties_hr, S_OK | VDS_S_PROPERTIES_INCOMPLETE),
                    &format!(
                        "IVdsVolume::GetProperties diagnostic HRESULT0x{:08x}",
                        properties_hr as u32
                    ),
                )?;
                let complete = properties_hr == S_OK;
                require(
                    !complete || (raw.id.bytes() != [0; 16] && raw.flags & !KNOWN_FLAGS == 0),
                    "VDS volume identity or known role classification is unavailable",
                )?;
                let critical = complete && raw.flags & CRITICAL_FLAGS != 0;
                let available =
                    complete && raw.status == 1 && raw.health == 1 && raw.transition == 1;
                if critical {
                    require(
                        raw.size > 0 && matches!(raw.kind, 10..=14) && available,
                        "Critical VDS role has unknown, unstable or unavailable properties",
                    )?;
                }
                let name = limits.string(raw.name, !critical)?;
                let name = (!name.is_empty()).then_some(name);
                require(
                    !result.volumes.iter().any(|value| {
                        value.volume_id == raw.id.bytes()
                            || value.volume_name.as_ref().is_some_and(|known| {
                                name.as_ref()
                                    .is_some_and(|name| known.eq_ignore_ascii_case(name))
                            })
                    }),
                    "Duplicate/ambiguous VDS volume identity/name",
                )?;
                let mapped = if critical {
                    require(
                        events.len() < 127,
                        "Critical VDS volume enumeration exceeds native event capacity",
                    )?;
                    let name = name
                        .as_deref()
                        .ok_or_else(|| invalid("Critical VDS role has no native volume name"))?;
                    let mapped = extents(name, raw.flags, binding, events)?;
                    limits.charge((mapped.len() as u64) * mem::size_of::<VdsExtent>() as u64)?;
                    Some(mapped)
                } else {
                    // Frozen shadow/journal/data volumes may be offline. Their
                    // flags/identity remain inventory facts; no missing map is
                    // treated as proof that a critical volume is safe.
                    None
                };
                // SAFETY: same live volume interface; requery properties after native mapping.
                let mut closing: VolumeRaw = unsafe { mem::zeroed() };
                let closing_hr =
                    unsafe { ((*(*volume.raw).vtable).properties)(volume.raw, &mut closing) };
                require(
                    matches!(closing_hr, S_OK | VDS_S_PROPERTIES_INCOMPLETE),
                    &format!(
                        "IVdsVolume::GetProperties(closing) diagnostic HRESULT0x{:08x}",
                        closing_hr as u32
                    ),
                )?;
                let closing_name = limits.string(closing.name, !critical)?;
                let closing_name = (!closing_name.is_empty()).then_some(closing_name);
                require(
                    closing_hr == properties_hr
                        && closing.id.bytes() == raw.id.bytes()
                        && closing.kind == raw.kind
                        && closing.status == raw.status
                        && closing.health == raw.health
                        && closing.transition == raw.transition
                        && closing.size == raw.size
                        && closing.flags == raw.flags
                        && closing.recommended_fs == raw.recommended_fs
                        && closing_name == name,
                    "VDS volume properties changed across native extent observation",
                )?;
                result.vds_system_volume_count += u64::from(complete && raw.flags & 1 != 0);
                result.vds_boot_volume_count += u64::from(complete && raw.flags & 2 != 0);
                result.volumes.push(VdsVolumeRoles {
                    provider_id,
                    pack_id,
                    volume_id: raw.id.bytes(),
                    volume_name: name,
                    volume_type: raw.kind,
                    status: raw.status,
                    health: raw.health,
                    transition: raw.transition,
                    size_bytes: raw.size,
                    vds_flags: raw.flags,
                    critical_flags: raw.flags & CRITICAL_FLAGS,
                    properties_hresult: properties_hr,
                    closing_properties_hresult: closing_hr,
                    role_classification_qualified: complete,
                    reported_online_healthy_stable: available,
                    extents: mapped,
                    extent_observation_note: (!critical).then(|| {
                        if complete {
                            "complete noncritical diagnostic inventory; extents not queried".into()
                        } else {
                            "UNCLASSIFIED partial VDS properties; no role flags are authoritative"
                                .into()
                        }
                    }),
                });
            }
        }
    }
    require(
        !result.software_providers.is_empty()
            && !result.packs.is_empty()
            && !result.volumes.is_empty(),
        "VDS diagnostic enumeration is empty",
    )?;
    result.software_providers.sort_by_key(|value| value.id);
    result.packs.sort_by_key(|value| value.id);
    result.volumes.sort_by_key(|value| value.volume_id);
    result.accounted_metadata_bytes = limits.retained_bytes;
    result.vds_enumeration_completed = true;
    result.vds_critical_role_extents_outside_target = result
        .volumes
        .iter()
        .all(|v| v.role_classification_qualified)
        && result.vds_system_volume_count > 0
        && result.vds_boot_volume_count > 0;
    Ok(result)
}

/// Optional legacy-provider diagnostics. This cannot qualify the current
/// partition role policy; authoritative Storage Management/native checks do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct RuntimeVolumeRoleDiagnostic {
    pub observation: Option<RuntimeVolumeRoleObservation>,
    pub error: Option<String>,
    pub used_as_source_admission_authority: bool,
}
pub(super) fn runtime_volume_role_diagnostics(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> RuntimeVolumeRoleDiagnostic {
    match observe_runtime_volume_roles(binding, budget, events) {
        Ok(observation) => RuntimeVolumeRoleDiagnostic {
            observation: Some(observation),
            error: None,
            used_as_source_admission_authority: false,
        },
        Err(error) => RuntimeVolumeRoleDiagnostic {
            observation: None,
            error: Some(error.to_string().chars().take(4096).collect()),
            used_as_source_admission_authority: false,
        },
    }
}
