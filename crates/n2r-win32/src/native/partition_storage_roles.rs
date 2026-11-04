//! Fresh native WMI Storage Management role facts. No setters or writer issuer.
//! VDS partial properties are deliberately not used by this collector.
use super::partition_isolation::{
    PartitionObservationBudget, PartitionSourceBinding, PartitionVolumeExtent,
};
use super::{NativeEvent, control, device_file};
use crate::layout;
use serde::Serialize;
use std::{
    cell::RefCell,
    ffi::c_void,
    io, ptr,
    time::{Duration, Instant},
};
fn invalid(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}
fn need(v: bool, m: &str) -> io::Result<()> {
    if v { Ok(()) } else { Err(invalid(m)) }
}
fn exact(op: &str, hr: i32) -> io::Result<()> {
    if hr == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{op}: HRESULT0x{:08x}",
            hr as u32
        )))
    }
}
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
const LOCATOR_CLASS: Guid = Guid {
    a: 0x4590f811,
    b: 0x1d3a,
    c: 0x11d0,
    d: [0x89, 0x1f, 0, 0xaa, 0, 0x4b, 0x2e, 0x24],
};
const LOCATOR_IID: Guid = Guid {
    a: 0xdc12a687,
    b: 0x737f,
    c: 0x11cf,
    d: [0x88, 0x4d, 0, 0xaa, 0, 0x4b, 0x2e, 0x24],
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
        out: *mut *mut c_void,
    ) -> i32;
    fn CoInitializeSecurity(
        sd: *mut c_void,
        count: i32,
        services: *mut c_void,
        reserved: *mut c_void,
        authn: u32,
        imp: u32,
        auth: *mut c_void,
        capabilities: u32,
        reserved2: *mut c_void,
    ) -> i32;
    fn CoSetProxyBlanket(
        proxy: *mut c_void,
        authn: u32,
        authz: u32,
        principal: *mut u16,
        level: u32,
        imp: u32,
        identity: *mut c_void,
        capabilities: u32,
    ) -> i32;
}
#[link(name = "oleaut32")]
unsafe extern "system" {
    fn SysAllocStringLen(value: *const u16, length: u32) -> *mut u16;
    fn SysFreeString(value: *mut u16);
    fn SysStringLen(value: *const u16) -> u32;
    fn VariantClear(value: *mut Variant) -> i32;
}
#[repr(C)]
struct UnknownVtable {
    query: usize,
    add: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
struct Locator {
    vtable: *const LocatorVtable,
}
#[repr(C)]
struct LocatorVtable {
    unknown: UnknownVtable,
    connect: unsafe extern "system" fn(
        *mut Locator,
        *mut u16,
        *mut u16,
        *mut u16,
        *mut u16,
        i32,
        *mut u16,
        *mut c_void,
        *mut *mut Services,
    ) -> i32,
}
#[repr(C)]
struct Services {
    vtable: *const ServicesVtable,
}
#[repr(C)]
struct ServicesVtable {
    unknown: UnknownVtable,
    unused: [usize; 17],
    query: unsafe extern "system" fn(
        *mut Services,
        *mut u16,
        *mut u16,
        i32,
        *mut c_void,
        *mut *mut Enumeration,
    ) -> i32,
}
#[repr(C)]
struct Enumeration {
    vtable: *const EnumerationVtable,
}
#[repr(C)]
struct EnumerationVtable {
    unknown: UnknownVtable,
    reset: usize,
    next: unsafe extern "system" fn(*mut Enumeration, i32, u32, *mut *mut Object, *mut u32) -> i32,
}
#[repr(C)]
struct Object {
    vtable: *const ObjectVtable,
}
#[repr(C)]
struct ObjectVtable {
    unknown: UnknownVtable,
    qualifiers: usize,
    get: unsafe extern "system" fn(
        *mut Object,
        *const u16,
        i32,
        *mut Variant,
        *mut i32,
        *mut i32,
    ) -> i32,
}
// Native x64 VARIANT: eight-byte tag/reserved prefix and sixteen-byte union.
#[repr(C)]
struct Variant {
    vt: u16,
    reserved: [u16; 3],
    data: [u64; 2],
}
const _: () = assert!(std::mem::size_of::<Variant>() == 24);
impl Drop for Variant {
    fn drop(&mut self) {
        unsafe {
            VariantClear(self);
        }
    }
}
struct Bstr(*mut u16);
impl Bstr {
    fn new(text: &str) -> io::Result<Self> {
        let v: Vec<u16> = text.encode_utf16().collect();
        need(v.len() <= 512, "WMI input string exceeds bound")?;
        let raw = unsafe { SysAllocStringLen(v.as_ptr(), v.len() as u32) };
        need(!raw.is_null(), "WMI BSTR allocation failed")?;
        Ok(Self(raw))
    }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) }
    }
}
struct Com<T>(*mut T);
impl<T> Com<T> {
    fn returned(raw: *mut T, hr: i32, op: &str) -> io::Result<Self> {
        if !raw.is_null() {
            let value = Self(raw);
            exact(op, hr)?;
            Ok(value)
        } else {
            exact(op, hr)?;
            Err(invalid("WMI succeeded without an interface"))
        }
    }
}
impl<T> Drop for Com<T> {
    fn drop(&mut self) {
        unsafe {
            let vtable = *(self.0.cast::<*const UnknownVtable>());
            ((*vtable).release)(self.0.cast());
        }
    }
}
struct Apartment(bool);
impl Apartment {
    fn new() -> io::Result<Self> {
        let hr = unsafe { CoInitializeEx(ptr::null_mut(), 0) };
        if hr == 0 || hr == 1 {
            Ok(Self(true))
        } else if hr as u32 == 0x80010106 {
            Ok(Self(false))
        } else {
            exact("WMI CoInitializeEx", hr)?;
            unreachable!()
        }
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() }
        }
    }
}
// The connection stays on its actual COM thread. Each observation executes two
// new forward-only queries; this is never a cache of role facts or authority.
struct Session {
    services: Com<Services>,
    _apartment: Apartment,
}
impl Session {
    fn new() -> io::Result<Self> {
        let apartment = Apartment::new()?;
        let hr = unsafe {
            CoInitializeSecurity(
                ptr::null_mut(),
                -1,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                3,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        need(
            hr == 0 || hr as u32 == 0x80010119,
            "WMI COM security initialization failed",
        )?;
        let mut locator = ptr::null_mut();
        let hr = unsafe {
            CoCreateInstance(
                &LOCATOR_CLASS,
                ptr::null_mut(),
                1,
                &LOCATOR_IID,
                &mut locator,
            )
        };
        let locator: Com<Locator> = Com::returned(locator.cast(), hr, "WMI locator")?;
        let namespace = Bstr::new(r"ROOT\Microsoft\Windows\Storage")?;
        let mut services = ptr::null_mut();
        let hr = unsafe {
            ((*(*locator.0).vtable).connect)(
                locator.0,
                namespace.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0x80,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut services,
            )
        };
        let services = Com::returned(services, hr, "WMI ConnectServer(Storage)")?;
        exact("WMI CoSetProxyBlanket", unsafe {
            CoSetProxyBlanket(
                services.0.cast(),
                10,
                0,
                ptr::null_mut(),
                3,
                3,
                ptr::null_mut(),
                0,
            )
        })?;
        Ok(Self {
            services,
            _apartment: apartment,
        })
    }
}
thread_local! {static CONNECTION:RefCell<Option<Session>>=const{RefCell::new(None)};}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct StoragePartitionRole {
    pub disk_number: u32,
    pub partition_number: u32,
    pub guid: [u8; 16],
    pub gpt_type: [u8; 16],
    pub offset: u64,
    pub size: u64,
    pub is_boot: bool,
    pub is_system: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct NativeStoragePartitionRole {
    pub role: StoragePartitionRole,
    pub native_partition_info: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct PartitionStorageRoleObservation {
    pub binding: PartitionSourceBinding,
    pub selected: Option<StoragePartitionRole>,
    pub selected_native_partition_info: Vec<u8>,
    pub selected_is_boot: Option<bool>,
    pub selected_is_system: Option<bool>,
    pub current_windows: NativeStoragePartitionRole,
    pub critical_partitions: Vec<NativeStoragePartitionRole>,
    pub catalog_complete: bool,
    pub queried_disks: Vec<u32>,
}
impl PartitionStorageRoleObservation {
    pub(super) fn same_critical_roles(&self, other: &Self) -> bool {
        // Target type/attributes and its expected mount visibility are controlled by
        // the actual lifecycle. All remaining native identity bytes stay exact.
        fn target(a: &[u8], b: &[u8]) -> bool {
            a.len() == 144
                && b.len() == 144
                && a[..32] == b[..32]
                && a[48..64] == b[48..64]
                && a[72..] == b[72..]
        }
        self.catalog_complete
            && other.catalog_complete
            && self.binding == other.binding
            && self.queried_disks == other.queried_disks
            && self.selected_is_boot != Some(true)
            && other.selected_is_boot != Some(true)
            && self.selected_is_system != Some(true)
            && other.selected_is_system != Some(true)
            && target(
                &self.selected_native_partition_info,
                &other.selected_native_partition_info,
            )
            && self.current_windows == other.current_windows
            && self.critical_partitions == other.critical_partitions
    }
}
fn get(object: &Com<Object>, name: &str, cim: i32) -> io::Result<Variant> {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut value = Variant {
        vt: 0,
        reserved: [0; 3],
        data: [0; 2],
    };
    let mut actual = 0;
    exact("IWbemClassObject::Get", unsafe {
        ((*(*object.0).vtable).get)(
            object.0,
            name.as_ptr(),
            0,
            &mut value,
            &mut actual,
            ptr::null_mut(),
        )
    })?;
    need(
        actual == cim && value.vt != 0 && value.vt != 1,
        "WMI required property is NULL/unknown or has another CIM type",
    )?;
    Ok(value)
}
fn string(value: &Variant) -> io::Result<String> {
    need(value.vt == 8, "WMI property is not BSTR")?;
    let raw = value.data[0] as *const u16;
    need(!raw.is_null(), "WMI BSTR is NULL")?;
    let n = unsafe { SysStringLen(raw) } as usize;
    need(n > 0 && n <= 128, "WMI property string exceeds bound")?;
    let units = unsafe { std::slice::from_raw_parts(raw, n) };
    need(!units.contains(&0), "WMI property contains NUL")?;
    String::from_utf16(units).map_err(io::Error::other)
}
fn u32_property(object: &Com<Object>, name: &str) -> io::Result<u32> {
    let v = get(object, name, 19)?;
    need(v.vt == 3 || v.vt == 19, "WMI uint32 encoding differs")?;
    Ok(v.data[0] as u32)
}
fn u64_property(object: &Com<Object>, name: &str) -> io::Result<u64> {
    let v = get(object, name, 21)?;
    let text = string(&v)?;
    need(
        text.bytes().all(|b| b.is_ascii_digit()),
        "WMI uint64 token is not exact decimal",
    )?;
    text.parse().map_err(io::Error::other)
}
fn bool_property(object: &Com<Object>, name: &str) -> io::Result<bool> {
    let v = get(object, name, 11)?;
    let b = v.data[0] as i16;
    need(
        v.vt == 11 && (b == 0 || b == -1),
        "WMI boolean encoding is unknown",
    )?;
    Ok(b == -1)
}
fn guid_property(object: &Com<Object>, name: &str) -> io::Result<[u8; 16]> {
    let v = get(object, name, 8)?;
    let s = string(&v)?;
    let result = layout::guid_bytes(s.trim_matches(['{', '}']))?;
    need(result != [0; 16], "WMI GPT GUID is zero")?;
    Ok(result)
}
fn query(
    session: &Session,
    disks: &[u32],
    maximum: usize,
    deadline: Instant,
) -> io::Result<Vec<StoragePartitionRole>> {
    let filter = disks
        .iter()
        .map(|n| format!("DiskNumber={n}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let text = format!(
        "SELECT DiskNumber,PartitionNumber,Guid,GptType,Offset,Size,IsBoot,IsSystem FROM MSFT_Partition WHERE {filter}"
    );
    let language = Bstr::new("WQL")?;
    let text = Bstr::new(&text)?;
    let mut enumeration = ptr::null_mut();
    let hr = unsafe {
        ((*(*session.services.0).vtable).query)(
            session.services.0,
            language.0,
            text.0,
            0x30,
            ptr::null_mut(),
            &mut enumeration,
        )
    };
    let enumeration = Com::returned(enumeration, hr, "IWbemServices::ExecQuery(MSFT_Partition)")?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(maximum).map_err(io::Error::other)?;
    loop {
        need(
            Instant::now() < deadline,
            "WMI partition catalog deadline exhausted",
        )?;
        let mut object = ptr::null_mut();
        let mut count = 0;
        let hr = unsafe {
            ((*(*enumeration.0).vtable).next)(enumeration.0, 1000, 1, &mut object, &mut count)
        };
        let object = if object.is_null() {
            None
        } else {
            Some(Com(object))
        };
        if hr == 1 && count == 0 {
            need(object.is_none(), "WMI end-of-enumeration returned object")?;
            break;
        }
        // Timeout/partial enumeration never means complete coverage.
        need(
            hr == 0 && count == 1,
            "WMI partition enumeration incomplete or timed out",
        )?;
        let object = object.ok_or_else(|| invalid("WMI Next returned no object"))?;
        need(
            rows.len() < maximum,
            "WMI partition row count exceeds admitted metadata budget",
        )?;
        let row = StoragePartitionRole {
            disk_number: u32_property(&object, "DiskNumber")?,
            partition_number: u32_property(&object, "PartitionNumber")?,
            guid: guid_property(&object, "Guid")?,
            gpt_type: guid_property(&object, "GptType")?,
            offset: u64_property(&object, "Offset")?,
            size: u64_property(&object, "Size")?,
            is_boot: bool_property(&object, "IsBoot")?,
            is_system: bool_property(&object, "IsSystem")?,
        };
        need(
            disks.contains(&row.disk_number)
                && row.partition_number > 0
                && row.size > 0
                && row.offset.checked_add(row.size).is_some(),
            "WMI partition identity/extent invalid",
        )?;
        need(
            !rows.iter().any(|r: &StoragePartitionRole| {
                r.guid == row.guid
                    || (r.disk_number == row.disk_number
                        && r.partition_number == row.partition_number)
            }),
            "Duplicate WMI partition identity",
        )?;
        rows.push(row);
    }
    rows.sort_by_key(|r| (r.disk_number, r.partition_number));
    need(!rows.is_empty(), "WMI partition catalog empty")?;
    Ok(rows)
}
fn native(
    row: &StoragePartitionRole,
    events: &mut Vec<NativeEvent>,
) -> io::Result<NativeStoragePartitionRole> {
    let file = device_file(
        &format!(
            r"\\?\GLOBALROOT\Device\Harddisk{}\Partition{}",
            row.disk_number, row.partition_number
        ),
        false,
        false,
    )?;
    let info = control(
        &file,
        "storage-role-native-partition",
        0x0007_0048,
        &[],
        144,
        events,
    )?;
    let device = control(
        &file,
        "storage-role-native-device",
        super::DEVICE,
        &[],
        12,
        events,
    )?;
    need(
        info.len() == 144
            && layout::u32_at(&info, 0)? == 1
            && layout::u32_at(&info, 24)? == row.partition_number
            && layout::u64_at(&info, 8)? == row.offset
            && layout::u64_at(&info, 16)? == row.size
            && info[48..64] == row.guid
            && info[32..48] == row.gpt_type
            && device.len() == 12
            && layout::u32_at(&device, 0)? == 7
            && layout::u32_at(&device, 4)? == row.disk_number
            && layout::u32_at(&device, 8)? == row.partition_number,
        "MSFT_Partition/native device identity mismatch",
    )?;
    Ok(NativeStoragePartitionRole {
        role: row.clone(),
        native_partition_info: info,
    })
}
fn windows_extent(events: &mut Vec<NativeEvent>) -> io::Result<PartitionVolumeExtent> {
    let mut name = [0u16; 512];
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } as usize;
    need(
        n >= 3 && n < name.len() && name[1] == b':' as u16 && name[2] == b'\\' as u16,
        "Actual Windows volume route unavailable",
    )?;
    let letter = char::from_u32(name[0] as u32).ok_or_else(|| invalid("Windows letter invalid"))?;
    need(letter.is_ascii_alphabetic(), "Windows letter not local")?;
    let file = device_file(&format!(r"\\.\{letter}:"), false, false)?;
    let ext = control(
        &file,
        "storage-role-current-windows-extents",
        super::VOLUME_EXTENTS,
        &[],
        32,
        events,
    )?;
    need(
        ext.len() == 32 && layout::u32_at(&ext, 0)? == 1,
        "Windows extent incomplete",
    )?;
    Ok(PartitionVolumeExtent {
        disk_number: layout::u32_at(&ext, 8)?,
        offset: layout::u64_at(&ext, 16)?,
        length: layout::u64_at(&ext, 24)?,
        native_bytes: ext,
    })
}
fn outside(row: &StoragePartitionRole, binding: &PartitionSourceBinding) -> bool {
    let t = &binding.storage.identity;
    row.disk_number != binding.storage.disk_number
        || row.offset + row.size <= t.partition_offset
        || row.offset >= t.partition_offset + t.partition_bytes
}
/// Complete fresh required-disk catalog, bracketed around actual readonly
/// native handle/device/partition identity queries. No saved row is accepted.
pub(super) fn observe_partition_storage_roles(
    binding: &PartitionSourceBinding,
    budget: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionStorageRoleObservation> {
    binding.validate()?;
    budget.validate()?;
    need(events.len() < 112, "Storage role event workspace exhausted")?;
    let maximum = usize::try_from((budget.gpt_entry_bytes / 128).min(budget.ram_bytes / 8192))
        .map_err(io::Error::other)?;
    need(
        maximum > 0 && maximum <= 8192,
        "Storage role catalog budget invalid",
    )?;
    let windows = windows_extent(events)?;
    let mut disks = vec![binding.storage.disk_number, windows.disk_number];
    disks.sort_unstable();
    disks.dedup();
    CONNECTION.with(|slot| {
        let mut cached = slot
            .try_borrow_mut()
            .map_err(|_| invalid("Recursive WMI role observation"))?;
        if cached.is_none() {
            *cached = Some(Session::new()?);
        }
        let session = cached.as_ref().unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let before = query(session, &disks, maximum, deadline)?;
        let target_guid = layout::guid_bytes(&binding.storage.identity.partition_guid)?;
        let selected = before
            .iter()
            .find(|r| r.disk_number == binding.storage.disk_number && r.guid == target_guid)
            .cloned();
        need(
            !before.iter().any(|row| {
                row.disk_number == binding.storage.disk_number
                    && row.partition_number == binding.storage.identity.partition_number
                    && row.guid != target_guid
            }),
            "WMI selected partition number names a different GUID",
        )?;
        // Query the selected raw partition even if a private type has no CIM row.
        let file = device_file(
            &format!(
                r"\\?\GLOBALROOT\Device\Harddisk{}\Partition{}",
                binding.storage.disk_number, binding.storage.identity.partition_number
            ),
            false,
            false,
        )?;
        let target = control(
            &file,
            "storage-role-selected-native",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        let device = control(
            &file,
            "storage-role-selected-device",
            super::DEVICE,
            &[],
            12,
            events,
        )?;
        need(
            target.len() == 144
                && layout::u32_at(&target, 0)? == 1
                && layout::u32_at(&target, 24)? == binding.storage.identity.partition_number
                && layout::u64_at(&target, 8)? == binding.storage.identity.partition_offset
                && layout::u64_at(&target, 16)? == binding.storage.identity.partition_bytes
                && target[48..64] == target_guid
                && device.len() == 12
                && layout::u32_at(&device, 0)? == 7
                && layout::u32_at(&device, 4)? == binding.storage.disk_number
                && layout::u32_at(&device, 8)? == binding.storage.identity.partition_number,
            "Storage-role selected native binding differs",
        )?;
        if let Some(row) = &selected {
            need(
                !row.is_boot && !row.is_system,
                "Selected partition is boot/system",
            )?;
            let checked = native(row, events)?;
            need(
                checked.native_partition_info == target,
                "Selected CIM/native partition differs",
            )?;
        } else {
            need(
                target[32..48] == layout::guid_bytes("b627aadb-a893-48b6-aa0b-71e5f30ee370")?,
                "Selected Basic partition missing from complete live catalog",
            )?;
        }
        let current = before
            .iter()
            .filter(|r| {
                r.disk_number == windows.disk_number
                    && r.offset == windows.offset
                    && r.size == windows.length
            })
            .collect::<Vec<_>>();
        need(
            current.len() == 1 && current[0].is_boot && outside(current[0], binding),
            "Actual Windows partition missing/currentBoot role or overlaps target",
        )?;
        let current_windows = native(current[0], events)?;
        let mut critical = Vec::new();
        for row in before.iter().filter(|r| r.is_boot || r.is_system) {
            need(
                outside(row, binding),
                "Boot/system partition overlaps selected target",
            )?;
            critical.push(if row == current[0] {
                current_windows.clone()
            } else {
                native(row, events)?
            });
        }
        let after = query(session, &disks, maximum, deadline)?;
        need(
            before == after && windows_extent(events)? == windows,
            "Storage role catalog/Windows binding changed across native queries",
        )?;
        need(
            control(
                &file,
                "storage-role-selected-native-closing",
                0x0007_0048,
                &[],
                144,
                events,
            )? == target,
            "Storage-role selected native info changed across catalog",
        )?;
        // None never claims an observed false role. The caller's actual retained
        // private lifecycle/lock must preserve its earlier live Basic role witness.
        let selected_is_boot = selected.as_ref().map(|row| row.is_boot);
        let selected_is_system = selected.as_ref().map(|row| row.is_system);
        let result = PartitionStorageRoleObservation {
            binding: binding.clone(),
            selected,
            selected_native_partition_info: target,
            selected_is_boot,
            selected_is_system,
            current_windows,
            critical_partitions: critical,
            catalog_complete: true,
            queried_disks: disks,
        };
        let output = serde_json::to_vec(&result).map_err(io::Error::other)?;
        need(
            output.len() <= 65536 && events.len() < 128,
            "Storage role evidence exceeds native event bound",
        )?;
        events.push(NativeEvent {
            operation: "native-msft-partition-role-catalog".into(),
            control_code: 0,
            input: Vec::new(),
            succeeded: true,
            native_error: None,
            output,
        });
        Ok(result)
    })
}
