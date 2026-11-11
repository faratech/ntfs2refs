//! One query-only Storage WMI class-availability observation, not role facts.
use super::Failure;
use serde::Serialize;
use std::{ffi::c_void, io, ptr};

#[derive(Debug, Serialize)]
pub struct HResult {
    pub operation: &'static str,
    pub hresult: i32,
}
#[derive(Debug, Serialize)]
pub struct Availability {
    pub namespace: &'static str,
    pub query: &'static str,
    pub calls: Vec<HResult>,
    pub namespace_connected: bool,
    pub class_enumeration_observed: bool,
    pub first_row_observed: Option<bool>,
    pub failure: Option<Failure>,
    pub complete_partition_roles_observed: bool,
    pub critical_roles_clear: bool,
    pub synchronous_com_has_hard_wall_timeout: bool,
}
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
const CLSID: Guid = Guid {
    a: 0x4590f811,
    b: 0x1d3a,
    c: 0x11d0,
    d: [0x89, 0x1f, 0, 0xaa, 0, 0x4b, 0x2e, 0x24],
};
const IID: Guid = Guid {
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
    fn CoSetProxyBlanket(
        proxy: *mut c_void,
        authn: u32,
        authz: u32,
        principal: *mut u16,
        level: u32,
        imp: u32,
        auth: *mut c_void,
        capabilities: u32,
    ) -> i32;
}
#[link(name = "oleaut32")]
unsafe extern "system" {
    fn SysAllocStringLen(value: *const u16, len: u32) -> *mut u16;
    fn SysFreeString(value: *mut u16);
}
#[repr(C)]
struct Unknown {
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
    unknown: Unknown,
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
    unknown: Unknown,
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
    unknown: Unknown,
    reset: usize,
    next: unsafe extern "system" fn(*mut Enumeration, i32, u32, *mut *mut c_void, *mut u32) -> i32,
}
struct Com<T>(*mut T);
impl<T> Drop for Com<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let v = *(self.0.cast::<*const Unknown>());
                ((*v).release)(self.0.cast());
            }
        }
    }
}
struct Apartment(bool);
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() }
        }
    }
}
struct Bstr(*mut u16);
impl Bstr {
    fn new(text: &str) -> io::Result<Self> {
        let units: Vec<u16> = text.encode_utf16().collect();
        if units.len() > 256 {
            return Err(io::Error::other("bounded WMI string exceeded"));
        }
        let value = unsafe { SysAllocStringLen(units.as_ptr(), units.len() as u32) };
        if value.is_null() {
            Err(io::Error::other("WMI BSTR allocation failed"))
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) }
    }
}
fn call(out: &mut Availability, name: &'static str, hr: i32) -> i32 {
    out.calls.push(HResult {
        operation: name,
        hresult: hr,
    });
    hr
}
fn exact(hr: i32) -> io::Result<()> {
    if hr == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "WMI returned HRESULT0x{:08x}",
            hr as u32
        )))
    }
}

pub(super) fn observe() -> Availability {
    let mut out = Availability {
        namespace: r"ROOT\Microsoft\Windows\Storage",
        query: "SELECT DiskNumber FROM MSFT_Partition",
        calls: Vec::new(),
        namespace_connected: false,
        class_enumeration_observed: false,
        first_row_observed: None,
        failure: None,
        complete_partition_roles_observed: false,
        critical_roles_clear: false,
        synchronous_com_has_hard_wall_timeout: false,
    };
    let result = (|| -> io::Result<()> {
        let hr = call(&mut out, "CoInitializeEx(MTA)", unsafe {
            CoInitializeEx(ptr::null_mut(), 0)
        });
        if hr != 0 && hr != 1 && hr as u32 != 0x80010106 {
            exact(hr)?;
        }
        let _apartment = Apartment(hr == 0 || hr == 1);
        let mut raw = ptr::null_mut();
        let hr = call(&mut out, "CoCreateInstance(WbemLocator)", unsafe {
            CoCreateInstance(&CLSID, ptr::null_mut(), 1, &IID, &mut raw)
        });
        let locator = Com(raw.cast::<Locator>());
        exact(hr)?;
        if locator.0.is_null() {
            return Err(io::Error::other("WMI locator returned NULL"));
        }
        let namespace = Bstr::new(out.namespace)?;
        let mut services = ptr::null_mut();
        let hr = call(&mut out, "IWbemLocator::ConnectServer(Storage)", unsafe {
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
        });
        let services = Com(services);
        exact(hr)?;
        if services.0.is_null() {
            return Err(io::Error::other("WMI service returned NULL"));
        }
        out.namespace_connected = true;
        let hr = call(&mut out, "CoSetProxyBlanket(actualServices)", unsafe {
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
        });
        exact(hr)?;
        let language = Bstr::new("WQL")?;
        let query = Bstr::new(out.query)?;
        let mut enumeration = ptr::null_mut();
        let hr = call(
            &mut out,
            "IWbemServices::ExecQuery(MSFT_Partition)",
            unsafe {
                ((*(*services.0).vtable).query)(
                    services.0,
                    language.0,
                    query.0,
                    0x30,
                    ptr::null_mut(),
                    &mut enumeration,
                )
            },
        );
        let enumeration = Com(enumeration);
        exact(hr)?;
        if enumeration.0.is_null() {
            return Err(io::Error::other("WMI enumerator returned NULL"));
        }
        let mut object = ptr::null_mut();
        let mut count = 0;
        let hr = call(
            &mut out,
            "IEnumWbemClassObject::Next(oneRow,1000ms)",
            unsafe {
                ((*(*enumeration.0).vtable).next)(enumeration.0, 1000, 1, &mut object, &mut count)
            },
        );
        let _object = Com(object);
        match (hr, count, object.is_null()) {
            (0, 1, false) => out.first_row_observed = Some(true),
            (1, 0, true) => out.first_row_observed = Some(false),
            _ => {
                return Err(io::Error::other(format!(
                    "WMI class availability not established: HRESULT0x{:08x},count{count},null{}",
                    hr as u32,
                    object.is_null()
                )));
            }
        }
        out.class_enumeration_observed = true;
        Ok(())
    })();
    if let Err(error) = result {
        out.failure = Some(Failure::from(error));
    }
    out
}
