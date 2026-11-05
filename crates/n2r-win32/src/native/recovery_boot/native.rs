use super::*;
use std::os::windows::process::CommandExt;
use std::{
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Instant,
};
use windows_sys::Win32::System::{
    Registry::{
        HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_SZ, RegCloseKey,
        RegFlushKey, RegOpenKeyExW, RegQueryValueExW,
    },
    SystemInformation::GetSystemDirectoryW,
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFirmwareEnvironmentVariableW(
        name: *const u16,
        vendor: *const u16,
        buffer: *mut std::ffi::c_void,
        bytes: u32,
    ) -> u32;
    fn GetProcessTimes(
        process: *mut std::ffi::c_void,
        creation: *mut u64,
        exit: *mut u64,
        kernel: *mut u64,
        user: *mut u64,
    ) -> i32;
    fn MultiByteToWideChar(
        page: u32,
        flags: u32,
        input: *const u8,
        bytes: i32,
        output: *mut u16,
        units: i32,
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        buffer: *mut std::ffi::c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}
pub(super) fn kernel_boot_identifier() -> io::Result<[u8; 16]> {
    let mut value = [0u64; 4];
    let mut returned = 0;
    let status =
        unsafe { NtQuerySystemInformation(90, value.as_mut_ptr().cast(), 32, &mut returned) };
    need(
        status == 0 && returned == 32,
        "native boot environment identifier unavailable",
    )?;
    let bytes = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), 32) };
    need(
        layout::u32_at(bytes, 16)? == 2,
        "UEFI boot environment required",
    )?;
    bytes[..16].try_into().map_err(io::Error::other)
}
struct Key(windows_sys::Win32::System::Registry::HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn key(path: &str) -> io::Result<Key> {
    let mut k = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(path).as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut k,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(Key(k))
}
pub(super) fn reg_bytes(path: &str, name: &str, kind: u32, maximum: usize) -> io::Result<Vec<u8>> {
    let k = key(path)?;
    let mut value = vec![0; maximum];
    let mut n = maximum as u32;
    let mut actual = 0;
    let status = unsafe {
        RegQueryValueExW(
            k.0,
            wide(name).as_ptr(),
            ptr::null(),
            &mut actual,
            value.as_mut_ptr(),
            &mut n,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    need(
        actual == kind && n as usize <= maximum,
        "native registry type/length differs",
    )?;
    value.truncate(n as usize);
    Ok(value)
}
fn current_option_sha(prefix:&str) -> io::Result<[u8; 32]> {
    let data = reg_bytes(
        r"SYSTEM\CurrentControlSet\Control",
        "SystemStartOptions",
        REG_SZ,
        32768,
    )?;
    need(
        data.len().is_multiple_of(2),
        "native boot options encoding differs",
    )?;
    let units: Vec<_> = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let end = units
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| bad("native boot options unterminated"))?;
    let value = String::from_utf16(&units[..end]).map_err(io::Error::other)?;
    let pins: Vec<_> = value
        .split_ascii_whitespace()
        .filter_map(|part| part.strip_prefix(prefix))
        .collect();
    need(
        pins.len() == 1 && pins[0].len() == 64,
        "actual kernel boot options do not contain exactly one recovery intent pin",
    )?;
    hex::decode(pins[0])
        .map_err(io::Error::other)?
        .try_into()
        .map_err(|_| bad("native boot intent SHA width invalid"))
}
pub(super) fn current_intent_sha()->io::Result<[u8;32]>{current_option_sha("N2RRECOVERYINTENT=")}
pub(super) fn current_bootstrap_sha()->io::Result<[u8;32]>{current_option_sha("N2RRECOVERYBOOTSTRAP=")}
pub(super) fn require_san3() -> io::Result<()> {
    let current = reg_bytes(r"SYSTEM\Select", "Current", REG_DWORD, 4)?;
    let default = reg_bytes(r"SYSTEM\Select", "Default", REG_DWORD, 4)?;
    for value in [current, default] {
        let id = layout::u32_at(&value, 0)?;
        need(
            (1..=999).contains(&id),
            "actual selected ControlSet invalid",
        )?;
        need(
            layout::u32_at(
                &reg_bytes(
                    &format!(r"SYSTEM\ControlSet{id:03}\Services\partmgr\Parameters"),
                    "SanPolicy",
                    REG_DWORD,
                    4,
                )?,
                0,
            )? == 3,
            "actual PE selected SAN policy is not early OfflineAll3",
        )?;
    }
    Ok(())
}
/// Error-only native event context. Return the ORIGINAL error object so
/// raw_os_error survives exactly. No extra native operation or success event.
pub(super) fn diagnose<T>(result:io::Result<T>,operation:&str,phase:&str,context:&str,
    events:&mut Vec<NativeEvent>)->io::Result<T> {
    if let Err(error)=&result {
        // Preserve existing event limits and every prior record. On a full
        // vector the original failure still wins; no diagnostics mask it.
        if events.len()<128 {
            let route:String=context.chars().take(4096).collect();
            let message:String=error.to_string().chars().take(4096).collect();
            if let Ok(output)=serde_json::to_vec(&serde_json::json!({
                "kind":"actual-native-boot-step-failed-v1","phase":phase,
                "context":route,"message":message,"raw_os_error":error.raw_os_error(),
                "original_error_returned_unchanged":true})) {
                if output.len()<=65536 { events.push(NativeEvent{operation:operation.into(),control_code:0,
                    input:Vec::new(),succeeded:false,native_error:error.raw_os_error(),output}); }
            }
        }
    }
    result
}
pub(super) fn flush_system_bcd_with_events(events:&mut Vec<NativeEvent>)->io::Result<()> {
    let k=diagnose(key("BCD00000000"),"boot-system-BCD-flush-failed",
        "RegOpenKeyExW-KEY_QUERY_VALUE","HKLM\\BCD00000000",events)?;
    let status=unsafe{RegFlushKey(k.0)};
    let result=if status!=0{Err(io::Error::from_raw_os_error(status as i32))}else{Ok(())};
    diagnose(result,"boot-system-BCD-flush-failed","RegFlushKey","HKLM\\BCD00000000",events)
}
#[allow(dead_code)]
pub(super) fn flush_system_bcd()->io::Result<()> {flush_system_bcd_with_events(&mut Vec::new())}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct FirmwareIdentity {
    pub current: u16,
    pub order: Vec<u16>,
    pub option: Vec<u8>,
    pub secure_boot: Vec<u8>,
    pub read_privilege_audit: serde_json::Value,
}
impl FirmwareIdentity {
    pub(super) fn require_same(&self, other: &Self) -> io::Result<()> {
        need(
            self.current == other.current
                && self.order == other.order
                && self.option == other.option
                && self.secure_boot == other.secure_boot,
            "actual firmware boot selection/security changed",
        )
    }
}
fn variable(name: &str, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; maximum];
    let n = unsafe {
        GetFirmwareEnvironmentVariableW(
            wide(name).as_ptr(),
            wide("{8be4df61-93ca-11d2-aa0d-00e098032b8c}").as_ptr(),
            bytes.as_mut_ptr().cast(),
            maximum as u32,
        )
    };
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    need(n as usize <= maximum, "firmware variable oversized")?;
    bytes.truncate(n as usize);
    Ok(bytes)
}
pub(super) fn firmware(efi: &EfiIdentity) -> io::Result<FirmwareIdentity> {
    let mut privileges =
        crate::attestation_native::Privileges::enable_for(&["SeSystemEnvironmentPrivilege"])
            .map_err(|e| {
                if e.to_string().contains("privilege absent") {
                    io::Error::from_raw_os_error(1314)
                } else {
                    e
                }
            })?;
    let observed = (|| {
        let current = variable("BootCurrent", 2)?;
        need(current.len() == 2, "native BootCurrent width invalid")?;
        let current = u16::from_le_bytes(current.as_slice().try_into().map_err(io::Error::other)?);
        let bytes = variable("BootOrder", 4096)?;
        need(
            bytes.len().is_multiple_of(2) && !bytes.is_empty(),
            "native BootOrder invalid",
        )?;
        let order: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        need(
            order.first() == Some(&current),
            "current Windows firmware entry is not persistent first BootOrder",
        )?;
        match variable("BootNext", 2) {
            Err(e) if e.raw_os_error() == Some(203) => (),
            Err(e) => return Err(e),
            Ok(_) => {
                return Err(bad(
                    "pending firmware BootNext forbids persistent recovery guard",
                ));
            }
        }
        let option = variable(&format!("Boot{current:04X}"), 65536)?;
        verify_option(&option, efi)?;
        let secure_boot = variable("SecureBoot", 1)?;
        need(
            secure_boot == [1],
            "Secure Boot must remain enabled; no policy change is attempted",
        )?;
        Ok(FirmwareIdentity {
            current,
            order,
            option,
            secure_boot,
            read_privilege_audit: serde_json::Value::Null,
        })
    })();
    let restored = privileges.restore();
    match (observed, restored) {
        (Ok(mut v), Ok(())) => {
            v.read_privilege_audit =
                serde_json::to_value(privileges.audit()).map_err(io::Error::other)?;
            Ok(v)
        }
        (Err(e), Ok(())) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Err(e), Err(r)) => Err(io::Error::new(
            e.kind(),
            format!("{e}; firmware-read privilege restoration failed: {r}"),
        )),
    }
}
fn verify_option(option: &[u8], efi: &EfiIdentity) -> io::Result<()> {
    need(
        option.len() >= 10 && layout::u32_at(option, 0)? & 1 != 0,
        "active UEFI load option required",
    )?;
    let path_bytes =
        u16::from_le_bytes(option[4..6].try_into().map_err(io::Error::other)?) as usize;
    let mut at = 6;
    loop {
        need(
            at + 2 <= option.len(),
            "UEFI option description unterminated",
        )?;
        let n = u16::from_le_bytes(option[at..at + 2].try_into().map_err(io::Error::other)?);
        at += 2;
        if n == 0 {
            break;
        }
    }
    let end = at
        .checked_add(path_bytes)
        .ok_or_else(|| bad("firmware path overflow"))?;
    need(end <= option.len(), "firmware device path truncated")?;
    let (mut hd, mut file, mut ended) = (false, false, false);
    while at < end {
        need(at + 4 <= end, "firmware node header truncated")?;
        let n = u16::from_le_bytes(
            option[at + 2..at + 4]
                .try_into()
                .map_err(io::Error::other)?,
        ) as usize;
        need(n >= 4 && at + n <= end, "firmware node length invalid")?;
        let node = &option[at..at + n];
        match (node[0], node[1]) {
            (4, 1) => {
                need(
                    n == 42 && !hd && node[40] == 2 && node[41] == 2,
                    "unique GPT EFI firmware partition node required",
                )?;
                need(
                    node[24..40] == layout::guid_bytes(&efi.binding.identity.partition_guid)?
                        && layout::u64_at(node, 8)?
                            .checked_mul(u64::from(efi.binding.identity.logical_sector_bytes))
                            == Some(efi.binding.identity.partition_offset)
                        && layout::u64_at(node, 16)?
                            .checked_mul(u64::from(efi.binding.identity.logical_sector_bytes))
                            == Some(efi.binding.identity.partition_bytes),
                    "actual firmware boot ESP differs",
                )?;
                hd = true;
            }
            (4, 4) => {
                need(
                    n >= 6 && (n - 4).is_multiple_of(2) && !file,
                    "firmware file path node invalid",
                )?;
                let units: Vec<_> = node[4..]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                need(
                    units.last() == Some(&0)
                        && !units[..units.len() - 1].contains(&0)
                        && String::from_utf16(&units[..units.len() - 1])
                            .map_err(io::Error::other)?
                            .eq_ignore_ascii_case(r"\EFI\Microsoft\Boot\bootmgfw.efi"),
                    "firmware didnotload native source ESP Bootmgfw",
                )?;
                file = true;
            }
            (0x7f, 0xff) => {
                need(n == 4 && at + n == end, "UEFI end node differs")?;
                ended = true;
            }
            _ => (),
        }
        at += n;
    }
    need(
        hd && file && ended,
        "complete native Windows firmware device/file path absent",
    )
}
pub(super) fn persist(path: &Path, value: &impl Serialize, maximum: u64) -> io::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    need(
        bytes.len() as u64 <= maximum,
        "boot control record exceeds admitted bound",
    )?;
    // This is a fresh, ordinary control-only directory. Two bounded .bcd
    // metadata files have a separate reservation; every JSON plus NTFS
    // allocation slack is charged against the aggregate control quota.
    use std::os::windows::fs::MetadataExt;
    let parent = path
        .parent()
        .ok_or_else(|| bad("boot control parent absent"))?;
    let mut used = (bytes.len() as u64)
        .checked_add(65535)
        .ok_or_else(|| bad("boot control charge overflow"))?;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let m = std::fs::symlink_metadata(entry.path())?;
        need(
            m.is_file() && m.file_attributes() & 0x400 == 0,
            "unexpected entry in owned boot control directory",
        )?;
        match entry.path().extension().and_then(|v| v.to_str()) {
            Some("json") => {
                used = used
                    .checked_add(m.len())
                    .and_then(|n| n.checked_add(65535))
                    .ok_or_else(|| bad("boot control charge overflow"))?;
            }
            Some("bcd") => (),
            _ => return Err(bad("unexpected file kind in owned boot control directory")),
        }
        need(
            used <= maximum,
            "aggregate boot control bytes plus allocation slack exceed admission",
        )?;
    }
    need(
        used <= maximum,
        "boot control admission smaller than actual record",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let mut check = vec![0; bytes.len()];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut check)?;
    need(check == bytes, "boot control durable readback differs")?;
    Ok(digest(&check))
}
#[derive(Serialize)]
struct ToolRecord<'a> {
    kind: &'static str,
    arguments: &'a [String],
    process_id: u32,
    creation_100ns: u64,
    actual_exit: Option<i32>,
    timed_out: bool,
    stdout: &'a [u8],
    stderr: &'a [u8],
    overflow: bool,
}
struct OwnedChild(std::process::Child);
impl std::ops::Deref for OwnedChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
    }
}
static TOOL_RECORD_ORDINAL: AtomicU64 = AtomicU64::new(0);

pub(super) struct Tool {
    path: PathBuf,
    _file: File,
    budget: RecoveryBootBudget,
    spent: AtomicU64,
}
impl Tool {
    pub(super) fn system(budget: RecoveryBootBudget) -> io::Result<Self> {
        let mut path = vec![0u16; 32768];
        let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
        need(
            n > 0 && n < path.len(),
            "actual system directory unavailable",
        )?;
        let path = PathBuf::from(String::from_utf16(&path[..n]).map_err(io::Error::other)?)
            .join("bcdedit.exe");
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        need(
            file.metadata()?.is_file(),
            "actual system BCD tool unavailable",
        )?;
        Ok(Self {
            path,
            _file: file,
            budget,
            spent: AtomicU64::new(0),
        })
    }
    pub(super) fn run(
        &self,
        store: Option<&Path>,
        args: &[String],
        directory: &Path,
    ) -> io::Result<Vec<u8>> {
        let mut all = Vec::new();
        if let Some(store) = store {
            all.extend([
                "/store".into(),
                store
                    .to_str()
                    .ok_or_else(|| bad("Unicode BCD store path required"))?
                    .into(),
            ]);
        }
        all.extend_from_slice(args);
        let mut child = OwnedChild(
            Command::new(&self.path)
                .creation_flags(0x0800_0000)
                .args(&all)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let pid = child.id();
        let (mut creation, mut exit, mut kernel, mut user) = (0, 0, 0, 0);
        need(
            unsafe {
                GetProcessTimes(
                    child.0.as_raw_handle(),
                    &mut creation,
                    &mut exit,
                    &mut kernel,
                    &mut user,
                )
            } != 0,
            "actual BCD child birth unavailable",
        )?;
        fn drain(
            mut input: impl Read + Send + 'static,
        ) -> io::Result<thread::JoinHandle<io::Result<(Vec<u8>, bool)>>> {
            thread::Builder::new()
                .name("n2r-bcd-bounded-drain".into())
                .stack_size(256 * 1024)
                .spawn(move || {
                    let mut saved = Vec::new();
                    let mut buffer = [0u8; 8192];
                    let mut overflow = false;
                    loop {
                        let n = input.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        let keep = n.min(65536usize.saturating_sub(saved.len()));
                        saved.extend_from_slice(&buffer[..keep]);
                        overflow |= keep != n;
                    }
                    Ok((saved, overflow))
                })
        }
        let stdout = drain(
            child
                .stdout
                .take()
                .ok_or_else(|| bad("BCD stdout missing"))?,
        )?;
        let stderr = drain(
            child
                .stderr
                .take()
                .ok_or_else(|| bad("BCD stderr missing"))?,
        )?;
        let until = Instant::now()
            + Duration::from_millis(u64::from(self.budget.tool_timeout_milliseconds));
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() >= until {
                timed_out = true;
                child.kill()?;
                let reap = Instant::now() + Duration::from_secs(5);
                break loop {
                    if let Some(s) = child.try_wait()? {
                        break s;
                    }
                    need(
                        Instant::now() < reap,
                        "owned BCD child did not terminate within bounded post-kill interval",
                    )?;
                    thread::sleep(Duration::from_millis(20));
                };
            }
            thread::sleep(Duration::from_millis(20));
        };
        let (out, out_over) = stdout
            .join()
            .map_err(|_| bad("BCD stdout drain panicked"))??;
        let (err, err_over) = stderr
            .join()
            .map_err(|_| bad("BCD stderr drain panicked"))??;
        let ordinal=TOOL_RECORD_ORDINAL.fetch_update(Ordering::Relaxed,Ordering::Relaxed,
            |value|value.checked_add(1)).map_err(|_|bad("native BCD command ordinal overflow"))?;
        let record = ToolRecord {
            kind: "actual-native-bcdedit-child-v1",
            arguments: &all,
            process_id: pid,
            creation_100ns: creation,
            actual_exit: status.code(),
            timed_out,
            stdout: &out,
            stderr: &err,
            overflow: out_over || err_over,
        };
        let record_bytes = serde_json::to_vec(&record).map_err(io::Error::other)?.len() as u64;
        self.spent
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(record_bytes)
                    .filter(|n| *n <= self.budget.maximum_control_bytes / 2)
            })
            .map_err(|_| {
                bad("aggregate native BCD command records exceed admitted control quota")
            })?;
        persist(
            &directory.join(format!("bcd-command-{ordinal:04}.json")),
            &record,
            self.budget.maximum_control_bytes,
        )?;
        need(
            status.success() && !timed_out && !out_over && !err_over,
            "native BCD operation failed/overflowed; preserve intent/store; no retry",
        )?;
        Ok(out)
    }
    pub(super) fn set(&self, id: &str, key: &str, value: &str, directory: &Path) -> io::Result<()> {
        self.run(
            None,
            &["/set".into(), id.into(), key.into(), value.into()],
            directory,
        )
        .map(|_| ())
    }
    pub(super) fn enum_all(&self,store:&Path,directory:&Path)
        ->io::Result<BTreeMap<String,BTreeMap<String,Vec<String>>>> {
        self.enum_all_at(Some(store),directory)
    }
    pub(super) fn enum_system_all(&self,directory:&Path)->io::Result<BTreeMap<String,BTreeMap<String,Vec<String>>>> {
        self.enum_all_at(None,directory)
    }
    fn enum_all_at(&self,store:Option<&Path>,directory:&Path)->io::Result<BTreeMap<String,BTreeMap<String,Vec<String>>>> {
        let bytes=self.run(store,&["/enum".into(),"all".into(),"/v".into()],directory)?;
        let text=decode(&bytes)?.replace("\r\n","\n");
        let mut objects=BTreeMap::new();
        for block in text.split("\n\n").filter(|s|!s.trim().is_empty()) {
            let fields=parse(block)?;
            let id=canonical_guid(one(&fields,"identifier")?)?;
            need(objects.insert(id,fields).is_none(),"duplicate actual native BCD object")?;
        }
        need(objects.contains_key(BOOTMGR),"complete native BCD object domain omits BootMgr")?;
        Ok(objects)
    }
    pub(super) fn enum_object(
        &self,
        store: Option<&Path>,
        id: &str,
        directory: &Path,
    ) -> io::Result<BTreeMap<String, Vec<String>>> {
        let bytes = self.run(store, &["/enum".into(), id.into(), "/v".into()], directory)?;
        parse(&decode(&bytes)?)
    }
}
fn decode(bytes: &[u8]) -> io::Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.iter().skip(1).step_by(2).take(16).all(|b| *b == 0)
    {
        let b = if bytes.starts_with(&[0xff, 0xfe]) {
            &bytes[2..]
        } else {
            bytes
        };
        need(b.len().is_multiple_of(2), "BCD Unicode output truncated")?;
        return String::from_utf16(
            &b.chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(io::Error::other);
    }
    let n = unsafe {
        MultiByteToWideChar(1, 8, bytes.as_ptr(), bytes.len() as i32, ptr::null_mut(), 0)
    };
    need(n > 0, "native OEM BCD output encoding unknown")?;
    let mut out = vec![0; n as usize];
    need(
        unsafe {
            MultiByteToWideChar(
                1,
                8,
                bytes.as_ptr(),
                bytes.len() as i32,
                out.as_mut_ptr(),
                n,
            )
        } == n,
        "native BCD output decode incomplete",
    )?;
    String::from_utf16(&out).map_err(io::Error::other)
}
pub(super) fn parse(text: &str) -> io::Result<BTreeMap<String, Vec<String>>> {
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    let mut last = None;
    for line in text.lines() {
        if line.trim().is_empty() || line.trim().chars().all(|c| c == '-') {
            continue;
        }
        if line.len() < 24 {
            continue;
        }
        let (key, value) = line.split_at(24);
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let key = if key.is_empty() {
            last.clone()
                .ok_or_else(|| bad("BCD continuation has no element"))?
        } else {
            need(
                key.bytes().all(|b| b.is_ascii_alphanumeric()),
                "unsupported/localized BCD key",
            )?;
            let key = key.to_ascii_lowercase();
            last = Some(key.clone());
            key
        };
        let value = if value.len() == 38 && value.starts_with('{') {
            canonical_guid(value)?
        } else {
            value.to_owned()
        };
        fields.entry(key).or_default().push(value);
    }
    need(
        fields.contains_key("identifier"),
        "en-US explicit native BCD object absent",
    )?;
    Ok(fields)
}
