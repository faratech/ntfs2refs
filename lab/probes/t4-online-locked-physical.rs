//! UNBUILT/UNRUN finite T4 ONLINE+LOCK/DISMOUNT physical-write control.
//! std-only Win32/CNG FFI. No product dependency, setter, source-D open or retry.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows only; no operation");
    std::process::exit(1)
}
#[cfg(windows)]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("T4 physical control failed: {e}; no retry/restore");
        std::process::exit(1)
    }
}
#[cfg(windows)]
mod probe {
    use std::{
        collections::BTreeMap,
        ffi::c_void,
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path},
        ptr,
    };
    const DISK: u64 = 128849018880;
    const T: u64 = 64422412288;
    const TL: u64 = 2147483648;
    const REL: u64 = 1291976704;
    const ABS: u64 = 65714388992;
    const N: usize = 8192;
    const DISKG: &str = "1f804918-e98f-4a71-9022-fc00c3cb7c26";
    const TG: &str = "20e3748f-b912-47c3-86aa-2285ab2b5583";
    const CG: &str = "c6c3318f-a7c8-47b9-be6d-6dde5e00862f";
    const DG: &str = "4310d74c-614f-435b-9cf1-7ff664391590";
    const PRIVATE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
    const BASIC: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    const MARKER: &str = "153758bfed87777818c67e021f91ee89f8d96c365177d08f51f7e6371b7bf5aa";
    const CPIN: &str = "6c6413b8c0b413e072aeebaf36dd2c56d6d7fb98eb34a5e8ec895a932554346a";
    const CFILE: &str = r"C:\ntfs2refs\partition-isolation-probe-803bb22b85044f74916d9cc6fda878c8\os-live-marker.bin";
    const ACK: &str =
        "T4-only:20e3748f-b912-47c3-86aa-2285ab2b5583:8192-same-bytes:ONLINE-LOCKED-PHYSICAL";
    const INVALID: *mut c_void = (-1isize) as *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            p: *const u16,
            a: u32,
            s: u32,
            sec: *mut c_void,
            c: u32,
            f: u32,
            t: *mut c_void,
        ) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn DeviceIoControl(
            h: *mut c_void,
            c: u32,
            i: *const c_void,
            ni: u32,
            o: *mut c_void,
            no: u32,
            n: *mut u32,
            x: *mut c_void,
        ) -> i32;
        fn SetFilePointerEx(h: *mut c_void, at: i64, out: *mut i64, m: u32) -> i32;
        fn ReadFile(h: *mut c_void, b: *mut c_void, n: u32, got: *mut u32, x: *mut c_void) -> i32;
        fn WriteFile(
            h: *mut c_void,
            b: *const c_void,
            n: u32,
            got: *mut u32,
            x: *mut c_void,
        ) -> i32;
        fn FlushFileBuffers(h: *mut c_void) -> i32;
        fn GetFileInformationByHandleEx(h: *mut c_void, c: u32, b: *mut c_void, n: u32) -> i32;
        fn GetCurrentProcessId() -> u32;
        fn GetWindowsDirectoryW(b: *mut u16, n: u32) -> u32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(c: u32, b: *mut c_void, n: u32, got: *mut u32) -> i32;
    }
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptOpenAlgorithmProvider(
            h: *mut *mut c_void,
            a: *const u16,
            p: *const u16,
            f: u32,
        ) -> i32;
        fn BCryptCloseAlgorithmProvider(h: *mut c_void, f: u32) -> i32;
        fn BCryptGetProperty(
            h: *mut c_void,
            p: *const u16,
            o: *mut u8,
            n: u32,
            got: *mut u32,
            f: u32,
        ) -> i32;
        fn BCryptCreateHash(
            a: *mut c_void,
            h: *mut *mut c_void,
            o: *mut u8,
            n: u32,
            s: *const u8,
            ns: u32,
            f: u32,
        ) -> i32;
        fn BCryptHashData(h: *mut c_void, b: *const u8, n: u32, f: u32) -> i32;
        fn BCryptFinishHash(h: *mut c_void, b: *mut u8, n: u32, f: u32) -> i32;
        fn BCryptDestroyHash(h: *mut c_void) -> i32;
    }
    fn bad(m: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, m)
    }
    fn need(v: bool, m: &str) -> io::Result<()> {
        if v { Ok(()) } else { Err(bad(m)) }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|n| format!("{n:02x}")).collect()
    }
    fn unhex(s: &str) -> io::Result<Vec<u8>> {
        need(
            s.len() % 2 == 0
                && s.len() <= 262144
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "canonical bounded lowerhex required",
        )?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(io::Error::other))
            .collect()
    }
    fn guid(s: &str) -> io::Result<Vec<u8>> {
        let raw = unhex(&s.replace('-', ""))?;
        need(raw.len() == 16, "GUID size")?;
        let mut b = raw;
        b[..4].reverse();
        b[4..6].reverse();
        b[6..8].reverse();
        Ok(b)
    }
    fn u32at(b: &[u8], i: usize) -> io::Result<u32> {
        Ok(u32::from_le_bytes(
            b.get(i..i + 4)
                .ok_or_else(|| bad("shortu32"))?
                .try_into()
                .map_err(io::Error::other)?,
        ))
    }
    fn u64at(b: &[u8], i: usize) -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            b.get(i..i + 8)
                .ok_or_else(|| bad("shortu64"))?
                .try_into()
                .map_err(io::Error::other)?,
        ))
    }
    fn cng(s: i32) -> io::Result<()> {
        if s >= 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!("CNG status0x{:08x}", s as u32)))
        }
    }
    struct Algorithm(*mut c_void);
    impl Drop for Algorithm {
        fn drop(&mut self) {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
    struct Hash(*mut c_void);
    impl Drop for Hash {
        fn drop(&mut self) {
            unsafe {
                BCryptDestroyHash(self.0);
            }
        }
    }
    fn sha(b: &[u8]) -> io::Result<String> {
        need(b.len() <= 1048576, "hash bound")?;
        let mut a = ptr::null_mut();
        cng(unsafe {
            BCryptOpenAlgorithmProvider(&mut a, wide("SHA256").as_ptr(), ptr::null(), 0)
        })?;
        let a = Algorithm(a);
        let mut len = 0u32;
        let mut got = 0;
        cng(unsafe {
            BCryptGetProperty(
                a.0,
                wide("ObjectLength").as_ptr(),
                (&mut len as *mut u32).cast(),
                4,
                &mut got,
                0,
            )
        })?;
        need(got == 4 && (1..=65536).contains(&len), "CNG workspace")?;
        let mut mem = vec![0; len as usize];
        let mut h = ptr::null_mut();
        cng(unsafe { BCryptCreateHash(a.0, &mut h, mem.as_mut_ptr(), len, ptr::null(), 0, 0) })?;
        let h = Hash(h);
        cng(unsafe { BCryptHashData(h.0, b.as_ptr(), b.len() as u32, 0) })?;
        let mut out = [0; 32];
        cng(unsafe { BCryptFinishHash(h.0, out.as_mut_ptr(), 32, 0) })?;
        Ok(hex(&out))
    }
    fn esc(s: &str) -> String {
        let mut o = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c if c < ' ' => o.push_str(&format!("\\u{:04x}", c as u32)),
                c => o.push(c),
            }
        }
        o.push('"');
        o
    }
    struct Log {
        f: File,
        bytes: usize,
        calls: u32,
    }
    impl Log {
        fn record(&mut self, s: &str) -> io::Result<()> {
            need(
                s.len() <= 131072 && self.bytes + s.len() + 1 <= 4194304,
                "receipt bound",
            )?;
            self.f.write_all(s.as_bytes())?;
            self.f.write_all(b"\n")?;
            self.f.sync_all()?;
            self.bytes += s.len() + 1;
            Ok(())
        }
        fn native(
            &mut self,
            op: &str,
            ok: bool,
            error: Option<i32>,
            requested: u32,
            returned: u32,
        ) -> io::Result<()> {
            self.calls += 1;
            self.record(&format!("{{\"kind\":\"actual-native-call\",\"ordinal\":{},\"operation\":{},\"succeeded\":{},\"error\":{},\"requested_bytes\":{},\"returned_bytes\":{}}}",self.calls,esc(op),ok,error.map(|e|e.to_string()).unwrap_or("null".into()),requested,returned))
        }
    }
    struct Handle {
        raw: *mut c_void,
    }
    impl Handle {
        fn open(path: &str, access: u32, flags: u32, op: &str, l: &mut Log) -> io::Result<Self> {
            let h = unsafe {
                CreateFileW(
                    wide(path).as_ptr(),
                    access,
                    3,
                    ptr::null_mut(),
                    3,
                    flags,
                    ptr::null_mut(),
                )
            };
            let error = (h == INVALID || h.is_null()).then(io::Error::last_os_error);
            let owner = if error.is_none() {
                Some(Self { raw: h })
            } else {
                None
            };
            l.native(
                op,
                error.is_none(),
                error.as_ref().and_then(io::Error::raw_os_error),
                access,
                0,
            )?;
            if let Some(e) = error {
                Err(e)
            } else {
                owner.ok_or_else(|| bad("missing opened owner"))
            }
        }
        fn close(mut self, op: &str, l: &mut Log) -> io::Result<()> {
            let h = self.raw;
            self.raw = INVALID;
            let ok = unsafe { CloseHandle(h) } != 0;
            let e = (!ok).then(io::Error::last_os_error);
            l.native(op, ok, e.as_ref().and_then(io::Error::raw_os_error), 0, 0)?;
            if let Some(e) = e { Err(e) } else { Ok(()) }
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.raw != INVALID && !self.raw.is_null() {
                unsafe {
                    CloseHandle(self.raw);
                }
            }
        }
    }
    fn ctl(
        h: &Handle,
        code: u32,
        input: &[u8],
        maximum: usize,
        op: &str,
        l: &mut Log,
    ) -> io::Result<Vec<u8>> {
        need(maximum <= 65536, "control bound")?;
        let mut b = vec![0; maximum];
        let mut n = 0;
        let ok = unsafe {
            DeviceIoControl(
                h.raw,
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                b.as_mut_ptr().cast(),
                maximum as u32,
                &mut n,
                ptr::null_mut(),
            )
        } != 0;
        let e = (!ok).then(io::Error::last_os_error);
        l.native(
            op,
            ok,
            e.as_ref().and_then(io::Error::raw_os_error),
            maximum as u32,
            n,
        )?;
        if let Some(e) = e {
            return Err(e);
        }
        need(n as usize <= maximum, "control returned length")?;
        b.truncate(n as usize);
        Ok(b)
    }
    #[repr(C, align(4096))]
    struct Aligned([u8; 65536]);
    fn read_at(h: &Handle, at: u64, n: usize, op: &str, l: &mut Log) -> io::Result<Vec<u8>> {
        need(n > 0 && n <= 65536 && at <= i64::MAX as u64, "bounded read")?;
        let mut pos = 0;
        let ok = unsafe { SetFilePointerEx(h.raw, at as i64, &mut pos, 0) } != 0;
        let e = (!ok).then(io::Error::last_os_error);
        l.native(
            &format!("{op}-seek"),
            ok,
            e.as_ref().and_then(io::Error::raw_os_error),
            0,
            0,
        )?;
        if let Some(e) = e {
            return Err(e);
        }
        need(pos == at as i64, "read seek differs")?;
        let mut b = Box::new(Aligned([0; 65536]));
        let mut got = 0;
        let ok = unsafe {
            ReadFile(
                h.raw,
                b.0.as_mut_ptr().cast(),
                n as u32,
                &mut got,
                ptr::null_mut(),
            )
        } != 0;
        let e = (!ok).then(io::Error::last_os_error);
        l.native(
            op,
            ok,
            e.as_ref().and_then(io::Error::raw_os_error),
            n as u32,
            got,
        )?;
        if let Some(e) = e {
            return Err(e);
        }
        need(got as usize == n, "short read; refusing")?;
        Ok(b.0[..n].to_vec())
    }
    fn crc(b: &[u8]) -> u32 {
        let mut c = 0xffffffffu32;
        for v in b {
            c ^= u32::from(*v);
            for _ in 0..8 {
                c = (c >> 1) ^ (0xedb88320u32 & 0u32.wrapping_sub(c & 1));
            }
        }
        !c
    }
    fn header(b: &[u8]) -> io::Result<()> {
        need(b.len() == 512 && &b[..8] == b"EFI PART", "GPT signature")?;
        let n = u32at(b, 12)? as usize;
        need((92..=512).contains(&n), "GPT header size")?;
        let mut d = b[..n].to_vec();
        d[16..20].fill(0);
        need(crc(&d) == u32at(b, 16)?, "GPT header CRC")
    }
    struct Config {
        map: BTreeMap<String, String>,
    }
    impl Config {
        fn field(&self, k: &str) -> io::Result<&str> {
            self.map
                .get(k)
                .map(String::as_str)
                .ok_or_else(|| bad("missing exact config field"))
        }
        fn bytes(&self, k: &str) -> io::Result<Vec<u8>> {
            unhex(self.field(k)?)
        }
        fn load(path: &Path, pin: &str) -> io::Result<Self> {
            let name = path.to_str().ok_or_else(|| bad("Unicode config path"))?;
            need(
                name.starts_with(r"C:\") && !name[3..].contains(':'),
                "config DATA reads restricted to ordinary guest C path",
            )?;
            ordinary(path.parent().ok_or_else(|| bad("config parent"))?)?;
            let m = fs::symlink_metadata(path)?;
            need(
                m.is_file() && m.file_attributes() & 0x400 == 0 && m.len() <= 262144,
                "ordinary bounded config",
            )?;
            let mut f = OpenOptions::new().read(true).share_mode(1).open(path)?;
            let mut b = Vec::new();
            f.read_to_end(&mut b)?;
            need(sha(&b)? == pin, "config SHA differs")?;
            let s = String::from_utf8(b).map_err(io::Error::other)?;
            let mut map = BTreeMap::new();
            for line in s.lines() {
                let (k, v) = line
                    .split_once('=')
                    .ok_or_else(|| bad("config key=value"))?;
                need(
                    map.insert(k.to_owned(), v.to_owned()).is_none(),
                    "duplicate config field",
                )?;
            }
            let c = Self { map };
            need(
                c.map.len() == 8
                    && c.field("kind")? == "T4-ONLINE-LOCKED-PHYSICAL-v1"
                    && c.field("ack")? == ACK,
                "exact eight-field probe config",
            )?;
            need(
                c.field("boot_unix_ms")?
                    .parse::<u64>()
                    .map_err(io::Error::other)?
                    == 1793856847028,
                "actual current AP boot config required",
            )?;
            for k in ["snapshot_sha256", "observed_receipt_sha256"] {
                need(
                    c.field(k)?.len() == 64 && c.bytes(k)?.len() == 32,
                    "config hash width",
                )?;
            }
            for k in ["target_info_hex", "C_info_hex", "D_info_hex"] {
                need(c.bytes(k)?.len() == 144, "native row pin length")?;
            }
            Ok(c)
        }
    }
    fn ordinary(path: &Path) -> io::Result<()> {
        need(
            path.is_absolute()
                && !path
                    .components()
                    .any(|p| matches!(p, Component::CurDir | Component::ParentDir)),
            "ordinary absolute ancestry",
        )?;
        for a in path.ancestors() {
            let m = fs::symlink_metadata(a)?;
            need(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary ancestry",
            )?;
        }
        Ok(())
    }
    fn boot() -> io::Result<u64> {
        let mut b = [0u8; 48];
        let mut n = 0;
        let s =
            unsafe { NtQuerySystemInformation(3, b.as_mut_ptr().cast(), b.len() as u32, &mut n) };
        if s < 0 { return Err(io::Error::other(format!("actual boot query failed: NTSTATUS=0x{:08x}, returned_bytes={n}, buffer_bytes={}", s as u32, b.len()))); }
        let ticks = u64at(&b, 0)?;
        ticks
            .checked_sub(116444736000000000)
            .map(|v| v / 10000)
            .ok_or_else(|| bad("boot epoch"))
    }
    fn bind_info(info: &[u8], g: &str, number: u32, at: u64, n: u64) -> io::Result<()> {
        need(
            info.len() == 144
                && u32at(info, 0)? == 1
                && u32at(info, 24)? == number
                && u64at(info, 8)? == at
                && u64at(info, 16)? == n
                && info[48..64] == guid(g)?
                && u64at(info, 64)? == 0,
            "exact GPT native selected identity/attrs differs",
        )
    }
    fn snapshot(h: &Handle, c: &Config, l: &mut Log) -> io::Result<String> {
        let d = ctl(h, 0x002d1080, &[], 12, "physical-device", l)?;
        need(
            d.len() == 12 && u32at(&d, 0)? == 7 && u32at(&d, 4)? == 0 && u32at(&d, 8)? == 0,
            "actual physical0 native device",
        )?;
        let len = ctl(h, 0x0007405c, &[], 8, "physical-length", l)?;
        need(
            len.len() == 8 && u64at(&len, 0)? == DISK,
            "actual120GiB disk length",
        )?;
        let mut input = [0u8; 12];
        input[0] = 6;
        let alignment = ctl(h, 0x002d1400, &input, 28, "physical-alignment", l)?;
        need(
            alignment.len() == 28
                && u32at(&alignment, 16)? == 512
                && u32at(&alignment, 20)? == 4096,
            "actual512/4096 alignment",
        )?;
        let attrs = ctl(h, 0x000700f0, &[], 16, "physical-attributes", l)?;
        need(
            attrs.len() == 16 && u64at(&attrs, 8)? == 0,
            "physical disk must remain ONLINE/RW",
        )?;
        let native = ctl(h, 0x00070050, &[], 65536, "physical-native-GPT", l)?;
        need(
            native.len() >= 48
                && u32at(&native, 0)? == 1
                && native[8..24] == guid(DISKG)?
                && native.len() == 48 + 144 * u32at(&native, 4)? as usize
                && u32at(&native, 4)? <= 128,
            "complete native GPT framing",
        )?;
        for (k, g, no, at, n) in [
            ("target_info_hex", TG, 4, T, TL),
            ("C_info_hex", CG, 3, 331350016, 64091062272),
            ("D_info_hex", DG, 6, 68719476736, 55834574848),
        ] {
            let expected = c.bytes(k)?;
            bind_info(&expected, g, no, at, n)?;
            let rows: Vec<_> = native[48..]
                .chunks_exact(144)
                .filter(|row| row[48..64] == guid(g).unwrap())
                .collect();
            need(
                rows.len() == 1 && rows[0] == expected.as_slice(),
                "actual complete native row differs from operator pin",
            )?;
            if no == 4 {
                need(
                    expected[32..48] == guid(PRIVATE)? || expected[32..48] == guid(BASIC)?,
                    "T type must be actual Basic orprojectPrivate0",
                )?;
            }
            if no == 6 {
                need(
                    expected[32..48] == guid(PRIVATE)?,
                    "AP D6 must remain PRIVATE0",
                )?;
            }
        }
        let mbr = read_at(h, 0, 512, "physical-MBR-metadata", l)?;
        let p = read_at(h, 512, 512, "physical-primary-GPT-metadata", l)?;
        header(&p)?;
        need(
            u64at(&p, 24)? == 1
                && u64at(&p, 32)? == DISK / 512 - 1
                && p[56..72] == guid(DISKG)?
                && u64at(&p, 72)? == 2,
            "primary GPT geometry",
        )?;
        let count = u32at(&p, 80)? as usize;
        let width = u32at(&p, 84)? as usize;
        need(count == 128 && width == 128, "fixture GPT128x128")?;
        let entries = read_at(
            h,
            u64at(&p, 72)?
                .checked_mul(512)
                .ok_or_else(|| bad("GPT offset"))?,
            count * width,
            "physical-primary-array-metadata",
            l,
        )?;
        need(crc(&entries) == u32at(&p, 88)?, "primary array CRC")?;
        let b = read_at(h, DISK - 512, 512, "physical-backup-GPT-metadata", l)?;
        header(&b)?;
        need(
            u64at(&b, 24)? == DISK / 512 - 1
                && u64at(&b, 32)? == 1
                && u32at(&b, 80)? == 128
                && u32at(&b, 84)? == 128
                && b[56..72] == guid(DISKG)?
                && u64at(&b, 72)? == DISK / 512 - 33,
            "backup GPT geometry",
        )?;
        let be = read_at(
            h,
            u64at(&b, 72)?
                .checked_mul(512)
                .ok_or_else(|| bad("backup offset"))?,
            entries.len(),
            "physical-backup-array-metadata",
            l,
        )?;
        need(
            be == entries && crc(&be) == u32at(&b, 88)?,
            "complete GPT arrays differ",
        )?;
        let target = &entries[3 * 128..4 * 128];
        need(
            target[16..32] == guid(TG)?
                && u64at(target, 32)?.checked_mul(512) == Some(T)
                && u64at(target, 40)?
                    .checked_sub(u64at(target, 32)?)
                    .and_then(|v| v.checked_add(1))
                    .and_then(|v| v.checked_mul(512))
                    == Some(TL)
                && u64at(target, 48)? == 0,
            "raw slot4 target differs",
        )?;
        let mut all = mbr;
        all.extend(&p);
        all.extend(&entries);
        all.extend(&b);
        all.extend(&native);
        let pin = sha(&all)?;
        need(
            pin == c.field("snapshot_sha256")?,
            "actual complete GPT/MBR/native snapshot differs from CURRENT observer pin",
        )?;
        l.record(&format!("{{\"kind\":\"complete-native-GPT-C-D-T-bookend\",\"sha256\":{},\"target_only_window_absolute\":{},\"disk_online_rw\":true}}",esc(&pin),ABS))?;
        Ok(pin)
    }
    fn volume_bind(h: &Handle, c: &Config, l: &mut Log) -> io::Result<()> {
        let d = ctl(h, 0x002d1080, &[], 12, "T-native-device", l)?;
        need(
            d.len() == 12 && u32at(&d, 0)? == 7 && u32at(&d, 4)? == 0 && u32at(&d, 8)? == 4,
            "actual T0/4 device",
        )?;
        let p = ctl(h, 0x00070048, &[], 144, "T-native-partition", l)?;
        need(
            p == c.bytes("target_info_hex")?,
            "T exact native144 differs",
        )?;
        let e = ctl(h, 0x00560000, &[], 32, "T-native-volume-extents", l)?;
        need(
            e.len() == 32
                && u32at(&e, 0)? == 1
                && u32at(&e, 8)? == 0
                && u64at(&e, 16)? == T
                && u64at(&e, 24)? == TL,
            "T exact one native extent",
        )?;
        need(
            ctl(h, 0x00070024, &[], 0, "T-IS-WRITABLE-online", l)?.is_empty(),
            "T writable query unexpected bytes",
        )
    }
    fn c_control(l: &mut Log) -> io::Result<String> {
        let mut w = [0u16; 512];
        let n = unsafe { GetWindowsDirectoryW(w.as_mut_ptr(), 512) };
        need(
            n >= 3
                && n < 512
                && w[0] == (b'C' as u16)
                && w[1] == (b':' as u16)
                && w[2] == (b'\\' as u16),
            "actualWindows C route",
        )?;
        let h = Handle::open(CFILE, 0x80000000, 0x00200000, "C-control-READONLY-open", l)?;
        let mut id = [0u8; 24];
        let mut st = [0u8; 24];
        for (class, b) in [(18, &mut id), (1, &mut st)] {
            let ok =
                unsafe { GetFileInformationByHandleEx(h.raw, class, b.as_mut_ptr().cast(), 24) }
                    != 0;
            let e = (!ok).then(io::Error::last_os_error);
            l.native(
                "C-control-native-metadata",
                ok,
                e.as_ref().and_then(io::Error::raw_os_error),
                24,
                if ok { 24 } else { 0 },
            )?;
            if let Some(e) = e {
                return Err(e);
            }
        }
        need(
            u64at(&id, 0)? == 12259941802954451809
                && u64at(&st, 8)? == 4096
                && u32at(&st, 16)? == 1
                && st[20] == 0
                && st[21] == 0,
            "actual ordinaryC control serial/EOF/links/state",
        )?;
        let bytes = read_at(&h, 0, 4096, "C-control-fixed4KiB-READ", l)?;
        need(sha(&bytes)? == CPIN, "C control hash differs")?;
        h.close("C-control-close", l)?;
        Ok(hex(&id))
    }
    #[derive(Default)]
    struct Outcome {
        writes: u32,
        requested: u32,
        returned: u32,
        api: bool,
        flush_called: bool,
        flush_ok: bool,
        readback: bool,
    }
    impl Outcome {
        fn json(&self) -> String {
            format!(
                "{{\"physical_WriteFile_calls\":{},\"requested_bytes\":{},\"returned_bytes\":{},\"WriteFile_succeeded\":{},\"physical_flush_called\":{},\"physical_flush_succeeded\":{},\"same_bytes_readback_verified\":{},\"D6_payload_write_calls\":0,\"GPT_setters\":0,\"offline_or_online_calls\":0}}",
                self.writes,
                self.requested,
                self.returned,
                self.api,
                self.flush_called,
                self.flush_ok,
                self.readback
            )
        }
    }
    // This raw RW owner never escapes. Payload methods accept NO offset/length; only fixedcheckedT8KiB.
    struct PhysicalWindow {
        h: Handle,
        issued: bool,
    }
    impl PhysicalWindow {
        fn rewrite_same_once(
            &mut self,
            c: &Config,
            original: &[u8],
            l: &mut Log,
            o: &mut Outcome,
        ) -> io::Result<()> {
            need(
                !self.issued
                    && original.len() == N
                    && sha(original)? == MARKER
                    && T.checked_add(REL) == Some(ABS)
                    && REL + N as u64 <= TL
                    && ABS + N as u64 <= T + TL
                    && T >= 331350016 + 64091062272
                    && T + TL <= 68719476736,
                "one fixed T-only disjoint physical window",
            )?;
            snapshot(&self.h, c, l)?;
            let before = read_at(&self.h, ABS, N, "physical-T-marker-READ-before", l)?;
            need(
                before == original,
                "actual physical marker differs before ONE write",
            )?;
            let mut b = Box::new(Aligned([0; 65536]));
            b.0[..N].copy_from_slice(original);
            let mut pos = 0;
            let ok = unsafe { SetFilePointerEx(self.h.raw, ABS as i64, &mut pos, 0) } != 0;
            let e = (!ok).then(io::Error::last_os_error);
            l.native(
                "physical-T-marker-write-seek",
                ok,
                e.as_ref().and_then(io::Error::raw_os_error),
                0,
                0,
            )?;
            if let Some(e) = e {
                return Err(e);
            }
            need(pos == ABS as i64, "physical write seek")?;
            l.record("{\"kind\":\"durable-BEFORE-single-physical-WriteFile\",\"absolute_offset\":65714388992,\"bytes\":8192,\"T_lock_retained\":true,\"sourceD_not_opened\":true}")?;
            self.issued = true;
            o.writes += 1;
            o.requested = N as u32;
            let mut n = 0;
            let ok = unsafe {
                WriteFile(
                    self.h.raw,
                    b.0.as_ptr().cast(),
                    N as u32,
                    &mut n,
                    ptr::null_mut(),
                )
            } != 0;
            let e = (!ok).then(io::Error::last_os_error);
            o.api = ok;
            o.returned = n;
            l.native(
                "physical-T-ONE-WriteFile",
                ok,
                e.as_ref().and_then(io::Error::raw_os_error),
                N as u32,
                n,
            )?;
            if let Some(e) = e {
                return Err(e);
            }
            need(
                n == N as u32,
                "short physical write; NO flush/retry/readback",
            )?;
            o.flush_called = true;
            let ok = unsafe { FlushFileBuffers(self.h.raw) } != 0;
            let e = (!ok).then(io::Error::last_os_error);
            o.flush_ok = ok;
            l.native(
                "physical-T-FlushFileBuffers",
                ok,
                e.as_ref().and_then(io::Error::raw_os_error),
                0,
                0,
            )?;
            if let Some(e) = e {
                return Err(e);
            }
            let after = read_at(&self.h, ABS, N, "physical-T-marker-READ-after", l)?;
            need(
                after == original && sha(&after)? == MARKER,
                "physical flushed readback differs",
            )?;
            o.readback = true;
            Ok(())
        }
    }
    fn attempt(c: &Config, l: &mut Log, o: &mut Outcome) -> io::Result<()> {
        need(
            boot()?
                == c.field("boot_unix_ms")?
                    .parse::<u64>()
                    .map_err(io::Error::other)?,
            "actual boot differs",
        )?;
        let ro = Handle::open(
            r"\\.\PhysicalDrive0",
            0x80000000,
            0x20000000,
            "physical0-READONLY-metadata-open",
            l,
        )?;
        let initial = snapshot(&ro, c, l)?;
        let cc = c_control(l)?;
        // Literal path cannot be redirected to D6 by config. Entire GPT/native binding was verified BEFORE opening T for data.
        let volume = Handle::open(
            r"\\?\GLOBALROOT\Device\Harddisk0\Partition4",
            0xc0000000,
            0xa0000000,
            "T4-ONLY-RW-owner-open",
            l,
        )?;
        volume_bind(&volume, c, l)?;
        let ntfs = ctl(&volume, 0x00090064, &[], 128, "T-NTFS-native-geometry", l)?;
        need(
            ntfs.len() >= 96
                && u64at(&ntfs, 0)? == 0xb83a28253a27dede
                && u32at(&ntfs, 40)? == 512
                && u32at(&ntfs, 44)? == 4096,
            "originalT NTFS serial/geometry",
        )?;
        let dirty = ctl(&volume, 0x00090078, &[], 4, "T-NTFS-dirty-query", l)?;
        need(
            dirty.len() == 4 && u32at(&dirty, 0)? & 1 == 0,
            "T filesystem dirty",
        )?;
        for (code, name) in [
            (0x00090018, "T-FSCTL_LOCK_VOLUME"),
            (0x00090020, "T-FSCTL_DISMOUNT_VOLUME"),
            (0x00090083, "T-FSCTL_ALLOW_EXTENDED_DASD_IO"),
        ] {
            need(
                ctl(&volume, code, &[], 0, name, l)?.is_empty(),
                "T control unexpected bytes",
            )?;
        }
        volume_bind(&volume, c, l)?;
        need(
            snapshot(&ro, c, l)? == initial && c_control(l)? == cc,
            "locked nativeC/GPT bookends",
        )?;
        let original = read_at(&volume, REL, N, "T-locked-owner-fixed-marker-READ", l)?;
        need(
            sha(&original)? == MARKER,
            "original exactT marker differs; NO physical write",
        )?;
        let mut physical = PhysicalWindow {
            h: Handle::open(
                r"\\.\PhysicalDrive0",
                0xc0000000,
                0xa0000000,
                "physical0-RW-private-window-open",
                l,
            )?,
            issued: false,
        };
        physical.rewrite_same_once(c, &original, l, o)?;
        need(
            snapshot(&physical.h, c, l)? == initial && c_control(l)? == cc,
            "postwrite nativeC/GPT bookends",
        )?;
        volume_bind(&volume, c, l)?;
        let final_t = read_at(
            &volume,
            REL,
            N,
            "T-locking-owner-fixed-marker-final-READ",
            l,
        )?;
        need(final_t == original, "lockingT owner readback differs")?;
        physical.h.close("physical0-RW-window-close", l)?;
        volume.close("T-locking-owner-close-releases-lock", l)?;
        need(
            snapshot(&ro, c, l)? == initial && c_control(l)? == cc && boot()? == 1793856847028,
            "postclose nativeC/GPT/boot bookends",
        )?;
        ro.close("physical0-READONLY-close", l)?;
        need(
            o.writes == 1 && o.returned == 8192 && o.flush_ok && o.readback,
            "actual complete singlewrite outcome",
        )?;
        Ok(())
    }
    pub fn run() -> io::Result<()> {
        let a: Vec<String> = std::env::args().skip(1).collect();
        need(
            a.len() == 8
                && a[0] == "--config"
                && a[2] == "--config-sha256"
                && a[4] == "--attempt"
                && a[6] == "--acknowledge-T-only"
                && a[7] == ACK,
            "exact config/pin/freshattempt/fixedT acknowledgement",
        )?;
        need(
            a[5].len() == 32
                && a[5]
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "fresh lowerhex32attempt",
        )?;
        let c = Config::load(Path::new(&a[1]), &a[3])?;
        ordinary(Path::new(r"C:\ntfs2refs"))?;
        let dir = Path::new(r"C:\ntfs2refs").join(format!("T-online-locked-physical-{}", a[5]));
        fs::create_dir(&dir)?;
        ordinary(&dir)?;
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(1)
            .open(dir.join("native.jsonl"))?;
        let mut log = Log {
            f,
            bytes: 0,
            calls: 0,
        };
        log.record(&format!("{{\"kind\":\"T4-ONLINE-LOCKED-PHYSICAL-single-control\",\"attempt\":{},\"pid\":{},\"boot_ms\":{},\"config_sha256\":{},\"historical_offline_failure_not_explained_away\":true,\"sourceD_open_calls\":0,\"conversion_or_recovery_authority\":false}}",esc(&a[5]),unsafe{GetCurrentProcessId()},boot()?,esc(&a[3])))?;
        let mut o = Outcome::default();
        let result = attempt(&c, &mut log, &mut o);
        let error = result.as_ref().err().map(|e| e.to_string());
        let native_error = result.as_ref().err().and_then(io::Error::raw_os_error);
        let terminal = format!(
            "{{\"kind\":\"T-online-locked-physical-terminal\",\"success\":{},\"native_calls\":{},\"outcome\":{},\"error\":{},\"native_error\":{},\"failure_unwind_closes_handles_but_native_close_status_unobserved\":{},\"retry_or_auto_restore\":false,\"stable_release_or_D6_qualification\":false}}",
            result.is_ok(),
            log.calls,
            o.json(),
            error.as_deref().map(esc).unwrap_or("null".into()),
            native_error.map(|e| e.to_string()).unwrap_or("null".into()),
            result.is_err()
        );
        let saved = log.record(&terminal);
        eprintln!("{}", terminal);
        match (result, saved) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        }
    }
}
