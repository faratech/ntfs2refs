//! Full-Windows owned recovery-WIM builder. NO BCD/firmware/source data writer.
//! All DISM targets/copies/temporary hive live under one fresh independent-J root.
use super::*;
use crate::{
    journal_file::GeneralJournalStorageBinding,
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
    reference_file::ReferenceFileSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Storage::FileSystem::GetVolumeInformationByHandleW,
    System::{
        Registry::*,
        SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
    },
};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryImageInput {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryImageBudget {
    pub ram_bytes: u64,
    pub maximum_input_bytes: u64,
    pub admitted_working_bytes: u64,
    pub maximum_final_wim_bytes: u64,
    pub minimum_free_bytes: u64,
    pub maximum_command_output_bytes: u64,
    pub maximum_command_seconds: u64,
    pub maximum_evidence_bytes: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryImageRequest {
    pub root: PathBuf,
    pub run_id: String,
    pub boot_wim: RecoveryImageInput,
    pub wim_index: u32,
    pub boot_sdi: RecoveryImageInput,
    pub runner: RecoveryImageInput,
    /// Pinned routing/resources copied into RAM before SAN3 leaves J offline.
    /// Its data does not grant source write or recovery authority.
    pub bootstrap: RecoveryImageInput,
    pub startup_args: Vec<String>,
    pub prepared_bundle_sha256: [u8; 32],
    pub budget: RecoveryImageBudget,
    pub observation: PartitionObservationBudget,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryImageArtifactPin {
    pub role: &'static str,
    pub path: PathBuf,
    pub snapshot: ReferenceFileSnapshot,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryImageCommand {
    pub tool: PathBuf,
    pub args: Vec<String>,
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub actual_exit_observed: bool,
    pub elapsed_ms: u128,
    pub termination_requested: bool,
    pub termination_error: Option<String>,
    pub monitor_error: Option<String>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub available_J_before: u64,
    pub available_J_after: u64,
}
struct HeldArtifact {
    file: RefCell<File>,
    pin: RecoveryImageArtifactPin,
}
pub struct OwnedRecoveryImage {
    source: PartitionSourceBinding,
    journal: GeneralJournalStorageBinding,
    root: PathBuf,
    root_guid: String,
    wim: PathBuf,
    sdi: PathBuf,
    runner: PathBuf,
    startup_args: Vec<String>,
    bundle: [u8; 32],
    control_sets: Vec<u32>,
    artifacts: Vec<HeldArtifact>,
    pins: Vec<RecoveryImageArtifactPin>,
    commands: Vec<RecoveryImageCommand>,
    _ancestors: Vec<File>,
    budget: RecoveryImageBudget,
    observation: PartitionObservationBudget,
    journal_volume: File,
    origin_marker: PathBuf,
}
fn bad(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.into())
}
fn need(v: bool, m: &str) -> io::Result<()> {
    if v { Ok(()) } else { Err(bad(m)) }
}
fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn system_dir() -> io::Result<PathBuf> {
    let mut b = [0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(b.as_mut_ptr(), b.len() as u32) } as usize;
    need(n > 0 && n < b.len(), "actual System32 unavailable")?;
    Ok(PathBuf::from(
        String::from_utf16(&b[..n]).map_err(io::Error::other)?,
    ))
}
fn full_windows(events: &mut Vec<NativeEvent>) -> io::Result<u32> {
    let mut key = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w(r"SYSTEM\CurrentControlSet\Control\MiniNT").as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status == 0 {
        unsafe {
            RegCloseKey(key);
        };
        return Err(bad("recovery image build is FULL Windows only, never PE"));
    }
    need(matches!(status, 2 | 3), "MiniNT absence couldnotbeproved")?;
    current_windows_disk(events)
}
fn path_text(p: &Path) -> io::Result<String> {
    let s = p.to_str().ok_or_else(|| bad("Unicode path required"))?;
    need(
        p.is_absolute()
            && !s.contains(['\0', '\r', '\n'])
            && !p
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "ordinary absolute path required",
    )?;
    Ok(s.into())
}
fn parent_chain(p: &Path) -> io::Result<Vec<File>> {
    let mut out = Vec::new();
    for a in p.ancestors() {
        let m = fs::symlink_metadata(a)?;
        need(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "ordinary held parent required",
        )?;
        out.push(
            OpenOptions::new()
                .access_mode(0x80)
                .share_mode(1)
                .custom_flags(0x02200000)
                .open(a)?,
        );
    }
    Ok(out)
}
fn available(p: &Path) -> io::Result<u64> {
    Ok(crate::resource_native::observe_available_resources(p)?.scratch_available_bytes)
}
fn store(p: &Path, v: &impl Serialize, limit: u64) -> io::Result<()> {
    let b = serde_json::to_vec(v).map_err(io::Error::other)?;
    need(
        b.len() as u64 <= limit,
        "bounded recovery image evidence required",
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(p)?;
    f.write_all(&b)?;
    f.write_all(b"\n")?;
    f.sync_all()
}
fn input_file(i: &RecoveryImageInput, source: &PartitionSourceBinding) -> io::Result<File> {
    path_text(&i.path)?;
    let f = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&i.path)?;
    need(
        f.metadata()?.is_file()
            && f.metadata()?.file_attributes() & 0x400 == 0
            && f.metadata()?.len() == i.bytes,
        "held input EOF/type differs",
    )?;
    let actual = crate::file_storage::final_path_guid(&f)?;
    let src = format!("{}\\", source.storage.volume_path()?);
    need(
        !actual
            .get(..src.len())
            .is_some_and(|v| v.eq_ignore_ascii_case(&src)),
        "input cannotread selected sourceD payload",
    )?;
    Ok(f)
}
fn copy_pin(
    input: &RecoveryImageInput,
    target: &Path,
    source: &PartitionSourceBinding,
    maximum: u64,
) -> io::Result<()> {
    need(input.bytes > 0 && input.bytes <= maximum, "input capacity")?;
    let mut from = input_file(input, source)?;
    let before = from.metadata()?;
    let mut to = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .open(target)?;
    let mut left = input.bytes;
    let mut buf = vec![0u8; 1024 * 1024];
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    while left > 0 {
        let n = usize::try_from(left.min(buf.len() as u64)).map_err(io::Error::other)?;
        from.read_exact(&mut buf[..n])?;
        hash.update(&buf[..n]);
        to.write_all(&buf[..n])?;
        left -= n as u64;
    }
    let mut extra = [0u8; 1];
    need(
        from.read(&mut extra)? == 0
            && from.metadata()?.len() == before.len()
            && from.metadata()?.modified()? == before.modified()?,
        "held input changed during streamcopy",
    )?;
    need(
        <[u8; 32]>::from(hash.finalize()) == input.sha256,
        "independent input SHA differs",
    )?;
    to.sync_all()?;
    need(
        crate::sha256_native::hash_range(&mut to, 0, input.bytes)? == input.sha256,
        "same-file copied bytes readback differs",
    )?;
    Ok(())
}
fn same_file_copy(from: &Path, to: &Path, max: u64) -> io::Result<()> {
    let mut f = OpenOptions::new().read(true).share_mode(1).open(from)?;
    let n = f.metadata()?.len();
    need(n > 0 && n <= max, "owned file copy bound")?;
    let hash = crate::sha256_native::hash_range(&mut f, 0, n)?;
    drop(f);
    let input = RecoveryImageInput {
        path: from.to_path_buf(),
        bytes: n,
        sha256: hash,
    };
    let mut r = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&input.path)?;
    let mut o = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .open(to)?;
    let mut buffer = [0u8; 65536];
    let mut left = n;
    while left > 0 {
        let n = (left.min(buffer.len() as u64)) as usize;
        r.read_exact(&mut buffer[..n])?;
        o.write_all(&buffer[..n])?;
        left -= n as u64;
    }
    o.sync_all()?;
    need(
        crate::sha256_native::hash_range(&mut o, 0, n)? == hash,
        "mounted-image copy readback differs",
    )
}
fn startup(args: &[String], bundle: [u8; 32]) -> io::Result<Vec<u8>> {
    need(
        args.len() <= 64 && args.iter().map(String::len).sum::<usize>() <= 8192,
        "startup arg budget",
    )?;
    let pin = hex::encode(bundle);
    need(
        args.iter().any(|s| s == &pin),
        "startup must carry exact OUTER prepared bundle SHA",
    )?;
    let mut cmd = String::from(
        "@echo off\r\n\"%SystemRoot%\\System32\\wpeinit.exe\"\r\n\"%SystemRoot%\\System32\\n2r-runner.exe\"",
    );
    for a in args {
        need(
            !a.is_empty()
                && a.len() <= 2048
                && !a
                    .chars()
                    .any(|c| c.is_control() || "\"&|<>^%!(),".contains(c)),
            "unsafe startup literal arg",
        )?;
        let trailing = a.chars().rev().take_while(|c| *c == '\\').count();
        cmd.push_str(" \"");
        cmd.push_str(a);
        cmd.extend(std::iter::repeat_n('\\', trailing));
        cmd.push('"');
    }
    // Preserve failure in the recovery console. Exiting winpeshl's only app
    // could otherwise reboot and accidentally retry an unqualified state.
    // Reboot is requested only after the Rust runner actually returns zero.
    cmd.push_str("\r\nset \"N2R_EXIT=%ERRORLEVEL%\"\r\nif not \"%N2R_EXIT%\"==\"0\" goto n2r_failed\r\n\"%SystemRoot%\\System32\\wpeutil.exe\" Reboot\r\necho Restart request returned. Restart normally when ready.\r\ngoto n2r_console\r\n:n2r_failed\r\necho Conversion stopped. Preserve recovery artifacts and review the error above.\r\n:n2r_console\r\n\"%SystemRoot%\\System32\\cmd.exe\" /d /k\r\nexit /b %N2R_EXIT%\r\n");
    Ok(cmd.into_bytes())
}
fn write_bytes(p: &Path, b: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(1)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    let n = f.metadata()?.len();
    let expected: [u8; 32] = sha2::Sha256::digest(b).into();
    need(
        n == b.len() as u64 && crate::sha256_native::hash_range(&mut f, 0, n)? == expected,
        "startup/config exact write/readback differs",
    )
}
fn command(
    tool: &Path,
    args: Vec<String>,
    root: &Path,
    index: usize,
    b: RecoveryImageBudget,
) -> io::Result<RecoveryImageCommand> {
    let out = root.join(format!("command-{index:02}.stdout.log"));
    let err = root.join(format!("command-{index:02}.stderr.log"));
    let stdout = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .share_mode(1)
        .open(&out)?;
    let stderr = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .share_mode(1)
        .open(&err)?;
    let before = available(root)?;
    need(before >= b.minimum_free_bytes, "J minfree before command")?;
    let start = Instant::now();
    let mut child = Command::new(tool)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .creation_flags(0x08000000)
        .current_dir(root)
        .env("TEMP", root.join("temp"))
        .env("TMP", root.join("temp"))
        .spawn()?;
    let pid = child.id();
    let mut terminated = false;
    let mut termination_error = None;
    let mut monitor_error = None;
    let status = loop {
        let observed = (|| -> io::Result<_> {
            let exited = child.try_wait()?;
            let over = start.elapsed() > Duration::from_secs(b.maximum_command_seconds)
                || stdout
                    .metadata()?
                    .len()
                    .saturating_add(stderr.metadata()?.len())
                    > b.maximum_command_output_bytes
                || available(root)? < b.minimum_free_bytes;
            Ok((exited, over))
        })();
        match observed {
            Ok((Some(status), _)) => break status,
            Ok((None, false)) => std::thread::sleep(Duration::from_millis(50)),
            other => {
                if let Err(e) = other {
                    monitor_error = Some(e.to_string());
                }
                terminated = true;
                if let Err(e) = child.kill() {
                    termination_error = Some(e.to_string());
                }
                // Never return while an owned native command is known still running.
                break child.wait()?;
            }
        }
    };
    stdout.sync_all()?;
    stderr.sync_all()?;
    let after = available(root)?;
    let record = RecoveryImageCommand {
        tool: tool.to_path_buf(),
        args,
        pid,
        exit_code: status.code(),
        actual_exit_observed: true,
        elapsed_ms: start.elapsed().as_millis(),
        termination_requested: terminated,
        termination_error,
        monitor_error,
        stdout_path: out,
        stderr_path: err,
        stdout_bytes: stdout.metadata()?.len(),
        stderr_bytes: stderr.metadata()?.len(),
        available_J_before: before,
        available_J_after: after,
    };
    store(
        &root.join(format!("command-{index:02}.json")),
        &record,
        b.maximum_evidence_bytes,
    )?;
    Ok(record)
}
fn checked_command(
    tool: &Path,
    args: Vec<String>,
    root: &Path,
    b: RecoveryImageBudget,
    records: &mut Vec<RecoveryImageCommand>,
    initial_free: u64,
) -> io::Result<()> {
    let r = command(tool, args, root, records.len(), b)?;
    let ok = r.exit_code == Some(0)
        && !r.termination_requested
        && r.monitor_error.is_none()
        && r.stdout_bytes.saturating_add(r.stderr_bytes) <= b.maximum_command_output_bytes
        && r.available_J_after >= b.minimum_free_bytes
        && initial_free.saturating_sub(r.available_J_after) <= b.admitted_working_bytes;
    records.push(r);
    need(
        ok,
        "actual owned image command failed/timedout/overbudget; preserve all owned artifacts",
    )
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open_key(path: &str, access: u32) -> io::Result<Key> {
    let mut h = std::ptr::null_mut();
    let s = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w(path).as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut h,
        )
    };
    if s != 0 {
        Err(io::Error::from_raw_os_error(s as i32))
    } else {
        Ok(Key(h))
    }
}
fn dword(key: &Key, name: &str) -> io::Result<u32> {
    let mut t = 0;
    let mut n = 4;
    let mut v = 0u32;
    let s = unsafe {
        RegQueryValueExW(
            key.0,
            w(name).as_ptr(),
            std::ptr::null_mut(),
            &mut t,
            (&mut v as *mut u32).cast(),
            &mut n,
        )
    };
    if s != 0 {
        return Err(io::Error::from_raw_os_error(s as i32));
    }
    need(
        t == REG_DWORD && n == 4,
        "actual mountedIMAGE Select/Policy must beDWORD",
    )?;
    Ok(v)
}
fn san_image(hive: &str) -> io::Result<Vec<u32>> {
    let select = open_key(&format!("{hive}\\Select"), KEY_QUERY_VALUE)?;
    let mut sets = vec![dword(&select, "Current")?, dword(&select, "Default")?];
    sets.sort_unstable();
    sets.dedup();
    for n in &sets {
        need(
            (1..=999).contains(n),
            "actual image ControlSet select invalid",
        )?;
        let cs = format!("{hive}\\ControlSet{n:03}");
        let _existing = open_key(&cs, KEY_QUERY_VALUE)?;
        let path = format!("{cs}\\Services\\partmgr\\Parameters");
        let mut key = std::ptr::null_mut();
        let mut disposition = 0;
        let s = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                w(&path).as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        if s != 0 {
            return Err(io::Error::from_raw_os_error(s as i32));
        }
        let key = Key(key);
        let three = 3u32;
        let s = unsafe {
            RegSetValueExW(
                key.0,
                w("SanPolicy").as_ptr(),
                0,
                REG_DWORD,
                (&three as *const u32).cast(),
                4,
            )
        };
        if s != 0 {
            return Err(io::Error::from_raw_os_error(s as i32));
        }
        need(
            dword(&key, "SanPolicy")? == 3,
            "IMAGE earlySAN3 readback differs",
        )?;
        let s = unsafe { RegFlushKey(key.0) };
        if s != 0 {
            return Err(io::Error::from_raw_os_error(s as i32));
        }
    }
    let root = open_key(hive, KEY_QUERY_VALUE)?;
    let s = unsafe { RegFlushKey(root.0) };
    if s != 0 {
        return Err(io::Error::from_raw_os_error(s as i32));
    }
    Ok(sets)
}
fn enrollment(
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    jv: &File,
    b: PartitionObservationBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    source.validate()?;
    journal.validate()?;
    need(
        source.storage.disk_number != journal.disk.disk_number
            && layout::guid_bytes(&source.storage.identity.disk_guid)?
                != layout::guid_bytes(&journal.disk.identity.disk_guid)?,
        "recovery image J must be different physical disk",
    )?;
    need(
        source.storage.identity.partition_bytes == 55834574848
            && source.storage.identity.logical_sector_bytes == 512
            && source.storage.identity.physical_sector_bytes == 4096,
        "fixed shared52GiB source profile required",
    )?;
    let os = full_windows(events)?;
    need(
        os == source.storage.disk_number,
        "fullWindows shared source physicalOSproof differs",
    )?;
    let mut physical = device_file(
        &format!("\\\\.\\PhysicalDrive{}", source.storage.disk_number),
        false,
        false,
    )?;
    let observed = partition_isolation::observe_basic(&mut physical, source, b, events)?;
    need(
        observed.gpt.target_attributes == 0x1000000000000000,
        "prepared source must retain actualBASICRO",
    )?;
    journal.disk.validate_volume_extent(&control(
        jv,
        "recovery-image-J-native-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        events,
    )?)?;
    let info = control(
        jv,
        "recovery-image-J-native-info",
        0x00070048,
        &[],
        144,
        events,
    )?;
    need(
        info.len() == 144
            && info[48..64] == layout::guid_bytes(&journal.disk.identity.partition_guid)?
            && layout::u64_at(&info, 8)? == journal.disk.identity.partition_offset
            && layout::u64_at(&info, 16)? == journal.disk.identity.partition_bytes,
        "actual held J native enrollment differs",
    )?;
    let jp = device_file(
        &format!("\\\\.\\PhysicalDrive{}", journal.disk.disk_number),
        false,
        false,
    )?;
    let jl = control(
        &jp,
        "recovery-image-J-physical-length",
        LENGTH,
        &[],
        8,
        events,
    )?;
    let jg = control(
        &jp,
        "recovery-image-J-physical-GPT",
        LAYOUT,
        &[],
        65536,
        events,
    )?;
    need(
        jl.len() == 8
            && layout::u64_at(&jl, 0)? == journal.disk.identity.disk_bytes
            && jg.len() >= 48
            && layout::u32_at(&jg, 0)? == 1
            && jg[8..24] == layout::guid_bytes(&journal.disk.identity.disk_guid)?,
        "actualindependentJphysicalGUID/lengthdiffers",
    )?;
    let mut label = [0u16; 261];
    let mut fsname = [0u16; 32];
    let mut serial = 0;
    let mut comp = 0;
    let mut flags = 0;
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            jv.as_raw_handle(),
            label.as_mut_ptr(),
            261,
            &mut serial,
            &mut comp,
            &mut flags,
            fsname.as_mut_ptr(),
            32,
        )
    } != 0;
    if !ok {
        return Err(io::Error::last_os_error());
    }
    need(
        fsname[..5] == [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0],
        "fixed nativeNTFS journal required",
    )
}
fn image_subdir(path: &Path, mount: &Path) -> io::Result<()> {
    let relative = path
        .strip_prefix(mount)
        .map_err(|_| bad("imagepathleavesownedmount"))?;
    let mut at = mount.to_path_buf();
    for part in relative.components() {
        need(
            matches!(part, Component::Normal(_)),
            "ordinaryimagecomponent",
        )?;
        at.push(part);
        let m = fs::symlink_metadata(&at)?;
        need(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "mountedimagechilddirectoryisredirected",
        )?;
    }
    Ok(())
}
fn hold_artifact(role: &'static str, path: PathBuf, maximum: u64) -> io::Result<HeldArtifact> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&path)?;
    crate::file_storage::require_readonly_access(&file)?;
    let snapshot = crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    need(
        snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
        "bounded ordinary final artifact",
    )?;
    let sha256 = crate::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)?;
    need(
        crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == snapshot,
        "finalartifact changed during held hash",
    )?;
    Ok(HeldArtifact {
        file: RefCell::new(file),
        pin: RecoveryImageArtifactPin {
            role,
            path,
            snapshot,
            sha256,
        },
    })
}
impl OwnedRecoveryImage {
    pub fn source_binding(&self) -> &PartitionSourceBinding {
        &self.source
    }
    pub fn journal_binding(&self) -> &GeneralJournalStorageBinding {
        &self.journal
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn root_guid_path(&self) -> &str {
        &self.root_guid
    }
    pub fn wim_path(&self) -> &Path {
        &self.wim
    }
    pub fn sdi_path(&self) -> &Path {
        &self.sdi
    }
    pub fn runner_path(&self) -> &Path {
        &self.runner
    }
    pub fn startup_args(&self) -> &[String] {
        &self.startup_args
    }
    pub fn prepared_bundle_sha256(&self) -> [u8; 32] {
        self.bundle
    }
    pub fn artifact_pins(&self) -> &[RecoveryImageArtifactPin] {
        &self.pins
    }
    pub fn san_policy(&self) -> u32 {
        3
    }
    pub fn san_control_sets(&self) -> &[u32] {
        &self.control_sets
    }
    pub fn commands(&self) -> &[RecoveryImageCommand] {
        &self.commands
    }
    pub fn origin_marker_path(&self) -> &Path {
        &self.origin_marker
    }
    pub fn origin_marker_ram_relative_path(&self) -> &str {
        r"Windows\System32\ntfs2refs-recovery-origin.json"
    }
    pub fn origin_marker_sha256(&self) -> [u8; 32] {
        self.pins
            .iter()
            .find(|p| p.role == "origin-marker")
            .expect("ownedoriginmarker")
            .sha256
    }
    pub fn wim_sha256(&self) -> [u8; 32] {
        self.pins
            .iter()
            .find(|p| p.role == "wim")
            .expect("ownedWIM")
            .sha256
    }
    pub fn sdi_sha256(&self) -> [u8; 32] {
        self.pins
            .iter()
            .find(|p| p.role == "sdi")
            .expect("ownedSDI")
            .sha256
    }
    pub fn runner_sha256(&self) -> [u8; 32] {
        self.pins
            .iter()
            .find(|p| p.role == "runner")
            .expect("ownedrunner")
            .sha256
    }
    pub fn bootstrap_sha256(&self) -> [u8; 32] {
        self.pins
            .iter()
            .find(|p| p.role == "bootstrap")
            .expect("constructed recovery image always owns bootstrap")
            .sha256
    }
    pub fn revalidate(&self) -> io::Result<()> {
        let mut events = Vec::new();
        enrollment(
            &self.source,
            &self.journal,
            &self.journal_volume,
            self.observation,
            &mut events,
        )?;
        need(
            available(&self.root)? >= self.budget.minimum_free_bytes,
            "J reserve beforeBCD",
        )?;
        for a in &self.artifacts {
            let mut f = a
                .file
                .try_borrow_mut()
                .map_err(|_| bad("artifact alreadyborrowed"))?;
            need(
                crate::reference_file::observe_reference_file_handle_with_limit(
                    &f,
                    self.budget.maximum_final_wim_bytes,
                )? == a.pin.snapshot
                    && crate::sha256_native::hash_range(&mut *f, 0, a.pin.snapshot.file_bytes)?
                        == a.pin.sha256,
                "actualheldrecoveryartifact identity/hash changed",
            )?;
        }
        Ok(())
    }
}
/// No native operation executes until this caller explicitly invokes build.
pub fn build(
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    journal_volume: &File,
    request: &RecoveryImageRequest,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OwnedRecoveryImage> {
    use sha2::Digest;
    let b = request.budget;
    need(
        b.ram_bytes >= 16 * 1024 * 1024
            && b.maximum_command_seconds > 0
            && b.maximum_command_seconds <= 7200
            && b.maximum_command_output_bytes > 0
            && b.maximum_evidence_bytes >= 65536
            && b.maximum_final_wim_bytes > 0
            && request.wim_index > 0
            && request.wim_index <= 16,
        "explicitboundedimagebudgets/index required",
    )?;
    need(
        request.run_id.len() == 32
            && request
                .run_id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "freshlowerhex32imageid",
    )?;
    path_text(&request.root)?;
    need(!request.root.exists(), "OWNEDfreshJrootrequired")?;
    let parent = request.root.parent().ok_or_else(|| bad("imageparent"))?;
    let ancestors = parent_chain(parent)?;
    enrollment(source, journal, journal_volume, request.observation, events)?;
    let parent_file = ancestors.first().ok_or_else(|| bad("heldparent"))?;
    let prefix = format!("{}\\", journal.disk.volume_path()?.trim_end_matches('\\'));
    need(
        crate::file_storage::final_path_guid(parent_file)?
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)),
        "actualheldimageparentmustbeJ",
    )?;
    let total = request
        .boot_wim
        .bytes
        .checked_add(request.boot_sdi.bytes)
        .and_then(|n| n.checked_add(request.runner.bytes))
        .and_then(|n| n.checked_add(request.bootstrap.bytes))
        .ok_or_else(|| bad("inputbyteoverflow"))?;
    need(
        total <= b.maximum_input_bytes
            && b.admitted_working_bytes
                >= total.checked_mul(2).ok_or_else(|| bad("workingoverflow"))?,
        "actualcopy+workingbudget insufficient",
    )?;
    let initial_free = available(parent)?;
    need(
        initial_free
            >= b.admitted_working_bytes
                .checked_add(b.minimum_free_bytes)
                .ok_or_else(|| bad("reserveoverflow"))?,
        "upfrontactualJcapacitycannotcoverimagework+reserve",
    )?;
    need(
        b.ram_bytes
            <= crate::resource_native::observe_available_resources(parent)?
                .available_physical_bytes,
        "actualRAM cannotcoverbuilderworkspace",
    )?;
    fs::create_dir(&request.root)?;
    let root = request.root.clone();
    let root_handle = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1)
        .custom_flags(0x02200000)
        .open(&root)?;
    let root_guid = crate::file_storage::final_path_guid(&root_handle)?;
    let mut ancestors = ancestors;
    ancestors.push(root_handle);
    let mount = root.join("mount");
    let scratch = root.join("dism-scratch");
    for dir in [&mount, &scratch, &root.join("temp")] {
        fs::create_dir(dir)?;
    }
    let wim = root.join("boot.wim");
    let sdi = root.join("boot.sdi");
    let runner = root.join("runner.exe");
    let bootstrap = root.join("n2r-bootstrap.json");
    let script = root.join("n2r-start.cmd");
    let ini = root.join("winpeshl.ini");
    let unattend = root.join("san3.xml");
    let origin_marker = root.join("ntfs2refs-recovery-origin.json");
    let mut records = Vec::new();
    let mut mounted = false;
    let mut hive_loaded = false;
    let operation = (|| -> io::Result<Vec<u32>> {
        copy_pin(&request.boot_wim, &wim, source, b.maximum_input_bytes)?;
        copy_pin(&request.boot_sdi, &sdi, source, b.maximum_input_bytes)?;
        copy_pin(&request.runner, &runner, source, b.maximum_input_bytes)?;
        copy_pin(&request.bootstrap, &bootstrap, source, b.ram_bytes / 64)?;
        // Before a persistent loader can point at this image, prove that its
        // boot-bound routing describes the SAME actually enrolled source/J.
        // A later BootGuard refusal cannot undo an early wrong-disk online.
        let mut route_file = OpenOptions::new().read(true).share_mode(1)
            .custom_flags(0x0020_0000).open(&bootstrap)?;
        let mut route_bytes = Vec::new();
        route_bytes.try_reserve_exact(usize::try_from(request.bootstrap.bytes).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        (&mut route_file).take(request.bootstrap.bytes.checked_add(1)
            .ok_or_else(|| bad("bootstrap route length overflow"))?).read_to_end(&mut route_bytes)?;
        need(route_bytes.len() as u64 == request.bootstrap.bytes
            && <[u8;32]>::from(sha2::Sha256::digest(&route_bytes)) == request.bootstrap.sha256,
            "held copied bootstrap route differs from admitted image input")?;
        #[derive(Deserialize)]
        struct BootstrapRouting {
            schema_version: u32,
            source: PartitionSourceBinding,
            journal: GeneralJournalStorageBinding,
            prepared_bundle_sha256: String,
        }
        let route: BootstrapRouting = serde_json::from_slice(&route_bytes).map_err(io::Error::other)?;
        need(route.schema_version == 1 && route.source == *source && route.journal == *journal
            && route.prepared_bundle_sha256 == hex::encode(request.prepared_bundle_sha256),
            "RAM bootstrap must preserve exact actually enrolled image source/J/bundle domain")?;
        drop(route_bytes);
        drop(route_file);
        write_bytes(
            &script,
            &startup(&request.startup_args, request.prepared_bundle_sha256)?,
        )?;
        write_bytes(&ini,b"[LaunchApps]\r\n%SYSTEMROOT%\\System32\\cmd.exe, /d /s /c X:\\Windows\\System32\\n2r-start.cmd\r\n")?;
        write_bytes(&unattend,br#"<?xml version="1.0" encoding="utf-8"?><unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="offlineServicing"><component name="Microsoft-Windows-PartitionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><SanPolicy>3</SanPolicy></component></settings></unattend>"#)?;
        store(
            &root.join("before-mount.json"),
            &serde_json::json!({"kind":"owned-recovery-image-before-mount","request":request,"source":source,"journal":journal,"actualJavailable":initial_free,"noBCD_orfirmware":true}),
            b.maximum_evidence_bytes,
        )?;
        let system = system_dir()?;
        let dism = system.join("Dism.exe");
        let reg = system.join("reg.exe");
        need(
            dism.is_file() && reg.is_file(),
            "officialSystem32DISM/reg required",
        )?;
        let common = vec![
            "/English".into(),
            format!("/ScratchDir:{}", path_text(&scratch)?),
            format!("/LogPath:{}", path_text(&root.join("dism.log"))?),
        ];
        let mut args = common.clone();
        args.extend([
            "/Mount-Image".into(),
            format!("/ImageFile:{}", path_text(&wim)?),
            format!("/Index:{}", request.wim_index),
            format!("/MountDir:{}", path_text(&mount)?),
            "/CheckIntegrity".into(),
        ]);
        mounted = true;
        checked_command(&dism, args, &root, b, &mut records, initial_free)?;
        let sys = mount.join("Windows/System32");
        image_subdir(&sys, &mount)?;
        need(
            sys.join("wpeinit.exe").is_file() && sys.join("winpeshl.exe").is_file()
                && sys.join("drivers/refs.sys").is_file(),
            "selected owned image must contain WinPE startup and native ReFS driver",
        )?;
        same_file_copy(&runner, &sys.join("n2r-runner.exe"), b.maximum_input_bytes)?;
        same_file_copy(
            &bootstrap,
            &sys.join("n2r-bootstrap.json"),
            b.ram_bytes / 64,
        )?;
        // Existing stock startup files are intentionally replaced ONLY inside owned copiedWIM.
        for (from, to) in [
            (&script, sys.join("n2r-start.cmd")),
            (&ini, sys.join("winpeshl.ini")),
        ] {
            if to.exists() {
                let saved = root.join(format!(
                    "original-{}",
                    to.file_name()
                        .ok_or_else(|| bad("startupname"))?
                        .to_string_lossy()
                ));
                let m = fs::symlink_metadata(&to)?;
                need(
                    m.is_file() && m.file_attributes() & 0x400 == 0 && m.len() <= 65536,
                    "existingownedimagestartupmustbeordinaryboundedfile",
                )?;
                same_file_copy(&to, &saved, 65536)?;
                fs::remove_file(&to)?;
            }
            same_file_copy(from, &to, 65536)?;
        }
        let mut args = common.clone();
        args.extend([
            format!("/Image:{}", path_text(&mount)?),
            format!("/Apply-Unattend:{}", path_text(&unattend)?),
        ]);
        checked_command(&dism, args, &root, b, &mut records, initial_free)?;
        let alias = format!("N2RRecovery_{}", request.run_id);
        match open_key(&alias, KEY_QUERY_VALUE) {
            Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => (),
            Err(e) => return Err(e),
            Ok(_) => return Err(bad("temporaryIMAGEhivekeycollision")),
        };
        let config = sys.join("config");
        image_subdir(&config, &mount)?;
        let hive = config.join("SYSTEM");
        let hm = fs::symlink_metadata(&hive)?;
        need(
            hm.is_file() && hm.file_attributes() & 0x400 == 0,
            "ownedmountedSYSTEMhivemissingorredirected",
        )?;
        hive_loaded = true;
        let load = checked_command(
            &reg,
            vec!["load".into(), format!("HKLM\\{alias}"), path_text(&hive)?],
            &root,
            b,
            &mut records,
            initial_free,
        );
        let configured = load.and_then(|()| san_image(&alias));
        // Always close/flushofflinekeys BEFORE one explicit unload. Never continue
        // tocommit if eitheractualconfigureorunloadstatusisunknown.
        let unload = checked_command(
            &reg,
            vec!["unload".into(), format!("HKLM\\{alias}")],
            &root,
            b,
            &mut records,
            initial_free,
        );
        if unload.is_ok() {
            hive_loaded = false;
        }
        let sets = match (configured, unload) {
            (Ok(v), Ok(())) => v,
            (Err(a), Err(z)) => {
                return Err(bad(format!(
                    "imageSANconfigurationfailed:{a}; temporaryhiveunloadalsofailed:{z}"
                )));
            }
            (Err(e), _) | (_, Err(e)) => return Err(e),
        };
        match open_key(&alias, KEY_QUERY_VALUE) {
            Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => (),
            _ => return Err(bad("temporaryIMAGEhiveremainsloaded; no commit")),
        };
        let marker = serde_json::json!({"kind":"ntfs2refs-owned-recovery-WIM-origin-v1","builder_nonce":request.run_id,
 "prepared_OUTER_bundle_sha256":hex::encode(request.prepared_bundle_sha256),"source":source,"journal":journal,
 "runner_sha256":hex::encode(request.runner.sha256),"startup_args":request.startup_args,"early_SAN_policy":3,
 "actual_IMAGE_ControlSets":sets,"current_default_select_verified":true,"no_final_WIM_self_hash":true});
        let marker_wire = serde_json::to_vec(&marker).map_err(io::Error::other)?;
        need(marker_wire.len() <= 65536, "originmarkerbound")?;
        write_bytes(&origin_marker, &marker_wire)?;
        same_file_copy(
            &origin_marker,
            &sys.join("ntfs2refs-recovery-origin.json"),
            65536,
        )?;
        store(
            &root.join("mounted-SAN3-startup-verified.json"),
            &serde_json::json!({"selectedControlSets":sets,"SANpolicy":3,"temporaryHiveUnloaded":true,"startupArgs":request.startup_args,"preparedOUTERbundleSHA":hex::encode(request.prepared_bundle_sha256),"verifiedMountedRunnerSHA":hex::encode(request.runner.sha256),"coldBootActuallyQualified":false}),
            b.maximum_evidence_bytes,
        )?;
        let mut args = common;
        args.extend([
            "/Unmount-Image".into(),
            format!("/MountDir:{}", path_text(&mount)?),
            "/Commit".into(),
            "/CheckIntegrity".into(),
        ]);
        checked_command(&dism, args, &root, b, &mut records, initial_free)?;
        mounted = false;
        need(
            fs::read_dir(&mount)?.next().is_none(),
            "DISMreturnedbutownedmountnotempty",
        )?;
        Ok(sets)
    })();
    let control_sets = match operation {
        Ok(v) => v,
        Err(error) => {
            let _ = store(
                &root.join("FAILED-preserved.json"),
                &serde_json::json!({"error":error.to_string(),"mountMayRemainActive":mounted,"temporaryIMAGEhiveMayRemainLoaded":hive_loaded,"commands":records,"allOwnedArtifactsPreserved":true,"automaticDeleteDiscardBCDSourceDataCalls":false}),
                b.maximum_evidence_bytes,
            );
            return Err(error);
        }
    };
    enrollment(source, journal, journal_volume, request.observation, events)?;
    let mut artifacts = Vec::new();
    for (role, path, max) in [
        ("wim", wim.clone(), b.maximum_final_wim_bytes),
        ("sdi", sdi.clone(), b.maximum_input_bytes),
        ("runner", runner.clone(), b.maximum_input_bytes),
        ("bootstrap", bootstrap.clone(), b.ram_bytes / 64),
        ("startup", script.clone(), 65536),
        ("winpeshl", ini.clone(), 65536),
        ("san3-unattend", unattend.clone(), 65536),
        ("origin-marker", origin_marker.clone(), 65536),
    ] {
        artifacts.push(hold_artifact(role, path, max)?);
    }
    let pins = artifacts.iter().map(|p| p.pin.clone()).collect();
    let image = OwnedRecoveryImage {
        source: source.clone(),
        journal: journal.clone(),
        root,
        wim,
        sdi,
        runner,
        root_guid,
        startup_args: request.startup_args.clone(),
        bundle: request.prepared_bundle_sha256,
        control_sets,
        artifacts,
        pins,
        commands: records,
        _ancestors: ancestors,
        budget: b,
        observation: request.observation,
        journal_volume: journal_volume.try_clone()?,
        origin_marker,
    };
    image.revalidate()?;
    store(
        &image.root.join("recovery-image-built.json"),
        &serde_json::json!({"kind":"owned-SAN3-recovery-image-built-v1","artifacts":image.pins,"commands":image.commands,"SANpolicy":3,"controlSets":image.control_sets,"commitCommandExit0":true,"coldBootQualified":false,"noBCDorSourceWriter":true}),
        b.maximum_evidence_bytes,
    )?;
    Ok(image)
}
