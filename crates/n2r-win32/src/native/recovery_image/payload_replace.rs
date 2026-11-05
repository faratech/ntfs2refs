//! Exact named payload replacement ONLY inside this builder's freshly copied
//! and mounted WIM. Original inputs/old image/old evidence are never targets.
use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DISPOSITION_INFO, FileAttributeTagInfo, FileDispositionInfo, GetFileInformationByHandleEx,
    SetFileInformationByHandle,
};
// Actual five-path receipt fe787754... proved this provider, not WOF/links.
const WIM_TAG: u32 = 0x8000_0008;
#[derive(Clone, Copy)]
enum Kind {
    Ordinary,
    Wim,
}
pub(super) struct MountedCopy {
    root: PathBuf,
    mount: PathBuf,
}
pub(super) fn mounted(
    root: &Path,
    mount: &Path,
    wim: &Path,
    index: u32,
    command: &RecoveryImageCommand,
) -> io::Result<MountedCopy> {
    need(
        mount == root.join("mount") && wim == root.join("boot.wim") && index > 0,
        "copied WIM mount scope does not bind current owned root/image/index",
    )?;
    let expected = vec![
        "/English".to_owned(),
        format!("/ScratchDir:{}", path_text(&root.join("dism-scratch"))?),
        format!("/LogPath:{}", path_text(&root.join("dism.log"))?),
        "/Mount-Image".into(),
        format!("/ImageFile:{}", path_text(wim)?),
        format!("/Index:{index}"),
        format!("/MountDir:{}", path_text(mount)?),
        "/CheckIntegrity".into(),
    ];
    need(
        command.args == expected
            && command.tool == system_dir()?.join("Dism.exe")
            && command.pid > 0
            && command.actual_exit_observed
            && command.exit_code == Some(0)
            && !command.termination_requested
            && command.termination_error.is_none()
            && command.monitor_error.is_none(),
        "actual successful native mount command does not belong to this copied WIM/index/root",
    )?;
    image_subdir(&mount.join("Windows/System32"), mount)?;
    Ok(MountedCopy {
        root: root.to_owned(),
        mount: mount.to_owned(),
    })
}
fn tag(file: &File) -> io::Result<[u32; 2]> {
    let mut value = [0u32; 2];
    // SAFETY: live File, exact initialized FILE_ATTRIBUTE_TAG_INFO eight bytes.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            value.as_mut_ptr().cast(),
            8,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn nt_name(file: &File) -> io::Result<String> {
    let observed = crate::native::offline_environment::kernel_ram_backing::object_name(file);
    observed.name.ok_or_else(|| {
        bad(format!(
            "owned mounted payload NT-name unknown: {:?}",
            observed.failure
        ))
    })
}
fn require_name(file: &File, expected: &str) -> io::Result<()> {
    need(
        nt_name(file)?.eq_ignore_ascii_case(expected),
        "actual mounted file object escapes exact owned System32 target",
    )
}

fn identity(file: &File, kind: Kind) -> io::Result<Vec<u32>> {
    let observed = crate::native::offline_environment::kernel_ram_backing::legacy52(file);
    if !observed.succeeded {
        return Err(observed
            .native_error
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| bad("mounted payload native52 identity unavailable")));
    }
    let raw = observed
        .raw_u32
        .ok_or_else(|| bad("mounted payload native52 response absent"))?;
    need(raw.len() == 13, "mounted payload native52 width differs")?;
    let observed = tag(file)?;
    need(
        observed[0] == raw[0]
            && match kind {
                Kind::Ordinary => raw[0] & 0x410 == 0 && observed[1] == 0,
                Kind::Wim => raw[0] == 1568 && observed[1] == WIM_TAG,
            },
        "actual mounted payload is neither ordinary nor the exact proven WIM placeholder",
    )?;
    // Access time can change during reads; identity/creation/write time,
    // attributes, EOF, links and actual file index must remain exact.
    Ok([0usize, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12]
        .iter()
        .map(|i| raw[*i])
        .collect())
}
fn context(error: io::Error, phase: &str, target: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "owned copied-WIM {phase} {}: {error}; native_error={:?}",
            target.display(),
            error.raw_os_error()
        ),
    )
}
/// `root` and `mount` are original live build locals. No public/path adoption
/// constructor or caller-controlled target exists; five names are admitted.
pub(super) fn replace(
    scope: &MountedCopy,
    from: &Path,
    name: &str,
    maximum: u64,
) -> io::Result<()> {
    let root = scope.root.as_path();
    let mount = scope.mount.as_path();
    let input_name = match name {
        "n2r-runner.exe" => "runner.exe",
        "n2r-bootstrap.json" => "n2r-bootstrap.json",
        "ntfs2refs-recovery-origin.json" => "ntfs2refs-recovery-origin.json",
        "n2r-start.cmd" => "n2r-start.cmd",
        "winpeshl.ini" => "winpeshl.ini",
        _ => return Err(bad("unknown copied-WIM replacement name")),
    };
    need(
        mount == root.join("mount") && from == root.join(input_name) && maximum > 0,
        "replacement is not this actual fresh builder root/mount/input",
    )?;
    let sys = mount.join("Windows/System32");
    image_subdir(&sys, mount)?;
    let to = sys.join(name);
    match fs::symlink_metadata(&to) {
        Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => (),
        Err(e) => return Err(context(e, "inspect existing payload", &to)),
        Ok(metadata) => {
            need(
                metadata.file_attributes() & 0x10 == 0
                    && (metadata.file_attributes() & 0x400 == 0
                        || metadata.file_attributes() == 1568)
                    && metadata.len() > 0
                    && metadata.len() <= maximum,
                "existing copied-WIM payload must be ordinary/nonempty/bounded",
            )?;
            // DELETE belongs only to this exact opened copied-WIM file. Its
            // sharing excludes other ordinary writers/deleters during backup.
            let mut old = OpenOptions::new()
                .access_mode(0x0011_0081)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&to)
                .map_err(|e| context(e, "open exact old payload", &to))?;
            let observed_tag = tag(&old)?;
            let kind = if observed_tag[0] & 0x400 == 0 {
                Kind::Ordinary
            } else {
                need(
                    observed_tag == [1568, WIM_TAG],
                    "unknown copied-WIM reparse provider; no follow/delete",
                )?;
                Kind::Wim
            };
            let directory = OpenOptions::new()
                .access_mode(0x0010_0080)
                .share_mode(3)
                .custom_flags(0x0220_0000)
                .open(&sys)?;
            let expected_name = format!("{}\\{name}", nt_name(&directory)?.trim_end_matches('\\'));
            require_name(&old, &expected_name)?;
            let before = identity(&old, kind)?;
            let n = old.metadata()?.len();
            need(
                n == metadata.len()
                    && old.metadata()?.file_attributes() == metadata.file_attributes(),
                "mounted payload changed across actual open",
            )?;
            let mut followed = match kind {
                Kind::Ordinary => None,
                Kind::Wim => {
                    // Read provider content normally; the no-follow DELETE
                    // owner remains the exact namespace object. Share DELETE
                    // only allows that already-held owner; this handle cannot delete.
                    let data = OpenOptions::new()
                        .access_mode(0x0010_0081)
                        .share_mode(5)
                        .open(&to)
                        .map_err(|e| context(e, "open proven WIM-provider content", &to))?;
                    require_name(&data, &expected_name)?;
                    let observed = tag(&data)?;
                    let observed_kind = if observed == [32, 0] {
                        Kind::Ordinary
                    } else {
                        Kind::Wim
                    };
                    let data_id = identity(&data, observed_kind)?;
                    need(
                        data_id[1..] == before[1..] && data.metadata()?.len() == n,
                        "provider-followed WIM content is not same exact held namespace file/EOF",
                    )?;
                    Some(data)
                }
            };
            let saved = root.join(format!("original-{name}"));
            let mut backup = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&saved)
                .map_err(|e| context(e, "create NEW backup", &saved))?;
            let reader = match followed.as_mut() {
                Some(data) => data,
                None => &mut old,
            };
            let mut hash = sha2::Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut left = n;
            while left > 0 {
                let count = left.min(buffer.len() as u64) as usize;
                reader.read_exact(&mut buffer[..count])?;
                backup.write_all(&buffer[..count])?;
                hash.update(&buffer[..count]);
                left -= count as u64;
            }
            let mut eof = [0u8; 1];
            need(
                reader.read(&mut eof)? == 0,
                "same held old copied-WIM file EOF/identity changed during backup",
            )?;
            require_name(&old, &expected_name)?;
            need(
                identity(&old, kind)? == before,
                "same WIM deletion owner changed during provider backup",
            )?;
            if let Some(data) = followed.as_ref() {
                require_name(data, &expected_name)?;
                let observed = tag(data)?;
                let observed_kind = if observed == [32, 0] {
                    Kind::Ordinary
                } else {
                    Kind::Wim
                };
                need(
                    identity(data, observed_kind)?[1..] == before[1..],
                    "same provider data identity changed during backup",
                )?;
            }
            drop(followed);
            let expected: [u8; 32] = hash.finalize().into();
            backup.sync_all()?;
            need(
                backup.metadata()?.len() == n
                    && crate::sha256_native::hash_range(&mut backup, 0, n)? == expected,
                "copied-WIM backup flush/readback hash or EOF differs; old file preserved",
            )?;
            backup.seek(SeekFrom::Start(n))?;
            need(backup.read(&mut eof)? == 0, "backup has unexpected tail")?;
            drop(backup);
            image_subdir(&sys, mount)?;
            need(
                identity(&old, kind)? == before,
                "old payload changed before exact held deletion",
            )?;
            // Same FILE_OBJECT deletion, after durable backup. No pathname
            // delete, permission change, recursive cleanup or retry fallback.
            require_name(&old, &expected_name)?;
            match kind {
                Kind::Ordinary => crate::file_storage::mark_delete_on_close(&old)?,
                Kind::Wim => {
                    need(
                        identity(&old, Kind::Wim)? == before,
                        "actual WIM owner changed before disposition",
                    )?;
                    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                    // SAFETY: exact SDK disposition, same DELETE-authorized
                    // no-follow object validated as current owned WIM target.
                    // Generic ordinary-file deletion guards remain unchanged.
                    if unsafe {
                        SetFileInformationByHandle(
                            old.as_raw_handle(),
                            FileDispositionInfo,
                            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                            std::mem::size_of_val(&disposition) as u32,
                        )
                    } == 0
                    {
                        return Err(context(
                            io::Error::last_os_error(),
                            "delete exact verified WIM owner",
                            &to,
                        ));
                    }
                }
            }
            drop(old);
            match fs::symlink_metadata(&to) {
                Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => (),
                Err(e) => return Err(context(e, "observe old target absence", &to)),
                Ok(_) => {
                    return Err(bad(
                        "backed-up copied-WIM target still present; no replacement retry",
                    ));
                }
            }
        }
    }
    image_subdir(&sys, mount)?;
    same_file_copy(from, &to, maximum).map_err(|e| context(e, "copy/readback NEW payload", &to))
}
