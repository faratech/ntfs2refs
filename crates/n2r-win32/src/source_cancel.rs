//! Exclusive unchanged-source cancellation. No raw payload writer is exposed.
pub mod preparation;
use crate::{general_layout::GeneralDiskBinding, layout::invalid, native::NativeEvent};
use serde::Serialize;
use std::{io, os::windows::fs::MetadataExt};
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW, SetVolumeMountPointW,
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}

pub fn validate_mount_paths(paths: &[String]) -> io::Result<()> {
    require(paths.len() <= 128, "cancel mount-path count exceeded")?;
    let mut seen = std::collections::BTreeSet::new();
    for path in paths {
        crate::discovery::validate_root(path)?;
        let b = path.as_bytes();
        require(
            b.len() >= 3
                && b[0].is_ascii_alphabetic()
                && b[1] == b':'
                && b[2] == b'\\'
                && path.len() <= 1024,
            "cancel requires ordinary drive/folder mount roots",
        )?;
        for part in path[3..]
            .trim_end_matches('\\')
            .split('\\')
            .filter(|p| !p.is_empty())
        {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            require(
                !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    && !(stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && matches!(stem.as_bytes()[3], b'1'..=b'9')),
                "device-name mount path refused",
            )?;
        }
        require(
            seen.insert(path.to_lowercase()),
            "duplicate cancel mount paths",
        )?;
    }
    Ok(())
}
fn destination_volume(path: &str) -> io::Result<Option<String>> {
    let input: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut output = [0u16; 1024];
    // SAFETY: validated terminated input and initialized bounded output buffer.
    if unsafe {
        GetVolumeNameForVolumeMountPointW(input.as_ptr(), output.as_mut_ptr(), output.len() as u32)
    } == 0
    {
        let e = io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(2 | 3 | 4390)) {
            return Ok(None);
        }
        return Err(e);
    }
    let end = output
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| invalid("unterminated occupied mount root"))?;
    String::from_utf16(&output[..end])
        .map(Some)
        .map_err(|_| invalid("invalid occupied mount root"))
}
fn preflight_paths(binding: &GeneralDiskBinding, paths: &[String]) -> io::Result<Vec<String>> {
    validate_mount_paths(paths)?;
    let mut missing = vec![];
    for path in paths {
        match destination_volume(path)? {
            Some(existing) => require(
                crate::layout::guid_bytes(&crate::discovery::volume_guid(&existing)?)?
                    == crate::layout::guid_bytes(&binding.volume_guid)?,
                "cancel mount root belongs to a foreign volume",
            )?,
            None => {
                if path.len() > 3 {
                    let target = std::path::Path::new(path.trim_end_matches('\\'));
                    for parent in target.ancestors() {
                        let m = std::fs::symlink_metadata(parent)?;
                        require(
                            m.is_dir() && m.file_attributes() & 0x400 == 0,
                            "cancel mount folder ancestry is nonordinary",
                        )?;
                    }
                    require(
                        std::fs::read_dir(target)?.next().is_none(),
                        "cancel mount folder is not empty",
                    )?;
                }
                missing.push(path.clone());
            }
        }
    }
    Ok(missing)
}
/// Check all destinations before any availability transition. This never sets
/// a mount point or changes source attributes.
pub fn preflight_mount_paths(binding: &GeneralDiskBinding, paths: &[String]) -> io::Result<()> {
    binding.validate()?;
    preflight_paths(binding, paths).map(drop)
}
#[derive(Debug, Serialize)]
pub struct MountRestoration {
    pub binding: GeneralDiskBinding,
    pub requested: Vec<String>,
    pub changed: Vec<String>,
    pub after: crate::MountPathObservation,
}
pub fn restore_ntfs_mount_paths(
    binding: GeneralDiskBinding,
    paths: &[String],
    events: &mut Vec<NativeEvent>,
) -> io::Result<MountRestoration> {
    let binding = preparation::native_batch(events, |batch| {
        crate::rediscover_general_volume_wait(binding, batch)
    })?;
    require(
        preparation::native_batch(events, |batch| {
            crate::mounted_filesystem_general(binding.clone(), batch)
        })? == "NTFS",
        "cancelled source did not mount as NTFS",
    )?;
    let missing = preflight_paths(&binding, paths)?;
    let volume: Vec<u16> = format!("{}\\", binding.volume_path()?)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut changed = vec![];
    for path in missing {
        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        // SAFETY: source hardware/NTFS and all unoccupied destinations are checked;
        // synchronous Mount Manager call retains neither terminated buffer.
        if unsafe { SetVolumeMountPointW(name.as_ptr(), volume.as_ptr()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        changed.push(path);
    }
    let after = preparation::native_batch(events, |batch| {
        crate::capture_mount_paths_general(binding.clone(), batch)
    })?;
    let a: std::collections::BTreeSet<_> = after.paths.iter().map(|p| p.to_lowercase()).collect();
    let b: std::collections::BTreeSet<_> = paths.iter().map(|p| p.to_lowercase()).collect();
    require(
        a == b,
        "original source mount-path set differs after cancellation",
    )?;
    Ok(MountRestoration {
        binding,
        requested: paths.to_vec(),
        changed,
        after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_roots_refuse_aliases_devices_and_duplicates() {
        validate_mount_paths(&["F:\\".into(), "C:\\mount\\data\\".into()]).unwrap();
        for bad in [
            "F:",
            "F:/",
            "\\\\server\\share\\",
            "C:\\..\\",
            "C:\\CON\\",
            "C:\\mount.\\",
            "C:\\mount \\",
        ] {
            assert!(validate_mount_paths(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(validate_mount_paths(&["F:\\".into(), "f:\\".into()]).is_err());
    }
}
