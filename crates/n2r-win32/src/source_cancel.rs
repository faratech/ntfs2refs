//! Exclusive unchanged-source cancellation. No raw payload writer is exposed.
pub mod preparation;
use crate::{
    attestation_native::Privileges,
    general_layout::GeneralDiskBinding,
    layout::invalid,
    native::{self, GeneralDiskState, NativeEvent},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW, SetVolumeMountPointW,
};

pub struct UnchangedSourceLease {
    file: File,
    binding: GeneralDiskBinding,
    before: GeneralDiskState,
    source_sha256: String,
    bytes_read: u64,
    privileges: Privileges,
}
#[derive(Debug, Serialize)]
pub struct Cancellation {
    pub binding: GeneralDiskBinding,
    pub before: GeneralDiskState,
    pub after: GeneralDiskState,
    pub source_sha256: String,
    pub native_bytes_read: u64,
    pub exclusive_source_lease: bool,
    pub raw_source_writes: u64,
    pub source_handle_closed: bool,
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}
fn pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl UnchangedSourceLease {
    pub fn prove(
        binding: GeneralDiskBinding,
        expected: &GeneralDiskState,
        expected_sha256: &str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        require(
            pin(expected_sha256) && expected.disk_attributes == 3,
            "cancel requires exact frozen attrs3/hash",
        )?;
        require(
            native::current_windows_disk(events)? != binding.disk_number,
            "Windows disk cannot be cancelled",
        )?;
        let privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        // Sharing zero excludes every existing or future converter raw handle.
        // The same RW management handle is retained across proof and restoration;
        // no payload Write API or second source handle is used.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x80000000)
            .open(format!("\\\\.\\PhysicalDrive{}", binding.disk_number))?;
        let before = native::general_disk_state(&file, &binding, events)?;
        require(
            &before == expected && before.disk_attributes == 3,
            "actual frozen source identity/state differs",
        )?;
        file.seek(SeekFrom::Start(binding.identity.partition_offset))?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut left = binding.identity.partition_bytes;
        let mut first = true;
        let mut bytes_read = 0;
        while left > 0 {
            let count = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            if first {
                require(
                    count >= 512
                        && &buffer[3..11] == b"NTFS    "
                        && buffer[510..512] == [0x55, 0xaa]
                        && u16::from_le_bytes(buffer[11..13].try_into().unwrap()) == 512
                        && buffer[13] == 8,
                    "actual source is not the supported NTFS boot profile",
                )?;
                first = false;
            }
            hash.update(&buffer[..count]);
            left -= count as u64;
            bytes_read += count as u64;
        }
        let source_sha256 = hex::encode(hash.finalize());
        require(
            source_sha256 == expected_sha256
                && native::general_disk_state(&file, &binding, events)? == before,
            "source bytes or identity changed before cancellation",
        )?;
        Ok(Self {
            file,
            binding,
            before,
            source_sha256,
            bytes_read,
            privileges,
        })
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn restore_original_online(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Cancellation> {
        require(
            native::general_disk_state(&self.file, &self.binding, events)? == self.before,
            "exclusive source changed after proof",
        )?;
        native::set_attributes(&self.file, 0, events)?;
        native::refresh_disk_properties(&self.file, events)?;
        let after = native::general_disk_state(&self.file, &self.binding, events)?;
        let mut expected = self.before.clone();
        expected.disk_attributes = 0;
        require(
            after == expected,
            "cancel source identity/online state differs",
        )?;
        let result = Cancellation {
            binding: self.binding.clone(),
            before: self.before.clone(),
            after,
            source_sha256: self.source_sha256.clone(),
            native_bytes_read: self.bytes_read,
            exclusive_source_lease: true,
            raw_source_writes: 0,
            source_handle_closed: true,
        };
        native::close_file(self.file, "close-exclusive-cancel-source", events)?;
        self.privileges.restore()?;
        Ok(result)
    }
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
    let binding = crate::rediscover_general_volume_wait(binding, events)?;
    require(
        crate::mounted_filesystem_general(binding.clone(), events)? == "NTFS",
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
    let after = crate::capture_mount_paths_general(binding.clone(), events)?;
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
    fn exclusive_lease_excludes_live_reader_and_blocks_new_reader_until_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("lease.bin");
        std::fs::write(&path, b"unchanged source").unwrap();
        let worker = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        let failure = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .unwrap_err();
        assert_eq!(failure.raw_os_error(), Some(32));
        drop(worker);
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        assert!(
            OpenOptions::new()
                .read(true)
                .share_mode(3)
                .open(&path)
                .is_err()
        );
        drop(lease);
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged source");
    }
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
