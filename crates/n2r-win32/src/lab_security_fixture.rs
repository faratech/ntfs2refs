//! Native security operations only on newly created objects in the enrolled lab.
//! These handles cannot be manufactured from paths to existing files. No raw
//! volume I/O, permission repair, deletion or conversion authority is exposed.
use crate::{
    attestation::{PrivilegeState, Snapshot},
    attestation_native::{Privileges, snapshot},
    discovery, file_storage,
    general_layout::GeneralDiskBinding,
    layout,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{BackupWrite, CreateDirectoryW, CreateFileW},
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn enrolled_volume(expected_filesystem: &str) -> io::Result<GeneralDiskBinding> {
    if !matches!(expected_filesystem, "NTFS" | "ReFS") {
        return Err(invalid("security observer filesystem must be NTFS or ReFS"));
    }
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11") {
        return Err(invalid("security fixture requires the enrolled lab guest"));
    }
    let source = discovery::discover(r"H:\", discovery::Role::Source)?;
    let identity = &source.binding.identity;
    if source.binding.disk_number != 6
        || layout::guid_bytes(&identity.disk_guid)?
            != layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
        || layout::guid_bytes(&identity.partition_guid)?
            != layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
        || identity.partition_number != 2
        || identity.partition_offset != 32 * 1024 * 1024
        || identity.partition_bytes != 52 * 1024 * 1024 * 1024
        || identity.disk_bytes != 56 * 1024 * 1024 * 1024
        || source.disk_is_windows_disk
        || !source.read_only
        || source.source_write_requests != 0
        || !source.observed_twice_unchanged
        || source.filesystem != expected_filesystem
        || source.label != "n2r-links-source"
        || source.bytes_per_sector != 512
        || source.sectors_per_cluster != 8
    {
        return Err(invalid("exact enrolled H: fixture volume required"));
    }
    Ok(source.binding)
}

fn enrolled_source() -> io::Result<GeneralDiskBinding> {
    enrolled_volume("NTFS")
}

/// Privileges are held for the fixture lifetime, then explicitly restored.
/// Drop also uses the existing best-effort restoration guard on error paths.
pub struct FixtureSession {
    privileges: Privileges,
    source: GeneralDiskBinding,
}

impl FixtureSession {
    pub fn begin() -> io::Result<Self> {
        let source = enrolled_source()?;
        let privileges = Privileges::enable_for(&[
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
        ])?;
        Ok(Self { privileges, source })
    }

    pub fn create_file(&self, path: &Path, descriptor: &[u8]) -> io::Result<OwnedObject> {
        self.create(path, descriptor, false)
    }

    pub fn create_directory(&self, path: &Path, descriptor: &[u8]) -> io::Result<OwnedObject> {
        self.create(path, descriptor, true)
    }

    fn create(&self, path: &Path, descriptor: &[u8], directory: bool) -> io::Result<OwnedObject> {
        validate_fixture_path(path)?;
        if enrolled_source()? != self.source {
            return Err(invalid("security fixture source route changed"));
        }
        // Retain ordinary ancestor handles without delete sharing across the
        // create/open sequence. The newly created object is never reopened by
        // an arbitrary caller-supplied existing path through this interface.
        let ancestors = hold_ancestors(path)?;
        if fs::symlink_metadata(path).is_ok() {
            return Err(invalid("security fixture path already exists"));
        }
        let mut aligned = crate::shadow_native::descriptor(descriptor)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: aligned.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        name.push(0);
        let file = if directory {
            // SAFETY: validated fresh lab path, live self-relative descriptor
            // in aligned storage, NUL-terminated path and initialized structure.
            if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
                return Err(io::Error::last_os_error());
            }
            OpenOptions::new()
                .access_mode(0x011e01ff)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(path)?
        } else {
            // SAFETY: CREATE_NEW refuses existing files; same checked path and
            // aligned descriptor. No DELETE right or delete sharing is granted.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    0x011e01ff,
                    3,
                    &attributes,
                    1,
                    0x02200000,
                    ptr::null_mut(),
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: unique ownership of the newly returned native handle.
            unsafe { File::from_raw_handle(handle) }
        };
        let metadata = file.metadata()?;
        if metadata.file_attributes() & 0x400 != 0 || metadata.is_dir() != directory {
            return Err(invalid("new security fixture object type differs"));
        }
        let identity = file_storage::file_id_info(&file)?;
        if enrolled_source()? != self.source {
            return Err(invalid(
                "security fixture source route changed after create",
            ));
        }
        Ok(OwnedObject {
            file,
            path: path.to_owned(),
            directory,
            identity,
            _ancestors: ancestors,
        })
    }

    pub fn finish(mut self) -> io::Result<Vec<PrivilegeState>> {
        self.privileges.restore()?;
        Ok(self.privileges.audit().to_vec())
    }
}

/// Read-only file/security observation on the enrolled NTFS or converted ReFS
/// fixture. Backup privilege permits reading an intentionally empty DACL without
/// changing that DACL. No restore privilege or write-capable file handle exists.
pub struct ObservationSession {
    privileges: Privileges,
    source: GeneralDiskBinding,
    filesystem: String,
}

impl ObservationSession {
    pub fn begin(expected_filesystem: &str) -> io::Result<Self> {
        let source = enrolled_volume(expected_filesystem)?;
        let privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
        Ok(Self {
            privileges,
            source,
            filesystem: expected_filesystem.into(),
        })
    }

    pub fn open_file(&self, path: &Path, directory: bool) -> io::Result<File> {
        validate_fixture_path(path)?;
        if enrolled_volume(&self.filesystem)? != self.source {
            return Err(invalid("security observer source route changed"));
        }
        // Open through backup semantics before inspecting attributes: ordinary
        // pathname metadata APIs may themselves be refused by an empty DACL.
        let _ancestors = hold_readonly_ancestors(path)?;
        let file = OpenOptions::new()
            .access_mode(0x01020089)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(path)?;
        let before = file_storage::file_id_info(&file)?;
        let metadata = file.metadata()?;
        if metadata.file_attributes() & 0x400 != 0 || metadata.is_dir() != directory {
            return Err(invalid("security observer object type differs"));
        }
        if enrolled_volume(&self.filesystem)? != self.source
            || file_storage::file_id_info(&file)? != before
        {
            return Err(invalid("security observer route or identity changed"));
        }
        Ok(file)
    }

    pub fn snapshot(&self, file: &File) -> Snapshot {
        snapshot(file)
    }

    pub fn finish(mut self) -> io::Result<Vec<PrivilegeState>> {
        self.privileges.restore()?;
        Ok(self.privileges.audit().to_vec())
    }
}

fn hold_readonly_ancestors(path: &Path) -> io::Result<Vec<File>> {
    let mut ancestors = Vec::new();
    for ancestor in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(ancestor)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary security observer ancestry required"));
        }
        ancestors.push(file);
    }
    Ok(ancestors)
}

fn validate_fixture_path(path: &Path) -> io::Result<()> {
    let components: Vec<_> = path.components().collect();
    if components.len() < 3
        || components.len() > 11
        || !matches!(components[0], Component::Prefix(prefix) if matches!(prefix.kind(), Prefix::Disk(b'H')))
        || !matches!(components[1], Component::RootDir)
    {
        return Err(invalid("absolute enrolled H: fixture path required"));
    }
    for (index, component) in components.iter().enumerate().skip(2) {
        let Component::Normal(part) = component else {
            return Err(invalid("fixture traversal or alternate prefix refused"));
        };
        let part = part
            .to_str()
            .ok_or_else(|| invalid("fixture components must be valid Unicode"))?;
        if !crate::shadow_names::valid_unicode_component(part) {
            return Err(invalid("fixture component exceeds the source name profile"));
        }
        if index == 2 {
            let Some(id) = part.strip_prefix("SecurityFixture-") else {
                return Err(invalid("fresh security-fixture root required"));
            };
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid("security fixture root identity differs"));
            }
        }
    }
    Ok(())
}

fn hold_ancestors(path: &Path) -> io::Result<Vec<File>> {
    let mut ancestors = Vec::new();
    for ancestor in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary security fixture ancestry required"));
        }
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(ancestor)?;
        let opened = file.metadata()?;
        if !opened.is_dir() || opened.file_attributes() & 0x400 != 0 {
            return Err(invalid("security fixture ancestry changed while opening"));
        }
        ancestors.push(file);
    }
    Ok(ancestors)
}

pub struct OwnedObject {
    file: File,
    path: PathBuf,
    directory: bool,
    identity: String,
    _ancestors: Vec<File>,
}

#[derive(Serialize)]
pub struct RestoreReport {
    pub path: PathBuf,
    pub directory: bool,
    pub file_id_info: String,
    pub intended_descriptor_sha256: String,
    pub stream_sha256: String,
    pub submitted_bytes: u32,
    pub accepted_bytes: u32,
    pub context_released: bool,
    pub before: Snapshot,
    pub after: Snapshot,
}

impl OwnedObject {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn snapshot(&self) -> Snapshot {
        snapshot(&self.file)
    }

    /// Attempts the exact supplied descriptor on this newly created object.
    /// The report deliberately exposes actual native readback; accepted bytes
    /// do not prove that the filesystem retained the requested ACL state.
    pub fn restore_security(&self, descriptor: &[u8]) -> io::Result<RestoreReport> {
        let _aligned = crate::shadow_native::descriptor(descriptor)?;
        if file_storage::file_id_info(&self.file)? != self.identity {
            return Err(invalid("owned security fixture identity changed"));
        }
        let before = snapshot(&self.file);
        let mut stream = vec![0u8; 20];
        stream[..4].copy_from_slice(&3u32.to_le_bytes());
        stream[4..8].copy_from_slice(&2u32.to_le_bytes());
        stream[8..16].copy_from_slice(&(descriptor.len() as u64).to_le_bytes());
        stream.extend_from_slice(descriptor);
        let mut accepted = 0;
        let mut context = ptr::null_mut();
        // SAFETY: actual constructor-owned synchronous handle with security
        // rights, bounded initialized backup stream, private initially NULL context.
        let ok = unsafe {
            BackupWrite(
                self.file.as_raw_handle(),
                stream.as_ptr(),
                stream.len() as u32,
                &mut accepted,
                0,
                1,
                &mut context,
            )
        };
        let failure = (ok == 0).then(io::Error::last_os_error);
        let mut ignored = 0;
        // SAFETY: mandatory context cleanup even after a failed first call.
        let cleaned = unsafe {
            BackupWrite(
                self.file.as_raw_handle(),
                ptr::null(),
                0,
                &mut ignored,
                1,
                1,
                &mut context,
            )
        };
        if let Some(error) = failure {
            return Err(error);
        }
        if cleaned == 0 {
            return Err(io::Error::last_os_error());
        }
        if accepted as usize != stream.len() {
            return Err(invalid("partial security fixture backup restoration"));
        }
        let after = snapshot(&self.file);
        if file_storage::file_id_info(&self.file)? != self.identity {
            return Err(invalid(
                "owned security fixture identity changed after restore",
            ));
        }
        Ok(RestoreReport {
            path: self.path.clone(),
            directory: self.directory,
            file_id_info: self.identity.clone(),
            intended_descriptor_sha256: hex::encode(Sha256::digest(descriptor)),
            stream_sha256: hex::encode(Sha256::digest(&stream)),
            submitted_bytes: stream.len() as u32,
            accepted_bytes: accepted,
            context_released: true,
            before,
            after,
        })
    }
}
