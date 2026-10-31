//! Owned creation and no-follow observation for one enrolled reparse fixture.
//! No existing-object setters, deletion, raw writes or conversion authority.
use crate::{
    attestation::{PrivilegeState, Snapshot},
    attestation_native::{Privileges, snapshot_with_ea},
    discovery, file_storage,
    general_layout::GeneralDiskBinding,
    layout,
    reparse_layout::Point,
    reparse_native,
};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::FromRawHandle,
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{CreateDirectoryW, CreateFileW},
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn enrolled(filesystem: &str) -> io::Result<GeneralDiskBinding> {
    if !matches!(filesystem, "NTFS" | "ReFS")
        || std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
    {
        return Err(invalid(
            "enrolled reparse fixture filesystem/guest required",
        ));
    }
    let role = if filesystem == "NTFS" {
        discovery::Role::Source
    } else {
        discovery::Role::Shadow
    };
    let source = discovery::discover(r"H:\", role)?;
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
        || source.filesystem != filesystem
        || source.label != "n2r-links-source"
        || source.bytes_per_sector != 512
        || source.sectors_per_cluster != 8
    {
        return Err(invalid("exact enrolled disk-6 H: reparse fixture required"));
    }
    Ok(source.binding)
}

fn components(path: &Path) -> io::Result<Vec<String>> {
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 3
        || parts.len() > 18
        || !matches!(parts[0], Component::Prefix(prefix) if matches!(prefix.kind(), Prefix::Disk(b'H')))
        || !matches!(parts[1], Component::RootDir)
    {
        return Err(invalid("absolute bounded H: reparse-fixture path required"));
    }
    let mut names = Vec::new();
    for part in parts.into_iter().skip(2) {
        let Component::Normal(name) = part else {
            return Err(invalid("fixture traversal refused"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| invalid("Unicode fixture names required"))?;
        if !crate::shadow_names::valid_unicode_component(name) {
            return Err(invalid("invalid reparse fixture component"));
        }
        names.push(name.to_owned());
    }
    let id = names[0]
        .strip_prefix("ReparseFixture-")
        .ok_or_else(|| invalid("reparse fixture namespace required"))?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("reparse fixture namespace identity differs"));
    }
    Ok(names)
}

fn ancestors(path: &Path) -> io::Result<Vec<File>> {
    let mut paths: Vec<_> = path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    paths.reverse();
    let mut held = Vec::new();
    for ancestor in paths {
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(ancestor)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary no-follow fixture ancestors required"));
        }
        held.push(file);
    }
    Ok(held)
}

fn private_descriptor() -> Vec<u8> {
    // Self-relative O:SY G:SY D:P(A;;FA;;;SY), with the owner/group sharing
    // the same bounded LocalSystem SID. Native descriptor() validates it again.
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let mut bytes = vec![0; 60];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x9004u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&20u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&32u32.to_le_bytes());
    bytes[20..32].copy_from_slice(&sid);
    bytes[32] = 2;
    bytes[34..36].copy_from_slice(&28u16.to_le_bytes());
    bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&20u16.to_le_bytes());
    bytes[44..48].copy_from_slice(&0x001f_01ffu32.to_le_bytes());
    bytes[48..60].copy_from_slice(&sid);
    bytes
}

pub struct FixtureSession {
    privileges: Privileges,
    source: GeneralDiskBinding,
    filesystem: String,
    writable: bool,
    owner: Arc<()>,
    namespace: Option<String>,
}
impl FixtureSession {
    pub fn begin(expected_filesystem: &str, write: bool) -> io::Result<Self> {
        if write && expected_filesystem != "NTFS" {
            return Err(invalid("fixture creation is confined to enrolled NTFS"));
        }
        let source = enrolled(expected_filesystem)?;
        let names: &[&str] = if write {
            &[
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeSecurityPrivilege",
                "SeCreateSymbolicLinkPrivilege",
            ]
        } else {
            &["SeBackupPrivilege", "SeSecurityPrivilege"]
        };
        Ok(Self {
            privileges: Privileges::enable_for(names)?,
            source,
            filesystem: expected_filesystem.into(),
            writable: write,
            owner: Arc::new(()),
            namespace: None,
        })
    }

    pub fn source(&self) -> &GeneralDiskBinding {
        &self.source
    }

    fn guard(&self) -> io::Result<()> {
        if enrolled(&self.filesystem)? != self.source {
            return Err(invalid("reparse fixture volume route changed"));
        }
        Ok(())
    }
    fn actual(&self, names: &[String]) -> io::Result<PathBuf> {
        Ok(PathBuf::from(format!(
            "{}\\{}",
            self.source.volume_path()?,
            names.join("\\")
        )))
    }
    fn namespace_matches(&self, names: &[String]) -> io::Result<()> {
        if self
            .namespace
            .as_ref()
            .is_some_and(|name| name != &names[0])
        {
            return Err(invalid("one fixture namespace per live session required"));
        }
        Ok(())
    }

    pub fn create_file(&mut self, path: &Path) -> io::Result<OwnedObject> {
        self.create(path, false)
    }
    pub fn create_directory(&mut self, path: &Path) -> io::Result<OwnedObject> {
        self.create(path, true)
    }

    fn create(&mut self, path: &Path, directory: bool) -> io::Result<OwnedObject> {
        if !self.writable {
            return Err(invalid("read-only fixture session cannot create"));
        }
        let names = components(path)?;
        self.namespace_matches(&names)?;
        if self.namespace.is_none() && (!directory || names.len() != 1) {
            return Err(invalid(
                "first create must be the fresh fixture root directory",
            ));
        }
        self.guard()?;
        let actual = self.actual(&names)?;
        let held = ancestors(&actual)?;
        match fs::symlink_metadata(&actual) {
            Ok(_) => return Err(invalid("fixture path already exists; no overwrite/reuse")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let descriptor = private_descriptor();
        let mut descriptor = crate::shadow_native::descriptor(&descriptor)?;
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        let name: Vec<u16> = actual.as_os_str().encode_wide().chain(Some(0)).collect();
        let file = if directory {
            // SAFETY: fresh checked namespace and held ordinary ancestors;
            // bounded validated private descriptor and terminated name.
            if unsafe { CreateDirectoryW(name.as_ptr(), &security) } == 0 {
                return Err(io::Error::last_os_error());
            }
            OpenOptions::new()
                .access_mode(0x011e01ff)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(&actual)?
        } else {
            // SAFETY: CREATE_NEW, no DELETE right/sharing, same verified path
            // and live self-relative descriptor. Existing paths always fail.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    0x011e01ff,
                    3,
                    &security,
                    1,
                    0x02200000,
                    ptr::null_mut(),
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            unsafe { File::from_raw_handle(handle) }
        };
        let metadata = file.metadata()?;
        if metadata.is_dir() != directory || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("fresh owned reparse fixture type differs"));
        }
        let identity = file_storage::file_id_info(&file)?;
        self.guard()?;
        self.namespace = Some(names[0].clone());
        Ok(OwnedObject {
            file,
            path: path.into(),
            directory,
            identity,
            owner: Arc::clone(&self.owner),
            _ancestors: held,
        })
    }

    pub fn set_point(&mut self, object: &OwnedObject, point: &Point) -> io::Result<Point> {
        if !self.writable || !Arc::ptr_eq(&self.owner, &object.owner) {
            return Err(invalid(
                "point SET requires this session's actual fresh owned object",
            ));
        }
        self.guard()?;
        if file_storage::file_id_info(&object.file)? != object.identity {
            return Err(invalid("owned reparse fixture identity changed before SET"));
        }
        let observed = reparse_native::restore_fresh_owned(&object.file, point)?;
        self.guard()?;
        if file_storage::file_id_info(&object.file)? != object.identity {
            return Err(invalid("owned reparse fixture identity changed after SET"));
        }
        Ok(observed)
    }

    pub fn open(&mut self, path: &Path, directory: bool) -> io::Result<ReadObject> {
        let names = components(path)?;
        self.namespace_matches(&names)?;
        self.guard()?;
        let actual = self.actual(&names)?;
        let held = ancestors(&actual)?;
        let file = OpenOptions::new()
            .access_mode(0x01020089)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(&actual)?;
        let identity = file_storage::file_id_info(&file)?;
        // FileType::is_dir can classify a no-follow directory symlink as a
        // symlink. Preserve the object's actual directory attribute instead.
        if (file.metadata()?.file_attributes() & 16 != 0) != directory {
            return Err(invalid("read-only fixture type differs"));
        }
        let point = reparse_native::capture(&file)?;
        let snapshot = snapshot_with_ea(&file);
        let observed = snapshot
            .reparse
            .as_ref()
            .ok_or_else(|| invalid("canonical reparse observation missing"))?;
        if observed.error.is_some() || observed.point != point {
            return Err(invalid("canonical reparse observations disagree"));
        }
        self.guard()?;
        if file_storage::file_id_info(&file)? != identity {
            return Err(invalid("read-only fixture identity changed"));
        }
        self.namespace = Some(names[0].clone());
        Ok(ReadObject {
            file,
            snapshot,
            point,
            _ancestors: held,
        })
    }

    pub fn finish(mut self) -> io::Result<Vec<PrivilegeState>> {
        self.guard()?;
        self.privileges.restore()?;
        Ok(self.privileges.audit().to_vec())
    }
}

pub struct OwnedObject {
    file: File,
    path: PathBuf,
    directory: bool,
    identity: String,
    owner: Arc<()>,
    _ancestors: Vec<File>,
}
impl OwnedObject {
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn directory(&self) -> bool {
        self.directory
    }
    pub fn file_id_info(&self) -> &str {
        &self.identity
    }
    pub fn snapshot(&self) -> Snapshot {
        snapshot_with_ea(&self.file)
    }
}

pub struct ReadObject {
    file: File,
    pub snapshot: Snapshot,
    pub point: Option<Point>,
    _ancestors: Vec<File>,
}
impl ReadObject {
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn point(&self) -> Option<&Point> {
        self.point.as_ref()
    }
}
