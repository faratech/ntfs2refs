//! Compression setters exist only for this session's newly created lab objects.
//! The observer uses backup read handles and never changes existing objects.
use crate::{
    attestation::{IoctlQuery, PrivilegeState, Query, Snapshot},
    attestation_native::{Privileges, snapshot_with_ea},
    discovery, file_storage,
    general_layout::GeneralDiskBinding,
    layout, stream_native,
};
use serde::Serialize;
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
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{CreateDirectoryW, CreateFileW, GetFileInformationByHandleEx},
    System::IO::DeviceIoControl,
};

fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

fn enrolled(filesystem: &str) -> io::Result<GeneralDiskBinding> {
    if !matches!(filesystem, "NTFS" | "ReFS")
        || std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
    {
        return Err(invalid(
            "enrolled compression-fixture guest/filesystem required",
        ));
    }
    let role = if filesystem == "NTFS" {
        discovery::Role::Source
    } else {
        discovery::Role::Shadow
    };
    let source = discovery::discover(r"H:\", role)?;
    let id = &source.binding.identity;
    if source.binding.disk_number != 6
        || layout::guid_bytes(&id.disk_guid)?
            != layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
        || layout::guid_bytes(&id.partition_guid)?
            != layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
        || id.partition_number != 2
        || id.partition_offset != 32 * 1024 * 1024
        || id.partition_bytes != 52 * 1024 * 1024 * 1024
        || id.disk_bytes != 56 * 1024 * 1024 * 1024
        || source.disk_is_windows_disk
        || !source.read_only
        || source.source_write_requests != 0
        || !source.observed_twice_unchanged
        || source.filesystem != filesystem
        || source.label != "n2r-links-source"
        || source.bytes_per_sector != 512
        || source.sectors_per_cluster != 8
    {
        return Err(invalid(
            "exact enrolled disk-6 H: compression fixture required",
        ));
    }
    Ok(source.binding)
}
fn components(path: &Path) -> io::Result<Vec<String>> {
    let parts: Vec<_> = path.components().collect();
    if !(3..=8).contains(&parts.len())
        || !matches!(parts[0], Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(b'H')))
        || !matches!(parts[1], Component::RootDir)
    {
        return Err(invalid("bounded absolute H: fixture path required"));
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
            return Err(invalid("invalid fixture component"));
        }
        names.push(name.to_owned());
    }
    let id = names[0]
        .strip_prefix("CompressionFixture-")
        .ok_or_else(|| invalid("compression fixture namespace required"))?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("fixture namespace identity differs"));
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
    paths
        .into_iter()
        .map(|p| {
            let file = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(p)?;
            let metadata = file.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid("ordinary no-follow fixture ancestry required"));
            }
            Ok(file)
        })
        .collect()
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
    pub fn begin(filesystem: &str, writable: bool) -> io::Result<Self> {
        if writable && filesystem != "NTFS" {
            return Err(invalid("fixture writes confined to NTFS"));
        }
        let source = enrolled(filesystem)?;
        let names: &[&str] = if writable {
            &[
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeSecurityPrivilege",
            ]
        } else {
            &["SeBackupPrivilege", "SeSecurityPrivilege"]
        };
        Ok(Self {
            privileges: Privileges::enable_for(names)?,
            source,
            filesystem: filesystem.into(),
            writable,
            owner: Arc::new(()),
            namespace: None,
        })
    }
    fn guard(&self) -> io::Result<()> {
        if enrolled(&self.filesystem)? != self.source {
            return Err(invalid("compression fixture route changed"));
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
    fn scope(&self, names: &[String]) -> io::Result<()> {
        if self.namespace.as_ref().is_some_and(|n| n != &names[0]) {
            return Err(invalid("one fixture namespace per session"));
        }
        Ok(())
    }
    pub fn create(&mut self, path: &Path, directory: bool) -> io::Result<OwnedObject> {
        if !self.writable {
            return Err(invalid("observer cannot create"));
        }
        let names = components(path)?;
        self.scope(&names)?;
        if self.namespace.is_none() && (names.len() != 1 || !directory) {
            return Err(invalid("first create must be fresh fixture root"));
        }
        self.guard()?;
        let actual = self.actual(&names)?;
        let held = ancestors(&actual)?;
        match fs::symlink_metadata(&actual) {
            Ok(_) => return Err(invalid("fixture path exists; no reuse")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let name: Vec<u16> = actual.as_os_str().encode_wide().chain(Some(0)).collect();
        let file = if directory {
            // SAFETY: new checked fixture path with held ordinary ancestors.
            if unsafe { CreateDirectoryW(name.as_ptr(), ptr::null()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            OpenOptions::new()
                .access_mode(0x011e01ff)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(&actual)?
        } else {
            // SAFETY: CREATE_NEW cannot overwrite existing files; no delete sharing.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    0x011e01ff,
                    3,
                    ptr::null(),
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
            return Err(invalid("new fixture type differs"));
        }
        let identity = file_storage::file_id_info(&file)?;
        self.guard()?;
        self.namespace = Some(names[0].clone());
        Ok(OwnedObject {
            file,
            path: path.into(),
            directory,
            identity,
            owner: self.owner.clone(),
            _ancestors: held,
        })
    }
    pub fn create_stream(&mut self, base: &OwnedObject, name: &str) -> io::Result<OwnedObject> {
        self.owned(base)?;
        if base.directory || !crate::shadow_names::valid_unicode_component(name) {
            return Err(invalid("ordinary owned file and stream component required"));
        }
        let names = components(&base.path)?;
        self.scope(&names)?;
        let actual = self.actual(&names)?;
        let actual = PathBuf::from(format!("{}:{name}:$DATA", actual.display()));
        let held = ancestors(&self.actual(&names)?)?;
        let wide: Vec<u16> = actual.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: CREATE_NEW on this session's held new file and validated ADS name.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0x011e01ff,
                3,
                ptr::null(),
                1,
                0x02200000,
                ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let identity = file_storage::file_id_info(&file)?;
        if identity != base.identity {
            return Err(invalid("fresh named stream identity differs"));
        }
        self.guard()?;
        Ok(OwnedObject {
            file,
            path: base.path.clone(),
            directory: false,
            identity,
            owner: self.owner.clone(),
            _ancestors: held,
        })
    }
    fn owned(&self, object: &OwnedObject) -> io::Result<()> {
        if !self.writable || !Arc::ptr_eq(&self.owner, &object.owner) {
            return Err(invalid("setter requires actual newly owned object"));
        }
        self.guard()?;
        if file_storage::file_id_info(&object.file)? != object.identity {
            return Err(invalid("owned identity changed"));
        }
        Ok(())
    }
    pub fn set_compression(&self, object: &OwnedObject) -> io::Result<CompressionObservation> {
        self.owned(object)?;
        if object.file.metadata()?.len() != 0 {
            return Err(invalid("compression SET requires empty owned object"));
        }
        let format = 2u16;
        let mut used = 0u32;
        // SAFETY: live owned handle; bounded u16 LZNT1 input, synchronous request.
        if unsafe {
            DeviceIoControl(
                object.file.as_raw_handle(),
                0x0009c040,
                (&format as *const u16).cast(),
                2,
                ptr::null_mut(),
                0,
                &mut used,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if used != 0 {
            return Err(invalid("unexpected compression SET output"));
        }
        self.owned(object)?;
        let observation = compression(&object.file);
        if observation.format != Some(2) {
            return Err(invalid("LZNT1 SET readback differs"));
        }
        Ok(observation)
    }
    pub fn open(
        &mut self,
        path: &Path,
        directory: bool,
        stream: Option<&str>,
    ) -> io::Result<ReadObject> {
        let names = components(path)?;
        self.scope(&names)?;
        self.guard()?;
        let actual = self.actual(&names)?;
        let held = ancestors(&actual)?;
        if stream.is_some_and(|s| directory || !crate::shadow_names::valid_unicode_component(s)) {
            return Err(invalid("invalid observer stream"));
        }
        let actual = stream.map_or(actual.clone(), |s| {
            PathBuf::from(format!("{}:{s}:$DATA", actual.display()))
        });
        let file = OpenOptions::new()
            .access_mode(0x01020089)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(&actual)?;
        let metadata = file.metadata()?;
        if (metadata.file_attributes() & 16 != 0) != directory
            || metadata.file_attributes() & 0x400 != 0
        {
            return Err(invalid("ordinary observer object required"));
        }
        let identity = file_storage::file_id_info(&file)?;
        self.guard()?;
        self.namespace = Some(names[0].clone());
        Ok(ReadObject {
            file,
            identity,
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
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}
pub struct ReadObject {
    file: File,
    identity: String,
    _ancestors: Vec<File>,
}
impl ReadObject {
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn observe(&self) -> io::Result<ObjectObservation> {
        if file_storage::file_id_info(&self.file)? != self.identity {
            return Err(invalid("observer identity changed"));
        }
        let (retrieval, retrieval_continuation) = stream_native::retrieval_queries(&self.file);
        Ok(ObjectObservation {
            file_id_info: self.identity.clone(),
            snapshot: snapshot_with_ea(&self.file),
            compression: compression(&self.file),
            retrieval,
            retrieval_continuation,
        })
    }
}
#[derive(Serialize)]
pub struct CompressionObservation {
    pub format: Option<u16>,
    pub query: IoctlQuery,
    pub compression_info: Query,
}
#[derive(Serialize)]
pub struct ObjectObservation {
    pub file_id_info: String,
    pub snapshot: Snapshot,
    pub compression: CompressionObservation,
    pub retrieval: IoctlQuery,
    pub retrieval_continuation: Vec<IoctlQuery>,
}
fn compression(file: &File) -> CompressionObservation {
    let query = stream_native::ioctl(file, 0x0009003c, &[], 2);
    let format = (query.native_error.is_none() && query.bytes.len() == 2)
        .then(|| u16::from_le_bytes(query.bytes[..2].try_into().unwrap()));
    let mut aligned = [0u64; 2];
    // SAFETY: 16-byte aligned initialized FILE_COMPRESSION_INFO output.
    let success = unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 8, aligned.as_mut_ptr().cast(), 16)
    };
    let error = (success == 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(31));
    let bytes = if error.is_none() {
        aligned.iter().flat_map(|n| n.to_le_bytes()).collect()
    } else {
        Vec::new()
    };
    CompressionObservation {
        format,
        query,
        compression_info: Query {
            class: 8,
            bytes,
            native_error: error,
        },
    }
}
