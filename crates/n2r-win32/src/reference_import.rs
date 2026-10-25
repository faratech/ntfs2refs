//! Lab-only import boundary for an independently created, completely blank VHDX.
use crate::{layout, native};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::IO::DeviceIoControl,
    },
    core::GUID,
};
pub const DISK_BYTES: u64 = 64 << 30;
pub const PARTITION_OFFSET: u64 = 16 << 20;
pub const PARTITION_BYTES: u64 = 52 << 30;
pub const PAYLOAD_OFFSET: u64 = 41_955_328;
pub const PAYLOAD_BYTES: u64 = 4096;
const CHUNK: usize = 1 << 20;
const DEVICE: u32 = 0x002d1080;
const LENGTH: u32 = 0x0007405c;
const ALIGNMENT: u32 = 0x002d1400;
const LAYOUT: u32 = 0x00070050;
const GET_ATTRIBUTES: u32 = 0x000700f0;
const SET_ATTRIBUTES: u32 = 0x0007c0f4;
const UPDATE: u32 = 0x00070140;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub experiment_id: String,
    pub vhd_path: String,
    pub persistent_vhd_id: String,
    pub disk_number: u32,
}
impl Binding {
    pub fn validate(&self) -> io::Result<()> {
        require(
            self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
            "lowercase experiment ID required",
        )?;
        require(
            self.vhd_path
                == format!(
                    "J:\\ntfs2refs-reference\\{}\\reference.vhdx",
                    self.experiment_id
                ),
            "enrolled reference path differs",
        )?;
        require(
            (3..=63).contains(&self.disk_number),
            "reference excludes OS/source/journal routes",
        )?;
        require(
            layout::guid_bytes(&self.persistent_vhd_id)? != [0; 16],
            "empty VHD identity",
        )
    }
    pub fn physical_path(&self) -> String {
        format!("\\\\.\\PhysicalDrive{}", self.disk_number)
    }
}
fn require(ok: bool, s: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(layout::invalid(s)) }
}
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn valid_hash(p: &str) -> bool {
    p.len() == 64
        && p.bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn uninitialized_layout(bytes: &[u8]) -> io::Result<bool> {
    // A newly created VHDX is reported as RAW by Storage Management, while
    // IOCTL_DISK_GET_DRIVE_LAYOUT_EX can return an entirely zero 48-byte
    // MBR-style header. This is not permission to import over an MBR disk:
    // the complete disk must still pass the subsequent zero-content scan.
    if bytes.len() == 48 && bytes.iter().all(|byte| *byte == 0) {
        return Ok(true);
    }
    Ok(bytes.len() >= 48 && layout::u32_at(bytes, 0)? == 2 && layout::u32_at(bytes, 4)? == 0)
}
fn validate_imported_layout(state: &State, disk_number: u32) -> io::Result<()> {
    layout::validate_layout(
        &state.layout,
        &layout::DiskBinding {
            disk_number,
            volume_guid: "00c9f113-e0b9-49d8-b031-130aef8ef3fb".into(),
            identity: layout::PartitionIdentity {
                disk_guid: "b4ab4dbc-6bd7-4199-8e4a-01b828e98584".into(),
                partition_guid: "00c9f113-e0b9-49d8-b031-130aef8ef3fb".into(),
                partition_number: 2,
                disk_bytes: DISK_BYTES,
                partition_offset: PARTITION_OFFSET,
                partition_bytes: PARTITION_BYTES,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
        },
    )
}
fn guid(b: [u8; 16]) -> GUID {
    GUID {
        data1: u32::from_le_bytes(b[..4].try_into().unwrap()),
        data2: u16::from_le_bytes(b[4..6].try_into().unwrap()),
        data3: u16::from_le_bytes(b[6..8].try_into().unwrap()),
        data4: b[8..].try_into().unwrap(),
    }
}
#[repr(C)]
struct Storage {
    device_id: u32,
    vendor: GUID,
}
#[repr(C)]
struct OpenParameters {
    version: u32,
    get_info_only: i32,
    read_only: i32,
    resiliency: GUID,
}
#[link(name = "virtdisk")]
unsafe extern "system" {
    fn OpenVirtualDisk(
        storage: *const Storage,
        path: *const u16,
        access: u32,
        flags: u32,
        parameters: *const OpenParameters,
        handle: *mut HANDLE,
    ) -> u32;
    fn GetVirtualDiskInformation(
        handle: HANDLE,
        size: *mut u32,
        info: *mut u8,
        used: *mut u32,
    ) -> u32;
    fn GetVirtualDiskPhysicalPath(handle: HANDLE, size: *mut u32, path: *mut u16) -> u32;
}
struct VirtualHandle(HANDLE);
impl Drop for VirtualHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: uniquely owned query handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}
impl VirtualHandle {
    fn open(b: &Binding) -> io::Result<Self> {
        let storage = Storage {
            device_id: 3,
            vendor: guid(layout::guid_bytes("ec984aec-a0f9-47e9-901f-71415a66345b")?),
        };
        let parameters = OpenParameters {
            version: 2,
            get_info_only: 0,
            read_only: 0,
            resiliency: guid([0; 16]),
        };
        let path: Vec<u16> = b.vhd_path.encode_utf16().chain(Some(0)).collect();
        let mut handle = ptr::null_mut();
        // SAFETY: complete V2 parameters, live terminated path/output pointer.
        let error =
            unsafe { OpenVirtualDisk(&storage, path.as_ptr(), 0, 0, &parameters, &mut handle) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        require(!handle.is_null(), "missing VHD handle")?;
        Ok(Self(handle))
    }
    fn query(&self, version: u32) -> io::Result<Vec<u8>> {
        let mut words = [0u64; 32];
        words[0] = u64::from(version);
        let mut size = 256;
        let mut used = 0;
        // SAFETY: aligned initialized information union and output sizes.
        let e = unsafe {
            GetVirtualDiskInformation(self.0, &mut size, words.as_mut_ptr().cast(), &mut used)
        };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        require((8..=256).contains(&used), "VHD information size differs")?;
        let bytes: Vec<u8> = words
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .take(used as usize)
            .collect();
        require(
            layout::u32_at(&bytes, 0)? == version,
            "VHD query version differs",
        )?;
        Ok(bytes)
    }
    fn observe(&self, b: &Binding) -> io::Result<VhdObservation> {
        let size = self.query(1)?;
        let id = self.query(14)?;
        let kind = self.query(7)?;
        let physical = self.query(10)?;
        require(
            size.len() >= 32 && id.len() >= 24 && kind.len() >= 12 && physical.len() >= 12,
            "truncated VHD information",
        )?;
        require(
            id[8..24] == layout::guid_bytes(&b.persistent_vhd_id)?
                && layout::u64_at(&size, 8)? == DISK_BYTES
                && layout::u32_at(&size, 24)? == 2 << 20
                && layout::u32_at(&size, 28)? == 512
                && layout::u32_at(&kind, 8)? == 3
                && layout::u32_at(&physical, 8)? == 4096,
            "VHD identity/type/geometry differs",
        )?;
        let backing = layout::u64_at(&size, 16)?;
        require(
            backing > 0 && backing <= 6 << 30,
            "VHD backing exceeds bound",
        )?;
        let mut path = [0u16; 256];
        let mut length = 512;
        // SAFETY: live VHD handle and initialized bounded UTF-16 buffer.
        let e = unsafe { GetVirtualDiskPhysicalPath(self.0, &mut length, path.as_mut_ptr()) };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let end = path
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| layout::invalid("unterminated provider path"))?;
        let path = String::from_utf16(&path[..end])
            .map_err(|_| layout::invalid("invalid provider path"))?;
        require(
            path.eq_ignore_ascii_case(&b.physical_path()),
            "provider physical path differs",
        )?;
        Ok(VhdObservation {
            persistent_vhd_id: b.persistent_vhd_id.clone(),
            physical_path: path,
            backing_bytes: backing,
        })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct VhdObservation {
    pub persistent_vhd_id: String,
    pub physical_path: String,
    pub backing_bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct State {
    pub disk_attributes: u64,
    pub device: Vec<u8>,
    pub length: Vec<u8>,
    pub alignment: Vec<u8>,
    pub layout: Vec<u8>,
    pub vhd: VhdObservation,
}
#[derive(Clone, Debug, Serialize)]
pub struct PatchObservation {
    pub partition_offset: u64,
    pub length: u64,
    pub old_sha256: String,
    pub new_sha256: String,
}
#[derive(Debug, Serialize)]
pub struct ImportProof {
    pub disk_sha256: String,
    pub blank_bytes_checked: u64,
    pub reference_bytes_written: u64,
    pub payload_sha256: String,
}
#[derive(Debug, Serialize)]
pub struct PreparedProof {
    pub binding: Binding,
    pub import_disk_sha256: String,
    pub payload_sha256: String,
    pub patches: Vec<PatchObservation>,
    pub state: State,
    pub native_mount_qualified: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reference,
    Overlay,
    Prepared,
    HandedOff,
}
pub struct FreshReferenceDisk {
    binding: Binding,
    virtual_disk: VirtualHandle,
    file: File,
    phase: Phase,
    last_end: u64,
    reference_bytes: u64,
    import_hash: String,
    payload_hash: String,
    patches: Vec<PatchObservation>,
    privileges: crate::attestation_native::Privileges,
}
fn control(f: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    let mut words = vec![0u64; capacity.div_ceil(8)];
    let mut returned = 0;
    // SAFETY: synchronous control on held disk; bounded initialized buffers.
    let ok = unsafe {
        DeviceIoControl(
            f.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if capacity == 0 {
                ptr::null_mut()
            } else {
                words.as_mut_ptr().cast()
            },
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    require(returned as usize <= capacity, "disk control overrun")?;
    Ok(words
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .take(returned as usize)
        .collect())
}
fn attributes(f: &File) -> io::Result<u64> {
    let b = control(f, GET_ATTRIBUTES, &[], 16)?;
    require(
        b.len() == 16 && layout::u32_at(&b, 0)? == 16,
        "malformed disk attributes",
    )?;
    let a = layout::u64_at(&b, 8)?;
    require(a & !3 == 0, "unknown disk attributes")?;
    Ok(a)
}
fn set_attributes(f: &File, a: u64) -> io::Result<()> {
    let mut b = [0u8; 40];
    b[..4].copy_from_slice(&40u32.to_le_bytes());
    b[4] = 1;
    b[8..16].copy_from_slice(&a.to_le_bytes());
    b[16..24].copy_from_slice(&3u64.to_le_bytes());
    control(f, SET_ATTRIBUTES, &b, 0)?;
    require(attributes(f)? == a, "persistent disk transition failed")
}
impl FreshReferenceDisk {
    pub fn open_blank(binding: Binding) -> io::Result<Self> {
        binding.validate()?;
        require(
            std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
            "owned lab guest required",
        )?;
        for path in std::path::Path::new(&binding.vhd_path).ancestors() {
            use std::os::windows::fs::MetadataExt;
            require(
                std::fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
                "VHD path has reparse ancestry",
            )?;
        }
        let privileges =
            crate::attestation_native::Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        let virtual_disk = VirtualHandle::open(&binding)?;
        virtual_disk.observe(&binding)?;
        let mut events = vec![];
        require(
            native::current_windows_disk(&mut events)? != binding.disk_number,
            "reference routes to Windows disk",
        )?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0x80000000)
            .open(binding.physical_path())?;
        let mut d = Self {
            binding,
            virtual_disk,
            file,
            phase: Phase::Reference,
            last_end: 0,
            reference_bytes: 0,
            import_hash: String::new(),
            payload_hash: String::new(),
            patches: vec![],
            privileges,
        };
        let before = d.state()?;
        require(
            before.disk_attributes == 1 || before.disk_attributes == 3,
            "blank reference must already be offline",
        )?;
        require(
            uninitialized_layout(&before.layout)?,
            "reference must be RAW with no partitions",
        )?;
        let mut b = vec![0u8; CHUNK];
        d.file.seek(SeekFrom::Start(0))?;
        let mut n = 0;
        while n < DISK_BYTES {
            d.file.read_exact(&mut b)?;
            require(
                b.iter().all(|v| *v == 0),
                "populated disk refused before import",
            )?;
            n += CHUNK as u64;
        }
        require(
            d.state()?.disk_attributes == before.disk_attributes,
            "disk exclusion changed during zero proof",
        )?;
        set_attributes(&d.file, 1)?;
        Ok(d)
    }
    pub fn restore_privileges(&mut self) -> io::Result<()> {
        self.privileges.restore()
    }
    pub fn state(&self) -> io::Result<State> {
        let vhd = self.virtual_disk.observe(&self.binding)?;
        let device = control(&self.file, DEVICE, &[], 12)?;
        let length = control(&self.file, LENGTH, &[], 8)?;
        let mut q = [0u8; 12];
        q[..4].copy_from_slice(&6u32.to_le_bytes());
        let alignment = control(&self.file, ALIGNMENT, &q, 64)?;
        require(
            device.len() == 12
                && layout::u32_at(&device, 0)? == 7
                && layout::u32_at(&device, 4)? == self.binding.disk_number
                && length.len() == 8
                && layout::u64_at(&length, 0)? == DISK_BYTES
                && alignment.len() >= 28
                && layout::u32_at(&alignment, 16)? == 512
                && layout::u32_at(&alignment, 20)? == 4096,
            "native route/geometry differs",
        )?;
        Ok(State {
            disk_attributes: attributes(&self.file)?,
            device,
            length,
            alignment,
            layout: control(&self.file, LAYOUT, &[], 65536)?,
            vhd,
        })
    }
    fn require_offline(&self) -> io::Result<()> {
        self.virtual_disk.observe(&self.binding)?;
        require(
            attributes(&self.file)? & 1 == 1,
            "reference lost disk exclusion",
        )
    }
    pub fn read_at(&mut self, offset: u64, b: &mut [u8]) -> io::Result<()> {
        require(
            offset.is_multiple_of(512)
                && b.len().is_multiple_of(512)
                && offset
                    .checked_add(b.len() as u64)
                    .is_some_and(|e| e <= DISK_BYTES),
            "reference read bounds differ",
        )?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(b)
    }
    pub fn write_reference_chunk(&mut self, offset: u64, b: &[u8]) -> io::Result<()> {
        require(
            self.phase == Phase::Reference
                && offset >= self.last_end
                && offset.is_multiple_of(CHUNK as u64)
                && b.len() == CHUNK
                && offset
                    .checked_add(CHUNK as u64)
                    .is_some_and(|e| e <= DISK_BYTES)
                && self.reference_bytes + b.len() as u64 <= 256 << 20,
            "reference chunk phase/bounds/budget differs",
        )?;
        self.require_offline()?;
        let mut old = vec![0; b.len()];
        self.read_at(offset, &mut old)?;
        require(
            old.iter().all(|v| *v == 0),
            "reference chunk no longer blank",
        )?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(b)?;
        self.read_at(offset, &mut old)?;
        require(old == b, "reference chunk readback differs")?;
        self.last_end = offset + b.len() as u64;
        self.reference_bytes += b.len() as u64;
        Ok(())
    }
    pub fn verify_reference(
        &mut self,
        disk_pin: &str,
        payload_pin: &str,
        fixed_pin: &str,
        footer: &[u8],
    ) -> io::Result<ImportProof> {
        require(
            self.phase == Phase::Reference
                && valid_hash(disk_pin)
                && valid_hash(payload_pin)
                && valid_hash(fixed_pin)
                && footer.len() == 512,
            "reference proof phase/hash differs",
        )?;
        self.require_offline()?;
        self.file.sync_all()?;
        let mut hash = Sha256::new();
        let mut b = vec![0; CHUNK];
        self.file.seek(SeekFrom::Start(0))?;
        let mut n = 0;
        while n < DISK_BYTES {
            self.file.read_exact(&mut b)?;
            hash.update(&b);
            n += CHUNK as u64;
        }
        let actual = hex::encode(hash.clone().finalize());
        require(actual == disk_pin, "complete imported disk SHA-256 differs")?;
        hash.update(footer);
        require(
            hex::encode(hash.finalize()) == fixed_pin,
            "imported disk plus fixed footer SHA-256 differs",
        )?;
        let mut payload = [0u8; 4096];
        self.read_at(PARTITION_OFFSET + PAYLOAD_OFFSET, &mut payload)?;
        let payload = digest(&payload);
        require(payload == payload_pin, "imported payload differs")?;
        self.require_offline()?;
        control(&self.file, UPDATE, &[], 0)?;
        let state = self.state()?;
        require(state.disk_attributes == 1, "imported disk lost exclusion")?;
        validate_imported_layout(&state, self.binding.disk_number)?;
        self.import_hash = actual.clone();
        self.payload_hash = payload.clone();
        self.phase = Phase::Overlay;
        Ok(ImportProof {
            disk_sha256: actual,
            blank_bytes_checked: DISK_BYTES,
            reference_bytes_written: self.reference_bytes,
            payload_sha256: payload,
        })
    }
    pub fn apply_metadata_patch(
        &mut self,
        offset: u64,
        b: &[u8],
        old_pin: &str,
        new_pin: &str,
    ) -> io::Result<()> {
        let end = offset
            .checked_add(b.len() as u64)
            .ok_or_else(|| layout::invalid("metadata overflow"))?;
        require(
            self.phase == Phase::Overlay
                && self.patches.len() < 8
                && b.len() == 16384
                && offset.is_multiple_of(4096)
                && end <= PARTITION_BYTES
                && !(offset < PAYLOAD_OFFSET + PAYLOAD_BYTES && PAYLOAD_OFFSET < end)
                && valid_hash(old_pin)
                && valid_hash(new_pin)
                && digest(b) == new_pin,
            "metadata phase/bounds/protected payload/hash differs",
        )?;
        require(
            self.patches
                .iter()
                .all(|p| offset >= p.partition_offset + p.length || p.partition_offset >= end),
            "metadata ranges overlap",
        )?;
        self.require_offline()?;
        let at = PARTITION_OFFSET + offset;
        let mut old = vec![0; b.len()];
        self.read_at(at, &mut old)?;
        require(digest(&old) == old_pin, "old metadata SHA differs")?;
        self.file.seek(SeekFrom::Start(at))?;
        self.file.write_all(b)?;
        self.file.sync_all()?;
        self.read_at(at, &mut old)?;
        require(digest(&old) == new_pin, "durable metadata readback differs")?;
        self.patches.push(PatchObservation {
            partition_offset: offset,
            length: b.len() as u64,
            old_sha256: old_pin.into(),
            new_sha256: new_pin.into(),
        });
        Ok(())
    }
    fn verify_final_pages(&mut self) -> io::Result<()> {
        for i in 0..self.patches.len() {
            let p = self.patches[i].clone();
            let mut b = vec![0; p.length as usize];
            self.read_at(PARTITION_OFFSET + p.partition_offset, &mut b)?;
            require(digest(&b) == p.new_sha256, "final metadata page changed")?;
        }
        let mut p = [0u8; 4096];
        self.read_at(PARTITION_OFFSET + PAYLOAD_OFFSET, &mut p)?;
        require(
            digest(&p) == self.payload_hash,
            "adopted payload was rewritten",
        )
    }
    pub fn finish_overlay(&mut self) -> io::Result<PreparedProof> {
        require(
            self.phase == Phase::Overlay && self.patches.len() == 8,
            "complete eight-page overlay required",
        )?;
        self.require_offline()?;
        self.file.sync_all()?;
        self.verify_final_pages()?;
        set_attributes(&self.file, 3)?;
        control(&self.file, UPDATE, &[], 0)?;
        let state = self.state()?;
        validate_imported_layout(&state, self.binding.disk_number)?;
        require(
            state.disk_attributes == 3,
            "prepared reference lost persistent exclusion",
        )?;
        self.phase = Phase::Prepared;
        Ok(PreparedProof {
            binding: self.binding.clone(),
            import_disk_sha256: self.import_hash.clone(),
            payload_sha256: self.payload_hash.clone(),
            patches: self.patches.clone(),
            state,
            native_mount_qualified: false,
        })
    }
    /// Caller first persists PreparedProof and explicit handoff intent.
    pub fn handoff(&mut self, p: &PreparedProof) -> io::Result<State> {
        require(
            self.phase == Phase::Prepared
                && p.binding.vhd_path == self.binding.vhd_path
                && p.binding.persistent_vhd_id == self.binding.persistent_vhd_id
                && p.import_disk_sha256 == self.import_hash
                && p.payload_sha256 == self.payload_hash,
            "prepared handoff proof differs",
        )?;
        self.require_offline()?;
        self.verify_final_pages()?;
        self.phase = Phase::HandedOff;
        set_attributes(&self.file, 0)?;
        control(&self.file, UPDATE, &[], 0)?;
        let state = self.state()?;
        validate_imported_layout(&state, self.binding.disk_number)?;
        require(
            state.disk_attributes == 0,
            "native handoff did not bring disk online",
        )?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_native_layout_accepts_observed_zero_header_without_accepting_mbr_data() {
        assert!(uninitialized_layout(&[0; 48]).unwrap());
        let mut raw = [0; 48];
        raw[..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(uninitialized_layout(&raw).unwrap());
        raw[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(!uninitialized_layout(&raw).unwrap());
        let mut mbr = [0; 48];
        mbr[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
        assert!(!uninitialized_layout(&mbr).unwrap());
        assert!(!uninitialized_layout(&[0; 47]).unwrap());
        assert!(!uninitialized_layout(&[0; 192]).unwrap());
    }
    #[test]
    fn enrollment_rejects_existing_roles_paths_and_empty_virtual_identity() {
        let id = "0123456789abcdef0123456789abcdef";
        let binding = Binding {
            experiment_id: id.into(),
            vhd_path: format!("J:\\ntfs2refs-reference\\{id}\\reference.vhdx"),
            persistent_vhd_id: "a0c231ef-a959-4a6e-8ae2-7d80363eebe6".into(),
            disk_number: 3,
        };
        binding.validate().unwrap();
        assert_eq!(binding.physical_path(), "\\\\.\\PhysicalDrive3");
        for number in [0, 1, 2, 64, u32::MAX] {
            let mut b = binding.clone();
            b.disk_number = number;
            assert!(b.validate().is_err());
        }
        for path in [
            "J:\\ntfs2refs-shadow\\0123456789abcdef0123456789abcdef\\shadow.vhdx",
            "C:\\Windows\\reference.vhdx",
            "\\\\.\\PhysicalDrive3",
            "J:\\ntfs2refs-reference\\..\\reference.vhdx",
        ] {
            let mut b = binding.clone();
            b.vhd_path = path.into();
            assert!(b.validate().is_err());
        }
        let mut b = binding.clone();
        b.persistent_vhd_id = "00000000-0000-0000-0000-000000000000".into();
        assert!(b.validate().is_err());
        let mut b = binding;
        b.experiment_id = "A".repeat(32);
        assert!(b.validate().is_err());
    }
}
