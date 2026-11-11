//! Private physical data backing. Readers have no RW handle. A writer can
//! only be opened by this parent module's actual spent J/AP gate permit.
use super::*;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct Reader {
    file: File,
    binding: PartitionSourceBinding,
    token: PartitionOwnerToken,
    native_layout: Vec<u8>,
}
pub(super) struct Writer {
    file: File,
    binding: PartitionSourceBinding,
    token: PartitionOwnerToken,
}
fn absolute(binding: &PartitionSourceBinding, relative: u64, bytes: usize) -> io::Result<u64> {
    let id = &binding.storage.identity;
    if !relative.is_multiple_of(GRANULE)
        || !bytes.is_multiple_of(GRANULE as usize)
        || bytes > MAX_IO
        || relative
            .checked_add(bytes as u64)
            .is_none_or(|end| end > id.partition_bytes)
    {
        return Err(io::Error::other(
            "physical source transfer escapes aligned volume-relative window",
        ));
    }
    let offset = id
        .partition_offset
        .checked_add(relative)
        .ok_or_else(|| io::Error::other("physical source base addition overflow"))?;
    let end = offset
        .checked_add(bytes as u64)
        .ok_or_else(|| io::Error::other("physical source transfer overflow"))?;
    let limit = id
        .partition_offset
        .checked_add(id.partition_bytes)
        .ok_or_else(|| io::Error::other("physical source bound overflow"))?;
    if offset < id.partition_offset || end > limit || end > id.disk_bytes || end > i64::MAX as u64 {
        return Err(io::Error::other(
            "physical source transfer crosses partition/disk bound",
        ));
    }
    Ok(offset)
}
fn native(
    file: &File,
    binding: &PartitionSourceBinding,
    expected_layout: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<()> {
    let device = control(
        file,
        "physical-data-native-device",
        super::super::DEVICE,
        &[],
        12,
        events,
    )?;
    let length = control(
        file,
        "physical-data-native-length",
        super::super::LENGTH,
        &[],
        8,
        events,
    )?;
    let mut query = [0u8; 12];
    query[0] = 6;
    let alignment = control(
        file,
        "physical-data-native-alignment",
        super::super::ALIGNMENT,
        &query,
        28,
        events,
    )?;
    binding.storage.validate_alignment(&alignment)?;
    if expected_layout.len() < 48 || expected_layout.len() > 65536 {
        return Err(io::Error::other(
            "physical source native layout is not a complete bounded snapshot",
        ));
    }
    let layout = control(
        file,
        "physical-data-native-complete-layout",
        super::super::LAYOUT,
        &[],
        expected_layout.len(),
        events,
    )?;
    if device.len() != 12
        || crate::layout::u32_at(&device, 0)? != 7
        || crate::layout::u32_at(&device, 4)? != binding.storage.disk_number
        || crate::layout::u32_at(&device, 8)? != 0
        || length.len() != 8
        || crate::layout::u64_at(&length, 0)? != binding.storage.identity.disk_bytes
        || layout != expected_layout
    {
        return Err(io::Error::other(
            "physical source data handle is not the actual complete disk (partition0)",
        ));
    }
    Ok(())
}
fn read(
    file: &mut File,
    binding: &PartitionSourceBinding,
    relative: u64,
    bytes: &mut [u8],
) -> io::Result<usize> {
    let offset = absolute(binding, relative, bytes.len())?;
    if file.seek(SeekFrom::Start(offset))? != offset {
        return Err(io::Error::other("physical source read seek differs"));
    }
    file.read(bytes)
}
impl Reader {
    pub(super) fn open(
        binding: &PartitionSourceBinding,
        token: PartitionOwnerToken,
        native_layout: &[u8],
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        binding.validate()?;
        if !binding
            .storage
            .identity
            .partition_offset
            .is_multiple_of(GRANULE)
            || !binding
                .storage
                .identity
                .partition_bytes
                .is_multiple_of(GRANULE)
        {
            return Err(io::Error::other(
                "physical source bounds are not granule-aligned",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                binding.storage.disk_number
            ))?;
        native(&file, binding, native_layout, events)?;
        Ok(Self {
            file,
            binding: binding.clone(),
            token,
            native_layout: native_layout.to_vec(),
        })
    }
    pub(super) fn revalidate(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        native(&self.file, &self.binding, &self.native_layout, events)
    }
    // Parent owner/lane serializes this kernel seek/read using the SAME token.
    pub(super) fn read_at(&mut self, relative: u64, bytes: &mut [u8]) -> io::Result<usize> {
        read(&mut self.file, &self.binding, relative, bytes)
    }
    pub(super) fn duplicate_lane(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<super::super::partition_lifecycle::held_read::HeldSourceRead> {
        super::super::partition_lifecycle::held_read::duplicate_physical_bound(
            &self.file,
            &self.binding,
            &self.token,
            events,
        )
    }
    pub(super) fn open_writer(
        &self,
        permit: PhysicalWritePermit,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Writer> {
        if !self.token.same_owner(&permit.owner) || self.binding != permit.binding {
            return Err(io::Error::other(
                "physical writer permit belongs to another actual source",
            ));
        }
        // This private ctor is called ONLY after the existing gate has been
        // spent and actual AP/RB/J/source authentication completed. No RW
        // handle exists in Reader or from any serialized route/profile input.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(format!(
                "\\\\.\\PhysicalDrive{}",
                self.binding.storage.disk_number
            ))?;
        native(&file, &self.binding, &self.native_layout, events)?;
        Ok(Writer {
            file,
            binding: self.binding.clone(),
            token: self.token.clone(),
        })
    }
}
impl Writer {
    pub(super) fn read_at(
        &mut self,
        token: &PartitionOwnerToken,
        relative: u64,
        bytes: &mut [u8],
    ) -> io::Result<usize> {
        if !self.token.same_owner(token) {
            return Err(io::Error::other("physical readback source token changed"));
        }
        read(&mut self.file, &self.binding, relative, bytes)
    }
    pub(super) fn write_at(
        &mut self,
        token: &PartitionOwnerToken,
        relative: u64,
        bytes: &[u8],
    ) -> io::Result<usize> {
        if !self.token.same_owner(token) {
            return Err(io::Error::other("physical source writer token changed"));
        }
        let offset = absolute(&self.binding, relative, bytes.len())?;
        if self.file.seek(SeekFrom::Start(offset))? != offset {
            return Err(io::Error::other("physical source write seek differs"));
        }
        self.file.write(bytes)
    }
    pub(super) fn flush(&self, token: &PartitionOwnerToken) -> io::Result<()> {
        if !self.token.same_owner(token) {
            return Err(io::Error::other("physical source flush token changed"));
        }
        self.file.sync_all()
    }
}
