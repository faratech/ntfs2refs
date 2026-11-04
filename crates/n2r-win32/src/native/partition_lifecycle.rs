//! Partition-only lifecycle/read-lane interface. No whole-disk transition is a
//! substitute. Fresh admission issuance intentionally remains UNAVAILABLE.
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::{
    AlignedBuffer, MAX_IO, NativeEvent, PartitionOwnerToken, PartitionScopedOwner, control,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
};

/// Complete durable target-only preparation guard, not parsed intent JSON.
/// Constructor/issuer is absent until cancellation/type lifecycle is complete.
pub struct PartitionPreparationGuard {
    _unissued: (),
}
/// Must own the real mounted-NTFS freeze/native-RO evidence and complete guard.
/// No observation, boolean, saved file or GeneralFreezeObservation creates it.
pub struct PartitionNtfsAdmission {
    owner: PartitionOwnerToken,
    _guard: PartitionPreparationGuard,
    _unissued_protected_native: (),
}
pub fn freeze_mounted_ntfs_partition(
    _binding: PartitionSourceBinding,
    _budget: PartitionObservationBudget,
    _guard: PartitionPreparationGuard,
    _events: &mut Vec<NativeEvent>,
) -> io::Result<(PartitionScopedOwner, PartitionNtfsAdmission)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "target-only Basic/private freeze and protected native-RO witness issuer not implemented; no source transition performed",
    ))
}
pub fn require_complete_fresh_ntfs_admission(
    owner: &PartitionScopedOwner,
    admission: &PartitionNtfsAdmission,
) -> io::Result<()> {
    if !admission.owner.same_owner(&owner.owner_token()) {
        return Err(io::Error::other(
            "partition native admission belongs to a different actual owner",
        ));
    }
    // There is currently no constructor that could have produced admission.
    // Never fall back to the legacy physical READ_ONLY observation lease.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "partition native-RO and complete preparation guard issuance remain pending",
    ))
}

/// Independent readonly FILE_OBJECT/cursor opened while actual owner remains
/// held. No Write, Deserialize or caller-selected path constructor exists.
pub struct PartitionReadLane {
    file: File,
    binding: PartitionSourceBinding,
    token: PartitionOwnerToken,
    buffer: AlignedBuffer,
    position: u64,
    poisoned: bool,
}
impl PartitionReadLane {
    pub const fn read_buffer_memory_bytes() -> u64 {
        MAX_IO as u64
    }
    pub fn from_owner(
        owner: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        owner.revalidate(events)?;
        let binding = owner.binding().clone();
        let token = owner.owner_token();
        let route = format!(
            "\\\\?\\GLOBALROOT\\Device\\Harddisk{}\\Partition{}",
            binding.storage.disk_number, binding.storage.identity.partition_number
        );
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0xa000_0000)
            .open(route)?;
        let mut lane = Self {
            file,
            binding,
            token,
            buffer: AlignedBuffer::new()?,
            position: 0,
            poisoned: false,
        };
        lane.revalidate(owner, events)?;
        Ok(lane)
    }
    pub fn byte_len(&self) -> u64 {
        self.binding.storage.identity.partition_bytes
    }
    pub fn revalidate(
        &mut self,
        owner: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        let result = (|| {
            if self.poisoned
                || !self.token.same_owner(&owner.owner_token())
                || self.binding != *owner.binding()
            {
                return Err(io::Error::other(
                    "readonly partition lane lost original live owner",
                ));
            }
            owner.revalidate(events)?;
            let number = control(
                &self.file,
                "readonly-partition-lane-device",
                super::DEVICE,
                &[],
                12,
                events,
            )?;
            let info = control(
                &self.file,
                "readonly-partition-lane-info",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            let target_guid =
                crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?;
            let expected = owner.state().partition.gpt.native_layout[48..]
                .chunks_exact(144)
                .find(|row| row[48..64] == target_guid)
                .ok_or_else(|| io::Error::other("readonly lane target native row absent"))?;
            if number.len() != 12
                || crate::layout::u32_at(&number, 4)? != self.binding.storage.disk_number
                || crate::layout::u32_at(&number, 0)? != 7
                || crate::layout::u32_at(&number, 8)?
                    != self.binding.storage.identity.partition_number
                || info.len() != 144
                || info.as_slice() != expected
                || crate::layout::u64_at(&info, 8)?
                    != self.binding.storage.identity.partition_offset
                || crate::layout::u64_at(&info, 16)? != self.byte_len()
                || info[48..64]
                    != crate::layout::guid_bytes(&self.binding.storage.identity.partition_guid)?
                || info[32..48]
                    != crate::layout::guid_bytes("b627aadb-a893-48b6-aa0b-71e5f30ee370")?
            {
                return Err(io::Error::other(
                    "readonly lane actual partition route differs",
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
impl Seek for PartitionReadLane {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let p = match p {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.byte_len()) + i128::from(n),
        };
        if self.poisoned || p < 0 || p > i128::from(self.byte_len()) {
            self.poisoned = true;
            return Err(io::Error::other("partition lane seek outside bounds"));
        }
        self.position = p as u64;
        Ok(self.position)
    }
}
impl Read for PartitionReadLane {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let result = (|| {
            if self.poisoned {
                return Err(io::Error::other("partition read lane poisoned"));
            }
            if out.is_empty() || self.position == self.byte_len() {
                return Ok(0);
            }
            let lead = (self.position % 4096) as usize;
            let n =
                (out.len().min(MAX_IO - lead) as u64).min(self.byte_len() - self.position) as usize;
            let transfer = (lead + n).div_ceil(4096) * 4096;
            let at = self.position - lead as u64;
            if self.file.seek(SeekFrom::Start(at))? != at {
                return Err(io::Error::other("partition lane seek differs"));
            }
            let got = self.file.read(&mut self.buffer.bytes_mut()[..transfer])?;
            if got < lead + n {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short partition lane read",
                ));
            }
            out[..n].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + n]);
            self.position += n as u64;
            Ok(n)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
