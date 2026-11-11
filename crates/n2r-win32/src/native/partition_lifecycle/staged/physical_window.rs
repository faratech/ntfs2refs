//! Read-only physical partition window borrowed from the actual live lock
//! owner. No source volume open/data I/O, RW file, writer or public raw handle.
use super::*;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};

pub(in crate::native) struct LockedPhysicalPartitionReader<'guard> {
    guard: &'guard mut PartitionPreparationGuard,
    physical: File,
    token: PartitionPreparationToken,
    buffer: AlignedBuffer,
    base: u64,
    length: u64,
    disk_bytes: u64,
    position: u64,
    bytes_read: u64,
    poisoned: bool,
    _memory: Box<dyn ReportMemoryLease>,
}
#[derive(Serialize)]
pub(in crate::native) struct PhysicalReadWindowReceipt {
    kind: &'static str,
    binding: PartitionSourceBinding,
    physical_base: u64,
    window_bytes: u64,
    source_bytes_read: u64,
    real_volume_lock_owner_retained: bool,
    source_volume_payload_io_calls: u64,
    physical_write_handle_issued: bool,
    persistent_exclusion_or_quiescence_qualified: bool,
    grants_source_write_authority: bool,
}
impl PartitionPreparationGuard {
    /// Read workspace is prepaid by the caller's actual accountant. Borrowing
    /// this guard retains its actual locked Volume FILE_OBJECT separately from
    /// the READ-only physical handle for the complete reader lifetime.
    pub(in crate::native) fn physical_partition_reader<'guard>(
        &'guard mut self,
        memory: &dyn ReportMemoryAccountant,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<LockedPhysicalPartitionReader<'guard>> {
        require(
            self.locked
                && self.volume.is_some()
                && self.physical.is_some()
                && self.stage != PartitionPreparationStage::Poisoned,
            "physical source reader requires the actual still-held volume lock owner",
        )?;
        let id = &self.binding.storage.identity;
        let base = id.partition_offset;
        let length = id.partition_bytes;
        let disk_bytes = id.disk_bytes;
        require(
            base.is_multiple_of(4096)
                && length.is_multiple_of(4096)
                && length > 0
                && base
                    .checked_add(length)
                    .is_some_and(|end| end <= disk_bytes),
            "physical source window alignment/extent is not representable",
        )?;
        let lease = memory.reserve(MAX_IO as u64)?;
        let physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.storage.disk_number),
            false,
            true,
        )?;
        let token = self.token.clone();
        let mut value = LockedPhysicalPartitionReader {
            guard: self,
            physical,
            token,
            buffer: AlignedBuffer::new()?,
            base,
            length,
            disk_bytes,
            position: 0,
            bytes_read: 0,
            poisoned: false,
            _memory: lease,
        };
        value.revalidate(events)?;
        Ok(value)
    }
}
impl LockedPhysicalPartitionReader<'_> {
    fn require_held(&self) -> io::Result<()> {
        require(
            !self.poisoned
                && self.guard.locked
                && self.guard.volume.is_some()
                && self.guard.physical.is_some()
                && self.guard.stage != PartitionPreparationStage::Poisoned
                && self.token.same_owner(&self.guard.token)
                && self.base == self.guard.binding.storage.identity.partition_offset
                && self.length == self.guard.binding.storage.identity.partition_bytes,
            "physical source read window lost actual original protection/bounds",
        )
    }
    pub(in crate::native) fn revalidate(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.guard
            .checkpoint("physical-window-metadata-before", events)?;
        let result = (|| {
            self.require_held()?;
            let target: [u8; 16] = self
                .guard
                .current_info
                .get(32..48)
                .ok_or_else(|| invalid("physical window current native row missing"))?
                .try_into()
                .map_err(|_| invalid("physical window target type width differs"))?;
            // This explicit observer NEVER opens the selected source namespace.
            // The actual volume LOCK FileObject remains in guard.volume.
            let mut metadata = device_file(
                &format!(
                    "\\\\.\\PhysicalDrive{}",
                    self.guard.binding.storage.disk_number
                ),
                false,
                false,
            )?;
            let current = super::super::super::partition_isolation::observe_physical_only(
                &mut metadata,
                &self.guard.binding,
                self.guard.budget,
                events,
                target,
            )?;
            let data_device = control(
                &self.physical,
                "physical-window-data-device",
                super::super::super::DEVICE,
                &[],
                12,
                events,
            )?;
            let data_length = control(
                &self.physical,
                "physical-window-data-length",
                super::super::super::LENGTH,
                &[],
                8,
                events,
            )?;
            require(
                data_device == current.disk_device && data_length == current.disk_length,
                "physical data and readonly metadata handles refer to different disk geometry",
            )?;
            self.guard.expected_gpt(&current)?;
            let old = &self.guard.baseline;
            require(
                current.disk_device == old.disk_device
                    && current.disk_length == old.disk_length
                    && current.alignment == old.alignment
                    && current.disk_attributes == 0
                    && current.windows_volume == old.windows_volume
                    && current.paging == old.paging,
                "physical window native disk/GPT/C/page identity changed",
            )?;
            self.guard
                .checkpoint("physical-window-critical-before", events)?;
            let dumps =
                observe_configured_dump_locations(&self.guard.binding, self.guard.budget, events)?;
            let roles =
                observe_partition_storage_roles(&self.guard.binding, self.guard.budget, events)?;
            require(
                dumps == self.guard.dumps && roles.same_critical_roles(&self.guard.roles),
                "physical window configured/current critical roles changed",
            )
        })();
        let closed = self
            .guard
            .checkpoint("physical-window-metadata-after", events);
        let result = match (result, closed) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Err(closed)) => Err(io::Error::new(
                error.kind(),
                format!("{error}; physical window event checkpoint also failed: {closed}"),
            )),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(in crate::native) fn finish(
        mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PhysicalReadWindowReceipt> {
        self.revalidate(events)?;
        Ok(PhysicalReadWindowReceipt {
            kind: "actual-locked-physical-partition-read-window",
            binding: self.guard.binding.clone(),
            physical_base: self.base,
            window_bytes: self.length,
            source_bytes_read: self.bytes_read,
            real_volume_lock_owner_retained: true,
            source_volume_payload_io_calls: 0,
            physical_write_handle_issued: false,
            persistent_exclusion_or_quiescence_qualified: false,
            grants_source_write_authority: false,
        })
    }
}
impl Seek for LockedPhysicalPartitionReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.require_held()?;
        let value = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        if value < 0 || value > i128::from(self.length) {
            self.poisoned = true;
            return Err(invalid("physical source logical seek outside partition"));
        }
        self.position = value as u64;
        Ok(self.position)
    }
}
impl Read for LockedPhysicalPartitionReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let result = (|| {
            self.require_held()?;
            if out.is_empty() || self.position == self.length {
                return Ok(0);
            }
            let lead = (self.position % 4096) as usize;
            let count =
                (out.len().min(MAX_IO - lead) as u64).min(self.length - self.position) as usize;
            let transfer = (lead + count).div_ceil(4096) * 4096;
            let relative = self.position - lead as u64;
            let absolute = self
                .base
                .checked_add(relative)
                .ok_or_else(|| invalid("physical source offset overflow"))?;
            let end = absolute
                .checked_add(transfer as u64)
                .ok_or_else(|| invalid("physical source transfer overflow"))?;
            let limit = self
                .base
                .checked_add(self.length)
                .ok_or_else(|| invalid("physical source window overflow"))?;
            require(
                absolute >= self.base && end <= limit && end <= self.disk_bytes,
                "physical source transfer would escape selected partition",
            )?;
            // The physical READ handle is unique and private; this method owns
            // its kernel cursor across the absolute seek/read pair.
            require(
                self.physical.seek(SeekFrom::Start(absolute))? == absolute,
                "physical source kernel seek differs",
            )?;
            let got = self
                .physical
                .read(&mut self.buffer.bytes_mut()[..transfer])?;
            require(got >= lead + count, "short bounded physical source read")?;
            out[..count].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + count]);
            self.position += count as u64;
            self.bytes_read = self
                .bytes_read
                .checked_add(count as u64)
                .ok_or_else(|| invalid("physical source read accounting overflow"))?;
            Ok(count)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
