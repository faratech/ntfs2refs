//! Already-operational Basic0 metadata only. No general source data reader, original
//! content comparison, lock, setter, writer, replay gate or restoration owner.
use super::*;

#[derive(Serialize)]
pub struct OperationalPartitionMetadata {
    pub mounted_binding: crate::general_layout::GeneralDiskBinding,
    pub filesystem: String,
    pub label: crate::volume_label::VolumeLabel,
    pub mount_paths: MountPathObservation,
    pub current_contents_reverified: bool,
}
pub struct PartitionOperationalTerminal {
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    baseline: TerminalMetadataBaseline,
    volume: File,
    mounted_binding: crate::general_layout::GeneralDiskBinding,
    info: Vec<u8>,
    filesystem: String,
}
impl PartitionOperationalTerminal {
    /// One discovery metadata sector only. Exclusive borrow prevents a shared
    /// FILE_OBJECT cursor race; no general Read/Seek/raw handle escapes.
    pub fn discovery_metadata(&mut self) -> io::Result<Vec<u8>> {
        let sector = usize::try_from(self.binding.storage.identity.logical_sector_bytes)
            .map_err(io::Error::other)?;
        need(
            matches!(sector, 512 | 4096),
            "operational discovery sector profile unsupported",
        )?;
        let mut bytes = AlignedBuffer::new()?;
        let mut file = self.volume.try_clone()?;
        need(
            file.seek(SeekFrom::Start(0))? == 0,
            "operational discovery metadata seek differs",
        )?;
        let count = file.read(&mut bytes.bytes_mut()[..sector])?;
        need(
            count == sector,
            "short operational discovery metadata sector",
        )?;
        Ok(bytes.bytes_mut()[..512].to_vec())
    }
    /// None only for positively observed PRIVATE0 or BasicRO, which keep
    /// their existing separate actual owners. Unknown/error never falls back.
    pub fn open_if_actual_basic0(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Option<Self>> {
        binding.validate()?;
        budget.validate()?;
        publication_checkpoint(
            Ok(()),
            observer,
            "operational-terminal-route-opening",
            events,
        )?;
        let (info, _) = super::super::partition_storage_roles::selected_from_physical_layout(
            &binding, budget, events,
        )?;
        let attrs = crate::layout::u64_at(&info, 64)?;
        if (info[32..48] == crate::layout::guid_bytes(PRIVATE)? && attrs == 0)
            || (info[32..48] == crate::layout::guid_bytes(BASIC)? && attrs == RO)
        {
            return publication_checkpoint(
                Ok(None),
                observer,
                "operational-terminal-route-not-basic0",
                events,
            );
        }
        need(
            info[32..48] == crate::layout::guid_bytes(BASIC)? && attrs == 0,
            "operational reconciliation requires positively observed Basic0; unknown native state refuses",
        )?;
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        let partition =
            partition_isolation::observe_basic(&mut physical, &binding, budget, events)?;
        need(
            partition.gpt.target_attributes == 0
                && partition.disk_attributes == 0
                && partition.paging.all_locations_resolved
                && !partition.paging.source_hosts_active_pagefile,
            "operational source current native protection/critical routes differ",
        )?;
        publication_checkpoint(
            Ok(()),
            observer,
            "operational-terminal-native-gpt-C-page",
            events,
        )?;
        let dumps =
            partition_dump_locations::observe_configured_dump_locations(&binding, budget, events)?;
        let roles = super::super::partition_storage_roles::observe_partition_storage_roles(
            &binding, budget, events,
        )?;
        need(
            dumps.configured_locations_outside_target && roles.catalog_complete,
            "operational current critical routes are unresolved",
        )?;
        publication_checkpoint(
            Ok(()),
            observer,
            "operational-terminal-current-roles",
            events,
        )?;
        let (mounted_binding, volume) =
            find_terminal_volume(&binding, &info, budget, observer, events)?;
        let fs = terminal_volume_info(&volume)?;
        need(
            matches!(fs.filesystem.as_str(), "NTFS" | "ReFS") && fs.flags & 0x80000 == 0,
            "operational source is not current writable NTFS/ReFS",
        )?;
        let value = Self {
            binding,
            budget,
            baseline: TerminalMetadataBaseline {
                partition,
                configured_dump_locations: dumps,
                storage_current_partition_roles: roles,
            },
            volume,
            mounted_binding,
            info,
            filesystem: fs.filesystem,
        };
        value.revalidate(observer, events)?;
        Ok(Some(value))
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub fn windows_volume(&self) -> &partition_isolation::PartitionVolumeExtent {
        &self.baseline.partition.windows_volume
    }
    pub fn native_partition_info(&self) -> &[u8] {
        &self.info
    }
    pub fn require_closed_kind(&self, kind: PartitionTerminalKind) -> io::Result<()> {
        need(
            self.filesystem
                == if kind == PartitionTerminalKind::Handoff {
                    "ReFS"
                } else {
                    "NTFS"
                },
            "operational filesystem differs from actual closed HND/ABT; no replay or restoration is available",
        )
    }
    pub fn current_metadata(&self) -> io::Result<OperationalPartitionMetadata> {
        let current = terminal_volume_info(&self.volume)?;
        need(
            current.filesystem == self.filesystem && current.flags & 0x80000 == 0,
            "operational filesystem/protection changed",
        )?;
        let paths =
            super::super::capture_mount_paths_for_bound_volume(self.mounted_binding.clone())?;
        need(
            paths.all_paths_resolve_to_bound_volume,
            "operational mount paths are unresolved",
        )?;
        Ok(OperationalPartitionMetadata {
            mounted_binding: self.mounted_binding.clone(),
            filesystem: current.filesystem,
            label: current.label,
            mount_paths: paths,
            current_contents_reverified: false,
        })
    }
    pub fn revalidate(
        &self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        publication_checkpoint(
            Ok(()),
            observer,
            "operational-terminal-before-native-bookend",
            events,
        )?;
        let result = (|| {
            let mut physical = device_file(
                &format!("\\\\.\\PhysicalDrive{}", self.binding.storage.disk_number),
                false,
                false,
            )?;
            let actual = partition_isolation::observe_basic(
                &mut physical,
                &self.binding,
                self.budget,
                events,
            )?;
            let old = &self.baseline.partition;
            need(
                actual.gpt == old.gpt
                    && actual.disk_device == old.disk_device
                    && actual.disk_length == old.disk_length
                    && actual.alignment == old.alignment
                    && actual.disk_attributes == 0
                    && actual.windows_volume == old.windows_volume
                    && actual.paging == old.paging,
                "operational current GPT/C/page/physical binding changed during observation",
            )?;
            let dumps = partition_dump_locations::observe_configured_dump_locations(
                &self.binding,
                self.budget,
                events,
            )?;
            let roles = super::super::partition_storage_roles::observe_partition_storage_roles(
                &self.binding,
                self.budget,
                events,
            )?;
            need(
                dumps == self.baseline.configured_dump_locations
                    && roles.same_critical_roles(&self.baseline.storage_current_partition_roles),
                "operational current configured/critical routes changed",
            )?;
            let device = control(
                &self.volume,
                "operational-terminal-DEVICE",
                super::super::DEVICE,
                &[],
                12,
                events,
            )?;
            let info = control(
                &self.volume,
                "operational-terminal-PARTITION_INFO",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            let ext = control(
                &self.volume,
                "operational-terminal-EXTENTS",
                VOLUME_EXTENTS,
                &[],
                32,
                events,
            )?;
            self.mounted_binding.validate_volume_extent(&ext)?;
            need(
                device.len() == 12
                    && crate::layout::u32_at(&device, 0)? == 7
                    && crate::layout::u32_at(&device, 4)? == self.binding.storage.disk_number
                    && crate::layout::u32_at(&device, 8)?
                        == self.binding.storage.identity.partition_number
                    && info == self.info,
                "operational selected native volume identity changed",
            )?;
            let writable = control(
                &self.volume,
                "operational-terminal-IS_WRITABLE",
                0x0007_0024,
                &[],
                0,
                events,
            )?;
            need(
                writable.is_empty(),
                "operational writable query returned unexpected data",
            )?;
            let fs = terminal_volume_info(&self.volume)?;
            need(
                fs.filesystem == self.filesystem && fs.flags & 0x80000 == 0,
                "operational filesystem/protection changed",
            )
        })();
        publication_checkpoint(
            result,
            observer,
            "operational-terminal-native-bookend",
            events,
        )
    }
}
