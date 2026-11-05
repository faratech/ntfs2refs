//! Actual selected BasicRO terminal source. No private owner, FS lock, fresh
//! admission or source writer can be constructed from this metadata capability.
use super::*;
use std::time::{Duration, Instant};
pub struct PartitionBasicReadonlyTerminal {
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    physical: File,
    data_profile:PartitionDataProfile,
    physical_data:Option<PartitionPhysicalDataOwner>,
    baseline: TerminalMetadataBaseline,
    volume: File,
    mounted_binding: crate::general_layout::GeneralDiskBinding,
    info: Vec<u8>,
    token: PartitionOwnerToken,
    filesystem: String,
}
impl PartitionBasicReadonlyTerminal {
    /// None means a positively observed native project-private0 route ONLY;
    /// the caller must still run the full private-owner opener. Basic0 never
    /// falls back to old snapshot hashes or raw replay.
    pub fn open_if_actual_basic_ro(
        binding: PartitionSourceBinding,
        budget: PartitionObservationBudget,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Option<Self>> {
        Self::open_with_profile(binding,budget,observer,events,PartitionDataProfile::PrivateVolumeV2)
    }
    /// Readonly-only route for the explicitly versioned physical protocol.
    /// No lock, admission, replay eligibility or source writer is inferred.
    pub fn open_if_actual_basic_ro_physical(
        binding:PartitionSourceBinding,budget:PartitionObservationBudget,
        observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>
    )->io::Result<Option<Self>> {
        Self::open_with_profile(binding,budget,observer,events,PartitionDataProfile::BasicReadonlyPhysicalV3)
    }
    fn open_with_profile(binding:PartitionSourceBinding,budget:PartitionObservationBudget,
        observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>,data_profile:PartitionDataProfile
    )->io::Result<Option<Self>> {
        binding.validate()?;
        budget.validate()?;
        publication_checkpoint(Ok(()), observer, "basic-ro-terminal-route-opening", events)?;
        let (info, _) = super::super::partition_storage_roles::selected_from_physical_layout(
            &binding, budget, events,
        )?;
        if info[32..48] == crate::layout::guid_bytes(PRIVATE)?
            && crate::layout::u64_at(&info, 64)? == 0
        {
            return publication_checkpoint(
                Ok(None),
                observer,
                "basic-ro-terminal-route-private",
                events,
            );
        }
        need(
            info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&info, 64)? == RO,
            "terminal restart supports private0 or actual BasicRO only; operational Basic0 reconciliation remains unsupported",
        )?;
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            false,
            false,
        )?;
        let partition =
            partition_isolation::observe_basic(&mut physical, &binding, budget, events)?;
        need(
            partition.gpt.target_attributes == RO
                && partition.paging.all_locations_resolved
                && !partition.paging.source_hosts_active_pagefile,
            "actual BasicRO source protection/pagefile evidence differs",
        )?;
        publication_checkpoint(
            Ok(()),
            observer,
            "basic-ro-terminal-native-gpt-C-page",
            events,
        )?;
        let dumps =
            partition_dump_locations::observe_configured_dump_locations(&binding, budget, events)?;
        let roles = super::super::partition_storage_roles::observe_partition_storage_roles(
            &binding, budget, events,
        )?;
        need(
            dumps.configured_locations_outside_target && roles.catalog_complete,
            "BasicRO configured/current critical routes unresolved",
        )?;
        publication_checkpoint(Ok(()), observer, "basic-ro-terminal-current-roles", events)?;
        let started = Instant::now();
        let mut found = None;
        for attempt in 0..60 {
            match find_terminal_volume(&binding, &info, budget, observer, events) {
                Ok(value) => {
                    found = Some(value);
                    break;
                }
                Err(error)
                    if terminal_publication_pending(&error)
                        && attempt < 59
                        && started.elapsed() < Duration::from_secs(15) =>
                {
                    publication_checkpoint(
                        Ok(()),
                        observer,
                        "basic-ro-terminal-publication-pending",
                        events,
                    )?;
                    std::thread::sleep(
                        Duration::from_millis(250)
                            .min(Duration::from_secs(15).saturating_sub(started.elapsed())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        let (mounted_binding, volume) =
            found.ok_or_else(|| bad("actual BasicRO terminal volume not published"))?;
        let token = PartitionOwnerToken::readonly_terminal_identity();
        let fs = terminal_volume_info(&volume)?;
        need(
            matches!(fs.filesystem.as_str(), "ReFS" | "NTFS") && fs.flags & 0x80000 != 0,
            "actual mounted terminal filesystem is not protected NTFS/ReFS",
        )?;
        let reply = control(
            &volume,
            "basic-ro-terminal-extended-dasd",
            0x0009_0083,
            &[],
            0,
            events,
        )?;
        need(
            reply.is_empty(),
            "BasicRO terminal extended DASD reply differs",
        )?;
        let physical_data=if data_profile==PartitionDataProfile::BasicReadonlyPhysicalV3 {
            Some(PartitionPhysicalDataOwner::open_readonly(&binding,token.clone(),&partition.gpt.native_layout,events)?)
        }else{None};
        let value = Self {
            data_profile,physical_data,
            binding,
            budget,
            physical,
            baseline: TerminalMetadataBaseline {
                partition,
                configured_dump_locations: dumps,
                storage_current_partition_roles: roles,
            },
            volume,
            mounted_binding,
            info,
            token,
            filesystem: fs.filesystem,
        };
        value.revalidate(observer, events)?;
        Ok(Some(value))
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub fn owner_token(&self) -> &PartitionOwnerToken {
        &self.token
    }
    pub fn windows_volume(&self) -> &partition_isolation::PartitionVolumeExtent {
        &self.baseline.partition.windows_volume
    }
    pub fn filesystem(&self) -> &str {
        &self.filesystem
    }
    pub fn revalidate(
        &self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        publication_checkpoint(
            Ok(()),
            observer,
            "basic-ro-terminal-before-native-bookend",
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
                "BasicRO full GPT/C/page/physical binding changed",
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
                "BasicRO configured/current critical routes changed",
            )?;
            let dev = control(
                &self.volume,
                "basic-ro-terminal-DEVICE",
                super::super::DEVICE,
                &[],
                12,
                events,
            )?;
            let info = control(
                &self.volume,
                "basic-ro-terminal-PARTITION_INFO",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            let ext = control(
                &self.volume,
                "basic-ro-terminal-EXTENTS",
                VOLUME_EXTENTS,
                &[],
                32,
                events,
            )?;
            self.mounted_binding.validate_volume_extent(&ext)?;
            need(
                dev.len() == 12
                    && crate::layout::u32_at(&dev, 0)? == 7
                    && crate::layout::u32_at(&dev, 4)? == self.binding.storage.disk_number
                    && crate::layout::u32_at(&dev, 8)?
                        == self.binding.storage.identity.partition_number
                    && info == self.info,
                "BasicRO actual mounted native identity/extent changed",
            )?;
            let at = events.len();
            let writable = control(
                &self.volume,
                "basic-ro-terminal-IS_WRITABLE",
                0x0007_0024,
                &[],
                0,
                events,
            );
            need(
                writable.is_err()
                    && events
                        .get(at)
                        .is_some_and(|v| !v.succeeded && v.native_error == Some(19)),
                "BasicRO actual selected device did not report WRITE_PROTECT19",
            )?;
            let fs = terminal_volume_info(&self.volume)?;
            need(
                fs.filesystem == self.filesystem && fs.flags & 0x80000 != 0,
                "BasicRO actual filesystem protection changed",
            )
        })();
        publication_checkpoint(result, observer, "basic-ro-terminal-native-bookend", events)
    }
    pub(in crate::native) fn reader(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<TerminalRawReader> {
        let data=if let Some(data)=self.physical_data.as_ref(){
            data.revalidate_native(events)?;data.duplicate_readonly(events)?
        }else{super::super::partition_lifecycle::held_read::duplicate_bound(&self.volume,&self.binding,&self.info,&self.token,events)?};
        Ok(TerminalRawReader {
            file: TerminalReadBacking::Held(data),
            buffer: AlignedBuffer::new()?,
            position: 0,
            length: self.binding.storage.identity.partition_bytes,
        })
    }
    /// Actual closed-J/source observation only; never a replay/write gate.
    pub fn authenticate_closed(
        &mut self,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &super::super::paged_recovery::PagedRecoveryPins<'_>,
        kind: PartitionTerminalKind,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionClosedJournalObservation> {
        need(
            self.filesystem
                == if kind == PartitionTerminalKind::Handoff {
                    "ReFS"
                } else {
                    "NTFS"
                },
            "actual BasicRO filesystem conflicts with closed HND/ABT",
        )?;
        super::super::paged_recovery::authenticate_basic_ro_closed(
            self, policy, journal, pins, kind, observer, events,
        )
    }
    /// Authenticate real original external files and closed source/J bytes while
    /// protected, then adopt the already-observed readonly stage. No SET occurs.
    pub fn into_authenticated_terminal<'j, 'p>(
        mut self,
        files: PartitionRestartFiles,
        published_sha256: [u8; 32],
        policy: &'j HeldPagedWritePolicy,
        journal: &'j mut File,
        pins: super::super::paged_recovery::PagedRecoveryPins<'p>,
        kind: PartitionTerminalKind,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionTerminalRestorationGuard<'j, 'p>> {
        self.revalidate(observer, events)?;
        need(
            self.filesystem
                == if kind == PartitionTerminalKind::Handoff {
                    "ReFS"
                } else {
                    "NTFS"
                },
            "actual BasicRO filesystem conflicts with closed lifecycle",
        )?;
        let origin = Origin::authenticate(
            files,
            published_sha256,
            &self.binding,
            self.budget,
            &self.baseline.partition.windows_volume,
            &pins,
        )?;
        need(origin.data_profile==self.data_profile,"closed readonly route and authenticated source profile differ")?;
        let mut expected = origin.original_info.clone();
        expected[64..72].copy_from_slice(&RO.to_le_bytes());
        need(
            self.info == expected,
            "BasicRO native info differs from authenticated original Basic+readonly",
        )?;
        validate_origin_layout(&origin, &self.binding, &expected, &self.baseline.partition)?;
        need(
            physical_read(&self.binding, 0, 512)? == origin.original_mbr,
            "BasicRO protective MBR differs from original authenticated source",
        )?;
        let closed = super::super::paged_recovery::authenticate_basic_ro_closed(
            &mut self, policy, journal, &pins, kind, observer, events,
        )?;
        let mut guard = PartitionTerminalRestorationGuard {
            file: None,
            data_profile:self.data_profile,
            physical_data:self.physical_data,
            physical: self.physical,
            binding: self.binding,
            budget: self.budget,
            baseline: self.baseline,
            token: self.token,
            origin,
            closed,
            policy,
            journal,
            pins,
            kind,
            stage: PartitionTerminalStage::Readonly,
            current_info: self.info,
            mounted_binding: self.mounted_binding,
            mounted: Some(self.volume),
        };
        guard.revalidate_metadata_checkpoint(
            observer,
            "basic-ro-terminal-origin-adopted",
            events,
        )?;
        guard.require_readonly(events)?;
        guard.revalidate_closed_checkpoint(observer, "basic-ro-terminal-closed-adopted", events)?;
        Ok(guard)
    }
}
