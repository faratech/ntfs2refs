//! Actual offline-owner 3->2->3 NTFS observation. No fabricated General state.
use super::*;
use crate::{
    attestation::{NativeObservationDomain, NativeRequestDomain},
    general_layout::GeneralDiskBinding,
    observation_pages::{NativeObservationBudget, PagedNativeObservation},
    shadow_native::report_memory::ReportMemoryAccountant,
};
use sha2::Digest;
use std::{path::Path, sync::Arc};
fn digest_json<T: serde::Serialize>(v: &T) -> io::Result<String> {
    Ok(hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(v).map_err(io::Error::other)?,
    )))
}

/// Private actual origin capability; no Clone/Deserialize/data constructor.
pub struct OfflineFreshWitness {
    origin: Arc<()>,
    binding: PartitionSourceBinding,
    boot_fingerprint: String,
    kernel_fingerprint: String,
    before: OfflineSourcePhysicalFacts,
    after: OfflineSourcePhysicalFacts,
    mounted_binding: GeneralDiskBinding,
    original_label: crate::volume_label::VolumeLabel,
    mount_paths: crate::native::MountPathObservation,
    txf: Option<crate::txf_native::Observation>,
    txf_error: Option<String>,
    vss_catalog: Option<crate::vss_observation::Observation>,
    vss_error: Option<String>,
}
impl OfflineFreshWitness {
    /// Actual pre-lock NTFS label, not a GeneralProbe/SourceLabel projection.
    pub fn original_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.original_label
    }
    pub fn mount_paths(&self) -> &crate::native::MountPathObservation {
        &self.mount_paths
    }
    pub fn mounted_binding(&self) -> &GeneralDiskBinding {
        &self.mounted_binding
    }
    pub fn before_freeze_txf(&self) -> Option<&crate::txf_native::Observation> {
        self.txf.as_ref()
    }
    pub fn before_freeze_txf_error(&self) -> Option<&str> {
        self.txf_error.as_deref()
    }
    pub fn vss_catalog(&self) -> Option<&crate::vss_observation::Observation> {
        self.vss_catalog.as_ref()
    }
    pub fn vss_error(&self) -> Option<&str> {
        self.vss_error.as_deref()
    }
    pub fn actual_kernel_fingerprint(&self) -> &str {
        &self.kernel_fingerprint
    }
    fn require_idle(&self) -> io::Result<()> {
        let t = self
            .txf
            .as_ref()
            .ok_or_else(|| invalid("actual before-lock offline TxF observation unavailable"))?;
        require(
            t.native_volume_state_stably_clear
                && matches!(
                    t.default_rm_state(),
                    crate::txf_native::DefaultRmState::QueriedEmpty
                        | crate::txf_native::DefaultRmState::Inactive
                ),
            "actual before-lock offline TxF is dirty/active/unknown",
        )?;
        self.vss_catalog
            .as_ref()
            .ok_or_else(|| invalid("actual before-lock VSS catalog unavailable"))?
            .require_observed_catalog_clear()
    }
    pub fn require_environment(
        &self,
        env: &mut OfflineOwningEnvironment,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        require(
            self.binding == env.source
                && self.boot_fingerprint == digest_json(&env.facts.boot)?
                && self.kernel_fingerprint == digest_json(&env.facts.kernel_image)?,
            "actual fresh witness belongs to another source/boot/kernel",
        )?;
        let current = source_facts(&mut env.physical, &env.source, env.budget, events)?;
        require(
            current.disk_attributes & !3 == 0,
            "unknown source disk attributes",
        )?;
        env.require_current_at_attributes(current.disk_attributes, events)?;
        let mut original = self.before.clone();
        original.disk_attributes = current.disk_attributes;
        require(
            self.before == self.after && current == original,
            "before-lock source physical/native identity changed",
        )?;
        self.require_idle()
    }
}

/// Opaque native phase. Only this module can create it after an actual env/
/// physical state proof. It exposes no Write/Seek/raw handle/path constructor.
pub struct OfflineReadonlyNtfsPhase<'a> {
    env: &'a mut OfflineOwningEnvironment,
    volume: File,
    mounted: GeneralDiskBinding,
    expected_attributes: u64,
    sink: PartitionNativeEventSink,
}
impl OfflineReadonlyNtfsPhase<'_> {
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.mounted
    }
    pub(crate) fn duplicate_volume(&self) -> io::Result<File> {
        self.volume.try_clone()
    }
    pub(crate) fn expected_attributes(&self) -> u64 {
        self.expected_attributes
    }
    pub(crate) fn require_current(
        &mut self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<OfflineSourcePhysicalFacts> {
        checkpoint(&self.sink, "offline-NTFS-phase-current-opening", events)?;
        self.env
            .require_current_at_attributes(self.expected_attributes, events)?;
        let actual = source_facts(
            &mut self.env.physical,
            &self.env.source,
            self.env.budget,
            events,
        )?;
        require(
            actual.disk_attributes == self.expected_attributes,
            "offline NTFS phase lost actual disk attributes",
        )?;
        let ext = control(
            &self.volume,
            "offline-ntfs-phase-native-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        self.mounted.validate_volume_extent(&ext)?;
        let info = control(
            &self.volume,
            "offline-ntfs-phase-native-partition",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        let guid = layout::guid_bytes(&self.env.source.storage.identity.partition_guid)?;
        let rows: Vec<_> = actual.gpt.native_layout[48..]
            .chunks_exact(144)
            .filter(|r| r[48..64] == guid)
            .collect();
        require(
            rows.len() == 1 && info.as_slice() == rows[0],
            "actual readonly NTFS volume differs from full source GPT",
        )?;
        if self.expected_attributes == 2 {
            match control(
                &self.volume,
                "offline-ntfs-phase-actual-WRITE_PROTECT19",
                0x0007_0024,
                &[],
                0,
                events,
            ) {
                Err(e) if e.raw_os_error() == Some(19) => (),
                Err(e) => return Err(e),
                Ok(_) => return Err(invalid("readonly NTFS phase reports writable")),
            }
        }
        checkpoint(&self.sink, "offline-NTFS-phase-current-closed", events)?;
        Ok(actual)
    }
}
fn mounted_binding(
    env: &mut OfflineOwningEnvironment,
    sink: &PartitionNativeEventSink,
    events: &mut Vec<NativeEvent>,
) -> io::Result<GeneralDiskBinding> {
    let names = catalog_names((env.budget.ram_bytes / 4096).min(4096))?;
    let mut found = None;
    let guid = layout::guid_bytes(&env.source.storage.identity.partition_guid)?;
    for name in &names {
        if unsafe { GetDriveTypeW(wide(name).as_ptr()) } == 6 {
            continue;
        }
        let query = match OpenOptions::new()
            .access_mode(0x0010_0080)
            .share_mode(3)
            .open(name.trim_end_matches('\\'))
        {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 21 | 1167)) => continue,
            Err(e) => return Err(e),
        };
        let dev = control(
            &query,
            "offline-ntfs-volume-lookup-metadata-device",
            DEVICE,
            &[],
            12,
            events,
        )?;
        if dev.len() == 12
            && layout::u32_at(&dev, 0)? == 7
            && layout::u32_at(&dev, 4)? == env.source.storage.disk_number
        {
            let info = control(
                &query,
                "offline-ntfs-volume-lookup-native-info",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            if info.len() == 144 && info[48..64] == guid {
                let ext = control(
                    &query,
                    "offline-ntfs-volume-lookup-native-extents",
                    VOLUME_EXTENTS,
                    &[],
                    32,
                    events,
                )?;
                let mut binding = env.source.storage.clone();
                binding.volume_guid = name[11..47].to_owned();
                binding.validate_volume_extent(&ext)?;
                require(found.is_none(), "multiple actual source NTFS GUID routes")?;
                found = Some(binding);
            }
        }
        close_file(query, "offline-ntfs-volume-lookup-metadata-close", events)?;
        checkpoint(sink, "offline-NTFS-volume-lookup-row", events)?;
    }
    require(
        catalog_names((env.budget.ram_bytes / 4096).min(4096))? == names,
        "actual volume GUID catalog changed during source lookup",
    )?;
    found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, OfflineNtfsNotPublished))
}
#[derive(Debug)]
struct OfflineNtfsNotPublished;
impl std::fmt::Display for OfflineNtfsNotPublished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual NTFS source not published yet")
    }
}
impl std::error::Error for OfflineNtfsNotPublished {}
fn open_phase<'a>(
    env: &'a mut OfflineOwningEnvironment,
    expected: u64,
    sink: &PartitionNativeEventSink,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineReadonlyNtfsPhase<'a>> {
    for attempt in 0..if expected == 2 { 60 } else { 1 } {
        checkpoint(sink, "offline-NTFS-publication-attempt-opening", events)?;
        env.require_current_at_attributes(expected, events)?;
        let candidate = mounted_binding(env, sink, events);
        checkpoint(sink, "offline-NTFS-publication-metadata-complete", events)?;
        match candidate {
            Ok(mounted) => match device_file(&mounted.volume_path()?, false, false) {
                Ok(volume) => {
                    let mut phase = OfflineReadonlyNtfsPhase {
                        env,
                        volume,
                        mounted,
                        expected_attributes: expected,
                        sink: sink.clone(),
                    };
                    phase.require_current(events)?;
                    return Ok(phase);
                }
                Err(e) if expected == 2 && matches!(e.raw_os_error(), Some(2 | 3 | 21 | 1167)) => {
                    ()
                }
                Err(e) => return Err(e),
            },
            Err(e)
                if expected == 2
                    && e.get_ref()
                        .is_some_and(|v| v.is::<OfflineNtfsNotPublished>()) =>
            {
                ()
            }
            Err(e) => return Err(e),
        }
        if attempt < 59 {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    Err(invalid(
        "actual readonly NTFS source was not published within bounded metadata wait",
    ))
}

fn actual_phase_label(
    phase: &mut OfflineReadonlyNtfsPhase<'_>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<crate::volume_label::VolumeLabel> {
    phase.require_current(events)?;
    let mut label = [0u16; 261];
    let mut filesystem = [0u16; 32];
    let mut serial = 0;
    let mut component = 0;
    let mut flags = 0;
    // SAFETY: actual retained phase volume FileObject, initialized bounded
    // output arrays/scalars, synchronous query. No label/path setter exists.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW(
            std::os::windows::io::AsRawHandle::as_raw_handle(&phase.volume),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } != 0;
    let error = (!ok).then(io::Error::last_os_error);
    require(
        events.len() < crate::MAX_BATCH_EVENTS,
        "actual label event workspace exhausted",
    )?;
    events.push(NativeEvent {
        operation: "offline-before-lock-native-volume-label".into(),
        control_code: 0,
        input: Vec::new(),
        succeeded: ok,
        native_error: error.as_ref().and_then(io::Error::raw_os_error),
        output: if ok {
            serde_json::to_vec(&(
                label.as_slice(),
                filesystem.as_slice(),
                serial,
                component,
                flags,
            ))
            .map_err(io::Error::other)?
        } else {
            Vec::new()
        },
    });
    if let Some(error) = error {
        return Err(error);
    }
    let n = label
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| invalid("actual NTFS label unterminated"))?;
    let fs = filesystem
        .iter()
        .position(|u| *u == 0)
        .ok_or_else(|| invalid("actual NTFS filesystem name unterminated"))?;
    require(
        &filesystem[..fs] == [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16],
        "pre-lock label does not belong to actual NTFS phase",
    )?;
    let value = crate::volume_label::VolumeLabel::from_utf16(label[..n].to_vec())?;
    phase.require_current(events)?;
    Ok(value)
}

/// Called BEFORE all real source-volume locks/freeze by the holder constructor.
/// Unknown results remain explicit and cannot pass require_environment/admission.
pub(super) fn capture_offline_fresh_witness(
    env: &mut OfflineOwningEnvironment,
    sink: &PartitionNativeEventSink,
    events: &mut Vec<NativeEvent>,
) -> io::Result<OfflineFreshWitness> {
    checkpoint(sink, "offline-before-lock-witness-opening", events)?;
    env.require_current(events)?;
    let before = env.facts.source_physical.clone();
    checkpoint(sink, "offline-before-lock-environment", events)?;
    require(
        before.disk_attributes == 0,
        "fresh offline native witness requires original online/RW source metadata",
    )?;
    let binding = env.source.clone();
    let boot_fingerprint = digest_json(&env.facts.boot)?;
    let kernel_fingerprint = digest_json(&env.facts.kernel_image)?;
    let mut phase = open_phase(env, 0, sink, events)?;
    let mounted_binding = phase.binding().clone();
    let original_label = actual_phase_label(&mut phase, events)?;
    let mount_paths = crate::native::capture_mount_paths_for_bound_volume(mounted_binding.clone())?;
    require(
        mount_paths.all_paths_resolve_to_bound_volume,
        "actual pre-lock mount paths do not all resolve to bound source",
    )?;
    phase.require_current(events)?;
    let txf_result = crate::txf_native::observe_offline_bound_phase(&mut phase, events);
    let (txf, txf_error) = match txf_result {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let vss_result =
        crate::vss_observation::observe_catalog(&format!("{}\\", phase.binding().volume_path()?));
    let (vss_catalog, vss_error) = match vss_result {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    };
    require(
        actual_phase_label(&mut phase, events)? == original_label,
        "actual pre-lock NTFS label changed across native observation",
    )?;
    let paths_after = crate::native::capture_mount_paths_for_bound_volume(mounted_binding.clone())?;
    require(
        paths_after.binding == mount_paths.binding
            && paths_after.paths == mount_paths.paths
            && paths_after.all_paths_resolve_to_bound_volume,
        "actual pre-lock NTFS mount paths changed across native observation",
    )?;
    let after = phase.require_current(events)?;
    close_file(
        phase.volume,
        "offline-before-lock-NTFS-volume-close",
        events,
    )?;
    require(
        before == after,
        "source changed during actual pre-lock NTFS witness",
    )?;
    checkpoint(sink, "offline-before-lock-witness-complete", events)?;
    Ok(OfflineFreshWitness {
        origin: Arc::new(()),
        binding,
        boot_fingerprint,
        kernel_fingerprint,
        before,
        after,
        mounted_binding,
        original_label,
        mount_paths,
        txf,
        txf_error,
        vss_catalog,
        vss_error,
    })
}

struct ReadonlyLease<'a> {
    core: &'a mut Core,
    management: File,
    events: &'a mut Vec<NativeEvent>,
    restore_attempted: bool,
    entered: bool,
}
impl ReadonlyLease<'_> {
    fn enter(&mut self) -> io::Result<()> {
        self.core
            .env
            .require_current_at_attributes(3, self.events)?;
        let actual = source_facts(
            &mut self.management,
            &self.core.env.source,
            self.core.env.budget,
            self.events,
        )?;
        let mut expected = self.core.env.facts.source_physical.clone();
        expected.disk_attributes = 3;
        require(
            actual == expected,
            "actual offline readonly management handle binding differs",
        )?;
        self.entered = true; // setter may change state even on an error; Drop restores3.
        set_attributes(&self.management, 2, self.events)?;
        require(
            control(
                &self.management,
                "offline-native-readonly-refresh-properties",
                crate::native::UPDATE_PROPERTIES,
                &[],
                0,
                self.events,
            )?
            .is_empty(),
            "readonly refresh returned bytes",
        )?;
        self.core
            .env
            .require_current_at_attributes(2, self.events)?;
        self.core.expected_attributes = 2;
        checkpoint(
            &self.core.sink,
            "offline-native-readonly-actual2",
            self.events,
        )
    }
    fn finish(&mut self) -> io::Result<()> {
        self.restore_attempted = true;
        let result = (|| {
            set_attributes(&self.management, 3, self.events)?;
            require(
                control(
                    &self.management,
                    "offline-native-restore3-refresh-properties",
                    crate::native::UPDATE_PROPERTIES,
                    &[],
                    0,
                    self.events,
                )?
                .is_empty(),
                "restore refresh returned bytes",
            )?;
            self.core
                .env
                .require_current_at_attributes(3, self.events)?;
            self.core.expected_attributes = 3;
            Ok(())
        })();
        if result.is_err() {
            self.core.poisoned = true;
        }
        let closed = checkpoint(
            &self.core.sink,
            "offline-native-actual3-restored",
            self.events,
        );
        match (result, closed) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), _) | (_, Err(e)) => {
                self.core.poisoned = true;
                Err(e)
            }
        }
    }
}
impl Drop for ReadonlyLease<'_> {
    fn drop(&mut self) {
        if self.entered && !self.restore_attempted {
            if self.finish().is_err() {
                self.core.poisoned = true;
            }
        }
    }
}

pub struct OfflinePagedNtfsObservation {
    owner: OfflineSourceOwnerToken,
    origin: Arc<()>,
    binding: PartitionSourceBinding,
    mounted_binding: GeneralDiskBinding,
    domain: PagedNativeObservation,
    before: OfflineSourceState,
    readonly_before: OfflineSourceState,
    readonly_after: OfflineSourceState,
    after: OfflineSourceState,
    txf: Option<crate::txf_native::Observation>,
    txf_error: Option<String>,
    vss_before: Option<crate::vss_observation::Observation>,
    vss_before_error: Option<String>,
    vss_after: Option<crate::vss_observation::Observation>,
    vss_after_error: Option<String>,
    prefreeze_clear: bool,
}
impl OfflinePagedNtfsObservation {
    pub fn domain(&self) -> &PagedNativeObservation {
        &self.domain
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub fn mounted_binding(&self) -> &GeneralDiskBinding {
        &self.mounted_binding
    }
    pub fn before(&self) -> &OfflineSourceState {
        &self.before
    }
    pub fn after(&self) -> &OfflineSourceState {
        &self.after
    }
    pub fn readonly_before(&self) -> &OfflineSourceState {
        &self.readonly_before
    }
    pub fn readonly_after(&self) -> &OfflineSourceState {
        &self.readonly_after
    }
    pub fn txf(&self) -> Option<&crate::txf_native::Observation> {
        self.txf.as_ref()
    }
    pub fn txf_error(&self) -> Option<&str> {
        self.txf_error.as_deref()
    }
    pub fn vss_before_error(&self) -> Option<&str> {
        self.vss_before_error.as_deref()
    }
    pub fn vss_after_error(&self) -> Option<&str> {
        self.vss_after_error.as_deref()
    }
    pub fn vss_before(&self) -> Option<&crate::vss_observation::Observation> {
        self.vss_before.as_ref()
    }
    pub fn vss_after(&self) -> Option<&crate::vss_observation::Observation> {
        self.vss_after.as_ref()
    }
    pub fn require_owner(&self, t: &OfflineSourceOwnerToken) -> io::Result<()> {
        require(
            self.owner.same_owner(t),
            "offline native pages belong to another actual source owner",
        )
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.domain.revalidate()?;
        let request = &self.domain.header().request;
        require(
            request.disk_number == self.binding.storage.disk_number
                && request.partition_offset == self.binding.storage.identity.partition_offset
                && request.partition_length == self.binding.storage.identity.partition_bytes
                && request.volume == format!("{}\\", self.mounted_binding.volume_path()?)
                && !self.domain.header().conversion_qualified,
            "native domain actual mounted binding/profile differs",
        )?;
        require(
            self.before.binding == self.binding
                && self.after.binding == self.binding
                && self.before.actual == self.after.actual
                && self.before.actual.disk_attributes == 3
                && self.readonly_before.actual.disk_attributes == 2
                && self.readonly_after.actual.disk_attributes == 2
                && self.readonly_before.actual == self.readonly_after.actual,
            "offline native actual3/2/3 metadata bookends differ",
        )
    }
    pub fn require_admission_evidence(&self) -> io::Result<()> {
        self.revalidate()?;
        require(
            self.prefreeze_clear,
            "actual pre-lock TxF/VSS evidence missing/active/unknown",
        )?;
        let t = self
            .txf
            .as_ref()
            .ok_or_else(|| invalid("actual readonly offline TxF unknown"))?;
        require(
            t.native_volume_state_stably_clear
                && t.default_rm_state() == crate::txf_native::DefaultRmState::Inactive,
            "actual readonly offline TxF didnotproveInactive",
        )?;
        let a = self
            .vss_before
            .as_ref()
            .ok_or_else(|| invalid("actual readonly VSS before unknown"))?;
        let b = self
            .vss_after
            .as_ref()
            .ok_or_else(|| invalid("actual readonly VSS after unknown"))?;
        a.require_observed_snapshot_absence()?;
        b.require_observed_snapshot_absence()?;
        require(
            a.same_source_and_provider_inventory(b),
            "actual readonly VSS inventory changed",
        )
    }
}
impl OfflineFrozenSource {
    /// Builds selectors only AFTER native actual mounted GUID is observed. The
    /// returned wrapper retains actual3/2/3 owner scope, never General state.
    pub fn observe_ntfs_paged_with_memory<D: NativeRequestDomain>(
        &mut self,
        path: &Path,
        budget: NativeObservationBudget,
        single_content_pass: bool,
        require_vss: bool,
        accountant: Arc<dyn ReportMemoryAccountant>,
        events: &mut Vec<NativeEvent>,
        selectors: impl FnOnce(&GeneralDiskBinding) -> io::Result<D>,
    ) -> io::Result<OfflinePagedNtfsObservation> {
        require(
            self.core.fresh
                && !self.core.poisoned
                && self.core.expected_attributes == 3
                && !self.core.gate_ever_issued
                && !self.core.writer_ever_issued,
            "fresh unactivated actualoffline owner required for nativeRO capture",
        )?;
        let before = self.core.state(events)?;
        let token = self.core.token.clone();
        let binding = self.core.env.source.clone();
        let witness = self
            .core
            .fresh_witness
            .as_ref()
            .ok_or_else(|| invalid("actual before-lock offline witness absent"))?;
        let origin = witness.origin.clone();
        let prefreeze_clear = witness.require_idle().is_ok();
        let management = device_file(
            &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
            true,
            false,
        )?;
        let mut lease = ReadonlyLease {
            core: &mut self.core,
            management,
            events,
            restore_attempted: false,
            entered: false,
        };
        let operation: io::Result<_> = (|| {
            lease.enter()?;
            let readonly_before = lease.core.state(lease.events)?;
            let mut phase = open_phase(&mut lease.core.env, 2, &lease.core.sink, lease.events)?;
            let mounted_binding = phase.binding().clone();
            let requests = selectors(&mounted_binding)?;
            let request = requests.header();
            request.validate()?;
            require(
                request.disk_number == binding.storage.disk_number
                    && request.partition_offset == binding.storage.identity.partition_offset
                    && request.partition_length == binding.storage.identity.partition_bytes
                    && request.volume == format!("{}\\", mounted_binding.volume_path()?),
                "native request doesnotmatchactualofflineRO binding",
            )?;
            let vss_pre = if require_vss {
                Some(crate::vss_observation::observe_snapshot_presence(
                    &request.volume,
                ))
            } else {
                None
            };
            phase.require_current(lease.events)?;
            let domain = crate::attestation_native::collect_file_metadata_paged_domain_with_memory(
                &requests,
                path,
                budget,
                single_content_pass,
                accountant,
            )?;
            let txf_result =
                crate::txf_native::observe_offline_bound_phase(&mut phase, lease.events);
            let vss_post = if require_vss {
                Some(crate::vss_observation::observe_snapshot_presence(
                    &request.volume,
                ))
            } else {
                None
            };
            phase.require_current(lease.events)?;
            close_file(
                phase.volume,
                "offline-native-readonly-volume-close-before-restore3",
                lease.events,
            )?;
            let readonly_after = lease.core.state(lease.events)?;
            Ok((
                domain,
                mounted_binding,
                readonly_before,
                readonly_after,
                txf_result,
                vss_pre,
                vss_post,
            ))
        })();
        let restored = lease.finish();
        drop(lease);
        restored?;
        let after = self.core.state(events)?;
        let (
            domain,
            mounted_binding,
            readonly_before,
            readonly_after,
            txf_result,
            vss_pre,
            vss_post,
        ) = operation?;
        let (txf, txf_error) = match txf_result {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let (vss_before, vss_before_error) = match vss_pre {
            Some(Ok(v)) => (Some(v), None),
            Some(Err(e)) => (None, Some(e.to_string())),
            None => (None, Some("notrequested; NOT clear evidence".into())),
        };
        let (vss_after, vss_after_error) = match vss_post {
            Some(Ok(v)) => (Some(v), None),
            Some(Err(e)) => (None, Some(e.to_string())),
            None => (None, Some("notrequested; NOT clear evidence".into())),
        };
        let observed = OfflinePagedNtfsObservation {
            owner: token,
            origin,
            binding,
            mounted_binding,
            domain,
            before,
            readonly_before,
            readonly_after,
            after,
            txf,
            txf_error,
            vss_before,
            vss_before_error,
            vss_after,
            vss_after_error,
            prefreeze_clear,
        };
        observed.revalidate()?;
        Ok(observed)
    }
}

impl NativeObservationDomain for OfflinePagedNtfsObservation {
    fn header(&self) -> &crate::attestation::Report {
        self.domain.header()
    }
    fn len(&self) -> usize {
        self.domain.len()
    }
    fn logical_len(&self) -> usize {
        self.domain.logical_len()
    }
    fn namespace_len(&self) -> usize {
        self.domain.namespace_len()
    }
    fn observation(
        &self,
        i: usize,
    ) -> io::Result<std::borrow::Cow<'_, crate::attestation::Observation>> {
        self.domain.observation(i)
    }
    fn logical_file(
        &self,
        i: usize,
    ) -> io::Result<std::borrow::Cow<'_, crate::attestation::LogicalFile>> {
        self.domain.logical_file(i)
    }
    fn namespace_file(
        &self,
        i: usize,
    ) -> io::Result<std::borrow::Cow<'_, crate::attestation::NamespaceFile>> {
        self.domain.namespace_file(i)
    }
    fn row_view(&self, i: usize) -> io::Result<crate::attestation::NativeObservationRow<'_>> {
        self.domain.row_view(i)
    }
    fn request_row(
        &self,
        i: usize,
    ) -> io::Result<std::borrow::Cow<'_, crate::attestation::NativeRequestRow>> {
        self.domain.request_row(i)
    }
    fn request_len(&self) -> io::Result<usize> {
        self.domain.request_len()
    }
    fn revalidate(&self) -> io::Result<()> {
        OfflinePagedNtfsObservation::revalidate(self)
    }
    fn validate_encoded_size(&self, n: usize) -> io::Result<()> {
        self.domain.validate_encoded_size(n)
    }
    fn maximum_security_descriptor_bytes(&self) -> usize {
        self.domain.maximum_security_descriptor_bytes()
    }
    fn is_paged(&self) -> bool {
        true
    }
}
