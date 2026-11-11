//! Actual selected-partition NTFS evidence. The only collector borrows an opaque
//! live Basic+READ_ONLY phase; saved reports/paths cannot recreate that phase.
use crate::{
    attestation::{
        NativeObservationDomain, NativeRequestDomain, Report, Request,
        validate_native_request_domain,
    },
    attestation_native::{AttestationRoute, Route},
    native::NativeEvent,
    native::partition_lifecycle::{PartitionPreparationToken, PartitionReadonlyPhase},
    observation_pages::{NativeObservationBudget, NativePageWriter, PagedNativeObservation},
};
use serde::Serialize;
use std::{fs::File, io, path::Path, sync::Arc};

// Query-only bridge to the same native collector implementation. Returned raw
// facts live in the explicit partition protection record; no event is invented.
fn control(
    file: &File,
    _label: &str,
    code: u32,
    input: &[u8],
    capacity: u32,
    _events: &mut Vec<NativeEvent>,
) -> io::Result<Vec<u8>> {
    if !input.is_empty() {
        return Err(io::Error::other(
            "partition attestation accepts query-only controls",
        ));
    }
    crate::attestation_native::control(file, code, capacity as usize)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartitionReadonlyRoute {
    pub volume_extents: Vec<u8>,
    pub ntfs_volume_data: Vec<u8>,
    pub readonly_partition_info: Vec<u8>,
    pub actual_physical_disk_attributes: Vec<u8>,
    pub physical_disk_is_writable_succeeded: bool,
    pub partition_write_protect_error: i32,
}

/// Owns real paged observations plus the actual preparation-token association.
/// No Deserialize, Clone, saved receipt or public constructor grants admission.
pub struct PartitionPagedNtfsObservation {
    domain: PagedNativeObservation,
    preparation: PartitionPreparationToken,
    before: PartitionReadonlyRoute,
    after: PartitionReadonlyRoute,
    txf: crate::txf_native::PartitionTxfObservation,
    vss_before: crate::vss_observation::Observation,
    vss_after: crate::vss_observation::Observation,
}
impl PartitionPagedNtfsObservation {
    /// Consuming terminal transfer of the actual retained native-page owner.
    /// This creates no new observation, source admission or reopened guard.
    pub(crate) fn into_terminal_domain(self) -> PagedNativeObservation {
        self.domain
    }
    pub fn domain(&self) -> &PagedNativeObservation {
        &self.domain
    }
    pub fn preparation_token(&self) -> &PartitionPreparationToken {
        &self.preparation
    }
    pub fn before(&self) -> &PartitionReadonlyRoute {
        &self.before
    }
    pub fn after(&self) -> &PartitionReadonlyRoute {
        &self.after
    }
    pub fn txf(&self) -> &crate::txf_native::PartitionTxfObservation {
        &self.txf
    }
    pub fn vss_before(&self) -> &crate::vss_observation::Observation {
        &self.vss_before
    }
    pub fn vss_after(&self) -> &crate::vss_observation::Observation {
        &self.vss_after
    }
    pub fn require_phase(
        &self,
        phase: &mut PartitionReadonlyPhase<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if !self.preparation.same_owner(&phase.preparation_token()) || self.before != self.after {
            return Err(io::Error::other(
                "partition native observation lost actual preparation owner/protection",
            ));
        }
        phase.revalidate(events)?;
        self.domain.revalidate()?;
        phase.require_original_vss_catalog_clear()?;
        self.vss_before.require_observed_snapshot_absence()?;
        self.vss_after.require_observed_snapshot_absence()?;
        self.txf.require_phase(phase, events)
    }
}
struct PartitionRouteCollector<'a, 'p> {
    phase: &'a mut PartitionReadonlyPhase<'p>,
    events: &'a mut Vec<NativeEvent>,
    before: Option<PartitionReadonlyRoute>,
    after: Option<PartitionReadonlyRoute>,
}
impl AttestationRoute for PartitionRouteCollector<'_, '_> {
    fn observe(&mut self, volume: &File, disk: &File, request: &Request) -> io::Result<Route> {
        self.phase.revalidate(self.events)?;
        let binding = self.phase.binding();
        if request.disk_number != binding.storage.disk_number
            || request.partition_offset != binding.storage.identity.partition_offset
            || request.partition_length != binding.storage.identity.partition_bytes
            || !request
                .volume
                .trim_end_matches('\\')
                .eq_ignore_ascii_case(binding.storage.volume_path()?.trim_end_matches('\\'))
        {
            return Err(io::Error::other(
                "native NTFS request differs from actual readonly partition phase",
            ));
        }
        let extents = control(
            volume,
            "partition-native-extents",
            0x0056_0000,
            &[],
            32,
            self.events,
        )?;
        binding.storage.validate_volume_extent(&extents)?;
        let ntfs = control(
            volume,
            "partition-native-ntfs-data",
            0x0009_0064,
            &[],
            128,
            self.events,
        )?;
        let info = control(
            volume,
            "partition-native-info",
            0x0007_0048,
            &[],
            144,
            self.events,
        )?;
        let attrs = control(
            disk,
            "partition-native-actual-disk-attributes",
            0x0007_00f0,
            &[],
            16,
            self.events,
        )?;
        let physical_writable = control(
            disk,
            "partition-native-actual-disk-writable",
            0x0007_0024,
            &[],
            0,
            self.events,
        )?;
        if !physical_writable.is_empty() {
            return Err(io::Error::other("unexpected physical writable response"));
        }
        let partition_error = match control(
            volume,
            "partition-native-write-protection",
            0x0007_0024,
            &[],
            0,
            self.events,
        ) {
            Ok(_) => {
                return Err(io::Error::other(
                    "selected readonly NTFS partition reports writable",
                ));
            }
            Err(error) => error.raw_os_error().ok_or(error)?,
        };
        let protection = self.phase.protection();
        let cluster = crate::layout::u32_at(&ntfs, 44)?;
        if partition_error != 19
            || protection.partition_write_protect_error != 19
            || extents != protection.volume_extents
            || info != protection.readonly_partition_info
            || ntfs != protection.ntfs_volume_data
            || ntfs.len() < 96
            || crate::layout::u64_at(&ntfs, 0)? != request.ntfs_serial
            || crate::layout::u32_at(&ntfs, 40)? != 512
            || !cluster.is_power_of_two()
            || !(4096..=2 * 1024 * 1024).contains(&cluster)
            || attrs.len() != 16
            || crate::layout::u32_at(&attrs, 0)? != 16
            || crate::layout::u64_at(&attrs, 8)? != 0
            || protection.physical_disk_attributes != 0
        {
            return Err(io::Error::other(
                "actual target readonly partition/GPT/NTFS/physical-state evidence differs",
            ));
        }
        self.phase.revalidate(self.events)?;
        let current = PartitionReadonlyRoute {
            volume_extents: extents.clone(),
            ntfs_volume_data: ntfs.clone(),
            readonly_partition_info: info,
            actual_physical_disk_attributes: attrs.clone(),
            physical_disk_is_writable_succeeded: true,
            partition_write_protect_error: partition_error,
        };
        if self.before.is_none() {
            self.before = Some(current);
        } else if self.after.is_none() {
            self.after = Some(current);
        } else {
            return Err(io::Error::other(
                "unexpected additional partition protection bracket",
            ));
        }
        // These fields remain ACTUAL PHYSICAL facts. Zero denotes successful
        // physical IOCTL_IS_WRITABLE; no fictitious disk attrs2/error19 exists.
        Ok((extents, ntfs, attrs, 0))
    }
}

pub fn collect_partition_ntfs_paged(
    phase: &mut PartitionReadonlyPhase<'_>,
    selectors: &impl NativeRequestDomain,
    path: &Path,
    budget: NativeObservationBudget,
    single_content_pass: bool,
    accountant: Arc<dyn crate::shadow_native::report_memory::ReportMemoryAccountant>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<PartitionPagedNtfsObservation> {
    phase.revalidate(events)?;
    let preparation = phase.preparation_token();
    let volume_guid = format!("{}\\", phase.binding().storage.volume_path()?);
    phase.require_original_vss_catalog_clear()?;
    let vss_before = crate::vss_observation::observe_snapshot_presence(&volume_guid)?;
    vss_before.require_observed_snapshot_absence()?;
    let txf = crate::txf_native::observe_partition(phase, events)?;
    let admission = selectors
        .header()
        .resource_profile
        .ok_or_else(|| {
            io::Error::other("partition native collection requires an explicit resource profile")
        })?
        .resource_admission()?
        .ok_or_else(|| {
            io::Error::other("partition native collection requires complete resource budget")
        })?;
    if budget != admission.native_observation_budget()? {
        return Err(io::Error::other(
            "partition native observation budget differs",
        ));
    }
    validate_native_request_domain(selectors)?;
    let memory =
        crate::observation_pages::memory::Memory::new(accountant, budget, selectors.len(), path)?;
    let mut sink =
        NativePageWriter::new(path, budget, selectors.header().resource_profile.unwrap())?;
    let mut routes = PartitionRouteCollector {
        phase,
        events,
        before: None,
        after: None,
    };
    let header: Report = crate::attestation_native::collect_file_metadata_with_routes(
        selectors.header(),
        selectors,
        single_content_pass,
        Some(&mut sink),
        &mut routes,
    )?;
    let before = routes
        .before
        .take()
        .ok_or_else(|| io::Error::other("opening readonly partition observation absent"))?;
    let after = routes
        .after
        .take()
        .ok_or_else(|| io::Error::other("closing readonly partition observation absent"))?;
    if before != after {
        return Err(io::Error::other(
            "readonly partition observation changed during native collection",
        ));
    }
    drop(routes);
    let receipt = sink.finish(&header)?;
    drop(header);
    let domain = PagedNativeObservation::open_with_memory(path, &receipt.sha256, budget, memory)?;
    let vss_after = crate::vss_observation::observe_snapshot_presence(&volume_guid)?;
    vss_after.require_observed_snapshot_absence()?;
    if !vss_before.same_source_and_provider_inventory(&vss_after) {
        return Err(io::Error::other(
            "VSS provider/source inventory changed during partition native collection",
        ));
    }
    let observed = PartitionPagedNtfsObservation {
        domain,
        preparation,
        before,
        after,
        txf,
        vss_before,
        vss_after,
    };
    observed.require_phase(phase, events)?;
    Ok(observed)
}
