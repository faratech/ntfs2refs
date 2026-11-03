//! Live authority to construct only the selected fresh native shadow.
//! A serialized observation cannot recreate this owning capability.
use super::*;

pub struct ConstructionEnrollment<'source> {
    pub(super) source: &'source native::GeneralFrozenPartition,
    pub(super) pair: GeneralSourceShadowBinding,
    pub(super) source_before: native::GeneralDiskState,
    pub(super) shadow_before: native::GeneralDiskState,
    pub(super) volume: File,
    pub(super) root: File,
    pub(super) root_id: Vec<u8>,
    pub(super) privileges: Privileges,
    pub(super) events: Vec<NativeEvent>,
}

/// The original observed source freeze is required. Reopening an excluded disk
/// or deserializing its report does not supply that witness. This capability
/// permits shadow construction only; source admission remains independent.
pub fn enroll<'source>(
    source: &'source native::GeneralFrozenPartition,
    pair: &GeneralSourceShadowBinding,
) -> io::Result<ConstructionEnrollment<'source>> {
    enroll_with_resource_profile(
        source,
        pair,
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    )
}
pub fn enroll_with_resource_profile<'source>(
    source: &'source native::GeneralFrozenPartition,
    pair: &GeneralSourceShadowBinding,
    profile: crate::attestation::ResourceProfile,
) -> io::Result<ConstructionEnrollment<'source>> {
    profile.resource_admission()?;
    pair.validate_with_resource_profile(Some(profile))?;
    if source.binding() != &pair.source || source.freeze_observation().is_none() {
        return Err(invalid(
            "construction enrollment requires the original observed source freeze",
        ));
    }
    let mut events = Vec::new();
    let source_before = source.state(&mut events)?;
    let shadow_before =
        native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
    if source_before.disk_attributes != 3 || shadow_before.disk_attributes != 0 {
        return Err(invalid(
            "construction enrollment requires excluded source and writable shadow",
        ));
    }
    let privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ])?;
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pair.shadow.volume_path()?)?;
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    check_mounted_profile(&volume, pair.shadow.identity.partition_bytes)?;
    let root = open(&format!("{}\\", pair.shadow.volume_path()?), true, true)?;
    validate_open_type(&root, true)?;
    let root_id = info(&root, 18, 24)?;
    let mut enrollment = ConstructionEnrollment {
        source,
        pair: pair.clone(),
        source_before,
        shadow_before,
        volume,
        root,
        root_id,
        privileges,
        events,
    };
    enrollment.revalidate()?;
    Ok(enrollment)
}

impl ConstructionEnrollment<'_> {
    pub(super) fn revalidate(&mut self) -> io::Result<()> {
        if self.source.freeze_observation().is_none()
            || self.source.binding() != &self.pair.source
            || self.source.state(&mut self.events)? != self.source_before
            || native::observe_general_disk_state_readonly(
                self.pair.shadow.clone(),
                &mut self.events,
            )? != self.shadow_before
            || info(&self.root, 18, 24)? != self.root_id
        {
            return Err(invalid(
                "live construction enrollment identity or exclusion changed",
            ));
        }
        self.pair
            .shadow
            .validate_volume_extent(&ctl(&self.volume, 0x00560000, &[], 1024)?)?;
        check_mounted_profile(&self.volume, self.pair.shadow.identity.partition_bytes)?;
        Ok(())
    }

    pub(super) fn observation(&self) -> serde_json::Value {
        serde_json::json!({
            "kind":"live-native-shadow-construction-enrollment",
            "pair":self.pair,"source_before":self.source_before,"shadow_before":self.shadow_before,
            "root_file_id_info":self.root_id,"original_observed_source_freeze":true,
            "refs_major":3,"refs_minor":14,"cluster_bytes":4096,"sector_bytes":512,
            "retrieval_base_sectors":0,"source_write_authority":false,
            "serialized_observation_is_not_authority":true,"events":self.events,
        })
    }
}

fn check_mounted_profile(volume: &File, partition_bytes: u64) -> io::Result<()> {
    query_refs_314_volume_data(volume, partition_bytes)?;
    let base = ctl(volume, stream_layout::GET_BASE, &[], 8)?;
    if base.len() != 8 || layout::u64_at(&base, 0)? != 0 {
        return Err(invalid("construction shadow retrieval base differs"));
    }
    let mut filesystem = [0u16; 32];
    let mut label = [0u16; 128];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    // SAFETY: the bound live volume and initialized, bounded output buffers
    // remain valid for this synchronous native query.
    if unsafe {
        GetVolumeInformationByHandleW(
            volume.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let decode = |value: &[u16]| -> io::Result<String> {
        let end = value
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| invalid("unterminated shadow volume property"))?;
        String::from_utf16(&value[..end]).map_err(|_| invalid("invalid shadow volume property"))
    };
    if decode(&filesystem)? != "ReFS"
        || decode(&label)? != "n2r-retained-shadow"
        || flags & 0x80000 != 0
    {
        return Err(invalid(
            "fresh construction requires the prepared writable ReFS shadow label/profile",
        ));
    }
    Ok(())
}
