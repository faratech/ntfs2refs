//! Allocation-only user namespace on an independently bound fresh ReFS shadow.
//! The files stay SYSTEM-only and contain no admitted payload yet. A live tree
//! exposes placement operations, never source writes or conversion authority.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub struct PrivateTree {
    // Files close before the volume and privilege lease on drop. No drop path
    // restores public permissions over uninitialized scratch contents.
    files: BTreeMap<usize, unwritten::PrivatePlaceholder>,
    volume: File,
    pair: GeneralSourceShadowBinding,
    source_before: native::GeneralDiskState,
    initial_objects: Vec<serde_json::Value>,
    events: Vec<NativeEvent>,
    privileges: Privileges,
}

impl PrivateTree {
    /// Apply one placement through the private constructor's state machine.
    pub fn place(
        &mut self,
        object_index: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        let file = self
            .files
            .get_mut(&object_index)
            .ok_or_else(|| invalid("private user file absent"))?;
        let result = serde_json::to_value(file.place(&self.volume, vcn, lcn, clusters)?)
            .map_err(io::Error::other)?;
        self.require_source_excluded()?;
        Ok(result)
    }

    /// All prefix clusters must already be placed. This never restores ACLs
    /// or claims that the scratch file contains the original logical bytes.
    pub fn advance_placed_prefix(&mut self, object_index: usize, bytes: u64) -> io::Result<()> {
        self.require_source_excluded()?;
        self.files
            .get_mut(&object_index)
            .ok_or_else(|| invalid("private user file absent"))?
            .advance_valid_data(bytes, true)?;
        self.require_source_excluded()
    }

    /// Materialize a small/resident stream or tail after its retained prefix
    /// is valid. The caller supplies bytes from its checked source reader.
    pub fn materialize_range(
        &mut self,
        object_index: usize,
        components: &[String],
        logical_length: u64,
        offset: u64,
        bytes: &[u8],
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        let expected_path = format!(
            "{}\\{}",
            self.pair.shadow.volume_path()?,
            components.join("\\")
        );
        let file = self
            .files
            .get_mut(&object_index)
            .ok_or_else(|| invalid("private materialization file absent"))?;
        if file.path != expected_path || file.logical_length() != logical_length {
            return Err(invalid("private materialization object binding differs"));
        }
        let proof = file.initialize_at(offset, bytes)?;
        self.require_source_excluded()?;
        Ok(proof)
    }

    pub fn source_binding(&self) -> &GeneralDiskBinding {
        &self.pair.source
    }

    fn require_source_excluded(&self) -> io::Result<()> {
        let mut events = Vec::new();
        if native::observe_general_disk_state_readonly(self.pair.source.clone(), &mut events)?
            != self.source_before
            || native::observe_general_disk_state_readonly(self.pair.shadow.clone(), &mut events)?
                .disk_attributes
                != 0
        {
            return Err(invalid(
                "private tree source exclusion or shadow state changed",
            ));
        }
        Ok(())
    }

    /// Snapshot only metadata and mappings. No placeholder payload is read.
    pub fn report(&self) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        let mut files = Vec::with_capacity(self.files.len());
        for (&index, file) in &self.files {
            let mut row = file_observation(index, &file.path, file.metadata_handle())?;
            row["materialized_bytes"] = file.materialized_bytes().into();
            row["readback_bytes"] = file.readback_bytes().into();
            row["valid_prefix_bytes"] = file.valid_prefix().into();
            files.push(row);
        }
        let readback_bytes = self.files.values().try_fold(0u64, |n, f| {
            n.checked_add(f.readback_bytes())
                .ok_or_else(|| invalid("private readback total overflow"))
        })?;
        let materialized_bytes = self.files.values().try_fold(0u64, |n, f| {
            n.checked_add(f.materialized_bytes())
                .ok_or_else(|| invalid("private materialization total overflow"))
        })?;
        self.require_source_excluded()?;
        Ok(
            serde_json::json!({"schema_version":1,"kind":"native-private-tree-allocation-template",
            "pair":self.pair,"source_before":self.source_before,"objects":self.initial_objects,
            "files":files,"events":self.events,"privileges":self.privileges.audit(),
            "user_payload_bytes_read":readback_bytes,
            "user_payload_bytes_written":materialized_bytes,
            "formatter_preflight_may_read_cache":true,"source_payload_writes":0,
            "security_timestamps_attributes_pending":true,"system_objects_pending":true,
            "physical_payload_io_measured":false,"conversion_qualified":false}),
        )
    }
}

fn file_observation(index: usize, path: &str, file: &File) -> io::Result<serde_json::Value> {
    let standard = info(file, 1, 24)?;
    let logical = layout::u64_at(&standard, 8)?;
    let allocated = layout::u64_at(&standard, 0)?;
    if layout::u32_at(&standard, 16)? != 1 || standard[20] != 0 || standard[21] != 0 {
        return Err(invalid("private file type, deletion or link count differs"));
    }
    // Empty and subcluster allocations have no promised nonresident retrieval
    // map. They will be materialized, rather than admitted as retained runs.
    let capture = if logical == 0 || (logical < 4096 && allocated < 4096) {
        None
    } else {
        Some(
            crate::stream_native::retrieval_capture(file)
                .map_err(|e| io::Error::new(e.kind(), format!("private mapping {path}: {e}")))?,
        )
    };
    Ok(
        serde_json::json!({"object_index":index,"path":path,"logical_length":logical,
        "allocated_length":allocated,"snapshot":snapshot(file),
        "data_form":if logical==0 {"empty"}else if capture.is_none(){"subcluster-allocation"}else{"nonresident"},
        "retrieval":capture.as_ref().map(|c| &c.canonical),
        "retrieval_page_proof":capture.as_ref().map(|c| &c.proof),
        "source_security_restoration_pending":true,"logical_content_verification_pending":true}),
    )
}

/// Metadata-only recovery observation after a constructor/report refusal.
/// Existing files are never recreated, resized, initialized or deleted.
pub fn observe_existing(
    pair: &GeneralSourceShadowBinding,
    input: &[Input<'_>],
) -> io::Result<serde_json::Value> {
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || input.is_empty()
        || input.len() > 1280
        || !input[0].directory
        || !input[0].components.is_empty()
    {
        return Err(invalid("enrolled private tree observation required"));
    }
    for item in input {
        if item.components.len() > 16
            || item
                .components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
        {
            return Err(invalid("private observation path differs"));
        }
    }
    let mut events = Vec::new();
    let before = native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    let target_before =
        native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?;
    if before.disk_attributes != 3
        || target_before.disk_attributes != 0
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid("private observation disk state differs"));
    }
    let mut privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
    let root = format!("{}\\", pair.shadow.volume_path()?);
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, item) in input.iter().enumerate() {
        if item
            .components
            .first()
            .is_some_and(|s| s == "System Volume Information")
        {
            continue;
        }
        let path = format!("{root}{}", item.components.join("\\"));
        let file = open(&path, item.directory, false)?;
        if item.directory {
            let entries = enumerate(&file)?;
            let actual: BTreeSet<_> = entries
                .iter()
                .filter(|e| e.name_utf16 != [46] && e.name_utf16 != [46, 46])
                .map(|e| e.name_utf16.clone())
                .collect();
            let expected: BTreeSet<_> = input
                .iter()
                .filter(|i| {
                    i.components.len() == item.components.len() + 1
                        && i.components[..item.components.len()] == *item.components
                })
                .map(|i| {
                    i.components
                        .last()
                        .unwrap()
                        .encode_utf16()
                        .collect::<Vec<_>>()
                })
                .collect();
            if actual != expected {
                return Err(invalid("private user namespace differs from supplied tree"));
            }
            directories.push(serde_json::json!({"object_index":index,"components":item.components,"snapshot":snapshot(&file)}));
        } else {
            let row = file_observation(index, &path, &file)?;
            if row["logical_length"] != item.logical_length() {
                return Err(invalid("private file length differs"));
            }
            let id = info(&file, 18, 24)?;
            if !ids.insert(id) {
                return Err(invalid("private file identity repeats"));
            }
            files.push(row);
        }
    }
    if native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)? != before
        || native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
            != target_before
    {
        return Err(invalid("private observation route changed"));
    }
    privileges.restore()?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"native-private-tree-existing-observation",
        "pair":pair,"source_before":before,"files":files,"directories":directories,"events":events,
        "user_payload_bytes_read":0,"user_payload_bytes_written":0,"source_payload_writes":0,
        "security_timestamps_attributes_pending":true,"system_objects_pending":true,
        "physical_payload_io_measured":false,"conversion_qualified":false}),
    )
}

/// Create the canonical user paths without initializing duplicate payload.
/// Root/system metadata is explicitly pending, never silently dropped. This
/// prototype is confined to the existing enrolled disposable machine/disks.
pub fn allocate(pair: &GeneralSourceShadowBinding, input: &[Input<'_>]) -> io::Result<PrivateTree> {
    pair.validate_with_resource_profile(Some(
        crate::attestation::ResourceProfile::ExperimentalStreamingTreeV2,
    ))?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        || pair.source.disk_number != 1
        || pair.shadow.disk_number != 3
        || pair
            .source
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "1b191872-c372-41ee-a416-e18863996f54"
        || pair
            .shadow
            .identity
            .disk_guid
            .trim_matches(['{', '}'])
            .to_ascii_lowercase()
            != "c0f2cd39-ad3d-484e-9990-0e6eba74485f"
        || input.is_empty()
        || input.len() > 1280
        || !input[0].directory
        || !input[0].components.is_empty()
    {
        return Err(invalid("enrolled private tree scope differs"));
    }
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut total = 0u64;
    for item in input {
        let key = crate::shadow_names::conservative_path_key(item.components);
        if item.components.len() > 16
            || item
                .components
                .iter()
                .any(|s| !crate::shadow_names::valid_unicode_component(s))
            || !names.insert(key.clone())
            || (!item.components.is_empty()
                && !directories.contains(&crate::shadow_names::conservative_path_key(
                    &item.components[..item.components.len() - 1],
                )))
        {
            return Err(invalid(
                "private tree path collision, ordering or parent differs",
            ));
        }
        descriptor(item.security)?;
        if item.directory {
            if item.logical_length() != 0 {
                return Err(invalid("directory has payload"));
            }
            directories.insert(key);
        } else {
            total = total
                .checked_add(item.logical_length())
                .ok_or_else(|| invalid("private tree length overflow"))?;
        }
    }
    if total > pair.shadow.identity.partition_bytes
        || directories.len() > 256
        || input.len() - directories.len() > 1024
    {
        return Err(invalid("private tree geometry or object budget exceeded"));
    }
    let mut events = Vec::new();
    let source_before =
        native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    if source_before.disk_attributes != 3
        || native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
            .disk_attributes
            != 0
        || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
    {
        return Err(invalid("excluded source and writable ReFS shadow required"));
    }
    let privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ])?;
    let root = format!("{}\\", pair.shadow.volume_path()?);
    let (mut sectors, mut sector_bytes, mut free, mut clusters) = (0, 0, 0, 0);
    let root_name = wide(&root);
    // SAFETY: bound NUL-terminated root and initialized geometry outputs.
    if unsafe {
        GetDiskFreeSpaceW(
            root_name.as_ptr(),
            &mut sectors,
            &mut sector_bytes,
            &mut free,
            &mut clusters,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if u64::from(sectors) * u64::from(sector_bytes) != 4096 {
        return Err(invalid(
            "private tree requires a 4-KiB ReFS allocation unit",
        ));
    }
    let root_handle = open(&root, true, true)?;
    let initial = enumerate(&root_handle)?;
    if initial.iter().any(|entry| {
        entry.name_utf16 != [46]
            && entry.name_utf16 != [46, 46]
            && !(entry.name_utf16
                == "System Volume Information"
                    .encode_utf16()
                    .collect::<Vec<_>>()
                && entry.attributes & 16 != 0
                && entry.attributes & 0x400 == 0)
    }) {
        return Err(invalid("fresh shadow required for private tree allocation"));
    }
    if initial.iter().any(|e| {
        e.name_utf16
            == "System Volume Information"
                .encode_utf16()
                .collect::<Vec<_>>()
    }) && !input
        .iter()
        .any(|i| i.directory && i.components == ["System Volume Information"])
    {
        return Err(invalid(
            "existing system namespace must be explicitly represented",
        ));
    }
    // Reuse the existing narrow formatter-cache preflight; unknown SVI entries
    // refuse. Target-only IndexerVolumeGuid normalization is already scoped to
    // these enrolled disks and never touches the excluded source.
    let _existing = existing_system_entries(&root, &initial, input, true, &mut events)?;
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(pair.shadow.volume_path()?)?;
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    let mut files = BTreeMap::new();
    let mut objects = Vec::with_capacity(input.len());
    // Reuse a private file's atomic descriptor to create private directories.
    // Its descriptor is constant rather than derived from source ACLs.
    let sd = private_descriptor()?;
    for (index, item) in input.iter().enumerate() {
        let system = item
            .components
            .first()
            .is_some_and(|s| s == "System Volume Information");
        if item.components.is_empty() || system {
            objects.push(
                serde_json::json!({"object_index":index,"components":item.components,
                "disposition":"pending-system-or-root-metadata"}),
            );
            continue;
        }
        if item.directory {
            let private = Input {
                components: item.components,
                directory: true,
                times: item.times,
                attributes: 16,
                security: &sd,
                expected_api_security: None,
                payload: &[],
                expected_length: None,
                expected_sha256: None,
                source_offset: None,
                source_runs: vec![],
            };
            create(
                &format!("{root}{}", item.components.join("\\")),
                &private,
                index,
                None,
            )?;
        } else {
            let file = unwritten::PrivatePlaceholder::allocate_named(
                &root,
                item.components,
                item.logical_length(),
                pair.shadow.identity.partition_bytes,
            )?;
            files.insert(index, file);
        }
        objects.push(
            serde_json::json!({"object_index":index,"components":item.components,
            "logical_length":item.logical_length(),"disposition":"private-uninitialized",
            "source_security_sha256":hex::encode(Sha256::digest(item.security)),
            "source_metadata_restoration_pending":true,"payload_supply_pending":!item.directory}),
        );
    }
    volume.sync_all()?;
    let tree = PrivateTree {
        files,
        volume,
        pair: pair.clone(),
        source_before,
        initial_objects: objects,
        events,
        privileges,
    };
    tree.require_source_excluded()?;
    Ok(tree)
}

fn private_descriptor() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    let text = wide("O:SYG:SYD:P(A;;FA;;;SY)");
    let mut sd = ptr::null_mut();
    let mut length = 0;
    // SAFETY: constant SDDL, bounded allocated self-relative descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut sd, &mut length)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = if (20..=65536).contains(&length) {
        Ok(unsafe { std::slice::from_raw_parts(sd.cast::<u8>(), length as usize) }.to_vec())
    } else {
        Err(invalid("private descriptor bounds differ"))
    };
    unsafe {
        LocalFree(sd);
    }
    result
}
