//! Measured full-cluster payload destinations, including relocated data. This
//! is a read-routing snapshot, not a frozen allocation graph or write ticket.
use super::*;

#[derive(Debug, Serialize)]
pub struct PayloadRoute {
    pub object_index: usize,
    pub logical_offset: u64,
    pub target_physical_offset: u64,
    pub length: u64,
    pub stream_length: u64,
    pub components: Vec<String>,
    pub expected_sha256: String,
    pub native_file_id: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SourceBackedRoutes {
    pair: GeneralSourceShadowBinding,
    entries: Vec<PayloadRoute>,
    payload_bytes: u64,
}

impl SourceBackedRoutes {
    /// Recheck the same owning files after native metadata restoration and
    /// capture the resulting mounted allocation, before final lock/dismount.
    pub fn revalidate_mounted_and_capture(&self) -> io::Result<MountedAllocation> {
        let _privileges = Privileges::enable_for(&["SeBackupPrivilege", "SeSecurityPrivilege"])?;
        self.revalidate_mounted()?;
        let volume = File::options()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(self.pair.shadow.volume_path()?)?;
        self.pair
            .shadow
            .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
        let result = capture_volume(&self.pair, &volume)?;
        self.revalidate_mounted()?;
        Ok(result)
    }
    fn revalidate_mounted(&self) -> io::Result<()> {
        let mut seen = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for route in &self.entries {
            if !seen.insert(route.object_index) {
                continue;
            }
            let path = format!(
                "{}\\{}",
                self.pair.shadow.volume_path()?,
                route.components.join("\\")
            );
            let file = open(&path, false, false)?;
            let state = snapshot(&file);
            let id = query_bytes(&state, 18, 24)?[8..24].to_vec();
            let standard = query_bytes(&state, 1, 24)?;
            if id != route.native_file_id
                || !ids.insert(id)
                || layout::u64_at(standard, 8)? != route.stream_length
                || layout::u32_at(standard, 16)? != 1
                || standard[20] != 0
                || standard[21] != 0
            {
                return Err(invalid(
                    "source-backed file identity/shape changed after metadata restoration",
                ));
            }
            let capture = crate::stream_native::retrieval_capture(&file)?;
            let runs = crate::stream_layout::parse_complete_retrieval(&capture.canonical)?;
            for r in self
                .entries
                .iter()
                .filter(|r| r.object_index == route.object_index)
            {
                if r.native_file_id != route.native_file_id
                    || !mapping_matches_run(
                        &runs,
                        r.logical_offset / 4096,
                        r.target_physical_offset / 4096,
                        (r.length / 4096) as u32,
                    )?
                {
                    return Err(invalid(
                        "source-backed physical mapping changed after metadata restoration",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn entries(&self) -> &[PayloadRoute] {
        &self.entries
    }
    pub fn pair(&self) -> &GeneralSourceShadowBinding {
        &self.pair
    }
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
}

/// Actual mounted allocation observations. Captured before LOCK because this
/// ReFS profile refuses bitmap queries through the successfully locked handle.
/// This type deliberately cannot masquerade as a frozen allocation witness.
#[derive(Debug, Serialize)]
pub struct MountedAllocation {
    pair: GeneralSourceShadowBinding,
    phase: &'static str,
    legacy: crate::bitmap_layout::AllocationMap,
    metadata: crate::bitmap_layout::AllocationMap,
    frozen_graph_verified: bool,
}
impl MountedAllocation {
    pub fn metadata(&self) -> &crate::bitmap_layout::AllocationMap {
        &self.metadata
    }
}

pub(super) fn allocation(tree: &PrivateTree) -> io::Result<MountedAllocation> {
    tree.require_source_excluded()?;
    let result = capture_volume(&tree.pair, &tree.volume)?;
    tree.require_source_excluded()?;
    Ok(result)
}

fn capture_volume(
    pair: &GeneralSourceShadowBinding,
    volume: &File,
) -> io::Result<MountedAllocation> {
    let mut events = Vec::new();
    let before = native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
    if before.disk_attributes != 3
        || native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
            .disk_attributes
            != 0
    {
        return Err(invalid(
            "excluded source/writable shadow required for mounted allocation",
        ));
    }
    let bytes = pair.shadow.identity.partition_bytes;
    let legacy = crate::bitmap_observation::Observation::capture(volume, &[0; 8], bytes, true)?;
    let mut input = [0u8; 16];
    input[8] = 1;
    let metadata = crate::bitmap_observation::Observation::capture(volume, &input, bytes, true)?;
    let result = MountedAllocation {
        pair: pair.clone(),
        phase: "mounted-before-lock",
        legacy: legacy.allocation_map(bytes)?,
        metadata: metadata.allocation_map(bytes)?,
        frozen_graph_verified: false,
    };
    if native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)? != before {
        return Err(invalid("source changed during mounted allocation capture"));
    }
    Ok(result)
}

pub(super) fn capture(tree: &PrivateTree, input: &[Input<'_>]) -> io::Result<SourceBackedRoutes> {
    tree.require_source_excluded()?;
    if !tree.placement_complete || input.len() != tree.initial_objects.len() {
        return Err(invalid(
            "complete live placement/input required for source-backed routes",
        ));
    }
    let mut entries = Vec::new();
    let mut payload_bytes = 0u64;
    for (&index, file) in &tree.files {
        let item = input
            .get(index)
            .ok_or_else(|| invalid("payload input absent"))?;
        let initial = &tree.initial_objects[index];
        let expected = item
            .expected_sha256
            .ok_or_else(|| invalid("payload source digest absent"))?;
        if item.directory
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || initial["components"]
                != serde_json::to_value(item.components).map_err(io::Error::other)?
            || initial["payload_expected_sha256"].as_str() != Some(expected)
        {
            return Err(invalid("source-backed canonical input differs"));
        }
        tree.validate_stream_shape(index, item.components, item.logical_length())?;
        let prefix = file.logical_length() / 4096 * 4096;
        if file.valid_prefix() < prefix {
            return Err(invalid("source-backed prefix is not storage-valid"));
        }
        let mut mapped = file.tracked_mappings().to_vec();
        mapped.sort_unstable_by_key(|r| r.0);
        let mut cursor = 0u64;
        for (vcn, lcn, clusters) in mapped {
            let length = u64::from(clusters) * 4096;
            if vcn * 4096 != cursor || length == 0 || cursor + length > prefix {
                return Err(invalid("source-backed logical coverage differs"));
            }
            entries.push(PayloadRoute {
                object_index: index,
                logical_offset: cursor,
                target_physical_offset: lcn * 4096,
                length,
                stream_length: file.logical_length(),
                components: item.components.to_vec(),
                expected_sha256: expected.to_owned(),
                native_file_id: info(file.metadata_handle(), 18, 24)?[8..24].to_vec(),
            });
            if entries.len() > 4096 {
                return Err(invalid("source-backed route budget exceeded"));
            }
            cursor += length;
        }
        if cursor != prefix {
            return Err(invalid("source-backed full-cluster prefix incomplete"));
        }
        payload_bytes = payload_bytes
            .checked_add(prefix)
            .ok_or_else(|| invalid("payload total overflow"))?;
    }
    entries.sort_unstable_by_key(|r| r.target_physical_offset);
    let mut end = 0;
    for route in &entries {
        let next = route
            .target_physical_offset
            .checked_add(route.length)
            .filter(|v| *v <= tree.pair.shadow.identity.partition_bytes)
            .ok_or_else(|| invalid("payload destination escapes partition"))?;
        if route.target_physical_offset < end {
            return Err(invalid("payload destinations overlap"));
        }
        end = next;
    }
    tree.require_source_excluded()?;
    Ok(SourceBackedRoutes {
        pair: tree.pair.clone(),
        entries,
        payload_bytes,
    })
}
