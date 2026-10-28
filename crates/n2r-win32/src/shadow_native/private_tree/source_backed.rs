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
}

#[derive(Debug, Serialize)]
pub struct SourceBackedRoutes {
    pair: GeneralSourceShadowBinding,
    entries: Vec<PayloadRoute>,
    payload_bytes: u64,
}

impl SourceBackedRoutes {
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
    let bytes = tree.pair.shadow.identity.partition_bytes;
    let legacy =
        crate::bitmap_observation::Observation::capture(&tree.volume, &[0; 8], bytes, true)?;
    let mut input = [0u8; 16];
    input[8] = 1;
    let metadata =
        crate::bitmap_observation::Observation::capture(&tree.volume, &input, bytes, true)?;
    let result = MountedAllocation {
        pair: tree.pair.clone(),
        phase: "mounted-before-lock",
        legacy: legacy.allocation_map(bytes)?,
        metadata: metadata.allocation_map(bytes)?,
        frozen_graph_verified: false,
    };
    tree.require_source_excluded()?;
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
