//! Measured full-cluster payload destinations, including relocated data. This
//! is a read-routing snapshot, not a frozen allocation graph or write ticket.
use super::*;

#[derive(Debug, Serialize)]
pub struct PayloadRoute {
    pub object_index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_name_utf16: Vec<u16>,
    pub logical_offset: u64,
    pub target_physical_offset: u64,
    pub length: u64,
    pub stream_length: u64,
    pub components: Vec<String>,
    pub expected_sha256: Option<String>,
    pub native_file_id: Vec<u8>,
    #[serde(skip_serializing_if = "one_link")]
    pub expected_link_count: u32,
}
fn one_link(count: &u32) -> bool {
    *count == 1
}

#[derive(Debug, Serialize)]
pub struct SourceBackedRoutes {
    pair: GeneralSourceShadowBinding,
    entries: Vec<PayloadRoute>,
    payload_bytes: u64,
}

impl SourceBackedRoutes {
    /// Re-derive every full-cluster source-backed prefix from the post-freeze
    /// native READ_ONLY witness. This consumes no saved success JSON and reads
    /// no placeholder payload. Expected hashes remain expectations: callers
    /// must bind them to the admitted source and prove the composite contents.
    pub fn from_protected_layout(
        observation: &native::GeneralLiveRefsLayoutObservation,
    ) -> io::Result<Self> {
        let observed = observation.report();
        let report = observed.native();
        if observation.before() != observation.after()
            || observation.before().disk_attributes != 3
            || observation.observed_readonly().disk_attributes != 2
            || report.payload_bytes_written != 0
            || report.conversion_qualified
            || report.objects.len() != observed.expected_stream_sha256.len()
        {
            return Err(invalid("protected source-backed layout context differs"));
        }
        let mut entries = Vec::new();
        let mut payload_bytes = 0u64;
        for (index, object) in report.objects.iter().enumerate() {
            let standard = query_bytes(&object.before, 1, 24)?;
            if standard[21] != 0 {
                continue;
            }
            for named in &object.named_streams {
                let ns = query_bytes(&named.before, 1, 24)?;
                let length = layout::u64_at(ns, 8)?;
                let prefix = length / 4096 * 4096;
                let sparse = named.sparse.as_ref();
                if named.expected_sha256.is_none()
                    && (!length.is_multiple_of(4096) || sparse.is_some() || named.resident_data)
                {
                    return Err(invalid(
                        "digest-free named route requires complete plain initialized clusters",
                    ));
                }
                if prefix == 0 || (sparse.is_some() && named.retrieval.is_empty()) {
                    continue;
                }
                let needed = sparse.map_or(prefix, |s| {
                    s.expected
                        .allocated
                        .iter()
                        .map(|r| r.length.min(prefix.saturating_sub(r.offset)))
                        .sum()
                });
                if named.resident_data || named.retrieval_page_proof.is_none() {
                    return Err(invalid("named payload has no complete native map"));
                }
                let id = query_bytes(&named.before, 18, 24)?[8..24].to_vec();
                let mut covered = 0;
                for run in stream_layout::parse_complete_retrieval(&named.retrieval)? {
                    let at = run
                        .vcn
                        .checked_mul(4096)
                        .ok_or_else(|| invalid("named VCN overflow"))?;
                    if at >= prefix {
                        break;
                    }
                    let bytes = run
                        .clusters
                        .checked_mul(4096)
                        .ok_or_else(|| invalid("named length overflow"))?
                        .min(prefix - at);
                    let Some(lcn) = run.lcn else {
                        if sparse.is_some() {
                            continue;
                        } else {
                            return Err(invalid("named prefix hole"));
                        }
                    };
                    let offset = lcn
                        .checked_mul(4096)
                        .ok_or_else(|| invalid("named LCN overflow"))?;
                    if (sparse.is_none() && at != covered) || bytes == 0 {
                        return Err(invalid("named prefix coverage differs"));
                    }
                    entries.push(PayloadRoute {
                        object_index: index,
                        stream_name_utf16: named.name_utf16.clone(),
                        logical_offset: at,
                        target_physical_offset: offset,
                        length: bytes,
                        stream_length: length,
                        components: object.components.clone(),
                        expected_sha256: named.expected_sha256.clone(),
                        native_file_id: id.clone(),
                        expected_link_count: layout::u32_at(ns, 16)?,
                    });
                    if entries.len() > 4096 {
                        return Err(invalid("protected route budget exceeded"));
                    }
                    covered += bytes;
                }
                if covered != needed {
                    return Err(invalid("named full-cluster prefix incomplete"));
                }
                payload_bytes += needed;
            }
            let length = layout::u64_at(standard, 8)?;
            let prefix = length / 4096 * 4096;
            let sparse = object.sparse.as_ref();
            if prefix == 0 || (sparse.is_some() && object.retrieval.is_empty()) {
                continue;
            }
            let needed = sparse.map_or(prefix, |s| {
                s.expected
                    .allocated
                    .iter()
                    .map(|r| r.length.min(prefix.saturating_sub(r.offset)))
                    .sum()
            });
            let expected = &observed.expected_stream_sha256[index];
            if expected.is_none()
                && (!length.is_multiple_of(4096) || sparse.is_some() || object.resident_data)
            {
                return Err(invalid(
                    "digest-free route requires complete plain initialized clusters",
                ));
            }
            if object.resident_data || object.retrieval_page_proof.is_none() {
                return Err(invalid(
                    "protected payload prefix has no complete native map",
                ));
            }
            let id = query_bytes(&object.before, 18, 24)?[8..24].to_vec();
            let mut covered = 0u64;
            for run in stream_layout::parse_complete_retrieval(&object.retrieval)? {
                let at = run
                    .vcn
                    .checked_mul(4096)
                    .ok_or_else(|| invalid("protected payload VCN overflow"))?;
                if at >= prefix {
                    break;
                }
                let bytes = run
                    .clusters
                    .checked_mul(4096)
                    .ok_or_else(|| invalid("protected payload length overflow"))?
                    .min(prefix - at);
                let Some(lcn) = run.lcn else {
                    if sparse.is_some() {
                        continue;
                    } else {
                        return Err(invalid("protected payload prefix contains a hole"));
                    }
                };
                let offset = lcn
                    .checked_mul(4096)
                    .ok_or_else(|| invalid("protected payload LCN overflow"))?;
                if (sparse.is_none() && at != covered) || bytes == 0 {
                    return Err(invalid("protected payload prefix coverage differs"));
                }
                entries.push(PayloadRoute {
                    object_index: index,
                    stream_name_utf16: Vec::new(),
                    logical_offset: at,
                    target_physical_offset: offset,
                    length: bytes,
                    stream_length: length,
                    components: object.components.clone(),
                    expected_sha256: expected.clone(),
                    native_file_id: id.clone(),
                    expected_link_count: layout::u32_at(standard, 16)?,
                });
                if entries.len() > 4096 {
                    return Err(invalid("protected source-backed route budget exceeded"));
                }
                covered = covered
                    .checked_add(bytes)
                    .ok_or_else(|| invalid("protected prefix total overflow"))?;
            }
            if covered != needed {
                return Err(invalid("protected full-cluster prefix incomplete"));
            }
            payload_bytes = payload_bytes
                .checked_add(needed)
                .ok_or_else(|| invalid("protected payload total overflow"))?;
        }
        entries.sort_unstable_by_key(|route| route.target_physical_offset);
        let mut end = 0;
        for route in &entries {
            let next = route
                .target_physical_offset
                .checked_add(route.length)
                .filter(|next| *next <= observed.pair().shadow.identity.partition_bytes)
                .ok_or_else(|| invalid("protected payload escapes the partition"))?;
            if route.target_physical_offset < end {
                return Err(invalid("protected payload destinations overlap"));
            }
            end = next;
        }
        Ok(Self {
            pair: observed.pair().clone(),
            entries,
            payload_bytes,
        })
    }

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
        let mut ids = BTreeMap::new();
        for route in &self.entries {
            if !seen.insert((route.object_index, route.stream_name_utf16.clone())) {
                continue;
            }
            let path = streams::path(
                &self.pair.shadow.volume_path()?,
                &route.components,
                &route.stream_name_utf16,
            )?;
            let file = open(&path, false, false)?;
            let state = snapshot(&file);
            let id = query_bytes(&state, 18, 24)?[8..24].to_vec();
            let standard = query_bytes(&state, 1, 24)?;
            if id != route.native_file_id
                || ids
                    .insert(id, route.object_index)
                    .is_some_and(|old| old != route.object_index)
                || layout::u64_at(standard, 8)? != route.stream_length
                || layout::u32_at(standard, 16)? != route.expected_link_count
                || standard[20] != 0
                || standard[21] != 0
            {
                return Err(invalid(
                    "source-backed file identity/shape changed after metadata restoration",
                ));
            }
            let capture = crate::stream_native::retrieval_capture(&file)?;
            let runs = crate::stream_layout::parse_complete_retrieval(&capture.canonical)?;
            for r in self.entries.iter().filter(|r| {
                r.object_index == route.object_index
                    && r.stream_name_utf16 == route.stream_name_utf16
            }) {
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
    for (key, file) in &tree.files {
        let index = key.object_index;
        let item = streams::view(input, key)?;
        let initial = &tree.initial_objects[index];
        let expected = item.expected_sha256;
        if expected.is_none() {
            streams::validate_extent_only(
                item.logical_length(),
                item.source_offset,
                &item.source_runs,
                item.sparse.is_some(),
                tree.pair.source.identity.partition_bytes,
            )?;
        }
        if item.directory
            || expected.is_some_and(|digest| !crate::content_digest::is_hex(digest))
            || initial["components"]
                != serde_json::to_value(item.components).map_err(io::Error::other)?
            || (key.name_utf16.is_empty()
                && (initial.get("payload_expected_sha256").is_none()
                    || initial["payload_expected_sha256"].as_str() != expected))
        {
            return Err(invalid("source-backed canonical input differs"));
        }
        tree.validate_stream_shape_named(
            index,
            &key.name_utf16,
            item.components,
            item.logical_length(),
        )?;
        let prefix = file.logical_length() / 4096 * 4096;
        if file.valid_prefix() < prefix {
            return Err(invalid("source-backed prefix is not storage-valid"));
        }
        let mut mapped = file.tracked_mappings().to_vec();
        mapped.sort_unstable_by_key(|r| r.0);
        let mut cursor = 0u64;
        let mut stream_payload = 0u64;
        for (vcn, lcn, clusters) in mapped {
            let length = u64::from(clusters) * 4096;
            if vcn * 4096 != cursor || length == 0 || cursor + length > prefix {
                return Err(invalid("source-backed logical coverage differs"));
            }
            let parts = if let Some(target) = tree.sparse_targets.get(key) {
                target.parts(cursor, length, true)?
            } else {
                vec![sparse_stream::Island {
                    logical: cursor,
                    dense: cursor,
                    length,
                }]
            };
            let logical_length = tree
                .sparse_targets
                .get(key)
                .map_or(file.logical_length(), |t| t.logical_length);
            let identity = if let Some(target) = tree.sparse_targets.get(key) {
                info(&target.file, 18, 24)?
            } else {
                info(file.metadata_handle(), 18, 24)?
            };
            for part in parts {
                let n = part
                    .length
                    .min((logical_length / 4096 * 4096).saturating_sub(part.logical));
                if n == 0 {
                    continue;
                }
                entries.push(PayloadRoute {
                    object_index: index,
                    stream_name_utf16: key.name_utf16.clone(),
                    logical_offset: part.logical,
                    target_physical_offset: lcn * 4096 + part.dense - cursor,
                    length: n,
                    stream_length: logical_length,
                    components: item.components.to_vec(),
                    expected_sha256: expected.map(str::to_owned),
                    native_file_id: identity[8..24].to_vec(),
                    expected_link_count: super::super::hard_links::count(&item)?,
                });
                stream_payload += n;
            }
            if entries.len() > 4096 {
                return Err(invalid("source-backed route budget exceeded"));
            }
            cursor += length;
        }
        if cursor != prefix {
            return Err(invalid("source-backed full-cluster prefix incomplete"));
        }
        payload_bytes = payload_bytes
            .checked_add(stream_payload)
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
