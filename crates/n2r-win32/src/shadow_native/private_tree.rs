//! Allocation-only user namespace on an independently bound fresh ReFS shadow.
//! The files stay SYSTEM-only and contain no admitted payload yet. A live tree
//! exposes placement operations, never source writes or conversion authority.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
mod enrollment;
mod metadata;
mod placement;
mod source_backed;
mod supply;
mod system_payloads;
pub use enrollment::{ConstructionEnrollment, enroll};
pub use source_backed::{MountedAllocation, PayloadRoute, SourceBackedRoutes};
pub use supply::{SupplyPlan, SupplyRange};

/// Tree-wide FSCTL_MOVE_FILE ceiling shared by deferred allocation, evacuation
/// and final placement: about two submissions per retained NTFS run for a
/// fragmented 1024-file tree of up to 16,384 runs. It is a ceiling, not a
/// guarantee: placement admits at most 4096 desired runs (the downstream
/// route bound) and reserves each move proof's bound against
/// MAX_PLACEMENT_ARTIFACT_BYTES before that move's native IO, refusing first.
pub const MAX_PLACEMENT_SUBMISSIONS: usize = 32_768;

/// Check the same limits used by the mover before allocating any placeholders.
pub fn validate_placement_limits(bytes: u64, submissions: usize) -> io::Result<()> {
    placement::validate_limits(bytes, submissions)
}

pub struct PrivateTree {
    // Files close before the volume and privilege lease on drop. No drop path
    // restores public permissions over uninitialized scratch contents.
    files: BTreeMap<StreamKey, unwritten::PrivatePlaceholder>,
    stream_slots: BTreeMap<usize, StreamKey>,
    volume: File,
    pair: GeneralSourceShadowBinding,
    source_before: native::GeneralDiskState,
    initial_objects: Vec<serde_json::Value>,
    events: Vec<NativeEvent>,
    privileges: Privileges,
    original_coordinates: BTreeMap<StreamKey, Vec<(u64, u64, u64)>>,
    placement_started: bool,
    placement_complete: bool,
    placement_progress: serde_json::Value,
    system_identities: BTreeMap<Vec<String>, Vec<u8>>,
    system_payloads_started: bool,
    system_payloads_complete: bool,
    // Constructor-owned identity anchors, never reconstructed from a report.
    // Directories/root stay open without DELETE sharing for the whole session.
    metadata_targets: BTreeMap<usize, File>,
    metadata_input_sha256: [u8; 32],
    construction_enrollment: Option<serde_json::Value>,
}

impl PrivateTree {
    fn file_by_slot(&self, slot: usize) -> io::Result<&unwritten::PrivatePlaceholder> {
        self.stream_slots
            .get(&slot)
            .and_then(|key| self.files.get(key))
            .ok_or_else(|| invalid("stream placement slot absent"))
    }
    fn file_by_slot_mut(&mut self, slot: usize) -> io::Result<&mut unwritten::PrivatePlaceholder> {
        let key = self
            .stream_slots
            .get(&slot)
            .ok_or_else(|| invalid("stream placement slot absent"))?;
        self.files
            .get_mut(key)
            .ok_or_else(|| invalid("stream placement file absent"))
    }
    fn place_slot(
        &mut self,
        slot: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        let key = self
            .stream_slots
            .get(&slot)
            .cloned()
            .ok_or_else(|| invalid("stream placement slot absent"))?;
        self.place_named(key.object_index, &key.name_utf16, vcn, lcn, clusters)
    }
    fn reposition_slot(
        &mut self,
        slot: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        let key = self
            .stream_slots
            .get(&slot)
            .cloned()
            .ok_or_else(|| invalid("stream placement slot absent"))?;
        self.reposition_named(key.object_index, &key.name_utf16, vcn, lcn, clusters)
    }
    /// Complete metadata only on this owning disposable maintenance session.
    /// Consumes the owner even on partial failure: no retry/placement authority
    /// is returned. Source-backed prefixes are not logical-content verified by
    /// this operation, and the returned diagnostic grants no write authority.
    pub fn complete_source_metadata(
        self,
        input: &[Input<'_>],
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<serde_json::Value> {
        metadata::complete(self, input, same_security)
    }

    /// Only bounded recognized SVI files, not user payload or raw source writes.
    pub fn materialize_system_payloads(
        &mut self,
        input: &[Input<'_>],
        writer: &mut dyn FnMut(usize, &mut File) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        self.require_bound_input(input)?;
        system_payloads::run(self, input, writer)
    }
    pub fn mounted_allocation_snapshot(&self) -> io::Result<MountedAllocation> {
        source_backed::allocation(self)
    }
    /// Prepare storage-valid private prefixes without filling either retained
    /// or relocated payload. Payload must subsequently be supplied from NTFS.
    pub fn prepare_source_backed_prefixes(&mut self) -> io::Result<()> {
        self.require_source_excluded()?;
        if !self.placement_complete {
            return Err(invalid(
                "complete placement required for source-backed preparation",
            ));
        }
        for file in self.files.values_mut() {
            let prefix = file.logical_length() / 4096 * 4096;
            if prefix > 0 {
                file.advance_valid_data(prefix, true)?;
            }
        }
        self.require_source_excluded()
    }

    pub fn source_backed_routes(&self, input: &[Input<'_>]) -> io::Result<SourceBackedRoutes> {
        source_backed::capture(self, input)
    }
    /// Diagnostic progress only; partial attempts never supply conversion or
    /// resume authority. Available even when a native file has been poisoned.
    pub fn placement_progress(&self) -> &serde_json::Value {
        &self.placement_progress
    }
    pub fn validate_stream_shape(
        &self,
        index: usize,
        components: &[String],
        length: u64,
    ) -> io::Result<()> {
        self.validate_stream_shape_named(index, &[], components, length)
    }
    pub fn validate_stream_shape_named(
        &self,
        index: usize,
        name: &[u16],
        components: &[String],
        length: u64,
    ) -> io::Result<()> {
        self.require_source_excluded()?;
        let file = self
            .files
            .get(&StreamKey::named(index, name))
            .ok_or_else(|| invalid("private verification stream absent"))?;
        let path = streams::path(&self.pair.shadow.volume_path()?, components, name)?;
        let standard = info(file.metadata_handle(), 1, 24)?;
        if file.path != path
            || file.logical_length() != length
            || layout::u64_at(&standard, 8)? != length
            || layout::u32_at(&standard, 16)? != 1
            || standard[20] != 0
            || standard[21] != 0
        {
            return Err(invalid("private verification stream shape differs"));
        }
        file.check_placements()
    }

    /// Only materialization data is readable from the shadow in a hybrid
    /// session. Source-reference bytes must come from the frozen original.
    pub fn read_materialized_range(
        &mut self,
        index: usize,
        offset: u64,
        output: &mut [u8],
    ) -> io::Result<()> {
        self.read_materialized_range_named(index, &[], offset, output)
    }
    pub fn read_materialized_range_named(
        &mut self,
        index: usize,
        name: &[u16],
        offset: u64,
        output: &mut [u8],
    ) -> io::Result<()> {
        let key = StreamKey::named(index, name);
        if !self.placement_complete {
            return Err(invalid("live complete placement required for hybrid read"));
        }
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or_else(|| invalid("hybrid read overflow"))?;
        if !output.is_empty()
            && self.original_coordinates.get(&key).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|(start, _, len)| offset < *start + *len && *start < end)
            })
        {
            return Err(invalid(
                "hybrid source reference cannot read shadow placeholder bytes",
            ));
        }
        self.files
            .get_mut(&key)
            .ok_or_else(|| invalid("private materialized stream absent"))?
            .read_initialized_at(offset, output)
    }
    pub fn supply_plan(&self) -> io::Result<SupplyPlan> {
        supply::plan(self)
    }
    pub fn place_source_prefixes(&mut self, input: &[Input<'_>]) -> io::Result<serde_json::Value> {
        placement::run(
            self,
            input,
            self.pair.shadow.identity.partition_bytes,
            MAX_PLACEMENT_SUBMISSIONS,
        )
    }
    pub fn place_source_prefixes_with_limits(
        &mut self,
        input: &[Input<'_>],
        bytes: u64,
        moves: usize,
    ) -> io::Result<serde_json::Value> {
        placement::run(self, input, bytes, moves)
    }
    /// Apply one placement through the private constructor's state machine.
    pub fn place(
        &mut self,
        object_index: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        self.place_named(object_index, &[], vcn, lcn, clusters)
    }
    pub fn place_named(
        &mut self,
        object_index: usize,
        name: &[u16],
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        self.placement_complete = false;
        self.original_coordinates.clear();
        let file = self
            .files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private user file absent"))?;
        let result = serde_json::to_value(file.place(&self.volume, vcn, lcn, clusters)?)
            .map_err(io::Error::other)?;
        self.require_source_excluded()?;
        Ok(result)
    }

    /// Relocate a previously tracked unwritten range to its final placement.
    /// Native failure poisons the file; it cannot become a retry loop.
    pub fn reposition(
        &mut self,
        object_index: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        self.reposition_named(object_index, &[], vcn, lcn, clusters)
    }
    pub fn reposition_named(
        &mut self,
        object_index: usize,
        name: &[u16],
        vcn: u64,
        lcn: u64,
        clusters: u32,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        self.placement_complete = false;
        self.original_coordinates.clear();
        let file = self
            .files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private reposition file absent"))?;
        let proof = serde_json::to_value(file.reposition(&self.volume, vcn, lcn, clusters)?)
            .map_err(io::Error::other)?;
        self.require_source_excluded()?;
        Ok(proof)
    }

    /// All prefix clusters must already be placed. This never restores ACLs
    /// or claims that the scratch file contains the original logical bytes.
    pub fn advance_placed_prefix(&mut self, object_index: usize, bytes: u64) -> io::Result<()> {
        self.advance_placed_prefix_named(object_index, &[], bytes)
    }
    pub fn advance_placed_prefix_named(
        &mut self,
        object_index: usize,
        name: &[u16],
        bytes: u64,
    ) -> io::Result<()> {
        self.require_source_excluded()?;
        self.files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private user file absent"))?
            .advance_valid_data(bytes, true)?;
        self.require_source_excluded()
    }

    /// Prepare private scratch for a tail write without copying its prefix.
    /// This is explicitly NOT a retained-source or logical-content proof.
    pub fn prepare_unplaced_prefix(
        &mut self,
        object_index: usize,
        bytes: u64,
    ) -> io::Result<serde_json::Value> {
        self.prepare_unplaced_prefix_named(object_index, &[], bytes)
    }
    pub fn prepare_unplaced_prefix_named(
        &mut self,
        object_index: usize,
        name: &[u16],
        bytes: u64,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        self.files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private tail file absent"))?
            .prepare_unplaced_prefix(bytes)?;
        self.require_source_excluded()?;
        Ok(
            serde_json::json!({"object_index":object_index,"storage_valid_prefix_bytes":bytes,
            "source_prefix_contents_verified":false,"original_physical_positions_verified":false,
            "private_scratch_only":true,"conversion_qualified":false}),
        )
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
        self.materialize_range_named(object_index, &[], components, logical_length, offset, bytes)
    }
    pub fn materialize_range_named(
        &mut self,
        object_index: usize,
        name: &[u16],
        components: &[String],
        logical_length: u64,
        offset: u64,
        bytes: &[u8],
    ) -> io::Result<serde_json::Value> {
        let key = StreamKey::named(object_index, name);
        self.require_source_excluded()?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("materialization range overflow"))?;
        if !bytes.is_empty()
            && self.placement_complete
            && self.original_coordinates.get(&key).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|(start, _, len)| offset < *start + *len && *start < end)
            })
        {
            return Err(invalid(
                "materialization overlaps an original-coordinate source reference",
            ));
        }
        let expected_path = streams::path(&self.pair.shadow.volume_path()?, components, name)?;
        let file = self
            .files
            .get_mut(&key)
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

    fn require_bound_input(&self, input: &[Input<'_>]) -> io::Result<()> {
        if metadata::input_digest(input) != self.metadata_input_sha256 {
            return Err(invalid("private constructor source input changed"));
        }
        Ok(())
    }

    /// Snapshot only metadata and mappings. No placeholder payload is read.
    pub fn report(&self) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        let mut files = Vec::with_capacity(self.files.len());
        for (key, file) in &self.files {
            let mut row =
                file_observation(key.object_index, &file.path, file.metadata_handle(), 1)?;
            if !key.name_utf16.is_empty() {
                row["stream_name_utf16"] =
                    serde_json::to_value(&key.name_utf16).map_err(io::Error::other)?;
            }
            row["materialized_bytes"] = file.materialized_bytes().into();
            row["readback_bytes"] = file.readback_bytes().into();
            row["valid_prefix_bytes"] = file.valid_prefix().into();
            row["verification_read_bytes"] = file.verification_read_bytes().into();
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
        let verification_read_bytes = self.files.values().try_fold(0u64, |n, f| {
            n.checked_add(f.verification_read_bytes())
                .ok_or_else(|| invalid("private verify total overflow"))
        })?;
        self.require_source_excluded()?;
        Ok(
            serde_json::json!({"schema_version":1,"kind":"native-private-tree-allocation-template",
            "pair":self.pair,"source_before":self.source_before,"objects":self.initial_objects,
            "construction_enrollment":self.construction_enrollment,
            "files":files,"events":self.events,"privileges":self.privileges.audit(),
            "user_payload_bytes_read":readback_bytes,
            "user_payload_bytes_written":materialized_bytes,
            "hybrid_shadow_verification_bytes_read":verification_read_bytes,
            "formatter_preflight_may_read_cache":true,"source_payload_writes":0,
            "security_timestamps_attributes_pending":true,"system_objects_pending":true,
            "system_payloads_pending":!self.system_payloads_complete,
            "physical_payload_io_measured":false,"conversion_qualified":false}),
        )
    }
}

fn file_observation(
    index: usize,
    path: &str,
    file: &File,
    expected_links: u32,
) -> io::Result<serde_json::Value> {
    let standard = info(file, 1, 24)?;
    let logical = layout::u64_at(&standard, 8)?;
    let allocated = layout::u64_at(&standard, 0)?;
    if layout::u32_at(&standard, 16)? != expected_links || standard[20] != 0 || standard[21] != 0 {
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
    super::hard_links::validate(
        input,
        super::hard_links::MAX_NAMES,
        crate::shadow_names::valid_unicode_component,
    )?;
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
                .flat_map(super::hard_links::paths)
                .filter(|path| {
                    path.len() == item.components.len() + 1 && path.starts_with(item.components)
                })
                .map(|path| path.last().unwrap().encode_utf16().collect::<Vec<_>>())
                .collect();
            if actual != expected {
                return Err(invalid("private user namespace differs from supplied tree"));
            }
            directories.push(serde_json::json!({"object_index":index,"components":item.components,"snapshot":snapshot(&file)}));
        } else {
            let mut row = file_observation(index, &path, &file, super::hard_links::count(item)?)?;
            let aliases = super::hard_links::observe(&root, item, &snapshot(&file), false)?;
            if !aliases.is_empty() {
                row["additional_names"] =
                    serde_json::to_value(aliases).map_err(io::Error::other)?;
            }
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
    {
        return Err(invalid("enrolled private tree scope differs"));
    }
    allocate_checked(pair, input, None)
}

/// Consume actual selected-device enrollment into the same owned constructor.
/// This does not issue source admission or authorize source raw writes.
pub fn allocate_enrolled(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &[Input<'_>],
) -> io::Result<PrivateTree> {
    enrollment.revalidate()?;
    let pair = enrollment.pair.clone();
    allocate_checked(&pair, input, Some(enrollment))
}

fn allocate_checked(
    pair: &GeneralSourceShadowBinding,
    input: &[Input<'_>],
    enrollment: Option<ConstructionEnrollment<'_>>,
) -> io::Result<PrivateTree> {
    super::hard_links::validate(
        input,
        super::hard_links::MAX_NAMES,
        crate::shadow_names::valid_unicode_component,
    )?;
    streams::validate(input, pair.shadow.identity.partition_bytes)?;
    if input.is_empty()
        || input.len() > 1280
        || !input[0].directory
        || !input[0].components.is_empty()
    {
        return Err(invalid("private tree root or object bound differs"));
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
            for named in &item.named_streams {
                total = total
                    .checked_add(named.expected_length)
                    .ok_or_else(|| invalid("private stream total overflow"))?;
            }
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
    let (privileges, root_handle, enrolled_volume, construction_enrollment) =
        if let Some(mut owned) = enrollment {
            owned.revalidate()?;
            let observed = owned.observation();
            // Enrollment retains its complete audit in the observation. This
            // constructor is a separate native-control phase with its own
            // bound; do not charge the same earlier queries a second time.
            (
                owned.privileges,
                owned.root,
                Some(owned.volume),
                Some(observed),
            )
        } else {
            let privileges = Privileges::enable_for(&[
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeSecurityPrivilege",
                "SeManageVolumePrivilege",
            ])?;
            (privileges, open(&root, true, true)?, None, None)
        };
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
    let system_identities = existing_system_entries(&root, &initial, input, true, &mut events)?;
    let volume = if let Some(volume) = enrolled_volume {
        volume
    } else {
        File::options()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(pair.shadow.volume_path()?)?
    };
    pair.shadow
        .validate_volume_extent(&ctl(&volume, 0x00560000, &[], 1024)?)?;
    let mut files = BTreeMap::new();
    let mut metadata_targets = BTreeMap::new();
    metadata_targets.insert(0, root_handle);
    // Pin every formatter object the constructor admitted. Subsequent system
    // supply must update these same objects, not a caller-selected path.
    for (index, item) in input.iter().enumerate() {
        if let Some(id) = system_identities.get(item.components) {
            let handle = open(
                &format!("{root}{}", item.components.join("\\")),
                item.directory,
                true,
            )?;
            if query_bytes(&snapshot(&handle), 18, 24)?[8..24] != *id {
                return Err(invalid(
                    "system identity changed during constructor pinning",
                ));
            }
            metadata_targets.insert(index, handle);
        }
    }
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
                additional_names: &[],
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
                named_streams: Vec::new(),
            };
            create(
                &format!("{root}{}", item.components.join("\\")),
                &private,
                index,
                None,
            )?;
            metadata_targets.insert(
                index,
                open(&format!("{root}{}", item.components.join("\\")), true, true)?,
            );
        } else {
            let file = unwritten::PrivatePlaceholder::allocate_named(
                &root,
                item.components,
                item.logical_length(),
                pair.shadow.identity.partition_bytes,
            )?;
            for named in &item.named_streams {
                let stream = unwritten::PrivatePlaceholder::allocate_named_stream(
                    &root,
                    item.components,
                    named.name_utf16,
                    named.expected_length,
                    pair.shadow.identity.partition_bytes,
                    file.metadata_handle(),
                )?;
                files.insert(StreamKey::named(index, named.name_utf16), stream);
            }
            files.insert(StreamKey::unnamed(index), file);
        }
        objects.push(
            serde_json::json!({"object_index":index,"components":item.components,
            "logical_length":item.logical_length(),"disposition":"private-uninitialized",
            "payload_expected_sha256":item.expected_sha256,
            "source_security_sha256":hex::encode(Sha256::digest(item.security)),
            "source_metadata_restoration_pending":true,"payload_supply_pending":!item.directory}),
        );
    }
    volume.sync_all()?;
    let mut stream_slots = BTreeMap::new();
    let mut next = input.len();
    for key in files.keys() {
        let slot = if key.name_utf16.is_empty() {
            key.object_index
        } else {
            let n = next;
            next += 1;
            n
        };
        stream_slots.insert(slot, key.clone());
    }
    let tree = PrivateTree {
        files,
        stream_slots,
        volume,
        pair: pair.clone(),
        source_before,
        initial_objects: objects,
        events,
        privileges,
        original_coordinates: BTreeMap::new(),
        placement_started: false,
        placement_complete: false,
        placement_progress: serde_json::Value::Null,
        system_identities,
        system_payloads_started: false,
        system_payloads_complete: false,
        metadata_targets,
        metadata_input_sha256: metadata::input_digest(input),
        construction_enrollment,
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
