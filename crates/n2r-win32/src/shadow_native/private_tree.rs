//! Allocation-only user namespace on an independently bound fresh ReFS shadow.
//! The files stay SYSTEM-only and contain no admitted payload yet. A live tree
//! exposes placement operations, never source writes or conversion authority.
use super::input_domain::{DomainMetadata, InputDomain, ObjectInput, SliceInputs};
use super::*;
pub use crate::native::{PartitionSourceMetadataState, PartitionSourceMetadataWitness};
use std::collections::{BTreeMap, BTreeSet};
mod enrollment;
mod memory;
pub(super) mod metadata;
mod placement;
pub mod recovery;
mod routed_prefix;
mod source_backed;
pub(super) mod source_scope;
mod supply;
mod supply_snapshot;
mod system_payloads;
pub use enrollment::{
    ConstructionEnrollment, PartitionConstructionEnrollment, enroll,
    enroll_partition_with_resource_profile, enroll_with_resource_profile,
};
pub use placement::{PlacementEvidenceSink, ResourcePlacementReport};
pub use routed_prefix::RoutedPrefixReady;
pub use source_backed::{
    MountedAllocation, PayloadRoute, SourceBackedRoutes, ValidatedSourceBackedRoutes,
};
pub use supply::{StreamSupplySummary, SupplyKind, SupplyPlan, SupplyRange};
pub use supply_snapshot::NativeReadOnlySupplyStreamSnapshot;

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
    sparse_targets: BTreeMap<StreamKey, sparse_stream::Target>,
    carrier_directory: Option<sparse_stream::CarrierDirectory>,
    volume: File,
    pair: GeneralSourceShadowBinding,
    backing_guard: Option<std::sync::Arc<crate::managed_shadow::BackingResourceGuard>>,
    source_before: source_scope::ConstructionSourceState,
    partition_source: Option<source_scope::PartitionShadowConstructionLease>,
    dedicated_source: Option<source_scope::DedicatedShadowConstructionLease>,
    initial_objects: Vec<serde_json::Value>,
    events: Vec<NativeEvent>,
    privileges: Privileges,
    reparse_privileges: Option<Privileges>,
    original_coordinates: BTreeMap<StreamKey, Vec<(u64, u64, u64)>>,
    materialized_tails: BTreeMap<StreamKey, MaterializedTail>,
    placement_started: bool,
    placement_complete: bool,
    recovery_origin: Option<std::sync::Arc<()>>,
    placement_progress: serde_json::Value,
    system_identities: BTreeMap<Vec<String>, Vec<u8>>,
    // Actual source ordinals of constructor-owned SVI directories. These are
    // enrolled with metadata handles during parent-first private allocation.
    system_directory_indices: Vec<usize>,
    system_payloads_started: bool,
    system_payloads_complete: bool,
    // Constructor-owned identity anchors, never reconstructed from a report.
    // Directories/root stay open without DELETE sharing for the whole session.
    metadata_targets: BTreeMap<usize, File>,
    metadata_input_sha256: [u8; 32],
    metadata_object_limit: usize,
    metadata_resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    construction_enrollment: Option<serde_json::Value>,
    // All tree-owned maps, handles and receipts drop before returning RAM.
    memory: Option<memory::Owner>,
}

#[derive(Clone, Serialize)]
struct MaterializedTail {
    scope: &'static str,
    object_index: usize,
    stream_name_utf16: Vec<u16>,
    logical_length: u64,
    offset: u64,
    bytes: u64,
    sha256: String,
    readback_verified: bool,
    native_file_id: Vec<u8>,
    source_prefix_contents_verified: bool,
}

fn register_sparse(
    root: &str,
    directory: &Option<sparse_stream::CarrierDirectory>,
    key: StreamKey,
    target: sparse_stream::Target,
    files: &mut BTreeMap<StreamKey, unwritten::PrivatePlaceholder>,
    targets: &mut BTreeMap<StreamKey, sparse_stream::Target>,
    partition: u64,
) -> io::Result<()> {
    if target.dense_length != 0 {
        let dir = directory
            .as_ref()
            .ok_or_else(|| invalid("sparse carrier directory missing"))?;
        let mut hash = Sha256::new();
        for unit in &key.name_utf16 {
            hash.update(unit.to_le_bytes());
        }
        let name = format!(
            "carrier-{}-{}.bin",
            key.object_index,
            hex::encode(hash.finalize())
        );
        let carrier = unwritten::PrivatePlaceholder::allocate_carrier(
            root,
            &[dir.component.clone(), name],
            target.dense_length,
            partition,
        )?;
        files.insert(key.clone(), carrier);
    }
    targets.insert(key, target);
    Ok(())
}

impl PrivateTree {
    /// Records an already completed native allocation. This compact observation
    /// is not an ownership token and cannot recreate a native tree on resume.
    pub fn allocation_observation(&self) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        let observation = serde_json::json!({
            "kind":"native-private-shadow-allocation-v1",
            "pair":self.pair,
            "input_sha256":hex::encode(self.metadata_input_sha256),
            "objects":self.metadata_object_limit,
            "streams":self.files.len(),
            "system_objects":self.system_identities.len(),
            "allocation_ram_accounted":self.allocation_ram_accounted(),
            "source_payload_writes":0,
            "conversion_authorized":false,
        });
        self.require_source_excluded()?;
        Ok(observation)
    }

    pub fn attach_backing_resource_guard(&mut self,
        guard: std::sync::Arc<crate::managed_shadow::BackingResourceGuard>) -> io::Result<()> {
        if self.backing_guard.is_some() {
            return Err(invalid("private tree backing capacity owner already attached"));
        }
        guard.require_binding(&self.pair.shadow)?;
        guard.check_before_operation(0)?;
        self.backing_guard = Some(guard);
        Ok(())
    }

    pub(super) fn before_backing_mutation(&self, operation_bytes: u64) -> io::Result<()> {
        if let Some(guard) = &self.backing_guard {
            guard.require_binding(&self.pair.shadow)?;
            guard.check_before_operation(operation_bytes)?;
        }
        Ok(())
    }

    fn record_materialized_tail(
        &mut self,
        key: &StreamKey,
        logical_length: u64,
        offset: u64,
        bytes: &[u8],
        native_file_id: Vec<u8>,
    ) -> io::Result<()> {
        let prefix = logical_length / 4096 * 4096;
        if prefix == 0 || prefix == logical_length || offset > prefix {
            return Ok(());
        }
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return Ok(());
        };
        if end < logical_length {
            return Ok(());
        }
        let start = (prefix - offset) as usize;
        let stop = (logical_length - offset) as usize;
        if let Some(memory) = &self.memory {
            memory.tail(key)?;
        }
        self.materialized_tails.insert(
            key.clone(),
            MaterializedTail {
                scope: "constructor-owned-plain-tail-materialization-v1",
                object_index: key.object_index,
                stream_name_utf16: key.name_utf16.clone(),
                logical_length,
                offset: prefix,
                bytes: logical_length - prefix,
                sha256: hex::encode(Sha256::digest(&bytes[start..stop])),
                readback_verified: true,
                native_file_id,
                source_prefix_contents_verified: false,
            },
        );
        Ok(())
    }

    fn require_materialized_tail(
        &self,
        key: &StreamKey,
        item: &Input<'_>,
    ) -> io::Result<Option<MaterializedTail>> {
        let length = item.logical_length();
        let prefix = length / 4096 * 4096;
        if item.expected_sha256.is_some() || length == prefix {
            return Ok(None);
        }
        if prefix == 0 || item.sparse.is_some() {
            return Err(invalid(
                "digest-free partial stream has no plain source prefix",
            ));
        }
        let proof = self
            .materialized_tails
            .get(key)
            .ok_or_else(|| invalid("digest-free partial stream tail was not materialized"))?;
        let handle = if let Some(target) = self.sparse_targets.get(key) {
            if target.sparse_mode {
                return Err(invalid("digest-free sparse tail is outside this profile"));
            }
            &target.file
        } else {
            self.files
                .get(key)
                .ok_or_else(|| invalid("materialized tail file absent"))?
                .metadata_handle()
        };
        if proof.logical_length != length
            || proof.offset != prefix
            || proof.bytes != length - prefix
            || proof.native_file_id != info(handle, 18, 24)?
        {
            return Err(invalid(
                "digest-free materialized tail identity/range differs",
            ));
        }
        Ok(Some(proof.clone()))
    }

    fn placement_view<'a>(&self, input: &'a [Input<'_>], key: &StreamKey) -> io::Result<Input<'a>> {
        let item = streams::view(input, key)?;
        if let Some(target) = self.sparse_targets.get(key) {
            target.placement_view(item)
        } else {
            Ok(item)
        }
    }
    fn placement_view_object<'a>(
        &self,
        object: &'a Input<'_>,
        key: &StreamKey,
    ) -> io::Result<Input<'a>> {
        let item = streams::view_object(object, &key.name_utf16)?;
        if let Some(target) = self.sparse_targets.get(key) {
            target.placement_view(item)
        } else {
            Ok(item)
        }
    }
    fn finish_sparse_streams(
        &mut self,
    ) -> io::Result<(
        BTreeMap<StreamKey, File>,
        Vec<(StreamKey, sparse_stream::TailProof)>,
    )> {
        let mut result = BTreeMap::new();
        let mut tails = Vec::new();
        for (key, target) in std::mem::take(&mut self.sparse_targets) {
            self.before_backing_mutation(4096)?;
            let (file, tail) = target.finish(self.files.remove(&key))?;
            if let Some(tail) = tail {
                tails.push((key.clone(), tail));
            }
            result.insert(key, file);
        }
        if let Some(directory) = self.carrier_directory.take() {
            self.before_backing_mutation(0)?;
            directory.retire()?;
        }
        self.before_backing_mutation(0)?;
        self.volume.sync_all()?;
        Ok((result, tails))
    }
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
    fn place_slot_with_evidence(
        &mut self,
        slot: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
        guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        let key = self
            .stream_slots
            .get(&slot)
            .cloned()
            .ok_or_else(|| invalid("stream placement slot absent"))?;
        self.place_named_with_evidence(key.object_index, &key.name_utf16, vcn, lcn, clusters, guard)
    }
    fn reposition_slot_with_evidence(
        &mut self,
        slot: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
        guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        let key = self
            .stream_slots
            .get(&slot)
            .cloned()
            .ok_or_else(|| invalid("stream placement slot absent"))?;
        self.reposition_named_with_evidence(
            key.object_index,
            &key.name_utf16,
            vcn,
            lcn,
            clusters,
            guard,
        )
    }

    fn move_slot_resource_with_evidence(
        &mut self,
        slot: usize,
        vcn: u64,
        lcn: u64,
        clusters: u32,
        reposition: bool,
        guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
    ) -> io::Result<unwritten::ResourceMoveValue> {
        self.require_source_excluded()?;
        self.before_backing_mutation(u64::from(clusters) * 4096)?;
        if self.metadata_resource_admission.is_none() || self.memory.is_none() {
            return Err(invalid("actual resource construction owner absent"));
        }
        self.placement_complete = false;
        self.original_coordinates.clear();
        let key = self
            .stream_slots
            .get(&slot)
            .ok_or_else(|| invalid("resource stream slot absent"))?;
        let file = self
            .files
            .get_mut(key)
            .ok_or_else(|| invalid("resource placeholder absent"))?;
        if !file.resource_placement_enabled() {
            return Err(invalid("resource placeholder not enrolled"));
        }
        let proof = if reposition {
            file.reposition_with_evidence(&self.volume, vcn, lcn, clusters, guard)
        } else {
            file.place_with_evidence(&self.volume, vcn, lcn, clusters, guard)
        };
        self.require_source_excluded()?;
        proof?.into_resource_value()
    }
    /// Complete metadata only on this owning disposable maintenance session.
    /// Consumes the owner even on partial failure: no retry/placement authority
    /// is returned. Source-backed prefixes are not logical-content verified by
    /// this operation, and the returned diagnostic grants no write authority.
    pub fn complete_source_metadata_domain(
        self,
        input: &impl InputDomain,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<serde_json::Value> {
        metadata::complete_domain(self, input, same_security)
    }

    /// Complete source metadata plus separately derived Windows alias paths.
    /// Canonical input identities/counts are unchanged. Only the actual bound
    /// OfflineWindows source and constructor-owned ReFS shadow are admitted.
    pub fn complete_source_metadata_windows_aliases_domain(
        self,
        input: &impl InputDomain,
        aliases: &impl super::windows_aliases::WindowsAliasInputDomain,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<(serde_json::Value, super::windows_aliases::VerifiedWindowsAliases)> {
        metadata::complete_windows_aliases_domain(self, input, aliases, same_security)
    }

    /// Explicit Windows-only provisional construction. Trust ACEs are retained
    /// in the original expectation domain while temporary audit placeholders
    /// permit native metadata construction. The returned report is provisional;
    /// raw repair and strict original native readback are still required.
    pub fn complete_source_metadata_windows_aliases_domain_with_security_placeholders(
        self,
        input: &impl InputDomain,
        aliases: &impl super::windows_aliases::WindowsAliasInputDomain,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<(serde_json::Value, super::windows_aliases::VerifiedWindowsAliases)> {
        metadata::complete_windows_aliases_domain_with_security_placeholders(self, input, aliases, same_security)
    }

    pub fn materialize_system_payloads_domain(
        &mut self,
        input: &impl InputDomain,
        writer: &mut dyn FnMut(usize, &mut File) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        self.require_bound_input_domain(input)?;
        system_payloads::run_domain(self, input, writer)
    }

    pub fn place_source_prefixes_domain(
        &mut self,
        input: &impl InputDomain,
        bytes: u64,
        moves: usize,
    ) -> io::Result<serde_json::Value> {
        placement::run_domain(self, input, bytes, moves)
    }

    /// V4 resource-derived placement with complete paged evidence retained by
    /// the caller. This cannot be selected by a legacy profile or JSON flag.
    pub fn place_source_prefixes_resource_domain(
        &mut self,
        input: &impl InputDomain,
        bytes: u64,
        moves: usize,
        evidence: &mut dyn PlacementEvidenceSink,
    ) -> io::Result<ResourcePlacementReport> {
        placement::run_resource_domain(self, input, bytes, moves, evidence)
    }

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
        let backing_guard = self.backing_guard.clone();
        for file in self.files.values_mut() {
            let prefix = file.logical_length() / 4096 * 4096;
            if prefix > 0 && !file.revalidate_recovered_prefix(prefix)? {
                if let Some(guard) = &backing_guard { guard.check_before_operation(0)?; }
                file.advance_valid_data(prefix, true).map_err(|e|io::Error::new(e.kind(),
                    format!("source-backed prefix initialization failed: path={:?}, prefix={prefix}: {e}",file.path)))?;
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
    /// Observe real allocation/storage readiness without reading scratch data.
    /// This proves no source contents and grants no conversion authority.
    pub fn observe_routed_prefix_named(
        &self,
        index: usize,
        name: &[u16],
        components: &[String],
        logical_length: u64,
        prefix: u64,
    ) -> io::Result<RoutedPrefixReady> {
        routed_prefix::observe(self, index, name, components, logical_length, prefix)
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
        let key=self.validate_stream_shape_metadata(index,name,components,length)?;
        self.files.get(&key).map_or(Ok(()),|file|file.check_placements())
    }
    /// Metadata half of the existing stream check. Only the scoped read-only
    /// snapshot pairs it with its same-FileObject complete-map observation.
    fn validate_stream_shape_metadata(
        &self,index:usize,name:&[u16],components:&[String],length:u64,
    )->io::Result<StreamKey>{
        let key = StreamKey::named(index, name);
        if let Some(target) = self.sparse_targets.get(&key) {
            if target.path != streams::path(&self.pair.shadow.volume_path()?, components, name)?
                || target.logical_length != length
            {
                return Err(invalid("sparse stream identity differs"));
            }
            if let Some(file) = self.files.get(&key) {
                if file.logical_length() != target.dense_length {
                    return Err(invalid("sparse carrier length differs"));
                }
            } else if target.dense_length != 0 {
                return Err(invalid("sparse carrier missing"));
            }
            return Ok(key);
        }
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
        Ok(key)
    }

    /// One immutable native supply observation. The callback cannot mutate
    /// this tree, and native/file/source closing checks precede its output.
    pub fn with_readonly_supply_stream_snapshot<T>(
        &self,index:usize,name:&[u16],components:&[String],logical:u64,maximum_range_bytes:u64,
        consume:impl FnOnce(&NativeReadOnlySupplyStreamSnapshot<'_>)->io::Result<T>,
    )->io::Result<T>{
        supply_snapshot::with_snapshot(self,index,name,components,logical,maximum_range_bytes,consume)
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
            return Err(invalid("live complete placement required for sparse read"));
        }
        if let Some(target) = self.sparse_targets.get(&key) {
            let parts = target.parts(offset, output.len() as u64, false)?;
            if parts.iter().any(|part| {
                self.original_coordinates.get(&key).is_some_and(|ranges| {
                    ranges.iter().any(|(start, _, length)| {
                        part.dense < *start + *length && *start < part.dense + part.length
                    })
                })
            }) {
                return Err(invalid("sparse shadow read overlaps retained source bytes"));
            }
            let file = self
                .files
                .get_mut(&key)
                .ok_or_else(|| invalid("sparse materialization carrier absent"))?;
            for part in parts {
                let local = (part.logical - offset) as usize;
                file.read_initialized_at(
                    part.dense,
                    &mut output[local..local + part.length as usize],
                )?;
            }
            return Ok(());
        }
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
    /// Recheck this actual constructor's immutable input identity once per
    /// supply/verification phase; no deserialized plan grants this binding.
    pub fn validate_input_domain(&self, input: &impl InputDomain) -> io::Result<()> {
        self.require_source_excluded()?;
        self.require_bound_input_domain(input)
    }
    /// Obtain a conservative pre-query bound from the actual retained stream.
    /// This getter allocates nothing and grants no stream-validity authority.
    pub fn supply_stream_workspace_bytes(
        &self,
        object_index: usize,
        name: &[u16],
    ) -> io::Result<u64> {
        supply::workspace_bytes(self, object_index, name)
    }

    /// Observe one live private stream in logical order, including sparse holes.
    /// No whole-tree plan or retained callback row collection is constructed.
    pub fn visit_supply_stream_named(
        &self,
        object_index: usize,
        name: &[u16],
        components: &[String],
        logical_length: u64,
        visitor: impl FnMut(SupplyKind, &SupplyRange) -> io::Result<()>,
    ) -> io::Result<StreamSupplySummary> {
        self.validate_stream_shape_named(object_index, name, components, logical_length)?;
        let summary = supply::stream(self, &StreamKey::named(object_index, name), visitor)?;
        if summary.logical_bytes != logical_length {
            return Err(invalid(
                "live supply stream length differs from canonical input",
            ));
        }
        self.validate_stream_shape_named(object_index, name, components, logical_length)?;
        Ok(summary)
    }
    /// This flag is set only after the owning system-supply operation's native
    /// readback. Serialized receipts cannot mark an incomplete phase complete.
    pub fn require_system_payloads_complete(&self) -> io::Result<()> {
        self.require_source_excluded()?;
        if !self.system_payloads_complete {
            return Err(invalid("actual owning system payload supply is incomplete"));
        }
        Ok(())
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
        self.place_named_with_evidence(object_index, name, vcn, lcn, clusters, |_| Ok(()))
    }

    fn place_named_with_evidence(
        &mut self,
        object_index: usize,
        name: &[u16],
        vcn: u64,
        lcn: u64,
        clusters: u32,
        guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        self.before_backing_mutation(u64::from(clusters) * 4096)?;
        self.placement_complete = false;
        self.original_coordinates.clear();
        let file = self
            .files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private user file absent"))?;
        let proof = file.place_with_evidence(&self.volume, vcn, lcn, clusters, guard);
        self.require_source_excluded()?;
        serde_json::to_value(proof?).map_err(io::Error::other)
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
        self.reposition_named_with_evidence(object_index, name, vcn, lcn, clusters, |_| Ok(()))
    }

    fn reposition_named_with_evidence(
        &mut self,
        object_index: usize,
        name: &[u16],
        vcn: u64,
        lcn: u64,
        clusters: u32,
        guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        self.require_source_excluded()?;
        self.before_backing_mutation(u64::from(clusters) * 4096)?;
        self.placement_complete = false;
        self.original_coordinates.clear();
        let file = self
            .files
            .get_mut(&StreamKey::named(object_index, name))
            .ok_or_else(|| invalid("private reposition file absent"))?;
        let proof = file.reposition_with_evidence(&self.volume, vcn, lcn, clusters, guard);
        self.require_source_excluded()?;
        serde_json::to_value(proof?).map_err(io::Error::other)
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
        let key = StreamKey::named(object_index, name);
        if let Some(target) = self.sparse_targets.get(&key) {
            if target.dense_length == 0 {
                return Ok(());
            }
            if self
                .files
                .get(&key)
                .is_none_or(|f| f.valid_prefix() != target.dense_length)
            {
                return Err(invalid(
                    "sparse carrier must be prepared as dense data first",
                ));
            }
            return Ok(());
        }
        self.before_backing_mutation(0)?;
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
        let key = StreamKey::named(object_index, name);
        if let Some(target) = self.sparse_targets.get(&key) {
            if target.dense_length != 0
                && self
                    .files
                    .get(&key)
                    .is_none_or(|f| f.valid_prefix() != target.dense_length)
            {
                return Err(invalid("sparse carrier is not prepared"));
            }
            return Ok(
                serde_json::json!({"object_index":object_index,"stream_name_utf16":name,"sparse_carrier_prepared":true}),
            );
        }
        self.before_backing_mutation(0)?;
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
        let _working = self
            .memory
            .as_ref()
            .map(|m| m.materialization(bytes.len(), 0))
            .transpose()?;
        let key = StreamKey::named(object_index, name);
        self.require_source_excluded()?;
        let write_end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("materialization range overflow"))?;
        if self
            .materialized_tails
            .get(&key)
            .is_some_and(|proof| offset < proof.offset + proof.bytes && proof.offset < write_end)
        {
            self.materialized_tails.remove(&key);
        }
        if let Some(target) = self.sparse_targets.get(&key) {
            let _island_memory = self
                .memory
                .as_ref()
                .map(|m| {
                    let count = target
                        .islands
                        .len()
                        .min(bytes.len().div_ceil(4096).saturating_add(2));
                    m.working(
                        (count as u64)
                            .checked_mul(1024)
                            .ok_or_else(|| invalid("private island RAM overflow"))?,
                    )
                })
                .transpose()?;
            let end = offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("sparse materialization range overflow"))?;
            if target.logical_length != logical_length
                || target.path != streams::path(&self.pair.shadow.volume_path()?, components, name)?
                || bytes.len() > 65536
                || end > logical_length
            {
                return Err(invalid("sparse materialization identity differs"));
            }
            // A bounded logical request may span real data islands and holes.
            // Only intersections with allocated islands can be written. Hole
            // bytes must be zero and never cause carrier allocation or writes.
            let parts: Vec<_> = target
                .islands
                .iter()
                .filter_map(|island| {
                    let start = offset.max(island.logical);
                    let stop = end.min(island.logical + island.length);
                    (start < stop).then(|| sparse_stream::Island {
                        logical: start,
                        dense: island.dense + start - island.logical,
                        length: stop - start,
                    })
                })
                .collect();
            let mut allocated = vec![false; bytes.len()];
            for part in &parts {
                let local = (part.logical - offset) as usize;
                allocated[local..local + part.length as usize].fill(true);
            }
            if bytes
                .iter()
                .zip(&allocated)
                .any(|(&byte, &is_allocated)| !is_allocated && byte != 0)
            {
                return Err(invalid(
                    "nonzero materialization bytes target a sparse hole",
                ));
            }
            if self.placement_complete
                && parts.iter().any(|part| {
                    self.original_coordinates.get(&key).is_some_and(|ranges| {
                        ranges.iter().any(|(start, _, length)| {
                            part.dense < *start + *length && *start < part.dense + part.length
                        })
                    })
                })
            {
                return Err(invalid(
                    "sparse materialization overlaps retained source reference",
                ));
            }
            let mut proofs = Vec::new();
            let mut readback = vec![0u8; bytes.len()];
            if !parts.is_empty() {
                let backing_guard = self.backing_guard.clone();
                let file = self
                    .files
                    .get_mut(&key)
                    .ok_or_else(|| invalid("sparse materialization carrier absent"))?;
                for part in parts {
                    let local = (part.logical - offset) as usize;
                    let stop = local + part.length as usize;
                    if let Some(guard) = &backing_guard { guard.check_before_operation(part.length)?; }
                    proofs.push(file.initialize_at(part.dense, &bytes[local..stop])?);
                    file.read_initialized_at(part.dense, &mut readback[local..stop])?;
                }
            }
            if readback != bytes {
                return Err(invalid("sparse logical materialization readback differs"));
            }
            let sha256 = hex::encode(Sha256::digest(&readback));
            let hole_bytes = allocated.iter().filter(|&&value| !value).count();
            let native_file_id = info(&target.file, 18, 24)?;
            let plain = !target.sparse_mode;
            self.require_source_excluded()?;
            if plain {
                self.record_materialized_tail(&key, logical_length, offset, bytes, native_file_id)?;
            }
            return Ok(
                serde_json::json!({"object_index":object_index,"stream_name_utf16":name,
                    "offset":offset,"bytes":bytes.len(),"sha256":sha256,"readback_verified":true,
                    "logical_hole_bytes":hole_bytes,"parts":proofs,"conversion_qualified":false}),
            );
        }
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
        self.before_backing_mutation(bytes.len() as u64)?;
        let file = self
            .files
            .get_mut(&key)
            .ok_or_else(|| invalid("private materialization file absent"))?;
        if file.path != expected_path || file.logical_length() != logical_length {
            return Err(invalid("private materialization object binding differs"));
        }
        let proof = file.initialize_at(offset, bytes)?;
        let native_file_id = info(file.metadata_handle(), 18, 24)?;
        self.require_source_excluded()?;
        self.record_materialized_tail(&key, logical_length, offset, bytes, native_file_id)?;
        Ok(proof)
    }

    /// Scoped to allocation containers and materialize_range calls. Placement,
    /// enrollment and final metadata/system stages are not covered by this bit.
    pub fn allocation_ram_accounted(&self) -> bool {
        self.memory.is_some()
    }

    pub fn source_binding(&self) -> &GeneralDiskBinding {
        &self.pair.source
    }

    fn require_source_excluded(&self) -> io::Result<()> {
        if let Some(admission) = self.metadata_resource_admission {
            admission.validate()?;
            let held = (self.files.len() as u64)
                .checked_add(self.sparse_targets.len() as u64)
                .and_then(|n| n.checked_add(self.metadata_targets.len() as u64))
                .and_then(|n| n.checked_add(u64::from(self.carrier_directory.is_some())))
                .and_then(|n| n.checked_add(u64::from(self.dedicated_source.is_some())))
                // Volume, privilege leases and temporary native control opens.
                .and_then(|n| n.checked_add(8))
                .ok_or_else(|| invalid("native owned handle count overflow"))?;
            if held > admission.budget.handle_slots {
                return Err(invalid(
                    "actual native owner handles exceed admitted resource budget",
                ));
            }
        }
        let mut events = Vec::new();
        let result = (|| {
            if let Some(lease)=&self.partition_source{
                lease.check_shadow_operation(&mut events)?;
            }else if let Some(lease)=&self.dedicated_source{
                lease.check_shadow_operation(&self.pair, &self.source_before, &mut events)?;
            }else{
                self.source_before.require(&self.pair,None,&mut events)?;
            }
            if native::observe_general_disk_state_readonly(self.pair.shadow.clone(), &mut events)?
                .disk_attributes
                != 0
            {
                return Err(invalid(
                    "private tree source exclusion or shadow state changed",
                ));
            }
            Ok(())
        })();
        if let Some(lease) = &self.partition_source {
            let witness=lease.witness();
            let drained = witness.checkpoint_native_events(
                "partition-private-tree-source-shadow-check",
                &mut events,
            );
            match (result, drained) {
                (Err(error), Err(checkpoint)) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; private-tree event checkpoint also failed: {checkpoint}"),
                )),
                (Err(error), _) | (_, Err(error)) => Err(error),
                (Ok(()), Ok(())) => Ok(()),
            }
        } else {
            result
        }
    }

    // Only the new whole-disk Windows SHADOW lease adds these explicit full
    // critical-role fences. Legacy, unenrolled and partition paths are unchanged.
    fn require_dedicated_shadow_boundary(&self) -> io::Result<()> {
        if let Some(lease) = &self.dedicated_source {
            lease.revalidate_boundary(&self.pair, &self.source_before, &mut Vec::new())?;
        }
        Ok(())
    }

    fn require_bound_input(&self, input: &[Input<'_>]) -> io::Result<()> {
        self.require_bound_input_domain(&SliceInputs(input))
    }
    fn require_bound_input_domain(&self, input: &impl InputDomain) -> io::Result<()> {
        if let Some(admission) = self.metadata_resource_admission {
            input.require_resource_metadata(admission)?;
        }
        if metadata::input_digest_domain(input)? != self.metadata_input_sha256 {
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
    allocate_checked(pair, input, None, None)
}

/// Consume actual selected-device enrollment into the same owned constructor.
/// This does not issue source admission or authorize source raw writes.
pub fn allocate_enrolled(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &[Input<'_>],
) -> io::Result<PrivateTree> {
    enrollment.revalidate()?;
    let pair = enrollment.pair.clone();
    allocate_checked(&pair, input, Some(enrollment), None)
}

/// Count/metadata admission supplements actual selected-device enrollment. It
/// cannot replace enrollment, source isolation or a later source certificate.
pub fn allocate_enrolled_with_resource_profile(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &[Input<'_>],
    profile: crate::attestation::ResourceProfile,
) -> io::Result<PrivateTree> {
    enrollment.revalidate()?;
    let pair = enrollment.pair.clone();
    profile.count_admission()?;
    allocate_checked(&pair, input, Some(enrollment), Some(profile))
}

fn allocate_checked(
    pair: &GeneralSourceShadowBinding,
    input: &[Input<'_>],
    enrollment: Option<ConstructionEnrollment<'_>>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<PrivateTree> {
    allocate_domain(pair, &SliceInputs(input), enrollment, resource_profile)
}

/// Consume one authenticated object at a time while retaining all native
/// handles and the complete source-input fingerprint through completion.
pub fn allocate_enrolled_domain(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
) -> io::Result<PrivateTree> {
    enrollment.revalidate()?;
    profile.count_admission()?;
    let pair = enrollment.pair.clone();
    allocate_domain(&pair, input, Some(enrollment), Some(profile))
}

/// Explicit V4 allocation accounting. Enrollment observation, placement and
/// final metadata/system stages remain separate resource obligations.
pub fn allocate_enrolled_domain_with_memory(
    enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    memory: Arc<dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<PrivateTree> {
    let admission = profile
        .resource_admission()?
        .ok_or_else(|| invalid("accounted private allocation requires actual V4 admission"))?;
    let owner = memory::Owner::new(
        memory,
        input.len(),
        usize::try_from(admission.data_streams).map_err(io::Error::other)?,
        admission.budget.max_row_bytes,
    )?;
    let pair = enrollment.pair.clone();
    allocate_domain_with_memory(&pair, input, Some(enrollment), Some(profile), Some(owner))
}

pub fn allocate_enrolled_partition_domain_with_memory(
    enrollment: PartitionConstructionEnrollment,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    memory: Arc<dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<PrivateTree> {
    allocate_enrolled_domain_with_memory(enrollment.inner, input, profile, memory)
}

fn allocate_domain(
    pair: &GeneralSourceShadowBinding,
    input: &impl InputDomain,
    enrollment: Option<ConstructionEnrollment<'_>>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<PrivateTree> {
    allocate_domain_with_memory(pair, input, enrollment, resource_profile, None)
}

/// Descriptive eligibility only. No native handles, enrollment, write owner or
/// source-preservation proof is issued. Filesystem-dependent checks still run
/// in the actual constructor and final protected observations.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ConstructorInputPreflight {
    pub objects: usize,
    pub files: usize,
    pub directories: usize,
    pub data_streams: usize,
    pub logical_bytes: u64,
    pub preflight_index_bytes: Option<u64>,
    pub source_ranges: Option<usize>,
    pub system_payload: SystemPayloadInputPreflight,
}

/// Pure source-side system-stream eligibility. Existing formatter collisions
/// and actual system-file identities require the live constructor separately.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SystemPayloadInputPreflight {
    pub directories: usize,
    pub files: usize,
    pub logical_bytes: u64,
}

/// Independently check source system-stream eligibility even if another
/// constructor check refuses first. Live formatter collisions remain deferred.
pub fn preflight_system_payload_input_domain(
    input: &impl InputDomain,
) -> io::Result<SystemPayloadInputPreflight> {
    system_payloads::validate_input_domain(input, |_| false)
}

/// Run exactly the constructor's bounded input checks on a held immutable
/// domain. `volume_root` supplies path syntax/length only, not target identity.
/// Descriptor validation includes native in-memory SD/ACL validation; this
/// function never opens a device/volume/file or invokes a native setter.
pub fn preflight_resource_input_domain(
    input: &impl InputDomain,
    admission: crate::tree_resources::SourceResourceAdmission,
    partition_bytes: u64,
    volume_root: &str,
    memory: &dyn report_memory::ReportMemoryAccountant,
) -> io::Result<ConstructorInputPreflight> {
    admission.validate()?;
    if partition_bytes == 0 || !partition_bytes.is_multiple_of(4096)
        || partition_bytes > i64::MAX as u64
        || !volume_root.starts_with("\\\\?\\Volume{") || !volume_root.ends_with("}\\")
    {
        return Err(invalid("pure constructor geometry or volume-root syntax differs"));
    }
    let guid = &volume_root[11..volume_root.len() - 2];
    crate::layout::guid_bytes(guid)?;
    preflight_input_domain(
        input, partition_bytes, volume_root,
        Some(crate::attestation::ResourceProfile::ResourceBoundedV4(Some(admission))),
        Some(memory),
    )
}

fn preflight_input_domain(
    input: &impl InputDomain,
    partition_bytes: u64,
    resource_root: &str,
    resource_profile: Option<crate::attestation::ResourceProfile>,
    memory: Option<&dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<ConstructorInputPreflight> {
    let admission = resource_profile
        .map(crate::attestation::ResourceProfile::count_admission)
        .transpose()?
        .flatten();
    let resource_admission = resource_profile
        .map(crate::attestation::ResourceProfile::resource_admission)
        .transpose()?
        .flatten();
    if let Some(value) = resource_admission {
        input.require_resource_metadata(value)?;
    }
    if let Some(value) = admission.filter(|value| value.requires_paged_metadata()) {
        input.require_paged_metadata(
            value.expected_page_budget()?,
            u64::from(value.maximum_expected_tree_bytes),
        )?;
    }
    let maximum_objects = if let Some(value) = resource_admission {
        usize::try_from(value.objects()?).map_err(io::Error::other)?
    } else {
        admission.map_or(1280, |value| value.object_slots as usize)
    };
    let maximum_streams = resource_admission
        .map(|value| usize::try_from(value.data_streams).map_err(io::Error::other))
        .transpose()?
        .unwrap_or(streams::MAX_STREAMS);
    if memory.is_some() && resource_admission.is_none() {
        return Err(invalid(
            "accounted private allocation requires actual V4 admission",
        ));
    }
    let preflight_plan = memory
        .map(|_| super::domain_memory::input_plan(input))
        .transpose()?;
    let preflight_ram = match (memory, &preflight_plan) {
        (Some(memory), Some(plan)) => Some(memory.reserve(plan.preflight_bytes)?),
        _ => None,
    };
    if input.is_empty() || input.len() > maximum_objects {
        return Err(invalid("private tree root or object bound differs"));
    }
    if let Some(admission) = resource_admission {
        super::hard_links::validate_resource_domain(
            input,
            admission.maximum_namespace_names()?,
            resource_root,
            crate::shadow_names::valid_unicode_component,
        )?;
    } else {
        super::hard_links::validate_domain(
            input,
            super::hard_links::MAX_NAMES,
            crate::shadow_names::valid_unicode_component,
        )?;
    }
    let mut stream_count = 0usize;
    input.for_each(|_, item| {
        stream_count = stream_count
            .checked_add(usize::from(!item.directory))
            .and_then(|count| count.checked_add(item.named_streams.len()))
            .filter(|count| *count <= maximum_streams)
            .ok_or_else(|| invalid("constructor complete stream domain exceeds bound"))?;
        if resource_admission.is_some() {
            streams::validate_resource(
                std::slice::from_ref(item),
                partition_bytes,
                maximum_streams,
            )
        } else {
            streams::validate(
                std::slice::from_ref(item),
                partition_bytes,
            )
        }
    })?;
    let root_owner = if input.is_empty() {
        return Err(invalid("private tree root or object bound differs"));
    } else {
        input.object(0)?
    };
    let root_input = root_owner.input();
    if input.is_empty()
        || input.len() > maximum_objects
        || !root_input.directory
        || !root_input.components.is_empty()
    {
        return Err(invalid("private tree root or object bound differs"));
    }
    drop(root_input);
    drop(root_owner);
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut total = 0u64;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
        if !basic_input_allowed(&item) {
            return Err(invalid("owning metadata input outside bounded source profile"));
        }
        let key = crate::shadow_names::conservative_path_key(item.components);
        if resource_admission.map_or(item.components.len() > 16, |_| {
            !super::hard_links::resource_path_valid(resource_root, item.components)
        }) || item
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
        if let Some(a) = resource_admission {
            descriptor_with_limit(item.security, a.budget.max_row_bytes)?;
        } else {
            descriptor(item.security)?;
        }
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
    if let Some(admission) = admission {
        admission.validate_tree(
            input.len() - directories.len(),
            directories.len(),
            stream_count,
        )?;
        admission.validate_constructor_metadata(&DomainMetadata(input))?;
    }
    if let Some(admission) = resource_admission {
        admission.validate_tree(
            (input.len() - directories.len()) as u64,
            directories.len() as u64,
            stream_count as u64,
        )?;
        admission.validate_constructor_metadata(&DomainMetadata(input))?;
    }
    if total > partition_bytes
        || (admission.is_none()
            && resource_admission.is_none()
            && (directories.len() > 256 || input.len() - directories.len() > 1024))
    {
        return Err(invalid("private tree geometry or object budget exceeded"));
    }
    let result = ConstructorInputPreflight {
        objects: input.len(),
        files: input.len() - directories.len(),
        directories: directories.len(),
        data_streams: stream_count,
        logical_bytes: total,
        preflight_index_bytes: preflight_plan.as_ref().map(|plan| plan.preflight_bytes),
        source_ranges: preflight_plan.as_ref().map(|plan| plan.source_ranges),
        system_payload: system_payloads::validate_input_domain(input, |_| false)?,
    };
    drop(names);
    drop(directories);
    drop(preflight_ram);
    Ok(result)
}

fn allocate_domain_with_memory(
    pair: &GeneralSourceShadowBinding,
    input: &impl InputDomain,
    enrollment: Option<ConstructionEnrollment<'_>>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
    memory: Option<memory::Owner>,
) -> io::Result<PrivateTree> {
    input.require_mutation_binding(&pair.shadow)?;
    let payer = memory.as_ref().map(|owner| owner.payer());
    let resource_root = format!("{}\\", pair.shadow.volume_path()?);
    preflight_input_domain(
        input, pair.shadow.identity.partition_bytes, &resource_root,
        resource_profile, payer.as_deref(),
    )?;
    let resource_admission = resource_profile
        .map(crate::attestation::ResourceProfile::resource_admission)
        .transpose()?
        .flatten();
    let maximum_objects = if let Some(value) = resource_admission {
        usize::try_from(value.objects()?).map_err(io::Error::other)?
    } else {
        resource_profile.map(crate::attestation::ResourceProfile::count_admission)
            .transpose()?.flatten().map_or(1280, |value| value.object_slots as usize)
    };
    let mut events = Vec::new();
    let dedicated_source = match (resource_admission, payer.as_deref(), enrollment.as_ref()) {
        (Some(_), Some(payer), Some(owned))
            if pair.source.layout_profile == crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows => {
            match &owned.source {
                source_scope::ConstructionSource::Dedicated(source) => Some(
                    source_scope::DedicatedShadowConstructionLease::begin(
                        source, pair, &owned.source_before, payer, &mut events,
                    )?,
                ),
                source_scope::ConstructionSource::Partition(_) => None,
            }
        }
        _ => None,
    };
    let opening = (|| {
        let source_before = if let (Some(lease), Some(owned)) = (&dedicated_source, enrollment.as_ref()) {
            lease.check_shadow_operation(pair, &owned.source_before, &mut events)?;
            owned.source_before.clone()
        } else if let Some(owned) = enrollment
            .as_ref()
            .filter(|owned| owned.source.partition().is_some())
        {
            owned
                .source_before
                .require(pair, owned.source.partition(), &mut events)?;
            owned.source_before.clone()
        } else {
            let source =
                native::observe_general_disk_state_readonly(pair.source.clone(), &mut events)?;
            if source.disk_attributes != 3 {
                return Err(invalid("excluded dedicated source required"));
            }
            source_scope::ConstructionSourceState::Dedicated(source)
        };
        if native::observe_general_disk_state_readonly(pair.shadow.clone(), &mut events)?
            .disk_attributes
            != 0
            || native::mounted_filesystem_general(pair.shadow.clone(), &mut events)? != "ReFS"
        {
            return Err(invalid("excluded source and writable ReFS shadow required"));
        }
        Ok(source_before)
    })();
    let source_before = if let Some(witness) = enrollment
        .as_ref()
        .and_then(|owned| owned.source.partition())
    {
        let drained =
            witness.checkpoint_native_events("partition-private-allocation-opening", &mut events);
        match (opening, drained) {
            (Ok(value), Ok(())) => value,
            (Err(error), Err(checkpoint)) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; allocation opening checkpoint also failed: {checkpoint}"),
                ));
            }
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }
    } else {
        opening?
    };
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
    let (privileges, root_handle, enrolled_volume, construction_enrollment, partition_source) =
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
                owned.source.into_partition(),
            )
        } else {
            let privileges = Privileges::enable_for(&[
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeSecurityPrivilege",
                "SeManageVolumePrivilege",
            ])?;
            (privileges, open(&root, true, true)?, None, None, None)
        };
    let reparse_privileges =
        if input.any(|item| item.reparse.is_some_and(|point| point.tag() == 0xa000000c))? {
            Some(Privileges::enable_for(&["SeCreateSymbolicLinkPrivilege"])?)
        } else {
            None
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
    }) && !input.any(|i| i.directory && i.components == ["System Volume Information"])?
    {
        return Err(invalid(
            "existing system namespace must be explicitly represented",
        ));
    }
    // Reuse the existing narrow formatter-cache preflight; unknown SVI entries
    // refuse. Target-only IndexerVolumeGuid normalization is already scoped to
    // these enrolled disks and never touches the excluded source.
    let system = existing_system_entries_domain(&root, &initial, input, true, &mut events);
    let mut system_identities = if let Some(lease) = &partition_source {
        let witness=lease.witness();
        let drained = witness
            .checkpoint_native_events("partition-private-allocation-global-queries", &mut events);
        match (system, drained) {
            (Ok(value), Ok(())) => value,
            (Err(error), Err(checkpoint)) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; allocation global checkpoint also failed: {checkpoint}"),
                ));
            }
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }
    } else {
        system?
    };
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
    let mut sparse_targets = BTreeMap::new();
    let needs_carriers = input.any(|item| {
        item.sparse.is_some_and(|s| !s.allocated.is_empty())
            || item.named_streams.iter().any(|s| {
                (s.sparse.is_none() && s.expected_length >= 4096)
                    || s.sparse.is_some_and(|v| !v.allocated.is_empty())
            })
    })?;
    // The formatter's root would hand its ACL auto-inherit flags to every
    // object created below it; clear them before the first creation.
    input.before_mutation(0)?;
    super::cache_refresh::clear_acl_auto_inheritance(&root_handle)?;
    let carrier_directory = if needs_carriers {
        input.before_mutation(0)?;
        Some(sparse_stream::CarrierDirectory::create(&root)?)
    } else {
        None
    };
    let mut metadata_targets = BTreeMap::new();
    metadata_targets.insert(0, root_handle);
    let allocation_progress = |pass, completed| input.progress(crate::progress::Update::new(
        crate::progress::Phase::ShadowAllocation, crate::progress::Unit::Objects,
        completed, Some(input.len() as u64),
    ).with_pass(pass));
    // Pin every formatter object the constructor admitted. Subsequent system
    // supply must update these same objects, not a caller-selected path.
    // The loops below run inside a closure only so that a failure can name
    // the object it stopped on; their control flow is unchanged.
    let failing_object = std::cell::Cell::new(0usize);
    (|| -> io::Result<()> {
    for index in 0..input.len() {
        failing_object.set(index);
        allocation_progress(0, index as u64);
        let owner = input.object(index)?;
        let item = owner.input();
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
    Ok(())
    })()
    .map_err(|error| super::cache_refresh::at_object(input, "system object pinning", failing_object.get(), error))?;
    allocation_progress(0, input.len() as u64);
    // The same for every other formatter directory pinned above, such as
    // System Volume Information, before children are created inside it.
    for (index, handle) in &metadata_targets {
        if *index != 0 && input.object(*index)?.input().directory {
            input.before_mutation(0)?;
            super::cache_refresh::clear_acl_auto_inheritance(handle)
                .map_err(|error| super::cache_refresh::at_object(input, "formatter directory auto-inheritance reset", *index, error))?;
        }
    }
    let global_query_memory = memory
        .as_ref()
        .map(|m| {
            m.close_global_queries(
                pair,
                &source_before,
                &events,
                &system_identities,
                &construction_enrollment,
                &carrier_directory,
            )
        })
        .transpose()?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(input.len())
        .map_err(io::Error::other)?;
    if memory.is_some() && objects.capacity() > input.len().saturating_mul(2) {
        return Err(invalid("private object Vec exceeded prepaid capacity"));
    }
    // Reuse a private file's atomic descriptor to create private directories.
    // Its descriptor is constant rather than derived from source ACLs.
    let sd = private_descriptor()?;
    let mut system_directory_indices = Vec::new();
    (|| -> io::Result<()> {
    for index in 0..input.len() {
        failing_object.set(index);
        allocation_progress(1, index as u64);
        let owner = input.object(index)?;
        let item = owner.input();
        let row_memory = memory
            .as_ref()
            .map(|m| m.row_peak(&item).and_then(|n| m.working(n)))
            .transpose()?;
        let system = item
            .components
            .first()
            .is_some_and(|s| s == "System Volume Information");
        if system && item.directory {
            // Pure preflight admits only the SVI root and ordinary empty
            // immediate child directories. Global input order already proved
            // parents precede children; pin that exact held parent again.
            if item.components.len() == 2 {
                let parent_index = *system_directory_indices.first()
                    .ok_or_else(|| invalid("system child directory precedes its owned root"))?;
                let parent = metadata_targets.get(&parent_index)
                    .ok_or_else(|| invalid("owned system root metadata handle absent"))?;
                validate_open_type(parent, true)?;
                let parent_id = info(parent, 18, 24)?;
                let parent_components = &item.components[..1];
                if system_identities.get(parent_components)
                    .is_none_or(|id| parent_id[8..24] != *id)
                    || parent_id[..8] != info(&metadata_targets[&0], 18, 24)?[..8]
                {
                    return Err(invalid("owned system parent identity or volume differs"));
                }
            }
            if !system_identities.contains_key(item.components) {
                let private = Input {
                    components: item.components,
                    additional_names: &[],
                    directory: true,
                    times: item.times,
                    attributes: 16,
                    security: &sd,
                    expected_api_security: None,
                    extended_attributes: None,
                    reparse: None,
                    payload: &[],
                    expected_length: None,
                    expected_sha256: None,
                    source_offset: None,
                    source_runs: Vec::new(),
                    named_streams: Vec::new(),
                    sparse: None,
                };
                let path = format!("{root}{}", item.components.join("\\"));
                // Fresh-only CreateDirectory refuses every collision. Do not
                // merge, adopt, clear or delete an existing child directory.
                input.before_mutation(0)?;
                create(&path, &private, index, None)?;
                let handle = open(&path, true, true)?;
                let id = info(&handle, 18, 24)?;
                if id[..8] != info(&metadata_targets[&0], 18, 24)?[..8]
                    || system_identities.values().any(|old| old.as_slice() == &id[8..24])
                    || enumerate(&handle)?.iter().any(|entry|
                        entry.name_utf16 != [46] && entry.name_utf16 != [46, 46])
                {
                    return Err(invalid("fresh system directory identity or empty namespace differs"));
                }
                system_identities.insert(item.components.to_vec(), id[8..24].to_vec());
                if metadata_targets.insert(index, handle).is_some() {
                    return Err(invalid("duplicate system directory metadata ordinal"));
                }
            } else if !metadata_targets.contains_key(&index) {
                return Err(invalid("existing system directory lacks its constructor metadata handle"));
            }
            system_directory_indices.try_reserve_exact(1).map_err(io::Error::other)?;
            if system_directory_indices.capacity() > (system_directory_indices.len() + 1).saturating_mul(2) {
                return Err(invalid("system directory ordinal capacity exceeds paid state"));
            }
            system_directory_indices.push(index);
        }
        if item.components.is_empty() || system {
            objects.push(
                serde_json::json!({"object_index":index,"components":item.components,
                "disposition":"pending-system-or-root-metadata"}),
            );
            if let (Some(memory), Some(guard)) = (&memory, row_memory) {
                let mut retained = memory::object_bytes(
                        index,
                        &objects,
                        &files,
                        &sparse_targets,
                        &metadata_targets,
                    )?;
                if system && item.directory {
                    // Own the new identity-map key/ID and directory ordinal
                    // state in addition to object_bytes' metadata handle.
                    let path_bytes = item.components.iter().try_fold(0u64, |sum, part|
                        sum.checked_add(part.len() as u64)
                            .ok_or_else(|| invalid("system directory path RAM overflow")))?;
                    retained = retained.checked_add(8192)
                        .and_then(|n| n.checked_add(path_bytes.checked_mul(8)?))
                        .and_then(|n| n.checked_add((item.components.len() as u64).checked_mul(256)?))
                        .ok_or_else(|| invalid("system directory retained RAM overflow"))?;
                }
                memory.retain(guard, retained)?;
            }
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
                extended_attributes: None,
                reparse: None,
                payload: &[],
                expected_length: None,
                expected_sha256: None,
                source_offset: None,
                source_runs: vec![],
                named_streams: Vec::new(),
                sparse: None,
            };
            input.before_mutation(0)?;
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
            let key = StreamKey::unnamed(index);
            input.before_mutation(0)?;
            if let Some(layout) = item.sparse {
                let target = sparse_stream::Target::create(
                    &root,
                    item.components,
                    &[],
                    item.logical_length(),
                    layout,
                    None,
                )?;
                register_sparse(
                    &root,
                    &carrier_directory,
                    key.clone(),
                    target,
                    &mut files,
                    &mut sparse_targets,
                    pair.shadow.identity.partition_bytes,
                )?;
            } else {
                files.insert(
                    key.clone(),
                    unwritten::PrivatePlaceholder::allocate_named(
                        &root,
                        item.components,
                        item.logical_length(),
                        pair.shadow.identity.partition_bytes,
                    )?,
                );
            }
            for named in &item.named_streams {
                input.before_mutation(0)?;
                let base = if let Some(target) = sparse_targets.get(&key) {
                    &target.file
                } else {
                    files[&key].metadata_handle()
                };
                if let Some(layout) = named.sparse {
                    let target = sparse_stream::Target::create(
                        &root,
                        item.components,
                        named.name_utf16,
                        named.expected_length,
                        layout,
                        Some(base),
                    )?;
                    register_sparse(
                        &root,
                        &carrier_directory,
                        StreamKey::named(index, named.name_utf16),
                        target,
                        &mut files,
                        &mut sparse_targets,
                        pair.shadow.identity.partition_bytes,
                    )?;
                } else if named.expected_length >= 4096 {
                    // ReFS may report success for MOVE_FILE on an ADS without
                    // moving its extents. Place an ordinary owned carrier and
                    // clone its validated extents into the exact named stream.
                    let target = sparse_stream::Target::create_plain(
                        &root,
                        item.components,
                        named.name_utf16,
                        named.expected_length,
                        Some(base),
                    )?;
                    register_sparse(
                        &root,
                        &carrier_directory,
                        StreamKey::named(index, named.name_utf16),
                        target,
                        &mut files,
                        &mut sparse_targets,
                        pair.shadow.identity.partition_bytes,
                    )?;
                } else {
                    let stream = unwritten::PrivatePlaceholder::allocate_named_stream(
                        &root,
                        item.components,
                        named.name_utf16,
                        named.expected_length,
                        pair.shadow.identity.partition_bytes,
                        base,
                    )?;
                    files.insert(StreamKey::named(index, named.name_utf16), stream);
                }
            }
        }
        objects.push(
            serde_json::json!({"object_index":index,"components":item.components,
            "logical_length":item.logical_length(),"disposition":"private-uninitialized",
            "payload_expected_sha256":item.expected_sha256,
            "source_security_sha256":hex::encode(Sha256::digest(item.security)),
            "source_metadata_restoration_pending":true,"payload_supply_pending":!item.directory}),
        );
        if let (Some(memory), Some(guard)) = (&memory, row_memory) {
            memory.retain(
                guard,
                memory::object_bytes(index, &objects, &files, &sparse_targets, &metadata_targets)?,
            )?;
        }
    }
    Ok(())
    })()
    .map_err(|error| super::cache_refresh::at_object(input, "shadow allocation", failing_object.get(), error))?;
    allocation_progress(1, input.len() as u64);
    input.before_mutation(0)?;
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
        let slot_memory = memory
            .as_ref()
            .map(|m| memory::slot_bytes(key).and_then(|n| m.working(n)))
            .transpose()?;
        stream_slots.insert(slot, key.clone());
        if let (Some(memory), Some(guard)) = (&memory, slot_memory) {
            memory.retain(guard, memory::slot_bytes(key)?)?;
        }
    }
    let metadata_input_sha256 = {
        let _digest_memory = memory.as_ref().map(|m| m.metadata_digest()).transpose()?;
        metadata::input_digest_domain(input)?
    };
    let tree = PrivateTree {
        files,
        stream_slots,
        sparse_targets,
        carrier_directory,
        volume,
        pair: pair.clone(),
        backing_guard: None,
        source_before,
        partition_source,
        dedicated_source,
        initial_objects: objects,
        events,
        privileges,
        reparse_privileges,
        original_coordinates: BTreeMap::new(),
        materialized_tails: BTreeMap::new(),
        placement_started: false,
        placement_complete: false,
        recovery_origin: None,
        placement_progress: serde_json::Value::Null,
        system_identities,
        system_directory_indices,
        system_payloads_started: false,
        system_payloads_complete: false,
        metadata_targets,
        metadata_input_sha256,
        metadata_object_limit: maximum_objects,
        metadata_resource_admission: resource_admission,
        construction_enrollment,
        memory,
    };
    tree.require_source_excluded()?;
    tree.require_dedicated_shadow_boundary()?;
    if let Some(memory) = &tree.memory {
        // Close the final state after the last source/shadow check, while the
        // global query lease still pays for that operation and the handoff.
        memory.close_base(&tree)?;
    }
    // All global temporary buffers finish before their query lease is freed.
    drop(initial);
    drop(root_name);
    drop(root);
    drop(sd);
    drop(global_query_memory);
    Ok(tree)
}

pub(super) fn private_descriptor() -> io::Result<Vec<u8>> {
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
