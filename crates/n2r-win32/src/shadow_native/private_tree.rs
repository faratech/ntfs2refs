//! Allocation-only user namespace on an independently bound fresh ReFS shadow.
//! The files stay SYSTEM-only and contain no admitted payload yet. A live tree
//! exposes placement operations, never source writes or conversion authority.
use super::input_domain::{DomainMetadata, InputDomain, ObjectInput, SliceInputs};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
mod enrollment;
mod metadata;
mod placement;
mod source_backed;
mod supply;
mod system_payloads;
pub use enrollment::{ConstructionEnrollment, enroll, enroll_with_resource_profile};
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
    sparse_targets: BTreeMap<StreamKey, sparse_stream::Target>,
    carrier_directory: Option<sparse_stream::CarrierDirectory>,
    volume: File,
    pair: GeneralSourceShadowBinding,
    source_before: native::GeneralDiskState,
    initial_objects: Vec<serde_json::Value>,
    events: Vec<NativeEvent>,
    privileges: Privileges,
    reparse_privileges: Option<Privileges>,
    original_coordinates: BTreeMap<StreamKey, Vec<(u64, u64, u64)>>,
    materialized_tails: BTreeMap<StreamKey, MaterializedTail>,
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
    metadata_object_limit: usize,
    metadata_resource_admission: Option<crate::tree_resources::SourceResourceAdmission>,
    construction_enrollment: Option<serde_json::Value>,
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
    fn record_materialized_tail(
        &mut self,
        key: &StreamKey,
        logical_length: u64,
        offset: u64,
        bytes: &[u8],
        native_file_id: Vec<u8>,
    ) {
        let prefix = logical_length / 4096 * 4096;
        if prefix == 0 || prefix == logical_length || offset > prefix {
            return;
        }
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return;
        };
        if end < logical_length {
            return;
        }
        let start = (prefix - offset) as usize;
        let stop = (logical_length - offset) as usize;
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
            let (file, tail) = target.finish(self.files.remove(&key))?;
            if let Some(tail) = tail {
                tails.push((key.clone(), tail));
            }
            result.insert(key, file);
        }
        if let Some(directory) = self.carrier_directory.take() {
            directory.retire()?;
        }
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
                file.check_placements()?;
            } else if target.dense_length != 0 {
                return Err(invalid("sparse carrier missing"));
            }
            return Ok(());
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
                let file = self
                    .files
                    .get_mut(&key)
                    .ok_or_else(|| invalid("sparse materialization carrier absent"))?;
                for part in parts {
                    let local = (part.logical - offset) as usize;
                    let stop = local + part.length as usize;
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
                self.record_materialized_tail(&key, logical_length, offset, bytes, native_file_id);
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
        self.record_materialized_tail(&key, logical_length, offset, bytes, native_file_id);
        Ok(proof)
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

fn allocate_domain(
    pair: &GeneralSourceShadowBinding,
    input: &impl InputDomain,
    enrollment: Option<ConstructionEnrollment<'_>>,
    resource_profile: Option<crate::attestation::ResourceProfile>,
) -> io::Result<PrivateTree> {
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
    if input.is_empty() || input.len() > maximum_objects {
        return Err(invalid("private tree root or object bound differs"));
    }
    let resource_root = format!("{}\\", pair.shadow.volume_path()?);
    if let Some(admission) = resource_admission {
        super::hard_links::validate_resource_domain(
            input,
            admission.maximum_namespace_names()?,
            &resource_root,
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
                pair.shadow.identity.partition_bytes,
                maximum_streams,
            )
        } else {
            streams::validate(
                std::slice::from_ref(item),
                pair.shadow.identity.partition_bytes,
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
        let key = crate::shadow_names::conservative_path_key(item.components);
        if resource_admission.map_or(item.components.len() > 16, |_| {
            !super::hard_links::resource_path_valid(&resource_root, item.components)
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
    if total > pair.shadow.identity.partition_bytes
        || (admission.is_none()
            && resource_admission.is_none()
            && (directories.len() > 256 || input.len() - directories.len() > 1024))
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
    let system_identities =
        existing_system_entries_domain(&root, &initial, input, true, &mut events)?;
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
    let carrier_directory = if needs_carriers {
        Some(sparse_stream::CarrierDirectory::create(&root)?)
    } else {
        None
    };
    let mut metadata_targets = BTreeMap::new();
    metadata_targets.insert(0, root_handle);
    // Pin every formatter object the constructor admitted. Subsequent system
    // supply must update these same objects, not a caller-selected path.
    for index in 0..input.len() {
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
    let mut objects = Vec::with_capacity(input.len());
    // Reuse a private file's atomic descriptor to create private directories.
    // Its descriptor is constant rather than derived from source ACLs.
    let sd = private_descriptor()?;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
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
        sparse_targets,
        carrier_directory,
        volume,
        pair: pair.clone(),
        source_before,
        initial_objects: objects,
        events,
        privileges,
        reparse_privileges,
        original_coordinates: BTreeMap::new(),
        materialized_tails: BTreeMap::new(),
        placement_started: false,
        placement_complete: false,
        placement_progress: serde_json::Value::Null,
        system_identities,
        system_payloads_started: false,
        system_payloads_complete: false,
        metadata_targets,
        metadata_input_sha256: metadata::input_digest_domain(input)?,
        metadata_object_limit: maximum_objects,
        metadata_resource_admission: resource_admission,
        construction_enrollment,
    };
    tree.require_source_excluded()?;
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
