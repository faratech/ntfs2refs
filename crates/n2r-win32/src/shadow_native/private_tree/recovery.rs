//! Cold adoption of a native private shadow, either unwritten or freshly
//! proven dense and storage-ready after completed placement. Persisted pins
//! describe provenance only; fresh enrollment and complete native audits issue
//! the new owner. No old PrivateTree, creator flags, or move log is restored.
use super::*;
#[path = "metadata_recovery.rs"]
pub mod metadata_transition;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ExternalOriginPins {
    pub prior_preparation_sha256: [u8; 32],
    pub expected_pages_sha256: [u8; 32],
    pub authenticated_checkpoint_sha256: [u8; 32],
    pub new_epoch: [u8; 16],
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct PartialPlacementSpend {
    /// Authenticated upper bounds, not merely successfully flushed records.
    pub prior_submissions_upper: usize,
    pub prior_move_bytes_upper: u64,
    pub uncertain_tail_submissions: usize,
    pub uncertain_tail_move_bytes: u64,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RecoveryLimits {
    pub cumulative_maximum_move_bytes: u64,
    pub cumulative_maximum_submissions: usize,
}

/// Opaque, nonserializable native origin, bound to exactly one new tree owner.
pub struct RecoveredOrigin {
    token: Arc<()>,
    prior_submissions: usize,
    prior_bytes: u64,
    remaining_submissions: usize,
    remaining_bytes: u64,
    pins: ExternalOriginPins,
    namespace_sha256: [u8; 32],
    placed_ready: bool,
    payloads_ready: bool,
    _memory: Box<dyn report_memory::ReportMemoryLease>,
}
impl RecoveredOrigin {
    pub(super) fn require_tree(&self, tree: &PrivateTree) -> io::Result<()> {
        if tree
            .recovery_origin
            .as_ref()
            .is_none_or(|t| !Arc::ptr_eq(t, &self.token))
            || !tree.placement_started
            || tree.placement_complete
        {
            return Err(invalid("actual recovered native tree origin differs"));
        }
        Ok(())
    }
    pub(super) fn remaining(&self) -> (u64, usize) {
        (self.remaining_bytes, self.remaining_submissions)
    }
    pub(super) fn payloads_ready(&self) -> bool {
        self.payloads_ready
    }
    pub(super) fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"kind":if self.payloads_ready {"fresh-native-recovered-initialized-payload-origin-v1"}else if self.placed_ready {"fresh-native-recovered-source-backed-origin-v1"}else{"fresh-native-recovered-unwritten-origin-v1"},
            "pins":self.pins,"namespace_sha256":hex::encode(self.namespace_sha256),
            "prior_submissions_upper":self.prior_submissions,"prior_move_bytes_upper":self.prior_bytes,
            "remaining_submissions":self.remaining_submissions,"remaining_move_bytes":self.remaining_bytes,
            "historical_creator_identity_claimed":false,"saved_flags_used_as_authority":false,
            "source_payload_bytes_read":0,"source_payload_writes":0})
    }
}
pub struct RecoveredPrivateTree {
    tree: PrivateTree,
    origin: RecoveredOrigin,
    attempted: bool,
}
impl RecoveredPrivateTree {
    pub fn attach_backing_resource_guard(
        &mut self,
        guard: std::sync::Arc<crate::managed_shadow::BackingResourceGuard>,
    ) -> io::Result<()> {
        self.tree.attach_backing_resource_guard(guard)
    }

    /// Diagnostic progress only. It cannot recreate or transfer this owner.
    pub fn placement_progress(&self) -> &serde_json::Value {
        self.tree.placement_progress()
    }
    pub fn origin_observation(&self) -> serde_json::Value {
        self.origin.receipt()
    }
    pub fn place_remaining_domain(
        &mut self,
        input: &impl InputDomain,
        sink: &mut dyn PlacementEvidenceSink,
    ) -> io::Result<ResourcePlacementReport> {
        if self.attempted || self.origin.placed_ready {
            return Err(invalid(
                "recovered placement already attempted; preserve without retry",
            ));
        }
        self.attempted = true;
        placement::run_recovered_resource_domain(&mut self.tree, input, &self.origin, sink)
    }
    /// Reconstruct readiness from current native maps without submitting moves.
    /// The old completed batch selects this audit; it grants no native owner.
    pub fn rehydrate_placed_domain(
        &mut self,
        input: &impl InputDomain,
        sink: &mut dyn PlacementEvidenceSink,
    ) -> io::Result<ResourcePlacementReport> {
        if self.attempted || !self.origin.placed_ready {
            return Err(invalid("fresh placed-recovery audit required exactly once"));
        }
        self.attempted = true;
        placement::rehydrate_recovered_resource_domain(&mut self.tree, input, &self.origin, sink)
    }
    pub fn into_placed_tree(self) -> io::Result<PrivateTree> {
        if !self.attempted || !self.tree.placement_complete {
            return Err(invalid(
                "recovered tree lacks completed native remaining placement",
            ));
        }
        Ok(self.tree)
    }
}

fn same_security(a: &[u8], b: &[u8]) -> io::Result<bool> {
    use crate::security_descriptor::{AclLayout, SidRange};
    let x = crate::security_descriptor::validate(a)?;
    let y = crate::security_descriptor::validate(b)?;
    let sid = |buf: &[u8], part: Option<SidRange>| -> Vec<u8> {
        part.map(|s| buf[s.offset..s.offset + s.length].to_vec())
            .unwrap_or_default()
    };
    let acl = |buf: &[u8], part: AclLayout| -> io::Result<Vec<Vec<u8>>> {
        let Some(offset) = part.offset else {
            return Ok(Vec::new());
        };
        let mut at = offset + 8;
        let mut rows = Vec::new();
        for _ in 0..part.ace_count {
            let bytes = u16::from_le_bytes(buf[at + 2..at + 4].try_into().unwrap()) as usize;
            rows.push(buf[at..at + bytes].to_vec());
            at += bytes;
        }
        Ok(rows)
    };
    Ok(x.control == y.control
        && x.rm_control == y.rm_control
        && sid(a, x.owner) == sid(b, y.owner)
        && sid(a, x.group) == sid(b, y.group)
        && x.dacl.presence == y.dacl.presence
        && x.sacl.presence == y.sacl.presence
        && x.dacl.revision == y.dacl.revision
        && x.sacl.revision == y.sacl.revision
        && acl(a, x.dacl)? == acl(b, y.dacl)?
        && acl(a, x.sacl)? == acl(b, y.sacl)?)
}
pub(in crate::shadow_native) fn require_private_security(
    file: &File,
    directory: bool,
) -> io::Result<()> {
    let sd = private_descriptor()?;
    let input = Input {
        components: &[],
        additional_names: &[],
        directory,
        times: [1; 4],
        attributes: if directory { 16 } else { 32 },
        security: &sd,
        expected_api_security: None,
        extended_attributes: None,
        reparse: None,
        case_sensitive: None,
        payload: &[],
        expected_length: None,
        expected_sha256: None,
        source_offset: None,
        source_runs: Vec::new(),
        named_streams: Vec::new(),
        sparse: None,
    };
    let before = info(file, 18, 24)?;
    if !security_matches(
        &input,
        &security_snapshot_with_limit(file, Some(65536)),
        &same_security,
    )? || info(file, 18, 24)? != before
    {
        return Err(invalid(
            "recovered object is not the exact private SYSTEM descriptor",
        ));
    }
    Ok(())
}

fn carrier_name(key: &StreamKey) -> String {
    let mut h = Sha256::new();
    for c in &key.name_utf16 {
        h.update(c.to_le_bytes());
    }
    format!(
        "carrier-{}-{}.bin",
        key.object_index,
        hex::encode(h.finalize())
    )
}
struct Namespace {
    rows: BTreeMap<Vec<String>, (Vec<u8>, bool)>,
    ids: BTreeSet<Vec<u8>>,
    children: BTreeMap<Vec<String>, usize>,
}
impl Namespace {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            ids: BTreeSet::new(),
            children: BTreeMap::new(),
        }
    }
    fn get(&self, path: &[String]) -> Option<&(Vec<u8>, bool)> {
        self.rows.get(path)
    }
    fn insert(&mut self, path: Vec<String>, value: (Vec<u8>, bool)) -> io::Result<()> {
        if self.rows.contains_key(&path) || !self.ids.insert(value.0.clone()) {
            return Err(invalid(
                "recovered native namespace repeats an identity or path",
            ));
        }
        if !path.is_empty() {
            let parent = &path[..path.len() - 1];
            if self
                .rows
                .get(parent)
                .is_none_or(|(_, directory)| !directory)
            {
                return Err(invalid(
                    "recovered native namespace parent is absent or not a directory",
                ));
            }
            *self.children.entry(parent.to_vec()).or_default() += 1;
        }
        self.rows.insert(path, value);
        Ok(())
    }
}
fn remember(
    namespace: &mut Namespace,
    path: &[String],
    file: &File,
    directory: bool,
    volume: &[u8],
) -> io::Result<()> {
    let id = info(file, 18, 24)?;
    if id[..8] != *volume {
        return Err(invalid("recovered native namespace changes volume"));
    }
    namespace.insert(path.to_vec(), (id, directory))?;
    Ok(())
}
fn exact_children(
    file: &File,
    path: &[String],
    namespace: &Namespace,
    hash: &mut Sha256,
    payer: &dyn report_memory::ReportMemoryAccountant,
) -> io::Result<()> {
    let before = info(file, 18, 24)?;
    let count = namespace.children.get(path).copied().unwrap_or(0);
    // Paid by the expected child count, for what a listing is: the records
    // Windows returns, the names decoded, the parsed entries, and a node of
    // the identity set for each.
    let (evidence, listing) = namespace_layout::listing_memory(count)
        .ok_or_else(|| invalid("recovered directory evidence workspace overflow"))?;
    let _memory = payer.reserve(
        (count as u64)
            .checked_mul(64)
            .and_then(|n| n.checked_add(listing))
            .ok_or_else(|| invalid("recovered directory memory overflow"))?,
    )?;
    let mut seen = BTreeSet::new();
    for child in enumerate_with_resource_budget(file, Some(evidence))
        .map_err(|error| io::Error::other(format!("recovered directory {path:?}: {error}")))?
    {
        if child.name_utf16 == [46] || child.name_utf16 == [46, 46] {
            continue;
        }
        let name = String::from_utf16(&child.name_utf16)
            .map_err(|_| invalid("recovered directory has invalid UTF-16"))?;
        let mut full = path.to_vec();
        full.push(name);
        let (id, dir) = namespace
            .get(&full)
            .ok_or_else(|| invalid("recovered directory contains an extra path"))?;
        if child.attributes & 0x400 != 0
            || (child.attributes & 16 != 0) != *dir
            || child.file_id.as_slice() != &id[8..24]
            || !seen.insert(child.file_id)
        {
            return Err(invalid(
                "recovered parent/child native identity or type differs",
            ));
        }
    }
    if seen.len() != count || info(file, 18, 24)? != before {
        return Err(invalid(
            "recovered complete directory namespace coverage changed",
        ));
    }
    hash.update((path.len() as u64).to_le_bytes());
    for p in path {
        hash.update((p.len() as u64).to_le_bytes());
        hash.update(p.as_bytes());
    }
    hash.update(&before);
    for id in seen {
        hash.update(id);
    }
    Ok(())
}
fn exact_streams(file: &File, item: &Input<'_>) -> io::Result<()> {
    let raw = stream_info(file)?;
    let (entries, _) = stream_layout::parse_streams(&raw)?;
    if entries.len() != 1 + item.named_streams.len() {
        return Err(invalid("recovered stream set count differs"));
    }
    for e in entries {
        let (length, carrier_target) = if e.name.is_empty() {
            (item.logical_length(), item.sparse.is_some())
        } else {
            let n = item
                .named_streams
                .iter()
                .find(|n| n.name_utf16 == e.name)
                .ok_or_else(|| invalid("recovered unexpected named stream"))?;
            (
                n.expected_length,
                n.sparse.is_some() || n.expected_length >= crate::target_cluster::bytes(),
            )
        };
        let expected = if carrier_target {
            crate::target_cluster::ceil(length)
                .ok_or_else(|| invalid("recovered stream EOF overflow"))?
        } else {
            length
        };
        if e.logical_size != expected {
            return Err(invalid("recovered native stream EOF differs"));
        }
    }
    Ok(())
}

/// Requires fresh native exclusion; historical metadata can never issue it.
/// There are no allocation, resize, deletion, initialization or payload reads.
pub fn adopt_unwritten_domain(
    enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    spend: PartialPlacementSpend,
    limits: RecoveryLimits,
    pins: ExternalOriginPins,
) -> io::Result<RecoveredPrivateTree> {
    adopt_recovery_domain(
        enrollment, input, profile, payer, spend, limits, pins, false, false,
    )
}

/// Fresh native private-tree and initialized-prefix audit. Historical payload
/// bytes are not trusted: the normal supply pass must replay all exceptions.
pub fn adopt_placed_domain(
    enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    spend: PartialPlacementSpend,
    limits: RecoveryLimits,
    pins: ExternalOriginPins,
) -> io::Result<RecoveredPrivateTree> {
    adopt_recovery_domain(
        enrollment, input, profile, payer, spend, limits, pins, true, false,
    )
}
/// Adopt a fully initialized but still private payload tree. This does not
/// trust the previous supply verdict: callers must freshly verify user bytes,
/// native routes and system payloads before metadata completion. A tree whose
/// metadata transition began is deliberately rejected by the private namespace
/// and security audits, rather than downgraded to an unwritten tree.
pub fn adopt_payloads_domain(
    enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    spend: PartialPlacementSpend,
    limits: RecoveryLimits,
    pins: ExternalOriginPins,
) -> io::Result<RecoveredPrivateTree> {
    adopt_recovery_domain(
        enrollment, input, profile, payer, spend, limits, pins, true, true,
    )
}
fn adopt_recovery_domain(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    profile: crate::attestation::ResourceProfile,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    spend: PartialPlacementSpend,
    limits: RecoveryLimits,
    pins: ExternalOriginPins,
    placed_ready: bool,
    payloads_ready: bool,
) -> io::Result<RecoveredPrivateTree> {
    let admission = profile
        .resource_admission()?
        .ok_or_else(|| invalid("cold adoption requires V4 resource admission"))?;
    if enrollment.pair.source.layout_profile
        != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        || !matches!(
            &enrollment.source,
            source_scope::ConstructionSource::Dedicated(_)
        )
        || pins.prior_preparation_sha256 == [0; 32]
        || pins.expected_pages_sha256 == [0; 32]
        || pins.authenticated_checkpoint_sha256 == [0; 32]
        || pins.new_epoch == [0; 16]
    {
        return Err(invalid(
            "cold adoption requires actual Windows freeze and external origin pins",
        ));
    }
    let prior_submissions = spend
        .prior_submissions_upper
        .checked_add(spend.uncertain_tail_submissions)
        .ok_or_else(|| invalid("prior placement submissions overflow"))?;
    let prior_bytes = spend
        .prior_move_bytes_upper
        .checked_add(spend.uncertain_tail_move_bytes)
        .ok_or_else(|| invalid("prior placement byte spend overflow"))?;
    let remaining_submissions = limits
        .cumulative_maximum_submissions
        .checked_sub(prior_submissions)
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("cumulative placement submissions exhausted"))?;
    let remaining_bytes = limits
        .cumulative_maximum_move_bytes
        .checked_sub(prior_bytes)
        .filter(|n| *n >= crate::target_cluster::bytes())
        .ok_or_else(|| invalid("cumulative moved-byte allowance exhausted"))?;
    let origin_memory = payer.reserve(65536)?;
    let memory = memory::Owner::new(
        payer.clone(),
        input.len(),
        usize::try_from(admission.data_streams).map_err(io::Error::other)?,
        admission.budget.max_row_bytes,
    )?;
    let root = format!("{}\\", enrollment.pair.shadow.volume_path()?);
    preflight_input_domain(
        input,
        enrollment.pair.shadow.identity.partition_bytes,
        &root,
        Some(profile),
        Some(payer.as_ref()),
    )?;
    enrollment.revalidate()?;
    let mut events = Vec::new();
    let source = match &enrollment.source {
        source_scope::ConstructionSource::Dedicated(s) => *s,
        _ => {
            return Err(invalid(
                "cold adoption requires an actual whole-disk source owner",
            ));
        }
    };
    let dedicated = source_scope::DedicatedShadowConstructionLease::begin(
        source,
        &enrollment.pair,
        &enrollment.source_before,
        payer.as_ref(),
        &mut events,
    )?;
    let observation = enrollment.observation();
    // Pay the actual native query workspace plus a conservative node/key/ID
    // envelope before building the full namespace index. It is released after
    // the complete directory audit, not retained as another tree copy.
    let mut namespace_bytes = (input.len() as u64)
        .checked_add(admission.data_streams)
        .and_then(|n| n.checked_mul(2048))
        .ok_or_else(|| invalid("recovery namespace RAM overflow"))?;
    input.for_each(|_, i| {
        for p in i.components {
            namespace_bytes = namespace_bytes
                .checked_add(
                    (p.len() as u64)
                        .checked_mul(8)
                        .and_then(|n| n.checked_add(128))
                        .ok_or_else(|| invalid("path RAM overflow"))?,
                )
                .ok_or_else(|| invalid("path RAM overflow"))?;
        }
        Ok(())
    })?;
    let _namespace_memory = payer.reserve(
        namespace_bytes
            .checked_add(64 * 1024 * 1024)
            .ok_or_else(|| invalid("namespace query RAM overflow"))?,
    )?;
    enrollment.volume.sync_all()?;
    let root_id = info(&enrollment.root, 18, 24)?;
    let initial = enumerate(&enrollment.root)?;
    let needs_carriers = input.any(|i| {
        i.sparse.is_some_and(|s| !s.allocated.is_empty())
            || i.named_streams.iter().any(|s| {
                s.expected_length >= crate::target_cluster::bytes()
                    || s.sparse.is_some_and(|v| !v.allocated.is_empty())
            })
    })?;
    let mut candidates = initial
        .iter()
        .filter_map(|e| String::from_utf16(&e.name_utf16).ok())
        .filter(|s| s.starts_with("n2r-sparse-carriers-"));
    let carrier_directory = match (needs_carriers, candidates.next(), candidates.next()) {
        (true, Some(name), None) => Some(sparse_stream::CarrierDirectory::reopen_unwritten(
            &root, name,
        )?),
        (false, None, None) => None,
        _ => {
            return Err(invalid(
                "recovered sparse carrier directory coverage differs",
            ));
        }
    };
    let mut namespace = Namespace::new();
    namespace.insert(Vec::new(), (root_id.clone(), true))?;
    if let Some(d) = &carrier_directory {
        remember(
            &mut namespace,
            &[d.component.clone()],
            d.recovery_handle(),
            true,
            &root_id[..8],
        )?;
    }
    let mut files = BTreeMap::new();
    let reopen_placeholder = if payloads_ready {
        unwritten::PrivatePlaceholder::reopen_payloads
    } else if placed_ready {
        unwritten::PrivatePlaceholder::reopen_placed
    } else {
        unwritten::PrivatePlaceholder::reopen_unwritten
    };
    let mut sparse_targets = BTreeMap::new();
    let mut metadata_targets = BTreeMap::new();
    metadata_targets.insert(0, enrollment.root);
    let mut system_identities = BTreeMap::new();
    let mut system_directory_indices = Vec::new();
    let mut objects = Receipts::for_objects(input.len(), true)?;
    let tracked = admission.placement_slots()?;
    let partition = enrollment.pair.shadow.identity.partition_bytes;
    for index in 0..input.len() {
        let owner = input.object(index)?;
        let item = owner.input();
        let row = memory.working(memory.row_peak(&item)?)?;
        if item.components.is_empty() {
            objects.push(|| serde_json::json!({"object_index":index,"disposition":"fresh-recovered-root-metadata-pending"}));
            memory.retain(
                row,
                memory::object_bytes(index, &objects, &files, &sparse_targets, &metadata_targets)?,
            )?;
            continue;
        }
        let system = item.components[0] == "System Volume Information";
        if system {
            let path = format!("{root}{}", item.components.join("\\"));
            if payloads_ready && !std::path::Path::new(&path).try_exists()? {
                return Err(invalid("completed payload system object is absent"));
            }
            // All source SVI directories must exist already. Only the narrow
            // formatter files may be absent or contain native cache data.
            if item.directory || std::path::Path::new(&path).try_exists()? {
                if !item.directory && !formatter_cache_name(&item.components[1]) && !payloads_ready
                {
                    return Err(invalid("recovered SVI file is outside formatter exception"));
                }
                let handle = open(&path, item.directory, true)?;
                if payloads_ready && !item.directory && !formatter_cache_name(&item.components[1]) {
                    require_private_security(&handle, false)?;
                }
                if item.components.len() == 2 && item.directory {
                    require_private_security(&handle, true)?;
                }
                if !item.directory {
                    let standard = info(&handle, 1, 24)?;
                    if layout::u64_at(&standard, 8)? > 1024 * 1024
                        || layout::u32_at(&standard, 16)? != 1
                    {
                        return Err(invalid("recovered formatter file exceeds native profile"));
                    }
                    let raw = stream_info(&handle)?;
                    let (streams, _) = stream_layout::parse_streams(&raw)?;
                    if streams.len() != 1 || !streams[0].name.is_empty() {
                        return Err(invalid("recovered formatter file has named streams"));
                    }
                }
                remember(
                    &mut namespace,
                    item.components,
                    &handle,
                    item.directory,
                    &root_id[..8],
                )?;
                system_identities.insert(
                    item.components.to_vec(),
                    info(&handle, 18, 24)?[8..24].to_vec(),
                );
                metadata_targets.insert(index, handle);
            }
            if item.directory {
                system_directory_indices.push(index);
            }
            objects.push(|| serde_json::json!({"object_index":index,"disposition":"fresh-recovered-system-metadata-pending"}));
        } else if item.directory {
            let handle = open(&format!("{root}{}", item.components.join("\\")), true, true)?;
            require_private_security(&handle, true)?;
            remember(
                &mut namespace,
                item.components,
                &handle,
                true,
                &root_id[..8],
            )?;
            metadata_targets.insert(index, handle);
            objects.push(|| serde_json::json!({"object_index":index,"disposition":"fresh-recovered-private-directory"}));
        } else {
            for position in 0..=item.named_streams.len() {
                let (name, length, sparse) = if position == 0 {
                    (&[][..], item.logical_length(), item.sparse)
                } else {
                    let n = &item.named_streams[position - 1];
                    (n.name_utf16, n.expected_length, n.sparse)
                };
                let key = if name.is_empty() {
                    StreamKey::unnamed(index)
                } else {
                    StreamKey::named(index, name)
                };
                if sparse.is_some()
                    || (!name.is_empty() && length >= crate::target_cluster::bytes())
                {
                    let plain;
                    let layout = if let Some(s) = sparse {
                        s
                    } else {
                        plain = crate::sparse_layout::SparseLayout::from_allocated(
                            length,
                            length,
                            vec![crate::sparse_layout::LogicalRange {
                                offset: 0,
                                length: crate::target_cluster::ceil(length)
                                    .ok_or_else(|| invalid("recovered plain EOF overflow"))?,
                            }],
                        )?;
                        &plain
                    };
                    let target = sparse_stream::Target::reopen_unwritten(
                        &root,
                        item.components,
                        name,
                        length,
                        layout,
                        sparse.is_some(),
                    )?;
                    if name.is_empty() {
                        remember(
                            &mut namespace,
                            item.components,
                            &target.file,
                            false,
                            &root_id[..8],
                        )?;
                        exact_streams(&target.file, &item)?;
                    } else {
                        require_base_identity(&namespace, item.components, &target.file)?;
                    }
                    if target.dense_length != 0 {
                        let dir = carrier_directory
                            .as_ref()
                            .ok_or_else(|| invalid("recovered carrier directory missing"))?;
                        let components = vec![dir.component.clone(), carrier_name(&key)];
                        let file = reopen_placeholder(
                            &root,
                            &components,
                            &[],
                            target.dense_length,
                            partition,
                            true,
                            admission,
                            tracked,
                            remaining_submissions,
                            remaining_bytes,
                            payer.clone(),
                        )?;
                        remember(
                            &mut namespace,
                            &components,
                            file.metadata_handle(),
                            false,
                            &root_id[..8],
                        )?;
                        let streams = stream_info(file.metadata_handle())?;
                        let (entries, _) = stream_layout::parse_streams(&streams)?;
                        if entries.len() != 1
                            || !entries[0].name.is_empty()
                            || entries[0].logical_size != target.dense_length
                        {
                            return Err(invalid(
                                "recovered carrier has extra streams or changed EOF",
                            ));
                        }
                        files.insert(key.clone(), file);
                    }
                    sparse_targets.insert(key, target);
                } else {
                    let file = reopen_placeholder(
                        &root,
                        item.components,
                        name,
                        length,
                        partition,
                        false,
                        admission,
                        tracked,
                        remaining_submissions,
                        remaining_bytes,
                        payer.clone(),
                    )?;
                    if name.is_empty() {
                        remember(
                            &mut namespace,
                            item.components,
                            file.metadata_handle(),
                            false,
                            &root_id[..8],
                        )?;
                        exact_streams(file.metadata_handle(), &item)?;
                    } else {
                        require_base_identity(&namespace, item.components, file.metadata_handle())?;
                    }
                    files.insert(key, file);
                }
            }
            objects.push(|| serde_json::json!({"object_index":index,"disposition":if placed_ready {"fresh-native-placed-prefix-owner"}else{"fresh-native-unwritten-owner"},"historical_creator_claimed":false}));
        }
        memory.retain(
            row,
            memory::object_bytes(index, &objects, &files, &sparse_targets, &metadata_targets)?,
        )?;
    }
    let mut namespace_hash = Sha256::new();
    for (index, file) in &metadata_targets {
        let owner = input.object(*index)?;
        let item = owner.input();
        if item.directory {
            exact_children(
                file,
                item.components,
                &namespace,
                &mut namespace_hash,
                payer.as_ref(),
            )?;
        }
    }
    if let Some(d) = &carrier_directory {
        exact_children(
            d.recovery_handle(),
            &[d.component.clone()],
            &namespace,
            &mut namespace_hash,
            payer.as_ref(),
        )?;
    }
    let mut stream_slots = BTreeMap::new();
    let mut next = input.len();
    for key in files.keys() {
        let slot = if key.name_utf16.is_empty() {
            key.object_index
        } else {
            let slot = next;
            next += 1;
            slot
        };
        let guard = memory.working(memory::slot_bytes(key)?)?;
        stream_slots.insert(slot, key.clone());
        memory.retain(guard, memory::slot_bytes(key)?)?;
    }
    let digest = {
        let _guard = memory.metadata_digest()?;
        metadata::input_digest_domain(input)?
    };
    let token = Arc::new(());
    let tree = PrivateTree {
        files,
        stream_slots,
        sparse_targets,
        carrier_directory,
        volume: enrollment.volume,
        pair: enrollment.pair,
        backing_guard: None,
        source_before: enrollment.source_before,
        partition_source: None,
        dedicated_source: Some(dedicated),
        initial_objects: objects,
        events,
        privileges: enrollment.privileges,
        reparse_privileges: if input.any(|i| i.reparse.is_some_and(|r| r.tag() == 0xa000000c))? {
            Some(Privileges::enable_for(&["SeCreateSymbolicLinkPrivilege"])?)
        } else {
            None
        },
        original_coordinates: BTreeMap::new(),
        materialized_tails: BTreeMap::new(),
        placement_started: true,
        placement_complete: false,
        recovery_origin: Some(token.clone()),
        placement_progress: serde_json::Value::Null,
        system_identities,
        system_directory_indices,
        system_payloads_started: false,
        system_payloads_complete: false,
        metadata_targets,
        metadata_input_sha256: digest,
        metadata_object_limit: usize::try_from(admission.objects()?).map_err(io::Error::other)?,
        metadata_resource_admission: Some(admission),
        construction_enrollment: Some(observation),
        memory: Some(memory),
    };
    tree.require_source_excluded()?;
    tree.require_dedicated_shadow_boundary()?;
    placement::audit_recovered_maps(&tree, remaining_bytes, remaining_submissions)?;
    tree.memory.as_ref().unwrap().close_base(&tree)?;
    let origin = RecoveredOrigin {
        placed_ready,
        payloads_ready,
        token,
        prior_submissions,
        prior_bytes,
        remaining_submissions,
        remaining_bytes,
        pins,
        namespace_sha256: namespace_hash.finalize().into(),
        _memory: origin_memory,
    };
    Ok(RecoveredPrivateTree {
        tree,
        origin,
        attempted: false,
    })
}
fn require_base_identity(namespace: &Namespace, path: &[String], file: &File) -> io::Result<()> {
    let actual = info(file, 18, 24)?;
    if namespace.get(path).is_none_or(|(id, _)| actual != *id) {
        return Err(invalid(
            "recovered named stream differs from its base file identity",
        ));
    }
    Ok(())
}

impl PrivateTree {
    /// Reissue system-supply readiness from current native bytes, never a flag.
    pub fn revalidate_recovered_system_payloads_domain(
        &mut self,
        input: &impl InputDomain,
    ) -> io::Result<serde_json::Value> {
        system_payloads::revalidate_completed_domain(self, input)
    }

    /// Renew the partial-tail witness after source/target comparison. This
    /// reads the native tail again under the retained identity and does not
    /// write, initialize, resize or clone a stream.
    pub fn revalidate_recovered_materialized_tail_named(
        &mut self,
        index: usize,
        name: &[u16],
        components: &[String],
        logical_length: u64,
        offset: u64,
        expected: &[u8],
    ) -> io::Result<()> {
        let prefix = crate::target_cluster::floor(logical_length);
        let end = offset
            .checked_add(expected.len() as u64)
            .ok_or_else(|| invalid("recovered tail interval overflow"))?;
        if prefix == 0 || prefix == logical_length || offset > prefix || end < logical_length {
            return Ok(());
        }
        if self.recovery_origin.is_none() || expected.len() > 65536 {
            return Err(invalid("recovered tail owner or range differs"));
        }
        self.validate_stream_shape_named(index, name, components, logical_length)?;
        let key = StreamKey::named(index, name);
        let native_id = if let Some(target) = self.sparse_targets.get(&key) {
            info(&target.file, 18, 24)?
        } else {
            info(
                self.files
                    .get(&key)
                    .ok_or_else(|| invalid("recovered tail file absent"))?
                    .metadata_handle(),
                18,
                24,
            )?
        };
        let _work = self
            .memory
            .as_ref()
            .ok_or_else(|| invalid("recovered tail payer absent"))?
            .working(crate::target_cluster::bytes())?;
        // A tail is shorter than one target cluster.
        let mut actual = vec![0u8; crate::target_cluster::bytes_usize()];
        let count = (logical_length - prefix) as usize;
        self.read_materialized_range_named(index, name, prefix, &mut actual[..count])?;
        let start = (prefix - offset) as usize;
        if actual[..count] != expected[start..start + count] {
            return Err(invalid("recovered materialized tail differs from source"));
        }
        self.record_materialized_tail(&key, logical_length, offset, expected, native_id)?;
        self.validate_stream_shape_named(index, name, components, logical_length)
    }
}
