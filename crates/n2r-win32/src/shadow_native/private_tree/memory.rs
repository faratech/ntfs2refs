//! Incremental native-constructor memory. Every guard is obtained before the
//! operation it covers; no saved report can construct this payer capability.
use super::*;
use crate::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};
use std::{
    cell::{Cell, RefCell},
    mem,
    sync::Arc,
};

pub(super) struct Owner {
    payer: Arc<dyn ReportMemoryAccountant>,
    tails: RefCell<BTreeSet<StreamKey>>,
    guards: RefCell<Vec<Box<dyn ReportMemoryLease>>>,
    base: RefCell<Box<dyn ReportMemoryLease>>,
    base_bytes: Cell<u64>,
    _registry: Box<dyn ReportMemoryLease>,
    row_bytes: u64,
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("private constructor RAM overflow"))
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("private constructor RAM overflow"))
}
fn vec_bytes<T>(v: &Vec<T>) -> io::Result<u64> {
    mul(v.capacity() as u64, mem::size_of::<T>() as u64)
}
fn strings(v: &Vec<String>) -> io::Result<u64> {
    v.iter()
        .try_fold(vec_bytes(v)?, |n, s| add(n, s.capacity() as u64))
}
fn key(k: &StreamKey) -> io::Result<u64> {
    vec_bytes(&k.name_utf16)
}
// BTreeMap does not expose node capacity. `complete_node` is more than one
// of its nodes takes: eleven slots, twelve edges if it is an inner node, its
// header and the allocator's.
fn complete_node<K, V>() -> io::Result<u64> {
    add(
        mul((mem::size_of::<K>() + mem::size_of::<V>()) as u64, 16)?,
        256,
    )
}
// What one entry of a large map is charged. Every node but the root holds
// five entries at least, so N entries fill at most N/5 leaves and fewer
// than N/25 inner nodes: under a quarter of a node an entry. A third is
// charged. (A complete node an entry was charged before; the maps these
// entries go into hold one for every stream of the volume.) The root of a
// map that is still small is in the constructor's base reservation.
fn node<K, V>() -> io::Result<u64> {
    Ok(complete_node::<K, V>()?.div_ceil(3))
}
// What the nodes of a map of its own with `entries` entries take: one node
// up to eleven entries, and at most a leaf for every five and an inner node
// for every twenty-five beyond.
fn tree<K, V>(entries: usize) -> io::Result<u64> {
    let nodes = if entries <= 11 {
        1
    } else {
        entries as u64 / 4 + 2
    };
    mul(complete_node::<K, V>()?, nodes)
}
fn json(v: &serde_json::Value) -> io::Result<u64> {
    use serde_json::Value;
    match v {
        Value::String(s) => Ok(s.capacity() as u64),
        Value::Array(a) => a.iter().try_fold(vec_bytes(a)?, |n, v| add(n, json(v)?)),
        // An object is a map of its own: its nodes once, then what each
        // key and value holds on the heap. (A complete node was charged
        // for every field: 13 KiB for the receipt of one small file, which
        // refused a volume of 500,000 files for memory it did not use.)
        Value::Object(m) => m
            .iter()
            .try_fold(tree::<String, Value>(m.len())?, |n, (k, v)| {
                add(n, add(k.capacity() as u64, json(v)?)?)
            }),
        _ => Ok(0),
    }
}
fn state(scope: &source_scope::ConstructionSourceState) -> io::Result<u64> {
    let s = match scope {
        source_scope::ConstructionSourceState::Dedicated(state) => state,
        source_scope::ConstructionSourceState::Partition(state) => {
            return Ok(state.retained_memory_ceiling_bytes);
        }
    };
    let mut n = 0;
    for b in [&s.device, &s.disk_length, &s.alignment, &s.gpt_layout] {
        n = add(n, vec_bytes(b)?)?;
    }
    Ok(n)
}
impl Owner {
    pub(super) fn new(
        payer: Arc<dyn ReportMemoryAccountant>,
        objects: usize,
        streams: usize,
        row_bytes: u64,
    ) -> io::Result<Self> {
        let count = objects
            .checked_add(
                streams
                    .checked_mul(2)
                    .ok_or_else(|| invalid("private guard count overflow"))?,
            )
            .and_then(|n| n.checked_add(16))
            .ok_or_else(|| invalid("private guard count overflow"))?;
        let registry = add(
            mul(
                count as u64,
                2 * mem::size_of::<Box<dyn ReportMemoryLease>>() as u64,
            )?,
            mul(add(count as u64, 2)?, payer.lease_heap_bytes())?,
        )?;
        let registry = payer.reserve(add(
            add(
                registry,
                mul(
                    objects as u64,
                    2 * mem::size_of::<serde_json::Value>() as u64,
                )?,
            )?,
            4096,
        )?)?;
        let base_bytes = add(mul(row_bytes, 8)?, 64 * 1024 * 1024)?;
        let base = payer.reserve(base_bytes)?;
        let mut guards = Vec::new();
        guards.try_reserve_exact(count).map_err(io::Error::other)?;
        Ok(Self {
            payer,
            tails: RefCell::new(BTreeSet::new()),
            guards: RefCell::new(guards),
            base: RefCell::new(base),
            base_bytes: Cell::new(base_bytes),
            _registry: registry,
            row_bytes,
        })
    }
    pub(super) fn payer(&self) -> Arc<dyn ReportMemoryAccountant> {
        Arc::clone(&self.payer)
    }
    pub(super) fn working(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.payer.reserve(bytes)
    }
    /// The workspace for allocating one object.
    ///
    /// It follows the object, as the walk's does
    /// ([`crate::shadow_native::report_memory`]): its snapshot, which holds
    /// no more than the largest security descriptor Windows can produce, and
    /// the mapping queries of its longest stream, which cannot return more
    /// extents than a stream of that length has clusters. It used to be
    /// eight of the largest row the budget admits and thirty-two of the
    /// largest mapping reply there is: an eighth and a sixty-fourth of the
    /// run's memory for every object in turn, 1.4 GB on a machine with
    /// 16 GB, and what a volume of 500,000 files was refused for (#129).
    pub(super) fn row_peak(&self, item: &Input<'_>) -> io::Result<u64> {
        let path = item
            .components
            .iter()
            .try_fold(0u64, |n, s| add(n, s.len() as u64))?;
        let streams = add(item.named_streams.len() as u64, 1)?;
        let longest = item
            .named_streams
            .iter()
            .map(|stream| stream.expected_length)
            .fold(item.logical_length(), u64::max);
        let mut n = add(
            add(
                crate::shadow_native::report_memory::snapshot_peak(self.row_bytes)?,
                mul(
                    crate::retrieval_paging::returned_bytes_for_stream(longest) as u64,
                    32,
                )?,
            )?,
            mul(add(path, 4096)?, mul(streams, 16)?)?,
        )?;
        if let Some(s) = item.sparse {
            n = add(n, mul(s.allocated.len() as u64, 512)?)?;
        }
        for s in &item.named_streams {
            if let Some(s) = s.sparse {
                n = add(n, mul(s.allocated.len() as u64, 512)?)?;
            }
        }
        Ok(n)
    }
    pub(super) fn retain(
        &self,
        mut guard: Box<dyn ReportMemoryLease>,
        bytes: u64,
    ) -> io::Result<()> {
        if guard.shrink_to(bytes).is_err() {
            // What the object keeps is more than its workspace was: the
            // workspace follows the object's streams, and what is kept is
            // measured. A reservation of what is kept takes its place.
            guard = self.payer.reserve(bytes)?;
        }
        let mut guards = self.guards.borrow_mut();
        if guards.len() == guards.capacity() {
            return Err(invalid("private constructor guard registry exhausted"));
        }
        guards.push(guard);
        Ok(())
    }
    pub(super) fn retain_from(
        &self,
        guard: &mut Option<Box<dyn ReportMemoryLease>>,
        bytes: u64,
    ) -> io::Result<()> {
        let mut guards = self.guards.borrow_mut();
        if guards.len() == guards.capacity() {
            return Err(invalid("private constructor guard registry exhausted"));
        }
        guard
            .as_mut()
            .ok_or_else(|| invalid("actual retained state guard absent"))?
            .shrink_to(bytes)?;
        guards.push(guard.take().expect("validated actual retained state guard"));
        Ok(())
    }
    fn static_bytes(
        pair: &GeneralSourceShadowBinding,
        source_before: &source_scope::ConstructionSourceState,
        events: &Vec<NativeEvent>,
        system_identities: &BTreeMap<Vec<String>, Vec<u8>>,
        construction_enrollment: &Option<serde_json::Value>,
        carrier_directory: &Option<sparse_stream::CarrierDirectory>,
    ) -> io::Result<u64> {
        let mut n = add(state(source_before)?, vec_bytes(events)?)?;
        for event in events {
            n = add(
                n,
                add(
                    event.operation.capacity() as u64,
                    add(vec_bytes(&event.input)?, vec_bytes(&event.output)?)?,
                )?,
            )?;
        }
        for (path, id) in system_identities {
            n = add(
                n,
                add(
                    node::<Vec<String>, Vec<u8>>()?,
                    add(strings(path)?, vec_bytes(id)?)?,
                )?,
            )?;
        }
        if let Some(v) = construction_enrollment {
            n = add(n, json(v)?)?;
        }
        if let Some(c) = carrier_directory {
            n = add(n, c.retained_memory_bytes()?)?;
        }
        for p in [&pair.source, &pair.shadow] {
            n = add(
                n,
                (p.volume_guid.capacity()
                    + p.identity.disk_guid.capacity()
                    + p.identity.partition_guid.capacity()) as u64,
            )?;
        }
        n = add(n, node::<usize, File>()?)?;
        add(n, 65536)
    }
    /// Finish the one-off global query phase before per-object allocation.
    /// Keep its real static owners paid, and pay a separate small allowance
    /// for the remaining global route/descriptor queries before shrinking.
    pub(super) fn close_global_queries(
        &self,
        pair: &GeneralSourceShadowBinding,
        source_before: &source_scope::ConstructionSourceState,
        events: &Vec<NativeEvent>,
        system_identities: &BTreeMap<Vec<String>, Vec<u8>>,
        construction_enrollment: &Option<serde_json::Value>,
        carrier_directory: &Option<sparse_stream::CarrierDirectory>,
    ) -> io::Result<Box<dyn ReportMemoryLease>> {
        // Remaining global disk-state queries use 64 KiB replies; this also
        // covers their event copies and the fresh-root/constant-SDDL buffers.
        // Per-file queries and input decoding have their own separate leases.
        let queries = self.working(4 * 1024 * 1024)?;
        let current = Self::static_bytes(
            pair,
            source_before,
            events,
            system_identities,
            construction_enrollment,
            carrier_directory,
        )?;
        let previous = self.base_bytes.get();
        self.base.borrow_mut().shrink_to(current).map_err(|error| {
            io::Error::new(error.kind(), format!(
                "private constructor initial base shrink failed: previous_bytes={previous}, current_static_bytes={current}: {error}"
            ))
        })?;
        self.base_bytes.set(current);
        Ok(queries)
    }
    pub(super) fn close_base(&self, tree: &PrivateTree) -> io::Result<()> {
        let current = Self::static_bytes(
            &tree.pair,
            &tree.source_before,
            &tree.events,
            &tree.system_identities,
            &tree.construction_enrollment,
            &tree.carrier_directory,
        )?;
        let previous = self.base_bytes.get();
        // Allocation may add owned SVI identity-map entries after the initial
        // static-base shrink. Per-row leases cover those insertions. Reaccount
        // the complete final static state with a new real lease; a shrink-only
        // lease must never be used to grow it. The old base and the caller's
        // global-query workspace remain held until replacement is admitted.
        let replacement = self.payer.reserve(current).map_err(|error| {
            io::Error::new(error.kind(), format!(
                "private constructor final base replacement reservation failed: previous_bytes={previous}, current_static_bytes={current}, growth_bytes={}: {error}",
                current.saturating_sub(previous)
            ))
        })?;
        let old = self.base.replace(replacement);
        self.base_bytes.set(current);
        drop(old);
        Ok(())
    }
    pub(super) fn metadata_digest(&self) -> io::Result<Box<dyn ReportMemoryLease>> {
        // input_digest_domain may serialize a complete sparse/EA value; pay
        // its one-current-object workspace before invoking that serializer.
        self.working(mul(self.row_bytes, 8)?)
    }
    pub(super) fn materialization(
        &self,
        bytes: usize,
        islands: usize,
    ) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.working(add(
            add(mul(bytes as u64, 8)?, mul(islands as u64, 1024)?)?,
            32 * 1024 * 1024,
        )?)
    }
    pub(super) fn tail(&self, k: &StreamKey) -> io::Result<()> {
        if self.tails.borrow().contains(k) {
            return Ok(());
        }
        let bytes = add(
            add(
                node::<StreamKey, MaterializedTail>()?,
                node::<StreamKey, ()>()?,
            )?,
            add(mul(key(k)?, 3)?, 256)?,
        )?;
        let guard = self.working(bytes)?;
        self.retain(guard, bytes)?;
        self.tails.borrow_mut().insert(k.clone());
        Ok(())
    }
}
pub(super) fn object_bytes(
    index: usize,
    objects: &Vec<serde_json::Value>,
    files: &BTreeMap<StreamKey, unwritten::PrivatePlaceholder>,
    targets: &BTreeMap<StreamKey, sparse_stream::Target>,
    metadata: &BTreeMap<usize, File>,
) -> io::Result<u64> {
    let mut n = json(
        objects
            .last()
            .ok_or_else(|| invalid("private object receipt absent"))?,
    )?;
    if metadata.contains_key(&index) && index != 0 {
        n = add(n, node::<usize, File>()?)?;
    }
    let start = StreamKey::unnamed(index);
    let end = StreamKey::unnamed(
        index
            .checked_add(1)
            .ok_or_else(|| invalid("private object index overflow"))?,
    );
    for (k, f) in files.range(start.clone()..end.clone()) {
        n = add(
            n,
            add(
                node::<StreamKey, unwritten::PrivatePlaceholder>()?,
                add(key(k)?, f.retained_memory_bytes()?)?,
            )?,
        )?;
    }
    for (k, t) in targets.range(start..end) {
        n = add(
            n,
            add(
                node::<StreamKey, sparse_stream::Target>()?,
                add(key(k)?, t.retained_memory_bytes()?)?,
            )?,
        )?;
    }
    Ok(n)
}

pub(super) fn original_coordinates_bytes(tree: &PrivateTree) -> io::Result<u64> {
    coordinate_map_bytes(&tree.original_coordinates)
}
pub(super) fn coordinate_map_bytes(
    coordinates: &BTreeMap<StreamKey, Vec<(u64, u64, u64)>>,
) -> io::Result<u64> {
    coordinates
        .iter()
        .try_fold(65536u64, |n, (stream, ranges)| {
            add(
                n,
                add(
                    node::<StreamKey, Vec<(u64, u64, u64)>>()?,
                    add(key(stream)?, vec_bytes(ranges)?)?,
                )?,
            )
        })
}
pub(super) fn value_bytes(value: &serde_json::Value) -> io::Result<u64> {
    json(value)
}
pub(super) fn slot_bytes(k: &StreamKey) -> io::Result<u64> {
    add(node::<usize, StreamKey>()?, key(k)?)
}

#[cfg(test)]
mod charge_tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn a_receipt_is_charged_its_nodes_once_and_what_its_fields_hold() {
        let receipt = serde_json::json!({
            "object_index": 7, "components": ["feature-manyfiles", "00", "00000", "file-0000007.dat"],
            "disposition": "created", "file_id": "0x0001000000000123", "streams": 1,
            "logical_bytes": 412, "placement": {"kind": "resident", "bytes": 412}
        });
        let charged = json(&receipt).unwrap();
        let node = complete_node::<String, Value>().unwrap();
        // Two maps (the receipt and its placement), each of one node.
        let Value::Object(fields) = &receipt else {
            unreachable!()
        };
        let held: u64 = fields.keys().map(|key| key.capacity() as u64).sum();
        assert!(charged >= 2 * node + held, "{charged}");
        // Not a node for every field, as it was.
        assert!(charged < 4 * node, "{charged} for {} fields", fields.len());
        // A node is at least what eleven slots, twelve edges and the
        // headers take.
        let slots =
            (11 * (mem::size_of::<String>() + mem::size_of::<Value>()) + 12 * 8 + 32) as u64;
        assert!(node >= slots, "{node} < {slots}");
    }

    #[test]
    fn a_map_is_charged_at_least_the_nodes_it_can_have() {
        let whole = complete_node::<String, Value>().unwrap();
        assert_eq!(tree::<String, Value>(0).unwrap(), whole);
        assert_eq!(tree::<String, Value>(11).unwrap(), whole);
        // Beyond one node: a leaf for every five entries and an inner node
        // for every twenty-five are the most a tree has.
        for entries in [12usize, 60, 1000, 100_000] {
            let most = (entries / 5 + entries / 25 + 2) as u64;
            assert!(
                tree::<String, Value>(entries).unwrap() >= most * whole,
                "{entries}"
            );
        }
        // And an entry of a large shared map is charged more than its share.
        let entry = node::<usize, File>().unwrap();
        assert!(entry * 100 >= complete_node::<usize, File>().unwrap() * 24);
    }
}
#[cfg(test)]
mod workspace_tests {
    use super::*;
    use crate::shadow_native::report_memory::test_payer::Counted;

    const MIB: u64 = 1024 * 1024;

    fn item<'a>(
        components: &'a [String],
        length: u64,
        named_streams: Vec<NamedStreamInput<'a>>,
    ) -> Input<'a> {
        Input {
            components,
            additional_names: &[],
            directory: false,
            times: [0; 4],
            attributes: 32,
            security: &[],
            expected_api_security: None,
            extended_attributes: None,
            reparse: None,
            payload: &[],
            expected_length: Some(length),
            expected_sha256: None,
            source_offset: None,
            source_runs: Vec::new(),
            named_streams,
            sparse: None,
        }
    }

    #[test]
    fn the_workspace_of_an_object_follows_its_streams_not_the_machine() {
        let components = vec![
            "feature-manyfiles".to_owned(),
            "file-0000007.dat".to_owned(),
        ];
        let small = item(&components, 412, Vec::new());
        let peak_with = |row_bytes: u64, item: &Input<'_>| {
            let payer = Arc::new(Counted::with_limit(u64::MAX));
            Owner::new(payer, 16, 16, row_bytes)
                .unwrap()
                .row_peak(item)
                .unwrap()
        };
        // A machine with 16 GB free admits rows of 141 MiB, one with 64 GB
        // rows of 600 MiB: a small file's workspace is the same on both,
        // and a few megabytes. (It was eight of those rows and thirty-two
        // of the largest mapping reply there is: 1.4 GB on the first.)
        let on_16 = peak_with(141 * MIB, &small);
        assert_eq!(on_16, peak_with(600 * MIB, &small));
        assert!(on_16 < 8 * MIB, "{on_16}");
        // A long file's is larger by what its mapping can take, and a named
        // stream longer than the file decides it.
        let long = item(&components, 64 << 30, Vec::new());
        let long_peak = peak_with(141 * MIB, &long);
        assert!(long_peak > on_16, "{long_peak}");
        let name: Vec<u16> = "payload".encode_utf16().collect();
        let stream = |expected_length| NamedStreamInput {
            name_utf16: &name,
            expected_length,
            expected_sha256: None,
            source_offset: None,
            source_runs: Vec::new(),
            sparse: None,
        };
        let with_stream = item(&components, 412, vec![stream(64 << 30)]);
        assert!(peak_with(141 * MIB, &with_stream) >= long_peak);
        let with_short = item(&components, 412, vec![stream(100)]);
        assert!(peak_with(141 * MIB, &with_short) < long_peak);
    }

    #[test]
    fn what_an_object_keeps_is_reserved_even_beyond_its_workspace() {
        let payer = Arc::new(Counted::with_limit(u64::MAX));
        let owner = Owner::new(payer.clone(), 16, 16, MIB).unwrap();
        let before = payer.held();
        // The usual case: what is kept is less than the workspace.
        let workspace = owner.working(4 * MIB).unwrap();
        owner.retain(workspace, 6000).unwrap();
        assert_eq!(payer.held(), before + 6000);
        // What is kept is measured; when it is more than the workspace was,
        // it is reserved as what it is and the workspace is returned.
        let workspace = owner.working(4096).unwrap();
        owner.retain(workspace, 3 * MIB).unwrap();
        assert_eq!(payer.held(), before + 6000 + 3 * MIB);
        // And with no room for it the object is refused.
        let tight = Arc::new(Counted::with_limit(u64::MAX));
        let owner = Owner::new(tight.clone(), 16, 16, MIB).unwrap();
        let workspace = owner.working(4096).unwrap();
        let none = Arc::new(Counted::with_limit(0));
        let refusing = Owner {
            payer: none,
            ..owner
        };
        assert!(refusing.retain(workspace, 3 * MIB).is_err());
    }
}
