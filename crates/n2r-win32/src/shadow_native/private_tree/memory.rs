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
// BTreeMap does not expose node capacity. Prepay one complete oversized node
// per inserted entry, rather than charging a hypothetical maximum row per file.
fn node<K, V>() -> io::Result<u64> {
    add(
        mul((mem::size_of::<K>() + mem::size_of::<V>()) as u64, 16)?,
        256,
    )
}
fn json(v: &serde_json::Value) -> io::Result<u64> {
    use serde_json::Value;
    match v {
        Value::String(s) => Ok(s.capacity() as u64),
        Value::Array(a) => a.iter().try_fold(vec_bytes(a)?, |n, v| add(n, json(v)?)),
        Value::Object(m) => m.iter().try_fold(0, |n, (k, v)| {
            add(
                n,
                add(
                    node::<String, Value>()?,
                    add(k.capacity() as u64, json(v)?)?,
                )?,
            )
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
    pub(super) fn row_peak(&self, item: &Input<'_>) -> io::Result<u64> {
        let path = item
            .components
            .iter()
            .try_fold(0u64, |n, s| add(n, s.len() as u64))?;
        let streams = add(item.named_streams.len() as u64, 1)?;
        let mut n = add(
            add(
                mul(self.row_bytes, 8)?,
                mul(crate::retrieval_paging::MAX_RETURNED_BYTES as u64, 32)?,
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
        guard.shrink_to(bytes)?;
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
