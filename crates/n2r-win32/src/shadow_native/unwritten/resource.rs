//! V4-only native-placement budgets. These helpers carry real payer leases;
//! they do not create file, source, device, or move authority.
use super::{destination_limits, invalid};
use crate::{
    retrieval_paging::{self, Capture, Limits},
    shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease},
    tree_resources::SourceResourceAdmission,
};
use std::{fs::File, io, mem, sync::Arc};

type Lease = Box<dyn ReportMemoryLease>;

pub(super) struct ResourcePlacement {
    pub(super) max_tracked_slots: usize,
    pub(super) max_moves: usize,
    pub(super) retrieval_bytes: usize,
    payer: Arc<dyn ReportMemoryAccountant>,
    // The currently owned `PrivatePlaceholder::placed` vector drops before
    // this field when its owner is destroyed. Replacements reserve the new
    // owner before releasing the previous one.
    placed: Option<Lease>,
    _state: Lease,
}

/// See [`ResourcePlacement::retrieval_bytes_for`]: of a row of `row` bytes,
/// what the mapping of a file of `file_bytes` can take.
fn retrieval_bytes_for(row: usize, file_bytes: u64) -> usize {
    row.min(retrieval_paging::returned_bytes_for_stream(file_bytes).saturating_mul(4))
}

/// Holes may outlive the placeholder and thus retain their own actual lease.
pub(crate) struct ResourceTrackedHoles {
    holes: Vec<(u64, u32)>,
    _lease: Lease,
}
impl ResourceTrackedHoles {
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, (u64, u32)> {
        self.holes.iter()
    }
    pub(crate) fn len(&self) -> usize {
        self.holes.len()
    }
}

impl ResourcePlacement {
    pub(super) fn new(
        admission: SourceResourceAdmission,
        max_tracked_slots: usize,
        requested_moves: usize,
        max_move_bytes: u64,
        payer: Arc<dyn ReportMemoryAccountant>,
    ) -> io::Result<Self> {
        admission.validate()?;
        let slots = admission.placement_slots()?;
        let byte_moves = usize::try_from(max_move_bytes / crate::target_cluster::bytes())
            .map_err(io::Error::other)?;
        if slots == 0
            || max_tracked_slots == 0
            || max_tracked_slots > slots
            || requested_moves == 0
            || requested_moves > byte_moves
        {
            return Err(invalid("resource placement slots or move budget differ"));
        }
        let retrieval_bytes =
            usize::try_from(admission.budget.max_row_bytes).map_err(io::Error::other)?;
        Limits::for_resource_bytes(retrieval_bytes)?;
        // The inline Option/state and Arc pointer already belong to the
        // prepaid placeholder BTree node. Only the actual lease adapter and
        // a small fixed allocation/control allowance are added on enablement.
        let state_bytes = 256u64
            .checked_add(payer.lease_heap_bytes())
            .ok_or_else(|| invalid("resource placement state RAM overflow"))?;
        let state = payer.reserve(state_bytes)?;
        Ok(Self {
            max_tracked_slots,
            max_moves: requested_moves,
            retrieval_bytes,
            payer,
            placed: None,
            _state: state,
        })
    }

    /// The caller holds `workspace` through every native query and resulting
    /// capture/proof. Complete retrieval assembly is unchanged.
    pub(super) fn capture(&self, file: &File) -> io::Result<Capture> {
        crate::stream_native::retrieval_capture_resource(file, self.retrieval_bytes)
    }

    /// The mapping of the VCNs from `start` to `limit` only, under the same
    /// limits and the same workspace as [`Self::capture`].
    pub(super) fn capture_range(&self, file: &File, start: u64, limit: u64) -> io::Result<Capture> {
        crate::stream_native::retrieval_range_capture_resource(
            file,
            self.retrieval_bytes,
            start,
            limit,
        )
    }

    /// The room a file of `file_bytes` can take of the row that mapping
    /// queries are limited to: a stream has no more extents than clusters,
    /// and a query's limits allow a quarter of the row for what it returns.
    /// The workspaces below were sized by the row itself, a sixty-fourth of
    /// the run's memory, eight times over: an eighth of the ledger for
    /// tracking a file of one cluster, and again for every move.
    fn retrieval_bytes_for(&self, file_bytes: u64) -> usize {
        retrieval_bytes_for(self.retrieval_bytes, file_bytes)
    }

    pub(super) fn tracking_workspace(&self, file_bytes: u64) -> io::Result<Lease> {
        let clusters = usize::try_from(file_bytes / crate::target_cluster::bytes())
            .map_err(io::Error::other)?;
        let slots = self.max_tracked_slots.min(clusters);
        let bytes = (self.retrieval_bytes_for(file_bytes) as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add((slots as u64).checked_mul(256)?))
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("resource tracking RAM overflow"))?;
        self.payer.reserve(bytes)
    }

    /// Pay bitmap windows, lossless encodings, complete retrieval assembly,
    /// and tracked-map clones before submitting a native move.
    pub(super) fn move_workspace(
        &self,
        file_bytes: u64,
        clusters: u32,
        tracked: usize,
    ) -> io::Result<Lease> {
        if clusters == 0 || tracked > self.max_tracked_slots {
            return Err(invalid("resource move workspace bounds differ"));
        }
        let windows = destination_limits(clusters)?;
        let retrieval_bytes = self.retrieval_bytes_for(file_bytes);
        let bytes = (retrieval_bytes as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add((windows.max_returned_bytes as u64).checked_mul(16)?))
            .and_then(|n| n.checked_add((windows.max_window_bytes as u64).checked_mul(8)?))
            .and_then(|n| n.checked_add((windows.max_pages as u64).checked_mul(2048)?))
            .and_then(|n| n.checked_add((tracked as u64).checked_add(4)?.checked_mul(256)?))
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("resource move workspace overflow"))?;
        let retrieval = Limits::for_resource_bytes(retrieval_bytes)?;
        let canonical = (retrieval.max_extents as u64)
            .checked_mul(16)
            .and_then(|n| n.checked_add(16))
            .ok_or_else(|| invalid("resource canonical bound overflow"))?;
        // Serialization happens after native query temporaries drop. Keep
        // the larger peak, then TRANSFER this prepaid guard into the returned
        // JSON owner: no allocator reservation is required after movement.
        // into_resource_value first owns the raw canonical bytes and one
        // Value array, then drops that raw Placement before returning. The
        // enclosing move record creates a second Value array while the first
        // owner/guard stays live. Both compact sizing and the resource sink
        // serialize into streaming writers, not a third whole-proof buffer.
        // Two Value slots per canonical byte therefore cover both stages;
        // every paging/window allowance below remains independently paid.
        // (The mapping now stays raw bytes in the proof and the record is
        // serialized once, so this is more than a move takes; it is left
        // as it was until a change of its own narrows it.)
        let json = canonical
            .checked_mul(2 * mem::size_of::<serde_json::Value>() as u64)
            .and_then(|n| n.checked_add((retrieval.max_pages as u64).checked_mul(6144)?))
            .and_then(|n| n.checked_add((windows.max_returned_bytes as u64).checked_mul(32)?))
            .and_then(|n| n.checked_add((windows.max_window_bytes as u64).checked_mul(16)?))
            .and_then(|n| n.checked_add((windows.max_pages as u64).checked_mul(4096)?))
            .and_then(|n| n.checked_add(8 * 1024 * 1024 + self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("resource JSON proof bound overflow"))?;
        self.payer.reserve(bytes.max(json))
    }

    pub(super) fn coverage_workspace(&self, capacity: usize) -> io::Result<Lease> {
        self.payer.reserve(
            (capacity as u64)
                .checked_mul(3 * mem::size_of::<(u64, u64, u32)>() as u64)
                .and_then(|n| n.checked_add(65536 + self.payer.lease_heap_bytes()))
                .ok_or_else(|| invalid("resource coverage RAM overflow"))?,
        )
    }

    pub(super) fn reserve_placed(&self, length: usize, capacity: usize) -> io::Result<Lease> {
        if length > self.max_tracked_slots
            || capacity < length
            || capacity > self.max_tracked_slots.saturating_mul(2)
        {
            return Err(invalid("resource tracked-map capacity exceeds admission"));
        }
        let bytes = (capacity as u64)
            .checked_mul(mem::size_of::<(u64, u64, u32)>() as u64)
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("resource retained mapping RAM overflow"))?;
        self.payer.reserve(bytes)
    }

    /// Call only after the old vector has dropped and the new vector is held.
    pub(super) fn replace_placed_lease(&mut self, lease: Lease) {
        self.placed = Some(lease);
    }

    /// The caller retains its tracking workspace until this own lease exists.
    pub(super) fn hold_holes(&self, holes: Vec<(u64, u32)>) -> io::Result<ResourceTrackedHoles> {
        if holes.len() > self.max_tracked_slots
            || holes.capacity() > self.max_tracked_slots.saturating_mul(2)
        {
            return Err(invalid("resource deferred holes exceed admission"));
        }
        let bytes = (holes.capacity() as u64)
            .checked_mul(mem::size_of::<(u64, u32)>() as u64)
            .and_then(|n| n.checked_add(self.payer.lease_heap_bytes()))
            .ok_or_else(|| invalid("resource retained holes RAM overflow"))?;
        let lease = self.payer.reserve(bytes)?;
        Ok(ResourceTrackedHoles {
            holes,
            _lease: lease,
        })
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;

    #[test]
    fn a_files_mapping_workspace_follows_its_clusters_up_to_the_row() {
        const MIB: usize = 1024 * 1024;
        // A machine with 16 GB free limits a row to 141 MiB. A file of one
        // cluster can return one response's worth of extents, and its
        // workspace is eight times four of that: a megabyte, where it was
        // 1.1 GB.
        let small = retrieval_bytes_for(141 * MIB, 4096);
        assert_eq!(small, 4 * retrieval_paging::returned_bytes_for_stream(4096));
        assert!(8 * small < 2 * MIB, "{small}");
        // It grows with the file,
        let larger = retrieval_bytes_for(141 * MIB, 1 << 30);
        assert!(larger > small && larger < 141 * MIB, "{larger}");
        // up to what the longest mapping this process accepts returns, and
        // never beyond the row.
        assert_eq!(
            retrieval_bytes_for(141 * MIB, u64::MAX),
            (4 * retrieval_paging::max_returned_bytes()).min(141 * MIB)
        );
        // A row shorter than the file could need stays the limit.
        assert_eq!(retrieval_bytes_for(65536, 1 << 30), 65536);
        // The query limits made from it still hold a complete response.
        assert!(Limits::for_resource_bytes(small).is_ok());
    }
}
