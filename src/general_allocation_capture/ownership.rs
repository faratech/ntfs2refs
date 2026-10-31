//! Same-handle native freeze and raw required/allocation observations.
use crate::{
    ntfs_admission::ResourceProfile, refs_allocator, refs_inspect, refs_ownership,
    refs_required_ranges, refs_write_set::ByteRange,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralFrozenPartition, GeneralReadonlyAllocationWitness, NativeEvent};
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

const MAX_RAW_READ_BYTES: u64 = 256 * 1024 * 1024;
const MAX_GRAPH_PAGES: u32 = 8192;

struct Measured<'a> {
    target: &'a mut GeneralFrozenPartition,
    bytes: u64,
    calls: u64,
}
impl Read for Measured<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self
            .bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > MAX_RAW_READ_BYTES)
        {
            return Err(io::Error::other(
                "native ownership raw-read budget exceeded",
            ));
        }
        let count = self.target.read(bytes)?;
        self.bytes += count as u64;
        self.calls += 1;
        Ok(count)
    }
}
impl Seek for Measured<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.target.seek(position)
    }
}

#[derive(Serialize)]
pub(super) struct BoundObservation {
    binding: n2r_win32::general_layout::GeneralDiskBinding,
    frozen_state: n2r_win32::GeneralDiskState,
    selected_native_phase: n2r_win32::GeneralAllocationPhase,
    native_query_physically_readonly: bool,
    selected_metadata_bitmap_sha256: String,
    raw_required: refs_required_ranges::GenerationUnion,
    raw_medium: refs_allocator::MediumAllocatorObservation,
    raw_small: refs_allocator::SmallAllocatorObservation,
    reconciliation: refs_ownership::OwnershipReconciliation,
    logical_raw_bytes_read: u64,
    raw_read_calls: u64,
    raw_read_accounting_scope: &'static str,
    max_raw_read_bytes: u64,
    live_freeze_witness_validated_before_and_after: bool,
    complete_graph_verified: bool,
    reconstruction_authorized: bool,
}

pub(super) fn collect(
    target: &mut GeneralFrozenPartition,
    witness: &GeneralReadonlyAllocationWitness,
    resources: ResourceProfile,
    events: &mut Vec<NativeEvent>,
) -> Result<BoundObservation> {
    ensure!(
        resources.is_streaming(),
        "required ownership observation needs the explicit streaming-v2 profile"
    );
    target.validate_readonly_allocation_witness(witness, events)?;
    let before = target.state(events)?;
    let length = target.byte_len();
    ensure!(
        before.disk_attributes == 3 && target.binding() == witness.binding(),
        "required ownership needs the exact persistently excluded frozen handle"
    );
    let snapshot = witness.snapshot();
    ensure!(
        witness.observed_readonly().disk_attributes == 2,
        "native allocation query was not physically read-only"
    );
    let allocation = snapshot.metadata_inclusive();
    ensure!(
        allocation.cluster_count.checked_mul(4096) == Some(length),
        "native bitmap domain differs"
    );
    let native: Vec<_> = allocation
        .ranges
        .iter()
        .map(|r| ByteRange {
            offset: r.offset,
            length: r.length,
        })
        .collect();
    let mut reader = Measured {
        target,
        bytes: 0,
        calls: 0,
    };
    let refs = refs_inspect::inspect_physical_bootstrap(&mut reader, length)?;
    let required = refs_required_ranges::inspect(
        &mut reader,
        &refs.geometry,
        refs.bootstrap
            .as_ref()
            .context("required ownership bootstrap absent")?,
        MAX_GRAPH_PAGES,
    )?;
    let medium =
        refs_allocator::inspect_medium_with_resource_profile(&mut reader, length, resources)?;
    let small =
        refs_allocator::inspect_small_with_resource_profile(&mut reader, length, resources)?;
    let highest = required
        .generations
        .iter()
        .map(|g| (g.checkpoint_clock, g.checkpoint_lcn))
        .max()
        .context("required ownership has no checked generation")?;
    ensure!(
        medium.allocator_walk_complete
            && small.allocator_walk_complete
            && (medium.checkpoint_clock, medium.checkpoint_lcn) == highest
            && (small.checkpoint_clock, small.checkpoint_lcn) == highest,
        "raw allocator walks are not complete on the selected checkpoint"
    );
    let raw_medium: Vec<_> = medium
        .allocated_ranges
        .iter()
        .map(|r| ByteRange {
            offset: r.offset,
            length: r.length,
        })
        .collect();
    let raw_small: Vec<_> = small
        .allocated_ranges
        .iter()
        .map(|r| ByteRange {
            offset: r.offset,
            length: r.length,
        })
        .collect();
    let reconciliation = refs_ownership::reconcile(
        length,
        &native,
        &raw_medium,
        &raw_small,
        &required.observed_required_ranges,
    )?;
    ensure!(
        allocation.allocated_clusters.checked_mul(4096)
            == Some(reconciliation.native_allocated_bytes),
        "native bitmap count differs from its complete intervals"
    );
    let bytes = reader.bytes;
    let calls = reader.calls;
    drop(reader);
    target.validate_readonly_allocation_witness(witness, events)?;
    ensure!(
        target.state(events)? == before,
        "native ownership exclusion or route changed"
    );
    Ok(BoundObservation {
        binding: witness.binding().clone(),
        frozen_state: before,
        selected_native_phase: snapshot.phase(),
        native_query_physically_readonly: true,
        selected_metadata_bitmap_sha256: allocation.bitmap_sha256.clone(),
        raw_required: required,
        raw_medium: medium,
        raw_small: small,
        reconciliation,
        logical_raw_bytes_read: bytes,
        raw_read_calls: calls,
        max_raw_read_bytes: MAX_RAW_READ_BYTES,
        raw_read_accounting_scope: "Logical raw reads in required-ownership collection only; preceding bootstrap reads and native FSCTL I/O are excluded.",
        live_freeze_witness_validated_before_and_after: true,
        complete_graph_verified: false,
        reconstruction_authorized: false,
    })
}
