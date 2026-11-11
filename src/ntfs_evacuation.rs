//! Read-only, best-effort NTFS collision evacuation estimates.
//!
//! An empty ReFS volume's observed occupied intervals are only a lower bound on
//! its eventual native allocation. These suggestions neither reserve space nor
//! authorize FSCTL_MOVE_FILE, raw writes, source admission, or conversion. A
//! preparation implementation must independently bind/recheck live NTFS objects,
//! preserve their contents through native moves, and then obtain a fresh complete
//! source inventory and opaque certificate. Final native ReFS placement remains
//! authoritative. There is deliberately no device I/O or report deserialization.

use crate::ntfs_inspect::{
    AllocationReconciliationStatus, FileInventory, MetadataRole, NtfsInspection, StreamInventory,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

/// Partition-relative bytes. Both target occupancy and immutable target anchors
/// use this representation; neither input is an authenticated allocation proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ByteInterval {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bounds all vector capacity allocated by this call, including temporary
    /// ownership/exclusion intervals and report spare capacity. Borrowed input
    /// storage and the caller's JSON serialization are outside this budget.
    pub max_metadata_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    PlainInitializedUnnamedUserData,
    SystemMetadata,
    UnclassifiedMetadataRole,
    Directory,
    ExtensionRecord,
    UnresolvedFileIdentity,
    NamedStream,
    ResidentStream,
    SparseStream,
    CompressedStream,
    EncryptedStream,
    OtherStreamFlags,
    MissingStandardInformation,
    UnsupportedFileAttributes,
    UninitializedData,
    AttributeMismatch,
    InvalidPlainLayout,
    NoInitializedWholeClusters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NoObservedCollision,
    SkippedUnsupported,
    CollisionOutsideInitializedWholeClusters,
    AllEligibleCollisionsHaveSuggestions,
    SomeEligibleCollisionsLackOutsideHeadroom,
}

/// A suggestion in NTFS cluster units, never an executable/native request.
/// Counts are split at u32::MAX clusters, matching the native count field without
/// retaining one report item per cluster.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct MoveCandidate {
    pub record_number: u64,
    pub sequence_number: u16,
    pub stream_index: usize,
    pub starting_vcn: u64,
    pub source_lcn: u64,
    pub destination_lcn: u64,
    pub cluster_count: u32,
}

/// Every inventoried DATA stream receives a decision, including system, resident,
/// and unsupported streams. Indices refer to the supplied inventory; stream names
/// and contents are not copied into this bounded report or discarded by a move.
#[derive(Debug, Serialize)]
pub struct StreamDecision {
    pub record_number: u64,
    pub sequence_number: u16,
    pub stream_index: usize,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub eligibility: Eligibility,
    pub outcome: Outcome,
    /// Physical allocation intersecting target occupancy/anchors, rounded out to
    /// NTFS clusters. Includes partial EOF clusters and excess reservations.
    pub observed_collision_bytes: u64,
    /// Only whole clusters wholly before initialized EOF, for eligible streams.
    pub eligible_collision_bytes: u64,
    pub proposed_move_bytes: u64,
    pub unplanned_collision_bytes: u64,
    pub first_move_index: usize,
    pub move_count: usize,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub ntfs_cluster_bytes: u32,
    pub partition_bytes: u64,
    pub target_avoid_cluster_bytes: u64,
    /// Union of all source-owned allocation intersecting known target exclusions;
    /// includes unsupported streams and non-DATA NTFS metadata.
    pub source_owned_collision_bytes: u64,
    /// Required simultaneous space for all eligible collisions. No proposed move
    /// is allowed to reuse any original source-owned cluster, even after another
    /// move would have freed it.
    pub required_outside_headroom_bytes: u64,
    /// NTFS-free clusters outside the *observed* target exclusions. This can
    /// overestimate space outside final native ReFS allocation.
    pub observed_outside_free_bytes: u64,
    pub observed_headroom_shortfall_bytes: u64,
    pub proposed_move_bytes: u64,
    pub source_owned_collision_bytes_left_unplanned: u64,
    /// M reads + M writes for the M suggested payload bytes. Native metadata,
    /// verification, retries, and later conversion I/O are not included.
    pub estimated_payload_read_bytes: u64,
    pub estimated_payload_write_bytes: u64,
    pub estimated_payload_io_bytes: u64,
    pub streams: Vec<StreamDecision>,
    pub moves: Vec<MoveCandidate>,
    /// Conservative allocation accounting: also charges temporary vectors after
    /// their storage is released. Hitting the limit returns Err, never truncation.
    pub metadata_reserved_bytes: u64,
    pub metadata_limit_bytes: u64,
    pub target_occupancy_is_lower_bound: bool,
    pub preparation_best_effort: bool,
    pub final_native_placement_required: bool,
    pub fresh_source_inventory_and_certificate_required: bool,
    pub source_admitted: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: u64,
    end: u64,
}

impl Span {
    fn length(self) -> u64 {
        self.end - self.start // Every constructor establishes start < end.
    }
}

struct Budget {
    used: u64,
    limit: u64,
}

impl Budget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .context("evacuation metadata accounting overflow")?;
        ensure!(
            self.used <= self.limit,
            "evacuation metadata budget exceeded; no partial plan returned"
        );
        Ok(())
    }

    fn push<T>(&mut self, items: &mut Vec<T>, item: T) -> Result<()> {
        let element = u64::try_from(std::mem::size_of::<T>())?;
        ensure!(element != 0, "zero-sized evacuation metadata element");
        if items.len() == items.capacity() {
            let slots = ((self.limit - self.used) / element).min(64);
            ensure!(
                slots != 0,
                "evacuation metadata budget exceeded; no partial plan returned"
            );
            let before = items.capacity();
            items
                .try_reserve_exact(usize::try_from(slots)?)
                .context("allocating bounded evacuation metadata")?;
            let added = u64::try_from(items.capacity() - before)?
                .checked_mul(element)
                .context("evacuation vector capacity overflow")?;
            self.charge(added)?;
        }
        items.push(item);
        Ok(())
    }
}

/// Sort/merge in place. Source ownership additionally rejects overlap instead of
/// concealing an inconsistent inventory under a union operation.
fn normalize(spans: &mut Vec<Span>, reject_overlap: bool) -> Result<()> {
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let mut written = 0usize;
    for read in 0..spans.len() {
        let next = spans[read];
        if written != 0 && next.start <= spans[written - 1].end {
            ensure!(
                !reject_overlap || next.start == spans[written - 1].end,
                "reconciled NTFS ownership contains overlapping physical intervals"
            );
            spans[written - 1].end = spans[written - 1].end.max(next.end);
        } else {
            spans[written] = next;
            written = written.checked_add(1).context("interval count overflow")?;
        }
    }
    spans.truncate(written);
    Ok(())
}

fn total_bytes(spans: &[Span]) -> Result<u64> {
    spans.iter().try_fold(0u64, |total, span| {
        total
            .checked_add(span.length())
            .context("evacuation interval byte total overflow")
    })
}

fn each_intersection(
    exclusions: &[Span],
    range: Span,
    mut visit: impl FnMut(Span) -> Result<()>,
) -> Result<()> {
    let first = exclusions.partition_point(|span| span.end <= range.start);
    for excluded in &exclusions[first..] {
        if excluded.start >= range.end {
            break;
        }
        visit(Span {
            start: range.start.max(excluded.start),
            end: range.end.min(excluded.end),
        })?;
    }
    Ok(())
}

fn collision_bytes(exclusions: &[Span], range: Span) -> Result<u64> {
    let mut bytes = 0u64;
    each_intersection(exclusions, range, |intersection| {
        bytes = bytes
            .checked_add(intersection.length())
            .context("evacuation collision total overflow")?;
        Ok(())
    })?;
    Ok(bytes)
}

fn target_exclusions(
    occupied: &[ByteInterval],
    anchors: &[ByteInterval],
    partition_bytes: u64,
    domain: u64,
    cluster: u64,
    budget: &mut Budget,
) -> Result<Vec<Span>> {
    let mut spans = Vec::new();
    for interval in occupied.iter().chain(anchors) {
        let end = interval
            .offset
            .checked_add(interval.length)
            .context("target occupancy/anchor interval overflow")?;
        ensure!(
            interval.length != 0 && end <= partition_bytes,
            "target occupancy/anchor interval is empty or outside the partition"
        );
        if interval.offset >= domain {
            continue; // No NTFS cluster or candidate destination exists here.
        }
        let end = end
            .min(domain)
            .checked_next_multiple_of(cluster)
            .context("target exclusion cluster rounding overflow")?;
        budget.push(
            &mut spans,
            Span {
                start: interval.offset / cluster * cluster,
                end,
            },
        )?;
    }
    normalize(&mut spans, false)?;
    Ok(spans)
}

fn source_ownership(
    raw: &NtfsInspection,
    domain: u64,
    cluster: u64,
    budget: &mut Budget,
) -> Result<Vec<Span>> {
    let reconciliation = raw
        .allocation_reconciliation
        .as_ref()
        .context("evacuation requires raw allocation reconciliation")?;
    // `inventory_complete` is a broader inspector/admission claim which this
    // alpha intentionally leaves false. ConsistentRawModel specifically proves
    // the complete raw allocation inventory against the observed bitmap; check
    // its retained counts and ownership below without promoting it to admission.
    ensure!(
        reconciliation.status == AllocationReconciliationStatus::ConsistentRawModel
            && reconciliation.domain_clusters == raw.geometry.total_clusters,
        "evacuation requires a complete, exactly reconciled NTFS allocation model"
    );
    let allocated = raw
        .allocated_clusters
        .context("missing reconciled NTFS allocated cluster count")?;
    let free = raw
        .free_clusters
        .context("missing reconciled NTFS free cluster count")?;
    ensure!(
        allocated.checked_add(free) == Some(raw.geometry.total_clusters),
        "reconciled NTFS allocation counts differ from the cluster domain"
    );
    let canonical = raw.files.iter().flat_map(|file| file.attributes.iter());
    // Match the reconciler: canonical DATA owns its complete allocation once;
    // a nonresident ATTRIBUTE_LIST still owns its original metadata storage.
    let lists = raw.attribute_assemblies.iter().filter_map(|assembly| {
        assembly
            .base
            .attributes
            .iter()
            .find(|attribute| attribute.type_code == 0x20 && !attribute.resident)
    });
    let mut spans = Vec::new();
    let mut intervals = 0usize;
    for attribute in canonical.chain(lists) {
        if attribute.resident {
            continue; // Resident bytes are contained in the MFT allocation.
        }
        for extent in &attribute.extents {
            let Some(physical) = extent.physical_offset else {
                continue; // Sparse holes have no physical ownership.
            };
            let end = physical
                .checked_add(extent.length)
                .context("NTFS owned interval overflow")?;
            ensure!(
                extent.length != 0
                    && physical.is_multiple_of(cluster)
                    && extent.length.is_multiple_of(cluster)
                    && extent.logical_offset.is_multiple_of(cluster)
                    && end <= domain,
                "NTFS owned interval is not a whole cluster range inside the domain"
            );
            budget.push(
                &mut spans,
                Span {
                    start: physical,
                    end,
                },
            )?;
            intervals = intervals
                .checked_add(1)
                .context("NTFS ownership interval count overflow")?;
        }
    }
    ensure!(
        intervals == reconciliation.physical_intervals,
        "NTFS physical interval count differs from the reconciled inventory"
    );
    normalize(&mut spans, true)?;
    ensure!(
        allocated.checked_mul(cluster) == Some(total_bytes(&spans)?),
        "NTFS ownership union differs from reconciled allocated clusters"
    );
    Ok(spans)
}

fn eligibility(file: &FileInventory, stream: &StreamInventory, cluster: u64) -> Eligibility {
    use Eligibility::*;
    if file.is_directory {
        return Directory;
    }
    if file.record_number < 16
        || file.is_metadata
        || matches!(
            file.metadata_role,
            MetadataRole::ReservedSystemRecord | MetadataRole::ExtendDescendantCandidate
        )
    {
        return SystemMetadata;
    }
    if file.base_file_reference != 0 {
        return ExtensionRecord;
    }
    if file.metadata_role != MetadataRole::OutsideExtendCandidate
        || file.metadata_role_issue.is_some()
    {
        return UnclassifiedMetadataRole;
    }
    if file.sequence_number == 0 || file.names.is_empty() {
        return UnresolvedFileIdentity;
    }
    if !stream.name_utf16.is_empty() || !stream.name.is_empty() {
        return NamedStream;
    }
    if stream.resident {
        return ResidentStream;
    }
    if stream.flags & 0x8000 != 0 {
        return SparseStream;
    }
    if stream.flags & 0x0001 != 0 {
        return CompressedStream;
    }
    if stream.flags & 0x4000 != 0 {
        return EncryptedStream;
    }
    if stream.flags != 0 {
        return OtherStreamFlags;
    }
    let Some(standard) = &file.standard_information else {
        return MissingStandardInformation;
    };
    // SYSTEM, DIRECTORY, SPARSE, REPARSE, COMPRESSED, OFFLINE and ENCRYPTED.
    // The planner has no policy for preparing these file semantics.
    if standard.file_attributes & 0x5e15 != 0 {
        return UnsupportedFileAttributes;
    }
    if stream.initialized_size != stream.logical_size {
        return UninitializedData;
    }
    let mut matches = file
        .attributes
        .iter()
        .filter(|attribute| attribute.type_code == 0x80 && attribute.name_utf16.is_empty());
    let Some(attribute) = matches.next() else {
        return AttributeMismatch;
    };
    if matches.next().is_some()
        || file
            .streams
            .iter()
            .filter(|candidate| candidate.name_utf16.is_empty())
            .count()
            != 1
        || attribute.resident
        || attribute.flags != 0
        || attribute.lowest_vcn != 0
        || attribute.compression_unit != 0
        || attribute.total_allocated_size.is_some()
        || attribute.extents != stream.extents
        || attribute.logical_size != stream.logical_size
        || attribute.initialized_size != stream.initialized_size
        || attribute.allocated_size != stream.allocated_size
    {
        return AttributeMismatch;
    }
    let Some(rounded_eof) = stream.logical_size.checked_next_multiple_of(cluster) else {
        return InvalidPlainLayout;
    };
    if stream.allocated_size < rounded_eof || !stream.allocated_size.is_multiple_of(cluster) {
        return InvalidPlainLayout;
    }
    let mut coverage = 0u64;
    for extent in &stream.extents {
        if extent.logical_offset != coverage
            || extent.length == 0
            || !extent.length.is_multiple_of(cluster)
            || !extent
                .physical_offset
                .is_some_and(|offset| offset.is_multiple_of(cluster))
        {
            return InvalidPlainLayout;
        }
        let Some(end) = coverage.checked_add(extent.length) else {
            return InvalidPlainLayout;
        };
        coverage = end;
    }
    if coverage != stream.allocated_size {
        return InvalidPlainLayout;
    }
    if stream.initialized_size < cluster {
        return NoInitializedWholeClusters;
    }
    PlainInitializedUnnamedUserData
}

/// Enumerates original free gaps lazily. It never credits a proposed source
/// release or allocates a bitmap proportional to the volume's cluster count.
struct Destinations<'a> {
    blocked: &'a [Span],
    next_block: usize,
    cursor: u64,
    domain: u64,
    maximum_move_bytes: u64,
}

impl Destinations<'_> {
    fn take(&mut self, wanted: u64) -> Result<Option<Span>> {
        ensure!(wanted != 0, "empty evacuation destination request");
        while self.cursor < self.domain {
            if let Some(blocked) = self.blocked.get(self.next_block) {
                if self.cursor >= blocked.start {
                    self.cursor = self.cursor.max(blocked.end);
                    self.next_block = self
                        .next_block
                        .checked_add(1)
                        .context("evacuation destination interval count overflow")?;
                    continue;
                }
            }
            let gap_end = self
                .blocked
                .get(self.next_block)
                .map_or(self.domain, |span| span.start);
            let length = wanted
                .min(gap_end - self.cursor)
                .min(self.maximum_move_bytes);
            let start = self.cursor;
            self.cursor = start
                .checked_add(length)
                .context("evacuation destination extent overflow")?;
            return Ok(Some(Span {
                start,
                end: self.cursor,
            }));
        }
        Ok(None)
    }
}

/// Plan only from a complete reconciled inspection and supplied byte intervals.
/// No source contents are read, no moves run, and no new source certificate is
/// created. Unsupported collisions remain in the report and ordinary native
/// conversion remains responsible for them. Any malformed geometry, ownership,
/// arithmetic overflow or exhausted metadata budget rejects the whole estimate.
pub fn plan(
    raw: &NtfsInspection,
    partition_bytes: u64,
    observed_empty_refs_occupied: &[ByteInterval],
    target_anchors: &[ByteInterval],
    limits: Limits,
) -> Result<Plan> {
    let cluster = u64::from(raw.geometry.cluster_size);
    let domain = raw
        .geometry
        .total_clusters
        .checked_mul(cluster)
        .context("NTFS evacuation cluster domain overflow")?;
    ensure!(
        cluster.is_power_of_two()
            && raw.geometry.bytes_per_sector != 0
            && cluster.is_multiple_of(u64::from(raw.geometry.bytes_per_sector))
            && domain != 0
            && domain <= raw.geometry.volume_size
            && raw.geometry.volume_size <= partition_bytes
            && raw.geometry.volume_size / cluster == raw.geometry.total_clusters,
        "unsupported or inconsistent NTFS evacuation geometry"
    );
    let mut budget = Budget {
        used: 0,
        limit: limits.max_metadata_bytes,
    };
    budget.charge(u64::try_from(std::mem::size_of::<Plan>())?)?;
    let owned = source_ownership(raw, domain, cluster, &mut budget)?;
    let avoid = target_exclusions(
        observed_empty_refs_occupied,
        target_anchors,
        partition_bytes,
        domain,
        cluster,
        &mut budget,
    )?;
    let mut blocked = Vec::new();
    for span in owned.iter().chain(&avoid) {
        budget.push(&mut blocked, *span)?;
    }
    normalize(&mut blocked, false)?;
    let outside_free = domain
        .checked_sub(total_bytes(&blocked)?)
        .context("evacuation exclusions exceed the NTFS cluster domain")?;
    let mut source_collisions = 0u64;
    for span in &owned {
        source_collisions = source_collisions
            .checked_add(collision_bytes(&avoid, *span)?)
            .context("NTFS collision union total overflow")?;
    }
    let mut destinations = Destinations {
        blocked: &blocked,
        next_block: 0,
        cursor: 0,
        domain,
        maximum_move_bytes: u64::from(u32::MAX)
            .checked_mul(cluster)
            .context("evacuation native move size overflow")?,
    };
    let mut streams = Vec::new();
    let mut moves = Vec::new();
    let mut required_headroom = 0u64;
    let mut moved = 0u64;
    for file in &raw.files {
        for (stream_index, stream) in file.streams.iter().enumerate() {
            let eligibility = eligibility(file, stream, cluster);
            let eligible = eligibility == Eligibility::PlainInitializedUnnamedUserData;
            let initialized_whole_bytes = stream.initialized_size / cluster * cluster;
            let first_move_index = moves.len();
            let mut collision = 0u64;
            let mut eligible_collision = 0u64;
            let mut stream_moved = 0u64;
            for extent in &stream.extents {
                let Some(physical) = extent.physical_offset else {
                    continue;
                };
                let end = physical
                    .checked_add(extent.length)
                    .context("stream physical extent overflow during evacuation planning")?;
                ensure!(
                    extent.length != 0 && end <= domain,
                    "stream physical extent escapes the reconciled NTFS domain"
                );
                collision = collision
                    .checked_add(collision_bytes(
                        &avoid,
                        Span {
                            start: physical,
                            end,
                        },
                    )?)
                    .context("stream collision total overflow")?;
                if !eligible || extent.logical_offset >= initialized_whole_bytes {
                    continue;
                }
                let movable_length = extent
                    .length
                    .min(initialized_whole_bytes - extent.logical_offset);
                let movable_end = physical
                    .checked_add(movable_length)
                    .context("movable initialized extent overflow")?;
                each_intersection(
                    &avoid,
                    Span {
                        start: physical,
                        end: movable_end,
                    },
                    |intersection| {
                        eligible_collision = eligible_collision
                            .checked_add(intersection.length())
                            .context("eligible collision byte total overflow")?;
                        let mut source = intersection.start;
                        while source < intersection.end {
                            let Some(destination) = destinations.take(intersection.end - source)?
                            else {
                                break; // Explicitly report the unmoved collision.
                            };
                            let length = destination.length();
                            let logical = extent
                                .logical_offset
                                .checked_add(source - physical)
                                .context("evacuation source VCN overflow")?;
                            ensure!(
                                source.is_multiple_of(cluster)
                                    && destination.start.is_multiple_of(cluster)
                                    && logical.is_multiple_of(cluster)
                                    && length != 0
                                    && length.is_multiple_of(cluster),
                                "evacuation suggestion is not a whole NTFS cluster move"
                            );
                            budget.push(
                                &mut moves,
                                MoveCandidate {
                                    record_number: file.record_number,
                                    sequence_number: file.sequence_number,
                                    stream_index,
                                    starting_vcn: logical / cluster,
                                    source_lcn: source / cluster,
                                    destination_lcn: destination.start / cluster,
                                    cluster_count: u32::try_from(length / cluster)?,
                                },
                            )?;
                            stream_moved = stream_moved
                                .checked_add(length)
                                .context("stream evacuation byte total overflow")?;
                            source = source
                                .checked_add(length)
                                .context("evacuation source extent overflow")?;
                        }
                        Ok(())
                    },
                )?;
            }
            required_headroom = required_headroom
                .checked_add(eligible_collision)
                .context("required outside headroom overflow")?;
            moved = moved
                .checked_add(stream_moved)
                .context("evacuation payload byte total overflow")?;
            let outcome = if !eligible {
                Outcome::SkippedUnsupported
            } else if collision == 0 {
                Outcome::NoObservedCollision
            } else if eligible_collision == 0 {
                Outcome::CollisionOutsideInitializedWholeClusters
            } else if stream_moved == eligible_collision {
                Outcome::AllEligibleCollisionsHaveSuggestions
            } else {
                Outcome::SomeEligibleCollisionsLackOutsideHeadroom
            };
            budget.push(
                &mut streams,
                StreamDecision {
                    record_number: file.record_number,
                    sequence_number: file.sequence_number,
                    stream_index,
                    logical_bytes: stream.logical_size,
                    allocated_bytes: stream.allocated_size,
                    eligibility,
                    outcome,
                    observed_collision_bytes: collision,
                    eligible_collision_bytes: eligible_collision,
                    proposed_move_bytes: stream_moved,
                    unplanned_collision_bytes: collision
                        .checked_sub(stream_moved)
                        .context("planned stream moves exceed its collisions")?,
                    first_move_index,
                    move_count: moves
                        .len()
                        .checked_sub(first_move_index)
                        .context("evacuation move index underflow")?,
                },
            )?;
        }
    }
    ensure!(
        moved <= outside_free && moved == required_headroom.min(outside_free),
        "evacuation suggestions differ from outside-headroom accounting"
    );
    let shortfall = if required_headroom > outside_free {
        required_headroom
            .checked_sub(outside_free)
            .context("evacuation headroom shortfall underflow")?
    } else {
        0
    };
    Ok(Plan {
        schema_version: 1,
        ntfs_cluster_bytes: raw.geometry.cluster_size,
        partition_bytes,
        target_avoid_cluster_bytes: total_bytes(&avoid)?,
        source_owned_collision_bytes: source_collisions,
        required_outside_headroom_bytes: required_headroom,
        observed_outside_free_bytes: outside_free,
        observed_headroom_shortfall_bytes: shortfall,
        proposed_move_bytes: moved,
        source_owned_collision_bytes_left_unplanned: source_collisions
            .checked_sub(moved)
            .context("planned moves exceed the source-owned collision union")?,
        estimated_payload_read_bytes: moved,
        estimated_payload_write_bytes: moved,
        estimated_payload_io_bytes: moved
            .checked_mul(2)
            .context("evacuation M-read plus M-write estimate overflow")?,
        streams,
        moves,
        metadata_reserved_bytes: budget.used,
        metadata_limit_bytes: budget.limit,
        target_occupancy_is_lower_bound: true,
        preparation_best_effort: true,
        final_native_placement_required: true,
        fresh_source_inventory_and_certificate_required: true,
        source_admitted: false,
        executable: false,
    })
}
