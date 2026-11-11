use super::PreparationInventory;
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroupSeal},
    general_composite_target::paged_memory::ArenaReportMemory,
    ntfs_inspect::{
        RootFileDomain,
        paged_storage::{PagedMetadataRange, SourcePagePin, SourceScratch},
        record_store::{SortedRecordStore, SortedRecordWriter},
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent,
    general_layout::GeneralDiskBinding,
    ntfs_preparation::resource::{self as native, ShadowBitmapView},
    tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

mod eligibility;
use eligibility::{Eligibility, Outcome};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Span {
    pub offset: u64,
    pub length: u64,
}
impl Span {
    fn end(self) -> Result<u64> {
        self.offset
            .checked_add(self.length)
            .context("prealignment interval overflow")
    }
}
fn key(a: u64, b: u64) -> [u8; 16] {
    let mut k = [0; 16];
    k[..8].copy_from_slice(&a.to_be_bytes());
    k[8..].copy_from_slice(&b.to_be_bytes());
    k
}
fn close(writer: SortedRecordWriter, scratch: &SourceScratch) -> Result<SortedRecordStore> {
    let pin = writer.finish()?;
    SortedRecordStore::open(&pin, scratch)
}

/// Only callback rows from the live SDK observation enter this builder in the
/// actual collector below. The completed stores remain hints, never authority.
pub(crate) struct TargetHintBuilder {
    legacy: SortedRecordWriter,
    metadata: SortedRecordWriter,
    last: [u64; 2],
    count: [u64; 2],
    partition: u64,
}
pub(crate) struct TargetHints {
    binding: GeneralDiskBinding,
    legacy: SortedRecordStore,
    metadata: SortedRecordStore,
    anchors: [Span; 2],
    native: PagedMetadataRange,
    native_pin: SourcePagePin,
    scratch: SourceScratch,
    _directory: std::fs::File,
}
impl TargetHintBuilder {
    fn new(root: &Path, partition: u64, scratch: &SourceScratch) -> Result<Self> {
        Ok(Self {
            legacy: SortedRecordWriter::new(&root.join("legacy"), *b"N2RPHLG1", scratch)?,
            metadata: SortedRecordWriter::new(&root.join("metadata"), *b"N2RPHMT1", scratch)?,
            last: [0; 2],
            count: [0; 2],
            partition,
        })
    }
    fn emit(&mut self, view: ShadowBitmapView, offset: u64, length: u64) -> Result<()> {
        let slot = match view {
            ShadowBitmapView::Legacy => 0,
            ShadowBitmapView::Metadata => 1,
        };
        let end = offset
            .checked_add(length)
            .filter(|e| *e <= self.partition)
            .context("native shadow hint escapes partition")?;
        ensure!(
            length > 0
                && offset.is_multiple_of(4096)
                && length.is_multiple_of(4096)
                && offset >= self.last[slot],
            "native shadow hint order/alignment differs"
        );
        let writer = if slot == 0 {
            &mut self.legacy
        } else {
            &mut self.metadata
        };
        writer.push(key(offset, 0), &Span { offset, length })?;
        self.last[slot] = end;
        self.count[slot] = self.count[slot]
            .checked_add(1)
            .context("hint count overflow")?;
        Ok(())
    }
}
impl TargetHints {
    pub(crate) fn collect(
        binding: GeneralDiskBinding,
        resources: ResourceBudget,
        root: &Path,
        arena: &ArtifactArena,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        binding.validate()?;
        resources.validate()?;
        ensure!(
            arena.budget() == resources
                && scratch
                    .artifact_group()
                    .is_some_and(|g| g.arena().same_arena(arena)),
            "shadow hint scratch differs from the actual prealignment arena"
        );
        let directory = super::create_child(arena, root)?;
        let mut builder = TargetHintBuilder::new(root, binding.identity.partition_bytes, scratch)?;
        let payer = ArenaReportMemory(arena.clone());
        let observation = native::observe_shadow_occupancy(
            binding.clone(),
            resources,
            &payer,
            |view, offset, length| builder.emit(view, offset, length).map_err(io::Error::other),
        )?;
        ensure!(
            observation.binding == binding
                && observation.before == observation.after
                && observation.before.disk_attributes == 0
                && observation.legacy_ranges == builder.count[0]
                && observation.metadata_ranges == builder.count[1],
            "actual shadow observation route/state changed"
        );
        let anchors = observation.bootstrap_avoidance.map(|s| Span {
            offset: s.offset,
            length: s.length,
        });
        let legacy = close(builder.legacy, scratch)?;
        let metadata = close(builder.metadata, scratch)?;
        let mut facts = scratch.writer(&root.join("native-hints.pages"), *b"N2RPHNT1")?;
        serde_json::to_writer(&mut facts, &observation)?;
        let pin = facts.finish()?;
        let native = PagedMetadataRange::open(&pin, scratch)?;
        Ok(Self {
            binding,
            legacy,
            metadata,
            anchors,
            native,
            native_pin: pin,
            scratch: scratch.clone(),
            _directory: directory,
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.legacy.revalidate()?;
        self.metadata.revalidate()?;
        crate::ntfs_inspect::SourceMetadataRange::revalidate(&self.native)
    }
}

#[derive(Serialize, Deserialize)]
struct OwnedInterval {
    lcn: u64,
    clusters: u64,
}
/// A constant number of bounded cursor rows; no union vector or volume bitmap.
struct Cursor<'a> {
    store: &'a SortedRecordStore,
    index: u64,
    cluster: u64,
    domain: u64,
    ownership: bool,
    round: bool,
}
fn cursor(
    store: &SortedRecordStore,
    cluster: u64,
    domain: u64,
    ownership: bool,
    round: bool,
) -> Cursor<'_> {
    Cursor {
        store,
        index: 0,
        cluster,
        domain,
        ownership,
        round,
    }
}
impl Cursor<'_> {
    fn at(&self, index: u64) -> Result<Span> {
        let mut s = if self.ownership {
            let s: OwnedInterval = self.store.get(index)?;
            Span {
                offset: s
                    .lcn
                    .checked_mul(self.cluster)
                    .context("ownership LCN overflow")?,
                length: s
                    .clusters
                    .checked_mul(self.cluster)
                    .context("ownership length overflow")?,
            }
        } else {
            self.store.get::<Span>(index)?
        };
        ensure!(s.length > 0, "empty prealignment input interval");
        if self.round {
            let end = s
                .end()?
                .min(self.domain)
                .checked_next_multiple_of(self.cluster)
                .context("rounded hint end overflow")?
                .min(self.domain);
            s.offset = s.offset.min(self.domain) / self.cluster * self.cluster;
            s.length = end - s.offset;
        } else {
            ensure!(
                s.end()? <= self.domain,
                "prealignment input interval escapes domain"
            );
        }
        ensure!(
            s.offset.is_multiple_of(self.cluster) && s.length.is_multiple_of(self.cluster),
            "prealignment cluster interval differs"
        );
        Ok(s)
    }
    fn peek(&mut self) -> Result<Option<Span>> {
        while self.index < self.store.len() {
            let span = self.at(self.index)?;
            if span.length != 0 {
                return Ok(Some(span));
            }
            self.index += 1;
        }
        Ok(None)
    }
    fn advance(&mut self) {
        self.index += 1;
    }
}
fn union(
    mut cursors: Vec<Cursor<'_>>,
    anchors: &[Span],
    writer: &mut SortedRecordWriter,
) -> Result<u64> {
    // There are two or three known cursor kinds, not one item per source row.
    let mut anchor = 0;
    let mut pending: Option<Span> = None;
    let mut bytes = 0u64;
    loop {
        let mut chosen = None;
        for (i, c) in cursors.iter_mut().enumerate() {
            if let Some(s) = c.peek()? {
                if chosen.is_none_or(|(_, old): (usize, Span)| s.offset < old.offset) {
                    chosen = Some((i, s));
                }
            }
        }
        if let Some(s) = anchors.get(anchor).copied() {
            if chosen.is_none_or(|(_, old)| s.offset < old.offset) {
                chosen = Some((cursors.len(), s));
            }
        }
        let Some((which, s)) = chosen else { break };
        if which == cursors.len() {
            anchor += 1
        } else {
            cursors[which].advance()
        }
        if let Some(old) = pending.as_mut() {
            let end = old.end()?;
            if s.offset <= end {
                old.length = end.max(s.end()?) - old.offset;
                continue;
            }
        }
        if let Some(old) = pending.take() {
            writer.push(key(old.offset, 0), &old)?;
            bytes = bytes
                .checked_add(old.length)
                .context("union bytes overflow")?;
        }
        pending = Some(s);
    }
    if let Some(s) = pending {
        writer.push(key(s.offset, 0), &s)?;
        bytes = bytes
            .checked_add(s.length)
            .context("union bytes overflow")?;
    }
    Ok(bytes)
}
fn intersections(
    store: &SortedRecordStore,
    start: u64,
    end: u64,
    mut emit: impl FnMut(Span) -> Result<()>,
) -> Result<u64> {
    ensure!(start <= end, "invalid collision interval");
    let (mut lo, mut hi) = (0, store.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if store.get::<Span>(mid)?.end()? <= start {
            lo = mid + 1
        } else {
            hi = mid
        }
    }
    let mut bytes = 0u64;
    while lo < store.len() {
        let s: Span = store.get(lo)?;
        if s.offset >= end {
            break;
        }
        let at = s.offset.max(start);
        let stop = s.end()?.min(end);
        if at < stop {
            let span = Span {
                offset: at,
                length: stop - at,
            };
            bytes = bytes
                .checked_add(span.length)
                .context("collision bytes overflow")?;
            emit(span)?;
        }
        lo += 1;
    }
    Ok(bytes)
}
struct Destinations<'a> {
    blocked: &'a SortedRecordStore,
    index: u64,
    cursor: u64,
    domain: u64,
    maximum: u64,
}
impl Destinations<'_> {
    fn take(&mut self, wanted: u64) -> Result<Option<Span>> {
        while self.cursor < self.domain {
            let next = if self.index == self.blocked.len() {
                None
            } else {
                Some(self.blocked.get::<Span>(self.index)?)
            };
            if let Some(s) = next {
                if s.offset <= self.cursor {
                    self.cursor = self.cursor.max(s.end()?);
                    self.index += 1;
                    continue;
                }
            }
            let end = next.map_or(self.domain, |s| s.offset);
            let length = wanted.min(end - self.cursor).min(self.maximum);
            ensure!(length > 0, "empty prealignment destination");
            let offset = self.cursor;
            self.cursor += length;
            return Ok(Some(Span { offset, length }));
        }
        Ok(None)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Move {
    pub record_number: u64,
    pub sequence_number: u16,
    pub stream_index: u64,
    pub expected_logical_bytes: u64,
    pub starting_vcn: u64,
    pub source_lcn: u64,
    pub destination_lcn: u64,
    pub cluster_count: u32,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Decision {
    pub record_number: u64,
    pub sequence_number: u16,
    pub stream_index: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub eligibility: Eligibility,
    pub outcome: Outcome,
    pub observed_collision_bytes: u64,
    pub eligible_collision_bytes: u64,
    pub proposed_move_bytes: u64,
    pub unplanned_collision_bytes: u64,
    pub first_move_index: u64,
    pub move_count: u64,
}
/// All decisions/moves and their exclusions are closed owning page stores.
/// They are suggestions only. Native execution must revalidate every request.
pub(crate) struct PreparationPlan {
    source: GeneralDiskBinding,
    metadata_sha256: String,
    cluster: u64,
    ntfs_serial: u64,
    domain: u64,
    moves: SortedRecordStore,
    decisions: SortedRecordStore,
    avoid: SortedRecordStore,
    blocked: SortedRecordStore,
    facts: SortedRecordStore,
    hints: TargetHints,
    source_seal: ArtifactGroupSeal,
    _seal: ArtifactGroupSeal,
    _directory: std::fs::File,
}
impl PreparationPlan {
    pub(crate) fn build(
        inventory: &PreparationInventory,
        hints: TargetHints,
        root: &Path,
        scratch: &SourceScratch,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        inventory.revalidate(events)?;
        hints.revalidate()?;
        let arena = inventory.seal.permit().arena();
        ensure!(
            scratch
                .artifact_group()
                .is_some_and(|g| g.arena().same_arena(arena))
                && hints
                    .scratch
                    .artifact_group()
                    .is_some_and(|g| g.arena().same_arena(arena))
                && hints.binding.disk_number != inventory.source.disk_number
                && hints.binding.identity.partition_bytes
                    == inventory.source.identity.partition_bytes,
            "prealignment source/target/planner actual owners differ"
        );
        let directory = super::create_child(arena, root)?;
        let geometry = &inventory.raw.header().geometry;
        let cluster = u64::from(geometry.cluster_size);
        let domain = geometry
            .total_clusters
            .checked_mul(cluster)
            .context("NTFS cluster domain overflow")?;
        ensure!(
            cluster.is_power_of_two()
                && domain > 0
                && domain <= geometry.volume_size
                && geometry.volume_size <= inventory.source.identity.partition_bytes,
            "NTFS prealignment geometry differs"
        );
        let owned = SortedRecordStore::open(
            &inventory.raw.allocation().physical_ownership,
            &inventory.raw.metadata_scratch(),
        )?;
        let mut anchors = hints.anchors;
        for a in &mut anchors {
            let end = a
                .end()?
                .min(domain)
                .checked_next_multiple_of(cluster)
                .context("anchor rounding overflow")?
                .min(domain);
            a.offset = a.offset.min(domain) / cluster * cluster;
            a.length = end - a.offset;
        }
        let mut avoid_writer = SortedRecordWriter::new(&root.join("avoid"), *b"N2RPAVD1", scratch)?;
        union(
            vec![
                cursor(&hints.legacy, cluster, domain, false, true),
                cursor(&hints.metadata, cluster, domain, false, true),
            ],
            &anchors,
            &mut avoid_writer,
        )?;
        let avoid = close(avoid_writer, scratch)?;
        let mut blocked_writer =
            SortedRecordWriter::new(&root.join("blocked"), *b"N2RPBLK1", scratch)?;
        let blocked_bytes = union(
            vec![
                cursor(&owned, cluster, domain, true, false),
                cursor(&avoid, cluster, domain, false, false),
            ],
            &[],
            &mut blocked_writer,
        )?;
        let blocked = close(blocked_writer, scratch)?;
        let outside = domain
            .checked_sub(blocked_bytes)
            .context("NTFS outside-free count underflow")?;
        let mut source_collisions = 0u64;
        for i in 0..owned.len() {
            let s = cursor(&owned, cluster, domain, true, false).at(i)?;
            source_collisions = source_collisions
                .checked_add(intersections(&avoid, s.offset, s.end()?, |_| Ok(()))?)
                .context("source collisions overflow")?;
        }
        let mut destinations = Destinations {
            blocked: &blocked,
            index: 0,
            cursor: 0,
            domain,
            maximum: u64::from(u32::MAX) * cluster,
        };
        let mut decisions =
            SortedRecordWriter::new(&root.join("decisions"), *b"N2RPDEC1", scratch)?;
        let mut moves = SortedRecordWriter::new(&root.join("moves"), *b"N2RPMOV1", scratch)?;
        let (mut move_count, mut decision_count, mut required, mut proposed) =
            (0u64, 0u64, 0u64, 0u64);
        for ordinal in 0..inventory.raw.file_count() {
            let _row_ram = scratch.lease_ram(
                scratch
                    .budget()
                    .record_bytes
                    .checked_mul(8)
                    .context("prealignment FILE workspace overflow")?,
            )?;
            let file = inventory.raw.file(ordinal)?;
            let mut file_move = 0u64;
            for (stream_index, stream) in file.streams.iter().enumerate() {
                let eligibility = eligibility::classify(&file, stream, cluster);
                let eligible = eligibility == Eligibility::PlainInitializedUnnamedUserData;
                let whole = stream.initialized_size / cluster * cluster;
                let first = move_count;
                let (mut collision, mut movable, mut moved) = (0u64, 0u64, 0u64);
                for extent in &stream.extents {
                    let Some(physical) = extent.physical_offset else {
                        continue;
                    };
                    let end = physical
                        .checked_add(extent.length)
                        .filter(|e| *e <= domain)
                        .context("source stream extent escapes reconciled domain")?;
                    collision = collision
                        .checked_add(intersections(&avoid, physical, end, |_| Ok(()))?)
                        .context("stream collision overflow")?;
                    if !eligible || extent.logical_offset >= whole {
                        continue;
                    }
                    let end = physical + extent.length.min(whole - extent.logical_offset);
                    movable = movable
                        .checked_add(intersections(&avoid, physical, end, |span| {
                            let mut at = span.offset;
                            while at < span.end()? {
                                let Some(destination) = destinations.take(span.end()? - at)? else {
                                    break;
                                };
                                let logical = extent
                                    .logical_offset
                                    .checked_add(at - physical)
                                    .context("source VCN overflow")?;
                                ensure!(
                                    logical.is_multiple_of(cluster)
                                        && at.is_multiple_of(cluster)
                                        && destination.offset.is_multiple_of(cluster)
                                        && destination.length.is_multiple_of(cluster),
                                    "noncluster prealignment proposal"
                                );
                                moves.push(
                                    key(file.record_number, file_move),
                                    &Move {
                                        record_number: file.record_number,
                                        sequence_number: file.sequence_number,
                                        stream_index: stream_index as u64,
                                        expected_logical_bytes: stream.logical_size,
                                        starting_vcn: logical / cluster,
                                        source_lcn: at / cluster,
                                        destination_lcn: destination.offset / cluster,
                                        cluster_count: u32::try_from(destination.length / cluster)?,
                                    },
                                )?;
                                move_count =
                                    move_count.checked_add(1).context("move count overflow")?;
                                file_move += 1;
                                moved = moved
                                    .checked_add(destination.length)
                                    .context("move byte count overflow")?;
                                at += destination.length;
                            }
                            Ok(())
                        })?)
                        .context("movable collision overflow")?;
                }
                let outcome = if !eligible {
                    Outcome::SkippedUnsupported
                } else if collision == 0 {
                    Outcome::NoObservedCollision
                } else if movable == 0 {
                    Outcome::CollisionOutsideInitializedWholeClusters
                } else if moved == movable {
                    Outcome::AllEligibleCollisionsHaveSuggestions
                } else {
                    Outcome::SomeEligibleCollisionsLackOutsideHeadroom
                };
                decisions.push(
                    key(file.record_number, stream_index as u64),
                    &Decision {
                        record_number: file.record_number,
                        sequence_number: file.sequence_number,
                        stream_index: stream_index as u64,
                        logical_bytes: stream.logical_size,
                        allocated_bytes: stream.allocated_size,
                        eligibility,
                        outcome,
                        observed_collision_bytes: collision,
                        eligible_collision_bytes: movable,
                        proposed_move_bytes: moved,
                        unplanned_collision_bytes: collision
                            .checked_sub(moved)
                            .context("move exceeds collision")?,
                        first_move_index: first,
                        move_count: move_count - first,
                    },
                )?;
                decision_count = decision_count
                    .checked_add(1)
                    .context("decision count overflow")?;
                required = required
                    .checked_add(movable)
                    .context("required headroom overflow")?;
                proposed = proposed
                    .checked_add(moved)
                    .context("proposal bytes overflow")?;
            }
        }
        let moves = close(moves, scratch)?;
        let decisions = close(decisions, scratch)?;
        let mut facts = SortedRecordWriter::new(&root.join("facts"), *b"N2RPLAN1", scratch)?;
        facts.push([0;16],&serde_json::json!({"schema_version":1,"kind":"paged-ntfs-prealignment-hints",
            "source":inventory.source,"shadow":hints.binding,"source_metadata_sha256":inventory.metadata_sha256(),
            "target_hint_pins":{"legacy":hints.legacy.pin(),"metadata":hints.metadata.pin(),"native":&hints.native_pin},
            "stream_decisions":decision_count,"proposed_moves":move_count,"proposed_move_bytes":proposed,
            "source_owned_collision_bytes":source_collisions,"required_outside_headroom_bytes":required,
            "observed_outside_free_bytes":outside,"unplanned_collision_bytes":source_collisions.checked_sub(proposed).context("proposal exceeds ownership collision")?,
            "target_occupancy_is_lower_bound":true,"original_free_destinations_only":true,
            "fresh_frozen_source_inventory_and_certificate_required":true,"source_admitted":false,"executable":false}))?;
        let facts = close(facts, scratch)?;
        inventory.revalidate(events)?;
        hints.revalidate()?;
        let seal = scratch.seal()?;
        Ok(Self {
            source: inventory.source.clone(),
            metadata_sha256: inventory.metadata_sha256().to_owned(),
            cluster,
            ntfs_serial: geometry.serial_number,
            domain,
            moves,
            decisions,
            avoid,
            blocked,
            facts,
            hints,
            source_seal: inventory.seal.clone(),
            _seal: seal,
            _directory: directory,
        })
    }
    pub(crate) fn move_count(&self) -> u64 {
        self.moves.len()
    }
    pub(crate) fn artifact_arena(&self) -> &ArtifactArena {
        self._seal.permit().arena()
    }
    pub(crate) fn source(&self) -> &GeneralDiskBinding {
        &self.source
    }
    pub(crate) fn ntfs_serial(&self) -> u64 {
        self.ntfs_serial
    }
    pub(crate) fn cluster_bytes(&self) -> u64 {
        self.cluster
    }
    pub(crate) fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }
    pub(crate) fn summary(&self) -> Result<serde_json::Value> {
        self.facts.get(0)
    }
    pub(crate) fn move_hint(&self, ordinal: u64) -> Result<Move> {
        self.moves.get(ordinal)
    }
    pub(crate) fn decision_count(&self) -> u64 {
        self.decisions.len()
    }
    pub(crate) fn decision(&self, ordinal: u64) -> Result<Decision> {
        self.decisions.get(ordinal)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.moves.revalidate()?;
        self.decisions.revalidate()?;
        self.avoid.revalidate()?;
        self.blocked.revalidate()?;
        self.facts.revalidate()?;
        self.hints.revalidate()?;
        self.source_seal.revalidate()?;
        self._seal.revalidate()
    }
}
