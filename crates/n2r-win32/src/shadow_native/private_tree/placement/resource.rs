//! Resource-derived planner limits and caller-owned complete evidence.
//! These descriptors cannot construct a private tree or source authority.
use super::*;

/// The actual root implementation stores every record in a closed paged
/// artifact. `reserve_next` must refuse BEFORE native IO if that complete
/// next proof cannot fit its already reserved scratch/record envelope.
pub trait PlacementEvidenceSink {
    fn maximum_bytes(&self) -> u64;
    fn reserve_next(&mut self, maximum_json_bytes: u64) -> io::Result<()>;
    fn push(&mut self, kind: &'static str, value: &serde_json::Value) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<serde_json::Value>;
}

/// The bounded result keeps its actual shared payer until every owned JSON
/// path, pin and progress field has dropped, independently of the tree.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct ResourcePlacementReport {
    value: serde_json::Value,
    #[serde(skip)]
    _memory: Box<dyn report_memory::ReportMemoryLease>,
}
impl std::ops::Deref for ResourcePlacementReport {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl ResourcePlacementReport {
    pub(super) fn new(
        value: serde_json::Value,
        mut memory: Box<dyn report_memory::ReportMemoryLease>,
    ) -> io::Result<Self> {
        let measured = memory::value_bytes(&value).and_then(|n| {
            n.checked_add(4096)
                .ok_or_else(|| invalid("placement report RAM overflow"))
        });
        let measured = match measured {
            Ok(n) => n,
            Err(error) => {
                drop(value);
                return Err(error);
            }
        };
        if let Err(error) = memory.shrink_to(measured) {
            drop(value);
            return Err(error);
        }
        Ok(Self {
            value,
            _memory: memory,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub desired: usize,
    pub tracked: usize,
    pub owned: usize,
    pub scratch_intervals: usize,
    pub subruns: usize,
    pub moves: usize,
    pub evidence: usize,
    pub bitmap: crate::bitmap_streaming::Limits,
    pub resource: bool,
}
impl Limits {
    pub(super) fn legacy(partition: u64, moves: usize) -> io::Result<Self> {
        Ok(Self {
            desired: MAX_ADMITTED_RANGES,
            tracked: MAX_TRACKED_EXTENTS,
            owned: MAX_OWNED_RANGES,
            scratch_intervals: MAX_SCRATCH_INTERVALS,
            subruns: retention_layout::MAX_SUBRUNS,
            moves,
            evidence: MAX_PLACEMENT_ARTIFACT_BYTES,
            bitmap: crate::bitmap_streaming::source_limits(partition / cluster())?,
            resource: false,
        })
    }
    pub(super) fn resource(
        admission: crate::tree_resources::SourceResourceAdmission,
        partition: u64,
        move_bytes: u64,
        requested_moves: usize,
        evidence_bytes: u64,
    ) -> io::Result<Self> {
        admission.validate()?;
        if partition == 0
            || !partition.is_multiple_of(cluster())
            || i64::try_from(partition).is_err()
            || move_bytes < cluster()
            || requested_moves == 0
        {
            return Err(invalid(
                "resource placement geometry or moved-byte budget differs",
            ));
        }
        // A retained interval may coexist with the desired/avoid indexes,
        // owned/eligible sweeps, deferred/final plans and their BTree nodes.
        // This is a RAM-derived capacity; allocations are separately prepaid
        // against actual counts before each phase, not this whole maximum.
        let slots = usize::try_from(admission.budget.retained_index_bytes / 8192)
            .map_err(io::Error::other)?;
        let byte_moves = usize::try_from(move_bytes / cluster()).map_err(io::Error::other)?;
        let moves = requested_moves.min(byte_moves);
        let bitmap = crate::bitmap_streaming::resource_source_limits(
            partition / cluster(),
            admission.budget.max_row_bytes,
        )?;
        let scratch_intervals = bitmap
            .max_allocated_ranges
            .checked_mul(2)
            .and_then(|n| n.checked_add(slots))
            .and_then(|n| n.checked_add(2))
            .ok_or_else(|| invalid("resource scratch interval count overflow"))?;
        if evidence_bytes > admission.budget.scratch_bytes {
            return Err(invalid(
                "placement evidence exceeds the actual total scratch budget",
            ));
        }
        let evidence = usize::try_from(evidence_bytes).map_err(io::Error::other)?;
        if slots == 0 || moves == 0 || evidence == 0 {
            return Err(invalid(
                "resource placement has no admitted working/evidence capacity",
            ));
        }
        Ok(Self {
            desired: slots,
            tracked: slots,
            owned: slots,
            scratch_intervals,
            subruns: slots,
            moves,
            evidence,
            bitmap,
            resource: true,
        })
    }
}

pub(super) struct Bitmap {
    observation: Observation,
    _memory: Option<Box<dyn report_memory::ReportMemoryLease>>,
}
impl std::ops::Deref for Bitmap {
    type Target = Observation;
    fn deref(&self) -> &Observation {
        &self.observation
    }
}

fn bitmap_bytes(value: &Observation) -> io::Result<u64> {
    let Observation::Streamed { proof, summary, .. } = value else {
        return Err(invalid(
            "resource placement requires complete streamed bitmap owners",
        ));
    };
    let mut bytes = (summary.allocated_ranges.capacity() as u64)
        .checked_mul(mem::size_of::<crate::bitmap_streaming::ClusterRange>() as u64)
        .ok_or_else(|| invalid("placement bitmap RAM overflow"))?;
    for text in [
        &summary.encoding,
        &summary.bitmap_data_sha256,
        &summary.canonical_bitmap_sha256,
        &summary.page_transcript_sha256,
        &proof.encoding,
        &proof.canonical_bitmap_sha256,
    ] {
        bytes = bytes
            .checked_add(text.capacity() as u64)
            .ok_or_else(|| invalid("placement bitmap RAM overflow"))?;
    }
    bytes = bytes
        .checked_add(
            (proof.pages.capacity() as u64)
                .checked_mul(mem::size_of::<crate::bitmap_paging::PageProof>() as u64)
                .ok_or_else(|| invalid("placement bitmap RAM overflow"))?,
        )
        .ok_or_else(|| invalid("placement bitmap RAM overflow"))?;
    for page in &proof.pages {
        bytes = bytes
            .checked_add(page.input.capacity() as u64)
            .and_then(|n| n.checked_add(page.response_sha256.capacity() as u64))
            .ok_or_else(|| invalid("placement bitmap RAM overflow"))?;
    }
    if let Some(streaming) = &proof.streaming {
        bytes = bytes
            .checked_add(streaming.bitmap_data_sha256.capacity() as u64)
            .and_then(|n| n.checked_add(streaming.page_transcript_sha256.capacity() as u64))
            .ok_or_else(|| invalid("placement bitmap RAM overflow"))?;
    }
    bytes
        .checked_add(4096)
        .ok_or_else(|| invalid("placement bitmap RAM overflow"))
}

pub(super) fn capture_bitmap(
    tree: &PrivateTree,
    template: &[u8],
    limits: Limits,
) -> io::Result<Bitmap> {
    if !limits.resource {
        return Ok(Bitmap {
            observation: Observation::capture(
                &tree.volume,
                template,
                tree.pair.shadow.identity.partition_bytes,
                true,
            )?,
            _memory: None,
        });
    }
    let memory = tree
        .memory
        .as_ref()
        .ok_or_else(|| invalid("resource placement payer absent"))?;
    let row = tree
        .metadata_resource_admission
        .ok_or_else(|| invalid("resource placement admission absent"))?
        .budget
        .max_row_bytes;
    let mut lease = memory.working(report_memory::bitmap_peak(row)?)?;
    let observation = Observation::capture_with_bounded_ranges(
        &tree.volume,
        template,
        tree.pair.shadow.identity.partition_bytes,
        limits.bitmap,
    )?;
    lease.shrink_to(bitmap_bytes(&observation)?)?;
    Ok(Bitmap {
        observation,
        _memory: Some(lease),
    })
}

pub(super) enum Planner<'a> {
    Legacy(crate::bitmap_observation::RetentionPlanner<'a>),
    Resource(retention_layout::ResourcePlanner<'a>),
}
pub(super) enum Subruns {
    Legacy(retention_layout::Plan),
    Resource(retention_layout::ResourcePlan),
}
impl std::ops::Deref for Subruns {
    type Target = retention_layout::Plan;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(p) => p,
            Self::Resource(p) => p,
        }
    }
}
impl Planner<'_> {
    pub(super) fn plan(
        &self,
        run: retention_layout::SourceRun,
        maximum: usize,
    ) -> io::Result<Subruns> {
        match self {
            Self::Legacy(p) => p.plan(run, maximum).map(Subruns::Legacy),
            Self::Resource(p) => p.plan(run, maximum).map(Subruns::Resource),
        }
    }
}
pub(super) fn planner<'a>(
    legacy: &'a Observation,
    metadata: &'a Observation,
    partition: u64,
    limits: Limits,
    payer: Option<&'a dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<Planner<'a>> {
    if !limits.resource {
        return Ok(Planner::Legacy(
            legacy.retention_planner(metadata, partition)?,
        ));
    }
    match (legacy, metadata) {
        (Observation::Streamed { summary: a, .. }, Observation::Streamed { summary: b, .. }) => Ok(
            Planner::Resource(retention_layout::StreamedPlanner::new_resource(
                a,
                b,
                partition,
                limits.bitmap,
                limits.subruns,
                payer.ok_or_else(|| invalid("resource planner payer absent"))?,
            )?),
        ),
        _ => Err(invalid("resource placement bitmap profiles differ")),
    }
}

pub(super) enum Evacuation {
    Legacy(shadow_evacuation::Plan),
    Resource(shadow_evacuation::ResourcePlan),
}

pub(super) enum MoveProof {
    Legacy(serde_json::Value),
    Resource(unwritten::ResourceMoveValue),
}
impl std::ops::Deref for MoveProof {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(value) => value,
            Self::Resource(value) => value,
        }
    }
}
impl serde::Serialize for MoveProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&**self, serializer)
    }
}
pub(super) fn move_slot(
    tree: &mut PrivateTree,
    slot: usize,
    vcn: u64,
    lcn: u64,
    clusters: u32,
    reposition: bool,
    resource: bool,
    guard: impl FnMut(&unwritten::DestinationWindows) -> io::Result<()>,
) -> io::Result<MoveProof> {
    if resource {
        tree.move_slot_resource_with_evidence(slot, vcn, lcn, clusters, reposition, guard)
            .map(MoveProof::Resource)
    } else if reposition {
        tree.reposition_slot_with_evidence(slot, vcn, lcn, clusters, guard)
            .map(MoveProof::Legacy)
    } else {
        tree.place_slot_with_evidence(slot, vcn, lcn, clusters, guard)
            .map(MoveProof::Legacy)
    }
}
impl std::ops::Deref for Evacuation {
    type Target = shadow_evacuation::Plan;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(p) => p,
            Self::Resource(p) => p,
        }
    }
}
pub(super) fn evacuation(
    legacy: &Observation,
    metadata: &Observation,
    eligible: &[shadow_evacuation::Extent],
    owned: &[shadow_evacuation::Extent],
    partition: u64,
    remaining: usize,
    limits: Limits,
    payer: Option<&dyn report_memory::ReportMemoryAccountant>,
) -> io::Result<Evacuation> {
    let bounds = shadow_evacuation::RangeLimits {
        max_source_extents: if limits.resource {
            limits.desired
        } else {
            MAX_PLACEMENT_RANGES
        },
        max_shadow_extents: limits.tracked,
        max_blocked: limits
            .owned
            .checked_add(if limits.resource {
                limits.desired
            } else {
                MAX_PLACEMENT_RANGES
            })
            .ok_or_else(|| invalid("resource blocked intersection count overflow"))?,
        max_moves: limits.moves,
        margin: MARGIN,
    };
    // The clones below are real temporary allocation maps, not permission
    // inferred from allocation bits. Charge their actual known range counts
    // before copying either complete view.
    let count = |view: &Observation| match view {
        Observation::Streamed { summary, .. } => Ok(summary.allocated_ranges.len()),
        _ => Err(invalid("resource evacuation needs complete streamed views")),
    };
    let _maps = if limits.resource {
        let rows = count(legacy)?
            .checked_add(count(metadata)?)
            .ok_or_else(|| invalid("evacuation map count overflow"))?;
        Some(
            payer
                .ok_or_else(|| invalid("evacuation payer absent"))?
                .reserve(
                    (rows as u64)
                        .checked_mul(64)
                        .and_then(|n| n.checked_add(65536))
                        .ok_or_else(|| invalid("evacuation map RAM overflow"))?,
                )?,
        )
    } else {
        None
    };
    let a = legacy.allocation_map(partition)?;
    let b = metadata.allocation_map(partition)?;
    if limits.resource {
        shadow_evacuation::plan_ranges_resource(
            &a,
            &b,
            eligible,
            owned,
            partition,
            remaining,
            bounds,
            limits.bitmap.max_allocated_ranges,
            payer.ok_or_else(|| invalid("evacuation payer absent"))?,
        )
        .map(Evacuation::Resource)
    } else {
        shadow_evacuation::plan_ranges(&a, &b, eligible, owned, partition, remaining, bounds)
            .map(Evacuation::Legacy)
    }
}
