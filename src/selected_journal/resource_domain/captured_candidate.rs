//! Read only the selected changed bytes from a real protected capture.
//! ZERO comes from its verified classification, literals from its held file,
//! and COPY from a separately reopened frozen source lane. This is not a
//! source-admission certificate, journal ticket or target-write capability.
use super::{ResourceJournalDomain, add};
use crate::{
    general_composite_target::paged::ProtectedPagedTargetSelection,
    general_shadow::capture_index::CaptureIndexRange,
    general_source_admission::resource::{ResourceSourceContext, source_owner::ResourceSourceReadLane}, lab_reconstruct::ReadSeek,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralDiskState, GeneralFrozenPartition, NativeEvent};
use std::io::{self, Read, Seek, SeekFrom};

pub(crate) struct ProtectedCapturedCandidate<'a> {
    proof: &'a ProtectedPagedTargetSelection,
    source_lane: ResourceSourceReadLane,
    source_before: Option<GeneralDiskState>,
    partition_owner: Option<n2r_win32::PartitionOwnerToken>,
    shadow_before: GeneralDiskState,
    image_length: u64,
    position: u64,
    cached: Option<(u64, CaptureIndexRange)>,
    _lane_memory: crate::artifact_arena::ArenaRamLease,
}

impl<'a> ProtectedCapturedCandidate<'a> {
    /// The actual still-borrowed protected target; never reconstructed from
    /// the capture summary or a persisted route pin.
    pub(crate) fn protected_proof(&self) -> &'a ProtectedPagedTargetSelection {
        self.proof
    }

    pub(crate) fn open(
        proof: &'a ProtectedPagedTargetSelection,
        domain: &ResourceJournalDomain<'_>,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<Self> {
        ensure!(
            std::ptr::eq(domain.capture(), proof.captured()),
            "journal domain does not borrow the exact protected capture owner"
        );
        context.require_source_evidence()?;
        context.recheck_source(events)?;
        proof.scope().revalidate()?;
        proof.captured().revalidate()?;
        ensure!(
            proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "protected capture source inventory differs from its actual context"
        );
        // GeneralFrozenPartition owns a 4 MiB aligned native I/O buffer. The
        // lease is acquired before opening that second lane and remains held
        // until after the lane itself has been dropped.
        let lane_ram = GeneralFrozenPartition::read_buffer_memory_bytes()
            .checked_add(64 * 1024)
            .context("source lane RAM overflow")?;
        let lane_memory = context
            .arena()
            .context("source lane needs the actual shared arena")?
            .reserve_ram(lane_ram)?;
        let (source, _) = context.scoped_source_and_inspection();
        ensure!(
            source.binding() == &proof.scope().pair().source
                && shadow.binding() == &proof.scope().pair().shadow,
            "protected capture source/shadow route differs"
        );
        let source_before = source.state(events)?;
        let shadow_before = shadow.state(events)?;
        ensure!(
            source_before.disk_attributes == 3
                && shadow_before.disk_attributes == 3
                && proof.native().before() == &shadow_before
                && proof.native().after() == &shadow_before,
            "protected capture requires the original excluded source and shadow"
        );
        let mut source_lane = ResourceSourceReadLane::open(source, events)?;
        ensure!(
            source_lane.dedicated_state(events)? == source_before,
            "captured-candidate source lane differs from the real frozen source"
        );
        let image_length = domain.facts().image_length;
        ensure!(
            source.byte_len() == image_length
                && GeneralFrozenPartition::byte_len(shadow) == image_length
                && source_lane.byte_len() == image_length,
            "captured-candidate image geometry differs"
        );
        Ok(Self {
            proof,
            source_lane,
            _lane_memory: lane_memory,
            source_before:Some(source_before),
            partition_owner:None,
            shadow_before,
            image_length,
            position: 0,
            cached: None,
        })
    }

    pub(crate) fn require_domain(&self, domain: &ResourceJournalDomain<'_>) -> Result<()> {
        ensure!(
            std::ptr::eq(domain.capture(), self.proof.captured()),
            "journal domain and captured-candidate proof are not the same owner"
        );
        Ok(())
    }

    /// Recheck the original source fingerprint/owners and the actual target
    /// after preparation. The target proof still does not grant activation.
    pub(crate) fn revalidate(
        &mut self,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> Result<()> {
        let proof = self.protected_proof();
        proof.captured().with_revalidation(|witness| {
            self.revalidate_with_capture_witness(context, shadow, events, witness)
        })?;
        // Keep a complete end check for this standalone boundary too; the
        // scoped witness does not exclude raw writes during the callback.
        proof.captured().revalidate()
    }

    pub(crate) fn revalidate_with_capture_witness(
        &mut self,
        context: &mut ResourceSourceContext,
        shadow: &mut GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
        witness: &crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    ) -> Result<()> {
        witness.require_capture(self.proof.captured())?;
        self.proof.scope().revalidate()?;
        context.recheck_source(events)?;
        ensure!(
            self.proof.scope().source_inspection_sha256() == context.inspection_sha256(),
            "captured-candidate source inventory changed"
        );
        let (source, _) = context.scoped_source_and_inspection();
        ensure!(
            source.binding() == &self.proof.scope().pair().source
                && shadow.binding() == &self.proof.scope().pair().shadow
                && Some(source.state(events)?) == self.source_before
                && Some(self.source_lane.dedicated_state(events)?) == self.source_before
                && shadow.state(events)? == self.shadow_before,
            "captured-candidate frozen route or exclusion changed"
        );
        self.proof
            .recheck_frozen_target_with_capture_witness(shadow, events, witness)?;
        Ok(())
    }

    fn find_row(&mut self, offset: u64) -> Result<CaptureIndexRange> {
        let index = self.proof.captured().index();
        if let Some((_, row)) = self.cached {
            if row.offset <= offset && offset < add(row.offset, row.length)? {
                return Ok(row);
            }
        }
        let (mut low, mut high) = (0u64, index.len());
        while low < high {
            let mid = low + (high - low) / 2;
            let row = index.range(mid)?;
            if add(row.offset, row.length)? <= offset {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        ensure!(
            low < index.len(),
            "captured-candidate read escapes selected rows"
        );
        let row = index.range(low)?;
        ensure!(
            row.offset <= offset && offset < add(row.offset, row.length)?,
            "captured-candidate read enters an unselected gap"
        );
        self.cached = Some((low, row));
        Ok(row)
    }
}

impl Read for ProtectedCapturedCandidate<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.image_length {
            return Ok(0);
        }
        let row = self
            .find_row(self.position)
            .map_err(|e| io::Error::other(format!("{e:#}")))?;
        let within = self.position - row.offset;
        let count = usize::try_from((row.length - within).min(output.len() as u64))
            .map_err(io::Error::other)?;
        if row.new_is_zero {
            output[..count].fill(0);
        } else if let Some(source) = row.copy_source_offset {
            let offset = source
                .checked_add(within)
                .ok_or_else(|| io::Error::other("captured COPY offset overflow"))?;
            self.source_lane.seek(SeekFrom::Start(offset))?;
            self.source_lane.read_exact(&mut output[..count])?;
        } else {
            let offset = row
                .packed_offset
                .checked_add(within)
                .ok_or_else(|| io::Error::other("captured literal offset overflow"))?;
            self.proof
                .captured()
                .literal()
                .read_exact_at(offset, &mut output[..count])
                .map_err(|e| io::Error::other(format!("{e:#}")))?;
        }
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("captured-candidate cursor overflow"))?;
        Ok(count)
    }
}

impl Seek for ProtectedCapturedCandidate<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.image_length) + i128::from(v),
        };
        if position < 0 || position > i128::from(self.image_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "captured-candidate seek escapes image",
            ));
        }
        self.position = u64::try_from(position).map_err(io::Error::other)?;
        Ok(self.position)
    }
}

impl ReadSeek for ProtectedCapturedCandidate<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.image_length)
    }
}

impl<'a> ProtectedCapturedCandidate<'a> {
    pub(crate) fn open_partition(
        proof:&'a ProtectedPagedTargetSelection,domain:&ResourceJournalDomain<'_>,
        context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow:&mut GeneralFrozenPartition,events:&mut Vec<NativeEvent>,
    )->Result<Self>{
        ensure!(std::ptr::eq(domain.capture(),proof.captured()),"partition journal does not borrow exact protected capture");
        context.require_source_evidence()?;context.recheck_source(events)?;
        proof.scope().revalidate()?;proof.captured().revalidate()?;
        let token=context.owner_token();
        proof.native().require_partition_source_owner(&token)?;
        ensure!(proof.scope().matches_source_owner(context.source_owner_identity())
            &&proof.scope().source_inspection_sha256()==context.inspection_sha256(),
            "partition capture source owner/inventory differs");
        let lane_ram=n2r_win32::partition_lifecycle::PartitionReadLane::read_buffer_memory_bytes()
            .checked_add(64*1024).context("partition source lane RAM overflow")?;
        let lane_memory=context.arena().reserve_ram(lane_ram)?;
        let(owner,admission,_)=context.source_admission_and_inspection();
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner,admission)?;
        ensure!(owner.binding().storage==proof.scope().pair().source
            &&shadow.binding()==&proof.scope().pair().shadow,"partition source/shadow route differs");
        owner.revalidate(events)?;
        let shadow_before=shadow.state(events)?;
        ensure!(shadow_before.disk_attributes==3&&proof.native().before()==&shadow_before
            &&proof.native().after()==&shadow_before,"protected partition target lost actual shadow exclusion");
        let lane=n2r_win32::partition_lifecycle::PartitionReadLane::from_owner(owner,events)?;
        let source_lane=ResourceSourceReadLane::Partition(lane);
        let image_length=domain.facts().image_length;
        ensure!(n2r_win32::PartitionScopedOwner::byte_len(owner)==image_length&&n2r_win32::GeneralFrozenPartition::byte_len(shadow)==image_length&&source_lane.byte_len()==image_length,
            "partition capture/journal image geometry differs");
        Ok(Self{proof,source_lane,source_before:None,partition_owner:Some(token),shadow_before,image_length,
            position:0,cached:None,_lane_memory:lane_memory})
    }
    pub(crate) fn revalidate_partition(
        &mut self,context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow:&mut GeneralFrozenPartition,events:&mut Vec<NativeEvent>,
    )->Result<()> {
        let proof=self.proof;
        proof.captured().with_revalidation(|witness|self.revalidate_partition_with_capture_witness(context,shadow,events,witness))?;
        proof.captured().revalidate()
    }
    pub(crate) fn revalidate_partition_with_capture_witness(
        &mut self,context:&mut crate::general_source_admission::resource::partition::PartitionResourceSourceContext,
        shadow:&mut GeneralFrozenPartition,events:&mut Vec<NativeEvent>,
        witness:&crate::general_shadow::paged_capture::CaptureRevalidation<'_>,
    )->Result<()> {
        witness.require_capture(self.proof.captured())?;self.proof.scope().revalidate()?;context.recheck_source(events)?;
        let token=context.owner_token();
        ensure!(self.source_before.is_none()&&self.partition_owner.as_ref().is_some_and(|p|p.same_owner(&token))
            &&self.proof.scope().matches_source_owner(context.source_owner_identity())
            &&self.proof.scope().source_inspection_sha256()==context.inspection_sha256(),
            "partition candidate lost actual original context/token");
        self.proof.native().require_partition_source_owner(&token)?;
        let(owner,admission,_)=context.source_admission_and_inspection();
        n2r_win32::partition_lifecycle::require_complete_fresh_ntfs_admission(owner,admission)?;
        owner.revalidate(events)?;
        ensure!(owner.binding().storage==self.proof.scope().pair().source
            &&shadow.binding()==&self.proof.scope().pair().shadow&&shadow.state(events)?==self.shadow_before,
            "partition candidate source/target binding or shadow state changed");
        match &mut self.source_lane {
            ResourceSourceReadLane::Partition(lane)=>lane.revalidate(owner,events)?,
            ResourceSourceReadLane::Dedicated(_)=>anyhow::bail!("partition candidate acquired dedicated source lane"),
        }
        self.proof.recheck_frozen_target_with_capture_witness(shadow,events,witness)
    }
}
