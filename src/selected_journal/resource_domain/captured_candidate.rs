//! Read only the selected changed bytes from a real protected capture.
//! ZERO comes from its verified classification, literals from its held file,
//! and COPY from a separately reopened frozen source lane. This is not a
//! source-admission certificate, journal ticket or target-write capability.
use super::{ResourceJournalDomain, add};
use crate::{
    general_composite_target::paged::ProtectedPagedTargetSelection,
    general_shadow::capture_index::CaptureIndexRange,
    general_source_admission::resource::ResourceSourceContext, lab_reconstruct::ReadSeek,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{GeneralDiskState, GeneralFrozenPartition, NativeEvent};
use std::io::{self, Read, Seek, SeekFrom};

pub(crate) struct ProtectedCapturedCandidate<'a> {
    proof: &'a ProtectedPagedTargetSelection,
    source_lane: GeneralFrozenPartition,
    source_before: GeneralDiskState,
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
        let (source, _) = context.source_and_inspection();
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
        let mut source_lane = GeneralFrozenPartition::reopen(source.binding().clone(), events)?;
        ensure!(
            source_lane.state(events)? == source_before,
            "captured-candidate source lane differs from the real frozen source"
        );
        let image_length = domain.facts().image_length;
        ensure!(
            GeneralFrozenPartition::byte_len(source) == image_length
                && GeneralFrozenPartition::byte_len(shadow) == image_length
                && GeneralFrozenPartition::byte_len(&source_lane) == image_length,
            "captured-candidate image geometry differs"
        );
        Ok(Self {
            proof,
            source_lane,
            _lane_memory: lane_memory,
            source_before,
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
        let (source, _) = context.source_and_inspection();
        ensure!(
            source.binding() == &self.proof.scope().pair().source
                && shadow.binding() == &self.proof.scope().pair().shadow
                && source.state(events)? == self.source_before
                && self.source_lane.state(events)? == self.source_before
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
