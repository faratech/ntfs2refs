//! New native owners of existing, independently proven unwritten placeholders.
//! Saved creator flags are deliberately not an input to this module.
use super::*;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;

/// ReFS storage-VDL evidence, separate from the initialized-region validator.
/// Query the entire EOF using VALID_NONCACHED_DATA (2). A single usage-zero
/// region covering that EOF proves there is no initialized storage prefix.
/// Unsupported operations and partial/ambiguous replies refuse adoption.
pub(in crate::shadow_native) fn require_zero_storage_vdl(
    file: &File,
    bytes: u64,
) -> io::Result<()> {
    let identity = super::super::info(file, 18, 24)?;
    let before = super::super::info(file, 1, 24)?;
    if u64::from_le_bytes(before[8..16].try_into().unwrap()) != bytes
        || before[20] != 0
        || before[21] != 0
    {
        return Err(invalid("unwritten adoption EOF/type/delete state differs"));
    }
    // Settle cached writes before observing storage VDL. This is a flush, never
    // SetFileValidData, a payload write, or a saved-state inference.
    file.sync_all()?;
    let mut input = [0u8; 24];
    input[8..16].copy_from_slice(&bytes.max(1).to_le_bytes());
    input[16..20].copy_from_slice(&2u32.to_le_bytes());
    let regions = super::super::ctl(file, 0x0009_0284, &input, 64)?;
    if regions.len() != 40
        || u32::from_le_bytes(regions[4..8].try_into().unwrap()) != 1
        || u32::from_le_bytes(regions[8..12].try_into().unwrap()) != 1
        || i64::from_le_bytes(regions[16..24].try_into().unwrap()) != 0
        || u32::from_le_bytes(regions[32..36].try_into().unwrap()) != 0
    {
        return Err(invalid(
            "native full-EOF storage-VDL is not one unwritten region",
        ));
    }
    let length = i64::from_le_bytes(regions[24..32].try_into().unwrap());
    let rounded = bytes
        .checked_add(4095)
        .ok_or_else(|| invalid("VDL EOF overflow"))?
        / 4096
        * 4096;
    if length < 0
        || (length as u64) < bytes
        || (length as u64) > rounded
        || super::super::info(file, 18, 24)? != identity
        || super::super::info(file, 1, 24)? != before
    {
        return Err(invalid(
            "native unwritten region coverage or identity changed",
        ));
    }
    Ok(())
}

impl PrivatePlaceholder {
    pub(in crate::shadow_native) fn current_allocated_ranges(&self) -> io::Result<Vec<(u64, u64)>> {
        if !self.recovered_origin {
            return Err(invalid("native recovered file owner required"));
        }
        let resource = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("recovered resource capture absent"))?;
        let _memory = resource.tracking_workspace(self.bytes)?;
        let capture = resource.capture(&self.file)?;
        let mut out = Vec::new();
        for run in &capture.runs {
            if let Some(lcn) = run.lcn {
                if lcn
                    .checked_add(run.clusters)
                    .is_none_or(|n| n > self.partition / 4096)
                {
                    return Err(invalid("recovered full retrieval map escapes partition"));
                }
                if out.len() == resource.max_tracked_slots {
                    return Err(invalid("recovered full-map slot bound exhausted"));
                }
                out.push((lcn, run.clusters));
            }
        }
        Ok(out)
    }
    pub(in crate::shadow_native) fn reopen_unwritten(
        root: &str,
        components: &[String],
        name: &[u16],
        bytes: u64,
        partition: u64,
        retire: bool,
        admission: crate::tree_resources::SourceResourceAdmission,
        tracked: usize,
        moves: usize,
        move_bytes: u64,
        payer: Arc<dyn super::super::report_memory::ReportMemoryAccountant>,
    ) -> io::Result<Self> {
        let path = super::super::streams::path(root, components, name)?;
        let file = File::options()
            .access_mode(0xc1020000 | if retire { 0x10000 } else { 0 })
            .share_mode(0)
            .custom_flags(0x80200080)
            .open(&path)?;
        super::super::validate_open_type(&file, false)?;
        super::super::private_tree::recovery::require_private_security(&file, false)?;
        let standard = super::super::info(&file, 1, 24)?;
        if u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1 {
            return Err(invalid("recovered placeholder has additional hard links"));
        }
        require_zero_storage_vdl(&file, bytes)?;
        let retire_identity = if retire {
            Some(super::super::info(&file, 18, 24)?)
        } else {
            None
        };
        // These are new flags derived from the just-completed native proof,
        // rather than restored historical flags or a reset old owner.
        let mut value = Self {
            file,
            path,
            bytes,
            partition,
            placed: Vec::new(),
            valid_data_submitted: false,
            valid_prefix: 0,
            materialized_bytes: 0,
            readback_bytes: 0,
            verification_read_bytes: 0,
            poisoned: false,
            move_submissions: 0,
            initial_mapping_tracked: false,
            retrieval_extents: 0,
            retire_identity,
            resource: None,
            recovered_origin: true,
        };
        value.enable_resource_placement(admission, tracked, moves, move_bytes, payer)?;
        // Pay and capture the complete CURRENT map, including holes. The old
        // move log is neither required nor replayed to reconstruct ownership.
        drop(value.track_current_prefix_resource()?);
        Ok(value)
    }

    pub(in crate::shadow_native) fn recovered_holes_resource(
        &self,
    ) -> io::Result<ResourceTrackedHoles> {
        if !self.recovered_origin
            || !self.initial_mapping_tracked
            || self.poisoned
            || self.valid_prefix != 0
            || self.valid_data_submitted
            || self.move_submissions != 0
        {
            return Err(invalid("fresh native recovered-map owner required"));
        }
        require_zero_storage_vdl(&self.file, self.bytes)?;
        self.verify_placements()?;
        let resource = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("recovered resource owner absent"))?;
        let _workspace = resource.tracking_workspace(self.bytes)?;
        // The old generic placement check proves all tracked pieces remain.
        // Cold adoption additionally proves there are NO newly allocated
        // pieces inside formerly observed holes before deriving that hole set.
        let capture = resource.capture(&self.file)?;
        let mut first_tracked = 0usize;
        let prefix = self.bytes / 4096;
        for run in &capture.runs {
            let Some(lcn) = run.lcn else {
                continue;
            };
            let mut cursor = run.vcn;
            let end = (run.vcn + run.clusters).min(prefix);
            while cursor < end {
                while self
                    .placed
                    .get(first_tracked)
                    .is_some_and(|&(v, _, n)| v + u64::from(n) <= cursor)
                {
                    first_tracked += 1;
                }
                let &(v, l, n) = self
                    .placed
                    .get(first_tracked)
                    .ok_or_else(|| invalid("recovered hole gained native allocation"))?;
                if v > cursor || l + cursor - v != lcn + cursor - run.vcn {
                    return Err(invalid("recovered complete current mapping changed"));
                }
                cursor = (v + u64::from(n)).min(end);
            }
        }
        let mut holes = Vec::new();
        let mut cursor = 0u64;
        for &(vcn, _, count) in &self.placed {
            if vcn < cursor {
                return Err(invalid("recovered logical ranges overlap"));
            }
            while cursor < vcn {
                let count = (vcn - cursor).min(u64::from(u32::MAX)) as u32;
                holes.push((cursor, count));
                cursor += u64::from(count);
            }
            cursor = vcn
                .checked_add(u64::from(count))
                .ok_or_else(|| invalid("recovered VCN overflow"))?;
        }
        let end = self.bytes / 4096;
        while cursor < end {
            let count = (end - cursor).min(u64::from(u32::MAX)) as u32;
            holes.push((cursor, count));
            cursor += u64::from(count);
        }
        if cursor != end || holes.len() + self.placed.len() > resource.max_tracked_slots {
            return Err(invalid("recovered holes exceed native map bound"));
        }
        resource.hold_holes(holes)
    }
}
