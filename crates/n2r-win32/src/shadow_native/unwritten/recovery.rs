//! New native owners of existing, independently proven unwritten placeholders.
//! Saved creator flags are deliberately not an input to this module.
use super::*;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;

/// ReFS storage-VDL evidence, separate from the initialized-region validator.
/// Query the entire EOF using VALID_NONCACHED_DATA (2). ReFS may split an
/// unwritten file at allocation boundaries, so prove gap-free usage-zero
/// coverage across every returned region, including paginated responses.
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
    super::super::unwritten_regions::require(file,bytes)?;
    if super::super::info(file, 18, 24)? != identity
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
        let identity = super::super::info(&self.file, 18, 24)?;
        let standard = super::super::info(&self.file, 1, 24)?;
        if u64::from_le_bytes(standard[8..16].try_into().unwrap()) != self.bytes
            || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
            || standard[20] != 0 || standard[21] != 0
        {
            return Err(invalid("recovered allocation EOF/link/type/delete state differs"));
        }
        let (first, continuation) = crate::stream_native::retrieval_queries_resource(
            &self.file, resource.retrieval_bytes)?;
        // ReFS may report inline resident bytes as allocation (for example,
        // EOF174/allocation176) while correctly returning no payload LCNs.
        // Reuse the ordinary verifier's resident-allocation contract; cluster
        // allocations still require the complete native retrieval map.
        let allocation = u64::from_le_bytes(standard[..8].try_into().unwrap());
        let no_payload_allocation = allocation == 0
            || super::super::resident_allocation(self.bytes, allocation);
        let empty = no_payload_allocation && continuation.is_empty()
            && ((first.native_error == Some(38) && first.bytes.is_empty())
                || (self.bytes == 0 && first.native_error.is_none()
                    && first.bytes.len() == 16
                    && u32::from_le_bytes(first.bytes[..4].try_into().unwrap()) == 0));
        if super::super::info(&self.file, 18, 24)? != identity
            || super::super::info(&self.file, 1, 24)? != standard
        {
            return Err(invalid("recovered allocation identity or lengths changed"));
        }
        if empty { return Ok(Vec::new()); }
        let capture = crate::retrieval_paging::assemble_queries_with_limits(
            &first, &continuation,
            crate::retrieval_paging::Limits::for_resource_bytes(resource.retrieval_bytes)?,
        ).map_err(|error| io::Error::new(error.kind(), format!(
            "recovered allocation capture failed: path={:?}, logical_bytes={}, allocation_bytes={}, first_error={:?}, first_bytes={}, continuation_pages={}: {error}",
            self.path, self.bytes,
            u64::from_le_bytes(standard[..8].try_into().unwrap()),
            first.native_error, first.bytes.len(), continuation.len())))?;
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
        Self::reopen_recovered(root,components,name,bytes,partition,retire,admission,
            tracked,moves,move_bytes,payer,false)
    }
    pub(in crate::shadow_native) fn reopen_placed(
        root:&str,components:&[String],name:&[u16],bytes:u64,partition:u64,retire:bool,
        admission:crate::tree_resources::SourceResourceAdmission,tracked:usize,moves:usize,
        move_bytes:u64,payer:Arc<dyn super::super::report_memory::ReportMemoryAccountant>,
    )->io::Result<Self>{
        Self::reopen_recovered(root,components,name,bytes,partition,retire,admission,
            tracked,moves,move_bytes,payer,true)
    }
    fn reopen_recovered(
        root:&str,components:&[String],name:&[u16],bytes:u64,partition:u64,retire:bool,
        admission:crate::tree_resources::SourceResourceAdmission,tracked:usize,moves:usize,
        move_bytes:u64,payer:Arc<dyn super::super::report_memory::ReportMemoryAccountant>,
        placed_ready:bool,
    )->io::Result<Self>{
        let path = super::super::streams::path(root, components, name)?;
        let file = File::options()
            .access_mode(0xc1020000 | if retire { 0x10000 } else { 0 })
            .share_mode(0)
            .custom_flags(0x80200080)
            .open(&path)?;
        super::super::validate_open_type(&file, false)?;
        super::super::private_tree::recovery::require_private_security(&file, false)?;
        let recovered_id=super::super::info(&file,18,24)?;
        let standard = super::super::info(&file, 1, 24)?;
        if u64::from_le_bytes(standard[8..16].try_into().unwrap()) != bytes
            || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
            || standard[20] != 0 || standard[21] != 0
        {
            return Err(invalid("recovered placeholder EOF/link/type/delete state differs"));
        }
        // ReFS may store sub-cluster EOFs initialized inside metadata even
        // after allocation-only SetEndOfFile. No cluster from these streams
        // can be retained: the normal supply pass rewrites their entire EOF.
        // Keep valid_prefix/materialized_bytes zero so recovery never treats
        // their current contents as admitted payload.
        if bytes >= 4096 && !placed_ready {
            require_zero_storage_vdl(&file, bytes)?;
        }
        let prefix=bytes/4096*4096;
        let mut placed_resource=if placed_ready {
            Some(resource::ResourcePlacement::new(admission,tracked,moves,move_bytes,payer.clone())?)
        }else{None};
        let mut placed_map=Vec::new();
        let mut retrieval_extents=0;
        if let Some(resource)=placed_resource.as_mut() {
            let _work=resource.tracking_workspace(bytes)?;
            if prefix>0 {
                super::super::initialized_regions::capture_initialized(
                    &file,prefix,2,resource.retrieval_bytes)?.validate(prefix,2)?;
                let capture=resource.capture(&file)?;
                retrieval_extents=capture.runs.len();
                let mut cursor=0u64;
                for run in &capture.runs {
                    if run.vcn>=prefix/4096 {break;}
                    let lcn=run.lcn.ok_or_else(||invalid("placed recovery prefix has a native hole"))?;
                    if run.vcn!=cursor || run.clusters==0 {
                        return Err(invalid("placed recovery prefix is not dense and complete"));
                    }
                    let end=run.vcn.checked_add(run.clusters).ok_or_else(||invalid("placed recovery VCN overflow"))?
                        .min(prefix/4096);
                    let mut at=run.vcn;
                    while at<end {
                        if placed_map.len()==resource.max_tracked_slots {return Err(invalid("placed recovery map exceeds paid slots"));}
                        let count=(end-at).min(u64::from(u32::MAX)) as u32;
                        let physical=lcn.checked_add(at-run.vcn).ok_or_else(||invalid("placed recovery LCN overflow"))?;
                        if physical.checked_add(u64::from(count)).is_none_or(|n|n>partition/4096){return Err(invalid("placed recovery map escapes shadow"));}
                        placed_map.push((at,physical,count));at+=u64::from(count);
                    }
                    cursor=end;
                }
                if cursor!=prefix/4096 {return Err(invalid("placed recovery prefix allocation ends early"));}
                super::super::initialized_regions::capture_initialized(
                    &file,prefix,2,resource.retrieval_bytes)?.validate(prefix,2)?;
            }
            if super::super::info(&file,1,24)?!=standard
                ||super::super::info(&file,18,24)?!=recovered_id {return Err(invalid("placed recovery file identity or shape changed"));}
            let lease=resource.reserve_placed(placed_map.len(),placed_map.capacity())?;
            resource.replace_placed_lease(lease);
        }
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
            placed: placed_map,
            valid_data_submitted: placed_ready && prefix>0,
            valid_prefix: if placed_ready {prefix}else{0},
            materialized_bytes: 0,
            readback_bytes: 0,
            verification_read_bytes: 0,
            poisoned: false,
            move_submissions: 0,
            initial_mapping_tracked: placed_ready,
            retrieval_extents,
            retire_identity,
            resource: placed_resource,
            recovered_origin: true,
        };
        if placed_ready {return Ok(value);}
        value.enable_resource_placement(admission, tracked, moves, move_bytes, payer)?;
        // Pay and capture the complete CURRENT map, including holes. The old
        // move log is neither required nor replayed to reconstruct ownership.
        drop(value.track_current_prefix_resource()?);
        Ok(value)
    }

    /// Fresh readiness only; no previously written payload bytes are trusted.
    pub(in crate::shadow_native) fn revalidate_recovered_prefix(&self,prefix:u64)->io::Result<bool>{
        if !self.recovered_origin || !self.valid_data_submitted {return Ok(false);}
        if self.poisoned || self.valid_prefix!=prefix || prefix==0 {
            return Err(invalid("recovered placed prefix state differs"));
        }
        let resource=self.resource.as_ref().ok_or_else(||invalid("placed prefix payer absent"))?;
        let _work=resource.tracking_workspace(self.bytes)?;
        self.file.sync_all()?;
        super::super::initialized_regions::capture_initialized(&self.file,prefix,2,
            resource.retrieval_bytes)?.validate(prefix,2)?;
        self.verify_placements()?;
        Ok(true)
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
        let resource = self
            .resource
            .as_ref()
            .ok_or_else(|| invalid("recovered resource owner absent"))?;
        // There is no whole-cluster placement prefix for a tiny stream.
        // Its physical allocation was audited separately, and supply rewrites
        // the complete EOF; neither resident bytes nor a tail become retained.
        if self.bytes < 4096 {
            let identity = super::super::info(&self.file, 18, 24)?;
            let standard = super::super::info(&self.file, 1, 24)?;
            if !self.placed.is_empty()
                || u64::from_le_bytes(standard[8..16].try_into().unwrap()) != self.bytes
                || u32::from_le_bytes(standard[16..20].try_into().unwrap()) != 1
                || standard[20] != 0 || standard[21] != 0
            {
                return Err(invalid("recovered tiny-stream placement or EOF/link/type differs"));
            }
            if super::super::info(&self.file, 18, 24)? != identity
                || super::super::info(&self.file, 1, 24)? != standard
            {
                return Err(invalid("recovered tiny-stream identity or lengths changed"));
            }
            return resource.hold_holes(Vec::new());
        }
        require_zero_storage_vdl(&self.file, self.bytes)?;
        self.verify_placements()?;
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
