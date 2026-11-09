//! One read-only stream batch. Live immutable tree ownership and actual
//! same-FileObject duplicates scope the cached summary/ranges to this callback.
//! No snapshot can cross a tree write, serialize authority, or expose handles.
use super::*;

#[derive(PartialEq,Eq)]
struct Metadata {
    basic:[u8;40],standard:[u8;24],identity:[u8;24],tag:[u8;8],security:Vec<u8>,
}
impl Metadata {
    fn capture(file:&File)->io::Result<Self>{
        validate_open_type(file,false)?;
        let value=Self{basic:info(file,0,40)?.try_into().map_err(|_|invalid("supply basic size differs"))?,
            standard:info(file,1,24)?.try_into().map_err(|_|invalid("supply standard size differs"))?,
            identity:info(file,18,24)?.try_into().map_err(|_|invalid("supply identity size differs"))?,
            tag:info(file,9,8)?.try_into().map_err(|_|invalid("supply tag size differs"))?,
            security:super::routed_prefix::security(file)?};
        if value.standard[20]!=0||value.standard[21]!=0||u32::from_le_bytes(value.standard[16..20].try_into().unwrap())!=1 {
            return Err(invalid("supply snapshot file link/type/delete state differs"));
        }
        Ok(value)
    }
}
struct NativeFile {
    file:File,metadata:Metadata,mapping:Option<[u8;32]>,
}
impl NativeFile {
    fn capture(file:&File,placeholder:Option<&unwritten::PrivatePlaceholder>)->io::Result<Self>{
        let duplicate=crate::file_storage::duplicate_readonly(file)?;
        crate::file_storage::require_readonly_access(&duplicate)?;
        let metadata=Metadata::capture(&duplicate)?;
        let mapping=placeholder.map(|p|p.readonly_supply_mapping_fingerprint(&duplicate)).transpose()?.flatten();
        if Metadata::capture(&duplicate)?!=metadata{return Err(invalid("supply snapshot metadata changed during map capture"));}
        Ok(Self{file:duplicate,metadata,mapping})
    }
    fn revalidate(&self,placeholder:Option<&unwritten::PrivatePlaceholder>)->io::Result<()> {
        let before=Metadata::capture(&self.file)?;
        let mapping=placeholder.map(|p|p.readonly_supply_mapping_fingerprint(&self.file)).transpose()?.flatten();
        let after=Metadata::capture(&self.file)?;
        if before!=self.metadata||after!=self.metadata||mapping!=self.mapping {
            return Err(invalid("readonly supply snapshot metadata/security/complete map changed"));
        }Ok(())
    }
}

/// Issued only inside with_readonly_supply_stream_snapshot. The immutable
/// borrow prevents any safe PrivateTree write while this native batch exists.
pub struct NativeReadOnlySupplyStreamSnapshot<'tree> {
    tree:&'tree PrivateTree,
    key:StreamKey,
    primary:Option<NativeFile>,
    sparse:Option<NativeFile>,
    summary:StreamSupplySummary,
    ranges:Vec<(SupplyKind,SupplyRange)>,
    // The actual shared payer stays live until every native handle, key,
    // descriptor, summary and range above has dropped.
    _memory:Box<dyn report_memory::ReportMemoryLease>,
    _ranges_memory:Box<dyn report_memory::ReportMemoryLease>,
}
impl NativeReadOnlySupplyStreamSnapshot<'_> {
    pub fn summary(&self)->&StreamSupplySummary{&self.summary}
    pub fn ranges(&self)->&[(SupplyKind,SupplyRange)]{&self.ranges}
    pub(super) fn tree(&self)->&PrivateTree{self.tree}
    pub(super) fn key(&self)->&StreamKey{&self.key}
    fn revalidate(&self)->io::Result<()> {
        if let Some(file)=&self.primary {file.revalidate(self.tree.files.get(&self.key))?;}
        if let Some(file)=&self.sparse {file.revalidate(None)?;}
        Ok(())
    }
}
pub(super) fn close_result<T>(result:io::Result<T>,closing:io::Result<()>,label:&str)->io::Result<T>{
    match(result,closing){(Ok(value),Ok(()))=>Ok(value),
        (Err(error),Err(close))=>Err(io::Error::new(error.kind(),format!("{error}; {label} also failed: {close}"))),
        (Err(error),_)=>Err(error),(_,Err(error))=>Err(io::Error::new(error.kind(),format!("{label}: {error}")))}
}
pub(super) fn with_snapshot<T>(
    tree:&PrivateTree,index:usize,name:&[u16],components:&[String],logical:u64,maximum_range_bytes:u64,
    consume:impl FnOnce(&NativeReadOnlySupplyStreamSnapshot<'_>)->io::Result<T>,
)->io::Result<T>{
    // Native full source/shadow fences are PER STREAM, never cached across a
    // write or callback. Even creation/callback failures execute the closing.
    let opening=tree.require_source_excluded();
    let result=(||{
        opening?;
        if !tree.placement_complete{return Err(invalid("readonly supply snapshot requires complete live placement"));}
        let admission=tree.metadata_resource_admission.ok_or_else(||invalid("readonly supply snapshot requires V4 admission"))?;
        let payer=tree.memory.as_ref().ok_or_else(||invalid("readonly supply snapshot payer absent"))?.payer();
        let maximum=maximum_range_bytes.min(admission.budget.max_row_bytes.checked_mul(8).ok_or_else(||invalid("supply snapshot row overflow"))?);
        let work=tree.supply_stream_workspace_bytes(index,name)?;
        // Pay before the first owned key, metadata buffer, or native duplicate.
        let memory=payer.reserve(work.checked_add(1024*1024).ok_or_else(||invalid("supply snapshot RAM overflow"))?)?;
        let key=tree.validate_stream_shape_metadata(index,name,components,logical)?;
        let primary=tree.files.get(&key);
        let sparse=tree.sparse_targets.get(&key);
        // The dense interval partition contributes at most two pieces per
        // retained reference. Each sparse island boundary adds one split and
        // each declared logical hole one range; no row maximum is leased for
        // an ordinary one-range stream.
        let references=tree.original_coordinates.get(&key).map_or(0,Vec::len);
        let maximum_ranges=references.checked_mul(2)
            .and_then(|n|n.checked_add(sparse.map_or(0,|t|t.islands.len())))
            .and_then(|n|n.checked_add(sparse.map_or(0,|t|t.layout.holes.len())))
            .and_then(|n|n.checked_add(4)).ok_or_else(||invalid("supply snapshot range count overflow"))?;
        let per_range=(std::mem::size_of::<(SupplyKind,SupplyRange)>() as u64)
            .checked_add((name.len() as u64).checked_mul(2).ok_or_else(||invalid("supply name RAM overflow"))?)
            .ok_or_else(||invalid("supply range RAM overflow"))?;
        let range_memory=(maximum_ranges as u64).checked_mul(per_range)
            .and_then(|n|n.checked_mul(2)).and_then(|n|n.checked_add(4096))
            .ok_or_else(||invalid("supply snapshot range RAM overflow"))?;
        if range_memory>maximum{return Err(invalid("readonly supply interval bounds exceed actual row budget"));}
        let range_lease=payer.reserve(range_memory)?;
        let extra=usize::from(primary.is_some())+usize::from(sparse.is_some());
        let handles=(tree.files.len() as u64).checked_add(tree.sparse_targets.len() as u64)
            .and_then(|n|n.checked_add(tree.metadata_targets.len() as u64))
            .and_then(|n|n.checked_add(u64::from(tree.carrier_directory.is_some())))
            .and_then(|n|n.checked_add(u64::from(tree.dedicated_source.is_some())))
            .and_then(|n|n.checked_add(8+extra as u64)).ok_or_else(||invalid("supply snapshot handle count overflow"))?;
        if handles>admission.budget.handle_slots{return Err(invalid("supply snapshot duplicates exceed actual handle slots"));}
        let primary=primary.map(|file|NativeFile::capture(file.metadata_handle(),Some(file))).transpose()?;
        let sparse=sparse.map(|target|NativeFile::capture(&target.file,None)).transpose()?;
        let mut snapshot=NativeReadOnlySupplyStreamSnapshot{tree,key,primary,sparse,
            summary:StreamSupplySummary{logical_bytes:0,materialize_bytes:0,source_reference_bytes:0,hole_bytes:0,ranges:0,ordered_range_sha256:String::new()},
            ranges:Vec::new(),_memory:memory,_ranges_memory:range_lease};
        let mut ranges=Vec::new();
        ranges.try_reserve_exact(maximum_ranges).map_err(io::Error::other)?;
        if ranges.capacity()>maximum_ranges.saturating_mul(2){return Err(invalid("snapshot range vector exceeds paid capacity"));}
        let mut range_bytes=0u64;
        let built=supply::stream_in_snapshot(&snapshot,|kind,range|{
            let next=(std::mem::size_of::<(SupplyKind,SupplyRange)>() as u64)
                .checked_add((range.stream_name_utf16.len() as u64).checked_mul(2).ok_or_else(||invalid("snapshot stream name overflow"))?)
                .ok_or_else(||invalid("snapshot range size overflow"))?;
            range_bytes=range_bytes.checked_add(next).ok_or_else(||invalid("snapshot range total overflow"))?;
            if range_bytes>maximum{return Err(invalid("readonly supply ranges exceed actual row budget"));}
            if ranges.len()==maximum_ranges{return Err(invalid("snapshot range count exceeds actual interval bound"));}
            ranges.push((kind,range.clone()));Ok(())
        });
        let result=match built {
            Ok(summary)=>{
                if summary.logical_bytes!=logical{return close_result(Err(invalid("snapshot canonical logical length differs")),snapshot.revalidate(),"supply snapshot native closing");}
                snapshot.summary=summary;snapshot.ranges=ranges;
                // The callback may reserve/clone bounded app output, but no
                // mutable tree API can run under this immutable borrow.
                consume(&snapshot)
            },Err(error)=>Err(error),
        };
        close_result(result,snapshot.revalidate(),"supply snapshot native closing")
    })();
    close_result(result,tree.require_source_excluded(),"supply snapshot full source/shadow closing fence")
}
