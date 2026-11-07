//! Opaque exact-file TxF marker observations within the existing Windows
//! physically read-only native collection. No source setters or RM controls.
use crate::{
    attestation::{FileIdentity, NativeRequestDomain},
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
    shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease},
};
use serde::Serialize;
use std::{fmt, fs::{File, OpenOptions}, io, mem, os::windows::{fs::OpenOptionsExt, io::{AsRawHandle, FromRawHandle}}, ptr, sync::Arc};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType, GetFileInformationByHandleEx, OpenFileById},
    System::IO::DeviceIoControl,
};

// winioctl.h 10.0.26100.0: CTL_CODE(FILE_DEVICE_FILE_SYSTEM,82/91/92,
// METHOD_BUFFERED,FILE_READ_DATA). Official output layouts are48/16 bytes.
const QUERY_RM: u32 = (9 << 16) | (1 << 14) | (82 << 2);
const GET_METADATA: u32 = (9 << 16) | (1 << 14) | (91 << 2);
const GET_VERSION: u32 = (9 << 16) | (1 << 14) | (92 << 2);
const MAX_REPLY: usize = 65536;
fn invalid(s: impl Into<String>) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, s.into()) }
fn u32_at(b: &[u8], at: usize) -> io::Result<u32> { Ok(u32::from_le_bytes(b.get(at..at+4).ok_or_else(||invalid("short marker DWORD"))?.try_into().unwrap())) }
fn u64_at(b: &[u8], at: usize) -> io::Result<u64> { Ok(u64::from_le_bytes(b.get(at..at+8).ok_or_else(||invalid("short marker QWORD"))?.try_into().unwrap())) }

#[derive(Debug, Serialize)]
pub struct WindowsTxfQuery {
    pub operation: &'static str,
    pub code_or_class: u32,
    pub succeeded: bool,
    pub native_error: Option<i32>,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct WindowsTxfMarkerRow {
    pub identity: FileIdentity,
    pub open_error: Option<i32>,
    pub file_id_before: Option<WindowsTxfQuery>,
    pub standard_before: Option<WindowsTxfQuery>,
    pub attributes_before: Option<WindowsTxfQuery>,
    pub metadata: Option<WindowsTxfQuery>,
    pub version: Option<WindowsTxfQuery>,
    pub resource_manager: Option<WindowsTxfQuery>,
    pub file_id_after: Option<WindowsTxfQuery>,
    pub standard_after: Option<WindowsTxfQuery>,
    pub attributes_after: Option<WindowsTxfQuery>,
}
#[derive(Debug, Serialize)]
pub struct WindowsTxfPass {
    pub volume_open_error: Option<i32>,
    pub volume_extents: Option<WindowsTxfQuery>,
    pub ntfs_volume_data: Option<WindowsTxfQuery>,
    pub rows: Vec<WindowsTxfMarkerRow>,
}
#[derive(Debug, Serialize)]
pub struct WindowsTxfAudit {
    pub kind: &'static str,
    pub binding: GeneralDiskBinding,
    pub source_inspection_sha256: String,
    pub ntfs_serial: u64,
    pub before: Option<WindowsTxfPass>,
    pub after: Option<WindowsTxfPass>,
    pub source_write_calls: u64,
    pub payload_read_calls: u64,
    pub rm_mutation_calls: u64,
}
/// Not constructible or deserializable by the application. The same opaque
/// owner retains all raw queries and the shared memory payments.
pub struct VerifiedWindowsTxfMarkers {
    audit: WindowsTxfAudit,
    selected: Vec<(usize, FileIdentity)>,
    _leases: Vec<Box<dyn ReportMemoryLease>>,
}
impl fmt::Debug for VerifiedWindowsTxfMarkers {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.debug_struct("VerifiedWindowsTxfMarkers").field("markers",&self.selected.len()).finish_non_exhaustive() }
}
impl VerifiedWindowsTxfMarkers {
    pub fn binding(&self)->&GeneralDiskBinding { &self.audit.binding }
    pub fn audit(&self)->&WindowsTxfAudit { &self.audit }
    pub fn len(&self)->usize { self.selected.len() }
    pub fn is_empty(&self)->bool { self.selected.is_empty() }
    pub fn require_identity_scope(&self,binding:&GeneralDiskBinding,inspection_sha256:[u8;32],identity:&FileIdentity)->io::Result<()> {
        if binding != &self.audit.binding || hex::encode(inspection_sha256)!=self.audit.source_inspection_sha256
            || !self.selected.iter().any(|(_,id)|id==identity) {
            return Err(invalid("Windows TxF marker belongs to another actual source/inspection/identity"));
        }
        Ok(())
    }
    pub fn require_raw_marker_scope(&self,binding:&GeneralDiskBinding,inspection_sha256:[u8;32],identity:&FileIdentity,raw:&[u8;56])->io::Result<()> {
        self.require_identity_scope(binding,inspection_sha256,identity)?;
        for pass in [&self.audit.before,&self.audit.after] {
            let row=pass.as_ref().and_then(|pass|pass.rows.iter().find(|row|&row.identity==identity))
                .ok_or_else(||invalid("Windows TxF raw marker has no exact native row"))?;
            let metadata=bytes(&row.metadata,48)?;
            if metadata[..8]!=raw[16..24] || metadata[8..16]!=[0;8] || metadata[32..40]!=raw[24..32] {
                return Err(invalid("raw Windows TxF marker ID/LSN differs from protected native before/after queries"));
            }
        }
        Ok(())
    }
    pub(crate) fn refuse(self:Arc<Self>,error:io::Error)->io::Error {
        io::Error::other(VerifiedRefusal{reason:error.to_string(),witness:self})
    }
}
#[derive(Debug)]
struct VerifiedRefusal { reason:String,witness:Arc<VerifiedWindowsTxfMarkers> }
impl fmt::Display for VerifiedRefusal {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {write!(f,"Windows TxF protected collection refused: {}; retained native evidence: {}",self.reason,serde_json::to_string(self.witness.audit()).map_err(|_|fmt::Error)?)}
}
impl std::error::Error for VerifiedRefusal {}
pub(crate) struct PendingWindowsTxfMarkers {
    audit: WindowsTxfAudit,
    selected: Vec<(usize, FileIdentity)>,
    leases: Vec<Box<dyn ReportMemoryLease>>,
}
struct Refusal {
    reason: String,
    audit: WindowsTxfAudit,
    _leases: Vec<Box<dyn ReportMemoryLease>>,
}
impl fmt::Debug for Refusal { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.debug_struct("WindowsTxfRefusal").field("reason",&self.reason).field("audit",&self.audit).finish() } }
impl fmt::Display for Refusal {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {
        write!(f,"Windows TxF marker observation refused: {}; retained native evidence: {}",self.reason,
            serde_json::to_string(&self.audit).map_err(|_|fmt::Error)?)
    }
}
impl std::error::Error for Refusal {}
impl PendingWindowsTxfMarkers {
    pub(crate) fn refuse(self,error:io::Error)->io::Error { io::Error::other(Refusal{reason:error.to_string(),audit:self.audit,_leases:self.leases}) }
    pub(crate) fn begin(binding:&GeneralDiskBinding,selectors:&impl NativeRequestDomain,payer:&Arc<dyn ReportMemoryAccountant>)->io::Result<Self> {
        let header=selectors.header();
        if binding.layout_profile!=GeneralDiskLayoutProfile::OfflineWindows || header.disk_number!=binding.disk_number
            || header.partition_offset!=binding.identity.partition_offset || header.partition_length!=binding.identity.partition_bytes
            || header.volume!=format!("{}\\",binding.volume_path()?) || header.source_inspection_sha256.len()!=64 {
            return Err(invalid("actual offline Windows marker source binding required"));
        }
        let base_bytes=(256*1024u64).checked_add(payer.lease_heap_bytes()).ok_or_else(||invalid("Windows TxF marker base RAM overflow"))?;
        let base=payer.reserve(base_bytes)?;
        let mut result=Self{audit:WindowsTxfAudit{kind:"protected-Windows-TxF-marker-observation-v1",binding:binding.clone(),source_inspection_sha256:header.source_inspection_sha256.clone(),ntfs_serial:header.ntfs_serial,before:None,after:None,source_write_calls:0,payload_read_calls:0,rm_mutation_calls:0},selected:Vec::new(),leases:vec![base]};
        let selection=(||->io::Result<()>{
            for index in 0..selectors.len() {
                if let Some(identity)=selectors.windows_txf_metadata_identity(index)? {
                    if identity!=selectors.identity(index)? || (identity.record_number!=5&&identity.record_number<16)
                        || result.selected.last().is_some_and(|(_,previous)|previous.record_number>=identity.record_number) {
                        return Err(invalid("Windows TxF marker selector identity/order differs"));
                    }
                    // Covers both retained64KiB query replies, all fixed native
                    // identity fields, vector growth and bounded error audit.
                    let retained_bytes=(512*1024u64).checked_add(payer.lease_heap_bytes())
                        .and_then(|bytes|bytes.checked_add(4*mem::size_of::<WindowsTxfMarkerRow>() as u64))
                        .ok_or_else(||invalid("Windows TxF marker retained RAM overflow"))?;
                    let lease=payer.reserve(retained_bytes)?;
                    result.selected.try_reserve(1).map_err(io::Error::other)?;
                    result.leases.try_reserve(1).map_err(io::Error::other)?;
                    result.leases.push(lease);result.selected.push((index,identity));
                }
            }
            Ok(())
        })();
        if let Err(error)=selection {return Err(result.refuse(error));}
        let (pass,status)=capture(binding,&result.selected,header.ntfs_serial);
        result.audit.before=Some(pass);
        if let Err(error)=status {return Err(result.refuse(error));}
        Ok(result)
    }
    pub(crate) fn finish(mut self,selectors:&impl NativeRequestDomain)->io::Result<VerifiedWindowsTxfMarkers> {
        let selection=(||->io::Result<()>{
            if selectors.header().source_inspection_sha256!=self.audit.source_inspection_sha256 || selectors.header().ntfs_serial!=self.audit.ntfs_serial {return Err(invalid("Windows TxF marker source changed during collection"));}
            let mut count=0;
            for index in 0..selectors.len(){if let Some(id)=selectors.windows_txf_metadata_identity(index)?{
                if self.selected.get(count)!=Some(&(index,id)){return Err(invalid("Windows TxF marker selection changed"));}count+=1;
            }}
            if count!=self.selected.len(){return Err(invalid("Windows TxF marker coverage changed"));}Ok(())
        })();
        if let Err(error)=selection{return Err(self.refuse(error));}
        let (pass,status)=capture(&self.audit.binding,&self.selected,self.audit.ntfs_serial);self.audit.after=Some(pass);
        if let Err(error)=status{return Err(self.refuse(error));}
        let before=self.audit.before.as_ref().unwrap();let after=self.audit.after.as_ref().unwrap();
        let stable=before.rows.len()==after.rows.len()&&before.rows.iter().zip(&after.rows).all(|(a,b)|
            a.identity==b.identity&&same(&a.file_id_before,&b.file_id_before)&&same(&a.standard_before,&b.standard_before)
                &&same(&a.attributes_before,&b.attributes_before)&&same(&a.metadata,&b.metadata)&&same(&a.version,&b.version)
                &&same(&a.resource_manager,&b.resource_manager));
        if !stable {
            return Err(self.refuse(invalid("Windows TxF marker native facts changed across complete collection")));
        }
        Ok(VerifiedWindowsTxfMarkers{audit:self.audit,selected:self.selected,_leases:self.leases})
    }
}
fn same(a:&Option<WindowsTxfQuery>,b:&Option<WindowsTxfQuery>)->bool {match(a,b){(Some(a),Some(b))=>a.succeeded==b.succeeded&&a.native_error==b.native_error&&a.bytes==b.bytes,_=>false}}
fn query(file:&File,code:u32,name:&'static str,capacity:usize)->WindowsTxfQuery {
    let mut bytes=vec![0;capacity];let mut used=0;
    // SAFETY: live read-only metadata handle, bounded initialized output,
    // no input and no overlapped operation. All listed controls are queries.
    let success=unsafe{DeviceIoControl(file.as_raw_handle(),code,ptr::null(),0,bytes.as_mut_ptr().cast(),capacity as u32,&mut used,ptr::null_mut())}!=0;
    let mut error=if success{None}else{Some(io::Error::last_os_error().raw_os_error().unwrap_or(31))};
    let success=success&&(used as usize<=capacity);if used as usize>capacity{error=Some(13);bytes.clear();}else{bytes.truncate(used as usize);}bytes.shrink_to_fit();
    WindowsTxfQuery{operation:name,code_or_class:code,succeeded:success,native_error:error,bytes}
}
fn info(file:&File,class:i32,length:usize,name:&'static str)->WindowsTxfQuery {
    let mut bytes=vec![0;length];
    // SAFETY: exact bounded FILE_*_INFO output and a live no-follow handle.
    let succeeded=unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),class,bytes.as_mut_ptr().cast(),length as u32)}!=0;
    let error=if succeeded{None}else{bytes.clear();Some(io::Error::last_os_error().raw_os_error().unwrap_or(31))};
    WindowsTxfQuery{operation:name,code_or_class:class as u32,succeeded,native_error:error,bytes}
}
fn capture(binding:&GeneralDiskBinding,selected:&[(usize,FileIdentity)],serial:u64)->(WindowsTxfPass,io::Result<()>) {
    let mut pass=WindowsTxfPass{volume_open_error:None,volume_extents:None,ntfs_volume_data:None,rows:Vec::new()};
    let status=(||->io::Result<()>{
        let volume=match OpenOptions::new().read(true).share_mode(7).custom_flags(0x02000000).open(binding.volume_path()?){Ok(v)=>v,Err(e)=>{pass.volume_open_error=e.raw_os_error();return Err(e);}};
        pass.volume_extents=Some(query(&volume,0x560000,"IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",64));
        pass.ntfs_volume_data=Some(query(&volume,0x90064,"FSCTL_GET_NTFS_VOLUME_DATA",128));
        let ext=pass.volume_extents.as_ref().unwrap();let ntfs=pass.ntfs_volume_data.as_ref().unwrap();
        if !ext.succeeded||!ntfs.succeeded||ntfs.bytes.len()<96||u64_at(&ntfs.bytes,0)?!=serial{return Err(invalid("Windows TxF marker volume native route/NTFS serial differs"));}
        binding.validate_volume_extent(&ext.bytes)?;
        for (_,identity) in selected {
            let mut row=WindowsTxfMarkerRow{identity:identity.clone(),open_error:None,file_id_before:None,standard_before:None,attributes_before:None,metadata:None,version:None,resource_manager:None,file_id_after:None,standard_after:None,attributes_after:None};
            let descriptor=FILE_ID_DESCRIPTOR{dwSize:mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,Type:FileIdType,Anonymous:FILE_ID_DESCRIPTOR_0{FileId:identity.reference() as i64}};
            // SAFETY: exact NTFS file reference; READ_DATA is required only by
            // the three official metadata FSCTLs, never consumed as payload.
            let handle=unsafe{OpenFileById(volume.as_raw_handle(),&descriptor,0x81,7,ptr::null(),0x02200000)};
            if handle==INVALID_HANDLE_VALUE||handle.is_null(){let error=io::Error::last_os_error();row.open_error=error.raw_os_error();pass.rows.push(row);return Err(error);}
            // SAFETY: unique ownership of the new native file handle.
            let file=unsafe{File::from_raw_handle(handle)};
            row.file_id_before=Some(info(&file,18,24,"FileIdInfo"));row.standard_before=Some(info(&file,1,24,"FileStandardInfo"));row.attributes_before=Some(info(&file,9,8,"FileAttributeTagInfo"));
            row.metadata=Some(query(&file,GET_METADATA,"FSCTL_TXFS_GET_METADATA_INFO",48));row.version=Some(query(&file,GET_VERSION,"FSCTL_TXFS_GET_TRANSACTED_VERSION",16));row.resource_manager=Some(query(&file,QUERY_RM,"FSCTL_TXFS_QUERY_RM_INFORMATION",MAX_REPLY));
            row.file_id_after=Some(info(&file,18,24,"FileIdInfo"));row.standard_after=Some(info(&file,1,24,"FileStandardInfo"));row.attributes_after=Some(info(&file,9,8,"FileAttributeTagInfo"));
            pass.rows.push(row);validate_row(pass.rows.last().unwrap(),serial)?;
        }
        Ok(())
    })();(pass,status)
}
fn bytes(query:&Option<WindowsTxfQuery>,length:usize)->io::Result<&[u8]> {let q=query.as_ref().ok_or_else(||invalid("missing marker query"))?;if !q.succeeded||q.native_error.is_some()||q.bytes.len()!=length{return Err(invalid(format!("Windows TxF marker query {} failed/changed shape: {:?}",q.operation,q.native_error)));}Ok(&q.bytes)}
fn validate_row(row:&WindowsTxfMarkerRow,serial:u64)->io::Result<()> {
    let id=bytes(&row.file_id_before,24)?;let standard=bytes(&row.standard_before,24)?;let attrs=bytes(&row.attributes_before,8)?;
    if u64_at(id,0)?!=serial||u64_at(id,8)?!=row.identity.reference()||u64_at(id,16)?!=0||standard[20]!=0||u32_at(attrs,0)?&0x400!=0||u32_at(attrs,4)?!=0
        || !same(&row.file_id_before,&row.file_id_after)||!same(&row.standard_before,&row.standard_after)||!same(&row.attributes_before,&row.attributes_after){return Err(invalid("Windows TxF marker native identity/type changed"));}
    let metadata=bytes(&row.metadata,48)?;let version=bytes(&row.version,16)?;
    if metadata[16..32]!=[0;16]||u32_at(metadata,40)?!=0||u32_at(version,0)?!=0xffff_fffe||u32_at(version,4)?!=0||version[8..16]!=[0;8]{return Err(invalid("Windows TxF marker has an active transaction or version/miniversion state"));}
    let rm=row.resource_manager.as_ref().ok_or_else(||invalid("missing exact-file RM query"))?;
    let expected=if row.identity.record_number==5{6801}else{6803};
    if rm.succeeded||rm.native_error!=Some(expected)||!rm.bytes.is_empty(){return Err(invalid("Windows TxF marker is not an exact non-RM file or protected inactive default root"));}
    Ok(())
}
