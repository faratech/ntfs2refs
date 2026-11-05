//! NEW cold closed-J terminal owner. No preboot Windows owner is reconstructed.
use super::*;
use crate::native::{HeldPagedWritePolicy,PagedRecoveryPins,PartitionSnapshot,ProtectedReadonlyRefsAccess,ReadonlyRefsScope,
 partition_restoration::{PartitionRestorationObserver,terminal_volume_info,find_terminal_volume,restore_terminal_mounts,preflight_mounts},recovery_boot::{RecoveryBootGuard,RecoveryBootRestorationReceipt}};
use crate::{general_layout::{GeneralDiskBinding,GeneralSourceShadowBinding},volume_label::VolumeLabel};
use std::cell::RefCell;
use serde_json::Value;
const RO:u64=0x1000_0000_0000_0000;
fn sha(bytes:&[u8])->[u8;32]{Sha256::digest(bytes).into()}
fn vbytes(v:&Value)->io::Result<Vec<u8>>{serde_json::from_value(v.clone()).map_err(io::Error::other)}
fn digest(v:&Value)->io::Result<[u8;32]>{hex::decode(v.as_str().ok_or_else(||invalid("SHA string absent"))?).map_err(io::Error::other)?.try_into().map_err(|_|invalid("SHA width differs"))}
fn checkpoint_terminal(observer:&mut impl PartitionRestorationObserver,phase:&'static str,e:&mut Vec<NativeEvent>)->io::Result<()>{observer.checkpoint_native_events(phase,e)?;require(e.is_empty(),"terminal durable sink did not drain")}
fn read_control(file:&mut File,expected:[u8;32],maximum:u64,j:&crate::journal_file::GeneralJournalStorageBinding,serial:u64)->io::Result<(Value,crate::reference_file::ReferenceFileSnapshot)>{
 crate::file_storage::require_readonly_access(file)?;let s=crate::reference_file::observe_reference_file_handle_with_limit(file,maximum)?;
 require(s.file_bytes>0&&s.number_of_links==1&&s.volume_serial_number==serial&&s.final_path.starts_with(&(j.disk.volume_path()?+"\\")),"terminal held control is not actual ordinary native J metadata")?;
 require(crate::sha256_native::hash_range(file,0,s.file_bytes)?==expected,"terminal control hash differs")?;
 file.seek(SeekFrom::Start(0))?;let mut b=vec![0;s.file_bytes as usize];file.read_exact(&mut b)?;
 require(sha(&b)==expected&&crate::reference_file::observe_reference_file_handle_with_limit(file,maximum)?==s,"held terminal control changed")?;
 Ok((serde_json::from_slice(&b).map_err(io::Error::other)?,s))
}
fn crc(bytes:&[u8])->u32{let mut c=!0u32;for b in bytes{c^=u32::from(*b);for _ in 0..8{c=(c>>1)^(0xedb88320&0u32.wrapping_sub(c&1))}}!c}
fn original_gpt(mut g:super::super::PartitionGptObservation,original:&[u8])->io::Result<super::super::PartitionGptObservation>{
 let at=(g.target_slot as usize-1).checked_mul(g.entry_bytes as usize).ok_or_else(||invalid("target GPT slot overflow"))?;
 require(at+g.entry_bytes as usize<=g.entries.len(),"target GPT slot outside array")?;
 g.entries[at+48..at+56].copy_from_slice(&original[64..72]);
 let guid=&original[48..64];let mut found=0;
 for row in g.native_layout[48..].chunks_exact_mut(144){if &row[48..64]==guid{row.copy_from_slice(original);found+=1}}
 require(found==1,"original native target is not unique")?;g.target_attributes=layout::u64_at(original,64)?;
 for h in [&mut g.primary_header,&mut g.backup_header]{h[88..92].copy_from_slice(&crc(&g.entries).to_le_bytes());h[16..20].fill(0);let n=layout::u32_at(h,12)?as usize;let c=crc(&h[..n]);h[16..20].copy_from_slice(&c.to_le_bytes());}
 Ok(g)
}
#[derive(Serialize)]
pub struct OfflinePreparedTerminalReceipt {pub kind:OfflineTerminalKind,pub binding:PartitionSourceBinding,
 pub native_before_writable_verified:bool,pub original_attributes_name_type_restored:bool,pub label_restored:bool,pub mounts_restored:bool,
 pub raw_replay_performed:bool,pub boot:RecoveryBootRestorationReceipt}
pub struct OfflinePreparedTerminalGuard<'j,'p>{
 source:RefCell<Option<OfflinePreparedAvailableSource>>,boot:RefCell<Option<RecoveryBootGuard>>,policy:&'j HeldPagedWritePolicy,
 journal:RefCell<&'j mut File>,pins:PagedRecoveryPins<'p>,budget:PartitionObservationBudget,token:OfflineSourceOwnerToken,
 binding:PartitionSourceBinding,mounted_binding:GeneralDiskBinding,mounted:Option<File>,basis:OfflineSourceState,original_info:Vec<u8>,
 expected_original_gpt:super::super::PartitionGptObservation,original_mbr:Vec<u8>,label:VolumeLabel,mounts:Vec<String>,kind:OfflineTerminalKind,
 _outer:File,_publication:File,_intent:File,
}
impl<'j,'p> OfflinePreparedTerminalGuard<'j,'p>{
 #[allow(clippy::too_many_arguments)]
 pub fn open(mut source:OfflinePreparedAvailableSource,mut boot:RecoveryBootGuard,policy:&'j HeldPagedWritePolicy,journal:&'j mut File,
 pins:PagedRecoveryPins<'p>,mut outer:File,mut publication:File,mut intent:File,budget:PartitionObservationBudget,
 observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>)->io::Result<Self>{
 budget.validate()?;checkpoint_terminal(observer,"offline-terminal-closed-opening",events)?;
 source.revalidate_closed(policy,journal,&pins,events)?;boot.require_current_boot(&source.owner_token(),events)?;
 let basis=source.state(events)?;let token=source.owner_token();let binding=source.binding().clone();let kind=source.terminal_kind();
 let (envelope,_)=read_control(&mut outer,boot.facts().prepared_bundle_sha256,budget.ram_bytes/256,pins.journal_binding,pins.journal_identity.volume_serial_number)?;
 require(envelope["core"]["source"]==serde_json::to_value(&binding.storage).map_err(io::Error::other)?,"terminal outer source differs")?;
 let (publication_value,_)=read_control(&mut publication,digest(&envelope["core"]["publication_sha256"])?,budget.ram_bytes/256,pins.journal_binding,pins.journal_identity.volume_serial_number)?;
 let scope=&publication_value["source_scope"];let pin=&scope["complete_preparation_guard"];
 require(scope["kind"]=="partition-ro-physical-v3"&&pin["version"]==2&&pin["observed_stage"]=="ReadonlyPhysicalLocked"
  &&publication_value["source"]==envelope["core"]["source"]&&*pin==envelope["core"]["source_preparation"],"terminal is not authenticated cold physical preparation scope")?;
 // The recorded JSON is metadata only; never deserialize a real native
 // observation/capability. Compare it against the independently queried handle.
 let recorded=&pin["intent_file"];
 let recorded_id=vbytes(&recorded["file_id_128"])?;
 let recorded_path=recorded["final_path"].as_str().ok_or_else(||invalid("recorded intent final path absent"))?;
 let recorded_allocation=recorded["allocation_bytes"].as_u64().ok_or_else(||invalid("recorded intent allocation absent"))?;
 let actual=crate::reference_file::observe_reference_file_handle_with_limit(&intent,16*1024*1024)?;
 require(actual.file_id_128.as_slice()==recorded_id.as_slice()
  &&Some(actual.volume_serial_number)==recorded["volume_serial_number"].as_u64()
  &&Some(actual.file_bytes)==recorded["file_bytes"].as_u64()
  &&actual.final_path.eq_ignore_ascii_case(recorded_path)
  &&Some(u64::from(actual.file_attributes))==recorded["file_attributes"].as_u64()
  &&actual.number_of_links==1&&recorded["number_of_links"].as_u64()==Some(1)
  &&actual.allocation_bytes>=actual.file_bytes&&actual.allocation_bytes<=recorded_allocation
  &&crate::sha256_native::hash_range(&mut intent,0,actual.file_bytes)?==digest(&pin["intent_prefix_sha256"])?,"terminal same held original intent differs")?;
 intent.seek(SeekFrom::Start(0))?;let mut consumed=0;let mut sequence=0;let mut latest=None;
 while consumed<actual.file_bytes{let mut h=[0u8;40];intent.read_exact(&mut h)?;let n=u64::from_le_bytes(h[..8].try_into().map_err(io::Error::other)?);
  require(n>0&&n<=4*1024*1024&&n.checked_mul(32).is_some_and(|v|v<=budget.ram_bytes/2)&&consumed+40+n<=actual.file_bytes,"terminal original frame exceeds budget")?;
  let mut bytes=vec![0;n as usize];intent.read_exact(&mut bytes)?;require(sha(&bytes)==h[8..40],"terminal intent frame hash differs")?;
  let frame:Value=serde_json::from_slice(&bytes).map_err(io::Error::other)?;sequence+=1;
  require(sequence<=2&&frame["sequence"].as_u64()==Some(sequence)&&frame["binding"]==pin["binding"],"terminal original frame lineage differs")?;latest=Some(frame);consumed+=40+n;
 }
 let frame=latest.ok_or_else(||invalid("terminal original intent empty"))?;
 require(sequence==2&&frame["kind"]=="partition-readonly-physical-pre-AP-intent-v2"&&!frame["source_AP_issued"].as_bool().unwrap_or(true),"terminal original protected frame not valid")?;
 let original_info=vbytes(&frame["original_partition_info"])?;require(original_info==vbytes(&pin["original_partition_info"])?&&original_info.len()==144
  &&original_info[32..48]==layout::guid_bytes(BASIC)?&&layout::u64_at(&original_info,64)?==0,"terminal original native Basic0 differs")?;
 let mut protected=original_info.clone();protected[64..72].copy_from_slice(&RO.to_le_bytes());require(vbytes(&frame["desired_partition_info"])?==protected,"terminal source protection epoch differs")?;
 let expected_original_gpt=original_gpt(basis.actual.gpt.clone(),&original_info)?;
 require(serde_json::to_value(&expected_original_gpt).map_err(io::Error::other)?==frame["original_gpt"],"terminal complete original GPT/siblings differ")?;
 let original_mbr=vbytes(&frame["original_mbr"])?;
 require(original_mbr.len()==512&&sha(&original_mbr)==digest(&pin["original_mbr_sha256"])?,"terminal original MBR pin differs")?;
 let mut physical=device_file(&format!(r"\\.\PhysicalDrive{}",binding.storage.disk_number),false,false)?;let mut mbr=[0u8;512];physical.read_exact(&mut mbr)?;
 require(mbr.as_slice()==original_mbr.as_slice(),"terminal current protective MBR differs")?;
 let label:VolumeLabel=serde_json::from_value(publication_value["expected_source_label"].clone()).map_err(io::Error::other)?;label.validate()?;
 let mounts:Vec<String>=serde_json::from_value(publication_value["expected_mount_paths"].clone()).map_err(io::Error::other)?;
 let mut mounted=None;for attempt in 0..60{match find_terminal_volume(&binding,&protected,budget,observer,events){Ok(v)=>{mounted=Some(v);break},Err(e)if e.kind()==io::ErrorKind::NotFound&&attempt<59=>std::thread::sleep(std::time::Duration::from_millis(250)),Err(e)=>return Err(e)}}
 let (mounted_binding,volume)=mounted.ok_or_else(||invalid("terminal readonly volume publication absent"))?;
 let value=Self{source:RefCell::new(Some(source)),boot:RefCell::new(Some(boot)),policy,journal:RefCell::new(journal),pins,budget,token,binding,mounted_binding,
  mounted:Some(volume),basis,original_info,expected_original_gpt,original_mbr,label,mounts,kind,_outer:outer,_publication:publication,_intent:intent};
 value.require_readonly(events)?;checkpoint_terminal(observer,"offline-terminal-actual-readonly-mounted",events)?;Ok(value)
 }
 fn require_readonly(&self,events:&mut Vec<NativeEvent>)->io::Result<()>{
  let mut source=self.source.try_borrow_mut().map_err(|_|invalid("terminal source borrowed"))?;
  let actual=source.as_mut().ok_or_else(||invalid("terminal source consumed"))?.state(events)?;
  require(actual.actual==self.basis.actual,"terminal complete readonly source native baseline changed")?;
  let volume=self.mounted.as_ref().ok_or_else(||invalid("terminal mount closed"))?;
  let info=control(volume,"offline-terminal-readonly-native144",0x00070048,&[],144,events)?;
  let mut ro=self.original_info.clone();ro[64..72].copy_from_slice(&RO.to_le_bytes());require(info==ro,"terminal readonly native target differs")?;
  let at=events.len();let tested=control(volume,"offline-terminal-IS_WRITABLE-must19",0x00070024,&[],0,events);
  require(tested.is_err()&&events.get(at).is_some_and(|e|!e.succeeded&&e.native_error==Some(19)),"terminal partition does not enforce actual readonly19")?;
  let f=terminal_volume_info(volume)?;require(f.flags&0x80000!=0&&f.filesystem==if self.kind==OfflineTerminalKind::Handoff{"ReFS"}else{"NTFS"},"terminal actual readonly filesystem differs")?;
  let closed=source.as_mut().unwrap().state(events)?;require(closed.actual==self.basis.actual,"terminal readonly closing native source changed")
 }
 pub fn readonly_volume(&self)->OfflineTerminalReadonlyVolume<'_, 'j, 'p>{OfflineTerminalReadonlyVolume{guard:self}}
 pub fn original_label(&self)->&VolumeLabel{&self.label}
 pub fn kind(&self)->OfflineTerminalKind{self.kind}
 pub fn observe_aborted(&self,events:&mut Vec<NativeEvent>)->io::Result<OfflineAbortedReadonlyProof>{
  require(self.kind==OfflineTerminalKind::Aborted,"actual closed ABT required")?;self.require_readonly(events)?;
  let mut source=self.source.borrow_mut();source.as_mut().unwrap().revalidate_closed(self.policy,&mut self.journal.borrow_mut(),&self.pins,events)?;
  require(terminal_volume_info(self.mounted.as_ref().unwrap())?.label==self.label,"restored readonly NTFS label differs")?;
  Ok(OfflineAbortedReadonlyProof{owner:self.token.clone()})
 }
 pub fn finish_handoff(self,proof:crate::shadow_native::OfflineReadonlyFidelity,output:&Path,observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>)->io::Result<OfflinePreparedTerminalReceipt>{
  require(self.kind==OfflineTerminalKind::Handoff,"actual HND required")?;proof.require_owner(&self.token,&self.mounted_binding)?;self.finish(output,observer,events)
 }
 pub fn finish_aborted(self,proof:OfflineAbortedReadonlyProof,output:&Path,observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>)->io::Result<OfflinePreparedTerminalReceipt>{
  require(self.kind==OfflineTerminalKind::Aborted&&proof.owner.same_owner(&self.token),"actual ABT readonly proof differs")?;self.finish(output,observer,events)
 }
 fn finish(mut self,output:&Path,observer:&mut impl PartitionRestorationObserver,events:&mut Vec<NativeEvent>)->io::Result<OfflinePreparedTerminalReceipt>{
  self.require_readonly(events)?;let mut source=self.source.get_mut().take().ok_or_else(||invalid("terminal source consumed"))?;
  let boot=self.boot.get_mut().take().ok_or_else(||invalid("terminal boot consumed"))?;
  source.revalidate_closed(self.policy,&mut self.journal.borrow_mut(),&self.pins,events)?;
  let desired=self.original_info.clone();let mut protected=desired.clone();protected[64..72].copy_from_slice(&RO.to_le_bytes());
  preflight_mounts(&self.mounts,&self.mounted_binding,&protected)?;
  checkpoint_terminal(observer,"offline-terminal-original-mounts-preflight-before-boot-or-writable",events)?;
  observer.before_partition_change(if self.kind==OfflineTerminalKind::Handoff{crate::PartitionTerminalKind::Handoff}else{crate::PartitionTerminalKind::Aborted},&protected,&desired)?;
  drop(self.mounted.take());
  let (source,boot_receipt)=boot.restore_normal_boot(source,self.policy,&mut self.journal.borrow_mut(),&self.pins,output,observer,events)?;
  // A closed source and actual readonly native proof precede normal selection.
  // Consume every old source/checker owner BEFORE the first writable FSD epoch.
  let before=source.offline_environment_facts().source_physical.clone();
  let mut disk=device_file(&format!("\\\\.\\PhysicalDrive{}",self.binding.storage.disk_number),false,false)?;
  require(source_facts(&mut disk,&self.binding,self.budget,events)?==self.basis.actual,"terminal held physical source changed before metadata transfer")?;
  let route=format!(r"\\?\GLOBALROOT\Device\Harddisk{}\Partition{}",self.binding.storage.disk_number,self.binding.storage.identity.partition_number);
  let management=OpenOptions::new().read(true).write(true).share_mode(3).open(route)?;
  require(control(&management,"offline-terminal-before-typed-SET-native144",0x00070048,&[],144,events)?==protected,"terminal setter handle differs")?;
  drop(source);
  let mut input=[0u8;120];input[..4].copy_from_slice(&1u32.to_le_bytes());input[8..].copy_from_slice(&desired[32..]);
  let reply=crate::native::control_set_gpt_partition(&management,"offline-terminal-single-target-original-Basic0",&input,events)?;require(reply.is_empty(),"terminal typed setter returned unexpected output")?;
  require(control(&management,"offline-terminal-original-native144-readback",0x00070048,&[],144,events)?==desired,"terminal typed setter readback differs")?;drop(management);
  let after=source_facts(&mut disk,&self.binding,self.budget,events)?;disk.seek(SeekFrom::Start(0))?;let mut mbr=[0u8;512];disk.read_exact(&mut mbr)?;require(mbr.as_slice()==self.original_mbr.as_slice(),"terminal protective MBR changed")?;
  require(after.device==before.device&&after.length==before.length&&after.alignment==before.alignment&&after.disk_attributes==0&&after.gpt==self.expected_original_gpt,"terminal original full GPT/siblings/C metadata differs")?;
  checkpoint_terminal(observer,"offline-terminal-original-Basic0-complete-before-filesystem",events)?;
  let (mounted_binding,volume)=find_terminal_volume(&self.binding,&desired,self.budget,observer,events)?;
  let filesystem=if self.kind==OfflineTerminalKind::Handoff{"ReFS"}else{"NTFS"};let info=terminal_volume_info(&volume)?;
  require(info.filesystem==filesystem&&info.flags&0x80000==0,"native writable target is not the verified filesystem")?;
  if info.label!=self.label{let root=format!("{}\\",mounted_binding.volume_path()?);let w:Vec<_>=root.encode_utf16().chain([0]).collect();let label=self.label.terminated()?;
   if unsafe{windows_sys::Win32::Storage::FileSystem::SetVolumeLabelW(w.as_ptr(),label.as_ptr())}==0{return Err(io::Error::last_os_error())}}
  require(terminal_volume_info(&volume)?.label==self.label,"terminal native label restoration differs")?;
  restore_terminal_mounts(&self.mounts,&mounted_binding,&desired)?;checkpoint_terminal(observer,"offline-terminal-writable-label-mounts-complete",events)?;
  Ok(OfflinePreparedTerminalReceipt{kind:self.kind,binding:PartitionSourceBinding{storage:mounted_binding},native_before_writable_verified:true,original_attributes_name_type_restored:true,label_restored:true,mounts_restored:true,raw_replay_performed:false,boot:boot_receipt})
 }
}
pub struct OfflineAbortedReadonlyProof{owner:OfflineSourceOwnerToken}
pub struct OfflineTerminalReadonlyVolume<'g,'j,'p>{guard:&'g OfflinePreparedTerminalGuard<'j,'p>}
impl OfflineTerminalReadonlyVolume<'_, '_, '_>{
 pub fn binding(&self)->&GeneralDiskBinding{&self.guard.mounted_binding}
 pub fn owner_token(&self)->OfflineSourceOwnerToken{self.guard.token.clone()}
 pub fn label(&self)->io::Result<VolumeLabel>{Ok(terminal_volume_info(self.guard.mounted.as_ref().unwrap())?.label)}
 pub fn require_readonly(&self,events:&mut Vec<NativeEvent>)->io::Result<()>{self.guard.require_readonly(events)}
 pub fn observe_converted_metadata_with_memory(&self,pair:GeneralSourceShadowBinding,input:&impl crate::shadow_native::input_domain::InputDomain,
 same:impl Fn(&[u8],&[u8])->io::Result<bool>,profile:crate::attestation::ResourceProfile,memory:&dyn crate::shadow_native::report_memory::ReportMemoryAccountant,
 events:&mut Vec<NativeEvent>)->io::Result<crate::shadow_native::OfflineReadonlyFidelity>{
  self.require_readonly(events)?;let checked=crate::shadow_native::observe_offline_converted_readonly(self,pair,input,same,profile,memory);
  let closed=self.require_readonly(events);match(checked,closed){(Ok(v),Ok(()))=>Ok(v),(Err(e),_)|(_,Err(e))=>Err(e)}
 }
}
impl ProtectedReadonlyRefsAccess for OfflineTerminalReadonlyVolume<'_, '_, '_>{
 fn binding(&self)->&GeneralDiskBinding{self.binding()}
 fn volume(&self)->&File{self.guard.mounted.as_ref().unwrap()}
 fn scope(&self)->ReadonlyRefsScope{ReadonlyRefsScope::SelectedPartition}
 fn snapshot(&self,binding:&crate::layout::DiskBinding,events:&mut Vec<NativeEvent>)->io::Result<PartitionSnapshot>{
  require(binding.disk_number==self.binding().disk_number&&binding.identity==self.binding().identity&&binding.volume_guid==self.binding().volume_guid,"offline native snapshot binding differs")?;
  self.guard.require_readonly(events)?;
  Ok(PartitionSnapshot{binding:binding.clone(),disk_attributes:self.guard.basis.actual.disk_attributes,device:self.guard.basis.actual.device.clone(),length:self.guard.basis.actual.length.clone(),alignment:self.guard.basis.actual.alignment.clone(),layout:self.guard.basis.actual.gpt.native_layout.clone()})
 }
}
