<# One explicitly selected native reconstruction phase in the owned guest. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$PhaseId,
 [Parameter(Mandatory)][ValidateSet('prepare','apply','resume','rollback','handoff')][string]$Operation,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [string]$TicketSha256,
 [ValidateRange(30,7200)][int]$TimeoutSeconds=3600
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-NRFields($Value,[string[]]$Names){
 if($null-eq$Value-or@($Value.PSObject.Properties).Count-ne$Names.Count){throw 'Reconstruction fields differ.'}
 foreach($n in $Names){if(-not($Value.PSObject.Properties.Name-ccontains$n)){throw ('Missing reconstruction field: '+$n)}}
}
function Assert-NRBool($Value,[bool]$Expected){if($Value-isnot[bool]-or$Value-ne$Expected){throw 'Explicit reconstruction boolean differs.'}}
function Assert-NRNumber($Value,[decimal]$Minimum,[decimal]$Maximum){
 if($null-eq$Value-or$Value-is[string]-or$Value-is[bool]-or$Value-isnot[ValueType]){throw 'Numeric reconstruction field differs.'}
 $n=[decimal]$Value;if($n-lt$Minimum-or$n-gt$Maximum-or$n-ne[decimal]::Truncate($n)){throw 'Reconstruction numeric bound differs.'}
}
function Assert-NRHash($Value){if($Value-isnot[string]-or$Value-cnotmatch '\A[0-9a-f]{64}\z'){throw 'Reconstruction SHA-256 pin differs.'}}
function Assert-NRGuid($Value){if($Value-isnot[string]-or$Value-cnotmatch '\A(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})\z'-or[guid]$Value-eq[guid]::Empty){throw 'Reconstruction GUID differs.'}}
function Assert-NRSame($Expected,$Actual){
 if($null-eq$Expected-or$null-eq$Actual){if($null-ne$Expected-or$null-ne$Actual){throw 'Reconstruction null differs.'};return}
 if($Expected-is[Array]){if($Actual-isnot[Array]-or$Expected.Count-ne$Actual.Count){throw 'Reconstruction array differs.'};for($i=0;$i-lt$Expected.Count;$i++){Assert-NRSame $Expected[$i] $Actual[$i]};return}
 if($Expected-is[pscustomobject]){Assert-NRFields $Actual @($Expected.PSObject.Properties.Name);foreach($n in $Expected.PSObject.Properties.Name){Assert-NRSame $Expected.$n $Actual.$n};return}
 if($Expected-is[string]){if($Actual-isnot[string]-or$Expected-cne$Actual){throw 'Reconstruction string differs.'};return}
 if($Expected-is[bool]){Assert-NRBool $Actual $Expected;return}
 if($Actual-is[string]-or$Actual-is[bool]-or$Expected-ne$Actual){throw 'Reconstruction scalar differs.'}
}
function Assert-NRBytes($Value,[int]$Minimum,[int]$Maximum){
 if($Value-isnot[Array]-or$Value.Count-lt$Minimum-or$Value.Count-gt$Maximum){throw 'Native byte-buffer length differs.'}
 foreach($b in $Value){Assert-NRNumber $b 0 255}
}
function Assert-NRPartition($Identity,[long]$DiskBytes,[long]$PartitionBytes){
 Assert-NRFields $Identity @('disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')
 Assert-NRGuid $Identity.disk_guid;Assert-NRGuid $Identity.partition_guid
 foreach($pair in @(@('partition_number',2),@('disk_bytes',$DiskBytes),@('partition_offset',16MB),@('partition_bytes',$PartitionBytes),@('logical_sector_bytes',512),@('physical_sector_bytes',4096))){Assert-NRNumber $Identity.($pair[0]) $pair[1] $pair[1]}
}
function Assert-NRRequest($Request,[string]$ExpectedId){
 Assert-NRFields $Request @('schema_version','experiment_id','probe','comparison','journal','max_journal_bytes')
 Assert-NRNumber $Request.schema_version 1 1
 if($Request.experiment_id-cne$ExpectedId-or$ExpectedId-cnotmatch '\A[0-9a-f]{32}\z'){throw 'Reconstruction experiment differs.'}
 $p=$Request.probe;Assert-NRFields $p @('schema_version','experiment_id','fixture_evidence_sha256','target','shadow','retained_offset','source_retained_sha256','shadow_retained_sha256');Assert-NRNumber $p.schema_version 1 1
 if($p.experiment_id-cne$ExpectedId){throw 'Probe experiment differs.'}
 foreach($role in @('target','shadow')){$b=$p.$role;Assert-NRFields $b @('disk_number','volume_guid','identity');$number=if($role-ceq'target'){1}else{3};Assert-NRNumber $b.disk_number $number $number;Assert-NRGuid $b.volume_guid;Assert-NRPartition $b.identity 64GB 52GB}
 foreach($h in @($p.fixture_evidence_sha256,$p.source_retained_sha256,$p.shadow_retained_sha256)){Assert-NRHash $h}
 Assert-NRNumber $p.retained_offset 8GB (9GB-65536)
 if($p.retained_offset%4096-ne0-or$p.source_retained_sha256-ceq$p.shadow_retained_sha256){throw 'Retained native range or A/B proof differs.'}
 $c=$Request.comparison;Assert-NRFields $c @('schema_version','sector_size','expected_length','source_sha256','shadow_sha256','retained_ranges','max_change_bytes','max_ranges')
 foreach($pair in @(@('schema_version',1),@('sector_size',4096),@('expected_length',52GB))){Assert-NRNumber $c.($pair[0]) $pair[1] $pair[1]}
 Assert-NRHash $c.source_sha256;Assert-NRHash $c.shadow_sha256;Assert-NRNumber $c.max_change_bytes 0 256MB;Assert-NRNumber $c.max_ranges 1 65536
 if($c.retained_ranges-isnot[Array]-or$c.retained_ranges.Count-ne1){throw 'Exactly one retained range required.'}
 $r=$c.retained_ranges[0];Assert-NRFields $r @('offset','length','source_sha256','shadow_sha256');Assert-NRNumber $r.offset $p.retained_offset $p.retained_offset;Assert-NRNumber $r.length 65536 65536
 if($r.source_sha256-cne$p.source_retained_sha256-or$r.shadow_sha256-cne$p.shadow_retained_sha256){throw 'Comparison retained pins differ.'}
 $j=$Request.journal;Assert-NRFields $j @('disk_number','externally_enrolled_disk_unique_id','volume_guid','identity');Assert-NRNumber $j.disk_number 2 2;Assert-NRGuid $j.volume_guid;Assert-NRPartition $j.identity 8GB (8GB-32MB)
 if($j.externally_enrolled_disk_unique_id-cne'600224806AAC261F021F249596F332FC'){throw 'External journal enrollment differs.'}
 $roles=@($p.target,$p.shadow,$j)
 for($a=0;$a-lt3;$a++){for($b=$a+1;$b-lt3;$b++){if([guid]$roles[$a].volume_guid-eq[guid]$roles[$b].volume_guid-or[guid]$roles[$a].identity.disk_guid-eq[guid]$roles[$b].identity.disk_guid-or[guid]$roles[$a].identity.partition_guid-eq[guid]$roles[$b].identity.partition_guid){throw 'Reconstruction storage identities overlap.'}}}
 Assert-NRNumber $Request.max_journal_bytes 1 768MB
}
function Assert-NRJournalEnrollment($Request,$Disk,$Partition,$Volume){
 $j=$Request.journal
 if($Disk.Number-ne2-or$Disk.UniqueId-cne$j.externally_enrolled_disk_unique_id-or$Disk.Size-ne8GB-or$Disk.PartitionStyle-cne'GPT'-or[guid]$Disk.Guid-ne[guid]$j.identity.disk_guid-or$Disk.LogicalSectorSize-ne512-or$Disk.PhysicalSectorSize-ne4096){throw 'Current J disk enrollment differs.'}
 foreach($n in @('IsBoot','IsSystem','IsOffline','IsReadOnly')){Assert-NRBool $Disk.$n $false}
 if($Partition.DiskNumber-ne2-or$Partition.PartitionNumber-ne2-or$Partition.DriveLetter-cne'J'-or$Partition.Offset-ne16MB-or$Partition.Size-ne(8GB-32MB)-or[guid]$Partition.Guid-ne[guid]$j.identity.partition_guid){throw 'Current J partition enrollment differs.'}
 if($Volume.DriveLetter-cne'J'-or$Volume.FileSystem-cne'NTFS'-or$Volume.FileSystemLabel-cne'ntfs2refs-journal'-or$Volume.AllocationUnitSize-ne4096-or$Volume.UniqueId-isnot[string]-or$Volume.UniqueId-cnotmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'){throw 'Current J filesystem enrollment differs.'}
 if([guid]$Volume.UniqueId.Substring(11,36)-ne[guid]$j.volume_guid){throw 'Current J volume GUID differs.'}
}
function Assert-NRTicket($Ticket,$Request){
 Assert-NRFields $Ticket @('schema_version','binding','immutable_sha256','immutable_length','journal_length');Assert-NRNumber $Ticket.schema_version 1 1
 Assert-NRFields $Ticket.binding @('experiment_id','target_identity_sha256','shadow_identity_sha256','journal_identity_sha256')
 if($Ticket.binding.experiment_id-cne$Request.experiment_id){throw 'Trusted ticket experiment differs.'}
 foreach($h in @($Ticket.immutable_sha256,$Ticket.binding.target_identity_sha256,$Ticket.binding.shadow_identity_sha256,$Ticket.binding.journal_identity_sha256)){Assert-NRHash $h}
 if(@($Ticket.binding.target_identity_sha256,$Ticket.binding.shadow_identity_sha256,$Ticket.binding.journal_identity_sha256|Select-Object -Unique).Count-ne3){throw 'Trusted storage identity hashes overlap.'}
 Assert-NRNumber $Ticket.immutable_length 256 $Request.max_journal_bytes;Assert-NRNumber $Ticket.journal_length 8448 $Request.max_journal_bytes
 if($Ticket.immutable_length+8192-ne$Ticket.journal_length){throw 'Trusted journal length differs.'}
}
function Assert-NROrdinarySnapshot($Value,[long]$Maximum){
 Assert-NRFields $Value @('final_path','volume_serial_number','file_id_128','file_bytes','allocation_bytes','file_attributes','number_of_links')
 if($Value.final_path-isnot[string]-or-not$Value.final_path.StartsWith('\\?\Volume{')-or$Value.final_path.Length-gt4096){throw 'Native ordinary final path differs.'}
 Assert-NRNumber $Value.volume_serial_number 1 ([decimal]'18446744073709551615');Assert-NRBytes $Value.file_id_128 16 16
 if(@($Value.file_id_128|Where-Object{$_-ne0}).Count-eq0){throw 'Empty native file ID.'}
 Assert-NRNumber $Value.file_bytes 0 $Maximum;Assert-NRNumber $Value.allocation_bytes 0 (768MB+4095);Assert-NRNumber $Value.file_attributes 0 ([long]4294967295);Assert-NRNumber $Value.number_of_links 1 1
 if($Value.file_attributes-band0x4e50){throw 'Nonordinary native file flags.'}
}
function Assert-NRPartitionSnapshot($Value,$Expected,[int]$Attributes){
 Assert-NRFields $Value @('binding','disk_attributes','device','length','alignment','layout');Assert-NRSame $Expected $Value.binding;Assert-NRNumber $Value.disk_attributes $Attributes $Attributes
 foreach($spec in @(@('device',12,12),@('length',8,8),@('alignment',28,28),@('layout',48,65536))){Assert-NRBytes $Value.($spec[0]) $spec[1] $spec[2]}
}
function Assert-NRJournalSnapshot($Value,$Expected,[long]$Length){
 Assert-NRFields $Value @('schema_version','identity','disk_number','final_path','file_bytes','allocation_bytes','file_attributes','number_of_links','externally_enrolled_disk_unique_id','external_unique_id_verified','sharing_mode_verified','observations_match_before_after','conversion_qualified','evidence')
 Assert-NRNumber $Value.schema_version 1 1;Assert-NRNumber $Value.disk_number 2 2;Assert-NRNumber $Value.file_bytes $Length $Length
 Assert-NRNumber $Value.number_of_links 1 1;Assert-NRNumber $Value.allocation_bytes 0 (768MB+4095);Assert-NRNumber $Value.file_attributes 0 ([long]4294967295)
 if($Value.file_attributes-band0x4e50-or$Value.final_path-isnot[string]-or-not$Value.final_path.StartsWith('\\?\Volume{')-or$Value.final_path.Length-gt4096){throw 'Journal snapshot file shape differs.'}
 foreach($n in @('external_unique_id_verified','sharing_mode_verified','conversion_qualified')){Assert-NRBool $Value.$n $false};Assert-NRBool $Value.observations_match_before_after $true
 if($Value.externally_enrolled_disk_unique_id-cne$Expected.externally_enrolled_disk_unique_id){throw 'Journal snapshot external enrollment differs.'}
 $i=$Value.identity;Assert-NRFields $i @('volume_serial_number','file_id_128','volume_guid','disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')
 Assert-NRNumber $i.volume_serial_number 1 ([decimal]'18446744073709551615');Assert-NRBytes $i.file_id_128 16 16
 foreach($name in @('volume_guid','disk_guid','partition_guid')){$guid=if($name-ceq'volume_guid'){$Expected.volume_guid}else{$Expected.identity.$name};Assert-NRSame ([guid]$guid).ToByteArray() $i.$name}
 foreach($name in @('partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){Assert-NRNumber $i.$name $Expected.identity.$name $Expected.identity.$name}
 $e=$Value.evidence;Assert-NRFields $e @('file_id_info','file_standard_info','file_attribute_tag_info','volume_extents','disk_device_number','disk_length','disk_alignment','disk_layout')
 foreach($spec in @(@('file_id_info',24,24),@('file_standard_info',24,24),@('file_attribute_tag_info',8,8),@('volume_extents',32,32),@('disk_device_number',12,12),@('disk_length',8,8),@('disk_alignment',28,28),@('disk_layout',48,65536))){Assert-NRBytes $e.($spec[0]) $spec[1] $spec[2]}
}
function Assert-NRResult($Report,$Request,[string]$ExpectedOperation,[string]$ExpectedRequestHash,$Ticket,[string]$ExpectedTicketHash,[string]$ExpectedIntent,[string]$IntentHash,[string]$ExpectedJournal){
 Assert-NRFields $Report @('schema_version','kind','operation','success','phase','error','request_sha256','input_ticket_sha256','request_file','input_ticket_file','journal_path','intent_path','intent_sha256','journal_open_attempted','journal_create_may_have_been_issued','journal_file','native_operation_invoked','native','ticket_write_may_have_been_issued','ticket_persisted','ticket_sha256','ticket_file','artifacts_preserved_on_failure','online_transition_requested','conversion_qualified','boot_qualified')
 Assert-NRNumber $Report.schema_version 1 1
 if($Report.kind-cne'native-reconstruction-cli-result'-or$Report.operation-cne$ExpectedOperation-or$Report.phase-cne'complete-disks-remain-offline'-or$null-ne$Report.error-or$Report.request_sha256-cne$ExpectedRequestHash-or$Report.journal_path-cne$ExpectedJournal-or$Report.intent_path-cne$ExpectedIntent-or$Report.intent_sha256-cne$IntentHash){throw 'CLI completion identity differs.'}
 foreach($n in @('success','journal_open_attempted','native_operation_invoked','artifacts_preserved_on_failure')){Assert-NRBool $Report.$n $true};foreach($n in @('online_transition_requested','conversion_qualified','boot_qualified')){Assert-NRBool $Report.$n $false}
 $prepare=$ExpectedOperation-ceq'prepare';Assert-NRBool $Report.journal_create_may_have_been_issued $prepare;Assert-NRBool $Report.ticket_write_may_have_been_issued $prepare;Assert-NRBool $Report.ticket_persisted $prepare
 Assert-NROrdinarySnapshot $Report.request_file 128KB;Assert-NROrdinarySnapshot $Report.journal_file 768MB
 if($prepare){if($null-ne$Report.input_ticket_sha256-or$null-ne$Report.input_ticket_file-or$Report.ticket_sha256-cne$ExpectedTicketHash){throw 'New ticket evidence differs.'};Assert-NROrdinarySnapshot $Report.ticket_file 64KB}
 else{if($Report.input_ticket_sha256-cne$ExpectedTicketHash-or$null-ne$Report.ticket_sha256-or$null-ne$Report.ticket_file){throw 'Independent input ticket differs.'};Assert-NROrdinarySnapshot $Report.input_ticket_file 64KB}
 Assert-NRTicket $Ticket $Request
 $n=$Report.native;Assert-NRFields $n @('schema_version','kind','operation','request','success','phase','error','observed_binding','target_before','shadow_before','journal_before','target_after','shadow_after','journal_after','plan','preparation','execution','counters','events','payload_write_requests_issued','journal_write_requests_may_have_been_issued','handoff_request_may_have_been_issued','disks_observed_offline_at_end','online_transition_requested','conversion_qualified','boot_qualified')
 Assert-NRNumber $n.schema_version 1 1
 if($n.kind-cne'native-lab-journal-reconstruction'-or$n.operation-cne$ExpectedOperation-or$n.phase-cne'complete-disks-remain-offline'-or$null-ne$n.error){throw 'Native completion identity differs.'}
 Assert-NRSame $Request $n.request;Assert-NRSame $Ticket.binding $n.observed_binding
 foreach($name in @('success','journal_write_requests_may_have_been_issued','disks_observed_offline_at_end')){Assert-NRBool $n.$name $true};foreach($name in @('online_transition_requested','conversion_qualified','boot_qualified')){Assert-NRBool $n.$name $false}
 Assert-NRBool $n.handoff_request_may_have_been_issued ($ExpectedOperation-ceq'handoff')
 foreach($phase in @('before','after')){Assert-NRPartitionSnapshot $n.('target_'+$phase) $Request.probe.target 1;Assert-NRPartitionSnapshot $n.('shadow_'+$phase) $Request.probe.shadow 3}
 $beforeLength=if($prepare){0}else{$Ticket.journal_length};Assert-NRNumber $Report.journal_file.file_bytes $beforeLength $beforeLength;Assert-NRJournalSnapshot $n.journal_before $Request.journal $beforeLength;Assert-NRJournalSnapshot $n.journal_after $Request.journal $Ticket.journal_length
 Assert-NRSame $n.journal_before.identity $n.journal_after.identity
 Assert-NRSame $Report.journal_file.file_id_128 $n.journal_before.identity.file_id_128
 Assert-NRSame $Report.journal_file.volume_serial_number $n.journal_before.identity.volume_serial_number
 $changed=0L;$patches=0L;$writeExpected=0L
 if($prepare){
  if($null-ne$n.plan-or$null-ne$n.execution){throw 'Preparation unexpectedly reports execution.'}
  $p=$n.preparation;Assert-NRFields $p @('ticket','changed_bytes','before_payload_bytes','after_payload_bytes','overhead_bytes','patch_count','expected_postimage_sha256','preparation_durable','conversion_qualified');Assert-NRSame $Ticket $p.ticket
  Assert-NRNumber $p.changed_bytes 0 $Request.comparison.max_change_bytes;Assert-NRNumber $p.patch_count 0 $Request.comparison.max_ranges;Assert-NRNumber $p.before_payload_bytes $p.changed_bytes $p.changed_bytes;Assert-NRNumber $p.after_payload_bytes $p.changed_bytes $p.changed_bytes;Assert-NRNumber $p.overhead_bytes 8448 $Request.max_journal_bytes
  if(2*$p.changed_bytes+$p.overhead_bytes-ne$Ticket.journal_length){throw 'Journal byte accounting differs.'}
  Assert-NRHash $p.expected_postimage_sha256;Assert-NRBool $p.preparation_durable $true;Assert-NRBool $p.conversion_qualified $false
 }else{
  if($null-ne$n.preparation){throw 'Execution unexpectedly prepares a journal.'}
  $p=$n.plan;Assert-NRFields $p @('patch_count','changed_bytes','expected_postimage_sha256','immutable_sha256');Assert-NRNumber $p.patch_count 0 $Request.comparison.max_ranges;Assert-NRNumber $p.changed_bytes 0 $Request.comparison.max_change_bytes;Assert-NRHash $p.expected_postimage_sha256
  if($p.immutable_sha256-cne$Ticket.immutable_sha256){throw 'Inspected journal pin differs.'};$changed=[long]$p.changed_bytes;$patches=[long]$p.patch_count
  $e=$n.execution;Assert-NRFields $e @('operation','target_sha256','target_bytes_written','patches_written','retained_bytes_unchanged','handoff_recorded','conversion_qualified')
  $expectedName=if($ExpectedOperation-ceq'rollback'){'rolled-back-before-handoff'}elseif($ExpectedOperation-ceq'handoff'){'handoff-recorded'}else{'applied-before-handoff'}
  $expectedHash=if($ExpectedOperation-ceq'rollback'){$Request.comparison.source_sha256}else{$p.expected_postimage_sha256}
  if($e.operation-cne$expectedName-or$e.target_sha256-cne$expectedHash){throw 'Native postimage or operation differs.'}
  if($ExpectedOperation-cne'handoff'){$writeExpected=$changed};$patchExpected=if($ExpectedOperation-ceq'handoff'){0}else{$patches}
  Assert-NRNumber $e.target_bytes_written $writeExpected $writeExpected;Assert-NRNumber $e.patches_written $patchExpected $patchExpected;Assert-NRBool $e.retained_bytes_unchanged $true;Assert-NRBool $e.handoff_recorded ($ExpectedOperation-ceq'handoff');Assert-NRBool $e.conversion_qualified $false
 }
 Assert-NRBool $n.payload_write_requests_issued ($writeExpected-gt0)
 $c=$n.counters;Assert-NRFields $c @('target_bytes_read','target_bytes_written','target_write_bytes_requested','shadow_bytes_read','shadow_bytes_written','shadow_write_bytes_requested')
 foreach($name in @('target_bytes_read','shadow_bytes_read')){Assert-NRNumber $c.$name 1 (8*52GB+2GB)};foreach($name in @('target_bytes_written','target_write_bytes_requested')){Assert-NRNumber $c.$name $writeExpected $writeExpected};foreach($name in @('shadow_bytes_written','shadow_write_bytes_requested')){Assert-NRNumber $c.$name 0 0}
 if($n.events-isnot[Array]-or$n.events.Count-lt1-or$n.events.Count-gt128){throw 'Native event budget differs.'}
 foreach($event in $n.events){Assert-NRFields $event @('operation','control_code','input','succeeded','native_error','output');Assert-NRBool $event.succeeded $true;if($null-ne$event.native_error-or$event.operation-isnot[string]-or$event.operation.Length-lt1-or$event.operation.Length-gt128){throw 'Native control evidence differs.'};Assert-NRNumber $event.control_code 0 ([long]4294967295);Assert-NRBytes $event.input 0 64;Assert-NRBytes $event.output 0 65536}
}
function Assert-NROrdinaryPath([string]$Path,[switch]$Directory){
 $full=[IO.Path]::GetFullPath($Path);if($full-cne$Path){throw 'Canonical explicit guest path required.'}
 $current=$full;$first=$true
 while($current){$item=Get-Item -LiteralPath $current -Force;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or($first-and([bool]$item.PSIsContainer-ne[bool]$Directory))-or(-not$first-and-not$item.PSIsContainer)){throw 'Ordinary artifact and ancestors required.'};$parent=[IO.Directory]::GetParent($current);$current=if($parent){$parent.FullName}else{$null};$first=$false}
}
function Open-NRPin([string]$Path,[string]$Hash,[long]$Maximum){
 Assert-NRHash $Hash;Assert-NROrdinaryPath $Path
 $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-lt1-or$stream.Length-gt$Maximum){throw 'Pinned process input exceeds bound.'};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-cne$Hash){throw 'Pinned process input hash differs.'};$stream.Position=0;return $stream}catch{$stream.Dispose();throw}
}
function Read-NRArtifact([string]$Path,[long]$Maximum,[switch]$AllowEmpty){
 Assert-NROrdinaryPath $Path;$s=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($s.Length-gt$Maximum-or(-not$AllowEmpty-and$s.Length-lt1)){throw 'Process artifact exceeds bound.'};$bytes=New-Object byte[] $s.Length;$at=0;while($at-lt$bytes.Length){$n=$s.Read($bytes,$at,$bytes.Length-$at);if($n-le0){throw 'Short process artifact.'};$at+=$n};return ,$bytes}finally{$s.Dispose()}
}
function Get-NRHash([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Convert-NRJson([byte[]]$Bytes){if($Bytes.Length-ge3-and$Bytes[0]-eq239-and$Bytes[1]-eq187-and$Bytes[2]-eq191){throw 'Unexpected JSON BOM.'};(New-Object Text.UTF8Encoding($false,$true)).GetString($Bytes)|ConvertFrom-Json}
function Initialize-N2RProcessCapture {
 # Embedded identically in both pinned wrappers: no extra staged dependency.
 # A fresh managed type is required; never reuse an unpinned preloaded runner.
 if('Ntfs2Refs.BoundedLabProcess'-as[type]){throw 'Fresh PowerShell process required for pinned process capture.'}
 Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
namespace Ntfs2Refs {
 public sealed class BoundedLabProcess : IDisposable {
  const int Limit=65536;
  static readonly object Gate=new object();
  static readonly List<BoundedLabProcess> Active=new List<BoundedLabProcess>();
  readonly Process process=new Process();
  Task stdout,stderr;bool complete,disposed;int overflow;
  public int Id { get { return process.Id; } }
  public int ExitCode { get { if(!complete)throw new InvalidOperationException("Completion is unknown.");return process.ExitCode; } }
  public bool OutputLimitExceeded { get { return Interlocked.CompareExchange(ref overflow,0,0)!=0; } }
  public static int RetainedCount { get { lock(Gate)return Active.Count; } }
  async Task Pump(Stream input,FileStream output) {
   byte[] buffer=new byte[4096];int written=0;
   try {
    while(true){int n=await input.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)break;
     int keep=Math.Min(n,Limit-written);if(keep>0){await output.WriteAsync(buffer,0,keep).ConfigureAwait(false);written+=keep;}
     if(keep<n)Interlocked.Exchange(ref overflow,1);
    }
   } finally { try { output.Flush(true); } finally { output.Dispose(); } }
  }
  public static BoundedLabProcess Start(string executable,string arguments,string directory,string stdoutPath,string stderrPath) {
   if(!Path.IsPathRooted(executable)||!Path.IsPathRooted(directory)||!Path.IsPathRooted(stdoutPath)||!Path.IsPathRooted(stderrPath)||
      String.Equals(Path.GetFullPath(stdoutPath),Path.GetFullPath(stderrPath),StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Absolute distinct process/capture paths required.");
   BoundedLabProcess capture=new BoundedLabProcess();FileStream output=null,error=null;bool started=false;
   try {
    output=new FileStream(stdoutPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,true);
    error=new FileStream(stderrPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,true);
    ProcessStartInfo info=capture.process.StartInfo;info.FileName=executable;info.Arguments=arguments;info.WorkingDirectory=directory;
    info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.RedirectStandardInput=true;
    if(!capture.process.Start())throw new IOException("Managed child start returned false.");started=true;
    // Process.Start owns the native process handle; force its retained access now.
    lock(Gate)Active.Add(capture);
    IntPtr handle=capture.process.Handle;if(handle==IntPtr.Zero)throw new IOException("Started process handle absent.");
    capture.stdout=capture.Pump(capture.process.StandardOutput.BaseStream,output);output=null;
    capture.stderr=capture.Pump(capture.process.StandardError.BaseStream,error);error=null;
    capture.process.StandardInput.Close();
    return capture;
   } catch {
    // After Start, retain the process and any active pumps even if setup failed.
    // There is deliberately no Kill, timed-out Dispose or output-file deletion.
    if(!started){capture.process.Dispose();if(output!=null)output.Dispose();if(error!=null)error.Dispose();}
    throw;
   }
  }
  public bool WaitForExit(int milliseconds) {
   if(disposed)throw new ObjectDisposedException("BoundedLabProcess");
   if(milliseconds<1||milliseconds>7200000)throw new ArgumentOutOfRangeException("milliseconds");
   if(complete)return true;Stopwatch watch=Stopwatch.StartNew();
   if(!process.WaitForExit(milliseconds))return false;
   int left=(int)Math.Max(0,milliseconds-watch.ElapsedMilliseconds);
   if(stdout==null||stderr==null||!Task.WaitAll(new Task[]{stdout,stderr},left))return false;
   complete=true;return true;
  }
  public void Dispose() {
   if(disposed)return;if(!complete)throw new InvalidOperationException("Unknown child/capture completion must be preserved.");
   process.Dispose();disposed=true;lock(Gate)Active.Remove(this);
  }
 }
}
'@
}
function Complete-NRProcess($Process,$Record,[int]$Seconds){
 if($Seconds-lt30-or$Seconds-gt7200){throw 'Process deadline outside bound.'}
 if(-not$Process.WaitForExit($Seconds*1000)){throw 'Native reconstruction deadline exceeded; preserve process and branch.'}
 $Record.completionKnown=$true;$Record.exitCode=$Process.ExitCode
 if($null-eq$Record.exitCode-or$Record.exitCode-isnot[int]){throw 'Native process exit code is not determinate.'}
 if($Process.OutputLimitExceeded){throw 'Native process output exceeded the 64 KiB capture bound; preserved prefixes are incomplete.'}
}
function Write-NRRecord([string]$Path,$Value){
 $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($Value|ConvertTo-Json -Depth 12));if($bytes.Length-gt64KB){throw 'Process record exceeds bound.'}
 $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
if(-not$PSCmdlet.ShouldProcess('exact enrolled offline target, read-only shadow and external J journal',('Run one pinned '+$Operation+' phase; never online, kill or advance phases'))){return}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Exact owned guest required.'}
if($Operation-ceq'prepare'){if($TicketSha256){throw 'Prepare does not accept an existing ticket pin.'}}else{Assert-NRHash $TicketSha256}
$runRoot='C:\ntfs2refs\native-reconstruct\'+$RunId;$root=$runRoot+'\'+$PhaseId
Assert-NROrdinaryPath $root -Directory
if(@(Get-ChildItem -LiteralPath $root -Force).Count-ne2){throw 'Exactly the pinned binary and request must be staged.'}
$binary=$root+'\lab-native-reconstruct.exe';$requestPath=$root+'\request.json';$ticketPath=$runRoot+'\ticket.json';$outputPath=$root+'\result.json';$intentPath=$root+'\result.intent.json';$journalPath='J:\ntfs2refs-shadow\'+$RunId+'\reconstruction.journal'
$arguments=@($Operation,'--request',$requestPath,'--request-sha256',$RequestSha256,'--journal',$journalPath,'--ticket',$ticketPath,'--output',$outputPath)
if($Operation-cne'prepare'){$arguments+=@('--ticket-sha256',$TicketSha256)}
$record=[ordered]@{schemaVersion=1;kind='native-reconstruction-process';runId=$RunId;phaseId=$PhaseId;operation=$Operation;requestSha256=$RequestSha256;binarySha256=$BinarySha256;independentTicketSha256=$TicketSha256;arguments=$arguments;timeoutSeconds=$TimeoutSeconds;createdUtc=[DateTime]::UtcNow.ToString('o');processId=$null;completionKnown=$false;exitCode=$null;launchAttempted=$false;status='preflight';nativeResultVerified=$false;artifacts=@();ticketSha256=$null;onlineTransitionRequested=$false;conversionQualified=$false;statePreservationRequired=$true}
$binaryPin=$null;$requestPin=$null;$ticketPin=$null;$process=$null;$intentWritten=$false
try{
 $binaryPin=Open-NRPin $binary $BinarySha256 16MB;$requestPin=Open-NRPin $requestPath $RequestSha256 128KB
 $request=Convert-NRJson (Read-NRArtifact $requestPath 128KB);Assert-NRRequest $request $RunId
 if($Operation-ceq'prepare'){if(Test-Path -LiteralPath $ticketPath){throw 'New trusted ticket already exists.'};if(Test-Path -LiteralPath $journalPath){throw 'New reconstruction journal already exists.'};Assert-NROrdinaryPath ([IO.Path]::GetDirectoryName($journalPath)) -Directory}
 else{$ticketPin=Open-NRPin $ticketPath $TicketSha256 64KB;$ticket=Convert-NRJson (Read-NRArtifact $ticketPath 64KB);Assert-NRTicket $ticket $request;Assert-NROrdinaryPath $journalPath}
 Assert-NROrdinaryPath ('J:\ntfs2refs-shadow\'+$RunId+'\shadow.vhdx')
 $jd=Get-Disk -Number 2;$jp=@(Get-Partition -DriveLetter J);$jv=@(Get-Volume -DriveLetter J)
 if($jp.Count-ne1-or$jv.Count-ne1){throw 'Exactly one J partition and volume required.'};Assert-NRJournalEnrollment $request $jd $jp[0] $jv[0]
 $record.status='launch-intent';Write-NRRecord ($root+'\process-intent.json') $record;$intentWritten=$true
 Initialize-N2RProcessCapture;$record.launchAttempted=$true
 $process=[Ntfs2Refs.BoundedLabProcess]::Start($binary,($arguments-join' '),$root,($root+'\reconstruct.stdout'),($root+'\reconstruct.stderr'))
 $record.processId=$process.Id;Write-NRRecord ($root+'\process-started.json') $record
 Complete-NRProcess $process $record $TimeoutSeconds
 $loaded=@{}
 foreach($spec in @(@('reconstruct.stdout',64KB,$true),@('reconstruct.stderr',64KB,$true),@('result.intent.json',256KB,$false),@('result.json',16MB,$false))){
  $path=$root+'\'+$spec[0];if(Test-Path -LiteralPath $path){$bytes=Read-NRArtifact $path $spec[1] -AllowEmpty:([bool]$spec[2]);$record.artifacts+=,[pscustomobject]@{name=$spec[0];length=$bytes.Length;sha256=(Get-NRHash $bytes)};if($spec[0]-like'*.json'){$loaded[$spec[0]]=Convert-NRJson $bytes}}
 }
 if($record.exitCode-ne0){throw ('Native reconstruction exited '+$record.exitCode+'; preserve all branch evidence.')}
 if(-not$loaded.ContainsKey('result.json')-or-not$loaded.ContainsKey('result.intent.json')-or$record.artifacts.Count-ne4){throw 'Native completion artifacts incomplete.'}
 $cli=$loaded['result.json'];$intent=$loaded['result.intent.json'];$intentHash=($record.artifacts|Where-Object name -CEQ 'result.intent.json').sha256
 Assert-NRFields $intent @('schema_version','kind','operation','request_sha256','request','request_file','ticket_path','independent_ticket_sha256','journal_path','phase','may_modify_journal_after_this_intent','may_issue_target_payload_writes_after_this_intent','online_transition_allowed','conversion_qualified','boot_qualified')
 if($intent.kind-cne'native-reconstruction-intent'-or$intent.operation-cne$Operation-or$intent.request_sha256-cne$RequestSha256-or$intent.ticket_path-cne$ticketPath-or$intent.journal_path-cne$journalPath-or$intent.phase-cne'before-journal-open'){throw 'Native durable intent differs.'};Assert-NRNumber $intent.schema_version 1 1;Assert-NRSame $request $intent.request;Assert-NRSame $cli.request_file $intent.request_file
 Assert-NRBool $intent.may_modify_journal_after_this_intent $true;Assert-NRBool $intent.may_issue_target_payload_writes_after_this_intent ($Operation-cin@('apply','resume','rollback'));foreach($name in @('online_transition_allowed','conversion_qualified','boot_qualified')){Assert-NRBool $intent.$name $false}
 if($Operation-ceq'prepare'){
  if($null-ne$intent.independent_ticket_sha256){throw 'Prepare intent has unexpected ticket pin.'};Assert-NRHash $cli.ticket_sha256
  $ticketPin=Open-NRPin $ticketPath $cli.ticket_sha256 64KB;$ticketBytes=Read-NRArtifact $ticketPath 64KB;$ticket=Convert-NRJson $ticketBytes;$record.ticketSha256=$cli.ticket_sha256
 }else{if($intent.independent_ticket_sha256-cne$TicketSha256){throw 'Intent ticket pin differs.'};$record.ticketSha256=$TicketSha256}
 Assert-NRResult $cli $request $Operation $RequestSha256 $ticket $record.ticketSha256 $intentPath $intentHash $journalPath
 $record.nativeResultVerified=$true;$record.status='native-reconstruction-phase-verified-disks-offline'
}catch{$record.status='failed-preserved';$record['error']=$_.Exception.ToString()}
finally{
 if($ticketPin){$ticketPin.Dispose()};if($requestPin){$requestPin.Dispose()};if($binaryPin){$binaryPin.Dispose()};if($process-and$record.completionKnown){$process.Dispose()}
 $record['processIntentPersisted']=$intentWritten;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-NRRecord ($root+'\process-result.json') $record
}
[pscustomobject]@{Status=$record.status;RunId=$RunId;PhaseId=$PhaseId;Operation=$Operation;EvidenceDirectory=$root;OperationCompletionKnown=$record.completionKnown;NativeResultVerified=$record.nativeResultVerified;TicketSha256=$record.ticketSha256;StatePreservationRequired=$true;ConversionQualified=$false}
