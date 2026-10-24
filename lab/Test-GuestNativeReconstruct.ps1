<# Pure schema/enrollment/process mocks and WhatIf. No device, VM or file writes. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$failed=$false;try{&$Body|Out-Null}catch{$failed=$true};Check $failed $Name}
function Clone($Value){$Value|ConvertTo-Json -Depth 32|ConvertFrom-Json}
$path=Join-Path $PSScriptRoot 'guest\Invoke-GuestNativeReconstruct.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'wrapper parses'
foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($f.Extent.Text))}
function Identity([int]$Id,[long]$Disk,[long]$Length){[pscustomobject]@{disk_guid=('{0:d8}-1111-2222-aabb-123456789abc'-f$Id);partition_guid=('{0:d8}-1111-2222-aabb-123456789abc'-f($Id+1));partition_number=2;disk_bytes=$Disk;partition_offset=16MB;partition_bytes=$Length;logical_sector_bytes=512;physical_sector_bytes=4096}}
function Binding([int]$Number,[int]$Id){[pscustomobject]@{disk_number=$Number;volume_guid=('{0:d8}-1111-2222-aabb-123456789abc'-f($Id+2));identity=(Identity $Id 64GB 52GB)}}
$id='a'*32;$phase='b'*32;$requestHash='a'*64;$ticketHash='b'*64;$intentHash='c'*64
$runRoot='C:\ntfs2refs\native-reconstruct\'+$id;$caseRoot=$runRoot+'\'+$phase;$intentPath=$caseRoot+'\result.intent.json';$journalPath='J:\ntfs2refs-shadow\'+$id+'\reconstruction.journal'
$probe=[pscustomobject]@{schema_version=1;experiment_id=$id;fixture_evidence_sha256=('5'*64);target=(Binding 1 10);shadow=(Binding 3 20);retained_offset=8GB;source_retained_sha256=('3'*64);shadow_retained_sha256=('4'*64)}
$request=[pscustomobject]@{schema_version=1;experiment_id=$id;probe=$probe;comparison=[pscustomobject]@{schema_version=1;sector_size=4096;expected_length=52GB;source_sha256=('1'*64);shadow_sha256=('2'*64);retained_ranges=@([pscustomobject]@{offset=8GB;length=65536;source_sha256=('3'*64);shadow_sha256=('4'*64)});max_change_bytes=256MB;max_ranges=65536};journal=[pscustomobject]@{disk_number=2;externally_enrolled_disk_unique_id='600224806AAC261F021F249596F332FC';volume_guid='00000032-1111-2222-aabb-123456789abc';identity=(Identity 30 8GB (8GB-32MB))};max_journal_bytes=768MB}
$binding=[pscustomobject]@{experiment_id=$id;target_identity_sha256=('6'*64);shadow_identity_sha256=('7'*64);journal_identity_sha256=('8'*64)}
$ticket=[pscustomobject]@{schema_version=1;binding=$binding;immutable_sha256=('9'*64);immutable_length=16384;journal_length=24576}
function Ordinary([int]$Id,[long]$Length){[pscustomobject]@{final_path='\\?\Volume{00000032-1111-2222-aabb-123456789abc}\ntfs2refs\file';volume_serial_number=123;file_id_128=(@($Id)*16);file_bytes=$Length;allocation_bytes=$Length;file_attributes=32;number_of_links=1}}
function PartitionSnapshot($Binding,[int]$Attributes){[pscustomobject]@{binding=(Clone $Binding);disk_attributes=$Attributes;device=(@(0)*12);length=(@(0)*8);alignment=(@(0)*28);layout=(@(0)*336)}}
function JournalSnapshot([long]$Length){
 $j=$request.journal;$i=$j.identity
 [pscustomobject]@{schema_version=1;identity=[pscustomobject]@{volume_serial_number=123;file_id_128=(@(1)*16);volume_guid=([guid]$j.volume_guid).ToByteArray();disk_guid=([guid]$i.disk_guid).ToByteArray();partition_guid=([guid]$i.partition_guid).ToByteArray();partition_number=2;disk_bytes=8GB;partition_offset=16MB;partition_bytes=(8GB-32MB);logical_sector_bytes=512;physical_sector_bytes=4096};disk_number=2;final_path='\\?\Volume{00000032-1111-2222-aabb-123456789abc}\journal';file_bytes=$Length;allocation_bytes=$Length;file_attributes=32;number_of_links=1;externally_enrolled_disk_unique_id=$j.externally_enrolled_disk_unique_id;external_unique_id_verified=$false;sharing_mode_verified=$false;observations_match_before_after=$true;conversion_qualified=$false;evidence=[pscustomobject]@{file_id_info=(@(0)*24);file_standard_info=(@(0)*24);file_attribute_tag_info=(@(0)*8);volume_extents=(@(0)*32);disk_device_number=(@(0)*12);disk_length=(@(0)*8);disk_alignment=(@(0)*28);disk_layout=(@(0)*336)}}
}
function Report([string]$Operation){
 $prepare=$Operation-ceq'prepare';$handoff=$Operation-ceq'handoff';$write=if($prepare-or$handoff){0}else{4096};$before=if($prepare){0}else{$ticket.journal_length}
 $summary=$null;$plan=$null;$execution=$null
 if($prepare){$summary=[pscustomobject]@{ticket=(Clone $ticket);changed_bytes=4096;before_payload_bytes=4096;after_payload_bytes=4096;overhead_bytes=16384;patch_count=1;expected_postimage_sha256=('e'*64);preparation_durable=$true;conversion_qualified=$false}}
 else{$plan=[pscustomobject]@{patch_count=1;changed_bytes=4096;expected_postimage_sha256=('e'*64);immutable_sha256=$ticket.immutable_sha256};$name=if($handoff){'handoff-recorded'}elseif($Operation-ceq'rollback'){'rolled-back-before-handoff'}else{'applied-before-handoff'};$targetHash=if($Operation-ceq'rollback'){$request.comparison.source_sha256}else{'e'*64};$execution=[pscustomobject]@{operation=$name;target_sha256=$targetHash;target_bytes_written=$write;patches_written=$(if($handoff){0}else{1});retained_bytes_unchanged=$true;handoff_recorded=$handoff;conversion_qualified=$false}}
 $native=[pscustomobject]@{schema_version=1;kind='native-lab-journal-reconstruction';operation=$Operation;request=(Clone $request);success=$true;phase='complete-disks-remain-offline';error=$null;observed_binding=(Clone $binding);target_before=(PartitionSnapshot $probe.target 1);shadow_before=(PartitionSnapshot $probe.shadow 3);journal_before=(JournalSnapshot $before);target_after=(PartitionSnapshot $probe.target 1);shadow_after=(PartitionSnapshot $probe.shadow 3);journal_after=(JournalSnapshot $ticket.journal_length);plan=$plan;preparation=$summary;execution=$execution;counters=[pscustomobject]@{target_bytes_read=104GB;target_bytes_written=$write;target_write_bytes_requested=$write;shadow_bytes_read=52GB;shadow_bytes_written=0;shadow_write_bytes_requested=0};events=@([pscustomobject]@{operation='get-disk-attributes';control_code=0x700f0;input=@();succeeded=$true;native_error=$null;output=@(16,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0)});payload_write_requests_issued=($write-gt0);journal_write_requests_may_have_been_issued=$true;handoff_request_may_have_been_issued=$handoff;disks_observed_offline_at_end=$true;online_transition_requested=$false;conversion_qualified=$false;boot_qualified=$false}
 [pscustomobject]@{schema_version=1;kind='native-reconstruction-cli-result';operation=$Operation;success=$true;phase='complete-disks-remain-offline';error=$null;request_sha256=$requestHash;input_ticket_sha256=$(if($prepare){$null}else{$ticketHash});request_file=(Ordinary 3 4096);input_ticket_file=$(if($prepare){$null}else{Ordinary 4 1024});journal_path=$journalPath;intent_path=$intentPath;intent_sha256=$intentHash;journal_open_attempted=$true;journal_create_may_have_been_issued=$prepare;journal_file=(Ordinary 1 $before);native_operation_invoked=$true;native=$native;ticket_write_may_have_been_issued=$prepare;ticket_persisted=$prepare;ticket_sha256=$(if($prepare){$ticketHash}else{$null});ticket_file=$(if($prepare){Ordinary 4 1024}else{$null});artifacts_preserved_on_failure=$true;online_transition_requested=$false;conversion_qualified=$false;boot_qualified=$false}
}
Assert-NRRequest $request $id;$script:checks++;Assert-NRTicket $ticket $request;$script:checks++
foreach($op in @('prepare','apply','resume','rollback','handoff')){Assert-NRResult (Report $op) $request $op $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath;$script:checks++}
foreach($change in @(
 {param($r)$r.schema_version='1'},{param($r)$r.experiment_id='b'*32},{param($r)$r.probe.experiment_id='b'*32},
 {param($r)$r.probe.target.disk_number=0},{param($r)$r.probe.shadow.disk_number=4},{param($r)$r.probe.shadow.identity.disk_guid=$r.probe.target.identity.disk_guid},
 {param($r)$r.journal.identity.disk_guid=$r.probe.target.identity.disk_guid},{param($r)$r.journal.volume_guid=$r.probe.shadow.volume_guid},
 {param($r)$r.probe.retained_offset++},{param($r)$r.probe.retained_offset=9GB},{param($r)$r.probe.source_retained_sha256=$r.probe.shadow_retained_sha256},
 {param($r)$r.comparison.retained_ranges=@()},{param($r)$r.comparison.retained_ranges[0].length=32768},{param($r)$r.comparison.retained_ranges[0].source_sha256='f'*64},
 {param($r)$r.comparison.sector_size=512},{param($r)$r.comparison.expected_length=51GB},{param($r)$r.comparison.max_change_bytes=256MB+1},{param($r)$r.comparison.max_ranges=65537},
 {param($r)$r.journal.externally_enrolled_disk_unique_id='foreign'},{param($r)$r.journal.identity.partition_bytes=8GB},{param($r)$r.max_journal_bytes=0}
)){$bad=Clone $request;&$change $bad;Reject {Assert-NRRequest $bad $id} 'request mutation refused'}
$disk=[pscustomobject]@{Number=2;UniqueId=$request.journal.externally_enrolled_disk_unique_id;Size=8GB;PartitionStyle='GPT';Guid=$request.journal.identity.disk_guid;LogicalSectorSize=512;PhysicalSectorSize=4096;IsBoot=$false;IsSystem=$false;IsOffline=$false;IsReadOnly=$false}
$partition=[pscustomobject]@{DiskNumber=2;PartitionNumber=2;DriveLetter='J';Offset=16MB;Size=(8GB-32MB);Guid=$request.journal.identity.partition_guid}
$volume=[pscustomobject]@{DriveLetter='J';FileSystem='NTFS';FileSystemLabel='ntfs2refs-journal';AllocationUnitSize=4096;UniqueId=('\\?\Volume{'+$request.journal.volume_guid+'}\')}
Assert-NRJournalEnrollment $request $disk $partition $volume;$script:checks++
foreach($name in @('IsBoot','IsSystem','IsOffline','IsReadOnly')){$d=Clone $disk;$d.$name=$true;Reject {Assert-NRJournalEnrollment $request $d $partition $volume} 'journal state refused'}
$d=Clone $disk;$d.UniqueId='wrong';Reject {Assert-NRJournalEnrollment $request $d $partition $volume} 'journal route alone insufficient'
$p=Clone $partition;$p.Guid=$probe.target.identity.partition_guid;Reject {Assert-NRJournalEnrollment $request $disk $p $volume} 'journal partition binding'
$v=Clone $volume;$v.UniqueId='\\?\Volume{00000099-1111-2222-aabb-123456789abc}\';Reject {Assert-NRJournalEnrollment $request $disk $partition $v} 'journal mounted volume binding'
foreach($change in @(
 {param($r)$r.success=$false},{param($r)$r.success=1},{param($r)$r.error='failed'},{param($r)$r.request_sha256='f'*64},
 {param($r)$r.input_ticket_sha256='f'*64},{param($r)$r.intent_sha256='f'*64},{param($r)$r.journal_path='J:\shadow.vhdx'},
 {param($r)$r.online_transition_requested=$true},{param($r)$r.conversion_qualified=$true},{param($r)$r.boot_qualified=$true},
 {param($r)$r.ticket_persisted=$true},{param($r)$r.journal_create_may_have_been_issued=$true},{param($r)$r.request_file.number_of_links=2},
 {param($r)$r.native.request.probe.fixture_evidence_sha256='f'*64},{param($r)$r.native.observed_binding.journal_identity_sha256='f'*64},
 {param($r)$r.native.success=$false},{param($r)$r.native.target_after.disk_attributes=0},{param($r)$r.native.shadow_after.disk_attributes=1},
 {param($r)$r.native.journal_after.identity.file_id_128[0]=2},{param($r)$r.native.journal_after.file_bytes++},
 {param($r)$r.native.journal_after.number_of_links=2},{param($r)$r.native.journal_after.file_attributes=512},{param($r)$r.journal_file.file_bytes++},
 {param($r)$r.native.plan.changed_bytes=256MB+1},{param($r)$r.native.plan.immutable_sha256='f'*64},{param($r)$r.native.execution.target_sha256='f'*64},
 {param($r)$r.native.execution.target_bytes_written++},{param($r)$r.native.execution.patches_written=2},{param($r)$r.native.execution.handoff_recorded=$true},
 {param($r)$r.native.execution.retained_bytes_unchanged=$false},{param($r)$r.native.counters.shadow_write_bytes_requested=1},
 {param($r)$r.native.counters.target_write_bytes_requested++},{param($r)$r.native.payload_write_requests_issued=$false},
 {param($r)$r.native.events[0].succeeded=$false},{param($r)$r.native.events=@()},{param($r)$r.native.disks_observed_offline_at_end=$false},
 {param($r)$r.native.handoff_request_may_have_been_issued=$true},{param($r)$r.native.journal_before.external_unique_id_verified=$true}
)){$bad=Clone (Report 'apply');&$change $bad;Reject {Assert-NRResult $bad $request 'apply' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'completion mutation refused'}
foreach($op in @('prepare','handoff')){
 $bad=Clone (Report $op);$bad.native.payload_write_requests_issued=$true;Reject {Assert-NRResult $bad $request $op $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'no target payload writes in prepare/handoff'
}
$bad=Clone (Report 'prepare');$bad.native.preparation.preparation_durable=$false;Reject {Assert-NRResult $bad $request 'prepare' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'durable preparation required'
$bad=Clone (Report 'handoff');$bad.native.execution.handoff_recorded=$false;Reject {Assert-NRResult $bad $request 'handoff' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'durable handoff required'
$bad=Clone (Report 'rollback');$bad.native.execution.target_sha256='e'*64;Reject {Assert-NRResult $bad $request 'rollback' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'rollback requires original source hash'
$bad=Clone (Report 'apply');$bad|Add-Member online $true;Reject {Assert-NRResult $bad $request 'apply' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath} 'unknown report fields refused'
$zero=Clone (Report 'apply');$zero.native.plan.changed_bytes=0;$zero.native.plan.patch_count=0;$zero.native.execution.target_bytes_written=0;$zero.native.execution.patches_written=0;$zero.native.counters.target_bytes_written=0;$zero.native.counters.target_write_bytes_requested=0;$zero.native.payload_write_requests_issued=$false
Assert-NRResult $zero $request 'apply' $requestHash $ticket $ticketHash $intentPath $intentHash $journalPath;$script:checks++
function FakeProcess([bool]$WaitResult,$Exit){$p=[pscustomobject]@{waitResult=$WaitResult;ExitCode=$Exit;waitMilliseconds=0;waitThrows=$false;OutputLimitExceeded=$false};$p|Add-Member ScriptMethod WaitForExit {param($ms)$this.waitMilliseconds=$ms;if($this.waitThrows){throw 'wait failed'};return $this.waitResult};$p}
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $true ([int]0);Complete-NRProcess $p $r 30;Check ($r.completionKnown-and$r.exitCode-eq0-and$p.waitMilliseconds-eq30000) 'successful bounded completion'
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $false ([int]0);Reject {Complete-NRProcess $p $r 30} 'timeout refuses';Check (-not$r.completionKnown-and$null-eq$r.exitCode) 'timeout preserves unknown process'
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $true ([int]5);Complete-NRProcess $p $r 30;Check ($r.completionKnown-and$r.exitCode-eq5) 'nonzero completion remains exportable'
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $true $null;Reject {Complete-NRProcess $p $r 30} 'missing exit code refuses';Check $r.completionKnown 'exit observed even without code'
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $true ([int]0);$p.OutputLimitExceeded=$true;Reject {Complete-NRProcess $p $r 30} 'capture overflow refuses';Check ($r.completionKnown-and$r.exitCode-eq0) 'overflow exit remains determinate'
$r=[ordered]@{completionKnown=$false;exitCode=$null};$p=FakeProcess $false $null;$p.waitThrows=$true;Reject {Complete-NRProcess $p $r 30} 'wait failure';Check (-not$r.completionKnown) 'wait failure unknown'
foreach($seconds in @(0,29,7201,[int]::MaxValue)){Reject {Complete-NRProcess (FakeProcess $true ([int]0)) ([ordered]@{completionKnown=$false;exitCode=$null}) $seconds} 'finite deadline bound'}
Check ((Get-NRHash ([Text.Encoding]::UTF8.GetBytes('abc')))-ceq'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') 'independent artifact hash'
$wide=Convert-NRJson ([Text.Encoding]::UTF8.GetBytes('{"volume_serial_number":18446744073709551615}'));Assert-NRNumber $wide.volume_serial_number 1 ([decimal]'18446744073709551615');$script:checks++
Reject {Convert-NRJson ([byte[]]@(239,187,191,123,125))} 'JSON BOM refused'
$commands=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
foreach($forbidden in @('Stop-Process','Stop-VM','Remove-Item','Set-Disk','Format-Volume','Initialize-Disk','Dismount-VHD','Mount-VHD')){Check (-not($commands-ccontains$forbidden)) ('no mutation/cleanup command '+$forbidden)}
Check (@($commands|Where-Object{$_-ceq'Start-Process'}).Count-eq0) 'no detached cmdlet process wrapper'
Check ([regex]::Matches($ast.Extent.Text,'\[Ntfs2Refs\.BoundedLabProcess\]::Start\(').Count-eq1) 'one retained managed process launch only'
Check (-not($ast.Extent.Text-match '\.Kill\s*\(')) 'never kill uncertain child'
&$path -RunId $id -PhaseId $phase -Operation prepare -RequestSha256 $requestHash -BinarySha256 ('d'*64) -WhatIf;$script:checks++
Write-Output ('Guest native reconstruction: {0} pure/schema/enrollment/fake-process/WhatIf checks passed; no VM, device or file-write calls.'-f$script:checks)
