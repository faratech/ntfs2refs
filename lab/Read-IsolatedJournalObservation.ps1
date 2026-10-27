<# PROPOSED ONE-SHOT OBSERVER FOR REVIEW. Do not run as part of source tests.
   Reads only the enrolled isolated guest journal. Reports are observations,
   never ZeroProof, durable writer exclusion, initialization or write authority. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

# These four predicates are pure; the separate source tests extract only them.
function Get-IsolatedJournalObservationOutputPath([string]$Path){
 $root='D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review'
 if([string]::IsNullOrWhiteSpace($Path)-or$Path-cnotmatch'\A[Dd]:\\'-or$Path.Contains('..')-or$Path.Contains('/')-or$Path.EndsWith('\')){throw 'Unambiguous absolute observation output required.'}
 $full=[IO.Path]::GetFullPath($Path)
 if(-not[string]::Equals([IO.Path]::GetDirectoryName($full),$root,[StringComparison]::OrdinalIgnoreCase)-or
  [IO.Path]::GetFileName($full)-cnotmatch'\Ajournal-observation-review-[0-9]{8}T[0-9]{9}Z\z'){throw 'Fresh direct child journal-observation-review-YYYYMMDDTHHMMSSfffZ required.'}
 $full
}
function Assert-IsolatedObservationCapacity($Capacity){
 if($Capacity.MaximumActualBytes-ne208GB-or$Capacity.MinimumFreeBytes-ne64GB-or
  $Capacity.ActualBytes-lt0-or$Capacity.ActualBytes-gt(208GB-128MB)-or$Capacity.FreeBytes-lt(64GB+128MB)){throw 'Observation requires the exact208GiB lab ceiling,64GiB reserve and128MiB allowance.'}
}
function Assert-IsolatedObservationNoWorkers($Workers){
 if(-not($Workers.inventory_complete-is[bool])-or-not$Workers.inventory_complete-or
  @($Workers.active_tasks).Count-or@($Workers.known_project_processes).Count){throw 'Active, unknown or incomplete known-project worker inventory blocks observation.'}
}
function Assert-IsolatedObservationReport($Report,[string]$Token){
 foreach($name in @('informationalOnly','grantsInitializationAuthority','grantsWriteAuthority','atomicImmutabilityClaimed','durableWriterFenceEstablished','identityMatchedBeforeAfter')){
  if($Report.$name-isnot[bool]){throw 'Observation flags must be actual Boolean values.'}
 }
 foreach($name in @('complete','allZeroObserved','informationalOnly','grantsInitializationAuthority','grantsWriteAuthority','atomicImmutabilityClaimed')){
  if($Report.content.$name-isnot[bool]){throw 'Stream observation flags must be actual Boolean values.'}
 }
 foreach($value in @($Report.nativeBytesRead,$Report.nativeReadCalls,$Report.content.requestedBytes,$Report.content.bytesRead,$Report.content.readCalls,$Report.content.nonzeroBytes,$Report.content.firstNonzeroOffset)){
  if($value-isnot[int]-and$value-isnot[long]-and$value-isnot[uint32]-and$value-isnot[uint64]){throw 'Observation counts must be actual integer values.'}
 }
 $stamps=@()
 foreach($value in @($Report.startedUtc,$Report.content.startedUtc,$Report.content.finishedUtc,$Report.finishedUtc)){
  $stamp=[DateTime]::MinValue
  if($value-isnot[string]-or-not[DateTime]::TryParseExact($value,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$stamp)-or
   $stamp.Kind-ne[DateTimeKind]::Utc-or$stamp.ToString('o')-cne$value){throw 'Canonical UTC observation timestamps required.'}
  $stamps+=$stamp
 }
 if($stamps[0]-gt$stamps[1]-or$stamps[1]-gt$stamps[2]-or$stamps[2]-gt$stamps[3]){throw 'Observation timestamp interval changed or ran backward.'}
 if($Token-cnotmatch'\A[0-9a-f]{64}\z'-or$Report.kind-cne'isolated-journal-readonly-content-observation'-or
  -not($Report.informationalOnly-is[bool])-or-not$Report.informationalOnly-or
  $Report.grantsInitializationAuthority-ne$false-or$Report.grantsWriteAuthority-ne$false-or$Report.atomicImmutabilityClaimed-ne$false-or$Report.durableWriterFenceEstablished-ne$false-or
  $Report.identityMatchedBeforeAfter-ne$true-or$Report.nativeBytesRead-ne8GB-or$Report.nativeReadCalls-lt1-or$Report.nativeReadCalls-gt1048576-or
  $Report.beforeSnapshotSha256-cnotmatch'\A[0-9a-f]{64}\z'-or$Report.afterSnapshotSha256-cne$Report.beforeSnapshotSha256-or
  $Report.content.identityToken-cne$Token-or$Report.content.requestedBytes-ne8GB-or$Report.content.bytesRead-ne8GB-or$Report.content.complete-ne$true-or
  $Report.content.informationalOnly-ne$true-or$Report.content.grantsInitializationAuthority-ne$false-or$Report.content.grantsWriteAuthority-ne$false-or$Report.content.atomicImmutabilityClaimed-ne$false-or
  $Report.content.contentSha256-cnotmatch'\A[0-9a-f]{64}\z'-or$Report.content.readCalls-lt1-or$Report.content.readCalls-gt1048576-or
  $Report.content.nonzeroBytes-lt0-or$Report.content.nonzeroBytes-gt8GB-or
  @($Report.queries).Count-lt1-or@($Report.queries).Count-gt32){throw 'Incomplete/out-of-profile journal observation or authority claim refused.'}
 if(($Report.content.nonzeroBytes-eq0-and($Report.content.allZeroObserved-ne$true-or$Report.content.firstNonzeroOffset-ne-1))-or
  ($Report.content.nonzeroBytes-gt0-and($Report.content.allZeroObserved-ne$false-or$Report.content.firstNonzeroOffset-lt0-or$Report.content.firstNonzeroOffset-ge8GB))){throw 'Inconsistent nonzero-byte observation refused.'}
}
function Assert-IsolatedObservationFreshHostType($LoadedType=('Ntfs2RefsResearch.IsolatedHostFileIdentity' -as[type])){
 if($null-ne$LoadedType){throw 'Use a fresh PowerShell process: preloaded IsolatedHostFileIdentity type is refused before Add-Type.'}
}

$workspace='D:\code\ntfs2refs';$isolatedRoot=Join-Path $workspace '.lab\hyperv\isolated-reference-20261026-review'
$vmId=[guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
$full=Get-IsolatedJournalObservationOutputPath $OutputDirectory
$pins=[Collections.Generic.List[object]]::new();$projectLeases=[Collections.Generic.List[object]]::new()
$events=[Collections.Generic.List[object]]::new();$hostLease=$null;$session=$null;$created=$false;$phase='initial-refusals';$guestCallAttempted=$false;$completion=$null
function Ordinary([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force
 if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary observation path required.'}
 $parent=if($item.PSIsContainer){$item.Parent}else{$item.Directory}
 while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Observation path ancestry contains a reparse point.'};$parent=$parent.Parent}
}
function Hash-Bytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Pin-Source([string]$Path,[long]$Limit=2MB){
 Ordinary $Path $false;$file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($file.Length-le0-or$file.Length-gt$Limit){throw 'Pinned source/reference exceeds its byte bound.'}
  $sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $file.Position=0;$record=[pscustomobject]@{path=[IO.Path]::GetFullPath($Path);bytes=$file.Length;sha256=$hash;stream=$file};$pins.Add($record);$file=$null;$record
 }finally{if($file){$file.Dispose()}}
}
function Event([string]$Name,$Data){
 if($events.Count-ge64){throw 'Observation event count exceeded.'}
 $events.Add([pscustomobject]@{phase=$Name;observed_utc=[DateTime]::UtcNow.ToString('o');data=$Data})
}
function Assert-OutputBudget([long]$Additional=0){
 $items=@(Get-ChildItem -LiteralPath $full -Force)
 if($items.Count-gt32){throw 'Host observation artifact count exceeded.'};$total=0L
 foreach($item in $items){if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Only ordinary direct host artifacts permitted.'};$total+=$item.Length}
 if($Additional-lt0-or$total-gt(16MB-$Additional)){throw 'Host observation output exceeds16MiB.'}
}
function Save([string]$Name,$Value){
 if($Name-cnotmatch'\A[a-z][a-z0-9-]*\z'){throw 'Fixed host-only JSON artifact name required.'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));Assert-OutputBudget $bytes.Length
 $file=[IO.File]::Open((Join-Path $full ($Name+'.json')),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Host-Workers {
 $allTasks=@(Get-ScheduledTask -ErrorAction Stop)
 if($allTasks.Count-gt8192){throw 'Host task inventory exceeds bound.'}
 $tasks=@($allTasks|Where-Object {$_.TaskName-like'N2R-*'})
 $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if($tasks.Count-gt4096-or$processes.Count-gt8192){throw 'Known-worker inventory exceeds bound.'}
 $active=@($tasks|Where-Object {$_.State.ToString()-notin@('Ready','Disabled')}|ForEach-Object {[pscustomobject]@{name=$_.TaskName;state=$_.State.ToString()}})
 $known=@($processes|Where-Object {$_.ProcessId-ne$PID-and($_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'-or
  ($_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and[string]$_.CommandLine-match'(?i)ntfs2refs'-and[string]$_.CommandLine-match'(?i)(?:Start|Dispatch|Complete|Finish|Preserve|Prepare|Provision|Write|Convert|Reconstruct|Restore|Initialize|Format)-[^\s"'']+\.ps1'))}|ForEach-Object {
   [pscustomobject]@{pid=$_.ProcessId;name=$_.Name;executable=$_.ExecutablePath}})
 [pscustomobject]@{inventory_complete=$true;active_tasks=$active;known_project_processes=$known;process_count=$processes.Count;project_task_count=$tasks.Count;coverage='Known observable N2R names and project controller command lines; not arbitrary writers or an administrator/kernel fence.';observed_utc=[DateTime]::UtcNow.ToString('o')}
}
function Journal-Metadata {
 $path=Join-Path $isolatedRoot 'disks\journal.vhdx'
 $held=@($hostLease.pins|Where-Object {$_.path.Equals($path,[StringComparison]::OrdinalIgnoreCase)})
 if($held.Count-ne1){throw 'Exactly one held enrolled journal path identity required.'}
 Ordinary $path $false;$item=Get-Item -LiteralPath $path -Force
 [pscustomobject]@{path=$path;host_file_id=$held[0].identity.file_id;raw_file_id_hex=$held[0].identity.raw_file_id_hex;
  file_bytes=[long]$item.Length;last_write_utc=$item.LastWriteTimeUtc.ToString('o');last_write_ticks=$item.LastWriteTimeUtc.Ticks;content_immutable=$false;durable_writer_fence=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}
}

# Future guest execution has exactly one report-only native observation site.
# Assembly bytes are loaded in memory; no guest file or scheduled task is created.
$guestObservation={
 param([string]$AssemblyBase64,[string]$AssemblySha256,[guid]$ExpectedVm,[string]$ExpectedToken)
 Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
 function Workers {
  $allTasks=@(Get-ScheduledTask -ErrorAction Stop);if($allTasks.Count-gt8192){throw 'Guest task inventory exceeds bound.'}
  $tasks=@($allTasks|Where-Object {$_.TaskName-like'N2R-*'});$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
  if($tasks.Count-gt4096-or$processes.Count-gt8192){throw 'Guest known-worker inventory exceeds bound.'}
  $active=@($tasks|Where-Object {$_.State.ToString()-notin@('Ready','Disabled')}|ForEach-Object {[pscustomobject]@{name=$_.TaskName;state=$_.State.ToString()}})
  $known=@($processes|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'-or
   ($_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and[string]$_.CommandLine-match'(?i)C:\\ntfs2refs\\')}|ForEach-Object {[pscustomobject]@{pid=$_.ProcessId;name=$_.Name;executable=$_.ExecutablePath}})
  [pscustomobject]@{inventory_complete=$true;active_tasks=$active;known_project_processes=$known;process_count=$processes.Count;project_task_count=$tasks.Count;observed_utc=[DateTime]::UtcNow.ToString('o')}
 }
 $before=Workers;$after=$null;$report=$null;$errorText=$null;$invocations=0;$loadedHash=$null
 try{
  if([guid]$ExpectedVm-ne[guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'-or$env:COMPUTERNAME-cne'N2R-WIN11'-or
   $ExpectedToken-cnotmatch'\A[0-9a-f]{64}\z'-or$AssemblySha256-cnotmatch'\A[0-9a-f]{64}\z'-or$AssemblyBase64.Length-gt4MB){throw 'Exact isolated guest and bounded pinned assembly required.'}
  if($before.active_tasks.Count-or$before.known_project_processes.Count){throw 'Known guest project worker blocks observation.'}
  foreach($name in @('IsolatedJournalReader','IsolatedJournalContentObservation','IsolatedJournalObservation','IsolatedJournalDeviceProfile','ZeroProof')){
   if(('Ntfs2RefsResearch.'+$name)-as[type]){throw 'A preloaded guest research type blocks assembly reuse.'}
  }
  $bytes=[Convert]::FromBase64String($AssemblyBase64)
  if($bytes.Length-le0-or$bytes.Length-gt2MB){throw 'Bounded .NET4 reader assembly required.'}
  $sha=[Security.Cryptography.SHA256]::Create();try{$loadedHash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($loadedHash-cne$AssemblySha256){throw 'Reader assembly pin differs in guest memory.'}
  $assembly=[Reflection.Assembly]::Load($bytes);$type=$assembly.GetType('Ntfs2RefsResearch.IsolatedJournalReader',$true,$false)
  if($type.GetField('DurableWriterExclusionSupported').GetRawConstantValue()-ne$false){throw 'Disabled durable-zero-proof gate changed.'}
  $tokenMethod=$type.GetMethod('ExpectedIdentityToken',[Reflection.BindingFlags]'Public,Static')
  if([string]$tokenMethod.Invoke($null,@())-cne$ExpectedToken){throw 'Observed reader token differs from exact enrolled host material.'}
  $method=$type.GetMethod('ObserveReadOnly',[type[]]@([guid],[string]))
  if($null-eq$method-or$method.ReturnType.FullName-cne'Ntfs2RefsResearch.IsolatedJournalContentObservation'){throw 'Report-only observation API signature differs.'}
  $invocations=1;$report=$method.Invoke($null,[object[]]@($ExpectedVm,$ExpectedToken))
 }catch{$errorText=$_.Exception.ToString()}
 finally{try{$after=Workers}catch{$errorText=([string]$errorText+'; after-inventory: '+$_.Exception.Message)}}
 [pscustomobject]@{kind='isolated-journal-guest-observation-attempt';success=($null-eq$errorText);native_api_invocations=$invocations;
  assembly_sha256=$loadedHash;before_workers=$before;after_workers=$after;report=$report;error=$errorText;
  guest_file_staging=$false;guest_attributes_changed=$false;privileges_changed=$false;initialization_authorized=$false;write_authority=$false;
  reader_lifetime='Private API using scope closes the native reader before its data-only return; transport failure does not establish worker termination.'}
}

try{
 if($PSVersionTable.PSEdition-cne'Desktop'-or$PSVersionTable.PSVersion.Major-ne5){throw 'Review and use a fresh Windows PowerShell5.1 -NoProfile process.'}
 Assert-IsolatedObservationFreshHostType
 Ordinary $isolatedRoot $true
 if(Test-Path -LiteralPath $full){throw 'Existing observation output cannot be retried or overwritten.'}
 $phase='pin-all-source-before-load'
 $sourceNames=@('Read-IsolatedJournalObservation.ps1','IsolatedHostIdentity.psm1','IsolatedHostGraph.psm1','IsolatedBaselineGuards.psm1',
  'host\IsolatedHostFileIdentity.Windows.cs','Lab.psm1','lab.config.json','guest\IsolatedJournalZero.cs','guest\IsolatedJournalDeviceProfile.cs',
  'guest\IsolatedJournalObservation.cs','guest\IsolatedJournalReader.Windows.cs')
 foreach($name in $sourceNames){$null=Pin-Source (Join-Path $PSScriptRoot $name)}
 $framework=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
 foreach($name in @('csc.exe','mscorlib.dll','System.dll','System.Core.dll')){$null=Pin-Source (Join-Path $framework $name) 16MB}
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 Import-Module (Join-Path $PSScriptRoot 'IsolatedHostIdentity.psm1') -Force
 $capacity=Lab\Get-LabCapacity -Configuration (Lab\Get-LabConfiguration -WorkspaceRoot $workspace)
 Assert-IsolatedObservationCapacity $capacity
 Lab\Assert-LabCapacity -Capacity $capacity -AdditionalBytes 128MB
 $null=New-Item -ItemType Directory -Path $full -ErrorAction Stop;$created=$true;Ordinary $full $true
 Save 'source-pins' @{sources=@($pins|ForEach-Object {[pscustomobject]@{path=$_.path;bytes=$_.bytes;sha256=$_.sha256}});held_readonly_source_handles=$true;credential_material_included=$false}
 Event 'sources-pinned' @{count=$pins.Count;host_output=$full;write_authority=$false}
 $phase='ordinary-project-concurrency-guards'
 $lockPaths=@((Join-Path $isolatedRoot 'journal-observation-controller.lock'),(Join-Path $isolatedRoot 'readiness-owner.lock'),
  (Join-Path $workspace '.lab\hyperv\reference-isolation-approved-20261026T130646790Z\stage2-controller.lock'),
  (Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026\active-alpha-controller.lock'),(Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026\fault-dispatch.lock'))
 foreach($path in $lockPaths){
  $exists=Test-Path -LiteralPath $path
  if($exists){Ordinary $path $false;if((Get-Item -LiteralPath $path).Length-ne0){throw 'Known project lease shape differs.'}}
  elseif($path-cne$lockPaths[0]){throw 'Known project concurrency lease is absent; do not invent another controller contract.'}
  $mode=if($exists){[IO.FileMode]::Open}else{[IO.FileMode]::CreateNew}
  $projectLeases.Add([pscustomobject]@{path=$path;stream=[IO.File]::Open($path,$mode,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)})
 }
 Save 'concurrency-guards' @{paths=$lockPaths;ordinary_project_cooperation_only=$true;durable_writer_fence=$false}
 $hostBefore=Host-Workers;Save 'host-workers-before' $hostBefore;Assert-IsolatedObservationNoWorkers $hostBefore
 $phase='compile-host-only-netframework-reader'
 $dll=Join-Path $full 'IsolatedJournalObservation.Net4.dll'
 if(Test-Path -LiteralPath $dll){throw 'Fresh host assembly path required.'}
 $arguments=@('/nologo','/noconfig','/nostdlib+','/target:library','/optimize+','/debug-','/platform:anycpu','/warn:4','/warnaserror+',('/out:'+$dll))
 foreach($name in @('mscorlib.dll','System.dll','System.Core.dll')){$arguments+=('/reference:'+(Join-Path $framework $name))}
 foreach($name in @('IsolatedJournalZero.cs','IsolatedJournalDeviceProfile.cs','IsolatedJournalObservation.cs','IsolatedJournalReader.Windows.cs')){$arguments+=(Join-Path $PSScriptRoot ('guest\'+$name))}
 $compileLines=[Collections.Generic.List[string]]::new();$compileBytes=0L
 & (Join-Path $framework 'csc.exe') @arguments 2>&1|ForEach-Object {$line=[string]$_;$compileBytes+=[Text.Encoding]::UTF8.GetByteCount($line);if($compileBytes-gt2MB){throw 'Compiler transcript exceeds bound.'};$compileLines.Add($line)}
 $compilerExit=$LASTEXITCODE;Save 'compiler-transcript' @{compiler=(Join-Path $framework 'csc.exe');arguments=$arguments;exit_code=$compilerExit;lines=$compileLines.ToArray()}
 if($compilerExit-ne0){throw 'Pinned .NET Framework4 compiler failed; no guest call is allowed.'}
 Ordinary $dll $false;Assert-OutputBudget
 $dllBytes=[IO.File]::ReadAllBytes($dll);if($dllBytes.Length-le0-or$dllBytes.Length-gt2MB){throw 'Host reader assembly exceeds bound.'}
 $dllHash=Hash-Bytes $dllBytes
 Save 'assembly-pin' @{path=$dll;bytes=$dllBytes.Length;sha256=$dllHash;target_runtime='.NET Framework4';guest_delivery='in-memory byte array only'}
 $phase='acquire-default-complete-host-identity'
 Assert-IsolatedObservationFreshHostType
 $hostLease=IsolatedHostIdentity\Get-IsolatedHostIdentityLease
 $graph=IsolatedHostIdentity\Test-IsolatedHostIdentityLease $hostLease
 if($hostLease.writer_exclusion_established-or$hostLease.write_authority){throw 'Identity observations unexpectedly claim writer exclusion or writes.'}
 Save 'host-identity-before' @{host=$hostLease.snapshot;graph=$graph;default_provider=$true;identity_pins_held=$true;durable_writer_fence=$false}
 $journalBefore=Journal-Metadata;Save 'journal-backing-before' $journalBefore
 $phase='open-existing-credential-exact-vm-session'
 $credentialPath=Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml';Ordinary $credentialPath $false
 $credential=Import-Clixml -LiteralPath $credentialPath
 $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $null=IsolatedHostIdentity\Test-IsolatedHostIdentityLease $hostLease
 $hostImmediate=Host-Workers;Save 'host-workers-before-call' $hostImmediate;Assert-IsolatedObservationNoWorkers $hostImmediate
 $material='isolated-journal-zero-v1|8f7fc646-8c9f-41d0-b65a-ecfadccfc36a|\\?\Volume{fcccb0cc-ddbb-46a4-ab61-ab5f91c889ca}\|0x000000000007c9c40000000000000010|600224806AAC261F021F249596F332FC|8589934592|512|4096'
 $token=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($material))
 Save 'observation-intent' @{vm_id=$vmId.ToString('D');disk_number=2;requested_bytes=8GB;buffer_bytes=1MB;dll_sha256=$dllHash;identity_token=$token;
  requested_native_api='IsolatedJournalReader.ObserveReadOnly(Guid,string)';maximum_attempts=1;host_identity_pins_held=$true;
  zero_proof_requested=$false;initialization_authorized=$false;write_authority=$false;atomic_content_snapshot_claimed=$false;durable_writer_fence=$false;created_utc=[DateTime]::UtcNow.ToString('o')}
 $phase='one-shot-readonly-guest-observation';$guestCallAttempted=$true
 $observed=Invoke-Command -Session $session -ScriptBlock $guestObservation -ArgumentList ([Convert]::ToBase64String($dllBytes)),$dllHash,$vmId,$token
 Save 'guest-observation' $observed
 $phase='revalidate-held-host-identity-and-known-workers'
 $hostAfter=Host-Workers;Save 'host-workers-after' $hostAfter
 $graphAfter=IsolatedHostIdentity\Test-IsolatedHostIdentityLease $hostLease
 $journalAfter=Journal-Metadata;Save 'journal-backing-after' $journalAfter
 Save 'host-identity-after' @{host=$hostLease.snapshot;graph=$graphAfter;identity_pins_still_held=$true;durable_writer_fence=$false}
 Assert-IsolatedObservationNoWorkers $hostAfter
 Assert-IsolatedObservationNoWorkers $observed.before_workers;Assert-IsolatedObservationNoWorkers $observed.after_workers
 if($observed.success-ne$true-or$observed.native_api_invocations-ne1-or$observed.assembly_sha256-cne$dllHash-or$observed.guest_file_staging-or$observed.guest_attributes_changed-or$observed.privileges_changed-or$observed.write_authority){throw 'The one guest observation did not return its pinned data-only result.'}
 Assert-IsolatedObservationReport $observed.report $token
 $sameMetadata=$journalBefore.file_bytes-eq$journalAfter.file_bytes-and$journalBefore.last_write_ticks-eq$journalAfter.last_write_ticks
 if(-not$sameMetadata){throw 'Enrolled journal backing length/mtime changed during observation; preserved bytes are observations only.'}
 $completion=@{schema_version=1;kind='isolated-journal-host-content-observation';success=$true;vm_id=$vmId.ToString('D');disk_number=2;assembly_sha256=$dllHash;
  requested_bytes=8GB;bytes_read=$observed.report.content.bytesRead;content_sha256=$observed.report.content.contentSha256;
  nonzero_bytes=$observed.report.content.nonzeroBytes;first_nonzero_offset=$observed.report.content.firstNonzeroOffset;all_zero_observed=$observed.report.content.allZeroObserved;
  journal_backing_metadata_unchanged=$sameMetadata;known_project_workers_absent_before_after=$true;complete_host_identity_revalidated=$true;
  informational_only=$true;atomic_content_snapshot_claimed=$false;durable_writer_fence_established=$false;zero_proof_issued=$false;
  initialization_authorized=$false;write_authority=$false;device_attributes_changed=$false;guest_files_created=0;
  coverage='One sequential observation through Windows/Hyper-V; matching before/after identities and metadata do not exclude concurrent, alias, lower-stack, malicious administrator or kernel writers.';completed_utc=[DateTime]::UtcNow.ToString('o')}
 Event 'completed' @{bytes_read=$observed.report.content.bytesRead;informational_only=$true;write_authority=$false}
}catch{
 if($created){Save 'failed' @{phase=$phase;error=$_.Exception.ToString();guest_call_attempted=$guestCallAttempted;guest_termination_inferred=$false;
  automatic_retry_authorized=$false;initialization_authorized=$false;write_authority=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}}
 throw
}finally{
 $cleanupErrors=[Collections.Generic.List[string]]::new()
 if($session){try{Remove-PSSession $session -ErrorAction Stop}catch{$cleanupErrors.Add('Session cleanup: '+$_.Exception.Message)}}
 if($hostLease){try{IsolatedHostIdentity\Close-IsolatedHostIdentityLease $hostLease}catch{$cleanupErrors.Add('Host identity cleanup: '+$_.Exception.Message)}}
 for($i=$projectLeases.Count-1;$i-ge0;$i--){try{$projectLeases[$i].stream.Dispose()}catch{$cleanupErrors.Add('Project lease cleanup: '+$_.Exception.Message)}}
 for($i=$pins.Count-1;$i-ge0;$i--){try{$pins[$i].stream.Dispose()}catch{$cleanupErrors.Add('Source pin cleanup: '+$_.Exception.Message)}}
 if($created){Save 'transcript' @{events=$events.ToArray();host_only=$true;no_device_or_vm_setters=$true;known_project_guards_are_not_a_durable_writer_fence=$true;finished_utc=[DateTime]::UtcNow.ToString('o')}}
 if($cleanupErrors.Count){if($created){Save 'cleanup-failed' @{errors=$cleanupErrors.ToArray();success=$false;write_authority=$false}};throw ('Observation cleanup incomplete: '+($cleanupErrors-join'; '))}
 if($null-ne$completion){Save 'result' $completion;Write-Host ('Read-only isolated journal observation complete; host evidence: '+$full)}
}
