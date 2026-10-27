<# Pure/refusal/AST tests only. The launcher main body and its guest scriptblock
   are never executed. No native identity, VM, credential or device API runs. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$refused=$false;try{&$Action|Out-Null}catch{$refused=$true};Check $refused $Message}
$path=Join-Path $PSScriptRoot 'Read-IsolatedJournalObservation.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Check ($errors.Count-eq0) 'Launcher syntax failed.'
$pureNames=@('Get-IsolatedJournalObservationOutputPath','Assert-IsolatedObservationCapacity','Assert-IsolatedObservationNoWorkers','Assert-IsolatedObservationReport','Assert-IsolatedObservationFreshHostType')
foreach($name in $pureNames){
 $definitions=@($ast.FindAll({param($node) $node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq$name},$false))
 Check ($definitions.Count-eq1) ('Unique pure definition required: '+$name)
 . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$root='D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review'
$good=$root+'\journal-observation-review-20261027T120102003Z'
Check ((Get-IsolatedJournalObservationOutputPath $good)-ceq$good) 'Exact direct output path refused.'
foreach($bad in @('', '.', 'journal-observation-review-20261027T120102003Z',
 ($good+'\'),($root+'\nested\journal-observation-review-20261027T120102003Z'),
 ($root+'\..\isolated-reference-20261026-review\journal-observation-review-20261027T120102003Z'),
 ($good.Replace('\','/')),($good.Replace('D:','C:')),($good.Replace('journal-observation','host-identity')),
 ($good+'-retry'),($good.Substring(0,$good.Length-1)),('\\server\share\journal-observation-review-20261027T120102003Z'))){
 Reject {Get-IsolatedJournalObservationOutputPath $bad} ('Ambiguous/foreign output accepted: '+$bad)
}
$capacity=[pscustomobject]@{MaximumActualBytes=208GB;MinimumFreeBytes=64GB;ActualBytes=100GB;FreeBytes=100GB}
Assert-IsolatedObservationCapacity $capacity;Check $true 'Valid bounded capacity refused.'
foreach($field in @('MaximumActualBytes','MinimumFreeBytes','ActualBytes','FreeBytes')){
 $copy=$capacity|ConvertTo-Json|ConvertFrom-Json
 $copy.$field=switch($field){'MaximumActualBytes'{209GB};'MinimumFreeBytes'{63GB};'ActualBytes'{208GB};'FreeBytes'{64GB}}
 Reject {Assert-IsolatedObservationCapacity $copy} ('Capacity guard ignored '+$field)
}
$workers=[pscustomobject]@{inventory_complete=$true;active_tasks=@();known_project_processes=@()}
Assert-IsolatedObservationNoWorkers $workers;Check $true 'Empty complete known-worker observation refused.'
foreach($field in @('inventory_complete','active_tasks','known_project_processes')){
 $copy=$workers|ConvertTo-Json|ConvertFrom-Json
 $copy.$field=if($field-ceq'inventory_complete'){$false}else{@([pscustomobject]@{name='synthetic-writer'})}
 Reject {Assert-IsolatedObservationNoWorkers $copy} ('Known/incomplete worker observation accepted: '+$field)
}
$workers.inventory_complete='true';Reject {Assert-IsolatedObservationNoWorkers $workers} 'Serialized Boolean-like completeness accepted.'
Assert-IsolatedObservationFreshHostType -LoadedType $null;Check $true 'Fresh host type predicate refused null.'
foreach($loaded in @([string],'foreign preloaded type',[pscustomobject]@{FullName='Ntfs2RefsResearch.IsolatedHostFileIdentity'})){
 Reject {Assert-IsolatedObservationFreshHostType -LoadedType $loaded} 'Foreign/preloaded host type accepted.'
}
# Exercise the host collector only behind throwing/in-memory command mocks.
# No scheduled-task provider or CIM API is reached by these checks.
$hostFunction=@($ast.FindAll({param($node) $node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq'Host-Workers'},$false))
Check ($hostFunction.Count-eq1) 'Unique host worker collector missing.'
. ([scriptblock]::Create($hostFunction[0].Extent.Text))
$script:taskFault=$true;$script:cimFault=$false;$script:cimCalls=0;$script:fakeTasks=@();$script:fakeProcesses=@()
function Get-ScheduledTask {param([string]$ErrorAction) if($script:taskFault){throw 'Injected task provider access failure.'};$script:fakeTasks}
function Get-CimInstance {param([string]$ClassName,[string]$ErrorAction) $script:cimCalls++;if($script:cimFault){throw 'Injected CIM access failure.'};$script:fakeProcesses}
Reject {Host-Workers} 'Task provider failure became an empty successful worker inventory.'
Check ($script:cimCalls-eq0) 'Task inventory failure continued to process query.'
$script:taskFault=$false;$script:cimFault=$true
Reject {Host-Workers} 'CIM failure became an empty successful worker inventory.'
$script:cimFault=$false
Assert-IsolatedObservationNoWorkers (Host-Workers);Check $true 'Mocked empty known-worker set refused.'
$script:fakeTasks=@([pscustomobject]@{TaskName='N2R-Synthetic';State='Running'})
Reject {Assert-IsolatedObservationNoWorkers (Host-Workers)} 'Mocked active known N2R task accepted.'
$script:fakeTasks=@();$script:fakeProcesses=@([pscustomobject]@{ProcessId=987654;Name='ntfs2refs.exe';ExecutablePath='synthetic';CommandLine=$null})
Reject {Assert-IsolatedObservationNoWorkers (Host-Workers)} 'Known N2R process with unavailable command line accepted.'
function Fixture {
 [pscustomobject]@{kind='isolated-journal-readonly-content-observation';informationalOnly=$true;grantsInitializationAuthority=$false;
  grantsWriteAuthority=$false;atomicImmutabilityClaimed=$false;durableWriterFenceEstablished=$false;identityMatchedBeforeAfter=$true;
  nativeBytesRead=8GB;nativeReadCalls=8192;beforeSnapshotSha256=('b'*64);afterSnapshotSha256=('b'*64);queries=@([pscustomobject]@{code=1});
  startedUtc='2026-10-27T12:00:00.0000000Z';finishedUtc='2026-10-27T12:05:00.0000000Z';
  content=[pscustomobject]@{identityToken=('a'*64);requestedBytes=8GB;bytesRead=8GB;readCalls=8193;complete=$true;contentSha256=('c'*64);
   startedUtc='2026-10-27T12:00:01.0000000Z';finishedUtc='2026-10-27T12:04:59.0000000Z';
   nonzeroBytes=0;firstNonzeroOffset=-1;allZeroObserved=$true;informationalOnly=$true;grantsInitializationAuthority=$false;
   grantsWriteAuthority=$false;atomicImmutabilityClaimed=$false}}
}
$report=Fixture;Assert-IsolatedObservationReport $report ('a'*64);Check $true 'Complete zero observation refused.'
$report=Fixture;$report.content.nonzeroBytes=1;$report.content.firstNonzeroOffset=8GB-1;$report.content.allZeroObserved=$false
Assert-IsolatedObservationReport $report ('a'*64);Check $true 'Nonzero content incorrectly refused rather than observed.'
foreach($field in @('grantsInitializationAuthority','grantsWriteAuthority','atomicImmutabilityClaimed','durableWriterFenceEstablished')){
 $report=Fixture;$report.$field=$true;Reject {Assert-IsolatedObservationReport $report ('a'*64)} ('Native authority claim accepted: '+$field)
 $report=Fixture;$report.$field='False';Reject {Assert-IsolatedObservationReport $report ('a'*64)} ('String authority flag accepted: '+$field)
}
foreach($field in @('grantsInitializationAuthority','grantsWriteAuthority','atomicImmutabilityClaimed')){
 $report=Fixture;$report.content.$field=$true;Reject {Assert-IsolatedObservationReport $report ('a'*64)} ('Stream authority claim accepted: '+$field)
}
foreach($failure in @('early-eof','wrong-size','wrong-token','bad-hash','changed-snapshot','not-informational','false-native-identity','bad-read-count','bad-first-nonzero','bad-zero-flag','too-many-queries','bad-utc','backward-time','string-count')){
 $report=Fixture
 switch($failure){
  'early-eof'{$report.content.bytesRead=8GB-512} 'wrong-size'{$report.nativeBytesRead=8GB-512}
  'wrong-token'{$report.content.identityToken='d'*64} 'bad-hash'{$report.content.contentSha256='not-a-pin'}
  'changed-snapshot'{$report.afterSnapshotSha256='d'*64} 'not-informational'{$report.informationalOnly=$false}
  'false-native-identity'{$report.identityMatchedBeforeAfter=$false} 'bad-read-count'{$report.nativeReadCalls=1048577}
  'bad-first-nonzero'{$report.content.nonzeroBytes=1;$report.content.allZeroObserved=$false;$report.content.firstNonzeroOffset=8GB}
  'bad-zero-flag'{$report.content.allZeroObserved=$false} 'too-many-queries'{$report.queries=@(1..33)}
  'bad-utc'{$report.startedUtc='2026-10-27T12:00:00+00:00'} 'backward-time'{$report.finishedUtc='2026-10-27T12:00:00.0000000Z'}
  'string-count'{$report.content.bytesRead='8589934592'}
 }
 Reject {Assert-IsolatedObservationReport $report ('a'*64)} ('Incomplete/inconsistent report accepted: '+$failure)
}

# Dispatch structure and source gates are inspected, never invoked.
$commands=@($ast.FindAll({param($node) $node-is[Management.Automation.Language.CommandAst]},$true))
$taskQueries=@($commands|Where-Object {$_.GetCommandName()-ceq'Get-ScheduledTask'})
Check ($taskQueries.Count-eq2) 'Host/guest known-worker task inventory sites differ.'
foreach($query in $taskQueries){Check ($query.Extent.Text-ceq'Get-ScheduledTask -ErrorAction Stop') 'Task provider errors can be suppressed or confused with no matching task.'}
foreach($forbidden in @('Start-VM','Stop-VM','Restart-VM','Restore-VMSnapshot','Checkpoint-VM','Import-VM','Add-VMHardDiskDrive','Remove-VMHardDiskDrive',
 'Set-VM','Set-VMMemory','Set-VMProcessor','Set-VMDvdDrive','Set-Disk','Initialize-Disk','Format-Volume','Clear-Disk','Set-Partition','New-Partition',
 'Set-ExecutionPolicy','Copy-VMFile','Register-ScheduledTask','Start-ScheduledTask','Remove-Item','Move-Item','Set-LocalUser','Add-LocalGroupMember')){
 Check (@($commands|Where-Object {$_.GetCommandName()-ceq$forbidden}).Count-eq0) ('Forbidden launcher command: '+$forbidden)
}
$acquire=@($commands|Where-Object {$_.GetCommandName()-ceq'IsolatedHostIdentity\Get-IsolatedHostIdentityLease'})
Check ($acquire.Count-eq1-and$acquire[0].CommandElements.Count-eq1) 'Identity acquisition uses an injected provider or extra acquisition.'
Check (@($commands|Where-Object {$_.GetCommandName()-ceq'IsolatedHostIdentity\Test-IsolatedHostIdentityLease'}).Count-ge3) 'Held identity is not revalidated around the read.'
Check (@($commands|Where-Object {$_.GetCommandName()-ceq'IsolatedHostIdentity\Close-IsolatedHostIdentityLease'}).Count-eq1) 'Identity cleanup site differs.'
$sessions=@($commands|Where-Object {$_.GetCommandName()-ceq'New-PSSession'})
Check ($sessions.Count-eq1-and$sessions[0].Extent.Text-match'-VMId \$vmId') 'Session is not confined to the exact recorded VM.'
$invocations=@($commands|Where-Object {$_.GetCommandName()-ceq'Invoke-Command'})
Check ($invocations.Count-eq1-and$invocations[0].Extent.Text-match'-ScriptBlock \$guestObservation') 'Guest observation is not one-shot.'
Check ($ast.Extent.Text-match"GetMethod\('ObserveReadOnly',\[type\[\]\]@\(\[guid\],\[string\]\)\)") 'Guest API signature is not pinned.'
Check ($ast.Extent.Text-match'\[Reflection.Assembly\]::Load\(\$bytes\)') 'Guest assembly is not loaded in memory.'
Check ($ast.Extent.Text-match"durableWriterFenceEstablished"-and$ast.Extent.Text-match'atomic_content_snapshot_claimed=\$false') 'Observation limits are not explicit.'
Check ($ast.Extent.Text-notmatch'::(?:OpenReadOnly|ScanAndBind|ScanJournal)\(') 'Disabled native proof API is called.'
Check ($ast.Extent.Text-notmatch'ExecutionPolicyBypass|-ExecutionPolicy|ReadAllBytes\([^)]*PhysicalDrive') 'Policy bypass or unbounded raw buffering found.'
Check (@($commands|Where-Object {$_.GetCommandName()-ceq'Assert-IsolatedObservationFreshHostType'}).Count-ge2) 'Fresh-host-type refusal is missing before module/native load.'
Check (@($commands|Where-Object {$_.GetCommandName()-ceq'Pin-Source'}).Count-ge2) 'Source/framework inputs are not pinned before load.'
Check ($ast.Extent.Text-match"'/noconfig'"-and$ast.Extent.Text-match"'/nostdlib\+'"-and$ast.Extent.Text-match"Framework64\\v4.0.30319") 'Host compiler/runtime target differs.'
Check ($ast.Extent.Text-match'FileMode\]::CreateNew'-and$ast.Extent.Text-match'16MB-\$Additional') 'Fresh/bounded host artifact writes are missing.'
Check ($ast.Extent.Text-match'known_project_guards_are_not_a_durable_writer_fence=\$true') 'Ordinary project leases are misrepresented.'
[pscustomobject]@{checks=$script:checks;passed=$true;launcher_executed=$false;native_identity_calls=0;vm_operations=0;credential_accesses=0;
 device_opens=0;native_observation_calls=0;synthetic_bytes_allocated=0;production_source_files_changed=0}
