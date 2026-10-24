<# Injected VM snapshots only; no Hyper-V imports, management calls, or artifact writes. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$bad=$false;try{&$Body|Out-Null}catch{$bad=$true};Check $bad $Name}
$workspace=Split-Path -Parent $PSScriptRoot;$baseline='eda059b3-6d50-46bb-bdf4-018b99b5b34f';$vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'
$script:manifest=[pscustomobject]@{vmId=$vmId};$script:configuration=[pscustomobject]@{mock=$true}
foreach($spec in @(@('scripts/Invoke-LabRetainedNativeProbe.ps1',@('Wait-RetainedProbeRestored','Complete-RetainedProbeBaseline')),@('scripts/Invoke-LabRetainedPreparation.ps1',@('Assert-RetainedPreparationVM')))){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $spec[0]),[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'Production source parses.'
 foreach($name in $spec[1]){$defs=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$true));Check ($defs.Count-eq1) 'Exactly one reviewed function.';. ([scriptblock]::Create($defs[0].Extent.Text))}
}
function Snapshot([string]$State='Off',[string]$Parent=$baseline,[long]$Memory=4GB,[bool]$Dynamic=$false){[pscustomobject]@{Id=$vmId;State=$State;ParentSnapshotId=$Parent;MemoryStartup=$Memory;DynamicMemoryEnabled=$Dynamic;Generation=2}}
function Reset([object[]]$Sequence){$script:sequence=$Sequence;$script:reads=0;$script:sets=0;$script:sleeps=0;$script:saved=0;$script:firmwareReads=0;$script:secureBoot='On';$script:networks=@();$script:record=[ordered]@{baselineRestored=$false;memoryRestored=$false};$script:phase='restore-baseline';$script:failSet=$false;$script:firstFirmwareOff=$false;$script:failSave=$false;$script:queryDelayMilliseconds=0}
function Get-OwnedLabVM{param($Configuration,$Manifest);Check ($Configuration.mock-and$Manifest.vmId-ceq$vmId) 'Exact ownership context passed.';$i=[Math]::Min($script:reads,$script:sequence.Count-1);$script:reads++;if($script:queryDelayMilliseconds){[Threading.Thread]::Sleep($script:queryDelayMilliseconds)};$item=$script:sequence[$i];if($item-is[string]){throw $item};$item}
function Get-VMFirmware{param($VM);$script:firmwareReads++;[pscustomobject]@{SecureBoot=$(if($script:firstFirmwareOff-and$script:firmwareReads-eq1){'Off'}else{$script:secureBoot})}}
function Get-VMNetworkAdapter{param($VM);$script:networks}
function Set-VMMemory{param($VM,$StartupBytes,$DynamicMemoryEnabled);$script:sets++;Check ($VM.Id-ceq$vmId-and$VM.State-ceq'Off'-and$VM.ParentSnapshotId-ceq$baseline-and$StartupBytes-eq4GB-and$DynamicMemoryEnabled-is[bool]-and-not$DynamicMemoryEnabled) 'Memory change requires observed exact off baseline.';if($script:failSet){throw 'mock memory operation failed'}}
function Start-Sleep{param($Milliseconds);Check ($Milliseconds-ge1-and$Milliseconds-le1000) 'Bounded one-second polling interval.';$script:sleeps++}
function Save-RetainedProbeProgress{$script:saved++;if($script:failSave){throw 'mock evidence persistence failed'}}
function Invoke-LabAction{throw 'Readiness must never restore/start a VM.'}
function Start-VM{throw 'Readiness must never start a VM.'}
function Stop-VM{throw 'Readiness must never stop a VM.'}

Reset @((Snapshot));Complete-RetainedProbeBaseline $baseline
Check ($script:reads-eq2-and$script:sets-eq0-and$script:sleeps-eq0-and$script:saved-eq2) 'Already ready baseline needs no mutation.'
Check ($record.restoreReadinessObservations.Count-eq2-and$record.restoreReadinessObservations[0].expectedMemoryBytes-eq0-and$record.restoreReadinessObservations[1].expectedMemoryBytes-eq4GB) 'Both baseline stages recorded.'
Check (-not$record.baselineRestored-and-not$record.memoryRestored) 'Helper never marks enclosing workflow successful.'
$old=[guid]::NewGuid().ToString('D')
Reset @((Snapshot Off $old 8GB),(Snapshot Restoring $baseline 8GB),(Snapshot Off $baseline 8GB),(Snapshot Off $baseline 8GB),(Snapshot))
Complete-RetainedProbeBaseline $baseline
Check ($script:reads-eq5-and$script:sets-eq1-and$script:sleeps-eq3-and$script:saved-eq5) 'Delayed parent/state and delayed memory converge without restoring again.'
Check (@($record.restoreReadinessObservations|Where-Object ready).Count-eq2) 'Only exact stage matches marked ready.'
Check ($record.restoreReadinessObservations[0].parentSnapshotId-ceq$old-and$record.restoreReadinessObservations[1].state-ceq'Restoring'-and$record.restoreReadinessObservations[3].memoryStartup-eq8GB) 'Diagnostics retain transient values.'
foreach($o in $record.restoreReadinessObservations){Check ($o.vmId-ceq$vmId-and$o.expectedParent-ceq$baseline-and$o.attempt-ge1-and$o.attempt-le31-and$o.elapsedMilliseconds-ge0-and$o.observedUtc-and$o.phase-ceq'restore-baseline') 'Bounded observation provenance.'}
Reset @('mock transient query error',(Snapshot));Complete-RetainedProbeBaseline $baseline
Check ($script:reads-eq3-and$script:sets-eq0-and$record.restoreReadinessObservations[0].error-ceq'mock transient query error'-and-not$record.restoreReadinessObservations[0].ready) 'Transient query error is preserved before fresh success.'
Reset @((Snapshot));$script:firstFirmwareOff=$true;Complete-RetainedProbeBaseline $baseline
Check ($script:reads-eq3-and$script:sets-eq0-and$record.restoreReadinessObservations[1].error-and-not$record.restoreReadinessObservations[1].ready) 'Full guard refusal is recorded, never treated as ready.'
foreach($bad in @((Snapshot Running),(Snapshot Restoring),(Snapshot Off $old),'mock persistent query failure')){
 Reset @($bad);Reject {Complete-RetainedProbeBaseline $baseline} 'Persistent wrong state/parent/query must refuse.'
 Check ($script:reads-eq31-and$script:sets-eq0-and$script:sleeps-eq30-and$script:saved-eq31) 'Pre-memory refusal exhausts only bounded observations.'
 Check (@($record.restoreReadinessObservations|Where-Object ready).Count-eq0) 'Refused observations never qualify.'
}
$wrong=Snapshot;$wrong.Id=[guid]::NewGuid().ToString('D');Reset @($wrong);Reject {Complete-RetainedProbeBaseline $baseline} 'Wrong VM identity refuses.';Check ($script:sets-eq0-and$script:reads-eq31) 'No mutation against wrong identity.'
foreach($bad in @((Snapshot Off $baseline 8GB),(Snapshot Off $baseline 4GB $true))){
 Reset @($bad);Reject {Complete-RetainedProbeBaseline $baseline} 'Persistent wrong memory policy refuses.'
 Check ($script:sets-eq1-and$script:reads-eq32-and$script:saved-eq32) 'Memory set is never retried and final readiness stays bounded.'
}
foreach($guard in @('firmware','network','generation')){
 $v=Snapshot;Reset @($v);if($guard-ceq'firmware'){$script:secureBoot='Off'}elseif($guard-ceq'network'){$script:networks=@([pscustomobject]@{SwitchName='unexpected'})}else{$v.Generation=1}
 Reject {Complete-RetainedProbeBaseline $baseline} 'Final full VM guard remains strict.'
 Check ($script:sets-eq0-and$script:reads-eq32-and$record.restoreReadinessObservations[-1].error) 'Full guard failure preserves diagnostics.'
}
Reset @((Snapshot Off $baseline 8GB));$script:failSet=$true;Reject {Complete-RetainedProbeBaseline $baseline} 'Memory failure propagates without retry.';Check ($script:reads-eq1-and$script:sets-eq1-and$script:saved-eq1) 'Memory failure retains first observation.'
Reset @((Snapshot));$script:failSave=$true;Reject {Complete-RetainedProbeBaseline $baseline} 'Evidence persistence failure propagates.';Check ($script:reads-eq1-and$script:sets-eq0) 'No memory work after evidence failure.'
Reset @((Snapshot));Reject {Complete-RetainedProbeBaseline ([guid]::Empty.ToString('D'))} 'Empty baseline pin refused.';Check ($script:reads-eq0-and$script:sets-eq0) 'Invalid pin makes no management read.'
Reset @((Snapshot));Reject {Wait-RetainedProbeRestored $baseline 16GB} 'Unexpected memory profile refuses.';Check ($script:reads-eq0) 'Bad memory profile does not query.'
Reset @((Snapshot));$script:queryDelayMilliseconds=1100;Reject {Wait-RetainedProbeRestored $baseline 0 -TimeoutSeconds 1} 'An otherwise matching query returned after the monotonic deadline refuses.'
Check ($script:reads-eq1-and$script:sleeps-eq0-and$script:sets-eq0-and$record.restoreReadinessObservations.Count-eq1-and-not$record.restoreReadinessObservations[0].ready-and$record.restoreReadinessObservations[0].elapsedMilliseconds-ge1000) 'Expired query cannot qualify or cause another poll/mutation.'
Reset @((Snapshot));foreach($seconds in @(0,31)){Reject {Wait-RetainedProbeRestored $baseline 0 -TimeoutSeconds $seconds} 'Deadline cannot exceed the fixed production cap or be disabled.'};Check ($script:reads-eq0) 'Invalid deadline makes no query.'

# Initial selected/prepared restore waits only observe: no memory correction is permitted.
Reset @((Snapshot Off $baseline 4GB),(Snapshot Restoring $old 8GB),(Snapshot Off $old 8GB));$script:phase='restore-selected'
$ready=Wait-RetainedProbeRestored $old 8GB
Check ($ready.ParentSnapshotId-ceq$old-and$script:reads-eq3-and$script:sets-eq0-and$script:sleeps-eq2) 'Initial delayed restore reaches exact 8GiB checkpoint without mutation.'
Check ($record.restoreReadinessObservations[-1].expectedMemoryBytes-eq8GB-and$record.restoreReadinessObservations[-1].phase-ceq'restore-selected') 'Initial restore diagnostics distinguish branch/profile.'
Reset @((Snapshot Off $old 4GB));Reject {Wait-RetainedProbeRestored $old 8GB} 'Initial wrong memory refuses.';Check ($script:sets-eq0-and$script:reads-eq31) 'Initial wrong profile never sets memory or starts.'

foreach($name in @('Invoke-LabRetainedNativeProbe.ps1','Invoke-LabNativeReconstruct.ps1','Invoke-LabConvertedVerification.ps1')){
 $text=[IO.File]::ReadAllText((Join-Path $workspace ('scripts/'+$name)));$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'All integrated runners parse.'
 Check ([regex]::Matches($text,'Complete-RetainedProbeBaseline \$baselineId').Count-eq1) 'Exactly one shared baseline completion per runner.'
 Check ($text.Contains('Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null;Complete-RetainedProbeBaseline $baselineId')) 'Baseline readiness follows the single restore.'
 Check ($text.IndexOf('Complete-RetainedProbeBaseline $baselineId')-lt$text.IndexOf('$record.baselineRestored=$true')) 'Success flags follow strict readiness.'
 Check (-not$text.Contains("throw 'Restored baseline differs.'")) 'Immediate transient-state assertion removed.'
 $selected=if($name-ceq'Invoke-LabRetainedNativeProbe.ps1'){'$prepared.outcomeCheckpointId'}else{'$selectedId'}
 Check ($text.Contains(('Out-Null;Wait-RetainedProbeRestored '+$selected+' 8GB|Out-Null'))) 'Initial checkpoint restore also waits.'
 Check ($text.IndexOf(('Wait-RetainedProbeRestored '+$selected+' 8GB|Out-Null'))-lt$text.IndexOf('Invoke-LabAction -Action Start')) 'First Start follows exact initial readiness.'
 if($name-cne'Invoke-LabRetainedNativeProbe.ps1'){Check ($text.Contains("'Wait-RetainedProbeRestored','Complete-RetainedProbeBaseline'")) 'Helpers imported from pinned reviewed source.'}
}
Write-Output ('PASS: '+$script:checks+' checkpoint readiness mock/integration checks; no VM, device, or artifact writes.')
