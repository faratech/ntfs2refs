<# Pure evidence guards, mocked transport and WhatIf only. No VM actions. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabVdlProbe.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($definition in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $definition.Extent.Text}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 25|ConvertFrom-Json}
function Artifact([string]$Name,[long]$Length=100,[string]$Sha=('a'*64)){[pscustomobject]@{name=$Name;length=$Length;sha256=$Sha;attributes='Archive'}}
$profile=Get-VdlHostProfile
$id='a'*32;$scriptSha='b'*64;$nativeSha='c'*64;$controlSha='d'*64
$phase='MeasureInitializedControl'
$control=Get-Content -LiteralPath (Join-Path $workspace ('.lab\hyperv\'+$profile.controlDirectory+'\after\verify.json')) -Raw|ConvertFrom-Json
$origin=Read-VdlHostPinned (Join-Path $workspace ('.lab\hyperv\'+$profile.placementDirectory+'\host-result.json')) $profile.placementHostSha256
Assert-VdlHostOrigin $origin $profile;$checks++
foreach($field in @('outcomeCheckpointId','outcomeCheckpointName','guestEvidenceSha256','probeId','vmId')){$bad=Clone $origin;$bad.$field='wrong';Reject {Assert-VdlHostOrigin $bad $profile} 'Wrong source branch accepted.'}
foreach($field in @('evidenceExported','cleanRemountVerified','remountEvidenceExported','cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored','moveCompleted')){$bad=Clone $origin;$bad.$field=$false;Reject {Assert-VdlHostOrigin $bad $profile} 'Incomplete source branch accepted.'}
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';sizeBytes=64GB;controllerLocation=0;vhdId=[guid]::NewGuid().ToString()},[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';sizeBytes=8GB;controllerLocation=2;vhdId=[guid]::NewGuid().ToString()})}
Assert-VdlHostManifest $manifest $profile;$checks++
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$field=if($field -ceq 'role'){'os'}elseif($field -ceq 'vhdId'){'wrong'}else{0};Reject {Assert-VdlHostManifest $bad $profile} 'Different target accepted.'}
$script:connected=$false;$script:secure='On'
function Get-VMNetworkAdapter {param($VM)[pscustomobject]@{SwitchName=$(if($script:connected){'external'}else{''})}}
function Get-VMFirmware {param($VM)[pscustomobject]@{SecureBoot=$script:secure}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-VdlHostVM $vm $profile.baselineId 4GB;$checks++
foreach($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=$profile.checkpointId})){$bad=Clone $vm;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-VdlHostVM $bad $profile.baselineId 4GB} 'Unsafe starting VM accepted.'}
$connected=$true;Reject {Assert-VdlHostVM $vm $profile.baselineId 4GB} 'Connected VM accepted.';$connected=$false
$secure='Off';Reject {Assert-VdlHostVM $vm $profile.baselineId 4GB} 'Changed Secure Boot accepted.';$secure='On'
$saved=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId}
Assert-VdlHostCheckpoint $saved $profile;$checks++
foreach($field in @('Id','Name','VMId')){$bad=Clone $saved;$bad.$field='wrong';Reject {Assert-VdlHostCheckpoint $bad $profile} 'Different checkpoint accepted.'}
Reject {Assert-VdlHostCheckpoint $saved $profile -Baseline} 'Saved source confused with baseline.'
$outcome=[pscustomobject]@{Id=[guid]::NewGuid().ToString();Name=('vdl-probe-data-'+$id);VMId=$profile.vmId}
Assert-VdlHostOutcome $outcome $outcome.Name $profile;$checks++
foreach($value in @($profile.checkpointId,$profile.baselineId,[guid]::Empty.ToString(),'wrong')){$bad=Clone $outcome;$bad.Id=$value;Reject {Assert-VdlHostOutcome $bad $outcome.Name $profile} 'Invalid outcome ID accepted.'}

function Snapshot([string]$Name,[bool]$Initialized) {
    $vdl=if($Initialized){65536}else{0};$usage=if($Initialized){3}else{0}
    [pscustomobject]@{name=$Name;fileId64=$(if($Initialized){$profile.fixtureId}else{'0x3000000000002799'});volumeSerialHex=$profile.volumeSerial;exactState=$true;standard=[pscustomobject]@{allocationBytes=65536;eofBytes=65536;links=1;directory=$false;deletePending=$false};cached=[pscustomobject]@{requestedUsage=1;complete=$true;prefixQualified=$true;vdlBytes=$vdl;regions=@([pscustomobject]@{offset=0;length=65536;usage=$usage})};onDisk=[pscustomobject]@{requestedUsage=2;complete=$true;prefixQualified=$true;vdlBytes=$vdl;regions=@([pscustomobject]@{offset=0;length=65536;usage=$usage})};extents=@([pscustomobject]@{startingVcn=0;nextVcn=16;lcn=$(if($Initialized){$profile.fixtureLcn}else{2000000})})}
}
function QueryBundle([string]$Phase) {
    $stage=Get-VdlHostStage $Phase;$root='C:\ntfs2refs\vdl-probe\'+$id+'\'+$stage
    $names=@(foreach($when in @('before','after')){foreach($kind in @('Standard','Cached','OnDisk','Extents')){'control-'+$when+$kind}})
    if($stage -ceq 'allocation'){$names+=@('allocation-emptyStandard','allocation-allocatedStandard');$names+=@(foreach($when in @('immediate','flushed','reopened')){foreach($kind in @('Standard','Cached','OnDisk','Extents')){'allocation-'+$when+$kind}})}
    $queries=@();$files=@((Artifact ($stage+'.json') 100 $controlSha),(Artifact 'original-before.json'),(Artifact 'original-after.json'))
    if($stage -ceq 'allocation'){$files+=Artifact 'started.json'}
    foreach($name in $names){$spec=Get-VdlHostQuerySpec $name $Phase;$length=if($name -clike '*Standard'){24}elseif($name -clike '*Extents'){32}else{40};$files+=Artifact ($name+'.bin') $length;$queries+=[pscustomobject]@{name=$name;api=$spec.api;controlCode=$spec.code;informationClass=$spec.informationClass;inputHex=$spec.inputHex;inputBytes=$spec.inputBytes;outputCapacityBytes=$spec.capacity;succeeded=$true;nativeError=0;bytesReturned=$length;bufferPath=($root+'\'+$name+'.bin');bufferSha256=('a'*64);startedUtc='2026-10-24T00:00:00Z';finishedUtc='2026-10-24T00:00:01Z'}}
    [pscustomobject]@{files=$files;queries=$queries}
}
function Response([string]$Phase,[bool]$Qualified=$true){$stage=Get-VdlHostStage $Phase;[pscustomobject]@{Phase=$Phase;MeasurementId=$id;Status=$(if($stage -ceq 'control'){'initialized-vdl-control-qualified'}else{'allocation-zero-vdl-observed'});EvidenceDirectory=('C:\ntfs2refs\vdl-probe\'+$id+'\'+$stage);ControlQualified=$Qualified;ZeroVdlQualified=($stage -ceq 'allocation');TargetWriteRequestsIssued=($stage -ceq 'allocation');MoveAttempted=$false;SetValidDataAttempted=$false;ConversionQualified=$false}}
$bundle=QueryBundle $phase;$response=Response $phase
$nativeControl=[pscustomobject]@{status='initialized-vdl-control-qualified';phase='complete';error=$null;fixturePath=('F:\fixtures\placement-'+$profile.placementProbeId+'\initialized.bin');sha256Before=$profile.fixtureSha256;sha256After=$profile.fixtureSha256;targetWriteRequestsIssued=$false;directoryCreated=$false;fileCreated=$false;allocationRequested=$false;eofRequested=$false;explicitFlushRequested=$false;controlQualified=$true;zeroVdlQualified=$false;operations=@();snapshots=@((Snapshot 'before' $true),(Snapshot 'after' $true))}
$record=[pscustomobject]@{schemaVersion=1;kind='native-vdl-probe';phase=$phase;measurementId=$id;placementProbeId=$profile.placementProbeId;placementEvidenceSha256=$profile.placementEvidenceSha256;controlEvidenceSha256='';scriptSha256=$scriptSha;nativeSourceSha256=$nativeSha;finishedUtc='2026-10-24T00:01:00Z';status=$response.Status;target=$control.target.guest;partition=$control.partition;volumeUniqueId='\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\';controlQualified=$true;zeroVdlQualified=$false;targetWriteRequestsIssued=$false;targetWriteRequestsMayHaveBeenIssued=$false;originalFixturesUnchanged=$true;newFilePayloadReads=$false;newFilePayloadWrites=$false;moveAttempted=$false;setValidDataAttempted=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;nativeQueries=$bundle.queries;controlObservation=$nativeControl}
Assert-VdlHostRecord $record $response $profile $control $bundle.files $scriptSha $nativeSha;$checks++
$export=[pscustomobject]@{record=$record;files=$bundle.files}
Check ((Assert-VdlHostAllocationGate $export $profile $scriptSha $nativeSha) -ceq $controlSha) 'Qualified control did not return the exported proof hash.'
Check (-not (Get-VdlHostDisposition $record).checkpointRequired) 'Read-only control requested a checkpoint.'
foreach($field in @('newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified','targetWriteRequestsIssued','targetWriteRequestsMayHaveBeenIssued')){$bad=Clone $record;$bad.$field=$true;Reject {Assert-VdlHostRecord $bad $response $profile $control $bundle.files $scriptSha $nativeSha} 'Unsafe control evidence accepted.'}
foreach($field in @('measurementId','placementProbeId','placementEvidenceSha256','scriptSha256','nativeSourceSha256','controlEvidenceSha256','volumeUniqueId','finishedUtc')){$bad=Clone $record;$bad.$field=if($field -ceq 'controlEvidenceSha256'){'bad'}else{''};Reject {Assert-VdlHostRecord $bad $response $profile $control $bundle.files $scriptSha $nativeSha} "Missing or changed control provenance accepted: $field."}
foreach($field in @('ControlQualified','ZeroVdlQualified','TargetWriteRequestsIssued')){$bad=Clone $response;$bad.$field='false';Reject {Assert-VdlHostResponse $bad $id $phase} 'Stringified response boolean accepted.'}
foreach($change in @(@{name='..\control.json'},@{name='allocation.json'},@{length=0},@{length=(1MB+1)},@{sha256='bad'},@{attributes='ReparsePoint'},@{attributes='Directory'})){$bad=Artifact 'control.json';foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-VdlHostArtifact $bad $phase} 'Invalid export artifact accepted.'}
foreach($kind in @('Standard','Cached','OnDisk','Extents')){$name='control-before'+$kind+'.bin';$maximum=(Get-VdlHostQuerySpec ('control-before'+$kind) $phase).capacity;Assert-VdlHostArtifact (Artifact $name $maximum) $phase;$checks++;Reject {Assert-VdlHostArtifact (Artifact $name ($maximum+1)) $phase} 'Oversized native output accepted.'}
Reject {Assert-VdlHostArtifactSet @() $phase} 'Empty export accepted.'
Reject {Assert-VdlHostArtifactSet @((Artifact 'control.json'),(Artifact 'control.json')) $phase} 'Duplicate export accepted.'
Reject {Get-VdlHostQuerySpec 'allocation-emptyStandard' $phase} 'Allocation query in measurement accepted.'
Reject {Get-VdlHostQuerySpec "control-beforeStandard`n" $phase} 'Trailing newline in query accepted.'
foreach($field in @('api','controlCode','informationClass','inputHex','inputBytes','outputCapacityBytes','bytesReturned','bufferPath','bufferSha256','finishedUtc')){$bad=Clone $record;$bad.nativeQueries[0].$field=if($field -cin @('informationClass','inputBytes','outputCapacityBytes','bytesReturned')){9999}elseif($field -ceq 'finishedUtc'){''}else{'bad'};Reject {Assert-VdlHostRecord $bad $response $profile $control $bundle.files $scriptSha $nativeSha} "Invalid query provenance accepted: $field."}
$bad=Clone $record;$bad.nativeQueries+=Clone $bad.nativeQueries[0];Reject {Assert-VdlHostRecord $bad $response $profile $control $bundle.files $scriptSha $nativeSha} 'Duplicate query accepted.'
foreach($change in @(@{status='blocked'},@{controlQualified=$false},@{originalFixturesUnchanged=$false},@{scriptSha256=('e'*64)},@{nativeSourceSha256=('e'*64)},@{targetWriteRequestsIssued=$true})){$bad=Clone $export;foreach($key in $change.Keys){$bad.record.$key=$change[$key]};Reject {Assert-VdlHostAllocationGate $bad $profile $scriptSha $nativeSha} 'Unqualified stage one allowed allocation.'}
foreach($change in @(@{fileId64='0x3000000000002799'},@{volumeSerialHex='0x00000000'},@{exactState=$false})){$bad=Clone $nativeControl.snapshots[0];foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-VdlHostSnapshot $bad 65536 $profile -Control} 'Changed initialized control accepted.'}
$bad=Clone $nativeControl.snapshots[0];$bad.cached.regions[0].offset=1;Reject {Assert-VdlHostSnapshot $bad 65536 $profile -Control} 'Incomplete VDL region coverage accepted.'
$bad=Clone $nativeControl.snapshots[0];$bad.onDisk.vdlBytes=0;Reject {Assert-VdlHostSnapshot $bad 65536 $profile -Control} 'Wrong initialized VDL accepted.'
$bad=Clone $nativeControl.snapshots[0];$bad.extents[0].lcn++;Reject {Assert-VdlHostSnapshot $bad 65536 $profile -Control} 'Moved initialized control accepted.'

# A returned, unsuccessful native query remains exportable, but cannot unlock allocation.
$blocked=Clone $record;$blocked.controlQualified=$false;$blocked.status='initialized-vdl-control-unresolved';$blocked.controlObservation.controlQualified=$false;$blocked.controlObservation.status=$blocked.status
$blockedResponse=Clone $response;$blockedResponse.ControlQualified=$false;$blockedResponse.Status=$blocked.status
$blocked.nativeQueries[1].succeeded=$false;$blocked.nativeQueries[1].nativeError=1;$blocked.nativeQueries[1].bytesReturned=0;$blocked.nativeQueries[1].bufferPath=$null;$blocked.nativeQueries[1].bufferSha256=$null
$blockedFiles=@($bundle.files|Where-Object name -CNE 'control-beforeCached.bin')
Assert-VdlHostRecord $blocked $blockedResponse $profile $control $blockedFiles $scriptSha $nativeSha;$checks++
Check (-not (Get-VdlHostDisposition $blocked).checkpointRequired) 'Determinate blocked query cannot cleanly stop.'
Reject {Assert-VdlHostAllocationGate ([pscustomobject]@{record=$blocked;files=$blockedFiles}) $profile $scriptSha $nativeSha} 'Blocked API control allowed allocation.'
$bad=Clone $blocked;$bad.originalFixturesUnchanged=$false;Reject {Get-VdlHostDisposition $bad} 'Changed original fixture allowed cleanup.'

$allocationPhase='AllocateZeroVdl';$allocationResponse=Response $allocationPhase;$allocationBundle=QueryBundle $allocationPhase
$allocation=Clone $record;$allocation.phase=$allocationPhase;$allocation.status=$allocationResponse.Status;$allocation.controlEvidenceSha256=$controlSha;$allocation.zeroVdlQualified=$true;$allocation.targetWriteRequestsIssued=$true;$allocation.targetWriteRequestsMayHaveBeenIssued=$true;$allocation.nativeQueries=$allocationBundle.queries
$nativeAllocation=[pscustomobject]@{status='allocation-zero-vdl-observed';phase='complete';error=$null;fixturePath=('F:\fixtures\vdl-'+$id+'\uninitialized.bin');sha256Before=$null;sha256After=$null;targetWriteRequestsIssued=$true;directoryCreated=$true;fileCreated=$true;allocationRequested=$true;eofRequested=$true;explicitFlushRequested=$true;privateAclVerified=$true;zeroVdlQualified=$true;snapshots=@((Snapshot 'immediate' $false),(Snapshot 'flushed' $false),(Snapshot 'reopened' $false));operations=@([pscustomobject]@{name='FileAllocationInfo';inputHex='0000010000000000';succeeded=$true;nativeError=0;finishedUtc='now'},[pscustomobject]@{name='FileEndOfFileInfo';inputHex='0000010000000000';succeeded=$true;nativeError=0;finishedUtc='now'},[pscustomobject]@{name='FlushFileBuffers';inputHex='';succeeded=$true;nativeError=0;finishedUtc='now'})}
$allocation|Add-Member allocationObservation $nativeAllocation
Assert-VdlHostRecord $allocation $allocationResponse $profile $control $allocationBundle.files $scriptSha $nativeSha $controlSha;$checks++
$disposition=Get-VdlHostDisposition $allocation;Check ($disposition.checkpointRequired -and $disposition.fileCreated) 'New file can be discarded without an outcome checkpoint.'
foreach($field in @('fileCreated','directoryCreated','targetWriteRequestsIssued','allocationRequested','eofRequested','explicitFlushRequested')){$bad=Clone $allocation;$bad.allocationObservation.$field=$null;Reject {Get-VdlHostDisposition $bad} 'Unknown allocation outcome allowed cleanup.'}
$bad=Clone $allocation;$bad.PSObject.Properties.Remove('allocationObservation');Reject {Get-VdlHostDisposition $bad} 'Missing allocation completion allowed cleanup.'
$bad=Clone $allocation;$bad.allocationObservation.operations[0].finishedUtc='';Reject {Get-VdlHostDisposition $bad} 'Unfinished native operation allowed cleanup.'
$bad=Clone $allocation;$bad.allocationObservation.sha256After='a'*64;Reject {Get-VdlHostDisposition $bad} 'New-file payload hash accepted.'
$bad=Clone $allocation;$bad.allocationObservation.operations[0].inputHex='0000020000000000';Reject {Get-VdlHostDisposition $bad} 'Unbounded allocation input accepted.'
$bad=Clone $allocation;$bad.allocationObservation.snapshots[2].cached.vdlBytes=65536;Reject {Assert-VdlHostRecord $bad $allocationResponse $profile $control $allocationBundle.files $scriptSha $nativeSha $controlSha} 'Nonzero allocation VDL qualified.'
Reject {Assert-VdlHostRecord $allocation $allocationResponse $profile $control $allocationBundle.files $scriptSha $nativeSha ('e'*64)} 'Different prior control hash accepted.'
$partial=Clone $allocation;$partial.zeroVdlQualified=$false;$partial.status='blocked';$partial.allocationObservation.status='blocked';$partial.allocationObservation.zeroVdlQualified=$false;$partial.allocationObservation.phase='private-create';$partial.allocationObservation.fileCreated=$false;$partial.allocationObservation.allocationRequested=$false;$partial.allocationObservation.eofRequested=$false;$partial.allocationObservation.explicitFlushRequested=$false;$partial.allocationObservation.operations=@()
Check (Get-VdlHostDisposition $partial).checkpointRequired 'Created directory or attempted writes discarded without checkpoint.'

# Actual command wrapper, remoting primitives mocked. Incomplete calls stay unknown.
$session='mock-session';$script:scenario='success';$script:removed=0;$script:commandIndeterminate=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock)Check $script:commandIndeterminate 'Dispatch did not set unknown completion.';if($script:scenario -ceq 'dispatch-failure'){throw 'transport failed'};[pscustomobject]@{State=$(if($script:scenario -ceq 'timeout'){'Running'}elseif($script:scenario -ceq 'receive-failure'){'Failed'}else{'Completed'})}}
function Wait-Job {param($Job,$Timeout)if($script:scenario -cne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)if($script:scenario -ceq 'receive-failure'){throw 'transport lost'};'answer'}
function Remove-Job {param($Job,[switch]$Force)$script:removed++}
$answer=@(Invoke-BoundedVdlCommand -ScriptBlock {} -TimeoutSeconds 30)
Check ($answer.Count -eq 1 -and $answer[0] -ceq 'answer' -and -not $script:commandIndeterminate -and $script:removed -eq 1) 'Completed command not recognized.'
foreach($testScenario in @('dispatch-failure','receive-failure','timeout')){$script:scenario=$testScenario;$script:removed=0;$script:commandIndeterminate=$false;Reject {Invoke-BoundedVdlCommand -ScriptBlock {} -TimeoutSeconds 30} 'Incomplete command accepted.';Check $script:commandIndeterminate 'Unknown completion cleared.';if($testScenario -ceq 'timeout'){Check ($script:removed -eq 0) 'Running job forcibly removed.'}}
$commands=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($commands|Where-Object{$_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Stop-VM','Stop-Job','Set-VMFirmware','Checkpoint-VM')}).Count -eq 0) 'Unexpected host mutation or forced stop.'
$topTry=$ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]}|Select-Object -Last 1
$catchCommands=@($topTry.CatchClauses[0].FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($catchCommands|Where-Object{$_ -in @('Invoke-LabAction','Stop-VdlHostGuest','Set-VMMemory','Remove-Job')}).Count -eq 0) 'Failure handler mutates preserved branch.'
$text=$ast.Extent.Text
Check ($text.IndexOf('$record.controlEvidenceExported=$true') -lt $text.IndexOf('$controlSha=Assert-VdlHostAllocationGate')) 'Allocation gate precedes exported control.'
Check ($text.IndexOf('Save-VdlHostProgress # Durable intent') -lt $text.IndexOf('-Phase AllocateZeroVdl -PlacementProbeId')) 'Allocation intent not durable before dispatch.'
Check ($text.IndexOf('$record.allocationEvidenceExported=$true') -lt $text.IndexOf('    Stop-VdlHostGuest')) 'Shutdown precedes exported allocation evidence.'
Check ($text.IndexOf('$record.outcomeCheckpointCreated=$true') -lt $text.IndexOf("`$record.phase='restore-baseline'")) 'Baseline restore precedes outcome checkpoint.'
$dry=& $path -WhatIf
Check ($dry.DryRun -and $dry.MemoryBytes -eq 8GB -and $dry.MaximumNewFileBytes -eq 65536 -and -not $dry.NewFilePayloadReads -and -not $dry.NewFilePayloadWrites -and -not $dry.MoveAttempted -and -not $dry.SetValidDataAttempted -and -not $dry.ConversionQualified) 'WhatIf contract failed.'
"Lab VDL probe: $checks checks passed."
