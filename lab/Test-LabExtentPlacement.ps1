<# Pure guards, mocked transport failures and WhatIf only; no VM actions. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabExtentPlacement.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($name in @('Get-ExtentPlacementProfile','Assert-ExtentPlacementManifest','Assert-ExtentPlacementVM','Assert-ExtentPlacementCheckpoint','Assert-ExtentPlacementResponse','Assert-ExtentPlacementArtifact','Assert-ExtentPlacementArtifactSet','Assert-ExtentPlacementRecord','Assert-ExtentPlacementObservation','Assert-ExtentPlacementSameObservation','Assert-ExtentPlacementCompleted','Assert-ExtentPlacementRemount','Assert-ExtentPlacementRemountArtifacts','Assert-ExtentPlacementOutcomeCheckpoint','Invoke-BoundedPlacementCommand')) {
    $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
    Invoke-Expression $definition.Extent.Text
}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
$profile=Get-ExtentPlacementProfile
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';sizeBytes=64GB;controllerLocation=0;vhdId=[guid]::NewGuid().ToString()},[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';sizeBytes=8GB;controllerLocation=2;vhdId=[guid]::NewGuid().ToString()})}
Assert-ExtentPlacementManifest $manifest $profile; $checks++
$bad=Clone $manifest;$bad.vmId=[guid]::NewGuid().ToString();Reject {Assert-ExtentPlacementManifest $bad $profile} 'Different VM accepted.'
$bad=Clone $manifest;$bad.disks=$bad.disks[0..1];Reject {Assert-ExtentPlacementManifest $bad $profile} 'Missing journal accepted.'
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$field=if($field -ceq 'role'){'os'}elseif($field -ceq 'vhdId'){[guid]::NewGuid().ToString()}else{0};Reject {Assert-ExtentPlacementManifest $bad $profile} "Bad target $field accepted."}
$script:connected=$false;$script:secure='On'
function Get-VMNetworkAdapter {param($VM)[pscustomobject]@{SwitchName=$(if($script:connected){'external'}else{''})}}
function Get-VMFirmware {param($VM)[pscustomobject]@{SecureBoot=$script:secure}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-ExtentPlacementVM $vm $profile.baselineId 4GB;$checks++
foreach($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=$profile.checkpointId})){$bad=Clone $vm;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentPlacementVM $bad $profile.baselineId 4GB} 'Unsafe VM start state accepted.'}
$connected=$true;Reject {Assert-ExtentPlacementVM $vm $profile.baselineId 4GB} 'Connected network accepted.';$connected=$false
$secure='Off';Reject {Assert-ExtentPlacementVM $vm $profile.baselineId 4GB} 'Changed Secure Boot accepted.';$secure='On'
$saved=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId}
Assert-ExtentPlacementCheckpoint $saved $profile;$checks++
$baseline=[pscustomobject]@{Id=$profile.baselineId;Name='installed-clean';VMId=$profile.vmId}
Assert-ExtentPlacementCheckpoint $baseline $profile -Baseline;$checks++
foreach($field in @('Id','Name','VMId')){$bad=Clone $saved;$bad.$field='other';Reject {Assert-ExtentPlacementCheckpoint $bad $profile} 'Different saved checkpoint accepted.'}
Reject {Assert-ExtentPlacementCheckpoint $saved $profile -Baseline} 'Native checkpoint confused with installed-clean.'
$outcome=[pscustomobject]@{Id=[guid]::NewGuid().ToString();Name='extent-placement-data-test';VMId=$profile.vmId}
Assert-ExtentPlacementOutcomeCheckpoint $outcome $outcome.Name $profile;$checks++
foreach($change in @(@{Id=$profile.checkpointId},@{Id=$profile.baselineId},@{Id=[guid]::Empty.ToString()},@{Id='bad'},@{Name='old'},@{VMId=[guid]::NewGuid().ToString()})){$bad=Clone $outcome;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentPlacementOutcomeCheckpoint $bad $outcome.Name $profile} 'Invalid outcome checkpoint accepted.'}
$id='a'*32
$response=[pscustomobject]@{ProbeId=$id;Status='native-placement-observed-awaiting-remount';EvidenceDirectory=('C:\ntfs2refs\extent-placement\'+$id);FixturePath=('F:\fixtures\placement-'+$id+'\initialized.bin');TargetWriteRequestsIssued=$true;MoveAttempted=$true;MoveCompleted=$true;CleanRemountVerified=$false;PhysicalMappingVerified=$false;ConversionQualified=$false}
Assert-ExtentPlacementResponse $response $id;$checks++
foreach($change in @(@{ProbeId=('b'*32)},@{Status='converted'},@{EvidenceDirectory='C:\Windows'},@{FixturePath='F:\other.bin'},@{MoveAttempted=$false},@{TargetWriteRequestsIssued=$false},@{MoveCompleted='true'},@{CleanRemountVerified=$true},@{PhysicalMappingVerified=$true},@{ConversionQualified=$true})){$bad=Clone $response;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentPlacementResponse $bad $id} 'Invalid placement response accepted.'}
$blockedResponse=Clone $response;$blockedResponse.Status='blocked';$blockedResponse.MoveAttempted=$false;$blockedResponse.MoveCompleted=$false
Assert-ExtentPlacementResponse $blockedResponse $id;$checks++ # blocked does not imply no target writes
function Artifact([string]$Name,[long]$Length,[string]$Sha=('a'*64)){[pscustomobject]@{name=$Name;length=$Length;sha256=$Sha;attributes='Archive'}}
$json=Artifact 'placement.json' 1024
$pattern=Artifact 'expected-pattern.bin' 65536 ('b'*64)
Assert-ExtentPlacementArtifactSet @($json,$pattern);$checks++
foreach($change in @(@{name='..\placement.json'},@{name='payload.raw'},@{length=0},@{length=(1MB+1)},@{sha256='bad'},@{attributes='ReparsePoint'})){$bad=Clone $json;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentPlacementArtifact $bad} 'Unsafe artifact accepted.'}
foreach($spec in @(@('expected-pattern.bin',65536),@('originalBeforeExtents.bin',16400),@('originalAfterExtents.bin',16400),@('beforeExtents.bin',272),@('afterExtents.bin',272),@('candidateBitmap.bin',2MB),@('candidateMetadataBitmap.bin',2MB))){$file=Artifact $spec[0] $spec[1];Assert-ExtentPlacementArtifact $file;$checks++;$file.length++;Reject {Assert-ExtentPlacementArtifact $file} 'Oversized native artifact accepted.';$file.length=0;Reject {Assert-ExtentPlacementArtifact $file} 'Empty native artifact accepted.'}
Reject {Assert-ExtentPlacementArtifact (Artifact 'expected-pattern.bin' 65535)} 'Partial expected pattern accepted.'
Assert-ExtentPlacementArtifact (Artifact 'beforeExtents.bin' 1);$checks++ # malformed nonempty replies remain exportable
Reject {Assert-ExtentPlacementArtifactSet @()} 'Empty export accepted.'
Reject {Assert-ExtentPlacementArtifactSet @($pattern)} 'Missing primary JSON accepted.'
Reject {Assert-ExtentPlacementArtifactSet @($json,$json)} 'Duplicate export names accepted.'
$remountFiles=@((Artifact 'identity.json' 1024),(Artifact 'allocation-remount.json' 1024))
Assert-ExtentPlacementRemountArtifacts $remountFiles;$checks++
Reject {Assert-ExtentPlacementRemountArtifacts @($remountFiles[0])} 'Incomplete remount export accepted.'
foreach($change in @(@{name='placement.json'},@{length=(1MB+1)},@{attributes='ReparsePoint'},@{sha256='bad'})){$bad=Clone $remountFiles;foreach($key in $change.Keys){$bad[0].$key=$change[$key]};Reject {Assert-ExtentPlacementRemountArtifacts $bad} 'Invalid remount export accepted.'}

# Load only previously exported native evidence. No native API or VM action is invoked.
$controlRoot=Join-Path $workspace '.lab\hyperv\devdrive\win11-20261023T230635404Z\after'
$control=Get-Content -LiteralPath (Join-Path $controlRoot 'verify.json') -Raw|ConvertFrom-Json
$capturedAllocation=Get-Content -LiteralPath (Join-Path $controlRoot 'allocation-after.json') -Raw|ConvertFrom-Json
$captured=($capturedAllocation.files|Where-Object path -CEQ 'fixtures\nonresident.bin').observation
$scriptSha='c'*64;$nativeSha='d'*64;$collectorSha='e'*64
$before=[pscustomobject]@{length=65536;sha256=$pattern.sha256;fileId64='0x3000000000004701';volumeSerialHex=$captured.volumeSerialHex;extents=@([pscustomobject]@{startingVcn=0;nextVcn=16;lcn=1600000})}
$after=Clone $before;$after.extents[0].lcn=65536
$record=[pscustomobject]@{schemaVersion=1;kind='native-initialized-file-placement';phase='InitializedFilePlacement';nativePhase='complete';probeId=$id;status=$response.Status;controlRunId=$profile.controlRunId;controlEvidenceSha256=$profile.controlEvidenceSha256;capturedAllocationSha256=$profile.capturedAllocationSha256;scriptSha256=$scriptSha;nativeSourceSha256=$nativeSha;target=$control.target.guest;partition=$control.partition;volumeUniqueId=$capturedAllocation.volume.uniqueId;fixturePath=$response.FixturePath;maximumFixtureBytes=65536;maximumMoveCalls=1;requestedVcn=0;requestedClusters=16;requestedLcn=65536;moveCallCount=1;bitmapCandidateIsReservation=$false;rawMetadataAddressEquivalenceVerified=$false;targetWriteRequestsIssued=$true;fixtureCreated=$true;fixtureFullyInitialized=$true;creationFlushed=$true;moveAttempted=$true;moveCompleted=$true;contentPreserved=$true;originalUnchanged=$true;originalIndependentObservationUnchanged=$true;requestedPlacementObserved=$true;cleanRemountVerified=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;privilegeAdjustmentAttempted=$false;rawDiskWrites=$false;expectedSha256=$pattern.sha256;before=$before;after=$after;originalBefore=$captured;originalAfter=$captured;nativeQueries=@()}
$files=@($json,$pattern,(Artifact 'started.json' 1024),(Artifact 'allocation-before.json' 1024),(Artifact 'allocation-after.json' 1024))
foreach($name in @('originalBeforeExtents','beforeExtents','candidateBitmap','candidateMetadataBitmap','move','afterExtents','originalAfterExtents')){
    $move=$name -ceq 'move';$extended=$name -ceq 'candidateMetadataBitmap'
    $capacity=if($move){0}elseif($name -clike 'original*'){16400}elseif($name -clike '*Extents'){272}else{2MB}
    $input=if($move){32}elseif($extended){16}else{8}
    $hex=if($move){'0100000000000000000000000000000000000100000000001000000000000000'}elseif($extended){'00000000000000000100000000000000'}else{'0000000000000000'}
    $code=if($move){'0x00090074'}elseif($name -clike '*Extents'){'0x00090073'}else{'0x0009006f'}
    $query=[pscustomobject]@{name=$name;controlCode=$code;inputBytes=$input;inputHex=$hex;outputCapacityBytes=$capacity;succeeded=$true;nativeError=0;bytesReturned=$(if($move){0}else{32});bufferPath=$(if($move){$null}else{$response.EvidenceDirectory+'\'+$name+'.bin'});bufferSha256=$(if($move){$null}else{'f'*64})}
    $record.nativeQueries+=$query
    if(-not $move){$files+=Artifact ($name+'.bin') 32 ('f'*64)}
}
Assert-ExtentPlacementArtifactSet $files;$checks++
Assert-ExtentPlacementRecord $record $response $profile $control $files $scriptSha $nativeSha;$checks++
Assert-ExtentPlacementCompleted $record $captured $files;$checks++
foreach($field in @('schemaVersion','kind','phase','probeId','status','controlRunId','controlEvidenceSha256','capturedAllocationSha256','scriptSha256','nativeSourceSha256','fixturePath','maximumFixtureBytes','maximumMoveCalls','requestedVcn','requestedClusters','moveCallCount')){$bad=Clone $record;$bad.$field=if($field -cin @('schemaVersion','maximumFixtureBytes','maximumMoveCalls','requestedVcn','requestedClusters','moveCallCount')){999}else{'wrong'};Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} "Changed $field accepted."}
foreach($field in @('cleanRemountVerified','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified','privilegeAdjustmentAttempted','rawDiskWrites','bitmapCandidateIsReservation','rawMetadataAddressEquivalenceVerified')){$bad=Clone $record;$bad.$field=$true;Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Unsupported qualification accepted.'}
foreach($field in @('targetWriteRequestsIssued','moveAttempted','moveCompleted')){$bad=Clone $record;$bad.$field=$false;Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Conflicting operation flag accepted.'}
foreach($field in @('role','uniqueId','sizeBytes','location')){$bad=Clone $record;$bad.target.$field='wrong';Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Changed target accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $record;$bad.partition.$field='wrong';Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Changed GPT or geometry accepted.'}
foreach($change in @(@{name='bad'},@{controlCode='0x00090074'},@{inputBytes=32},@{inputHex='bad'},@{outputCapacityBytes=999},@{bufferPath='C:\elsewhere.bin'},@{bufferSha256=('0'*64)},@{bytesReturned=31})){$bad=Clone $record;foreach($key in $change.Keys){$bad.nativeQueries[0].$key=$change[$key]};Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Invalid native query provenance accepted.'}
$bad=Clone $record;$bad.nativeQueries+=Clone $bad.nativeQueries[0];Reject {Assert-ExtentPlacementRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Duplicate native query accepted.'
$blocked=Clone $record;$blocked.status='blocked';$blocked.nativePhase='create-initialized-fixture';$blocked.nativeQueries=@();$blocked.moveAttempted=$false;$blocked.moveCompleted=$false;$blocked.moveCallCount=0
Assert-ExtentPlacementRecord $blocked $blockedResponse $profile $control @($json) $scriptSha $nativeSha;$checks++
Reject {Assert-ExtentPlacementCompleted $blocked $captured @($json)} 'Blocked after-write run permitted reboot/restore.'
Reject {Assert-ExtentPlacementRecord $blocked $blockedResponse $profile $control @($json,(Artifact 'beforeExtents.bin' 1)) $scriptSha $nativeSha} 'Unreferenced native buffer accepted.'
foreach($field in @('targetWriteRequestsIssued','fixtureCreated','fixtureFullyInitialized','creationFlushed','moveAttempted','moveCompleted','contentPreserved','originalUnchanged','originalIndependentObservationUnchanged')){$bad=Clone $record;$bad.$field=$false;Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Incomplete write/content proof accepted.'}
foreach($field in @('length','sha256','fileId64','volumeSerialHex')){$bad=Clone $record;$bad.originalAfter.$field=if($field -ceq 'length'){1}else{'wrong'};Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Original content/identity change accepted.'}
$bad=Clone $record;$bad.originalAfter.extents[0].lcn++;Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Original mapping change accepted.'
$bad=Clone $record;$bad.before.sha256='0'*64;Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Pattern mismatch accepted.'
foreach($lcn in @(-1,65535,65537,(52GB/4096))){$bad=Clone $record;$bad.requestedLcn=$lcn;Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Out-of-bounds move destination accepted.'}
foreach($change in @(@{startingVcn=1},@{nextVcn=17},@{lcn=-1},@{lcn=(52GB/4096)})){$bad=Clone $record;foreach($key in $change.Keys){$bad.after.extents[0].$key=$change[$key]};Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Malformed post-move map accepted.'}
$bad=Clone $record;$bad.status='integrity-check-failed';Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Integrity failure permitted reboot/restore.'
$bad=Clone $record;$bad.requestedPlacementObserved=$false;Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'False movement claim accepted.'
foreach($index in @(8,16,24,28)){$bad=Clone $record;$move=@($bad.nativeQueries|Where-Object name -CEQ 'move')[0];$move.inputHex=$move.inputHex.Substring(0,$index*2)+'01'+$move.inputHex.Substring(($index+1)*2);Reject {Assert-ExtentPlacementCompleted $bad $captured $files} 'Move ABI disagreement accepted.'}
$rejected=Clone $record;$rejected.status='native-move-rejected';$rejected.after=Clone $rejected.before;$rejected.requestedPlacementObserved=$false;$move=@($rejected.nativeQueries|Where-Object name -CEQ 'move')[0];$move.succeeded=$false;$move.nativeError=5
Assert-ExtentPlacementCompleted $rejected $captured $files;$checks++ # returned native error is a measured outcome
$unexpected=Clone $record;$unexpected.status='native-move-returned-unexpected-mapping';$unexpected.after=Clone $unexpected.before;$unexpected.requestedPlacementObserved=$false
Assert-ExtentPlacementCompleted $unexpected $captured $files;$checks++

$remountIdentity=[pscustomobject]@{schemaVersion=1;kind='native-extent-placement-remount';probeId=$id;controlEvidenceSha256=$profile.controlEvidenceSha256;capturedAllocationSha256=$profile.capturedAllocationSha256;target=$control.target.guest;partition=$control.partition;volumeUniqueId=$record.volumeUniqueId}
$remountAllocation=Clone $capturedAllocation;$remountAllocation.evidenceScriptSha256=$collectorSha
$newObservation=Clone $after;foreach($key in @('complete','stableDuringObservation')){$newObservation|Add-Member -NotePropertyName $key -NotePropertyValue $true};$newObservation|Add-Member -NotePropertyName status -NotePropertyValue 'mapping-returned'
$remountAllocation.files=@($remountAllocation.files[0],[pscustomobject]@{path=('fixtures\placement-'+$id+'\initialized.bin');stream=':$DATA';observation=$newObservation})
Assert-ExtentPlacementRemount $remountIdentity $remountAllocation $record $control $collectorSha;$checks++
foreach($field in @('schemaVersion','kind','probeId','controlEvidenceSha256','capturedAllocationSha256','volumeUniqueId')){$bad=Clone $remountIdentity;$bad.$field=if($field -ceq 'schemaVersion'){2}else{'wrong'};Reject {Assert-ExtentPlacementRemount $bad $remountAllocation $record $control $collectorSha} 'Changed remount provenance accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $remountIdentity;$bad.partition.$field='wrong';Reject {Assert-ExtentPlacementRemount $bad $remountAllocation $record $control $collectorSha} 'Changed remount GPT accepted.'}
foreach($field in @('complete','evidenceScriptSha256','windowsBuild','logicalSectorSize','physicalSectorSize')){$bad=Clone $remountAllocation;$bad.$field=if($field -ceq 'complete'){$false}elseif($field -clike '*SectorSize'){1}else{'wrong'};Reject {Assert-ExtentPlacementRemount $remountIdentity $bad $record $control $collectorSha} 'Invalid remount evidence accepted.'}
foreach($field in @('sourceWriteRequestsIssued','physicalMappingVerified','conversionQualified','bootQualified')){$bad=Clone $remountAllocation;$bad.$field=$true;Reject {Assert-ExtentPlacementRemount $remountIdentity $bad $record $control $collectorSha} 'Unsupported remount claim accepted.'}
foreach($index in @(0,1)){foreach($field in @('complete','stableDuringObservation','length','sha256','fileId64','volumeSerialHex')){$bad=Clone $remountAllocation;$bad.files[$index].observation.$field=if($field -cin @('complete','stableDuringObservation')){$false}elseif($field -ceq 'length'){1}else{'wrong'};Reject {Assert-ExtentPlacementRemount $remountIdentity $bad $record $control $collectorSha} 'Changed remounted file accepted.'};$bad=Clone $remountAllocation;$bad.files[$index].observation.extents[0].lcn++;Reject {Assert-ExtentPlacementRemount $remountIdentity $bad $record $control $collectorSha} 'Changed remount mapping accepted.'}

# Exercise the real bounded helper with remoting/job primitives mocked.
$session='mock-session';$script:scenario='success';$script:removed=0;$script:commandIndeterminate=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock)Check $script:commandIndeterminate 'Operation must be indeterminate before dispatch.';if($script:scenario -ceq 'dispatch-failure'){throw 'transport failed'};[pscustomobject]@{State=$(if($script:scenario -ceq 'timeout'){'Running'}elseif($script:scenario -ceq 'receive-failure'){'Failed'}else{'Completed'})}}
function Wait-Job {param($Job,$Timeout)if($script:scenario -cne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)if($script:scenario -ceq 'receive-failure'){throw 'transport lost during operation'};'answer'}
function Remove-Job {param($Job,[switch]$Force)$script:removed++}
$answer=@(Invoke-BoundedPlacementCommand -ScriptBlock {} -TimeoutSeconds 30)
Check ($answer.Count -eq 1 -and $answer[0] -ceq 'answer' -and -not $script:commandIndeterminate -and $script:removed -eq 1) 'Completed command was not handled correctly.'
foreach($testScenario in @('dispatch-failure','receive-failure','timeout')){$script:scenario=$testScenario;$script:removed=0;$script:commandIndeterminate=$false;Reject {Invoke-BoundedPlacementCommand -ScriptBlock {} -TimeoutSeconds 30} 'Incomplete command accepted.';Check $script:commandIndeterminate 'Uncertain completion was cleared.';if($testScenario -ceq 'timeout'){Check ($script:removed -eq 0) 'Running job was forcibly removed.'}}
$commandNames=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($commandNames|Where-Object{$_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Stop-VM','Stop-Job','Set-VMFirmware','Checkpoint-VM')}).Count -eq 0) 'Unexpected host mutation or forced stop.'
$topTry=$ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]}|Select-Object -Last 1
$catchCommands=@($topTry.CatchClauses[0].FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($catchCommands|Where-Object{$_ -in @('Invoke-LabAction','Stop-ExtentPlacementGuest','Set-VMMemory','Remove-Job')}).Count -eq 0) 'Failure handler mutates preserved branch.'
$text=$ast.Extent.Text
Check ($text.IndexOf('    Assert-ExtentPlacementCompleted $export.record') -lt $text.IndexOf('    Stop-ExtentPlacementGuest')) 'Shutdown can precede complete evidence validation.'
Check ($text.IndexOf('$record.targetWriteRequestsMayHaveBeenIssued=$true') -lt $text.IndexOf('$responses=@(Invoke-BoundedPlacementCommand')) 'Dispatch lacks prior write intent.'
Check ($text.IndexOf('$record.remountEvidenceExported=$true') -lt $text.IndexOf("`$record.phase='preserve-off-state-outcome'")) 'Outcome preservation can precede remount export.'
Check ($text.IndexOf('$record.outcomeCheckpointCreated=$true') -lt $text.IndexOf("`$record.phase='restore-baseline'")) 'Restore can precede saved outcome verification.'
Check ($text.IndexOf('$record.cleanShutdown=$true') -lt $text.IndexOf("`$record.phase='preserve-off-state-outcome'")) 'Outcome checkpoint can precede final clean shutdown.'
$dry=& $path -WhatIf
Check ($dry.DryRun -and $dry.MemoryBytes -eq 8GB -and $dry.MaximumFixtureBytes -eq 65536 -and $dry.MaximumMoveCalls -eq 1 -and -not $dry.TargetWriteRequestsIssued -and -not $dry.MoveAttempted -and -not $dry.RawDiskWrites -and -not $dry.ConversionQualified) 'WhatIf contract failed.'
"Lab extent placement: $checks checks passed."
