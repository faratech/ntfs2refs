<# Pure guards, mocked transport failures and WhatIf only; no VM actions. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabExtentDiscovery.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($name in @('Get-ExtentDiscoveryProfile','Assert-ExtentDiscoveryManifest','Assert-ExtentDiscoveryVM','Assert-ExtentDiscoveryCheckpoint','Assert-ExtentDiscoveryResponse','Assert-ExtentDiscoveryArtifact','Assert-ExtentDiscoveryArtifactSet','Assert-ExtentDiscoveryRecord','Invoke-BoundedDiscoveryCommand')) {
    $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
    Invoke-Expression $definition.Extent.Text
}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
$profile=Get-ExtentDiscoveryProfile
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';sizeBytes=64GB;controllerLocation=0;vhdId=[guid]::NewGuid().ToString()},[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';sizeBytes=8GB;controllerLocation=2;vhdId=[guid]::NewGuid().ToString()})}
Assert-ExtentDiscoveryManifest $manifest $profile; $checks++
$bad=Clone $manifest;$bad.vmId=[guid]::NewGuid().ToString();Reject {Assert-ExtentDiscoveryManifest $bad $profile} 'Different VM accepted.'
$bad=Clone $manifest;$bad.disks=$bad.disks[0..1];Reject {Assert-ExtentDiscoveryManifest $bad $profile} 'Missing journal accepted.'
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$field=if($field -ceq 'role'){'os'}elseif($field -ceq 'vhdId'){[guid]::NewGuid().ToString()}else{0};Reject {Assert-ExtentDiscoveryManifest $bad $profile} "Bad target $field accepted."}
$script:connected=$false;$script:secure='On'
function Get-VMNetworkAdapter {param($VM)[pscustomobject]@{SwitchName=$(if($script:connected){'external'}else{''})}}
function Get-VMFirmware {param($VM)[pscustomobject]@{SecureBoot=$script:secure}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB;$checks++
foreach($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=$profile.checkpointId})){$bad=Clone $vm;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentDiscoveryVM $bad $profile.baselineId 4GB} 'Unsafe VM start state accepted.'}
$connected=$true;Reject {Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB} 'Connected network accepted.';$connected=$false
$secure='Off';Reject {Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB} 'Changed Secure Boot accepted.';$secure='On'
$saved=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId}
Assert-ExtentDiscoveryCheckpoint $saved $profile;$checks++
$baseline=[pscustomobject]@{Id=$profile.baselineId;Name='installed-clean';VMId=$profile.vmId}
Assert-ExtentDiscoveryCheckpoint $baseline $profile -Baseline;$checks++
foreach($field in @('Id','Name','VMId')){$bad=Clone $saved;$bad.$field='other';Reject {Assert-ExtentDiscoveryCheckpoint $bad $profile} 'Different saved checkpoint accepted.'}
Reject {Assert-ExtentDiscoveryCheckpoint $saved $profile -Baseline} 'Native checkpoint confused with installed-clean.'
$id='a'*32
$response=[pscustomobject]@{DiscoveryId=$id;Status='observed-with-unresolved-results';EvidenceDirectory=('C:\ntfs2refs\extent-discovery\'+$id);MoveAttempted=$false;PhysicalMappingVerified=$false;ConversionQualified=$false}
Assert-ExtentDiscoveryResponse $response $id;$checks++
foreach($change in @(@{DiscoveryId=('b'*32)},@{Status='converted'},@{EvidenceDirectory='C:\Windows'},@{MoveAttempted=$true},@{PhysicalMappingVerified=$true},@{ConversionQualified=$true},@{MoveAttempted='false'})){$bad=Clone $response;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentDiscoveryResponse $bad $id} 'Unqualified response accepted.'}
$json=[pscustomobject]@{name='discovery.json';length=1024;sha256=('a'*64);attributes='Archive'}
$binary=[pscustomobject]@{name='baseBefore.bin';length=8;sha256=('b'*64);attributes='Archive'}
Assert-ExtentDiscoveryArtifactSet @($json,$binary);$checks++
foreach($change in @(@{name='..\discovery.json'},@{name='payload.raw'},@{length=0},@{length=(1MB+1)},@{sha256='bad'},@{attributes='ReparsePoint'})){$bad=Clone $json;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ExtentDiscoveryArtifact $bad} 'Unsafe artifact accepted.'}
foreach($length in @(0,9)){$bad=Clone $binary;$bad.length=$length;Reject {Assert-ExtentDiscoveryArtifact $bad} 'Invalid base buffer length accepted.'}
$partial=Clone $binary;$partial.length=7;Assert-ExtentDiscoveryArtifact $partial;$checks++
$bitmap=Clone $binary;$bitmap.name='bitmapExtendedFlags1.bin';$bitmap.length=2MB
Assert-ExtentDiscoveryArtifact $bitmap;$checks++
$bitmap.length=2MB+1;Reject {Assert-ExtentDiscoveryArtifact $bitmap} 'Oversized bitmap accepted.'
Reject {Assert-ExtentDiscoveryArtifactSet @()} 'Empty export accepted.'
Reject {Assert-ExtentDiscoveryArtifactSet @($binary)} 'Export without discovery.json accepted.'
Reject {Assert-ExtentDiscoveryArtifactSet @($json,$json)} 'Duplicate export names accepted.'
$control=[pscustomobject]@{target=[pscustomobject]@{guest=[pscustomobject]@{role='target';uniqueId='60022480D091C4251B5FFD619706C2B5';sizeBytes=64GB;location='owned-slot-1'}};partition=[pscustomobject]@{guid='{00c9f113-e0b9-49d8-b031-130aef8ef3fb}';diskGuid='{b4ab4dbc-6bd7-4199-8e4a-01b828e98584}';number=2;offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096}}
$scriptSha='c'*64;$nativeSha='d'*64
$record=[pscustomobject]@{schemaVersion=1;kind='native-extent-discovery';phase='ReadOnlyDiscovery';discoveryId=$id;status=$response.Status;controlRunId=$profile.controlRunId;controlEvidenceSha256=$profile.controlEvidenceSha256;capturedAllocationSha256=$profile.capturedAllocationSha256;scriptSha256=$scriptSha;nativeSourceSha256=$nativeSha;target=$control.target.guest;partition=$control.partition;sourceWriteRequestsIssued=$false;moveImplemented=$false;moveAttempted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;nativeMoveSupport='unmeasured';nativeQueries=@([pscustomobject]@{name='baseBefore';controlCode='0x00090234';bufferPath=($response.EvidenceDirectory+'\baseBefore.bin');bufferSha256=$binary.sha256;bytesReturned=8})}
Assert-ExtentDiscoveryRecord $record $response $profile $control @($json,$binary) $scriptSha $nativeSha;$checks++
foreach($field in @('schemaVersion','kind','phase','discoveryId','status','controlRunId','controlEvidenceSha256','capturedAllocationSha256','scriptSha256','nativeSourceSha256','nativeMoveSupport')){$bad=Clone $record;$bad.$field=if($field -ceq 'schemaVersion'){2}else{'wrong'};Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} "Changed $field accepted."}
foreach($field in @('sourceWriteRequestsIssued','moveImplemented','moveAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')){$bad=Clone $record;$bad.$field=$true;Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} 'Unperformed qualification accepted.'}
foreach($field in @('role','uniqueId','sizeBytes','location')){$bad=Clone $record;$bad.target.$field='wrong';Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} 'Changed target accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $record;$bad.partition.$field='wrong';Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} 'Changed GPT or geometry accepted.'}
foreach($field in @('name','controlCode','bufferPath','bufferSha256','bytesReturned')){$bad=Clone $record;$bad.nativeQueries[0].$field=if($field -ceq 'bytesReturned'){7}else{'wrong'};Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} 'Invalid buffer provenance accepted.'}
$bad=Clone $record;$bad.nativeQueries+=Clone $bad.nativeQueries[0];Reject {Assert-ExtentDiscoveryRecord $bad $response $profile $control @($json,$binary) $scriptSha $nativeSha} 'Duplicate native query accepted.'
$blockedResponse=Clone $response;$blockedResponse.Status='blocked'
$blocked=Clone $record;$blocked.status='blocked';$blocked.nativeQueries=@()
Assert-ExtentDiscoveryRecord $blocked $blockedResponse $profile $control @($json) $scriptSha $nativeSha;$checks++
Reject {Assert-ExtentDiscoveryRecord $blocked $blockedResponse $profile $control @($json,$binary) $scriptSha $nativeSha} 'Unreferenced native buffer accepted.'
$refused=Clone $record;$refused.nativeQueries[0].bufferPath=$null;$refused.nativeQueries[0].bufferSha256=$null;$refused.nativeQueries[0].bytesReturned=0
Assert-ExtentDiscoveryRecord $refused $response $profile $control @($json) $scriptSha $nativeSha;$checks++

# Actual host orchestration helper, with only remoting/job primitives mocked.
$session='mock-session';$script:scenario='success';$script:removed=0;$script:commandIndeterminate=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock)Check $script:commandIndeterminate 'Operation must be marked indeterminate before dispatch.';if($script:scenario -ceq 'dispatch-failure'){throw 'transport failed'};[pscustomobject]@{State=$(if($script:scenario -ceq 'timeout'){'Running'}elseif($script:scenario -ceq 'receive-failure'){'Failed'}else{'Completed'})}}
function Wait-Job {param($Job,$Timeout)if($script:scenario -cne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)if($script:scenario -ceq 'receive-failure'){throw 'transport lost during operation'};'answer'}
function Remove-Job {param($Job,[switch]$Force)$script:removed++}
$answer=@(Invoke-BoundedDiscoveryCommand -ScriptBlock {} -TimeoutSeconds 30)
Check ($answer.Count -eq 1 -and $answer[0] -ceq 'answer' -and -not $script:commandIndeterminate -and $script:removed -eq 1) 'Completed command was not handled correctly.'
foreach($testScenario in @('dispatch-failure','receive-failure','timeout')){$script:scenario=$testScenario;$script:removed=0;$script:commandIndeterminate=$false;Reject {Invoke-BoundedDiscoveryCommand -ScriptBlock {} -TimeoutSeconds 30} 'Incomplete command accepted.';Check $script:commandIndeterminate 'Uncertain command completion was cleared.';if($testScenario -ceq 'timeout'){Check ($script:removed -eq 0) 'Running job was forcibly removed.'}}
$commandNames=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($commandNames|Where-Object{$_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Stop-VM','Stop-Job','Set-VMFirmware','Checkpoint-VM')}).Count -eq 0) 'Unexpected host mutation or forced stop.'
$topTry=$ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]} | Select-Object -Last 1
$catchCommands=@($topTry.CatchClauses[0].FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($catchCommands|Where-Object{$_ -in @('Invoke-LabAction','Stop-ExtentDiscoveryGuest','Set-VMMemory','Remove-Job')}).Count -eq 0) 'Failure handler mutates preserved branch.'
$text=$ast.Extent.Text
Check ($text.IndexOf('$record.evidenceExported=$true') -lt $text.IndexOf('    Stop-ExtentDiscoveryGuest')) 'Shutdown can precede validated export.'
Check ($text.IndexOf('$record.cleanShutdown=$true') -lt $text.IndexOf("`$record.phase='restore-baseline'")) 'Restore can precede clean shutdown.'
$dry=& $path -WhatIf
Check ($dry.DryRun -and $dry.MemoryBytes -eq 8GB -and -not $dry.SourceWriteRequestsIssued -and -not $dry.MoveAttempted -and -not $dry.RawDiskWrites -and -not $dry.ConversionQualified) 'WhatIf contract failed.'
"Lab extent discovery: $checks checks passed."
