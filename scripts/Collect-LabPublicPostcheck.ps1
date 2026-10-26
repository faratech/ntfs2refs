<# Host-only native-result collector. No native work is dispatched here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
# Load only reviewed host definitions, never the dispatcher's body or a guest file.
$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Dispatch-LabPublicPostcheck.ps1'),[ref]$null,[ref]$errors)
if($errors){throw ($errors.Message-join'; ')}
foreach($name in @('Test-ExpectedHandoff','Read-PostcheckPin','Assert-StrictPostcheckTree','Assert-PostcheckMutation','Get-NativePostcheckObservation','Assert-NativePostcheckObservation')){
 $definitions=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$false));if($definitions.Count-ne1){throw 'Unique reviewed host helper required.'};. ([scriptblock]::Create($definitions[0].Extent.Text))
}
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root;$dispatch=Get-Content (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($dispatch.schemaVersion-ne2-or$dispatch.kind-cne'native-public-postcheck-dispatch'-or$dispatch.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.originRunId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.operation-notin@('Verify','Mutate','VerifyAfterMutation')-or$dispatch.taskName-cne('N2R-NativePostcheck-'+$dispatch.stepId)-or$dispatch.guestRoot-cne('C:\ntfs2refs\native-public-postchecks\'+$dispatch.stepId)-or$dispatch.powershellWorkerLoaded-or$dispatch.securitySettingsChanged-or[guid]$dispatch.vmId-ne[guid]$vm.Id-or[guid]$dispatch.checkpointId-ne[guid]$vm.ParentSnapshotId-or$vm.State-ne'Running'){throw 'Native postcheck dispatch or owned branch differs.'}
$config=Read-PostcheckPin (Join-Path $directory 'configuration.json') $dispatch.configurationSha256 128KB
if($config.schemaVersion-ne2-or$config.kind-cne'native-public-postcheck-request'-or$config.stepId-cne$dispatch.stepId-or$config.originRunId-cne$dispatch.originRunId-or$config.operation-cne$dispatch.operation-or$config.taskName-cne$dispatch.taskName-or$config.inputRoot-cne$dispatch.guestRoot-or$config.nativeOutput-cne$dispatch.guestOutput-or$config.binarySha256-cne$dispatch.binarySha256-or$config.requestSha256-cne$dispatch.requestSha256-or$config.expectationSha256-cne$dispatch.expectationSha256-or[bool]$config.sourceOnlyAfterReboot-ne[bool]$dispatch.sourceOnlyAfterReboot-or$config.powershellWorkerLoaded-or$config.securitySettingsChanged){throw 'Native configuration and dispatch binding differ.'}
$expectedName=if($config.operation-ceq'Mutate'){'mutation.json'}elseif($config.operation-ceq'VerifyAfterMutation'){'verify-after.json'}else{'verify.json'}
if($config.nativeReportName-cne$expectedName-or$config.nativeOutput-cne(Join-Path $config.inputRoot $expectedName)-or$config.journal-cne('\\?\Volume{7435ee94-c435-403f-a515-dec1ccd5094e}\ntfs2refs-shadow\'+$config.originRunId+'\reconstruction.journal')){throw 'Exact native report or closed journal route differs.'}
if(Test-Path (Join-Path $directory 'collected.json')){throw 'Native terminal result already collected.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestRoot,$config.nativeReportName) -ScriptBlock {
  param($TaskName,$Root,$ReportName);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;state=[string]$task.State}}
  $names=@($ReportName);if($ReportName-ceq'mutation.json'){$names+='mutation.intent.json'}
  $files=@(foreach($name in $names){$path=Join-Path $Root $name;if(Test-Path -LiteralPath $path){$f=Get-Item $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt16MB){throw 'Native result is not bounded ordinary output.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}}})
  [pscustomobject]@{terminal=$true;state=[string]$task.State;exitCode=$info.LastTaskResult;files=$files}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='native-public-postcheck-still-running';taskName=$dispatch.taskName;state=$observed.state};return}
 foreach($file in $observed.files){$path=Join-Path $directory $file.name;if(Test-Path -LiteralPath $path){throw 'Native export destination already exists.'};Copy-Item -LiteralPath (Join-Path $dispatch.guestRoot $file.name) -Destination $path -FromSession $session;if((Get-Item $path).Length-ne$file.length-or(Get-FileHash $path).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Native report changed during export.'}}
 $state=$null;$stateError=$null;try{$state=Get-NativePostcheckObservation $session $config;Assert-NativePostcheckObservation $state $config}catch{$stateError=$_.Exception.ToString()}
 $pre=Get-Content (Join-Path $directory 'preflight.json') -Raw|ConvertFrom-Json
 $success=$false;$errorText=$null;$mutationSha=$null;$verified=0
 try{
  if($observed.exitCode-ne0-or$stateError-or-not$state-or$state.bootUtcTicks-ne$pre.bootUtcTicks){throw 'Known native exit0 and unchanged guarded boot/state required.'}
  $pin=@($observed.files|Where-Object {$_.name-ceq$config.nativeReportName});if($pin.Count-ne1){throw 'Pinned native report absent.'}
  $report=Read-PostcheckPin (Join-Path $directory $config.nativeReportName) $pin[0].sha256 16MB
  if($config.operation-ceq'Mutate'){Assert-PostcheckMutation $report $dispatch.stepId $config.preMutationRootBasic;$mutationSha=$pin[0].sha256}
  else{Assert-StrictPostcheckTree $report $config $config.mutationReportSha256;$verified=$config.expectedObjectCount;if($config.operation-ceq'VerifyAfterMutation'){$mutationSha=$config.mutationReportSha256}}
  $success=$true
 }catch{$errorText=$_.Exception.ToString()}
 $record=[ordered]@{schemaVersion=2;kind='native-public-postcheck-observation';stepId=$dispatch.stepId;originRunId=$dispatch.originRunId;operation=$dispatch.operation;sourceOnlyAfterReboot=[bool]$dispatch.sourceOnlyAfterReboot;taskName=$dispatch.taskName;exitCode=$observed.exitCode;success=[bool]$success;expectedObjectCount=$config.expectedObjectCount;strictlyVerifiedObjects=$verified;mutationReportSha256=$mutationSha;preMutationRootBasic=$config.preMutationRootBasic;requiresPostMutationVerification=($config.operation-ceq'Mutate');bootUtcTicks=if($state){$state.bootUtcTicks}else{$null};sourceState=$state;stateError=$stateError;error=$errorText;files=$observed.files;powershellWorkerLoaded=$false;securitySettingsChanged=$false;rawReplayRequested=$false;diskAttributeSettersRequested=$false;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 18));$f=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
