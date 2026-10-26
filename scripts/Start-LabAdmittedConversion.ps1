<# Retry a terminal pre-write qualification failure using the same enrolled
   NTFS source and an explicitly reset disposable ReFS shadow. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PreviousDirectory,
 [string]$BinaryPath=(Join-Path $PSScriptRoot '../target/release/lab-convert-admitted-tree.exe'),[switch]$PublicCli,
 [string]$AfterPublicCancelDirectory,[ValidateRange(0,4096)][int]$InterruptAfterWrites=0)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$previous=Assert-LabPath $PreviousDirectory $cfg.Root
$old=Get-Content (Join-Path $previous 'dispatch.json') -Raw|ConvertFrom-Json
$terminal=Get-Content (Join-Path $previous 'collected.json') -Raw|ConvertFrom-Json
$request=Get-Content (Join-Path $previous 'input.json') -Raw|ConvertFrom-Json
if($PublicCli-and$InterruptAfterWrites){throw 'Fault injection is laboratory-only.'}
$afterCancel=[bool]$AfterPublicCancelDirectory
$expectedCheckpoint=if($afterCancel){[guid]$old.checkpointId}else{[guid]'272e62d4-ffc5-4ac0-8bb4-46c64f9a9655'}
if($vm.State-ne'Running'-or$vm.ParentSnapshotId-ne$expectedCheckpoint-or[guid]$vm.Id-ne[guid]$old.vmId-or$old.kind-cne'certificate-backed-conversion-dispatch'-or$terminal.runId-cne$old.runId-or$terminal.success-or$terminal.exitCode-eq0-or$terminal.failure.phase-cnotin@('qualification','journal-preparation')-or-not$terminal.sourceOffline-or-not$terminal.sourceReadOnly-or(Test-Path (Join-Path $previous 'ticket.json'))){throw 'Collected pre-activation failure and exact owned branch required.'}
if($afterCancel){
 $cancelDirectory=Assert-LabPath $AfterPublicCancelDirectory $cfg.Root
 $cd=Get-Content -LiteralPath (Join-Path $cancelDirectory 'dispatch.json') -Raw|ConvertFrom-Json
 $cc=Get-Content -LiteralPath (Join-Path $cancelDirectory 'collected.json') -Raw|ConvertFrom-Json
 if($cd.kind-cne'public-cancel-dispatch'-or$cd.originRunId-cne$old.runId-or[guid]$cd.vmId-ne[guid]$vm.Id-or[guid]$cd.checkpointId-ne$expectedCheckpoint-or$cc.kind-cne'public-cancel-observation'-or$cc.stepId-cne$cd.stepId-or-not$cc.success-or$cc.exitCode-ne0-or$cc.sourceOffline-or$cc.sourceReadOnly-or$cc.sourceFileSystem-cne'NTFS'-or$cc.driveLetter-cne'F'-or-not$cc.rawSourceHashMatchedBeforeWritableMount-or-not$cc.originalMountPathsMatched-or-not$cc.fourLogicalFilesMatched){throw 'Successful public cancellation of this same attempt required.'}
}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB){throw 'Bounded ordinary converter required.'}
$binarySha=(Get-FileHash $binary.FullName).Hash.ToLowerInvariant();$id=[guid]::NewGuid().ToString('N');$request.experiment_id=$id
$publicBinary=$null;$publicSha=$null
if($InterruptAfterWrites){$publicBinary=Get-Item -LiteralPath (Join-Path $workspace 'target/release/ntfs2refs.exe') -Force;if($publicBinary.PSIsContainer-or($publicBinary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$publicBinary.Length-gt16MB){throw 'Ordinary public recovery executable required.'};$publicSha=(Get-FileHash -LiteralPath $publicBinary.FullName).Hash.ToLowerInvariant()}
$output=Assert-LabPath (Join-Path $cfg.Root ('certificate-conversion/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
$request|ConvertTo-Json -Depth 14|Set-Content -LiteralPath (Join-Path $output 'input.json') -Encoding utf8
$requestSha=(Get-FileHash (Join-Path $output 'input.json')).Hash.ToLowerInvariant()
$root='C:\ntfs2refs\conversion-inputs\'+$id;$result='C:\ntfs2refs\conversions\'+$id;$task='N2R-AdmittedConvert-'+$id
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential
 $prepared=Invoke-Command -Session $session -ArgumentList @($old.taskName,$root,$afterCancel) -ScriptBlock {
  param($OldTask,$Root,$AfterCancel);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-ScheduledTask -TaskName $OldTask).State-in@('Running','Queued')-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'An owning-guest operation is still active.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$partition=Get-Partition -DiskNumber 3 -PartitionNumber 2
  if([guid]$source.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or$source.IsOffline-eq$AfterCancel-or$source.IsReadOnly-eq$AfterCancel-or$source.IsBoot-or$source.IsSystem-or[guid]$shadow.Guid-ne[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'-or$shadow.IsBoot-or$shadow.IsSystem-or[guid]$partition.Guid-ne[guid]'e071a0c1-5f96-4327-85e8-da9b831e27d3'-or$partition.Size-ne52GB-or$partition.Offset-ne16MB-or[guid](Get-Disk -Number 2).Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'){throw 'Enrolled source, shadow or journal identity/state differs.'}
  $file=[IO.File]::Open('\\.\PhysicalDrive1',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$null=$file.Seek(16MB,[IO.SeekOrigin]::Begin);$boot=[byte[]]::new(512);if($file.Read($boot,0,512)-ne512-or[Text.Encoding]::ASCII.GetString($boot,3,8)-cne'NTFS    '){throw 'Source is no longer original NTFS.'}}finally{$file.Dispose()}
  Set-Disk -Number 3 -IsReadOnly $false;Set-Disk -Number 3 -IsOffline $false
  Format-Volume -Partition (Get-Partition -DiskNumber 3 -PartitionNumber 2) -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-shadow' -Confirm:$false -Force|Out-Null
  if(-not$AfterCancel){Set-Disk -Number 1 -IsReadOnly $false;Set-Disk -Number 1 -IsOffline $false}
  if((Get-Volume -DriveLetter F).FileSystem-cne'NTFS'){throw 'Source did not return as NTFS.'}
  New-Item -ItemType Directory -Path $Root|Out-Null
  [pscustomobject]@{sourceNtfs=$true;shadowReset=$true;preparedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 $prepared|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'preparation.json') -Encoding utf8
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\converter.exe') -ToSession $session
 Copy-Item -LiteralPath (Join-Path $output 'input.json') -Destination ($root+'\input.json') -ToSession $session
 if($publicBinary){Copy-Item -LiteralPath $publicBinary.FullName -Destination ($root+'\ntfs2refs.exe') -ToSession $session}
 Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'converter.exe')
 [ordered]@{schemaVersion=1;kind='certificate-backed-conversion-dispatch';entrypoint=if($PublicCli){'public-cli'}elseif($InterruptAfterWrites){'lab-one-flushed-write-interruption'}else{'lab'};runId=$id;taskName=$task;guestRoot=$root;guestOutput=$result;requestSha256=$requestSha;binarySha256=$binarySha;publicCliSha256=$publicSha;expectedExitCode=if($InterruptAfterWrites){86}else{0};interruptAfterWrites=$InterruptAfterWrites;repositoryCommit=(git -C $workspace rev-parse HEAD);afterPublicCancelDirectory=$AfterPublicCancelDirectory;vmId=[string]$vm.Id;checkpointId=[string]$vm.ParentSnapshotId;previousDirectory=$previous;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'dispatch.json') -Encoding utf8
 Invoke-Command -Session $session -ArgumentList @($root,$result,$task,$requestSha,$binarySha,[bool]$PublicCli,$InterruptAfterWrites,$publicSha) -ScriptBlock {
  param($Root,$Output,$Task,$RequestSha,$BinarySha,$PublicCli,$InterruptAfterWrites,$PublicSha);$ErrorActionPreference='Stop'
  if((Get-FileHash ($Root+'\converter.exe')).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash ($Root+'\input.json')).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Converter pins differ.'}
  $prefix=if($PublicCli){'convert '}else{''}
  if($PublicSha-and(Get-FileHash -LiteralPath ($Root+'\ntfs2refs.exe')).Hash.ToLowerInvariant()-cne$PublicSha){throw 'Public recovery executable pin differs.'}
  $fault=if($InterruptAfterWrites){' --interrupt-after-writes '+$InterruptAfterWrites}else{''}
  $action=New-ScheduledTaskAction -Execute ($Root+'\converter.exe') -Argument ($prefix+'--request "'+$Root+'\input.json" --request-sha256 '+$RequestSha+' --output "'+$Output+'"'+$fault)
  $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings $settings|Out-Null;Start-ScheduledTask -TaskName $Task
 }|Out-Null
 [pscustomobject]@{directory=$output;taskName=$task;guestOutput=$result}
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
