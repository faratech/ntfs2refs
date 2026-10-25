<# Preserve a successful converted guest as a stopped Hyper-V checkpoint. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConversionDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11
$directory=Assert-LabPath $ConversionDirectory $cfg.Root
$hostResult=Get-Content (Join-Path $directory 'host-result.json') -Raw|ConvertFrom-Json
$start=Get-Content (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$finish=Get-Content (Join-Path $directory 'guest-finish.json') -Raw|ConvertFrom-Json
$shadow=Get-Content (Join-Path $start.shadowDirectory 'host-result.json') -Raw|ConvertFrom-Json
if($hostResult.status-cne'native-conversion-complete'-or-not$finish.success-or-not$finish.rollback_closed-or-not$finish.native-or$start.experimentId-cne$shadow.runId){throw 'Native converted-tree completion is not established.'}
$vm=Get-OwnedLabVM $cfg $manifest
if($vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or[guid]$vm.ParentSnapshotId-ne[guid]$shadow.shadowCheckpointId){throw 'Unexpected running conversion branch.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 64MB
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml')
$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential
 Invoke-Command -Session $session -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE){throw 'Guest shutdown failed.'}}|Out-Null
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
$deadline=[DateTime]::UtcNow.AddSeconds(180)
do{$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
if($vm.State-ne'Off'){throw 'Guest shutdown was not observed.'}
$name='ordinary-tree-converted-'+$start.runId
Checkpoint-VM -VM $vm -SnapshotName $name
$checkpoint=Get-ExactLabCheckpoint -VM $vm -Name $name
if($checkpoint.State-ne'Off'-or$checkpoint.MemoryStartup-ne8GB){throw 'Converted checkpoint state differs.'}
$record=[ordered]@{kind='ordinary-tree-converted-checkpoint';runId=$start.runId;checkpointId=[string]$checkpoint.Id;checkpointName=$name;finishSha256=(Get-FileHash (Join-Path $directory 'guest-finish.json')).Hash.ToLowerInvariant();guestState='Off';capturedUtc=[DateTime]::UtcNow.ToString('o')}
$path=Join-Path $directory 'converted-checkpoint.json'
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 8))
$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]$record
