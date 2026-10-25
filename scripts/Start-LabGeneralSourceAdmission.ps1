<# Collect native source evidence on the already frozen NTFS branch. The
   Rust observer restores offline/read-only exclusion before returning. #>
[CmdletBinding()]
param([ValidateSet('full','internal-index','observed-freeze')][string]$Profile='full', [string]$BinaryPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
if($vm.State-ne'Running'-or$vm.ParentSnapshotId-ne[guid]'481eb504-504d-40a4-8a6c-6e48d087b6e9'){throw 'Running original frozen NTFS branch required.'}
if(-not$BinaryPath){$BinaryPath=Join-Path $workspace $(switch($Profile){'full'{'target/release/lab-inspect-frozen-general.exe'};'observed-freeze'{'target/release/lab-freeze-general-source.exe'};default{'target/release/lab-inspect-ntfs-internals.exe'}})}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB){throw 'Bounded ordinary collector binary required.'}
$binarySha=(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()
$binding=Join-Path $cfg.Root 'ntfs-shortname-differential/win11-20261025T145523275Z/binding.json'
$bindingSha='60cbaacbf2d0e4a0de866e5507d825a99df61108ea76d87764202068e988f5e7'
if((Get-FileHash -LiteralPath $binding).Hash.ToLowerInvariant()-cne$bindingSha){throw 'Source binding differs.'}
$id=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\general-source-admission\'+$id;$taskName='N2R-GeneralSource-'+$id
$output=Assert-LabPath (Join-Path $cfg.Root ('general-source-admission/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'collector.exe')
Copy-Item -LiteralPath $binding -Destination (Join-Path $output 'binding.json')
$record=[ordered]@{schemaVersion=1;kind='general-live-source-admission-dispatch';profile=$Profile;runId=$id;gitCommit=(git -C $workspace rev-parse HEAD);binarySha256=$binarySha;bindingSha256=$bindingSha;vmId=[string]$vm.Id;parentSnapshotId=[string]$vm.ParentSnapshotId;savedReFSCheckpointId='713c2e66-32b0-43e5-a6a2-a35098c3972c';taskName=$taskName;guestOutput=$root+'\basis.json';guestRoot=$root;startedUtc=[DateTime]::UtcNow.ToString('o')}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 8));$f=[IO.File]::Open((Join-Path $output 'dispatch.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 Invoke-Command -Session $session -ArgumentList @($root,$Profile) -ScriptBlock {
  param($Root,$Profile);$ErrorActionPreference='Stop'
  $disk=Get-Disk -Number 1
  if([guid]$disk.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or
    $(if($Profile-eq'observed-freeze'){$disk.IsOffline-or$disk.IsReadOnly}else{-not$disk.IsOffline-or-not$disk.IsReadOnly})){throw 'Source identity or expected initial protection differs.'}
  if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'A lab task is still running.'}
  New-Item -ItemType Directory -Path $Root -ErrorAction Stop|Out-Null
 }|Out-Null
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\collector.exe') -ToSession $session
 Copy-Item -LiteralPath $binding -Destination ($root+'\binding.json') -ToSession $session
 Invoke-Command -Session $session -ArgumentList @($root,$taskName,$binarySha,$bindingSha,$Profile) -ScriptBlock {
  param($Root,$TaskName,$BinarySha,$BindingSha,$Profile);$ErrorActionPreference='Stop'
  if((Get-FileHash ($Root+'\collector.exe')).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash ($Root+'\binding.json')).Hash.ToLowerInvariant()-cne$BindingSha){throw 'Guest collector pins differ.'}
  $extra=if($Profile-eq'full'){'--ordinary-tree '}else{''}
  $action=New-ScheduledTaskAction -Execute ($Root+'\collector.exe') -Argument ('--native '+$extra+'--binding "'+$Root+'\binding.json" --binding-sha256 '+$BindingSha+' --output "'+$Root+'\basis.json"')
  $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings|Out-Null
  Start-ScheduledTask -TaskName $TaskName
 }|Out-Null
 [pscustomobject]@{status='general-source-observation-dispatched';directory=$output;taskName=$taskName;binarySha256=$binarySha}
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
