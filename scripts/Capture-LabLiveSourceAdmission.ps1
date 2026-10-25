<# Actual source observation from the frozen-tree checkpoint. Native Rust owns
   the read-only mount lease and the full-image checks on both sides. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Stopped clean baseline required.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 1GB
$cp=Get-ExactLabCheckpoint -VM $vm -Name 'existing-tree-shadow-frozen-4cf7abc7c0174772868802161b563b7e'
if($cp.Id-ne[guid]'7bcaf7f9-07a5-463b-bc88-3a4f88e0e5e1'-or$cp.State-ne'Off'-or$cp.MemoryStartup-ne8GB){throw 'Frozen tree checkpoint differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned native binary required.'}
$id=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\source-admission\'+$id
$output=Assert-LabPath (Join-Path $cfg.Root ('source-admission/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{kind='live-source-admission-observation';runId=$id;sourceCheckpointId=[string]$cp.Id;binarySha256=$BinarySha256;status='started';operationCompletionKnown=$true;sourceAdmitted=$false;conversionQualified=$false;error=$null}
$request=Join-Path $cfg.Root 'existing-tree/win11-20261024T195711446Z/freeze-request.json';$requestSha=(Get-FileHash $request).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-ntfs-freeze.exe');Copy-Item -LiteralPath $request -Destination (Join-Path $output 'request.json')
$pins=@();foreach($p in @('src/ntfs_freeze.rs','src/bin/lab-ntfs-freeze.rs','src/ntfs_admission.rs','src/ntfs_attestation.rs','crates/n2r-win32/src/native.rs','crates/n2r-win32/src/attestation_native.rs','crates/n2r-win32/src/lib.rs','Cargo.toml','crates/n2r-win32/Cargo.toml','Cargo.lock','scripts/Capture-LabLiveSourceAdmission.ps1')){
 $to=Join-Path $output ('sources/'+$p);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $workspace $p) -Destination $to;$pins+=@([pscustomobject]@{path=$p;sha256=(Get-FileHash $to).Hash.ToLowerInvariant()})
};Save 'sources.json' $pins;Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
try{
 Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.ParentSnapshotId-eq$cp.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.ParentSnapshotId-ne$cp.Id){throw 'Checkpoint restore incomplete.'};Start-VM -VM $vm|Out-Null
 for($i=0;$i-lt90;$i++){try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}
 if(-not$session){throw 'Guest session unavailable.'}
 Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {param($Root);$ErrorActionPreference='Stop';foreach($p in @('C:\ntfs2refs\source-admission',$Root)){if(Test-Path $p){$f=Get-Item $p -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary artifacts required.'}}else{New-Item -ItemType Directory -Path $p|Out-Null}}}|Out-Null
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\lab-ntfs-freeze.exe') -ToSession $session;Copy-Item -LiteralPath $request -Destination ($root+'\request.json') -ToSession $session
 $record.operationCompletionKnown=$false
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$BinarySha256,$requestSha) -ScriptBlock {
  param($Root,$BinarySha,$RequestSha);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash ($Root+'\lab-ntfs-freeze.exe')).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash ($Root+'\request.json')).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Copied pins differ.'}
  $d=Get-Disk -Number 1;if(-not$d.IsOffline-or-not$d.IsReadOnly-or$d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'){throw 'Initial source protection differs.'}
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Root+'\lab-ntfs-freeze.exe';$psi.Arguments='--request "'+$Root+'\request.json" --request-sha256 '+$RequestSha+' --output "'+$Root+'\basis.json" --inspection-output "'+$Root+'\inspection.json" --reopen --observation-output "'+$Root+'\observation.json"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Native source process failed to start.'};$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\process.json',([ordered]@{pid=$p.Id;executable=$psi.FileName;arguments=$psi.Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(1800000)){throw ('Native source process still live; preserve PID '+$p.Id)}
  [IO.File]::WriteAllText($Root+'\stdout',$stdout.Result);[IO.File]::WriteAllText($Root+'\stderr',$stderr.Result)
  $d=Get-Disk -Number 1
  [pscustomobject]@{status='native-exit-observed';exitCode=$p.ExitCode;sourceOffline=$d.IsOffline;sourceReadonly=$d.IsReadOnly;basisSha256=(Get-FileHash ($Root+'\basis.json')).Hash.ToLowerInvariant()}
 }
 if(-not(Wait-Job $job -Timeout 2100)){throw 'Native source operation live/unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1-or$reply[0].status-cne'native-exit-observed'){throw 'Native source completion unknown.'}
 $record.operationCompletionKnown=$true;Save 'guest-reply.json' $reply[0]
 foreach($name in @('basis.json','basis.intent.json','process.json','stdout','stderr')){Copy-Item -LiteralPath ($root+'\'+$name) -Destination (Join-Path $output $name) -FromSession $session}
 foreach($name in @('inspection.json','observation.json')){$exists=Invoke-Command -Session $session -ArgumentList ($root+'\'+$name) -ScriptBlock {param($Path);Test-Path -LiteralPath $Path};if($exists){Copy-Item -LiteralPath ($root+'\'+$name) -Destination (Join-Path $output $name) -FromSession $session}}
 if((Get-FileHash (Join-Path $output 'basis.json')).Hash.ToLowerInvariant()-cne$reply[0].basisSha256){throw 'Exported basis differs.'}
 if($reply[0].exitCode-ne0-or-not$reply[0].sourceOffline-or-not$reply[0].sourceReadonly){throw 'Source observation failed; terminal evidence exported and branch preserved.'}
 $basis=Get-Content (Join-Path $output 'basis.json') -Raw|ConvertFrom-Json
 if(-not$basis.success-or$basis.basis.source_sha256-cne'798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89'){throw 'Source basis changed.'}
 Invoke-Command -Session $session -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE){throw 'Shutdown failed.'}}|Out-Null
 for($i=0;$i-lt45;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 1};if($vm.State-ne'Off'){throw 'Guest still running.'};Remove-PSSession $session;$session=$null
 $name='existing-tree-live-source-'+$id;Checkpoint-VM -VM $vm -SnapshotName $name;$saved=Get-ExactLabCheckpoint -VM $vm -Name $name;$record['checkpointId']=[string]$saved.Id;$record['checkpointName']=$name
 $baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean;if($baseline.Id-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Baseline differs.'};Restore-VMSnapshot -VMSnapshot $baseline -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.MemoryStartup-eq4GB-and$vm.ParentSnapshotId-eq$baseline.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne$baseline.Id){throw 'Baseline restore unverified.'}
 $record.status='live-source-observed-image-unchanged'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
