<# Host orchestration only. Source preparation, natural allocation and Rust
   freeze/inspection run inside the owning guest. No ReFS construction here. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not$PSCmdlet.ShouldProcess('Owned disposable installed-clean VM','Populate an ordinary NTFS tree, freeze and inspect it, verify exclusion after restart, checkpoint and restore baseline')){return}
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration -WorkspaceRoot $workspace;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or[guid]$vm.ParentSnapshotId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'-or(Get-VMFirmware -VM $vm).SecureBoot-ne'On'-or@(Get-VMNetworkAdapter -VM $vm|Where-Object SwitchName).Count){throw 'Exact clean, off, protected and disconnected baseline required.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 2GB
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned freeze binary required.'}
$run=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\existing-tree\'+$run
$output=Assert-LabPath (Join-Path $cfg.Root ('existing-tree/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output | Out-Null
function Save-New([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));$f=[IO.File]::Open((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='ordinary-ntfs-tree-freeze-host';runId=$run;status='started';phase='archive';vmId=[string]$vm.Id;output=$output;binarySha256=$BinarySha256;operationCompletionKnown=$true;sourcePlacementOperations=0;conversionQualified=$false;error=$null}
$sourcePaths=@('lab/guest/GuestLab.psm1','lab/guest/Register-GuestDisk.ps1','lab/guest/Prepare-GuestRetainedSource.ps1','lab/guest/Populate-GuestExistingTree.ps1','scripts/Prepare-LabExistingTree.ps1','lab/Lab.psm1','lab/lab.config.json','src/ntfs_freeze.rs','src/ntfs_backup.rs','src/ntfs_inspect.rs','src/lab_reconstruct.rs','src/bin/lab-ntfs-freeze.rs','crates/n2r-win32/src/native.rs','crates/n2r-win32/src/layout.rs','Cargo.toml','Cargo.lock')
$pins=@();foreach($p in $sourcePaths){$from=Join-Path $workspace $p;$to=Join-Path $output ('sources/'+$p);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath $from -Destination $to;$pins+=@([ordered]@{path=$p;sha256=(Get-FileHash -LiteralPath $to).Hash.ToLowerInvariant()})}
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-ntfs-freeze.exe');Save-New 'sources.json' $pins;Save-New 'started.json' $record
$credential=Import-Clixml -LiteralPath (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
function Connect-Guest {
 $deadline=[DateTime]::UtcNow.AddSeconds(240)
 do {try{return New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 throw 'Guest session unavailable; preserve current branch.'
}
function Invoke-Guest([scriptblock]$Body,[object[]]$Arguments=@(),[int]$Timeout=120){
 $script:job=Invoke-Command -Session $session -AsJob -ScriptBlock $Body -ArgumentList $Arguments
 if(-not(Wait-Job -Job $script:job -Timeout $Timeout)){$record.operationCompletionKnown=$false;throw 'Guest job still live or completion unknown; preserve branch and job.'}
 $reply=@(Receive-Job -Job $script:job -ErrorAction Stop)
 if($script:job.State-ne'Completed'){throw 'Guest job failed; preserve branch.'}
 Remove-Job -Job $script:job;$script:job=$null
 return $reply
}
function Export-File([string]$Guest,[string]$Name,[long]$Maximum=2MB){
 $meta=@(Invoke-Guest -Arguments @($Guest,$Maximum) -Body {param($Path,$Maximum);$i=Get-Item -LiteralPath $Path -Force;if($i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$i.Length-gt$Maximum){throw 'Bounded ordinary export required.'};[pscustomobject]@{length=$i.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}})
 if($meta.Count-ne1){throw 'Ambiguous export metadata.'};$dest=Join-Path $output $Name
 Copy-Item -LiteralPath $Guest -Destination $dest -FromSession $session
 if((Get-Item -LiteralPath $dest).Length-ne$meta[0].length-or(Get-FileHash -LiteralPath $dest).Hash.ToLowerInvariant()-cne$meta[0].sha256){throw 'Export hash differs.'}
 return $meta[0].sha256
}
function Run-Freeze([string]$Name,[bool]$Reopen){
 $record.phase=$Name
 $record.operationCompletionKnown=$false
 $reply=@(Invoke-Guest -Timeout 1920 -Arguments @($root,$Name,$Reopen,$BinarySha256) -Body {
  param($Root,$Name,$Reopen,$BinarySha)
  $ErrorActionPreference='Stop';$binary=$Root+'\lab-ntfs-freeze.exe';$request=$Root+'\freeze-request.json'
  if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$BinarySha){throw 'Guest binary pin differs.'}
  $requestSha=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$binary;$psi.Arguments='--request "'+$request+'" --request-sha256 '+$requestSha+' --output "'+$Root+'\'+$Name+'.json" --inspection-output "'+$Root+'\'+$Name+'.inspection.json"'+$(if($Reopen){' --reopen'}else{''});$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Freeze process did not start.'};$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\'+$Name+'.process.json',([ordered]@{pid=$p.Id;binarySha256=$BinarySha;requestSha256=$requestSha;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(1800000)){return [pscustomobject]@{status='native-still-running';pid=$p.Id;operationCompletionKnown=$false}}
  [IO.File]::WriteAllText($Root+'\'+$Name+'.stdout',$out.Result);[IO.File]::WriteAllText($Root+'\'+$Name+'.stderr',$err.Result)
  $report=Get-Content -LiteralPath ($Root+'\'+$Name+'.json') -Raw|ConvertFrom-Json
  if($p.ExitCode-ne0-or-not$report.success-or$report.phase-cne'complete-source-remains-offline-read-only'-or$report.basis.after.disk_attributes-ne3-or$report.native_bytes_written-ne0){throw ('Freeze failed; preserve artifacts: '+$err.Result)}
  $d=Get-Disk -Number 1;if(-not$d.IsOffline-or-not$d.IsReadOnly-or$d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'){throw 'Actual source exclusion differs.'}
  [pscustomobject]@{status='frozen';pid=$p.Id;sourceSha256=$report.basis.source_sha256;inspectionSha256=$report.inspection_sha256;bytesRead=$report.native_bytes_read;rawWrites=$report.native_bytes_written}
 })
 if($reply.Count-ne1-or$reply[0].status-cne'frozen'){if($reply.Count-eq1){$record['pendingNativeProcess']=$reply[0]};throw 'Native completion unverified; preserve branch and session.'}
 $record.operationCompletionKnown=$true
 foreach($suffix in @('.json','.intent.json','.inspection.json','.process.json','.stdout','.stderr')){[void](Export-File ($root+'\'+$Name+$suffix) ($Name+$suffix) $(if($suffix-eq'.inspection.json'){64MB}else{2MB}))}
 Save-New ($Name+'.reply.json') $reply[0]
 return $reply[0]
}
function Stop-Guest {
 Invoke-Guest -Timeout 30 -Body {& shutdown.exe /s /t 0;if($LASTEXITCODE-ne0){throw 'Shutdown request failed.'}}|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
 if($vm.State-ne'Off'){throw 'Guest still live; preserve branch.'}
 Remove-PSSession $session;$script:session=$null
}
try{
 Set-VMMemory -VM $vm -StartupBytes 8GB -DynamicMemoryEnabled $false;Start-VM -VM $vm|Out-Null
 $session=Connect-Guest;$ready=@(Initialize-LabGuestSession $session);if($ready.Count-ne1-or$ready[0].status-cne'ready'){throw 'Guest script policy initialization failed.'};Save-New 'session.json' $ready[0]
 Invoke-Guest -Arguments @($root) -Body {param($Root);foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\retained-source','C:\ntfs2refs\existing-tree',$Root,($Root+'\helpers'))){if(-not(Test-Path -LiteralPath $p)){New-Item -ItemType Directory -Path $p|Out-Null};$i=Get-Item -LiteralPath $p -Force;if(-not$i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary artifact ancestry required.'}}}|Out-Null
 foreach($p in $sourcePaths|Where-Object {$_-like'lab/guest/*'}){Copy-Item -LiteralPath (Join-Path $output ('sources/'+$p)) -Destination ($root+'\helpers\'+[IO.Path]::GetFileName($p)) -ToSession $session}
 Copy-Item -LiteralPath (Join-Path $output 'lab-ntfs-freeze.exe') -Destination ($root+'\lab-ntfs-freeze.exe') -ToSession $session
 $verified=@(Invoke-Guest -Arguments @($root,@($pins|Where-Object {$_.path-like'lab/guest/*'})) -Body {param($Root,$Pins);foreach($pin in $Pins){$file=$Root+'\helpers\'+[IO.Path]::GetFileName($pin.path);if((Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Guest helper pin differs.'};[pscustomobject]@{path=$pin.path;sha256=$pin.sha256}}})
 if($verified.Count-ne4){throw 'Copied source verification is incomplete.'};Save-New 'guest-source-pins.json' $verified
 $record.phase='prepare-source'
 $target=@($manifest.disks|Where-Object role -eq target)[0]|ConvertTo-Json -Compress
 $record.operationCompletionKnown=$false
 $prepared=@(Invoke-Guest -Timeout 300 -Arguments @($root,$run,$target) -Body {param($Root,$Run,$Target);& ($Root+'\helpers\Prepare-GuestRetainedSource.ps1') -RunId $Run -HostTargetJson $Target -Confirm:$false})
 if($prepared.Count-eq1-and$prepared[0].OperationCompletionKnown-is[bool]){$record.operationCompletionKnown=$prepared[0].OperationCompletionKnown}
 if($prepared.Count-ne1-or$prepared[0].Status-cne'ntfs-source-prepared'-or-not$prepared[0].OperationCompletionKnown){throw 'Source preparation failed; preserve branch.'}
 $platformSha=Export-File ('C:\ntfs2refs\retained-source\'+$run+'\prepare.json') 'platform.json'
 $record.operationCompletionKnown=$false
 $populated=@(Invoke-Guest -Arguments @($root,$run,$platformSha) -Body {param($Root,$Run,$PlatformSha);& ($Root+'\helpers\Populate-GuestExistingTree.ps1') -RunId $Run -PlatformSha256 $PlatformSha})
 if($populated.Count-ne1-or$populated[0].status-cne'populated-before-converter'-or$populated[0].files-ne4){throw 'Population failed; preserve branch.'}
 $record.operationCompletionKnown=$true
 foreach($name in @('population.intent.json','population.json','freeze-request.json')){[void](Export-File ($root+'\'+$name) $name)}
 $first=Run-Freeze 'freeze' $false
 Stop-Guest
 $vm=Get-OwnedLabVM $cfg $manifest;Start-VM -VM $vm|Out-Null;$session=Connect-Guest
 $second=Run-Freeze 'reopen' $true
 if($first.sourceSha256-cne$second.sourceSha256){throw 'Source changed across restart.'}
 Stop-Guest
 Assert-LabCapacity (Get-LabCapacity $cfg)
 $vm=Get-OwnedLabVM $cfg $manifest;$name='existing-tree-frozen-'+$run
 Checkpoint-VM -VM $vm -SnapshotName $name|Out-Null;$cp=Get-ExactLabCheckpoint -VM $vm -Name $name
 if($cp.State-ne'Off'-or$cp.MemoryStartup-ne8GB){throw 'Unexpected source outcome checkpoint.'}
 $record['sourceCheckpointId']=[string]$cp.Id;$record['sourceCheckpointName']=$name;$record['sourceSha256']=$first.sourceSha256
 $baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
 if($baseline.Id-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Baseline identity differs.'}
 Restore-VMSnapshot -VMSnapshot $baseline -Confirm:$false
 # The provider can briefly return the pre-restore configuration. Re-query the
 # same enrolled VM; never repeat the restore or alter a different branch.
 for($attempt=0;$attempt-lt15;$attempt++){
  $vm=Get-OwnedLabVM $cfg $manifest
  if($vm.State-eq'Off'-and$vm.MemoryStartup-eq4GB-and$vm.ParentSnapshotId-eq$baseline.Id){break}
  Start-Sleep -Milliseconds 1000
 }
 if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne$baseline.Id){throw 'Baseline restoration differs.'}
 $record.status='existing-tree-frozen-and-reopened';$record.phase='complete'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();$record['errorPosition']=$_.InvocationInfo.PositionMessage;throw}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save-New 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
