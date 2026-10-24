<# Query an already staged, read-only native NTFS corpus inside the owned VM.
Native source I/O is read-only. Artifact files are saved on the guest OS disk
and in the host lab store; source disk state and payload are not changed.
Use Invoke-GuestNtfsAttestation.ps1 for the separately bounded blank-disk setup. #>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [guid]$SourceCheckpointId='eda059b3-6d50-46bb-bdf4-018b99b5b34f')
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
$manifest=Read-LabManifest $configuration win11;$vm=Get-OwnedLabVM $configuration $manifest
if($vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or$vm.DynamicMemoryEnabled-or[guid]$vm.ParentSnapshotId-ne$SourceCheckpointId-or@(Get-VMNetworkAdapter -VM $vm|Where-Object SwitchName).Count){throw 'Exact running disposable source branch required.'}
if($SourceCheckpointId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){$cp=@(Get-VMCheckpoint -VM $vm|Where-Object Id -EQ $SourceCheckpointId);if($cp.Count-ne1-or$cp[0].Name-cne('ntfs-source-attestation-'+$RunId)-or$cp[0].State-ne'Off'-or$cp[0].MemoryStartup-ne8GB){throw 'Prepared source checkpoint identity differs.'}}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 32MB
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned bounded collector binary required.'}
$observation=[guid]::NewGuid().ToString('N');$guestRoot='C:\ntfs2refs\ntfs-attestation\'+$RunId
$output=Join-Path $configuration.Root ('ntfs-attestation/file-handles-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $output|Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-ntfs-file-attestation-capture';runId=$RunId;observationId=$observation;vmId=[string]$vm.Id;output=$output;guestRoot=$guestRoot;status='started';nativeIoWrites=0;conversionQualified=$false;error=$null}
function Save-CaptureJson([string]$Name,$Value){$b=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value|ConvertTo-Json -Depth 32));$f=New-Object IO.FileStream((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$nativePath=Join-Path $workspace 'lab/guest/NativeNtfsCorpusDisk.cs'
$nativeSha=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
$inspection=Join-Path $workspace '.lab/development/security-observation-20261024T130105835Z/control.json'
$inspectionSha='a1b25e0e0bcabe41455fd67a25c55b7017b6b8da9ac6437e0c062b7dc2b86baa'
if((Get-FileHash -LiteralPath $inspection -Algorithm SHA256).Hash.ToLowerInvariant()-cne$inspectionSha){throw 'Frozen source inspection differs.'}
$record['sourceCheckpointId']=[string]$SourceCheckpointId
$sources=@('Cargo.toml','Cargo.lock','lab/lab.config.json','crates/n2r-win32/Cargo.toml','crates/n2r-win32/src/attestation.rs','crates/n2r-win32/src/attestation_native.rs','crates/n2r-win32/src/stream_layout.rs','crates/n2r-win32/src/stream_native.rs','crates/n2r-win32/src/logical_hash.rs','src/ntfs_attestation.rs','src/ntfs_stream_attestation.rs','src/ntfs_data_attestation.rs','src/bin/lab-ntfs-attest.rs','lab/guest/NativeNtfsCorpusDisk.cs','lab/guest/Invoke-GuestNtfsAttestation.ps1','scripts/Capture-LabNtfsFileAttestation.ps1')
$sources+=@('crates/n2r-win32/src/lib.rs','crates/n2r-win32/src/namespace_layout.rs','crates/n2r-win32/src/namespace_native.rs','src/lib.rs','src/ntfs_namespace_attestation.rs','src/ntfs_admission.rs','src/ntfs_backup.rs','src/ntfs_inspect.rs')
$pins=@();foreach($path in $sources){$from=Join-Path $workspace $path;$to=Join-Path $output ('sources/'+$path);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath $from -Destination $to;$pins+=@([ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash.ToLowerInvariant()})}
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-ntfs-attest.exe');Save-CaptureJson 'sources.json' $pins
$credential=Import-Clixml -LiteralPath (Join-Path $configuration.Root 'win11/secrets/guest-credential.xml')
$session=New-PSSession -VMId $vm.Id -Credential $credential;$job=$null
try {
 Copy-Item -LiteralPath $binary.FullName -Destination ($guestRoot+'\'+$observation+'.exe') -ToSession $session
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($guestRoot,$observation,$BinarySha256,$nativeSha) -ScriptBlock {
  param($Root,$Observation,$BinarySha,$NativeSha);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  foreach($p in @('C:\','C:\ntfs2refs','C:\ntfs2refs\ntfs-attestation',$Root)){$f=Get-Item -LiteralPath $p -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary artifact ancestry required.'}}
  $prior=Get-Content -LiteralPath ($Root+'\guest-result.json') -Raw|ConvertFrom-Json
  $expected='86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727'
  if($prior.status-cne'collected'-or$prior.beforeSha256-cne$expected-or$prior.afterSha256-cne$expected-or-not$prior.readOnlyMount){throw 'Existing frozen read-only setup required.'}
  $d=Get-Disk -Number 1;if([string]$d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or$d.IsOffline-or-not$d.IsReadOnly-or[guid]$d.Guid-ne[guid]$prior.diskGuid){throw 'Original protected target differs.'}
  $native=$Root+'\NativeNtfsCorpusDisk.cs';$binary=$Root+'\'+$Observation+'.exe'
  if((Get-FileHash -LiteralPath $native -Algorithm SHA256).Hash.ToLowerInvariant()-cne$NativeSha-or(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$BinarySha){throw 'Guest native artifact pins differ.'}
  if(-not('Ntfs2Refs.NativeNtfsCorpusDisk'-as[type])){Add-Type -TypeDefinition (Get-Content -LiteralPath $native -Raw)}
  $before=[Ntfs2Refs.NativeNtfsCorpusDisk]::Hash([guid]$prior.diskGuid,[guid]$prior.partitionGuid,2)
  if($before-cne$expected){throw 'Pre-query corpus bytes differ.'}
  $request=$Root+'\request.json';$requestSha=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant()
  if($requestSha-cne$prior.requestSha256){throw 'Original request changed.'}
  $report=$Root+'\'+$Observation+'.json';$stdout=$Root+'\'+$Observation+'.stdout';$stderr=$Root+'\'+$Observation+'.stderr'
  if((Test-Path -LiteralPath $report)-or(Test-Path -LiteralPath $stdout)-or(Test-Path -LiteralPath $stderr)){throw 'Fresh observation outputs required.'}
  $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=$binary;$psi.Arguments='collect --request "'+$request+'" --request-sha256 '+$requestSha+' --output "'+$report+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=New-Object Diagnostics.Process;$p.StartInfo=$psi;if(-not$p.Start()){throw 'Collector failed to start.'};$outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
  if(-not$p.WaitForExit(120000)){throw ('Collector still running; preserve branch and PID '+$p.Id)}
  [IO.File]::WriteAllText($stdout,$outTask.Result);[IO.File]::WriteAllText($stderr,$errTask.Result)
  if($p.ExitCode-ne0){throw ('Collector failed: '+$errTask.Result)}
  $after=[Ntfs2Refs.NativeNtfsCorpusDisk]::Hash([guid]$prior.diskGuid,[guid]$prior.partitionGuid,2);if($after-cne$expected){throw 'Post-query corpus bytes differ.'}
  [pscustomobject]@{status='collected';beforeSha256=$before;afterSha256=$after;nativeSha256=(Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash.ToLowerInvariant();requestSha256=$requestSha;binarySha256=$BinarySha;nativeSourceSha256=$NativeSha;reportBytes=(Get-Item -LiteralPath $report).Length;pid=$p.Id;exitCode=$p.ExitCode}
 }
 if(-not(Wait-Job -Job $job -Timeout 180)){throw 'Guest capture remains live/unknown; preserve branch and job.'}
 $reply=@(Receive-Job -Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1-or$reply[0].status-cne'collected'-or$reply[0].reportBytes-gt16MB){throw 'Ambiguous/unbounded capture result.'}
 Save-CaptureJson 'guest-reply.json' $reply[0]
 Copy-Item -LiteralPath ($guestRoot+'\'+$observation+'.json') -Destination (Join-Path $output 'native.json') -FromSession $session
 Copy-Item -LiteralPath ($guestRoot+'\request.json') -Destination (Join-Path $output 'request.json') -FromSession $session
 if((Get-FileHash -LiteralPath (Join-Path $output 'native.json') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$reply[0].nativeSha256-or(Get-FileHash -LiteralPath (Join-Path $output 'request.json') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$reply[0].requestSha256){throw 'Export hash differs.'}
 & $binary.FullName compare --inspection $inspection --inspection-sha256 $inspectionSha --native (Join-Path $output 'native.json') --native-sha256 $reply[0].nativeSha256 --output (Join-Path $output 'comparison.json')
 if($LASTEXITCODE-ne0){throw 'Raw/native comparison failed.'}
 $record['nativeSha256']=$reply[0].nativeSha256;$record['comparisonSha256']=(Get-FileHash -LiteralPath (Join-Path $output 'comparison.json') -Algorithm SHA256).Hash.ToLowerInvariant();$record.status='captured'
}catch{$record.status='failed';$record.error=$_.Exception.ToString()}
finally{
 if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force;Remove-PSSession $session}
 elseif(-not$job){Remove-PSSession $session}
 Save-CaptureJson 'host-result.json' $record
}
[pscustomobject]$record
