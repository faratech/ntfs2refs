<# Continue only a measured existing shadow branch. No create/format/restore-VM
   operations are exposed. Failed native results are exported, never retried. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [Parameter(Mandatory)][ValidateSet('RootSecurity','Construct','Verify','FinalizeSecurity','Freeze')][string]$Mode)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $Directory $cfg.Root
$start=Get-Content (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$request=Get-Content (Join-Path $directory 'request.json') -Raw|ConvertFrom-Json
$requestSha=(Get-FileHash (Join-Path $directory 'request.json')).Hash.ToLowerInvariant()
if($vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or[guid]$vm.ParentSnapshotId-ne[guid]$start.sourceCheckpointId-or$request.source.disk_number-ne1-or$request.shadow.disk_number-ne3-or$request.source_sha256-cne$start.sourceSha256){throw 'Existing running source/shadow branch differs.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 32MB
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned binary required.'}
$step=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\tree-shadow\'+$start.runId
$output=Assert-LabPath (Join-Path $cfg.Root ('existing-tree-shadow-steps/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$p=Join-Path $output $Name;$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{kind='existing-shadow-native-step';stepId=$step;mode=$Mode;parentDirectory=$directory;runId=$start.runId;binarySha256=$BinarySha256;requestSha256=$requestSha;status='started';operationCompletionKnown=$true;sourceAdmitted=$false;conversionQualified=$false;error=$null}
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-tree-shadow.exe')
Copy-Item -LiteralPath (Join-Path $directory 'request.json') -Destination (Join-Path $output 'request.json')
$pins=@();foreach($p in @('src/bin/lab-tree-shadow.rs','src/shadow_tree.rs','src/tree_placement.rs','crates/n2r-win32/src/shadow_native.rs','crates/n2r-win32/src/region_layout.rs','crates/n2r-win32/src/bitmap_layout.rs','src/ntfs_freeze.rs','scripts/Continue-LabExistingTreeShadow.ps1','Cargo.toml','crates/n2r-win32/Cargo.toml','.cargo/config.toml','Cargo.lock')){
 $to=Join-Path $output ('sources/'+$p);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $workspace $p) -Destination $to;$pins+=@([pscustomobject]@{path=$p;sha256=(Get-FileHash $to).Hash.ToLowerInvariant()})
};Save 'sources.json' $pins;Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=New-PSSession -VMId $vm.Id -Credential $credential;$job=$null
try{
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\lab-tree-shadow-'+$step+'.exe') -ToSession $session
 $record.operationCompletionKnown=$false
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$step,$Mode,$BinarySha256,$requestSha,$request) -ScriptBlock {
  param($Root,$Step,$Mode,$BinarySha,$RequestSha,$Request)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function CheckSource{$d=Get-Disk -Number 1;if($d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or[guid]$d.Guid-ne[guid]$Request.source.identity.disk_guid-or-not$d.IsOffline-or-not$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem){throw 'Source exclusion or identity differs.'}}
  CheckSource
  if(Get-Process -Name 'lab-tree-shadow*','lab-native-reconstruct*' -ErrorAction SilentlyContinue){throw 'Native operation already live.'}
  $exe=$Root+'\lab-tree-shadow-'+$Step+'.exe';$req=$Root+'\request.json'
  if((Get-FileHash $exe).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash $req).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Copied binary or existing request differs.'}
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$exe;$psi.Arguments='--request "'+$req+'" --request-sha256 '+$RequestSha+' --output "'+$Root+'\'+$Step+'.json"'
  if($Mode-ceq'RootSecurity'){$psi.Arguments+=' --root-security-experiment'}elseif($Mode-ceq'Verify'){$psi.Arguments+=' --verify-only'}
  elseif($Mode-ceq'FinalizeSecurity'){$psi.Arguments+=' --finalize-security'}
  elseif($Mode-ceq'Freeze'){$psi.Arguments+=' --verify-only --freeze-shadow'}
  $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Native process failed to start.'};$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\'+$Step+'.process.json',([ordered]@{pid=$p.Id;executable=$exe;arguments=$psi.Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(900000)){throw ('Native operation still live; preserve PID '+$p.Id)}
  [IO.File]::WriteAllText($Root+'\'+$Step+'.stdout',$out.Result);[IO.File]::WriteAllText($Root+'\'+$Step+'.stderr',$err.Result);CheckSource
  [pscustomobject]@{status='native-exit-observed';exitCode=$p.ExitCode;reportSha256=(Get-FileHash ($Root+'\'+$Step+'.json')).Hash.ToLowerInvariant()}
 }
 if(-not(Wait-Job $job -Timeout 1200)){throw 'Native operation live/unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1-or$reply[0].status-cne'native-exit-observed'){throw 'Native completion unknown.'}
 $record.operationCompletionKnown=$true;Save 'guest-reply.json' $reply[0]
 foreach($pair in @(@('.json','report.json'),@('.intent.json','intent.json'),@('.process.json','process.json'),@('.stdout','stdout'),@('.stderr','stderr'))){Copy-Item -LiteralPath ($root+'\'+$step+$pair[0]) -Destination (Join-Path $output $pair[1]) -FromSession $session}
 if((Get-FileHash (Join-Path $output 'report.json')).Hash.ToLowerInvariant()-cne$reply[0].reportSha256){throw 'Exported report differs.'}
 $report=Get-Content (Join-Path $output 'report.json') -Raw|ConvertFrom-Json
 $record['exitCode']=$reply[0].exitCode;$record['reportSha256']=$reply[0].reportSha256
 $record.status=if($reply[0].exitCode-eq0-and$report.success){'native-step-verified'}else{'native-step-failed-terminal'}
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
