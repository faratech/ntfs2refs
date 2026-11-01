# Owning-guest NTFS-managed preparation; no raw conversion/recovery or VM power.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$HostCase,
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][string]$RoutingSeed,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RoutingSeedSha256,
 [Parameter(Mandatory)][string]$ContentExpectation,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ContentExpectationSha256
)
$ErrorActionPreference='Stop'
$base='D:\code\ntfs2refs\.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$held=[Collections.Generic.List[IO.FileStream]]::new()
$session=$null
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function Hold([string]$path,[string]$pin,[long]$max){
 $p=[IO.Path]::GetFullPath($path)
 Need ($p-ceq$path-and$p.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Pinned input must be under the owned lab root.'
 $m=Get-Item -LiteralPath $p -Force
 Need (-not$m.PSIsContainer-and$m.Length-le$max-and($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-eq0) 'Bounded ordinary input required.'
 $f=[IO.File]::Open($p,'Open','Read','Read');$held.Add($f)
 $sha=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($sha.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 Need ($actual-ceq$pin) 'Input pin differs.'
 return @{path=$p;bytes=$f.Length;sha256=$pin}
}
try{
 Need ($HostCase.StartsWith($base+'\ntfs-owned-preparation-',[StringComparison]::OrdinalIgnoreCase)-and(Test-Path -LiteralPath (Join-Path $HostCase 'restored.json'))-and-not(Test-Path -LiteralPath (Join-Path $HostCase 'dispatch.json'))) 'One fresh root-owned restored case required.'
 $manifestPin=Hold $ToolsetManifest $ToolsetManifestSha256 1MB
 $manifest=Get-Content -LiteralPath $ToolsetManifest -Raw -Encoding UTF8|ConvertFrom-Json
 Need ($manifest.schema_version-eq1-and$manifest.kind-ceq'ntfs-owned-preparation-toolset'-and@($manifest.tools).Count-eq3) 'Three pinned roles required.'
 $tools=@()
 foreach($name in @('lab-prepare-ntfs.exe','lab-managed-shadow.exe','lab-content-digest.exe')){
  $rows=@($manifest.tools|Where-Object name -CEQ $name);Need ($rows.Count-eq1) 'Unique native role required.'
  $tools+=Hold $rows[0].path $rows[0].sha256 64MB
  $tools[-1].name=$name
 }
 $seedPin=Hold $RoutingSeed $RoutingSeedSha256 131072
 $expectedPin=Hold $ContentExpectation $ContentExpectationSha256 64MB
 $v=Get-VM -Id $vmId
 Need ($v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'-and$v.MemoryAssigned-eq4GB-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and@(Get-VMSnapshot -VM $v).Count-eq10) 'Exact already-running clean source and10 retained checkpoints required.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $capacity=Get-LabCapacity -Configuration (Get-LabConfiguration)
 Assert-LabCapacity -Capacity $capacity -AdditionalBytes 16GB
 $run=Split-Path -Leaf $HostCase
 $stage='C:\ntfs2refs\'+$run
 $task='N2R-'+$run
 $c=@{stage=$stage;task=$task;tools=$tools;source_commit=$manifest.preparation_source_commit;seed_sha256=$RoutingSeedSha256;expectation_sha256=$ContentExpectationSha256;maximum_payload_bytes=52GB}
 $body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'configuration.json') -Raw -Encoding UTF8|ConvertFrom-Json
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function Save([string]$name,$value){$p=Join-Path $c.stage $name;$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 32));$f=[IO.File]::Open($p,'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Source{
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
 Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.Size-eq64GB-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Offset-eq16MB-and$p.Size-eq52GB-and'F:\'-in@($p.AccessPaths)-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source'-and(Get-Partition -DriveLetter C).DiskNumber-eq0) 'Actual clean F1 source differs.'
}
function Idle{
 Need (@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0-and@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0) 'Other project work is live.'
}
function Native([string]$name,[string[]]$argv,[string]$role){
 $tool=@($c.tools|Where-Object name -CEQ $name);Need ($tool.Count-eq1) 'Unique pinned tool required.'
 $exe=Join-Path $c.stage $name;Need ((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()-ceq$tool[0].sha256) 'Staged tool pin differs.'
 $args=($argv|ForEach-Object{Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe native argument.';$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'})-join' '
 $out=Join-Path $c.stage ($role+'.stdout.log');$err=Join-Path $c.stage ($role+'.stderr.log')
 Save ($role+'-intent.json') @{binary=$exe;binary_sha256=$tool[0].sha256;argv=$argv;utc=[DateTime]::UtcNow.ToString('o')}
 $p=Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $c.stage -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
 try{$null=$p.Handle;Save ($role+'-process.json') @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();handle_retained=$true};$p.WaitForExit();$p.Refresh();$exit=$p.ExitCode;Save ($role+'-terminal.json') @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();native_exit=$exit;utc=[DateTime]::UtcNow.ToString('o')};Need ($null-ne$exit-and$exit-eq0) ($role+' native exit differs; no retry.')}finally{$p.Dispose()}
}
$phase='preflight'
try{
 Idle;Source
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and@(Get-Disk).Count-eq6-and@(Get-Disk|Where-Object Number -ge 6).Count-eq0) 'Fresh guest/shadow slot required.'
 Save 'worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();utc=[DateTime]::UtcNow.ToString('o')}
 $seedPath=Join-Path $c.stage 'routing-seed.json';$expectedPath=Join-Path $c.stage 'content-expectation.json'
 Need ((Get-FileHash -LiteralPath $seedPath).Hash.ToLowerInvariant()-ceq$c.seed_sha256-and(Get-FileHash -LiteralPath $expectedPath).Hash.ToLowerInvariant()-ceq$c.expectation_sha256) 'Copied routing/content pins differ.'
 $seed=Get-Content -LiteralPath $seedPath -Raw -Encoding UTF8|ConvertFrom-Json
 Need ($seed.pair.source.disk_number-eq1-and[guid]$seed.pair.source.identity.partition_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617') 'Only exact source routing reused.'
 $phase='new-native-shadow'
 $managed=Join-Path $c.stage 'managed-shadow';New-Item -ItemType Directory -Path $managed|Out-Null
 Native 'lab-managed-shadow.exe' @('--directory',$managed,'--partition-bytes','55834574848','--acknowledge-new-disposable-staging') 'managed'
 $made=Get-Content -LiteralPath (Join-Path $managed 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json
 Need ($made.success-and$made.binding.disk_number-eq6-and$made.source_writes-eq0-and-not$made.source_binding_supplied) 'Actual new managed shadow differs.'
 $r=[ordered]@{schema_version=3;verification_policy='extent_identity_v1';selected_capacity_policy='source_free_actual_bytes_v1';source_resource_profile=@{experimental_object_envelope_v3=$null};experiment_id=([guid]::NewGuid().ToString('N'));pair=@{source=$seed.pair.source;shadow=$made.binding};journal=$seed.journal;max_journal_bytes=8GB;max_literal_backing_bytes=256MB;max_combined_scratch_bytes=10GB;verify_existing_shadow=$false}
 Save 'request.json' $r
 $request=Join-Path $c.stage 'request.json';$pin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
 $phase='ntfs-owned-preparation'
 Native 'lab-prepare-ntfs.exe' @('--request',$request,'--request-sha256',$pin,'--output',(Join-Path $c.stage 'preparation'),'--acknowledge-ntfs-managed-preparation','--maximum-payload-bytes',([string]$c.maximum_payload_bytes)) 'preparation'
 $result=Get-Content -LiteralPath (Join-Path $c.stage 'preparation\result.json') -Raw -Encoding UTF8|ConvertFrom-Json
 Need ($result.moved_bytes-gt0-and$result.verified_moves-gt0-and-not$result.source_admitted-and$result.fresh_source_inventory_and_certificate_required-and$result.final_native_placement_required) 'Actual verified moves and fresh-admission boundary required.'
 Source;Idle
 $phase='independent-contents'
 $expected=Get-Content -LiteralPath $expectedPath -Raw -Encoding UTF8|ConvertFrom-Json
 $files=@($expected.objects|Where-Object {-not$_.directory});Need ($files.Count-eq811) 'Full811 stream baseline required.'
 $rows=[Collections.Generic.List[object]]::new();$batch=[Collections.Generic.List[string]]::new();$want=[Collections.Generic.List[string]]::new();$batchNumber=0;$matched=0;$chars=0
 function FinishBatch{
  if($batch.Count-eq0){return}
  $role='contents-'+$script:batchNumber
  Native 'lab-content-digest.exe' (@('--backup-read')+$batch.ToArray()) $role
  $actual=Get-Content -LiteralPath (Join-Path $c.stage ($role+'.stdout.log')) -Raw -Encoding UTF8|ConvertFrom-Json
  Need ($actual.Count-eq$want.Count) 'Digest batch coverage differs.'
  for($i=0;$i-lt$actual.Count;$i++){Need ($actual[$i]-ceq$want[$i]) 'Independent logical contents changed.';$rows.Add(@{path=$batch[$i];expected=$want[$i];actual=$actual[$i]});$script:matched++}
  $batch.Clear();$want.Clear();$script:chars=0;$script:batchNumber++
 }
 foreach($o in $files){
  Need ($o.sha256-cmatch'\A[0-9a-f]{32}\z') 'Actual full-content reference required.'
  $named=$o.PSObject.Properties['named_streams'];Need ($null-eq$named-or@($named.Value).Count-eq0) 'This source baseline must have no named streams.'
  $parts=@();foreach($component in $o.path){Need ($component-is[string]) 'Canonical string path component required.';$part=[string]$component;Need ($part-cnotmatch'[\\/:"\r\n\x00]') 'Ordinary baseline component required.';$parts+=@($part)}
  $p='F:\'+($parts-join'\');Need ((Get-Item -LiteralPath $p -Force).Length-eq$o.length) 'Post-preparation EOF differs.'
  if($batch.Count-ge128-or$chars+$p.Length+3-gt24000){FinishBatch}
  $batch.Add($p);$want.Add($o.sha256);$chars+=$p.Length+3
 }
 FinishBatch
 Need ($matched-eq811) 'Incomplete independent content coverage.'
 Save 'independent-contents.json' @{success=$true;complete_default_stream_hashes=$matched;baseline_sha256=$c.expectation_sha256;rows=$rows.ToArray();raw_source_replayed=$false}
 Source;Idle
 Save 'result.json' @{success=$true;kind='ntfs-owned-preparation-native-observation';preparation=$result;independent_hashes=$matched;source_is_ntfs=$true;conversion_or_raw_replay_started=$false;fresh_source_certificate_required=$true;metadata_preservation_beyond_mover_observations_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'failed.json' @{phase=$phase;error=$_.Exception.Message;retry_performed=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
 Need ($errors.Count-eq0) 'Guest script syntax differs.'
 [IO.File]::WriteAllText((Join-Path $HostCase 'guest.ps1'),$body,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $HostCase 'configuration.json'),($c|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $base '..\win11\secrets\guest-credential.xml'))
 Invoke-Command -Session $session -ScriptBlock {param($p)if(Test-Path -LiteralPath $p){throw 'Fresh guest stage required'};New-Item -ItemType Directory -Path $p|Out-Null} -ArgumentList $stage
 foreach($t in $tools){Copy-Item -LiteralPath $t.path -Destination (Join-Path $stage $t.name) -ToSession $session}
 Copy-Item -LiteralPath $RoutingSeed -Destination (Join-Path $stage 'routing-seed.json') -ToSession $session
 Copy-Item -LiteralPath $ContentExpectation -Destination (Join-Path $stage 'content-expectation.json') -ToSession $session
 foreach($leaf in @('guest.ps1','configuration.json')){Copy-Item -LiteralPath (Join-Path $HostCase $leaf) -Destination (Join-Path $stage $leaf) -ToSession $session}
 $dispatch=@{kind='ntfs-owned-preparation-dispatch';stage=$stage;task=$task;toolset_manifest_pin=$manifestPin;content_baseline=$expectedPin;routing_only_seed=$seedPin;source_commit=$manifest.preparation_source_commit;capacity=$capacity;forecast_bytes=16GB;utc=[DateTime]::UtcNow.ToString('o')}
 $dispatch|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $HostCase 'dispatch.json')
 Invoke-Command -Session $session -ScriptBlock {param($stage,$task)$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $stage 'guest.ps1')+'"') -WorkingDirectory $stage;$principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40);Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null;Start-ScheduledTask -TaskName $task;[pscustomobject]@{stage=$stage;task=$task;state=(Get-ScheduledTask -TaskName $task).State.ToString()}} -ArgumentList $stage,$task
}finally{if($null-ne$session){Remove-PSSession $session};foreach($f in $held){$f.Dispose()}}
