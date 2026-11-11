# Ordinary filesystem workload and guest restart on a volume converted by the
# allocation-bounded mode. File I/O only: no raw device access, recovery,
# checkpoints or restores. Root boots the converted state separately.
[CmdletBinding()]param(
 [Parameter(Mandatory)][ValidatePattern('\AC:\\ProgramData\\ntfs2refs\\runs\\(?:[0-9a-f]{32}\\conversion|recovery-[0-9a-f]{32}\\resume)\z')][string]$ConversionRecords,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][string]$DigestToolPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DigestToolSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ConversionResultSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FinalizationSha256,
 [Parameter(Mandatory)][ValidatePattern('\AC:\\(?:ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion|ntfs2refs\\alloc-interrupt-[0-9a-f]{32}\\conversion)\\expectation[.]json\z')][string]$ExpectationPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectationSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedMainSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('alloc-mutation-20261029-'+$run)
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10));Need ($b.Length-le1MB) 'Small mutation receipt exceeds one MiB.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
function Guest([scriptblock]$Block,[object[]]$Arguments=@()){Invoke-Command -VMId $id -Credential $cred -ErrorAction Stop -ScriptBlock $Block -ArgumentList $Arguments}
function WaitGuest{$deadline=(Get-Date).AddMinutes(8);while((Get-Date)-lt$deadline){try{$null=Guest {$env:COMPUTERNAME};return}catch{Start-Sleep -Seconds 10}};throw 'Guest did not return after restart.'}
function HostGuard{$v=Get-VM -Id $id;Need ($v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0) 'Converted lab VM must be running on the expected parent.'}
$idle={
 $ErrorActionPreference='Stop'
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-ne0-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-ne0){throw 'Project workers must be inactive before mutation or shutdown.'}
}
HostGuard
New-Item -ItemType Directory -Path $root|Out-Null
# Shared guest verifier: original user files from the admitted expectation, plus
# the mutation manifest when present. System Volume Information is excluded.
$verify={param($Records,$Manifest,$Tool,$ToolPin,$ResultPin,$FinalPin,$ExpectedPath,$ExpectedPin)
 $ErrorActionPreference='Stop';$vol=Get-Volume -DriveLetter F;$disk=Get-Disk -Number 1
 function ReadPinned([string]$Path,[string]$Pin){
  $m=Get-Item -LiteralPath $Path -Force
  if($m.PSIsContainer-or($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$m.Length-le0-or$m.Length-gt64MB){throw 'Bounded ordinary conversion record required.'}
  $a=$m.Directory;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse conversion ancestry.'};$a=$a.Parent}
  if((Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()-cne$Pin){throw 'Pinned conversion record changed.'}
  return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)
 }
 $r=ReadPinned (Join-Path $Records 'result.json') $ResultPin
 $resumed=$Records-cmatch '\\recovery-[0-9a-f]{32}\\resume\z'
 $finalName=if($resumed){'completion.json'}else{'finalization.json'}
 $f=ReadPinned (Join-Path $Records $finalName) $FinalPin
 if($r.success-ne$true-or$f.success-ne$true-or$f.rollback_closed-ne$true-or$null-ne$f.error-or$f.mount_paths_preserved-ne$true){throw 'Successful completed allocation conversion required.'}
 if($resumed){
  if($r.kind-cne'allocation-bounded-recovery'-or$r.outcome-cne'refs_completed'-or$r.action-notin@('resume','verify_handoff')-or$r.source_admitted-ne$false-or$r.fresh_apply_authorized-ne$false){throw 'Successful ReFS resume result required.'}
  $bundlePath=Join-Path $Records 'bundle.json';$bundleMeta=Get-Item -LiteralPath $bundlePath -Force
  if($bundleMeta.PSIsContainer-or($bundleMeta.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$bundleMeta.Length-le0-or$bundleMeta.Length-gt65536){throw 'Bounded saved recovery bundle required.'}
  $bundle=[IO.File]::ReadAllText($bundlePath)|ConvertFrom-Json
  if($bundle.kind-cne'allocation-bounded-recovery-bundle'-or$bundle.expectation.path-cne$ExpectedPath-or$bundle.expectation.sha256-cne$ExpectedPin){throw 'Resume bundle does not name the pinned expectation.'}
  $ticket=ReadPinned (Join-Path $Records 'selected-ticket.json') $bundle.ticket.sha256
 }else{
  if($r.kind-cne'experimental-allocation-bounded-conversion'-or$r.source_admitted-ne$true-or$r.rollback_closed-ne$true-or$r.expected_tree_sha256-cne$ExpectedPin-or$ExpectedPath-cne(Join-Path $Records 'expectation.json')){throw 'Completed conversion does not name the pinned expectation.'}
  $ticket=ReadPinned (Join-Path $Records 'selected-ticket.json') $r.ticket_sha256
 }
 $e=ReadPinned $ExpectedPath $ExpectedPin
 $handoffName=if($resumed-and$r.action-eq'verify_handoff'){'verified-handoff.json'}else{'handoff.json'}
 $hfile=Get-Item -LiteralPath (Join-Path $Records $handoffName) -Force
 if($hfile.PSIsContainer-or($hfile.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$hfile.Length-gt65536){throw 'Bounded ordinary handoff record required.'}
 $h=[IO.File]::ReadAllText($hfile.FullName)|ConvertFrom-Json
 $sameDigest=@($h.selected_sha256).Count-eq32-and@($ticket.new_selected_sha256).Count-eq32
 if($sameDigest){for($i=0;$i-lt32;$i++){if($h.selected_sha256[$i]-ne$ticket.new_selected_sha256[$i]){$sameDigest=$false;break}}}
 if($h.replay_closed-ne$true-or$h.selected_bytes-ne$ticket.selected_bytes-or$h.range_count-ne$ticket.range_count-or-not$sameDigest){throw 'Completed HND does not match the selected ticket; this workload cannot replay a journal.'}
 $m=Get-Item -LiteralPath $Tool -Force
 if($m.PSIsContainer-or($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$m.Length-le0-or$m.Length-gt64MB-or(Get-FileHash -LiteralPath $Tool).Hash.ToLowerInvariant()-cne$ToolPin){throw 'Pinned staged content-digest tool differs.'}
 $files=@($e.objects|Where-Object {-not $_.directory -and $_.path[0] -cne 'System Volume Information'})
 # Records carry the XXH3-128 content digest; lab-content-digest computes it in argument order.
 $paths=@($files|ForEach-Object {
  foreach($part in $_.path){if($part-isnot[string]-or$part.Length-eq0-or$part-in@('.','..')-or$part-match'[\\/"\x00-\x1f]'){throw 'Invalid expected file path.'}}
  'F:\'+($_.path -join '\')
 })
 $digests=[Collections.Generic.List[object]]::new();$next=0;$batches=0
 while($next-lt$paths.Count){
  $batch=[Collections.Generic.List[string]]::new();$characters=$Tool.Length+2
  while($next-lt$paths.Count-and$batch.Count-lt64){
   $cost=$paths[$next].Length+3
   if($characters+$cost-gt20000){if($batch.Count-eq0){throw 'A digest path exceeds the bounded command line.'};break}
   $batch.Add($paths[$next]);$characters+=$cost;$next++
  }
  $arguments=$batch.ToArray();$lines=@(& $Tool @arguments);$exit=$LASTEXITCODE
  if($exit-ne0){throw ('Content-digest tool exited '+$exit)}
  $json=$lines-join'';if($json.Length-gt16384){throw 'Digest output exceeds the bounded batch.'}
  $values=@($json|ConvertFrom-Json|ForEach-Object {$_})
  if($values.Count-ne$batch.Count){throw 'Digest result count differs from ordered path batch.'}
  foreach($value in $values){if($value-isnot[string]-or$value-cnotmatch'\A[0-9a-f]{32}\z'){throw 'Digest tool could not read a file.'};$digests.Add($value)}
  $batches++
 }
 $ok=0;$bad=@();for($i=0;$i-lt$files.Count;$i++){$o=$files[$i];$p=$paths[$i];if(-not(Test-Path -LiteralPath $p)){$bad+="missing $p";continue};if($digests.Count-eq$files.Count-and$digests[$i]-ceq$o.sha256-and(Get-Item -LiteralPath $p).Length-eq$o.length){$ok++}else{$bad+="differs $p"}}
 $mut=$null;if($Manifest){$m=$Manifest|ConvertFrom-Json;$mok=0;foreach($f in $m.files){$p=$f.path;if((Test-Path -LiteralPath $p)-and(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-ceq$f.sha256){$mok++}else{$bad+="mutation differs $p"}};$deletedAbsent=-not(Test-Path -LiteralPath $m.deleted);$entries=@(Get-ChildItem -LiteralPath $m.entries_dir -File).Count;$mut=@{files_expected=@($m.files).Count;files_matching=$mok;deleted_absent=$deletedAbsent;entries_expected=$m.entries;entries_present=$entries}}
 if([guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$disk.IsBoot-or$disk.IsSystem){throw 'Converted source identity differs.'}
 @{filesystem=$vol.FileSystem;cluster=$vol.AllocationUnitSize;label=$vol.FileSystemLabel;disk1_online=(-not $disk.IsOffline);original_user_files=$files.Count;original_user_files_matching=$ok;expected_tree_sha256=$ExpectedPin;resumed_conversion=$resumed;digest_batches=$batches;digest_batch_max_files=64;digest_command_max_utf16=20000;mutation=$mut;problems=$bad;utc=[DateTime]::UtcNow.ToString('o')}}
try{
 # Stage the read-only content-digest tool; its pin is saved with the results.
 Guest $idle
 $digestTool=[IO.Path]::GetFullPath($DigestToolPath);$toolInfo=Get-Item -LiteralPath $digestTool -Force
 Need (-not$toolInfo.PSIsContainer-and-not($toolInfo.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$toolInfo.Length-gt0-and$toolInfo.Length-le64MB-and(Get-FileHash -LiteralPath $digestTool).Hash.ToLowerInvariant()-ceq$DigestToolSha256) 'Explicit pinned digest tool required.'
 $ancestor=$toolInfo.Directory;while($null-ne$ancestor){Need (-not($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse digest-tool ancestry.';$ancestor=$ancestor.Parent}
 $toolStage='C:\ntfs2refs\mutation-'+$run;$guestTool=Join-Path $toolStage 'lab-content-digest.exe';$session=New-PSSession -VMId $id -Credential $cred
 try{Invoke-Command -Session $session -ArgumentList $toolStage -ScriptBlock {param($Stage);$ErrorActionPreference='Stop';if(Test-Path -LiteralPath $Stage){throw 'Fresh digest stage required.'};$a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse digest-stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null};Copy-Item -LiteralPath $digestTool -ToSession $session -Destination $guestTool}finally{Remove-PSSession $session}
 Save 'content-digest-tool.json' @{path=$digestTool;guest_path=$guestTool;sha256=$DigestToolSha256;algorithm='xxh3-128'}
 Save 'conversion-pins.json' @{conversion_records=$ConversionRecords;result_sha256=$ConversionResultSha256;finalization_sha256=$FinalizationSha256;expectation_path=$ExpectationPath;expectation_sha256=$ExpectationSha256;source_commit=$SourceCommit;main_sha256=$ExpectedMainSha256;build_provenance_supplied_by_controller=$true;expected_parent=$ExpectedParent.ToString()}
 $before=Guest $verify @($ConversionRecords,$null,$guestTool,$DigestToolSha256,$ConversionResultSha256,$FinalizationSha256,$ExpectationPath,$ExpectationSha256);Save 'verify-before.json' $before
 Need ($before.filesystem-ceq'ReFS'-and$before.cluster-eq4096-and$before.label-ceq'n2r-stream-source'-and$before.disk1_online-and$before.original_user_files_matching-eq$before.original_user_files-and$before.original_user_files-gt0) 'Converted ReFS baseline differs before mutation.'
 Guest $idle
 $mutation=Guest {param($Run)
  $ErrorActionPreference='Stop';$dir="F:\n2r-mutation-$Run";if(Test-Path -LiteralPath $dir){throw 'Fresh mutation directory required.'};New-Item -ItemType Directory -Path $dir|Out-Null
  $rng=[Random]::new(20261029);$made=@()
  foreach($spec in @(@{name='fifty.bin';mib=50},@{name='eighty.bin';mib=80},@{name='ten.bin';mib=10})){$p=Join-Path $dir $spec.name;$fs=[IO.File]::Open($p,'CreateNew','Write','None');try{$buf=[byte[]]::new(1MB);for($i=0;$i-lt$spec.mib;$i++){$rng.NextBytes($buf);$fs.Write($buf,0,$buf.Length)};$fs.Flush($true)}finally{$fs.Dispose()};$made+=@{path=$p;sha256=(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()}}
  $renamed=Join-Path $dir 'eighty-renamed.bin';Move-Item -LiteralPath (Join-Path $dir 'eighty.bin') -Destination $renamed;($made|Where-Object {$_.path -like '*eighty.bin'}).path=$renamed
  $deleted=Join-Path $dir 'ten.bin';Remove-Item -LiteralPath $deleted;$made=@($made|Where-Object {$_.path -ne $deleted})
  $entries=Join-Path $dir 'entries';New-Item -ItemType Directory -Path $entries|Out-Null;$small=[byte[]]::new(4096);for($i=0;$i-lt128;$i++){$rng.NextBytes($small);[IO.File]::WriteAllBytes((Join-Path $entries ('entry-{0:D3}.bin'-f$i)),$small)}
  Write-VolumeCache -DriveLetter F
  @{directory=$dir;files=$made;deleted=$deleted;entries_dir=$entries;entries=128;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5 -Compress
 } @($run)
 Save 'mutation-manifest.json' ($mutation|ConvertFrom-Json)
 $afterMutation=Guest $verify @($ConversionRecords,$mutation,$guestTool,$DigestToolSha256,$ConversionResultSha256,$FinalizationSha256,$ExpectationPath,$ExpectationSha256);Save 'verify-after-mutation.json' $afterMutation
 Need (@($afterMutation.problems).Count-eq0-and$afterMutation.mutation.files_matching-eq2-and$afterMutation.mutation.deleted_absent-and$afterMutation.mutation.entries_present-eq128) 'Mutation verification failed before restart.'
 # Clean guest shutdown and cold start, as in the frozen alpha's reboot check.
 HostGuard;Guest $idle
 $rebootStart=[DateTime]::UtcNow;Stop-VM -VM (Get-VM -Id $id) -ErrorAction Stop
 $deadline=(Get-Date).AddMinutes(4);while((Get-VM -Id $id).State.ToString()-cne'Off'-and(Get-Date)-lt$deadline){Start-Sleep -Seconds 5};Need ((Get-VM -Id $id).State.ToString()-ceq'Off') 'Guest did not shut down cleanly.'
 Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop;WaitGuest
 HostGuard;Guest $idle
 $afterReboot=Guest $verify @($ConversionRecords,$mutation,$guestTool,$DigestToolSha256,$ConversionResultSha256,$FinalizationSha256,$ExpectationPath,$ExpectationSha256);Save 'verify-after-reboot.json' $afterReboot
 $events=Guest {param($Since)$ErrorActionPreference='Stop';@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=[DateTime]$Since} -ErrorAction SilentlyContinue|Where-Object {$_.ProviderName -match 'ReFS' -and $_.Level -le 3}|Select-Object -First 50|ForEach-Object {@{id=$_.Id;level=$_.Level;provider=$_.ProviderName;time=$_.TimeCreated.ToUniversalTime().ToString('o');message=($_.Message -split "`n")[0]}})} @((Get-Content -LiteralPath (Join-Path $root 'verify-before.json') -Raw|ConvertFrom-Json).utc)
 Save 'refs-system-events.json' @{refs_warning_or_error_events_since_baseline=@($events).Count;events=$events}
 Need ($afterReboot.filesystem-ceq'ReFS'-and$afterReboot.label-ceq'n2r-stream-source'-and@($afterReboot.problems).Count-eq0-and$afterReboot.original_user_files_matching-eq$afterReboot.original_user_files-and$afterReboot.mutation.files_matching-eq2-and$afterReboot.mutation.deleted_absent-and$afterReboot.mutation.entries_present-eq128) 'Post-restart verification failed.'
 Save 'result.json' @{schema_version=1;kind='allocation-bounded-mutation-and-restart';success=$true;run_id=$run;conversion_records=$ConversionRecords;conversion_result_sha256=$ConversionResultSha256;finalization_sha256=$FinalizationSha256;expectation_path=$ExpectationPath;source_commit=$SourceCommit;main_sha256=$ExpectedMainSha256;build_provenance_supplied_by_controller=$true;content_digest_tool_sha256=$DigestToolSha256;expected_tree_sha256=$afterReboot.expected_tree_sha256;resumed_conversion=$afterReboot.resumed_conversion;original_user_files_verified=$afterReboot.original_user_files;new_files_verified=2;entries_verified=128;restart_issued_utc=$rebootStart.ToString('o');refs_warning_or_error_events=@($events).Count;raw_device_access=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'result.json') -Raw
}catch{Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false};throw}
