# Ordinary filesystem workload and guest restart on a volume converted by the
# allocation-bounded mode. File I/O only: no raw device access, recovery,
# checkpoints or restores. Root boots the converted state separately.
[CmdletBinding()]param(
 [Parameter(Mandatory)][ValidatePattern('\AC:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion\z')][string]$ConversionRecords,
 [Parameter(Mandatory)][guid]$ExpectedParent
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('alloc-mutation-20261029-'+$run)
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10));$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
function Guest([scriptblock]$Block,[object[]]$Arguments=@()){Invoke-Command -VMId $id -Credential $cred -ErrorAction Stop -ScriptBlock $Block -ArgumentList $Arguments}
function WaitGuest{$deadline=(Get-Date).AddMinutes(8);while((Get-Date)-lt$deadline){try{$null=Guest {$env:COMPUTERNAME};return}catch{Start-Sleep -Seconds 10}};throw 'Guest did not return after restart.'}
$v=Get-VM -Id $id;Need ($v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and@(Get-VMNetworkAdapter -VM $v).Count-eq0) 'Converted lab VM must be running on the expected parent.'
New-Item -ItemType Directory -Path $root|Out-Null
# Shared guest verifier: original user files from the admitted expectation, plus
# the mutation manifest when present. System Volume Information is excluded.
$verify={param($Records,$Manifest)
 $ErrorActionPreference='Stop';$vol=Get-Volume -DriveLetter F;$disk=Get-Disk -Number 1
 $e=Get-Content -LiteralPath (Join-Path $Records 'expectation.json') -Raw -Encoding UTF8|ConvertFrom-Json
 $files=@($e.objects|Where-Object {-not $_.directory -and $_.path[0] -cne 'System Volume Information'})
 # Records carry the XXH3-128 content digest; lab-content-digest computes it in argument order.
 $paths=@($files|ForEach-Object {'F:\'+($_.path -join '\')});$digests=@(((& 'C:\ntfs2refs\tools\lab-content-digest.exe' @paths) -join '')|ConvertFrom-Json|ForEach-Object {$_})
 $ok=0;$bad=@();for($i=0;$i-lt$files.Count;$i++){$o=$files[$i];$p=$paths[$i];if(-not(Test-Path -LiteralPath $p)){$bad+="missing $p";continue};if($digests.Count-eq$files.Count-and$digests[$i]-ceq$o.sha256-and(Get-Item -LiteralPath $p).Length-eq$o.length){$ok++}else{$bad+="differs $p"}}
 $mut=$null;if($Manifest){$m=$Manifest|ConvertFrom-Json;$mok=0;foreach($f in $m.files){$p=$f.path;if((Test-Path -LiteralPath $p)-and(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-ceq$f.sha256){$mok++}else{$bad+="mutation differs $p"}};$deletedAbsent=-not(Test-Path -LiteralPath $m.deleted);$entries=@(Get-ChildItem -LiteralPath $m.entries_dir -File).Count;$mut=@{files_expected=@($m.files).Count;files_matching=$mok;deleted_absent=$deletedAbsent;entries_expected=$m.entries;entries_present=$entries}}
 @{filesystem=$vol.FileSystem;cluster=$vol.AllocationUnitSize;label=$vol.FileSystemLabel;disk1_online=(-not $disk.IsOffline);original_user_files=$files.Count;original_user_files_matching=$ok;mutation=$mut;problems=$bad;utc=[DateTime]::UtcNow.ToString('o')}}
try{
 # Stage the read-only content-digest tool; its pin is saved with the results.
 $digestTool=Join-Path $workspace 'target\release\lab-content-digest.exe';$session=New-PSSession -VMId $id -Credential $cred
 try{Invoke-Command -Session $session {New-Item -ItemType Directory -Path 'C:\ntfs2refs\tools' -Force|Out-Null};Copy-Item -LiteralPath $digestTool -ToSession $session -Destination 'C:\ntfs2refs\tools\lab-content-digest.exe' -Force}finally{Remove-PSSession $session}
 Save 'content-digest-tool.json' @{path=$digestTool;sha256=(Get-FileHash -LiteralPath $digestTool).Hash.ToLowerInvariant();algorithm='xxh3-128'}
 $before=Guest $verify @($ConversionRecords,$null);Save 'verify-before.json' $before
 Need ($before.filesystem-ceq'ReFS'-and$before.cluster-eq4096-and$before.label-ceq'n2r-stream-source'-and$before.disk1_online-and$before.original_user_files_matching-eq$before.original_user_files-and$before.original_user_files-gt0) 'Converted ReFS baseline differs before mutation.'
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
 $afterMutation=Guest $verify @($ConversionRecords,$mutation);Save 'verify-after-mutation.json' $afterMutation
 Need (@($afterMutation.problems).Count-eq0-and$afterMutation.mutation.files_matching-eq2-and$afterMutation.mutation.deleted_absent-and$afterMutation.mutation.entries_present-eq128) 'Mutation verification failed before restart.'
 # Clean guest shutdown and cold start, as in the frozen alpha's reboot check.
 $rebootStart=[DateTime]::UtcNow;Stop-VM -VM (Get-VM -Id $id) -Force -ErrorAction Stop
 $deadline=(Get-Date).AddMinutes(4);while((Get-VM -Id $id).State.ToString()-cne'Off'-and(Get-Date)-lt$deadline){Start-Sleep -Seconds 5};Need ((Get-VM -Id $id).State.ToString()-ceq'Off') 'Guest did not shut down cleanly.'
 Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop;WaitGuest
 $afterReboot=Guest $verify @($ConversionRecords,$mutation);Save 'verify-after-reboot.json' $afterReboot
 $events=Guest {param($Since)$ErrorActionPreference='Stop';@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=[DateTime]$Since} -ErrorAction SilentlyContinue|Where-Object {$_.ProviderName -match 'ReFS' -and $_.Level -le 3}|Select-Object -First 50|ForEach-Object {@{id=$_.Id;level=$_.Level;provider=$_.ProviderName;time=$_.TimeCreated.ToUniversalTime().ToString('o');message=($_.Message -split "`n")[0]}})} @((Get-Content -LiteralPath (Join-Path $root 'verify-before.json') -Raw|ConvertFrom-Json).utc)
 Save 'refs-system-events.json' @{refs_warning_or_error_events_since_baseline=@($events).Count;events=$events}
 Need ($afterReboot.filesystem-ceq'ReFS'-and$afterReboot.label-ceq'n2r-stream-source'-and@($afterReboot.problems).Count-eq0-and$afterReboot.original_user_files_matching-eq$afterReboot.original_user_files-and$afterReboot.mutation.files_matching-eq2-and$afterReboot.mutation.deleted_absent-and$afterReboot.mutation.entries_present-eq128) 'Post-restart verification failed.'
 Save 'result.json' @{schema_version=1;kind='allocation-bounded-mutation-and-restart';success=$true;run_id=$run;conversion_records=$ConversionRecords;original_user_files_verified=$afterReboot.original_user_files;new_files_verified=2;entries_verified=128;restart_issued_utc=$rebootStart.ToString('o');refs_warning_or_error_events=@($events).Count;raw_device_access=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'result.json') -Raw
}catch{Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false};throw}
