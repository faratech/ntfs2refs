param([Parameter(Mandatory)][string]$Root,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$CandidateSha,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{7,40}\z')][string]$SourceCommit,
 [long]$ExpectedPartitionBytes=66238545920L)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($Root-notmatch'\AC:\\ntfs2refs\\boot-conversion-[0-9a-f]{7}-[0-9a-f]{32}\z'-or$Root-notlike('*boot-conversion-'+$SourceCommit.Substring(0,7)+'-*')){throw 'Unexpected conversion case'}
$marker=[IO.File]::Open((Join-Path $Root 'started.marker'),'CreateNew','Write','Read')
try{$marker.WriteByte(1);$marker.Flush($true)}finally{$marker.Dispose()}
$process=$null;$output=$null;$errors=$null
try{
 $os=Get-CimInstance Win32_OperatingSystem;$current=Get-Partition -DriveLetter C
 $source=Get-Partition -DriveLetter D;$disk=Get-Disk -Number $source.DiskNumber
 if([DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()-ne1793995332223L-or$current.DiskNumber-ne1-or(Get-Volume -DriveLetter C).FileSystem-cne'ReFS'-or$source.DiskNumber-ne0-or$source.PartitionNumber-ne3-or$source.IsBoot-or$source.IsSystem-or[guid]$source.Guid-ne[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'){throw 'Actual alternate Windows/source binding changed'}
 if($ExpectedPartitionBytes-notin@(66238545920L,66236448768L)-or$disk.UniqueId-cne'60022480BEA35BA9D496D5AFF633D768'-or$disk.IsOffline-or$disk.IsReadOnly-or$disk.Size-ne64GB-or$source.Offset-ne331350016L-or$source.Size-ne$ExpectedPartitionBytes-or(Get-Volume -DriveLetter D).FileSystem-cne'NTFS'){throw 'Original NTFS source geometry/state changed'}
 if(@(Get-Process -Name inspect -ErrorAction SilentlyContinue).Count){throw 'Read-only inspectors must be closed before exclusive conversion'}
 $exe=Join-Path $Root 'ntfs2refs.exe';if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()-cne$CandidateSha){throw 'Candidate copy differs'}
 $scratch=Join-Path $Root 'scratch';$null=New-Item -ItemType Directory -Path $scratch
 $arguments=@('--drive','D','--windows-boot-volume','--scratch-directory',$scratch,'--target-format','dev-drive')
 foreach($arg in $arguments){if($arg-match'[\s"]'){throw 'Unexpected native argument quoting'}}
 $process=[Diagnostics.Process]::new();$process.StartInfo.FileName=$exe
 $process.StartInfo.Arguments=$arguments-join' ';$process.StartInfo.UseShellExecute=$false
 $process.StartInfo.CreateNoWindow=$true;$process.StartInfo.RedirectStandardInput=$true
 $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
 # Publish short phase/error messages as they arrive, including a refusal
 # before slow supported cleanup hashes; preserve exact byte order/content.
 $output=[IO.FileStream]::new((Join-Path $Root 'stdout.log'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,1)
 $errors=[IO.FileStream]::new((Join-Path $Root 'stderr.log'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,1)
 $watch=[Diagnostics.Stopwatch]::StartNew();if(-not$process.Start()){throw 'Converter did not start'}
 $outTask=$process.StandardOutput.BaseStream.CopyToAsync($output,65536)
 $errTask=$process.StandardError.BaseStream.CopyToAsync($errors,65536)
 $intent=@{pid=$process.Id;birth_ms=[DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();worker_pid=$PID;candidate_sha256=$CandidateSha;source_commit=$SourceCommit;arguments=$arguments;source_disk=0;source_partition=3;source_partition_bytes_before=$ExpectedPartitionBytes;confirmation='one affirmative line authorized for this exact guest source';native_launches=1}
 [IO.File]::WriteAllText((Join-Path $Root 'native-process.json'),($intent|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 $process.StandardInput.WriteLine('y');$process.StandardInput.Flush();$process.StandardInput.Close()
 $peak=0L;while(-not$process.WaitForExit(1000)){$process.Refresh();$peak=[Math]::Max($peak,$process.PeakWorkingSet64)}
 $watch.Stop();$null=$outTask.GetAwaiter().GetResult();$null=$errTask.GetAwaiter().GetResult()
 $output.Flush($true);$errors.Flush($true)
 $receipt=@{native_exit=$process.ExitCode;pid=$process.Id;birth_ms=$intent.birth_ms;owned_process_handle_observed=$true;wall_seconds=$watch.Elapsed.TotalSeconds;peak_working_set_bytes=$peak;ram_measurement_scope='native converter process only';source_mount_not_probed_after_exit=$true;native_launches=1}
 [IO.File]::WriteAllText((Join-Path $Root 'native-terminal.json'),($receipt|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 exit $process.ExitCode
}catch{
 [IO.File]::WriteAllText((Join-Path $Root 'worker-error.txt'),($_|Out-String),[Text.UTF8Encoding]::new($false));throw
}finally{if($null-ne$output){$output.Dispose()};if($null-ne$errors){$errors.Dispose()};if($null-ne$process){$process.Dispose()}}
