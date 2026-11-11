param(
 [Parameter(Mandatory)][string]$Root,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BindingSha,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$InspectorSha
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($Root-notmatch'\AC:\\ntfs2refs\\boot-source-inspection-[0-9a-f]{32}\z'){throw 'Unexpected inspection root'}
$marker=[IO.File]::Open((Join-Path $Root 'started.marker'),'CreateNew','Write','Read')
try{$marker.WriteByte(1);$marker.Flush($true)}finally{$marker.Dispose()}
$process=$null
try{
 $os=Get-CimInstance Win32_OperatingSystem
 $current=Get-Partition -DriveLetter C;$source=Get-Partition -DriveLetter D
 if([DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()-ne1793995332223L-or$current.DiskNumber-ne1-or(Get-Volume -DriveLetter C).FileSystem-cne'ReFS'-or$source.DiskNumber-ne0-or$source.IsBoot-or$source.IsSystem-or[guid]$source.Guid-ne[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-or(Get-Volume -DriveLetter D).FileSystem-cne'NTFS'){throw 'Bound alternate Windows/source state changed'}
 if([long]$os.FreePhysicalMemory*1024-lt4294967296L){throw 'Two 2GiB inspection ceilings require 4GiB available physical RAM'}
 $exe=Join-Path $Root 'inspect.exe';$binding=Join-Path $Root 'binding.json'
 if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()-cne$InspectorSha-or(Get-FileHash -LiteralPath $binding -Algorithm SHA256).Hash.ToLowerInvariant()-cne$BindingSha){throw 'Actual inspection inputs differ'}
 $arguments=@('--binding',$binding,'--binding-sha256',$BindingSha,'--output',(Join-Path $Root 'output'),'--ram-bytes','2147483648','--scratch-bytes','34359738368')
 foreach($argument in $arguments){if($argument-match'[\s"]'){throw 'Unexpected native argument quoting'}}
 $process=[Diagnostics.Process]::new();$process.StartInfo.FileName=$exe
 $process.StartInfo.Arguments=$arguments-join' ';$process.StartInfo.UseShellExecute=$false
 $process.StartInfo.CreateNoWindow=$true;$process.StartInfo.RedirectStandardInput=$true
 $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
 $watch=[Diagnostics.Stopwatch]::StartNew()
 if(-not$process.Start()){throw 'Inspector did not start'}
 $process.StandardInput.Close();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
 @{pid=$process.Id;process_birth_ms=[DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();worker_pid=$PID;native_exe_sha256=$InspectorSha;binding_sha256=$BindingSha;ram_bytes=2147483648L;source_scratch_subcap_bytes=4294967296L;source_writes_authorized=$false}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $Root 'native-process.json') -Encoding UTF8
 $peak=0L
 while(-not$process.WaitForExit(1000)){$process.Refresh();$peak=[Math]::Max($peak,$process.PeakWorkingSet64)}
 $watch.Stop();$out=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
 [IO.File]::WriteAllText((Join-Path $Root 'stdout.log'),$out,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $Root 'stderr.log'),$err,[Text.UTF8Encoding]::new($false))
 $terminal=@{exit_code=$process.ExitCode;owned_process_handle_observed=$true;wall_seconds=$watch.Elapsed.TotalSeconds;peak_working_set_bytes=$peak;ram_measurement_scope='Windows native inspector process only';source_payload_write_calls=0;source_frozen=$false;conversion_authorized=$false;stderr_tail=$err.Substring([Math]::Max(0,$err.Length-2400));guest_root=$Root}
 [IO.File]::WriteAllText((Join-Path $Root 'native-terminal.json'),($terminal|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 exit $process.ExitCode
}catch{
 [IO.File]::WriteAllText((Join-Path $Root 'worker-error.txt'),($_|Out-String),[Text.UTF8Encoding]::new($false))
 throw
}finally{if($null-ne$process){$process.Dispose()}}
