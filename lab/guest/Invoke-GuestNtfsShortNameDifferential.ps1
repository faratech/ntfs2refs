<# Per-volume short-name policy differential on the disposable NTFS disk.
   The Rust probe holds a volume lock while reading raw NTFS metadata. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ProbePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ProbeSha256,
 [Parameter(Mandatory)][string]$BindingPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BindingSha256,
 [Parameter(Mandatory)][string]$OutputDirectory
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Save([string]$Name,$Value){$p=Join-Path $OutputDirectory $Name;$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$script:toolIndeterminate=$false
function Run([string]$Exe,[string]$Arguments){$psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Exe;$psi.Arguments=$Arguments;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Tool did not start.'};$script:toolIndeterminate=$true;$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync();if(-not$p.WaitForExit(120000)){throw ('Tool remains live after deadline: '+$p.Id)};$script:toolIndeterminate=$false;[pscustomobject]@{exitCode=$p.ExitCode;stdout=$stdout.Result;stderr=$stderr.Result}}
function CheckDisk {
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
 if($d.IsBoot-or$d.IsSystem-or$d.IsOffline-or$d.IsReadOnly-or[guid]$d.Guid-ne[guid]$binding.identity.disk_guid-or[guid]$p.Guid-ne[guid]$binding.identity.partition_guid-or$p.Offset-ne$binding.identity.partition_offset-or$p.Size-ne$binding.identity.partition_bytes-or$p.DriveLetter-cne'F'-or$v.FileSystem-cne'NTFS'-or$v.FileSystemLabel-cne'n2r-retained-source'){throw 'Disposable mounted NTFS identity differs.'}
}
function Observe([string]$Name,[int]$ExpectedState){
 CheckDisk
 $query=Run $fsutil '8dot3name query F:'
 $match=[regex]::Match($query.stdout,'The volume state is: ([01])')
 if($query.exitCode-ne0-or-not$match.Success-or[int]$match.Groups[1].Value-ne$ExpectedState){throw 'Native per-volume short-name state differs.'}
 Save ($Name+'-query.json') $query
 $out=Join-Path $OutputDirectory ($Name+'.json')
 $probe=Run $ProbePath ('--binding "'+$BindingPath+'" --binding-sha256 '+$BindingSha256+' --output "'+$out+'"')
 Save ($Name+'-process.json') $probe
 if($probe.exitCode-ne0){throw ('Locked raw probe failed: '+$probe.stderr)}
 $report=Get-Content -LiteralPath $out -Raw|ConvertFrom-Json
 if(-not$report.success-or-not$report.observation.unlock_verified-or$report.payload_writes-ne0-or$report.policy_changes-ne0){throw 'Locked raw observation incomplete.'}
 CheckDisk
 [pscustomobject]@{name=$Name;nativeState=$ExpectedState;flags=[int]$report.observation.volume_flags;valueHex=[string]$report.observation.volume_information_hex;reportSha256=(Get-FileHash -LiteralPath $out).Hash.ToLowerInvariant();report=$report}
}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or(Test-Path -LiteralPath $OutputDirectory)){throw 'Fresh disposable guest output required.'}
if((Get-FileHash -LiteralPath $ProbePath).Hash.ToLowerInvariant()-cne$ProbeSha256-or(Get-FileHash -LiteralPath $BindingPath).Hash.ToLowerInvariant()-cne$BindingSha256){throw 'Probe or binding pin differs.'}
$binding=Get-Content -LiteralPath $BindingPath -Raw|ConvertFrom-Json
if($binding.disk_number-ne1-or$binding.identity.partition_bytes-ne52GB){throw 'Bound disposable NTFS profile differs.'}
CheckDisk
$global=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name NtfsDisable8dot3NameCreation).NtfsDisable8dot3NameCreation
if($global-ne2){throw 'Global policy must already be per-volume; no global change is permitted.'}
$parent=Get-Item -LiteralPath (Split-Path $OutputDirectory -Parent) -Force
if(-not$parent.PSIsContainer-or($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary output parent required.'}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null
$fsutil=Join-Path $env:SystemRoot 'System32\fsutil.exe'
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$record=[ordered]@{schemaVersion=1;kind='native-ntfs-short-name-differential';windowsBuild=[string]$version.CurrentBuildNumber;windowsRevision=$version.UBR;bindingSha256=$BindingSha256;probeSha256=$ProbeSha256;globalPolicy=$global;policyChangeCommands=@('8dot3name set F: 0','8dot3name set F: 1');globalPolicyChanged=$false;shortNamesStripped=$false;payloadWrites=0;status='started';error=$null;restoredDisabled=$false;mappingConfirmed=$false}
Save 'started.json' $record
$restoreNeeded=$false
try{
 $original=Observe 'disabled-before' 1
 $restoreNeeded=$true;$set=Run $fsutil '8dot3name set F: 0';Save 'enable-command.json' $set;if($set.exitCode-ne0){throw 'Per-volume enable failed.'}
 $enabled=Observe 'enabled' 0
 $set=Run $fsutil '8dot3name set F: 1';Save 'restore-command.json' $set;if($set.exitCode-ne0){throw 'Per-volume disable restoration failed.'}
 $restored=Observe 'disabled-restored' 1;$restoreNeeded=$false;$record.restoredDisabled=$true
 $record.mappingConfirmed=($original.flags-bxor$enabled.flags)-eq128-and($original.flags-band128)-eq128-and($enabled.flags-band128)-eq0-and$restored.flags-eq$original.flags-and$original.valueHex-ceq$restored.valueHex-and$original.valueHex.Substring(0,20)-ceq$enabled.valueHex.Substring(0,20)
 $users=@(39,40,41,42);$before=@($original.report.observation.ntfs.files|Where-Object {$_.record_number-in$users}|Select-Object record_number,sequence_number,names,streams);$after=@($restored.report.observation.ntfs.files|Where-Object {$_.record_number-in$users}|Select-Object record_number,sequence_number,names,streams)
 if($before.Count-ne4-or$after.Count-ne4-or@($before.streams|Where-Object {$_.logical_hash_status-cne'complete'-or$_.logical_sha256-cnotmatch'\A[0-9a-f]{64}\z'}).Count-or@($after.streams|Where-Object {$_.logical_hash_status-cne'complete'-or$_.logical_sha256-cnotmatch'\A[0-9a-f]{64}\z'}).Count){throw 'Complete user-stream hashes required.'}
 if(($before|ConvertTo-Json -Depth 16 -Compress)-cne($after|ConvertTo-Json -Depth 16 -Compress)){throw 'User namespace, stream mappings or logical hashes changed.'}
 $record['observations']=@($original,$enabled,$restored)|Select-Object name,nativeState,flags,valueHex,reportSha256
 $record['userStreamsUnchanged']=$true;$record.status='completed'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{if($restoreNeeded-and-not$script:toolIndeterminate){$recovery=Run $fsutil '8dot3name set F: 1';Save 'emergency-restore-command.json' $recovery;$q=Run $fsutil '8dot3name query F:';Save 'emergency-restore-query.json' $q;$record.restoredDisabled=$recovery.exitCode-eq0-and$q.exitCode-eq0-and$q.stdout-match'The volume state is: 1'}elseif($restoreNeeded){$record['restoreDeferredForLiveTool']=$true};$record['completedUtc']=[DateTime]::UtcNow.ToString('o');Save 'result.json' $record}
[pscustomobject]$record
