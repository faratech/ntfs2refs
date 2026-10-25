<# Ordinary sequential NTFS writes only. Never relocates source extents. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReportPath,[ValidateRange(0,2147483647)][int]$Seed=1311912524)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$sourcePath='F:\natural-large.bin';$fileBytes=128MB;$chunkBytes=1MB
function Assert-NewPath([string]$Path){
 try{$null=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;throw ('Path already exists: '+$Path)}
 catch [System.Management.Automation.ItemNotFoundException]{}
}
function Source-Identity {
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
 $letter=@(Get-Partition -DriveLetter F)
 if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or$d.IsBoot-or$d.IsSystem-or$d.IsOffline-or$d.IsReadOnly-or
   [guid]$d.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or$d.PartitionStyle-cne'GPT'-or
   $p.IsBoot-or$p.IsSystem-or[guid]$p.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or
   $p.Offset-ne16MB-or$p.Size-ne52GB-or[string]$p.DriveLetter-cne'F'-or$letter.Count-ne1-or$letter[0].DiskNumber-ne1-or
   $letter[0].PartitionNumber-ne2-or$v.FileSystem-cne'NTFS'){throw 'Owned mounted writable NTFS identity differs.'}
 $root=Get-Item -LiteralPath 'F:\' -Force
 if(-not$root.PSIsContainer-or($root.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary source root required.'}
 [pscustomobject]@{diskNumber=1;diskGuid=[string]$d.Guid;diskUniqueId=[string]$d.UniqueId;diskBytes=[long]$d.Size;
  partitionNumber=2;partitionGuid=[string]$p.Guid;partitionOffset=[long]$p.Offset;partitionBytes=[long]$p.Size;
  driveLetter='F';fileSystem=[string]$v.FileSystem;volumePath=[string]$v.Path;volumeLabel=[string]$v.FileSystemLabel;
  allocationUnitBytes=[int]$v.AllocationUnitSize;logicalSectorBytes=[int]$d.LogicalSectorSize;physicalSectorBytes=[int]$d.PhysicalSectorSize;
  offline=[bool]$d.IsOffline;readOnly=[bool]$d.IsReadOnly}
}
if($ReportPath.Length-gt512-or$ReportPath-cnotmatch'\AC:\\'-or$ReportPath.Contains('/')-or$ReportPath.Contains('..')-or
 $ReportPath.Substring(3).Contains(':')-or-not$ReportPath.EndsWith('.json',[StringComparison]::OrdinalIgnoreCase)-or
 [IO.Path]::GetFullPath($ReportPath)-cne$ReportPath){throw 'Canonical bounded JSON report path on C: required.'}
Assert-NewPath $ReportPath
$ancestor=Split-Path $ReportPath -Parent
while($ancestor){$item=Get-Item -LiteralPath $ancestor -Force
 if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary existing report ancestry required.'}
 $next=Split-Path $ancestor -Parent;if($next-ceq$ancestor){break};$ancestor=$next}
$before=Source-Identity;Assert-NewPath $sourcePath
$fsutil=Join-Path $env:SystemRoot 'System32\fsutil.exe';$tool=Get-Item -LiteralPath $fsutil -Force
if($tool.PSIsContainer-or($tool.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary native fsutil required.'}
$record=[ordered]@{schemaVersion=1;kind='naturally-allocated-ntfs-large-file';status='started';sourcePath=$sourcePath;
 seed=$Seed;generator='System.Random.NextBytes';runtimeVersion=[string][Environment]::Version;chunkBytes=$chunkBytes;requestedBytes=$fileBytes;
 bytesWritten=0;flushed=$false;fileSha256=$null;fileAttributes=$null;sourceBefore=$before;sourceAfter=$null;queryExtents=$null;
 dataRelocationsRequested=0;sourceLeftMountedNtfs=$false;error=$null;startedUtc=[DateTime]::UtcNow.ToString('o')}
$report=[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$stream=$null;$hashStream=$null;$query=$null
try{
 $stream=[IO.FileStream]::new($sourcePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,$chunkBytes,[IO.FileOptions]::WriteThrough)
 $random=[Random]::new($Seed);$buffer=[byte[]]::new($chunkBytes)
 while($record.bytesWritten-lt$fileBytes){$random.NextBytes($buffer);$stream.Write($buffer,0,$buffer.Length);$record.bytesWritten+=$buffer.Length}
 $stream.Flush($true);$record.flushed=$true;$stream.Dispose();$stream=$null
 $item=Get-Item -LiteralPath $sourcePath -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$fileBytes){throw 'Created payload type or length differs.'}
 $hashStream=[IO.File]::Open($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$record.fileSha256=[BitConverter]::ToString($sha.ComputeHash($hashStream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 $hashStream.Dispose();$hashStream=$null
 $record.fileAttributes=[string]$item.Attributes;$record['fileAttributeBits']=[int]$item.Attributes
 $record['logicalBytes']=[long]$item.Length;$record['lastWriteUtc']=$item.LastWriteTimeUtc.ToString('o')
 $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$fsutil;$psi.Arguments='file queryextents F:\natural-large.bin'
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $query=[Diagnostics.Process]::new();$query.StartInfo=$psi
 if(-not$query.Start()){throw 'Native extent query did not start.'}
 $stdout=$query.StandardOutput.ReadToEndAsync();$stderr=$query.StandardError.ReadToEndAsync()
 $record.queryExtents=[ordered]@{executable=$fsutil;executableSha256=(Get-FileHash -LiteralPath $fsutil -Algorithm SHA256).Hash.ToLowerInvariant();
  arguments=$psi.Arguments;processId=$query.Id;exitCode=$null;completionKnown=$false;stdout=$null;stderr=$null}
 if(-not$query.WaitForExit(60000)){throw ('Read-only extent query remains live: PID '+$query.Id)}
 $record.queryExtents.exitCode=$query.ExitCode;$record.queryExtents.completionKnown=$true
 if($stdout.Result.Length-gt16MB-or$stderr.Result.Length-gt1MB){throw 'Native extent query exceeded report bounds.'}
 $record.queryExtents.stdout=$stdout.Result;$record.queryExtents.stderr=$stderr.Result
 $after=Source-Identity;$record.sourceAfter=$after;$record.sourceLeftMountedNtfs=$true
 if(($before|ConvertTo-Json -Depth 4 -Compress)-cne($after|ConvertTo-Json -Depth 4 -Compress)){throw 'Source identity changed during creation.'}
 if($query.ExitCode-ne0){throw ('Native extent query failed with exit code '+$query.ExitCode)}
 $record.status='created-naturally'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{
 if($stream){$stream.Dispose()};if($hashStream){$hashStream.Dispose()}
 $record['completedUtc']=[DateTime]::UtcNow.ToString('o')
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 10))
 if($bytes.Length-gt64MB){$report.Dispose();throw 'Report exceeds its bound.'}
 try{$report.Write($bytes,0,$bytes.Length);$report.Flush($true)}finally{$report.Dispose()}
 if($query-and$record.queryExtents-and$record.queryExtents.completionKnown){$query.Dispose()}
}
[pscustomobject]$record
