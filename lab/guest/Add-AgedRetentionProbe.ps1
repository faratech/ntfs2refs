<# Bounded ordinary NTFS allocation-history fixture. Run only after recovery.
   Does not move source extents or delete the probe, even if placement is low. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReportPath,
 [ValidatePattern('\A[0-9a-f]{32}\z')][string]$FixtureId=([guid]::NewGuid().ToString('N')),
 [ValidateRange(0,2147483647)][int]$Seed=1311912525)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-NewPath([string]$Path){try{$null=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;throw ('Path already exists: '+$Path)}catch [Management.Automation.ItemNotFoundException]{}}
function Source-Identity {
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume;$letter=@(Get-Partition -DriveLetter F)
 if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or-not[Environment]::Is64BitProcess-or$d.IsBoot-or$d.IsSystem-or$d.IsOffline-or$d.IsReadOnly-or[guid]$d.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or$d.PartitionStyle-cne'GPT'-or$d.Size-ne64GB-or$p.IsBoot-or$p.IsSystem-or[guid]$p.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or$p.Offset-ne16MB-or$p.Size-ne52GB-or[string]$p.DriveLetter-cne'F'-or$letter.Count-ne1-or$letter[0].DiskNumber-ne1-or$letter[0].PartitionNumber-ne2-or$v.FileSystem-cne'NTFS'-or$v.AllocationUnitSize-ne4096-or$d.LogicalSectorSize-ne512-or$d.PhysicalSectorSize-ne4096){throw 'Owned online writable NTFS source profile differs.'}
 $root=Get-Item -LiteralPath 'F:\' -Force;if(-not$root.PSIsContainer-or($root.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary source root required.'}
 [pscustomobject]@{diskNumber=1;diskGuid=[string]$d.Guid;diskBytes=[long]$d.Size;partitionNumber=2;partitionGuid=[string]$p.Guid;partitionOffset=[long]$p.Offset;partitionBytes=[long]$p.Size;driveLetter='F';fileSystem=[string]$v.FileSystem;volumePath=[string]$v.Path;volumeLabel=[string]$v.FileSystemLabel;allocationUnitBytes=[int]$v.AllocationUnitSize;logicalSectorBytes=[int]$d.LogicalSectorSize;physicalSectorBytes=[int]$d.PhysicalSectorSize;offline=[bool]$d.IsOffline;readOnly=[bool]$d.IsReadOnly}
}
function Assert-NoWorker {
 if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count-or(Get-Process -Name 'converter','ntfs2refs','ntfs2refs-recover','public-cli','qualifier' -ErrorAction SilentlyContinue)){throw 'Live or queued conversion/recovery worker blocks fixture creation.'}
}
if($ReportPath.Length-gt512-or$ReportPath-cnotmatch'\AC:\\'-or$ReportPath.Contains('/')-or$ReportPath.Contains('..')-or$ReportPath.Substring(3).Contains(':')-or-not$ReportPath.EndsWith('.json',[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFullPath($ReportPath)-cne$ReportPath){throw 'Fresh canonical bounded C: JSON report required.'}
Assert-NewPath $ReportPath;$ancestor=Split-Path $ReportPath -Parent
while($ancestor){$item=Get-Item -LiteralPath $ancestor -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary existing report ancestry required.'};$next=Split-Path $ancestor -Parent;if($next-ceq$ancestor){break};$ancestor=$next}
Assert-NoWorker;$before=Source-Identity
$helper=Join-Path $PSScriptRoot 'NativeAgedRetentionProbe.cs';$helperItem=Get-Item -LiteralPath $helper -Force
if($helperItem.PSIsContainer-or($helperItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$helperItem.Length-gt64KB){throw 'Bounded ordinary aged-layout helper required.'}
if('Ntfs2Refs.NativeAgedRetentionProbe'-as[type]){throw 'Fresh process required for the measured helper source.'}
Add-Type -Path $helper
$native=New-Object Ntfs2Refs.NativeAgedRetentionProbe($FixtureId,$before.volumePath,$Seed)
Assert-NewPath $native.Result.reservationPath;Assert-NewPath $native.Result.probePath
$record=[ordered]@{schemaVersion=1;kind='aged-layout-ntfs-retention-probe';fixtureId=$FixtureId;status='started';stage='preflight';seed=$Seed;generator='System.Random.NextBytes';runtimeVersion=[string][Environment]::Version;helperSha256=(Get-FileHash -LiteralPath $helper).Hash.ToLowerInvariant();scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();reservationCapBytes=8GB;probeLogicalBytes=8MB;minimumSourceHeadroomBytes=1GB;positivePlacementMinimumOffset=8GB;sourceBefore=$before;sourceBeforeReservationDelete=$null;sourceAfter=$null;native=$native.Result;sourceMovesRequested=0;validDataSettersRequested=0;probeDeletionRequested=$false;error=$null;startedUtc=[DateTime]::UtcNow.ToString('o')}
$report=[IO.File]::Open($ReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
function Save-Report([string]$Stage){$record.stage=$Stage;$record.updatedUtc=[DateTime]::UtcNow.ToString('o');$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 20));if($bytes.Length-gt2MB){throw 'Aged-layout report exceeds bound.'};$report.Position=0;$report.SetLength(0);$report.Write($bytes,0,$bytes.Length);$report.Flush($true)}
try{
 Save-Report 'reservation-intent';Assert-NoWorker;$native.Reserve();Save-Report 'reservation-allocated-eof-zero'
 Assert-NoWorker;$native.CreateProbe();Save-Report 'probe-flushed-hashed-and-mapped'
 $preDelete=Source-Identity;$record.sourceBeforeReservationDelete=$preDelete
 if(($before|ConvertTo-Json -Compress)-cne($preDelete|ConvertTo-Json -Compress)){throw 'Source identity changed before owned reservation cleanup.'}
 Assert-NoWorker;Save-Report 'original-handle-reservation-delete-intent';$native.DeleteOwnedReservation();Save-Report 'owned-reservation-deleted'
 $record.sourceAfter=Source-Identity;if(($before|ConvertTo-Json -Compress)-cne($record.sourceAfter|ConvertTo-Json -Compress)){throw 'Source identity changed during aged-layout fixture.'}
 $record.status=if($native.Result.placementSuitable){'probe-created-aged-layout'}else{'probe-created-placement-unsuitable'}
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();$native.Result.error=$record.error;throw}
finally{
 try{$native.ClosePreserving()}catch{$record.status='failed-preserved';$record.cleanupError=$_.Exception.ToString()}
 if(-not$record.sourceAfter){try{$record.sourceAfter=Source-Identity}catch{$record.sourceAfterError=$_.Exception.ToString()}}
 $record.completedUtc=[DateTime]::UtcNow.ToString('o');try{Save-Report 'complete'}finally{$report.Dispose()}
}
[pscustomobject]$record
