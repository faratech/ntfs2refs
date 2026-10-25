<# Create one enrolled blank disk. Never initialize or format it. The importer
   must independently prove the whole disk is zero before writing anything. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ExperimentId,
 [Parameter(Mandatory)][guid]$PersistentVhdId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ShadowHelperSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReferenceHelperSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or$PersistentVhdId-eq[guid]::Empty){throw 'Owned guest and fresh identity required.'}
$report=Join-Path $PSScriptRoot 'creation.json'
if(Test-Path -LiteralPath $report){throw 'Creation report already exists.'}
foreach($spec in @(@('NativeShadowDisk.cs',$ShadowHelperSha256),@('NativeReferenceDisk.cs',$ReferenceHelperSha256))){
 $p=Join-Path $PSScriptRoot $spec[0];$f=Get-Item -LiteralPath $p -Force
 if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt256KB-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$spec[1]){throw 'Pinned ordinary helper required.'}
}
$j=Get-Partition -DriveLetter J;$disk=Get-Disk -Number $j.DiskNumber;$volume=$j|Get-Volume
if($j.DiskNumber-ne2-or[guid]$disk.Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'-or[guid]$j.Guid-ne[guid]'7435ee94-c435-403f-a515-dec1ccd5094e'-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or$volume.FileSystem-cne'NTFS'-or$volume.SizeRemaining-lt1GB){throw 'Enrolled journal storage and reserve required.'}
$path='J:\ntfs2refs-reference\'+$ExperimentId+'\reference.vhdx'
if(Test-Path -LiteralPath $path){throw 'Reference image already exists.'}
$parent=Split-Path $path -Parent
if(Test-Path -LiteralPath $parent){throw 'Fresh reference directory required.'}
Add-Type -Path @((Join-Path $PSScriptRoot 'NativeShadowDisk.cs'),(Join-Path $PSScriptRoot 'NativeReferenceDisk.cs'))
$privilege=[Ntfs2Refs.ShadowManageVolumePrivilege]::new()
$owned=[Ntfs2RefsResearch.NativeReferenceDisk]::new($path,$PersistentVhdId)
$record=[ordered]@{schemaVersion=1;kind='blank-reference-disk-creation';status='started';experimentId=$ExperimentId;persistentVhdId=[string]$PersistentVhdId;path=$path;native=$null;diskNumber=$null;diskOffline=$null;diskReadOnly=$null;partitionStyle=$null;rootHelperSha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();calls=$null;privilege=$null;error=$null;cleanupErrors=@();startedUtc=[DateTime]::UtcNow.ToString('o')}
try{
 New-Item -ItemType Directory -Path $parent|Out-Null
 $privilege.Enable()
 $native=$owned.CreateAndAttach();$record.native=$native
 $number=[int][Ntfs2Refs.NativeShadowDisk]::ParseDiskNumber($native.physicalPath);$record.diskNumber=$number
 $deadline=[DateTime]::UtcNow.AddSeconds(30);$new=$null
 do{$new=Get-Disk -Number $number -ErrorAction SilentlyContinue;if($new){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow-lt$deadline)
 if(-not$new-or$number-lt3-or$new.IsBoot-or$new.IsSystem-or$new.IsReadOnly-or$new.Size-ne64GB-or$new.LogicalSectorSize-ne512-or$new.PhysicalSectorSize-ne4096-or$new.PartitionStyle-cne'RAW'-or@(Get-Partition -DiskNumber $number -ErrorAction SilentlyContinue).Count){throw 'Fresh blank device identity, geometry or RAW state differs.'}
 if(-not$new.IsOffline){Set-Disk -Number $number -IsOffline $true}
 $new=Get-Disk -Number $number
 if(-not$new.IsOffline-or$new.IsReadOnly-or$new.PartitionStyle-cne'RAW'){throw 'Reference did not remain excluded RAW.'}
 $record.diskOffline=[bool]$new.IsOffline;$record.diskReadOnly=[bool]$new.IsReadOnly;$record.partitionStyle=[string]$new.PartitionStyle
 $record.status='created-blank-offline';$record['backingAllocatedBytes']=[Ntfs2Refs.WindowsShadowDiskApi]::AllocatedFileBytes($path)
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{
 try{$owned.Close()}catch{$record.cleanupErrors+=('reference-close: '+$_.Exception.Message)}
 try{$privilege.Restore()}catch{$record.cleanupErrors+=('privilege-restore: '+$_.Exception.Message)}
 $record.calls=@($owned.Calls);$record.privilege=$privilege.Audit;$record['closed']=$owned.Closed;$record['completedUtc']=[DateTime]::UtcNow.ToString('o')
 if($record.cleanupErrors.Count){$record.status='failed-cleanup-preserved'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 14))
 $stream=[IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
if($record.status-cne'created-blank-offline'){throw 'Reference preparation did not complete.'}
[pscustomobject]$record
