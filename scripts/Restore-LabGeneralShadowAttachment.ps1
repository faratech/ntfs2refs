<# Reattach the exact guest-local ReFS shadow after restoring its Hyper-V
   checkpoint. The provider opens it read-only before Windows sees disk 3. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ShadowDirectory,
 [Parameter(Mandatory)][string]$ReplayDirectory
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$shadow=Assert-LabPath $ShadowDirectory $cfg.Root
$replay=Assert-LabPath $ReplayDirectory (Join-Path $workspace '.lab/development')
$hostResult=Get-Content -LiteralPath (Join-Path $shadow 'host-result.json') -Raw|ConvertFrom-Json
$platformPath=Join-Path $shadow 'platform.json';$platform=Get-Content -LiteralPath $platformPath -Raw|ConvertFrom-Json
$requestPath=Join-Path $replay 'general-request.json';$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
$pins=Get-Content -LiteralPath (Join-Path $replay 'pins.json') -Raw|ConvertFrom-Json
if($vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$hostResult.shadowCheckpointId-or$hostResult.status-cne'independent-shadow-built-source-unchanged'-or$hostResult.runId-cne$request.experiment_id-or$platform.runId-cne$request.experiment_id-or$platform.status-cne'shadow-platform-prepared'-or$platform.backingPath-cne('J:\ntfs2refs-shadow\'+$request.experiment_id+'\shadow.vhdx')-or[guid]$platform.shadow.diskGuid-ne[guid]$request.pair.shadow.identity.disk_guid-or[guid]$platform.shadow.partitionGuid-ne[guid]$request.pair.shadow.identity.partition_guid-or(Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()-cne$pins.general_request_sha256){throw 'Frozen shadow checkpoint or pinned device identity differs.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 64MB
$nativePath=Join-Path $workspace 'lab/guest/NativeShadowDisk.cs'
$readOnlyPath=Join-Path $workspace 'lab/guest/NativeShadowReadOnlyAttachment.cs'
$mountPath=Join-Path $workspace 'lab/guest/NativeMountBoundary.cs'
$hashes=@{native=(Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant();readOnly=(Get-FileHash -LiteralPath $readOnlyPath).Hash.ToLowerInvariant();mount=(Get-FileHash -LiteralPath $mountPath).Hash.ToLowerInvariant();platform=(Get-FileHash -LiteralPath $platformPath).Hash.ToLowerInvariant()}
if($hashes.native-cne$platform.nativeSourceSha256){throw 'Pinned shadow native helper differs.'}
$run=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-shadow-reattach/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output -ErrorAction Stop|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 18));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='general-shadow-readonly-reattachment';runId=$run;experimentId=$request.experiment_id;vmId=[string]$vm.Id;parentSnapshotId=[string]$vm.ParentSnapshotId;shadowDirectory=$shadow;requestSha256=$pins.general_request_sha256;helperHashes=$hashes;status='started';error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest PowerShell Direct unavailable.'}
 $guestRoot='C:\ntfs2refs\general-replay\reattach-'+$run
 Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {param($Root)$ErrorActionPreference='Stop';$base='C:\ntfs2refs';$parent=Split-Path $Root -Parent;$baseItem=Get-Item -LiteralPath $base -Force;if(-not$baseItem.PSIsContainer-or($baseItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-or(Test-Path -LiteralPath $Root)){throw 'Fresh guest reattachment folder required.'};if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -ErrorAction Stop|Out-Null};$parentItem=Get-Item -LiteralPath $parent -Force;if(-not$parentItem.PSIsContainer-or($parentItem.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest replay parent differs.'};New-Item -ItemType Directory -Path $Root -ErrorAction Stop|Out-Null}|Out-Null
 Copy-Item -LiteralPath $readOnlyPath -Destination ($guestRoot+'\NativeShadowReadOnlyAttachment.cs') -ToSession $session
 Copy-Item -LiteralPath $mountPath -Destination ($guestRoot+'\NativeMountBoundary.cs') -ToSession $session
 $reply=Invoke-Command -Session $session -ArgumentList @($request.experiment_id,$platform.backingPath,[string]$platform.finalVhd.virtualDiskId,[string]$request.pair.source.identity.disk_guid,[string]$request.pair.shadow.identity.disk_guid,[string]$request.pair.shadow.identity.partition_guid,$guestRoot,$hashes) -ScriptBlock {
  param($Experiment,$Backing,$VhdId,$SourceGuid,$ShadowGuid,$PartitionGuid,$Root,$Hashes)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or@(Get-Disk).Count-ne3-or(Get-Disk -Number 3 -ErrorAction SilentlyContinue)){throw 'Guest device inventory differs before attachment.'}
  $source=Get-Disk -Number 1;$journal=Get-Disk -Number 2
  if([guid]$source.Guid-ne[guid]$SourceGuid-or-not$source.IsOffline-or-not$source.IsReadOnly-or$source.IsBoot-or$source.IsSystem-or$journal.IsOffline-or$journal.IsReadOnly){throw 'Source exclusion or journal state differs.'}
  $platformPath='C:\ntfs2refs\tree-shadow\'+$Experiment+'\platform.json';$nativePath='C:\ntfs2refs\tree-shadow\'+$Experiment+'\helpers\NativeShadowDisk.cs'
  if((Get-FileHash -LiteralPath $platformPath).Hash.ToLowerInvariant()-cne$Hashes.platform-or(Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant()-cne$Hashes.native-or(Get-FileHash -LiteralPath ($Root+'\NativeShadowReadOnlyAttachment.cs')).Hash.ToLowerInvariant()-cne$Hashes.readOnly-or(Get-FileHash -LiteralPath ($Root+'\NativeMountBoundary.cs')).Hash.ToLowerInvariant()-cne$Hashes.mount){throw 'Guest helper or platform pin differs.'}
  $p=Get-Content -LiteralPath $platformPath -Raw|ConvertFrom-Json
  if($p.backingPath-cne$Backing-or[guid]$p.finalVhd.virtualDiskId-ne[guid]$VhdId-or[guid]$p.shadow.diskGuid-ne[guid]$ShadowGuid-or[guid]$p.shadow.partitionGuid-ne[guid]$PartitionGuid){throw 'Guest saved shadow identity differs.'}
  $file=Get-Item -LiteralPath $Backing -Force
  if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-lt1-or$file.Length-gt6GB){throw 'Guest shadow backing differs.'}
  $before=(Get-FileHash -LiteralPath $Backing -Algorithm SHA256).Hash.ToLowerInvariant()
  Add-Type -Path @($nativePath,($Root+'\NativeMountBoundary.cs'),($Root+'\NativeShadowReadOnlyAttachment.cs'))
  $native=New-Object Ntfs2Refs.NativeShadowDisk($Backing,([guid]$VhdId),(New-Object Ntfs2Refs.ReadOnlyShadowDiskApi));$priv=New-Object Ntfs2Refs.ShadowManageVolumePrivilege
  try{$opened=$native.OpenOwned();try{$priv.Enable();$attached=$native.Attach()}finally{$priv.Restore()};if($attached.physicalPath-cne'\\.\PhysicalDrive3'){throw 'Attached shadow physical path differs.'};$protected=[Ntfs2Refs.NativeShadowProtection]::Observe([guid]$ShadowGuid,[guid]$PartitionGuid,$true);if($protected.attributesAfter-ne3-or-not$protected.cleanupComplete-or-not$protected.operationCompletionKnown){throw 'Provider shadow exclusion differs.'}}
  finally{if(-not$native.OperationActive){$native.Close()}}
  $disk=Get-Disk -Number 3;$part=Get-Partition -DiskNumber 3 -PartitionNumber 2
  if([guid]$disk.Guid-ne[guid]$ShadowGuid-or[guid]$part.Guid-ne[guid]$PartitionGuid-or-not$disk.IsOffline-or-not$disk.IsReadOnly-or$disk.IsBoot-or$disk.IsSystem-or$disk.Size-ne64GB-or-not$native.HandleCloseSucceeded){throw 'Reattached shadow identity or state differs.'}
  $after=(Get-FileHash -LiteralPath $Backing -Algorithm SHA256).Hash.ToLowerInvariant()
  if($before-cne$after-or-not(Get-Disk -Number 1).IsOffline-or-not(Get-Disk -Number 1).IsReadOnly){throw 'Backing or source changed during attachment.'}
  [pscustomobject]@{kind='general-shadow-readonly-attachment';experimentId=$Experiment;physicalPath=$attached.physicalPath;diskGuid=[string]$disk.Guid;partitionGuid=[string]$part.Guid;backingSha256=$after;backingLength=$file.Length;sourceOfflineReadOnly=$true;shadowOfflineReadOnly=$true;providerReadOnly=$true;handleClosed=$native.HandleCloseSucceeded;completedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'guest-reply.json' $reply
 if($reply.kind-cne'general-shadow-readonly-attachment'-or$reply.experimentId-cne$request.experiment_id-or[guid]$reply.diskGuid-ne[guid]$request.pair.shadow.identity.disk_guid-or-not$reply.sourceOfflineReadOnly-or-not$reply.shadowOfflineReadOnly-or-not$reply.providerReadOnly-or-not$reply.handleClosed){throw 'Guest reattachment report differs.'}
 $record.status='shadow-reattached-readonly';$record['backingSha256']=$reply.backingSha256
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
