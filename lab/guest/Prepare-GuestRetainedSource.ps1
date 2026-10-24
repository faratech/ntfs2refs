<# Initializes only the enrolled blank disposable target. This creates the NTFS
   source for the first retained-extent case; it is not the conversion step. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
 [Parameter(Mandatory)][string]$HostTargetJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('Enrolled blank target disk1','Create exact52GiB NTFS source partition; preserve all later fixture source sectors')) {
 [pscustomobject]@{DryRun=$true;RunId=$RunId;PartitionOffset=16MB;PartitionBytes=52GB;Filesystem='NTFS';Conversion=$false};return
}
function Assert-RetainedSourceHost($Spec) {
 if($Spec.role -cne 'target' -or $Spec.sizeBytes -ne 64GB -or $Spec.controllerLocation -ne 1 -or [string]$Spec.vhdId -ine '25c491d0-5f1b-4205-9e6f-fd619706c2b5') {throw 'Host target does not identify the owned original target VHD.'}
}
function Assert-RetainedBlankDisk($Disk) {
 if($Disk.Number -ne 1 -or [string]$Disk.UniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Disk.Size -ne 64GB -or $Disk.PartitionStyle -cne 'RAW' -or $Disk.IsOffline -or $Disk.IsReadOnly -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096) {throw 'Only the original blank online writable target disk1 is eligible.'}
}
function Assert-RetainedSourcePartition($Disk,$Part,$Expected) {
 if($Disk.Number -ne 1 -or $Disk.Size -ne 64GB -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.IsOffline -or $Disk.IsReadOnly -or $Disk.PartitionStyle -cne 'GPT' -or [string]$Disk.UniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096 -or [string]$Disk.Guid -ine [string]$Expected.diskGuid) {throw 'Enrolled GPT disk identity changed.'}
 if($Part.DiskNumber -ne $Disk.Number -or $Part.Offset -ne 16MB -or $Part.Size -ne 52GB -or [string]$Part.DriveLetter -cne 'F' -or $Part.IsBoot -or $Part.IsSystem -or $Part.PartitionNumber -ne $Expected.number -or [string]$Part.Guid -ine [string]$Expected.guid -or [string]$Part.GptType -ine '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}') {throw 'Exact nonboot basic-data partition identity/geometry changed.'}
 foreach($id in @([string]$Part.Guid,[string]$Disk.Guid)){if([guid]::Parse($id)-eq [guid]::Empty){throw 'Empty GPT identity.'}}
}
function Write-RetainedNewJson([string]$Path,$Value) {
 $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($Value|ConvertTo-Json -Depth 20))
 if($bytes.Length -gt 1MB){throw 'Bounded preparation evidence exceeded1MiB.'}
 $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Assert-RetainedEvidenceParents([string]$Path) {
 $full=[IO.Path]::GetFullPath($Path);if(-not $full.StartsWith('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence path outside lab root.'}
 $p=Split-Path -Parent $full
 while($p){if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p -Force;if(-not $i.PSIsContainer -or ($i.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Evidence ancestor is not an ordinary directory.'}};$next=Split-Path -Parent $p;if($next-eq$p){break};$p=$next}
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:'){throw 'Exact owned guest required.'}
$hostSpec=$HostTargetJson|ConvertFrom-Json;Assert-RetainedSourceHost $hostSpec
$runRoot='C:\ntfs2refs\retained-source\'+$RunId;Assert-RetainedEvidenceParents (Join-Path $runRoot 'prepare.json')
if(Test-Path -LiteralPath $runRoot){throw 'Preparation evidence exists; fresh baseline/run required.'}
New-Item -ItemType Directory -Path $runRoot | Out-Null
$record=[ordered]@{schemaVersion=1;kind='retained-ntfs-source-platform';runId=$RunId;status='blocked';phase='preflight';targetWriteRequestsIssued=$false;operationCompletionKnown=$true;formatAttempted=$false;formatSucceeded=$false;target=$null;partition=$null;volume=$null;conversionQualified=$false;createdUtc=[DateTime]::UtcNow.ToString('o');error=$null;scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()}
try {
 $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
 if($build.EditionID-cne'Professional' -or $build.CurrentBuildNumber-cne'26300' -or $build.UBR-ne9457){throw 'Unexpected guest build.'}
 $disk=Get-Disk -Number 1;Assert-LabGuestDisk $disk;Assert-RetainedBlankDisk $disk
 if(@(Get-Partition -DiskNumber 1 -ErrorAction SilentlyContinue).Count){throw 'Blank disk unexpectedly has partitions.'}
 if(@(Get-Partition -DriveLetter F -ErrorAction SilentlyContinue).Count -or (Test-Path -LiteralPath 'F:\')){throw 'F: must be unused.'}
 $format=Get-Command Format-Volume
 if($format.ModuleName-cne'Storage' -or -not $format.Module -or -not $format.Module.Path.StartsWith((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Storage\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Native Storage formatter required.'}
 $record['formatter']=[pscustomobject]@{command='Format-Volume';modulePath=$format.Module.Path;moduleSha256=(Get-FileHash -LiteralPath $format.Module.Path -Algorithm SHA256).Hash.ToLowerInvariant();filesystem='NTFS';allocationUnitSize=4096;label='n2r-retained-source';conversionOperation=$false}
 $identity=& (Join-Path $PSScriptRoot 'Register-GuestDisk.ps1') -UniqueId ([string]$disk.UniqueId) -Role target -OutputPath (Join-Path $runRoot 'target.json') -Confirm:$false
 $record.target=[pscustomobject]@{guest=$identity;host=$hostSpec};$disk=Get-LabGuestDisk $identity;Assert-RetainedBlankDisk $disk
 Write-RetainedNewJson (Join-Path $runRoot 'started.json') ([pscustomobject]@{schemaVersion=1;kind='retained-source-mutation-intent';runId=$RunId;target=$record.target;offset=16MB;length=52GB;filesystem='NTFS';targetMutationMayFollow=$true;createdUtc=[DateTime]::UtcNow.ToString('o')})
 $record.phase='partition';$record.targetWriteRequestsIssued=$true;$record.operationCompletionKnown=$false
 Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop | Out-Null
 $disk=Get-LabGuestDisk $identity
 if($disk.Number-ne1 -or $disk.PartitionStyle-cne'GPT'){throw 'Initialized target identity differs.'}
 $part=New-Partition -DiskNumber $disk.Number -Offset 16MB -Size 52GB -DriveLetter F -ErrorAction Stop
 $record.operationCompletionKnown=$true
 $record.partition=[pscustomobject]@{guid=[string]$part.Guid;diskGuid=[string]$disk.Guid;number=$part.PartitionNumber;offset=$part.Offset;length=$part.Size;letter='F';logicalSectorSize=512;physicalSectorSize=4096}
 Assert-RetainedSourcePartition $disk $part $record.partition
 $vol=Get-Volume -DriveLetter F
 if([string]$vol.FileSystem -notin @('','RAW','Unknown')){throw 'Only newly created RAW partition may be formatted.'}
 $record.phase='format-source';$record.formatAttempted=$true;$record.operationCompletionKnown=$false;$job=$null
 try {
  $job=Format-Volume -Partition $part -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-source' -Confirm:$false -AsJob
  if(-not (Wait-Job -Job $job -Timeout 180)){throw 'NTFS format completion unknown; preserve running branch.'}
  if($job.State-notin@('Completed','Failed')){throw 'Native format job stopped without a determinate terminal result; preserve branch.'}
  $record.operationCompletionKnown=$true;Receive-Job -Job $job -ErrorAction Stop | Out-Null
 } finally {if($job -and $job.State-in@('Completed','Failed','Stopped')){Remove-Job -Job $job -Force}}
 $disk=Get-LabGuestDisk $identity;$part=Get-Partition -DriveLetter F;Assert-RetainedSourcePartition $disk $part $record.partition
 $vol=Get-Volume -DriveLetter F
 if($vol.FileSystem-cne'NTFS' -or $vol.FileSystemLabel-cne'n2r-retained-source' -or $vol.AllocationUnitSize-ne4096 -or [string]$vol.Path-cnotmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'){throw 'NTFS source format/geometry/native volume name differs.'}
 $record.volume=[pscustomobject]@{guid=[string]$vol.Path;filesystem=[string]$vol.FileSystem;label=[string]$vol.FileSystemLabel;allocationUnitSize=$vol.AllocationUnitSize;reportedSize=$vol.Size}
 $record.formatSucceeded=$true;$record.status='ntfs-source-prepared';$record.phase='complete'
}catch{$record.error=$_.Exception.ToString();$record['errorId']=$_.FullyQualifiedErrorId;$record['errorPosition']=$_.InvocationInfo.PositionMessage}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-RetainedNewJson (Join-Path $runRoot 'prepare.json') $record}
[pscustomobject]@{Status=$record.status;RunId=$RunId;EvidenceDirectory=$runRoot;OperationCompletionKnown=$record.operationCompletionKnown;TargetWriteRequestsIssued=$record.targetWriteRequestsIssued;ConversionQualified=$false}
