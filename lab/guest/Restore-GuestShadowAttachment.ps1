<# Reattach exactly one existing guest-local shadow after reboot; never create or format. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ObservationId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparationEvidenceSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$NativeSourceSha256,
 [Parameter(Mandatory)][ValidateSet('Prepared','Excluded')][string]$Mode,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ProtectionNativeSourceSha256,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$MountNativeSourceSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('existing enrolled guest-local shadow','Reattach existing VHDX and verify requested disk state')){[pscustomobject]@{Status='what-if';Mode=$Mode;SourceTargetWrites=$false;ConversionQualified=$false};return}
function Assert-AttachmentBoolean($Value,[bool]$Expected,[string]$Name){if($Value -isnot [bool] -or $Value -ne $Expected){throw ('Unexpected explicit boolean: '+$Name)}}
function Assert-AttachmentGuid([string]$Value){if($Value -notmatch '\A\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\z' -or [guid]$Value -eq [guid]::Empty){throw 'Nonempty GUID required.'}}
function Assert-AttachmentPreparation($Proof,[string]$ExpectedRun,[string]$ExpectedNative){
 if($Proof.schemaVersion -ne 1 -or $Proof.kind -cne 'guest-local-shadow-platform' -or $Proof.status -cne 'shadow-platform-prepared' -or $Proof.runId -cne $ExpectedRun -or $Proof.nativeSourceSha256 -cne $ExpectedNative -or $Proof.backingPath -cne ('J:\ntfs2refs-shadow\'+$ExpectedRun+'\shadow.vhdx')){throw 'Pinned preparation identity differs.'}
 foreach($name in @('attachmentRetained','handleCloseSucceeded','nativeOperationCompletionKnown','privilegeRestored')){Assert-AttachmentBoolean $Proof.$name $true $name}
 foreach($name in @('sourceTargetWriteRequestsIssued','payloadCopied','conversionQualified','bootQualified')){Assert-AttachmentBoolean $Proof.$name $false $name}
 $j=$Proof.journal;$s=$Proof.shadow
 if($Proof.journalIdentity.uniqueId -cne '600224806AAC261F021F249596F332FC' -or $Proof.journalIdentity.sizeBytes -ne 8GB -or $Proof.journalIdentity.role -cne 'journal' -or $j.diskNumber -ne 2 -or $j.partitionNumber -ne 2 -or $j.offset -ne 16MB -or $j.length -ne (8GB-32MB) -or $j.letter -cne 'J' -or $j.filesystem -cne 'NTFS' -or $j.allocationUnitSize -ne 4096){throw 'Pinned journal geometry differs.'}
 if($s.physicalPath -cne '\\.\PhysicalDrive3' -or $s.diskNumber -ne 3 -or -not $s.diskUniqueId -or $s.diskUniqueId -cin @('60022480BEA35BA9D496D5AFF633D768','60022480D091C4251B5FFD619706C2B5','600224806AAC261F021F249596F332FC') -or $s.partitionNumber -ne 2 -or $s.offset -ne 16MB -or $s.length -ne 52GB -or $s.logicalSectorSize -ne 512 -or $s.physicalSectorSize -ne 4096 -or $s.letter -cne 'S' -or $s.filesystem -cne 'ReFS' -or $s.allocationUnitSize -ne 4096){throw 'Pinned shadow geometry differs.'}
 foreach($g in @($j.diskGuid,$j.partitionGuid,$s.diskGuid,$s.partitionGuid,$Proof.finalVhd.identifier,$Proof.finalVhd.virtualDiskId)){Assert-AttachmentGuid $g}
 foreach($g in @($j.volumeGuid,$s.volumeGuid)){if($g -cnotmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'){throw 'Pinned volume GUID path differs.'};Assert-AttachmentGuid $g.Substring(11,36)}
 if($Proof.vhdIdentityQueryVersion -ne 14 -or $Proof.vhdContentGenerationQueryVersion -ne 2 -or $Proof.finalVhd.identifierQueryVersion -ne 2 -or $Proof.finalVhd.virtualDiskIdQueryVersion -ne 14 -or $Proof.finalVhd.identifierSemantics -cne 'vhdx-content-generation' -or [guid]$Proof.finalVhd.virtualDiskId -ne [guid]$Proof.vhdIdentifier -or $Proof.finalVhd.virtualBytes -ne 64GB -or $Proof.finalVhd.blockBytes -ne 2MB -or $Proof.finalVhd.logicalSectorBytes -ne 512 -or $Proof.finalVhd.physicalSectorBytes -ne 4096 -or $Proof.finalVhd.providerSubtype -ne 3 -or $Proof.finalVhd.physicalPath -cne $s.physicalPath){throw 'Pinned independent VHDX identity differs.'}
}
function Assert-AttachmentOriginalDisks([object[]]$Disks){
 $ids=@('60022480BEA35BA9D496D5AFF633D768','60022480D091C4251B5FFD619706C2B5','600224806AAC261F021F249596F332FC')
 if($Disks.Count -ne 3 -or @($Disks.UniqueId|Select-Object -Unique).Count -ne 3){throw 'Require exactly three enrolled disks before attachment.'}
 for($i=0;$i -lt 3;$i++){$d=@($Disks|Where-Object Number -EQ $i);if($d.Count -ne 1 -or $d[0].UniqueId -cne $ids[$i] -or $d[0].Size -ne $(if($i -eq 2){8GB}else{64GB}) -or $d[0].LogicalSectorSize -ne 512 -or $d[0].PhysicalSectorSize -ne 4096){throw 'Original physical disk enrollment differs.'}}
}
function Assert-AttachmentPartition($Partition,$Disk,$Expected){
 if($Partition.DiskNumber -ne $Disk.Number -or $Partition.PartitionNumber -ne $Expected.partitionNumber -or [guid]$Partition.Guid -ne [guid]$Expected.partitionGuid -or $Partition.Offset -ne $Expected.offset -or $Partition.Size -ne $Expected.length -or $Partition.GptType -ine '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -or $Partition.IsBoot -or $Partition.IsSystem){throw 'Partition identity or geometry differs.'}
}
function Assert-AttachmentLayout([object[]]$Partitions,$Disk,$Expected){
 if($Partitions.Count -ne 2){throw 'Unexpected partition inventory.'};$main=@($Partitions|Where-Object PartitionNumber -EQ 2);$msr=@($Partitions|Where-Object PartitionNumber -EQ 1)
 if($main.Count -ne 1 -or $msr.Count -ne 1 -or $msr[0].DiskNumber -ne $Disk.Number -or $msr[0].GptType -ine '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -or $msr[0].Offset -lt 17408 -or ($msr[0].Offset%512) -ne 0 -or $msr[0].Size -le 0 -or ($msr[0].Size%512) -ne 0 -or ($msr[0].Offset+$msr[0].Size) -gt 16MB -or $msr[0].IsBoot -or $msr[0].IsSystem){throw 'Unexpected reserved partition layout.'};Assert-AttachmentPartition $main[0] $Disk $Expected;$main[0]
}
function Assert-AttachmentJournal($Disk,$Partition,$Volume,$Proof){
 $j=$Proof.journal
 if($Disk.Number -ne 2 -or $Disk.UniqueId -cne $Proof.journalIdentity.uniqueId -or [guid]$Disk.Guid -ne [guid]$j.diskGuid -or $Disk.Size -ne 8GB -or $Disk.PartitionStyle -cne 'GPT' -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.IsOffline -or $Disk.IsReadOnly -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096){throw 'Journal disk identity/state differs.'}
 Assert-AttachmentPartition $Partition $Disk $j
 if([string]$Partition.DriveLetter -cne 'J' -or $Volume.UniqueId -cne $j.volumeGuid -or $Volume.FileSystem -cne 'NTFS' -or $Volume.FileSystemLabel -cne 'ntfs2refs-journal' -or $Volume.AllocationUnitSize -ne 4096 -or $Volume.SizeRemaining -lt 1280MB){throw 'Journal mount, filesystem or reserve differs.'}
}
function Assert-AttachmentShadow($Disk,$Partition,$Proof,[string]$ExpectedMode){
 $s=$Proof.shadow;if($ExpectedMode -cnotin @('Prepared','Excluded')){throw 'Unknown attachment mode.'}
 if($Disk.Number -ne 3 -or $Disk.UniqueId -cne $s.diskUniqueId -or [guid]$Disk.Guid -ne [guid]$s.diskGuid -or $Disk.Size -ne 64GB -or $Disk.PartitionStyle -cne 'GPT' -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096){throw 'Reattached shadow disk identity differs.'}
 Assert-AttachmentPartition $Partition $Disk $s
 $excluded=$ExpectedMode -ceq 'Excluded';if([bool]$Disk.IsOffline -ne $excluded -or [bool]$Disk.IsReadOnly -ne $excluded){throw 'Reattached protection state differs; no attribute repair allowed.'}
}
function Assert-AttachmentVolume($Partition,$Volume,$Proof){if([string]$Partition.DriveLetter -cne 'S' -or $Volume.UniqueId -cne $Proof.shadow.volumeGuid -or $Volume.FileSystem -cne 'ReFS' -or $Volume.FileSystemLabel -cne 'n2r-retained-shadow' -or $Volume.AllocationUnitSize -ne 4096){throw 'Reattached mounted filesystem identity differs.'}}
function Assert-AttachmentOrdinary([string]$Path,[switch]$Directory){$f=Get-Item -LiteralPath $Path -Force;if(($f.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted)) -or [bool]$f.PSIsContainer -ne [bool]$Directory){throw 'Nonordinary attachment path.'};$f}
function New-AttachmentDirectory([string]$Path){
 if(Test-Path -LiteralPath $Path){throw 'New evidence directory already exists.'};New-Item -ItemType Directory -Path $Path|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)))}
 Set-Acl -LiteralPath $Path -AclObject $acl;Assert-AttachmentOrdinary $Path -Directory|Out-Null
}
function Save-AttachmentStage([string]$Stage){
 $record.stage=$Stage;$record.updatedUtc=[DateTime]::UtcNow.ToString('o');if($Stage.EndsWith('-intent')){$record.nativeOperationCompletionKnown=$false};if($native){$record.nativeCalls=@($native.Calls)}
 $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($record|ConvertTo-Json -Depth 18));if($bytes.Length -gt 1MB){throw 'Attachment evidence exceeds bound.'}
 $stream=New-Object IO.FileStream((Join-Path $outputRoot 'attachment.json'),[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Assert-AttachmentLetterFree{if(@(Get-Volume|Where-Object DriveLetter -CEQ 'S').Count -or @(Get-Partition|Where-Object DriveLetter -CEQ 'S').Count -or (Get-PSDrive -Name S -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath 'S:\')){throw 'Shadow letter is occupied.'}}
function Assert-AttachmentProtectionPins([string]$ExpectedMode,[string]$Protection,[string]$Mount){if($ExpectedMode -ceq 'Excluded'){foreach($hash in @($Protection,$Mount)){if($hash -cnotmatch '\A[0-9a-f]{64}\z'){throw 'Excluded requires independently pinned protection and mount helpers.'}}}elseif($Protection -or $Mount){throw 'Prepared must use only its original native profile.'}}
function Test-AttachmentCloseAllowed([bool]$NativeActive,[bool]$LetterActive,[bool]$ProtectionActive,[bool]$ProtectionCleanupComplete,[bool]$PrivilegeActive){-not$NativeActive-and-not$LetterActive-and-not$ProtectionActive-and$ProtectionCleanupComplete-and-not$PrivilegeActive}
function Assert-AttachmentTarget($Disk,[object[]]$Partitions,$Expected=$null){
 if($Disk.Number -ne 1 -or $Disk.UniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Disk.Size -ne 64GB -or $Disk.PartitionStyle -cne 'GPT' -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096){throw 'Original target enrollment differs.'};foreach($field in @('IsBoot','IsSystem','IsReadOnly')){Assert-AttachmentBoolean $Disk.$field $false $field};Assert-AttachmentBoolean $Disk.IsOffline $true IsOffline;Assert-AttachmentGuid ([string]$Disk.Guid)
 $main=@($Partitions|Where-Object PartitionNumber -EQ 2);if($main.Count-ne1){throw 'Original target partition missing.'};Assert-AttachmentGuid ([string]$main[0].Guid);$geometry=[pscustomobject]@{partitionNumber=2;partitionGuid=[string]$main[0].Guid;offset=16MB;length=52GB};$p=Assert-AttachmentLayout $Partitions $Disk $geometry
 $result=[pscustomobject]@{diskNumber=1;diskUniqueId=$Disk.UniqueId;diskGuid=[string]$Disk.Guid;partitionGuid=[string]$p.Guid;partitionNumber=2;diskBytes=64GB;partitionOffset=16MB;partitionBytes=52GB;logicalSectorBytes=512;physicalSectorBytes=4096;isOffline=$true;isReadOnly=$false}
 if($Expected){foreach($field in $result.PSObject.Properties.Name){if([string]$result.$field-cne[string]$Expected.$field){throw ('Original target changed: '+$field)}}};$result
}
function Get-AttachmentBackingHash([string]$Path){$f=Assert-AttachmentOrdinary $Path;if($f.Length-lt1-or$f.Length-gt256MB){throw 'Excluded backing hash is bounded to256MiB.'};$s=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{if($s.Length-ne$f.Length){throw 'Backing length changed.'};$sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};[pscustomobject]@{length=$s.Length;sha256=$hash}}finally{$s.Dispose()}}
function Assert-AttachmentProtection($Result,$Proof){
 if($Result.status-cne'provider-readonly-and-offline-observed'-or$Result.phase-cne'complete'-or$Result.error-or[guid]$Result.diskGuid-ne[guid]$Proof.shadow.diskGuid-or[guid]$Result.partitionGuid-ne[guid]$Proof.shadow.partitionGuid-or$Result.attributesBefore-lt0-or$Result.attributesBefore-gt3-or$Result.attributesAfter-ne3){throw 'Explicit exclusion evidence differs.'}
 foreach($field in @('requestedEstablishExclusion','providerReadOnlyBefore','providerReadOnlyAfter','exclusionObserved','operationCompletionKnown','cleanupComplete')){Assert-AttachmentBoolean $Result.$field $true $field};foreach($field in @('rawPayloadWriteRequestsIssued','conversionQualified','persistenceQualified')){Assert-AttachmentBoolean $Result.$field $false $field}
 $changed=$Result.attributesBefore-ne3;foreach($field in @('attributeOpenAttempted','attributeOpenReturned','attributeSetAttempted','attributeSetReturned','attributeSetSucceeded')){Assert-AttachmentBoolean $Result.$field $changed $field}
 $calls=@($Result.calls);$providerNames=@('providerWritableBefore','providerWritableAfter');if($changed){$providerNames+='providerWritablePreSet'};foreach($name in $providerNames){$c=@($calls|Where-Object name -CEQ $name);if($c.Count-ne1-or$c[0].error-ne19-or$c[0].code-ne0x70024-or$c[0].returned-ne0-or$c[0].capacity-ne0){throw 'Explicit provider write protection missing.'};Assert-AttachmentBoolean $c[0].succeeded $false $name}
 $set=@($calls|Where-Object name -CEQ 'SetOfflineReadOnly');if($set.Count-ne[int]$changed){throw 'Unexpected exclusion request count.'};if($changed){$c=$set[0];if($c.code-ne0x7c0f4-or$c.error-ne0-or$c.capacity-ne0-or$c.returned-ne0-or$c.inputHex-cne'28000000010000000300000000000000030000000000000000000000000000000000000000000000'){throw 'Exact exclusion request differs.'};Assert-AttachmentBoolean $c.succeeded $true 'SetOfflineReadOnly';$names=@($calls.name);if([array]::IndexOf($names,'providerWritableBefore')-ge[array]::IndexOf($names,'OpenPhysicalDrive3AttributeAccess')-or[array]::IndexOf($names,'providerWritablePreSet')-lt0-or[array]::IndexOf($names,'providerWritablePreSet')-ge[array]::IndexOf($names,'SetOfflineReadOnly')-or[array]::IndexOf($names,'SetOfflineReadOnly')-ge[array]::IndexOf($names,'providerWritableAfter')){throw 'Protection must precede exclusion.'}}
}

if($RunId.Length -ne 32 -or $ObservationId.Length -ne 32 -or $Mode -cnotin @('Prepared','Excluded') -or $env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or -not [Environment]::Is64BitProcess){throw 'Unexpected lab guest or identifiers.'}
Assert-AttachmentProtectionPins $Mode $ProtectionNativeSourceSha256 $MountNativeSourceSha256
$computer=Get-CimInstance Win32_ComputerSystem;$memory=(@(Get-CimInstance Win32_PhysicalMemory)|Measure-Object Capacity -Sum).Sum
if($computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or $memory -lt 8GB){throw 'Require enrolled guest and 8 GiB memory.'}
$original=@(Get-Disk);Assert-AttachmentOriginalDisks $original
$osPart=Get-Partition -DriveLetter C;$osDisk=Get-Disk -Number $osPart.DiskNumber
if($osDisk.Number -ne 0 -or $osDisk.UniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or -not $osDisk.IsBoot -or -not $osDisk.IsSystem -or (Get-Volume -DriveLetter C).FileSystem -cne 'NTFS'){throw 'Running OS differs.'}
foreach($dir in @('C:\','C:\ntfs2refs','C:\ntfs2refs\shadow-platform',('C:\ntfs2refs\shadow-platform\'+$RunId))){Assert-AttachmentOrdinary $dir -Directory|Out-Null}
$proofPath='C:\ntfs2refs\shadow-platform\'+$RunId+'\prepare.json';$proofFile=Assert-AttachmentOrdinary $proofPath
if($proofFile.Length -lt 1 -or $proofFile.Length -gt 1MB -or (Get-FileHash -LiteralPath $proofPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PreparationEvidenceSha256){throw 'Preparation evidence hash/size differs.'}
$proof=Get-Content -LiteralPath $proofPath -Raw|ConvertFrom-Json;Assert-AttachmentPreparation $proof $RunId $NativeSourceSha256
$targetBefore=$null;if($Mode-ceq'Excluded'){$targetBefore=Assert-AttachmentTarget (Get-Disk -Number 1) @(Get-Partition -DiskNumber 1)}
$journal=Get-Disk -Number 2;$jpart=Assert-AttachmentLayout @(Get-Partition -DiskNumber 2) $journal $proof.journal;Assert-AttachmentJournal $journal $jpart (Get-Volume -DriveLetter J) $proof
Assert-AttachmentLetterFree
$backing=$proof.backingPath;foreach($dir in @('J:\','J:\ntfs2refs-shadow',('J:\ntfs2refs-shadow\'+$RunId))){Assert-AttachmentOrdinary $dir -Directory|Out-Null}
$backingFile=Assert-AttachmentOrdinary $backing;if($backingFile.Length -lt 1 -or $backingFile.Length -gt 6GB){throw 'Backing file exceeds bound.'}
$backingBefore=$null;if($Mode-ceq'Excluded'){$backingBefore=Get-AttachmentBackingHash $backing}
$nativePath=Join-Path $PSScriptRoot 'NativeShadowDisk.cs';$nativeItem=Assert-AttachmentOrdinary $nativePath
if($nativeItem.Length -lt 1 -or $nativeItem.Length -gt 128KB -or (Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $NativeSourceSha256){throw 'Native attachment helper source differs.'}
if(('Ntfs2Refs.NativeShadowDisk' -as [type])-or('Ntfs2Refs.NativeShadowProtection'-as[type])-or('Ntfs2Refs.NativeMountBoundary'-as[type])){throw 'Native helper already loaded; require fresh session with pinned source.'}
$extraSources=@();if($Mode-ceq'Excluded'){$extraSources=@(@('NativeShadowReadOnlyAttachment.cs',$ProtectionNativeSourceSha256),@('NativeMountBoundary.cs',$MountNativeSourceSha256));foreach($source in $extraSources){$p=Join-Path $PSScriptRoot $source[0];$f=Assert-AttachmentOrdinary $p;if($f.Length-lt1-or$f.Length-gt128KB-or(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()-cne$source[1]){throw 'Protected attachment helper source differs.'}};Add-Type -Path @($nativePath,(Join-Path $PSScriptRoot 'NativeMountBoundary.cs'),(Join-Path $PSScriptRoot 'NativeShadowReadOnlyAttachment.cs'))}else{Add-Type -TypeDefinition (Get-Content -LiteralPath $nativePath -Raw)}
$parent='C:\ntfs2refs\shadow-attachment';if(-not (Test-Path -LiteralPath $parent)){New-AttachmentDirectory $parent};Assert-AttachmentOrdinary $parent -Directory|Out-Null
$runRoot=Join-Path $parent $RunId;if(-not (Test-Path -LiteralPath $runRoot)){New-AttachmentDirectory $runRoot};Assert-AttachmentOrdinary $runRoot -Directory|Out-Null
$outputRoot=Join-Path $runRoot $ObservationId;New-AttachmentDirectory $outputRoot
$native=$null;$privilege=$null;$letterOperationActive=$false;$protectionOperationActive=$false;$protectionCleanupComplete=$true
$record=[ordered]@{schemaVersion=1;kind='guest-local-shadow-attachment';runId=$RunId;observationId=$ObservationId;mode=$Mode;status='started';stage='preflight';createdUtc=[DateTime]::UtcNow.ToString('o');preparationEvidenceSha256=$PreparationEvidenceSha256;nativeSourceSha256=$NativeSourceSha256;scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();backingPath=$backing;expectedVhdIdentifier=$proof.finalVhd.virtualDiskId;vhdIdentityQueryVersion=14;vhdContentGenerationQueryVersion=2;expectedShadow=$proof.shadow;journal=$proof.journal;originalDisks=@($original|Select-Object Number,UniqueId,Size);attachAttempted=$false;attachmentRetained=$false;letterAssignmentAttempted=$false;handleCloseSucceeded=$false;nativeOperationCompletionKnown=$true;privilegeAdjustmentAttempted=$false;privilegeRestored=$true;manageVolumePrivilege=$null;nativeCalls=@();sourceTargetWriteRequestsIssued=$false;rawPayloadWriteRequestsIssued=$false;diskAttributeChangeRequestsIssued=$false;createFormatDetachDeleteRequestsIssued=$false;conversionQualified=$false;bootQualified=$false}
if($Mode-ceq'Excluded'){$record.protectionProfile='provider-readonly-explicit-exclusion';$record.protectionNativeSourceSha256=$ProtectionNativeSourceSha256;$record.mountNativeSourceSha256=$MountNativeSourceSha256;$record.openReadOnly=$true;$record.attachFlags=7;$record.physicalProtection=$null;$record.providerReadOnlyObserved=$false;$record.exclusionEstablished=$false;$record.shadowPersistenceQualified=$false;$record.originalTargetBefore=$targetBefore;$record.originalTargetAfter=$null;$record.originalTargetStatePreserved=$false;$record.backingBefore=$backingBefore;$record.backingAfter=$null;$record.backingUnchanged=$false;$record.diskAttributeChangeRequestsMayHaveBeenIssued=$false;$record.cleanupComplete=$false}
Save-AttachmentStage 'preflight'
try{
 if($Mode-ceq'Excluded'){$native=New-Object Ntfs2Refs.NativeShadowDisk($backing,([guid]$proof.finalVhd.virtualDiskId),(New-Object Ntfs2Refs.ReadOnlyShadowDiskApi))}else{$native=New-Object Ntfs2Refs.NativeShadowDisk($backing,([guid]$proof.finalVhd.virtualDiskId))};Save-AttachmentStage 'shadow-open-intent';$record.openedVhd=$native.OpenOwned()
 $privilege=New-Object Ntfs2Refs.ShadowManageVolumePrivilege;$record.manageVolumePrivilege=$privilege.Audit;$record.privilegeRestored=$false
 try{Save-AttachmentStage 'manage-volume-privilege-intent';$privilege.Enable();$record.attachAttempted=$true;Save-AttachmentStage 'shadow-attach-intent';$record.attachedVhd=$native.Attach()}
 finally{try{$privilege.Restore()}finally{$record.privilegeAdjustmentAttempted=$privilege.Audit.adjustmentAttempted;$record.privilegeRestored=($privilege.Audit.restored -and $privilege.Audit.tokenCloseSucceeded)}}
 if(-not $record.privilegeRestored -or $record.attachedVhd.physicalPath -cne $proof.shadow.physicalPath){throw 'Privilege restoration or physical path differs.'}
 $all=@(Get-Disk);if($all.Count -ne 4){throw 'Expected exactly one attached device.'};Assert-AttachmentOriginalDisks @($all|Where-Object Number -NE 3)
 $disk=Get-Disk -Number 3;$part=Assert-AttachmentLayout @(Get-Partition -DiskNumber 3) $disk $proof.shadow
 if($Mode-ceq'Prepared'){Assert-AttachmentShadow $disk $part $proof $Mode}else{if($disk.UniqueId-cne$proof.shadow.diskUniqueId-or[guid]$disk.Guid-ne[guid]$proof.shadow.diskGuid-or$disk.Size-ne64GB-or$disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096-or$disk.PartitionStyle-cne'GPT'-or$disk.IsBoot-or$disk.IsSystem){throw 'New protected shadow identity differs.'};Assert-AttachmentBoolean $disk.IsReadOnly $true 'provider IsReadOnly'}
 $record.observedBefore=[pscustomobject]@{diskUniqueId=$disk.UniqueId;diskGuid=[string]$disk.Guid;partitionGuid=[string]$part.Guid;isOffline=[bool]$disk.IsOffline;isReadOnly=[bool]$disk.IsReadOnly;driveLetter=[string]$part.DriveLetter}
 if($Mode-ceq'Excluded'){
  $protectionOperationActive=$true;$record.diskAttributeChangeRequestsMayHaveBeenIssued=$true;Save-AttachmentStage 'provider-protection-and-exclusion-intent'
  $physical=[Ntfs2Refs.NativeShadowProtection]::Observe([guid]$proof.shadow.diskGuid,[guid]$proof.shadow.partitionGuid,$true);$record.physicalProtection=$physical;$protectionOperationActive=-not$physical.operationCompletionKnown;$protectionCleanupComplete=$physical.cleanupComplete;$record.diskAttributeChangeRequestsIssued=$physical.attributeSetAttempted;$record.diskAttributeChangeRequestsMayHaveBeenIssued=$physical.attributeSetAttempted
  Assert-AttachmentProtection $physical $proof;$record.providerReadOnlyObserved=$true;$record.exclusionEstablished=$true
 }
 if($Mode -ceq 'Prepared'){
  if([string]$part.DriveLetter -cne 'S'){
   if([string]$part.DriveLetter -and [string]$part.DriveLetter -ne [string][char]0){throw 'Unexpected shadow letter; no reassignment permitted.'};Assert-AttachmentLetterFree
   $record.letterAssignmentAttempted=$true;$letterOperationActive=$true;Save-AttachmentStage 'shadow-letter-intent'
   Add-PartitionAccessPath -DiskNumber 3 -PartitionNumber $proof.shadow.partitionNumber -AccessPath 'S:\' -ErrorAction Stop;$letterOperationActive=$false
  }
  $part=Get-Partition -DiskNumber 3 -PartitionNumber $proof.shadow.partitionNumber;Assert-AttachmentVolume $part (Get-Volume -DriveLetter S) $proof
 }
 $disk=Get-Disk -Number 3;$part=Assert-AttachmentLayout @(Get-Partition -DiskNumber 3) $disk $proof.shadow;Assert-AttachmentShadow $disk $part $proof $Mode
 $record.observedAfter=[pscustomobject]@{diskUniqueId=$disk.UniqueId;diskGuid=[string]$disk.Guid;partitionGuid=[string]$part.Guid;isOffline=[bool]$disk.IsOffline;isReadOnly=[bool]$disk.IsReadOnly;driveLetter=[string]$part.DriveLetter;volumeGuid=$(if($Mode -ceq 'Prepared'){(Get-Volume -DriveLetter S).UniqueId}else{$null})}
 $record.finalVhd=$native.Observe($true);if($record.finalVhd.physicalPath -cne $proof.shadow.physicalPath){throw 'Final device path differs.'}
 $journal=Get-Disk -Number 2;$jpart=Assert-AttachmentLayout @(Get-Partition -DiskNumber 2) $journal $proof.journal;Assert-AttachmentJournal $journal $jpart (Get-Volume -DriveLetter J) $proof
 $file=Assert-AttachmentOrdinary $backing;$allocated=[Ntfs2Refs.WindowsShadowDiskApi]::AllocatedFileBytes($backing);if($file.Length -gt 6GB -or $allocated -lt 1 -or $allocated -gt 6GB){throw 'Reattached backing exceeds bound.'}
 $record.backing=[pscustomobject]@{fileBytes=$file.Length;allocatedBytes=$allocated;nativePhysicalBytes=$record.finalVhd.physicalBytes;journalFreeBytes=(Get-Volume -DriveLetter J).SizeRemaining}
 if($Mode-ceq'Excluded'){$record.backingAfter=Get-AttachmentBackingHash $backing;if($record.backingAfter.length-ne$record.backingBefore.length-or$record.backingAfter.sha256-cne$record.backingBefore.sha256){throw 'Read-only shadow backing changed.'};$record.backingUnchanged=$true;$record.originalTargetAfter=Assert-AttachmentTarget (Get-Disk -Number 1) @(Get-Partition -DiskNumber 1) $targetBefore;$record.originalTargetStatePreserved=$true;foreach($source in $extraSources){if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $source[0]) -Algorithm SHA256).Hash.ToLowerInvariant()-cne$source[1]){throw 'Protected attachment helper changed.'}}}
 if((Get-FileHash -LiteralPath $proofPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PreparationEvidenceSha256 -or (Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $NativeSourceSha256){throw 'Pinned inputs changed.'}
 $record.status='shadow-attachment-restored'
}catch{$record.status='failed-preserved';$record.failureStage=$record.stage;$record.error=$_.Exception.Message}
finally{
 if($native){$record.attachmentRetained=$native.Attached;if(Test-AttachmentCloseAllowed $native.OperationActive $letterOperationActive $protectionOperationActive $protectionCleanupComplete ([bool]($privilege-and$privilege.Audit.operationActive))){try{$native.Close()}catch{$record.status='failed-preserved';$record.closeError=$_.Exception.Message}};$record.handleCloseSucceeded=$native.HandleCloseSucceeded;$record.nativeCalls=@($native.Calls)}
 $record.nativeOperationCompletionKnown=(-not $letterOperationActive -and -not $protectionOperationActive -and (-not $native -or -not $native.OperationActive) -and (-not $privilege -or -not $privilege.Audit.operationActive));if($Mode-ceq'Excluded'){$record.cleanupComplete=($record.nativeOperationCompletionKnown-and$record.handleCloseSucceeded-and$record.privilegeRestored-and$protectionCleanupComplete)};$record.finishedUtc=[DateTime]::UtcNow.ToString('o');Save-AttachmentStage 'complete'
}
[pscustomobject]@{Status=$record.status;RunId=$RunId;ObservationId=$ObservationId;Mode=$Mode;EvidenceDirectory=$outputRoot;Attached=$record.attachmentRetained;OperationCompletionKnown=$record.nativeOperationCompletionKnown;ConversionQualified=$false}
