<# Owning-machine verification of one enrolled imported writer candidate.
   Disk attachment/online state and reboot belong to the dispatcher. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidatePattern('\AJ:\\ntfs2refs-reference\\[0-9a-f]{32}\\reference\.vhdx\z')][string]$ReferencePath,
 [Parameter(Mandatory)][string]$VolumeRoot,
 [Parameter(Mandatory)][ValidateRange(3,63)][int]$DiskNumber,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$VerificationId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HelperSha256,
 [Parameter(Mandatory)][string]$OutputDirectory,
 [switch]$Mutate
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Assert-OrdinaryAncestry([string]$Path) {
 $item=Get-Item -LiteralPath $Path -Force
 while($null-ne$item){
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or-not$item.PSIsContainer){throw 'Ordinary directory ancestry required.'}
  $next=Split-Path -Path $item.FullName -Parent
  if([string]::IsNullOrEmpty($next)-or$next-ceq$item.FullName){break}
  $item=Get-Item -LiteralPath $next -Force
 }
}
if(-not[Environment]::Is64BitProcess-or$env:SystemDrive-cne'C:'){throw 'The bounded x64 C: Windows profile is required.'}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($build.CurrentBuildNumber-cne'26300'-or$build.UBR-ne9457){throw 'Unexpected Windows driver qualification profile.'}
$driver=Join-Path $env:SystemRoot 'System32\drivers\refs.sys'
if((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Native ReFS driver pin changed.'}
$helper=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeImportedReference.cs') -Force
if($helper.PSIsContainer-or($helper.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$helper.Length-lt1-or$helper.Length-gt128KB-or(Get-FileHash -LiteralPath $helper.FullName -Algorithm SHA256).Hash.ToLowerInvariant()-cne$HelperSha256){throw 'Pinned ordinary verification helper required.'}
Assert-OrdinaryAncestry (Split-Path -Path $helper.FullName -Parent)
$backing=Get-Item -LiteralPath $ReferencePath -Force
if($backing.PSIsContainer-or($backing.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$backing.Length-lt1-or$backing.Length-gt6GB){throw 'Bounded ordinary reference backing required.'}
Assert-OrdinaryAncestry (Split-Path -Path $backing.FullName -Parent)
$output=[IO.Path]::GetFullPath($OutputDirectory)
if($output-cnotmatch'\AC:\\[^:]+\z'-or$output.EndsWith('\')-or(Test-Path -LiteralPath $output)){throw 'Fresh bounded C: evidence directory required.'}
Assert-OrdinaryAncestry (Split-Path -Path $output -Parent)
if('Ntfs2RefsResearch.NativeImportedReference'-as[type]){throw 'Fresh process required; the native helper must not be preloaded.'}
Add-Type -Path $helper.FullName
$canonical=[Ntfs2RefsResearch.NativeImportedReference]::ResolveRoot($VolumeRoot)
[Ntfs2RefsResearch.NativeImportedReference]::ValidateArguments($ReferencePath,$canonical,$DiskNumber,$VerificationId)
New-Item -ItemType Directory -Path $output | Out-Null
$record=[ordered]@{
 schemaVersion=1;kind='imported-reference-native-verification-envelope';status='started';verificationId=$VerificationId
 referencePath=$ReferencePath;persistentVhdId='a0c231ef-a959-4a6e-8ae2-7d80363eebe6';diskNumber=$DiskNumber;volumeRoot=$canonical
 scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();helperSha256=$HelperSha256
 refsDriverSha256='3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4';mutationRequested=[bool]$Mutate
 sourceDisk1UntouchedByScript=$true;rawWriteRequestsIssued=$false;diskAttributesChanged=$false;attachmentChanged=$false;formatAttempted=$false
 native=$null;error=$null;startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null
}
try{
 $os=Get-Partition -DriveLetter C
 $disk=Get-Disk -Number $DiskNumber
 if($os.DiskNumber-eq$DiskNumber-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.Size-ne64GB-or$disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096-or[string]$disk.PartitionStyle-cne'GPT'-or[guid]$disk.Guid-ne[guid]'b4ab4dbc-6bd7-4199-8e4a-01b828e98584'-or($Mutate-and$disk.IsReadOnly)){throw 'Imported disk route, GPT, geometry or state differs.'}
 $part=Get-Partition -DiskNumber $DiskNumber -PartitionNumber 2
 if($part.IsBoot-or$part.IsSystem-or[guid]$part.Guid-ne[guid]'00c9f113-e0b9-49d8-b031-130aef8ef3fb'-or$part.Offset-ne16MB-or$part.Size-ne52GB-or[guid]$part.GptType-ne[guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'){throw 'Imported data partition identity differs.'}
 $volumes=@($part | Get-Volume)
 if($volumes.Count-ne1-or[string]$volumes[0].UniqueId-ine$canonical-or$volumes[0].FileSystem-cne'ReFS'-or$volumes[0].FileSystemLabel-cne'ntfs2refs-target'-or$volumes[0].AllocationUnitSize-ne4096-or$volumes[0].Size-ne52GB){throw 'Mounted root is not the enrolled imported ReFS partition.'}
 $record.native=[Ntfs2RefsResearch.NativeImportedReference]::Observe($ReferencePath,$canonical,$DiskNumber,$VerificationId,[bool]$Mutate)
 if(-not$record.native.complete-or-not$record.native.cleanupComplete-or$record.native.error){throw 'Imported reference native verification did not complete; preserve diagnostics.'}
 $after=Get-Disk -Number $DiskNumber
 if($after.IsOffline-ne$disk.IsOffline-or$after.IsReadOnly-ne$disk.IsReadOnly-or[guid]$after.Guid-ne[guid]$disk.Guid){throw 'Native verification changed or lost the enrolled disk state.'}
 $record.status=if($Mutate){'native-read-mutation-verified'}else{'native-read-verified'}
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{
 $record.finishedUtc=[DateTime]::UtcNow.ToString('o')
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 18))
 if($bytes.Length-gt2MB){throw 'Native verification evidence exceeded2MiB.'}
 $stream=[IO.File]::Open((Join-Path $output 'verification.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
[pscustomobject]$record
