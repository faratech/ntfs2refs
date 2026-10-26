<# Read-only native control for an exact Windows reference imported without
   the independent writer overlay. Attachment/state transitions are external. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ImportDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ImportSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparedSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HandoffSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ResultSha256,
 [Parameter(Mandatory)][string]$ReferencePath,
 [Parameter(Mandatory)][string]$VolumeRoot,
 [Parameter(Mandatory)][ValidateRange(3,63)][int]$DiskNumber,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$VerificationId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HelperSha256,
 [Parameter(Mandatory)][string]$OutputDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-OrdinaryDirectory([string]$Path){
 $cursor=[IO.Path]::GetFullPath($Path)
 while($cursor){$item=Get-Item -LiteralPath $cursor -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary directory ancestry required.'};$next=Split-Path $cursor -Parent;if($next-ceq$cursor){break};$cursor=$next}
}
function Assert-BaselineProofs($Request,$Import,$Prepared,$Handoff,$Result,[string]$Reference,[int]$Number){
 $b=$Request.binding;$persistent=[guid]$b.persistent_vhd_id
 if($Request.schema_version-ne1-or$b.experiment_id-cnotmatch'\A[0-9a-f]{32}\z'-or$b.vhd_path-cne('J:\ntfs2refs-reference\'+$b.experiment_id+'\reference.vhdx')-or$b.vhd_path-cne$Reference-or$b.disk_number-ne$Number-or$Number-lt3-or$Number-gt63-or$persistent-eq[guid]::Empty-or$persistent-eq[guid]'a0c231ef-a959-4a6e-8ae2-7d80363eebe6'-or$Request.packet_sha256-cne'585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b'){throw 'Separately enrolled exact baseline packet/binding required.'}
 $diskHash='ea08681ba795322529e395febea156af8ec97687ed2bf192b6e6d0bc17f5af07'
 $payloadHash='6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786'
 if($Import.blank_bytes_checked-ne64GB-or$Import.reference_bytes_written-ne68157440-or$Import.disk_sha256-cne$diskHash-or$Import.payload_sha256-cne$payloadHash){throw 'Full blank/import/payload proof differs.'}
 if($Prepared.profile-cne'baseline_only'-or$Prepared.baseline_only-isnot[bool]-or-not$Prepared.baseline_only-or$Prepared.adopted_file_expected-isnot[bool]-or$Prepared.adopted_file_expected-or@($Prepared.patches).Count-ne0-or$Prepared.import_disk_sha256-cne$diskHash-or$Prepared.payload_sha256-cne$payloadHash-or$Prepared.native_mount_qualified-isnot[bool]-or$Prepared.native_mount_qualified){throw 'Unmodified baseline preparation required; writer/adoption proof refused.'}
 if($Prepared.binding.vhd_path-cne$b.vhd_path-or$Prepared.binding.experiment_id-cne$b.experiment_id-or$Prepared.binding.disk_number-ne$b.disk_number-or[guid]$Prepared.binding.persistent_vhd_id-ne$persistent-or$Prepared.state.disk_attributes-ne3-or$Handoff.disk_attributes-ne0){throw 'Baseline preparation/handoff identity or lifecycle differs.'}
 foreach($state in @($Prepared.state,$Handoff)){
  $device=[byte[]]$state.device;$length=[byte[]]$state.length;$alignment=[byte[]]$state.alignment
  if($device.Length-ne12-or[BitConverter]::ToUInt32($device,0)-ne7-or[BitConverter]::ToUInt32($device,4)-ne$Number-or[BitConverter]::ToUInt32($device,8)-ne0-or$length.Length-ne8-or[BitConverter]::ToUInt64($length,0)-ne64GB-or$alignment.Length-ne28-or[BitConverter]::ToUInt32($alignment,0)-ne28-or[BitConverter]::ToUInt32($alignment,4)-ne28-or[BitConverter]::ToUInt32($alignment,16)-ne512-or[BitConverter]::ToUInt32($alignment,20)-ne4096-or[BitConverter]::ToUInt32($alignment,24)-ne0-or[guid]$state.vhd.persistent_vhd_id-ne$persistent-or$state.vhd.physical_path-cne('\\.\PhysicalDrive'+$Number)-or$state.vhd.backing_bytes-lt1-or$state.vhd.backing_bytes-gt6GB){throw 'Recorded baseline native route/geometry differs.'}
  [Ntfs2RefsResearch.NativeImportedReference]::ValidateLayout([byte[]]$state.layout)
 }
 if($Result.kind-cne'restricted-reference-import'-or$Result.success-isnot[bool]-or-not$Result.success-or$Result.baseline_only-isnot[bool]-or-not$Result.baseline_only-or$Result.overlay_inputs_consumed-isnot[bool]-or$Result.overlay_inputs_consumed-or$Result.adopted_file_expected-isnot[bool]-or$Result.adopted_file_expected-or$Result.writer_metadata_pages-ne0-or$Result.writer_metadata_bytes-ne0-or$Result.writer_payload_writes-ne0-or$Result.reference_bytes_written-ne$Import.reference_bytes_written-or$Result.imported_disk_sha256-cne$diskHash-or$Result.payload_sha256-cne$payloadHash-or$Result.handoff_performed-isnot[bool]-or-not$Result.handoff_performed-or$Result.native_writer_qualified-or$Result.ntfs_conversion_qualified){throw 'Successful baseline-only handoff with no overlay consumption required.'}
 return $b
}
$held=[Collections.Generic.List[IO.FileStream]]::new()
function Read-BaselinePin([string]$Path,[string]$Pin){
 $meta=Get-Item -LiteralPath $Path -Force
 if($meta.PSIsContainer-or($meta.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$meta.Length-lt1-or$meta.Length-gt1MB){throw 'Bounded ordinary import proof required.'}
 $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($file)
 if($file.Length-ne$meta.Length-or$file.Length-gt1MB){throw 'Opened proof length changed.'}
 $sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 if($actual-cne$Pin){throw 'Import proof file pin differs.'};$file.Position=0
 $reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
 try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()};$text|ConvertFrom-Json
}
if(-not[Environment]::Is64BitProcess-or$env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Owned x64 Windows guest required.'}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($build.CurrentBuildNumber-cne'26300'-or$build.UBR-ne9457){throw 'Unexpected native driver profile.'}
$driver=Join-Path $env:SystemRoot 'System32\drivers\refs.sys'
if((Get-FileHash -LiteralPath $driver).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Native ReFS driver pin changed.'}
$helper=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeImportedReference.cs') -Force
if($helper.PSIsContainer-or($helper.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$helper.Length-gt128KB-or(Get-FileHash -LiteralPath $helper.FullName).Hash.ToLowerInvariant()-cne$HelperSha256){throw 'Pinned native helper required.'}
Assert-OrdinaryDirectory $PSScriptRoot;Assert-OrdinaryDirectory $ImportDirectory
$out=[IO.Path]::GetFullPath($OutputDirectory)
if($out-cnotmatch'\AC:\\[^:]+\z'-or$out.EndsWith('\')-or(Test-Path -LiteralPath $out)){throw 'Fresh C: evidence directory required.'}
Assert-OrdinaryDirectory (Split-Path $out -Parent)
if('Ntfs2RefsResearch.NativeImportedReference'-as[type]){throw 'Fresh process required; native helper must not be preloaded.'}
Add-Type -Path $helper.FullName
$record=[ordered]@{schemaVersion=1;kind='imported-baseline-native-verification-envelope';status='started';baselineOnly=$true;adoptedFileExpected=$false;verificationId=$VerificationId;importDirectory=$ImportDirectory;referencePath=$ReferencePath;diskNumber=$DiskNumber;volumeRoot=$null;persistentVhdId=$null;sourceDisk1UntouchedByScript=$true;rawWriteRequestsIssued=$false;diskAttributesChanged=$false;attachmentChanged=$false;formatAttempted=$false;importProofPins=[ordered]@{request=$RequestSha256;import=$ImportSha256;prepared=$PreparedSha256;handoff=$HandoffSha256;result=$ResultSha256};referenceProof=$null;native=$null;error=$null;helperSha256=$HelperSha256;scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null}
New-Item -ItemType Directory -Path $out|Out-Null
try{
 $request=Read-BaselinePin (Join-Path $ImportDirectory 'request.json') $RequestSha256
 $import=Read-BaselinePin (Join-Path $ImportDirectory 'import.json') $ImportSha256
 $prepared=Read-BaselinePin (Join-Path $ImportDirectory 'prepared.json') $PreparedSha256
 $handoff=Read-BaselinePin (Join-Path $ImportDirectory 'handoff.json') $HandoffSha256
 $result=Read-BaselinePin (Join-Path $ImportDirectory 'result.json') $ResultSha256
 $binding=Assert-BaselineProofs $request $import $prepared $handoff $result $ReferencePath $DiskNumber
 $record.persistentVhdId=$binding.persistent_vhd_id
 $record.referenceProof=[ordered]@{fullImportedDiskSha256=$import.disk_sha256;fixedVhdSha256='b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7';partitionSha256='805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9';payloadSha256=$import.payload_sha256;scope='pinned importer proof before first native mount';currentRawImageEqualityClaimed=$false;payloadOwnedByBaselineFile=$false;writerPages=0;overlayInputsConsumed=$false}
 $backing=Get-Item -LiteralPath $ReferencePath -Force
 if($backing.PSIsContainer-or($backing.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$backing.Length-lt1-or$backing.Length-gt6GB){throw 'Bounded ordinary baseline backing required.'}
 Assert-OrdinaryDirectory (Split-Path $ReferencePath -Parent)
 $canonical=[Ntfs2RefsResearch.NativeImportedReference]::ResolveRoot($VolumeRoot);$record.volumeRoot=$canonical
 [Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineArguments($ReferencePath,$canonical,$DiskNumber,$VerificationId,[guid]$binding.persistent_vhd_id)
 $os=Get-Partition -DriveLetter C;$disk=Get-Disk -Number $DiskNumber;$part=Get-Partition -DiskNumber $DiskNumber -PartitionNumber 2
 if($os.DiskNumber-eq$DiskNumber-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.Size-ne64GB-or$disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096-or[string]$disk.PartitionStyle-cne'GPT'-or[guid]$disk.Guid-ne[guid]'b4ab4dbc-6bd7-4199-8e4a-01b828e98584'-or$part.IsBoot-or$part.IsSystem-or[guid]$part.Guid-ne[guid]'00c9f113-e0b9-49d8-b031-130aef8ef3fb'-or$part.Offset-ne16MB-or$part.Size-ne52GB){throw 'Baseline route/GPT/geometry/state differs.'}
 $volumes=@($part|Get-Volume)
 if($volumes.Count-ne1-or[string]$volumes[0].UniqueId-ine$canonical-or$volumes[0].FileSystem-cne'ReFS'-or$volumes[0].FileSystemLabel-cne'ntfs2refs-target'-or$volumes[0].AllocationUnitSize-ne4096-or$volumes[0].Size-ne52GB){throw 'Baseline is not the expected native ReFS volume.'}
 $record.native=[Ntfs2RefsResearch.NativeImportedReference]::ObserveBaseline($ReferencePath,$canonical,$DiskNumber,$VerificationId,[guid]$binding.persistent_vhd_id)
 if(-not$record.native.complete-or-not$record.native.cleanupComplete-or$record.native.error-or-not$record.native.baselineOnly-or$record.native.adoptedFileExpected-or-not$record.native.adoptedFileAbsentObserved-or$record.native.adoptedAbsenceChecks-ne2-or@($record.native.before).Count-ne2-or@($record.native.after).Count-ne2){throw 'Native baseline verification did not complete.'}
 $after=Get-Disk -Number $DiskNumber
 if($after.IsOffline-ne$disk.IsOffline-or$after.IsReadOnly-ne$disk.IsReadOnly-or[guid]$after.Guid-ne[guid]$disk.Guid){throw 'Baseline disk state changed during observation.'}
 $record.status='unmodified-baseline-native-read-verified'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{
 foreach($file in $held){$file.Dispose()}
 $record.finishedUtc=[DateTime]::UtcNow.ToString('o');$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 18))
 if($bytes.Length-gt2MB){throw 'Baseline evidence exceeded2MiB.'}
 $stream=[IO.File]::Open((Join-Path $out 'verification.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
[pscustomobject]$record
