<# Prepare only the enrolled blank journal and a new independent guest-local VHDX. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,[Parameter(Mandatory)][string]$JournalManifestPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('enrolled journal and new local shadow','Prepare NTFS journal and independent ReFS Dev Drive shadow; never format source target')){[pscustomobject]@{Status='what-if';SourceTargetWrites=$false;PayloadCopy=$false;ConversionQualified=$false};return}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
function Assert-ShadowJournalManifest($Identity){
 if($Identity.schemaVersion -ne 1 -or $Identity.role -cne 'journal' -or $Identity.uniqueId -cne '600224806AAC261F021F249596F332FC' -or [string]$Identity.serialNumber -cne '' -or $Identity.sizeBytes -ne 8GB -or $Identity.location -cne 'Integrated : Bus 0 : Device 10738 : Function 51055 : Adapter 0 : Port 0 : Target 0 : LUN 2'){throw 'Unexpected journal enrollment.'}
}
function Assert-ShadowJournalBlank($Disk,[object[]]$Partitions){
 if($Disk.UniqueId -cne '600224806AAC261F021F249596F332FC' -or $Disk.Size -ne 8GB -or $Disk.PartitionStyle -cne 'RAW' -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.IsReadOnly -or $Disk.IsOffline -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096 -or $Partitions.Count){throw 'Journal must be exactly enrolled, blank, online and writable.'}
}
function Assert-ShadowNewDisk($Disk,[object[]]$Original,[string]$PhysicalPath,[object[]]$Partitions){
 $number=[Ntfs2Refs.NativeShadowDisk]::ParseDiskNumber($PhysicalPath)
 if($Disk.Number -ne $number -or @($Original|Where-Object{[string]$_.UniqueId -ceq [string]$Disk.UniqueId -or $_.Number -eq $Disk.Number}).Count -or -not $Disk.UniqueId -or $Disk.Size -ne 64GB -or $Disk.LogicalSectorSize -ne 512 -or $Disk.PhysicalSectorSize -ne 4096 -or $Disk.IsBoot -or $Disk.IsSystem -or $Disk.IsOffline -or $Disk.IsReadOnly -or $Disk.PartitionStyle -cne 'RAW' -or $Partitions.Count){throw 'Attached device is not the new blank shadow.'}
}
function Assert-ShadowPartition($Disk,$Partition,[long]$Length,[string]$Letter){
 if($Partition.DiskNumber -ne $Disk.Number -or $Partition.Offset -ne 16MB -or $Partition.Size -ne $Length -or [string]$Partition.DriveLetter -cne $Letter -or $Partition.IsBoot -or $Partition.IsSystem -or [string]$Partition.GptType -ine '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -or [guid]$Partition.Guid -eq [guid]::Empty -or [guid]$Disk.Guid -eq [guid]::Empty){throw 'Prepared partition geometry or identity differs.'}
}
function Assert-ShadowCapacity([uint64]$NativeBytes,[long]$FileBytes,[uint64]$AllocatedBytes,[long]$FreeBytes){
 if($NativeBytes -lt 1 -or $NativeBytes -gt 6GB -or $FileBytes -lt 1 -or $FileBytes -gt 6GB -or $AllocatedBytes -lt 1 -or $AllocatedBytes -gt 6GB -or $FreeBytes -lt 1280MB){throw 'Shadow exceeds 6 GiB or leaves less than 1.25 GiB journal reserve; no cap increase.'}
}
function Assert-ShadowOrdinaryPath([string]$Path,[switch]$Directory){
 $f=Get-Item -LiteralPath $Path -Force
 if(($f.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted)) -or ([bool]$f.PSIsContainer -ne [bool]$Directory)){throw 'Unexpected reparse/compressed/encrypted path or item type.'};$f
}
function New-ShadowPrivateDirectory([string]$Path){
 if(Test-Path -LiteralPath $Path){throw 'Private shadow directory already exists.'};New-Item -ItemType Directory -Path $Path|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);$acl.AddAccessRule($rule)}
 Set-Acl -LiteralPath $Path -AclObject $acl;Assert-ShadowOrdinaryPath $Path -Directory|Out-Null
}
function Save-ShadowStage([string]$Stage){$record.stage=$Stage;if($Stage.EndsWith('-intent')){$record.nativeOperationCompletionKnown=$false};if($native){$record.nativeCalls=@($native.Calls)};$record.updatedUtc=[DateTime]::UtcNow.ToString('o');$record|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $outputRoot 'prepare.json') -Encoding UTF8}
function Invoke-ShadowFormat($Partition,[switch]$DevDrive){
 $job=$null;$script:formatIndeterminate=$true
 try{if($DevDrive){$job=Format-Volume -Partition $Partition -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-shadow' -Confirm:$false -AsJob}else{$job=Format-Volume -Partition $Partition -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'ntfs2refs-journal' -Confirm:$false -AsJob}
  if(-not (Wait-Job -Job $job -Timeout 180)){throw 'Native format deadline exceeded; preserve running branch.'}
  if($job.State -notin @('Completed','Failed')){throw 'Native format state is unknown.'};$script:formatIndeterminate=$false;Receive-Job -Job $job -ErrorAction Stop|Out-Null
  if($job.State -ne 'Completed'){throw 'Native format did not complete.'}
 }finally{if($job -and $job.State -in @('Completed','Failed','Stopped')){Remove-Job -Job $job -Force}}
}
function Complete-ShadowQueryProcess($Process,$StdoutTask,$StderrTask,$Event){
 if(-not $Process.WaitForExit(30000)){throw 'Native query exceeded 30 seconds; preserve process and branch.'};$Event.nativeExitObserved=$true;$Event.exitCode=$Process.ExitCode
 if(-not $StdoutTask.Wait(5000) -or -not $StderrTask.Wait(5000)){throw 'Native query output did not finish within its bounded deadline.'}
 [pscustomobject]@{stdout=$StdoutTask.GetAwaiter().GetResult();stderr=$StderrTask.GetAwaiter().GetResult()}
}
function Invoke-ShadowQuery([string]$Name,[string[]]$Arguments){
 if($Name -cnotin @('system','devdrive','volume','refs') -or @($Arguments|Where-Object{$_ -cnotmatch '\A[A-Za-z0-9:]+\z'}).Count){throw 'Unexpected native query.'}
 $out=Join-Path $outputRoot ($Name+'.stdout');$err=Join-Path $outputRoot ($Name+'.stderr');if((Test-Path -LiteralPath $out) -or (Test-Path -LiteralPath $err)){throw 'Native query output exists.'}
 $script:queryIndeterminate=$true;$p=New-Object Diagnostics.Process;$started=$false
 $p.StartInfo=New-Object Diagnostics.ProcessStartInfo;$p.StartInfo.FileName=Join-Path $env:SystemRoot 'System32\fsutil.exe';$p.StartInfo.Arguments=[string]::Join(' ',$Arguments)
 $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 $event=[pscustomobject]@{name=$Name;processId=$null;startedUtc=[DateTime]::UtcNow.ToString('o');nativeExitObserved=$false;outputComplete=$false;exitCode=$null};$record.queryProcesses+=@($event);Save-ShadowStage ('query-'+$Name+'-intent')
 try{
  $started=$p.Start();if(-not $started){$script:queryIndeterminate=$false;throw 'Native query failed to start.'};$event.processId=$p.Id;Save-ShadowStage ('query-'+$Name+'-intent')
  $stdoutTask=$p.StandardOutput.ReadToEndAsync();$stderrTask=$p.StandardError.ReadToEndAsync()
  $captured=Complete-ShadowQueryProcess $p $stdoutTask $stderrTask $event;$stdout=$captured.stdout;$stderr=$captured.stderr;$encoding=New-Object Text.UTF8Encoding($false,$true)
  foreach($pair in @(@($out,$stdout),@($err,$stderr))){$bytes=$encoding.GetBytes([string]$pair[1]);if($bytes.Length -gt 64KB){throw 'Native query exceeds evidence bound.'};$stream=New-Object IO.FileStream($pair[0],[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}}
  $event.outputComplete=$true;$script:queryIndeterminate=$false
  [pscustomobject]@{name=$Name;command='fsutil.exe';arguments=$Arguments;exitCode=$p.ExitCode;stdout=$stdout;stderr=$stderr}
 }finally{if(-not $started -or (-not $script:queryIndeterminate -and $p.HasExited)){$p.Dispose()}}
}
function Test-ShadowDevDrive([string]$Text){
 if($Text -match '(?i)not formatted|not (?:a |an )?(?:trusted |untrusted )?developer volume|disabled|not enabled|blocked'){return $false}
 $Text -match '(?im)^\s*(?:This (?:is|volume is)|The volume is) (?:a trusted|an? untrusted) developer volume\.?\s*$' -or
 $Text -match '(?im)^\s*The volume is formatted as a developer volume(?: but is not trusted on this machine)?\.?\s*$'
}
function Get-ShadowComponent([string]$Path){$f=Assert-ShadowOrdinaryPath $Path;$s=Get-AuthenticodeSignature -LiteralPath $Path;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'Expected signed Microsoft native component.'};[pscustomobject]@{path=$Path;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant();fileVersion=$f.VersionInfo.FileVersion;signature=[string]$s.Status;signer=$s.SignerCertificate.Subject}}

if($RunId.Length -ne 32 -or $env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or -not [Environment]::Is64BitProcess){throw 'Unexpected guest or run identity.'}
$computer=Get-CimInstance Win32_ComputerSystem;$memory=(@(Get-CimInstance Win32_PhysicalMemory)|Measure-Object Capacity -Sum).Sum
if($computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or $memory -lt 8GB){throw 'Require the original disposable guest with 8 GiB memory.'}
$osPart=Get-Partition -DriveLetter C;$osDisk=Get-Disk -Number $osPart.DiskNumber
if($osDisk.UniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or -not $osDisk.IsBoot -or -not $osDisk.IsSystem -or (Get-Volume -DriveLetter C).FileSystem -cne 'NTFS'){throw 'Running OS identity changed.'}
$manifestFull=[IO.Path]::GetFullPath($JournalManifestPath)
if(-not $manifestFull.StartsWith('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)){throw 'Journal enrollment must be a bounded guest C: artifact.'}
$manifestItem=Assert-ShadowOrdinaryPath $manifestFull;if($manifestItem.Length -lt 1 -or $manifestItem.Length -gt 16KB){throw 'Journal enrollment size differs.'}
$identity=Get-Content -LiteralPath $manifestFull -Raw|ConvertFrom-Json;Assert-ShadowJournalManifest $identity
$journal=Get-LabGuestDisk $identity;Assert-ShadowJournalBlank $journal @(Get-Partition -DiskNumber $journal.Number -ErrorAction SilentlyContinue)
$original=@(Get-Disk|Select-Object Number,UniqueId,Size)
$required=@('60022480BEA35BA9D496D5AFF633D768','60022480D091C4251B5FFD619706C2B5','600224806AAC261F021F249596F332FC')
if($original.Count -ne 3 -or @($original|Where-Object UniqueId -CNotIn $required).Count -or @($original.UniqueId|Select-Object -Unique).Count -ne 3){throw 'Require only the three original enrolled disks.'}
foreach($letter in @('J','S')){if(@(Get-Volume|Where-Object DriveLetter -CEQ $letter).Count -or (Test-Path -LiteralPath ($letter+':\')) -or (Get-PSDrive -Name $letter -ErrorAction SilentlyContinue)){throw 'Reserved journal or shadow letter is occupied.'}}
foreach($dir in @('C:\','C:\ntfs2refs')){Assert-ShadowOrdinaryPath $dir -Directory|Out-Null}
$parent='C:\ntfs2refs\shadow-platform';if(-not (Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};Assert-ShadowOrdinaryPath $parent -Directory|Out-Null
$outputRoot=Join-Path $parent $RunId;New-ShadowPrivateDirectory $outputRoot
$nativePath=Join-Path $PSScriptRoot 'NativeShadowDisk.cs';$nativeItem=Assert-ShadowOrdinaryPath $nativePath;if($nativeItem.Length -gt 128KB){throw 'Unexpected native source size.'}
if(-not ('Ntfs2Refs.NativeShadowDisk' -as [type])){Add-Type -TypeDefinition (Get-Content -LiteralPath $nativePath -Raw)}
$vhdId=[guid]::NewGuid();$backing='J:\ntfs2refs-shadow\'+$RunId+'\shadow.vhdx';$native=$null;$privilegeScope=$null;$script:formatIndeterminate=$false;$script:queryIndeterminate=$false
$record=[ordered]@{schemaVersion=1;kind='guest-local-shadow-platform';runId=$RunId;status='started';stage='preflight';createdUtc=[DateTime]::UtcNow.ToString('o');scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();nativeSourceSha256=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant();journalManifestSha256=(Get-FileHash -LiteralPath $manifestFull -Algorithm SHA256).Hash.ToLowerInvariant();journalIdentity=$identity;originalDisks=$original;backingPath=$backing;vhdIdentifier=$vhdId.ToString('D');virtualBytes=64GB;maximumBackingBytes=6GB;minimumJournalFreeBytes=1280MB;journalWriteRequestsMayHaveBeenIssued=$false;shadowWriteRequestsMayHaveBeenIssued=$false;sourceTargetWriteRequestsIssued=$false;payloadCopied=$false;privilegeAdjustmentAttempted=$false;nativeOperationCompletionKnown=$true;attachmentRetained=$false;handleCloseSucceeded=$false;conversionQualified=$false;bootQualified=$false;nativeCalls=@()}
$record.privilegeRestored=$true;$record.manageVolumePrivilege=$null;$record.queryProcesses=@();$record.vhdIdentityQueryVersion=14;$record.vhdContentGenerationQueryVersion=2
Save-ShadowStage 'preflight'
try {
 $formatter=Get-Command Format-Volume
 if($formatter.ModuleName -cne 'Storage' -or -not $formatter.Module -or -not $formatter.Parameters.ContainsKey('DevDrive') -or -not $formatter.Module.Path.StartsWith((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Storage\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Native Dev Drive formatter unavailable.'}
 $record.components=@(foreach($relative in @('System32\virtdisk.dll','System32\fsutil.exe','System32\fmifs.dll','System32\drivers\refs.sys')){Get-ShadowComponent (Join-Path $env:SystemRoot $relative)})
 $record.formatter=[pscustomobject]@{command='Format-Volume';modulePath=$formatter.Module.Path;moduleVersion=[string]$formatter.Module.Version;moduleSha256=(Get-FileHash -LiteralPath $formatter.Module.Path -Algorithm SHA256).Hash.ToLowerInvariant();allocationUnitSize=4096;devDrive=$true;quick=$true}
 $record.systemDevDriveQuery=Invoke-ShadowQuery system @('devdrv','query')
 if($record.systemDevDriveQuery.exitCode -ne 0 -or $record.systemDevDriveQuery.stdout -notmatch '(?im)^Developer volumes are enabled\.\s*$' -or $record.systemDevDriveQuery.stdout -match '(?i)disabled|blocked|not enabled'){throw 'Dev Drive unavailable; no policy changes permitted.'}
 $journal=Get-LabGuestDisk $identity;Assert-ShadowJournalBlank $journal @(Get-Partition -DiskNumber $journal.Number -ErrorAction SilentlyContinue)
 $record.journalWriteRequestsMayHaveBeenIssued=$true;Save-ShadowStage 'journal-initialize-intent'
 Initialize-Disk -Number $journal.Number -PartitionStyle GPT|Out-Null
 $journal=Get-LabGuestDisk $identity;$jpart=New-Partition -DiskNumber $journal.Number -Offset 16MB -Size (8GB-32MB) -DriveLetter J
 $journal=Get-LabGuestDisk $identity;Assert-ShadowPartition $journal $jpart (8GB-32MB) J
 Save-ShadowStage 'journal-format-intent';Invoke-ShadowFormat $jpart
 $jpart=Get-Partition -DiskNumber $journal.Number -PartitionNumber $jpart.PartitionNumber;$journal=Get-LabGuestDisk $identity;Assert-ShadowPartition $journal $jpart (8GB-32MB) J
 $jvolume=Get-Volume -DriveLetter J
 if($jvolume.FileSystem -cne 'NTFS' -or $jvolume.FileSystemLabel -cne 'ntfs2refs-journal' -or $jvolume.AllocationUnitSize -ne 4096 -or $jvolume.SizeRemaining -lt 7GB -or (Get-Partition -DriveLetter J).DiskNumber -ne $journal.Number){throw 'Journal format/binding or free capacity differs.'}
 $record.journal=[pscustomobject]@{diskNumber=$journal.Number;diskGuid=[string]$journal.Guid;partitionGuid=[string]$jpart.Guid;partitionNumber=$jpart.PartitionNumber;offset=$jpart.Offset;length=$jpart.Size;volumeGuid=$jvolume.UniqueId;letter='J';filesystem='NTFS';allocationUnitSize=4096}
 Assert-ShadowOrdinaryPath 'J:\' -Directory|Out-Null;New-ShadowPrivateDirectory 'J:\ntfs2refs-shadow';New-ShadowPrivateDirectory ('J:\ntfs2refs-shadow\'+$RunId)
 if(Test-Path -LiteralPath $backing){throw 'Shadow backing file already exists.'}
 $native=New-Object Ntfs2Refs.NativeShadowDisk($backing,$vhdId)
 $record.shadowWriteRequestsMayHaveBeenIssued=$true;Save-ShadowStage 'shadow-create-intent';$native.Create()
 Save-ShadowStage 'shadow-open-intent';$record.createdVhd=$native.OpenOwned()
 $privilegeScope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege;$record.manageVolumePrivilege=$privilegeScope.Audit;$record.privilegeRestored=$false
 try{Save-ShadowStage 'manage-volume-privilege-intent';$privilegeScope.Enable();Save-ShadowStage 'shadow-attach-intent';$attached=$native.Attach();$record.attachedVhd=$attached}
 finally{try{$privilegeScope.Restore()}finally{$record.privilegeAdjustmentAttempted=$privilegeScope.Audit.adjustmentAttempted;$record.privilegeRestored=($privilegeScope.Audit.restored -and $privilegeScope.Audit.tokenCloseSucceeded)}}
 if(-not $record.privilegeRestored){throw 'Own-process privilege restoration is unqualified.'}
 $newNumber=[Ntfs2Refs.NativeShadowDisk]::ParseDiskNumber($attached.physicalPath)
 $disk=Get-Disk -Number $newNumber;Assert-ShadowNewDisk $disk $original $attached.physicalPath @(Get-Partition -DiskNumber $newNumber -ErrorAction SilentlyContinue)
 if(@(Get-Disk).Count -ne 4){throw 'Attachment did not create exactly one device.'}
 $shadowUnique=[string]$disk.UniqueId;$backingItem=Assert-ShadowOrdinaryPath $backing
 Assert-ShadowCapacity $attached.physicalBytes $backingItem.Length ([Ntfs2Refs.WindowsShadowDiskApi]::AllocatedFileBytes($backing)) (Get-Volume -DriveLetter J).SizeRemaining
 Save-ShadowStage 'shadow-initialize-intent';Initialize-Disk -Number $newNumber -PartitionStyle GPT|Out-Null
 $disk=Get-Disk -Number $newNumber;if($disk.UniqueId -cne $shadowUnique -or $native.Observe($true).physicalPath -cne $attached.physicalPath){throw 'Shadow identity changed before partitioning.'}
 $spart=New-Partition -DiskNumber $newNumber -Offset 16MB -Size 52GB -DriveLetter S
 $disk=Get-Disk -Number $newNumber;Assert-ShadowPartition $disk $spart 52GB S
 $record.shadow=[pscustomobject]@{physicalPath=$attached.physicalPath;diskNumber=$newNumber;diskUniqueId=$shadowUnique;diskGuid=[string]$disk.Guid;partitionGuid=[string]$spart.Guid;partitionNumber=$spart.PartitionNumber;offset=$spart.Offset;length=$spart.Size;logicalSectorSize=$disk.LogicalSectorSize;physicalSectorSize=$disk.PhysicalSectorSize;letter='S';volumeGuid=$null;filesystem=$null;allocationUnitSize=0}
 Save-ShadowStage 'shadow-native-format-intent';Invoke-ShadowFormat $spart -DevDrive
 $disk=Get-Disk -Number $newNumber;$spart=Get-Partition -DiskNumber $newNumber -PartitionNumber $record.shadow.partitionNumber;Assert-ShadowPartition $disk $spart 52GB S
 if($disk.UniqueId -cne $shadowUnique -or [string]$disk.Guid -cne $record.shadow.diskGuid -or [string]$spart.Guid -cne $record.shadow.partitionGuid){throw 'Formatted shadow identity changed.'}
 $svolume=Get-Volume -DriveLetter S
 if($svolume.FileSystem -cne 'ReFS' -or $svolume.FileSystemLabel -cne 'n2r-retained-shadow' -or $svolume.AllocationUnitSize -ne 4096 -or -not $svolume.UniqueId -or (Get-Partition -DriveLetter S).DiskNumber -ne $newNumber){throw 'Native shadow filesystem/binding differs.'}
 $record.shadow.volumeGuid=$svolume.UniqueId;$record.shadow.filesystem='ReFS';$record.shadow.allocationUnitSize=4096
 $record.nativeQueries=@((Invoke-ShadowQuery devdrive @('devdrv','query','S:')),(Invoke-ShadowQuery volume @('fsinfo','volumeinfo','S:')),(Invoke-ShadowQuery refs @('fsinfo','refsinfo','S:')))
 if(@($record.nativeQueries|Where-Object exitCode -NE 0).Count -or -not (Test-ShadowDevDrive $record.nativeQueries[0].stdout)){throw 'Native ReFS/Dev Drive evidence is unresolved.'}
 $record.finalVhd=$native.Observe($true);if($record.finalVhd.physicalPath -cne $attached.physicalPath){throw 'Final physical-device binding differs.'}
 $backingItem=Assert-ShadowOrdinaryPath $backing;$allocated=[Ntfs2Refs.WindowsShadowDiskApi]::AllocatedFileBytes($backing);$free=(Get-Volume -DriveLetter J).SizeRemaining
 Assert-ShadowCapacity $record.finalVhd.physicalBytes $backingItem.Length $allocated $free
 $record.backing=[pscustomobject]@{path=$backing;fileBytes=$backingItem.Length;allocatedBytes=$allocated;nativePhysicalBytes=$record.finalVhd.physicalBytes;journalFreeBytes=$free;journalDiskUniqueId=$identity.uniqueId;journalPartitionGuid=[string]$jpart.Guid}
 $record.status='shadow-platform-prepared';Save-ShadowStage 'prepared'
}catch{$record.status='failed-preserved';$record.failureStage=$record.stage;$record.error=$_.Exception.Message}
finally{
 if($native){$record.attachmentRetained=$native.Attached;if(-not $native.OperationActive -and -not $script:formatIndeterminate -and -not $script:queryIndeterminate){try{$native.Close()}catch{$record.status='failed-preserved';$record.closeError=$_.Exception.Message}};$record.nativeCalls=@($native.Calls);$record.handleCloseSucceeded=$native.HandleCloseSucceeded}
 $record.nativeOperationCompletionKnown=(-not $script:formatIndeterminate -and -not $script:queryIndeterminate -and (-not $native -or -not $native.OperationActive) -and (-not $privilegeScope -or -not $privilegeScope.Audit.operationActive));$record.finishedUtc=[DateTime]::UtcNow.ToString('o');Save-ShadowStage 'complete'
}
[pscustomobject]@{Status=$record.status;RunId=$RunId;EvidenceDirectory=$outputRoot;BackingPath=$backing;Attached=$record.attachmentRetained;OperationCompletionKnown=$record.nativeOperationCompletionKnown;ConversionQualified=$false}
