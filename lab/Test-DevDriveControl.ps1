<# Pure/mocked guards plus WhatIf: no VM actions, disk formats or policy changes. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$asts=@{}
foreach ($relative in @('scripts\Invoke-LabDevDriveControl.ps1','lab\guest\Invoke-GuestDevDriveControl.ps1')) {
    $tokens=$null; $errors=$null
    $asts[$relative]=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $relative),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ('Parse failure: ' + ($errors.Message -join '; ')) }
}
foreach ($name in @('Assert-DevDriveHostSpec','Get-DevDrivePartition','Test-DevDriveDesignation','Invoke-DevDriveQuery','Assert-DevDriveRemount')) {
    $definition=$asts['lab\guest\Invoke-GuestDevDriveControl.ps1'].Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name },$false)
    Invoke-Expression $definition.Extent.Text
}
foreach ($name in @('Assert-DevDriveStartState','Assert-DevDriveResult','Assert-DevDriveArtifact','Assert-DevDriveGuestRecord')) {
    $definition=$asts['scripts\Invoke-LabDevDriveControl.ps1'].Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name },$false)
    Invoke-Expression $definition.Extent.Text
}
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message }; $script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false; try { & $Action | Out-Null } catch { $failed=$true }; Check $failed $Message }
function Copy-Record($Object) { $Object | ConvertTo-Json -Depth 15 | ConvertFrom-Json }
$spec=[pscustomobject]@{ role='target'; sizeBytes=64GB; controllerLocation=1; vhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5' }
Assert-DevDriveHostSpec $spec; $checks++
foreach ($change in @(@{role='journal'},@{sizeBytes=8GB},@{controllerLocation=0},@{vhdId='no'},@{vhdId=[guid]::Empty.ToString()})) {
    $bad=Copy-Record $spec; foreach ($key in $change.Keys) { $bad.$key=$change[$key] }; Reject { Assert-DevDriveHostSpec $bad } 'Invalid host target accepted.'
}
$script:disk=[pscustomobject]@{ Number=1; Guid='a1aa0ac2-e1fa-4e16-82f8-edfb76e71733' }
$script:part=[pscustomobject]@{ DiskNumber=1; PartitionNumber=2; Guid='a2aa0ac2-e1fa-4e16-82f8-edfb76e71733'; Offset=16MB; Size=52GB; DriveLetter='F'; IsBoot=$false; IsSystem=$false }
$expected=[pscustomobject]@{ diskGuid=$disk.Guid; guid=$part.Guid; number=2; offset=16MB; length=52GB; letter='F' }
$script:volume=[pscustomobject]@{ FileSystem='ReFS'; FileSystemLabel='ntfs2refs-target'; AllocationUnitSize=4096 }
$script:duplicate=$false; $script:otherDisk=$false
function Get-LabGuestDisk { param($Identity) $script:disk }
function Get-Partition { param($DiskNumber,$DriveLetter) if ($PSBoundParameters.ContainsKey('DriveLetter') -and $script:otherDisk) { [pscustomobject]@{DiskNumber=0;Guid=$script:part.Guid} } else { $script:part; if ($script:duplicate) { $script:part } } }
function Get-Volume { param($DriveLetter) $script:volume }
Get-DevDrivePartition @{} $expected | Out-Null; $checks++
foreach ($field in @('PartitionNumber','Offset','Size')) {
    $saved=$part.$field; $part.$field=$saved+1; Reject { Get-DevDrivePartition @{} $expected } "Changed $field accepted."; $part.$field=$saved
}
foreach ($field in @('IsBoot','IsSystem')) { $part.$field=$true; Reject { Get-DevDrivePartition @{} $expected } 'Boot/system partition accepted.'; $part.$field=$false }
$part.DriveLetter='C'; Reject { Get-DevDrivePartition @{} $expected } 'Original OS drive accepted.'; $part.DriveLetter='F'
$disk.Guid='b1aa0ac2-e1fa-4e16-82f8-edfb76e71733'; Reject { Get-DevDrivePartition @{} $expected } 'Changed GPT disk accepted.'; $disk.Guid=$expected.diskGuid
$duplicate=$true; Reject { Get-DevDrivePartition @{} $expected } 'Duplicate partition accepted.'; $duplicate=$false
$otherDisk=$true; Reject { Get-DevDrivePartition @{} $expected } 'Letter rebound to OS accepted.'; $otherDisk=$false
Reject { Get-DevDrivePartition @{} $expected -Blank } 'Existing filesystem accepted for formatting.'
$volume.FileSystem='RAW'; Get-DevDrivePartition @{} $expected -Blank | Out-Null; $checks++
Reject { Get-DevDrivePartition @{} $expected } 'RAW volume accepted as Dev Drive.'
$volume.FileSystem='ReFS'; $volume.AllocationUnitSize=65536; Reject { Get-DevDrivePartition @{} $expected } 'Wrong cluster size accepted.'; $volume.AllocationUnitSize=4096
$volume.FileSystemLabel='other'; Reject { Get-DevDrivePartition @{} $expected } 'Unowned volume label accepted.'; $volume.FileSystemLabel='ntfs2refs-target'
foreach ($text in @('This is not a developer volume.','','Developer volumes are enabled.','Unknown result')) { Check (-not (Test-DevDriveDesignation $text)) 'Unproven Dev Drive designation accepted.' }
foreach ($text in @('This is a trusted developer volume.','The volume is formatted as a developer volume but is not trusted on this machine.','This volume is a trusted developer volume.')) { Check (Test-DevDriveDesignation $text) 'Known native designation refused.' }
foreach ($queryArgs in @(@('devdrv','enable'),@('devdrv','untrust','F:'),@('devdrv','query','F:\'),@('fsinfo','refsinfo','C:'),@('devdrv','query','F: & whoami'))) { Reject { Invoke-DevDriveQuery $queryArgs } 'Unreviewed native query invocation accepted.' }
$before=[pscustomobject]@{ bootTime='2026-10-23T22:00:00Z'; filesystem='ReFS'; allocationUnitSize=4096; partition=$expected; files=@([pscustomobject]@{name='nonresident.bin';length=4MB;sha256=('a'*64)},[pscustomobject]@{name='small.txt';length=64;sha256=('b'*64)}) }
$after=Copy-Record $before; $after.bootTime='2026-10-23T22:01:00Z'
Assert-DevDriveRemount $before $after; $checks++
$after.bootTime=$before.bootTime; Reject { Assert-DevDriveRemount $before $after } 'Same boot accepted.'; $after.bootTime='later'
$after.files[0].sha256='c'*64; Reject { Assert-DevDriveRemount $before $after } 'Changed data accepted.'; $after.files[0].sha256='a'*64
$after.files[0].length=3MB; Reject { Assert-DevDriveRemount $before $after } 'Changed file length accepted.'; $after.files[0].length=4MB
$after.files[1].name='nonresident.bin'; Reject { Assert-DevDriveRemount $before $after } 'Duplicate identity accepted.'; $after.files[1].name='small.txt'
$after.partition.offset=17MB; Reject { Assert-DevDriveRemount $before $after } 'Changed partition accepted.'; $after.partition.offset=16MB
$baseline=[pscustomobject]@{Id='eda059b3-6d50-46bb-bdf4-018b99b5b34f'}
$vm=[pscustomobject]@{State='Off'; MemoryStartup=4GB; DynamicMemoryEnabled=$false; ParentSnapshotId=$baseline.Id}
Assert-DevDriveStartState $vm $baseline; $checks++
foreach ($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=[guid]::Empty.ToString()})) { $bad=Copy-Record $vm; foreach ($key in $change.Keys) { $bad.$key=$change[$key] }; Reject { Assert-DevDriveStartState $bad $baseline } 'Unqualified start state accepted.' }
$result=[pscustomobject]@{ phase='Prepare';runId=('a'*32);status='prepared';resultFile='prepare.json';evidenceDirectory='C:\ntfs2refs\devdrive-control';refsBootVerified=$false;conversionQualified=$false }
Assert-DevDriveResult $result Prepare ('a'*32); $checks++
foreach ($change in @(@{phase='Verify'},@{runId=('b'*32)},@{status='complete'},@{resultFile='target.json'},@{refsBootVerified=$true},@{conversionQualified=$true},@{evidenceDirectory='C:\Windows'})) { $bad=Copy-Record $result; foreach ($key in $change.Keys) { $bad.$key=$change[$key] }; Reject { Assert-DevDriveResult $bad Prepare ('a'*32) } 'Unexpected remote result accepted.' }
$artifact=[pscustomobject]@{name='prepare.json'; length=1024; sha256=('a'*64);attributes='Archive'}
Assert-DevDriveArtifact $artifact; $checks++
foreach ($change in @(@{name='..\prepare.json'},@{name='control.raw'},@{length=-1},@{length=17MB},@{sha256='bad'},@{attributes='ReparsePoint'})) { $bad=Copy-Record $artifact; foreach ($key in $change.Keys) { $bad.$key=$change[$key] }; Reject { Assert-DevDriveArtifact $bad } 'Unexpected export accepted.' }
$hostText=$asts['scripts\Invoke-LabDevDriveControl.ps1'].Extent.Text
$guest=[pscustomobject]@{ schemaVersion=1;kind='devdrive-data-control';phase='Verify';runId=('a'*32);status='verified';ordinaryReFS=$false;rawCaptureComplete=$false;refsBootVerified=$false;conversionQualified=$false;restoreAllowed=$true;formatSucceeded=$true;remountVerified=$true;target=[pscustomobject]@{host=$spec;guest=[pscustomobject]@{role='target';sizeBytes=64GB}};partition=[pscustomobject]@{length=52GB;logicalSectorSize=512;physicalSectorSize=4096;guid=$expected.guid;diskGuid=$expected.diskGuid};sourceOs=[pscustomobject]@{fileSystem='NTFS';build='10.0.26300.9457';installedMemoryBytes=8GB};before=$before;after=$after }
Assert-DevDriveGuestRecord $guest Verify ('a'*32) $spec.vhdId; $checks++
foreach ($change in @(@{schemaVersion=2},@{kind='ordinary'},@{runId=('b'*32)},@{ordinaryReFS=$true},@{rawCaptureComplete=$true},@{refsBootVerified=$true},@{conversionQualified=$true},@{restoreAllowed=$false},@{formatSucceeded=$false},@{remountVerified=$false})) { $bad=Copy-Record $guest; foreach ($key in $change.Keys) { $bad.$key=$change[$key] }; Reject { Assert-DevDriveGuestRecord $bad Verify ('a'*32) $spec.vhdId } 'Inconsistent successful export accepted.' }
$bad=Copy-Record $guest; $bad.partition.diskGuid='bad'; Reject { Assert-DevDriveGuestRecord $bad Verify ('a'*32) $spec.vhdId } 'Missing disk GUID accepted.'
$bad=Copy-Record $guest; $bad.target.host.vhdId=[guid]::Empty.ToString(); Reject { Assert-DevDriveGuestRecord $bad Verify ('a'*32) $spec.vhdId } 'Changed VHD provenance accepted.'
$bad=Copy-Record $guest; $bad.sourceOs.fileSystem='ReFS'; Reject { Assert-DevDriveGuestRecord $bad Verify ('a'*32) $spec.vhdId } 'ReFS source OS confused with data control.'
$guestText=$asts['lab\guest\Invoke-GuestDevDriveControl.ps1'].Extent.Text
$hostCommands=@($asts['scripts\Invoke-LabDevDriveControl.ps1'].FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
Check (@($hostCommands | Where-Object {$_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Set-VMFirmware','Stop-VM')}).Count -eq 0) 'Host disk mutation, firmware selection, or forced stop found.'
Check (-not ($guestText -match '(?im)^\s*(?:Enable|Disable)-WindowsOptionalFeature\b|Set-SecureBootUEFI\b|devdrv\s+(?:enable|disable|trust|untrust|setfiltersallowed)')) 'Policy or feature mutation found.'
Check ($hostText.IndexOf('$formatIndeterminate=($phase') -lt $hostText.IndexOf('$phaseJob=Invoke-Command')) 'Formatting transport must be indeterminate before dispatch.'
Check ($hostText.Contains('Wait-Job -Job $phaseJob -Timeout 600') -and $hostText.Contains('Wait-Job -Job $probe -Timeout 10')) 'Guest/connection timeout guards absent.'
Check ($hostText.IndexOf('-Action Checkpoint') -lt $hostText.IndexOf('-Action Restore')) 'Successful checkpoint must precede baseline restore.'
Check ($guestText.Contains('-DevDrive -FileSystem ReFS -AllocationUnitSize 4096') -and $guestText.Contains('-Size 52GB')) 'Wrong native format profile.'
Check ($guestText.Contains('allocation-before.json') -and $guestText.Contains('allocation-after.json')) 'Allocation evidence integration missing.'
$dry=& (Join-Path $workspace 'scripts\Invoke-LabDevDriveControl.ps1') -WhatIf
Check ($dry.DryRun -and -not $dry.HostNativeDiskWrites -and $dry.MemoryBytes -eq 8GB -and $dry.PartitionBytes -eq 52GB) 'Host WhatIf contract failed.'
foreach ($phase in @('Prepare','Verify')) { $dry=& (Join-Path $workspace 'lab\guest\Invoke-GuestDevDriveControl.ps1') -Phase $phase -HostTargetJson '{}' -RunId ('a'*32) -WhatIf; Check ($dry.DryRun -and -not $dry.ReFSBootVerified) 'Guest WhatIf failed.' }
"Dev Drive control: $checks checks passed."
