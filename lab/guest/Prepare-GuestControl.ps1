[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidateSet('FormatNTFS','FormatReFS','Fixtures')][string]$Action
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$disk = Get-LabGuestDisk $manifest
if ($Action -ne 'Fixtures') {
    if ($disk.PartitionStyle -ne 'RAW') { throw 'Formatting only accepts an enrolled blank RAW disk. Restore the blank checkpoint for another control.' }
    $fs = if ($Action -eq 'FormatNTFS') { 'NTFS' } else { 'ReFS' }
    if ($manifest.role -eq 'journal' -and $fs -ne 'NTFS') { throw 'Use NTFS for recovery-journal storage.' }
    if (-not $PSCmdlet.ShouldProcess("$($disk.UniqueId) ($($disk.Size) bytes)","Initialize GPT and format disposable $($manifest.role) disk as $fs")) { return }
    $disk = Get-LabGuestDisk $manifest
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | Out-Null
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    $partition | Format-Volume -FileSystem $fs -AllocationUnitSize 4096 -NewFileSystemLabel ('ntfs2refs-' + $manifest.role) -Confirm:$false | Out-Null
    Get-Volume -DriveLetter $partition.DriveLetter | Select-Object DriveLetter,FileSystem,FileSystemLabel,AllocationUnitSize,Size
    return
}
if ($manifest.role -ne 'target') { throw 'Fixtures require the target role.' }
$partitions = @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter })
if ($partitions.Count -ne 1) { throw 'Expected exactly one mounted data partition.' }
$volume = Get-Volume -DriveLetter $partitions[0].DriveLetter
if ($volume.FileSystem -notin @('NTFS','ReFS') -or $volume.FileSystemLabel -ne 'ntfs2refs-target') { throw 'Unexpected fixture filesystem or label.' }
$root = "$($partitions[0].DriveLetter):\fixtures"
if (Test-Path -LiteralPath $root) { throw 'Fixture directory already exists; restore the blank/control checkpoint to repeat.' }
if (-not $PSCmdlet.ShouldProcess($root,'Create deterministic filesystem fixtures')) { return }
New-Item -ItemType Directory -Path $root | Out-Null
[IO.File]::WriteAllBytes((Join-Path $root 'empty.bin'),[byte[]]@())
[IO.File]::WriteAllText((Join-Path $root 'resident.txt'),'resident payload',[Text.Encoding]::UTF8)
$unicodeName = 'Unicode-' + [char]0x03bb + '-' + [char]0x6587 + [char]0x4ef6 + '.txt'
[IO.File]::WriteAllText((Join-Path $root $unicodeName),'unicode payload',[Text.Encoding]::UTF8)
$large = Join-Path $root 'nonresident.bin'
$stream = [IO.File]::Create($large)
try {
    $buffer = New-Object byte[] 65536
    for ($i=0;$i -lt $buffer.Length;$i++) { $buffer[$i] = [byte]($i % 251) }
    for ($i=0;$i -lt 256;$i++) { $stream.Write($buffer,0,$buffer.Length) }
    $stream.Flush($true)
} finally { $stream.Dispose() }
# .NET Framework path validation rejects ADS syntax; the filesystem provider
# exposes the documented stream API on Windows PowerShell 5.
Set-Content -LiteralPath $large -Stream named -Value 'alternate-stream' -Encoding UTF8 -NoNewline
New-Item -ItemType HardLink -Path (Join-Path $root 'hardlink.bin') -Target $large | Out-Null
New-Item -ItemType SymbolicLink -Path (Join-Path $root 'symlink.bin') -Target $large | Out-Null
$sparse = Join-Path $root 'sparse.bin'
$stream = [IO.File]::Create($sparse); $stream.Dispose()
& fsutil sparse setflag $sparse | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Native sparse-file creation failed.' }
$stream = [IO.File]::OpenWrite($sparse)
try { $stream.SetLength(16777216); $stream.Position = 8388608; $stream.WriteByte(0x5a); $stream.Flush($true) } finally { $stream.Dispose() }
$aclPath = Join-Path $root 'acl.txt'
[IO.File]::WriteAllText($aclPath,'ACL fixture')
$acl = Get-Acl -LiteralPath $aclPath
$acl.SetAccessRuleProtection($true,$true)
Set-Acl -LiteralPath $aclPath -AclObject $acl
[pscustomobject]@{ Root=$root; FileSystem=$volume.FileSystem; Notes='Fixtures include native metadata; the Rust inspector must report unsupported features rather than silently omit them.' }
