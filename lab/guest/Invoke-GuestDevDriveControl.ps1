<# Guest-only native Dev Drive data experiment. No ordinary-ReFS or OS-boot claims. #>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [Parameter(Mandatory)][string]$HostTargetJson,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runRoot = 'C:\ntfs2refs\devdrive-control'
if (-not $PSCmdlet.ShouldProcess('Enrolled blank 64 GiB target', "Dev Drive $Phase using a 52 GiB data partition; no policy changes or OS deployment")) {
    [pscustomobject]@{ DryRun=$true; Phase=$Phase; PartitionBytes=52GB; NativeDiskWrites=($Phase -ceq 'Prepare'); OrdinaryReFS=$false; ReFSBootVerified=$false }; return
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force

function Assert-DevDriveHostSpec($Spec) {
    $parsed = [guid]::Empty
    if ($Spec.role -cne 'target' -or $Spec.sizeBytes -ne 64GB -or $Spec.controllerLocation -ne 1 -or -not [guid]::TryParse([string]$Spec.vhdId,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Unexpected host target specification.' }
}
function Get-DevDrivePartition($Identity, $Expected, [switch]$Blank) {
    $disk = Get-LabGuestDisk $Identity
    $parts = @(Get-Partition -DiskNumber $disk.Number | Where-Object { [string]$_.Guid -ieq [string]$Expected.guid })
    if ($parts.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$Expected.guid)) { throw 'The target partition GUID must identify exactly one partition.' }
    $part = $parts[0]
    if ($part.PartitionNumber -ne $Expected.number -or $part.Offset -ne $Expected.offset -or $part.Size -ne 52GB -or $Expected.length -ne 52GB -or [string]$part.DriveLetter -cnotmatch '^[F-Z]$' -or [string]$part.DriveLetter -cne [string]$Expected.letter -or $part.IsBoot -or $part.IsSystem -or [string]$disk.Guid -ine [string]$Expected.diskGuid) { throw 'The target partition geometry, letter or role changed.' }
    $bound = @(Get-Partition -DriveLetter $Expected.letter)
    if ($bound.Count -ne 1 -or $bound[0].DiskNumber -ne $disk.Number -or [string]$bound[0].Guid -ine [string]$Expected.guid -or $Expected.letter -ceq $env:SystemDrive.TrimEnd(':')) { throw 'The target drive letter is ambiguous or belongs to another disk.' }
    $vol = @(Get-Volume -DriveLetter $Expected.letter)
    if ($vol.Count -ne 1) { throw 'Expected exactly one target volume.' }
    if ($Blank) {
        if ([string]$vol[0].FileSystem -notin @('','RAW','Unknown')) { throw 'Only the newly created blank data partition can be formatted.' }
    } elseif ($vol[0].FileSystem -cne 'ReFS' -or $vol[0].FileSystemLabel -cne 'ntfs2refs-target' -or $vol[0].AllocationUnitSize -ne 4096) { throw 'Expected the native ReFS data control with 4 KiB clusters.' }
    $part
}
function Test-DevDriveDesignation([string]$Text) {
    # Native fsutil also returns zero for a non-Dev volume. Fail closed on
    # unfamiliar wording and retain all output as provenance.
    $Text -notmatch '(?i)not a developer volume' -and
        ($Text -match '(?im)^\s*This (?:is|volume is) a trusted developer volume\.?\s*$' -or
         $Text -match '(?im)^\s*The volume is formatted as a developer volume\b' -or
         $Text -match '(?im)^\s*(?:This|The) volume is (?:a )?(?:trusted|untrusted) developer volume\b')
}
function Get-DevDriveComponent([string]$Path) {
    $f = Get-Item -LiteralPath $Path
    if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected native component path.' }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    [pscustomobject]@{ path=$f.FullName; version=$f.VersionInfo.FileVersion; sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant(); signature=[string]$sig.Status; signer=$(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }) }
}
function Invoke-DevDriveQuery([string[]]$Arguments) {
    foreach ($arg in $Arguments) { if ($arg -cnotmatch '^[A-Za-z0-9:]+$') { throw 'Unexpected read-only fsutil argument.' } }
    if (($Arguments -join ' ') -cnotmatch '^(?:devdrv query(?: [F-Z]:)?|fsinfo (?:volumeinfo|refsinfo) [F-Z]:)$') { throw 'Only the reviewed read-only filesystem queries are allowed.' }
    $p = New-Object Diagnostics.Process
    $p.StartInfo.FileName = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    $p.StartInfo.Arguments = $Arguments -join ' '
    $p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true
    $started=$false; $timedOut=$false; $out=$null; $err=$null
    try {
        $started=$p.Start()
        if (-not $started) { throw 'The read-only native query did not start.' }
        $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(30000)) { $timedOut=$true; $p.Kill(); if (-not $p.WaitForExit(10000)) { throw 'Native query could not be terminated.' } }
        if (-not $out.Wait(10000) -or -not $err.Wait(10000)) { throw 'Native query output did not close.' }
        $stdout=$out.GetAwaiter().GetResult(); $stderr=$err.GetAwaiter().GetResult()
        if ($stdout.Length -gt 1MB -or $stderr.Length -gt 1MB) { throw 'Native query output exceeds its evidence limit.' }
        [pscustomobject]@{ command='fsutil.exe'; arguments=@($Arguments); exitCode=$p.ExitCode; timedOut=$timedOut; stdout=$stdout; stderr=$stderr }
    } finally { if ($started -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit(10000) | Out-Null }; $p.Dispose() }
}
function Assert-DevDriveFixtureFile([string]$Path, [int64]$Length) {
    $f = Get-Item -LiteralPath $Path -Force
    if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -ne $Length -or $Length -gt 4MB) { throw 'Fixture type or bounded length changed.' }
    [pscustomobject]@{ name=$f.Name; length=$f.Length; sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
function Get-DevDriveObservation($Identity,$Partition) {
    Get-DevDrivePartition $Identity $Partition | Out-Null
    $volume=Get-Volume -DriveLetter $Partition.letter
    $queries=@(
        (Invoke-DevDriveQuery @('devdrv','query',($Partition.letter + ':'))),
        (Invoke-DevDriveQuery @('fsinfo','volumeinfo',($Partition.letter + ':'))),
        (Invoke-DevDriveQuery @('fsinfo','refsinfo',($Partition.letter + ':')))
    )
    $script:record['latestNativeQueries']=$queries
    if (@($queries | Where-Object { $_.exitCode -ne 0 -or $_.timedOut }).Count) { throw 'A native volume query failed.' }
    if (-not (Test-DevDriveDesignation $queries[0].stdout)) { throw ('Native Dev Drive designation is absent or unrecognized: ' + $queries[0].stdout) }
    $root = $Partition.letter + ':\fixtures'
    $dir=Get-Item -LiteralPath $root -Force
    if (-not $dir.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected fixture directory.' }
    $entries=@(Get-ChildItem -LiteralPath $root -Force)
    if ($entries.Count -ne 2 -or @($entries | Where-Object Name -cnotin @('nonresident.bin','small.txt')).Count) { throw 'Fixture inventory changed.' }
    $smallBytes=[Text.Encoding]::UTF8.GetBytes('ntfs2refs Dev Drive control ' + $RunId + "`n")
    $files=@((Assert-DevDriveFixtureFile (Join-Path $root 'nonresident.bin') 4MB),(Assert-DevDriveFixtureFile (Join-Path $root 'small.txt') $smallBytes.Length))
    [pscustomobject]@{ filesystem=[string]$volume.FileSystem; allocationUnitSize=$volume.AllocationUnitSize; size=$volume.Size; partition=$Partition; nativeQueries=$queries; files=$files; bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'); observedUtc=[DateTime]::UtcNow.ToString('o') }
}
function Assert-DevDriveRemount($Before,$After) {
    if ($Before.bootTime -ceq $After.bootTime -or [string]::IsNullOrWhiteSpace([string]$After.bootTime)) { throw 'Verification must occur after a different clean guest boot.' }
    foreach ($field in @('guid','diskGuid','number','offset','length','letter')) { if ([string]$Before.partition.$field -cne [string]$After.partition.$field) { throw 'Partition identity changed across reboot.' } }
    if ($Before.filesystem -cne 'ReFS' -or $After.filesystem -cne 'ReFS' -or $Before.allocationUnitSize -ne 4096 -or $After.allocationUnitSize -ne 4096 -or @($Before.files).Count -ne 2 -or @($After.files).Count -ne 2) { throw 'Filesystem or fixture inventory changed across reboot.' }
    foreach ($file in $Before.files) {
        $observedFiles=@($After.files | Where-Object name -CEQ $file.name)
        if ($observedFiles.Count -ne 1 -or $observedFiles[0].length -ne $file.length -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $observedFiles[0].sha256 -cne $file.sha256) { throw 'Logical file bytes changed across clean shutdown/reboot.' }
    }
}

$spec=$HostTargetJson | ConvertFrom-Json
Assert-DevDriveHostSpec $spec
if ($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:') { throw 'Unexpected lab guest.' }
if ($Phase -ceq 'Prepare') {
    if (Test-Path -LiteralPath $runRoot) { throw 'Dev Drive evidence already exists; baseline must be restored before another attempt.' }
    New-Item -ItemType Directory -Path $runRoot | Out-Null
} else {
    $rootItem=Get-Item -LiteralPath $runRoot -Force
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected Dev Drive evidence directory.' }
    if (Test-Path -LiteralPath (Join-Path $runRoot 'verify.json')) { throw 'Verification evidence already exists.' }
}
$record=[ordered]@{ schemaVersion=1; kind='devdrive-data-control'; phase=$Phase; runId=$RunId; status='started'; restoreAllowed=$true; stage='preflight'; scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant(); target=$null; partition=$null; formatter=$null; formatSucceeded=$false; before=$null; after=$null; remountVerified=$false; ordinaryReFS=$false; rawCaptureComplete=$false; refsBootVerified=$false; conversionQualified=$false; error=$null; createdUtc=[DateTime]::UtcNow.ToString('o') }
$recordPath=Join-Path $runRoot ($(if ($Phase -ceq 'Prepare') { 'prepare.json' } else { 'verify.json' }))
try {
    $computer=Get-CimInstance Win32_ComputerSystem
    $memory=@(Get-CimInstance Win32_PhysicalMemory)
    if ($computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or ($memory | Measure-Object Capacity -Sum).Sum -lt 8GB) { throw 'The native Dev Drive control requires the owned guest and at least 8 GiB installed memory.' }
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457) { throw 'Unexpected guest edition or build.' }
    $sourcePart=Get-Partition -DriveLetter C; $sourceDisk=Get-Disk -Number $sourcePart.DiskNumber
    if (-not $sourceDisk.IsBoot -or (Get-Volume -DriveLetter C).FileSystem -cne 'NTFS') { throw 'The running OS must remain the original NTFS baseline.' }
    $record['sourceOs']=[pscustomobject]@{ diskUniqueId=[string]$sourceDisk.UniqueId; fileSystem='NTFS'; edition='Professional'; build='10.0.26300.9457'; installedMemoryBytes=($memory | Measure-Object Capacity -Sum).Sum }
    $formatCommand=Get-Command Format-Volume
    if ($formatCommand.ModuleName -cne 'Storage' -or -not $formatCommand.Module -or -not $formatCommand.Parameters.ContainsKey('DevDrive') -or -not $formatCommand.Module.Path.StartsWith((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Storage\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Expected the native Storage Format-Volume command with DevDrive support.' }
    $fsutil=Get-DevDriveComponent (Join-Path $env:SystemRoot 'System32\fsutil.exe')
    if ($fsutil.signature -cne 'Valid' -or $fsutil.signer -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'Read-only filesystem query tool is not signed by Microsoft.' }
    $record.formatter=[pscustomobject]@{ command='Format-Volume'; modulePath=$formatCommand.Module.Path; moduleVersion=[string]$formatCommand.Module.Version; moduleSha256=(Get-FileHash -LiteralPath $formatCommand.Module.Path -Algorithm SHA256).Hash.ToLowerInvariant(); fsutil=$fsutil; components=@((Get-DevDriveComponent (Join-Path $env:SystemRoot 'System32\drivers\refs.sys')),(Get-DevDriveComponent (Join-Path $env:SystemRoot 'System32\fmifs.dll'))) }
    $query=Invoke-DevDriveQuery @('devdrv','query'); $record['systemDevDriveQuery']=$query
    if ($query.exitCode -ne 0 -or $query.timedOut -or $query.stdout -notmatch '(?im)^Developer volumes are enabled\.\s*$' -or $query.stdout -match '(?i)disabled|blocked|not enabled') { throw 'Dev Drive is unavailable or policy-blocked; configuration is preserved.' }
    if ($Phase -ceq 'Prepare') {
        $candidates=@(foreach ($d in @(Get-Disk | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.Size -eq 64GB })) {
            $m=@(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $d.Number)
            if ($m.Count -eq 1 -and (($m[0].SCSITargetId -eq 1 -and $m[0].SCSILogicalUnit -eq 0) -or ($m[0].SCSITargetId -eq 0 -and $m[0].SCSILogicalUnit -eq 1))) { $d }
        })
        if ($candidates.Count -ne 1) { throw 'Target is not uniquely mapped to the original host SCSI slot.' }
        $disk=$candidates[0]; Assert-LabGuestDisk $disk
        if ($disk.PartitionStyle -cne 'RAW' -or $disk.IsOffline -or $disk.IsReadOnly -or @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count) { throw 'Target must be online, writable and completely blank.' }
        $identity=& (Join-Path $PSScriptRoot 'Register-GuestDisk.ps1') -UniqueId ([string]$disk.UniqueId) -Role target -OutputPath (Join-Path $runRoot 'target.json') -Confirm:$false
        if ($identity.uniqueId -ceq [string]$sourceDisk.UniqueId) { throw 'Target collides with the running OS.' }
        $record.target=[pscustomobject]@{ guest=$identity; host=$spec }
        $used=@(Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter })
        $letters=@([char[]](70..90) | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $used -and -not (Test-Path -LiteralPath ($_ + ':\')) } | Select-Object -First 1)
        if ($letters.Count -ne 1) { throw 'No unused target letter is available.' }
        $record.stage='partitioning'
        $disk=Get-LabGuestDisk $identity; Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
        $disk=Get-LabGuestDisk $identity; $part=New-Partition -DiskNumber $disk.Number -Size 52GB -DriveLetter $letters[0]
        $record.partition=[pscustomobject]@{ guid=[string]$part.Guid; diskGuid=[string]$disk.Guid; number=$part.PartitionNumber; offset=$part.Offset; length=$part.Size; letter=[string]$part.DriveLetter; logicalSectorSize=$disk.LogicalSectorSize; physicalSectorSize=$disk.PhysicalSectorSize }
        $part=Get-DevDrivePartition $identity $record.partition -Blank
        $record.stage='native-devdrive-format'
        $record['formatRequest']=[pscustomobject]@{ command='Format-Volume'; devDrive=$true; fileSystem='ReFS'; allocationUnitSize=4096; label='ntfs2refs-target'; partition=$record.partition }
        $job=$null
        try {
            $job=Format-Volume -Partition $part -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'ntfs2refs-target' -Confirm:$false -AsJob
            if (-not (Wait-Job -Job $job -Timeout 180)) { $record.restoreAllowed=$false; throw 'Native format did not finish within 180 seconds; preserve guest and active operation for inspection.' }
            Receive-Job -Job $job -ErrorAction Stop | Out-Null
        } finally { if ($job -and $job.State -in @('Completed','Failed','Stopped')) { Remove-Job -Job $job -Force } }
        Get-DevDrivePartition $identity $record.partition | Out-Null; $record.formatSucceeded=$true
        $record.stage='fixtures'
        $fixtureRoot=$record.partition.letter + ':\fixtures'
        if (Test-Path -LiteralPath $fixtureRoot) { throw 'Fixture destination already exists.' }
        New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
        $stream=New-Object IO.FileStream((Join-Path $fixtureRoot 'nonresident.bin'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $buffer=New-Object byte[] 4096
            for ($i=0;$i -lt $buffer.Length;$i++) { $buffer[$i]=[byte]($i % 251) }
            for ($block=0;$block -lt 1024;$block++) {
                [Array]::Clear($buffer,0,64)
                $marker=[Text.Encoding]::ASCII.GetBytes(('N2R:' + $RunId + ':' + $block.ToString('D8')))
                [Array]::Copy($marker,$buffer,$marker.Length); $stream.Write($buffer,0,$buffer.Length)
            }
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        $small=[Text.Encoding]::UTF8.GetBytes('ntfs2refs Dev Drive control ' + $RunId + "`n")
        $stream=New-Object IO.FileStream((Join-Path $fixtureRoot 'small.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($small,0,$small.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        $record.before=Get-DevDriveObservation $identity $record.partition
        $allocation=& (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath (Join-Path $runRoot 'target.json') -FixtureRelativePath @('nonresident.bin','small.txt') -OutputPath (Join-Path $runRoot 'allocation-before.json') -MaximumHashMiB 8
        $record['allocation']=$allocation
        $record.status='prepared'; $record.stage='awaiting-clean-reboot'
    } else {
        $before=Get-Content -LiteralPath (Join-Path $runRoot 'prepare.json') -Raw | ConvertFrom-Json
        if ($before.schemaVersion -ne 1 -or $before.kind -cne 'devdrive-data-control' -or $before.runId -cne $RunId -or $before.status -cne 'prepared' -or -not $before.formatSucceeded -or -not $before.restoreAllowed -or $before.target.host.vhdId -cne $spec.vhdId -or $before.refsBootVerified -or $before.ordinaryReFS -or $before.conversionQualified -or $before.sourceOs.diskUniqueId -cne [string]$sourceDisk.UniqueId) { throw 'Preparation record does not match this data-control run.' }
        $identity=Get-Content -LiteralPath (Join-Path $runRoot 'target.json') -Raw | ConvertFrom-Json
        if ($identity.uniqueId -cne $before.target.guest.uniqueId -or $identity.location -cne $before.target.guest.location -or $identity.sizeBytes -ne $before.target.guest.sizeBytes) { throw 'Target enrollment changed across reboot.' }
        $record.target=$before.target; $record.partition=$before.partition; $record.before=$before.before; $record.formatSucceeded=$true
        $record.after=Get-DevDriveObservation $identity $record.partition
        Assert-DevDriveRemount $record.before $record.after
        $allocation=& (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath (Join-Path $runRoot 'target.json') -FixtureRelativePath @('nonresident.bin','small.txt') -OutputPath (Join-Path $runRoot 'allocation-after.json') -MaximumHashMiB 8
        $record['allocation']=$allocation
        $record.remountVerified=$true; $record.status='verified'; $record.stage='complete'
    }
} catch {
    $record.status='blocked'; $record.error=$_.Exception.Message
    $record['errorId']=$_.FullyQualifiedErrorId; $record['errorPosition']=$_.InvocationInfo.PositionMessage; $record['scriptStackTrace']=$_.ScriptStackTrace
} finally {
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $recordPath -Encoding UTF8
}
[pscustomobject]@{ status=$record.status; phase=$Phase; runId=$RunId; restoreAllowed=$record.restoreAllowed; evidenceDirectory=$runRoot; resultFile=[IO.Path]::GetFileName($recordPath); remountVerified=$record.remountVerified; refsBootVerified=$false; conversionQualified=$false }
