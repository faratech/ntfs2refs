<#
.SYNOPSIS
Uses a converted Windows installation after it has booted, and says whether
everything it did held.

.DESCRIPTION
The boot harness shows that the converted installation reaches the desktop.
This script, run in that Windows as an administrator, shows whether it can go
on being used and serviced: files are created, changed and deleted in a
profile; a path is opened through its former 8.3 name, which the conversion
left as a link beside the long name; Windows checks its own files (sfc) and
its component store (DISM); an optional feature whose payload is on the disk
is enabled and disabled, which makes the servicing stack write to the
converted volume; and the event log is searched for ReFS errors.

Prints one JSON object: a result per step, and "passed". A step that this
Windows cannot run is reported as skipped with the reason. Run the same
script in the Windows that was not converted (the control) to tell what the
conversion changed from what this build does anyway.
#>
[CmdletBinding()]
param(
    # A feature whose payload Windows keeps on the disk, enabled and then disabled.
    [string]$Feature = 'TelnetClient',
    [int]$NewFiles = 800
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$started = Get-Date
$steps = New-Object System.Collections.Generic.List[object]
$random = [Random]::new(20261113)
$sha = [Security.Cryptography.SHA256]::Create()
function Bytes([int]$n) { $b = New-Object byte[] $n; $random.NextBytes($b); , $b }
function Hash([string]$path) { $stream = [IO.File]::OpenRead($path); try { [BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-' } finally { $stream.Dispose() } }
function Step([string]$name, [scriptblock]$body) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try { $detail = & $body; $ok = $true }
    catch { $detail = "$($_.Exception.Message)"; $ok = if ($detail -like 'skipped:*') { $null } else { $false } }
    $steps.Add([pscustomobject]@{ step = $name; ok = $ok; seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1); detail = "$detail" })
}
$system = $env:SystemDrive
$volume = Get-Volume -DriveLetter $system[0]

Step 'files in a profile' {
    $work = Join-Path $env:USERPROFILE 'n2r-use'
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    $made = @{}
    foreach ($i in 0..($NewFiles - 1)) {
        $dir = '{0}\{1:d2}' -f $work, ($i % 13); $null = [IO.Directory]::CreateDirectory($dir)
        $bytes = Bytes ($random.Next(0, 150000)); $path = '{0}\file-{1:d4}.bin' -f $dir, $i
        [IO.File]::WriteAllBytes($path, $bytes); $made[$path] = [BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-'
    }
    foreach ($path in $made.Keys) { if ((Hash $path) -ne $made[$path]) { throw "a new file does not read back as written: $path" } }
    Rename-Item -LiteralPath (Join-Path $work '00') -NewName 'renamed'
    Remove-Item -LiteralPath (Join-Path $work '01') -Recurse -Force
    if (-not (Test-Path -LiteralPath (Join-Path $work 'renamed\file-0000.bin'))) { throw 'a renamed directory lost its file' }
    Remove-Item -LiteralPath $work -Recurse -Force
    "$NewFiles files written, read back, renamed and deleted in $env:USERPROFILE"
}
Step 'short names as links' {
    # ReFS has no 8.3 names. The conversion left each one of the NTFS volume
    # as a link beside its long name, so a stored short path still opens.
    $short = "$system\PROGRA~1"
    if (-not (Test-Path -LiteralPath $short)) { throw "skipped: $short does not exist (the source had no short names)" }
    $item = Get-Item -LiteralPath $short -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$short exists and is not a link" }
    $long = "$system\Program Files"
    $viaShort = @(Get-ChildItem -LiteralPath $short -Force | ForEach-Object Name | Sort-Object)
    $viaLong = @(Get-ChildItem -LiteralPath $long -Force | ForEach-Object Name | Sort-Object)
    if (Compare-Object $viaShort $viaLong) { throw "$short and $long list different names" }
    $probe = Get-ChildItem -LiteralPath "$long\Common Files" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | Select-Object -First 1
    if ($probe) {
        $through = $short + $probe.FullName.Substring($long.Length)
        if ((Hash $through) -ne (Hash $probe.FullName)) { throw "a file reads differently through the short path: $through" }
    }
    $listed = & cmd.exe /c dir /x "$system\" 2>&1 | Out-String
    "$short is a link to $($item.Target); it lists the $($viaLong.Count) names of $long, and a file reads the same through it. dir /x shows it as $(if ($listed -match '<SYMLINKD>\s+PROGRA~1') { 'a directory link' } else { 'an entry' })"
}
Step 'Windows checks its own files (sfc)' {
    $text = (& sfc.exe /scannow 2>&1 | Out-String) -replace "`0", ''
    $flat = ($text -replace '\s+', ' ').Trim()
    if ($flat -match 'did not find any integrity violations') { 'no integrity violations' }
    elseif ($flat -match 'found corrupt files and successfully repaired') { throw "sfc found and repaired corrupt files: $flat" }
    elseif ($flat -match 'found corrupt files but was unable') { throw "sfc found corrupt files it could not repair: $flat" }
    else { throw "sfc did not finish as expected (exit $LASTEXITCODE): $($flat.Substring([Math]::Max(0, $flat.Length - 300)))" }
}
Step 'component store (DISM ScanHealth)' {
    $text = (& dism.exe /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String)
    $flat = ($text -replace '\s+', ' ').Trim()
    if ($LASTEXITCODE -ne 0) { throw "DISM exited ${LASTEXITCODE}: $($flat.Substring([Math]::Max(0, $flat.Length - 300)))" }
    if ($flat -notmatch 'No component store corruption detected') { throw "DISM: $($flat.Substring([Math]::Max(0, $flat.Length - 300)))" }
    'no component store corruption'
}
Step 'servicing: enable and disable a feature' {
    $state = { (& dism.exe /Online /Get-FeatureInfo "/FeatureName:$Feature" 2>&1 | Out-String) -replace '\s+', ' ' }
    $before = & $state
    if ($before -notmatch 'State : (Disabled|Enabled)') { throw "skipped: this Windows has no feature $Feature it can report on" }
    if ($before -match 'State : Enabled') { throw "skipped: $Feature is already enabled" }
    $text = (& dism.exe /Online /Enable-Feature "/FeatureName:$Feature" /NoRestart 2>&1 | Out-String) -replace '\s+', ' '
    if ($LASTEXITCODE -notin 0, 3010) { throw "enabling $Feature failed (exit $LASTEXITCODE): $($text.Substring([Math]::Max(0, $text.Length - 300)))" }
    if ((& $state) -notmatch 'State : Enable') { throw "$Feature is not enabled after DISM said so" }
    $text = (& dism.exe /Online /Disable-Feature "/FeatureName:$Feature" /NoRestart 2>&1 | Out-String) -replace '\s+', ' '
    if ($LASTEXITCODE -notin 0, 3010) { throw "disabling $Feature failed (exit $LASTEXITCODE): $($text.Substring([Math]::Max(0, $text.Length - 300)))" }
    "$Feature enabled and disabled by the servicing stack"
}
# What Windows' own recovery environment and Setup make of this Windows:
# observed and recorded, whatever it is. Neither fails the test. (Microsoft
# documents starting Windows from ReFS for some builds only, and says that
# the recovery environment does not run from ReFS.)
Step 'recovery environment (reagentc /info), observed' {
    $text = (& reagentc.exe /info 2>&1 | Out-String) -replace '\s+', ' '
    $status = if ($text -match 'Windows RE status:\s*(\w+)') { $Matches[1] } else { 'not said' }
    $location = if ($text -match 'Windows RE location:\s*(\S*)') { $Matches[1] } else { '' }
    "reagentc exit $LASTEXITCODE; Windows RE status: $status; location: $(if ($location) { $location } else { 'none' })"
}
Step 'Setup compatibility scan from installation media, observed' {
    $media = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path -LiteralPath "$($_.DriveLetter):\setup.exe") } | Select-Object -First 1
    if (-not $media) { throw 'skipped: no installation media in a DVD drive' }
    # Scans and changes nothing: what an in-place repair upgrade would stop at.
    $setup = Start-Process -FilePath "$($media.DriveLetter):\setup.exe" -ArgumentList '/Auto', 'Upgrade', '/Quiet', '/NoReboot', '/DynamicUpdate', 'Disable', '/Compat', 'ScanOnly', '/Eula', 'Accept' -PassThru -Wait
    $code = '0x{0:X8}' -f ([uint32]([int64]$setup.ExitCode -band 0xFFFFFFFFL))
    $meaning = switch ($code) {
        '0xC1900210' { 'no compatibility issue found' }
        '0xC1900208' { 'a compatibility issue blocks the upgrade' }
        '0xC1900204' { 'the installation choice (keep files and apps) is not available' }
        '0xC1900200' { 'the machine does not meet the requirements' }
        '0xC190020E' { 'not enough free disk space' }
        default { 'see setup''s logs under $WINDOWS.~BT\Sources\Panther' }
    }
    $blocks = @(Get-ChildItem -LiteralPath "$system\`$WINDOWS.~BT\Sources\Panther" -Filter 'CompatData*.xml' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object {
        ([regex]::Matches((Get-Content -LiteralPath $_.FullName -Raw), 'BlockingType="(\w+)"[^>]*?(?:Title|Name)="([^"]*)"') | ForEach-Object { "$($_.Groups[1].Value): $($_.Groups[2].Value)" })
    }) | Where-Object { $_ -notmatch '^None' } | Select-Object -First 5
    "setup.exe /Compat ScanOnly exit $code ($meaning)$(if ($blocks) { '; ' + ($blocks -join '; ') })"
}
Step 'ReFS events' {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $started.AddMinutes(-30); Level = 1, 2 } -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'ReFS' })
    if ($events) { throw "ReFS logged $($events.Count) error(s) since the boot: $($events[0].Id) $((($events[0].Message -split "`n")[0]).Trim())" }
    'no ReFS error since the boot'
}
[pscustomobject]@{ system_drive = $system; file_system = $volume.FileSystem; health = "$($volume.HealthStatus)"; passed = -not ($steps | Where-Object { $_.ok -eq $false }); steps = $steps } | ConvertTo-Json -Depth 4 -Compress
