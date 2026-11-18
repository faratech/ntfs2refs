<#
.SYNOPSIS
Converts a data partition on the disk of the running Windows of a lab VM
through the restart route, and compares the volume's listing before and after.

.DESCRIPTION
A partition that shares its disk with the running Windows cannot be converted
while Windows runs: a conversion takes the disk offline. The restart route
prepares everything in Windows, restarts the machine into a minimal Windows
(WinPE) built from installation media, converts there and returns to Windows.

This script makes such a partition in the control OS of a lab VM (it shrinks
C: and makes P: beside it), fills it, lists it, starts the converter with
`--drive P --offline-media <the DVD>`, waits for the machine to go away and
come back, lists the volume again and compares.

The control OS must already be up from its checkpoint, with the scratch volume
S: and Windows installation media in its DVD drive:
`Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch [-VmId ...]`.
The attempt changes the control OS's disk; the next boot attempt restores the
checkpoint.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,39}$')][string]$Name,
    [Parameter(Mandatory)][guid]$VmId,
    [string]$Binary,
    # The executable that runs in WinPE. It is copied beside the converter
    # as ntfs2refs-recovery.exe, the name the converter looks for.
    [string]$RecoveryBinary,
    [string]$ManifestBinary,
    [string]$CredentialPath,
    # Size of the partition made beside C:. ReFS covers whole 64 MiB units,
    # and this route does not shrink a partition to one.
    [ValidateScript({ $_ % 64 -eq 0 -and $_ -ge 2048 })][int]$PartitionMB = 6144,
    [int]$Files = 400,
    # How long the machine may be away (restart, WinPE, conversion, return).
    [int]$AwayMinutes = 45,
    [string[]]$ConverterArgs = @()
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $RecoveryBinary) { $RecoveryBinary = Join-Path (Split-Path $Binary) 'lab-apply-prepared-offline.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path (Split-Path $Binary) 'lab-volume-manifest.exe' }
foreach ($file in $Binary, $RecoveryBinary, $ManifestBinary) { if (-not (Test-Path -LiteralPath $file)) { throw "Not found: $file" } }

$records = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $records) { throw "Attempt '$Name' already has records at $records; choose another -Name" }
$null = New-Item -ItemType Directory -Path $records
$progress = Join-Path $records 'progress.log'
function Say([string]$Text) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text; Add-Content -LiteralPath $progress -Value $line -Encoding UTF8; Write-Host $line }
$verdict = [ordered]@{
    name = $Name; outcome = 'harness-error'; vm_id = $VmId; partition_mb = $PartitionMB; files = $Files
    converter_sha256 = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    recovery_sha256 = (Get-FileHash -LiteralPath $RecoveryBinary -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Save-Verdict { [IO.File]::WriteAllText((Join-Path $records 'verdict.json'), ($verdict | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false)) }

$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is $($vm.State). Start its control OS first: Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -VmId $VmId" }
if (-not $CredentialPath) { $CredentialPath = Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml' }
$saved = Import-Clixml -LiteralPath $CredentialPath
$credential = [pscredential]::new('LabAdmin', $saved.Password)
$guestRoot = "C:\n2r\restart\$Name"
$session = $null
function Connect([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        try { return New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop }
        catch { if ((Get-Date) -gt $deadline) { throw }; Start-Sleep -Seconds 5 }
    }
}
function Screenshot([string]$Leaf) {
    # What the console shows while no session can be had (WinPE).
    try {
        $service = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
        $system = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$($VmId.ToString().ToUpper())'"
        $setting = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_VirtualSystemSettingData | Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized'
        $image = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $setting; WidthPixels = [uint16]1024; HeightPixels = [uint16]768 }
        if ($image.ReturnValue -eq 0) { [IO.File]::WriteAllBytes((Join-Path $records "$Leaf.rgb565"), [byte[]]$image.ImageData) }
    } catch { }
}

try {
    $session = Connect 60
    Say "attempt ${Name}: a $PartitionMB MiB partition beside C: on $($vm.Name), converted through a restart"
    $made = Invoke-Command -Session $session -ArgumentList $guestRoot, $PartitionMB, $Files -ScriptBlock {
        param($root, $partitionMB, $files)
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath 'S:\')) { throw 'The control OS has no scratch volume S:. Prepare it with Invoke-BootConversionAttempt.ps1 -NoConvert -KeepScratch.' }
        $media = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path -LiteralPath "$($_.DriveLetter):\sources\boot.wim") } | Select-Object -First 1
        if (-not $media) { throw 'No DVD drive with Windows installation media (sources\boot.wim) in the control OS.' }
        $null = New-Item -ItemType Directory -Path $root, 'S:\restart' -Force
        $c = Get-Partition -DriveLetter C
        if (Get-Partition -DriveLetter P -ErrorAction SilentlyContinue) { throw 'The control OS already has a volume P:.' }
        # C: gives up what Windows says it can: files that cannot be moved
        # (the page file, the end of the file table) bound it. The partition
        # is the size asked for, or the largest multiple of 64 MiB that
        # fits.
        $supported = Get-PartitionSupportedSize -DriveLetter C
        $room = $c.Size - $supported.SizeMin - 128MB
        $bytes = [Math]::Min([long]$partitionMB * 1MB, [long]([Math]::Floor($room / 64MB)) * 64MB)
        if ($bytes -lt 1024MB) { throw "C: can give up $([Math]::Round($room / 1MB)) MiB (it is $([Math]::Round($c.Size / 1GB, 1)) GiB and cannot be smaller than $([Math]::Round($supported.SizeMin / 1GB, 1)) GiB): too little for a partition beside it" }
        try { Resize-Partition -DriveLetter C -Size ($c.Size - $bytes - 64MB) } catch { throw "shrinking C: by $([Math]::Round(($bytes + 64MB) / 1MB)) MiB: $($_.Exception.Message)" }
        try { $partition = New-Partition -DiskNumber $c.DiskNumber -Size $bytes -DriveLetter P } catch { throw "making the partition beside C:: $($_.Exception.Message)" }
        $null = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'RESTART' -Confirm:$false
        # No 8.3 short names: a data volume that has them is refused.
        $null = & fsutil.exe 8dot3name set P: 1
        $random = New-Object Random 11
        foreach ($i in 1..$files) {
            $directory = 'P:\data\{0:d2}\{1:d2}' -f ($i % 7), ($i % 13)
            $null = New-Item -ItemType Directory -Path $directory -Force
            $content = New-Object byte[] ($random.Next(1, 400000)); $random.NextBytes($content)
            [IO.File]::WriteAllBytes("$directory\file-$i.bin", $content)
        }
        Set-Content -LiteralPath 'P:\data\note.txt' -Value 'a partition beside the running Windows' -Encoding UTF8
        Set-Content -LiteralPath 'P:\data\note.txt' -Stream 'second' -Value 'a second stream'
        $null = & fsutil.exe hardlink create 'P:\data\note-link.txt' 'P:\data\note.txt'
        $null = New-Item -ItemType Directory -Path 'P:\empty' -Force
        Write-VolumeCache -DriveLetter P
        $disk = Get-Disk -Number $c.DiskNumber
        [pscustomobject]@{
            media = "$($media.DriveLetter):\"; disk = $c.DiskNumber; style = "$($disk.PartitionStyle)"; partition = $partition.PartitionNumber
            offset = $partition.Offset; size = $partition.Size; c_size_after = (Get-Partition -DriveLetter C).Size
            windows_build = [Environment]::OSVersion.Version.ToString(); free_memory_bytes = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
        }
    }
    $verdict.made = $made
    Say "P: is partition $($made.partition) of disk $($made.disk) ($($made.style)), the disk of the running Windows; media at $($made.media)"

    Copy-Item -ToSession $session -LiteralPath $Binary -Destination "$guestRoot\ntfs2refs.exe" -Force
    Copy-Item -ToSession $session -LiteralPath $RecoveryBinary -Destination "$guestRoot\ntfs2refs-recovery.exe" -Force
    Copy-Item -ToSession $session -LiteralPath $ManifestBinary -Destination "$guestRoot\lab-volume-manifest.exe" -Force

    $before = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        $text = & "$root\lab-volume-manifest.exe" capture --root 'P:\' --output "$root\manifest-before.jsonl" 2>&1 | Out-String
        $list = @(& "$root\ntfs2refs.exe" --list 2>&1 | ForEach-Object { "$_" })
        $row = [string]($list | Where-Object { $_ -match '\sP:\\\s' } | Select-Object -First 1)
        [pscustomobject]@{ exit = $LASTEXITCODE; listing = $text.Trim(); row = $row.Trim(); list = $list
            serial = if ($row -match 'serial ([0-9A-F]{4}-[0-9A-F]{4})') { $Matches[1] } else { $null } }
    }
    [IO.File]::WriteAllLines((Join-Path $records 'list.txt'), [string[]]$before.list)
    $verdict.list_row = $before.row
    Say "--list: $($before.row)"
    Say "listed before: $($before.listing)"
    if (-not $before.serial) { $verdict.outcome = 'list-did-not-show-serial'; throw "--list shows no serial number for P:: $($before.row)" }

    $arguments = @('--drive', 'P', '--offline-media', $made.media, '--scratch-directory', 'S:\restart', '--yes', '--volume-serial', $before.serial) + $ConverterArgs
    $verdict.arguments = $arguments
    Say "converter: ntfs2refs.exe $($arguments -join ' ')"
    # Started as SYSTEM by a task, with its output in files on C:, which is
    # there again after the restart: the session does not outlive it.
    Invoke-Command -Session $session -ArgumentList $guestRoot, (,$arguments) -ScriptBlock {
        param($root, $arguments)
        $line = "`"$root\ntfs2refs.exe`" " + (($arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' ')
        Set-Content -LiteralPath "$root\run.cmd" -Encoding ASCII -Value "@echo off`r`n$line > `"$root\stdout.log`" 2> `"$root\stderr.log`"`r`necho %ERRORLEVEL% > `"$root\exit.txt`""
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c `"$root\run.cmd`""
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $null = Register-ScheduledTask -TaskName 'n2r-restart-route' -Action $action -Principal $principal -Settings $settings -Force
        Start-ScheduledTask -TaskName 'n2r-restart-route'
    }
    $started = Get-Date
    # The run prepares in Windows, then restarts the machine. Until then the
    # session answers; a converter that ends without a restart has refused
    # or failed.
    $restarted = $false; $last = ''
    while (-not $restarted) {
        Start-Sleep -Seconds 10
        try {
            $state = Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
                param($root)
                $exit = if (Test-Path -LiteralPath "$root\exit.txt") { (Get-Content -LiteralPath "$root\exit.txt" -Raw).Trim() } else { $null }
                $tail = if (Test-Path -LiteralPath "$root\stdout.log") { [string](Get-Content -LiteralPath "$root\stdout.log" -Tail 1) } else { '' }
                [pscustomobject]@{ exit = $exit; tail = $tail }
            }
            if ($state.tail -and $state.tail -ne $last) { $last = $state.tail; Say ("[{0:N0} s] {1}" -f ((Get-Date) - $started).TotalSeconds, $last.Substring(0, [Math]::Min(180, $last.Length))) }
            if ($null -ne $state.exit -and $state.exit -ne '0') {
                $verdict.outcome = 'refused-or-failed-in-windows'; $verdict.exit = $state.exit
                throw "the converter ended in Windows with exit $($state.exit) and did not restart"
            }
        } catch [System.Management.Automation.Remoting.PSRemotingTransportException] { $restarted = $true }
        catch { if ($_.Exception.Message -match 'session|pipeline|connection|broken|closed') { $restarted = $true } else { throw } }
        if (((Get-Date) - $started).TotalMinutes -gt $AwayMinutes) { $verdict.outcome = 'no-restart'; throw "no restart after $AwayMinutes minutes" }
    }
    $verdict.prepared_seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds)
    Say "the machine went away after $($verdict.prepared_seconds) s in Windows"
    Remove-PSSession $session -ErrorAction SilentlyContinue; $session = $null

    # Away: WinPE, the conversion, the return. No session can be had in
    # WinPE; the console is pictured once a minute.
    $away = Get-Date; $shot = 0
    while ($true) {
        Start-Sleep -Seconds 20
        if (((Get-Date) - $away).TotalSeconds -ge 60 * ($shot + 1)) { $shot++; Screenshot ('console-{0:d2}' -f $shot) }
        try {
            $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
            $null = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
            break
        } catch { $session = $null }
        if (((Get-Date) - $away).TotalMinutes -gt $AwayMinutes) { $verdict.outcome = 'did-not-return'; Screenshot 'console-last'; throw "Windows did not come back within $AwayMinutes minutes" }
    }
    $verdict.away_seconds = [Math]::Round(((Get-Date) - $away).TotalSeconds)
    Say "Windows is back after $($verdict.away_seconds) s away"

    $after = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        $volume = Get-Volume -DriveLetter P -ErrorAction SilentlyContinue
        $listed = ''; $summary = ''; $compare = $null
        if ($volume) {
            $listed = & "$root\lab-volume-manifest.exe" capture --root 'P:\' --output "$root\manifest-after.jsonl" 2>&1 | Out-String
            $summary = & "$root\lab-volume-manifest.exe" compare --exact --before "$root\manifest-before.jsonl" --after "$root\manifest-after.jsonl" --report "$root\manifest-report.json" 2>&1 | Out-String
            $compare = $LASTEXITCODE
        }
        $partition = Get-Partition -DriveLetter P -ErrorAction SilentlyContinue
        [pscustomobject]@{
            filesystem = if ($volume) { "$($volume.FileSystem)" } else { $null }; health = if ($volume) { "$($volume.HealthStatus)" } else { $null }
            read_only = if ($partition) { [bool]$partition.IsReadOnly } else { $null }
            listed = $listed.Trim(); summary = $summary.Trim(); compare_exit = $compare
            boot_default = [string](& bcdedit.exe /enum '{bootmgr}' 2>&1 | Where-Object { $_ -match '^(default|displayorder|timeout)' } | Out-String).Trim()
            runs = @(Get-ChildItem -LiteralPath 'S:\restart' -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)
        }
    }
    $verdict.after = $after
    Say "P: is $($after.filesystem), $($after.health), read-only: $($after.read_only)"
    Say "compare: $($after.summary)"
    foreach ($leaf in 'stdout.log', 'stderr.log', 'exit.txt', 'manifest-report.json') {
        try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records -Force -ErrorAction Stop } catch { }
    }
    # The run's small records, and what WinPE wrote beside them.
    try {
        Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
            param($root)
            $files = Get-ChildItem -LiteralPath 'S:\restart' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 4MB -and $_.Extension -in '.json', '.log', '.txt' }
            if ($files) { Compress-Archive -LiteralPath $files.FullName -DestinationPath "$root\records.zip" -Force }
        }
        Copy-Item -FromSession $session -LiteralPath "$guestRoot\records.zip" -Destination $records -Force -ErrorAction Stop
    } catch { Say "the run's records could not be collected: $($_.Exception.Message)" }
    $verdict.outcome = if ($after.filesystem -ne 'ReFS') { "returned-with-$($after.filesystem)" }
        elseif ($after.compare_exit -ne 0) { 'converted-but-listing-differs' }
        else { 'converted' }
}
catch {
    $verdict.error = "$($_.Exception.Message)"
    Say "ERROR: $($verdict.error)"
    if ($session) {
        foreach ($leaf in 'stdout.log', 'stderr.log', 'exit.txt') { try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records -Force -ErrorAction Stop } catch { } }
    }
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    Save-Verdict
    Say "outcome: $($verdict.outcome). Records: $records"
}
