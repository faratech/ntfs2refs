function Save-IntegritySource($Session, [string]$Name, [string]$Output) {
    $image = "S:\datalab\$Name.vhdx"
    $bytes = Invoke-Command -Session $Session -ArgumentList $image -ScriptBlock { param($path) (Get-Item -LiteralPath $path).Length }
    if ((Get-Volume -FilePath $Output).SizeRemaining -lt $bytes) { throw 'Insufficient private storage for the source snapshot' }
    Invoke-Command -Session $Session -ArgumentList $image -ScriptBlock {
        param($path)
        Dismount-DiskImage -ImagePath $path | Out-Null
    }
    try {
        Copy-Item -FromSession $Session -LiteralPath $image -Destination (Join-Path $Output 'before.vhdx')
    } finally {
        Invoke-Command -Session $Session -ArgumentList $image -ScriptBlock {
            param($path)
            $disk = Mount-DiskImage -ImagePath $path -PassThru | Get-Disk
            if (-not (Get-Partition -DriveLetter V -ErrorAction SilentlyContinue)) {
                Get-Partition -DiskNumber $disk.Number | Where-Object Type -eq 'Basic' | Set-Partition -NewDriveLetter V
            }
            if ((Get-Partition -DriveLetter V).DiskNumber -ne $disk.Number) { throw 'V: is not the integrity source' }
        }
    }
}

function Restart-IntegrityGuest($Session, [guid]$VmId, [pscredential]$Credential, [datetime]$PreviousBoot) {
    Invoke-Command -Session $Session -ScriptBlock {
        shutdown.exe /r /t 2 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restart the acceptance VM' }
    }
    Start-Sleep -Seconds 5
    $deadline = (Get-Date).AddMinutes(5)
    do {
        Start-Sleep -Seconds 2
        $next = New-PSSession -VMId $VmId -Credential $Credential -ErrorAction SilentlyContinue
        if ($next) {
            $boot = Invoke-Command -Session $next -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
            if ($boot -gt $PreviousBoot) { break }
            Remove-PSSession $next
            $next = $null
        }
    } while ((Get-Date) -lt $deadline)
    if (-not $next) { throw 'Acceptance guest did not restart' }
    Remove-PSSession $Session
    $next
}

function Initialize-IntegrityCrashCapture([guid]$VmId, [pscredential]$Credential, [string]$Output) {
    $session = New-PSSession -VMId $VmId -Credential $Credential -ErrorAction Stop
    try {
        $was = Invoke-Command -Session $session -ScriptBlock {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
            Set-ItemProperty -LiteralPath $key -Name CrashDumpEnabled -Value 3 -Type DWord
            Set-ItemProperty -LiteralPath $key -Name AutoReboot -Value 1 -Type DWord
            Set-ItemProperty -LiteralPath $key -Name LogEvent -Value 1 -Type DWord
            Set-ItemProperty -LiteralPath $key -Name MinidumpDir -Value '%SystemRoot%\Minidump' -Type ExpandString
            (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        }
        $session = Restart-IntegrityGuest $session $VmId $Credential $was
        $configuration = Invoke-Command -Session $session -ScriptBlock {
            $crash = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
            $page = @(Get-CimInstance Win32_PageFileUsage | Where-Object {
                $_.Name.StartsWith("$env:SystemDrive\", [StringComparison]::OrdinalIgnoreCase) -and $_.AllocatedBaseSize -ge 2
            })
            if ($crash.CrashDumpEnabled -ne 3 -or $crash.AutoReboot -ne 1 -or $crash.LogEvent -ne 1 -or !$page.Count) {
                throw 'The disposable guest lacks the small-dump policy or its system-volume paging file'
            }
            @{ kind = 'small-memory-dump'; directory = [Environment]::ExpandEnvironmentVariables($crash.MinidumpDir)
                page_file_mib = $page[0].AllocatedBaseSize; boot_utc = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
        }
        $configuration | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $Output 'crash-capture.json') -Encoding utf8
    } finally { if ($session) { Remove-PSSession $session } }
}

function Invoke-IntegrityReboot($Session, [guid]$VmId, [pscredential]$Credential, [string]$Name) {
    $saved = Invoke-Command -Session $Session -ScriptBlock {
        $path = 'V:\qualification-across-reboot.txt'
        [IO.File]::WriteAllText($path, 'ntfs2refs acceptance across reboot')
        [pscustomobject]@{ boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; hash = (Get-FileHash -LiteralPath $path).Hash }
    }
    $next = Restart-IntegrityGuest $Session $VmId $Credential $saved.boot
    try {
        Invoke-Command -Session $next -ArgumentList $Name, $saved.hash -ScriptBlock {
            param($name, $hash)
            $path = "S:\datalab\$name.vhdx"
            $image = Get-DiskImage -ImagePath $path
            if (-not $image.Attached) { $image = Mount-DiskImage -ImagePath $path -PassThru }
            $disk = $image | Get-Disk
            if (-not (Get-Partition -DriveLetter V -ErrorAction SilentlyContinue)) {
                Get-Partition -DiskNumber $disk.Number | Where-Object Type -eq 'Basic' | Set-Partition -NewDriveLetter V
            }
            if ((Get-Partition -DriveLetter V).DiskNumber -ne $disk.Number -or (Get-Volume -DriveLetter V).FileSystem -ne 'ReFS') { throw 'The acceptance ReFS volume did not return' }
            $marker = 'V:\qualification-across-reboot.txt'
            if ((Get-FileHash -LiteralPath $marker).Hash -ne $hash) { throw 'Acceptance data differs after reboot' }
            $path = 'V:\qualification-post-reboot.bin'
            $bytes = [byte[]]::new(4MB)
            [Random]::new(253).NextBytes($bytes)
            [IO.File]::WriteAllBytes($path, $bytes)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $expected = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') } finally { $sha.Dispose() }
            if ((Get-FileHash -LiteralPath $path).Hash -ne $expected) { throw 'Post-reboot allocation read-back differs' }
            Remove-Item -LiteralPath $path -Force
            if ((Get-FileHash -LiteralPath $marker).Hash -ne $hash) { throw 'Prior data differs after post-reboot mutation' }
            Remove-Item -LiteralPath $marker -Force
        }
    } catch {
        $script:session = $next
        throw
    }
    $next
}

function Save-IntegrityEvents($Session, [datetime]$Started, [string]$Name, [string]$Output, $Acceptance) {
    $data = Invoke-Command -Session $Session -ArgumentList $Started, $Name -ScriptBlock {
        param($start, $name)
        # Get-WinEvent interprets StartTime as local wall-clock time.
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $start.ToLocalTime() } -ErrorAction Stop |
                Where-Object { $_.ProviderName -match 'ReFS|Ntfs|volmgr|disk|storport' -and ($_.Level -le 3 -or $_.Id -in 131, 134) })
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $events = @()
        }
        $volume = Get-Volume -DriveLetter V -ErrorAction SilentlyContinue
        $partition = Get-Partition -DriveLetter V -ErrorAction SilentlyContinue
        $refs = if ($volume -and $volume.FileSystem -eq 'ReFS') { (& fsutil.exe fsinfo refsinfo V: 2>&1 | Out-String).Trim() }
        [pscustomobject]@{
            windows = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            volume = $volume | Select-Object Path, UniqueId, FileSystem, AllocationUnitSize, HealthStatus
            partition = $partition | Select-Object Guid, DiskNumber, PartitionNumber
            refs = $refs
            events = @($events | ForEach-Object {
                $created = $_.TimeCreated
                $utc = if ($created) { $created.ToUniversalTime().ToString('o') }
                @{ provider = $_.ProviderName; id = $_.Id; time = $created; time_utc = $utc; record = $_.RecordId; xml = $_.ToXml() }
            })
            progress = Get-Content -LiteralPath "C:\n2r\datalab\$name\use-progress.log" -Tail 20 -ErrorAction SilentlyContinue
        }
    }
    $steps = @()
    if ($Acceptance) { $steps = @($Acceptance.steps) }
    $data | Add-Member -NotePropertyName acceptance_steps -NotePropertyValue $steps
    $data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Output 'storage-events.json') -Encoding utf8
    # The isolated acceptance VM is dedicated to one experiment at a time.
    $serious = @($data.events | Where-Object { $_.provider -match 'ReFS' -and $_.id -in 131, 134 })
    @{ windows = $data.windows; refs = $data.refs; volume = $data.volume; partition = $data.partition
        serious_count = $serious.Count; events = @($data.events | ForEach-Object { @{ provider = $_.provider; id = $_.id; time = $_.time; record = $_.record } }) }
}

# A guest bugcheck can break PowerShell Direct before the guest log can be copied.
function Save-IntegrityHostCrashes([guid]$VmId, [datetime]$Started, [string]$Output) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Hyper-V-Worker-Admin'
            Id = 18590
            StartTime = $Started.ToLocalTime()
        } -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        $events = @()
    }
    $crashes = @(foreach ($event in $events) {
        $xml = $event.ToXml()
        $guest = ([xml]$xml).Event.UserData.VmlEventLog
        if ($guest.VmId -eq $VmId.ToString()) {
            [pscustomobject]@{
                time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                record = $event.RecordId
                bugcheck = $guest.VmErrorCode0
                xml = $xml
            }
        }
    })
    ConvertTo-Json -InputObject $crashes -Depth 3 |
        Set-Content -LiteralPath (Join-Path $Output 'host-guest-crashes.json') -Encoding utf8
    $crashes
}

function Save-IntegrityGuestDumps($Session, [datetime]$Started, [string]$Output) {
    $dumps = @(Invoke-Command -Session $Session -ArgumentList $Started.ToUniversalTime() -ScriptBlock {
        param($start)
        $directory = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name MinidumpDir
        $directory = [Environment]::ExpandEnvironmentVariables($directory)
        if (Test-Path -LiteralPath $directory) {
            Get-ChildItem -LiteralPath $directory -Filter '*.dmp' -File |
                Where-Object LastWriteTimeUtc -ge $start | Select-Object FullName, Name, Length, LastWriteTimeUtc
        }
    })
    $receipts = @(foreach ($dump in $dumps) {
        $destination = Join-Path $Output $dump.Name
        Copy-Item -FromSession $Session -LiteralPath $dump.FullName -Destination $destination
        if ((Get-Item -LiteralPath $destination).Length -ne $dump.Length) { throw "Guest dump copy length differs for $($dump.Name)" }
        @{ name = $dump.Name; bytes = $dump.Length; sha256 = (Get-FileHash -LiteralPath $destination).Hash
            last_write_utc = $dump.LastWriteTimeUtc }
    })
    @{
        status = if ($receipts.Count) { 'saved' } else { 'no-dump-written' }
        files = $receipts
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Output 'guest-dumps.json') -Encoding utf8
    $receipts.Count
}

function Save-IntegrityFailure($Session, [string]$Name, [string]$Output) {
    $image = "S:\datalab\$Name.vhdx"
    $bytes = Invoke-Command -Session $Session -ArgumentList $image, $Name -ScriptBlock {
        param($path, $name)
        $files = @(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath "C:\n2r\datalab\$name" -Recurse -File -Force) +
            @(Get-ChildItem -LiteralPath 'S:\datalab\runs' -Recurse -File -Force -ErrorAction SilentlyContinue)
        ($files | Measure-Object Length -Sum).Sum
    }
    if ((Get-Volume -FilePath $Output).SizeRemaining -lt $bytes) { throw 'Insufficient private storage for the failed image and recovery records' }
    Invoke-Command -Session $Session -ArgumentList $image -ScriptBlock {
        param($path)
        $info = Get-DiskImage -ImagePath $path
        if ($info.Attached) { Dismount-DiskImage -ImagePath $path | Out-Null }
    }
    Copy-Item -FromSession $Session -LiteralPath $image -Destination (Join-Path $Output 'after.vhdx')
    Copy-Item -FromSession $Session -LiteralPath "C:\n2r\datalab\$Name" -Destination (Join-Path $Output 'guest') -Recurse
    $runs = Invoke-Command -Session $Session -ScriptBlock { Get-ChildItem -LiteralPath 'S:\datalab\runs' -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName }
    $destination = Join-Path $Output 'runs'
    $null = New-Item -ItemType Directory -Path $destination
    foreach ($run in $runs) { Copy-Item -FromSession $Session -LiteralPath $run -Destination $destination -Recurse }
}
