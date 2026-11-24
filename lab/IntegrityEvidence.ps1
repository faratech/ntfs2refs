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

function Invoke-IntegrityReboot($Session, [guid]$VmId, [pscredential]$Credential, [string]$Name) {
    $saved = Invoke-Command -Session $Session -ScriptBlock {
        $path = 'V:\qualification-across-reboot.txt'
        [IO.File]::WriteAllText($path, 'ntfs2refs acceptance across reboot')
        [pscustomobject]@{ boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; hash = (Get-FileHash -LiteralPath $path).Hash }
    }
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
            if ($boot -gt $saved.boot) { break }
            Remove-PSSession $next
            $next = $null
        }
    } while ((Get-Date) -lt $deadline)
    if (-not $next) { throw 'Acceptance guest did not restart' }
    Remove-PSSession $Session
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
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $start } -ErrorAction Stop |
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
