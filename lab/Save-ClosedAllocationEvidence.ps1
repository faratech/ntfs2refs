# Archive closed allocation-run evidence without duplicating its bulk payloads.
# This observes a completed task. It never executes recovery or changes a VM,
# disk, checkpoint, source artifact or protection state.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\AN2R-[A-Za-z0-9_-]+\z')][string]$TaskName,
    [Parameter(Mandatory)][uint32]$ExpectedTaskResult,
    [Parameter(Mandatory)][hashtable]$GuestRoots,
    [Parameter(Mandatory)][string]$Destination
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$vmId = [guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$base = 'D:\code\ntfs2refs\.lab\hyperv\streaming-v2-20261027'
$credentialPath = 'D:\code\ntfs2refs\.lab\hyperv\win11\secrets\guest-credential.xml'
$session = $null
$created = $false
$copied = [Collections.Generic.List[object]]::new()
$before = $null
$inventory = $null

function Need([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Ordinary-HostAncestors([string]$Path) {
    $at = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($at)) {
        if (Test-Path -LiteralPath $at) {
            $item = Get-Item -LiteralPath $at -Force
            Need (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Host archive ancestry contains a reparse point.'
            Need ($item -is [IO.DirectoryInfo]) 'Host archive ancestry must be directories.'
        }
        $at = [IO.Path]::GetDirectoryName($at)
    }
}

function Save-NewJson([string]$Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 20))
    Need ($bytes.Length -le 64MB) 'Archive metadata exceeds 64 MiB.'
    $path = Join-Path $script:destinationPath $Name
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
    finally { $file.Dispose() }
    (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$guard = {
    param([string]$Name, [uint32]$Expected)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -cne 'N2R-WIN11') { throw 'The fixed owning guest is required.' }
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction Stop)
    if ($tasks.Count -ne 1 -or $tasks[0].State.ToString() -cne 'Ready') { throw 'The exact completed task must be Ready.' }
    $task = $tasks[0]
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    $result = [uint32]([int64]$info.LastTaskResult -band 4294967295L)
    if ($result -ne $Expected -or $info.LastRunTime.Year -lt 2000) { throw 'The actual completed task result differs.' }
    $activeTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready', 'Disabled')
    })
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'
    })
    if ($activeTasks.Count -ne 0 -or $processes.Count -ne 0) { throw 'A project task or executable remains active.' }
    [pscustomobject]@{
        computer = $env:COMPUTERNAME; task_name = $task.TaskName; task_path = $task.TaskPath
        task_state = $task.State.ToString(); task_result = $result
        last_run_utc = $info.LastRunTime.ToUniversalTime().ToString('o')
        active_project_tasks = 0; active_project_executables = 0; utc = [DateTime]::UtcNow.ToString('o')
    }
}

try {
    $destinationPath = [IO.Path]::GetFullPath($Destination.TrimEnd('\'))
    Need ($destinationPath.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) 'Destination must be below the exact allocation lab directory.'
    Need (-not (Test-Path -LiteralPath $destinationPath)) 'Archive destination must be new.'
    Ordinary-HostAncestors ([IO.Path]::GetDirectoryName($destinationPath))
    Need ($GuestRoots.Count -gt 0 -and $GuestRoots.Count -le 4096) 'One or more bounded guest roots are required.'
    $roots = [Collections.Generic.List[object]]::new()
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in @($GuestRoots.Keys | Sort-Object)) {
        Need ($role -is [string] -and $role -cmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z' -and $roles.Add($role)) 'Archive roles must be unique ordinary leaf names.'
        Need ($GuestRoots[$role] -is [string]) 'Each guest root must be an absolute path string.'
        $path = [string]$GuestRoots[$role]
        Need ($path -match '\AC:\\' -and $path.Substring(2).IndexOf(':') -lt 0 -and $path -notmatch '[\x00-\x1f]') 'Guest roots must use the ordinary C drive namespace.'
        $parts = $path.Substring(3).Split('\')
        Need (@($parts | Where-Object { $_ -in @('.', '..') }).Count -eq 0) 'Guest root traversal is not allowed.'
        $path = [IO.Path]::GetFullPath($path.TrimEnd('\'))
        Need ($path.StartsWith('C:\ntfs2refs\', [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith('C:\ProgramData\ntfs2refs\runs\', [StringComparison]::OrdinalIgnoreCase)) 'Guest root is outside the permitted evidence directories.'
        $roots.Add([pscustomobject]@{ role = $role; path = $path })
    }
    New-Item -ItemType Directory -Path $destinationPath -ErrorAction Stop | Out-Null
    $created = $true
    $session = New-PSSession -VMId $vmId -Credential (Import-Clixml -LiteralPath $credentialPath) -ErrorAction Stop
    $before = Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $TaskName, $ExpectedTaskResult
    $rootJson = $roots.ToArray() | ConvertTo-Json -Depth 4 -Compress
    $inventory = Invoke-Command -Session $session -ArgumentList $rootJson -ScriptBlock {
        param([string]$RootsJson)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $roots = @($RootsJson | ConvertFrom-Json | ForEach-Object { $_ })
        $entries = [Collections.Generic.List[object]]::new()
        $bulkExtensions = @('.bin', '.vhd', '.vhdx', '.avhd', '.avhdx', '.journal', '.raw', '.img', '.iso', '.vmdk', '.qcow', '.qcow2')
        $copiedBytes = 0L
        foreach ($root in $roots) {
            $rootPath = [IO.Path]::GetFullPath([string]$root.path)
            if (-not ($rootPath.StartsWith('C:\ntfs2refs\', [StringComparison]::OrdinalIgnoreCase) -or $rootPath.StartsWith('C:\ProgramData\ntfs2refs\runs\', [StringComparison]::OrdinalIgnoreCase))) { throw 'Guest evidence root escaped its namespace.' }
            $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
            if (-not ($rootItem -is [IO.DirectoryInfo])) { throw 'Guest evidence roots must be directories.' }
            $ancestor = $rootItem
            while ($null -ne $ancestor) {
                if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest evidence root ancestry contains a reparse point.' }
                $ancestor = $ancestor.Parent
            }
            $pending = [Collections.Generic.Stack[object]]::new()
            $pending.Push($rootItem)
            while ($pending.Count -ne 0) {
                $item = $pending.Pop()
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest evidence contains a reparse point.' }
                $path = [IO.Path]::GetFullPath($item.FullName)
                if (-not ($path.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'Guest evidence entry escaped its root.' }
                if ($entries.Count -ge 4096) { throw 'Guest evidence inventory exceeds 4096 entries.' }
                $relative = $path.Substring($rootPath.Length).TrimStart('\')
                if ($item -is [IO.DirectoryInfo]) {
                    $entries.Add([pscustomobject]@{ role = [string]$root.role; path = $path; relative_path = $relative; kind = 'directory'; bytes = 0L; sha256 = $null; disposition = 'copy-directory'; last_write_utc = $item.LastWriteTimeUtc.ToString('o') })
                    foreach ($child in $item.EnumerateFileSystemInfos()) {
                        if ($entries.Count + $pending.Count -ge 4096) { throw 'Guest evidence discovery exceeds 4096 entries.' }
                        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest evidence contains a reparse point.' }
                        $pending.Push($child)
                    }
                    continue
                }
                $bulk = [IO.Path]::GetExtension($path).ToLowerInvariant() -in $bulkExtensions
                if (-not $bulk -and $item.Length -gt 64MB) { throw ('Nonbulk evidence exceeds 64 MiB: ' + $path) }
                $digest = $null
                if (-not $bulk) {
                    $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    $afterHash = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($afterHash.Length -ne $item.Length -or $afterHash.LastWriteTimeUtc -ne $item.LastWriteTimeUtc -or ($afterHash.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest evidence changed while hashing.' }
                    $copiedBytes += $item.Length
                }
                $entries.Add([pscustomobject]@{
                    role = [string]$root.role; path = $path; relative_path = $relative; kind = 'file'
                    bytes = [long]$item.Length; sha256 = $digest; last_write_utc = $item.LastWriteTimeUtc.ToString('o')
                    disposition = $(if ($bulk) { 'retained-original-bulk' } else { 'copy-file' })
                    payload_opened = (-not $bulk)
                })
            }
        }
        [pscustomobject]@{ schema_version = 1; roots = $roots; entries = $entries.ToArray(); entry_count = $entries.Count; copy_bytes = $copiedBytes; utc = [DateTime]::UtcNow.ToString('o') }
    }
    Need ($inventory.entry_count -le 4096 -and @($inventory.entries).Count -eq $inventory.entry_count) 'Guest inventory entry count differs.'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration = Get-LabConfiguration -WorkspaceRoot 'D:\code\ntfs2refs'
    $capacity = Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed lab capacity epoch differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes ([long]$inventory.copy_bytes + 64MB)
    $inventoryPin = Save-NewJson 'inventory.json' $inventory
    foreach ($entry in $inventory.entries) {
        $rolePath = Join-Path $destinationPath $entry.role
        $path = if ([string]::IsNullOrEmpty($entry.relative_path)) { $rolePath } else { Join-Path $rolePath $entry.relative_path }
        $path = [IO.Path]::GetFullPath($path)
        Need ($path.StartsWith($destinationPath + '\', [StringComparison]::OrdinalIgnoreCase) -and ($path.Equals($rolePath, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($rolePath + '\', [StringComparison]::OrdinalIgnoreCase))) 'Archive entry escaped its role directory.'
        if ($entry.disposition -eq 'retained-original-bulk') { continue }
        if ($entry.kind -eq 'directory') {
            Ordinary-HostAncestors $path
            if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -ErrorAction Stop | Out-Null }
            continue
        }
        Need ($entry.disposition -eq 'copy-file' -and $entry.bytes -le 64MB -and $entry.sha256 -cmatch '\A[0-9a-f]{64}\z') 'Invalid copied-file manifest entry.'
        $parent = [IO.Path]::GetDirectoryName($path)
        Ordinary-HostAncestors $parent
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null }
        Need (-not (Test-Path -LiteralPath $path)) 'Archive file already exists.'
        Copy-Item -LiteralPath $entry.path -FromSession $session -Destination $path -ErrorAction Stop
        $saved = Get-Item -LiteralPath $path -Force
        Need ($saved -is [IO.FileInfo] -and -not ($saved.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $saved.Length -eq $entry.bytes) 'Copied evidence file type or length differs.'
        $pin = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Need ($pin -ceq $entry.sha256) 'Copied evidence file SHA-256 differs.'
        $copied.Add([pscustomobject]@{ role = $entry.role; relative_path = $entry.relative_path; source = $entry.path; destination = $path; bytes = [long]$saved.Length; sha256 = $pin })
    }
    # Recheck source metadata for all entries, including bulk originals, without
    # opening those bulk payloads. Rehash copied metadata only.
    $entryJson = $inventory.entries | ConvertTo-Json -Depth 6 -Compress
    $checked = Invoke-Command -Session $session -ArgumentList $entryJson -ScriptBlock {
        param([string]$EntriesJson)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $entries = @($EntriesJson | ConvertFrom-Json | ForEach-Object { $_ })
        $expectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) {
            if (-not $expectedPaths.Add([string]$entry.role + [char]0 + [string]$entry.path)) { throw 'Duplicate guest inventory path.' }
        }
        $count = 0
        foreach ($entry in $entries) {
            $item = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest evidence became a reparse point.' }
            if ($entry.kind -eq 'directory') {
                if (-not ($item -is [IO.DirectoryInfo])) { throw 'Guest evidence directory changed type.' }
            } else {
                if (($item -is [IO.DirectoryInfo]) -or $item.Length -ne $entry.bytes -or $item.LastWriteTimeUtc.ToString('o') -cne $entry.last_write_utc) { throw 'Guest evidence file changed after inventory.' }
                if ($entry.disposition -eq 'copy-file' -and (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Guest metadata changed during archive.' }
            }
            $count++
        }
        $discovered = 0
        foreach ($root in @($entries | Where-Object { $_.kind -eq 'directory' -and [string]::IsNullOrEmpty($_.relative_path) })) {
            $pending = [Collections.Generic.Stack[object]]::new()
            $pending.Push((Get-Item -LiteralPath $root.path -Force -ErrorAction Stop))
            while ($pending.Count -ne 0) {
                $item = $pending.Pop()
                $discovered++
                if ($discovered -gt 4096 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $expectedPaths.Contains([string]$root.role + [char]0 + [string]$item.FullName)) { throw 'Guest evidence directory contents changed during archive.' }
                if ($item -is [IO.DirectoryInfo]) {
                    foreach ($child in $item.EnumerateFileSystemInfos()) {
                        if ($discovered + $pending.Count -ge 4096) { throw 'Guest evidence directory contents exceed the bound.' }
                        $pending.Push($child)
                    }
                }
            }
        }
        if ($discovered -ne $count) { throw 'Guest evidence entry set differs from the inventory.' }
        [pscustomobject]@{ checked_entries = $count; complete_entry_set_rechecked = $true; bulk_payloads_opened = $false; utc = [DateTime]::UtcNow.ToString('o') }
    }
    Need ($checked.checked_entries -eq $inventory.entry_count) 'Guest archive completion count differs.'
    $after = Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $TaskName, $ExpectedTaskResult
    Need ($after.task_path -ceq $before.task_path -and $after.last_run_utc -ceq $before.last_run_utc) 'The completed task ran again during archiving.'
    $retained = @($inventory.entries | Where-Object disposition -eq 'retained-original-bulk')
    $receipt = [ordered]@{
        schema_version = 1; kind = 'closed-allocation-evidence-archive'; success = $true
        vm_id = $vmId.ToString('D'); task_name = $TaskName; expected_task_result = $ExpectedTaskResult
        destination = $destinationPath; inventory_sha256 = $inventoryPin
        admitted_capacity = $capacity; metadata_copy_forecast_bytes = ([long]$inventory.copy_bytes + 64MB)
        before = $before; after = $after; source_completion = $checked
        copied = $copied.ToArray(); retained_original_bulk = $retained
        source_files_deleted = $false; bulk_payloads_copied = $false; bulk_payloads_hashed = $false
        task_state_and_hashes_are_observations_not_authority = $true
        source_or_recovery_authority_granted = $false; utc = [DateTime]::UtcNow.ToString('o')
    }
    $receiptPin = Save-NewJson 'receipt.json' $receipt
    [pscustomobject]@{ success = $true; destination = $destinationPath; copied_files = $copied.Count; copied_bytes = $inventory.copy_bytes; retained_bulk_files = $retained.Count; receipt_sha256 = $receiptPin }
} catch {
    $failureRecord = $_
    $failure = $_.Exception.ToString()
    $failureObservation = $null
    if ($null -ne $session) {
        try { $failureObservation = Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $TaskName, $ExpectedTaskResult }
        catch { $failureObservation = [pscustomobject]@{ task_completion_recheck_failed = $true; error = $_.Exception.ToString() } }
    }
    if ($created) {
        try {
            $null = Save-NewJson 'archive-failed.json' ([ordered]@{
                schema_version = 1; kind = 'closed-allocation-evidence-archive-failure'; success = $false
                vm_id = $vmId.ToString('D'); task_name = $TaskName; expected_task_result = $ExpectedTaskResult
                destination = $destinationPath; before = $before; after_failure = $failureObservation; copied = $copied.ToArray()
                error = $failure; partial_archive_retained = $true
                retry_attempted = $false; source_files_deleted = $false; vm_or_disk_state_changed = $false
                source_or_recovery_authority_granted = $false; utc = [DateTime]::UtcNow.ToString('o')
            })
        } catch { Write-Warning 'The partial archive remains, but its failure receipt could not be saved.' }
    }
    throw $failureRecord
} finally {
    if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
