# Case-specific provisioning only. Requires Mike's separately recorded approval.
# No boot, credentials, networking, key-protector changes, or cleanup operations.
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace = Split-Path $PSScriptRoot -Parent
if ($workspace -ine 'D:\code\ntfs2refs') { throw 'Unexpected workspace.' }
$run = Join-Path $workspace '.lab\hyperv\reference-isolation-approved-20261026T130646790Z'
$destination = Join-Path $workspace '.lab\hyperv\isolated-reference-20261026-review'
$archive = 'C:\Users\mfara\ntfs2refs-archive\exports\win11-installed-clean\ntfs2refs-win11'
$name = 'ntfs2refs-reference-isolated'
$protectedId = [guid]'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'
$expectedCheckpoint = [guid]'f6393f52-56ce-4847-bc24-7d5e019ac2e2'
$reserve = [int64]68719476736
$growth = [int64]17179869184
function Save-Record($Name, $Value) {
    $path = Join-Path $run $Name
    if (Test-Path -LiteralPath $path) { throw "Record already exists: $Name; inspect before retry." }
    $Value | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $path -Encoding utf8
}
function Assert-Capacity([int64]$Additional = 0) {
    $capacity = Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes $Additional
    if ($capacity.FreeBytes -lt ($reserve + $growth)) { throw 'Reserve plus growth allowance would be breached.' }
    $capacity
}
function Assert-Protected {
    $original = Get-VM -Id $protectedId
    if ($original.ParentSnapshotId -ne $expectedCheckpoint -or @($original | Get-VMSnapshot).Count -ne 50) {
        throw 'Protected VM/checkpoints differ; no further action.'
    }
}
Assert-Protected
if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw 'Named VM already exists.' }
if (Test-Path -LiteralPath (Join-Path $run 'stage2-import-intent.json')) { throw 'Import intent already exists; inspect outcome, never retry blindly.' }
if (@(Get-ChildItem -LiteralPath $destination -File -Recurse -Force).Count) { throw 'Destination contains files.' }
$capacity = Assert-Capacity ([int64]18035647136 + $growth)
if ([int64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024 -lt 12GB) { throw 'Insufficient RAM for 8GiB plus overhead.' }
$approved = Get-Content -LiteralPath (Join-Path $run 'authorization-and-start.json') -Raw | ConvertFrom-Json
if ($approved.vm_name -cne $name -or $approved.vm_destination -cne $destination -or -not $approved.licensing_confirmed_by_user) {
    throw 'Recorded case scope differs; the operator still needs actual user authorization.'
}
$archiveRecord = Get-Content -LiteralPath (Join-Path $run 'stage2-archive-verification.json') -Raw | ConvertFrom-Json
$handles = @()
$owner = [IO.File]::Open((Join-Path $run 'stage2-controller.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    foreach ($row in $archiveRecord.files) {
        $item = Get-Item -LiteralPath $row.path -Force
        $expected = if ($row.modified_utc -is [DateTime]) { $row.modified_utc } else {
            [DateTime]::Parse([string]$row.modified_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        }
        $cursor = $item
        while ($cursor) {
            if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Archive reparse component.' }
            $cursor = $cursor.Parent
        }
        if ($item.Length -ne [int64]$row.length -or $item.LastWriteTimeUtc.Ticks -ne $expected.ToUniversalTime().Ticks) { throw 'Archive metadata changed.' }
        $handle = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $handles += $handle
        $hash = (Get-FileHash -InputStream $handle -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $row.sha256 -or $handle.Length -ne $item.Length) { throw 'Archive hash differs under held read-only handle.' }
    }
    $plan = Compare-VM -Path (Join-Path $archive 'Virtual Machines\EDA059B3-6D50-46BB-BDF4-018B99B5B34F.vmcx') `
        -Copy -GenerateNewId -VirtualMachinePath (Join-Path $destination 'vm') `
        -VhdDestinationPath (Join-Path $destination 'disks') -VhdSourcePath (Join-Path $archive 'Virtual Hard Disks') `
        -SnapshotFilePath (Join-Path $destination 'checkpoints') -SmartPagingFilePath (Join-Path $destination 'paging')
    if ($plan.Incompatibilities.Count) { throw 'Import requires compatibility changes outside scope.' }
    $newId = [guid]$plan.VM.Id
    if ($newId -in @([guid]::Empty, $protectedId, [guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f')) { throw 'Fresh VM ID not established.' }
    if (@($plan.VM | Get-VMNetworkAdapter | Where-Object SwitchName).Count) { throw 'Archive has connected networking.' }
    $security = Get-VMSecurity -VM $plan.VM
    $firmware = Get-VMFirmware -VM $plan.VM
    Save-Record 'stage2-import-intent.json' ([ordered]@{ new_vm_id=[string]$newId; name=$name; destination=$destination;
        source_tpm_enabled=$security.TpmEnabled; source_secure_boot=[string]$firmware.SecureBoot;
        source_secure_boot_template=[string]$firmware.SecureBootTemplate; free_before_bytes=$capacity.FreeBytes;
        source_files_held_read_only=$handles.Count; controller_pid=$PID; started_utc=[DateTime]::UtcNow.ToString('o') })
    $job = Import-VM -CompatibilityReport $plan -AsJob
    Save-Record 'stage2-import-job.json' @{ job_id=$job.Id; instance_id=[string]$job.InstanceId; new_vm_id=[string]$newId; controller_pid=$PID }
    Write-Output "Import started: $newId; job $($job.Id)"
    while ($job.State -in @('NotStarted','Running')) {
        if ([int64](Get-Volume -DriveLetter D).SizeRemaining -lt ($reserve + $growth)) {
            Stop-Job -Job $job
            throw 'Import stopped at reserve plus growth threshold; preserve all partial state.'
        }
        [void](Wait-Job -Job $job -Timeout 2)
    }
    if ($job.State -ne 'Completed') { throw "Import $($job.State); inspect without retry or cleanup." }
    $output = @(Receive-Job -Job $job -ErrorAction Stop)
    $vm = Get-VM -Id $newId
    if (-not $vm.Path.StartsWith($destination+'\', [StringComparison]::OrdinalIgnoreCase) -or [string]$vm.State -cne 'Off') {
        throw 'New VM path/state differs.'
    }
    Rename-VM -VM $vm -NewName $name
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 8GB
    foreach ($nic in @($vm | Get-VMNetworkAdapter)) { Remove-VMNetworkAdapter -VMNetworkAdapter $nic -Confirm:$false }
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false
    $vm = Get-VM -Id $newId
    $afterSecurity = Get-VMSecurity -VM $vm
    $afterFirmware = Get-VMFirmware -VM $vm
    if ($afterSecurity.TpmEnabled -ne $security.TpmEnabled -or [string]$afterFirmware.SecureBoot -cne [string]$firmware.SecureBoot `
        -or $afterFirmware.SecureBootTemplate -cne $firmware.SecureBootTemplate) { throw 'Security mismatch; no correction authorized.' }
    if ($vm.MemoryStartup -ne 8GB -or $vm.DynamicMemoryEnabled -or @($vm | Get-VMNetworkAdapter).Count -or [string]$vm.State -cne 'Off') {
        throw 'Approved offline configuration not established.'
    }
    $disks = @()
    foreach ($drive in @($vm | Get-VMHardDiskDrive)) {
        $path = [IO.Path]::GetFullPath($drive.Path)
        if (-not $path.StartsWith((Join-Path $destination 'disks')+'\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Disk escaped independent destination.' }
        $info = Get-VHD -Path $path
        if ($info.ParentPath -or $info.Attached) { throw 'Destination is not detached standalone storage.' }
        $row = @($archiveRecord.files | Where-Object { [IO.Path]::GetFileName($_.path) -ceq [IO.Path]::GetFileName($path) })
        if ($row.Count -ne 1) { throw 'No exact source pin for destination disk.' }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $row[0].sha256 -or (Get-Item -LiteralPath $path).Length -ne [int64]$row[0].length) { throw 'Destination copy does not match source pin; leave VM off.' }
        $fileId = @(fsutil file queryfileid $path)
        if ($LASTEXITCODE -ne 0) { throw 'Destination file identity unsupported.' }
        $links = @(fsutil hardlink list $path)
        if ($LASTEXITCODE -ne 0 -or $links.Count -ne 1) { throw 'Destination has unresolved backing-file aliases.' }
        $disks += [pscustomobject]@{ path=$path; controller_number=$drive.ControllerNumber; controller_location=$drive.ControllerLocation;
            vhd_id=[string]$info.DiskIdentifier; vhd_type=[string]$info.VhdType; parent_path=[string]$info.ParentPath;
            virtual_bytes=$info.Size; file_bytes=$info.FileSize; sha256=$hash; file_id_query=$fileId; hard_links=$links }
    }
    if ($disks.Count -ne 3) { throw 'Expected exactly OS, target and journal disks.' }
    foreach ($handle in $handles) { if (-not $handle.CanRead -or $handle.CanWrite) { throw 'Archive lease differs.' } }
    Assert-Protected
    $afterCapacity = Assert-Capacity
    Save-Record 'stage2-import-result.json' ([ordered]@{ schema_version=1; phase='verified-provisioned-offline'; vm_id=[string]$vm.Id;
        vm_name=$vm.Name; vm_path=$vm.Path; generation=$vm.Generation; state=[string]$vm.State;
        memory_startup_bytes=$vm.MemoryStartup; dynamic_memory_enabled=$vm.DynamicMemoryEnabled; processor_count=$vm.ProcessorCount;
        network_adapter_count=@($vm | Get-VMNetworkAdapter).Count; automatic_checkpoints_enabled=$vm.AutomaticCheckpointsEnabled;
        checkpoint_count=@($vm | Get-VMSnapshot).Count; tpm_enabled=$afterSecurity.TpmEnabled; secure_boot=[string]$afterFirmware.SecureBoot;
        secure_boot_template=[string]$afterFirmware.SecureBootTemplate; security_settings_changed=$false;
        credential_actions_performed=$false; guest_boot_attempted=$false; source_images_match_destination=$true;
        disk_identifiers_preserved_from_archive=$true; new_host_file_identities_recorded=$true; disks=$disks;
        free_after_bytes=$afterCapacity.FreeBytes; completed_utc=[DateTime]::UtcNow.ToString('o') })
    Get-Content -LiteralPath (Join-Path $run 'stage2-import-result.json') -Raw
} catch {
    $failurePath = Join-Path $run ('stage2-failure-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
    @{ error=$_.Exception.Message; controller_pid=$PID; time_utc=[DateTime]::UtcNow.ToString('o'); retry_authorized=$false } |
        ConvertTo-Json | Set-Content -LiteralPath $failurePath -Encoding utf8
    throw
} finally {
    foreach ($handle in $handles) { $handle.Dispose() }
    $owner.Dispose()
}
