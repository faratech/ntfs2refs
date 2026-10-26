# Historical case-specific readiness recorder. Approval strings below are actor
# claims, not independent provenance; see lab/PRESERVATION.md's corrected timeline.
# No guest settings or disk writes.
param([switch]$ApprovedBootRetry)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace = Split-Path $PSScriptRoot -Parent
if ($workspace -ine 'D:\code\ntfs2refs') { throw 'Unexpected workspace.' }
$root = Join-Path $workspace '.lab\hyperv\isolated-reference-20261026-review'
$id = [guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
$protectedId = [guid]'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'
$manifest = Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json
if ([guid]$manifest.vm_id -ne $id -or $manifest.vm_name -cne 'ntfs2refs-reference-isolated') { throw 'Enrollment differs.' }
$vm = Get-VM -Id $id
if ($vm.Name -cne $manifest.vm_name -or $vm.Path -ine $manifest.vm_path -or [string]$vm.State -cne 'Off' `
    -or $vm.MemoryStartup -ne 8GB -or $vm.DynamicMemoryEnabled -or @($vm | Get-VMNetworkAdapter).Count) { throw 'VM identity/state/offline configuration differs; do not redispatch.' }
if (@($vm | Get-VMSnapshot).Count) { throw 'Unexpected isolated checkpoints.' }
if ($ApprovedBootRetry) {
    $ejection = Get-Content -LiteralPath (Join-Path $root 'approved-iso-ejection-retry.json') -Raw | ConvertFrom-Json
    $dvd = @($vm | Get-VMDvdDrive | Where-Object { $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 3 })
    if ([guid]$ejection.vm_id -ne $id -or $dvd.Count -ne 1 -or $dvd[0].Path) { throw 'Approved media ejection is not the current state.' }
    if (Test-Path -LiteralPath (Join-Path $root 'approved-boot-readiness-retry.json')) { throw 'The one approved retry was already dispatched; inspect its outcome.' }
}
$protected = Get-VM -Id $protectedId
$oldIds = @($protected | Get-VMSnapshot | Select-Object -ExpandProperty Id | ForEach-Object { [string]$_ })
if ($oldIds.Count -ne 50 -or $protected.ParentSnapshotId -ne [guid]'f6393f52-56ce-4847-bc24-7d5e019ac2e2') { throw 'Protected state differs.' }
$paths = @($vm | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path)
if ($paths.Count -ne 3) { throw 'Disk count differs.' }
foreach ($disk in $manifest.disks) {
    if ($disk.path -notin $paths -or -not $disk.path.StartsWith((Join-Path $root 'disks')+'\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Disk route differs.' }
    $cursor = Get-Item -LiteralPath $disk.path -Force
    while ($cursor) { if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse disk path.' }; $cursor = $cursor.Parent }
    $vhd = Get-VHD -Path $disk.path
    if ($vhd.ParentPath -or $vhd.Attached -or [string]$vhd.DiskIdentifier -ine $disk.vhd_id -or $vhd.FileSize -ne [int64]$disk.file_bytes) { throw 'Standalone disk identity/length differs.' }
    $fileId = @(fsutil file queryfileid $disk.path)
    if ($LASTEXITCODE -ne 0 -or ($fileId -join '') -cne ($disk.file_id_query -join '')) { throw 'Host disk file identity differs.' }
    $links = @(fsutil hardlink list $disk.path)
    if ($LASTEXITCODE -ne 0 -or $links.Count -ne 1) { throw 'Backing alias unresolved.' }
}
$security = Get-VMSecurity -VM $vm
$firmware = Get-VMFirmware -VM $vm
if (-not $security.TpmEnabled -or [string]$firmware.SecureBoot -cne 'On') { throw 'Enrolled security differs; no correction authorized.' }
$capacity = Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB
if ($capacity.FreeBytes -lt (64GB + 16GB + 8GB)) { throw 'Insufficient reserve, growth and startup backing margin.' }
$memoryBefore = [int64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
if ($memoryBefore -lt 12GB) { throw 'Insufficient startup RAM plus overhead.' }
$run = Join-Path $root ('readiness-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
[void](New-Item -ItemType Directory -Path $run)
function Save-Readiness($Name, $Value) { $Value | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $run $Name) -Encoding utf8 }
$ownerMode = if ($ApprovedBootRetry) { [IO.FileMode]::Open } else { [IO.FileMode]::CreateNew }
$owner = [IO.File]::Open((Join-Path $root 'readiness-owner.lock'), $ownerMode, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$session = $null
$existingCredential = $null
$phase = 'preflight'
try {
    Save-Readiness 'preflight.json' ([ordered]@{ vm_id=[string]$id; name=$vm.Name; vm_path=$vm.Path; state=[string]$vm.State;
        host_disks=$manifest.disks; original_checkpoint_ids=$oldIds; memory_startup_bytes=$vm.MemoryStartup; no_nic=$true;
        free_disk_before_bytes=$capacity.FreeBytes; free_memory_before_bytes=$memoryBefore; guest_experiments_authorized=$false;
        scope='Specific approved named-VM boot and read-only PowerShell Direct readiness using existing credentials';
        started_utc=[DateTime]::UtcNow.ToString('o'); controller_pid=$PID })
    Write-Output "Readiness record: $run"
    if ($ApprovedBootRetry) {
        @{ vm_id=[string]$id; human_approval='Approved, directly in this chat; previously approved media ejection and one normal boot/read-only login retry';
            run_path=$run; controller_pid=$PID; started_utc=[DateTime]::UtcNow.ToString('o') } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'approved-boot-readiness-retry.json') -Encoding utf8
    }
    $phase = 'normal-boot'
    Start-VM -VM $vm -ErrorAction Stop
    $phase = 'boot-heartbeat'
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        if ([int64](Get-Volume -DriveLetter D).SizeRemaining -lt 80GB) { throw 'Reserve/growth margin entered; no further readiness work.' }
        $vm = Get-VM -Id $id
        if (@($vm | Get-VMNetworkAdapter).Count) { throw 'Unexpected networking; no connection authorized.' }
        $heartbeat = $vm | Get-VMIntegrationService -Name Heartbeat
        if ([string]$vm.State -eq 'Running' -and $heartbeat.PrimaryStatusDescription -eq 'OK') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Normal boot heartbeat timeout; do not alter TPM, firmware or setup.' }
        Start-Sleep -Seconds 2
    } while ($true)
    Save-Readiness 'boot-running.json' @{ vm_id=[string]$id; state=[string]$vm.State; heartbeat=$heartbeat.PrimaryStatusDescription;
        integration=@($vm | Get-VMIntegrationService | Select-Object Name,Enabled,PrimaryStatusDescription);
        free_disk_bytes=(Get-Volume -DriveLetter D).SizeRemaining; captured_utc=[DateTime]::UtcNow.ToString('o') }
    $credentialPath = Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'
    $cursor = Get-Item -LiteralPath $credentialPath -Force
    while ($cursor) { if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Credential reparse path.' }; $cursor = $cursor.Parent }
    $phase = 'existing-credential-load'
    $existingCredential = Import-Clixml -LiteralPath $credentialPath
    if ($existingCredential -isnot [Management.Automation.PSCredential]) { throw 'Existing credential unsupported; no credential creation authorized.' }
    # Explicit VM GUID is the only endpoint. No network, policy changes, or fallback credentials.
    $phase = 'one-powershell-direct-login'
    $session = New-PSSession -VMId $id -Credential $existingCredential -ErrorAction Stop
    $phase = 'read-only-guest-observation'
    $guest = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $os = Get-CimInstance Win32_OperatingSystem
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $product = Get-CimInstance Win32_ComputerSystemProduct
        $driver = Get-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\refs.sys')
        [pscustomobject]@{
            computer_name=$env:COMPUTERNAME; os_caption=$os.Caption; os_version=$os.Version; build_number=$os.BuildNumber;
            ubr=$cv.UBR; display_version=$cv.DisplayVersion; edition_id=$cv.EditionID; last_boot_time=$os.LastBootUpTime;
            computer_uuid=$product.UUID; ps_version=[string]$PSVersionTable.PSVersion;
            elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
            disks=@(Get-Disk | Select-Object Number,FriendlyName,SerialNumber,UniqueId,Guid,Path,Location,Size,PartitionStyle,LogicalSectorSize,PhysicalSectorSize,IsBoot,IsSystem,IsOffline,IsReadOnly,OperationalStatus);
            disk_devices=@(Get-CimInstance Win32_DiskDrive | Select-Object Index,DeviceID,SerialNumber,Size,BytesPerSector,SCSIBus,SCSIPort,SCSITargetId,SCSILogicalUnit,PNPDeviceID);
            partitions=@(Get-Partition | Select-Object DiskNumber,PartitionNumber,Guid,Offset,Size,GptType,DriveLetter,IsBoot,IsSystem,IsReadOnly,AccessPaths);
            volumes=@(Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,UniqueId,Path,Size,SizeRemaining,AllocationUnitSize,DriveType,HealthStatus);
            # Serialize enums as strings: remoted enum wrappers otherwise emit
            # both `value` and `Value`, which case-insensitive JSON readers reject.
            integration_services=@(Get-Service vmicheartbeat,vmicvmsession,vmictimesync,vmicshutdown,vmicguestinterface -ErrorAction SilentlyContinue |
                ForEach-Object { [pscustomobject]@{ Name=$_.Name; Status=[string]$_.Status; StartType=[string]$_.StartType } });
            refs_driver_version=$driver.VersionInfo.FileVersion; refs_driver_bytes=$driver.Length;
            refs_driver_sha256=(Get-FileHash -LiteralPath $driver.FullName -Algorithm SHA256).Hash.ToLowerInvariant();
            captured_utc=[DateTime]::UtcNow.ToString('o')
        }
    }
    Save-Readiness 'guest-observation.json' $guest
    if ($guest.computer_name -cne 'N2R-WIN11' -or $guest.build_number -ne '26300' -or -not $guest.elevated -or $guest.disks.Count -ne 3) {
        throw 'Observed guest differs from archived readiness profile; no remediation authorized.'
    }
    $vm = Get-VM -Id $id
    $protected = Get-VM -Id $protectedId
    $nowIds = @($protected | Get-VMSnapshot | Select-Object -ExpandProperty Id | ForEach-Object { [string]$_ })
    if (@(Compare-Object ($oldIds | Sort-Object) ($nowIds | Sort-Object)).Count -or $protected.ParentSnapshotId -ne [guid]'f6393f52-56ce-4847-bc24-7d5e019ac2e2') { throw 'Protected state changed.' }
    if (@($vm | Get-VMNetworkAdapter).Count -or (Get-VMSecurity -VM $vm).TpmEnabled -ne $security.TpmEnabled `
        -or [string](Get-VMFirmware -VM $vm).SecureBoot -cne [string]$firmware.SecureBoot) { throw 'Host isolation/security changed.' }
    $afterCapacity = Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
    Assert-LabCapacity -Capacity $afterCapacity
    if ($afterCapacity.FreeBytes -lt 80GB) { throw 'Post-boot reserve/growth margin insufficient.' }
    Save-Readiness 'binding-manifest.json' ([ordered]@{ schema_version=1; kind='isolated-read-only-guest-readiness'; status='ready';
        vm_id=[string]$id; vm_name=$vm.Name; vm_path=$vm.Path; state=[string]$vm.State; endpoint_transport='PowerShell Direct by explicit VM GUID';
        memory_startup_bytes=$vm.MemoryStartup; memory_assigned_bytes=$vm.MemoryAssigned; memory_demand_bytes=$vm.MemoryDemand;
        host_free_memory_before_bytes=$memoryBefore; host_free_memory_after_bytes=([int64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024);
        host_free_disk_before_bytes=$capacity.FreeBytes; host_free_disk_after_bytes=$afterCapacity.FreeBytes;
        minimum_host_free_reserve_bytes=[int64]68719476736; growth_allowance_bytes=[int64]17179869184;
        no_nic=$true; tpm_settings_preserved=$true; secure_boot_settings_preserved=$true; existing_credential_used=$true;
        credential_contents_recorded=$false; credential_changes_performed=$false; guest_queries_read_only=$true;
        raw_writes_or_experiments_performed=$false; original_checkpoint_ids_unchanged=$true; original_checkpoint_count=$nowIds.Count;
        host_disk_bindings_at_provision=$manifest.disks; guest=$guest; binding_grants_write_authority=$false;
        completed_utc=[DateTime]::UtcNow.ToString('o') })
    Write-Output "Guest readiness passed; binding manifest: $(Join-Path $run 'binding-manifest.json')"
} catch {
    Save-Readiness 'failure.json' @{ error=$_.Exception.Message; phase=$phase; existing_credential_loaded=($null -ne $existingCredential);
        guest_session_opened=($null -ne $session); vm_id=[string]$id; vm_state=[string](Get-VM -Id $id).State;
        credential_reset_authorized=$false; policy_or_security_changes_authorized=$false; captured_utc=[DateTime]::UtcNow.ToString('o') }
    throw
} finally {
    if ($session) { Remove-PSSession -Session $session }
    $existingCredential = $null
    $owner.Dispose()
}
