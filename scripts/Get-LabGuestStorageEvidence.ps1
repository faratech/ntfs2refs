[CmdletBinding(SupportsShouldProcess)]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess('ntfs2refs-win11', 'Boot owned guest, capture storage properties, cleanly shut down; restore baseline only if both data disks remain RAW and no experiment files exist')) { return }
$manifest = Read-LabManifest -Configuration $configuration -Lane win11
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Storage evidence starts with the owned VM off.' }
$baseline = Get-ExactLabCheckpoint -VM $vm -Name installed-clean
if ([string]$baseline.Id -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f') { throw 'Unexpected installed baseline.' }
$laneRoot = Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential = Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected lab credential identity.' }
$outputRoot = Assert-LabPath (Join-Path $laneRoot ('storage-evidence-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$session = $null
try {
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false | Out-Null
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    while (-not $session -and [DateTime]::UtcNow -lt $deadline) {
        $probe = $null
        try {
            $probe = Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock { $env:COMPUTERNAME }
            if (Wait-Job -Job $probe -Timeout 10) {
                $reply = @(Receive-Job -Job $probe -ErrorAction Stop)
                if ($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11') { $session = New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential }
            }
        } catch { } finally { if ($probe) { Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue } }
        if (-not $session) { Start-Sleep -Seconds 2 }
    }
    if (-not $session) { throw 'Guest storage probe could not authenticate before deadline.' }
    $evidence = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $computer = Get-CimInstance Win32_ComputerSystem
        $disks = @(Get-Disk | ForEach-Object {
            [pscustomobject]@{Number=$_.Number;UniqueId=[string]$_.UniqueId;SerialNumber=[string]$_.SerialNumber;BusType=[string]$_.BusType;BusTypeValue=$_.BusType;FriendlyName=[string]$_.FriendlyName;Size=$_.Size;Location=[string]$_.Location;PartitionStyle=[string]$_.PartitionStyle;IsBoot=$_.IsBoot;IsSystem=$_.IsSystem;IsOffline=$_.IsOffline;IsReadOnly=$_.IsReadOnly;LogicalSectorSize=$_.LogicalSectorSize;PhysicalSectorSize=$_.PhysicalSectorSize}
        })
        $experimentRoots = @('C:\ntfs2refs\control-ntfs','C:\ntfs2refs\control-refs')
        $roots = @(foreach ($path in $experimentRoots) {
            $exists = Test-Path -LiteralPath $path
            $files = @()
            if ($exists) {
                if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Experiment path is a reparse point.' }
                $files = @(Get-ChildItem -LiteralPath $path -Force | Select-Object -First 32 Name,Length,Attributes)
            }
            [pscustomobject]@{path=$path;exists=$exists;entries=$files}
        })
        [pscustomobject]@{computerName=$env:COMPUTERNAME;manufacturer=$computer.Manufacturer;model=$computer.Model;disks=$disks;scsiMapping=@(Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit);experimentRoots=$roots;capturedUtc=[DateTime]::UtcNow.ToString('o')}
    }
    $evidencePath = Join-Path $outputRoot 'storage.json'
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    $hash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest shutdown request failed.' } }
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session = $null
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    do { $vm = Get-VM -Id ([guid]$manifest.vmId); if ($vm.State -eq 'Off') { break }; Start-Sleep -Seconds 2 } while ([DateTime]::UtcNow -lt $deadline)
    if ($vm.State -ne 'Off') { throw 'Guest did not shut down cleanly; evidence retained without restore.' }
    $dataDisks = @($evidence.disks | Where-Object { -not $_.IsBoot -and -not $_.IsSystem })
    $emptyRoots = @($evidence.experimentRoots | Where-Object { @($_.entries).Count -ne 0 }).Count -eq 0
    $rawData = $dataDisks.Count -eq 2 -and @($dataDisks | Where-Object { $_.PartitionStyle -cne 'RAW' }).Count -eq 0 -and @($dataDisks | Where-Object Size -eq 64GB).Count -eq 1 -and @($dataDisks | Where-Object Size -eq 8GB).Count -eq 1
    $restored = $false
    if ($evidence.computerName -ceq 'N2R-WIN11' -and $rawData -and $emptyRoots -and (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash) {
        Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false | Out-Null
        $restored = $true
    }
    [pscustomobject]@{Evidence=$evidencePath;Sha256=$hash;VMState='Off';BaselineRestored=$restored}
} finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $credential = $null
}
