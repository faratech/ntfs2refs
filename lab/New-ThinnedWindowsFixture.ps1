<#
.SYNOPSIS
  Build the small real-Windows fixture checkpoint used for fast full-route runs.

.DESCRIPTION
  Restores the baseline checkpoint, boots the control OS, thins the original
  Windows volume on disk0 to roughly one object in -KeepOneIn (see
  guest\Thin-WindowsSource.ps1), shuts down cleanly and saves the result as a
  checkpoint named -FixtureCheckpoint. Invoke-BootConversionAttempt.ps1 -Fixture
  then starts from that checkpoint. The baseline itself is never changed.
#>
[CmdletBinding()]
param(
    [string]$Checkpoint = 'N2R-Qualification-NTFS-*',
    [string]$FixtureCheckpoint = 'N2R-Thinned-Fixture',
    [int]$KeepOneIn = 10,
    [int]$TimeoutMinutes = 120
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$vmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
function Say([string]$Text) { Write-Host ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text) }
$saved = Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$credential = [pscredential]::new('LabAdmin', $saved.Password)
function Connect([int]$Minutes) {
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        try { $s = New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop; $null = Invoke-Command -Session $s -ScriptBlock { 1 } -ErrorAction Stop; return $s }
        catch { Start-Sleep -Seconds 10 }
    }
    throw 'Control OS did not accept a PowerShell Direct session'
}

$vm = Get-VM -Id $vmId
$base = @(Get-VMSnapshot -VM $vm | Where-Object Name -Like $Checkpoint)
if ($base.Count -ne 1) { throw "Expected exactly one baseline checkpoint matching '$Checkpoint', found $($base.Count)" }
Get-VMSnapshot -VM $vm | Where-Object Name -EQ $FixtureCheckpoint | ForEach-Object { Say "removing previous '$FixtureCheckpoint' checkpoint"; Remove-VMSnapshot -VMSnapshot $_ -Confirm:$false }
while ((Get-VM -Id $vmId).Status -match 'Merg') { Start-Sleep -Seconds 5 }
Say "restoring baseline '$($base[0].Name)'"
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
Restore-VMSnapshot -VMSnapshot $base[0] -Confirm:$false
$vm = Get-VM -Id $vmId
if ($vm.State -eq 'Saved') { Remove-VMSavedState -VM $vm }
Start-VM -VM (Get-VM -Id $vmId)
$session = Connect 15

$source = Invoke-Command -Session $session -ScriptBlock {
    $system = Get-Partition -DriveLetter $env:SystemDrive[0]
    $p = Get-Partition | Where-Object { $_.DriveLetter -and $_.DiskNumber -ne $system.DiskNumber } |
        Where-Object { (Get-Volume -Partition $_).FileSystem -eq 'NTFS' } | Sort-Object Size -Descending | Select-Object -First 1
    if (-not $p -or -not (Test-Path "$($p.DriveLetter):\Windows\System32\config\SYSTEM")) { throw 'Offline Windows source volume not found' }
    $v = Get-Volume -Partition $p
    [pscustomobject]@{ letter = [string]$p.DriveLetter; disk = $p.DiskNumber; partition = $p.PartitionNumber; used = $v.Size - $v.SizeRemaining }
}
Say ("thinning {0}: (disk {1} partition {2}, {3:N1} GB used), keeping 1 in {4}" -f $source.letter, $source.disk, $source.partition, ($source.used / 1GB), $KeepOneIn)
$guestRoot = 'C:\n2r\thin'
Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock { param($root) $null = New-Item -ItemType Directory -Path $root -Force; Remove-Item "$root\result.json" -ErrorAction SilentlyContinue }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest\Thin-WindowsSource.ps1') -Destination "$guestRoot\thin.ps1" -ToSession $session
Invoke-Command -Session $session -ArgumentList $guestRoot, $source.letter, $KeepOneIn -ScriptBlock {
    param($root, $letter, $keep)
    Unregister-ScheduledTask -TaskName 'N2R-Thin' -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& '$root\thin.ps1' -Drive $letter -KeepOneIn $keep -ResultPath '$root\result.json' 2> '$root\error.txt'`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    $null = Register-ScheduledTask -TaskName 'N2R-Thin' -Action $action -Principal $principal -Settings $settings
    Start-ScheduledTask -TaskName 'N2R-Thin'
}
$deadline = (Get-Date).AddMinutes($TimeoutMinutes); $result = $null; $polls = 0
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 20; $polls++
    $state = Invoke-Command -Session $session -ArgumentList $guestRoot, $source.letter -ScriptBlock {
        param($root, $letter)
        $v = Get-Volume -DriveLetter $letter
        [pscustomobject]@{ task = (Get-ScheduledTask -TaskName 'N2R-Thin').State.ToString(); used = $v.Size - $v.SizeRemaining
            result = if (Test-Path "$root\result.json") { Get-Content "$root\result.json" -Raw } else { $null }
            error = if (Test-Path "$root\error.txt") { Get-Content "$root\error.txt" -Raw } else { $null } }
    }
    if ($polls % 6 -eq 0) { Say ("thinning: {0:N1} GB still used" -f ($state.used / 1GB)) }
    if ($state.result) { $result = $state.result | ConvertFrom-Json; break }
    if ($state.task -ne 'Running' -and $polls -gt 2) { throw "Thinning task stopped without a result. $($state.error)" }
}
if (-not $result) { throw 'Thinning timed out' }
if ($result.error) { throw "Thinning failed: $($result.error)" }
Say ("thinned in {0:N0} s: {1} files seen, {2} deleted, {3} kept by sample, {4} refused; {5} directories removed; {6:N1} GB used now" -f `
    $result.seconds, $result.files_seen, $result.files_deleted, $result.files_kept, $result.files_refused, $result.directories_deleted, ($result.volume_used_bytes_after / 1GB))
$case = Join-Path $workspace '.lab\hyperv\attempts'; $null = New-Item -ItemType Directory -Path $case -Force
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $case "fixture-$FixtureCheckpoint.json") -Encoding UTF8
Remove-PSSession $session
Say 'shutting the control OS down cleanly'
Stop-VM -VM (Get-VM -Id $vmId) -Force
if ((Get-VM -Id $vmId).State -ne 'Off') { throw 'VM did not shut down' }
Checkpoint-VM -VM (Get-VM -Id $vmId) -SnapshotName $FixtureCheckpoint
Say "checkpoint '$FixtureCheckpoint' saved"
