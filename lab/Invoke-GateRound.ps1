<#
.SYNOPSIS
Runs the lab's gates for one frozen build on every lab VM and reports them in
one table.

.DESCRIPTION
AGENTS.md says what has to pass before a change is committed. This script runs
it: five sets, the first two at the same time.

  fixtures  on the reference VM: the 1-in-10 fixture, the 1-in-40 fixture as
            an administrator, and the interrupted runs of the 1-in-40 fixture
            (ended half way through the source writes and resumed; the same
            rolled back; ended before finalization and resumed)
  data      on the other Windows 11 VMs: data volumes of every geometry,
            lived-in and many-file volumes, a shared disk, stops, recoveries,
            one volume with --recheck-everything, one held to the memory
            the estimate asks for it, one with middling memory held to a
            time, and the runs that stop for review (--review): committed,
            rolled back, written to after the stop (both commands refused),
            and ended at the two holds of a review run and recovered
  full      on the reference VM, with the host to itself: the full Windows
            volume, converted and booted on ReFS
  server    on the Windows Server VM: standard ReFS and the Dev Drive
  running   on the Windows 11 VMs other than the reference VM, with the host
            to itself: the Windows each VM runs from (C:), converted with
            one command in that Windows through its recovery environment
            (Invoke-RunningWindowsAttempt.ps1): --diagnose, a conversion
            that is then used, the power cut while the run prepares (NTFS
            has to be back) and at the hold half way through the source
            writes (the run has to recover to ReFS by itself). Each case
            starts from the VM's baseline checkpoint; each VM gets a working
            disk of its own first, made by a control-OS attempt

A build is a directory holding ntfs2refs.exe and lab-volume-manifest.exe, a
copy made for the round so that the tree can be built again meanwhile. Every
attempt is named <Prefix>-<case> and keeps its records under
.lab\hyperv\attempts as any attempt does; this script's own output goes to
<Build>\gate-<Prefix>.

The round starts with every lab VM off and leaves them off, with the scratch
disks it made deleted. It ends with a table of every case, what it was
expected to end as and what it ended as, and exits 1 if any differs.

The VMs' memory comes from what the host has free at the moment. Where that
is not enough for the reference VM's 24 GB beside the data VMs, the fixtures
run with less; where it is not enough for every data VM, fewer are used; and
where it is not enough for one, the data-volume cases wait for the fixtures.
The full Windows run always has the host to itself, and so has the running
set, which uses as many of its VMs as the host has memory and disk space
for (65 GB of disk a VM, as a full attempt).

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7b -Sets fixtures, data
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Build,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9]{0,7}$')][string]$Prefix,
    [ValidateSet('fixtures', 'data', 'full', 'server', 'running')][string[]]$Sets = @('fixtures', 'data', 'full', 'server', 'running'),
    [string]$ReferenceVm = 'ntfs2refs-reference-isolated',
    [string[]]$DataVm = @('ntfs2refs-reference-b', 'ntfs2refs-reference-c'),
    [string]$ServerVm = 'ntfs2refs-server2025',
    # The VMs whose own Windows the running set converts; the data VMs when
    # none is named.
    [string[]]$RunningVm = @(),
    # The most memory a lab VM is given, in GB. 24 is what the full Windows
    # volume is timed with; a host that shares its memory with other work
    # runs the round with less (12), slower, so that the other work's swings
    # do not end it (two rounds were lost to them on 17 and 18 November).
    [ValidateRange(8, 64)][int]$MaxVmGB = 24,
    [string]$ServerCredentialPath,
    # Only the cases named here, by the names the round gives them (as in
    # its table, without the prefix: 'fixture10', 'full-system', 'lived-in',
    # 'c-convert', ...): a short round for a change whose risk is known, or
    # the cases a round did not get to. The sets that hold none of them are
    # not run. A name no set has is refused.
    [string[]]$Only
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V

$workspace = Split-Path -Parent $PSScriptRoot
$attempts = Join-Path $workspace '.lab\hyperv\attempts'
$boot = Join-Path $PSScriptRoot 'Invoke-BootConversionAttempt.ps1'
$matrix = Join-Path $PSScriptRoot 'Invoke-DataVolumeMatrix.ps1'
$running = Join-Path $PSScriptRoot 'Invoke-RunningWindowsAttempt.ps1'
if (-not $RunningVm) { $RunningVm = $DataVm }
if (-not $ServerCredentialPath) {
    $ServerCredentialPath = Join-Path $workspace '.lab\hyperv\ntfs2refs-server2025\secrets\guest-credential.xml'
}
$Build = (Resolve-Path -LiteralPath $Build).Path
$binary = Join-Path $Build 'ntfs2refs.exe'
$manifest = Join-Path $Build 'lab-volume-manifest.exe'
foreach ($file in $binary, $manifest) {
    if (-not (Test-Path -LiteralPath $file)) { throw "$file is missing: a build is a directory with ntfs2refs.exe and lab-volume-manifest.exe" }
}
if (Get-ChildItem -LiteralPath $attempts -Directory -Filter "$Prefix-*" -ErrorAction SilentlyContinue) {
    throw "Attempts named '$Prefix-...' exist already under $attempts : choose another prefix"
}
$logs = Join-Path $Build "gate-$Prefix"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Say([string]$text) { Write-Host ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $text) }

# The VMs this round uses, by name; the rest of the host's VMs are left alone.
$wanted = @()
if ($Sets -contains 'fixtures' -or $Sets -contains 'full') { $wanted += $ReferenceVm }
if ($Sets -contains 'data') { $wanted += $DataVm }
if ($Sets -contains 'server') { $wanted += $ServerVm }
if ($Sets -contains 'running') { $wanted += $RunningVm }
$wanted = @($wanted | Select-Object -Unique)
$vms = @{}
foreach ($name in $wanted) {
    $vm = @(Get-VM -Name $name -ErrorAction SilentlyContinue)
    if ($vm.Count -ne 1) { throw "There is no single VM named '$name' on this host" }
    if ($vm[0].State -ne 'Off') { throw "VM '$name' is $($vm[0].State): a gate round starts with its VMs off" }
    $vms[$name] = $vm[0]
}

. "$PSScriptRoot/GateRoundCases.ps1" -MaxVmGB $MaxVmGB

if ($Only) {
    $known = @($fixtureRuns.Name) + @($fullRun.Name) + @($runningCases.Name) +
        @($dataCases + $serverCases | ForEach-Object { $_.Split('|', 2)[0] })
    $unknown = @($Only | Where-Object { $known -notcontains $_ })
    if ($unknown) { throw "-Only names cases no set has: $($unknown -join ', ')" }
    $fixtureRuns = @($fixtureRuns | Where-Object { $Only -contains $_.Name })
    $dataCases = @($dataCases | Where-Object { $Only -contains $_.Split('|', 2)[0] })
    $serverCases = @($serverCases | Where-Object { $Only -contains $_.Split('|', 2)[0] })
    $runningCases = @($runningCases | Where-Object { $Only -contains $_.Name })
    $Sets = @($Sets | Where-Object {
            ($_ -eq 'fixtures' -and $fixtureRuns) -or ($_ -eq 'data' -and $dataCases) -or
            ($_ -eq 'full' -and $Only -contains $fullRun.Name) -or ($_ -eq 'server' -and $serverCases) -or
            ($_ -eq 'running' -and $runningCases) })
    Say "only $($Only.Count) case(s), in the sets $($Sets -join ', ')"
}
$expected = Get-GateRoundExpectations $Sets "$Prefix-"

# One boot attempt after another on one VM, each with its console output in a
# file of its own. Run as a job, so that the data set can run beside it.
$bootChain = {
    param($boot, $runs, $prefix, $vmId, $binary, $manifest, $logs)
    foreach ($run in $runs) {
        $arguments = @{} + $run.Arguments
        $arguments.Name = "$prefix-$($run.Name)"
        $arguments.VmId = $vmId
        $arguments.Binary = $binary
        $arguments.ManifestBinary = $manifest
        try { & $boot @arguments *> (Join-Path $logs "$($arguments.Name).log") }
        catch { "$($arguments.Name) threw: $($_.Exception.Message)" | Add-Content -LiteralPath (Join-Path $logs 'errors.txt') }
    }
}

# One running-Windows attempt after another on one VM, as a job beside the
# other VMs'. Each restores the VM's baseline checkpoint first and gives the
# VM back the disks it detached when it ends.
$runningChain = {
    param($running, $cases, $prefix, $vmId, $binary, $scratch, $logs)
    foreach ($case in @($cases)) {
        $arguments = @{} + $case.Arguments
        $arguments.Name = "$prefix-$($case.Name)"
        $arguments.VmId = $vmId
        $arguments.Binary = $binary
        $arguments.ScratchVhdx = $scratch
        # What the cases' times were taken with.
        $arguments.MemoryGB = 8
        $arguments.Restore = $true
        $arguments.Reattach = $true
        try { & $running @arguments *> (Join-Path $logs "$($arguments.Name).log") }
        catch { "$($arguments.Name) threw: $($_.Exception.Message)" | Add-Content -LiteralPath (Join-Path $logs 'errors.txt') }
    }
}

function Stop-RoundVm([string]$name) {
    $vm = Get-VM -Name $name
    if ($vm.State -ne 'Off') { $vm | Stop-VM -Force -Confirm:$false }
    # The scratch disk of a control OS that was kept up for the data set, or
    # of an attempt of this round that was cut off.
    # (And the boot partition's disk a running-Windows attempt made beside
    # its working disk.)
    foreach ($drive in @(Get-VMHardDiskDrive -VMName $name | Where-Object { $_.Path -like (Join-Path $attempts "$Prefix-*\scratch.vhdx") -or $_.Path -like (Join-Path $attempts "$Prefix-*\boot.vhdx") })) {
        $path = $drive.Path
        Remove-VMHardDiskDrive -VMHardDiskDrive $drive
        Remove-Item -LiteralPath $path -Force
        Say "deleted the scratch disk $path"
    }
}

# Memory is sized from what the host has free, which other programs change
# from one minute to the next. The harness gives a VM no more than eight
# tenths of what is free when it starts and refuses to start one with less
# than 8 GB: a data VM therefore needs 10 GB free at its start, with a
# gigabyte to spare for what changes meanwhile, and each one before it
# takes its 8 GB and half a gigabyte more.
function Get-FreeGB { (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB }
# (The host keeps 8 GB, as the attempts themselves hold it to: counting 2.5 GB had a second data VM start its attempt and wait for memory the fixtures held.)
function Get-DataVmCount([double]$freeGB) { [math]::Max(0, [math]::Min($DataVm.Count, [math]::Floor(($freeGB - 8) / 8.5))) }

$fixtureJob = $null; $runningJobs = @()
try {
    if ($Sets -contains 'fixtures') {
        $free = Get-FreeGB
        if ($Sets -contains 'data') {
            # The fixtures leave the data VMs their memory where the host has
            # it: the reference VM does not need its 24 GB for them.
            # (A running VM costs the host a gigabyte or two beyond what it
            # is given.)
            $beside = 5 + 8 * $DataVm.Count
            $referenceGB = [math]::Floor([math]::Min($MaxVmGB, $free - $beside))
            # Too little for both at once: the reference VM takes what is
            # free less the host's 8 GB, and the data cases wait for it.
            if ($referenceGB -lt [math]::Min(16, $MaxVmGB)) { $referenceGB = [math]::Floor([math]::Max(8, [math]::Min($MaxVmGB, $free - 8))) }
            foreach ($run in $fixtureRuns) { $run.Arguments = $run.Arguments + @{ MemoryGB = [int]$referenceGB } }
        } else {
            foreach ($run in $fixtureRuns) { $run.Arguments = $run.Arguments + @{ MemoryGB = $MaxVmGB } }
        }
        Say ('fixtures and interrupted runs on {0} ({1:N1} GB of host memory free)' -f $ReferenceVm, $free)
        $fixtureJob = Start-Job -ScriptBlock $bootChain -ArgumentList $boot, $fixtureRuns, $Prefix, $vms[$ReferenceVm].Id.Guid, $binary, $manifest, $logs
        if ($Sets -contains 'data') {
            # The reference VM takes its memory when it starts; what the data
            # VMs get is measured after that.
            $deadline = (Get-Date).AddMinutes(10)
            do { Start-Sleep -Seconds 10 } until ((Get-VM -Name $ReferenceVm).State -eq 'Running' -or $fixtureJob.State -ne 'Running' -or (Get-Date) -gt $deadline)
            Start-Sleep -Seconds 20
        }
    }
    if ($Sets -contains 'data') {
        $count = Get-DataVmCount (Get-FreeGB)
        if ($count -eq 0 -and $fixtureJob) {
            Say ('{0:N1} GB of host memory are free beside the reference VM: the data-volume cases wait for the fixtures' -f (Get-FreeGB))
            $fixtureJob | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'fixtures-job.log')
            $fixtureJob = $null
            Stop-RoundVm $ReferenceVm
            $count = Get-DataVmCount (Get-FreeGB)
        }
        # Too little memory is no failure of the round: it waits for it.
        for ($waited = 0; $count -eq 0 -and $waited -lt 240 * 60; $waited += 30) {
            if ($waited % 600 -eq 0) { Say ('{0:N1} GB of host memory are free and a data VM needs 10: waiting' -f (Get-FreeGB)) }
            Start-Sleep -Seconds 30
            $count = Get-DataVmCount (Get-FreeGB)
        }
        if ($count -eq 0) { throw ('{0:N1} GB of host memory are free after four hours of waiting: a data VM needs 10' -f (Get-FreeGB)) }
        $used = @($DataVm | Select-Object -First $count)
        $number = 0
        foreach ($name in $used) {
            $number++
            # 8 GB is enough for every data-volume case; a VM that has the
            # memory to itself gets up to 12.
            $free = Get-FreeGB
            $give = if ($count -eq 1) { [math]::Floor([math]::Max(8, [math]::Min(12, $free - 8))) } else { 8 }
            Say ('control OS up on {0} with {1} GB ({2:N1} GB free)' -f $name, $give, $free)
            $control = "$Prefix-control-$number"
            & $boot -Name $control -NoConvert -KeepScratch -MemoryGB $give -VmId $vms[$name].Id.Guid -Binary $binary -ManifestBinary $manifest *> (Join-Path $logs "$control.log")
            $verdict = Join-Path $attempts "$control\verdict.json"
            if (-not (Test-Path -LiteralPath $verdict) -or (Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json).outcome -ne 'prepared-only') {
                throw "The control OS of $name did not come up: see $(Join-Path $logs "$control.log")"
            }
        }
        Say "$($dataCases.Count) data-volume cases on $($used -join ', ')"
        & $matrix -Prefix $Prefix -Cases $dataCases -VmId @($used | ForEach-Object { $vms[$_].Id.Guid }) -Binary $binary -ManifestBinary $manifest -LogDirectory $logs *> (Join-Path $logs 'matrix-data.log')
        foreach ($name in $used) { Stop-RoundVm $name }
    }
    if ($fixtureJob) {
        Say 'waiting for the fixtures and interrupted runs'
        $fixtureJob | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'fixtures-job.log')
    }
    if ($Sets -contains 'full') {
        Say "the full Windows volume on $ReferenceVm, with the host to itself"
        & $bootChain $boot @($fullRun) $Prefix $vms[$ReferenceVm].Id.Guid $binary $manifest $logs
    }
    if ($Sets -contains 'server') {
        Say "$($serverCases.Count) data-volume cases on $ServerVm"
        if ($vms.ContainsKey($ReferenceVm)) { Stop-RoundVm $ReferenceVm }
        $credential = Import-Clixml -LiteralPath $ServerCredentialPath
        Start-VM -Name $ServerVm
        $deadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 10
            $up = $false
            try { $up = (Invoke-Command -VMName $ServerVm -Credential $credential -ScriptBlock { $true } -ErrorAction Stop) } catch { }
        } until ($up -or (Get-Date) -gt $deadline)
        if (-not $up) { throw "$ServerVm did not answer PowerShell Direct within ten minutes" }
        & $matrix -Prefix $Prefix -Cases $serverCases -VmId $vms[$ServerVm].Id.Guid -Binary $binary -ManifestBinary $manifest -CredentialPath $ServerCredentialPath -LogDirectory $logs *> (Join-Path $logs 'matrix-server.log')
    }
    if ($Sets -contains 'running') {
        # The host to itself, as for the full Windows volume: each case
        # converts a whole Windows.
        foreach ($name in $wanted) { Stop-RoundVm $name }
        # A VM takes 8 GB and the host keeps 8; a conversion of the Windows
        # volume grows the VM's disks and its working disk by about 60 GB.
        $freeGB = Get-FreeGB
        $diskGB = (Get-Volume -FilePath $attempts).SizeRemaining / 1GB
        $count = [int][math]::Max(0, [math]::Min($RunningVm.Count, [math]::Min([math]::Floor(($freeGB - 8) / 8.5), [math]::Floor($diskGB / 65))))
        if ($count -eq 0) { throw ('The running set needs 16.5 GB of host memory and 65 GB of disk space for one VM: {0:N1} GB of memory and {1:N1} GB of disk are free' -f $freeGB, $diskGB) }
        $used = @($RunningVm | Select-Object -First $count)
        Say ('{0} running-Windows cases on {1}, 8 GB each ({2:N1} GB of host memory and {3:N1} GB of disk free)' -f $runningCases.Count, ($used -join ', '), $freeGB, $diskGB)
        for ($number = 0; $number -lt $used.Count; $number++) {
            $name = $used[$number]
            # The working disk: an NTFS volume on a disk of its own, made by a
            # control-OS attempt, which is then shut down so that the volume
            # is written out before the VM's checkpoint is restored under it.
            $work = "$Prefix-c-work-$($number + 1)"
            & $boot -Name $work -NoConvert -KeepScratch -ScratchFileSystem NTFS -MemoryGB 8 -VmId $vms[$name].Id.Guid -Binary $binary -ManifestBinary $manifest *> (Join-Path $logs "$work.log")
            $verdict = Join-Path $attempts "$work\verdict.json"
            if (-not (Test-Path -LiteralPath $verdict) -or (Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json).outcome -ne 'prepared-only') {
                throw "The working disk of $name was not made: see $(Join-Path $logs "$work.log")"
            }
            Stop-VM -Name $name -Force -Confirm:$false
            # Each VM takes every case whose place in the list is its own.
            $mine = @(for ($i = $number; $i -lt $runningCases.Count; $i += $used.Count) { $runningCases[$i] })
            Say "$name takes $(($mine | ForEach-Object { $_.Name }) -join ', ')"
            $runningJobs += Start-Job -ScriptBlock $runningChain -ArgumentList $running, $mine, $Prefix, $vms[$name].Id.Guid, $binary, (Join-Path $attempts "$work\scratch.vhdx"), $logs
        }
        $runningJobs | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'running-jobs.log')
    }
}
finally {
    if ($fixtureJob -and $fixtureJob.State -eq 'Running') { $fixtureJob | Stop-Job }
    foreach ($job in @($runningJobs)) { if ($job.State -eq 'Running') { $job | Stop-Job } }
    foreach ($name in $wanted) { try { Stop-RoundVm $name } catch { Say "could not turn $name off: $($_.Exception.Message)" } }
}

# One row a case: what it was to end as, what it ended as, whether the
# listing of the volume is the one taken before, and the converter's time.
$rows = @(foreach ($name in $expected.Keys) {
    $verdict = Join-Path $attempts "$name\verdict.json"
    $outcome = 'no verdict'; $listing = ''; $seconds = $null; $check = ''
    if (Test-Path -LiteralPath $verdict) {
        $v = Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json
        $outcome = $v.outcome
        if ($v.PSObject.Properties['manifest'] -and $v.manifest) { $listing = $v.manifest.result }
        if ($v.PSObject.Properties['converter'] -and $v.converter) {
            foreach ($field in 'wall_seconds', 'seconds') { if ($v.converter.PSObject.Properties[$field]) { $seconds = [math]::Round($v.converter.$field, 1); break } }
        }
        if ($v.PSObject.Properties['check'] -and $v.check -and $v.check.PSObject.Properties['agrees'] -and $v.check.agrees -eq $false) { $check = 'check disagreed' }
    }
    $ok = $outcome -eq $expected[$name] -and $listing -in '', 'identical' -and -not $check
    [pscustomobject]@{ Case = $name; Expected = $expected[$name]; Outcome = $outcome; Listing = $listing; Seconds = $seconds; Passed = $ok; Note = $check }
})
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$rows | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logs 'round.json') -Encoding utf8
$failed = @($rows | Where-Object { -not $_.Passed })
Say ('{0} of {1} cases as expected; records in {2}' -f ($rows.Count - $failed.Count), $rows.Count, $logs)
if ($failed) { exit 1 }
