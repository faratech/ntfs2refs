<#
.SYNOPSIS
Runs the lab's gates for one frozen build on every lab VM and reports them in
one table.

.DESCRIPTION
AGENTS.md says what has to pass before a change is committed. This script runs
it: four sets, the first two at the same time.

  fixtures  on the reference VM: the 1-in-10 fixture, the 1-in-40 fixture as
            an administrator, and the interrupted runs of the 1-in-40 fixture
            (ended half way through the source writes and resumed; the same
            rolled back; ended before finalization and resumed)
  data      on the other Windows 11 VMs: data volumes of every geometry,
            lived-in and many-file volumes, a shared disk, stops, recoveries,
            one volume with --recheck-everything
  full      on the reference VM, with the host to itself: the full Windows
            volume, converted and booted on ReFS
  server    on the Windows Server VM: standard ReFS and the Dev Drive

A build is a directory holding ntfs2refs.exe and lab-volume-manifest.exe, a
copy made for the round so that the tree can be built again meanwhile. Every
attempt is named <Prefix>-<case> and keeps its records under
.lab\hyperv\attempts as any attempt does; this script's own output goes to
<Build>\gate-<Prefix>.

The round starts with every lab VM off and leaves them off, with the scratch
disks it made deleted. It ends with a table of every case, what it was
expected to end as and what it ended as, and exits 1 if any differs.

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7b -Sets fixtures, data
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Build,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9]{0,7}$')][string]$Prefix,
    [ValidateSet('fixtures', 'data', 'full', 'server')][string[]]$Sets = @('fixtures', 'data', 'full', 'server'),
    [string]$ReferenceVm = 'ntfs2refs-reference-isolated',
    [string[]]$DataVm = @('ntfs2refs-reference-b', 'ntfs2refs-reference-c'),
    [string]$ServerVm = 'ntfs2refs-server2025',
    [string]$ServerCredentialPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V

$workspace = Split-Path -Parent $PSScriptRoot
$attempts = Join-Path $workspace '.lab\hyperv\attempts'
$boot = Join-Path $PSScriptRoot 'Invoke-BootConversionAttempt.ps1'
$matrix = Join-Path $PSScriptRoot 'Invoke-DataVolumeMatrix.ps1'
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
$vms = @{}
foreach ($name in $wanted) {
    $vm = @(Get-VM -Name $name -ErrorAction SilentlyContinue)
    if ($vm.Count -ne 1) { throw "There is no single VM named '$name' on this host" }
    if ($vm[0].State -ne 'Off') { throw "VM '$name' is $($vm[0].State): a gate round starts with its VMs off" }
    $vms[$name] = $vm[0]
}

# What each case is expected to end as follows from how it is run.
$expected = [ordered]@{}
function Get-ExpectedBootOutcome([hashtable]$arguments) {
    if ($arguments.ContainsKey('InterruptAt')) {
        if ($arguments['RecoverMode'] -eq 'rollback') { return 'ROLLED-BACK-NOT-BOOTED' }
        return 'RESUMED-NOT-BOOTED'
    }
    if ($arguments.ContainsKey('NoBoot')) { return 'converted-not-booted' }
    return 'BOOTED-ON-REFS'
}
function Get-ExpectedDataOutcome([string]$arguments) {
    if ($arguments -match '-ExpectRefusal\b') { return 'refused-as-expected' }
    if ($arguments -match '-StopDuringPreparation\b') { return 'preparation-cancelled' }
    if ($arguments -match '-Diagnose\b') { return 'diagnose-clean' }
    if ($arguments -match '-InterruptAt\b') {
        if ($arguments -match '-RecoverMode\s+rollback\b') { return 'rolled-back' }
        return 'resumed'
    }
    return 'converted'
}

$fixture40 = @{ Fixture = $true; FixtureCheckpoint = 'N2R-Thinned-Fixture-40'; NoBoot = $true }
$fixtureRuns = @(
    @{ Name = 'fixture10'; Arguments = @{ Fixture = $true; NoBoot = $true } }
    @{ Name = 'admin-fixture40'; Arguments = $fixture40 + @{ RunAs = 'administrator' } }
    @{ Name = 'apply-mid-resume'; Arguments = $fixture40 + @{ InterruptAt = 'apply-mid-ranges' } }
    @{ Name = 'apply-mid-rollback'; Arguments = $fixture40 + @{ InterruptAt = 'apply-mid-ranges'; RecoverMode = 'rollback' } }
    @{ Name = 'handoff-sealed-resume'; Arguments = $fixture40 + @{ InterruptAt = 'handoff-sealed' } }
)
$fullRun = @{ Name = 'full-system'; Arguments = @{} }

$lived = '-Content lived-in -DirectoryEntries 4000'
$dataCases = @(
    'plain|-Check'
    "lived-in|$lived -Check -Acceptance"
    '512-to-4k|-ClusterBytes 512 -Check -Acceptance'
    '512-to-64k|-ClusterBytes 512 -TargetClusterBytes 65536 -Check'
    '4kn-4k|-SectorBytes 4096 -Check'
    '4kn-64k-to-64k|-SectorBytes 4096 -ClusterBytes 65536 -TargetClusterBytes 65536 -Check'
    "lived-in-64k|$lived -TargetClusterBytes 65536 -Check -Acceptance"
    "lived-in-512|$lived -ClusterBytes 512 -Check"
    'odd-size|-PartitionMB 51237 -Check'
    'small-8g|-PartitionMB 8192 -Check'
    'many-20k|-Content many -Islands 20000 -Check'
    'files-20k|-Content minimal -Features manyfiles -FileCount 20000 -Check'
    '4k-admin|-RunAs administrator -Check'
    'shared|-Siblings -Check -Acceptance'
    "shared-lived-in|-Siblings $lived -Check"
    "lived-in-apply-mid-resume|$lived -InterruptAt apply-mid-ranges -Check"
    "lived-in-apply-mid-rollback|$lived -InterruptAt apply-mid-ranges -RecoverMode rollback -Check"
    "lived-in-handoff-sealed-resume|$lived -InterruptAt handoff-sealed -Check"
    'shared-apply-rollback|-Siblings -InterruptAt apply-mid-ranges -RecoverMode rollback -Check'
    "stop-supply-cancel|$lived -StopDuringPreparation payload_supply"
    "stop-journal-cancel|$lived -StopDuringPreparation recovery_journal"
    "lived-in-diagnose|$lived -Diagnose"
    "lived-in-listing|$lived -CompareListing"
    "lived-in-recheck|$lived -ConverterArgs --recheck-everything"
    'wide-drop|-Content minimal -Features shortnames-wide -DropShortNames -Check -Acceptance'
    'objectids|-Content minimal -Features objectids -Check'
    'security|-Content minimal -Features security -Check'
    'ea|-Content minimal -Features ea -Check'
    'links|-Content minimal -Features links -Check'
    'bigdir|-Content minimal -Features bigdir -Check'
    'casemark|-Content minimal -Features casemark -Check'
    'shortnames|-Content minimal -Features shortnames -Check -ExpectRefusal short-names.drop'
)
$serverCases = @(
    'std-4k|-TargetFormat standard -Check'
    'std-64k|-TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-512-to-4k|-ClusterBytes 512 -TargetFormat standard -Check'
    'std-512-to-64k|-ClusterBytes 512 -TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-4kn-4k|-SectorBytes 4096 -TargetFormat standard -Check'
    'std-4kn-64k-to-64k|-SectorBytes 4096 -ClusterBytes 65536 -TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-lived-in|-Content lived-in -Acceptance -TargetFormat standard -Check'
    'devdrive|-TargetFormat dev-drive -Check'
    'server-shared|-Siblings -TargetFormat default -Check -Acceptance'
    'std-apply-mid-rollback|-TargetFormat standard -InterruptAt apply-mid-ranges -RecoverMode rollback -Check'
    'std-handoff-resume|-TargetFormat standard -InterruptAt handoff-sealed -Check'
    'server-files-20k|-Content minimal -Features manyfiles -FileCount 20000 -TargetFormat default -Check'
)

if ($Sets -contains 'fixtures') { foreach ($run in $fixtureRuns) { $expected["$Prefix-$($run.Name)"] = Get-ExpectedBootOutcome $run.Arguments } }
if ($Sets -contains 'data') { foreach ($case in $dataCases) { $name, $rest = $case.Split('|', 2); $expected["$Prefix-$name"] = Get-ExpectedDataOutcome $rest } }
if ($Sets -contains 'full') { $expected["$Prefix-$($fullRun.Name)"] = Get-ExpectedBootOutcome $fullRun.Arguments }
if ($Sets -contains 'server') { foreach ($case in $serverCases) { $name, $rest = $case.Split('|', 2); $expected["$Prefix-$name"] = Get-ExpectedDataOutcome $rest } }

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

function Stop-RoundVm([string]$name) {
    $vm = Get-VM -Name $name
    if ($vm.State -ne 'Off') { $vm | Stop-VM -Force -Confirm:$false }
    # The scratch disk of a control OS that was kept up for the data set.
    foreach ($drive in @(Get-VMHardDiskDrive -VMName $name | Where-Object { $_.Path -like (Join-Path $attempts "$Prefix-control-*\scratch.vhdx") })) {
        $path = $drive.Path
        Remove-VMHardDiskDrive -VMHardDiskDrive $drive
        Remove-Item -LiteralPath $path -Force
        Say "deleted the scratch disk $path"
    }
}

$fixtureJob = $null
try {
    if ($Sets -contains 'fixtures') {
        Say "fixtures and interrupted runs on $ReferenceVm"
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
        # Each data VM gets an equal share of the memory that is free now,
        # with 6 GB left to the host; 12 GB is all a data-volume case uses.
        $freeGB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
        $each = [math]::Floor([math]::Min(12, ($freeGB - 6) / $DataVm.Count))
        if ($each -lt 6) { throw ('{0:N1} GB of host memory are free: not enough to give {1} data VMs 6 GB each beside the reference VM' -f $freeGB, $DataVm.Count) }
        $number = 0
        foreach ($name in $DataVm) {
            $number++
            Say "control OS up on $name with $each GB"
            $control = "$Prefix-control-$number"
            & $boot -Name $control -NoConvert -KeepScratch -MemoryGB $each -VmId $vms[$name].Id.Guid -Binary $binary -ManifestBinary $manifest *> (Join-Path $logs "$control.log")
            $verdict = Join-Path $attempts "$control\verdict.json"
            if (-not (Test-Path -LiteralPath $verdict) -or (Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json).outcome -ne 'prepared-only') {
                throw "The control OS of $name did not come up: see $(Join-Path $logs "$control.log")"
            }
        }
        Say "$($dataCases.Count) data-volume cases on $($DataVm -join ', ')"
        & $matrix -Prefix $Prefix -Cases $dataCases -VmId @($DataVm | ForEach-Object { $vms[$_].Id.Guid }) -Binary $binary -ManifestBinary $manifest -LogDirectory $logs *> (Join-Path $logs 'matrix-data.log')
        foreach ($name in $DataVm) { Stop-RoundVm $name }
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
}
finally {
    if ($fixtureJob -and $fixtureJob.State -eq 'Running') { $fixtureJob | Stop-Job }
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
