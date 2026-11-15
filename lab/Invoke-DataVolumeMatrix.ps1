<#
.SYNOPSIS
  Runs a list of data-volume attempts on one or more lab VMs at once.

.DESCRIPTION
  A case is '<name>|<arguments of Invoke-DataVolumeAttempt.ps1>', for example
  'lived-in|-Content lived-in -Check -Acceptance'. The cases are started in
  the order of the list: each VM takes the next one as soon as it is free, so
  attempts on different VMs run side by side and a long case does not hold up
  the short ones behind it. An attempt is named <Prefix>-<name> and keeps its
  records where it always does.

  One line is printed for every attempt as it ends, and at the end how the
  attempts ended and how long the whole took. The script's result is one
  object per attempt (name, vm, outcome, seconds, detail).

  Every VM must have its control OS up and a scratch volume S: before this is
  started:
    lab\Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -VmId <id> -MemoryGB 12
  (a VM made by New-ServerLabVm.ps1 is started with Start-VM). A second VM
  like the reference VM is made by New-LabVmClone.ps1 in seconds. A set of
  seventy cases took 2 h 20 min on one VM; attempts mostly wait for the
  guest, so two VMs of 12 GB take about half of that.

  -Binary and -ManifestBinary name the executables to test; give a copy that
  no build will overwrite while the cases run.

  A case that changes the machine for what comes after it on the same VM
  (-Features bitlocker: Windows then writes its recovery folders to every
  volume that arrives) belongs at the end of the list.

.EXAMPLE
  lab\Invoke-DataVolumeMatrix.ps1 -Prefix x1 -VmId $b, $c -Binary C:\frozen\ntfs2refs.exe -ManifestBinary C:\frozen\lab-volume-manifest.exe `
      -Cases 'plain|-Check', 'lived-in|-Content lived-in -Check -Acceptance', 'shared|-Siblings -Check'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Prefix,
    [Parameter(Mandatory)][string[]]$Cases,
    # The VMs to use, by their Hyper-V id.
    [Parameter(Mandatory)][string[]]$VmId,
    [string]$Binary,
    [string]$ManifestBinary,
    # The guest account's saved credential, where the VMs do not use the
    # reference VMs' (see Invoke-DataVolumeAttempt.ps1 -CredentialPath).
    [string]$CredentialPath,
    # Where each attempt's console output goes, as <Prefix>-<name>.log.
    # By default beside the binary, or in the attempts folder.
    [string]$LogDirectory
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$attempt = Join-Path $PSScriptRoot 'Invoke-DataVolumeAttempt.ps1'
$attempts = Join-Path $workspace '.lab\hyperv\attempts'
if (-not $LogDirectory) { $LogDirectory = if ($Binary) { Split-Path -Parent $Binary } else { $attempts } }
$null = New-Item -ItemType Directory -Path $LogDirectory -Force
$VmId = @($VmId | Select-Object -Unique)
$vmNames = @{}
foreach ($id in $VmId) {
    $vm = Get-VM -Id $id
    if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is not running: bring its control OS up first" }
    $vmNames[$id] = $vm.Name
}

# '<name>|-Switch -Name value ...' as a table of arguments. A value is
# whatever follows a parameter and does not start with a dash.
$queue = New-Object System.Collections.Generic.Queue[hashtable]
$names = New-Object System.Collections.Generic.List[string]
foreach ($case in $Cases) {
    $name, $rest = $case.Split('|', 2)
    if (-not $name -or $name -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "A case is '<name>|<arguments>': $case" }
    $arguments = @{}
    $tokens = @("$rest".Trim() -split '\s+' | Where-Object { $_ })
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if (-not $tokens[$i].StartsWith('-')) { throw "Case '$name': '$($tokens[$i])' follows no parameter" }
        $key = $tokens[$i].TrimStart('-')
        if ($i + 1 -lt $tokens.Count -and -not $tokens[$i + 1].StartsWith('-')) { $arguments[$key] = $tokens[$i + 1]; $i++ }
        else { $arguments[$key] = $true }
    }
    $arguments.Name = "$Prefix-$name"
    if ($Binary) { $arguments.Binary = $Binary }
    if ($ManifestBinary) { $arguments.ManifestBinary = $ManifestBinary }
    if ($CredentialPath -and -not $arguments.ContainsKey('CredentialPath')) { $arguments.CredentialPath = $CredentialPath }
    if ($names.Contains($arguments.Name)) { throw "Two cases are named '$name'" }
    # An attempt keeps its records under its name; an earlier one of the same
    # name would be taken for this one's.
    if (Test-Path -LiteralPath (Join-Path $attempts $arguments.Name)) { throw "An attempt named '$($arguments.Name)' exists already: choose another prefix" }
    $names.Add($arguments.Name)
    $queue.Enqueue($arguments)
}

# One attempt, in a process of its own. Its arguments come as text: tables
# do not all survive the way from one process to another as tables.
$worker = {
    param($attempt, $attempts, $logs, $vm, $caseJson)
    $case = ConvertFrom-Json -InputObject $caseJson
    $arguments = @{}
    foreach ($property in $case.PSObject.Properties) { $arguments[$property.Name] = $property.Value }
    $arguments.VmId = $vm
    $name = $arguments.Name
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $threw = $null
    try { & $attempt @arguments *> (Join-Path $logs "$name.log") } catch { $threw = "$($_.Exception.Message)" }
    $outcome = if ($threw) { 'harness-threw' } else { 'no verdict' }
    $detail = $threw
    $file = Join-Path $attempts "$name\verdict.json"
    if (-not $threw -and (Test-Path -LiteralPath $file)) {
        $verdict = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $has = { param($property) [bool]$verdict.PSObject.Properties[$property] }
        $outcome = "$($verdict.outcome)"
        $detail = if ((& $has 'converter') -and $verdict.converter -and $verdict.converter.error) { "$($verdict.converter.error)" }
            elseif ((& $has 'error') -and $verdict.error) { "harness: $($verdict.error)" }
            elseif ((& $has 'manifest') -and $verdict.manifest) { "listing $($verdict.manifest.result)" }
            else { $threw }
    }
    [pscustomobject]@{ name = $name; vm = $vm; outcome = $outcome; seconds = [Math]::Round($clock.Elapsed.TotalSeconds); detail = $detail }
}

$watch = [Diagnostics.Stopwatch]::StartNew()
$results = New-Object System.Collections.Generic.List[object]
$busy = @{}
try {
    while ($queue.Count -or $busy.Count) {
        foreach ($id in $VmId) {
            if ($busy.ContainsKey($id) -and $busy[$id].job.State -ne 'Running') {
                $job = $busy[$id].job
                $result = @(Receive-Job -Job $job -ErrorAction SilentlyContinue | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['outcome'] }) | Select-Object -Last 1
                if (-not $result) {
                    $reason = if ($job.ChildJobs[0].JobStateInfo.Reason) { "$($job.ChildJobs[0].JobStateInfo.Reason.Message)" } else { 'its process ended without a result' }
                    $result = [pscustomobject]@{ name = $busy[$id].name; vm = $id; outcome = 'no verdict'; seconds = 0; detail = $reason }
                }
                Remove-Job -Job $job -Force
                $busy.Remove($id)
                $results.Add($result)
                $shown = if ($result.detail) { "$($result.detail)" } else { '' }
                if ($shown.Length -gt 160) { $shown = $shown.Substring(0, 160) }
                Write-Host ('{0} {1} on {2} => {3} ({4} s){5}' -f (Get-Date -Format 'HH:mm:ss'), $result.name, $vmNames[$id], $result.outcome, $result.seconds, $(if ($shown) { " | $shown" }))
            }
            if (-not $busy.ContainsKey($id) -and $queue.Count) {
                $arguments = $queue.Dequeue()
                $caseJson = ConvertTo-Json -InputObject $arguments -Depth 3 -Compress
                $busy[$id] = @{ name = $arguments.Name; job = (Start-Job -ScriptBlock $worker -ArgumentList $attempt, $attempts, $LogDirectory, $id, $caseJson) }
            }
        }
        Start-Sleep -Milliseconds 500
    }
} finally {
    foreach ($id in @($busy.Keys)) { Stop-Job -Job $busy[$id].job -ErrorAction SilentlyContinue; Remove-Job -Job $busy[$id].job -Force -ErrorAction SilentlyContinue }
}
$serial = ($results | Measure-Object seconds -Sum).Sum
Write-Host ('{0} attempt(s) on {1} VM(s) in {2:N0} s; one after another they took {3:N0} s.' -f $results.Count, $VmId.Count, $watch.Elapsed.TotalSeconds, $serial)
foreach ($group in $results | Group-Object outcome | Sort-Object Count -Descending) { Write-Host ('  {0,3} {1}' -f $group.Count, $group.Name) }
$results
