<#
.SYNOPSIS
Runs the checks a pull request has to pass, locally, on one exact commit.

.DESCRIPTION
The checks are the ones the GitHub Actions workflow ran: the formatting, Clippy,
all tests, and every executable built in release mode, the converter started
once. GitHub Actions is not used for this repository (the owner's decision of
15 November 2026); this script is how a commit is checked before it is merged.

The commit is checked out into a worktree of its own, so that what is checked
is that commit and nothing the working tree happens to hold, and built into
one build directory that later runs reuse. The script prints a table, writes
it as Markdown for the pull request (-Report), and exits 1 if a check failed.
It does not run the lab's gates: lab\Invoke-GateRound.ps1 does.

.EXAMPLE
lab\Invoke-Checks.ps1                      # the commit that is checked out

.EXAMPLE
lab\Invoke-Checks.ps1 -Commit origin/my-branch -Report checks.md
#>
[CmdletBinding()]
param(
    # The commit to check: a hash, a branch or a tag.
    [string]$Commit = 'HEAD',
    # Where the checks build; reused from run to run. By default target\checks.
    [string]$BuildDirectory,
    # A file to write the table to, as Markdown.
    [string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$found = Get-Command cargo -ErrorAction SilentlyContinue
$cargo = if ($found) { $found.Source } else { Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe' }
if (-not (Test-Path -LiteralPath $cargo)) { throw "cargo was not found on PATH or at $cargo" }
$git = (Get-Command git).Source

$head = (& $git -C $workspace rev-parse --verify "$Commit^{commit}").Trim()
if ($LASTEXITCODE -ne 0 -or $head.Length -ne 40) { throw "'$Commit' does not name a commit" }
if (-not $BuildDirectory) { $BuildDirectory = Join-Path $workspace 'target\checks' }
New-Item -ItemType Directory -Force -Path $BuildDirectory | Out-Null
$BuildDirectory = (Resolve-Path -LiteralPath $BuildDirectory).Path
$logs = Join-Path $BuildDirectory "logs-$($head.Substring(0, 12))"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

# The commit by itself, beside the build directory: nothing uncommitted is
# in it, and a path that stays the same lets later runs reuse what was built.
$tree = Join-Path $BuildDirectory 'tree'
& $git -C $workspace worktree prune
if (Test-Path -LiteralPath $tree) { & $git -C $workspace worktree remove --force $tree 2>$null | Out-Null }
if (Test-Path -LiteralPath $tree) { Remove-Item -LiteralPath $tree -Recurse -Force }
& $git -C $workspace worktree add --detach --quiet $tree $head
if ($LASTEXITCODE -ne 0) { throw "could not check $head out into $tree" }

$rows = New-Object System.Collections.Generic.List[object]
function Invoke-Check([string]$job, [string]$name, [string]$exe, [string[]]$arguments) {
    $log = Join-Path $logs (($name -replace '[^A-Za-z0-9]+', '-').Trim('-') + '.log')
    Write-Host ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $name)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $tree
    try {
        # Cargo writes its progress to the error stream; neither stream is an
        # error by itself, the exit code is the result.
        $ErrorActionPreference = 'Continue'
        & $exe @arguments *> $log
        $exit = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = 'Stop'; Pop-Location }
    $row = [pscustomobject]@{ Job = $job; Check = $name; Exit = $exit; Seconds = [math]::Round($watch.Elapsed.TotalSeconds); Detail = ''; Log = $log }
    $rows.Add($row)
    return $row
}

$env:CARGO_TARGET_DIR = Join-Path $BuildDirectory 'build'
$env:CARGO_TERM_COLOR = 'never'
$failed = $false
try {
    # The toolchain the repository pins is the one that checks it.
    Push-Location $tree
    try { $compiler = @(& (Join-Path (Split-Path $cargo) 'rustc.exe') -vV) } finally { Pop-Location }
    $pinned = (Select-String -LiteralPath (Join-Path $tree 'rust-toolchain.toml') -Pattern '^channel\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
    $release = ($compiler | Where-Object { $_ -like 'release: *' }) -replace '^release: ', ''
    $hostLine = ($compiler | Where-Object { $_ -like 'host: *' }) -replace '^host: ', ''
    if ($release -ne $pinned) { throw "rustc $release is not the pinned $pinned" }

    $row = Invoke-Check 'checks' 'cargo fmt --all -- --check' $cargo @('fmt', '--all', '--', '--check')
    $row = Invoke-Check 'checks' 'cargo clippy --locked --workspace --all-targets' $cargo @('clippy', '--locked', '--workspace', '--all-targets')
    $text = @(Get-Content -LiteralPath $row.Log)
    $row.Detail = '{0} errors, {1} warnings (warnings are advisory)' -f @($text -match '^error').Count, @($text -match '^warning').Count
    $row = Invoke-Check 'tests' 'cargo test --locked --workspace --all-targets' $cargo @('test', '--locked', '--workspace', '--all-targets')
    $passed = 0; $failures = 0; $ignored = 0
    foreach ($line in @(Get-Content -LiteralPath $row.Log) -match '^test result:') {
        if ($line -match '(\d+) passed; (\d+) failed; (\d+) ignored') { $passed += [int]$Matches[1]; $failures += [int]$Matches[2]; $ignored += [int]$Matches[3] }
    }
    $row.Detail = "$passed passed, $failures failed, $ignored ignored"
    # Every executable of the workspace, the two a release ships among
    # them, built and linked as a release builds them.
    $row = Invoke-Check 'release' 'cargo build --locked --release --workspace --bins' $cargo @('build', '--locked', '--release', '--workspace', '--bins')
    $built = Join-Path $env:CARGO_TARGET_DIR 'release\ntfs2refs.exe'
    if ($row.Exit -eq 0) {
        $row = Invoke-Check 'release' 'ntfs2refs.exe --version' $built @('--version')
        $row.Detail = (Get-Content -LiteralPath $row.Log -TotalCount 1)
    }
    $failed = @($rows | Where-Object { $_.Exit -ne 0 }).Count -ne 0
}
finally {
    Remove-Item Env:CARGO_TARGET_DIR, Env:CARGO_TERM_COLOR -ErrorAction SilentlyContinue
    & $git -C $workspace worktree remove --force $tree 2>$null | Out-Null
}

$lines = @(
    "Checks run locally on ``$head`` (rustc $release, host ``$hostLine``) by ``lab\Invoke-Checks.ps1``:"
    ''
    '| job | check | result | seconds |'
    '|---|---|---|---|'
)
foreach ($row in $rows) {
    $result = "exit $($row.Exit)" + $(if ($row.Detail) { "; $($row.Detail)" } else { '' })
    $lines += "| $($row.Job) | ``$($row.Check)`` | $result | $($row.Seconds) |"
}
$lines += ''
$lines += $(if ($failed) { '**A check failed.**' } else { 'All checks passed.' })
$lines | ForEach-Object { Write-Host $_ }
if ($Report) { $lines | Set-Content -LiteralPath $Report -Encoding utf8 }
Write-Host "Logs: $logs"
if ($failed) { exit 1 }
