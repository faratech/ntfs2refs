#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path (Split-Path -Parent $PSScriptRoot) -Parent
function Assert-WorkflowReferences([string]$Yaml, [string]$Name) {
    foreach ($match in [regex]::Matches($Yaml, '(?m)^\s*(?:-\s+)?uses:[ \t]+([^\s#]+)')) {
        $reference = $match.Groups[1].Value.Trim('"', "'")
        if ($reference.StartsWith('./')) {
            if ($reference -notmatch '^\./\.github/workflows/[^/\\]+\.ya?ml$' -or
                -not (Test-Path -LiteralPath (Join-Path $root $reference) -PathType Leaf)) {
                throw "Missing or invalid local workflow in ${Name}: $reference"
            }
        } elseif ($reference -notmatch '^[^@]+@[0-9a-fA-F]{40}$') {
            throw "Expected a 40-hex action pin in ${Name}: $reference"
        }
    }
}

function Assert-ReleaseDependencies([string]$Yaml) {
    $requiredDependencies = [ordered]@{
        package = 'build', 'native', 'soak', 'lab'
        'verify-package' = 'build', 'package'
        publish = 'build', 'verify-package'
    }
    foreach ($job in $requiredDependencies.Keys) {
        $block = [regex]::Match($Yaml, "(?ms)^  ${job}:\r?\n(.*?)(?=^  [\w-]+:\r?$|\z)").Groups[1].Value
        $match = [regex]::Match($block, '(?m)^    needs:[ \t]*\[([^\]]+)\]')
        $needs = @($match.Groups[1].Value -split ',' | ForEach-Object Trim)
        foreach ($dependency in $requiredDependencies[$job]) {
            if ($dependency -cnotin $needs) { throw "$job must depend on $dependency" }
        }
        if ($job -eq 'publish' -and $block -notmatch '(?m)^    if:[ \t]+(?:\$\{\{[ \t]*)?inputs\.publish(?:[ \t]*\}\})?[ \t]*\r?$') {
            throw 'publish must require the explicit publication input'
        }
    }
}

function Assert-Fails([scriptblock]$Test, [string]$Expected) {
    try { & $Test } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
        return
    }
    throw "Expected failure: $Expected"
}

$workflowFiles = Get-ChildItem -LiteralPath (Join-Path $root '.github/workflows'), (Join-Path $root '.github/qualification') -File -Include '*.yml', '*.yaml' -Recurse
foreach ($file in $workflowFiles) { Assert-WorkflowReferences (Get-Content -LiteralPath $file.FullName -Raw) $file.Name }
$release = Get-Content -LiteralPath (Join-Path $root '.github/workflows/release.yml') -Raw
Assert-ReleaseDependencies $release
Assert-Fails { Assert-WorkflowReferences 'uses: actions/checkout@3d3c42e5aac5ba805da76410c181273ba90b1' 'bad-pin' } '40-hex action pin'
Assert-Fails { Assert-WorkflowReferences 'uses: ./.github/workflows/not-present.yml' 'missing-workflow' } 'Missing or invalid local workflow'
Assert-Fails { Assert-ReleaseDependencies ($release.Replace('[build, native, soak, lab]', '[build, native, soak]')) } 'package must depend on lab'
Assert-Fails { Assert-ReleaseDependencies ($release.Replace('[build, verify-package]', '[build, package]')) } 'publish must depend on verify-package'
Assert-Fails { Assert-ReleaseDependencies ($release.Replace('if: inputs.publish', 'if: always()')) } 'explicit publication input'

$coordinator = Join-Path $PSScriptRoot 'Invoke-PrivateQualification.ps1'
$oldRunId = $env:GITHUB_RUN_ID
$oldAttempt = $env:GITHUB_RUN_ATTEMPT
$oldRepository = $env:GITHUB_REPOSITORY
$oldExitCode = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
$callerExitCode = if ($oldExitCode) { $oldExitCode.Value }
$repo = 'example/private-lab'
$request = '1234-2'
$output = Join-Path ([IO.Path]::GetTempPath()) 'fake-qualification-output'
$fixture = @{ calls = $null; scenario = ''; clock = [datetime]::MinValue }

function gh {
    $global:LASTEXITCODE = 0
    $fixture.calls.Add(@($args))
    switch -CaseSensitive ($args[0..1] -join ' ') {
        'repo view' { '{"isPrivate":true}' }
        'workflow run' { }
        'run list' {
            if ($args[-1] -isnot [string] -or $args[-1] -cne 'databaseId,displayTitle' -or $args[-2] -cne '--json') {
                throw 'gh requires one JSON field argument'
            }
            if ($fixture.scenario -eq 'absent') { return '[]' }
            $match = @{ databaseId = 98; displayTitle = "ntfs2refs qualification $request" }
            $rows = if ($fixture.scenario -eq 'duplicate') { @($match, $match) }
                else { @(@{ databaseId = 99; displayTitle = 'ntfs2refs qualification 1234-1' }, $match) }
            ConvertTo-Json -InputObject $rows -Compress
        }
        'run watch' { if ($fixture.scenario -eq 'watch-failed') { $global:LASTEXITCODE = 1 } }
        'run download' { if ($fixture.scenario -eq 'download-failed') { $global:LASTEXITCODE = 1 } }
        default { throw "Unexpected gh command: $($args[0..1] -join ' ')" }
    }
}

function Get-Date { $fixture.clock = $fixture.clock.AddMinutes(16); $fixture.clock }
function Start-Sleep { }
try {
    $env:GITHUB_REPOSITORY = 'example/public'
    $env:GITHUB_RUN_ID = '1234'
    $env:GITHUB_RUN_ATTEMPT = '2'
    foreach ($scenario in 'success', 'absent', 'duplicate', 'watch-failed', 'download-failed') {
        $fixture.scenario = $scenario
        $fixture.clock = [datetime]'2026-01-01T00:00:00Z'
        $calls = [Collections.Generic.List[object]]::new()
        $fixture.calls = $calls
        $invoke = { & $coordinator -Repository $repo -Commit ('a' * 40) -Tag '0.0.5' -Output $output }
        switch ($scenario) {
            'success' { & $invoke }
            'absent' { Assert-Fails $invoke 'No private qualification run' }
            'duplicate' { Assert-Fails $invoke 'Multiple lab runs' }
            'watch-failed' { Assert-Fails $invoke "https://github.com/$repo/actions/runs/98" }
            'download-failed' { Assert-Fails $invoke 'GitHub CLI failed: run download' }
        }
        $expectedCalls = switch ($scenario) { 'absent' { 3 } 'duplicate' { 3 } 'watch-failed' { 4 } default { 5 } }
        if ($calls.Count -ne $expectedCalls -or $calls[1] -cnotcontains "request=$request" -or $calls[1] -cnotcontains 'release_run=1234') {
            throw "Unexpected gh dispatch or call count for $scenario"
        }
        if ($expectedCalls -ge 4 -and ($calls[3][2] -ne 98 -or $calls[3] -cnotcontains '--exit-status')) { throw 'Wrong private run watched' }
        if ($expectedCalls -eq 5 -and ($calls[4][2] -ne 98 -or $calls[4] -cnotcontains "lab-$request" -or $calls[4] -cnotcontains $output)) {
            throw 'Wrong private artifact selected'
        }
    }
} finally {
    $env:GITHUB_REPOSITORY = $oldRepository
    $env:GITHUB_RUN_ID = $oldRunId
    $env:GITHUB_RUN_ATTEMPT = $oldAttempt
    if ($oldExitCode) { $global:LASTEXITCODE = $callerExitCode }
    else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
}
'Release workflow references, dependencies and private coordinator checks passed.'
