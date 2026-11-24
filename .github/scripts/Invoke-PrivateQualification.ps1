#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$Commit,
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
if ($Repository -notmatch '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$' -or $Repository -eq $env:GITHUB_REPOSITORY) {
    throw 'Configure the private qualification repository in LAB_QUALIFICATION_REPOSITORY'
}
function Invoke-Gh {
    $result = & gh @args
    if ($LASTEXITCODE -ne 0) { throw "GitHub CLI failed: $($args[0..1] -join ' ')" }
    $result
}
$private = Invoke-Gh repo view $Repository --json isPrivate | ConvertFrom-Json
if (-not $private.isPrivate) { throw 'The lab workflow must be hosted in a private repository' }
$request = "$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
$workflow = 'ntfs2refs-qualification.yml'
Invoke-Gh workflow run $workflow --repo $Repository --ref main `
    -f "request=$request" -f "release_run=$env:GITHUB_RUN_ID" -f "commit=$Commit" -f "tag=$Tag"
$deadline = (Get-Date).AddMinutes(15)
do {
    $runs = @(Invoke-Gh run list --repo $Repository --workflow $workflow --branch main --event workflow_dispatch --limit 30 --json databaseId,displayTitle | ConvertFrom-Json)
    $match = @($runs | Where-Object displayTitle -CEQ "ntfs2refs qualification $request")
    if ($match.Count -gt 1) { throw "Multiple lab runs match $request" }
    if ($match.Count -eq 1) { break }
    Start-Sleep -Seconds 10
} while ((Get-Date) -lt $deadline)
if ($match.Count -ne 1) { throw "No private qualification run for $request" }
$run = $match[0].databaseId
Invoke-Gh run watch $run --repo $Repository --interval 20 --exit-status
Invoke-Gh run download $run --repo $Repository --name "lab-$request" --dir $Output
