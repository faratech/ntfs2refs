#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Case,
    [Parameter(Mandatory)][string]$Binaries,
    [Parameter(Mandatory)][string]$Records
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\NativeRegressionCases.ps1"
if (-not $NativeRegressionCases.Contains($Case)) { throw "Unknown native regression $Case" }
$caseSpec = $NativeRegressionCases[$Case]
$argsForSoak = @{ Profile = 'convert'; Seed = 315781002 }
foreach ($key in $caseSpec.Soak.Keys) { $argsForSoak[$key] = $caseSpec.Soak[$key] }
$global:LASTEXITCODE = 0
& "$PSScriptRoot\Invoke-Soak.ps1" -Binaries $Binaries -Records $Records -Rounds 1 @argsForSoak
if ($LASTEXITCODE -ne 0) { throw "Native regression $Case failed" }
$rows = @(Get-Content -LiteralPath (Join-Path $Records 'rounds.jsonl') | ConvertFrom-Json)
if ($rows.Count -ne 1) { throw "$Case must produce exactly one result" }
$row = $rows[0]
Assert-NativeRegressionVerdict $Case $row
$row | Add-Member -NotePropertyName case_id -NotePropertyValue $Case
$row | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Records 'regression.json') -Encoding utf8
