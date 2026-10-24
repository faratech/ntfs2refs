[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Status','Media','Create','Start','Stop','Checkpoint','Restore','ExportBaseline','ExportLogs')][string]$Action,
    [ValidateSet('win11','server')][string]$Lane = 'win11',
    [string]$IsoPath,
    [string]$CheckpointName,
    [string]$LogSource
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab\Lab.psm1') -Force
$parameters = @{ Action = $Action; Lane = $Lane; IsoPath = $IsoPath; CheckpointName = $CheckpointName; LogSource = $LogSource; WhatIf = $WhatIfPreference }
if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = $PSBoundParameters.Confirm }
Invoke-LabAction @parameters | ConvertTo-Json -Depth 10
