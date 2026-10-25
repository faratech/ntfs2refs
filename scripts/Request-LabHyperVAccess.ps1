<# One-time interactive launcher for the already authorized Hyper-V group grant.
   Run at the desktop; Windows itself presents the UAC consent dialog. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
$helper=Join-Path $PSScriptRoot 'Grant-LabHyperVAccess.ps1'
$outputRoot=Join-Path $workspace '.lab/development'
if(-not(Test-Path -LiteralPath $helper -PathType Leaf)-or-not(Test-Path -LiteralPath $outputRoot -PathType Container)){throw 'Reviewed helper or output directory is absent.'}
foreach($path in @($helper,$outputRoot)){$item=Get-Item -LiteralPath $path -Force;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Hyper-V setup path is a reparse point.'}}
$output=Join-Path $outputRoot ('hyperv-access-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
if(Test-Path -LiteralPath $output){throw 'Fresh Hyper-V setup result required.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$shell=(Get-Command powershell.exe -ErrorAction Stop).Source
$arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -OutputPath "'+$output+'"'
$process=Start-Process -FilePath $shell -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -PassThru -Wait
if($process.ExitCode-ne0-or-not(Test-Path -LiteralPath $output -PathType Leaf)){throw 'Elevated Hyper-V access grant did not complete; no membership claim is made.'}
$result=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
if($result.kind-cne'hyperv-administrators-membership'-or-not$result.verified-or$result.accountSid-cne$identity.User.Value-or-not$result.signOutInRequired){throw 'Elevated membership result differs from this Windows account.'}
Write-Output "Hyper-V Administrators membership verified for $($result.account). Sign out of Windows and sign back in before resuming VM work."
Write-Output "Result: $output"
