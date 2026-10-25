<# Grant the current account Hyper-V management rights after user approval.
   A new sign-in is required for a new access token to contain this group. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated administrator token required.'}
$group=Get-LocalGroup -Name 'Hyper-V Administrators' -ErrorAction Stop
$before=@(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)
$present=@($before|Where-Object {$_.SID.Value -ceq $identity.User.Value}).Count -gt 0
if(-not$present){Add-LocalGroupMember -Group $group.Name -Member $identity.Name -ErrorAction Stop}
$after=@(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)
$verified=@($after|Where-Object {$_.SID.Value -ceq $identity.User.Value}).Count -eq 1
if(-not$verified){throw 'Hyper-V Administrators membership was not verified.'}
$result=[ordered]@{schemaVersion=1;kind='hyperv-administrators-membership';account=$identity.Name;accountSid=$identity.User.Value;group=$group.Name;groupSid=$group.SID.Value;changed=(-not$present);verified=$verified;signOutInRequired=$true;capturedUtc=[DateTime]::UtcNow.ToString('o')}
$path=[IO.Path]::GetFullPath($OutputPath)
$parent=Split-Path $path -Parent
if(-not(Test-Path -LiteralPath $parent -PathType Container)-or(Test-Path -LiteralPath $path)){throw 'Fresh result path under an existing directory required.'}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 5))
$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]$result
