# Pin host-built Rust observers; this does not execute anything in the guest.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
if([guid]$dispatch.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or
    $dispatch.source_resource_profile-cne'experimental_streaming_tree_v2'){throw 'Enrolled streaming candidate required.'}
$destination=Join-Path $root 'rust-postcheck-tools'
if(Test-Path -LiteralPath $destination){throw 'Tool stage already exists; preserve its pins.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 16MB
$tools=@(foreach($name in @('lab-verify-general-converted.exe','lab-general-refs-mutation.exe')){
    $path=Join-Path $workspace ('target\release\'+$name)
    $item=Get-Item -LiteralPath $path
    if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt8MB){throw 'Ordinary bounded Rust observer required.'}
    [pscustomobject]@{name=$name;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
})
New-Item -ItemType Directory -Path $destination|Out-Null
foreach($tool in $tools){
    Copy-Item -LiteralPath (Join-Path $workspace ('target\release\'+$tool.name)) -Destination (Join-Path $destination $tool.name)
    if((Get-FileHash -LiteralPath (Join-Path $destination $tool.name)).Hash.ToLowerInvariant()-cne$tool.sha256){throw 'Observer copy pin differs.'}
}
$patch=(& git -C $workspace diff --binary -- src crates Cargo.toml Cargo.lock rust-toolchain.toml)-join"`n"
$value=@{kind='streaming-v2-rust-postcheck-tools';run_id=$dispatch.run_id;vm_id=$dispatch.vm_id;
    source_commit=(& git -C $workspace rev-parse HEAD).Trim();tools=$tools;
    working_tree_patch_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($patch))).ToLowerInvariant();
    no_guest_execution=$true;utc=[DateTime]::UtcNow.ToString('o')}
$f=[IO.File]::Open((Join-Path $destination 'manifest.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 6));$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
$value|ConvertTo-Json -Depth 6 -Compress
