<# PROPOSED FOR SEPARATE REVIEW. No guest session, credential, initialization,
   attachment, disk setter or zero scan is available in this revision. #>
[CmdletBinding()]param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$RequireZeroScan
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'IsolatedHostIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IsolatedJournalExclusion.psm1') -Force
$root='D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review\'
$full=[IO.Path]::GetFullPath($OutputDirectory)
if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $full) -or [IO.Path]::GetDirectoryName($full) -ine $root.TrimEnd('\') -or
    [IO.Path]::GetFileName($full) -cnotmatch '\Ahost-identity-review-[0-9]{8}T[0-9]{6}[0-9]{3}Z\z'){
    throw 'Fresh direct child host-identity-review-YYYYMMDDTHHMMSSfffZ output required.'
}
$parent=Get-Item -LiteralPath $root -Force
if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Ordinary review parent required.'}
$lease=$null
try{
    $lease=Get-IsolatedHostIdentityLease
    $graph=Test-IsolatedHostIdentityLease $lease
    $contract=Get-IsolatedJournalExclusionContract
    $result=[pscustomobject]@{schema_version=1;host=$lease.snapshot;graph=$graph;exclusion=$contract;
        zero_scan_requested=[bool]$RequireZeroScan;zero_scan_started=$false;guest_session_opened=$false;
        credentials_accessed=$false;source_payload_writes=0;write_authority=$false}
    $json=$result|ConvertTo-Json -Depth 32
    if([Text.Encoding]::UTF8.GetByteCount($json) -gt 16MB){throw 'Bounded host report exceeded 16 MiB.'}
    $null=New-Item -ItemType Directory -Path $full
    $stream=[IO.File]::Open((Join-Path $full 'host-prerequisite.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}
    finally{$stream.Dispose()}
    if($RequireZeroScan){Assert-IsolatedJournalExclusion -HostLease $lease}
    $result
}finally{if($null -ne $lease){Close-IsolatedHostIdentityLease $lease}}
