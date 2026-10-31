# Public CLI scaling case on the preserved independently populated NTFS source.
# Root restores/boots the exact snapshot first. This wrapper reads host metadata
# only before delegating to the reviewed dispatcher; it never changes source
# layout, powers/restores the VM, or creates conversion/recovery authority.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$MainSha256,
 [Parameter(Mandatory)][ValidateRange(1,67108864)][int]$MainBytes,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [ValidateRange(1,16777216)][long]$DigestToolBytes=286720,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$DigestToolSha256='e2b344333faa7830ba08507c9cf4960b7388e70f0ae3608b5217030ad292b371',
 [string]$BaselinePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$BaselineSha256,
 [ValidateRange(0,16384)][int]$MinimumExtentOnlyStreams=0,
 [ValidateRange(0,16384)][int]$MinimumTailExtentOnlyStreams=0,
 [ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes=40GB
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Ordinary([string]$Path,[long]$Maximum){
 $full=[IO.Path]::GetFullPath($Path);$m=Get-Item -LiteralPath $full -Force
 Need ($full-ceq$Path-and$full-cmatch'\A[A-Za-z]:\\'-and-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary absolute host file required.'
 $a=$m.Directory;Need (-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host file refused.'
 while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';$a=$a.Parent}
 return $m
}
Need ($ExpectedParent-eq[guid]'6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e') 'Exact preserved mixed NTFS parent required.'
$fixturePath=Join-Path $base 'mixed-fixture-20261029-3dccf8e8fa38487db6731284a12bceb9\fixture.json'
$fixturePin='7810754f1853490d399f87bf1b24f509a8c32716cee84d38babc7c385a487f66'
$null=Ordinary $fixturePath 1MB
Need ((Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$fixturePin) 'Original mixed fixture manifest pin differs.'
$fixture=[IO.File]::ReadAllText($fixturePath)|ConvertFrom-Json
Need ($fixture.files-eq808-and$fixture.directories-eq120-and$fixture.total_bytes-eq9885781381-and$fixture.filesystem-ceq'NTFS'-and$fixture.cluster-eq65536-and$fixture.label-ceq'n2r-stream-source'-and@($fixture.manifest).Count-eq808) 'Original complete 808-file/120-directory NTFS64K fixture required.'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$bytes=0L
foreach($file in $fixture.manifest){
 Need ($file.path-cmatch'\AF:\\[^:\x00\r\n]+\z'-and$seen.Add([string]$file.path)-and$file.length-ge0-and$file.sha256-cmatch'\A[0-9a-f]{64}\z') 'Invalid or duplicate fixture path/length/hash.'
 foreach($component in $file.path.Substring(3).Split('\')){Need ($component.Length-gt0-and$component-notin@('.','..')) 'Fixture traversal or empty component refused.'}
 $bytes+=[long]$file.length
}
Need ($bytes-eq9885781381) 'Complete fixture byte sum differs.'
$manifestFile=Ordinary $ToolsetManifest 1MB
Need ((Get-FileHash -LiteralPath $manifestFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$ToolsetManifestSha256) 'Sealed scaling toolset pin differs.'
$manifest=[IO.File]::ReadAllText($manifestFile.FullName)|ConvertFrom-Json
Need ($manifest.schema_version-eq1-and$manifest.kind-ceq'head-drive-toolset'-and$manifest.source_commit-ceq$SourceCommit-and@($manifest.tools).Count-eq3) 'Sealed public-build provenance required; old helper pins do not inherit new qualification.'
$required=@{
 'ntfs2refs.exe'=@{bytes=$MainBytes;sha256=$MainSha256}
 'lab-content-digest.exe'=@{bytes=$DigestToolBytes;sha256=$DigestToolSha256}
 'lab-query-refs-extents.exe'=@{bytes=1081344;sha256='6722a00cbc4947902eb167086bd62d94d823cc544119f632657d7f188fcc653f'}
}
$toolNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach($tool in $manifest.tools){
 Need (($required.Keys-ccontains[string]$tool.name)-and$toolNames.Add([string]$tool.name)-and$tool.path-ceq(Join-Path $manifestFile.DirectoryName $tool.name)) 'Exact unique toolset leaf/path required.'
 $wanted=$required[$tool.name];$file=Ordinary $tool.path 64MB
 Need ($file.Length-eq$wanted.bytes-and$tool.bytes-eq$wanted.bytes-and$tool.sha256-ceq$wanted.sha256-and(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$wanted.sha256) 'Sealed tool bytes or digest differ.'
}
$receipt=Join-Path $base 'optimized-compact-interrupt-20261029-c0218eb07cc742d8b8cb2b2738e31de3\recovery-cli-rollback-a2e4be16c5f74b588f27ee6ed5ea86cb\closed-recovery\receipt.json'
$parameters=@{
 ToolsetManifest=$ToolsetManifest;ToolsetManifestSha256=$ToolsetManifestSha256
 ExpectedParent=$ExpectedParent;ExpectedCheckpointIds=$ExpectedCheckpointIds
 MainSha256=$MainSha256;MainBytes=$MainBytes;SourceCommit=$SourceCommit
 NtfsReceiptPath=$receipt;NtfsReceiptSha256='049aa2ee3f43b8ed10f34f2a0904204217a41fd992947a36becf4b1c9e656379'
 SourceFixturePath=$fixturePath;SourceFixtureSha256=$fixturePin;ForecastAdditionalBytes=$ForecastAdditionalBytes
 MinimumExtentOnlyStreams=$MinimumExtentOnlyStreams;MinimumTailExtentOnlyStreams=$MinimumTailExtentOnlyStreams
}
if(-not[string]::IsNullOrEmpty($BaselinePath)-or-not[string]::IsNullOrEmpty($BaselineSha256)){
 $parameters.BaselinePath=$BaselinePath;$parameters.BaselineSha256=$BaselineSha256
}
# The dispatcher keeps exact current checkpoint equality, 4GiB/4CPU/noNIC,
# source F:/GPT/NTFS64K, Windows C:, G: and protected old shadow5 checks.
# Its observer derives every count from the new expectation and accepts the
# current native schema without substituting a saved source certificate.
& (Join-Path $PSScriptRoot 'Start-AllocationBoundedConversion.ps1') @parameters
