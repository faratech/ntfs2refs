# Package pinned, observed binaries only. No build, VM/device I/O or publication.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$source=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027\candidate3\terminal-evidence\stage'
$evidence=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027\candidate3'
$pins=@(
    @{name='ntfs2refs.exe';bytes=5203456L;sha256='38b5b8d142e612000ee00385efc3b4414293b13abad23f71e576f1c5e412b5f2'},
    @{name='ntfs2refs-bind.exe';bytes=1027072L;sha256='bed60077e59e8dd9b714abcb0e621275ee34ac324acb62d5477c259d3d89a09c'},
    @{name='ntfs2refs-recover.exe';bytes=2208256L;sha256='874c349b5da7b9413a849cf4b2761c52d5c60200cb3e2e6c61117f6bb3fed148'}
)
function Ordinary([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Ordinary package path required.'}
    $parent=if($item.PSIsContainer){$item.Parent}else{$item.Directory}
    while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Package ancestry contains a reparse point.'};$parent=$parent.Parent}
    $item
}
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-New([string]$Path,$Value){
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$result=Get-Content -LiteralPath (Join-Path $evidence 'terminal-evidence\run\result.json') -Raw|ConvertFrom-Json
$post=Get-Content -LiteralPath (Join-Path $evidence 'rust-postcheck\AfterReboot.json') -Raw|ConvertFrom-Json
$saved=Get-Content -LiteralPath (Join-Path $evidence 'passed-checkpoint.json') -Raw|ConvertFrom-Json
if(-not$result.success-or-not$result.source_admitted-or-not$result.rollback_closed-or-not$post.success-or-not$post.report.ordinary_tree_verified-or
    $saved.checkpoint_id-cne'cb6a32e9-f237-4d3f-a807-d97fc73f73a1'){throw 'Recorded conversion/reboot success required.'}
if((Get-PSDrive D).Free-lt64GB+64MB){throw 'Host reserve would be breached.'}
$destination=Join-Path $workspace ('.lab\releases\native-shadow-beta-20261027-'+[guid]::NewGuid().ToString('N'))
$content=Join-Path $destination 'ntfs2refs-native-shadow-beta'
$bin=Join-Path $content 'bin'
New-Item -ItemType Directory -Path $bin -ErrorAction Stop|Out-Null
$rows=@(foreach($pin in $pins){
    $original=Join-Path $source $pin.name;$item=Ordinary $original
    if($item.PSIsContainer-or$item.Length-ne$pin.bytes-or(Hash $original)-cne$pin.sha256){throw 'Pinned producer executable differs.'}
    $held=[IO.File]::Open($original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        $copy=Join-Path $bin $pin.name
        $output=[IO.File]::Open($copy,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$held.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()}
        if((Hash $copy)-cne$pin.sha256){throw 'Packaged executable hash differs.'}
    }finally{$held.Dispose()}
    [ordered]@{path=('bin/'+$pin.name);bytes=$pin.bytes;sha256=$pin.sha256}
})
foreach($doc in @(@('docs\native-shadow-beta-handoff.md','README.md'),@('docs\native-shadow-large-beta.md','RESULTS.md'))){
    $original=Join-Path $workspace $doc[0];$null=Ordinary $original
    Copy-Item -LiteralPath $original -Destination (Join-Path $content $doc[1]) -ErrorAction Stop
    $copy=Join-Path $content $doc[1]
    $rows += [ordered]@{path=$doc[1];bytes=(Get-Item -LiteralPath $copy).Length;sha256=(Hash $copy)}
}
Write-New (Join-Path $content 'manifest.json') ([ordered]@{
    kind='native-shadow-beta-local-handoff';source_commit='4befb3b92aa764a5dfe1eaf935380d75c9962909'
    dirty_patch_sha256='d99591b5f26b887b513260cf01b8e89d114cb173fa86d40869a1053518d313e9'
    windows_build='26300.9457';observed_source_cluster_bytes=65536;observed_target_cluster_bytes=4096;observed_partition_bytes=240GB
    result_sha256=(Hash (Join-Path $evidence 'terminal-evidence\run\result.json'))
    post_reboot_wrapper_sha256=(Hash (Join-Path $evidence 'rust-postcheck\AfterReboot.json'))
    larger_geometry_recovery_qualified=$false;arbitrary_volume_support=$false;payload_independent_scratch=$false
    files=$rows;utc=[DateTime]::UtcNow.ToString('o')
})
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=Join-Path $destination 'ntfs2refs-native-shadow-beta-20261027.zip'
[IO.Compression.ZipFile]::CreateFromDirectory($content,$zip,[IO.Compression.CompressionLevel]::Optimal,$true)
$receipt=[ordered]@{path=$zip;bytes=(Get-Item -LiteralPath $zip).Length;sha256=(Hash $zip);files=$rows.Count+1;published=$false;utc=[DateTime]::UtcNow.ToString('o')}
Write-New (Join-Path $destination 'handoff.json') $receipt
$receipt|ConvertTo-Json -Depth 5 -Compress
