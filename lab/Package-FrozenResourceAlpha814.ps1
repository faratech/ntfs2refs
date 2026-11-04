# Public-only v3 packaging: no build, Git, VM/device access, execution or publication.
# Qualification is separately reviewed observational evidence, never runtime authority.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$QualificationPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$QualificationSha256,
    [Parameter(Mandatory)][string]$ReadmePath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReadmeSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$candidate=Join-Path $workspace '.lab\development\release-candidates\resource-publication-cng-814f380'
$sourceCommit='814f380aa38be4d94e2a71ad221c779e5ab4dc7b'
$sourceTree='268200368a49bbf6e4feeb78fa43df141551ac31'
$buildSha='ea6d55adaa40b1bf2bfd04cb7842bdef63b9cbffb0f038697d23ae9330af8f64'
$sourceZipSha='94b94b177293f069d98521ef99e4a9e788a6b9e1977d6ca835f4c718cbc0fcc9'
$pins=@(
    @{name='ntfs2refs';bytes=16946176L;sha256='0f5be1c72b05ff030aad85b21be2c37f32ecccbf214af1ee4d6f7afd4807fafb';destination='ntfs2refs.exe'},
    @{name='lab-resource-diagnostic';bytes=8109056L;sha256='790de5dba9eaf3b17b58fb871e9733f73ee2531de7534c08037bd4e5071b092a';destination='tools/lab-resource-diagnostic.exe'},
    @{name='lab-observe-resource-recovery';bytes=1991168L;sha256='e8a5bd07ad59bf54cd6a22c152b7ac8055ebfb7e37f594af010dda8f13823276';destination='tools/lab-observe-resource-recovery.exe'}
)
$operationKeys=@('normal_conversion','mutation_cold_boot','first_flushed_write_interruption','resume','rollback','early_preparation_cancel','hnd_reconciliation','journal_open_failure','reserve_refusal','guard_copy_fault','independent_observation')
$held=[Collections.Generic.List[object]]::new()
$rows=[Collections.Generic.List[object]]::new()
$destinations=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$evidenceCopies=@{}
$contentRoot=$null
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Add([long]$A,[long]$B){Need ($A -ge 0 -and $B -ge 0 -and $A -le [long]::MaxValue-$B) 'Package byte accounting overflow';return [long]($A+$B)}
function Ordinary([string]$Path,[bool]$Directory){
    Need ([IO.Path]::IsPathRooted($Path) -and [IO.Path]::GetFullPath($Path) -ceq $Path) 'Canonical absolute package path required'
    $item=Get-Item -LiteralPath $Path -Force
    Need (($item -is [IO.DirectoryInfo]) -eq $Directory) 'Package route type differs'
    for($ancestor=$item;$null -ne $ancestor;){
        Need (-not ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Package reparse ancestry refused'
        if($ancestor -is [IO.DirectoryInfo]){$ancestor=$ancestor.Parent}else{$ancestor=$ancestor.Directory}
    }
    return $item
}
function WorkspaceFile([string]$Path){
    $full=if([IO.Path]::IsPathRooted($Path)){[IO.Path]::GetFullPath($Path)}else{[IO.Path]::GetFullPath((Join-Path $workspace $Path))}
    Need ($full.StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase) -and $full -notmatch '(?i)[\\/](?:secrets|credentials)[\\/]') 'Only ordinary workspace inputs are accepted'
    $null=Ordinary $full $false
    return $full
}
function HashStream([IO.Stream]$Stream){$h=[Security.Cryptography.SHA256]::Create();try{$Stream.Position=0;$v=([BitConverter]::ToString($h.ComputeHash($Stream))).Replace('-','').ToLowerInvariant();$Stream.Position=0;return $v}finally{$h.Dispose()}}
function HashFile([string]$Path){$s=[IO.File]::Open($Path,'Open','Read','Read');try{return HashStream $s}finally{$s.Dispose()}}
function Hold([string]$Path,[string]$Sha,[long]$Bytes,[string]$Destination,[string]$Role){
    Need ($Sha -cmatch '\A[0-9a-f]{64}\z' -and $Bytes -gt 0) 'Exact positive input pin required'
    Need ($Destination -cmatch '\A[A-Za-z0-9._/-]+\z' -and $Destination -notmatch '(?:\A|/)\.\.(?:/|\z)' -and $destinations.Add($Destination)) 'Unique safe package-relative path required'
    $path=WorkspaceFile $Path;$s=[IO.File]::Open($path,'Open','Read','Read')
    try{Need ($s.Length -eq $Bytes -and (HashStream $s) -ceq $Sha) 'Held source bytes differ from independently supplied pin';$r=[pscustomobject]@{path=$path;stream=$s;bytes=$Bytes;sha256=$Sha;destination=$Destination;role=$Role};$held.Add($r);return $r}catch{$s.Dispose();throw}
}
function JsonPin([string]$Path,[string]$Sha,[string]$Destination,[string]$Role){
    $path=WorkspaceFile $Path;$item=Get-Item -LiteralPath $path
    Need ($item.Length -gt 0 -and $item.Length -le 8MB -and $item.Extension -ceq '.json') 'Bounded ordinary JSON input required'
    $row=Hold $path $Sha $item.Length $Destination $Role
    $reader=[IO.StreamReader]::new($row.stream,[Text.Encoding]::UTF8,$true,65536,$true)
    try{$text=$reader.ReadToEnd()}finally{$reader.Dispose();$row.stream.Position=0}
    return [pscustomobject]@{row=$row;value=($text|ConvertFrom-Json)}
}
function MeasureTree([string]$Path,[bool]$AllowKnownLabAliases=$false){
    $null=Ordinary $Path $true;$sum=0L;$pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($Path)
    $known=@('allocation-43528b66c82c407c83bcde2008571f87','allocation-7058012df22d44b895f8c43fc127b161')
    while($pending.Count){foreach($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){
            Need $AllowKnownLabAliases 'Capacity census reparse route refused'
            $parent=[IO.Path]::GetFullPath((Split-Path $item.FullName -Parent))
            $expectedParents=@($known|ForEach-Object {Join-Path $workspace ('.lab\tests\'+$_)})
            Need ($parent -cin $expectedParents -and $item.Name -cin @('alias-directory','alias.bin')) 'Unknown .lab reparse route refused'
            $target=@($item.Target)
            Need ($target.Count -eq 1 -and [IO.Path]::IsPathRooted([string]$target[0])) 'Known alias must have one absolute target'
            $resolved=[IO.Path]::GetFullPath([string]$target[0]).TrimEnd('\')
            $expected=if($item.Name -ceq 'alias-directory'){$parent}else{Join-Path $parent 'ordinary file.bin'}
            Need ($resolved -ieq $expected -and (($item.Name -ceq 'alias-directory' -and $item.PSIsContainer -and $item.LinkType -ceq 'Junction') -or ($item.Name -ceq 'alias.bin' -and -not $item.PSIsContainer -and $item.LinkType -ceq 'SymbolicLink'))) 'Known alias type/target differs'
            $null=Ordinary $resolved ([bool]$item.PSIsContainer)
            $sum=Add $sum 65536
            continue
        }
        if($item -is [IO.DirectoryInfo]){$pending.Enqueue($item.FullName)}else{$sum=Add $sum $item.Length}
    }}
    return $sum
}
function Capacity([long]$AdditionalBytes){
    $settings=Get-Content -LiteralPath (Join-Path $workspace 'lab\lab.config.json') -Raw|ConvertFrom-Json
    Need ($settings.maximumActualBytes -eq 329374052988L -and $settings.minimumHostFreeBytes -eq 17179869184L) 'Original capacity policy changed; no epoch/cap reset is allowed'
    $total=0L;foreach($relative in @('.lab','target\shared-experiments','target\shared-experiments-staging')){$total=Add $total (MeasureTree (Join-Path $workspace $relative) ($relative -ceq '.lab'))}
    $free=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($workspace)).AvailableFreeSpace
    Need ($AdditionalBytes -ge 0 -and $AdditionalBytes -le $settings.maximumActualBytes -and $total -le $settings.maximumActualBytes-$AdditionalBytes) 'Complete lab/cache/staging allocation budget would be exceeded'
    Need ($AdditionalBytes -le $free -and $free-$AdditionalBytes -ge $settings.minimumHostFreeBytes) 'Original host free-space reserve would be breached'
    return [ordered]@{actual_bytes=$total;free_bytes=$free;maximum_actual_bytes=[long]$settings.maximumActualBytes;minimum_free_bytes=[long]$settings.minimumHostFreeBytes;additional_bytes=$AdditionalBytes;all_lab_shared_cache_and_staging_charged=$true;epoch_reset=$false}
}
function WriteNew([string]$Path,[byte[]]$Bytes){$f=[IO.File]::Open($Path,'CreateNew','Write','Read');try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function JsonBytes($Value){return [Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24))}
try{
    $build=JsonPin (Join-Path $candidate 'manifest.json') $buildSha 'provenance/build-manifest.json' 'unchanged-build-provenance'
    Need ($build.value.source_commit -ceq $sourceCommit -and $build.value.source_tree -ceq $sourceTree -and $build.value.archive.sha256 -ceq $sourceZipSha -and $build.value.archive.bytes -eq 1819336 -and $build.value.working_tree_inputs_used -eq $false -and $build.value.reproducible_build_verified -eq $false -and $build.value.experimental_shared_target -eq $true -and $build.value.shared_cache_reuse_allowed -eq $true) 'Literal 814 build provenance differs'
    $null=Hold (Join-Path $candidate 'source.zip') $sourceZipSha 1819336 'provenance/source.zip' 'unchanged-committed-source-archive'
    # All three original build rows remain provenance. Only the qualified public
    # executable is copied; unused lab tools gain neither shipment nor claims.
    Need (@($build.value.binaries).Count -eq 3) 'Original three-tool build manifest required'
    foreach($pin in $pins){
        $found=@($build.value.binaries|Where-Object name -CEQ $pin.name)
        Need ($found.Count -eq 1 -and $found[0].bytes -eq $pin.bytes -and $found[0].sha256 -ceq $pin.sha256) 'Build binary pin differs'
        if($pin.name -ceq 'ntfs2refs'){$null=Hold (Join-Path $candidate 'bin\ntfs2refs.exe') $pin.sha256 $pin.bytes 'ntfs2refs.exe' 'frozen-public-executable'}
    }
    $qual=JsonPin $QualificationPath $QualificationSha256 'qualification.json' 'external-observational-qualification'
    $q=$qual.value
    Need ($q.schema_version -eq 1 -and $q.kind -ceq '814-frozen-candidate-observational-qualification' -and $q.source_commit -ceq $sourceCommit -and $q.source_tree -ceq $sourceTree -and $q.build_manifest_sha256 -ceq $buildSha -and $q.source_archive_sha256 -ceq $sourceZipSha) 'External qualification does not bind the exact frozen source/build'
    foreach($name in @('observational_only','native_matrix_complete')){Need (($q.$name -is [bool]) -and $q.$name) 'Reviewed completed observational matrix required'}
    foreach($name in @('grants_runtime_authority','stable_release','power_loss_qualified')){Need (($q.$name -is [bool]) -and -not $q.$name) 'Qualification must remain experimental observational evidence'}
    Need (@($q.binaries).Count -eq $pins.Count) 'Exact three-binary qualification set required'
    foreach($pin in $pins){
        $matches=@($q.binaries|Where-Object name -CEQ $pin.name);Need ($matches.Count -eq 1) 'Unique binary qualification required';$b=$matches[0]
        Need ($b.bytes -eq $pin.bytes -and $b.sha256 -ceq $pin.sha256) 'Exact original build binary pin required'
        Need (($b.shipped -is [bool]) -and $b.shipped -eq ($pin.name -ceq 'ntfs2refs')) 'Public-only shipment must be explicit in every sidecar binary row'
        if($b.shipped){Need (@($b.operations).Count -gt 0) 'Shipped public executable requires its scoped native receipts'}
        # operations=[] is intentional for an unexecuted, unshipped lab tool.
        # Any supplied lab observation is still pinned and scoped below.
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($op in $b.operations){
            Need ($op.key -cin $operationKeys -and $seen.Add($op.key) -and $op.status -ceq 'passed' -and $op.evidence_sha256 -cmatch '\A[0-9a-f]{64}\z') 'Only unique known passed observational operation keys are accepted'
            $evidencePath=WorkspaceFile $op.evidence_path;Need ([IO.Path]::GetExtension($evidencePath) -ceq '.json') 'Operation evidence must be an ordinary workspace JSON receipt'
            $key=$evidencePath.ToLowerInvariant()
            if($evidenceCopies.ContainsKey($key)){Need ($evidenceCopies[$key] -ceq $op.evidence_sha256) 'Conflicting operation evidence pin'}else{$relative='evidence/receipt-'+$evidenceCopies.Count.ToString('D3')+'.json';$null=JsonPin $evidencePath $op.evidence_sha256 $relative 'observational-operation-receipt';$evidenceCopies[$key]=$op.evidence_sha256}
        }
        if($pin.name -ceq 'ntfs2refs'){foreach($key in @('normal_conversion','mutation_cold_boot','resume','rollback')){Need ($seen.Contains($key)) 'Public binary matrix lacks a required scoped native case'}}
    }
    $readmeFile=WorkspaceFile $ReadmePath;$readme=Get-Item -LiteralPath $readmeFile;Need ($readme.Extension -ceq '.md' -and $readme.Length -le 1MB) 'Bounded candidate-specific Markdown README required'
    $null=Hold $readmeFile $ReadmeSha256 $readme.Length 'README.md' 'independently-pinned-candidate-documentation'
    $inputBytes=0L;foreach($row in $held){$inputBytes=Add $inputBytes $row.bytes;$rows.Add([ordered]@{relative_path=$row.destination;bytes=$row.bytes;sha256=$row.sha256;source_path=$row.path;role=$row.role})}
    $manifest=[ordered]@{schema_version=1;kind='local-frozen-814-public-experimental-candidate';shipped_binaries=@('ntfs2refs');unshipped_tools_are_build_provenance_only=$true;unexecuted_tool_qualification_implied=$false;source_commit=$sourceCommit;source_tree=$sourceTree;build_manifest_sha256=$buildSha;qualification_sha256=$QualificationSha256;readme_sha256=$ReadmeSha256;observational_only=$true;grants_runtime_authority=$false;stable_release=$false;published=$false;power_loss_qualified=$false;reproducible_build_verified=$false;experimental_shared_target=$true;shared_cache_reuse_allowed=$true;embedded_registry_rebuilt=$false;manifest_excludes_own_hash=$true;files=$rows.ToArray();created_utc=[DateTime]::UtcNow.ToString('o')}
    $manifestBytes=JsonBytes $manifest;Need ($manifestBytes.Length -le 8MB) 'Bounded package file manifest required'
    $contentBytes=Add $inputBytes $manifestBytes.Length
    # NoCompression keeps a conservative, bounded ZIP forecast close to input
    # size. Fixed ASCII entry names fit the per-entry header/name allowance.
    $zipOverhead=Add 65536 ([long]($held.Count+1)*1024)
    $zipAllowance=Add $contentBytes $zipOverhead
    $required=Add (Add $contentBytes $zipAllowance) 65536
    $before=Capacity $required
    $packageParent=Join-Path $workspace '.lab\packages';if(-not(Test-Path -LiteralPath $packageParent)){$null=New-Item -ItemType Directory -Path $packageParent};$null=Ordinary $packageParent $true
    $packageRoot=Join-Path $packageParent ('frozen-814-public-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $packageRoot
    $contentRoot=Join-Path $packageRoot 'content';$null=New-Item -ItemType Directory -Path $contentRoot
    foreach($directory in @('provenance','evidence')){$null=New-Item -ItemType Directory -Path (Join-Path $contentRoot $directory)}
    $written=0L
    foreach($row in $held){
        Need ($row.stream.Length -eq $row.bytes -and (HashStream $row.stream) -ceq $row.sha256) 'Held source changed before package copy'
        $destination=[IO.Path]::GetFullPath((Join-Path $contentRoot $row.destination));Need ($destination.StartsWith($contentRoot+'\',[StringComparison]::OrdinalIgnoreCase)) 'Package output escaped its root';$null=Ordinary (Split-Path $destination -Parent) $true
        $output=[IO.File]::Open($destination,'CreateNew','Write','Read');try{$row.stream.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()};$row.stream.Position=0
        Need ((Get-Item -LiteralPath $destination).Length -eq $row.bytes -and (HashFile $destination) -ceq $row.sha256) 'Package copy readback differs';$written=Add $written $row.bytes
    }
    $manifestPath=Join-Path $contentRoot 'manifest.json';WriteNew $manifestPath $manifestBytes;$written=Add $written $manifestBytes.Length
    $manifestSha=HashFile $manifestPath;$archivePath=Join-Path $packageRoot 'ntfs2refs-814-public-experimental.zip';$null=Capacity ($required-$written)
    Add-Type -AssemblyName System.IO.Compression
    $archiveFile=[IO.File]::Open($archivePath,'CreateNew','ReadWrite','Read')
    try{$zip=[IO.Compression.ZipArchive]::new($archiveFile,[IO.Compression.ZipArchiveMode]::Create,$true);try{foreach($relative in (@($rows|ForEach-Object relative_path)+@('manifest.json')|Sort-Object)){
        $path=Join-Path $contentRoot $relative;$null=Ordinary $path $false;$s=[IO.File]::Open($path,'Open','Read','Read');try{$expected=if($relative -ceq 'manifest.json'){$manifestSha}else{@($rows|Where-Object relative_path -CEQ $relative)[0].sha256};Need ((HashStream $s) -ceq $expected) 'Package payload changed before ZIP copy';$entry=$zip.CreateEntry($relative,[IO.Compression.CompressionLevel]::NoCompression);$out=$entry.Open();try{$s.CopyTo($out)}finally{$out.Dispose()}}finally{$s.Dispose()}
    }}finally{$zip.Dispose()};$archiveFile.Flush($true);Need ($archiveFile.Length -le $zipAllowance) 'ZIP exceeded its admitted input/header allowance'}finally{$archiveFile.Dispose()}
    $archiveItem=Get-Item -LiteralPath $archivePath;$after=Capacity 65536
    $receipt=[ordered]@{schema_version=1;kind='local-frozen-814-public-package-receipt';shipped_binaries=@('ntfs2refs');unshipped_tools_are_build_provenance_only=$true;archive_name=$archiveItem.Name;archive_bytes=$archiveItem.Length;archive_sha256=(HashFile $archivePath);manifest_sha256=$manifestSha;qualification_sha256=$QualificationSha256;source_commit=$sourceCommit;source_tree=$sourceTree;build_manifest_sha256=$buildSha;stable_release=$false;published=$false;observational_only=$true;grants_runtime_authority=$false;epoch_reset=$false;reserved_additional_bytes=$required;content_bytes=$contentBytes;zip_allowance_bytes=$zipAllowance;capacity_before=$before;capacity_after=$after;utc=[DateTime]::UtcNow.ToString('o')}
    $receiptBytes=JsonBytes $receipt;Need ($receiptBytes.Length -le 65536) 'Archive receipt exceeds its admitted allowance';WriteNew (Join-Path $packageRoot 'archive-receipt.json') $receiptBytes
    [pscustomobject]@{package_root=$packageRoot;archive=$archivePath;archive_sha256=$receipt.archive_sha256;manifest_sha256=$manifestSha;published=$false;stable_release=$false}|ConvertTo-Json -Compress
}finally{foreach($row in $held){$row.stream.Dispose()}}
