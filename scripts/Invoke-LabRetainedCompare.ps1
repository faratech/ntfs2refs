<# Bounded Rust ordinary-file smoke test on the enrolled guest OS disk. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$RunTimeoutSeconds=120)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Compare new 8 KiB C: files using Rust, export evidence, cleanly restore installed-clean')){[pscustomobject]@{Action='RustRetainedCompare';DryRun=$true;MemoryBytes=4GB;InputLength=8192;DeviceControls=$false;ConversionQualified=$false};return}
function Get-RetainedCompareHash([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function New-RetainedCompareFixture {
    $source=New-Object byte[] 8192;for($i=1024;$i -lt 1536;$i++){$source[$i]=0x31}
    $shadow=[byte[]]$source.Clone();$shadow[0]=7;$shadow[1536]=9;for($i=1024;$i -lt 1536;$i++){$shadow[$i]=0x62}
    $post=[byte[]]$shadow.Clone();[Array]::Copy($source,1024,$post,1024,512)
    $request=[ordered]@{schema_version=1;sector_size=512;expected_length=8192;source_sha256=(Get-RetainedCompareHash $source);shadow_sha256=(Get-RetainedCompareHash $shadow);retained_ranges=@([ordered]@{offset=1024;length=512;source_sha256=(Get-RetainedCompareHash $source[1024..1535]);shadow_sha256=(Get-RetainedCompareHash $shadow[1024..1535])});max_change_bytes=1024;max_ranges=2}
    $patches=@(foreach($offset in @(0,1536)){[pscustomobject]@{offset=$offset;length=512;before_sha256=(Get-RetainedCompareHash $source[$offset..($offset+511)]);after_sha256=(Get-RetainedCompareHash $shadow[$offset..($offset+511)])}})
    [pscustomobject]@{Source=$source;Shadow=$shadow;Request=$request;Patches=$patches;ExpectedPostimageSha256=(Get-RetainedCompareHash $post)}
}
function Assert-RetainedCompareBaseline($Manifest,$VM,$Checkpoint) {
    $vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';$baseline='eda059b3-6d50-46bb-bdf4-018b99b5b34f'
    if($Manifest.vmId -ine $vmId -or @($Manifest.disks).Count -ne 3){throw 'Unexpected VM or disk inventory.'}
    $ids=@('a95ba3be-96d4-4e6f-995a-d5aff633d768','25c491d0-5f1b-4205-9e6f-fd619706c2b5','1f26ac6a-1f02-4989-b5c8-249596f332fc');$roles=@('os','target','journal')
    for($i=0;$i -lt 3;$i++){$d=@($Manifest.disks|Where-Object role -CEQ $roles[$i]);$size=if($i -eq 2){8GB}else{64GB};if($d.Count -ne 1 -or $d[0].controllerLocation -ne $i -or $d[0].sizeBytes -ne $size -or $d[0].vhdId -ine $ids[$i]){throw 'The original three owned disks are required.'}}
    if([string]$VM.Id -ine $vmId -or $VM.State -ne 'Off' -or $VM.MemoryStartup -ne 4GB -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $baseline){throw 'Require installed-clean, powered off, fixed 4 GiB.'}
    if([string]$Checkpoint.Id -ine $baseline -or $Checkpoint.Name -cne 'installed-clean' -or [string]$Checkpoint.VMId -ine $vmId -or $Checkpoint.State -ne 'Off' -or $Checkpoint.MemoryStartup -ne 4GB -or $Checkpoint.DynamicMemoryEnabled){throw 'Baseline identity changed.'}
    if(@(Get-VMNetworkAdapter -VM $VM|Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On'){throw 'Require disconnected network and Secure Boot.'}
}
function Assert-RetainedCompareBoolean($Object,[string]$Field,[bool]$Expected){if($Object.$Field -isnot [bool] -or $Object.$Field -ne $Expected){throw "Unexpected boolean: $Field."}}
function Assert-RetainedCompareCapabilities($Caps){
    if($Caps.schema_version -ne 1 -or @($Caps.qualified_boot_builds).Count){throw 'Unexpected capability qualification.'}
    Assert-RetainedCompareBoolean $Caps retained_range_comparison $true
    foreach($f in @('native_refs_writer','conversion_writes','journal_recovery')){Assert-RetainedCompareBoolean $Caps $f $false}
}
function Assert-RetainedCompareReport($Report,$Fixture,[string]$GuestRoot) {
    if($Report.schema_version -ne 1 -or $Report.kind -cne 'lab-retained-sector-comparison'){throw 'Unexpected report schema.'}
    $counts=@{compared_bytes=8192;differing_bytes=514;differing_sectors=3;retained_bytes=512;retained_differing_bytes=512;retained_differing_sectors=1;nonretained_differing_bytes=2;patch_bytes=1024;full_scan_input_bytes_read=32768;container_probe_bytes_read=32;total_input_bytes_read=32800}
    foreach($k in $counts.Keys){if($Report.$k -ne $counts[$k]){throw "Unexpected count: $k."}}
    foreach($f in @('executable','retained_file_semantics_verified','native_attestations_verified','allocation_qualified','conversion_qualified','boot_qualified')){Assert-RetainedCompareBoolean $Report $f $false}
    Assert-RetainedCompareBoolean $Report source_shadow_unchanged_after_comparison $true
    foreach($name in @('source','shadow')){$path=[string]$Report.$name.path;if($path.StartsWith('\\?\')){$path=$path.Substring(4)};if($path -cne ($GuestRoot+'\'+$name+'.raw') -or $Report.$name.length -ne 8192 -or $Report.$name.sha256 -cne $Fixture.Request.($name+'_sha256')){throw 'Input identity changed.'}}
    foreach($k in @('schema_version','sector_size','expected_length','source_sha256','shadow_sha256','max_change_bytes','max_ranges')){if([string]$Report.request.$k -cne [string]$Fixture.Request.$k){throw 'Request echo differs.'}}
    if(@($Report.request.retained_ranges).Count -ne 1 -or @($Report.retained_ranges).Count -ne 1 -or @($Report.patches).Count -ne 2){throw 'Unexpected range count.'}
    foreach($k in @('offset','length','source_sha256','shadow_sha256')){if([string]$Report.request.retained_ranges[0].$k -cne [string]$Fixture.Request.retained_ranges[0].$k -or [string]$Report.retained_ranges[0].$k -cne [string]$Fixture.Request.retained_ranges[0].$k){throw 'Retained range differs.'}}
    $r=$Report.retained_ranges[0];if($r.bytes_compared -ne 512 -or $r.differing_bytes -ne 512 -or $r.differing_sectors -ne 1){throw 'Retained observation differs.'};Assert-RetainedCompareBoolean $r hashes_match_request $true
    for($i=0;$i -lt 2;$i++){foreach($k in @('offset','length','before_sha256','after_sha256')){if([string]$Report.patches[$i].$k -cne [string]$Fixture.Patches[$i].$k){throw 'Unexpected sector patch.'}}}
    if($Report.expected_postimage_sha256 -cne $Fixture.ExpectedPostimageSha256){throw 'Hypothetical postimage differs.'}
}
function Assert-RetainedCompareInputs([object[]]$Observed,[object[]]$Expected) {
    $names=@('ntfs2refs.exe','source.raw','shadow.raw','retained-request.json')
    foreach($set in @(@{files=$Observed},@{files=$Expected})){
        if($set.files.Count -ne 4 -or @($set.files.name|Select-Object -Unique).Count -ne 4){throw 'Unexpected input count.'}
        foreach($f in $set.files){$max=if($f.name -ceq 'ntfs2refs.exe'){16MB}elseif($f.name -ceq 'retained-request.json'){128KB}else{8192};if($f.name -cnotin $names -or $f.length -lt 1 -or $f.length -gt $max -or ($f.name -clike '*.raw' -and $f.length -ne 8192) -or $f.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$f.attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))){throw 'Unsafe input metadata.'}}
    }
    foreach($f in $Expected){$a=@($Observed|Where-Object name -CEQ $f.name);if($a.Count -ne 1 -or $a[0].length -ne $f.length -or $a[0].sha256 -cne $f.sha256){throw 'Input changed.'}}
}
function Get-RetainedCompareOutputLimits { @{'comparison.json'=1MB;'capabilities.json'=64KB;'capabilities.stderr'=16KB;'compare.stdout'=16KB;'compare.stderr'=16KB;'run.json'=64KB} }
function Assert-RetainedCompareOutputs([object[]]$Files) {
    $limits=Get-RetainedCompareOutputLimits
    if($Files.Count -ne 6 -or @($Files.name|Select-Object -Unique).Count -ne 6){throw 'Unexpected output count.'}
    foreach($f in $Files){if(-not $limits.ContainsKey([string]$f.name) -or $f.length -lt 0 -or $f.length -gt $limits[$f.name] -or $f.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$f.attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))){throw 'Unsafe output metadata.'};if(($f.name -clike '*.json' -and $f.length -lt 1) -or ($f.name -cnotlike '*.json' -and $f.length -ne 0)){throw 'Unexpected diagnostics or empty JSON.'}}
}
function Assert-RetainedCompareGuestBinding($Binding) {
    if($Binding.computer -cne 'N2R-WIN11' -or $Binding.systemDrive -cne 'C:' -or $Binding.manufacturer -cne 'Microsoft Corporation' -or $Binding.model -cne 'Virtual Machine' -or $Binding.diskUniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or $Binding.diskBytes -ne 64GB -or $Binding.partitionDiskNumber -ne $Binding.diskNumber -or $Binding.driveLetter -cne 'C' -or $Binding.filesystem -cne 'NTFS' -or -not $Binding.volumeUniqueId){throw 'Guest C: is not the enrolled OS disk.'}
    foreach($f in @('diskIsBoot','diskIsSystem','partitionIsBoot')){Assert-RetainedCompareBoolean $Binding $f $true}
}
function Get-RetainedCompareGuestProgram {
    {
        param([string]$Phase,[string]$Id,[object[]]$Expected)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($Id -cnotmatch '\A[0-9a-f]{32}\z' -or $Phase -cnotin @('Setup','Run')){throw 'Invalid smoke invocation.'}
        $root='C:\ntfs2refs\retained-compare\'+$Id
        $system=Get-CimInstance Win32_ComputerSystem;$part=Get-Partition -DriveLetter C;$disk=Get-Disk -Number $part.DiskNumber;$volume=Get-Volume -DriveLetter C
        $binding=[pscustomobject]@{computer=$env:COMPUTERNAME;systemDrive=$env:SystemDrive;manufacturer=$system.Manufacturer;model=$system.Model;diskUniqueId=$disk.UniqueId;diskBytes=$disk.Size;diskNumber=$disk.Number;partitionDiskNumber=$part.DiskNumber;driveLetter=[string]$part.DriveLetter;filesystem=$volume.FileSystem;volumeUniqueId=$volume.UniqueId;diskIsBoot=[bool]$disk.IsBoot;diskIsSystem=[bool]$disk.IsSystem;partitionIsBoot=[bool]$part.IsBoot}
        if($binding.computer -cne 'N2R-WIN11' -or $binding.systemDrive -cne 'C:' -or $binding.manufacturer -cne 'Microsoft Corporation' -or $binding.model -cne 'Virtual Machine' -or $binding.diskUniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or $binding.diskBytes -ne 64GB -or -not $binding.diskIsBoot -or -not $binding.diskIsSystem -or -not $binding.partitionIsBoot -or $binding.filesystem -cne 'NTFS' -or -not $binding.volumeUniqueId){throw 'Guest OS disk enrollment differs.'}
        foreach($dir in @('C:\','C:\ntfs2refs','C:\ntfs2refs\retained-compare')){if(-not (Test-Path -LiteralPath $dir)){if($Phase -cne 'Setup'){throw 'Missing parent.'};New-Item -ItemType Directory -Path $dir|Out-Null};$d=Get-Item -LiteralPath $dir -Force;if(-not $d.PSIsContainer -or ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsafe ancestor.'}}
        if($Phase -ceq 'Setup'){if(Test-Path -LiteralPath $root){throw 'Run directory exists.'};New-Item -ItemType Directory -Path $root|Out-Null;return [pscustomobject]@{runId=$Id;root=$root;binding=$binding}}
        $r=Get-Item -LiteralPath $root -Force;if(-not $r.PSIsContainer -or ($r.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsafe run directory.'}
        $names=@('ntfs2refs.exe','source.raw','shadow.raw','retained-request.json');if($Expected.Count -ne 4 -or @(Get-ChildItem -LiteralPath $root -Force).Count -ne 4){throw 'Unexpected input count.'}
        $before=@(foreach($name in $names){$f=Get-Item -LiteralPath (Join-Path $root $name) -Force;$pin=@($Expected|Where-Object name -CEQ $name);if($pin.Count -ne 1 -or $f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -ne $pin[0].length -or (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin[0].sha256){throw 'Copied input differs.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=$pin[0].sha256;attributes=[int]$f.Attributes}})
        $started=[DateTime]::UtcNow.ToString('o');$exe=Join-Path $root 'ntfs2refs.exe'
        $caps=Start-Process -FilePath $exe -ArgumentList @('capabilities') -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $root 'capabilities.json') -RedirectStandardError (Join-Path $root 'capabilities.stderr')
        if($caps.ExitCode -ne 0){throw 'Capabilities failed; preserve guest.'}
        $argv=@('compare-retained','--source',($root+'\source.raw'),'--shadow',($root+'\shadow.raw'),'--request',($root+'\retained-request.json'),'--output',($root+'\comparison.json'))
        $compare=Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $root 'compare.stdout') -RedirectStandardError (Join-Path $root 'compare.stderr')
        if($compare.ExitCode -ne 0){throw 'Comparison failed; preserve guest.'}
        $after=@(foreach($name in $names){$f=Get-Item -LiteralPath (Join-Path $root $name) -Force;if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Input type changed.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();attributes=[int]$f.Attributes}})
        [ordered]@{schemaVersion=1;kind='rust-retained-comparison-guest';runId=$Id;root=$root;binding=$binding;startedUtc=$started;finishedUtc=[DateTime]::UtcNow.ToString('o');capabilitiesExitCode=$caps.ExitCode;comparisonExitCode=$compare.ExitCode;comparisonArguments=$argv;inputsBefore=$before;inputsAfter=$after;deviceControlsIssued=$false;targetWriteRequestsIssued=$false;conversionQualified=$false}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $root 'run.json') -Encoding UTF8
        $limits=@{'comparison.json'=1MB;'capabilities.json'=64KB;'capabilities.stderr'=16KB;'compare.stdout'=16KB;'compare.stderr'=16KB;'run.json'=64KB}
        if(@(Get-ChildItem -LiteralPath $root -Force).Count -ne 10){throw 'Unexpected artifact count.'}
        $files=@(foreach($name in $limits.Keys){$f=Get-Item -LiteralPath (Join-Path $root $name) -Force;if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -gt $limits[$name]){throw 'Export bound exceeded.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();attributes=[int]$f.Attributes}})
        [pscustomobject]@{runId=$Id;root=$root;files=$files}
    }
}
function Invoke-BoundedRetainedCompare([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60){
    $script:commandIndeterminate=$true;$job=$null
    try{$job=Invoke-Command -Session $session -AsJob -ScriptBlock $ScriptBlock -ArgumentList $Arguments;if(-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)){throw 'Guest deadline exceeded; preserve running branch.'};$answer=@(Receive-Job -Job $job -ErrorAction Stop);if($job.State -ne 'Completed'){throw 'Guest completion unknown.'};$script:commandIndeterminate=$false;$answer}finally{if($job -and $job.State -in @('Completed','Failed','Stopped')){Remove-Job -Job $job -Force}}
}
function Save-RetainedCompareProgress {$record|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8}
function Save-RetainedCompareSource([string]$Source,[string]$Destination,[string]$Sha256) {
    $item=Get-Item -LiteralPath $Source -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -lt 1 -or $item.Length -gt 128KB -or (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256 -or (Test-Path -LiteralPath $Destination)){throw 'Reviewed source identity or destination differs.'}
    Copy-Item -LiteralPath $Source -Destination $Destination
    if((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256 -or (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256){throw 'Reviewed source changed during archival copy.'}
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access required.'}
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-RetainedCompareBaseline $manifest $vm $baseline
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 4GB
$binary=Assert-LabPath -Path (Join-Path $workspace 'target\release\ntfs2refs.exe') -Root $workspace
$binaryItem=Get-Item -LiteralPath $binary -Force
if($binaryItem.PSIsContainer -or $binaryItem.Length -lt 1 -or $binaryItem.Length -gt 16MB){throw 'Release binary exceeds the ordinary-file profile.'}
$binarySha=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
if($binarySha -cne 'a3d3f0ca1c00e01ee481811eac81d3f592f829367e25e20140a10a1437a1155f'){throw 'Release binary differs from the reviewed build.'}
$credential=Import-Clixml -LiteralPath (Assert-LabPath -Path (Join-Path $configuration.Root 'win11\secrets\guest-credential.xml') -Root $configuration.Root)
if($credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential.'}
$runId=[guid]::NewGuid().ToString('N');$guestRoot='C:\ntfs2refs\retained-compare\'+$runId
$outputRoot=Assert-LabPath -Path (Join-Path $configuration.Root ('retained-compare\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) -Root $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'Host case exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$inputRoot=Join-Path $outputRoot 'inputs';$exportRoot=Join-Path $outputRoot 'guest';New-Item -ItemType Directory -Path $inputRoot,$exportRoot|Out-Null
$fixture=New-RetainedCompareFixture
[IO.File]::WriteAllBytes((Join-Path $inputRoot 'source.raw'),$fixture.Source);[IO.File]::WriteAllBytes((Join-Path $inputRoot 'shadow.raw'),$fixture.Shadow)
# Rust serde_json rejects a BOM, so request bytes use explicit UTF-8 without BOM.
[IO.File]::WriteAllText((Join-Path $inputRoot 'retained-request.json'),($fixture.Request|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
Copy-Item -LiteralPath $binary -Destination (Join-Path $inputRoot 'ntfs2refs.exe')
$expected=@(Get-ChildItem -LiteralPath $inputRoot -Force|ForEach-Object{[pscustomobject]@{name=$_.Name;length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();attributes=[int]$_.Attributes}})
Assert-RetainedCompareInputs $expected $expected
if(@($expected|Where-Object name -CEQ 'ntfs2refs.exe')[0].sha256 -cne $binarySha){throw 'Binary changed during archival copy.'}
$record=[ordered]@{schemaVersion=1;kind='rust-retained-comparison-host';runId=$runId;vmId=[string]$manifest.vmId;baselineId=[string]$baseline.Id;status='started';phase='preflight';binarySha256=$binarySha;expectedPostimageSha256=$fixture.ExpectedPostimageSha256;inputs=$expected;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();deviceControlsIssued=$false;targetWriteRequestsIssued=$false;conversionQualified=$false;guestComparisonVerified=$false;evidenceExported=$false;cleanShutdown=$false;baselineRestored=$false;createdUtc=[DateTime]::UtcNow.ToString('o')}
$reviewedRoot=Join-Path $outputRoot 'reviewed-sources';New-Item -ItemType Directory -Path $reviewedRoot|Out-Null
$modulePath=Join-Path $workspace 'lab\Lab.psm1';$record.labModuleSha256=(Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLowerInvariant()
Save-RetainedCompareSource $PSCommandPath (Join-Path $reviewedRoot 'Invoke-LabRetainedCompare.ps1') $record.hostScriptSha256
Save-RetainedCompareSource $modulePath (Join-Path $reviewedRoot 'Lab.psm1') $record.labModuleSha256
$session=$null;$script:commandIndeterminate=$false;Save-RetainedCompareProgress
try {
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null
    $record.phase='guest-connection';Save-RetainedCompareProgress;$deadline=[DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    do{$probe=$null;try{$probe=Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock {$env:COMPUTERNAME};if(Wait-Job -Job $probe -Timeout 10){$reply=@(Receive-Job -Job $probe -ErrorAction Stop);if($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11'){$session=New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop;break}}}catch{}finally{if($probe){Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue}};Start-Sleep -Seconds 2}while([DateTime]::UtcNow -lt $deadline)
    if(-not $session){throw 'PowerShell Direct unavailable.'}
    $setup=@(Invoke-BoundedRetainedCompare -ScriptBlock (Get-RetainedCompareGuestProgram) -Arguments @('Setup',$runId,@()))
    if($setup.Count -ne 1 -or $setup[0].runId -cne $runId -or $setup[0].root -cne $guestRoot){throw 'Unexpected guest setup response.'};Assert-RetainedCompareGuestBinding $setup[0].binding
    foreach($f in $expected){Copy-Item -LiteralPath (Join-Path $inputRoot $f.name) -Destination ($guestRoot+'\'+$f.name) -ToSession $session -ErrorAction Stop}
    $record.phase='rust-comparison';Save-RetainedCompareProgress
    $response=@(Invoke-BoundedRetainedCompare -ScriptBlock (Get-RetainedCompareGuestProgram) -Arguments @('Run',$runId,$expected) -TimeoutSeconds $RunTimeoutSeconds)
    if($response.Count -ne 1 -or $response[0].runId -cne $runId -or $response[0].root -cne $guestRoot){throw 'Unexpected completed guest response.'}
    $files=@($response[0].files);Assert-RetainedCompareOutputs $files;$record.phase='export';Save-RetainedCompareProgress
    foreach($f in $files){$path=Join-Path $exportRoot $f.name;Copy-Item -LiteralPath ($guestRoot+'\'+$f.name) -Destination $path -FromSession $session -ErrorAction Stop;$item=Get-Item -LiteralPath $path -Force;if($item.Length -ne $f.length -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Exported evidence differs.'}}
    $files|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $outputRoot 'export.json') -Encoding UTF8;$record.evidenceExported=$true
    $run=Get-Content -LiteralPath (Join-Path $exportRoot 'run.json') -Raw|ConvertFrom-Json
    if($run.schemaVersion -ne 1 -or $run.kind -cne 'rust-retained-comparison-guest' -or $run.runId -cne $runId -or $run.root -cne $guestRoot -or $run.capabilitiesExitCode -ne 0 -or $run.comparisonExitCode -ne 0 -or -not $run.startedUtc -or -not $run.finishedUtc){throw 'Guest completion differs.'}
    $argv=@('compare-retained','--source',($guestRoot+'\source.raw'),'--shadow',($guestRoot+'\shadow.raw'),'--request',($guestRoot+'\retained-request.json'),'--output',($guestRoot+'\comparison.json'));if(($run.comparisonArguments -join '|') -cne ($argv -join '|')){throw 'Guest command scope differs.'}
    foreach($f in @('deviceControlsIssued','targetWriteRequestsIssued','conversionQualified')){Assert-RetainedCompareBoolean $run $f $false}
    Assert-RetainedCompareGuestBinding $run.binding;Assert-RetainedCompareInputs $run.inputsBefore $expected;Assert-RetainedCompareInputs $run.inputsAfter $expected
    Assert-RetainedCompareCapabilities (Get-Content -LiteralPath (Join-Path $exportRoot 'capabilities.json') -Raw|ConvertFrom-Json)
    Assert-RetainedCompareReport (Get-Content -LiteralPath (Join-Path $exportRoot 'comparison.json') -Raw|ConvertFrom-Json) $fixture $guestRoot
    $record.guestComparisonVerified=$true;$record.phase='clean-shutdown';Save-RetainedCompareProgress
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest|Out-Null
    Invoke-BoundedRetainedCompare -TimeoutSeconds 30 -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE -ne 0){throw 'Clean shutdown failed.'}}|Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3);do{if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow -lt $deadline)
    Assert-RetainedCompareBaseline $manifest (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) (Get-ExactLabCheckpoint -VM (Get-VM -Id ([guid]$manifest.vmId)) -Name installed-clean)
    $record.cleanShutdown=$true;$record.phase='restore';Save-RetainedCompareProgress
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null
    Assert-RetainedCompareBaseline $manifest (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) (Get-ExactLabCheckpoint -VM (Get-VM -Id ([guid]$manifest.vmId)) -Name installed-clean)
    $record.baselineRestored=$true;$record.phase='complete';$record.status='rust-retained-comparison-verified'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.Message;throw}finally{$record.commandCompletionUnknown=$script:commandIndeterminate;$record.finishedUtc=[DateTime]::UtcNow.ToString('o');Save-RetainedCompareProgress;if($session -and -not $script:commandIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue}}
[pscustomobject]@{Status=$record.status;Evidence=$outputRoot;GuestComparisonVerified=$record.guestComparisonVerified;BaselineRestored=$record.baselineRestored;ConversionQualified=$false}
