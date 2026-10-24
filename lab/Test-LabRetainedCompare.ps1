<# Pure guard tests; no guest, Hyper-V action, or device I/O. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent;$path=Join-Path $workspace 'scripts\Invoke-LabRetainedCompare.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Value){$decoded=$Value|ConvertTo-Json -Depth 20|ConvertFrom-Json;if($decoded -is [array]){foreach($item in $decoded){$item}}else{$decoded}}
$fixture=New-RetainedCompareFixture;$root='C:\ntfs2refs\retained-compare\'+('a'*32)
Check ($fixture.Source.Length -eq 8192 -and $fixture.Shadow.Length -eq 8192) 'Wrong fixture lengths.'
Check ($fixture.ExpectedPostimageSha256 -cne $fixture.Request.source_sha256 -and $fixture.ExpectedPostimageSha256 -cne $fixture.Request.shadow_sha256) 'Postimage must differ from both inputs.'
$differences=@(0..8191|Where-Object{$fixture.Source[$_] -ne $fixture.Shadow[$_]});Check ($differences.Count -eq 514) 'Wrong changed byte count.'
Check (@($differences|Where-Object{$_ -ge 1024 -and $_ -lt 1536}).Count -eq 512) 'Retained differences missing.'
Check (($differences|Where-Object{$_ -lt 1024 -or $_ -ge 1536}) -join ',' -ceq '0,1536') 'Nonretained differences differ.'
Check ($fixture.Patches[0].offset -eq 0 -and $fixture.Patches[1].offset -eq 1536) 'Wrong expected patches.'
$retained=Clone $fixture.Request.retained_ranges[0];$retained|Add-Member bytes_compared 512;$retained|Add-Member differing_bytes 512;$retained|Add-Member differing_sectors 1;$retained|Add-Member hashes_match_request $true
$report=[pscustomobject]@{schema_version=1;kind='lab-retained-sector-comparison';request=(Clone $fixture.Request);source=[pscustomobject]@{path=($root+'\source.raw');length=8192;sha256=$fixture.Request.source_sha256};shadow=[pscustomobject]@{path=($root+'\shadow.raw');length=8192;sha256=$fixture.Request.shadow_sha256};compared_bytes=8192;differing_bytes=514;differing_sectors=3;retained_bytes=512;retained_differing_bytes=512;retained_differing_sectors=1;nonretained_differing_bytes=2;patch_bytes=1024;patches=(Clone $fixture.Patches);retained_ranges=@($retained);expected_postimage_sha256=$fixture.ExpectedPostimageSha256;source_shadow_unchanged_after_comparison=$true;full_scan_input_bytes_read=32768;container_probe_bytes_read=32;total_input_bytes_read=32800;executable=$false;retained_file_semantics_verified=$false;native_attestations_verified=$false;allocation_qualified=$false;conversion_qualified=$false;boot_qualified=$false}
Assert-RetainedCompareReport $report $fixture $root;$script:checks++
$b=Clone $report;$b.source.path='\\?\'+$b.source.path;$b.shadow.path='\\?\'+$b.shadow.path;Assert-RetainedCompareReport $b $fixture $root;$script:checks++
foreach($field in @('schema_version','compared_bytes','differing_bytes','differing_sectors','retained_bytes','retained_differing_bytes','retained_differing_sectors','nonretained_differing_bytes','patch_bytes','full_scan_input_bytes_read','container_probe_bytes_read','total_input_bytes_read')){$b=Clone $report;$b.$field++;Reject {Assert-RetainedCompareReport $b $fixture $root} ('Changed count accepted: '+$field)}
foreach($field in @('executable','retained_file_semantics_verified','native_attestations_verified','allocation_qualified','conversion_qualified','boot_qualified')){$b=Clone $report;$b.$field=$true;Reject {Assert-RetainedCompareReport $b $fixture $root} 'Authority claim accepted.';$b.$field='false';Reject {Assert-RetainedCompareReport $b $fixture $root} 'String false accepted.'}
foreach($field in @('kind','expected_postimage_sha256')){$b=Clone $report;$b.$field='wrong';Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed report identity accepted.'}
$b=Clone $report;$b.source_shadow_unchanged_after_comparison=$false;Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed inputs accepted.'
foreach($name in @('source','shadow')){foreach($field in @('path','sha256','length')){$b=Clone $report;$b.$name.$field=if($field -ceq 'length'){8191}else{'wrong'};Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed input identity accepted.'}}
foreach($field in @('schema_version','sector_size','expected_length','source_sha256','shadow_sha256','max_change_bytes','max_ranges')){$b=Clone $report;$b.request.$field='wrong';Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed request echo accepted.'}
foreach($field in @('offset','length','source_sha256','shadow_sha256')){$b=Clone $report;$b.request.retained_ranges[0].$field='wrong';Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed retained request accepted.';$b=Clone $report;$b.retained_ranges[0].$field='wrong';Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed retained observation accepted.'}
foreach($field in @('bytes_compared','differing_bytes','differing_sectors')){$b=Clone $report;$b.retained_ranges[0].$field++;Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed retained counters accepted.'}
$b=Clone $report;$b.retained_ranges[0].hashes_match_request=$false;Reject {Assert-RetainedCompareReport $b $fixture $root} 'Unbound retained hashes accepted.'
for($i=0;$i -lt 2;$i++){foreach($field in @('offset','length','before_sha256','after_sha256')){$b=Clone $report;$b.patches[$i].$field='wrong';Reject {Assert-RetainedCompareReport $b $fixture $root} 'Changed patch accepted.'}}
foreach($field in @('patches','retained_ranges')){$b=Clone $report;$b.$field=@();Reject {Assert-RetainedCompareReport $b $fixture $root} 'Missing comparison ranges accepted.'}
$b=Clone $report;$b.patches+=Clone $b.patches[0];Reject {Assert-RetainedCompareReport $b $fixture $root} 'Extra patch accepted.'
$caps=[pscustomobject]@{schema_version=1;qualified_boot_builds=@();retained_range_comparison=$true;native_refs_writer=$false;conversion_writes=$false;journal_recovery=$false};Assert-RetainedCompareCapabilities $caps;$script:checks++
foreach($field in @('native_refs_writer','conversion_writes','journal_recovery')){$b=Clone $caps;$b.$field=$true;Reject {Assert-RetainedCompareCapabilities $b} 'Write capability accepted.'}
$b=Clone $caps;$b.qualified_boot_builds=@('test');Reject {Assert-RetainedCompareCapabilities $b} 'Boot qualification accepted.'
$b=Clone $caps;$b.retained_range_comparison=$false;Reject {Assert-RetainedCompareCapabilities $b} 'Missing comparison capability accepted.'
$manifest=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\manifest.json') -Raw|ConvertFrom-Json
$vm=[pscustomobject]@{Id=$manifest.vmId;State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId='eda059b3-6d50-46bb-bdf4-018b99b5b34f'}
$checkpoint=[pscustomobject]@{Id=$vm.ParentSnapshotId;Name='installed-clean';VMId=$vm.Id;State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false}
$script:network='';$script:secureBoot='On'
function Get-VMNetworkAdapter {param($VM);[pscustomobject]@{SwitchName=$script:network}}
function Get-VMFirmware {param($VM);[pscustomobject]@{SecureBoot=$script:secureBoot}}
Assert-RetainedCompareBaseline $manifest $vm $checkpoint;$script:checks++
for($i=0;$i -lt 3;$i++){foreach($field in @('role','controllerLocation','sizeBytes','vhdId')){$b=Clone $manifest;$b.disks[$i].$field='wrong';Reject {Assert-RetainedCompareBaseline $b $vm $checkpoint} 'Changed owned disk accepted.'}}
$b=Clone $manifest;$b.disks=@($b.disks[0],$b.disks[1]);Reject {Assert-RetainedCompareBaseline $b $vm $checkpoint} 'Missing disk accepted.'
foreach($pair in @(@('Id','wrong'),@('State','Running'),@('MemoryStartup',8GB),@('DynamicMemoryEnabled',$true),@('ParentSnapshotId','wrong'))){$b=Clone $vm;$b.($pair[0])=$pair[1];Reject {Assert-RetainedCompareBaseline $manifest $b $checkpoint} 'Unsafe VM branch accepted.'}
foreach($pair in @(@('Id','wrong'),@('Name','wrong'),@('VMId','wrong'),@('State','Running'),@('MemoryStartup',8GB),@('DynamicMemoryEnabled',$true))){$b=Clone $checkpoint;$b.($pair[0])=$pair[1];Reject {Assert-RetainedCompareBaseline $manifest $vm $b} 'Wrong baseline accepted.'}
$script:network='external';Reject {Assert-RetainedCompareBaseline $manifest $vm $checkpoint} 'Connected network accepted.';$script:network='';$script:secureBoot='Off';Reject {Assert-RetainedCompareBaseline $manifest $vm $checkpoint} 'Disabled Secure Boot accepted.';$script:secureBoot='On'
$binding=[pscustomobject]@{computer='N2R-WIN11';systemDrive='C:';manufacturer='Microsoft Corporation';model='Virtual Machine';diskUniqueId='60022480BEA35BA9D496D5AFF633D768';diskBytes=64GB;diskNumber=0;partitionDiskNumber=0;driveLetter='C';filesystem='NTFS';volumeUniqueId='unique';diskIsBoot=$true;diskIsSystem=$true;partitionIsBoot=$true}
Assert-RetainedCompareGuestBinding $binding;$script:checks++
foreach($field in @('computer','systemDrive','manufacturer','model','diskUniqueId','diskBytes','partitionDiskNumber','driveLetter','filesystem','volumeUniqueId')){$b=Clone $binding;$b.$field=if($field -ceq 'volumeUniqueId'){''}else{'wrong'};Reject {Assert-RetainedCompareGuestBinding $b} 'Wrong guest OS identity accepted.'}
foreach($field in @('diskIsBoot','diskIsSystem','partitionIsBoot')){$b=Clone $binding;$b.$field=$false;Reject {Assert-RetainedCompareGuestBinding $b} 'Non-OS guest disk accepted.'}
$inputs=@(foreach($name in @('ntfs2refs.exe','source.raw','shadow.raw','retained-request.json')){[pscustomobject]@{name=$name;length=if($name -clike '*.raw'){8192}else{1024};sha256=('a'*64);attributes=32}})
Assert-RetainedCompareInputs $inputs $inputs;$script:checks++
for($i=0;$i -lt 4;$i++){foreach($pair in @(@('name','..\bad'),@('length',0),@('sha256',('b'*64)),@('attributes',1024))){$b=Clone $inputs;$b[$i].($pair[0])=$pair[1];Reject {Assert-RetainedCompareInputs $b $inputs} 'Changed/unsafe input accepted.'}}
$b=Clone $inputs;$b[0].length=16MB+1;Reject {Assert-RetainedCompareInputs $b $b} 'Oversized executable accepted.'
$b=Clone $inputs;$b[1].length=8191;Reject {Assert-RetainedCompareInputs $b $b} 'Wrong fixture length accepted.'
$outputs=@(foreach($name in (Get-RetainedCompareOutputLimits).Keys){[pscustomobject]@{name=$name;length=if($name -clike '*.json'){1}else{0};sha256=('a'*64);attributes=32}})
Assert-RetainedCompareOutputs $outputs;$script:checks++
foreach($pair in @(@('name','..\bad'),@('length',2MB),@('sha256','wrong'),@('attributes',1024))){$b=Clone $outputs;$b[0].($pair[0])=$pair[1];Reject {Assert-RetainedCompareOutputs $b} 'Unsafe export accepted.'}
foreach($name in @('capabilities.stderr','compare.stderr','compare.stdout')){$b=Clone $outputs;($b|Where-Object name -CEQ $name).length=1;Reject {Assert-RetainedCompareOutputs $b} 'Unexpected diagnostics accepted.'}
$b=Clone $outputs;$b[0].name=$b[1].name;Reject {Assert-RetainedCompareOutputs $b} 'Duplicate export accepted.'
# A timed-out remote command must remain indeterminate and must not be removed.
$script:removed=0;$session='fake'
function Invoke-Command {param($Session,[switch]$AsJob,$ScriptBlock,$ArgumentList);[pscustomobject]@{State=$script:jobState}}
function Wait-Job {param($Job,$Timeout);if($script:jobState -ceq 'Completed'){$Job}}
function Receive-Job {param($Job,$ErrorAction);'done'}
function Remove-Job {param($Job,[switch]$Force);$script:removed++}
$script:jobState='Running';Reject {Invoke-BoundedRetainedCompare -ScriptBlock {}} 'Timeout accepted.';Check $script:commandIndeterminate 'Timeout cleared indeterminate flag.';Check ($script:removed -eq 0) 'Timed-out job removed.'
$script:jobState='Completed';$reply=@(Invoke-BoundedRetainedCompare -ScriptBlock {});Check ($reply.Count -eq 1 -and $reply[0] -ceq 'done' -and -not $script:commandIndeterminate) 'Completed response invalid.';Check ($script:removed -eq 1) 'Completed job not removed.'
# Invalid IDs fail before any guest storage lookup.
$program=Get-RetainedCompareGuestProgram
foreach($id in @('..\bad',('a'*32+[char]10),('a'*31),('a'*33))){Reject {& $program Setup $id @()} 'Invalid guest run ID accepted.'}
Reject {& $program Arbitrary ('a'*32) @()} 'Unknown guest phase accepted.'
$source=Get-Content -LiteralPath $path -Raw
Check (-not ($source -match 'DeviceIoControl|Set-Disk|Format-Volume|Mount-VHD|WriteFile|FSCTL_')) 'Unexpected target/native control in file smoke harness.'
$temporaryRoot=Join-Path ([IO.Path]::GetTempPath()) ('n2r-retained-guards-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot|Out-Null
try{
    $original=Join-Path $temporaryRoot 'original.ps1';$archived=Join-Path $temporaryRoot 'archived.ps1';[IO.File]::WriteAllText($original,'# harmless reviewed source')
    $sha=(Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-RetainedCompareSource $original $archived $sha;Check ((Get-FileHash -LiteralPath $archived -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $sha) 'Source archive changed.'
    Reject {Save-RetainedCompareSource $original $archived $sha} 'Existing archive overwritten.'
    Reject {Save-RetainedCompareSource $original (Join-Path $temporaryRoot 'wrong.ps1') ('a'*64)} 'Wrong source hash accepted.'
    [IO.File]::AppendAllText($original,' changed');Reject {Save-RetainedCompareSource $original (Join-Path $temporaryRoot 'changed.ps1') $sha} 'Changed source archived.'
}finally{
    $resolved=[IO.Path]::GetFullPath($temporaryRoot);$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -cnotmatch '\An2r-retained-guards-[0-9a-f]{32}\z'){throw 'Unsafe temporary cleanup path.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
$dry=& $path -WhatIf;Check ($dry.DryRun -and -not $dry.DeviceControls -and -not $dry.ConversionQualified) 'WhatIf did not remain harmless.'
[pscustomobject]@{Checks=$script:checks;Passed=$true;VMOperations=$false}
