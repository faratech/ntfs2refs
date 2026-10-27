# Local frozen-alpha handoff only. No build, VM/device access or publication.
[CmdletBinding()]
param([ValidatePattern('\A(?:[0-9a-f]{40})?\z')][string]$HarnessCommit='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$packageRoot=Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026'
$labRoot=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$engine='96720eff89c7e808983c8d5c9800d475fe62515c'
$corePin='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$frozen=@(
 [pscustomobject]@{name='ntfs2refs.exe';bytes=4927488L;sha256=$corePin},
 [pscustomobject]@{name='ntfs2refs-bind.exe';bytes=961024L;sha256='6aa20fe55a47f34c8d360d95fa432e55ebc0b7e49d080d7bce09ea5d92126483'},
 [pscustomobject]@{name='lab-convert-admitted-tree.exe';bytes=3409920L;sha256='129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'},
 [pscustomobject]@{name='lab-verify-general-converted.exe';bytes=1457664L;sha256='b81990282876a4bd2a8de1ab13f748588d623a3f5e36123ad225c9112a54564a'},
 [pscustomobject]@{name='lab-general-refs-mutation.exe';bytes=1097728L;sha256='f35175710403be6140bb668709a14ce3408b6513c18d3419a233c7232affe18c'}
)
$cases=@(
 [pscustomobject]@{case='Normal';id='4ad0147fdde044fbb9d5073e5bfdbe8d';checkpoint='efa6117b-902f-4495-ba10-c3ac4f23553c';name='alpha-normal-converted-passed-ef9e1456af154eb0b85645a2a094848c'},
 [pscustomobject]@{case='Cancel';id='fd23326c56424b7b94cc4a92658ccb19';checkpoint='1cd601b8-c87d-42a8-a105-b1771fdf2b38';name='alpha-cancel-passed-fd23326c56424b7b94cc4a92658ccb19'},
 [pscustomobject]@{case='Resume';id='c2939b18b2fb4ee8836f859dcf1d13b8';checkpoint='072a065e-7f91-457f-ad27-709271b07014';name='alpha-resume-passed-c2939b18b2fb4ee8836f859dcf1d13b8'},
 [pscustomobject]@{case='RollbackWithoutShadow';id='d769b379604c46fd937d5f4fba3a236a';checkpoint='fc55b0d7-5899-4c1f-9404-4bf4a14b054c';name='alpha-rollbackwithoutshadow-passed-d769b379604c46fd937d5f4fba3a236a'}
)
function Ordinary([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force
 if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw ('Ordinary package path required: '+$Path)}
 $parent=if($item.PSIsContainer){$item.Parent}else{$item.Directory}
 while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Package path ancestry contains a reparse point.'};$parent=$parent.Parent}
}
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Read-Json([string]$Path){
 Ordinary $Path $false;$item=Get-Item -LiteralPath $Path
 if($item.Length-gt2MB){throw 'Bounded package evidence JSON required.'}
 [pscustomobject]@{path=$item.FullName;bytes=[long]$item.Length;sha256=(Hash $Path);value=(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)}
}
function True($Value){($Value-is[bool])-and$Value}
function Fresh-Directory([string]$Path){
 if(Test-Path -LiteralPath $Path){throw ('Fresh directory required: '+$Path)}
 $null=New-Item -ItemType Directory -Path $Path -ErrorAction Stop;Ordinary $Path $true
}
function Write-New([string]$Path,[byte[]]$Bytes){
 $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Json-New([string]$Path,$Value){Write-New $Path ([Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32)))}
function Relative-Destination([string]$Relative){
 if([IO.Path]::IsPathRooted($Relative)-or$Relative.Contains('..')-or$Relative.Contains(':')){throw 'Safe package-relative path required.'}
 $path=[IO.Path]::GetFullPath((Join-Path $contentRoot $Relative))
 if(-not$path.StartsWith($contentRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Package path escapes fresh content root.'}
 Ordinary (Split-Path $path -Parent) $true
 $path
}
$copied=[Collections.Generic.List[object]]::new()
function Copy-Pinned([string]$Source,[string]$Relative,[string]$Pin,[long]$Bytes,[string]$Role){
 if($Pin-cnotmatch'\A[0-9a-f]{64}\z'-or$Bytes-lt0-or$Bytes-gt16MB){throw 'Bounded canonical package pin required.'}
 Ordinary $Source $false;$destination=Relative-Destination $Relative
 $sourceStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($sourceStream.Length-ne$Bytes){throw 'Pinned source length changed.'}
  $hasher=[Security.Cryptography.SHA256]::Create()
  try{$actual=([BitConverter]::ToString($hasher.ComputeHash($sourceStream))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
  if($actual-cne$Pin){throw 'Pinned source bytes changed.'};$sourceStream.Position=0
  $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$sourceStream.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()}
 }finally{$sourceStream.Dispose()}
 if((Get-Item -LiteralPath $destination).Length-ne$Bytes-or(Hash $destination)-cne$Pin){throw 'Copied package bytes differ.'}
 $copied.Add([pscustomobject]@{relative_path=$Relative.Replace('\','/');bytes=$Bytes;sha256=$Pin;source_path=[IO.Path]::GetFullPath($Source);role=$Role})
}
function Evidence-Receipt([string]$Source,[string]$Relative){
 $full=[IO.Path]::GetFullPath($Source)
 if(-not$full.StartsWith($labRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetExtension($full)-cne'.json'-or
  $full-match'(?i)[\\/](?:secrets|credentials)[\\/]'){throw 'Only owned bounded JSON evidence receipts may be packaged.'}
 $record=Read-Json $full;Copy-Pinned $full $Relative $record.sha256 $record.bytes 'observational-evidence-receipt'
}

# Read and validate all gates before creating a handoff directory. These are
# recorded observations, never current VM/device state or runtime authority.
Ordinary $packageRoot $true;Ordinary $labRoot $true
$alpha=Read-Json (Join-Path $packageRoot 'alpha.json')
if($alpha.value.schema_version-ne1-or$alpha.value.engine_commit-cne$engine-or$alpha.value.tag-cne'alpha-native-shadow-20261026'-or
 @($alpha.value.executables).Count-ne5){throw 'Frozen alpha manifest differs.'}
foreach($row in $frozen){
 $actual=@($alpha.value.executables|Where-Object {$_.name-ceq$row.name})
 if($actual.Count-ne1-or$actual[0].bytes-ne$row.bytes-or$actual[0].sha256-cne$row.sha256){throw 'Frozen alpha executable manifest differs from literal candidate pins.'}
 $file=Join-Path (Join-Path $packageRoot 'bin') $row.name;Ordinary $file $false
 if((Get-Item -LiteralPath $file).Length-ne$row.bytes-or(Hash $file)-cne$row.sha256){throw 'Staged frozen executable differs; no rebuild is allowed.'}
}
$matrix=Read-Json (Join-Path $labRoot 'recovery-matrix-result.json')
if($matrix.value.kind-cne'native-shadow-alpha-bounded-recovery-matrix'-or-not(True $matrix.value.success)-or
 [guid]$matrix.value.vm_id-ne$vmId-or$matrix.value.engine_commit-cne$engine-or$matrix.value.executable_sha256-cne$corePin-or
 -not(True $matrix.value.all_prior_checkpoints_preserved)-or-not(True $matrix.value.controlled_process_fault_only)-or$matrix.value.power_loss_qualified-or
 @($matrix.value.cases).Count-ne4){throw 'Completed four-case frozen recovery matrix is required.'}
foreach($case in $cases){
 $actual=@($matrix.value.cases|Where-Object {$_.case-ceq$case.case})
 if($actual.Count-ne1-or[guid]$actual[0].checkpoint_id-ne[guid]$case.checkpoint-or$actual[0].name-cne$case.name){throw 'Recorded case/checkpoint identity differs.'}
}
$captureRoot=Join-Path $labRoot 'marker-capture-448ae48454814e75a45706b2807b8d78'
$markers=Read-Json (Join-Path $captureRoot 'result.json')
if($markers.value.kind-cne'frozen-alpha-readonly-marker-captures'-or-not(True $markers.value.success)-or
 [guid]$markers.value.final_vm_id-ne$vmId-or$markers.value.final_state-cne'Off'-or$markers.value.final_startup_bytes-ne8GB-or
 -not(True $markers.value.all_nine_alpha_checkpoints_present)-or$markers.value.matrix_result_sha256-cne$matrix.sha256-or
 $markers.value.power_loss_qualified-or[guid]$markers.value.observer_checkpoint-ne[guid]'73594b95-1e08-448d-aef1-833c7ba16f93'-or
 @($markers.value.captures).Count-ne3){throw 'Completed three-marker capture/final recorded snapshot state is required.'}
$markerReports=@()
foreach($name in @('Normal','Resume','RollbackWithoutShadow')){
 $capture=@($markers.value.captures|Where-Object {$_.case-ceq$name});$case=@($cases|Where-Object {$_.case-ceq$name})[0]
 if($capture.Count-ne1){throw 'Unique marker capture case required.'}
 $path=[IO.Path]::GetFullPath([string]$capture[0].report)
 if(-not$path.StartsWith((Join-Path $labRoot 'marker-pins')+'\',[StringComparison]::OrdinalIgnoreCase)-or
  [IO.Path]::GetFileName($path)-cne'result.json'){throw 'Owned standalone marker receipt path required.'}
 $receipt=Read-Json $path;$expectedMagic=if($name-ceq'RollbackWithoutShadow'){'N2RABT01'}else{'N2RHND01'}
 $expectedVersion=if($name-ceq'RollbackWithoutShadow'){4}else{3}
 if($receipt.sha256-cne$capture[0].report_sha256-or$receipt.value.kind-cne'native-shadow-alpha-journal-marker-observation'-or
  -not(True $receipt.value.success)-or$receipt.value.case-cne$name-or$receipt.value.case_id-cne$case.id-or
  [guid]$receipt.value.vm_id-ne$vmId-or[guid]$receipt.value.preserved_checkpoint-ne[guid]$case.checkpoint-or
  $receipt.value.marker_magic-cne$expectedMagic-or$receipt.value.marker_version-ne$expectedVersion-or
  $receipt.value.marker_sha256-cne$capture[0].marker_sha256-or$receipt.value.prefix_sha256-cne$capture[0].prefix_sha256-or
  $receipt.value.observation.immutable_sha256-cne$capture[0].immutable_body_sha256-or
  $receipt.value.recovery_or_write_authority_granted-or$receipt.value.source_or_target_raw_image_claimed){throw 'Pinned standalone marker receipt differs.'}
 $markerReports+=[pscustomobject]@{case=$name;record=$receipt}
}
$registry=Read-Json (Join-Path $workspace 'evidence\qualification-registry.json')
if($registry.value.schema_version-ne1-or@($registry.value.profiles|Where-Object {$_.id-ceq'ordinary-ntfs31-refs314-v2'}).Count-ne1){throw 'Current supplemental observational registry profile required.'}

$handoffId=[guid]::NewGuid().ToString('N')
$handoffRoot=Join-Path $packageRoot ('handoff-'+$handoffId);Fresh-Directory $handoffRoot
$contentRoot=Join-Path $handoffRoot 'content';Fresh-Directory $contentRoot
foreach($name in @('bin','docs','evidence')){Fresh-Directory (Join-Path $contentRoot $name)}
foreach($row in $frozen){Copy-Pinned (Join-Path (Join-Path $packageRoot 'bin') $row.name) ('bin\'+$row.name) $row.sha256 $row.bytes 'frozen-candidate-executable'}
Copy-Pinned $alpha.path 'evidence\frozen-alpha.json' $alpha.sha256 $alpha.bytes 'historical-freeze-manifest'
Copy-Pinned $registry.path 'evidence\qualification-registry.supplemental.json' $registry.sha256 $registry.bytes 'supplemental-observational-registry'
foreach($name in @('cli-workflow.md','device-binding-discovery.md','native-shadow-alpha.md','native-shadow-alpha-results.md')){
 $path=Join-Path (Join-Path $workspace 'docs') $name;Ordinary $path $false
 Copy-Pinned $path ('docs\'+$name) (Hash $path) (Get-Item -LiteralPath $path).Length 'operator-documentation'
}
Evidence-Receipt $matrix.path 'evidence\recovery-matrix-result.json'
Evidence-Receipt $markers.path 'evidence\marker-capture-result.json'
Evidence-Receipt (Join-Path $captureRoot 'Resume-shutdown-intent.json') 'evidence\final-observer-shutdown-intent.json'
foreach($row in $markerReports){Evidence-Receipt $row.record.path ('evidence\marker-'+$row.case+'.json')}
$normalRoot=Join-Path $labRoot 'postcheck\ef9e1456af154eb0b85645a2a094848c'
Evidence-Receipt (Join-Path $normalRoot 'result.json') 'evidence\Normal-completion.json'
Evidence-Receipt (Join-Path $normalRoot 'preserved-checkpoint.json') 'evidence\Normal-checkpoint.json'
Evidence-Receipt (Join-Path $normalRoot 'after-reboot-verified.json') 'evidence\Normal-after-reboot.json'
$cancelRoot=Join-Path $labRoot 'fault-cases\fd23326c56424b7b94cc4a92658ccb19'
Evidence-Receipt (Join-Path $cancelRoot 'cancel-result.json') 'evidence\Cancel-result.json'
Evidence-Receipt (Join-Path $cancelRoot 'recovery-preserved-checkpoint.json') 'evidence\Cancel-checkpoint.json'
Evidence-Receipt (Join-Path $cancelRoot 'recovery-after-reboot.json') 'evidence\Cancel-after-reboot.json'
$resumeRoot=Join-Path $labRoot 'fault-cases\c2939b18b2fb4ee8836f859dcf1d13b8'
$resumeController=Read-Json (Join-Path $resumeRoot 'resume-controller-intent.json')
if($resumeController.value.controller_id-cne'b5d5cc65c3ee437b96dfed9460fa72de'){throw 'Qualified resume controller differs.'}
$resumePost=Join-Path $resumeRoot 'resume-postcheck-b5d5cc65c3ee437b96dfed9460fa72de'
Evidence-Receipt (Join-Path $resumePost 'result.json') 'evidence\Resume-completion.json'
Evidence-Receipt (Join-Path $resumeRoot 'resume-preserved-checkpoint.json') 'evidence\Resume-checkpoint.json'
Evidence-Receipt (Join-Path $resumePost 'after-reboot-verified.json') 'evidence\Resume-after-reboot.json'
$rollbackRoot=Join-Path $labRoot 'fault-cases\d769b379604c46fd937d5f4fba3a236a'
Evidence-Receipt (Join-Path $rollbackRoot 'rollback-controller-result.json') 'evidence\RollbackWithoutShadow-completion.json'
Evidence-Receipt (Join-Path $rollbackRoot 'recovery-preserved-checkpoint.json') 'evidence\RollbackWithoutShadow-checkpoint.json'
Evidence-Receipt (Join-Path $rollbackRoot 'recovery-after-reboot.json') 'evidence\RollbackWithoutShadow-after-reboot.json'
$indexPath=Join-Path $contentRoot 'evidence\index.json'
Json-New $indexPath ([ordered]@{schema_version=1;kind='frozen-alpha-observational-evidence-index';engine_commit=$engine;core_executable_sha256=$corePin;
 case_ids=$cases;receipts=@($copied|Where-Object {$_.role-ceq'observational-evidence-receipt'});scope='Historical bounded observations only; no current VM/device identity, runtime admission or replay authority.'})
$copied.Add([pscustomobject]@{relative_path='evidence/index.json';bytes=(Get-Item -LiteralPath $indexPath).Length;sha256=(Hash $indexPath);source_path=$null;role='generated-evidence-index'})
$readme=@'
# ntfs2refs frozen native-shadow alpha

This is a local review handoff of the frozen experimental alpha, not a general
installer or production release. The converter runs on the Windows machine
owning the volumes; Hyper-V was test infrastructure only.

Engine source: 96720eff89c7e808983c8d5c9800d475fe62515c.
Core executable SHA-256:
714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841.

The recorded oracle is Windows 11 build 26300.9457, ReFS 3.14. The bounded
profile is a nonboot NTFS 3.1 data volume, 512-byte logical sectors, 4 KiB
clusters and 1 KiB MFT records; ordinary ASCII names and single unnamed,
uncompressed/unencrypted streams; at most 128 files, 32 directories and 256 MiB
logical contents, subject to exact admission and space checks. The observed
partition was 52 GiB. Advanced semantics, boot/system conversion and broader
Windows/storage compatibility remain excluded or unqualified.
ADS, hard links, DOS short-name aliases, sparse/compressed/encrypted sources,
reparse points, EAs and SACL preservation are outside this alpha profile.

Run from an elevated administrator process. Prepare separately owned source,
matching empty ReFS shadow (label n2r-retained-shadow), and independent journal
storage. Follow docs/device-binding-discovery.md to create fresh device bindings,
then docs/cli-workflow.md for pinned convert and recovery commands. Never reuse
the laboratory's requests, device identities or tickets on another volume.
The three lab-* executables are diagnostic/fault-test tools, not normal operator
entry points. No operation runs merely by extracting this archive.

The four recorded paths are normal conversion, preactivation cancel, controlled
first-flushed-write interruption/resume/finalize, and a separate interrupted
shadowless rollback. Mutation and clean reboot passed in their documented scopes.
These are bounded process-fault results, not storage power-loss qualification or
production certification. Read docs/native-shadow-alpha-results.md for limits.
Native-shadow construction still uses payload-proportional scratch/initialization.

The compiled capability registry predates test evidence; the included supplemental
registry is observational. It cannot grant admission, raw replay or current-image
authority. The original frozen-alpha manifest is preserved as a historical freeze
record, including its original native_qualified value. Marker receipts attest
journal bytes only, not current raw target images or native journal file identity.

manifest.json pins every included payload/document/evidence file (it excludes its
own hash). The external archive-receipt.json pins the ZIP and manifest. No full
journals, disk images, credentials, Microsoft binaries or VM backing files are
included. All original laboratory evidence remains in place.
'@
$readmePath=Join-Path $contentRoot 'README.md';Write-New $readmePath ([Text.UTF8Encoding]::new($false).GetBytes($readme))
$copied.Add([pscustomobject]@{relative_path='README.md';bytes=(Get-Item -LiteralPath $readmePath).Length;sha256=(Hash $readmePath);source_path=$null;role='generated-operator-readme'})
$manifestPath=Join-Path $contentRoot 'manifest.json'
Json-New $manifestPath ([ordered]@{schema_version=1;kind='local-frozen-native-shadow-alpha-handoff';handoff_id=$handoffId;engine_commit=$engine;tag='alpha-native-shadow-20261026';core_executable_sha256=$corePin;
 harness_commit=$(if($HarnessCommit){$HarnessCommit}else{$null});frozen_manifest_sha256=$alpha.sha256;supplemental_registry_sha256=$registry.sha256;
 matrix_sha256=$matrix.sha256;marker_capture_result_sha256=$markers.sha256;power_loss_qualified=$false;production_qualified=$false;
 manifest_excludes_own_hash=$true;files=$copied.ToArray();created_utc=[DateTime]::UtcNow.ToString('o')})

# ZIP contains only the explicitly copied/generated files above. CreateNew
# prevents overwriting any existing artifact; originals are never moved/deleted.
Add-Type -AssemblyName System.IO.Compression
$archivePath=Join-Path $handoffRoot 'ntfs2refs-native-shadow-alpha-20261026.zip'
$zipFile=[IO.File]::Open($archivePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
try{
 $zip=[IO.Compression.ZipArchive]::new($zipFile,[IO.Compression.ZipArchiveMode]::Create,$true)
 try{
  $entries=@($copied|ForEach-Object {$_.relative_path})+@('manifest.json')
  if(@($entries|Sort-Object -Unique).Count-ne$entries.Count){throw 'Duplicate ZIP destination refused.'}
  foreach($relative in ($entries|Sort-Object)){
   $path=Relative-Destination $relative;Ordinary $path $false
   $source=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   try{
    $expected=if($relative-ceq'manifest.json'){$null}else{@($copied|Where-Object {$_.relative_path-ceq$relative})[0]}
    $expectedPin=if($relative-ceq'manifest.json'){Hash $manifestPath}else{$expected.sha256}
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{$actual=([BitConverter]::ToString($hasher.ComputeHash($source))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
    if($actual-cne$expectedPin){throw 'Package content changed before ZIP copy.'};$source.Position=0
    $entry=$zip.CreateEntry($relative,[IO.Compression.CompressionLevel]::Optimal);$target=$entry.Open()
    try{$source.CopyTo($target)}finally{$target.Dispose()}
   }finally{$source.Dispose()}
  }
 }finally{$zip.Dispose()}
 $zipFile.Flush($true)
}finally{$zipFile.Dispose()}
$archiveReceipt=[ordered]@{schema_version=1;kind='local-frozen-alpha-archive-receipt';handoff_id=$handoffId;archive_name=[IO.Path]::GetFileName($archivePath);archive_bytes=(Get-Item -LiteralPath $archivePath).Length;archive_sha256=(Hash $archivePath);manifest_sha256=(Hash $manifestPath);engine_commit=$engine;core_executable_sha256=$corePin;published=$false;created_utc=[DateTime]::UtcNow.ToString('o')}
Json-New (Join-Path $handoffRoot 'archive-receipt.json') $archiveReceipt
[pscustomobject]@{handoff_root=$handoffRoot;archive=$archivePath;receipt=(Join-Path $handoffRoot 'archive-receipt.json');archive_sha256=$archiveReceipt.archive_sha256;published=$false}
