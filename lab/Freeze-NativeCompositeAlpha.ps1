# Offline byte freeze only. Does not build, test, publish, access VM/devices or
# read journals/images/packed payloads. Existing qualification remains scoped.
[CmdletBinding()]param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ConverterSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoverySha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$ConverterSourceRevision,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$RecoverySourceRevision,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ConverterProvenanceSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoveryManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoveryBuildReceiptSha256,
    [switch]$IncludeNativeObservers,
    [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$ObserverManifestSha256=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$converterRoot=Join-Path $base 'compact-admitted-retry-20261028';$recoveryRoot=Join-Path $base 'compact-admitted-interrupt-20261028\recovery-tools'
$converterPin='5e156f089b0fc6a67788154e841a74daad4a61028b16ea41391dc8f84e06f524';$recoveryPin='d48a46b13d9a0c4dfc4c241d038e290a2feb571b1a368fbf54c86f3806302028'
$converterCommit='fe7b9bc754f87319f8bc6d1c51bda6007fca5cb5';$recoveryCommit='d953baa810fb5e92fbc50bf6864cfd204e0f7f7f'
function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Ordinary([string]$Path,[bool]$Directory){$m=Get-Item -LiteralPath $Path -Force;Need ([bool]$m.PSIsContainer -eq $Directory -and -not($m.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Ordinary package path required.';$parent=if($m.PSIsContainer){$m.Parent}else{$m.Directory};while($null -ne $parent){Need (-not($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Package ancestry contains a reparse point.';$parent=$parent.Parent};$m}
function StreamHash([IO.Stream]$Stream){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Write-New([string]$Path,[byte[]]$Bytes){$f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$held=[Collections.Generic.List[IO.FileStream]]::new();$inputs=[Collections.Generic.List[object]]::new();$copied=[Collections.Generic.List[object]]::new();$payloadBytes=[long]0
function Enroll([string]$Source,[string]$Relative,[string]$Pin,[long]$ExpectedBytes,[string]$Role){
    Need ($Relative -cmatch '\A(?:bin|docs|provenance)/[A-Za-z0-9_.-]+\z' -and $Relative -notmatch '\.\.') 'Explicit safe package leaf required.'
    $m=Ordinary $Source $false;Need ($m.Length -gt 0 -and $m.Length -le 16MB -and ($ExpectedBytes -eq -1 -or $m.Length -eq $ExpectedBytes)) 'Frozen input length exceeds bound or pin.'
    $f=[IO.File]::Open($m.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);Need ($f.Length -eq $m.Length) 'Input changed at open.';$actual=StreamHash $f;$f.Position=0
    if($Pin){Need ($Pin -cmatch '\A[0-9a-f]{64}\z' -and $actual -ceq $Pin) 'Supplied input hash differs.'}
    $script:payloadBytes+=$f.Length;Need ($script:payloadBytes+2MB -lt 64MB) 'Payload plus generated-record allowance must remain below64MiB.'
    $row=[pscustomobject]@{source=$m.FullName;relative_path=$Relative;bytes=$f.Length;sha256=$actual;role=$Role;stream=$f};$inputs.Add($row);$row
}
function JsonValue($InputRecord){$InputRecord.stream.Position=0;$r=[IO.StreamReader]::new($InputRecord.stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$r.ReadToEnd()|ConvertFrom-Json}finally{$r.Dispose();$InputRecord.stream.Position=0}}
try{
    Need ($ConverterSha256 -ceq $converterPin -and $RecoverySha256 -ceq $recoveryPin -and $ConverterSourceRevision -ceq $converterCommit -and $RecoverySourceRevision -ceq $recoveryCommit) 'Only the exact reviewed converter/recovery binaries and separately recorded revisions may be frozen.'
    Need ([IO.Path]::IsPathRooted($OutputDirectory) -and -not$OutputDirectory.Contains('..') -and -not$OutputDirectory.Contains('/') -and $OutputDirectory.IndexOf([char]0) -lt 0) 'Fresh absolute local package directory required.'
    $output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\');$releaseRoot=Join-Path $workspace '.lab\releases'
    Need ($output.StartsWith($releaseRoot+'\',[StringComparison]::OrdinalIgnoreCase) -and -not$output.Substring(3).Contains(':') -and -not(Test-Path -LiteralPath $output)) 'Output must be a new child of host .lab\releases.'
    $null=Ordinary (Split-Path $output -Parent) $true
    $converterProvenance=Enroll (Join-Path $converterRoot 'intent.json') 'provenance/converter-dispatch.json' $ConverterProvenanceSha256 -1 'recorded-converter-dispatch-provenance'
    $manifestInput=Enroll (Join-Path $recoveryRoot 'manifest.json') 'provenance/recovery-toolset.json' $RecoveryManifestSha256 -1 'recorded-recovery-toolset-provenance'
    $buildInput=Enroll (Join-Path $recoveryRoot 'build-receipt.json') 'provenance/recovery-build-receipt.json' $RecoveryBuildReceiptSha256 -1 'recorded-recovery-build-receipt'
    $conversion=JsonValue $converterProvenance;$recovery=JsonValue $manifestInput;$build=JsonValue $buildInput
    Need ($conversion.run_id -ceq 'ac098b7437e04d2d928bc2e18f3b5218' -and $conversion.source_commit -ceq $ConverterSourceRevision -and $conversion.pins.'lab-convert-native-composite.exe' -ceq $converterPin) 'Converter dispatch source provenance differs.'
    Need ($recovery.schema_version -eq 1 -and $recovery.kind -ceq 'admitted-compact-recovery-toolset' -and $recovery.source_commit -ceq $RecoverySourceRevision -and @($recovery.tools).Count -eq 1) 'Recovery source/toolset provenance differs.'
    $tool=$recovery.tools[0];Need ($tool.name -ceq 'lab-recover-native-composite.exe' -and $tool.path -ceq (Join-Path $recoveryRoot $tool.name) -and $tool.bytes -eq 2444288 -and $tool.sha256 -ceq $recoveryPin) 'Recovery manifest executable differs.'
    Need ($build.kind -ceq 'recovery-current-source-build-receipt' -and $build.exit_code -eq 0 -and $build.source_commit -ceq $RecoverySourceRevision -and $build.binary_sha256 -ceq $recoveryPin -and $build.command -ceq 'cargo build --release --bin lab-recover-native-composite' -and $build.sealed_binary_unchanged -is [bool] -and $build.sealed_binary_unchanged) 'Recovery build receipt differs; packaging must not build a substitute.'
    $null=Enroll (Join-Path $converterRoot 'lab-convert-native-composite.exe') 'bin/lab-convert-native-composite.exe' $ConverterSha256 4142080 'frozen-lab-converter'
    $null=Enroll $tool.path 'bin/lab-recover-native-composite.exe' $RecoverySha256 $tool.bytes 'frozen-lab-recovery'
    $observerProvenance=$null
    if($IncludeNativeObservers){
        Need ($ObserverManifestSha256 -cmatch '\A[0-9a-f]{64}\z') 'Optional observers require an explicit manifest pin.';$observerRoot=Join-Path $converterRoot 'postcheck-tools'
        $observerInput=Enroll (Join-Path $observerRoot 'manifest.json') 'provenance/observer-toolset.json' $ObserverManifestSha256 -1 'separate-observer-provenance';$observerProvenance=JsonValue $observerInput
        Need ($observerProvenance.schema_version -eq 1 -and $observerProvenance.kind -ceq 'admitted-compact-postcheck-toolset' -and $observerProvenance.source_commit -ceq '64207c9f5124b6d345cd832e9b7269604a43bec7' -and @($observerProvenance.tools).Count -eq 2) 'Known separate observer source manifest required.'
        foreach($known in @(@{name='lab-verify-general-converted.exe';bytes=1597952;sha256='2cb316bdc1bb8606c38f862b55b73d62c194e45d1694c52d5bc9dcbee3ff9d4d'},@{name='lab-general-refs-mutation.exe';bytes=1112576;sha256='f6b3563cd1521b16a9c3b2f4f5f4b2d329cd5d9478840b03c76d737922e244bd'})){$found=@($observerProvenance.tools|Where-Object name -CEQ $known.name);Need ($found.Count -eq 1 -and $found[0].bytes -eq $known.bytes -and $found[0].sha256 -ceq $known.sha256 -and $found[0].path -ceq (Join-Path $observerRoot $known.name)) 'Exact optional observer pin differs.';$null=Enroll $found[0].path ('bin/'+$known.name) $known.sha256 $known.bytes 'optional-separately-built-lab-observer'}
    }else{Need ([string]::IsNullOrEmpty($ObserverManifestSha256)) 'Observer manifest pin supplied without observer selection.'}
    foreach($name in @('native-composite-experimental.md','metadata-write-set.md')){$null=Enroll (Join-Path $workspace ('docs\'+$name)) ('docs/'+$name) '' -1 'current-worktree-documentation-snapshot'}
    $null=Enroll (Join-Path $workspace 'evidence\native-composite-alpha-20261028.json') 'provenance/native-composite-alpha-20261028.json' '' -1 'current-observational-evidence-manifest-not-admission-authority'
    $converterResolved=(& git -C $workspace rev-parse --verify ($ConverterSourceRevision+'^{commit}')) -join '';Need ($LASTEXITCODE -eq 0 -and $converterResolved.Trim() -ceq $ConverterSourceRevision) 'Converter revision is not locally verifiable.'
    $recoveryResolved=(& git -C $workspace rev-parse --verify ($RecoverySourceRevision+'^{commit}')) -join '';Need ($LASTEXITCODE -eq 0 -and $recoveryResolved.Trim() -ceq $RecoverySourceRevision) 'Recovery revision is not locally verifiable.'
    & git -C $workspace diff --quiet --no-ext-diff $ConverterSourceRevision $RecoverySourceRevision -- src crates Cargo.toml Cargo.lock
    $treeExit=$LASTEXITCODE;Need ($treeExit -in @(0,1)) 'Read-only source-tree comparison failed.';$rustTreesEqual=$treeExit -eq 0
    $packagingHead=(& git -C $workspace rev-parse HEAD) -join '';Need ($LASTEXITCODE -eq 0) 'Packaging checkout revision unavailable.'
    $status=@(& git -C $workspace status --porcelain --untracked-files=no -- src crates Cargo.toml Cargo.lock);Need ($LASTEXITCODE -eq 0) 'Current source status unavailable.'
    $mainHash=(Get-FileHash -LiteralPath (Join-Path $workspace 'src\main.rs')).Hash.ToLowerInvariant()
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Approved storage epoch differs; packaging never resets the50-GB baseline.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes 64MB
    # Every input, supplied pin, provenance condition and resource gate above
    # passed before creating the package or copying its first file.
    $null=New-Item -ItemType Directory -Path $output -ErrorAction Stop;foreach($name in @('bin','docs','provenance')){$null=New-Item -ItemType Directory -Path (Join-Path $output $name) -ErrorAction Stop}
    foreach($entry in $inputs){$destination=Join-Path $output $entry.relative_path.Replace('/','\');$entry.stream.Position=0;Need ($entry.stream.Length -eq $entry.bytes -and (StreamHash $entry.stream) -ceq $entry.sha256) 'Held source changed before copying.';$entry.stream.Position=0;$f=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$entry.stream.CopyTo($f,65536);$f.Flush($true)}finally{$f.Dispose()};Need ((Get-Item -LiteralPath $destination).Length -eq $entry.bytes -and (Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant() -ceq $entry.sha256) 'Copied bytes/hash differ.';$copied.Add([pscustomobject]@{relative_path=$entry.relative_path;bytes=$entry.bytes;sha256=$entry.sha256;role=$entry.role;source_path=$entry.source})}
    $instructions=@'
# Frozen experimental native-composite alpha

These exact lab executables are confined to their enrolled disposable Windows
data-volume profile. This directory is an offline byte freeze, not an installer,
general-drive release, permission to operate a disk, or production qualification.
It runs nothing automatically. Hyper-V is test infrastructure; the tools operate
inside the machine owning the volume. Boot conversion remains outside scope.

Read docs/native-composite-experimental.md, especially Recovery, and its exact
evidence limits. The converter must obtain genuine live source admission and
construct/validate its target. Copied reports cannot create that authority.

Before any recovery, preserve the original complete output, request/ticket and
SHA-256 pins, expectation, compact-backing.json, composite-capture.json, exact
changed-clusters.bin identity/hash, independent reconstruction journal, and
original storage bindings. Those payload/recovery artifacts are NOT packaged.
Missing recovery material is not permission to substitute another file or plan.

resume finishes only an already activated offline target. finalize records the
durable HND boundary before native ReFS mounting. Pre-handoff rollback proves the
exact original, records ABT, then checks native NTFS. HND/ABT close old raw replay.
Never clear/repair a marker, force attributes or replay over native-modified data.
Each operation revalidates its own device, journal, backing and lifecycle gates.

Converter and recovery are DIFFERENT executables with DIFFERENT recorded source
commits. See manifest.json and the separate provenance receipts. Equal committed
Rust/dependency trees, when measured, do not establish reproducible builds or a
clean historical working tree. Current docs are a separately hashed snapshot.
Storage estimates remain workload-dependent, including dirty free space, the
test OS, metadata, packed differences and the old/new journal. No claim of low
scratch for arbitrary nonzero data follows from the predominantly zero fixture.
'@
    $instructionBytes=[Text.UTF8Encoding]::new($false).GetBytes($instructions);Write-New (Join-Path $output 'RECOVERY-AND-SCOPE.md') $instructionBytes
    $instructionPin=(Get-FileHash -LiteralPath (Join-Path $output 'RECOVERY-AND-SCOPE.md')).Hash.ToLowerInvariant();$memory=[IO.MemoryStream]::new($instructionBytes);try{Need ((StreamHash $memory) -ceq $instructionPin) 'Instruction readback differs.'}finally{$memory.Dispose()}
    $copied.Add([pscustomobject]@{relative_path='RECOVERY-AND-SCOPE.md';bytes=$instructionBytes.Length;sha256=$instructionPin;role='generated-conservative-operator-instructions';source_path=$null})
    $manifest=[ordered]@{schema_version=1;kind='offline-frozen-native-composite-laboratory-alpha';created_utc=[DateTime]::UtcNow.ToString('o');converter=@{sha256=$ConverterSha256;recorded_source_revision=$ConverterSourceRevision;provenance_sha256=$ConverterProvenanceSha256;build_receipt_available=$false};recovery=@{sha256=$RecoverySha256;recorded_source_revision=$RecoverySourceRevision;toolset_manifest_sha256=$RecoveryManifestSha256;build_receipt_sha256=$RecoveryBuildReceiptSha256};observers=$observerProvenance;committed_rust_dependency_trees_equal=$rustTreesEqual;source_comparison_paths=@('src','crates','Cargo.toml','Cargo.lock');executables_or_commits_identical=$false;historical_working_trees_clean_verified=$false;reproducible_build_verified=$false;current_checkout_is_frozen_build_source=$false;packaging_head=$packagingHead.Trim();packager_source_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();current_source_status=$status;current_source_status_is_packaging_time_only=$true;current_main_rs_sha256=$mainHash;documentation_snapshot_from_current_worktree=$true;files=$copied.ToArray();payload_bytes=$payloadBytes+$instructionBytes.Length;native_tests_run_by_packaging=$false;native_result_scope='Only the exact separately recorded disposable-fixture observations in bundled docs/provenance; no additional qualification inferred by packaging.';general_release_ready=$false;arbitrary_drive_support=$false;boot_conversion_qualified=$false;runtime_or_storage_admission_granted=$false;vm_or_device_actions_performed=$false;journal_images_packed_or_secrets_included=$false;packaged_executable_invocation_performed=$false;read_only_git_queries_performed=$true;storage_epoch_observation=$capacity}
    $manifestBytes=[Text.UTF8Encoding]::new($false).GetBytes(($manifest|ConvertTo-Json -Depth 20));Need ($manifestBytes.Length -le 1MB -and $payloadBytes+$instructionBytes.Length+$manifestBytes.Length -lt 64MB) 'Final package exceeds its strict64MiB bound.'
    Write-New (Join-Path $output 'manifest.json') $manifestBytes;$manifestPin=(Get-FileHash -LiteralPath (Join-Path $output 'manifest.json')).Hash.ToLowerInvariant()
    $memory=[IO.MemoryStream]::new($manifestBytes);try{Need ((StreamHash $memory) -ceq $manifestPin) 'Manifest readback differs.'}finally{$memory.Dispose()}
    [pscustomobject]@{output_directory=$output;manifest_sha256=$manifestPin;files=$copied.Count+1;bytes=$payloadBytes+$instructionBytes.Length+$manifestBytes.Length;general_release_ready=$false;native_tests_run=$false}|ConvertTo-Json
}finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}
