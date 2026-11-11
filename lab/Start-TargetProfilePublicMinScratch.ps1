# Explicit target-profile public CLI qualification on the unprepared golden source.
# Reuses the reviewed full observer; no VM power/restore/checkpoint or source
# preparation is performed here. The public CLI alone owns native placement.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('dev-drive','standard')][string]$TargetFormat,
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
    [Parameter(Mandatory)][string]$FreshBaselineManifestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FreshBaselineManifestSha256,
    [Parameter(Mandatory)][string]$DirectoryGrowthReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DirectoryGrowthReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$TargetFormat=$TargetFormat.ToLowerInvariant()
$candidateLabRoot=$PSScriptRoot
$candidateAdapterPath=$PSCommandPath
$candidateControllerPath=Join-Path $candidateLabRoot 'Start-PublicMinScratchExperiment.ps1'
$candidateOriginalControllerSha='e20b517d97ff376167d438ba0c37bbf7e2dd5e01b6a02ccac2c01113c838f0e0'
$candidateSourceLease=$null;$candidateAdapterLease=$null
function Hold-CandidateSource([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer-or$item.Length-le0-or$item.Length-gt1MB){throw 'Bounded ordinary dispatcher source required.'}
    $cursor=$item;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse dispatcher ancestry refused.'};if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
    return [IO.File]::Open($item.FullName,'Open','Read','Read')
}
function Candidate-Hash([IO.Stream]$Stream){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$Stream.Position=0}
}
function Replace-CandidateOnce([string]$Name,[string]$Before,[string]$After){
    $beforeText=$Before.Replace("`r`n","`n");$afterText=$After.Replace("`r`n","`n")
    if([regex]::Matches($script:candidateControllerText,[regex]::Escape($beforeText)).Count-ne1){throw ('Frozen public dispatcher anchor differs: '+$Name)}
    $script:candidateControllerText=$script:candidateControllerText.Replace($beforeText,$afterText)
}
try{
    if($ExpectedParent-ne[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'){throw 'Unprepared golden8329 source parent required; caller supplies the exact sealed runtime pins.'}
    $candidateSourceLease=Hold-CandidateSource $candidateControllerPath
    if((Candidate-Hash $candidateSourceLease)-cne$candidateOriginalControllerSha){throw 'Exact reviewed public dispatcher required; it is never edited or silently upgraded.'}
    $reader=[IO.StreamReader]::new($candidateSourceLease,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{$script:candidateControllerText=$reader.ReadToEnd().Replace("`r`n","`n")}finally{$reader.Dispose();$candidateSourceLease.Position=0}
    $candidateAdapterLease=Hold-CandidateSource $candidateAdapterPath
    $candidateAdapterSha=Candidate-Hash $candidateAdapterLease
    $candidateAdapterBytes=$candidateAdapterLease.Length
    Replace-CandidateOnce 'baseline module route' @'
. (Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1')
'@ @'
. (Join-Path $candidateLabRoot 'SourceBaselineSupport.ps1')
'@
    Replace-CandidateOnce 'held helper route' '$path=Join-Path $PSScriptRoot $Name;' '$path=Join-Path $candidateLabRoot $Name;'
    Replace-CandidateOnce 'capacity module route' @'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
'@ @'
    Import-Module (Join-Path $candidateLabRoot 'Lab.psm1') -Force
'@
    # This pinned base already contains the proof-backed duplicate cached-
    # access comparison. Retain that complete observer without another patch.
    Replace-CandidateOnce 'owned stream initialization' @'
$phase='preflight';$process=$null;$nativeExit=$null
'@ @'
$phase='preflight';$process=$null;$nativeExit=$null;$stdoutStream=$null;$stderrStream=$null;$stdoutPipe=$null;$stderrPipe=$null
'@
    Replace-CandidateOnce 'owned public process launch and bounded raw drains' @'
 $process=Start-Process -FilePath $binary -ArgumentList '--drive F --partition 2 --minimize-scratch' -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
'@ @'
 $startInfo=[Diagnostics.ProcessStartInfo]::new();$startInfo.UseShellExecute=$false;$startInfo.CreateNoWindow=$true
 $startInfo.FileName=$binary;$startInfo.Arguments='--drive F --partition 2 --minimize-scratch';$startInfo.WorkingDirectory=$c.stage
 $startInfo.RedirectStandardInput=$true;$startInfo.RedirectStandardOutput=$true;$startInfo.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$startInfo
 $stdoutStream=[IO.File]::Open($stdout,'CreateNew','Write','Read');$stderrStream=[IO.File]::Open($stderr,'CreateNew','Write','Read')
 Need ($process.Start()) 'Public CreateProcess did not return an owned child.'
 $stdoutPipe=$process.StandardOutput.BaseStream;$stderrPipe=$process.StandardError.BaseStream
 $stdoutDrain=$stdoutPipe.CopyToAsync($stdoutStream,65536);$stderrDrain=$stderrPipe.CopyToAsync($stderrStream,65536)
'@
    Replace-CandidateOnce 'synchronized logs before actual terminal observation' @'
 $process.WaitForExit();$clock.Stop();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
'@ @'
 $stdinStream=[IO.File]::Open($stdin,'Open','Read','Read')
 try{Need ($stdinStream.Length-eq5) 'Exact synchronized yes-CRLF input required.';$stdinStream.CopyTo($process.StandardInput.BaseStream,4096);$process.StandardInput.BaseStream.Flush()}finally{$stdinStream.Dispose();$process.StandardInput.Close()}
 $process.WaitForExit();$clock.Stop();$process.Refresh();$nativeExit=$process.ExitCode
 $null=$stdoutDrain.GetAwaiter().GetResult();$null=$stderrDrain.GetAwaiter().GetResult()
 $stdoutStream.Flush($true);$stderrStream.Flush($true);$stdoutStream.Dispose();$stdoutStream=$null;$stderrStream.Dispose();$stderrStream=$null
 $out=Log $stdout;$err=Log $stderr
'@
    Replace-CandidateOnce 'owned streams finally without process kill or retry' @'
finally{if($null-ne$process){$process.Dispose()};foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};$script:closedJsonCache.Clear();$script:labIndexes.Clear()}
'@ @'
finally{foreach($stream in @($stdoutPipe,$stderrPipe,$stdoutStream,$stderrStream)){if($null-ne$stream){try{$stream.Dispose()}catch{}}};if($null-ne$process){$process.Dispose()};foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};$script:closedJsonCache.Clear();$script:labIndexes.Clear()}
'@
    Replace-CandidateOnce 'archive exact derived controller before any guest stage' @'
    New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
'@ @'
    New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
    $derivedPath=Join-Path $root 'clean-candidate-public-controller.ps1';$derivedBytes=[Text.UTF8Encoding]::new($false).GetBytes($candidateControllerText)
    $derivedFile=[IO.File]::Open($derivedPath,'CreateNew','Write','Read');try{$derivedFile.Write($derivedBytes,0,$derivedBytes.Length);$derivedFile.Flush($true)}finally{$derivedFile.Dispose()}
    Need ((Get-FileHash -LiteralPath $derivedPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$candidateDerivedControllerSha) 'Archived derived public controller differs.'
    $null=OpenFreshBaselineHost $derivedPath $candidateDerivedControllerSha 1MB $held $false
    Save 'clean-candidate-dispatch-derivation.json' @{schema_version=1;kind='target-format-public-dispatch-derivation';original_controller_path=$candidateControllerPath;original_controller_sha256=$candidateOriginalControllerSha;derived_controller_path=$derivedPath;derived_controller_sha256=$candidateDerivedControllerSha;adapter_path=$candidateAdapterPath;adapter_sha256=$candidateAdapterSha;source_commit=$SourceCommit;toolset_manifest_sha256=$ToolsetManifestSha256;source_checkpoint=$ExpectedParent;requested_target_format=$TargetFormat;public_argv=@('--drive','F','--partition','2','--minimize-scratch');source_prearranged_by_adapter=$false;baseline_or_product_expectations_replaced=$false;new_qualification_inherited=$false;native_marker_qualified=$false;completion_inferred=$false;vm_power_restore_or_checkpoint_actions=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    Replace-CandidateOnce 'requested profile in pinned guest configuration' 'tools=$tools;source_commit=$SourceCommit;main_bytes=' 'tools=$tools;source_commit=$SourceCommit;target_format=$TargetFormat;main_bytes='
    Replace-CandidateOnce 'actual public argv with explicit target choice' @'
 $binary=Join-Path $c.stage 'ntfs2refs.exe';$cli=@('--drive','F','--partition','2','--minimize-scratch')
'@ @'
 $binary=Join-Path $c.stage 'ntfs2refs.exe';$cli=@('--drive','F','--partition','2','--minimize-scratch','--target-format',$c.target_format)
'@
    Replace-CandidateOnce 'owned process explicit target argument' @'
$startInfo.Arguments='--drive F --partition 2 --minimize-scratch'
'@ @'
$startInfo.Arguments='--drive F --partition 2 --minimize-scratch --target-format '+$c.target_format
'@
    # The host intent, host dispatch and archived derivation each retain the
    # same actual argv. The guest argv above uses its pinned configuration.
    $oldArgv="@('--drive','F','--partition','2','--minimize-scratch')"
    if([regex]::Matches($candidateControllerText,[regex]::Escape($oldArgv)).Count-ne3){throw 'Exactly three frozen host argv receipts required.'}
    $script:candidateControllerText=$candidateControllerText.Replace($oldArgv,"@('--drive','F','--partition','2','--minimize-scratch','--target-format',`$TargetFormat)")
    Replace-CandidateOnce 'standard formatter nonzero is a refusal, not capability qualification' @'
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and-not$out.truncated-and$ioOk) 'Actual public native0/complete stdout/native IO counters required; preserve without retry.'
'@ @'
 if($nativeExit-eq1-and$c.target_format-ceq'standard'){
  Need ($err.text-like'*owned staging standard native format refused*no fallback*') 'Native standard failure was not an actual formatter refusal; preserve without retry.'
  Idle;Protected;$d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
  Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and$p.DiskNumber-eq1-and$p.PartitionNumber-eq2-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Size-eq52GB-and$p.Offset-eq16MB-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source') 'Actual untouched online source NTFS identity required after formatter refusal.'
  $found=[regex]::Matches($out.text,'(?m)^(?:> )?Preparing temporary ReFS metadata storage[.] Recovery files: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32})[ \t]*\r?$');Need ($found.Count-eq1) 'One actual standard-format run path required.';$refusedRoot=$found[0].Groups[1].Value
  foreach($leaf in @('managed-shadow.json','ntfs-preparation','ntfs-preparation-result.json','devices.json','conversion')){Need (-not(Test-Path -LiteralPath (Join-Path $refusedRoot $leaf))) 'Standard formatter refusal must precede source preparation/freeze/certificate/journal conversion.'}
  $selection=Json (Join-Path $refusedRoot 'drive-selection.json');Need ($selection.requested_target_format-ceq'standard'-and$selection.confirmation-ceq'interactive affirmative'-and$selection.source_write_authority-eq$false) 'Actual requested standard selection differs.'
  Save 'standard-format-refusal.json' @{schema_version=1;kind='actual-standard-formatter-refusal';native_exit=1;requested_target_format='standard';actual_argv=$cli;source_online_NTFS=$true;source_preparation_or_freeze_reached=$false;source_certificate_or_journal_created=$false;conversion_completed=$false;unsupported_capability_proven=$false;standard_profile_qualified=$false;safe_no_fallback_refusal_observed=$true;formatter_stdout=(Log (Join-Path $refusedRoot 'shadow.format.stdout.log'));formatter_stderr=(Log (Join-Path $refusedRoot 'shadow.format.stderr.log'));automatic_fallback_or_retry=$false;native_marker_qualified=$false;stable_release=$false}
  Save 'wrapper-result.json' @{schema_version=1;kind='target-profile-formatter-refusal-observation';observation_passed=$true;native_exit_observed=$true;native_exit=1;requested_target_format='standard';conversion_completed=$false;unsupported_capability_proven=$false;standard_profile_qualified=$false;safe_no_fallback_refusal_observed=$true;independent_original_hashes_run=0;source_online_NTFS=$true;automatic_fallback_or_retry=$false;stable_release=$false}
  exit 0
 }
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and-not$out.truncated-and$ioOk) 'Actual public native0/complete stdout/native IO counters required; preserve without retry.'
'@
    Replace-CandidateOnce 'actual source/shadow policy required for positive profile result' @'
 Save 'public-command-performance.json' $metrics
'@ @'
 $shadowPolicy=Json (Join-Path $runRoot 'managed-shadow-policy.json');$sourcePolicy=Json (Join-Path $runRoot 'source-volume-policy.json');$wantedDev=$c.target_format-ceq'dev-drive'
 Need ($shadowPolicy.requested_target_format-ceq$c.target_format-and$shadowPolicy.requested_designation_verified-and$null-ne$shadowPolicy.actual_shadow_policy-and$null-ne$sourcePolicy.actual_source_policy-and$sourcePolicy.requested_target_format-ceq$c.target_format-and$sourcePolicy.requested_designation_matches-eq$true) 'Actual positive shadow/source designation observations required, never unknown/default inferred policy.'
 Need ($shadowPolicy.actual_shadow_policy.developer_volume-is[bool]-and$shadowPolicy.actual_shadow_policy.developer_volume-eq$wantedDev-and$sourcePolicy.actual_source_policy.developer_volume-is[bool]-and$sourcePolicy.actual_source_policy.developer_volume-eq$wantedDev-and$sourcePolicy.source_trust_inferred_from_shadow-eq$false-and$sourcePolicy.explicit_trust_or_filter_configuration_changed-eq$false-and$sourcePolicy.handoff_remains_closed) 'Actual designation must match request; machine trust is independently observed, not inferred or changed.'
 Need ([guid]$shadowPolicy.actual_shadow_policy.binding.identity.disk_guid-eq[guid]$devices.pair.shadow.identity.disk_guid-and[guid]$sourcePolicy.actual_source_policy.binding.identity.disk_guid-eq[guid]$devices.pair.source.identity.disk_guid) 'Policy records belong to different source/shadow volumes.'
 Save 'target-format-policy-observation.json' @{schema_version=1;requested_target_format=$c.target_format;actual_shadow_policy=$shadowPolicy;actual_source_policy=$sourcePolicy;unknown_trust_preserved_as_unknown=$true;policy_configuration_changed=$false;conversion_handoff_remains_closed=$true;stable_release=$false}
 Save 'public-command-performance.json' $metrics
'@
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($candidateControllerText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Derived clean public dispatcher syntax differs; nothing dispatched.'}
    $candidateBytes=[Text.UTF8Encoding]::new($false).GetBytes($candidateControllerText);$hash=[Security.Cryptography.SHA256]::Create()
    try{$candidateDerivedControllerSha=([BitConverter]::ToString($hash.ComputeHash($candidateBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $candidateArguments=@{};foreach($key in $PSBoundParameters.Keys){if($key-cne'TargetFormat'){$candidateArguments[$key]=$PSBoundParameters[$key]}}
    & ([scriptblock]::Create($candidateControllerText)) @candidateArguments
}finally{
    if($null-ne$candidateAdapterLease){$candidateAdapterLease.Dispose()}
    if($null-ne$candidateSourceLease){$candidateSourceLease.Dispose()}
}
