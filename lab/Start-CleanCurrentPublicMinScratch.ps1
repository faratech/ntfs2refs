# Exact clean4d8ca99 public CLI qualification on the unprepared golden source.
# Reuses the reviewed full observer; no VM power/restore/checkpoint or source
# preparation is performed here. The public CLI alone owns native placement.
[CmdletBinding()]
param(
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
    if($SourceCommit-cne'4d8ca993cf660ea7430b9cc8b229553946add82b'-or$ToolsetManifestSha256-cne'77edb210f6236d3e22ec18a2f6cccd043ea0f784ec9a2041afec7be0aba3b396'-or$ExpectedParent-ne[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'){throw 'Exact clean4d8ca99 toolset and unprepared golden8329 parent required.'}
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
    Save 'clean-candidate-dispatch-derivation.json' @{schema_version=1;kind='clean4d8ca99-public-dispatch-derivation';original_controller_path=$candidateControllerPath;original_controller_sha256=$candidateOriginalControllerSha;derived_controller_path=$derivedPath;derived_controller_sha256=$candidateDerivedControllerSha;adapter_path=$candidateAdapterPath;adapter_sha256=$candidateAdapterSha;source_commit=$SourceCommit;toolset_manifest_sha256=$ToolsetManifestSha256;source_checkpoint=$ExpectedParent;public_argv=@('--drive','F','--partition','2','--minimize-scratch');source_prearranged_by_adapter=$false;baseline_or_product_expectations_replaced=$false;new_qualification_inherited=$false;native_marker_qualified=$false;completion_inferred=$false;vm_power_restore_or_checkpoint_actions=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($candidateControllerText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Derived clean public dispatcher syntax differs; nothing dispatched.'}
    $candidateBytes=[Text.UTF8Encoding]::new($false).GetBytes($candidateControllerText);$hash=[Security.Cryptography.SHA256]::Create()
    try{$candidateDerivedControllerSha=([BitConverter]::ToString($hash.ComputeHash($candidateBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $candidateArguments=@{};foreach($key in $PSBoundParameters.Keys){$candidateArguments[$key]=$PSBoundParameters[$key]}
    & ([scriptblock]::Create($candidateControllerText)) @candidateArguments
}finally{
    if($null-ne$candidateAdapterLease){$candidateAdapterLease.Dispose()}
    if($null-ne$candidateSourceLease){$candidateSourceLease.Dispose()}
}
