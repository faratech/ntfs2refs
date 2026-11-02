# Public paged conversion of the separately pinned 1534-object directory fixture.
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
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [Parameter(Mandatory)][string]$AdditionalDirectoryReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AdditionalDirectoryReceiptSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$candidateLabRoot=$PSScriptRoot
$candidateAdapterPath=$PSCommandPath
$candidateControllerPath=Join-Path $candidateLabRoot 'Start-PublicMinScratchExperiment.ps1'
$candidateOriginalControllerSha='e20b517d97ff376167d438ba0c37bbf7e2dd5e01b6a02ccac2c01113c838f0e0'
$candidateSourceLease=$null;$candidateAdapterLease=$null;$candidateExtraLeases=[Collections.Generic.List[IO.FileStream]]::new()
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
    if($ExpectedParent-eq[guid]::Empty-or$ExpectedParent-eq[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'){throw 'Explicit saved post-fixture source checkpoint required; this helper never restores it.'}
    $candidateSourceLease=Hold-CandidateSource $candidateControllerPath
    if((Candidate-Hash $candidateSourceLease)-cne$candidateOriginalControllerSha){throw 'Exact reviewed public dispatcher required; it is never edited or silently upgraded.'}
    $reader=[IO.StreamReader]::new($candidateSourceLease,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{$script:candidateControllerText=$reader.ReadToEnd().Replace("`r`n","`n")}finally{$reader.Dispose();$candidateSourceLease.Position=0}
    $candidateAdapterLease=Hold-CandidateSource $candidateAdapterPath
    $candidateAdapterSha=Candidate-Hash $candidateAdapterLease
    $candidateAdapterBytes=$candidateAdapterLease.Length
    # Hold the frozen extracted sources before their host functions execute.
    $frozenSources=@{
        'Start-AllocationBoundedConversion.ps1'='a6511b32901845f34479a05ed67166c47e9fe673a890c91473cf67a9e1011863'
        'Start-PreparedSourcePerformanceExperiment.ps1'='9eeb4781c49d6246a6928f269c6fc68dd482fb3cddccf3be3f9c89a9ca54337f'
        'SourceBaselineSupport.ps1'='15fbf433444693316832766befda3cf642ba7743d49321e3f9df19c682607b97'
        'PublicMinScratchBaselineSupport.ps1'='d76c66703c831cd67c22bcddcfcf36ed34241ff0aa3e256dbeade8d20b2532ce'
    }
    foreach($name in $frozenSources.Keys){$lease=Hold-CandidateSource (Join-Path $candidateLabRoot $name);$candidateExtraLeases.Add($lease);if((Candidate-Hash $lease)-cne$frozenSources[$name]){throw ('Frozen extracted helper differs: '+$name)}}
    $pagedLease=Hold-CandidateSource (Join-Path $candidateLabRoot 'PagedMetadataObserverSupport.ps1');$candidateExtraLeases.Add($pagedLease);$candidatePagedSupportSha=Candidate-Hash $pagedLease
    if($candidatePagedSupportSha-cne'fe478fea7f63015f6d6140154a32380fcb768b1a41a520616e1e3a6ad146c2d2'){throw 'Frozen actual product paged observer differs.'}
    $largeLease=Hold-CandidateSource (Join-Path $candidateLabRoot 'LargePagedBaselineSupport.ps1');$candidateExtraLeases.Add($largeLease);$candidateLargeSupportSha=Candidate-Hash $largeLease
    $additionalLease=Hold-CandidateSource $AdditionalDirectoryReceiptPath;$candidateExtraLeases.Add($additionalLease);if((Candidate-Hash $additionalLease)-cne$AdditionalDirectoryReceiptSha256){throw 'Pinned extra directory receipt differs.'}
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
    Save 'clean-candidate-dispatch-derivation.json' @{schema_version=1;kind='large-paged-resource-public-dispatch-derivation';original_controller_path=$candidateControllerPath;original_controller_sha256=$candidateOriginalControllerSha;derived_controller_path=$derivedPath;derived_controller_sha256=$candidateDerivedControllerSha;adapter_path=$candidateAdapterPath;adapter_sha256=$candidateAdapterSha;source_commit=$SourceCommit;toolset_manifest_sha256=$ToolsetManifestSha256;source_checkpoint=$ExpectedParent;public_argv=@('--drive','F','--partition','2','--minimize-scratch');source_prearranged_by_adapter=$false;baseline_or_product_expectations_replaced=$false;new_qualification_inherited=$false;native_marker_qualified=$false;completion_inferred=$false;vm_power_restore_or_checkpoint_actions=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    Replace-CandidateOnce 'exact fifth independent observer role' '@($manifest.tools).Count-eq4' '@($manifest.tools).Count-eq5'
    Replace-CandidateOnce 'fifth role source pins' 'foreach($name in @(''ntfs2refs.exe'',''lab-convert-native-composite.exe'',''lab-content-digest.exe'',''lab-managed-shadow.exe'')){' 'foreach($name in @(''ntfs2refs.exe'',''lab-convert-native-composite.exe'',''lab-content-digest.exe'',''lab-managed-shadow.exe'',''lab-inspect-paged-metadata.exe'')){'
    Replace-CandidateOnce 'paged observer sources held and derived from exact original AST' @'
    $self=HeldScript 'Start-PublicMinScratchExperiment.ps1'
'@ @'
    $self=HeldScript 'Start-PublicMinScratchExperiment.ps1'
    $pagedSupport=HeldScript 'PagedMetadataObserverSupport.ps1'
    Need ($pagedSupport.sha256-ceq$candidatePagedSupportSha-and$support.sha256-ceq'15fbf433444693316832766befda3cf642ba7743d49321e3f9df19c682607b97') 'Held original and new paged observer support differ.'
    $legacyNodes=@($support.ast.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'AssertLabV3Envelope'},$true))
    Need ($legacyNodes.Count-eq1) 'One original schema1 envelope validator required.'
    $legacyV3Envelope=ReplaceOnce $legacyNodes[0].Extent.Text 'function AssertLabV3Envelope(' 'function AssertLegacyLabV3Envelope('
'@
    Replace-CandidateOnce 'strict derived map observer before any stage' @'
    $definitions.Add((LiteralAssignment $performance.ast 'sourceZeroFallback'))
'@ @'
    $mapNodes=@($bodyAst.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]-and$_.Name-ceq'AssertLabExtentScope'})
    Need ($mapNodes.Count-eq1) 'One frozen complete extent observer required.'
    $pagedExtentObserver=$mapNodes[0].Extent.Text
    $pagedExtentObserver=ReplaceOnce $pagedExtentObserver '$path=Join-Path $Records ''recovery-payload-manifest.json''' '$path=Join-Path $Records ''recovery-payload-manifest.pages'''
    $pagedExtentObserver=ReplaceOnce $pagedExtentObserver '$manifest=Json $path;' '$typedPages=Get-PagedMetadataInspection $Records;$manifest=$typedPages.complete_recovery_map_inspection;'
    $pagedExtentObserver=ReplaceOnce $pagedExtentObserver '$manifest.schema_version-eq1-and$manifest.kind-ceq''protected-target-stream-map-facts-v1''' '$manifest.schema_version-eq1-and$manifest.kind-ceq''read-only-pinned-recovery-map-pages-inspection'''
    $pagedExtentObserver=ReplaceOnce $pagedExtentObserver '-and@($manifest.bindings).Count-eq$fresh.stream_and_directory_bindings' '-and$manifest.bindings-eq$fresh.stream_and_directory_bindings'
    $pagedExtentObserver=ReplaceOnce $pagedExtentObserver 'bindings=@($manifest.bindings).Count;' 'bindings=$manifest.bindings;'
    $definitions.Add((LiteralAssignment $performance.ast 'sourceZeroFallback'))
'@
    Replace-CandidateOnce 'record new support origin' '$origins=@($normal,$performance,$support,$moveSupport,$self)' '$origins=@($normal,$performance,$support,$moveSupport,$self,$pagedSupport)'
    Replace-CandidateOnce 'actual guest paged file owners' '$script:labFreshBaseline=$null;$script:labBaselineContext=$null;$script:publicPreparationFacts=$null' '$script:labFreshBaseline=$null;$script:labBaselineContext=$null;$script:publicPreparationFacts=$null;$script:pagedInspectionCache=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase);$script:pagedMetadataHeld=[Collections.Generic.List[IO.FileStream]]::new()'
    Replace-CandidateOnce 'new function overrides follow complete original definitions' @'
    $guest=$guest.Replace('__FUNCTIONS__',($definitions-join[Environment]::NewLine)).Replace('__NORMAL_OBSERVER__',$observer)
'@ @'
    $pagedFunctions=$legacyV3Envelope+[Environment]::NewLine+[IO.File]::ReadAllText($pagedSupport.path)+[Environment]::NewLine+$pagedExtentObserver
    $guest=$guest.Replace('__FUNCTIONS__',(($definitions-join[Environment]::NewLine)+[Environment]::NewLine+$pagedFunctions)).Replace('__NORMAL_OBSERVER__',$observer)
    Save 'paged-observer-source-derivation.json' @{schema_version=1;kind='pinned-function-only-paged-observer-adaptation';legacy_source_path=$support.path;legacy_source_sha256=$support.sha256;paged_support_path=$pagedSupport.path;paged_support_sha256=$pagedSupport.sha256;extent_observer_source_path=$normal.path;extent_observer_source_sha256=$normal.sha256;historical_schema1_validator_preserved=$true;all_original_content_and_namespace_checks_preserved=$true;typed_binary_required=$true;fake_manifest_bindings_exported=$false;utc=[DateTime]::UtcNow.ToString('o')}
    $derivedSupportPath=Join-Path $root 'derived-paged-observer-functions.ps1';[IO.File]::WriteAllText($derivedSupportPath,$pagedFunctions,[Text.UTF8Encoding]::new($false));$derivedSupportSha=(Get-FileHash -LiteralPath $derivedSupportPath).Hash.ToLowerInvariant();$null=OpenFreshBaselineHost $derivedSupportPath $derivedSupportSha 1MB $held $false
'@
    Replace-CandidateOnce 'dispose retained paged observation owners' '$script:closedJsonCache.Clear();$script:labIndexes.Clear()}' '$script:closedJsonCache.Clear();$script:labIndexes.Clear();foreach($heldPage in $script:pagedMetadataHeld){$heldPage.Dispose()};$script:pagedMetadataHeld.Clear()}'
    Replace-CandidateOnce 'scoped additional fixture parameters' @'
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
'@ @'
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [Parameter(Mandatory)][string]$AdditionalDirectoryReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AdditionalDirectoryReceiptSha256,
'@
    Replace-CandidateOnce 'saved large source checkpoint only' '$ExpectedParent-in@($golden,$prepared)' '$ExpectedParent-ne[guid]::Empty-and$ExpectedParent-ne$golden-and$ExpectedParent-ne$prepared'
    Replace-CandidateOnce 'complete 1534 independent semantic coverage' '@($Expected.objects).Count-eq1084-and@($old.objects).Count-eq1084' '@($Expected.objects).Count-eq1534-and@($old.objects).Count-eq1534'
    Replace-CandidateOnce 'new large baseline support held' @'
    $pagedSupport=HeldScript 'PagedMetadataObserverSupport.ps1'
'@ @'
    $pagedSupport=HeldScript 'PagedMetadataObserverSupport.ps1'
    $largeSupport=HeldScript 'LargePagedBaselineSupport.ps1'
    Need ($largeSupport.sha256-ceq$candidateLargeSupportSha) 'Held large baseline observer support differs.'
'@
    Replace-CandidateOnce 'large source origin included' '$origins=@($normal,$performance,$support,$moveSupport,$self,$pagedSupport)' '$origins=@($normal,$performance,$support,$moveSupport,$self,$pagedSupport,$largeSupport)'
    Replace-CandidateOnce 'derive full-baseline functions only from held original AST' @'
    $baseline=ReadFreshLabSourceBaselineHost $FreshBaselineManifestPath $FreshBaselineManifestSha256 $DirectoryGrowthReceiptPath $DirectoryGrowthReceiptSha256 $ExpectedParent $base
'@ @'
$largeBaselinePath=Join-Path $candidateLabRoot 'SourceBaselineSupport.ps1';$largeTokens=$null;$largeErrors=$null
$largeBaselineAst=[Management.Automation.Language.Parser]::ParseFile($largeBaselinePath,[ref]$largeTokens,[ref]$largeErrors);Need ($largeErrors.Count-eq0) 'Held original baseline syntax differs.'
function LargeBaselineFunction([string]$Name){$rows=@($largeBaselineAst.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$Name},$true));Need ($rows.Count-eq1) 'One held baseline function required.';return $rows[0].Extent.Text}
$largeHostSource=LargeBaselineFunction 'ReadFreshLabSourceBaselineHost'
$largeHostSource=ReplaceOnce $largeHostSource '$m.schema_version-eq1-and$m.kind-ceq''lab-full-source-content-baseline-v1''' '$m.schema_version-eq2-and$m.kind-ceq''lab-full-source-content-baseline-pages-v2'''
$largeHostSource=ReplaceOnce $largeHostSource '$m.directories-gt256' '$m.directories-eq723'
$largeHostSource=ReplaceOnce $largeHostSource '$m.objects-le1280' '$m.objects-eq1534'
$largeHostSource=ReplaceOnce $largeHostSource '''observation-events.json''=@{key=''events'';name=''lab-fresh-observation-events.json''}}' '''observation-events.json''=@{key=''events'';name=''lab-fresh-observation-events.json''};''expectation.pages''=@{key=''expected_pages'';name=''lab-baseline-expectation.pages''};''expectation-pages.json''=@{key=''expected_page_receipt'';name=''lab-baseline-expectation-pages.json''}}'
$additionalHostLines=@(
'$additional=OpenFreshBaselineHost $AdditionalDirectoryReceiptPath $AdditionalDirectoryReceiptSha256 1MB $held $true',
' Need ($AdditionalDirectoryReceiptPath.StartsWith($LabBase+''\'',[StringComparison]::OrdinalIgnoreCase)-and$additional.value.kind-ceq''ntfs-paged-directory-object-fixture''-and$additional.value.success-eq$true-and$additional.value.created_directories-eq450-and$additional.value.created_payload_files-eq0-and$additional.value.original_payload_writes-eq0-and$additional.value.original_payload_bytes_read-eq0-and$additional.value.extent_moves-eq0-and@($additional.value.created_paths).Count-eq450-and[guid]$additional.value.source_parent_checkpoint-eq[guid]''83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'') ''Pinned metadata-only 450-directory source fixture required.''',
' $answer.files.additional_growth=@{path=$AdditionalDirectoryReceiptPath;bytes=$additional.item.Length;sha256=$AdditionalDirectoryReceiptSha256;name=''lab-additional-directory-growth.json''}',
' Need ($total+$file.Length+$growthFile.Length+$additional.item.Length-le256MB) ''Complete large baseline metadata exceeds original combined bound.''',
' $answer.sha256=$answer.files.expectation.sha256;'
)-join[Environment]::NewLine
$largeHostSource=ReplaceOnce $largeHostSource '$answer.sha256=$answer.files.expectation.sha256;' $additionalHostLines
$largeGuestBaselineSource=LargeBaselineFunction 'ReadFreshLabSourceBaselineGuest'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$null=Json $path;' 'if($path.EndsWith(''.pages'',[StringComparison]::Ordinal)){$null=Hold-PagedObserverFile $path $v.sha256 64MB}else{$null=Json $path};'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$m.kind-ceq''lab-full-source-content-baseline-v1''' '$m.schema_version-eq2-and$m.kind-ceq''lab-full-source-content-baseline-pages-v2'''
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$descriptor.directories-gt256' '$descriptor.directories-eq723'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$descriptor.objects-eq$m.objects' '$descriptor.objects-eq$m.objects-and$descriptor.objects-eq1534'
$largeGuestBaselineSource=ReplaceOnce $largeGuestBaselineSource '$script:labFreshBaseline=@{' '$additionalProof=AssertLargeAdditionalDirectories $e $m;Save ''additional-directories-baseline-verification.json'' $additionalProof;$script:labFreshBaseline=@{'
. ([scriptblock]::Create($largeHostSource))
    $baseline=ReadFreshLabSourceBaselineHost $FreshBaselineManifestPath $FreshBaselineManifestSha256 $DirectoryGrowthReceiptPath $DirectoryGrowthReceiptSha256 $ExpectedParent $base
'@
    Replace-CandidateOnce 'full baseline is distinct from product plan-ticket evidence' @'
    $pagedFunctions=$legacyV3Envelope+[Environment]::NewLine+[IO.File]::ReadAllText($pagedSupport.path)+[Environment]::NewLine+$pagedExtentObserver
'@ @'
    $pagedAst=$pagedSupport.ast;$productEnvelopeNodes=@($pagedAst.FindAll({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'AssertLabV3Envelope'},$true))
    Need ($productEnvelopeNodes.Count-eq1) 'One frozen actual-product paged envelope validator required.'
    $productEnvelope=ReplaceOnce $productEnvelopeNodes[0].Extent.Text 'function AssertLabV3Envelope(' 'function AssertProductPagedV3Envelope('
    $pagedFunctions=$legacyV3Envelope+[Environment]::NewLine+[IO.File]::ReadAllText($pagedSupport.path)+[Environment]::NewLine+$pagedExtentObserver+[Environment]::NewLine+$productEnvelope+[Environment]::NewLine+[IO.File]::ReadAllText($largeSupport.path)+[Environment]::NewLine+$largeGuestBaselineSource
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
    foreach($lease in $candidateExtraLeases){$lease.Dispose()}
}
