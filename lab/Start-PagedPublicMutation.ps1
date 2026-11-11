# Versioned adapter for the exact clean7feb normal 1534-object result.
# The reviewed workload stays unchanged; root owns save/shutdown/cold boot.
[CmdletBinding()]param(
 [ValidateSet('Mutate','VerifyAfterBoot')][string]$Operation='Mutate',
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
 [string]$MutationDispatchPath='',
 [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$MutationDispatchSha256='',
 [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$PreBootResultSha256=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$candidateLabRoot=$PSScriptRoot;$adapterPath=$PSCommandPath
$legacyPath=Join-Path $candidateLabRoot 'Start-CurrentPublicMutation.ps1';$legacySha='5971db294f596585ca9df13154cf6dfc69d3537a982082cf904ac77220bb3147'
$leases=[Collections.Generic.List[IO.FileStream]]::new()
function HoldMutationSource([string]$Path){
 $m=Get-Item -LiteralPath $Path -Force;if($m.PSIsContainer-or$m.Length-le0-or$m.Length-gt1MB){throw 'Bounded ordinary source required.'}
 $a=$m;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse source ancestry refused.'};if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($m.FullName,'Open','Read','Read');$leases.Add($f);$h=[Security.Cryptography.SHA256]::Create()
 try{$pin=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose();$f.Position=0}
 return @{stream=$f;path=$m.FullName;bytes=$f.Length;sha256=$pin}
}
function MutationReplace([string]$Name,[string]$Before,[string]$After){
 $before=$Before.Replace("`r`n","`n");$after=$After.Replace("`r`n","`n")
 if([regex]::Matches($script:controller,[regex]::Escape($before)).Count-ne1){throw ('Frozen mutation adaptation must match once: '+$Name)}
 $script:controller=$script:controller.Replace($before,$after)
}
try{
 if($SourceCommit-cne'7feb4c06d21e9de73bb88961197f5b745463e490'-or$ToolsetManifestSha256-cne'b0f6fe5fd4e02046739e9c177c838c1675c5a746b8662eec493402cca9e5e521'){throw 'Exact clean7feb sealed runtime required.'}
 $legacy=HoldMutationSource $legacyPath;if($legacy.sha256-cne$legacySha){throw 'Exact historical mutation source required; it is never edited.'}
 $adapter=HoldMutationSource $adapterPath
 $reader=[IO.StreamReader]::new($legacy.stream,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$script:controller=$reader.ReadToEnd().Replace("`r`n","`n")}finally{$reader.Dispose();$legacy.stream.Position=0}
 MutationReplace 'converted normal checkpoint' "afb9afa4-859e-471d-8600-2ba4abb9d2dd" "5ce766b0-c6e9-4007-b16d-363944240c51"
 MutationReplace 'public case and source stage' @'
$publicCase=Join-Path $base 'public-min-scratch-0cf3676b6409471dbe237e61053bb876';$publicStage='C:\ntfs2refs\public-min-scratch-0cf3676b6409471dbe237e61053bb876'
'@ @'
$publicCase=Join-Path $base 'public-min-scratch-608071c1ad524d07b1ef94237996cc6c';$publicStage='C:\ntfs2refs\public-min-scratch-608071c1ad524d07b1ef94237996cc6c'
'@
 MutationReplace 'actual normal engine records' 'dd3b74cc743eab2b4b8c5a4f85f66f9b' '4a1bad035614748a2fb5b77d649b2c00'
 MutationReplace 'exact source and runtime pins' '$SourceCommit-ceq''4d8ca993cf660ea7430b9cc8b229553946add82b''-and$ToolsetManifestSha256-ceq''77edb210f6236d3e22ec18a2f6cccd043ea0f784ec9a2041afec7be0aba3b396''' '$SourceCommit-ceq''7feb4c06d21e9de73bb88961197f5b745463e490''-and$ToolsetManifestSha256-ceq''b0f6fe5fd4e02046739e9c177c838c1675c5a746b8662eec493402cca9e5e521'''
 MutationReplace 'exact runtime diagnostic' 'Exact clean4d8 runtime and checkpoint set required.' 'Exact clean7feb runtime and checkpoint set required.'
 MutationReplace 'closed normal archive pin' '03097395779ac04fb2cbf4a79f5e52162f279f574d1f9fad4eb9cf919bf75311' '97b2e173906a5602b7baa953798c1ee52b85d7417f6f83ec923a8a14acc49475'
 MutationReplace 'actual normal run provenance' '$archive.run_id-ceq''0cf3676b6409471dbe237e61053bb876''' '$archive.run_id-ceq''608071c1ad524d07b1ef94237996cc6c'''
 MutationReplace 'complete independent object baseline count' '@($expected.objects).Count-eq1084' '@($expected.objects).Count-eq1534'
 MutationReplace 'truthful object scope and count' 'original_objects_verified=1084;' 'original_objects_verified=1534;original_object_verification_scope=''canonical_namespace_type_length'';all_acl_sacl_timestamp_fields_independently_verified=$false;'
 MutationReplace 'object baseline diagnostic label' 'Complete original1084-object baseline required.' 'Complete original1534-object baseline required.'
 MutationReplace 'module location under adapter' "Import-Module (Join-Path `$PSScriptRoot 'Lab.psm1')" "Import-Module (Join-Path `$candidateLabRoot 'Lab.psm1')"
 # The original snapshot remains the required mutation origin. A root-saved
 # direct child can hold the mutated state across the separate cold boot.
 $start=$controller.IndexOf('function HostGuard{',[StringComparison]::Ordinal);$end=$controller.IndexOf("`n`$workload=@'",$start,[StringComparison]::Ordinal)
 if($start-lt0-or$end-le$start){throw 'Exact original host guard extent required.'}
 $oldGuard=$controller.Substring($start,$end-$start)
 MutationReplace 'explicit normal/mutated checkpoint lineage' $oldGuard @'
function HostGuard{
 $v=Get-VM -Id $vmId;$snapshots=@(Get-VMSnapshot -VM $v);$ids=@($snapshots|ForEach-Object {$_.Id.ToString('D')});$expected=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});$node=@($snapshots|Where-Object {$_.Id-eq$ExpectedParent})
 $origin=if($Operation-ceq'Mutate'){$ExpectedParent-eq$converted}else{$ExpectedParent-eq$converted-or($node.Count-eq1-and$node[0].ParentSnapshotId-eq$converted)}
 Need ($origin-and$v.ParentSnapshotId-eq$ExpectedParent-and$node.Count-eq1-and$converted.ToString('D')-in$expected-and$ExpectedParent.ToString('D')-in$expected-and$v.State.ToString()-ceq'Running'-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$ids.Count-eq$expected.Count-and@($expected|Where-Object {$_-notin$ids}).Count-eq0) 'Exact normal5ce mutation origin or root-saved direct mutation child/cold-boot checkpoint required.'
}
'@
 MutationReplace 'archive exact derived source before guest staging' @'
 $null=New-Item -ItemType Directory -Path $root;$made=$true
'@ @'
 $null=New-Item -ItemType Directory -Path $root;$made=$true
 $derivedPath=Join-Path $root 'paged-public-mutation-controller.ps1';[IO.File]::WriteAllText($derivedPath,$controller,[Text.UTF8Encoding]::new($false));$derivedPin=(Get-FileHash -LiteralPath $derivedPath).Hash.ToLowerInvariant()
 Need ($derivedPin-ceq$derivedControllerSha) 'Archived derived mutation source differs.';$null=Hold $derivedPath $derivedPin 1MB $false
 Save 'paged-mutation-source-derivation.json' @{schema_version=1;kind='exact-7feb-1534-public-mutation-adaptation';legacy_source=$legacy.path;legacy_source_sha256=$legacy.sha256;adapter_path=$adapter.path;adapter_sha256=$adapter.sha256;derived_path=$derivedPath;derived_sha256=$derivedPin;source_commit=$SourceCommit;toolset_manifest_sha256=$ToolsetManifestSha256;normal_checkpoint=$converted;normal_archive_sha256='97b2e173906a5602b7baa953798c1ee52b85d7417f6f83ec923a8a14acc49475';workload_changed=$false;independent_original_streams=811;original_object_count=1534;object_scope='canonical_namespace_type_length';all_acl_sacl_timestamp_fields_independently_verified=$false;mutation_files=258;growth_entries=256;root_owns_reboot=$true;raw_device_or_journal_replay=$false;stable_release=$false}
'@
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($controller,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Derived paged mutation controller syntax differs; nothing dispatched.'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes($controller);$h=[Security.Cryptography.SHA256]::Create();try{$derivedControllerSha=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
 $arguments=@{};foreach($name in $PSBoundParameters.Keys){$arguments[$name]=$PSBoundParameters[$name]}
 & ([scriptblock]::Create($controller)) @arguments
}finally{foreach($stream in $leases){$stream.Dispose()}}
