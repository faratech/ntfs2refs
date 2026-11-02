# Recover-only HND2/RB2/ABT2 fault dispatch from exact original first-copy cuts.
# HND2 retains df88's HND1 lineage; RB2/ABT2 retain ebed's nested AP1 lineage.
# Root owns VM power/restore/checkpoint actions. A corrupt peer parks with owners
# retained; injected API errors must actually exit1 and leave the source offline.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
    [Parameter(Mandatory)][string]$SourceRequestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SourceRequestSha256,
    [Parameter(Mandatory)][string]$PreparedManagedReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparedManagedReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [switch]$AcknowledgeEnrolledDisposableDevices,
    [switch]$AcknowledgeUnqualifiedNativeMarkers,
    [Parameter(Mandatory)][string]$OriginalGuestBundlePath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OriginalGuestBundleSha256,
    [Parameter(Mandatory)][string]$PowerCheckpointReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PowerCheckpointReceiptSha256,
    [Parameter(Mandatory)][ValidateSet('RB2','HND2','ABT2')][string]$MarkerFaultCopy,
    [ValidateSet('corrupt-peer','write-error','flush-error','readback-error')][string]$MarkerFaultKind='corrupt-peer',
    [string]$OriginalAp1PowerCheckpointReceiptPath='',
    [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$OriginalAp1PowerCheckpointReceiptSha256=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$MarkerFaultCopy=$MarkerFaultCopy.ToUpperInvariant();$MarkerFaultKind=$MarkerFaultKind.ToLowerInvariant()
$faultLabRoot=$PSScriptRoot;$faultAdapterPath=$PSCommandPath
$faultIsNested=$MarkerFaultCopy-cin@('RB2','ABT2')
$faultRequestedSlot=@{HND2=5;RB2=3;ABT2=7}[$MarkerFaultCopy]
$faultExpectedParent=[guid](@{HND2='bfd2dfbe-b497-455d-95dd-9d7347145691';RB2='291c825f-3368-4039-ace3-2d9fbf10cc11';ABT2='83354c86-1103-4b0d-a99a-e23a8a78fdc8'}[$MarkerFaultCopy])
$faultControllerPath=Join-Path $faultLabRoot $(if($faultIsNested){'Start-NativeRollbackPowerRecovery.ps1'}else{'Start-NativeMarkerPowerRecovery.ps1'})
$faultOriginalControllerSha=if($faultIsNested){'ebedbc0e7faaa24c9d6076875b11b203ea7f4f5cec8a251dc56eaa244d4ae871'}else{'df88c9d563d1abc488e67322c966dcaced0a332936490e83fc14658193ed2def'}
$faultSourceLease=$null;$faultAdapterLease=$null
function Hold-FaultSource([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer-or$item.Length-le0-or$item.Length-gt1MB){throw 'Bounded ordinary controller source required.'}
    $cursor=$item;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse controller ancestry refused.'};if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
    return [IO.File]::Open($item.FullName,'Open','Read','Read')
}
function Fault-SourceHash([IO.Stream]$Stream){$hash=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$Stream.Position=0}}
function Replace-FaultOnce([string]$Name,[string]$Before,[string]$After){
    $beforeText=$Before.Replace("`r`n","`n");$afterText=$After.Replace("`r`n","`n")
    if([regex]::Matches($script:faultControllerText,[regex]::Escape($beforeText)).Count-ne1){throw ('Frozen fault-controller anchor differs: '+$Name)}
    $script:faultControllerText=$script:faultControllerText.Replace($beforeText,$afterText)
}
function Replace-FaultRegion([string]$Start,[string]$End,[string]$Replacement){
    if([regex]::Matches($script:faultControllerText,[regex]::Escape($Start)).Count-ne1-or[regex]::Matches($script:faultControllerText,[regex]::Escape($End)).Count-ne1){throw 'Unique frozen terminal observer boundaries required.'}
    $begin=$script:faultControllerText.IndexOf($Start,[StringComparison]::Ordinal);$finish=$script:faultControllerText.IndexOf($End,[StringComparison]::Ordinal)
    if($finish-le$begin){throw 'Fault observer boundaries are reversed.'}
    $script:faultControllerText=$script:faultControllerText.Substring(0,$begin)+$Replacement.Replace("`r`n","`n")+"`n"+$script:faultControllerText.Substring($finish)
}
try{
    if(-not$AcknowledgeEnrolledDisposableDevices-or-not$AcknowledgeUnqualifiedNativeMarkers){throw 'Both explicit lab acknowledgments required.'}
    if($ExpectedParent-ne$faultExpectedParent){throw 'Each marker copy requires its exact original HND1/RB1/ABT1 checkpoint; successful closed results are not fault inputs.'}
    if($faultIsNested){
        if([string]::IsNullOrEmpty($OriginalAp1PowerCheckpointReceiptPath)-or$OriginalAp1PowerCheckpointReceiptSha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'RB2/ABT2 require the separately pinned original AP1 power receipt.'}
    }elseif(-not[string]::IsNullOrEmpty($OriginalAp1PowerCheckpointReceiptPath)-or-not[string]::IsNullOrEmpty($OriginalAp1PowerCheckpointReceiptSha256)){throw 'HND2 uses its original HND1 receipt/bundle only, never nested AP1 inputs.'}
    $faultSourceLease=Hold-FaultSource $faultControllerPath
    if((Fault-SourceHash $faultSourceLease)-cne$faultOriginalControllerSha){throw 'Exact reviewed df88 or ebed power controller required; no frozen helper is modified.'}
    $reader=[IO.StreamReader]::new($faultSourceLease,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{$script:faultControllerText=$reader.ReadToEnd().Replace("`r`n","`n")}finally{$reader.Dispose();$faultSourceLease.Position=0}
    $faultAdapterLease=Hold-FaultSource $faultAdapterPath;$faultAdapterSha=Fault-SourceHash $faultAdapterLease
    if(-not$faultIsNested){
    Replace-FaultOnce 'HND recover-only fault parameters' @'
    [switch]$Rollback
'@ @'
    [switch]$Rollback,
    [Parameter(Mandatory)][ValidateSet('HND2')][string]$MarkerFaultCopy,
    [Parameter(Mandatory)][ValidateSet('corrupt-peer','write-error','flush-error','readback-error')][string]$MarkerFaultKind
'@
    }else{
    Replace-FaultOnce 'nested recover-only fault parameters' @'
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OriginalAp1PowerCheckpointReceiptSha256
'@ @'
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OriginalAp1PowerCheckpointReceiptSha256,
    [Parameter(Mandatory)][ValidateSet('RB2','ABT2')][string]$MarkerFaultCopy,
    [Parameter(Mandatory)][ValidateSet('corrupt-peer','write-error','flush-error','readback-error')][string]$MarkerFaultKind
'@
    }
    Replace-FaultOnce 'corruption parks; API injections exit' '$deliberatePause = $false' '$deliberatePause = $MarkerFaultKind -ceq ''corrupt-peer'''
    if(-not$faultIsNested){
    Replace-FaultOnce 'new HND fault stage' @'
$mode = if ($Rollback) { 'power-rollback' } else { 'power-resume' }
'@ @'
$mode = 'fault-'+$MarkerFaultCopy.ToLowerInvariant()+'-'+$MarkerFaultKind
'@
    Replace-FaultOnce 'HND1-only bundle route' '(?:ap1|hnd1)' '(?:hnd1)'
    Replace-FaultOnce 'HND1-only producer route' '(ap1|hnd1)' '(hnd1)'
    }else{
    Replace-FaultOnce 'new nested fault stage' @'
$mode = 'power-rollback-recovery'
'@ @'
$mode = 'fault-'+$MarkerFaultCopy.ToLowerInvariant()+'-'+$MarkerFaultKind
'@
    }
    Replace-FaultOnce 'fault module route' @'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
'@ @'
    Import-Module (Join-Path $faultLabRoot 'Lab.psm1') -Force
'@
    Replace-FaultOnce 'fault configuration and exact exit semantics' @'
        deliberate_pause=$false; pause_after_marker_copy=$null
        pause_marker_slot=$null; pause_signal_path=$null; pause_signal_bytes=$null
        expected_exit=0; bundle_path=$OriginalGuestBundlePath; bundle_sha256=$OriginalGuestBundleSha256
'@ @'
        deliberate_pause=$deliberatePause; pause_after_marker_copy=$null
        pause_marker_slot=$null; pause_signal_path=$null; pause_signal_bytes=$null
        marker_fault_copy=$MarkerFaultCopy;marker_fault_kind=$MarkerFaultKind;marker_fault_slot=$faultRequestedSlot
        marker_fault_signal_path=(Join-Path $output 'marker-fault.json');marker_fault_signal_bytes=32768
        expected_exit=$(if($deliberatePause){$null}else{1}); bundle_path=$OriginalGuestBundlePath; bundle_sha256=$OriginalGuestBundleSha256
'@
    $faultOldConfig=if($faultIsNested){
@'
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and$c.rollback-and-not$c.first_write_fault-and-not$c.deliberate_pause-and$c.expected_exit-eq0-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB) 'Pinned recovery-only configuration differs.'
'@
    }else{
@'
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and-not$c.first_write_fault-and-not$c.deliberate_pause-and$c.expected_exit-eq0-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB) 'Pinned recovery-only configuration differs.'
'@
    }
    Replace-FaultOnce 'strict original terminal/RB lineage and fault configuration' $faultOldConfig @'
 $faultLineage=($c.marker_fault_copy-ceq'HND2'-and-not$c.rollback-and$c.power_marker_copy-ceq'HND1'-and$c.power_marker_slot-eq4-and$c.expected_native_action-ceq'verify_handoff'-and$c.expected_original_lifecycle-ceq'handoff')-or($c.marker_fault_copy-ceq'RB2'-and$c.rollback-and$c.power_marker_copy-ceq'AP1'-and$c.rollback_power_marker_copy-ceq'RB1'-and$c.rollback_power_marker_slot-eq2-and$c.expected_native_action-ceq'rollback'-and$c.expected_original_lifecycle-ceq'rollback_intent')-or($c.marker_fault_copy-ceq'ABT2'-and$c.rollback-and$c.power_marker_copy-ceq'AP1'-and$c.rollback_power_marker_copy-ceq'ABT1'-and$c.rollback_power_marker_slot-eq6-and$c.expected_native_action-ceq'verify_aborted'-and$c.expected_original_lifecycle-ceq'aborted')
 Need ($faultLineage-and$c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and-not$c.first_write_fault-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB-and$c.marker_fault_copy-cin@('HND2','RB2','ABT2')-and$c.marker_fault_slot-eq[array]::IndexOf(@('AP1','AP2','RB1','RB2','HND1','HND2','ABT1','ABT2'),$c.marker_fault_copy)-and$c.marker_fault_kind-cin@('corrupt-peer','write-error','flush-error','readback-error')-and$c.mode-ceq('fault-'+$c.marker_fault_copy.ToLowerInvariant()+'-'+$c.marker_fault_kind)-and$c.marker_fault_signal_path-ceq(Join-Path $c.output 'marker-fault.json')-and$c.marker_fault_signal_bytes-eq32768-and(($c.marker_fault_kind-ceq'corrupt-peer'-and$c.deliberate_pause-and$null-eq$c.expected_exit)-or($c.marker_fault_kind-cne'corrupt-peer'-and-not$c.deliberate_pause-and$c.expected_exit-eq1))) 'Pinned recover-only terminal/RB fault configuration or original lifecycle differs.'
'@
    Replace-FaultOnce 'paired native fault CLI' @'
 $argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output);if($c.rollback){$argv+='--rollback'}
'@ @'
 $argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output);if($c.rollback){$argv+='--rollback'}
 $argv+=@('--marker-fault-copy',$c.marker_fault_copy,'--marker-fault-kind',$c.marker_fault_kind,'--marker-fault-signal',$c.marker_fault_signal_path)
'@
    Replace-FaultOnce 'native intent includes exact fault selector' "Save 'native-dispatch-intent.json' @{binary=`$binary;binary_sha256=`$producer.sha256;argv=`$argv;" "Save 'native-dispatch-intent.json' @{binary=`$binary;binary_sha256=`$producer.sha256;argv=`$argv;marker_fault_copy=`$c.marker_fault_copy;marker_fault_kind=`$c.marker_fault_kind;marker_fault_signal_path=`$c.marker_fault_signal_path;marker_fault_signal_bytes=32768;"
    Replace-FaultOnce 'owned process includes exact fault selector' "Save 'native-process.json' @{pid=`$nativePid;creation_ms=`$birth;parent_pid=`$PID;binary=`$binary;binary_sha256=`$producer.sha256;argv=`$argv;" "Save 'native-process.json' @{pid=`$nativePid;creation_ms=`$birth;parent_pid=`$PID;binary=`$binary;binary_sha256=`$producer.sha256;argv=`$argv;marker_fault_copy=`$c.marker_fault_copy;marker_fault_kind=`$c.marker_fault_kind;marker_fault_signal_path=`$c.marker_fault_signal_path;marker_fault_signal_bytes=32768;"
    if($faultIsNested){
        Replace-FaultOnce 'truthful nested fault dispatch kind' 'unqualified-native-marker-rollback-power-recovery-dispatch' 'unqualified-native-terminal-marker-fault-recovery-dispatch'
        Replace-FaultOnce 'nested host dispatch fault routes' 'operation=$Operation;mode=$mode;power_marker_copy=$rollbackPowerCopy;' 'operation=$Operation;mode=$mode;marker_fault_copy=$config.marker_fault_copy;marker_fault_kind=$config.marker_fault_kind;marker_fault_signal_path=$config.marker_fault_signal_path;marker_fault_signal_bytes=32768;power_marker_copy=$rollbackPowerCopy;'
    }else{
        Replace-FaultOnce 'truthful terminal fault dispatch kind' 'unqualified-native-marker-power-recovery-dispatch' 'unqualified-native-terminal-marker-fault-recovery-dispatch'
        Replace-FaultOnce 'terminal host dispatch fault routes' 'operation=$Operation;mode=$mode;power_marker_copy=$powerCopy;' 'operation=$Operation;mode=$mode;marker_fault_copy=$config.marker_fault_copy;marker_fault_kind=$config.marker_fault_kind;marker_fault_signal_path=$config.marker_fault_signal_path;marker_fault_signal_bytes=32768;power_marker_copy=$powerCopy;'
    }
    Replace-FaultOnce 'fault observation starts only after actual expected exit' " Need (`$null-ne`$nativeExit-and`$nativeExit-eq`$c.expected_exit) 'Actual process fault/unexpected exit; preserve all material without retry.'" " Need (`$null-ne`$nativeExit-and`$nativeExit-eq`$c.expected_exit-and`$nativeExit-eq1) 'Expected lab-injected actual exit1 required; no missing-process inference or retry.'"
    Replace-FaultRegion " `$result=Json (Join-Path `$c.output 'result.json');Need " "}catch{`n `$detail=FailureDetails `$_`n if(`$null-ne(Get-Variable c -ErrorAction SilentlyContinue))" @'
 $faultPath=$c.marker_fault_signal_path;$faultPin=Pin $faultPath;$fault=OpenPinned $faultPath $faultPin 32768 $true
 Need ((Get-Item -LiteralPath $faultPath).Length-eq32768-and$fault.schema_version-eq1-and$fault.kind-ceq'lab-selected-marker-fault'-and$fault.lab_only-and-not$fault.native_marker_qualified-and$fault.computer_name-ceq'N2R-WIN11'-and$fault.pid-eq$nativePid-and$fault.process_creation_unix_ms-eq$birth-and[decimal]::Floor(([decimal]$fault.process_creation_filetime_100ns-116444736000000000)/10000)-eq[decimal]$birth-and(Same $fault.argv (@($binary)+$argv))-and$fault.marker_copy-ceq$c.marker_fault_copy-and$fault.marker_slot-eq$c.marker_fault_slot-and$fault.marker_file_offset-eq($c.marker_fault_slot*4096)-and$fault.first_peer_file_offset-eq(($c.marker_fault_slot-1)*4096)-and$fault.marker_bytes-eq4096-and$fault.signal_path-ceq$faultPath-and$fault.signal_bytes-eq32768-and$fault.fault_kind-ceq$c.marker_fault_kind-and$fault.journal_format-ceq'N2RFRE02'-and$fault.journal_format_version-eq6-and$fault.journal_profile-ceq'CapacityPinnedV3'-and$fault.maximum_journal_bytes-eq8GB-and$fault.marker_profile-ceq'RedundantSourceFreeV1') 'Actual closed fault signal/process/argv/format/copy routes differ.'
 Marker $fault.storage $facts
 Need ($fault.marker_device_offset-eq@($fault.storage.marker_device_offsets)[$c.marker_fault_slot]-and$fault.signal_synced_before_readable-and$fault.journal_owner_retained_at_signal_publish-and$fault.intact_first_peer_verified_before_fault-and$fault.inactive_peer_verified_exact_zero_before_fault-and$fault.storage_revalidated_before_fault-and-not$fault.data_plane_writes_by_facility-and-not$fault.serialized_record_grants_authority-and-not$fault.automatic_continue-and-not$fault.timeout) 'Fault signal cannot grant authority or omit actual prerequisite/storage observations.'
 foreach($pin in @($fault.intact_first_peer_sha256,$fault.requested_peer_sha256)){Need ($pin-cmatch'\A[0-9a-f]{64}\z'-and$pin-cne('0'*64)) 'Actual canonical first/second peer digests required.'}
 Need ($fault.intact_first_peer_sha256-cne$fault.requested_peer_sha256-and$fault.synthetic_error-and-not$fault.actual_os_error-and$fault.injected_win32_error-eq1117-and-not$fault.skipped_api_issued-and$fault.journal_poisoned-and-not$fault.parks_after_publish-and-not$fault.requires_external_hard_poweroff-and$fault.expected_native_exit-eq1-and-not$fault.intact_first_peer_verified_after_fault-and-not$fault.storage_revalidated_after_fault-and$null-eq$fault.corruption-and$fault.io_fact_scope-ceq'selected-second-peer-write-path; prerequisite reads are recorded separately') 'Synthetic API fault must preserve truthful poison/error/publish scope; it is not a real OS error or successful recovery.'
 $write=($c.marker_fault_kind-cne'write-error');$flush=($c.marker_fault_kind-ceq'readback-error');$api=switch($c.marker_fault_kind){'write-error'{'WriteFile'}'flush-error'{'FlushFileBuffers'}'readback-error'{'ReadFile'}default{throw 'Unexpected terminal fault kind'}}
 Need ($fault.skipped_api-ceq$api-and$fault.marker_write_issued-eq$write-and$fault.marker_write_completed-eq$write-and$fault.marker_flush_issued-eq$flush-and$fault.marker_flush_completed-eq$flush-and-not$fault.marker_readback_issued-and-not$fault.marker_readback_completed) 'Fault receipt actual prior write/flush/readback scope differs.'
 if($write){Need ($null-eq$fault.observed_peer_sha256-and$fault.observed_peer_sha256_scope-ceq'unobserved-after-written-peer') 'Written peer remains unobserved after the injected flush/readback error.'}else{
  $zero=[Security.Cryptography.SHA256]::Create();try{$zeroPin=([BitConverter]::ToString($zero.ComputeHash([byte[]]::new(4096)))).Replace('-','').ToLowerInvariant()}finally{$zero.Dispose()}
  Need ($fault.observed_peer_sha256-ceq$zeroPin-and$fault.observed_peer_sha256_scope-ceq'pre-write-inactive-zero-peer') 'Write-error receipt must retain its actual pre-write zero-peer observation.'
 }
 $failed=Json (Join-Path $c.output 'failed.json')
 Need ($failed.schema_version-eq1-and$failed.kind-ceq'allocation-bounded-recovery-failure'-and$failed.phase-ceq'selected-journal-recovery'-and-not$failed.automatic_fallback_attempted-and-not$failed.fresh_apply_authorized-and$failed.completion_state_must_be_inspected-and$failed.error-like('*LAB-INJECTED marker '+$api+' skipped; synthetic ERROR_IO_DEVICE*')) 'Actual native failure must propagate through the existing recovery error path.'
 foreach($leaf in @('result.json','apply.json','handoff.json','rollback.json','verified-handoff.json','verified-rollback.json','completion.json')){Need (-not(Test-Path -LiteralPath (Join-Path $c.output $leaf))) 'Injected recovery cannot contain success/closure/native-mount outputs.'}
 $source=Binding $c.source $true $false
 Save 'native-marker-fault-observation.json' @{schema_version=1;kind='actual-lab-injected-native-marker-error-observation';fault_copy=$c.marker_fault_copy;fault_kind=$c.marker_fault_kind;fault_signal_sha256=$faultPin;fault=$fault;native_pid=$nativePid;native_creation_ms=$birth;native_exit=1;native_exit_observed=$true;existing_failure_path_observed=$true;target_remained_offline=$source.disk.IsOffline;source_readonly=$source.disk.IsReadOnly;synthetic_error_not_actual_OS_error=$true;source_or_replay_authority_granted=$false;raw_journal_opened_by_observer=$false;automatic_retry=$false;native_marker_qualified=$false;physical_power_loss_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Save 'wrapper-result.json' @{schema_version=1;kind='native-marker-injected-error-observation';observation_passed=$true;native_exit=1;native_exit_observed=$true;fault_copy=$c.marker_fault_copy;fault_kind=$c.marker_fault_kind;fault_signal_sha256=$faultPin;source_still_offline=$true;recovery_completed=$false;native_marker_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    Replace-FaultOnce 'archive exact fault derivation before guest staging' @'
    $null = New-Item -ItemType Directory -Path $root; $created = $true
'@ @'
    $null = New-Item -ItemType Directory -Path $root; $created = $true
    $derivedPath=Join-Path $root 'marker-fault-controller.ps1';$bytes=[Text.UTF8Encoding]::new($false).GetBytes($faultControllerText);$file=[IO.File]::Open($derivedPath,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    Need ((Get-FileHash -LiteralPath $derivedPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$faultDerivedControllerSha) 'Archived fault controller differs.';$null=OpenPinned $derivedPath $faultDerivedControllerSha 1MB $false
    Save 'marker-fault-derivation.json' @{schema_version=1;kind='reviewed-original-terminal-RB-marker-fault-controller';original_controller_sha256=$faultOriginalControllerSha;derived_controller_sha256=$faultDerivedControllerSha;derived_controller_path=$derivedPath;adapter_sha256=$faultAdapterSha;runtime_source_commit=$SourceCommit;toolset_manifest_sha256=$ToolsetManifestSha256;original_power_receipt_sha256=$PowerCheckpointReceiptSha256;original_ap1_power_receipt_sha256=$OriginalAp1PowerCheckpointReceiptSha256;original_bundle_path=$OriginalGuestBundlePath;original_bundle_sha256=$OriginalGuestBundleSha256;marker_fault_copy=$MarkerFaultCopy;marker_fault_kind=$MarkerFaultKind;marker_fault_slot=$faultRequestedSlot;fault_signal_path=(Join-Path $output 'marker-fault.json');fault_signal_bytes=32768;corruption_expected_to_park=$deliberatePause;expected_exit=$(if($deliberatePause){$null}else{1});completion_inferred=$false;vm_power_actions_performed=$false;source_or_replay_authority_granted=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($faultControllerText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Derived fault controller syntax differs; nothing dispatched.'}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($faultControllerText);$hash=[Security.Cryptography.SHA256]::Create();try{$faultDerivedControllerSha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $arguments=@{};foreach($key in $PSBoundParameters.Keys){$arguments[$key]=$PSBoundParameters[$key]}
    $arguments.MarkerFaultCopy=$MarkerFaultCopy;$arguments.MarkerFaultKind=$MarkerFaultKind
    if(-not$faultIsNested){$arguments.Remove('OriginalAp1PowerCheckpointReceiptPath');$arguments.Remove('OriginalAp1PowerCheckpointReceiptSha256')}
    & ([scriptblock]::Create($faultControllerText)) @arguments
}finally{if($null-ne$faultAdapterLease){$faultAdapterLease.Dispose()};if($null-ne$faultSourceLease){$faultSourceLease.Dispose()}}
