# Explicit rollback-marker pause from the ORIGINAL AP1 hard-power checkpoint.
# Derives a controller from exact reviewed bytes, never edits the running HND
# recovery helper. Root alone restores/boots/cuts power/checkpoints the VM.
# Returning a dispatch is not pause completion. Root must independently prove
# the closed 32KiB signal and live PID/birth/task before any hard power action.
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
    [Parameter(Mandatory)][ValidateSet('RB1','ABT1')][string]$PauseAfterMarkerCopy
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PauseAfterMarkerCopy=$PauseAfterMarkerCopy.ToUpperInvariant()
$originalControllerSha256='df88c9d563d1abc488e67322c966dcaced0a332936490e83fc14658193ed2def'
$controllerPath=Join-Path $PSScriptRoot 'Start-NativeMarkerPowerRecovery.ps1'
$sourceLease=$null
$adapterLease=$null
function Replace-ControllerOnce([string]$Name,[string]$Before,[string]$After) {
    $beforeText=$Before.Replace("`r`n","`n");$afterText=$After.Replace("`r`n","`n")
    if([regex]::Matches($script:derivedControllerText,[regex]::Escape($beforeText)).Count-ne1){throw ('Frozen controller anchor differs: '+$Name)}
    $script:derivedControllerText=$script:derivedControllerText.Replace($beforeText,$afterText)
}
function Hold-ControllerSource([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer-or$item.Length-le0-or$item.Length-gt1MB){throw 'Bounded ordinary controller source required.'}
    $cursor=$item
    while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse controller ancestry refused.'};if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
    return [IO.File]::Open($item.FullName,'Open','Read','Read')
}
function Controller-Hash([IO.Stream]$Stream) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$Stream.Position=0}
}
try {
    if(-not$AcknowledgeEnrolledDisposableDevices-or-not$AcknowledgeUnqualifiedNativeMarkers){throw 'Both explicit enrolled-device and unqualified-marker acknowledgments required.'}
    $sourceLease=Hold-ControllerSource $controllerPath
    if((Controller-Hash $sourceLease)-cne$originalControllerSha256){throw 'Exact reviewed power-recovery controller required; it is never rewritten or silently upgraded.'}
    $reader=[IO.StreamReader]::new($sourceLease,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{$script:derivedControllerText=$reader.ReadToEnd().Replace("`r`n","`n")}finally{$reader.Dispose();$sourceLease.Position=0}
    $adapterLease=Hold-ControllerSource $PSCommandPath
    $adapterSha256=Controller-Hash $adapterLease
    Replace-ControllerOnce 'paired rollback pause parameter' @'
    [switch]$Rollback
'@ @'
    [switch]$Rollback,
    [Parameter(Mandatory)][ValidateSet('RB1','ABT1')][string]$PauseAfterMarkerCopy
'@
    Replace-ControllerOnce 'explicit pause mode' '$deliberatePause = $false' '$deliberatePause = $true'
    Replace-ControllerOnce 'fresh rollback pause stage' @'
$mode = if ($Rollback) { 'power-rollback' } else { 'power-resume' }
'@ @'
$mode = 'power-rollback-pause-'+$PauseAfterMarkerCopy.ToLowerInvariant()
'@
    Replace-ControllerOnce 'direct output signal' '$pauseSignalPath = $null' '$pauseSignalPath = Join-Path $output ''marker-pause.json'''
    Replace-ControllerOnce 'exact rollback marker slot' '$pauseMarkerSlot = $null' '$pauseMarkerSlot = if ($PauseAfterMarkerCopy -ceq ''RB1'') { 2 } else { 6 }'
    Replace-ControllerOnce 'AP1-only original bundle' '(?:ap1|hnd1)' '(?:ap1)'
    Replace-ControllerOnce 'AP1-only original stage' '(ap1|hnd1)' '(ap1)'
    Replace-ControllerOnce 'AP1-only original slot' '$powerSlot = if ($powerCopy -ceq ''AP1'') { 0 } else { 4 }' '$powerSlot = 0'
    Replace-ControllerOnce 'rollback only from original AP1' @'
    Need (-not $Rollback -or $powerCopy -ceq 'AP1') 'HND1 already closes raw replay; only verify_handoff is allowed and rollback is refused.'
'@ @'
    Need ($Rollback -and $powerCopy -ceq 'AP1') 'Rollback pause requires the original AP1 power checkpoint; HND/RB/ABT and nested checkpoints cannot enter this dispatcher.'
'@
    Replace-ControllerOnce 'deliberate paired pause facts' @'
        deliberate_pause=$false; pause_after_marker_copy=$null
        pause_marker_slot=$null; pause_signal_path=$null; pause_signal_bytes=$null
        expected_exit=0; bundle_path=$OriginalGuestBundlePath; bundle_sha256=$OriginalGuestBundleSha256
'@ @'
        deliberate_pause=$true; pause_after_marker_copy=$PauseAfterMarkerCopy
        pause_marker_slot=$pauseMarkerSlot; pause_signal_path=$pauseSignalPath; pause_signal_bytes=32768
        expected_exit=$null; bundle_path=$OriginalGuestBundlePath; bundle_sha256=$OriginalGuestBundleSha256
'@
    Replace-ControllerOnce 'rollback expected action' @'
        expected_native_action=$(if ($powerCopy -ceq 'HND1') { 'verify_handoff' } elseif ($Rollback) { 'rollback' } else { 'resume' })
'@ @'
        expected_native_action='rollback'
'@
    Replace-ControllerOnce 'AP1 expected lifecycle' @'
        expected_original_lifecycle=$(if ($powerCopy -ceq 'HND1') { 'handoff' } else { 'apply_intent' })
'@ @'
        expected_original_lifecycle='apply_intent'
'@
    Replace-ControllerOnce 'strict guest rollback pause configuration' @'
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and-not$c.first_write_fault-and-not$c.deliberate_pause-and$c.expected_exit-eq0-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB) 'Pinned recovery-only configuration differs.'
'@ @'
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and$c.rollback-and-not$c.first_write_fault-and$c.deliberate_pause-and$null-eq$c.expected_exit-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB-and$c.power_marker_copy-ceq'AP1'-and$c.power_marker_slot-eq0-and$c.expected_native_action-ceq'rollback'-and$c.expected_original_lifecycle-ceq'apply_intent') 'Pinned original-AP1 rollback pause configuration differs.'
'@
    Replace-ControllerOnce 'strict paired pause route' @'
 Need ($null-eq$c.pause_after_marker_copy-and$null-eq$c.pause_marker_slot-and$null-eq$c.pause_signal_path-and$null-eq$c.pause_signal_bytes) 'Power recovery does not create a second pause or an automatic power action.'
'@ @'
 Need ($c.pause_after_marker_copy-cin@('RB1','ABT1')-and$c.pause_marker_slot-eq[array]::IndexOf(@('AP1','AP2','RB1','RB2','HND1','HND2','ABT1','ABT2'),$c.pause_after_marker_copy)-and$c.mode-ceq('power-rollback-pause-'+$c.pause_after_marker_copy.ToLowerInvariant())-and$c.pause_signal_path-ceq(Join-Path $c.output 'marker-pause.json')-and$c.pause_signal_bytes-eq32768) 'Only the exact paired RB1/ABT1 rollback pause and32KiB output signal are admitted.'
'@
    Replace-ControllerOnce 'native rollback pause argv' @'
 $argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output);if($c.rollback){$argv+='--rollback'}
'@ @'
 $argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output,'--rollback','--pause-after-marker-copy',$c.pause_after_marker_copy,'--pause-signal',$c.pause_signal_path)
'@
    Replace-ControllerOnce 'truthful pause dispatch kind' 'unqualified-native-marker-power-recovery-dispatch' 'unqualified-native-rollback-marker-pause-dispatch'
    Replace-ControllerOnce 'module route independent of dynamic script root' @'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
'@ @'
    Import-Module (Join-Path (Split-Path -Parent $controllerPath) 'Lab.psm1') -Force
'@
    # Preserve the exact derived source and provenance before any guest stage.
    # Variables below come only from this held adapter/controller invocation.
    Replace-ControllerOnce 'archive derived controller before guest actions' @'
    $null = New-Item -ItemType Directory -Path $root; $created = $true
'@ @'
    $null = New-Item -ItemType Directory -Path $root; $created = $true
    $derivedPath=Join-Path $root 'rollback-pause-controller.ps1'
    $derivedBytes=[Text.UTF8Encoding]::new($false).GetBytes($derivedControllerText)
    $derivedFile=[IO.File]::Open($derivedPath,'CreateNew','Write','Read')
    try{$derivedFile.Write($derivedBytes,0,$derivedBytes.Length);$derivedFile.Flush($true)}finally{$derivedFile.Dispose()}
    Need ((Get-FileHash -LiteralPath $derivedPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$derivedControllerSha256) 'Archived derived controller SHA differs.'
    $null=OpenPinned $derivedPath $derivedControllerSha256 1MB $false
    Save 'rollback-pause-derivation.json' @{schema_version=1;kind='exact-reviewed-power-controller-rollback-pause-derivation';original_controller_path=$controllerPath;original_controller_sha256=$originalControllerSha256;derived_controller_path=$derivedPath;derived_controller_sha256=$derivedControllerSha256;adapter_sha256=$adapterSha256;original_AP1_checkpoint_receipt_sha256=$PowerCheckpointReceiptSha256;original_AP1_bundle_path=$OriginalGuestBundlePath;original_AP1_bundle_sha256=$OriginalGuestBundleSha256;expected_original_checkpoint_id=$ExpectedParent;new_stage=$stage;new_output=$output;pause_after_marker_copy=$PauseAfterMarkerCopy;pause_marker_slot=$pauseMarkerSlot;pause_signal_path=$pauseSignalPath;pause_signal_bytes=32768;expected_exit=$null;completion_inferred=$false;native_marker_qualified=$false;power_actions_performed=$false;nested_power_origin_recovery_supported=$false;serialized_record_grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($derivedControllerText,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Derived rollback-pause controller syntax differs; nothing dispatched.'}
    $derivedBytes=[Text.UTF8Encoding]::new($false).GetBytes($derivedControllerText)
    $hash=[Security.Cryptography.SHA256]::Create()
    try{$derivedControllerSha256=([BitConverter]::ToString($hash.ComputeHash($derivedBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $controllerArguments=@{}
    foreach($key in $PSBoundParameters.Keys){$controllerArguments[$key]=$PSBoundParameters[$key]}
    $controllerArguments.Rollback=$true
    # Every host/device/origin/journal gate stays in the reviewed controller.
    # Native work is started once by its SYSTEM task, never by JSON authority.
    & ([scriptblock]::Create($derivedControllerText)) @controllerArguments
} finally {
    if($null-ne$adapterLease){$adapterLease.Dispose()}
    if($null-ne$sourceLease){$sourceLease.Dispose()}
}
