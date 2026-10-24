<# One explicitly selected native reconstruction phase in the owned guest. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidateSet('prepare','apply','resume','rollback','handoff')][string]$Operation,
 [string]$RequestPath,[string]$RequestSha256,[string]$RequestPinPath,[string]$RequestPinSha256,
 [string]$ReviewedSourcesPath,[string]$ReviewedSourcesSha256,
 [string]$PriorResultPath,[string]$PriorResultSha256,[string]$TicketSha256,
 [ValidateRange(60,900)][int]$BootTimeoutSeconds=300,
 [ValidateRange(30,7200)][int]$NativeTimeoutSeconds=3600
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
if(-not$PSCmdlet.ShouldProcess('owned offline checkpoint for one selected phase',('Run '+$Operation+' only; export, checkpoint and restore baseline after verified success'))){[pscustomobject]@{DryRun=$true;Operation=$Operation;AutomaticPhaseProgression=$false;ConversionQualified=$false};return}
function Get-RHSources{@('lab/guest/Invoke-GuestNativeReconstruct.ps1','lab/guest/Restore-GuestShadowAttachment.ps1','lab/guest/NativeShadowDisk.cs','lab/guest/NativeShadowReadOnlyAttachment.cs','lab/guest/NativeMountBoundary.cs','lab/Lab.psm1','scripts/New-LabNativeReconstructRequest.ps1','scripts/Invoke-LabRetainedNativeProbe.ps1','scripts/Invoke-LabNativeReconstruct.ps1','target/release/lab-native-reconstruct.exe')}
function Assert-RHBool($Value,[bool]$Expected){if($Value-isnot[bool]-or$Value-ne$Expected){throw 'Explicit reconstruction host boolean differs.'}}
function Assert-RHHash($Value){if($Value-isnot[string]-or$Value-cnotmatch '\A[0-9a-f]{64}\z'){throw 'Explicit reconstruction host SHA-256 pin required.'}}
function Assert-RHInteger($Value,[long]$Minimum,[long]$Maximum){if($null-eq$Value-or$Value-is[string]-or$Value-is[bool]-or$Value-lt$Minimum-or$Value-gt$Maximum-or[decimal]$Value-ne[decimal]::Truncate([decimal]$Value)){throw 'Bounded integer evidence required.'}}
function Assert-RHReviewed($Value){
 $names=@(Get-RHSources);if($Value.schemaVersion-ne1-or$Value.kind-cne'native-reconstruction-reviewed-sources'-or@($Value.files).Count-ne$names.Count-or@($Value.files.path|Select-Object -Unique).Count-ne$names.Count){throw 'Exact reviewed reconstruction sources required.'}
 foreach($f in $Value.files){if($f.path-cnotin$names){throw 'Unexpected reviewed source.'};Assert-RHHash $f.sha256}
}
function Read-RHBytes([string]$Path,[string]$Hash,[long]$Maximum,[bool]$AllowEmpty=$false){
 Assert-RHHash $Hash;$p=Assert-LabPath $Path $workspace
 $current=$p;while($current){$item=Get-Item -LiteralPath $current -Force;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse input path refused.'};if($current-cne$p-and-not$item.PSIsContainer){throw 'Input ancestor is not directory.'};$current=[IO.Path]::GetDirectoryName($current)}
 $f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or$f.Length-gt$Maximum-or(-not$AllowEmpty-and$f.Length-lt1)){throw 'Bounded ordinary pinned input required.'}
 $stream=New-Object IO.FileStream($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-gt$Maximum-or(-not$AllowEmpty-and$stream.Length-lt1)){throw 'Input length changed.'};$bytes=New-Object byte[] $stream.Length;$at=0;while($at-lt$bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);if($n-le0){throw 'Short pinned read.'};$at+=$n};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-cne$Hash){throw ('Input SHA differs: '+$f.Name)};return ,$bytes}finally{$stream.Dispose()}
}
function Read-RHJson([string]$Path,[string]$Hash,[long]$Maximum=2MB){
 $bytes=Read-RHBytes $Path $Hash $Maximum;$text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes)
 if($text.Length-gt0-and$text[0]-eq[char]0xfeff){$text=$text.Substring(1)}
 if($text-cmatch '\A[\x20\x09\x0a\x0d]*\uFEFF'){throw 'Only one leading UTF-8 BOM is permitted.'}
 $text|ConvertFrom-Json
}
function Import-RHFunctions([byte[]]$Bytes,[string[]]$Names){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput((New-Object Text.UTF8Encoding($false,$true)).GetString($Bytes),[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Pinned helper does not parse.'}
 foreach($name in $Names){$f=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false)|Where-Object Name -CEQ $name);if($f.Count-ne1){throw ('Exact archived function absent: '+$name)};$definition=[regex]::Replace($f[0].Extent.Text,('\Afunction\s+'+[regex]::Escape($name)+'\b'),('function script:'+$name));. ([scriptblock]::Create($definition))}
}
function Assert-RHPin($Pin,[string]$Run,[string]$Hash){
 Assert-RHInteger $Pin.schemaVersion 1 1;Assert-RHInteger $Pin.requestLength 1 128KB
 if($Pin.schemaVersion-ne1-or$Pin.kind-cne'native-reconstruction-request-pin'-or$Pin.runId-cne$Run-or$Pin.requestSha256-cne$Hash-or$Pin.requestLength-lt1-or$Pin.requestLength-gt128KB-or@($Pin.inputs).Count-ne10){throw 'Exact derived request provenance required.'}
 foreach($n in @('currentDeviceStateVerified','externalAttestationsPromotedToWriteAuthority','nativeOperationInvoked','conversionQualified','bootQualified')){Assert-RHBool $Pin.$n $false}
 Assert-RHHash $Pin.probeResultSha256
 foreach($f in $Pin.inputs){Assert-RHHash $f.sha256;Assert-RHInteger $f.length 1 2MB}
 if(@($Pin.inputs.path|Select-Object -Unique).Count-ne10){throw 'Provenance input paths overlap.'}
}
function Assert-RHPrior($Prior,[string]$Run,[string]$RequestHash,[string]$PinHash,[string]$TicketHash,[string]$Next){
 Assert-RHInteger $Prior.schemaVersion 1 1
 if($Prior.schemaVersion-ne1-or$Prior.kind-cne'native-reconstruction-host'-or$Prior.status-cne'native-phase-checkpointed'-or$Prior.phase-cne'complete'-or$Prior.runId-cne$Run-or$Prior.requestSha256-cne$RequestHash-or$Prior.requestPinSha256-cne$PinHash-or$Prior.ticketSha256-cne$TicketHash-or$Prior.phaseId-cnotmatch '\A[0-9a-f]{32}\z'-or$Prior.vmId-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or$Prior.baselineId-ine'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Completed prior reconstruction phase binding required.'}
 foreach($n in @('phaseExported','ticketExported','cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored','nativeResultVerified')){Assert-RHBool $Prior.$n $true}
 foreach($n in @('transportCompletionUnknown','guestOperationUnknown','sessionPreserved','conversionQualified')){Assert-RHBool $Prior.$n $false}
 foreach($n in @('nativeReportSha256','processResultSha256')){Assert-RHHash $Prior.$n}
 Assert-NativeProbeGuid $Prior.outcomeCheckpointId
 if($Prior.outcomeCheckpointName-cne('reconstruct-'+$Prior.operation+'-'+$Prior.phaseId)){throw 'Prior phase checkpoint name differs.'}
 $allowed=switch($Next){apply{@('prepare','rollback')}resume{@('prepare','apply','resume')}rollback{@('apply','resume')}handoff{@('apply','resume')}default{@()}}
 if($Prior.operation-cnotin$allowed){throw 'Selected phase has no approved completed predecessor.'}
}
function Assert-RHArtifacts([object[]]$Files,[bool]$Complete){
 if($Files.Count-lt1-or$Files.Count-gt9-or@($Files.name|Select-Object -Unique).Count-ne$Files.Count){throw 'Reconstruction artifact inventory differs.'};$sum=0L
 foreach($f in $Files){$max=0L;$empty=$false;switch -CaseSensitive($f.name){'lab-native-reconstruct.exe'{$max=16MB}'request.json'{$max=128KB}'result.json'{$max=16MB}'result.intent.json'{$max=256KB}'process-intent.json'{$max=64KB}'process-started.json'{$max=64KB}'process-result.json'{$max=64KB}'reconstruct.stdout'{$max=64KB;$empty=$true}'reconstruct.stderr'{$max=64KB;$empty=$true}}
  Assert-RHInteger $f.length 0 $max;if($max-eq0-or(-not$empty-and$f.length-eq0)-or([IO.FileAttributes]$f.attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Artifact name/type/size refused.'};Assert-RHHash $f.sha256;$sum+=$f.length
 };if($sum-gt34MB-or($Complete-and$Files.Count-ne9)){throw 'Artifact coverage or total bound differs.'}
}
function Assert-RHProcess($Result,$Intent,$Started,$Request,[string]$Run,[string]$Phase,[string]$Op,[string]$RequestHash,[string]$BinaryHash,[string]$TicketHash,[int]$ExpectedTimeout){
 $root='C:\ntfs2refs\native-reconstruct\'+$Run+'\'+$Phase;$arguments=@($Op,'--request',($root+'\request.json'),'--request-sha256',$RequestHash,'--journal',('J:\ntfs2refs-shadow\'+$Run+'\reconstruction.journal'),'--ticket',('C:\ntfs2refs\native-reconstruct\'+$Run+'\ticket.json'),'--output',($root+'\result.json'));if($Op-cne'prepare'){$arguments+=@('--ticket-sha256',$TicketHash)}
 foreach($r in @($Result,$Intent,$Started)){Assert-RHInteger $r.schemaVersion 1 1;Assert-RHInteger $r.timeoutSeconds $ExpectedTimeout $ExpectedTimeout;if($r.kind-cne'native-reconstruction-process'-or$r.runId-cne$Run-or$r.phaseId-cne$Phase-or$r.operation-cne$Op-or$r.requestSha256-cne$RequestHash-or$r.binarySha256-cne$BinaryHash){throw 'Reconstruction process provenance differs.'};Assert-NRSame $arguments $r.arguments;Assert-RHBool $r.onlineTransitionRequested $false;Assert-RHBool $r.conversionQualified $false;Assert-RHBool $r.statePreservationRequired $true;if($Op-ceq'prepare'){if(-not[string]::IsNullOrEmpty($r.independentTicketSha256)){throw 'Prepare unexpectedly has input ticket.'}}elseif($r.independentTicketSha256-cne$TicketHash){throw 'Independent process ticket pin differs.'}}
 foreach($pair in @(@($Result.completionKnown,$true),@($Result.nativeResultVerified,$true),@($Result.launchAttempted,$true),@($Result.processIntentPersisted,$true),@($Started.launchAttempted,$true),@($Intent.launchAttempted,$false))){Assert-RHBool $pair[0] $pair[1]}
 foreach($r in @($Intent,$Started)){Assert-RHBool $r.completionKnown $false;Assert-RHBool $r.nativeResultVerified $false;if($null-ne$r.exitCode-or$null-ne$r.ticketSha256){throw 'Pre-completion process record has completion output.'}}
 if($null-ne$Intent.processId){throw 'Prelaunch intent already has process identity.'};Assert-RHInteger $Result.processId 1 ([int]::MaxValue);Assert-RHInteger $Started.processId 1 ([int]::MaxValue)
 if($Result.status-cne'native-reconstruction-phase-verified-disks-offline'-or$Result.exitCode-is[string]-or$Result.exitCode-is[bool]-or$null-eq$Result.exitCode-or$Result.exitCode-ne0-or$Result.processId-le0-or$Result.processId-ne$Started.processId-or$Result.ticketSha256-cne$TicketHash-or@($Result.artifacts).Count-ne4){throw 'Reconstruction process completion differs.'}
}
function Assert-RHNativeIntent($Intent,$Cli,$Request,[string]$Op,[string]$RequestHash,[string]$Run,[string]$TicketHash){
 Assert-NRFields $Intent @('schema_version','kind','operation','request_sha256','request','request_file','ticket_path','independent_ticket_sha256','journal_path','phase','may_modify_journal_after_this_intent','may_issue_target_payload_writes_after_this_intent','online_transition_allowed','conversion_qualified','boot_qualified')
 if($Intent.schema_version-ne1-or$Intent.kind-cne'native-reconstruction-intent'-or$Intent.operation-cne$Op-or$Intent.request_sha256-cne$RequestHash-or$Intent.phase-cne'before-journal-open'-or$Intent.ticket_path-cne('C:\ntfs2refs\native-reconstruct\'+$Run+'\ticket.json')-or$Intent.journal_path-cne('J:\ntfs2refs-shadow\'+$Run+'\reconstruction.journal')){throw 'Native reconstruction intent differs.'}
 Assert-NRSame $Request $Intent.request;Assert-NRSame $Cli.request_file $Intent.request_file
 Assert-RHBool $Intent.may_modify_journal_after_this_intent $true;Assert-RHBool $Intent.may_issue_target_payload_writes_after_this_intent ($Op-cin@('apply','resume','rollback'))
 foreach($n in @('online_transition_allowed','conversion_qualified','boot_qualified')){Assert-RHBool $Intent.$n $false}
 if($Op-ceq'prepare'){if($null-ne$Intent.independent_ticket_sha256){throw 'Unexpected prepare intent ticket.'}}elseif($Intent.independent_ticket_sha256-cne$TicketHash){throw 'Native intent independent ticket differs.'}
}
function Export-RetainedProbe([string]$GuestRoot,[string]$Stage,[string]$Folder){
 if($Stage-cnotin@('attachment','reconstruction')){throw 'Unknown export stage.'};$files=@(Invoke-RetainedProbeCommand -Arguments @($GuestRoot) -Body {param($Root);$d=Get-Item -LiteralPath $Root -Force;if(-not$d.PSIsContainer-or($d.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest export directory differs.'};$all=@(Get-ChildItem -LiteralPath $Root -Force);if($all.Count-gt9){throw 'Export count exceeds bound.'};foreach($f in $all){if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt16MB){throw 'Guest export shape differs.'};[pscustomobject]@{name=$f.Name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant();attributes=[string]$f.Attributes}}})
 if($Stage-ceq'attachment'){Assert-RetainedProbeArtifacts $files attachment}else{Assert-RHArtifacts $files $false};$dir=Join-Path $outputRoot $Folder;New-Item -ItemType Directory -Path $dir|Out-Null
 foreach($f in $files){$dest=Join-Path $dir $f.name;Copy-Item -LiteralPath ($GuestRoot+'\'+$f.name) -Destination $dest -FromSession $session;$bytes=Read-RHBytes $dest $f.sha256 16MB $true;if($bytes.Length-ne$f.length){throw 'Export length changed.'}}
 $after=@(Invoke-RetainedProbeCommand -Arguments @($GuestRoot) -Body {param($Root);foreach($f in @(Get-ChildItem -LiteralPath $Root -Force)){if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt16MB){throw 'Export shape changed.'};[pscustomobject]@{name=$f.Name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant();attributes=[string]$f.Attributes}}})
 if($Stage-ceq'attachment'){Assert-RetainedProbeArtifacts $after attachment}else{Assert-RHArtifacts $after $false};if($files.Count-ne$after.Count){throw 'Export count changed.'};foreach($f in $files){$a=@($after|Where-Object name -CEQ $f.name);if($a.Count-ne1-or$a[0].sha256-cne$f.sha256-or$a[0].length-ne$f.length){throw 'Export bytes changed.'}}
 Write-RetainedProbeJson (Join-Path $dir 'exported-files.json') @($files) 64KB;[pscustomobject]@{directory=$dir;files=$files}
}

Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V management required.'}
foreach($hash in @($RequestSha256,$RequestPinSha256,$ReviewedSourcesSha256)){Assert-RHHash $hash}
if($Operation-ceq'prepare'){if($TicketSha256-or$PriorResultPath-or$PriorResultSha256){throw 'Prepare cannot reuse a prior phase or ticket.'}}else{Assert-RHHash $TicketSha256;Assert-RHHash $PriorResultSha256;if(-not$PriorResultPath){throw 'Non-Prepare requires an independently pinned prior result.'}}
$script:labRoot=Join-Path $workspace '.lab'
$requestPath=Assert-LabPath $RequestPath $labRoot;$requestPinPath=Assert-LabPath $RequestPinPath $labRoot;$reviewPath=Assert-LabPath $ReviewedSourcesPath $labRoot
$request=Read-RHJson $requestPath $RequestSha256 128KB;$pin=Read-RHJson $requestPinPath $RequestPinSha256 128KB;$review=Read-RHJson $reviewPath $ReviewedSourcesSha256 64KB;Assert-RHReviewed $review
$runId=$request.experiment_id;Assert-RHPin $pin $runId $RequestSha256
$phaseId=[guid]::NewGuid().ToString('N');$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('native-reconstruct\'+$Operation+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'New host evidence case already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$archive=Join-Path $outputRoot 'reviewed-sources';New-Item -ItemType Directory -Path $archive|Out-Null
# Bootstrap just these reviewed utility definitions; no imported top-level code runs.
$hostEntry=@($review.files|Where-Object path -CEQ 'scripts/Invoke-LabRetainedNativeProbe.ps1')[0]
$hostBytes=Read-RHBytes (Join-Path $workspace $hostEntry.path) $hostEntry.sha256 256KB
Import-RHFunctions $hostBytes @('Convert-RetainedProtectionHex','Get-RetainedProtectionGuid','Assert-RetainedProtectionLayout','Assert-RetainedProbeProtection')
Import-RHFunctions $hostBytes @('Write-RetainedProbeJson','Copy-RetainedProbePinned','Read-RetainedProbePinned','Assert-RetainedProbeBoolean','Assert-RetainedProbeCheckpoint','Assert-RetainedProbeArtifacts','Set-RetainedProbeReplyState','Assert-RetainedProbeReply','Assert-RetainedProbeAttachment','Read-RetainedProbeExport','Save-RetainedProbeProgress','Invoke-RetainedProbeCommand','Open-RetainedProbeSession','Assert-RetainedProbeCurrent','Wait-RetainedProbeRestored','Complete-RetainedProbeBaseline','Copy-RetainedProbeGuestSources','Restore-RetainedProbeShadow','Stop-RetainedProbeGuest','New-RetainedProbeCheckpoint')
$currentSources=@(foreach($entry in $review.files){$p=Join-Path $workspace $entry.path;$max=if($entry.path-ceq'target/release/lab-native-reconstruct.exe'){16MB}else{256KB};Read-RHBytes $p $entry.sha256 $max|Out-Null;Copy-RetainedProbePinned $p (Join-Path $archive ([IO.Path]::GetFileName($p))) $entry.sha256 $max})
$generator=@($currentSources|Where-Object name -CEQ 'New-LabNativeReconstructRequest.ps1')[0]
Import-RHFunctions (Read-RHBytes $generator.archive $generator.sha256 256KB) @('Assert-NGRHash','Assert-NGRBool','Assert-NGRNumber','Assert-NGRPath','Assert-NGRAncestors','Get-NGRSha','Read-NGRPinned','Convert-NGRJson','Import-NGRGuards','Get-NGRSource','Assert-NGRHost','New-NGRRequest')
$wrapper=@($currentSources|Where-Object name -CEQ 'Invoke-GuestNativeReconstruct.ps1')[0]
Import-RHFunctions (Read-RHBytes $wrapper.archive $wrapper.sha256 256KB) @('Assert-NRFields','Assert-NRBool','Assert-NRNumber','Assert-NRHash','Assert-NRGuid','Assert-NRSame','Assert-NRBytes','Assert-NRPartition','Assert-NRRequest','Assert-NRTicket','Assert-NROrdinarySnapshot','Assert-NRPartitionSnapshot','Assert-NRJournalSnapshot','Assert-NRResult')
Assert-NRRequest $request $runId
$proofEntry=@($pin.inputs|Where-Object{[IO.Path]::GetFileName($_.path)-ceq'host-result.json'});if($proofEntry.Count-ne1-or$proofEntry[0].sha256-cne$pin.probeResultSha256){throw 'Native probe trust root absent.'}
$probeResultPath=Assert-NGRPath $proofEntry[0].path $labRoot;$probeRoot=Split-Path -Parent $probeResultPath;$hostProof=Read-RHJson $probeResultPath $pin.probeResultSha256 2MB
foreach($f in $pin.inputs){$p=Assert-NGRPath $f.path $labRoot;$bytes=Read-RHBytes $p $f.sha256 2MB;if($bytes.Length-ne$f.length){throw 'Pinned derivation input length changed.'}}
foreach($spec in @(
 @('Invoke-GuestNativeProbe.ps1',@('Assert-NativeProbeFields','Assert-NativeProbeGuid','Assert-NativeProbeBinding','Assert-NativeProbeRequest','Assert-NativeProbeSame','Assert-NativeProbeResult')),
 @('Invoke-LabRetainedNativeProbe.ps1',@('Assert-RetainedProbeBoolean','Assert-RetainedProbePreparation')),
 @('Restore-GuestShadowAttachment.ps1',@('Assert-AttachmentBoolean','Assert-AttachmentGuid','Assert-AttachmentPreparation'))
)){$entry=Get-NGRSource $hostProof $spec[0];$p=Join-Path $probeRoot ('reviewed-sources\'+$spec[0]);Import-NGRGuards (Read-NGRPinned $p $entry.sha256 256KB) $spec[1]}
Assert-NGRHost $hostProof
if($pin.quiescentCheckpointId-ine$hostProof.quiescentCheckpointId-or$pin.quiescentCheckpointName-cne$hostProof.quiescentCheckpointName){throw 'Quiescent request provenance differs.'}
$probe=Read-RHJson (Join-Path $probeRoot 'request.json') $hostProof.requestSha256 16KB
$first=Read-RHJson (Join-Path $probeRoot 'first-native\probe.json') $hostProof.firstNativeReportSha256 1MB;$second=Read-RHJson (Join-Path $probeRoot 'second-native\probe.json') $hostProof.secondNativeReportSha256 1MB
$prepared=Read-RHJson (Join-Path $probeRoot 'preparation-host-result.json') $hostProof.preparationResultSha256 2MB
$source=Read-RHJson (Join-Path $probeRoot 'source-platform.json') $prepared.sourceEvidenceSha256 1MB;$shadow=Read-RHJson (Join-Path $probeRoot 'shadow-platform.json') $prepared.shadowEvidenceSha256 1MB
$derived=New-NGRRequest $hostProof $probe $first $second $prepared $source $shadow;Assert-NRSame $derived $request
$prepGuard=@($hostProof.preparationSourceHashes|Where-Object name -CEQ 'Invoke-LabRetainedPreparation.ps1');if($prepGuard.Count-ne1){throw 'Archived VM guard pin absent.'}
Import-RHFunctions (Read-RHBytes (Join-Path $probeRoot 'preparation-sources\Invoke-LabRetainedPreparation.ps1') $prepGuard[0].sha256 256KB) @('Assert-RetainedPreparationManifest','Assert-RetainedPreparationVM','Assert-RetainedPreparationBaseline')
$nativeSource=@($currentSources|Where-Object name -CEQ 'NativeShadowDisk.cs')[0];$attachmentSource=@($currentSources|Where-Object name -CEQ 'Restore-GuestShadowAttachment.ps1')[0];$binarySource=@($currentSources|Where-Object name -CEQ 'lab-native-reconstruct.exe')[0]
$protectionNativeSource=@($currentSources|Where-Object name -CEQ 'NativeShadowReadOnlyAttachment.cs')[0];$mountNativeSource=@($currentSources|Where-Object name -CEQ 'NativeMountBoundary.cs')[0]
foreach($s in @($protectionNativeSource,$mountNativeSource)){if($s.sha256-cne(Get-NGRSource $hostProof $s.name).sha256){throw 'Proven exclusion implementation changed.'}}
if($nativeSource.sha256-cne$shadow.nativeSourceSha256-or$attachmentSource.sha256-cne(Get-NGRSource $hostProof 'Restore-GuestShadowAttachment.ps1').sha256){throw 'Frozen shadow attachment dependency changed.'}
$guestSources=@($currentSources|Where-Object name -CIn @('Invoke-GuestNativeReconstruct.ps1','Restore-GuestShadowAttachment.ps1','NativeShadowDisk.cs','NativeShadowReadOnlyAttachment.cs','NativeMountBoundary.cs'))
$baselineId=$hostProof.baselineId;$selectedId=$hostProof.quiescentCheckpointId;$selectedName=$hostProof.quiescentCheckpointName;$prior=$null;$trustedTicket=$null
if($Operation-cne'prepare'){
 $priorPath=Assert-NGRPath $PriorResultPath $labRoot;if([IO.Path]::GetFileName($priorPath)-cne'host-result.json'){throw 'Exact prior host-result required.'};$prior=Read-RHJson $priorPath $PriorResultSha256 2MB;Assert-RHPrior $prior $runId $RequestSha256 $RequestPinSha256 $TicketSha256 $Operation
 $priorRoot=Split-Path -Parent $priorPath;$trustedTicket=Read-RHJson (Join-Path $priorRoot 'ticket.json') $TicketSha256 64KB;Assert-NRTicket $trustedTicket $request
 $priorReport=Read-RHJson (Join-Path $priorRoot 'phase\result.json') $prior.nativeReportSha256 16MB;$priorProcess=Read-RHJson (Join-Path $priorRoot 'phase\process-result.json') $prior.processResultSha256 64KB
 if($priorProcess.completionKnown-isnot[bool]-or-not$priorProcess.completionKnown-or$priorProcess.exitCode-is[string]-or$priorProcess.exitCode-is[bool]-or$null-eq$priorProcess.exitCode-or$priorProcess.exitCode-ne0-or$priorProcess.ticketSha256-cne$TicketSha256){throw 'Prior process is not independently complete.'}
 $priorIntent='C:\ntfs2refs\native-reconstruct\'+$runId+'\'+$prior.phaseId+'\result.intent.json';Assert-NRResult $priorReport $request $prior.operation $RequestSha256 $trustedTicket $TicketSha256 $priorIntent $priorReport.intent_sha256 ('J:\ntfs2refs-shadow\'+$runId+'\reconstruction.journal')
 $selectedId=$prior.outcomeCheckpointId;$selectedName=$prior.outcomeCheckpointName
 Copy-RetainedProbePinned $priorPath (Join-Path $outputRoot 'prior-host-result.json') $PriorResultSha256 2MB|Out-Null
}
foreach($spec in @(@($requestPath,'request.json',$RequestSha256,128KB),@($requestPinPath,'request-pin.json',$RequestPinSha256,128KB),@($probeResultPath,'probe-host-result.json',$pin.probeResultSha256,2MB),@((Join-Path $probeRoot 'preparation-host-result.json'),'preparation-host-result.json',$hostProof.preparationResultSha256,2MB),@((Join-Path $probeRoot 'shadow-platform.json'),'shadow-platform.json',$prepared.shadowEvidenceSha256,1MB))){Copy-RetainedProbePinned $spec[0] (Join-Path $outputRoot $spec[1]) $spec[2] $spec[3]|Out-Null}
Write-RetainedProbeJson (Join-Path $outputRoot 'reviewed-source-manifest.json') $review 64KB
$requestPath=Join-Path $outputRoot 'request.json';$requestSha=$RequestSha256
$manifest=Read-LabManifest -Configuration $configuration -Lane win11;Assert-RetainedPreparationManifest $manifest
$vm=Assert-RetainedProbeCurrent $baselineId 4GB;Assert-RetainedPreparationBaseline (Get-ExactLabCheckpoint -VM $vm -Name installed-clean)
Assert-RetainedProbeCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $selectedName) $selectedId $selectedName
$outcomeName='reconstruct-'+$Operation+'-'+$phaseId;if(@(Get-VMSnapshot -VM $vm|Where-Object Name -CEQ $outcomeName).Count){throw 'New phase checkpoint already exists.'};Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 2GB
$credential=Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $configuration.Root 'win11\secrets\guest-credential.xml') $configuration.Root);if($credential-isnot[Management.Automation.PSCredential]-or$credential.UserName-cne'N2R-WIN11\LabAdmin'){throw 'Guest credential differs.'}
$record=[ordered]@{schemaVersion=1;kind='native-reconstruction-host';runId=$runId;phaseId=$phaseId;operation=$Operation;status='started';phase='preflight';vmId=$manifest.vmId;baselineId=$baselineId;requestSha256=$RequestSha256;requestPinSha256=$RequestPinSha256;probeResultSha256=$pin.probeResultSha256;priorResultSha256=$PriorResultSha256;inputTicketSha256=$TicketSha256;ticketSha256=$null;selectedCheckpointId=$selectedId;selectedCheckpointName=$selectedName;sourceHashes=$currentSources;reviewedSourcesSha256=$ReviewedSourcesSha256;phaseExported=$false;ticketExported=$false;nativeResultVerified=$false;cleanShutdown=$false;outcomeCheckpointCreated=$false;outcomeCheckpointId=$null;outcomeCheckpointName=$outcomeName;baselineRestored=$false;memoryRestored=$false;conversionQualified=$false;bootQualified=$false;automaticPhaseProgression=$false;createdUtc=[DateTime]::UtcNow.ToString('o')}
$script:session=$null;$script:transportUnknown=$false;$script:guestOperationUnknown=$false;$script:guestPhaseInFlight=$false;$script:progressIndex=0;$script:phase='preflight'
try{
 Save-RetainedProbeProgress;Assert-RetainedProbeCurrent $baselineId 4GB|Out-Null;$script:phase='restore-selected';Save-RetainedProbeProgress
 Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $selectedName -Confirm:$false|Out-Null;Wait-RetainedProbeRestored $selectedId 8GB|Out-Null
 Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null;$script:session=Open-RetainedProbeSession;$policy=Initialize-LabGuestSession -Session $session;if($policy.status-cne'ready'){throw 'Guest session policy refused.'};Write-RetainedProbeJson (Join-Path $outputRoot 'session.json') $policy 64KB;Copy-RetainedProbeGuestSources
 $script:phase='reattach-excluded';Save-RetainedProbeProgress;$attachment=Restore-RetainedProbeShadow Excluded attachment;$record['attachmentSha256']=($attachment.files|Where-Object name -CEQ 'attachment.json').sha256
 $guestRoot='C:\ntfs2refs\native-reconstruct\'+$runId+'\'+$phaseId
 $script:phase='stage-phase';Save-RetainedProbeProgress
 Invoke-RetainedProbeCommand -Arguments @($runId,$phaseId,$Operation,$TicketSha256) -Body {param($Run,$Phase,$Op,$Ticket)
  foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\native-reconstruct')){if(-not(Test-Path -LiteralPath $p)){New-Item -ItemType Directory -Path $p|Out-Null};$f=Get-Item -LiteralPath $p -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest phase parent differs.'}}
  $runRoot='C:\ntfs2refs\native-reconstruct\'+$Run
  if($Op-ceq'prepare'){if(Test-Path -LiteralPath $runRoot){throw 'Prepare run directory already exists.'};New-Item -ItemType Directory -Path $runRoot|Out-Null}else{$d=Get-Item -LiteralPath $runRoot -Force;if(-not$d.PSIsContainer-or($d.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Prior run directory differs.'};$t=Get-Item -LiteralPath ($runRoot+'\ticket.json') -Force;if($t.PSIsContainer-or($t.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$t.Length-lt1-or$t.Length-gt64KB-or(Get-FileHash -LiteralPath $t.FullName).Hash.ToLowerInvariant()-cne$Ticket){throw 'Checkpoint trusted ticket differs.'}}
  $phaseRoot=$runRoot+'\'+$Phase;if(Test-Path -LiteralPath $phaseRoot){throw 'New guest phase exists.'};New-Item -ItemType Directory -Path $phaseRoot|Out-Null
 }|Out-Null
 Copy-Item -LiteralPath $binarySource.archive -Destination ($guestRoot+'\lab-native-reconstruct.exe') -ToSession $session;Copy-Item -LiteralPath $requestPath -Destination ($guestRoot+'\request.json') -ToSession $session
 $script:phase='native-'+$Operation;$script:guestPhaseInFlight=$true;Save-RetainedProbeProgress
 $replies=@(Invoke-RetainedProbeCommand -Timeout ($NativeTimeoutSeconds+180) -Arguments @($runId,$phaseId,$Operation,$RequestSha256,$binarySource.sha256,$TicketSha256,$NativeTimeoutSeconds) -Body {param($Run,$Phase,$Op,$RequestHash,$BinaryHash,$TicketHash,$Seconds);& 'C:\ntfs2refs\guest\Invoke-GuestNativeReconstruct.ps1' -RunId $Run -PhaseId $Phase -Operation $Op -RequestSha256 $RequestHash -BinarySha256 $BinaryHash -TicketSha256 $TicketHash -TimeoutSeconds $Seconds -Confirm:$false})
 if($replies.Count-ne1){throw 'Ambiguous native phase reply.'};$reply=$replies[0];Set-RetainedProbeReplyState $reply
 if($reply.RunId-cne$runId-or$reply.PhaseId-cne$phaseId-or$reply.Operation-cne$Operation-or$reply.EvidenceDirectory-cne$guestRoot){throw 'Guest phase reply identity differs.'};Assert-RHBool $reply.ConversionQualified $false;Assert-RHBool $reply.StatePreservationRequired $true
 if($script:guestOperationUnknown){throw 'Unknown native phase completion: preserve process, session and branch.'}
 $script:phase='export-phase';Save-RetainedProbeProgress;$export=Export-RetainedProbe $guestRoot reconstruction phase;$record.phaseExported=$true
 if($reply.Status-cne'native-reconstruction-phase-verified-disks-offline'){throw 'Guest phase failed; exported bounded artifacts and preserved branch.'};Assert-RHBool $reply.NativeResultVerified $true;Assert-RHArtifacts $export.files $true
 $processResult=Read-RetainedProbeExport $export process-result.json 64KB;$processIntent=Read-RetainedProbeExport $export process-intent.json 64KB;$processStarted=Read-RetainedProbeExport $export process-started.json 64KB
 Assert-RHHash $reply.TicketSha256;if($Operation-cne'prepare'-and$reply.TicketSha256-cne$TicketSha256){throw 'Returned independent ticket differs.'};$record.ticketSha256=$reply.TicketSha256
 $ticketObservation=@(Invoke-RetainedProbeCommand -Arguments @($runId,$record.ticketSha256) -Body {param($Run,$Hash);$p='C:\ntfs2refs\native-reconstruct\'+$Run+'\ticket.json';$f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-lt1-or$f.Length-gt64KB-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$Hash){throw 'Independent ticket export pin differs.'};[pscustomobject]@{length=$f.Length;sha256=$Hash}})
 if($ticketObservation.Count-ne1){throw 'Ambiguous ticket observation.'};Copy-Item -LiteralPath ('C:\ntfs2refs\native-reconstruct\'+$runId+'\ticket.json') -Destination (Join-Path $outputRoot 'ticket.json') -FromSession $session
 $ticket=Read-RHJson (Join-Path $outputRoot 'ticket.json') $record.ticketSha256 64KB;Assert-NRTicket $ticket $request;if($trustedTicket){Assert-NRSame $trustedTicket $ticket};$record.ticketExported=$true
 Assert-RHProcess $processResult $processIntent $processStarted $request $runId $phaseId $Operation $RequestSha256 $binarySource.sha256 $record.ticketSha256 $NativeTimeoutSeconds
 foreach($a in $processResult.artifacts){$f=@($export.files|Where-Object name -CEQ $a.name);if($a.name-cnotin@('reconstruct.stdout','reconstruct.stderr','result.intent.json','result.json')-or$f.Count-ne1-or$f[0].length-ne$a.length-or$f[0].sha256-cne$a.sha256){throw 'Child artifact pins differ.'}}
 if(@($processResult.artifacts.name|Select-Object -Unique).Count-ne4-or($export.files|Where-Object name -CEQ 'request.json').sha256-cne$RequestSha256-or($export.files|Where-Object name -CEQ 'lab-native-reconstruct.exe').sha256-cne$binarySource.sha256){throw 'Exact child artifact coverage differs.'}
 $cli=Read-RetainedProbeExport $export result.json 16MB;$intent=Read-RetainedProbeExport $export result.intent.json 256KB;$intentHash=($export.files|Where-Object name -CEQ 'result.intent.json').sha256
 Assert-RHNativeIntent $intent $cli $request $Operation $RequestSha256 $runId $record.ticketSha256
 Assert-NRResult $cli $request $Operation $RequestSha256 $ticket $record.ticketSha256 ($guestRoot+'\result.intent.json') $intentHash ('J:\ntfs2refs-shadow\'+$runId+'\reconstruction.journal')
 $record.nativeResultVerified=$true;$record['nativeReportSha256']=($export.files|Where-Object name -CEQ 'result.json').sha256;$record['processResultSha256']=($export.files|Where-Object name -CEQ 'process-result.json').sha256
 $script:phase='clean-shutdown';Save-RetainedProbeProgress;Stop-RetainedProbeGuest $selectedId;$record.cleanShutdown=$true
 $script:phase='save-phase-checkpoint';Save-RetainedProbeProgress;$outcome=New-RetainedProbeCheckpoint $outcomeName $selectedId;$record.outcomeCheckpointId=[string]$outcome.Id;$record.outcomeCheckpointCreated=$true
 $script:phase='restore-baseline';Save-RetainedProbeProgress;$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;Assert-RetainedPreparationBaseline (Get-ExactLabCheckpoint -VM $vm -Name installed-clean)
 Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null;Complete-RetainedProbeBaseline $baselineId
 $record.baselineRestored=$true;$record.memoryRestored=$true;$record.status='native-phase-checkpointed';$script:phase='complete'
}catch{$record.status='failed-preserved';$record['error']=$_.Exception.ToString();$record['errorPosition']=$_.InvocationInfo.PositionMessage;throw}
finally{$record.phase=$script:phase;$record['transportCompletionUnknown']=$script:transportUnknown;$record['guestOperationUnknown']=($script:guestOperationUnknown-or$script:guestPhaseInFlight);$record['sessionPreserved']=($null-ne$session);$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-RetainedProbeJson (Join-Path $outputRoot 'host-result.json') $record;$credential=$null}
[pscustomobject]@{Status=$record.status;RunId=$runId;PhaseId=$phaseId;Operation=$Operation;EvidenceDirectory=$outputRoot;OutcomeCheckpointId=$record.outcomeCheckpointId;TicketSha256=$record.ticketSha256;BaselineRestored=$record.baselineRestored;ConversionQualified=$false}
