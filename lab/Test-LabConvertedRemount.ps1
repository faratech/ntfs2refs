<# Pure predecessor/mode tests. Does not restore, boot or access a guest/device. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$script:checks=0
$workspace=Split-Path -Parent $PSScriptRoot
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$failure=$null;try{&$Body|Out-Null}catch{$failure=$_};Check ($null-ne$failure) $Name}
function Clone($Value){$Value|ConvertTo-Json -Depth 20|ConvertFrom-Json}
$path=Join-Path $workspace 'scripts/Invoke-LabConvertedVerification.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Check ($errors.Count-eq0) 'Host source must parse.'
foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($f.Extent.Text))}
Import-CVGuards ([IO.File]::ReadAllBytes((Join-Path $workspace 'scripts/Invoke-LabNativeReconstruct.ps1'))) @('Assert-RHBool','Assert-RHInteger')
Import-CVGuards ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'guest/Invoke-GuestNativeProbe.ps1'))) @('Assert-NativeProbeGuid')
$hash='a'*64;$run='b'*32;$prepareHash='c'*64;$applyHash='d'*64;$handoffHash='e'*64
Assert-CVModeInputs first-mount '' '';$script:checks++
Assert-CVModeInputs clean-remount 'ordinary/host-result.json' $hash;$script:checks++
foreach($mode in @('unknown','CLEAN-REMOUNT','')){Reject {Assert-CVModeInputs $mode '' ''} 'Unknown/case-shifted mode accepted.'}
foreach($modeCase in @(@('first-mount','p',''),@('first-mount','',$hash),@('first-mount',' ',' '),@('clean-remount','',$hash),@('clean-remount','  ',$hash),@('clean-remount','p',''),@('clean-remount','p','BAD'))){Reject {Assert-CVModeInputs $modeCase[0] $modeCase[1] $modeCase[2]} 'Mode/provenance pairing accepted.'}
$h=[pscustomobject]@{runId=$run;vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';requestSha256=$hash;ticketSha256=$hash;outcomeCheckpointId='e10dadcb-27e3-4551-9115-413e2a6d4cba';outcomeCheckpointName='reconstruct-handoff-22eefc99800a473687e43b9e80125439'}
$prior=[pscustomobject]@{schemaVersion=1;kind='converted-verification-host';status='retained-A-observed-readonly-checkpointed';phase='complete';runId=$run;vmId=$h.vmId;baselineId=$h.baselineId;mountId=('1'*32);observationId=('2'*32);prepareResultSha256=$prepareHash;applyResultSha256=$applyHash;handoffResultSha256=$handoffHash;requestSha256=$hash;ticketSha256=$hash;reviewedSourcesSha256=$hash;mountEvidenceSha256=$hash;verificationEvidenceSha256=$hash;inputSha256=$hash;selectedCheckpointId=$h.outcomeCheckpointId;selectedCheckpointName=$h.outcomeCheckpointName;outcomeCheckpointId='e7fda999-ad2e-4792-9011-e9b4fdaebf21';outcomeCheckpointName=('converted-readonly-'+('2'*32));attachmentExported=$true;mountExported=$true;verificationExported=$true;retainedNativeObservationVerified=$true;cleanShutdown=$true;outcomeCheckpointCreated=$true;baselineRestored=$true;memoryRestored=$true;transportCompletionUnknown=$false;guestOperationUnknown=$false;sessionPreserved=$false;journalRecoveryRequested=$false;reconstructionPhaseInvoked=$false;rawPayloadWriteRequestsIssued=$false;conversionQualified=$false;bootQualified=$false}
Assert-CVPriorObservation $prior $h $prepareHash $applyHash $handoffHash;$script:checks++
foreach($name in @('kind','status','phase','runId','vmId','baselineId','mountId','observationId','prepareResultSha256','applyResultSha256','handoffResultSha256','requestSha256','ticketSha256','reviewedSourcesSha256','mountEvidenceSha256','verificationEvidenceSha256','inputSha256','selectedCheckpointId','selectedCheckpointName','outcomeCheckpointId','outcomeCheckpointName')){$bad=Clone $prior;$bad.$name='wrong';Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} ('Changed prior field accepted: '+$name)}
foreach($value in @('1',$true,0,2)){$bad=Clone $prior;$bad.schemaVersion=$value;Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} 'Bad schema type/value accepted.'}
foreach($name in @('attachmentExported','mountExported','verificationExported','retainedNativeObservationVerified','cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored','transportCompletionUnknown','guestOperationUnknown','sessionPreserved','journalRecoveryRequested','reconstructionPhaseInvoked','rawPayloadWriteRequestsIssued','conversionQualified','bootQualified')){foreach($value in @('false',0,(-not$prior.$name))){$bad=Clone $prior;$bad.$name=$value;Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} ('Prior uncertainty/type accepted: '+$name)}}
$bad=Clone $prior;$bad.outcomeCheckpointId=$h.outcomeCheckpointId;Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} 'Handoff replay substituted for converted outcome.'
$bad=Clone $prior;$bad|Add-Member NoteProperty error 'failed';Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} 'Prior error accepted.'
foreach($pair in @(@('mode','clean-remount'),@('mountBoundaryInvoked',$false),@('mountEvidenceReused',$true))){$bad=Clone $prior;$bad|Add-Member NoteProperty $pair[0] $pair[1];Reject {Assert-CVPriorObservation $bad $h $prepareHash $applyHash $handoffHash} 'Inconsistent first-mount mode accepted.'}
$modern=Clone $prior;$modern|Add-Member NoteProperty mode first-mount;$modern|Add-Member NoteProperty mountBoundaryInvoked $true;$modern|Add-Member NoteProperty mountEvidenceReused $false
Assert-CVPriorObservation $modern $h $prepareHash $applyHash $handoffHash;$script:checks++
$proof=[pscustomobject]@{sourceHashes=@(Get-CVSources|ForEach-Object{[pscustomobject]@{name=[IO.Path]::GetFileName($_);sha256=$hash}})}
$recorded=Get-CVRecordedReview $proof;Check ($recorded.files.Count-eq17-and$recorded.files[0].sha256-ceq$hash) 'Recorded host source set did not reconstruct.'
$bad=Clone $proof;$bad.sourceHashes=$bad.sourceHashes[0..15];Reject {Get-CVRecordedReview $bad} 'Incomplete recorded source set accepted.'
$bad=Clone $proof;$bad.sourceHashes[1].name=$bad.sourceHashes[0].name;Reject {Get-CVRecordedReview $bad} 'Duplicate recorded source accepted.'
foreach($index in 0..16){$bad=Clone $proof;$bad.sourceHashes[$index].name='foreign';Reject {Get-CVRecordedReview $bad} 'Foreign recorded source accepted.';$bad=Clone $proof;$bad.sourceHashes[$index].sha256='BAD';Reject {Get-CVRecordedReview $bad} 'Malformed recorded source pin accepted.'}
$dry=&$path -Mode clean-remount -WhatIf;Check ($dry.DryRun-and$dry.Mode-ceq'clean-remount'-and-not$dry.HandoffReplayAllowed) 'Remount WhatIf must return without provenance/VM work.'
# Invalid combinations stop before reading a source manifest or importing Hyper-V.
Reject {&$path -Mode first-mount -PriorVerificationResultPath p -Confirm:$false} 'First-mount invocation accepted unexpected prior.'
Reject {&$path -Mode clean-remount -Confirm:$false} 'Remount invocation did not require prior provenance.'
Write-Output ('PASS: '+$script:checks+' clean-remount mode/predecessor checks; no VM/native calls.')
