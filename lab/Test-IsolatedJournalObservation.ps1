<# Pure observation/compile tests. The native ObserveReadOnly entry is NEVER invoked. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Check $failed $Message}
Add-Type -Path @((Join-Path $PSScriptRoot 'guest/IsolatedJournalObservation.cs'),
 (Join-Path $PSScriptRoot 'guest/IsolatedJournalZero.cs'),(Join-Path $PSScriptRoot 'guest/IsolatedJournalDeviceProfile.cs'),
 (Join-Path $PSScriptRoot 'guest/IsolatedJournalReader.Windows.cs'),(Join-Path $PSScriptRoot 'tests/IsolatedJournalObservationTestStream.cs'))
$identity='a'*64;$length=2MB+512
$source=[IsolatedJournalObservationTestStream]::new($length)
$result=[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,$length,$identity)
Check ($result.complete-and$result.bytesRead-eq$length-and$result.requestedBytes-eq$length-and$source.Generated-eq$length) 'Observation omitted bytes.'
Check ($result.allZeroObserved-and$result.nonzeroBytes-eq0-and$result.firstNonzeroOffset-eq-1) 'Zero observation differs.'
Check ($result.identityToken-ceq$identity-and$result.informationalOnly-and-not$result.grantsInitializationAuthority-and-not$result.grantsWriteAuthority-and-not$result.atomicImmutabilityClaimed) 'Observation acquired authority or atomicity claims.'
$sha=[Security.Cryptography.SHA256]::Create();try{$expected=[BitConverter]::ToString($sha.ComputeHash([byte[]]::new($length))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
Check ($result.contentSha256-ceq$expected) 'Incremental observation hash differs.'
Check ([DateTimeOffset]::Parse($result.finishedUtc)-ge[DateTimeOffset]::Parse($result.startedUtc)) 'Observation timestamp interval differs.'
$source.Dispose()
Check ($result.bytesRead-eq$length-and$result.contentSha256-ceq$expected) 'Report unexpectedly depends on a live stream.'
foreach($offset in @(0,(1MB-1),1MB,($length-1))){
 $source=[IsolatedJournalObservationTestStream]::new($length);$source.NonzeroAt=$offset
 $observation=[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,$length,$identity)
 $bytes=[byte[]]::new($length);$bytes[$offset]=255;$sha=[Security.Cryptography.SHA256]::Create()
 try{$expectedNonzero=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 Check ($observation.complete-and-not$observation.allZeroObserved-and$observation.nonzeroBytes-eq1-and$observation.firstNonzeroOffset-eq$offset-and$observation.contentSha256-ceq$expectedNonzero) ('Nonzero bytes were refused or misreported at '+$offset)
 $source.Dispose()
}
$source=[IsolatedJournalObservationTestStream]::new($length);$source.MaximumRead=37
$result=[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,$length,$identity)
Check ($result.complete-and$result.bytesRead-eq$length-and$result.readCalls-gt3) 'Legitimate short reads were not completed.';$source.Dispose()
foreach($fault in @('early-end','read-error','extra-byte','changed-length','changed-access','closed-at-eof','bad-count','wrong-position','wrong-seek','writable','unreadable','unseekable')){
 $source=[IsolatedJournalObservationTestStream]::new($length)
 switch($fault){
  'early-end'{$source.EarlyEnd=$length-512} 'read-error'{$source.FailAt=1MB} 'extra-byte'{$source.ExtraByte=$true}
  'changed-length'{$source.ChangeLengthAtEnd=$true} 'changed-access'{$source.ChangeAccessAtEnd=$true} 'closed-at-eof'{$source.CloseAtEnd=$true}
  'bad-count'{$source.BadCount=$true} 'wrong-position'{$source.WrongPosition=$true} 'wrong-seek'{$source.WrongSeek=$true}
  'writable'{$source.Writable=$true} 'unreadable'{$source.Readable=$false} 'unseekable'{$source.Seekable=$false}
 }
 Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,$length,$identity)} ('Incomplete/changed observation accepted: '+$fault)
 $source.Dispose()
}
Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($null,512,$identity)} 'Null stream accepted.'
foreach($bytes in @(0,513,([Ntfs2RefsResearch.IsolatedJournalObservation]::JournalBytes+512))){
 $source=[IsolatedJournalObservationTestStream]::new($bytes)
 Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,$bytes,$identity)} 'Out-of-profile byte bound accepted.'
 Check ($source.ReadCalls-eq0) 'Invalid length caused a read.';$source.Dispose()
}
$source=[IsolatedJournalObservationTestStream]::new(512)
foreach($bad in @('',('A'*64),('a'*63),('g'*64))){Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveRange($source,512,$bad)} 'Malformed identity accepted.'}
Check ($source.ReadCalls-eq0) 'Invalid identity caused a read.'
Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveJournal($source,$identity)} 'Native journal entry accepted a short stream.'
Check ($source.ReadCalls-eq0) 'Wrong journal size caused a read.';$source.Dispose()
# Exact8GiB logical profile is exercised lazily; the injected first-read error
# prevents an expensive8GiB synthetic scan and creates no file or image.
$source=[IsolatedJournalObservationTestStream]::new(8GB);$source.FailAt=0
Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveJournal($source,$identity)} 'Injected journal read failure accepted.'
Check ($source.ReadCalls-eq1-and$source.Generated-eq0) 'Exact journal profile was not passed to bounded reads.';$source.Dispose()
$source=[IsolatedJournalObservationTestStream]::new(8GB);$source.MaximumRead=1
Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::ObserveJournal($source,$identity)} 'Read-call budget was not enforced.'
Check ($source.ReadCalls-eq[Ntfs2RefsResearch.IsolatedJournalObservation]::MaximumReadCalls) 'Unexpected read-call budget boundary.';$source.Dispose()
$method=[Ntfs2RefsResearch.IsolatedJournalReader].GetMethod('ObserveReadOnly')
Check ($method.ReturnType-eq[Ntfs2RefsResearch.IsolatedJournalContentObservation]) 'Native observation does not return the data-only report type.'
foreach($reportType in @([Ntfs2RefsResearch.IsolatedJournalContentObservation],[Ntfs2RefsResearch.IsolatedJournalStreamObservation])){
 Check (-not[IO.Stream].IsAssignableFrom($reportType)) 'Observation report is a Stream.'
 foreach($field in $reportType.GetFields([Reflection.BindingFlags]'Instance,Public,NonPublic')){
  Check (-not[IO.Stream].IsAssignableFrom($field.FieldType)-and-not[Runtime.InteropServices.SafeHandle].IsAssignableFrom($field.FieldType)-and$field.FieldType-ne[Ntfs2RefsResearch.ZeroProof]-and$field.FieldType-ne[IntPtr]) 'Observation report retains a stream, handle or proof.'
 }
}
Check (-not[Ntfs2RefsResearch.IsolatedJournalReader]::DurableWriterExclusionSupported) 'Observation enabled the durable proof path.'
$type=[Ntfs2RefsResearch.IsolatedJournalContentObservation]::new()
Check ($type.informationalOnly-and-not$type.grantsInitializationAuthority-and-not$type.grantsWriteAuthority-and-not$type.atomicImmutabilityClaimed-and-not$type.durableWriterFenceEstablished) 'Native report defaults claim authority.'
# Synthetic report consistency tests only: these objects are not native reads
# and this predicate grants no authority. The native caller invokes it only
# after actual complete read coverage and before/after identity observations.
$constructors=@([Ntfs2RefsResearch.IsolatedJournalStreamObservation].GetConstructors([Reflection.BindingFlags]'Instance,NonPublic'))
Check ($constructors.Count-eq1) 'Bounded observation fixture constructor differs.'
function Claimed([long]$Requested=8GB,[long]$Read=8GB,[long]$Calls=8193,[long]$Nonzero=0,[long]$First=-1,[string]$IdentityToken=$identity,[string]$Hash=('b'*64)){
 return $constructors[0].Invoke([object[]]@($IdentityToken,$Hash,'2026-10-27T00:00:00Z','2026-10-27T00:00:01Z',$Requested,$Read,$Calls,$Nonzero,$First))
}
$claim=Claimed
[Ntfs2RefsResearch.IsolatedJournalObservation]::RequireCompleteZeroObservation($claim,$identity)
Check (-not$claim.grantsInitializationAuthority-and-not$claim.grantsWriteAuthority) 'Zero-only observation predicate granted authority.'
Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::RequireCompleteZeroObservation($null,$identity)} 'Null native observation accepted.'
foreach($fault in @('short-request','short-read','no-reads','over-budget','nonzero','bad-first','foreign-identity','bad-hash')){
 $claim=switch($fault){
  'short-request'{Claimed -Requested (8GB-512)} 'short-read'{Claimed -Read (8GB-512)} 'no-reads'{Claimed -Calls 0}
  'over-budget'{Claimed -Calls ([Ntfs2RefsResearch.IsolatedJournalObservation]::MaximumReadCalls+1)}
  'nonzero'{Claimed -Nonzero 1 -First 0} 'bad-first'{Claimed -First 0} 'foreign-identity'{Claimed -IdentityToken ('c'*64)} 'bad-hash'{Claimed -Hash ('z'*64)}
 }
 Reject {[Ntfs2RefsResearch.IsolatedJournalObservation]::RequireCompleteZeroObservation($claim,$identity)} ('Zero-only predicate accepted '+$fault)
}
[pscustomobject]@{checks=$checks;passed=$true;nativeObservationCalls=0;nativeApiCalls=0;deviceOpens=0;vmOperations=0;imageFilesCreated=0}
