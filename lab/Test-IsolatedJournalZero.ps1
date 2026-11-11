<# Pure zero-scanner tests: lazy managed streams only, no native/device/file opens. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ('Ntfs2RefsResearch.ZeroProof' -as [type]) {throw 'Fresh process required.'}
Add-Type -Path (Join-Path $PSScriptRoot 'guest/IsolatedJournalZero.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'tests/IsolatedJournalTestStream.cs')
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
$identity='a'*64
$length=2MB+512
$source=[IsolatedJournalTestStream]::new($length)
$proof=[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($source,$length,$identity)
Check ($proof.CheckedBytes -eq $length -and $proof.RequestedBytes -eq $length -and $source.Generated -eq $length) 'Incomplete range counted as complete.'
Check (-not $proof.IsJournalScope -and -not $proof.GrantsWriteAuthority) 'Range proof acquired journal/write authority.'
$proof.AssertCurrent($source,$identity);Check $true 'Same held stream refused.'
$sha=[Security.Cryptography.SHA256]::Create()
try{$expected=[BitConverter]::ToString($sha.ComputeHash([byte[]]::new($length))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
Check ($proof.ContentSha256 -ceq $expected) 'Incremental stream hash differs.'
Check ($proof.GetType().GetConstructors().Count -eq 0) 'Public proof constructor exposed.'
Reject {$proof.AssertCurrent([IsolatedJournalTestStream]::new($length),$identity)} 'A different stream replayed the proof.'
Reject {$proof.AssertCurrent($source,('b'*64))} 'A different identity replayed the proof.'
$source.Bytes+=512
Reject {$proof.AssertCurrent($source,$identity)} 'Changed length retained a valid proof.'
$source.Dispose()
Reject {$proof.AssertCurrent($source,$identity)} 'Closed stream retained a valid proof.'
foreach($offset in @(0,(1MB-1),1MB,($length-1))){
 $bad=[IsolatedJournalTestStream]::new($length);$bad.NonzeroAt=$offset
 Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($bad,$length,$identity)} ('Nonzero byte accepted at '+$offset)
 $bad.Dispose()
}
foreach($fault in @('early-end','read-failure','extra-byte','changed-length','bad-count','writable','unreadable','unseekable')){
 $bad=[IsolatedJournalTestStream]::new($length)
 switch($fault){
  'early-end'{$bad.EarlyEnd=$length-512} 'read-failure'{$bad.FailAt=1MB}
  'extra-byte'{$bad.ExtraByte=$true} 'changed-length'{$bad.ChangeLengthAtEnd=$true}
  'bad-count'{$bad.BadReadCount=$true} 'writable'{$bad.Writable=$true}
  'unreadable'{$bad.Readable=$false} 'unseekable'{$bad.Seekable=$false}
 }
 Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($bad,$length,$identity)} ('Fault accepted: '+$fault)
 $bad.Dispose()
}
foreach($bytes in @(0,513,([Ntfs2RefsResearch.IsolatedJournalZero]::JournalBytes+512))){
 $bad=[IsolatedJournalTestStream]::new($bytes)
 Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($bad,$bytes,$identity)} 'Out-of-profile range accepted.'
 Check ($bad.ReadCalls -eq 0) 'Invalid range caused a read.';$bad.Dispose()
}
$short=[IsolatedJournalTestStream]::new(4096);$short.MaximumRead=37
$split=[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($short,4096,$identity)
Check ($split.CheckedBytes -eq 4096 -and $short.ReadCalls -gt 2) 'Legitimate partial reads were not completed.'
$short.Dispose()
$bad=[IsolatedJournalTestStream]::new(512)
foreach($token in @('',('A'*64),('a'*63),('g'*64))){Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanRange($bad,512,$token)} 'Invalid identity token accepted.'}
Check ($bad.ReadCalls -eq 0) 'Invalid identity caused a read.';$bad.Dispose()
$short=[IsolatedJournalTestStream]::new(512)
Reject {[Ntfs2RefsResearch.IsolatedJournalZero]::ScanJournal($short,$identity)} 'Production journal accepted short stream.'
Check ($short.ReadCalls -eq 0) 'Wrong journal length caused a read.';$short.Dispose()
# One production-sized lazy read checks the fixed 8GiB policy without a disk
# image or an 8GiB allocation. The scanner reuses its single 1MiB buffer.
$journal=[IsolatedJournalTestStream]::new([Ntfs2RefsResearch.IsolatedJournalZero]::JournalBytes)
$journalProof=[Ntfs2RefsResearch.IsolatedJournalZero]::ScanJournal($journal,$identity)
Check ($journalProof.IsJournalScope -and $journalProof.CheckedBytes -eq 8GB -and $journal.Generated -eq 8GB) 'Production scope did not verify all 8GiB.'
Check (-not $journalProof.GrantsWriteAuthority) 'Journal proof acquired write authority.'
$journalProof.AssertCurrent($journal,$identity);Check $true 'Production proof lost the same held stream.'
$journal.Dispose()
[pscustomobject]@{checks=$checks;passed=$true;nativeOperations=0;deviceOperations=0;vmOperations=0;largeFilesCreated=0}
