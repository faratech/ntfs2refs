<# Pure metadata/layout and fake native lifecycle tests; no VM or native API calls. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$repo=Split-Path -Parent $PSScriptRoot;$script:checks=0
$sources=@('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs','NativeConvertedVerification.cs','NativeConvertedVerification.Windows.cs'|ForEach-Object{Join-Path $PSScriptRoot ('guest\'+$_)})+@((Join-Path $PSScriptRoot 'FakeRetainedFixture.cs'),(Join-Path $PSScriptRoot 'FakeConvertedVerification.cs'));Add-Type -Path $sources
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$failed=$false;try{&$Body|Out-Null}catch{$failed=$true};Check $failed $Name}
$expected=[FakeConvertedVerification]::Expected();[Ntfs2Refs.NativeConvertedVerification]::ValidateExpected($expected);$script:checks++
foreach($row in @(@($true,$false,0x00020081L),@($true,$true,0x01020081L),@($false,$false,0x80020080L),@($false,$true,0x81020080L))){$mask=[Ntfs2Refs.NativeConvertedVerification]::ObservationAccess($row[0],$row[1]);Check ($mask-eq$row[2]) 'exact directory-list/file-read access mask';Check (($mask-band0x40000116L)-eq0) 'observation mask has no payload or attribute writes'}
foreach($field in @('runId','diskGuid','partitionGuid','volumeGuid','sourceSha256','shadowSha256','fileId128','volumeSerial64','ownerSid','fileSddl','directorySddl')){$bad=[FakeConvertedVerification]::Expected();$bad.$field='';Reject {[Ntfs2Refs.NativeConvertedVerification]::ValidateExpected($bad)} ('expected '+$field)}
foreach($offset in @(0L,8589934593L,9663676416L,[long]::MaxValue)){$bad=[FakeConvertedVerification]::Expected();$bad.retainedOffset=$offset;Reject {[Ntfs2Refs.NativeConvertedVerification]::ValidateExpected($bad)} 'retained bound'}
$fake=New-Object FakeConvertedVerification;$result=[Ntfs2Refs.NativeConvertedVerification]::RunWith($fake,$expected)
Check ($result.complete-and$result.stable-and$result.cleanupComplete-and$result.privilegeRestored-and$result.status-ceq'retained-A-observed-through-protected-ReFS') 'complete protected native observation'
Check ($fake.opens-eq1-and$fake.captures-eq4-and$fake.reads-eq2-and$fake.reopens-eq1-and$fake.closes-eq1-and$result.payloadBytesRead-eq131072-and$result.payloadHashes.Count-eq2) 'bounded sequence'
Check (-not$result.targetWriteRequestsIssued-and-not$result.protectionChanged-and-not$result.mountRequested-and-not$result.explicitFlushRequested-and-not$result.conversionQualified) 'no mutation or conversion authority'
foreach($fault in @('open','disk','protection','flags','volume','identity','mapping','negative','base','storage','hole','cached','integrity','integrity-flags','sacl','security','ads','links','namespace','access','directory-time','raw-instability','directory-id','read','short','B','reopen','cleanup','privilege')){
 $fake=New-Object FakeConvertedVerification;$fake.fault=$fault;$result=[Ntfs2Refs.NativeConvertedVerification]::RunWith($fake,$expected)
 Check (-not$result.complete-and$result.status-in@('blocked','cleanup-failed')) ('refusal '+$fault)
 Check ($fake.closes-eq1-and$fake.reads-le2-and$fake.reopens-le1) ('cleanup bounds '+$fault)
 if($fault-in@('open','disk','protection','flags','volume','identity','mapping','negative','base','storage','hole','cached','integrity','integrity-flags','sacl','security','ads','links','namespace','directory-time')){Check ($fake.reads-eq0) ('no read after '+$fault)}
}
# Synthetic complete two-partition GPT reply, only native layout parsing below.
$layout=New-Object byte[] 336;[BitConverter]::GetBytes([uint32]1).CopyTo($layout,0);[BitConverter]::GetBytes([uint32]2).CopyTo($layout,4);([guid]$expected.diskGuid).ToByteArray().CopyTo($layout,8);[BitConverter]::GetBytes([long]17408).CopyTo($layout,24);[BitConverter]::GetBytes([long](64GB-34816)).CopyTo($layout,32)
foreach($spec in @(@(48,1,1MB,15MB,'e3c9e316-0b5c-4db8-817d-f92df00215ae','77777777-7777-7777-7777-777777777777'),@(192,2,16MB,52GB,'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7',$expected.partitionGuid))){$p=[int]$spec[0];[BitConverter]::GetBytes([uint32]1).CopyTo($layout,$p);[BitConverter]::GetBytes([long]$spec[2]).CopyTo($layout,$p+8);[BitConverter]::GetBytes([long]$spec[3]).CopyTo($layout,$p+16);[BitConverter]::GetBytes([uint32]$spec[1]).CopyTo($layout,$p+24);([guid]$spec[4]).ToByteArray().CopyTo($layout,$p+32);([guid]$spec[5]).ToByteArray().CopyTo($layout,$p+48)}
[Ntfs2Refs.NativeConvertedVerification]::ValidateLayout($layout,$expected);$script:checks++
foreach($at in @(0,4,8,192,200,208,216,224,240,256)){$bad=$layout.Clone();$bad[$at]=$bad[$at]-bxor1;Reject {[Ntfs2Refs.NativeConvertedVerification]::ValidateLayout($bad,$expected)} ('layout '+$at)}
Reject {[Ntfs2Refs.NativeConvertedVerification]::ValidateLayout($layout[0..334],$expected)} 'truncated layout'
# Ensure the distinct backend cannot accidentally expose a forbidden native import.
$type=[Ntfs2Refs.NativeConvertedVerification].Assembly.GetType('Ntfs2Refs.WindowsConvertedVerificationApi');$imports=@($type.GetMethods([Reflection.BindingFlags]'Static,NonPublic')|Where-Object{$_.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false).Count})
Check (@($imports|Where-Object Name -In @('WriteFile','SetFileTime','SetFileInformationByHandle','FlushFileBuffers','AttachVirtualDisk','DetachVirtualDisk')).Count-eq0) 'query backend has no mutation entry points'
Write-Output ("Converted verification: {0} pure/fake/layout checks passed; no VM/native calls."-f$script:checks)
