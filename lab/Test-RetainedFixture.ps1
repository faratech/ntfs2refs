<# Pure native-buffer/fake-API tests. No device or VM actions. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
Add-Type -Path @((Join-Path $repo 'lab\guest\NativeRetainedFixture.cs'),(Join-Path $repo 'lab\guest\NativeRetainedFixture.Windows.cs'),(Join-Path $PSScriptRoot 'FakeRetainedFixture.cs'))
$script:checks=0
function Check([bool]$Condition,[string]$Name){if(-not$Condition){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$bad=$false;try{&$Body|Out-Null}catch{$bad=$true};Check $bad $Name}
$id='0123456789abcdef0123456789abcdef';$a='\\?\Volume{11111111-1111-1111-1111-111111111111}\';$b='\\?\Volume{22222222-2222-2222-2222-222222222222}\'
[Ntfs2Refs.NativeRetainedFixture]::ValidateProfile('F:\',$a,$id,'A');$script:checks++
foreach($root in @('C:\','F:\x','\\server\share\','\\.\PhysicalDrive1','f:\')){Reject {[Ntfs2Refs.NativeRetainedFixture]::ValidateProfile($root,$a,$id,'A')} 'root boundary'}
Reject {[Ntfs2Refs.NativeRetainedFixture]::ValidateProfile('F:\',$a,$id,'B')} 'wrong role'
Reject {[Ntfs2Refs.NativeRetainedFixture]::ValidateProfile('S:\',$a,$id,'A')} 'wrong shadow role'
Reject {[Ntfs2Refs.NativeRetainedFixture]::ValidateProfile('F:\','\\?\Volume{00000000-0000-0000-0000-000000000000}\',$id,'A')} 'empty volume ID'
Reject {[Ntfs2Refs.NativeRetainedFixture]::Pattern('../x','A')} 'pattern run ID'
$pa=[Ntfs2Refs.NativeRetainedFixture]::Pattern($id,'A');$pb=[Ntfs2Refs.NativeRetainedFixture]::Pattern($id,'B')
Check ($pa.Length-eq65536-and$pb.Length-eq65536) 'pattern bound';$every=$true;for($i=0;$i-lt65536;$i++){if(($pa[$i]-bxor$pb[$i])-ne255){$every=$false;break}};Check $every 'all A/B bytes differ'
Check ([Ntfs2Refs.NativeRetainedFixture]::Hash($pa)-ceq'34e9681dba40e68b0d4bac869b2ea1801881fce70f13690269080650e16897e1') 'stable run pattern'
$basic=New-Object byte[] 40;for($i=0;$i-lt4;$i++){[BitConverter]::GetBytes([Ntfs2Refs.NativeRetainedFixture]::FixtureTime).CopyTo($basic,$i*8)};[BitConverter]::GetBytes([uint32]32).CopyTo($basic,32)
Check (([Ntfs2Refs.NativeRetainedFixture]::ParseBasic($basic,$false)).attributes-eq32) 'basic parse'
foreach($attr in @(0,16,512,1024,2048,16384,32800)){[BitConverter]::GetBytes([uint32]$attr).CopyTo($basic,32);Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseBasic($basic,$false)} 'unsupported attr'}
$standard=New-Object byte[] 24;[BitConverter]::GetBytes([long]65536).CopyTo($standard,0);[BitConverter]::GetBytes([long]65536).CopyTo($standard,8);[BitConverter]::GetBytes([uint32]1).CopyTo($standard,16)
Check (([Ntfs2Refs.NativeRetainedFixture]::ParseStandard($standard,$false)).eof-eq65536) 'standard parse'
foreach($idx in @(0,8,16,20,21)){$copy=$standard.Clone();$copy[$idx]=2;Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseStandard($copy,$false)} 'standard semantic refusal'}
$streams=New-Object byte[] 4096;[BitConverter]::GetBytes([uint32]14).CopyTo($streams,4);[BitConverter]::GetBytes([long]65536).CopyTo($streams,8);[BitConverter]::GetBytes([long]65536).CopyTo($streams,16);[Text.Encoding]::Unicode.GetBytes('::$DATA').CopyTo($streams,24)
Check (([Ntfs2Refs.NativeRetainedFixture]::ParseStreams($streams))[0]-ceq'::$DATA') 'unnamed stream'
$streams[0]=40;Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseStreams($streams)} 'ADS next offset';$streams[0]=0;$streams[24]=65;Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseStreams($streams)} 'named stream'
$map=New-Object byte[] 32;$map[0]=1;[BitConverter]::GetBytes([long]16).CopyTo($map,16);[BitConverter]::GetBytes([long]2097152).CopyTo($map,24)
Check (([Ntfs2Refs.NativeRetainedFixture]::ParseExtents($map))[0].lcn-eq2097152) 'positive mapping'
foreach($lcn in @([long]-1,[long]13631480,[long]::MaxValue)){[BitConverter]::GetBytes($lcn).CopyTo($map,24);Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseExtents($map)} 'negative/bounds map'}
$region=New-Object byte[] 40;$region[4]=1;$region[8]=1;[BitConverter]::GetBytes([long]65536).CopyTo($region,24);$region[32]=2
Check (([Ntfs2Refs.NativeRetainedFixture]::ParseValidRegions($region,2))[0].length-eq65536) 'full storage validity'
Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseValidRegions($region,1)} 'cached validity not inferred'
foreach($usage in @(0,1,32,255)){$region[32]=[byte]$usage;Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseValidRegions($region,2)} 'invalid native validity'}
Reject {[Ntfs2Refs.NativeRetainedFixture]::RegionInput(0)} 'usage input'
Check ([Ntfs2Refs.NativeRetainedFixture]::Offset(0,2097152)-eq8GB) 'native address arithmetic'
Reject {[Ntfs2Refs.NativeRetainedFixture]::Offset([long]::MaxValue,0)} 'offset overflow'
foreach($lcn in @(-1,0,65535,65537,13631488)){Reject {[Ntfs2Refs.NativeRetainedFixture]::MoveInput(1234,$lcn)} 'move bounds'}
$move=[Ntfs2Refs.NativeRetainedFixture]::MoveInput(1234,2097152);Check ($move.Length-eq32-and[BitConverter]::ToInt64($move,8)-eq0-and[BitConverter]::ToUInt32($move,24)-eq16) 'exact move ABI'
$bits=[FakeRetainedFixture]::Map(13631488);$bits2=$bits.Clone();$bits3=$bits.Clone();$bits2[16+262144]=1
Check ([Ntfs2Refs.NativeRetainedFixture]::SelectCandidate($bits,$bits2,$bits3)-eq2097168) 'intersection excludes allocated shadow'
$short=[FakeRetainedFixture]::Map(13631487);Check ([Ntfs2Refs.NativeRetainedFixture]::IsFree($short,2097152)) 'NTFS bounded declared total accepted'
Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckBitmap($bits[0..100])} 'truncated bitmap'
$padded=New-Object byte[] 2097152;[Array]::Copy($bits,$padded,$bits.Length);for($i=$bits.Length;$i-lt$padded.Length;$i++){$padded[$i]=255}
$coverage=[Ntfs2Refs.NativeRetainedFixture]::DescribeBitmap($padded)
Check ($coverage.declaredClusters-eq13631488-and$coverage.meaningfulBytes-eq1703952-and$coverage.returnedBytes-eq2097152-and$coverage.trailingBytes-eq393200-and$coverage.unusedBitsInLastByte-eq0) 'full capacity ReFS reply retains declared coverage'
Check ([Ntfs2Refs.NativeRetainedFixture]::SelectCandidate($short,$padded,$padded)-eq2097152) 'nonzero trailing bytes do not expand coverage'
$trimmed=New-Object byte[] ($bits.Length-1);[Array]::Copy($bits,$trimmed,$trimmed.Length);Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckBitmap($trimmed)} 'one missing meaningful byte refuses'
Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckBitmap((New-Object byte[] 2097153))} 'over capacity refuses'
$limited=[FakeRetainedFixture]::Map(2359296);$limitedPadded=New-Object byte[] 2097152;[Array]::Copy($limited,$limitedPadded,$limited.Length)
Reject {[Ntfs2Refs.NativeRetainedFixture]::IsFree($limitedPadded,2359296)} 'trailing zero bytes never extend declared clusters'
$partial=[Ntfs2Refs.NativeRetainedFixture]::DescribeBitmap($short);Check ($partial.declaredClusters-eq13631487-and$partial.unusedBitsInLastByte-eq1-and$partial.trailingBytes-eq0) 'partial last byte explicitly recorded'
Reject {[Ntfs2Refs.NativeRetainedFixture]::IsFree($short,13631472)} 'partial last byte cannot complete requested extent'
$offsetMap=$padded.Clone();[BitConverter]::GetBytes([long]8).CopyTo($offsetMap,0);Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckBitmap($offsetMap)} 'nonzero start remains unsupported'
Check ([FakeRetainedFixture]::Security($false).saclEmpty) 'full descriptor empty SACL'
$fake=New-Object FakeRetainedFixture;$r=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$true)
Check ($r.status-ceq'constructed-awaiting-raw-proof'-and$r.sourceFrozen-and$r.pairSemanticsMatch-and$r.cleanupComplete-and$r.privilegeRestored) 'construct success'
Check ($fake.creates-eq2-and$fake.moves-eq2-and$fake.sets-eq2-and$fake.closes-eq1) 'one move each and cleanup'
Check ($fake.seals-eq1-and$r.writeHandlesClosedBeforeFinalObservation) 'write handles closed before final observation'
Check ($r.lastAccessPolicyVerified-and$r.lastAccessPolicies.Count-eq12) 'all construction root folder and file handles suppress access updates'
Check ($r.namespaceVerified-and$r.namespaces.Count-eq10) 'all pinned native namespace observations complete'
[Ntfs2Refs.NativeRetainedFixture]::CheckAccessPolicies($r,$true);$script:checks++
$policy=$r.lastAccessPolicies[0];$policy.inputHex='0000000000000000';Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckAccessPolicies($r,$true)} 'timestamp assignment cannot masquerade as suppression';$policy.inputHex='ffffffffffffffff'
Reject {[Ntfs2Refs.NativeRetainedFixture]::AccessPolicy('C:\Windows\x','observation')} 'policy only owned fixtures'
Reject {[Ntfs2Refs.NativeRetainedFixture]::AccessPolicy('F:\retained\payload.bin','repair')} 'policy only observed handle stages'
$backend=[Ntfs2Refs.NativeRetainedFixture].Assembly.GetType('Ntfs2Refs.WindowsRetainedFixtureApi');$ft=$backend.GetNestedType('FT',[Reflection.BindingFlags]::NonPublic);$call=$backend.GetMethod('SetFileTime',([Reflection.BindingFlags]::Static-bor[Reflection.BindingFlags]::NonPublic));$parameters=$call.GetParameters()
Check ([Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($ft))-eq8-and$parameters.Length-eq4-and$parameters[1].ParameterType-eq[IntPtr]-and$parameters[2].ParameterType.IsByRef-and$parameters[2].ParameterType.GetElementType()-eq$ft-and$parameters[3].ParameterType-eq[IntPtr]) 'suppression uses exact FILETIME ABI with nullable other timestamps'
Check (-not$r.physicalMappingVerified-and-not$r.conversionQualified) 'no authority promotion'
Check (-not$r.source.after.fullyStorageValid-and-not$r.source.after.storageRegionQueryAttempted-and$r.source.after.storageValidityStatus-ceq'not-queried-NTFS-storage-validity-unknown') 'source storage remains explicitly unknown'
Check ($r.shadow.after.fullyStorageValid-and$r.shadow.after.storageRegionQueryAttempted) 'shadow storage remains measured'
$fake=New-Object FakeRetainedFixture;$r=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$false)
Check ($r.status-ceq'pair-observed'-and$fake.creates-eq0-and$fake.moves-eq0-and$fake.sets-eq0-and-not$r.targetWriteRequestsIssued) 'inspect has no setters or moves'
Check ($r.lastAccessPolicyVerified-and$r.lastAccessPolicies.Count-eq6) 'inspection suppression is separately explicit'
foreach($fault in @('open','create','partial-write','unclosed','unflushed','invented-NTFS-storage','storage','validity-hole','negative','integrity','enforcement','base','hash','identity','times','access-time','missing-access-policy','access-policy-failure','namespace-extra','namespace-incomplete','namespace-eof-error','wrong-map','sacl','pair-dir','overlap','stale','no-free','reject','throw-move','setter','seal','cleanup')){
 $fake=New-Object FakeRetainedFixture;$fake.fault=$fault;$r=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$true)
 Check ($r.status-in@('blocked','cleanup-failed')-and-not$r.sourceFrozen) ('blocked '+$fault)
 Check ($fake.closes-eq1-and$fake.moves-le2) ('bounded cleanup '+$fault)
 if($fault-in@('partial-write','unclosed','unflushed','invented-NTFS-storage','storage','validity-hole','negative','integrity','enforcement','base','sacl','overlap','stale','no-free')){Check ($fake.moves-eq0) ('no move after '+$fault)}
 if($fault-in@('reject','throw-move','setter')){Check ($fake.moves-eq1) ('no second move after '+$fault)}
}
$before=[FakeRetainedFixture]::Basic($false);$after=[FakeRetainedFixture]::Basic($false);$after.access=134372837118005111;Check (-not[Ntfs2Refs.NativeRetainedFixture]::SameBasic($before,$after)) 'measured access-only timestamp change still rejected'
$dir=[FakeRetainedFixture]::DirectoryBuffer('payload.bin',$false);$parsed=[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($dir);Check ($parsed.Count-eq1-and$parsed[0].name-ceq'payload.bin'-and$parsed[0].allocation-eq65536) 'native directory buffer parses ordinary file'
$zeroId=$dir.Clone();[Array]::Clear($zeroId,96,8);$zeroParsed=[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($zeroId);Check ($zeroParsed[0].fileId64-ceq'0x0000000000000000'-and$zeroParsed[0].name-ceq'payload.bin') 'directory64-bit ID is uninterpreted evidence including zero'
foreach($length in @(0,1,511,4096)){$bad=$dir.Clone();[BitConverter]::GetBytes([uint32]$length).CopyTo($bad,60);Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($bad)} 'directory filename length guard'}
foreach($offset in @(8,104,113,4096,4294967295)){$bad=$dir.Clone();[BitConverter]::GetBytes([uint32]$offset).CopyTo($bad,0);Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($bad)} 'directory next entry bound alignment'}
foreach($badName in @('x:y','x\y','x/y',('x'+[char]0+'y'))){Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory([FakeRetainedFixture]::DirectoryBuffer($badName,$false))} 'ambiguous directory name'}
$bad=$dir.Clone();$bad[68]=25;Reject {[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($bad)} 'short name length guard'
$first=[FakeRetainedFixture]::DirectoryBuffer('.',$true);[BitConverter]::GetBytes([uint32]112).CopyTo($first,0);[Array]::Copy($dir,0,$first,112,128);$entries=[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory($first);Check ($entries.Count-eq2-and$entries[1].name-ceq'payload.bin') 'aligned linked directory records'
$ns=New-Object Ntfs2Refs.RetainedNamespace;$ns.path='F:\retained';$ns.expectedFixture=$true;$ns.entries=$entries;[Ntfs2Refs.NativeRetainedFixture]::CheckNamespace($ns);$script:checks++
$ns.entries=@($entries[1],$entries[1]);Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckNamespace($ns)} 'duplicate directory entry refuses'
$ns.entries=@($entries[1]);$ns.entries[0].attributes=1056;Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckNamespace($ns)} 'reparse directory member refuses'
$emptyFake=New-Object FakeRetainedFixture;$emptyFake.fault='empty-root';$empty=[Ntfs2Refs.NativeRetainedFixture]::RunWith($emptyFake,$a,$b,$id,$true)
Check ($empty.status-ceq'constructed-awaiting-raw-proof'-and$empty.namespaceVerified-and$emptyFake.moves-eq2) 'bounded initial no-match then EOF permits later full construction'
Check ($empty.namespaces[0].emptyInitialNoMatchInterpreted-and$empty.namespaces[0].entries.Count-eq0-and-not$empty.queries[0].succeeded-and$empty.queries[0].nativeError-eq2-and-not$empty.queries[1].succeeded-and$empty.queries[1].nativeError-eq18) 'raw first error2 and continuation18 remain failures with explicit interpretation'
foreach($case in @('missing-continuation','later-error2','later-success','first-success','first-bytes','later-bytes','wrong-continuation-class','entries','unmarked','wrong-note')){
 $fake=New-Object FakeRetainedFixture;$fake.fault='empty-root';$bad=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$true)
 switch($case){'missing-continuation'{$bad.namespaces[0].queryNames=@($bad.namespaces[0].queryNames[0])}'later-error2'{$bad.queries[1].nativeError=2}'later-success'{$bad.queries[1].succeeded=$true}'first-success'{$bad.queries[0].succeeded=$true}'first-bytes'{$bad.queries[0].bytesReturned=1}'later-bytes'{$bad.queries[1].bytesReturned=1}'wrong-continuation-class'{$bad.queries[1].code=11}'entries'{$bad.namespaces[0].entries=[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory([FakeRetainedFixture]::DirectoryBuffer('System Volume Information',$true))}'unmarked'{$bad.namespaces[0].emptyInitialNoMatchInterpreted=$false}'wrong-note'{$bad.namespaces[0].initialNoMatchInterpretation='measured-empty'}}
 Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckNamespaces($bad,$true)} ('initial no-match '+$case)
}
$fake=New-Object FakeRetainedFixture;$fake.fault='empty-root';$bad=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$false);Check ($bad.status-ceq'blocked'-and$fake.moves-eq0-and$fake.creates-eq0) 'inspection never accepts initial no-match'
$fake=New-Object FakeRetainedFixture;$regular=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$b,$id,$true);$query=@($regular.queries|Where-Object name -CEQ ABeforeRootDirectory0)[0];$query.succeeded=$false;$query.nativeError=2;$query.bytesReturned=0;Reject {[Ntfs2Refs.NativeRetainedFixture]::CheckNamespaces($regular,$true)} 'populated stage cannot accept initial error2'
$before=[FakeRetainedFixture]::Basic($true);$after=[FakeRetainedFixture]::Basic($true);$after.access=134372845503312033;Check (-not[Ntfs2Refs.NativeRetainedFixture]::SameBasic($before,$after)) 'measured directory access-only timestamp change still rejected'
$fake=New-Object FakeRetainedFixture;Reject {[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,$a,$a,$id,$true)} 'volume alias';Check ($fake.creates-eq0-and$fake.moves-eq0) 'alias preflight'
Write-Output ("Retained fixture: {0} pure/native-buffer/mock checks passed; no VM/device calls."-f$script:checks)
