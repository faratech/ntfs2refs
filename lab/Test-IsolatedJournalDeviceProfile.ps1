<# Pure synthetic byte validation. No VM, native calls, device scans or images. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$ok,[string]$why){if(-not$ok){throw $why};$script:checks++}
function Reject([scriptblock]$action,[string]$why){$failed=$false;try{&$action|Out-Null}catch{$failed=$true};Check $failed $why}
$helper=Join-Path $PSScriptRoot 'guest/IsolatedJournalDeviceProfile.cs'
$text=Get-Content -LiteralPath $helper -Raw
Check ($text-cnotmatch'DllImport|CreateFile|DeviceIoControl|GetSystemFirmwareTable\(') 'Pure profile contains a native call/import.'
Add-Type -Path $helper
function U32([byte[]]$b,[int]$at,[uint32]$value){[BitConverter]::GetBytes($value).CopyTo($b,$at)}
function U16([byte[]]$b,[int]$at,[uint16]$value){[BitConverter]::GetBytes($value).CopyTo($b,$at)}
function NaaRow([byte[]]$b,[int]$at,[int]$next=0){
 U32 $b $at 1;U32 $b ($at+4) 3;U16 $b ($at+8) 16;U16 $b ($at+10) $next
 [byte[]]$naa=0x60,0x02,0x24,0x80,0x6a,0xac,0x26,0x1f,0x02,0x1f,0x24,0x95,0x96,0xf3,0x32,0xfc
 $naa.CopyTo($b,($at+16))
}
function Snapshot {
 $d=[byte[]]::new(12);U32 $d 0 7;U32 $d 4 2
 $l=[BitConverter]::GetBytes([long]8GB)
 $a=[byte[]]::new(28);U32 $a 0 28;U32 $a 4 28;U32 $a 16 512;U32 $a 20 4096
 $g=[byte[]]::new(48);U32 $g 0 2
 $r=[byte[]]::new(16);U32 $r 0 16
 $s=[byte[]]::new(8);U32 $s 0 8;$s[7]=2
 $ids=[byte[]]::new(44);U32 $ids 0 12;U32 $ids 4 44;U32 $ids 8 1;NaaRow $ids 12
 [pscustomobject]@{device=$d;length=$l;alignment=$a;layout=$g;attributes=$r;scsi=$s;identifiers=$ids}
}
function Validate($s){[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateSnapshot($s.device,$s.length,$s.alignment,$s.layout,$s.attributes,$s.scsi,$s.identifiers)}
function Smbios {
 $b=[byte[]]::new(41);$b[1]=2;$b[2]=6;U32 $b 4 33
 $b[8]=1;$b[9]=25;([guid][Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::FirmwareUuid).ToByteArray().CopyTo($b,16)
 $b[35]=127;$b[36]=4;return ,$b
}
$vm=[guid][Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::VmId
$machine=[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::MachineName
[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($vm,$machine,(Smbios));Check $true 'Valid caller refused.'
Check ([Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::JournalBytes-eq8GB) 'Journal size pin differs.'
$native=$false
foreach($method in [Ntfs2RefsResearch.IsolatedJournalDeviceProfile].GetMethods()){
 if(($method.Attributes-band[Reflection.MethodAttributes]::PinvokeImpl)-ne0){$native=$true}
}
Check (-not$native) 'Profile exposes native methods.'
foreach($case in @('foreign-vm','empty-vm','foreign-machine','lowercase-machine','null','short','oversize','old-version','short-header-length','long-header-length','truncated-formatted','short-type-one','missing-double-nul','wrong-uuid','big-endian-uuid','missing-type-one','duplicate-type-one','nonzero-tail','short-end-marker')){
 $b=Smbios;$id=$vm;$name=$machine
 switch($case){
  'foreign-vm'{$id=[guid]'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'} 'empty-vm'{$id=[guid]::Empty}
  'foreign-machine'{$name='HOST'} 'lowercase-machine'{$name=$machine.ToLowerInvariant()}
  'null'{$b=$null} 'short'{$b=[byte[]]::new(8)} 'oversize'{$b=[byte[]]::new(65537)}
  'old-version'{$b[2]=5} 'short-header-length'{U32 $b 4 32} 'long-header-length'{U32 $b 4 34}
  'truncated-formatted'{$b[9]=255} 'short-type-one'{$b[9]=24}
  'missing-double-nul'{$b[33]=1;$b[34]=1;$b[39]=1;$b[40]=1}
  'wrong-uuid'{$b[16]=$b[16]-bxor1}
  'big-endian-uuid'{[Array]::Reverse($b,16,4);[Array]::Reverse($b,20,2);[Array]::Reverse($b,22,2)}
  'missing-type-one'{$b[8]=2}
  'duplicate-type-one'{$copy=[byte[]]::new(68);[Array]::Copy($b,0,$copy,0,35);[Array]::Copy($b,8,$copy,35,27);[Array]::Copy($b,35,$copy,62,6);U32 $copy 4 60;$b=$copy}
  'nonzero-tail'{$b+=[byte]1;U32 $b 4 34}
  'short-end-marker'{$b[36]=3}
 }
 Reject {[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($id,$name,$b)} ('Caller accepted '+$case)
}
$b=Smbios;$b[1]=3;$b[2]=0
[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($vm,$machine,$b);Check $true 'SMBIOS3 byte order refused.'
$large=[byte[]]::new(65536);$b.CopyTo($large,0);U32 $large 4 65528
[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($vm,$machine,$large);Check $true 'Bounded maximum SMBIOS response refused.'
$bad=Smbios;$bad+=[byte[]]@(0,0);$bad[39]=65;U32 $bad 4 35
Reject {[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($vm,$machine,$bad)} 'SMBIOS end marker with strings accepted.'
# Walk an unrelated structure and ordinary strings before/after the type1.
$base=Smbios;$b=[byte[]]::new(51);[Array]::Copy($base,0,$b,0,8);U32 $b 4 43
$prefix=[byte[]]@(0,4,0,0,65,0,66,0,0);$prefix.CopyTo($b,8);[Array]::Copy($base,8,$b,17,27);[Array]::Copy($base,35,$b,44,6)
# The two bytes after Type1 are already its terminator; position44 starts type127.
[Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::ValidateCaller($vm,$machine,$b);Check $true 'SMBIOS structure/string walk failed.'
$s=Snapshot;$hash=Validate $s
Check ($hash-cmatch'\A[0-9a-f]{64}\z'-and$hash-ceq(Validate (Snapshot))) 'Snapshot hash is not deterministic lowercase SHA256.'
$framed=[IO.MemoryStream]::new();$domain=[Text.Encoding]::ASCII.GetBytes("n2r-isolated-journal-device-v1`0");$framed.Write($domain,0,$domain.Length)
foreach($key in @('device','length','alignment','layout','attributes','scsi','identifiers')){$raw=$s.$key;$n=[BitConverter]::GetBytes([uint32]$raw.Length);$framed.Write($n,0,4);$framed.Write($raw,0,$raw.Length)}
$sha=[Security.Cryptography.SHA256]::Create();try{$expected=[BitConverter]::ToString($sha.ComputeHash($framed.ToArray())).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$framed.Dispose()}
Check ($hash-ceq$expected) 'Raw length-framing hash contract differs.'
$s=Snapshot;U32 $s.device 8 ([uint32]::MaxValue);Check ((Validate $s)-cne$hash) 'RAW whole-device partition sentinel refused or normalized out of hash.'
$s=Snapshot;U32 $s.identifiers 0 16;Check ((Validate $s)-cne$hash) 'Descriptor structural version16 refused.'
$s=Snapshot;$s.alignment=[byte[]]::new(64);(Snapshot).alignment.CopyTo($s.alignment,0);$s.layout=[byte[]]::new(192);U32 $s.layout 0 2
Check ((Validate $s)-cne$hash) 'Bounded zero padding refused or normalized out of raw hash.'
$s=Snapshot;$s.identifiers=[byte[]]::new(65536);(Snapshot).identifiers.CopyTo($s.identifiers,0)
Check ((Validate $s)-cne$hash) 'Bounded maximum device-ID response padding refused.'
$s=Snapshot;U32 $s.alignment 8 64;U32 $s.alignment 12 32;Check ((Validate $s)-cne$hash) 'Valid cache alignment refused.'
# One additional port-associated ASCII vendor identifier, plus DWORD padding.
$s=Snapshot;$ids=[byte[]]::new(64);U32 $ids 0 12;U32 $ids 4 64;U32 $ids 8 2;NaaRow $ids 12 32
U32 $ids 44 2;U32 $ids 48 1;U16 $ids 52 3;U32 $ids 56 1;[Text.Encoding]::ASCII.GetBytes('ABC').CopyTo($ids,60);$s.identifiers=$ids
Check ((Validate $s)-cmatch'\A[0-9a-f]{64}\z') 'Valid additional identifier rejected.'
foreach($case in @('route-type','route-number','partition','wrong-length','alignment-version','alignment-size','logical-sector','physical-sector','sector-offset','cache-offset','cache-nonpower','alignment-padding','layout-style','partition-count','raw-reserved','attributes-version','attributes-reserved','attributes-bits','scsi-length','scsi-port','scsi-path','scsi-target','scsi-lun','id-version','id-size-small','id-size-large','id-count-zero','id-count-large','id-count-incomplete','id-code','id-type','id-association','id-payload-zero','id-payload-overflow','id-foreign-naa','id-last-next','id-padding','id-duplicate','id-overlap','id-unaligned','id-next-outside','id-nonzero-gap','id-invalid-ascii','id-invalid-utf8','id-missing-device')){
 $s=Snapshot
 switch($case){
  'route-type'{U32 $s.device 0 8} 'route-number'{U32 $s.device 4 1} 'partition'{U32 $s.device 8 2}
  'wrong-length'{[BitConverter]::GetBytes([long](8GB-512)).CopyTo($s.length,0)}
  'alignment-version'{U32 $s.alignment 0 24} 'alignment-size'{U32 $s.alignment 4 64}
  'logical-sector'{U32 $s.alignment 16 4096} 'physical-sector'{U32 $s.alignment 20 512} 'sector-offset'{U32 $s.alignment 24 512}
  'cache-offset'{U32 $s.alignment 12 1} 'cache-nonpower'{U32 $s.alignment 8 63}
  'alignment-padding'{$s.alignment+=[byte]1}
  'layout-style'{U32 $s.layout 0 1} 'partition-count'{U32 $s.layout 4 1} 'raw-reserved'{$s.layout[8]=1}
  'attributes-version'{U32 $s.attributes 0 8} 'attributes-reserved'{U32 $s.attributes 4 1} 'attributes-bits'{$s.attributes[8]=1}
  'scsi-length'{U32 $s.scsi 0 7} 'scsi-port'{$s.scsi[4]=1} 'scsi-path'{$s.scsi[5]=1} 'scsi-target'{$s.scsi[6]=1} 'scsi-lun'{$s.scsi[7]=1}
  'id-version'{U32 $s.identifiers 0 1} 'id-size-small'{U32 $s.identifiers 4 43} 'id-size-large'{U32 $s.identifiers 4 65537}
  'id-count-zero'{U32 $s.identifiers 8 0} 'id-count-large'{U32 $s.identifiers 8 1025} 'id-count-incomplete'{U32 $s.identifiers 8 2}
  'id-code'{U32 $s.identifiers 12 0} 'id-type'{U32 $s.identifiers 16 9} 'id-association'{U32 $s.identifiers 24 3}
  'id-payload-zero'{U16 $s.identifiers 20 0} 'id-payload-overflow'{U16 $s.identifiers 20 65535}
  'id-foreign-naa'{$s.identifiers[43]=$s.identifiers[43]-bxor1} 'id-last-next'{U16 $s.identifiers 22 32}
  'id-padding'{$s.identifiers+=[byte]1}
  'id-missing-device'{U32 $s.identifiers 24 1}
  default{
   $ids=[byte[]]::new(76);U32 $ids 0 12;U32 $ids 4 76;U32 $ids 8 2;NaaRow $ids 12 32;NaaRow $ids 44
   switch($case){
    'id-overlap'{U16 $ids 22 16} 'id-unaligned'{U16 $ids 22 33} 'id-next-outside'{U16 $ids 22 65532}
    'id-nonzero-gap'{$ids=[byte[]]::new(80);U32 $ids 0 12;U32 $ids 4 80;U32 $ids 8 2;NaaRow $ids 12 36;$ids[44]=1;NaaRow $ids 48}
    'id-invalid-ascii'{U32 $ids 44 2;U32 $ids 48 1;U32 $ids 56 1;$ids[60]=255}
    'id-invalid-utf8'{U32 $ids 44 3;U32 $ids 48 1;U32 $ids 56 1;$ids[60]=255}
   };$s.identifiers=$ids
  }
 }
 Reject {Validate $s} ('Snapshot accepted '+$case)
}
foreach($key in @('device','length','alignment','layout','attributes','scsi','identifiers')){
 $s=Snapshot;$s.$key=$null;Reject {Validate $s} ('Null '+$key+' accepted.')
 $s=Snapshot;$s.$key=[byte[]]$s.$key[0..($s.$key.Length-2)];Reject {Validate $s} ('Truncated '+$key+' accepted.')
}
foreach($entry in @(@('alignment',65),@('layout',193),@('identifiers',65537))){$s=Snapshot;$s.($entry[0])=[byte[]]::new($entry[1]);Reject {Validate $s} ('Overcap '+$entry[0]+' accepted.')}
[pscustomobject]@{checks=$checks;passed=$true;nativeOperations=0;deviceOperations=0;vmOperations=0;imageWrites=0}
