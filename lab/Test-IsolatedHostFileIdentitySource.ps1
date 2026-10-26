<# Compile and pure checks only. Never call Open with a valid path. No native,
   VM/device/credential operation, content scan, file mutation or policy change. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if('Ntfs2RefsResearch.IsolatedHostFileIdentity' -as [type]){throw 'Fresh process required.'}
Add-Type -Path (Join-Path $PSScriptRoot 'host/IsolatedHostFileIdentity.Windows.cs')
$script:checks=0
function Check([bool]$Good,[string]$Message){if(-not$Good){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$bad=$false;try{& $Action|Out-Null}catch{$bad=$true};Check $bad $Message}
$type=[Ntfs2RefsResearch.IsolatedHostFileIdentity];$flags=[Reflection.BindingFlags]'Static,NonPublic'
Check ($type.IsSealed-and$type.GetConstructors().Count-eq0-and@($type.GetConstructors([Reflection.BindingFlags]'Instance,NonPublic')|Where-Object{-not$_.IsPrivate}).Count-eq0) 'Live pin exposes construction or inheritance.'
Check ([IDisposable].IsAssignableFrom($type)) 'Pin does not own a disposal lifetime.'
$imports=@($type.GetMethods($flags)|Where-Object{$_.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false).Count-gt0}|Select-Object -ExpandProperty Name)
Check (@(Compare-Object ($imports|Sort-Object) (@('CreateFileW','GetFileInformationByHandleEx','GetFinalPathNameByHandleW')|Sort-Object)).Count-eq0) 'Unexpected native API surface.'
foreach($pair in @(@('ReadAttributes',0x80),@('ShareAccess',3),@('OpenExisting',3),@('OpenReparsePoint',0x00200000),@('BackupSemantics',0x02000000),@('FileIdInfo',18),@('FileStandardInfo',1),@('FileAttributeTagInfo',9),@('MaxComponents',64),@('MaxHeldHandles',8192))){
 Check ($type.GetField($pair[0],$flags).GetRawConstantValue()-eq$pair[1]) ('Native identity/budget constant differs: '+$pair[0])
}
$observation=[Ntfs2RefsResearch.IsolatedHostFileObservation]
Check ($observation.GetConstructors().Count-eq0-and$observation.GetFields().Count-eq0-and@($observation.GetProperties()|Where-Object{$null-ne$_.GetSetMethod()}).Count-eq0) 'Observation exposes mutable public state.'
# Valid strings exercise ONLY pure grammar, never the Open factory.
foreach($good in @('D:\code\ntfs2refs\file.vhdx','c:\data\file.vhdx',('E:\data\caf'+[char]0xe9+'.vhdx'))){
 Check ($type::ValidateDosPath($good).Length-eq$good.Length) 'Ordinary DOS grammar refused.'
}
$badPaths=@($null,'','D:relative.vhdx','\rooted.vhdx','\\server\share\file.vhdx','\\?\D:\file.vhdx','\\.\PhysicalDrive2','D:\','D:/file.vhdx','D:\a\..\file.vhdx','D:\.\file.vhdx','D:\a\\file.vhdx','D:\file.vhdx\','D:\file:stream','D:\file.','D:\file ','D:\CON','D:\con.txt','D:\CON .txt','D:\COM0.txt','D:\LPT9','D:\NUL','D:\CONIN$','D:\CLOCK$',('D:\bad'+[char]0+'name'),('D:\'+(('dir\'*64)+'leaf')))
foreach($bad in $badPaths){
 $refused=$false
 try{$type::Open($bad)|Out-Null}catch{$e=$_.Exception.InnerException;$refused=$e-is[IO.InvalidDataException]-and$e.Message-ceq'Absolute unambiguous local DOS file path required before native acquisition.'}
 Check $refused 'Invalid Open did not stop at its pure pre-native gate.'
}
$type::ValidateHandleBudget(0,65);Check $true 'Maximum bounded path reservation refused.'
$type::ValidateHandleBudget(8191,1);Check $true 'Final available native handle refused.'
foreach($case in @(@(8192,1),@(8193,1),@(-1,1),@(0,0),@(0,66))){Reject {$type::ValidateHandleBudget($case[0],$case[1])} 'Invalid global/path handle budget accepted.'}

$id=[byte[]]::new(24);$id[0]=1
for($i=0;$i-lt16;$i++){$id[8+$i]=[byte]($i+1)}
$standard=[byte[]]::new(24);[BitConverter]::GetBytes([long]4096).CopyTo($standard,0);[BitConverter]::GetBytes([long]1024).CopyTo($standard,8);$standard[16]=1
$tag=[byte[]]::new(8);$tag[0]=0x20
$path='\\?\Volume{11111111-1111-1111-1111-111111111111}\dir\file.vhdx'
$type::ValidateReply($path,$id,$standard,$tag,$false);Check $true 'Ordinary native byte reply refused.'
Check ($type::FormatRawFileId($id)-ceq'0x0102030405060708090a0b0c0d0e0f10') 'Raw file ID bytes were reordered.'
Check ($type::FormatVolumeSerial($id)-ceq'0x0000000000000001') 'Volume serial numeric formatting differs.'
foreach($kind in @('id-size','zero-id','zero-serial','standard-size','tag-size','delete-pending','directory','device','reparse','tag-value','no-links','negative-length')){
 $i=[byte[]]$id.Clone();$s=[byte[]]$standard.Clone();$a=[byte[]]$tag.Clone()
 switch($kind){
  'id-size'{$i=[byte[]]::new(23)} 'zero-id'{[Array]::Clear($i,8,16)} 'zero-serial'{[Array]::Clear($i,0,8)}
  'standard-size'{$s=[byte[]]::new(23)} 'tag-size'{$a=[byte[]]::new(7)}
  'delete-pending'{$s[20]=1} 'directory'{$s[21]=1} 'device'{$a[0]=0x40}
  'reparse'{$a[1]=4} 'tag-value'{$a[4]=1} 'no-links'{$s[16]=0} 'negative-length'{$s[15]=128}
 }
 Reject {$type::ValidateReply($path,$i,$s,$a,$false)} ('Invalid native reply accepted: '+$kind)
}
foreach($bad in @('D:\dir\file.vhdx','\\?\UNC\server\file','\\?\Volume{00000000-0000-0000-0000-000000000000}\file','\\?\Volume{11111111-1111-1111-1111-111111111111}\..\file','\\?\Volume{11111111-1111-1111-1111-111111111111}\file:ads','\\?\Volume{11111111-1111-1111-1111-111111111111}\')){
 Reject {$type::ValidateReply($bad,$id,$standard,$tag,$false)} 'Noncanonical final leaf path accepted.'
}
$directory=[byte[]]$standard.Clone();$directory[21]=1;$dirTag=[byte[]]::new(8);$dirTag[0]=0x10
$type::ValidateReply('\\?\Volume{11111111-1111-1111-1111-111111111111}\',$id,$directory,$dirTag,$true);Check $true 'Pinned volume-root reply refused.'
Check (-not$type::ValidateStableReplies($path,$id,$standard,$tag,$path,$id,$standard,$tag,$false)) 'Unchanged reply reported length change.'
$grown=[byte[]]$standard.Clone();[BitConverter]::GetBytes([long]8192).CopyTo($grown,8)
Check ($type::ValidateStableReplies($path,$id,$standard,$tag,$path,$id,$grown,$tag,$false)) 'Running VM growth was rejected or treated as immutable.'
foreach($kind in @('id','serial','links','path','reparse')){
 $i=[byte[]]$id.Clone();$s=[byte[]]$standard.Clone();$a=[byte[]]$tag.Clone();$after=$path
 switch($kind){'id'{$i[8]=99} 'serial'{$i[0]=2} 'links'{$s[16]=2} 'path'{$after=$path.Replace('file.vhdx','other.vhdx')} 'reparse'{$a[1]=4}}
 Reject {$type::ValidateStableReplies($path,$id,$standard,$tag,$after,$i,$s,$a,$false)} ('Changed held identity accepted: '+$kind)
}
[pscustomobject]@{checks=$script:checks;passed=$true;compile_only_native_adapter=$true;native_calls=0;valid_open_calls=0;vm_operations=0;device_opens=0;credentials_accessed=0;content_reads=0;file_mutations=0;writer_exclusion_proven=$false}
