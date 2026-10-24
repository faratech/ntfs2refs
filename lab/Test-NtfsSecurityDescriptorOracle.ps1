<# Windows buffer oracle only. Does not open a volume or query file permissions. #>
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$InspectionPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$InspectionSha256,
 [string]$OutputPath
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:checks++}
function Hash([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Unhex([string]$Value){Check ($Value.Length-ge40-and$Value.Length-le524248-and$Value.Length%2-eq0-and$Value-cmatch'\A[0-9a-f]+\z') 'Bounded relative descriptor hex required.';$bytes=New-Object byte[] ($Value.Length/2);for($i=0;$i-lt$bytes.Length;$i++){$bytes[$i]=[Convert]::ToByte($Value.Substring(2*$i,2),16)};return ,$bytes}
Check ($env:OS-ceq'Windows_NT'-and[Environment]::Is64BitProcess-and-not('NtfsSecurityBufferOracle'-as[type])) 'Fresh isolated x64 Windows process required.'
$at=[IO.Path]::GetFullPath($InspectionPath);while($at){$f=Get-Item -LiteralPath $at -Force;Check (-not($f.Attributes-band([IO.FileAttributes]::ReparsePoint-bor[IO.FileAttributes]::Compressed-bor[IO.FileAttributes]::Encrypted))) 'Ordinary pinned report required.';$at=[IO.Path]::GetDirectoryName($at)}
$f=Get-Item -LiteralPath $InspectionPath;Check (-not$f.PSIsContainer-and$f.Length-gt0-and$f.Length-le32MB) 'Inspection report size differs.'
$hold=New-Object IO.FileStream($f.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
 $bytes=New-Object byte[] $hold.Length;$at=0;while($at-lt$bytes.Length){$n=$hold.Read($bytes,$at,$bytes.Length-$at);Check ($n-gt0) 'Short report read.';$at+=$n};Check ((Hash $bytes)-ceq$InspectionSha256) 'Independent inspection hash differs.'
 $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes);if($text[0]-eq[char]0xfeff){$text=$text.Substring(1)};$inspection=$text|ConvertFrom-Json
 Check ($inspection.schema_version-eq1-and$inspection.filesystem.filesystem-ceq'Ntfs') 'Pinned NTFS inspection required.';$r=$inspection.filesystem.details.security_reconciliation
 Check ($r.status-ceq'consistent_raw_model'-and@($r.descriptors).Count-ge1-and@($r.descriptors).Count-le16384-and@($r.bindings).Count-eq$r.bound_files) 'Complete raw security model required.'
 Add-Type @'
using System.Runtime.InteropServices;
public static class NtfsSecurityBufferOracle {
 [DllImport("advapi32.dll")][return:MarshalAs(UnmanagedType.Bool)]public static extern bool IsValidSecurityDescriptor([In]byte[] descriptor);
 [DllImport("advapi32.dll")]public static extern uint GetSecurityDescriptorLength([In]byte[] descriptor);
}
'@
 $rows=@();$aceCount=0;$known=New-Object 'Collections.Generic.HashSet[string]'
 foreach($entry in $r.descriptors){
  $d=$entry.descriptor;$bytes=Unhex $d.relative_hex;Check ((Hash $bytes)-ceq$d.sha256) 'Descriptor hash differs.'
  Check ($bytes[0]-eq1-and([BitConverter]::ToUInt16($bytes,2)-band0x8000)-ne0) 'Relative revision1 descriptor required.'
  # The managed constructor bounds-checks the relative components before the
  # pointer-based native validators receive this already-pinned byte buffer.
  $managed=New-Object Security.AccessControl.RawSecurityDescriptor($bytes,0)
  Check ([NtfsSecurityBufferOracle]::IsValidSecurityDescriptor($bytes)) 'Windows rejected descriptor buffer.'
  Check ([NtfsSecurityBufferOracle]::GetSecurityDescriptorLength($bytes)-eq$d.minimum_length) 'Windows descriptor length differs.'
  Check ([int]$managed.ControlFlags-eq$d.control) 'Windows control flags differ.'
  $owner=if($null-ne$managed.Owner){$managed.Owner.Value}else{$null};$group=if($null-ne$managed.Group){$managed.Group.Value}else{$null}
  Check ($owner-ceq$d.owner_sid-and$group-ceq$d.group_sid) 'Windows owner/group SID differs.'
  foreach($pair in @(@('dacl',4,$managed.DiscretionaryAcl),@('sacl',16,$managed.SystemAcl))){
   $decoded=$d.($pair[0]);$nativeAcl=$pair[2];$present=($d.control-band$pair[1])-ne0
   $state=if(-not$present){'absent'}elseif($null-eq$nativeAcl){'null'}else{'present'}
   Check ($state-ceq$decoded.state) 'Absent/null/empty ACL distinction differs.'
   if($state-ceq'present'){
    Check ($nativeAcl.Revision-eq$decoded.revision-and$nativeAcl.Count-eq@($decoded.aces).Count) 'Windows ACL revision/count differs.'
    for($i=0;$i-lt$nativeAcl.Count;$i++){
     $a=$decoded.aces[$i];$n=$nativeAcl[$i];$raw=New-Object byte[] $n.BinaryLength;$n.GetBinaryForm($raw,0)
     Check ($raw.Length-eq$a.length-and[int]$n.AceType-eq$a.ace_type-and[int]$n.AceFlags-eq$a.flags) 'Windows ACE type/flags/size differs.'
     Check ($n-is[Security.AccessControl.QualifiedAce]) 'Windows cannot interpret this ACE trustee.'
     Check ($n.SecurityIdentifier.Value-ceq$a.trustee_sid-and[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$n.AccessMask),0)-eq$a.mask) 'Windows ACE trustee/mask differs.'
     if($n-is[Security.AccessControl.ObjectAce]){Check ([int]$n.ObjectAceFlags-eq$a.object_flags) 'Windows object ACE flags differ.';if($a.object_flags-band1){Check ($n.ObjectAceType.ToString().ToLowerInvariant()-ceq$a.object_type) 'Windows object ACE GUID differs.'};if($a.object_flags-band2){Check ($n.InheritedObjectAceType.ToString().ToLowerInvariant()-ceq$a.inherited_object_type) 'Windows inherited ACE GUID differs.'}}
     for($j=0;$j-lt$raw.Length;$j++){Check ($raw[$j]-eq$bytes[$a.offset+$j]) 'Windows ACE bytes/order differ.'};$aceCount++
    }
   }
  }
  [void]$known.Add($d.sha256);$rows+=,[pscustomobject]@{securityId=$entry.security_id;legacyRecord=$entry.legacy_record;sha256=$d.sha256;windowsLength=[NtfsSecurityBufferOracle]::GetSecurityDescriptorLength($bytes);sddl=$managed.GetSddlForm([Security.AccessControl.AccessControlSections]::All)}
 }
 foreach($binding in $r.bindings){Check ($known.Contains($binding.descriptor_sha256)) 'Binding has no validated descriptor.'}
 $result=[ordered]@{kind='windows-ntfs-security-buffer-oracle';status='passed';powerShellVersion=$PSVersionTable.PSVersion.ToString();dotNetVersion=[Environment]::Version.ToString();inspectionSha256=$InspectionSha256;sourceSha256=$inspection.source.sha256;descriptorCount=$rows.Count;aceCount=$aceCount;boundFiles=$r.bound_files;assertions=$checks;nativeFileSecurityQueried=$false;deviceOperations=0;sourceWritesRequested=$false;conversionQualified=$false;descriptors=$rows}
 if($OutputPath){$parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath)));Check ($parent.PSIsContainer-and-not($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Ordinary output parent required.';$out=New-Object IO.FileStream($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$encoded=[Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Depth 12));$out.Write($encoded,0,$encoded.Length);$out.Flush($true)}finally{$out.Dispose()}}
 [pscustomobject]@{Status=$result.status;Descriptors=$result.descriptorCount;Aces=$aceCount;BoundFiles=$r.bound_files;Assertions=$checks;NativeFileSecurityQueried=$false;DeviceOperations=0}
}finally{$hold.Dispose()}
