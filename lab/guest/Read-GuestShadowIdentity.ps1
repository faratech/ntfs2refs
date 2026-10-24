<# Read-only identity diagnosis for the preserved first shadow preparation. #>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparationSha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Exact owned guest required.'}
$root='C:\ntfs2refs\shadow-platform\'+$RunId;$prepare=Join-Path $root 'prepare.json'
if((Get-FileHash -LiteralPath $prepare -Algorithm SHA256).Hash.ToLowerInvariant()-cne$PreparationSha256){throw 'Failure evidence pin differs.'}
$spec=Get-Content -LiteralPath $prepare -Raw|ConvertFrom-Json
if($spec.runId-cne$RunId-or$spec.status-cne'failed-preserved'-or$spec.failureStage-cne'shadow-initialize-intent'-or-not$spec.nativeOperationCompletionKnown-or-not$spec.handleCloseSucceeded-or-not$spec.privilegeRestored){throw 'Exact completed preserved failure required.'}
$path='J:\ntfs2refs-shadow\'+$RunId+'\shadow.vhdx';if($spec.backingPath-cne$path){throw 'Backing path differs.'}
$j=Get-Disk -Number 2;$jp=Get-Partition -DriveLetter J
if($j.UniqueId-cne'600224806AAC261F021F249596F332FC'-or[string]$j.Guid-ine[string]$spec.journal.diskGuid-or$jp.DiskNumber-ne2-or[string]$jp.Guid-ine[string]$spec.journal.partitionGuid){throw 'Journal backing identity differs.'}
foreach($p in @('J:\','J:\ntfs2refs-shadow',('J:\ntfs2refs-shadow\'+$RunId),$path,$root)){$f=Get-Item -LiteralPath $p -Force;if($f.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse path refused.'}}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
public static class N2RReadOnlyShadowIdentity {
 [StructLayout(LayoutKind.Sequential)]struct Storage {public uint DeviceId;public Guid VendorId;}
 [StructLayout(LayoutKind.Sequential)]struct OpenInfo {public uint Version;public int GetInfoOnly,ReadOnly;public Guid ResiliencyGuid;}
 public sealed class Reply {public uint version,error,used,required;public bool succeeded;public string hex;}
 public sealed class Result {public uint openError,closeError;public bool opened,closed;public Reply[] replies;}
 public sealed class Header {public long offset;public ulong sequence;public bool signatureValid,checksumValid;public uint storedChecksum,computedChecksum;public string fileWriteGuid,dataWriteGuid,bytesBase64;}
 [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]static extern uint OpenVirtualDisk(ref Storage s,string path,uint access,uint flags,ref OpenInfo p,out IntPtr handle);
 [DllImport("virtdisk.dll",ExactSpelling=true)]static extern uint GetVirtualDiskInformation(IntPtr h,ref uint size,[In,Out]byte[] bytes,out uint used);
 [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool CloseHandle(IntPtr h);
 public static Result Read(string path) {
  Result result=new Result();Storage s=new Storage{DeviceId=3,VendorId=new Guid("ec984aec-a0f9-47e9-901f-71415a66345b")};
  OpenInfo p=new OpenInfo{Version=2,GetInfoOnly=1,ReadOnly=1};IntPtr h;
  result.openError=OpenVirtualDisk(ref s,path,0,0,ref p,out h);result.opened=result.openError==0&&h!=IntPtr.Zero&&h!=new IntPtr(-1);
  if(!result.opened)return result;
  List<Reply> replies=new List<Reply>();
  try{foreach(uint version in new uint[]{1,2,14}){byte[] bytes=new byte[256];Array.Copy(BitConverter.GetBytes(version),bytes,4);uint size=256,used;
    uint error=GetVirtualDiskInformation(h,ref size,bytes,out used);Reply r=new Reply{version=version,error=error,used=used,required=size,succeeded=error==0};
    if(used<=256)r.hex=BitConverter.ToString(bytes,0,(int)used).Replace("-","").ToLowerInvariant();replies.Add(r);}}
  finally{result.replies=replies.ToArray();result.closed=CloseHandle(h);if(!result.closed)result.closeError=(uint)Marshal.GetLastWin32Error();}
  return result;
 }
 public static Header[] ReadHeaders(string path) {
  List<Header> headers=new List<Header>();
  using(FileStream file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){
   foreach(long offset in new long[]{65536,131072}){
    file.Position=offset;byte[] b=new byte[4096];int done=0;while(done<b.Length){int n=file.Read(b,done,b.Length-done);if(n==0)throw new EndOfStreamException();done+=n;}
    uint crc=UInt32.MaxValue;for(int i=0;i<b.Length;i++){crc^=(i>=4&&i<8)?0U:b[i];for(int bit=0;bit<8;bit++)crc=(crc>>1)^((crc&1)!=0?0x82f63b78U:0U);}crc=~crc;
    byte[] f=new byte[16],d=new byte[16];Array.Copy(b,16,f,0,16);Array.Copy(b,32,d,0,16);uint stored=BitConverter.ToUInt32(b,4);
    headers.Add(new Header{offset=offset,sequence=BitConverter.ToUInt64(b,8),signatureValid=b[0]==104&&b[1]==101&&b[2]==97&&b[3]==100,checksumValid=stored==crc,storedChecksum=stored,computedChecksum=crc,fileWriteGuid=new Guid(f).ToString("D"),dataWriteGuid=new Guid(d).ToString("D"),bytesBase64=Convert.ToBase64String(b)});
   }
  }return headers.ToArray();
 }
}
'@
$before=Get-Disk -Number 3|Select-Object Number,UniqueId,Guid,Size,PartitionStyle,NumberOfPartitions,IsOffline,IsReadOnly
$native=[N2RReadOnlyShadowIdentity]::Read($path)
$headers=[N2RReadOnlyShadowIdentity]::ReadHeaders($path)
$after=Get-Disk -Number 3|Select-Object Number,UniqueId,Guid,Size,PartitionStyle,NumberOfPartitions,IsOffline,IsReadOnly
$record=[ordered]@{schemaVersion=1;kind='read-only-shadow-identity-observation';runId=$RunId;preparationSha256=$PreparationSha256;backingPath=$path;native=$native;headers=$headers;diskBefore=$before;diskAfter=$after;rawPayloadWritesIssued=$false;createdUtc=[DateTime]::UtcNow.ToString('o');scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()}
$outRoot='C:\ntfs2refs\shadow-identity\'+$RunId
if(Test-Path -LiteralPath $outRoot){throw 'Identity observation already exists.'};New-Item -ItemType Directory -Path $outRoot|Out-Null
$out=Join-Path $outRoot 'identity-observation.json';$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($record|ConvertTo-Json -Depth 8))
$file=New-Object IO.FileStream($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]@{Path=$out;Sha256=(Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLowerInvariant();Native=$native}
