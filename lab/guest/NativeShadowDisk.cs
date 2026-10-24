using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
namespace Ntfs2Refs {
 public sealed class ShadowCall { public string name,startedUtc,finishedUtc,outputHex,outputText;public uint error;public bool succeeded; }
 public sealed class ShadowInfo { public string identifier,virtualDiskId,physicalPath;public uint identifierQueryVersion=2,virtualDiskIdQueryVersion=14;public string identifierSemantics="vhdx-content-generation";public ulong virtualBytes,physicalBytes;public uint blockBytes,logicalSectorBytes,physicalSectorBytes,providerSubtype; }
 public interface IShadowDiskApi {
  uint Create(string path,Guid id,out IntPtr handle);uint Open(string path,out IntPtr handle);uint Attach(IntPtr handle);
  uint Query(IntPtr handle,uint version,out byte[] bytes);uint PhysicalPath(IntPtr handle,out string path);uint Close(IntPtr handle);
 }
 [StructLayout(LayoutKind.Sequential)] public struct ShadowStorageType {public uint DeviceId;public Guid VendorId;}
 [StructLayout(LayoutKind.Sequential)] public struct ShadowCreateV2 {
  public Guid UniqueId;public ulong MaximumSize;public uint BlockSizeInBytes,SectorSizeInBytes,PhysicalSectorSizeInBytes;
  public IntPtr ParentPath,SourcePath;public uint OpenFlags;public ShadowStorageType ParentVirtualStorageType,SourceVirtualStorageType;public Guid ResiliencyGuid;
 }
 [StructLayout(LayoutKind.Sequential)] public struct ShadowCreateParameters {public uint Version;public ShadowCreateV2 Version2;}
 [StructLayout(LayoutKind.Sequential)] public struct ShadowOpenParameters {public uint Version;public int GetInfoOnly,ReadOnly;public Guid ResiliencyGuid;}
 [StructLayout(LayoutKind.Sequential)] public struct ShadowAttachParameters {public uint Version,Reserved;}
 public sealed class WindowsShadowDiskApi:IShadowDiskApi {
  public static readonly Guid MicrosoftVendor=new Guid("ec984aec-a0f9-47e9-901f-71415a66345b");
  public static ShadowCreateParameters CreateParameters(Guid id){
   if(id==Guid.Empty||IntPtr.Size!=8)throw new ArgumentException("Require new GUID and x64.");
   ShadowCreateParameters p=new ShadowCreateParameters();p.Version=2;p.Version2.UniqueId=id;p.Version2.MaximumSize=NativeShadowDisk.VirtualBytes;
   p.Version2.BlockSizeInBytes=2097152;p.Version2.SectorSizeInBytes=512;p.Version2.PhysicalSectorSizeInBytes=4096;
   // NULL ParentPath/SourcePath: independent empty disk, never a payload clone.
   return p;
  }
  private static ShadowStorageType Storage(){return new ShadowStorageType{DeviceId=3,VendorId=MicrosoftVendor};}
  public uint Create(string path,Guid id,out IntPtr handle){ShadowStorageType s=Storage();ShadowCreateParameters p=CreateParameters(id);return CreateVirtualDisk(ref s,path,0,IntPtr.Zero,0,0,ref p,IntPtr.Zero,out handle);}
  public uint Open(string path,out IntPtr handle){ShadowStorageType s=Storage();ShadowOpenParameters p=new ShadowOpenParameters{Version=2,GetInfoOnly=0,ReadOnly=0};return OpenVirtualDisk(ref s,path,0,0,ref p,out handle);}
  public uint Attach(IntPtr handle){ShadowAttachParameters p=new ShadowAttachParameters{Version=1};return AttachVirtualDisk(handle,IntPtr.Zero,6,0,ref p,IntPtr.Zero);}
  public uint Query(IntPtr handle,uint version,out byte[] bytes){
   byte[] b=new byte[256];Array.Copy(BitConverter.GetBytes(version),b,4);uint size=(uint)b.Length,used;uint e=GetVirtualDiskInformation(handle,ref size,b,out used);
   if(e!=0){bytes=new byte[0];return e;}if(used>b.Length){bytes=new byte[0];return 0;}bytes=new byte[used];Array.Copy(b,bytes,used);return 0;
  }
  public uint PhysicalPath(IntPtr handle,out string path){StringBuilder b=new StringBuilder(256);uint size=512;uint e=GetVirtualDiskPhysicalPath(handle,ref size,b);path=e==0?b.ToString():null;return e;}
  public uint Close(IntPtr handle){if(CloseHandle(handle))return 0;uint e=(uint)Marshal.GetLastWin32Error();return e==0?6U:e;}
  public static ulong AllocatedFileBytes(string path){SetLastError(0);uint high;uint low=GetCompressedFileSizeW(path,out high);int e=Marshal.GetLastWin32Error();if(low==UInt32.MaxValue&&e!=0)throw new Win32Exception(e,"GetCompressedFileSizeW");return ((ulong)high<<32)|low;}
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]private static extern uint CreateVirtualDisk(ref ShadowStorageType s,string path,uint access,IntPtr security,uint flags,uint provider,ref ShadowCreateParameters p,IntPtr overlapped,out IntPtr handle);
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]private static extern uint OpenVirtualDisk(ref ShadowStorageType s,string path,uint access,uint flags,ref ShadowOpenParameters p,out IntPtr handle);
  [DllImport("virtdisk.dll",ExactSpelling=true)]private static extern uint AttachVirtualDisk(IntPtr handle,IntPtr security,uint flags,uint provider,ref ShadowAttachParameters p,IntPtr overlapped);
  [DllImport("virtdisk.dll",ExactSpelling=true)]private static extern uint GetVirtualDiskInformation(IntPtr handle,ref uint size,[In,Out]byte[] info,out uint used);
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]private static extern uint GetVirtualDiskPhysicalPath(IntPtr handle,ref uint size,StringBuilder path);
  [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]private static extern uint GetCompressedFileSizeW(string path,out uint high);
  [DllImport("kernel32.dll",ExactSpelling=true)]private static extern void SetLastError(uint error);
 }
 // No automatic detach/delete/retry/format, and no raw or file payload writes.
 public sealed class NativeShadowDisk {
  public const ulong VirtualBytes=64UL*1024*1024*1024,MaximumBackingBytes=6UL*1024*1024*1024;
  public readonly string Path;public readonly Guid Identifier;public readonly List<ShadowCall> Calls=new List<ShadowCall>();
  public bool CreateAttempted,Created,OpenAttempted,AttachAttempted,Attached,OperationActive,HandleCloseSucceeded;
  private IntPtr handle=IntPtr.Zero;private bool closeAttempted;private readonly IShadowDiskApi api;
  public NativeShadowDisk(string path,Guid id):this(path,id,new WindowsShadowDiskApi()){}
  public NativeShadowDisk(string path,Guid id,IShadowDiskApi api){
   if(!Regex.IsMatch(path??"",@"\AJ:\\ntfs2refs-shadow\\[0-9a-f]{32}\\shadow\.vhdx\z",RegexOptions.CultureInvariant)||id==Guid.Empty||api==null)throw new ArgumentException("Unexpected owned shadow path or identity.");
   Path=path;Identifier=id;this.api=api;
  }
  private ShadowCall Begin(string name){OperationActive=true;ShadowCall c=new ShadowCall{name=name,startedUtc=DateTime.UtcNow.ToString("o")};Calls.Add(c);return c;}
  private void Finish(ShadowCall c,uint error){c.error=error;c.succeeded=error==0;c.finishedUtc=DateTime.UtcNow.ToString("o");OperationActive=false;if(error!=0)throw new Win32Exception((int)error,c.name);}
  private static bool Valid(IntPtr p){return p!=IntPtr.Zero&&p!=new IntPtr(-1);}
  private void RequireHandle(){if(!Valid(handle))throw new InvalidOperationException("No owned virtual-disk handle.");}
  public void Create(){
   if(CreateAttempted||Valid(handle))throw new InvalidOperationException("Creation is single-attempt.");
   CreateAttempted=true;ShadowCall c=Begin("CreateVirtualDisk");IntPtr h;uint e=api.Create(Path,Identifier,out h);
   if(e==0&&Valid(h)){handle=h;Created=true;HandleCloseSucceeded=false;closeAttempted=false;}Finish(c,e);if(!Valid(handle))throw new InvalidDataException("CreateVirtualDisk returned success without a valid handle.");Close();
  }
  public ShadowInfo OpenOwned(){
   if(Valid(handle)||OpenAttempted)throw new InvalidOperationException("Open is single-attempt and requires no existing handle.");OpenAttempted=true;
   ShadowCall c=Begin("OpenVirtualDisk");IntPtr h;uint e=api.Open(Path,out h);
   if(e==0&&Valid(h)){handle=h;HandleCloseSucceeded=false;closeAttempted=false;}Finish(c,e);if(!Valid(handle))throw new InvalidDataException("OpenVirtualDisk returned success without a valid handle.");return Observe(false);
  }
  private byte[] Query(uint version){RequireHandle();ShadowCall c=Begin("GetVirtualDiskInformation:"+version);byte[] b;uint e=api.Query(handle,version,out b);if(b!=null&&b.Length<=256)c.outputHex=BitConverter.ToString(b).Replace("-","").ToLowerInvariant();Finish(c,e);if(b==null||b.Length<8||b.Length>256||BitConverter.ToUInt32(b,0)!=version)throw new InvalidDataException("VHD information version or size differs.");return b;}
  public static uint ParseDiskNumber(string path){Match m=Regex.Match(path??"",@"\A\\\\\.\\PhysicalDrive([0-9]{1,4})\z",RegexOptions.CultureInvariant);if(!m.Success)throw new InvalidDataException("Unexpected physical-device path.");return UInt32.Parse(m.Groups[1].Value,System.Globalization.CultureInfo.InvariantCulture);}
  public static ShadowInfo ParseInfo(byte[] size,byte[] identifier,byte[] subtype,byte[] physical,byte[] diskId,Guid expected){
   if(size==null||size.Length<32||identifier==null||identifier.Length<24||subtype==null||subtype.Length<12||physical==null||physical.Length<12||diskId==null||diskId.Length<24||BitConverter.ToUInt32(size,0)!=1||BitConverter.ToUInt32(identifier,0)!=2||BitConverter.ToUInt32(subtype,0)!=7||BitConverter.ToUInt32(physical,0)!=10||BitConverter.ToUInt32(diskId,0)!=14)throw new InvalidDataException("Truncated or unexpected VHD information.");
   byte[] id=new byte[16],stable=new byte[16];Array.Copy(identifier,8,id,0,16);Array.Copy(diskId,8,stable,0,16);
   ShadowInfo r=new ShadowInfo{identifier=new Guid(id).ToString("D"),virtualDiskId=new Guid(stable).ToString("D"),virtualBytes=BitConverter.ToUInt64(size,8),physicalBytes=BitConverter.ToUInt64(size,16),blockBytes=BitConverter.ToUInt32(size,24),logicalSectorBytes=BitConverter.ToUInt32(size,28),providerSubtype=BitConverter.ToUInt32(subtype,8),physicalSectorBytes=BitConverter.ToUInt32(physical,8)};
   // Query2 is the observed VHDX DataWriteGuid, which changes on content writes.
   // Query14 is the persistent creation identity; never re-enroll a changed value.
   if(new Guid(r.identifier)==Guid.Empty||new Guid(r.virtualDiskId)!=expected||expected==Guid.Empty||r.virtualBytes!=VirtualBytes||r.physicalBytes==0||r.physicalBytes>MaximumBackingBytes||r.blockBytes!=2097152||r.logicalSectorBytes!=512||r.physicalSectorBytes!=4096||r.providerSubtype!=3)throw new InvalidDataException("Shadow VHD identity/type/geometry/allocation differs.");return r;
  }
  public ShadowInfo Observe(bool requireAttached){ShadowInfo r=ParseInfo(Query(1),Query(2),Query(7),Query(10),Query(14),Identifier);if(requireAttached){ShadowCall c=Begin("GetVirtualDiskPhysicalPath");string p;uint e=api.PhysicalPath(handle,out p);if(p!=null&&p.Length<=256)c.outputText=p;Finish(c,e);ParseDiskNumber(p);r.physicalPath=p;}return r;}
  public ShadowInfo Attach(){RequireHandle();if(AttachAttempted)throw new InvalidOperationException("Attachment is single-attempt.");Observe(false);AttachAttempted=true;ShadowCall c=Begin("AttachVirtualDisk");uint e=api.Attach(handle);if(e==0)Attached=true;Finish(c,e);return Observe(true);}
  public void Close(){if(!Valid(handle))return;if(closeAttempted)throw new InvalidOperationException("A failed handle close is not retried.");closeAttempted=true;ShadowCall c=Begin("CloseHandle");uint e=api.Close(handle);if(e==0){handle=IntPtr.Zero;HandleCloseSucceeded=true;}Finish(c,e);}
 }
}

namespace Ntfs2Refs {
 public sealed class ShadowPrivilegePrevious {public uint Count,Attributes,ReturnedBytes;public long Luid;}
 public sealed class ShadowPrivilegeAudit {
  public string name="SeManageVolumePrivilege";public bool assigned,beforeCaptured,adjustmentAttempted,adjustmentReturned,restorationAttempted,restored,tokenCloseSucceeded,operationActive;
  public uint beforeAttributes,enabledAttributes,restoredAttributes;public long luid;public ShadowPrivilegePrevious previous;
  public readonly List<ShadowCall> calls=new List<ShadowCall>();
 }
 public interface IShadowPrivilegeApi {
  uint Open(out IntPtr token);uint Lookup(out long luid);uint Query(IntPtr token,out byte[] bytes);
  uint Adjust(IntPtr token,long luid,uint attributes,out ShadowPrivilegePrevious previous);uint Close(IntPtr token);
 }
 public sealed class WindowsShadowPrivilegeApi:IShadowPrivilegeApi {
  [StructLayout(LayoutKind.Sequential)]public struct TokenPrivileges {public uint Count,Low;public int High;public uint Attributes;}
  public uint Open(out IntPtr token){return OpenProcessToken(GetCurrentProcess(),0x28,out token)?0U:(uint)Marshal.GetLastWin32Error();}
  public uint Lookup(out long luid){return LookupPrivilegeValueW(null,"SeManageVolumePrivilege",out luid)?0U:(uint)Marshal.GetLastWin32Error();}
  public uint Query(IntPtr token,out byte[] bytes){byte[] b=new byte[65536];uint used;bool ok=GetTokenInformation(token,3,b,(uint)b.Length,out used);uint e=ok?0U:(uint)Marshal.GetLastWin32Error();if(!ok||used>b.Length){bytes=new byte[0];return e;}bytes=new byte[used];Array.Copy(b,bytes,used);return 0;}
  public uint Adjust(IntPtr token,long luid,uint attributes,out ShadowPrivilegePrevious previous){
   TokenPrivileges request=new TokenPrivileges{Count=1,Low=(uint)luid,High=(int)(luid>>32),Attributes=attributes},old;uint returned;
   SetLastError(0);bool ok=AdjustTokenPrivileges(token,false,ref request,16,out old,out returned);uint e=(uint)Marshal.GetLastWin32Error();
   previous=new ShadowPrivilegePrevious{Count=old.Count,Luid=((long)old.High<<32)|old.Low,Attributes=old.Attributes,ReturnedBytes=returned};return ok?e:(e==0?6U:e);
  }
  public uint Close(IntPtr token){if(CloseHandle(token))return 0;uint e=(uint)Marshal.GetLastWin32Error();return e==0?6U:e;}
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool LookupPrivilegeValueW(string system,string name,out long luid);
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetTokenInformation(IntPtr token,int type,[Out]byte[] bytes,uint capacity,out uint used);
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool AdjustTokenPrivileges(IntPtr token,[MarshalAs(UnmanagedType.Bool)]bool disableAll,ref TokenPrivileges request,uint capacity,out TokenPrivileges previous,out uint returned);
  [DllImport("kernel32.dll")]private static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool CloseHandle(IntPtr token);
  [DllImport("kernel32.dll",ExactSpelling=true)]private static extern void SetLastError(uint error);
 }
 public sealed class ShadowManageVolumePrivilege {
  public readonly ShadowPrivilegeAudit Audit=new ShadowPrivilegeAudit();private readonly IShadowPrivilegeApi api;
  private IntPtr token=IntPtr.Zero;private bool enableAttempted,restoreAttempted,closeAttempted;
  public ShadowManageVolumePrivilege():this(new WindowsShadowPrivilegeApi()){}
  public ShadowManageVolumePrivilege(IShadowPrivilegeApi api){if(api==null)throw new ArgumentNullException("api");this.api=api;}
  private ShadowCall Begin(string name){Audit.operationActive=true;ShadowCall c=new ShadowCall{name=name,startedUtc=DateTime.UtcNow.ToString("o")};Audit.calls.Add(c);return c;}
  private void End(ShadowCall c,uint error){c.error=error;c.succeeded=error==0;c.finishedUtc=DateTime.UtcNow.ToString("o");Audit.operationActive=false;if(error!=0)throw new Win32Exception((int)error,c.name);}
  public static uint[] FindPrivilege(byte[] b,long luid){
   if(b==null||b.Length<4||b.Length>65536)throw new InvalidDataException("Bounded TOKEN_PRIVILEGES required.");uint count=BitConverter.ToUInt32(b,0);
   if(count>2048||b.Length!=4+12*count)throw new InvalidDataException("TOKEN_PRIVILEGES count/length differs.");uint found=0,attributes=0;
   for(int i=0;i<count;i++)if(BitConverter.ToInt64(b,4+12*i)==luid){found++;attributes=BitConverter.ToUInt32(b,12+12*i);}
   if(found>1)throw new InvalidDataException("Duplicate process privilege.");return new[]{found,attributes};
  }
  private uint[] Query(){ShadowCall c=Begin("GetTokenInformation:TokenPrivileges");byte[] b;uint e=api.Query(token,out b);End(c,e);return FindPrivilege(b,Audit.luid);}
  public void Enable(){
   if(enableAttempted)throw new InvalidOperationException("Privilege enable is single-attempt.");enableAttempted=true;
   ShadowCall c=Begin("OpenProcessToken:current-process");IntPtr h;uint e=api.Open(out h);if(e==0&&h!=IntPtr.Zero&&h!=new IntPtr(-1))token=h;End(c,e);if(token==IntPtr.Zero)throw new InvalidDataException("No valid process token.");
   c=Begin("LookupPrivilegeValue:SeManageVolumePrivilege");long luid;e=api.Lookup(out luid);End(c,e);Audit.luid=luid;
   uint[] before=Query();Audit.assigned=before[0]==1;Audit.beforeAttributes=before[1];Audit.beforeCaptured=true;if(!Audit.assigned)throw new UnauthorizedAccessException("SeManageVolumePrivilege is not assigned to the existing token.");
   Audit.adjustmentAttempted=true;c=Begin("AdjustTokenPrivileges:enable");ShadowPrivilegePrevious previous;e=api.Adjust(token,luid,2,out previous);Audit.adjustmentReturned=true;Audit.previous=previous;End(c,e);
   if(previous==null||previous.Count>1||(previous.Count==1&&(previous.Luid!=luid||previous.Attributes!=Audit.beforeAttributes||previous.ReturnedBytes!=16))||(previous.Count==0&&(Audit.beforeAttributes&2)==0))throw new InvalidDataException("Previous privilege state differs from audited process state.");
   uint[] after=Query();Audit.enabledAttributes=after[1];if(after[0]!=1||after[1]!=(Audit.beforeAttributes|2U))throw new InvalidDataException("Process privilege was not enabled exactly.");
  }
  public void Restore(){
   if(Audit.operationActive)throw new InvalidOperationException("An indeterminate privilege call must be preserved.");
   if(restoreAttempted){if(Audit.restored&&Audit.tokenCloseSucceeded)return;throw new InvalidOperationException("Failed privilege cleanup is not retried.");}restoreAttempted=true;
   try{
    if(Audit.adjustmentAttempted){if(!Audit.adjustmentReturned||!Audit.beforeCaptured||!Audit.assigned)throw new InvalidOperationException("Previous process state is not qualified for restoration.");
     Audit.restorationAttempted=true;ShadowCall c=Begin("AdjustTokenPrivileges:restore-audited-state");ShadowPrivilegePrevious ignored;uint e=api.Adjust(token,Audit.luid,Audit.beforeAttributes,out ignored);End(c,e);
     uint[] restored=Query();Audit.restoredAttributes=restored[1];if(restored[0]!=1||restored[1]!=Audit.beforeAttributes)throw new InvalidDataException("Original process privilege state was not restored exactly.");
    }
    Audit.restored=true;
   }finally{
    if(token==IntPtr.Zero){Audit.tokenCloseSucceeded=true;}
    else if(!Audit.operationActive&&!closeAttempted){closeAttempted=true;ShadowCall c=Begin("CloseHandle:process-token");uint e=api.Close(token);if(e==0){token=IntPtr.Zero;Audit.tokenCloseSucceeded=true;}End(c,e);}
   }
  }
 }
}
