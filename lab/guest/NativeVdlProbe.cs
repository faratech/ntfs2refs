// Initialized-control observation and allocation-only experiment. No new-file
// payload I/O, movement, valid-data advancement or privilege changes.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class VdlStandard { public long allocationBytes,eofBytes;public uint links;public bool deletePending,directory; }
 public sealed class VdlRegion { public long offset,length;public uint usage; }
 public sealed class VdlRegions { public uint requestedUsage;public long vdlBytes;public bool complete,prefixQualified;public VdlRegion[] regions; }
 public sealed class VdlExtent { public long startingVcn,nextVcn,lcn; }
 public sealed class VdlQuery { public string name,api,inputHex,nativeMessage,startedUtc,finishedUtc;public uint controlCode,informationClass,bytesReturned;public int inputBytes,outputCapacityBytes,nativeError;public bool succeeded;public byte[] bytes; }
 public sealed class VdlSnapshot { public string name,fileId64,volumeSerialHex;public VdlStandard standard;public VdlRegions cached,onDisk;public VdlExtent[] extents;public bool exactState; }
 public sealed class VdlOperation { public string name,inputHex,startedUtc,finishedUtc;public bool succeeded;public int nativeError; }
 public sealed class VdlResult {
  public string status="blocked",phase="preflight",error,fixturePath,sha256Before,sha256After,privateSddl;
  public bool targetWriteRequestsIssued,directoryCreated,fileCreated,allocationRequested,eofRequested,explicitFlushRequested,privateAclVerified,controlQualified,zeroVdlQualified;
  public List<VdlQuery> queries=new List<VdlQuery>();public List<VdlOperation> operations=new List<VdlOperation>();public List<VdlSnapshot> snapshots=new List<VdlSnapshot>();
 }
 public static class NativeVdlProbe {
  const long FileBytes=65536,VolumeClusters=13631488;
  const uint Read=0x80000000,Write=0x40000000,OpenReparse=0x00200000,Backup=0x02000000;
  [StructLayout(LayoutKind.Sequential)] struct Info { public uint attributes;public System.Runtime.InteropServices.ComTypes.FILETIME created,accessed,written;public uint serial,sizeHigh,sizeLow,links,idHigh,idLow; }
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int length;public IntPtr descriptor;public int inherit; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW",ExactSpelling=true)] static extern SafeFileHandle CreatePrivateFile(string path,uint access,uint share,ref SecurityAttributes security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,ref SecurityAttributes security);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder name,uint capacity);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int infoClass,[Out]byte[] output,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int infoClass,byte[] input,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,uint revision,out IntPtr descriptor,out uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle handle,int objectType,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,uint revision,uint information,out IntPtr sddl,out uint length);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
  public static string PathFor(string id,bool initialized) {
   if(id==null || id.Length!=32 || !Regex.IsMatch(id,"^[0-9a-f]{32}$"))throw new ArgumentException("Expected bounded lowercase run ID.");
   return @"F:\fixtures\"+(initialized?"placement-":"vdl-")+id+(initialized?@"\initialized.bin":@"\uninitialized.bin");
  }
  public static byte[] RegionInput(uint usage) {
   if(usage!=1 && usage!=2)throw new ArgumentOutOfRangeException("usage");
   byte[] bytes=new byte[24];BitConverter.GetBytes(FileBytes).CopyTo(bytes,8);BitConverter.GetBytes(usage).CopyTo(bytes,16);return bytes;
  }
  public static VdlStandard ParseStandard(byte[] bytes) {
   return ParseStandardState(bytes,false);
  }
  public static VdlStandard ParseInitialStandard(byte[] bytes) {
   return ParseStandardState(bytes,true);
  }
  static VdlStandard ParseStandardState(byte[] bytes,bool initialEmpty) {
   if(bytes==null || bytes.Length!=24)throw new InvalidDataException("Expected exactly 24 standard-information bytes.");
   long allocated=BitConverter.ToInt64(bytes,0),eof=BitConverter.ToInt64(bytes,8);uint links=BitConverter.ToUInt32(bytes,16);
   if(links!=1 || bytes[20]!=0 || bytes[21]!=0)throw new InvalidDataException("Unexpected file links, deletion or directory state.");
   // The measured empty ReFS file reported 1024 allocated bytes and EOF zero.
   // Accept that observation only here; it does not identify an on-disk format.
   if(initialEmpty) {
    if(eof!=0 || (allocated!=0 && allocated!=1024))throw new InvalidDataException("Unmeasured initial empty-file allocation state.");
   } else if(allocated<0 || allocated>FileBytes || allocated%4096!=0 || eof<0 || eof>allocated)throw new InvalidDataException("File standard state is outside the bounded ordinary profile.");
   return new VdlStandard {allocationBytes=allocated,eofBytes=eof,links=links,deletePending=false,directory=false};
  }
  public static VdlRegions ParseRegions(byte[] bytes,uint requested) {
   RegionInput(requested);
   if(bytes==null || bytes.Length<40 || bytes.Length>400)throw new InvalidDataException("Bounded region entries required.");
   uint total=BitConverter.ToUInt32(bytes,4),count=BitConverter.ToUInt32(bytes,8);
   if(total==0 || total!=count || count>16 || bytes.Length!=16+24L*count)throw new InvalidDataException("Incomplete or malformed region counts.");
   List<VdlRegion> regions=new List<VdlRegion>();long next=0,vdl=0;bool invalidSeen=false,prefix=true;
   for(int i=0;i<count;i++) {
    int offset=16+24*i;long start=BitConverter.ToInt64(bytes,offset),length=BitConverter.ToInt64(bytes,offset+8);uint usage=BitConverter.ToUInt32(bytes,offset+16);
    if(start!=next || length<=0 || length>FileBytes-start || (usage&~31U)!=0)throw new InvalidDataException("Region gaps, overlap, unknown usage or bounds.");
    bool valid=(usage&requested)!=0;if(valid){if(invalidSeen)prefix=false;else vdl=start+length;}else invalidSeen=true;
    regions.Add(new VdlRegion {offset=start,length=length,usage=usage});next=start+length;
   }
   if(next!=FileBytes)throw new InvalidDataException("Regions do not cover the full requested file range.");
   return new VdlRegions {requestedUsage=requested,vdlBytes=prefix?vdl:-1,complete=true,prefixQualified=prefix,regions=regions.ToArray()};
  }
  public static VdlExtent[] ParseExtents(byte[] bytes) {
   if(bytes==null || bytes.Length<32 || bytes.Length>272 || BitConverter.ToInt64(bytes,8)!=0)throw new InvalidDataException("Bounded extent response required.");
   uint count=BitConverter.ToUInt32(bytes,0);if(count<1 || count>16 || bytes.Length!=16+16L*count)throw new InvalidDataException("Extent count differs.");
   List<VdlExtent> result=new List<VdlExtent>();long next=0;
   for(int i=0;i<count;i++){long end=BitConverter.ToInt64(bytes,16+16*i),lcn=BitConverter.ToInt64(bytes,24+16*i);if(end<=next || end>16 || lcn<0 || lcn>VolumeClusters-(end-next))throw new InvalidDataException("Unbounded or sparse extent.");result.Add(new VdlExtent {startingVcn=next,nextVcn=end,lcn=lcn});next=end;}
   if(next!=16)throw new InvalidDataException("Mapping does not cover exactly sixteen clusters.");return result.ToArray();
  }
  public static string PrivateSddl(string userSid,bool directory) {
   if(userSid==null || !Regex.IsMatch(userSid,@"^S-1-5-21-(\d+-){3}\d+$"))throw new ArgumentException("Expected the explicit local lab user SID.");
   string flags=directory?"OICI":"";return "O:"+userSid+"D:P(A;"+flags+";FA;;;SY)(A;"+flags+";FA;;;BA)(A;"+flags+";FA;;;"+userSid+")";
  }
  public static void ValidatePrivateSddl(string sddl,string userSid,bool directory) {
   PrivateSddl(userSid,directory);RawSecurityDescriptor sd=new RawSecurityDescriptor(sddl);
   if(sd.Owner==null || sd.Owner.Value!=userSid || (sd.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || sd.DiscretionaryAcl==null || sd.DiscretionaryAcl.Count!=3)throw new InvalidDataException("Private ACL owner/protection/count differs.");
   HashSet<string> allowed=new HashSet<string>(new string[]{userSid,"S-1-5-18","S-1-5-32-544"});AceFlags expected=directory?(AceFlags.ObjectInherit|AceFlags.ContainerInherit):AceFlags.None;
   foreach(GenericAce item in sd.DiscretionaryAcl){CommonAce ace=item as CommonAce;if(ace==null || ace.AceType!=AceType.AccessAllowed || ace.AccessMask!=0x1f01ff || ace.AceFlags!=expected || !allowed.Remove(ace.SecurityIdentifier.Value))throw new InvalidDataException("Unexpected private ACL permission or principal.");}
   if(allowed.Count!=0)throw new InvalidDataException("Missing private ACL principal.");
  }
  static void VerifyAcl(SafeFileHandle handle,string sid,bool directory) {
   IntPtr owner,group,dacl,sacl,descriptor,text=IntPtr.Zero;uint error=GetSecurityInfo(handle,1,5,out owner,out group,out dacl,out sacl,out descriptor);
   if(error!=0)throw new Win32Exception((int)error);
   try{uint length;if(!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor,1,5,out text,out length))throw new Win32Exception(Marshal.GetLastWin32Error());ValidatePrivateSddl(Marshal.PtrToStringUni(text),sid,directory);}finally{if(text!=IntPtr.Zero)LocalFree(text);if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
  }
  static Info Information(SafeFileHandle handle){Info info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());return info;}
  static void CheckHandle(SafeFileHandle handle,string path,bool directory) {
   Info info=Information(handle);if((info.attributes&0x400)!=0 || ((info.attributes&0x10)!=0)!=directory || (!directory && ((info.attributes&0x4a00)!=0 || info.links!=1)))throw new IOException("Unexpected ordinary file type or links.");
   StringBuilder final=new StringBuilder(512);uint count=GetFinalPathNameByHandle(handle,final,512,0);
   if(count==0 || count>=512 || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new IOException("Resolved handle path differs.");
  }
  static SafeFileHandle Open(string path,bool directory,bool writable) {
   SafeFileHandle handle=CreateFile(path,directory?0x20080U:(Read|(writable?Write:0)),directory?1U:0U,IntPtr.Zero,3,OpenReparse|(directory?Backup:0),IntPtr.Zero);
   if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}try{CheckHandle(handle,path,directory);return handle;}catch{handle.Dispose();throw;}
  }
  static List<SafeFileHandle> Pin(string volume) {
   if(Environment.MachineName!="N2R-WIN11" || Environment.GetEnvironmentVariable("SystemDrive")!="C:" || IntPtr.Size!=8)throw new InvalidOperationException("Owned x64 guest required.");
   List<SafeFileHandle> pins=new List<SafeFileHandle>();try{pins.Add(Open(@"F:\",true,false));pins.Add(Open(@"F:\fixtures",true,false));StringBuilder actual=new StringBuilder(64);if(!GetVolumeNameForVolumeMountPoint(@"F:\",actual,64) || !String.Equals(actual.ToString(),volume,StringComparison.OrdinalIgnoreCase))throw new IOException("Mounted volume GUID changed.");return pins;}catch{foreach(SafeFileHandle pin in pins)pin.Dispose();throw;}
  }
  static VdlQuery Query(VdlResult result,SafeFileHandle handle,string name,uint code,byte[] input,int capacity) {
   VdlQuery q=new VdlQuery {name=name,api=code==0?"GetFileInformationByHandleEx":"DeviceIoControl",controlCode=code,informationClass=code==0?1U:0U,inputBytes=input==null?0:input.Length,inputHex=input==null?"":Hex(input),outputCapacityBytes=capacity,startedUtc=DateTime.UtcNow.ToString("o")};result.queries.Add(q);
   byte[] buffer=new byte[capacity];uint returned=0;
   if(code==0){q.succeeded=GetFileInformationByHandleEx(handle,1,buffer,(uint)capacity);if(q.succeeded)returned=(uint)capacity;}else q.succeeded=DeviceIoControl(handle,code,input,(uint)input.Length,buffer,(uint)capacity,out returned,IntPtr.Zero);
   q.nativeError=q.succeeded?0:Marshal.GetLastWin32Error();q.nativeMessage=q.succeeded?"success":new Win32Exception(q.nativeError).Message;q.bytesReturned=returned;q.finishedUtc=DateTime.UtcNow.ToString("o");
   if(returned>capacity)throw new InvalidDataException("Native response exceeds capacity.");q.bytes=new byte[returned];Array.Copy(buffer,q.bytes,(int)returned);return q;
  }
  static VdlSnapshot Observe(VdlResult result,SafeFileHandle handle,string name,long expectedVdl) {
   VdlSnapshot s=new VdlSnapshot {name=name};result.snapshots.Add(s);Info info=Information(handle);s.fileId64="0x"+info.idHigh.ToString("x8")+info.idLow.ToString("x8");s.volumeSerialHex="0x"+info.serial.ToString("x8");
   VdlQuery standard=Query(result,handle,name+"Standard",0,null,24),cached=Query(result,handle,name+"Cached",0x00090284,RegionInput(1),400),disk=Query(result,handle,name+"OnDisk",0x00090284,RegionInput(2),400),extents=Query(result,handle,name+"Extents",0x00090073,new byte[8],272);
   if(!standard.succeeded || !cached.succeeded || !disk.succeeded || !extents.succeeded)return s;
   s.standard=ParseStandard(standard.bytes);s.cached=ParseRegions(cached.bytes,1);s.onDisk=ParseRegions(disk.bytes,2);s.extents=ParseExtents(extents.bytes);
   s.exactState=s.standard.eofBytes==FileBytes&&s.standard.allocationBytes==FileBytes&&s.cached.prefixQualified&&s.onDisk.prefixQualified&&s.cached.vdlBytes==expectedVdl&&s.onDisk.vdlBytes==expectedVdl;return s;
  }
  public static bool SameMapping(VdlSnapshot a,VdlSnapshot b) {
   if(a==null || b==null || !a.exactState || !b.exactState || a.fileId64!=b.fileId64 || a.volumeSerialHex!=b.volumeSerialHex || a.extents.Length!=b.extents.Length)return false;
   for(int i=0;i<a.extents.Length;i++)if(a.extents[i].startingVcn!=b.extents[i].startingVcn || a.extents[i].nextVcn!=b.extents[i].nextVcn || a.extents[i].lcn!=b.extents[i].lcn)return false;return true;
  }
  static string HashKnown(FileStream stream){if(stream.Length!=FileBytes)throw new IOException("Control length differs.");stream.Position=0;using(SHA256 sha=SHA256.Create())return Hex(sha.ComputeHash(stream));}
  public static VdlResult MeasureInitialized(string volume,string placementId,string expectedHash,string expectedId) {
   VdlResult result=new VdlResult();List<SafeFileHandle> pins=null;try{
    result.fixturePath=PathFor(placementId,true);if(!Regex.IsMatch(expectedHash??"","^[0-9a-f]{64}$") || !Regex.IsMatch(expectedId??"","^0x[0-9a-f]{16}$"))throw new ArgumentException("Pinned initialized control identity required.");
    pins=Pin(volume);pins.Add(Open(Path.GetDirectoryName(result.fixturePath),true,false));
    using(SafeFileHandle file=Open(result.fixturePath,false,false))using(FileStream stream=new FileStream(file,FileAccess.Read,65536,false)) {
     result.phase="read-only-control";result.sha256Before=HashKnown(stream);if(result.sha256Before!=expectedHash)throw new IOException("Initialized control hash differs.");
     VdlSnapshot before=Observe(result,file,"before",FileBytes),after=Observe(result,file,"after",FileBytes);result.sha256After=HashKnown(stream);
     result.controlQualified=SameMapping(before,after)&&before.fileId64==expectedId&&result.sha256After==expectedHash;
     result.status=result.controlQualified?"initialized-vdl-control-qualified":"initialized-vdl-control-unresolved";result.phase="complete";
    }
   }catch(Exception error){result.error=error.ToString();}finally{if(pins!=null)for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}return result;
  }
  static void SetSize(VdlResult result,SafeFileHandle file,string name,int infoClass) {
   byte[] input=BitConverter.GetBytes(FileBytes);VdlOperation op=new VdlOperation {name=name,inputHex=Hex(input),startedUtc=DateTime.UtcNow.ToString("o")};result.operations.Add(op);op.succeeded=SetFileInformationByHandle(file,infoClass,input,8);op.nativeError=op.succeeded?0:Marshal.GetLastWin32Error();op.finishedUtc=DateTime.UtcNow.ToString("o");if(!op.succeeded)throw new Win32Exception(op.nativeError,name);
  }
  static SecurityAttributes Security(string sddl,out IntPtr descriptor) {
   uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out descriptor,out size))throw new Win32Exception(Marshal.GetLastWin32Error());return new SecurityAttributes {length=Marshal.SizeOf(typeof(SecurityAttributes)),descriptor=descriptor,inherit=0};
  }
  public static VdlResult AllocateZero(string volume,string measurementId) {
   VdlResult result=new VdlResult();List<SafeFileHandle> pins=null;IntPtr folderSd=IntPtr.Zero,fileSd=IntPtr.Zero;
   try {
    result.fixturePath=PathFor(measurementId,false);pins=Pin(volume);string sid=WindowsIdentity.GetCurrent().User.Value;string dirSddl=PrivateSddl(sid,true);result.privateSddl=PrivateSddl(sid,false);
    SecurityAttributes folderSecurity=Security(dirSddl,out folderSd),fileSecurity=Security(result.privateSddl,out fileSd);string directory=Path.GetDirectoryName(result.fixturePath);
    result.phase="private-create";result.targetWriteRequestsIssued=true;if(!CreateDirectory(directory,ref folderSecurity))throw new Win32Exception(Marshal.GetLastWin32Error());result.directoryCreated=true;
    SafeFileHandle folder=Open(directory,true,false);pins.Add(folder);VerifyAcl(folder,sid,true);
    VdlSnapshot immediate,flushed;
    using(SafeFileHandle file=CreatePrivateFile(result.fixturePath,Read|Write,0,ref fileSecurity,1,OpenReparse,IntPtr.Zero)) {
     if(file.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());result.fileCreated=true;CheckHandle(file,result.fixturePath,false);VerifyAcl(file,sid,false);result.privateAclVerified=true;
     VdlQuery empty=Query(result,file,"emptyStandard",0,null,24);if(!empty.succeeded)throw new Win32Exception(empty.nativeError);ParseInitialStandard(empty.bytes);
     result.phase="reserve-allocation";result.allocationRequested=true;SetSize(result,file,"FileAllocationInfo",5);
     VdlQuery allocated=Query(result,file,"allocatedStandard",0,null,24);if(!allocated.succeeded)throw new Win32Exception(allocated.nativeError);VdlStandard allocatedInfo=ParseStandard(allocated.bytes);if(allocatedInfo.eofBytes!=0 || allocatedInfo.allocationBytes!=FileBytes)throw new IOException("Allocation-only state differs.");
     result.phase="set-eof";result.eofRequested=true;SetSize(result,file,"FileEndOfFileInfo",6);
     immediate=Observe(result,file,"immediate",0);if(!immediate.exactState){result.status="allocated-vdl-state-unresolved";return result;}
     result.phase="flush";result.explicitFlushRequested=true;VdlOperation flush=new VdlOperation {name="FlushFileBuffers",inputHex="",startedUtc=DateTime.UtcNow.ToString("o")};result.operations.Add(flush);flush.succeeded=FlushFileBuffers(file);flush.nativeError=flush.succeeded?0:Marshal.GetLastWin32Error();flush.finishedUtc=DateTime.UtcNow.ToString("o");if(!flush.succeeded)throw new Win32Exception(flush.nativeError);
     flushed=Observe(result,file,"flushed",0);if(!SameMapping(immediate,flushed)){result.status="allocated-vdl-state-unresolved";return result;}
    }
    result.phase="reopen";
    using(SafeFileHandle reopened=Open(result.fixturePath,false,false)){VerifyAcl(reopened,sid,false);VdlSnapshot after=Observe(result,reopened,"reopened",0);result.zeroVdlQualified=SameMapping(immediate,after)&&SameMapping(flushed,after);}
    result.status=result.zeroVdlQualified?"allocation-zero-vdl-observed":"allocated-vdl-state-unresolved";result.phase="complete";
   }catch(Exception error){result.error=error.ToString();}finally{if(fileSd!=IntPtr.Zero)LocalFree(fileSd);if(folderSd!=IntPtr.Zero)LocalFree(folderSd);if(pins!=null)for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}return result;
  }
 }
}
