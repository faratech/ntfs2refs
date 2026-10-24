// Metadata-only observation of one preserved lab file. No payload I/O or setters.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class VdlObservationStandard { public long allocationBytes,eofBytes;public uint links;public bool deletePending,directory; }
 public sealed class VdlObservationRegion { public long offset,length;public uint usage; }
 public sealed class VdlObservationRegions { public uint requestedUsage;public long prefixBytes;public bool complete,prefixShaped,prefixIsSummaryOnly=true;public VdlObservationRegion[] regions; }
 public sealed class VdlObservationExtent { public long startingVcn,nextVcn,lcn;public bool negativeMarker;public string interpretation; }
 public sealed class VdlObservationIdentity { public string fileId64,volumeSerialHex;public long length;public uint attributes,links; }
 public sealed class VdlObservationVolume { public string name,api="GetVolumeInformationW",filesystem,label;public uint flags,serial,maximumComponentLength;public bool succeeded,supportsSparseVdl,readOnlyVolume;public int nativeError; }
 public sealed class VdlObservationQuery { public string name,api,inputHex,startedUtc,finishedUtc,nativeMessage;public uint controlCode,informationClass,bytesReturned;public int inputBytes,outputCapacityBytes,nativeError;public bool succeeded;public byte[] bytes; }
 public sealed class VdlObservationSnapshot { public string name;public VdlObservationIdentity identity;public VdlObservationStandard standard;public VdlObservationRegions cached,onDisk;public VdlObservationExtent[] extents;public bool complete;public List<string> errors=new List<string>(); }
 public sealed class VdlObservationResult {
  public string status="blocked",phase="preflight",error,cleanupError,fixturePath=NativeVdlObservation.FilePath;
  public bool identityVerified,observationComplete,stableDuringObservation,cleanupComplete;
  public bool newFilePayloadReads,newFilePayloadWrites,targetWriteRequestsIssued,explicitFlushRequested,moveAttempted,setValidDataAttempted,allocationRequested,protectionChanged,privilegeAdjustmentAttempted,physicalMappingVerified,zeroVdlQualified,payloadCopyAvoidanceVerified,conversionQualified;
  public List<VdlObservationQuery> queries=new List<VdlObservationQuery>();public List<VdlObservationSnapshot> snapshots=new List<VdlObservationSnapshot>();public List<VdlObservationVolume> volumes=new List<VdlObservationVolume>();
 }
 public interface IVdlObservationApi {
  void Open(string volume);
  VdlObservationIdentity Identity();
  VdlObservationVolume Volume();
  VdlObservationQuery Query(string name,uint code,byte[] input,int capacity);
  void Close();
 }
 public static class NativeVdlObservation {
  public const string MeasurementId="2780e16cd7bb4d12a5ba8070bac0a1e7",FilePath=@"F:\fixtures\vdl-2780e16cd7bb4d12a5ba8070bac0a1e7\uninitialized.bin",VolumePath=@"\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\",FileId="0x3000000000002703",VolumeSerial="0x08425382";
  public static byte[] RegionInput(uint usage) {if(usage!=1 && usage!=2)throw new ArgumentOutOfRangeException("usage");byte[] b=new byte[24];BitConverter.GetBytes(65536L).CopyTo(b,8);BitConverter.GetBytes(usage).CopyTo(b,16);return b;}
  public static VdlObservationStandard ParseStandard(byte[] b) {
   if(b==null || b.Length!=24)throw new InvalidDataException("Expected 24 standard bytes.");long a=BitConverter.ToInt64(b,0),e=BitConverter.ToInt64(b,8);uint links=BitConverter.ToUInt32(b,16);
   if(a<0 || a>65536 || e!=65536 || links!=1 || b[20]!=0 || b[21]!=0)throw new InvalidDataException("Unexpected bounded file size, links or type.");
   return new VdlObservationStandard {allocationBytes=a,eofBytes=e,links=links};
  }
  public static VdlObservationRegions ParseRegions(byte[] b,uint requested) {
   RegionInput(requested);if(b==null || b.Length<40 || b.Length>400)throw new InvalidDataException("Bounded region entries required.");uint total=BitConverter.ToUInt32(b,4),count=BitConverter.ToUInt32(b,8);
   if(total==0 || total!=count || count>16 || b.Length!=16+24L*count)throw new InvalidDataException("Incomplete region counts.");
   List<VdlObservationRegion> rows=new List<VdlObservationRegion>();long next=0,prefix=0;bool invalid=false,shaped=true;
   for(int i=0;i<count;i++){int p=16+24*i;long start=BitConverter.ToInt64(b,p),length=BitConverter.ToInt64(b,p+8);uint usage=BitConverter.ToUInt32(b,p+16);if(start!=next || length<=0 || length>65536-start || (usage&~31U)!=0)throw new InvalidDataException("Region gap, overlap, bounds or unknown usage.");if((usage&requested)!=0){if(invalid)shaped=false;else prefix=start+length;}else invalid=true;rows.Add(new VdlObservationRegion {offset=start,length=length,usage=usage});next=start+length;}
   if(next!=65536)throw new InvalidDataException("Incomplete requested region coverage.");return new VdlObservationRegions {requestedUsage=requested,prefixBytes=shaped?prefix:-1,complete=true,prefixShaped=shaped,regions=rows.ToArray()};
  }
  public static VdlObservationExtent[] ParseSignedExtents(byte[] b) {
   if(b==null || b.Length<32 || b.Length>272 || BitConverter.ToInt64(b,8)!=0)throw new InvalidDataException("Bounded extent response required.");uint count=BitConverter.ToUInt32(b,0);if(count<1 || count>16 || b.Length!=16+16L*count)throw new InvalidDataException("Extent count differs.");
   List<VdlObservationExtent> rows=new List<VdlObservationExtent>();long next=0;
   for(int i=0;i<count;i++){long end=BitConverter.ToInt64(b,16+16*i),lcn=BitConverter.ToInt64(b,24+16*i);if(end<=next || end>16 || (lcn>=0 && lcn>13631488-(end-next)))throw new InvalidDataException("Extent range exceeds the bounded file/volume.");rows.Add(new VdlObservationExtent {startingVcn=next,nextVcn=end,lcn=lcn,negativeMarker=lcn<0,interpretation=lcn<0?"unresolved-ReFS-negative-marker":"native-LCN-physical-equivalence-unqualified"});next=end;}
   if(next!=16)throw new InvalidDataException("Incomplete sixteen-cluster coverage.");return rows.ToArray();
  }
  public static void CheckIdentity(VdlObservationIdentity i) {if(i==null || i.fileId64!=FileId || i.volumeSerialHex!=VolumeSerial || i.length!=65536 || i.links!=1 || (i.attributes&0x4410)!=0)throw new InvalidDataException("Preserved file identity, length or type changed.");}
  public static void SetVolumeFlags(VdlObservationVolume v) {v.supportsSparseVdl=(v.flags&0x10000000)!=0;v.readOnlyVolume=(v.flags&0x00080000)!=0;}
  static bool Equal(byte[] a,byte[] b){if(a==null || b==null || a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
  static VdlObservationSnapshot Observe(IVdlObservationApi api,VdlObservationResult result,string name) {
   VdlObservationSnapshot s=new VdlObservationSnapshot {name=name,identity=api.Identity()};CheckIdentity(s.identity);result.snapshots.Add(s);
   string[] names={"Standard","Cached","OnDisk","Extents"};uint[] codes={0,0x90284,0x90284,0x90073};byte[][] inputs={null,RegionInput(1),RegionInput(2),new byte[8]};int[] caps={24,400,400,272};
   for(int i=0;i<4;i++){
    VdlObservationQuery q=api.Query(name+names[i],codes[i],inputs[i],caps[i]);result.queries.Add(q);
    if(q==null || q.bytes==null || q.bytesReturned!=q.bytes.Length || q.bytes.Length>caps[i])throw new InvalidDataException("Native output exceeds its declared bound.");
    if(!q.succeeded){s.errors.Add(names[i]+" native error "+q.nativeError);continue;}
    try{if(i==0)s.standard=ParseStandard(q.bytes);else if(i==1)s.cached=ParseRegions(q.bytes,1);else if(i==2)s.onDisk=ParseRegions(q.bytes,2);else s.extents=ParseSignedExtents(q.bytes);}catch(Exception e){s.errors.Add(names[i]+": "+e.Message);}
   }
   CheckIdentity(api.Identity());s.complete=s.errors.Count==0;return s;
  }
  public static VdlObservationResult CollectWith(IVdlObservationApi api,string volume) {
   if(api==null || volume!=VolumePath)throw new ArgumentException("Exact preserved volume required.");VdlObservationResult r=new VdlObservationResult();
   try {
    r.phase="open-metadata";api.Open(volume);CheckIdentity(api.Identity());
    for(int i=0;i<2;i++){
     string name=i==0?"before":"after";r.phase="observe-"+name;VdlObservationVolume v=api.Volume();v.name=name;SetVolumeFlags(v);r.volumes.Add(v);
     if(v.succeeded && (v.filesystem!="ReFS" || v.label!="ntfs2refs-target" || v.serial!=0x08425382))throw new InvalidDataException("Mounted volume identity changed.");
     Observe(api,r,name);
    }
    CheckIdentity(api.Identity());r.identityVerified=true;r.observationComplete=r.snapshots[0].complete&&r.snapshots[1].complete&&r.volumes[0].succeeded&&r.volumes[1].succeeded;
    VdlObservationIdentity first=r.snapshots[0].identity,last=r.snapshots[1].identity;
    bool same=r.observationComplete&&r.volumes[0].flags==r.volumes[1].flags&&first.fileId64==last.fileId64&&first.volumeSerialHex==last.volumeSerialHex&&first.length==last.length&&first.links==last.links&&first.attributes==last.attributes;
    for(int i=0;i<4 && same;i++)same=Equal(r.queries[i].bytes,r.queries[i+4].bytes);
    r.stableDuringObservation=same;r.status=r.observationComplete?"metadata-observed":"native-query-unresolved";r.phase="complete";
   }catch(Exception e){r.error=e.ToString();}finally{try{api.Close();r.cleanupComplete=true;}catch(Exception e){r.cleanupError=e.ToString();r.status="cleanup-failed";}}
   return r;
  }
  public static VdlObservationResult Collect(string volume){return CollectWith(new WindowsVdlObservationApi(),volume);}
 }
 sealed class WindowsVdlObservationApi:IVdlObservationApi {
  const uint MetadataAccess=0x00020080,OpenReparse=0x00200000,Backup=0x02000000;
  [StructLayout(LayoutKind.Sequential)] struct Info {public uint attributes;public System.Runtime.InteropServices.ComTypes.FILETIME created,accessed,written;public uint serial,sizeHigh,sizeLow,links,idHigh,idLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder name,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetVolumeInformationW",ExactSpelling=true)] static extern bool GetVolumeInformation(string root,StringBuilder label,uint labelSize,out uint serial,out uint maximumComponent,out uint flags,StringBuilder filesystem,uint filesystemSize);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int infoClass,[Out]byte[] output,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle h,int objectType,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,uint revision,uint information,out IntPtr sddl,out uint length);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();SafeFileHandle file;
  static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  static Info InfoFor(SafeFileHandle h){Info i;if(!GetFileInformationByHandle(h,out i))throw new Win32Exception(Marshal.GetLastWin32Error());return i;}
  static void CheckPath(SafeFileHandle h,string path,bool directory){Info i=InfoFor(h);if((i.attributes&0x400)!=0 || ((i.attributes&0x10)!=0)!=directory)throw new IOException("Reparse or unexpected type.");StringBuilder final=new StringBuilder(512);uint n=GetFinalPathNameByHandle(h,final,512,0);if(n==0 || n>=512 || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new IOException("Resolved path differs.");}
  SafeFileHandle OpenPath(string path,bool directory){SafeFileHandle h=CreateFile(path,MetadataAccess,directory?1U:0U,IntPtr.Zero,3,OpenReparse|(directory?Backup:0),IntPtr.Zero);if(h.IsInvalid){int e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e);}handles.Add(h);CheckPath(h,path,directory);return h;}
  static void PrivateAcl(SafeFileHandle h,bool directory){
   IntPtr owner,group,dacl,sacl,descriptor,text=IntPtr.Zero;uint error=GetSecurityInfo(h,1,5,out owner,out group,out dacl,out sacl,out descriptor);if(error!=0)throw new Win32Exception((int)error);
   try{uint length;if(!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor,1,5,out text,out length))throw new Win32Exception(Marshal.GetLastWin32Error());RawSecurityDescriptor sd=new RawSecurityDescriptor(Marshal.PtrToStringUni(text));string sid=WindowsIdentity.GetCurrent().User.Value;
    if(sd.Owner==null || sd.Owner.Value!=sid || (sd.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || sd.DiscretionaryAcl==null || sd.DiscretionaryAcl.Count!=3)throw new InvalidDataException("Private ACL owner/protection/count changed.");HashSet<string> allowed=new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"});AceFlags flags=directory?(AceFlags.ObjectInherit|AceFlags.ContainerInherit):AceFlags.None;
    foreach(GenericAce item in sd.DiscretionaryAcl){CommonAce ace=item as CommonAce;if(ace==null || ace.AceType!=AceType.AccessAllowed || ace.AccessMask!=0x1f01ff || ace.AceFlags!=flags || !allowed.Remove(ace.SecurityIdentifier.Value))throw new InvalidDataException("Private ACL permissions changed.");}if(allowed.Count!=0)throw new InvalidDataException("Private ACL principal missing.");
   }finally{if(text!=IntPtr.Zero)LocalFree(text);if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
  }
  public void Open(string volume){
   if(Environment.MachineName!="N2R-WIN11" || Environment.GetEnvironmentVariable("SystemDrive")!="C:" || IntPtr.Size!=8 || volume!=NativeVdlObservation.VolumePath)throw new InvalidOperationException("Exact owned x64 guest required.");
   OpenPath(@"F:\",true);OpenPath(@"F:\fixtures",true);StringBuilder actual=new StringBuilder(64);if(!GetVolumeNameForVolumeMountPoint(@"F:\",actual,64) || actual.ToString()!=volume)throw new IOException("Mounted GUID differs.");
   SafeFileHandle folder=OpenPath(Path.GetDirectoryName(NativeVdlObservation.FilePath),true);PrivateAcl(folder,true);file=OpenPath(NativeVdlObservation.FilePath,false);PrivateAcl(file,false);
  }
  public VdlObservationIdentity Identity(){CheckPath(file,NativeVdlObservation.FilePath,false);Info i=InfoFor(file);return new VdlObservationIdentity {fileId64="0x"+i.idHigh.ToString("x8")+i.idLow.ToString("x8"),volumeSerialHex="0x"+i.serial.ToString("x8"),length=((long)i.sizeHigh<<32)|i.sizeLow,attributes=i.attributes,links=i.links};}
  public VdlObservationVolume Volume(){VdlObservationVolume v=new VdlObservationVolume();StringBuilder fs=new StringBuilder(32),label=new StringBuilder(128);v.succeeded=GetVolumeInformation(@"F:\",label,128,out v.serial,out v.maximumComponentLength,out v.flags,fs,32);v.nativeError=v.succeeded?0:Marshal.GetLastWin32Error();v.filesystem=fs.ToString();v.label=label.ToString();return v;}
  public VdlObservationQuery Query(string name,uint code,byte[] input,int capacity){
   VdlObservationQuery q=new VdlObservationQuery {name=name,api=code==0?"GetFileInformationByHandleEx":"DeviceIoControl",controlCode=code,informationClass=code==0?1U:0U,inputBytes=input==null?0:input.Length,inputHex=input==null?"":Hex(input),outputCapacityBytes=capacity,startedUtc=DateTime.UtcNow.ToString("o")};byte[] buffer=new byte[capacity];uint returned=0;
   if(code==0){q.succeeded=GetFileInformationByHandleEx(file,1,buffer,(uint)capacity);if(q.succeeded)returned=(uint)capacity;}else q.succeeded=DeviceIoControl(file,code,input,(uint)input.Length,buffer,(uint)capacity,out returned,IntPtr.Zero);
   q.nativeError=q.succeeded?0:Marshal.GetLastWin32Error();q.nativeMessage=q.succeeded?"success":new Win32Exception(q.nativeError).Message;q.bytesReturned=returned;q.finishedUtc=DateTime.UtcNow.ToString("o");if(returned>capacity)throw new InvalidDataException("Native output exceeds capacity.");q.bytes=new byte[returned];Array.Copy(buffer,q.bytes,(int)returned);return q;
  }
  public void Close(){List<string> errors=new List<string>();for(int i=handles.Count-1;i>=0;i--){SafeFileHandle h=handles[i];if(h.IsClosed || h.IsInvalid)continue;if(CloseHandle(h.DangerousGetHandle()))h.SetHandleAsInvalid();else errors.Add(Marshal.GetLastWin32Error().ToString());}if(errors.Count>0)throw new IOException("CloseHandle failed: "+String.Join(",",errors.ToArray()));}
 }
}
