// Query/read-only backend: no format, write, flush, mount, lock, online or detach entry point.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 sealed class WindowsConvertedVerificationApi:IConvertedVerificationApi {
  const uint Read=0x80000000,Metadata=0x20080,SecurityAccess=0x01000000,Reparse=0x200000,Backup=0x2000000;
  [StructLayout(LayoutKind.Sequential)]struct TP{public uint count,low;public int high;public uint attributes;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int informationClass,[Out]byte[] output,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder text,uint count,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool GetVolumeInformationByHandleW(SafeFileHandle h,StringBuilder label,uint labelCapacity,out uint serial,out uint component,out uint flags,StringBuilder fs,uint fsCapacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool GetDiskFreeSpaceW(string root,out uint clusterSectors,out uint sectorBytes,out uint free,out uint total);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(SafeFileHandle h,[Out]byte[] bytes,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFilePointerEx(SafeFileHandle h,long distance,out long position,uint method);
  [DllImport("advapi32.dll",SetLastError=true)]static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")]static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr address);
  [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint access,out SafeFileHandle token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool LookupPrivilegeValueW(string system,string name,out long luid);
  [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(SafeFileHandle token,int kind,[Out]byte[] output,uint capacity,out uint returned);
  [DllImport("advapi32.dll",SetLastError=true)]static extern bool AdjustTokenPrivileges(SafeFileHandle token,bool all,ref TP requested,uint capacity,out TP previous,out uint returned);
  [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
  ConvertedExpected expected;List<RetainedQuery> sink,opening;readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();readonly HashSet<SafeFileHandle> closeAttempts=new HashSet<SafeFileHandle>(),closedSuccessfully=new HashSet<SafeFileHandle>();readonly List<string> closeFailures=new List<string>();
  SafeFileHandle disk,volume,root,folder,file,token;long securityLuid;uint priorAttributes;bool priorCaptured,adjustmentAttempted;int readCalls,reopenCalls;
  readonly ConvertedSecurityPrivilege privilege=new ConvertedSecurityPrivilege();public ConvertedSecurityPrivilege SecurityPrivilege{get{return privilege;}}
  static void Fail(string message){throw new Win32Exception(Marshal.GetLastWin32Error(),message);}
  SafeFileHandle Add(SafeFileHandle h){if(h==null||h.IsInvalid){int error=Marshal.GetLastWin32Error();if(h!=null)h.Dispose();throw new Win32Exception(error,"Read-only native open failed.");}handles.Add(h);return h;}
  void CloseOne(SafeFileHandle h){if(h==null||h.IsClosed||h.IsInvalid)return;if(!closeAttempts.Add(h))throw new IOException("Uncertain handle close is not retried.");bool ok=CloseHandle(h.DangerousGetHandle());int error=ok?0:Marshal.GetLastWin32Error();h.SetHandleAsInvalid();if(!ok){string message="Read-only handle close failed: "+error;closeFailures.Add(message);throw new Win32Exception(error,message);}closedSuccessfully.Add(h);}
  RetainedQuery Query(SafeFileHandle h,string name,uint code,byte[] input,int capacity,int informationClass){
   if(sink==null||sink.Count>=40||capacity<0||capacity>65536)throw new InvalidDataException("Native query evidence bound exceeded.");
   RetainedQuery q=new RetainedQuery{name=name,api=informationClass<0?"DeviceIoControl":"GetFileInformationByHandleEx",code=informationClass<0?code:(uint)informationClass,inputHex=input==null?"":NativeRetainedFixture.Hex(input),capacity=capacity,startedUtc=DateTime.UtcNow.ToString("o")};sink.Add(q);byte[] output=capacity==0?null:new byte[capacity];uint n=0;
   if(informationClass<0)q.succeeded=DeviceIoControl(h,code,input,input==null?0:(uint)input.Length,output,(uint)capacity,out n,IntPtr.Zero);else{q.succeeded=GetFileInformationByHandleEx(h,informationClass,output,(uint)capacity);if(q.succeeded)n=(uint)capacity;}
   q.nativeError=q.succeeded?0:Marshal.GetLastWin32Error();q.finishedUtc=DateTime.UtcNow.ToString("o");q.bytesReturned=n;if(n>capacity)throw new InvalidDataException("Native output exceeded bounded capacity.");q.bytes=new byte[n];if(n>0)Array.Copy(output,q.bytes,n);return q;
  }
  byte[] Required(RetainedQuery q){if(!q.succeeded)throw new Win32Exception(q.nativeError,"Required read-only query failed: "+q.name);return q.bytes;}
  byte[] Info(SafeFileHandle h,string name,int cls,int capacity){return Required(Query(h,name,0,null,capacity,cls));}
  byte[] Control(SafeFileHandle h,string name,uint code,byte[] input,int capacity){return Required(Query(h,name,code,input,capacity,-1));}
  void DiskProof(){
   byte[] b=Control(disk,"Device",0x2d1080,null,12);if(b.Length!=12||BitConverter.ToUInt32(b,0)!=7||BitConverter.ToUInt32(b,4)!=1||BitConverter.ToUInt32(b,8)!=0)throw new InvalidDataException("Physical target routing differs.");
   b=Control(disk,"Length",0x7405c,null,8);if(b.Length!=8||BitConverter.ToInt64(b,0)!=NativeConvertedVerification.DiskBytes)throw new InvalidDataException("Physical target size differs.");
   byte[] property=new byte[12];property[0]=6;b=Control(disk,"Alignment",0x2d1400,property,28);if(b.Length!=28||BitConverter.ToUInt32(b,0)!=28||BitConverter.ToUInt32(b,4)!=28||BitConverter.ToUInt32(b,16)!=512||BitConverter.ToUInt32(b,20)!=4096||BitConverter.ToUInt32(b,24)!=0)throw new InvalidDataException("Physical alignment differs.");
   NativeConvertedVerification.ValidateLayout(Control(disk,"Layout",0x70050,null,65536),expected);
   b=Control(disk,"DiskAttributes",0x700f0,null,16);if(b.Length!=16||BitConverter.ToUInt32(b,0)!=16||BitConverter.ToUInt32(b,4)!=0||BitConverter.ToUInt64(b,8)!=2)throw new InvalidDataException("Require already online, read-only target disk.");
   RetainedQuery writable=Query(disk,"IsWritable",0x70024,null,0,-1);if(writable.succeeded||writable.nativeError!=19||writable.bytesReturned!=0)throw new InvalidDataException("Native write-protection refusal required.");
  }
  void CheckPath(SafeFileHandle h,string path,bool directory){byte[] b=Info(h,directory?"DirectoryType":"FileType",9,8);uint attr=BitConverter.ToUInt32(b,0);if(BitConverter.ToUInt32(b,4)!=0||(attr&0x400)!=0||((attr&16)!=0)!=directory||(!directory&&(attr&0x4a00)!=0))throw new InvalidDataException("Reparse or unsupported object type.");StringBuilder text=new StringBuilder(512);uint n=GetFinalPathNameByHandleW(h,text,512,1);if(n==0||n>=512||!String.Equals(text.ToString().TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("Pinned GUID-relative final path differs.");}
  SafeFileHandle OpenPath(string path,bool directory,bool security){SafeFileHandle h=Add(CreateFileW(path,NativeConvertedVerification.ObservationAccess(directory,security),directory?1U:0U,IntPtr.Zero,3,Reparse|(directory?Backup:0),IntPtr.Zero));CheckPath(h,path,directory);return h;}
  uint SecurityAttributes(){byte[] bytes=new byte[65536];uint returned;if(!GetTokenInformation(token,3,bytes,(uint)bytes.Length,out returned))Fail("Own-token privilege query failed.");if(returned<4||returned>bytes.Length||returned!=4+12L*BitConverter.ToUInt32(bytes,0))throw new InvalidDataException("Incomplete own-token privilege reply.");int found=0;uint attributes=0;for(int i=0;i<BitConverter.ToUInt32(bytes,0);i++)if(BitConverter.ToInt64(bytes,4+12*i)==securityLuid){found++;attributes=BitConverter.ToUInt32(bytes,12+12*i);}if(found!=1)throw new UnauthorizedAccessException("Exactly one assigned SeSecurityPrivilege required.");return attributes;}
  void AdjustSecurity(uint attributes){TP desired=new TP{count=1,low=(uint)securityLuid,high=(int)(securityLuid>>32),attributes=attributes},previous;uint returned;bool ok=AdjustTokenPrivileges(token,false,ref desired,16,out previous,out returned);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"Own-process SeSecurityPrivilege adjustment failed.");}
  void EnableSecurity(){SafeFileHandle h;if(!OpenProcessToken(GetCurrentProcess(),0x28,out h))Fail("Own-process token open failed.");token=Add(h);if(!LookupPrivilegeValueW(null,"SeSecurityPrivilege",out securityLuid))Fail("Own-process privilege lookup failed.");priorAttributes=SecurityAttributes();priorCaptured=true;privilege.beforeCaptured=true;privilege.beforeAttributes=priorAttributes;adjustmentAttempted=true;privilege.adjustmentAttempted=true;AdjustSecurity(priorAttributes|2U);privilege.enabledAttributes=SecurityAttributes();if(privilege.enabledAttributes!=(priorAttributes|2U))throw new UnauthorizedAccessException("Own-process privilege enable verification failed.");privilege.enabled=true;}
  RetainedSecurity Security(SafeFileHandle h,bool directory){
   IntPtr owner,group,dacl,sacl,descriptor;uint error=GetSecurityInfo(h,1,0x1f,out owner,out group,out dacl,out sacl,out descriptor);
   RetainedQuery q=new RetainedQuery{name=directory?"DirectorySecurity":"Security",api="GetSecurityInfo",code=31,inputHex="",capacity=16384,succeeded=error==0,nativeError=(int)error,startedUtc=DateTime.UtcNow.ToString("o")};sink.Add(q);
   try{if(error!=0)throw new Win32Exception((int)error,"Full security query failed.");uint length=GetSecurityDescriptorLength(descriptor);if(length<20||length>16384)throw new InvalidDataException("Security response exceeds bound.");q.bytes=new byte[length];Marshal.Copy(descriptor,q.bytes,0,(int)length);q.bytesReturned=length;return NativeRetainedFixture.ParseSecurity(q.bytes,expected.ownerSid,directory);}finally{q.finishedUtc=DateTime.UtcNow.ToString("o");if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
  }
  void OpenObjects(){root=OpenPath(expected.volumeGuid,true,false);folder=OpenPath(expected.volumeGuid+"retained",true,true);file=OpenPath(expected.volumeGuid+@"retained\payload.bin",false,true);}
  public void Open(ConvertedExpected e,List<RetainedQuery> queries){
   if(Environment.MachineName!="N2R-WIN11"||Environment.GetEnvironmentVariable("SystemDrive")!="C:"||IntPtr.Size!=8||WindowsIdentity.GetCurrent().User.Value!=e.ownerSid)throw new InvalidOperationException("Exact owned x64 guest/current local owner required.");expected=e;opening=queries;sink=opening;
   disk=Add(CreateFileW(@"\\.\PhysicalDrive1",Read,3,IntPtr.Zero,3,0,IntPtr.Zero));DiskProof();
   volume=Add(CreateFileW(e.volumeGuid.TrimEnd('\\'),Read,3,IntPtr.Zero,3,0,IntPtr.Zero));VolumeProof(null);EnableSecurity();OpenObjects();
  }
  void VolumeProof(ConvertedSnapshot s){
   byte[] b=Control(volume,"VolumeExtents",0x560000,null,32);if(b.Length!=32||BitConverter.ToUInt32(b,0)!=1||BitConverter.ToUInt32(b,8)!=1||BitConverter.ToInt64(b,16)!=NativeConvertedVerification.PartitionOffset||BitConverter.ToInt64(b,24)!=NativeConvertedVerification.PartitionBytes)throw new InvalidDataException("Fresh volume is not the original target partition.");
   StringBuilder label=new StringBuilder(128),fs=new StringBuilder(32);uint serial,component,flags;if(!GetVolumeInformationByHandleW(volume,label,128,out serial,out component,out flags,fs,32))Fail("Pinned volume query failed.");
   if(fs.ToString()!="ReFS"||label.ToString()!="n2r-retained-shadow"||serial!=expected.volumeSerial32||flags!=(expected.volumeFlags|0x80000U))throw new InvalidDataException("Protected mounted ReFS identity differs.");
   uint sectors,bytes,free,total;if(!GetDiskFreeSpaceW(expected.volumeGuid,out sectors,out bytes,out free,out total))Fail("Mounted cluster geometry query failed.");if(sectors!=8||bytes!=512||total!=expected.totalClusters)throw new InvalidDataException("Mounted cluster geometry differs.");
   if(s!=null){s.volumeFlags=flags;s.volumeSerial32=serial;s.totalClusters=total;s.readOnlyVolumeVerified=true;}
  }
  RetainedDirectoryEntry[] DirectoryEntries(SafeFileHandle h,bool isFolder){List<RetainedDirectoryEntry> entries=new List<RetainedDirectoryEntry>();for(int i=0;i<4;i++){RetainedQuery q=Query(h,(isFolder?"Folder":"Root")+"Directory"+i,0,null,4096,i==0?11:10);if(!q.succeeded){if(q.nativeError!=18)throw new Win32Exception(q.nativeError,"Protected directory enumeration failed.");RetainedNamespace observation=new RetainedNamespace{path=isFolder?@"F:\retained":@"F:\",expectedFixture=true,entries=entries.ToArray()};NativeRetainedFixture.CheckNamespace(observation);return observation.entries;}entries.AddRange(NativeRetainedFixture.ParseDirectory(q.bytes));if(entries.Count>(isFolder?3:5))throw new InvalidDataException("Protected directory inventory exceeded bound.");}throw new InvalidDataException("Protected directory enumeration did not terminate.");}
  string[] Namespace(){List<string> entries=new List<string>();foreach(RetainedDirectoryEntry e in DirectoryEntries(root,false))if(e.name!="."&&e.name!="..")entries.Add(e.name);DirectoryEntries(folder,true);entries.Sort(StringComparer.Ordinal);return entries.ToArray();}
  public void Capture(ConvertedSnapshot s){
   sink=s.queries;DiskProof();s.nativeDiskVerified=true;VolumeProof(s);CheckPath(file,expected.volumeGuid+@"retained\payload.bin",false);CheckPath(folder,expected.volumeGuid+"retained",true);s.namespaceEntries=Namespace();
   RetainedSnapshot f=new RetainedSnapshot{name=s.name};s.file=f;f.basic=NativeRetainedFixture.ParseBasic(Info(file,"Basic",0,40),false);f.standard=NativeRetainedFixture.ParseStandard(Info(file,"Standard",1,24),false);f.identity=NativeRetainedFixture.ParseIdentity(Info(file,"Id",18,24));f.streams=NativeRetainedFixture.ParseStreams(Info(file,"Streams",7,4096));f.security=Security(file,false);
   f.extents=NativeRetainedFixture.ParseExtents(Control(file,"Extents",0x90073,new byte[8],272));f.baseSectors=NativeRetainedFixture.ParseBase(Control(volume,"Base",0x90234,null,8));f.partitionOffset=NativeRetainedFixture.Offset(f.baseSectors,f.extents[0].lcn);
   f.cached=NativeRetainedFixture.ParseValidRegions(Control(file,"Cached",0x90284,NativeRetainedFixture.RegionInput(1),400),1);f.fullyCachedValid=true;f.storageRegionQueryAttempted=true;f.onDisk=NativeRetainedFixture.ParseValidRegions(Control(file,"OnDisk",0x90284,NativeRetainedFixture.RegionInput(2),400),2);f.fullyStorageValid=true;f.storageValidityStatus="native-full-storage-validity";
   byte[] integrity=Control(file,"Integrity",0x9027c,null,16);if(integrity.Length!=16||BitConverter.ToUInt16(integrity,2)!=0||BitConverter.ToUInt32(integrity,12)!=4096)throw new InvalidDataException("Integrity response shape differs.");f.integrityQueried=true;f.checksumAlgorithm=BitConverter.ToUInt16(integrity,0);f.integrityFlags=BitConverter.ToUInt32(integrity,4);
   s.directoryBasic=NativeRetainedFixture.ParseBasic(Info(folder,"DirectoryBasic",0,40),true);s.directorySecurity=Security(folder,true);s.directoryIdentity=NativeRetainedFixture.ParseIdentity(Info(folder,"DirectoryId",18,24));NativeRetainedFixture.ParseStandard(Info(folder,"DirectoryStandard",1,24),true);
  }
  public byte[] ReadPayload(){if(readCalls>=2)throw new InvalidOperationException("Maximum two64KiB reads.");readCalls++;long at;if(!SetFilePointerEx(file,0,out at,0)||at!=0)Fail("Read-only seek failed.");byte[] bytes=new byte[65536];uint n;if(!ReadFile(file,bytes,65536,out n,IntPtr.Zero))Fail("Converted logical read failed.");if(n!=65536)throw new IOException("Short converted logical read.");return bytes;}
  public void Reopen(){if(++reopenCalls!=1)throw new InvalidOperationException("Single read-only reopen allowed.");CloseOne(file);CloseOne(folder);CloseOne(root);sink=opening;DiskProof();VolumeProof(null);OpenObjects();}
  public void Close(){List<string> failures=new List<string>();if(adjustmentAttempted){try{if(!priorCaptured)throw new InvalidOperationException("Previous privilege state missing.");privilege.restorationAttempted=true;AdjustSecurity(priorAttributes);privilege.restoredAttributes=SecurityAttributes();if(privilege.restoredAttributes!=priorAttributes)throw new InvalidOperationException("Own-process privilege restoration differs.");privilege.restored=true;}catch(Exception e){failures.Add(e.Message);}}else privilege.restored=true;
   for(int i=handles.Count-1;i>=0;i--)try{CloseOne(handles[i]);}catch(Exception e){failures.Add(e.Message);}privilege.tokenClosed=token==null||closedSuccessfully.Contains(token);failures.AddRange(closeFailures);if(failures.Count!=0)throw new IOException(String.Join("; ",failures.ToArray()));
  }
 }
}
