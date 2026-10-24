// Native backend. All calls occur only in the exact owned guest; tests use the fake interface.
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
 sealed class WindowsRetainedFixtureApi:IRetainedFixtureApi {
  const uint Read=0x80000000,Write=0x40000000,Metadata=0x00020080,SecurityAccess=0x01000000,OpenReparse=0x00200000,Backup=0x02000000;
  [StructLayout(LayoutKind.Sequential)] struct SA {public int length;public IntPtr descriptor;public int inherit;}
  [StructLayout(LayoutKind.Sequential)] struct TP {public uint count;public uint low;public int high;public uint attributes;}
  [StructLayout(LayoutKind.Sequential)] struct FT {public uint low,high;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")] static extern SafeFileHandle CreateSecureFile(string path,uint access,uint share,ref SA security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,ref SA security);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder volume,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetVolumeInformationW",ExactSpelling=true)] static extern bool GetVolumeInformation(string root,StringBuilder label,uint labelCapacity,out uint serial,out uint component,out uint flags,StringBuilder fs,uint fsCapacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetDiskFreeSpace(string root,out uint sectorsPerCluster,out uint sectorBytes,out uint freeClusters,out uint totalClusters);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int informationClass,[Out]byte[] output,uint capacity);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int informationClass,byte[] input,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileTime(SafeFileHandle h,IntPtr creation,ref FT access,IntPtr write);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle h,[Out]byte[] bytes,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(SafeFileHandle h,byte[] bytes,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFilePointerEx(SafeFileHandle h,long distance,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle h);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,uint revision,out IntPtr descriptor,out uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeFileHandle token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out long luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(SafeFileHandle token,bool disableAll,ref TP state,uint capacity,out TP previous,out uint returned);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  sealed class Handles {public SafeFileHandle root,folder,file,volume;public uint diskNumber;}
  readonly Dictionary<string,Handles> handles=new Dictionary<string,Handles>();readonly List<SafeFileHandle> all=new List<SafeFileHandle>();
  RetainedPairResult result;bool constructing,privilegeChanged;SafeFileHandle token;TP previousPrivilege;string sid;
  static void Fail(string message){throw new Win32Exception(Marshal.GetLastWin32Error(),message);}
  SafeFileHandle Add(SafeFileHandle h){if(h==null||h.IsInvalid){int e=Marshal.GetLastWin32Error();if(h!=null)h.Dispose();throw new Win32Exception(e,"Native open failed.");}all.Add(h);return h;}
  static void CloseOne(SafeFileHandle h){if(h==null||h.IsClosed||h.IsInvalid)return;if(!CloseHandle(h.DangerousGetHandle()))Fail("CloseHandle failed.");h.SetHandleAsInvalid();}
  void EnableSecurityPrivilege() {
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))Fail("Own-process token open failed.");long luid;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid))Fail("SeSecurityPrivilege lookup failed.");
   TP wanted=new TP{count=1,low=(uint)luid,high=(int)(luid>>32),attributes=2};uint returned;
   bool ok=AdjustTokenPrivileges(token,false,ref wanted,16,out previousPrivilege,out returned);int error=Marshal.GetLastWin32Error();privilegeChanged=previousPrivilege.count!=0;
   if(!ok||error!=0)throw new Win32Exception(error,"Own-process SeSecurityPrivilege could not be enabled.");
   if(previousPrivilege.count>1)throw new InvalidDataException("Unexpected privilege restore state.");
  }
  RetainedQuery Q(SafeFileHandle h,string name,uint code,byte[] input,int capacity,int infoClass) {
   RetainedQuery q=new RetainedQuery{name=name,api=infoClass>=0?"GetFileInformationByHandleEx":"DeviceIoControl",code=infoClass>=0?(uint)infoClass:code,inputHex=input==null?"":NativeRetainedFixture.Hex(input),capacity=capacity,startedUtc=DateTime.UtcNow.ToString("o")};result.queries.Add(q);
   byte[] buffer=capacity==0?null:new byte[capacity];uint n=0;
   if(infoClass>=0){q.succeeded=GetFileInformationByHandleEx(h,infoClass,buffer,(uint)capacity);if(q.succeeded)n=(uint)capacity;}else q.succeeded=DeviceIoControl(h,code,input,input==null?0:(uint)input.Length,buffer,(uint)capacity,out n,IntPtr.Zero);
   q.nativeError=q.succeeded?0:Marshal.GetLastWin32Error();q.bytesReturned=n;q.finishedUtc=DateTime.UtcNow.ToString("o");if(n>capacity)throw new InvalidDataException("Native reply exceeded declared capacity.");q.bytes=new byte[n];if(n>0)Array.Copy(buffer,q.bytes,(int)n);return q;
  }
  byte[] Require(RetainedQuery q){if(!q.succeeded)throw new Win32Exception(q.nativeError,"Required native query failed: "+q.name);return q.bytes;}
  byte[] Info(SafeFileHandle h,string name,int cls,int capacity){return Require(Q(h,name,0,null,capacity,cls));}
  void CheckPath(SafeFileHandle h,string path,bool directory) {
   byte[] b=Info(h,"pathType",9,8);uint attrs=BitConverter.ToUInt32(b,0),tag=BitConverter.ToUInt32(b,4);
   if((attrs&0x400)!=0||tag!=0||((attrs&16)!=0)!=directory||(!directory&&(attrs&0x4a00)!=0))throw new InvalidDataException("Unsupported reparse/sparse/compressed/encrypted object.");
   StringBuilder p=new StringBuilder(512);uint n=GetFinalPathNameByHandle(h,p,512,0);if(n==0||n>=512||!String.Equals(p.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new IOException("Pinned final path differs.");
  }
  SafeFileHandle OpenPath(string path,bool directory,bool writable,bool security) {
   uint access=directory?Metadata|1U:Read|Metadata;if(writable)access|=directory?0x100U:Write|0x100U;if(security)access|=SecurityAccess;
   // SetFileTime's documented per-handle suppression requires only this extra
   // attribute right; observation handles still have no payload write access.
   access|=0x100U;
   SafeFileHandle h=Add(CreateFile(path,access,directory?1U:0U,IntPtr.Zero,3,OpenReparse|(directory?Backup:0),IntPtr.Zero));
   SuppressLastAccess(h,path,path.EndsWith(":\\")?"root":constructing?"construction":"observation");CheckPath(h,path,directory);return h;
  }
  void SuppressLastAccess(SafeFileHandle h,string path,string stage){
   RetainedAccessPolicy p=NativeRetainedFixture.AccessPolicy(path,stage);result.lastAccessPolicies.Add(p);FT access=new FT{low=UInt32.MaxValue,high=UInt32.MaxValue};
   p.succeeded=SetFileTime(h,IntPtr.Zero,ref access,IntPtr.Zero);p.nativeError=p.succeeded?0:Marshal.GetLastWin32Error();p.finishedUtc=DateTime.UtcNow.ToString("o");
   if(!p.succeeded)throw new Win32Exception(p.nativeError,"Per-handle last-access suppression failed.");
  }
  void Enumerate(SafeFileHandle h,RetainedFixtureState f,string stage,bool expected){
   bool folder=stage.EndsWith("Folder");RetainedNamespace observation=new RetainedNamespace{path=f.root+(folder?"retained":""),stage=stage,expectedFixture=expected};result.namespaces.Add(observation);List<string> names=new List<string>();List<RetainedDirectoryEntry> entries=new List<RetainedDirectoryEntry>();
   for(int i=0;i<4;i++){
    string name=f.role+stage+"Directory"+i;names.Add(name);observation.queryNames=names.ToArray();RetainedQuery q=Q(h,name,0,null,4096,i==0?11:10);
    if(!q.succeeded){
     if(constructing&&stage=="OpenRoot"&&!expected&&i==0&&entries.Count==0&&q.nativeError==2&&q.bytesReturned==0){observation.emptyInitialNoMatchInterpreted=true;observation.initialNoMatchInterpretation="documented-first-empty-search-not-reproduced-by-lab-diagnostic";observation.entries=new RetainedDirectoryEntry[0];continue;}
     if(q.nativeError!=18||q.bytesReturned!=0||(observation.emptyInitialNoMatchInterpreted&&(i!=1||entries.Count!=0)))throw new Win32Exception(q.nativeError,"Bounded directory enumeration failed.");observation.entries=entries.ToArray();NativeRetainedFixture.CheckNamespace(observation);if(observation.emptyInitialNoMatchInterpreted){CheckPath(h,f.root,true);CheckVolume(f,handles[f.role]);}observation.complete=true;return;
    }
    if(observation.emptyInitialNoMatchInterpreted)throw new InvalidDataException("Initial no-match may only be followed by an empty terminal reply.");
    entries.AddRange(NativeRetainedFixture.ParseDirectory(q.bytes));observation.entries=entries.ToArray();if(entries.Count>(folder?3:5))throw new InvalidDataException("Namespace entry bound exceeded.");
   }throw new InvalidDataException("Directory enumeration did not terminate within four calls.");
  }
  RetainedSecurity Security(SafeFileHandle h,bool directory,string name) {
   IntPtr owner,group,dacl,sacl,sd;uint error=GetSecurityInfo(h,1,0x1f,out owner,out group,out dacl,out sacl,out sd);
   RetainedQuery q=new RetainedQuery{name=name,api="GetSecurityInfo",code=0x1f,capacity=16384,inputHex="",startedUtc=DateTime.UtcNow.ToString("o"),succeeded=error==0,nativeError=(int)error};result.queries.Add(q);
   try{if(error!=0)throw new Win32Exception((int)error,"Full SACL/label security query failed.");uint n=GetSecurityDescriptorLength(sd);if(n<20||n>16384)throw new InvalidDataException("Security reply exceeds bound.");q.bytes=new byte[n];Marshal.Copy(sd,q.bytes,0,(int)n);q.bytesReturned=n;return NativeRetainedFixture.ParseSecurity(q.bytes,sid,directory);}finally{q.finishedUtc=DateTime.UtcNow.ToString("o");if(sd!=IntPtr.Zero)LocalFree(sd);}
  }
  void CheckVolume(RetainedFixtureState f,Handles h) {
   StringBuilder actual=new StringBuilder(64),fs=new StringBuilder(32),label=new StringBuilder(128);uint serial,component,flags,spc,bps,free,total;
   if(!GetVolumeNameForVolumeMountPoint(f.root,actual,64)||!String.Equals(actual.ToString(),f.volume,StringComparison.OrdinalIgnoreCase))throw new IOException("Volume GUID changed.");
   if(!GetVolumeInformation(f.root,label,128,out serial,out component,out flags,fs,32))Fail("Volume information failed.");
   if(fs.ToString()!=f.filesystem||label.ToString()!=(f.role=="A"?"n2r-retained-source":"n2r-retained-shadow")||(flags&0x80000)!=0)throw new InvalidDataException("Volume filesystem/label/protection changed.");
   if(!GetDiskFreeSpace(f.root,out spc,out bps,out free,out total))Fail("Cluster geometry query failed.");if(spc!=8||bps!=512)throw new InvalidDataException("Expected512-byte sectors/4096-byte clusters.");
   if(f.nativeTotalClusters!=0&&(f.volumeFlags!=flags||f.volumeSerial32!=serial||f.nativeTotalClusters!=total))throw new InvalidDataException("Mounted filesystem flags/serial/cluster count changed.");f.volumeFlags=flags;f.volumeSerial32=serial;f.nativeTotalClusters=total;
   byte[] b=Require(Q(h.volume,f.role+"VolumeExtents",0x00560000,null,32,-1));if(b.Length!=32||BitConverter.ToUInt32(b,0)!=1||BitConverter.ToInt64(b,16)!=16777216||BitConverter.ToInt64(b,24)!=NativeRetainedFixture.VolumeBytes)throw new InvalidDataException("Expected one52GiB volume extent at16MiB.");h.diskNumber=BitConverter.ToUInt32(b,8);if(h.diskNumber==0||(f.role=="A"&&h.diskNumber!=1))throw new InvalidDataException("Target disk identity outside fixture profile.");
   if(NativeRetainedFixture.ParseBase(Require(Q(h.volume,f.role+"OpenBase",0x90234,null,8,-1)))!=0)throw new InvalidDataException("First fixture requires zero retrieval base.");
  }
  public void Open(RetainedPairResult r,bool construct) {
   result=r;constructing=construct;if(Environment.MachineName!="N2R-WIN11"||Environment.GetEnvironmentVariable("SystemDrive")!="C:"||IntPtr.Size!=8)throw new InvalidOperationException("Exact owned x64 guest required.");sid=WindowsIdentity.GetCurrent().User.Value;NativeRetainedFixture.SecuritySddl(sid,false);EnableSecurityPrivilege();
   foreach(RetainedFixtureState f in new[]{r.source,r.shadow}){Handles h=new Handles();handles.Add(f.role,h);h.root=OpenPath(f.root,true,false,false);h.volume=Add(CreateFile(f.volume.TrimEnd('\\'),Read,3,IntPtr.Zero,3,0,IntPtr.Zero));CheckVolume(f,h);
    Enumerate(h.root,f,"OpenRoot",!construct);
    if(!construct){h.folder=OpenPath(f.root+"retained",true,false,true);h.file=OpenPath(f.path,false,false,true);}
   }
   if(handles["A"].diskNumber==handles["B"].diskNumber)throw new InvalidDataException("Independent source/shadow physical disks required.");
  }
  SA Descriptor(bool directory,out IntPtr descriptor){uint length;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(NativeRetainedFixture.SecuritySddl(sid,directory),1,out descriptor,out length))Fail("Creation security descriptor failed.");return new SA{length=Marshal.SizeOf(typeof(SA)),descriptor=descriptor,inherit=0};}
  public void Create(RetainedFixtureState f) {
   if(!constructing||f.fileCreated)throw new InvalidOperationException("Create is construction-only and single-shot.");Handles h=handles[f.role];IntPtr folderSd=IntPtr.Zero,fileSd=IntPtr.Zero;
   try{SA folder=Descriptor(true,out folderSd),file=Descriptor(false,out fileSd);
    if(!CreateDirectory(f.root+"retained",ref folder))Fail("Create-new fixture directory failed.");f.directoryCreated=true;h.folder=OpenPath(f.root+"retained",true,true,true);
    SafeFileHandle created=Add(CreateSecureFile(f.path,Read|Write|Metadata|SecurityAccess|0x100U,0,ref file,1,OpenReparse|0x80000000,IntPtr.Zero));f.fileCreated=true;SuppressLastAccess(created,f.path,"created");CheckPath(created,f.path,false);
    if(f.role=="B"){byte[] none=new byte[8];Require(Q(created,"BSetIntegrityNone",0x0009c280,none,0,-1));}
    byte[] pattern=NativeRetainedFixture.Pattern(result.runId,f.role);uint n;if(!WriteFile(created,pattern,65536,out n,IntPtr.Zero))Fail("Initialize pattern failed.");f.payloadBytesWritten=n;if(n!=65536)throw new IOException("Partial initialized fixture write.");f.payloadInitialized=true;
    if(!FlushFileBuffers(created))Fail("Creation flush failed.");f.creationFlushed=true;CloseOne(created);f.creationClosed=true;f.initializationProof="complete-ordinary-WriteFile-FlushFileBuffers-close-requires-logical-and-raw-readback";
    h.file=OpenPath(f.path,false,true,true);SetMetadata(f);
   }finally{if(fileSd!=IntPtr.Zero)LocalFree(fileSd);if(folderSd!=IntPtr.Zero)LocalFree(folderSd);}
  }
  public void SetMetadata(RetainedFixtureState f) {
   if(!constructing)throw new InvalidOperationException("Metadata setters forbidden after construction.");Handles h=handles[f.role];
   foreach(bool directory in new[]{false,true}){byte[] b=new byte[40];for(int i=0;i<4;i++)BitConverter.GetBytes(NativeRetainedFixture.FixtureTime).CopyTo(b,i*8);BitConverter.GetBytes(directory?16U:32U).CopyTo(b,32);if(!SetFileInformationByHandle(directory?h.folder:h.file,0,b,40))Fail("Fixed basic metadata setter failed.");}
   if(!FlushFileBuffers(h.file))Fail("Initialized fixture metadata flush failed.");f.metadataSet=true;
  }
  public RetainedSnapshot Observe(RetainedFixtureState f,string name) {
   Handles h=handles[f.role];CheckVolume(f,h);CheckPath(h.file,f.path,false);CheckPath(h.folder,f.root+"retained",true);
   string stage=name.EndsWith("After")?"After":"Before";Enumerate(h.root,f,stage+"Root",true);Enumerate(h.folder,f,stage+"Folder",true);
   RetainedSnapshot s=new RetainedSnapshot{name=name};s.identity=NativeRetainedFixture.ParseIdentity(Info(h.file,name+"Id",18,24));s.standard=NativeRetainedFixture.ParseStandard(Info(h.file,name+"Standard",1,24),false);s.basic=NativeRetainedFixture.ParseBasic(Info(h.file,name+"Basic",0,40),false);
   s.streams=NativeRetainedFixture.ParseStreams(Info(h.file,name+"Streams",7,4096));s.security=Security(h.file,false,name+"Security");
   s.extents=NativeRetainedFixture.ParseExtents(Require(Q(h.file,name+"Extents",0x90073,new byte[8],272,-1)));s.baseSectors=NativeRetainedFixture.ParseBase(Require(Q(h.volume,name+"Base",0x90234,null,8,-1)));
   s.cached=NativeRetainedFixture.ParseValidRegions(Require(Q(h.file,name+"Cached",0x90284,NativeRetainedFixture.RegionInput(1),400,-1)),1);s.fullyCachedValid=true;
   if(f.filesystem=="ReFS"){s.storageRegionQueryAttempted=true;s.onDisk=NativeRetainedFixture.ParseValidRegions(Require(Q(h.file,name+"OnDisk",0x90284,NativeRetainedFixture.RegionInput(2),400,-1)),2);s.fullyStorageValid=true;s.storageValidityStatus="native-full-storage-validity";}
   else{s.storageValidityStatus="not-queried-NTFS-storage-validity-unknown";}
   if(f.role=="B"){byte[] b=Require(Q(h.file,name+"Integrity",0x9027c,null,16,-1));if(b.Length!=16||BitConverter.ToUInt16(b,2)!=0||BitConverter.ToUInt32(b,12)!=4096)throw new InvalidDataException("Integrity response shape/cluster mismatch.");s.integrityQueried=true;s.checksumAlgorithm=BitConverter.ToUInt16(b,0);s.integrityFlags=BitConverter.ToUInt32(b,4);}
   long position;if(!SetFilePointerEx(h.file,0,out position,0)||position!=0)Fail("Fixture seek failed.");byte[] payload=new byte[65536];uint n;if(!ReadFile(h.file,payload,65536,out n,IntPtr.Zero))Fail("Bounded logical read failed.");if(n!=65536)throw new IOException("Short logical fixture read.");s.sha256=NativeRetainedFixture.Hash(payload);
   RetainedIdentity after=NativeRetainedFixture.ParseIdentity(Info(h.file,name+"IdAfter",18,24));RetainedBasic basicAfter=NativeRetainedFixture.ParseBasic(Info(h.file,name+"BasicAfter",0,40),false);
   if(after.fileId128!=s.identity.fileId128||after.volumeSerial64!=s.identity.volumeSerial64||!NativeRetainedFixture.SameBasic(s.basic,basicAfter))throw new IOException("Identity/basic metadata changed while hashing.");
   f.directoryBasic=NativeRetainedFixture.ParseBasic(Info(h.folder,name+"DirectoryBasic",0,40),true);f.directorySecurity=Security(h.folder,true,name+"DirectorySecurity");return s;
  }
  public byte[] Bitmap(RetainedFixtureState f,bool metadata,string name){byte[] input=new byte[metadata?16:8];if(metadata)input[8]=1;return Require(Q(handles[f.role].volume,name,0x9006f,input,NativeRetainedFixture.BitmapCapacity,-1));}
  public bool Move(RetainedFixtureState f,long lcn){if(!constructing||!f.fileCreated||f.moveCallCount!=1||f.moveCompleted)throw new InvalidOperationException("Only one initialized construction move permitted.");return Q(handles[f.role].volume,f.role+"Move",0x90074,NativeRetainedFixture.MoveInput(handles[f.role].file.DangerousGetHandle().ToInt64(),lcn),0,-1).succeeded;}
  public void Seal() {
   if(!constructing)throw new InvalidOperationException("Construction handles already sealed.");
   foreach(RetainedFixtureState f in new[]{result.source,result.shadow}){Handles h=handles[f.role];CloseOne(h.file);CloseOne(h.folder);}
   constructing=false;
   foreach(RetainedFixtureState f in new[]{result.source,result.shadow}){Handles h=handles[f.role];h.folder=OpenPath(f.root+"retained",true,false,true);h.file=OpenPath(f.path,false,false,true);}
  }
  public void Close() {
   List<string> errors=new List<string>();for(int i=all.Count-1;i>=0;i--)try{CloseOne(all[i]);}catch(Exception e){errors.Add(e.Message);}
   if(token!=null&&!token.IsInvalid&&!token.IsClosed){if(privilegeChanged){try{TP ignored;uint returned;bool ok=AdjustTokenPrivileges(token,false,ref previousPrivilege,16,out ignored,out returned);int e=Marshal.GetLastWin32Error();if(!ok||e!=0)throw new Win32Exception(e,"Restore own-process privilege failed.");privilegeChanged=false;}catch(Exception e){errors.Add(e.Message);}}try{CloseOne(token);}catch(Exception e){errors.Add(e.Message);}}
   if(errors.Count!=0)throw new IOException(String.Join("; ",errors.ToArray()));
  }
 }
}
