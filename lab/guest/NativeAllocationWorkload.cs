// Disposable, post-handoff qualification. All payload writes use ordinary files.
// Disk handles expose identity queries and attribute transitions only.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class AllocationFileProof {
  public string path,sha256,fileId128;public long length;public RetainedExtent[] extents;
 }
 public sealed class AllocationBitmapProof {
  public string stage,sha256;public long startingLcn,clusters,checkedClusters;public int returnedBytes,meaningfulBytes;public byte[] bytes;
  public List<AllocationFileProof> files=new List<AllocationFileProof>();
 }
 public sealed class AllocationWorkloadResult {
  public string phase="preflight",status="blocked",error,cleanupError,workloadId;
  public bool complete,cleanupComplete,operationActive,rawPayloadWriteRequestsIssued,conversionQualified,bootQualified;
  public long fileWriteBytesRequested,fileBytesWritten;public int filesCreated,renames,truncations,deletions;
  public ConvertedVerificationResult before,after;public List<MountCall> transitions;
  public List<AllocationBitmapProof> allocation=new List<AllocationBitmapProof>();
  public List<string> retainedHashes=new List<string>();public List<int> volumeOpenReadinessErrors=new List<int>(),readOnlyOpenReadinessErrors=new List<int>();public int nativeError;
 }
 public sealed class AllocationProtectionBoundary {
  readonly IMountBoundaryApi api;readonly ConvertedExpected expected;IntPtr disk;
  public readonly List<MountCall> Calls=new List<MountCall>();
  public string Stage="new";public bool OperationActive,CleanupComplete;bool closeAttempted,releaseFailed;
  public AllocationProtectionBoundary(IMountBoundaryApi a,ConvertedExpected e){if(a==null)throw new ArgumentNullException("api");NativeConvertedVerification.ValidateExpected(e);api=a;expected=e;}
  byte[] Control(string name,uint code,byte[] input,int capacity,int expectedError){
   if(OperationActive||closeAttempted)throw new InvalidOperationException("Uncertain or closed boundary.");
   MountCall c=new MountCall{name=name,code=code,inputHex=NativeRetainedFixture.Hex(input??new byte[0]),capacity=capacity,startedUtc=DateTime.UtcNow.ToString("o")};Calls.Add(c);OperationActive=true;
   byte[] bytes;uint error=api.Control(disk,code,input,capacity,out bytes);c.error=error;c.succeeded=error==0;c.finishedUtc=DateTime.UtcNow.ToString("o");OperationActive=false;
   if(bytes==null||bytes.Length>capacity)throw new InvalidDataException("Bounded native response required.");c.returned=bytes.Length;c.outputHex=NativeRetainedFixture.Hex(bytes);
   if(error!=expectedError)throw new Win32Exception((int)error,name+" returned an unexpected status.");return bytes;
  }
  public static byte[] AttributeInput(ulong attributes){if(attributes>3)throw new ArgumentException("Bounded disk attributes required.");byte[] b=new byte[40];BitConverter.GetBytes(40U).CopyTo(b,0);b[4]=1;BitConverter.GetBytes(attributes).CopyTo(b,8);BitConverter.GetBytes(3UL).CopyTo(b,16);return b;}
  void Proof(ulong attrs){
   byte[] b=Control("DeviceNumber",NativeMountBoundary.DeviceCode,null,12,0);if(b.Length!=12||BitConverter.ToUInt32(b,0)!=7||BitConverter.ToUInt32(b,4)!=1||BitConverter.ToUInt32(b,8)!=0)throw new InvalidDataException("Original disk1 required.");
   b=Control("Length",NativeMountBoundary.LengthCode,null,8,0);if(b.Length!=8||BitConverter.ToInt64(b,0)!=NativeConvertedVerification.DiskBytes)throw new InvalidDataException("Original disk length differs.");
   byte[] input=new byte[12];input[0]=6;b=Control("Alignment",NativeMountBoundary.AlignmentCode,input,28,0);if(b.Length!=28||BitConverter.ToUInt32(b,0)!=28||BitConverter.ToUInt32(b,4)!=28||BitConverter.ToUInt32(b,16)!=512||BitConverter.ToUInt32(b,20)!=4096||BitConverter.ToUInt32(b,24)!=0)throw new InvalidDataException("Original storage alignment differs.");
   NativeConvertedVerification.ValidateLayout(Control("Layout",NativeMountBoundary.LayoutCode,null,65536,0),expected);
   b=Control("Attributes",NativeMountBoundary.GetAttributesCode,null,16,0);if(b.Length!=16||BitConverter.ToUInt32(b,0)!=16||BitConverter.ToUInt32(b,4)!=0||BitConverter.ToUInt64(b,8)!=attrs)throw new InvalidDataException("Unexpected native disk protection state.");
   if(Control("Writable",NativeMountBoundary.WritableCode,null,0,(attrs&2)!=0?19:0).Length!=0)throw new InvalidDataException("Unexpected writable-query payload.");
  }
  void Set(ulong from,ulong to){Proof(from);Control("SetAttributes-"+from+"-"+to,NativeMountBoundary.SetAttributesCode,AttributeInput(to),0,0);Proof(to);}
  void OpenDisk(){OperationActive=true;uint error=api.OpenDisk(1,true,out disk);OperationActive=false;if(error!=0||disk==IntPtr.Zero||disk==new IntPtr(-1))throw new Win32Exception((int)error,"Original target handle open failed.");}
  void ReleaseDisk(){if(disk==IntPtr.Zero||disk==new IntPtr(-1))return;OperationActive=true;uint error=api.Close(disk);disk=IntPtr.Zero;OperationActive=false;if(error!=0){releaseFailed=true;throw new Win32Exception((int)error,"Single-attempt transition handle close failed.");}}
  public void MakeWritable(){if(Stage!="new")throw new InvalidOperationException("Writable transition is single-use.");Stage="opening";OpenDisk();Stage="offline-readonly";Set(2,3);Stage="offline-writable";Set(3,1);Stage="online-writable";Set(1,0);ReleaseDisk();Stage="writable";}
  public void MakeReadOnly(){if(Stage!="writable")throw new InvalidOperationException("Known writable state required.");Stage="reopening-writable";OpenDisk();Stage="offline-writable";Set(0,1);Stage="offline-readonly";Set(1,3);Stage="online-readonly";Set(3,2);ReleaseDisk();Stage="readonly";}
  public void Close(){if(closeAttempted)throw new InvalidOperationException("Boundary close is single-use.");if(OperationActive)throw new InvalidOperationException("Unknown boundary call; preserve handle.");closeAttempted=true;if(releaseFailed)throw new IOException("Prior handle release failed; cleanup cannot be certified.");if(disk!=IntPtr.Zero&&disk!=new IntPtr(-1)){uint e=api.Close(disk);disk=IntPtr.Zero;if(e!=0)throw new Win32Exception((int)e,"Disk handle close failed.");}CleanupComplete=true;}
 }
 public sealed class NativeAllocationWorkload {
  const int Unit=1048576,Count=32;const long WriteCap=64L*1048576;
  readonly ConvertedExpected expected;readonly string id;readonly AllocationWorkloadResult result;
  readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();AllocationProtectionBoundary boundary;SafeFileHandle volume;
  string root;readonly List<string> owned=new List<string>();bool directoryOwned;
  public NativeAllocationWorkload(ConvertedExpected e,string workloadId){NativeConvertedVerification.ValidateExpected(e);if(!Regex.IsMatch(workloadId??"",@"\A[0-9a-f]{32}\z"))throw new ArgumentException("Fresh workload identifier required.");expected=e;id=workloadId;result=new AllocationWorkloadResult{workloadId=id};}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inputBytes,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int cls,[Out]byte[] bytes,uint capacity);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFileTime(SafeFileHandle h,IntPtr creation,ref long access,IntPtr write);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint count,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool GetVolumeInformationByHandleW(SafeFileHandle h,StringBuilder label,uint count,out uint serial,out uint component,out uint flags,StringBuilder fs,uint fsCount);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool CreateDirectoryW(string path,IntPtr security);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool MoveFileW(string oldPath,string newPath);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool DeleteFileW(string path);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]static extern bool RemoveDirectoryW(string path);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
  static void Fail(string s){throw new Win32Exception(Marshal.GetLastWin32Error(),s);}
  SafeFileHandle Open(string p,uint access,bool directory,bool create){SafeFileHandle h=CreateFileW(p,access,3,IntPtr.Zero,create?1U:3U,0x00200000U|(directory?0x02000000U:0U),IntPtr.Zero);if(h==null||h.IsInvalid){int e=Marshal.GetLastWin32Error();if(h!=null)h.Dispose();throw new Win32Exception(e,"Bounded file open failed.");}handles.Add(h);return h;}
  void Close(SafeFileHandle h){if(h==null||h.IsClosed||h.IsInvalid)return;bool ok=CloseHandle(h.DangerousGetHandle());int e=ok?0:Marshal.GetLastWin32Error();h.SetHandleAsInvalid();if(!ok)throw new Win32Exception(e,"Single-attempt handle close failed.");}
  byte[] Info(SafeFileHandle h,int cls,int size){byte[] b=new byte[size];if(!GetFileInformationByHandleEx(h,cls,b,(uint)size))Fail("File metadata query failed.");return b;}
  byte[] Control(SafeFileHandle h,uint code,byte[] input,int size){if(size<0||size>2*Unit)throw new ArgumentException("Bounded query required.");byte[] b=new byte[size];uint n;if(!DeviceIoControl(h,code,input,(uint)(input==null?0:input.Length),b,(uint)size,out n,IntPtr.Zero))Fail("Required filesystem query failed: "+code);if(n>size)throw new IOException("Oversized query response.");byte[] used=new byte[n];Array.Copy(b,used,n);return used;}
  void Path(SafeFileHandle h,string p,bool directory){StringBuilder b=new StringBuilder(512);uint n=GetFinalPathNameByHandleW(h,b,512,1);if(n==0)Fail("Final path query failed.");if(n>=512||!String.Equals(b.ToString(),p,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("File handle escaped its exact volume path.");uint attrs=BitConverter.ToUInt32(Info(h,0,40),32);if((attrs&(0x400U|0x800U|0x200U|0x4000U))!=0||((attrs&16)!=0)!=directory)throw new InvalidDataException("Unsupported path encoding or reparse point.");}
  SafeFileHandle AwaitVolumeOpen(bool readOnly){
   // Read-only opens can lag a completed disk online transition. Do not repeat
   // any attribute change, mount, or write while awaiting volume discovery.
   for(int attempt=0;attempt<31;attempt++){try{return Open(expected.volumeGuid.TrimEnd('\\'),0x80000000,false,false);}catch(Win32Exception e){(readOnly?result.readOnlyOpenReadinessErrors:result.volumeOpenReadinessErrors).Add(e.NativeErrorCode);if(attempt==30||(e.NativeErrorCode!=2&&e.NativeErrorCode!=3&&e.NativeErrorCode!=21))throw;System.Threading.Thread.Sleep(1000);}}throw new IOException("Volume discovery budget exhausted.");
  }
  void OpenVolume(){
   volume=AwaitVolumeOpen(false);
   byte[] b=Control(volume,0x560000,null,32);if(b.Length!=32||BitConverter.ToUInt32(b,0)!=1||BitConverter.ToUInt32(b,8)!=1||BitConverter.ToInt64(b,16)!=NativeConvertedVerification.PartitionOffset||BitConverter.ToInt64(b,24)!=NativeConvertedVerification.PartitionBytes)throw new InvalidDataException("Original single target volume extent required.");
   StringBuilder label=new StringBuilder(80),fs=new StringBuilder(40);uint serial,component,flags;if(!GetVolumeInformationByHandleW(volume,label,80,out serial,out component,out flags,fs,40))Fail("Writable volume identity query failed.");if(label.ToString()!="n2r-retained-shadow"||fs.ToString()!="ReFS"||serial!=expected.volumeSerial32||flags!=expected.volumeFlags)throw new InvalidDataException("Writable native ReFS identity/flags differ.");
   b=Control(volume,0x90234,null,8);if(b.Length!=8||BitConverter.ToInt64(b,0)!=0)throw new InvalidDataException("Only zero retrieval-pointer base supported.");
  }
  public static RetainedExtent[] Extents(byte[] bytes,long length){
   if(bytes==null||bytes.Length<32||length<1||length>2L*Unit)throw new InvalidDataException("Bounded allocated file required.");uint count=BitConverter.ToUInt32(bytes,0);long vcn=BitConverter.ToInt64(bytes,8);if(count<1||count>1024||bytes.Length!=16+16L*count||vcn!=0)throw new InvalidDataException("Complete bounded retrieval pointers required.");List<RetainedExtent> rows=new List<RetainedExtent>();long clusters=(length+4095)/4096;
   for(int i=0;i<count;i++){long next=BitConverter.ToInt64(bytes,16+i*16),lcn=BitConverter.ToInt64(bytes,24+i*16);if(next<=vcn||next>clusters||lcn<0||lcn>13631488-(next-vcn))throw new InvalidDataException("Invalid initialized physical extent.");foreach(RetainedExtent old in rows)if(lcn<old.lcn+old.nextVcn-old.vcn&&old.lcn<lcn+next-vcn)throw new InvalidDataException("Self-overlapping physical extents.");rows.Add(new RetainedExtent{vcn=vcn,nextVcn=next,lcn=lcn});vcn=next;}
   if(vcn!=clusters)throw new InvalidDataException("File extent coverage differs.");return rows.ToArray();
  }
  public static void CheckAllocated(byte[] b,RetainedExtent[] runs,long retainedLcn,bool retained){
   if(b==null||b.Length<17||runs==null||runs.Length==0)throw new InvalidDataException("Complete allocation evidence required.");long start=BitConverter.ToInt64(b,0),count=BitConverter.ToInt64(b,8);if(start!=0||count!=13631488||b.Length<16+(count+7)/8||b.Length>2*Unit)throw new InvalidDataException("Exact full-volume allocation bitmap required.");
   // refs.sys may return the whole supplied buffer, including padding bits.
   // BitmapSize alone defines the valid cluster domain; preserve the raw tail
   // as evidence, but never interpret it as additional physical ownership.
   foreach(RetainedExtent run in runs){long n=run.nextVcn-run.vcn;if(n<=0||run.lcn<0||run.lcn>count-n)throw new InvalidDataException("Extent outside bitmap.");if(!retained&&run.lcn<retainedLcn+16&&retainedLcn<run.lcn+n)throw new InvalidDataException("New allocation overlaps retained payload.");for(long i=run.lcn;i<run.lcn+n;i++)if((b[16+i/8]&(1<<(int)(i%8)))==0)throw new InvalidDataException("Live extent is marked free.");}
  }
  static byte[] Pattern(int index,int version,int length){byte[] bytes=new byte[length];uint state=(uint)(0x9e3779b9U^(uint)(index+1)*0x85ebca6bU^(uint)(version+1)*0xc2b2ae35U);for(int i=0;i<bytes.Length;i++){state^=state<<13;state^=state>>17;state^=state<<5;bytes[i]=(byte)state;}return bytes;}
  string Name(int index){return root+"\\file-"+index.ToString("D2")+".bin";}
  void Write(string p,byte[] bytes,bool create,bool append){
   if(!p.StartsWith(root+"\\",StringComparison.Ordinal)||bytes.Length<1||bytes.Length>2*Unit||result.fileWriteBytesRequested>WriteCap-bytes.Length)throw new InvalidOperationException("Owned-file write bound exceeded.");
   SafeFileHandle h=Open(p,0xc0000080,false,create);if(create){owned.Add(p);result.filesCreated++;}Path(h,p,false);using(FileStream s=new FileStream(h,FileAccess.ReadWrite,65536,false)){if(append)s.Position=s.Length;result.fileWriteBytesRequested+=bytes.Length;result.operationActive=true;s.Write(bytes,0,bytes.Length);result.fileBytesWritten+=bytes.Length;s.Flush(true);result.operationActive=false;} // FileStream owns h after validation.
  }
  AllocationFileProof FileProof(string p,byte[] expectedBytes){
   SafeFileHandle h=Open(p,0x80000180,false,false);Path(h,p,false);long suppress=-1;if(!SetFileTime(h,IntPtr.Zero,ref suppress,IntPtr.Zero))Fail("Per-handle access-time suppression failed.");
   byte[] sb=Info(h,1,24);long eof=BitConverter.ToInt64(sb,8),allocation=BitConverter.ToInt64(sb,0);if(eof!=expectedBytes.Length||allocation!=((eof+4095)/4096)*4096||BitConverter.ToUInt32(sb,16)!=1||sb[20]!=0||sb[21]!=0)throw new InvalidDataException("File lengths/link identity differ.");
   RetainedIdentity identity=NativeRetainedFixture.ParseIdentity(Info(h,18,24));if(identity.volumeSerial64!=expected.volumeSerial64)throw new InvalidDataException("File belongs to another filesystem.");RetainedExtent[] extents=Extents(Control(h,0x90073,new byte[8],16400),expectedBytes.Length);string hash;
   using(FileStream s=new FileStream(h,FileAccess.Read,65536,false)){using(System.Security.Cryptography.SHA256 sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(s)).Replace("-","").ToLowerInvariant();}
   if(hash!=NativeRetainedFixture.Hash(expectedBytes))throw new InvalidDataException("Logical file hash differs.");return new AllocationFileProof{path=p,length=expectedBytes.Length,sha256=hash,fileId128=identity.fileId128,extents=extents};
  }
  AllocationFileProof Retained(){AllocationFileProof f=FileProof(expected.volumeGuid+@"retained\payload.bin",NativeRetainedFixture.Pattern(expected.runId,"A"));if(f.fileId128!=expected.fileId128||f.extents.Length!=1||f.extents[0].lcn!=expected.retainedOffset/4096||f.extents[0].nextVcn!=16)throw new InvalidDataException("Retained identity or physical mapping changed.");result.retainedHashes.Add(f.sha256);return f;}
  void Snapshot(string stage,Dictionary<string,byte[]> files){
   AllocationBitmapProof proof=new AllocationBitmapProof{stage=stage};foreach(KeyValuePair<string,byte[]> f in files)proof.files.Add(FileProof(f.Key,f.Value));AllocationFileProof retained=Retained();proof.files.Add(retained);
   proof.bytes=Control(volume,0x9006f,new byte[8],2*Unit);proof.sha256=NativeRetainedFixture.Hash(proof.bytes);result.allocation.Add(proof);proof.startingLcn=BitConverter.ToInt64(proof.bytes,0);proof.clusters=BitConverter.ToInt64(proof.bytes,8);proof.returnedBytes=proof.bytes.Length;proof.meaningfulBytes=16+(int)((proof.clusters+7)/8);
   List<RetainedExtent> exclusive=new List<RetainedExtent>();foreach(AllocationFileProof file in proof.files){CheckAllocated(proof.bytes,file.extents,expected.retainedOffset/4096,file==retained);foreach(RetainedExtent run in file.extents){foreach(RetainedExtent old in exclusive)if(run.lcn<old.lcn+old.nextVcn-old.vcn&&old.lcn<run.lcn+run.nextVcn-run.vcn)throw new InvalidDataException("Unrelated test files share a physical allocation.");exclusive.Add(run);proof.checkedClusters+=run.nextVcn-run.vcn;}}
  }
  void DeleteOwned(string path){int index=owned.IndexOf(path);if(index<0)throw new InvalidOperationException("Only successfully created files may be deleted.");result.operationActive=true;if(!DeleteFileW(path))Fail("Owned test file deletion failed.");result.operationActive=false;owned.RemoveAt(index);result.deletions++;}
  static void ObserveComplete(ConvertedVerificationResult r){if(r==null||!r.complete||!r.stable||!r.cleanupComplete||!r.privilegeRestored||r.error!=null||r.cleanupError!=null||r.payloadReadRequests!=2||r.payloadBytesRead!=131072)throw new InvalidDataException("Protected native semantic verification failed.");}
  public AllocationWorkloadResult Run(){
   try{
    if(Environment.MachineName!="N2R-WIN11"||Environment.GetEnvironmentVariable("SystemDrive")!="C:"||!Environment.Is64BitProcess)throw new InvalidOperationException("Exact isolated lab guest required.");
    result.phase="observe-readonly-before";result.before=NativeConvertedVerification.Observe(expected);ObserveComplete(result.before);
    boundary=new AllocationProtectionBoundary(new WindowsMountBoundaryApi(),expected);result.transitions=boundary.Calls;result.phase="make-writable";boundary.MakeWritable();
    result.phase="open-original-volume";OpenVolume();root=expected.volumeGuid+"allocation-"+id;result.operationActive=true;if(!CreateDirectoryW(root,IntPtr.Zero))Fail("New owned workload directory creation failed.");directoryOwned=true;result.operationActive=false;
    SafeFileHandle directory=Open(root,0x80,true,false);Path(directory,root,true);Close(directory);Dictionary<string,byte[]> files=new Dictionary<string,byte[]>();
    result.phase="create-32-files";for(int i=0;i<Count;i++){byte[] b=Pattern(i,0,Unit);string p=Name(i);Write(p,b,true,false);files.Add(p,b);}Snapshot("created",files);
    result.phase="grow-truncate-rename";for(int i=0;i<Count;i++){
     string p=Name(i);byte[] b=Pattern(i,1,65536);Write(p,b,false,true);byte[] grown=new byte[Unit+65536];Array.Copy(files[p],grown,Unit);Array.Copy(b,0,grown,Unit,b.Length);FileProof(p,grown);
     SafeFileHandle h=Open(p,0xc0000080,false,false);Path(h,p,false);using(FileStream s=new FileStream(h,FileAccess.ReadWrite,65536,false)){result.operationActive=true;s.SetLength(Unit/2);s.Flush(true);result.operationActive=false;}result.truncations++;byte[] truncated=new byte[Unit/2];Array.Copy(files[p],truncated,truncated.Length);files[p]=truncated;
     if(i%2==1){string renamed=root+"\\renamed-"+i.ToString("D2")+".bin";result.operationActive=true;if(!MoveFileW(p,renamed))Fail("Owned rename failed.");result.operationActive=false;owned.Remove(p);owned.Add(renamed);files.Remove(p);files.Add(renamed,truncated);result.renames++;}
    }Snapshot("mutated",files);
    result.phase="delete-and-reallocate";for(int i=0;i<Count;i+=2){string p=Name(i);DeleteOwned(p);files.Remove(p);}for(int i=0;i<8;i++){string p=root+"\\replacement-"+i.ToString("D2")+".bin";byte[] b=Pattern(i,2,2*Unit);Write(p,b,true,false);files.Add(p,b);}Snapshot("reallocated",files);
    result.phase="remove-owned-workload";foreach(string p in new List<string>(owned))DeleteOwned(p);files.Clear();Snapshot("cleaned",files);result.operationActive=true;if(!RemoveDirectoryW(root))Fail("Owned empty directory deletion failed.");directoryOwned=false;result.operationActive=false;Close(volume);
    result.phase="restore-readonly";boundary.MakeReadOnly();boundary.Close();Close(AwaitVolumeOpen(true));result.phase="observe-readonly-after";result.after=NativeConvertedVerification.Observe(expected);ObserveComplete(result.after);
    // Original metadata and security bytes must survive normal writable ReFS use.
    if(result.before.snapshots[0].directoryIdentity.fileId128!=result.after.snapshots[0].directoryIdentity.fileId128)throw new InvalidDataException("Retained directory identity changed.");
    result.complete=true;result.status="native-allocation-workload-passed";result.phase="complete";
   }catch(Exception e){result.error=e.ToString();Win32Exception w=e as Win32Exception;if(w!=null)result.nativeError=w.NativeErrorCode;}
   finally{
    // Close our handles; never retry protection, deletion, or a failed operation.
    try{if(!result.operationActive){foreach(SafeFileHandle h in handles)Close(h);if(boundary!=null&&!boundary.CleanupComplete&&!boundary.OperationActive)boundary.Close();result.cleanupComplete=true;}}catch(Exception e){result.cleanupError=e.ToString();result.complete=false;}
    if(boundary!=null&&boundary.OperationActive)result.operationActive=true;
    if(!result.complete&&directoryOwned)result.status="failed-owned-workload-preserved";
   }
   return result;
  }
 }
}
