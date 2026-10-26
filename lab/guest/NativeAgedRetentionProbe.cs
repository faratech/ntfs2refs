// Original bounded NTFS allocation-history fixture. No source extent movement,
// valid-data advancement, formatter, privilege adjustment or path-based delete.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace Ntfs2Refs {
 public sealed class AgedOperation {public string name,startedUtc,finishedUtc;public bool succeeded;public int error;public long requestedBytes,returnedBytes;}
 public sealed class AgedExtent {public long logicalOffset,physicalOffset,length;}
 public sealed class AgedFile {public string path,fileId,volumeSerial,retrievalHex,observedUtc;public long eofBytes,allocationBytes;public uint links;public bool deletePending;public AgedExtent[] extents;}
 public sealed class AgedSource {public string diskGuid,partitionGuid,volumePath,rootFileId,volumeSerial,layoutSha256;public long diskBytes,partitionOffset,partitionBytes,freeBytes;public ulong attributes;}
 public sealed class AgedResult {
  public string phase="new",reservationPath,probePath,generatedSha256,readbackSha256,error;
  public int seed;public long reservationPayloadBytesWritten,probeBytesWritten,reservationBytes=8589934592L,probeBytes=8388608L;
  public long freeAfterReservation=-1,freeAfterProbe=-1,freeAfterReservationDelete=-1;
  public bool reservationCreated,reservationAllocated,probeCreated,probeFlushed,probeComplete,placementSuitable,reservationDeleteAttempted,reservationDeleteReturned,reservationDeleted,closed;
  public int sourceMovesRequested,validDataSettersRequested;public AgedSource sourceBefore,sourceAfter;public AgedFile reservation,probe,probeAfterReservationDelete;
  public readonly List<AgedOperation> operations=new List<AgedOperation>();
 }
 public sealed class NativeAgedRetentionProbe {
  public const long ReservationBytes=8589934592L,ProbeBytes=8388608L,MinimumFreeHeadroom=1073741824L,PartitionBytes=55834574848L;
  const uint Read=0x80000000,Write=0x40000000,Delete=0x10000,OpenReparse=0x00200000,Backup=0x02000000,WriteThrough=0x80000000;
  readonly string volume;readonly int seed;IntPtr root,sourceVolume,disk,reservation,probe;string reservationId,probeId;bool closeAttempted;
  public readonly AgedResult Result=new AgedResult();
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool GetFileInformationByHandleEx(IntPtr handle,int infoClass,[Out]byte[] bytes,uint length);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool SetFileInformationByHandle(IntPtr handle,int infoClass,byte[] bytes,uint length);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool DeviceIoControl(IntPtr handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool FlushFileBuffers(IntPtr handle);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool WriteFile(IntPtr handle,byte[] bytes,uint length,out uint written,IntPtr overlapped);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool ReadFile(IntPtr handle,[Out]byte[] bytes,uint length,out uint read,IntPtr overlapped);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]static extern bool SetFilePointerEx(IntPtr handle,long distance,out long position,uint method);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern bool GetVolumeNameForVolumeMountPointW(string root,StringBuilder name,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern bool GetVolumeInformationByHandleW(IntPtr handle,StringBuilder label,uint labelCapacity,out uint serial,out uint component,out uint flags,StringBuilder fileSystem,uint fsCapacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern bool GetDiskFreeSpaceExW(string path,out ulong available,out ulong total,out ulong free);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern uint GetFileAttributesW(string path);
  static bool Valid(IntPtr h){return h!=IntPtr.Zero&&h!=new IntPtr(-1);}
  static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  static string FileId(byte[] b){byte[] id=new byte[16];Array.Copy(b,8,id,0,16);return Hex(id);}
  static Guid GuidAt(byte[] b,int at){byte[] g=new byte[16];Array.Copy(b,at,g,0,16);return new Guid(g);}
  public static void ValidateInputs(string id,string volumePath){Match m=Regex.Match(volumePath??"",@"\A\\\\\?\\Volume\{([0-9a-fA-F-]{36})\}\\\z");Guid parsed;if(!Regex.IsMatch(id??"",@"\A[0-9a-f]{32}\z")||!m.Success||!Guid.TryParse(m.Groups[1].Value,out parsed)||parsed==Guid.Empty)throw new ArgumentException("Fresh lowercase ID and exact nonempty volume-GUID root required.");}
  public static byte[] AllocationInput(){return BitConverter.GetBytes(ReservationBytes);}
  public static AgedFile ParseStandard(byte[] bytes){
   if(bytes==null||bytes.Length!=24)throw new InvalidDataException("Complete standard file information required.");
   long allocated=BitConverter.ToInt64(bytes,0),eof=BitConverter.ToInt64(bytes,8);uint links=BitConverter.ToUInt32(bytes,16);
   if(allocated<0||allocated>ReservationBytes||eof<0||eof>ProbeBytes||links!=1||bytes[21]!=0)throw new InvalidDataException("Ordinary bounded single-link file required.");
   return new AgedFile{allocationBytes=allocated,eofBytes=eof,links=links,deletePending=bytes[20]!=0};
  }
  public static AgedExtent[] ParseRetrieval(byte[] bytes,long allocated){
   if(allocated<ProbeBytes||allocated>16*1024*1024||allocated%4096!=0||bytes==null||bytes.Length<32||bytes.Length>16+16*1024||BitConverter.ToInt64(bytes,8)!=0)throw new InvalidDataException("Complete bounded initialized probe mapping required.");
   uint count=BitConverter.ToUInt32(bytes,0);if(count<1||count>1024||bytes.Length!=16+16L*count)throw new InvalidDataException("Partial retrieval response.");
   List<AgedExtent> result=new List<AgedExtent>();long next=0;
   for(int i=0;i<count;i++){long end=BitConverter.ToInt64(bytes,16+16*i),lcn=BitConverter.ToInt64(bytes,24+16*i);if(end<=next||end>allocated/4096||lcn<0||lcn>PartitionBytes/4096-(end-next))throw new InvalidDataException("Sparse, overflowing or out-of-volume retrieval run.");result.Add(new AgedExtent{logicalOffset=next*4096,physicalOffset=lcn*4096,length=(end-next)*4096});next=end;}
   if(next!=allocated/4096)throw new InvalidDataException("Retrieval pointers omit allocated probe clusters.");
   AgedExtent[] sorted=result.ToArray();Array.Sort(sorted,delegate(AgedExtent a,AgedExtent b){return a.physicalOffset.CompareTo(b.physicalOffset);});for(int i=1;i<sorted.Length;i++)if(sorted[i-1].physicalOffset+sorted[i-1].length>sorted[i].physicalOffset)throw new InvalidDataException("Probe allocations overlap.");return result.ToArray();
  }
  public static bool Suitable(AgedExtent[] extents){if(extents==null||extents.Length==0)return false;foreach(AgedExtent e in extents)if(e.physicalOffset<ReservationBytes)return false;return true;}
  public NativeAgedRetentionProbe(string id,string volumePath,int randomSeed){ValidateInputs(id,volumePath);volume=volumePath;seed=randomSeed;Result.seed=seed;Result.reservationPath=@"F:\.n2r-aged-reservation-"+id+".tmp";Result.probePath=@"F:\aged-retention-"+id+".bin";}
  AgedOperation Begin(string name,long requested){AgedOperation op=new AgedOperation{name=name,requestedBytes=requested,startedUtc=DateTime.UtcNow.ToString("o")};Result.operations.Add(op);return op;}
  void End(AgedOperation op,bool success,long returned){op.succeeded=success;op.returnedBytes=returned;op.error=success?0:Marshal.GetLastWin32Error();op.finishedUtc=DateTime.UtcNow.ToString("o");if(!success)throw new Win32Exception(op.error,op.name);}
  IntPtr Open(string path,uint access,uint share,uint creation,uint flags){AgedOperation op=Begin("CreateFile:"+path,0);IntPtr h=CreateFileW(path,access,share,IntPtr.Zero,creation,flags,IntPtr.Zero);End(op,Valid(h),0);return h;}
  void Close(ref IntPtr handle,string name){if(!Valid(handle))return;IntPtr h=handle;handle=IntPtr.Zero;AgedOperation op=Begin(name,0);End(op,CloseHandle(h),0);}
  byte[] Info(IntPtr h,int cls,int size){byte[] b=new byte[size];AgedOperation op=Begin("GetFileInformation:"+cls,0);End(op,GetFileInformationByHandleEx(h,cls,b,(uint)size),size);return b;}
  byte[] Control(IntPtr h,uint code,byte[] input,int capacity){if(code!=0x560000&&code!=0x90064&&code!=0x90073&&code!=0x7405c&&code!=0x70050&&code!=0x700f0&&code!=0x2d1400)throw new ArgumentException("Read-only control is not enrolled.");byte[] b=new byte[capacity];uint n;AgedOperation op=Begin("DeviceIoControl:"+code.ToString("x"),0);bool ok=DeviceIoControl(h,code,input,(uint)(input==null?0:input.Length),b,(uint)b.Length,out n,IntPtr.Zero);End(op,ok,n);if(n>capacity)throw new InvalidDataException("Oversized native response.");Array.Resize(ref b,(int)n);return b;}
  void CheckPath(IntPtr h,string path,bool directory){byte[] basic=Info(h,0,40);uint attrs=BitConverter.ToUInt32(basic,32);if((attrs&0x4e00)!=0||((attrs&16)!=0)!=directory)throw new InvalidDataException("Ordinary uncompressed/unencrypted path required.");StringBuilder final=new StringBuilder(512);uint n=GetFinalPathNameByHandleW(h,final,512,0);if(n==0||n>=512||!String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Resolved file handle path differs.");}
  AgedFile FileState(IntPtr h,string path,bool mapping){CheckPath(h,path,false);AgedFile f=ParseStandard(Info(h,1,24));byte[] id=Info(h,18,24);f.path=path;f.volumeSerial=BitConverter.ToUInt64(id,0).ToString("x16");f.fileId=FileId(id);f.observedUtc=DateTime.UtcNow.ToString("o");if(f.deletePending)throw new InvalidDataException("Unexpected pending file deletion.");if(mapping){byte[] raw=Control(h,0x90073,new byte[8],16+16*1024);f.retrievalHex=Hex(raw);f.extents=ParseRetrieval(raw,f.allocationBytes);}return f;}
  static void SameFile(AgedFile a,AgedFile b){if(a.fileId!=b.fileId||a.volumeSerial!=b.volumeSerial||a.eofBytes!=b.eofBytes||a.allocationBytes!=b.allocationBytes)throw new InvalidDataException("Owned file identity or lengths changed.");}
  static void SameSource(AgedSource a,AgedSource b){if(a.diskGuid!=b.diskGuid||a.partitionGuid!=b.partitionGuid||a.volumePath!=b.volumePath||a.rootFileId!=b.rootFileId||a.volumeSerial!=b.volumeSerial||a.layoutSha256!=b.layoutSha256||a.attributes!=b.attributes)throw new InvalidDataException("Owned source identity changed.");}
  AgedSource ObserveSource(){
   StringBuilder actual=new StringBuilder(64);if(!GetVolumeNameForVolumeMountPointW(@"F:\",actual,64)||!String.Equals(actual.ToString(),volume,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("F: volume identity changed.");
   StringBuilder label=new StringBuilder(64),fs=new StringBuilder(16);uint serial,component,flags;if(!GetVolumeInformationByHandleW(sourceVolume,label,64,out serial,out component,out flags,fs,16)||fs.ToString()!="NTFS")throw new InvalidDataException("Source is not mounted NTFS.");
   byte[] ext=Control(sourceVolume,0x560000,null,32);if(ext.Length!=32||BitConverter.ToUInt32(ext,0)!=1||BitConverter.ToUInt32(ext,8)!=1||BitConverter.ToInt64(ext,16)!=16777216L||BitConverter.ToInt64(ext,24)!=PartitionBytes)throw new InvalidDataException("Source physical extent changed.");
   byte[] ntfs=Control(sourceVolume,0x90064,null,256);if(ntfs.Length<96||BitConverter.ToUInt32(ntfs,40)!=512||BitConverter.ToUInt32(ntfs,44)!=4096||BitConverter.ToUInt32(ntfs,48)!=1024)throw new InvalidDataException("NTFS geometry differs.");
   byte[] attrs=Control(disk,0x700f0,null,16),length=Control(disk,0x7405c,null,8),input=new byte[12];input[0]=6;byte[] align=Control(disk,0x2d1400,input,28),layout=Control(disk,0x70050,null,65536);
   if(attrs.Length!=16||BitConverter.ToUInt64(attrs,8)!=0||length.Length!=8||BitConverter.ToInt64(length,0)!=68719476736L||align.Length!=28||BitConverter.ToUInt32(align,16)!=512||BitConverter.ToUInt32(align,20)!=4096||layout.Length<48||BitConverter.ToUInt32(layout,0)!=1||GuidAt(layout,8)!=new Guid("a01574d5-2a5c-4136-958a-dcf0d0e0f7aa"))throw new InvalidDataException("Enrolled online writable GPT source differs.");
   uint count=BitConverter.ToUInt32(layout,4);if(count<2||count>128||layout.Length!=48+144L*count)throw new InvalidDataException("Incomplete source GPT.");int data=0,msr=0;
   for(int i=0;i<count;i++){int p=48+144*i;long start=BitConverter.ToInt64(layout,p+8),bytes=BitConverter.ToInt64(layout,p+16);uint number=BitConverter.ToUInt32(layout,p+24);Guid type=GuidAt(layout,p+32);if(number==0&&bytes==0&&type==Guid.Empty)continue;if(BitConverter.ToUInt32(layout,p)!=1||BitConverter.ToUInt64(layout,p+64)!=0)throw new InvalidDataException("Unexpected GPT entry.");if(number==2&&GuidAt(layout,p+48)==new Guid("79eaccdf-38d3-4561-97cc-9276af5d223a")&&type==new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")&&start==16777216L&&bytes==PartitionBytes)data++;else if(number==1&&type==new Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae")&&start>=17408&&bytes>0&&start+bytes<=16777216L)msr++;else throw new InvalidDataException("Unexpected source partition.");}
   if(data!=1||msr!=1)throw new InvalidDataException("Exact data partition and MSR required.");CheckPath(root,@"F:\",true);byte[] rootId=Info(root,18,24);ulong available,total,free;if(!GetDiskFreeSpaceExW(@"F:\",out available,out total,out free)||available>Int64.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());
   using(SHA256 sha=SHA256.Create())return new AgedSource{diskGuid="a01574d5-2a5c-4136-958a-dcf0d0e0f7aa",partitionGuid="79eaccdf-38d3-4561-97cc-9276af5d223a",volumePath=volume,rootFileId=FileId(rootId),volumeSerial=BitConverter.ToUInt64(rootId,0).ToString("x16"),layoutSha256=Hex(sha.ComputeHash(layout)),diskBytes=68719476736L,partitionOffset=16777216L,partitionBytes=PartitionBytes,freeBytes=(long)available,attributes=0};
  }
  public void Reserve(){
   if(Result.phase!="new"||Environment.MachineName!="N2R-WIN11"||Environment.GetEnvironmentVariable("SystemDrive")!="C:"||IntPtr.Size!=8)throw new InvalidOperationException("Fresh owned x64 Windows guest fixture required.");Result.phase="source-bind";
   root=Open(@"F:\",0x20080,3,3,Backup|OpenReparse);sourceVolume=Open(@"\\.\F:",Read,3,3,0);disk=Open(@"\\.\PhysicalDrive1",Read,3,3,0);Result.sourceBefore=ObserveSource();
   if(Result.sourceBefore.freeBytes<ReservationBytes+ProbeBytes+MinimumFreeHeadroom)throw new IOException("Insufficient source space for the capped reservation and reserve.");
   Result.phase="create-exclusive-reservation";reservation=Open(Result.reservationPath,Read|Write|Delete,0,1,OpenReparse|WriteThrough);Result.reservationCreated=true;AgedFile empty=FileState(reservation,Result.reservationPath,false);Result.reservation=empty;if(empty.eofBytes!=0||empty.allocationBytes!=0||empty.volumeSerial!=Result.sourceBefore.volumeSerial)throw new InvalidDataException("Fresh empty reservation differs.");reservationId=empty.fileId;
   Result.phase="allocate-eight-gibibytes";AgedOperation op=Begin("FileAllocationInfo:reservation",ReservationBytes);End(op,SetFileInformationByHandle(reservation,5,AllocationInput(),8),0);Result.reservation=FileState(reservation,Result.reservationPath,false);if(Result.reservation.fileId!=reservationId||Result.reservation.eofBytes!=0||Result.reservation.allocationBytes!=ReservationBytes)throw new InvalidDataException("Reservation must remain EOF0 with exactly8GiB allocated.");Result.reservationAllocated=true;
   AgedSource after=ObserveSource();Result.freeAfterReservation=after.freeBytes;SameSource(Result.sourceBefore,after);if(after.freeBytes<ProbeBytes+MinimumFreeHeadroom)throw new IOException("Source reserve exhausted after allocation-only reservation.");Result.phase="reserved";
  }
  public void CreateProbe(){
   if(Result.phase!="reserved")throw new InvalidOperationException("Reservation must precede probe creation.");SameFile(Result.reservation,FileState(reservation,Result.reservationPath,false));SameSource(Result.sourceBefore,ObserveSource());
   Result.phase="write-probe";probe=Open(Result.probePath,Read|Write,0,1,OpenReparse|WriteThrough);Result.probeCreated=true;AgedFile empty=FileState(probe,Result.probePath,false);Result.probe=empty;probeId=empty.fileId;if(empty.eofBytes!=0||empty.allocationBytes!=0||empty.volumeSerial!=Result.sourceBefore.volumeSerial)throw new InvalidDataException("Fresh probe identity differs.");
   byte[] buffer=new byte[1048576];Random random=new Random(seed);using(SHA256 sha=SHA256.Create()){for(int i=0;i<8;i++){random.NextBytes(buffer);uint written;AgedOperation op=Begin("WriteFile:probe",buffer.Length);bool ok=WriteFile(probe,buffer,(uint)buffer.Length,out written,IntPtr.Zero);Result.probeBytesWritten+=written;End(op,ok,written);if(written!=buffer.Length)throw new IOException("Short initialized probe write.");sha.TransformBlock(buffer,0,buffer.Length,null,0);}sha.TransformFinalBlock(new byte[0],0,0);Result.generatedSha256=Hex(sha.Hash);}
   AgedOperation flush=Begin("FlushFileBuffers:probe",0);End(flush,FlushFileBuffers(probe),0);Result.probeFlushed=true;Close(ref probe,"CloseInitializedProbe");probe=Open(Result.probePath,Read,0,3,OpenReparse);
   Result.probe=FileState(probe,Result.probePath,true);if(Result.probe.fileId!=probeId||Result.probe.volumeSerial!=Result.sourceBefore.volumeSerial||Result.probe.eofBytes!=ProbeBytes)throw new InvalidDataException("Reopened initialized probe differs.");
   long position;if(!SetFilePointerEx(probe,0,out position,0)||position!=0)throw new Win32Exception(Marshal.GetLastWin32Error());using(SHA256 sha=SHA256.Create()){for(int i=0;i<8;i++){uint read;AgedOperation op=Begin("ReadFile:probe",buffer.Length);End(op,ReadFile(probe,buffer,(uint)buffer.Length,out read,IntPtr.Zero),read);if(read!=buffer.Length)throw new IOException("Short initialized probe read.");sha.TransformBlock(buffer,0,buffer.Length,null,0);}uint extra;End(Begin("ReadFile:probe-eof",1),ReadFile(probe,buffer,1,out extra,IntPtr.Zero),extra);if(extra!=0)throw new IOException("Probe grew beyond expected EOF.");sha.TransformFinalBlock(new byte[0],0,0);Result.readbackSha256=Hex(sha.Hash);}
   if(Result.readbackSha256!=Result.generatedSha256)throw new InvalidDataException("Probe readback digest differs.");SameFile(Result.probe,FileState(probe,Result.probePath,false));SameFile(Result.reservation,FileState(reservation,Result.reservationPath,false));Result.sourceAfter=ObserveSource();Result.freeAfterProbe=Result.sourceAfter.freeBytes;SameSource(Result.sourceBefore,Result.sourceAfter);if(Result.sourceAfter.freeBytes<MinimumFreeHeadroom)throw new IOException("Source headroom exhausted.");Result.probeComplete=true;Result.placementSuitable=Suitable(Result.probe.extents);Result.phase="probe-measured";
  }
  public void DeleteOwnedReservation(){
   if(Result.phase!="probe-measured"||!Result.probeComplete||!Valid(reservation))throw new InvalidOperationException("Complete probe and original exclusive reservation handle required.");SameSource(Result.sourceBefore,ObserveSource());SameFile(Result.reservation,FileState(reservation,Result.reservationPath,false));SameFile(Result.probe,FileState(probe,Result.probePath,false));
   Result.phase="delete-owned-reservation";Result.reservationDeleteAttempted=true;byte[] disposition=new byte[4];disposition[0]=1;AgedOperation op=Begin("FileDispositionInfo:original-reservation-handle",0);End(op,SetFileInformationByHandle(reservation,4,disposition,4),0);Result.reservationDeleteReturned=true;Close(ref reservation,"CloseDeletedReservation");
   uint attrs=GetFileAttributesW(Result.reservationPath);if(attrs!=UInt32.MaxValue||Marshal.GetLastWin32Error()!=2)throw new IOException("Reservation absence is unproven after handle deletion.");Result.reservationDeleted=true;Result.probeAfterReservationDelete=FileState(probe,Result.probePath,true);SameFile(Result.probe,Result.probeAfterReservationDelete);if(Result.probe.retrievalHex!=Result.probeAfterReservationDelete.retrievalHex)throw new InvalidDataException("Probe mapping changed across reservation cleanup.");Result.sourceAfter=ObserveSource();Result.freeAfterReservationDelete=Result.sourceAfter.freeBytes;SameSource(Result.sourceBefore,Result.sourceAfter);Result.phase="complete";
  }
  public void ClosePreserving(){if(closeAttempted)throw new InvalidOperationException("Handle cleanup is single-attempt.");closeAttempted=true;try{Close(ref probe,"CloseProbePreserving");Close(ref reservation,"CloseReservationPreserving");Close(ref root,"CloseSourceRoot");Close(ref sourceVolume,"CloseSourceVolume");Close(ref disk,"CloseSourceDisk");Result.closed=true;}catch(Exception e){Result.error=e.ToString();throw;}}
 }
}
