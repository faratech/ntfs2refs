// Bounded read evidence. The target handle requests GENERIC_READ only.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class RangeQuery {
  public string name,inputHex,nativeMessage,startedUtc,finishedUtc; public uint controlCode,bytesReturned;
  public int inputBytes,outputCapacityBytes,nativeError; public bool succeeded; public byte[] bytes;
 }
 public sealed class RangeBytes {
  public string name,startedUtc,finishedUtc; public long offset,actualSeekOffset; public int requestedBytes,bytesReturned,seekError,readError;
  public bool seekAttempted,seekSucceeded,readAttempted,readSucceeded; public byte[] bytes;
 }
 public sealed class RangeResult {
  public string status="blocked",phase="preflight",error; public bool opened,lockAttempted,lockSucceeded,unlockAttempted,unlockSucceeded,handleCloseAttempted,handleCloseSucceeded,nativeOperationReturned;
  public int openError,closeError,rangeReadCalls; public bool rawReadMayHaveBeenIssued; public long? baseSectors; public bool? oldSourceFreeInBoth,destinationAllocatedInBoth;
  public bool[] sourceBitsLegacy,sourceBitsMetadata,destinationBitsLegacy,destinationBitsMetadata;
  public List<RangeQuery> queries=new List<RangeQuery>(); public List<RangeBytes> reads=new List<RangeBytes>();
 }
 // Tests inject an API that never opens a device.
 public interface IRangeReadApi {
  RangeQuery Control(string name,uint code,byte[] input,int capacity);
  RangeBytes Read(string name,long offset,int bytes,int alignment);
  bool Close(out int error);
 }
 public static class NativeRangeRead {
  public const long VolumeBytes=55834574848L,PartitionOffset=16777216L,ClusterCount=13631488L,OldLcn=1508352L,NewLcn=1508384L;
  public const int RangeBytesCount=65536,MaximumBitmapBytes=2097152;
  public const uint BaseCode=0x00090234,BitmapCode=0x0009006f,ExtentsCode=0x00560000,LockCode=0x00090018,UnlockCode=0x0009001c;
  public const string ExpectedVolume=@"\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\";
  public static string ValidateProfile(string volumeName,int diskNumber,int logical,int physical) {
   if(!String.Equals(volumeName,ExpectedVolume,StringComparison.OrdinalIgnoreCase)||diskNumber<0||diskNumber>255||logical!=512||physical!=4096)throw new ArgumentException("Exact enrolled volume and 512/4096 geometry required.");
   return volumeName.Substring(0,volumeName.Length-1);
  }
  public static long ParseBase(byte[] bytes) {
   if(bytes==null||bytes.Length!=8)throw new InvalidDataException("Base must contain one 64-bit sector count.");
   long value=BitConverter.ToInt64(bytes,0);if(value<0||value>=VolumeBytes/512)throw new InvalidDataException("Base outside partition.");return value;
  }
  public static long Offset(long baseSectors,long lcn) {
   if(baseSectors<0||(lcn!=OldLcn&&lcn!=NewLcn))throw new ArgumentOutOfRangeException("Only the two recorded ranges are allowed.");
   checked{long value=baseSectors*512+lcn*4096;if(value<0||value%4096!=0||value>VolumeBytes-RangeBytesCount)throw new InvalidDataException("Range unaligned or outside partition.");return value;}
  }
  public static void ValidateExtents(byte[] bytes,int diskNumber) {
   if(bytes==null||bytes.Length!=32||diskNumber<0||diskNumber>255||BitConverter.ToUInt32(bytes,0)!=1||BitConverter.ToUInt32(bytes,8)!=(uint)diskNumber||BitConverter.ToInt64(bytes,16)!=PartitionOffset||BitConverter.ToInt64(bytes,24)!=VolumeBytes)throw new InvalidDataException("Handle differs from enrolled disk/partition extent.");
  }
  public static bool[] BitmapBits(byte[] bytes,long lcn) {
   if(bytes==null||bytes.Length<16+(ClusterCount+7)/8||bytes.Length>MaximumBitmapBytes||BitConverter.ToInt64(bytes,0)!=0||BitConverter.ToInt64(bytes,8)!=ClusterCount||(lcn!=OldLcn&&lcn!=NewLcn))throw new InvalidDataException("Complete measured bitmap domain required.");
   bool[] bits=new bool[16];for(int i=0;i<16;i++){long bit=lcn+i;bits[i]=(bytes[16+(int)(bit/8)]&(1<<(int)(bit%8)))!=0;}return bits;
  }
  public static bool All(bool[] bits,bool value){if(bits==null||bits.Length!=16)return false;foreach(bool bit in bits)if(bit!=value)return false;return true;}
  public static bool Equal(byte[] left,byte[] right){if(left==null||right==null||left.Length!=RangeBytesCount||right.Length!=RangeBytesCount)return false;for(int i=0;i<RangeBytesCount;i++)if(left[i]!=right[i])return false;return true;}
  static RangeQuery Query(RangeResult result,IRangeReadApi api,string name,uint code,byte[] input,int capacity) {
   RangeQuery query=api.Control(name,code,input,capacity);if(query==null)throw new InvalidDataException("Missing query response.");result.queries.Add(query);
   if(query.bytesReturned>capacity||query.bytes==null||query.bytes.Length!=query.bytesReturned)throw new InvalidDataException("Native buffer disagrees with bounded response.");
   if(!query.succeeded)throw new Win32Exception(query.nativeError,"Native control refused: "+name);return query;
  }
  public static RangeResult CollectWith(IRangeReadApi api,int diskNumber) {
   if(api==null||diskNumber<0||diskNumber>255)throw new ArgumentException("Expected private read API and disk identity.");
   RangeResult result=new RangeResult{opened=true};
   try {
    result.phase="bind-open-handle";
    long initialBase=ParseBase(Query(result,api,"baseBefore",BaseCode,null,8).bytes);
    ValidateExtents(Query(result,api,"volumeBefore",ExtentsCode,null,64).bytes,diskNumber);
    result.phase="single-lock";result.lockAttempted=true;
    Query(result,api,"lock",LockCode,null,0);result.lockSucceeded=true;
    result.phase="locked-identity-and-bitmaps";
    long lockedBase=ParseBase(Query(result,api,"baseLocked",BaseCode,null,8).bytes);
    if(lockedBase!=initialBase)throw new InvalidDataException("Base changed between binding and lock.");result.baseSectors=lockedBase;
    ValidateExtents(Query(result,api,"volumeLocked",ExtentsCode,null,64).bytes,diskNumber);
    byte[] legacy=Query(result,api,"bitmapLegacy",BitmapCode,new byte[8],MaximumBitmapBytes).bytes;
    byte[] extended=new byte[16];extended[8]=1;
    byte[] metadata=Query(result,api,"bitmapMetadata",BitmapCode,extended,MaximumBitmapBytes).bytes;
    result.sourceBitsLegacy=BitmapBits(legacy,OldLcn);result.sourceBitsMetadata=BitmapBits(metadata,OldLcn);
    result.destinationBitsLegacy=BitmapBits(legacy,NewLcn);result.destinationBitsMetadata=BitmapBits(metadata,NewLcn);
    result.oldSourceFreeInBoth=All(result.sourceBitsLegacy,false)&&All(result.sourceBitsMetadata,false);
    result.destinationAllocatedInBoth=All(result.destinationBitsLegacy,true)&&All(result.destinationBitsMetadata,true);
    if(result.destinationAllocatedInBoth!=true){result.status="destination-range-not-allocated";result.phase="locked-destination-allocation";return result;}
    // Reused source bytes may belong to unrelated files or metadata.
    // Stop the exact two-range profile rather than silently changing its scope.
    if(result.oldSourceFreeInBoth!=true){result.status="source-range-not-free";result.phase="locked-source-allocation";return result;}
    result.phase="two-bounded-reads";
    string[] names={"oldSource","destination"};long[] lcns={OldLcn,NewLcn};
    for(int i=0;i<2;i++) {
     long offset=Offset(lockedBase,lcns[i]);result.rawReadMayHaveBeenIssued=true;result.rangeReadCalls++;RangeBytes read=api.Read(names[i],offset,RangeBytesCount,4096);
     if(read==null)throw new InvalidDataException("Missing bounded read response.");result.reads.Add(read);
     if(read.name!=names[i]||read.offset!=offset||read.requestedBytes!=RangeBytesCount||read.bytesReturned<0||read.bytesReturned>RangeBytesCount||read.bytes==null||read.bytes.Length!=read.bytesReturned)throw new InvalidDataException("Raw read disagrees with bounded request.");
     if(!read.seekSucceeded||read.actualSeekOffset!=offset||!read.readSucceeded||read.bytesReturned!=RangeBytesCount)throw new IOException("Incomplete seek/read; partial evidence retained.");
    }
    result.status="ranges-read-awaiting-file-verification";result.phase="complete";
   }catch(Win32Exception error){result.status=result.lockAttempted&&!result.lockSucceeded?"native-lock-refused":"native-query-refused";result.error=error.ToString();}
   catch(Exception error){result.status="blocked";result.error=error.ToString();}
   finally {
    if(result.lockSucceeded){result.unlockAttempted=true;try{RangeQuery unlock=api.Control("unlock",UnlockCode,null,0);result.queries.Add(unlock);result.unlockSucceeded=unlock!=null&&unlock.succeeded;if(!result.unlockSucceeded){result.status="cleanup-failed";result.error+=(Environment.NewLine+"Native unlock refused.");}}catch(Exception error){result.status="cleanup-failed";result.error+=(Environment.NewLine+error.ToString());}}
    result.handleCloseAttempted=true;try{int error;result.handleCloseSucceeded=api.Close(out error);result.closeError=error;}catch(Exception error){result.error+=(Environment.NewLine+error.ToString());}
    if(!result.handleCloseSucceeded)result.status="cleanup-failed";
    result.nativeOperationReturned=true;
   }
   return result;
  }
  public static RangeResult Collect(string volumeName,int diskNumber,int logical,int physical) {
   string path=ValidateProfile(volumeName,diskNumber,logical,physical);NativeApi api=new NativeApi(path);
   if(!api.Opened)return new RangeResult{status="native-open-refused",openError=api.OpenError,nativeOperationReturned=true,handleCloseSucceeded=true};
   return CollectWith(api,diskNumber);
  }
  sealed class NativeApi:IRangeReadApi {
   SafeFileHandle handle;public bool Opened{get{return handle!=null&&!handle.IsInvalid;}}public int OpenError;
   public NativeApi(string path){handle=CreateFile(path,0x80000000,3,IntPtr.Zero,3,0x20000000,IntPtr.Zero);if(handle.IsInvalid){OpenError=Marshal.GetLastWin32Error();handle.Dispose();}}
   public RangeQuery Control(string name,uint code,byte[] input,int capacity) {
    if(code!=BaseCode&&code!=BitmapCode&&code!=ExtentsCode&&code!=LockCode&&code!=UnlockCode)throw new ArgumentException("Unreviewed native control.");
    RangeQuery query=new RangeQuery{name=name,controlCode=code,inputBytes=input==null?0:input.Length,inputHex=input==null?"":BitConverter.ToString(input).Replace("-","").ToLowerInvariant(),outputCapacityBytes=capacity,startedUtc=DateTime.UtcNow.ToString("o")};
    byte[] buffer=capacity==0?null:new byte[capacity];uint returned;
    query.succeeded=DeviceIoControl(handle,code,input,input==null?0:(uint)input.Length,buffer,(uint)capacity,out returned,IntPtr.Zero);query.nativeError=query.succeeded?0:Marshal.GetLastWin32Error();query.bytesReturned=returned;
    query.finishedUtc=DateTime.UtcNow.ToString("o");query.nativeMessage=query.succeeded?"success":new Win32Exception(query.nativeError).Message;
    if(returned>capacity)throw new InvalidDataException("Native output exceeded capacity.");query.bytes=new byte[returned];if(returned>0)Array.Copy(buffer,query.bytes,(int)returned);return query;
   }
   public RangeBytes Read(string name,long offset,int count,int alignment) {
    if((name!="oldSource"&&name!="destination")||offset<0||offset%4096!=0||offset>VolumeBytes-RangeBytesCount||count!=RangeBytesCount||alignment!=4096)throw new ArgumentException("Bounded aligned range required.");
    RangeBytes result=new RangeBytes{name=name,offset=offset,requestedBytes=count,bytes=new byte[0],startedUtc=DateTime.UtcNow.ToString("o"),seekAttempted=true};long actual;
    result.seekSucceeded=SetFilePointerEx(handle,offset,out actual,0);result.seekError=result.seekSucceeded?0:Marshal.GetLastWin32Error();result.actualSeekOffset=actual;
    if(!result.seekSucceeded||actual!=offset){result.finishedUtc=DateTime.UtcNow.ToString("o");return result;}
    IntPtr allocation=Marshal.AllocHGlobal(checked(count+alignment-1));
    try{IntPtr aligned=new IntPtr(checked(allocation.ToInt64()+alignment-1)&~((long)alignment-1));uint returned;result.readAttempted=true;
     result.readSucceeded=ReadFile(handle,aligned,(uint)count,out returned,IntPtr.Zero);result.readError=result.readSucceeded?0:Marshal.GetLastWin32Error();
     if(returned>count)throw new InvalidDataException("Native read exceeded capacity.");result.bytesReturned=(int)returned;result.bytes=new byte[returned];if(returned>0)Marshal.Copy(aligned,result.bytes,0,(int)returned);
    }finally{Marshal.FreeHGlobal(allocation);result.finishedUtc=DateTime.UtcNow.ToString("o");}return result;
   }
   public bool Close(out int error){bool closed=CloseHandle(handle.DangerousGetHandle());error=closed?0:Marshal.GetLastWin32Error();if(closed){handle.SetHandleAsInvalid();handle.Dispose();}return closed;}
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFilePointerEx(SafeFileHandle handle,long distance,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(SafeFileHandle handle,IntPtr buffer,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
 }
}
