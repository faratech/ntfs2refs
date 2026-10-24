// Disposable initialized-file experiment. Never a converter or a raw writer.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class PlacementExtent { public long startingVcn,nextVcn,lcn; }
 public sealed class PlacementObservation {
  public long length; public string sha256,fileId64,volumeSerialHex,attributes;
  public PlacementExtent[] extents;
 }
 public sealed class PlacementQuery {
  public string name,inputHex,startedUtc,finishedUtc,nativeMessage;
  public uint controlCode,bytesReturned; public int nativeError,inputBytes,outputCapacityBytes;
  public bool succeeded; public byte[] bytes;
 }
 public sealed class PlacementResult {
  public string status="blocked",phase="preflight",error,fixturePath,expectedSha256;
  public bool targetWriteRequestsIssued,fixtureDirectoryCreated,fixtureCreated,fixtureFullyInitialized,creationFlushed,moveAttempted,moveCompleted,contentPreserved,originalUnchanged,requestedPlacementObserved;
  public long requestedLcn=-1; public int moveCallCount;
  public PlacementObservation originalBefore,originalAfter,before,after;
  public List<PlacementQuery> queries=new List<PlacementQuery>();
 }
 public static class NativeExtentPlacement {
  public const long VolumeBytes=55834574848L, VolumeClusters=13631488;
  const uint Read=0x80000000,Write=0x40000000,ReadAttributes=0x80,Reparse=0x00200000,Backup=0x02000000;
  const int MaximumBitmapBytes=2097152;
  [StructLayout(LayoutKind.Sequential)] struct FileInformation {
   public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation,access,write;
   public uint volumeSerial,sizeHigh,sizeLow,links,indexHigh,indexLow;
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInformation info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(string path,StringBuilder name,uint length);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,IntPtr security);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  public static string FixturePath(string id) {
   if(id==null || !Regex.IsMatch(id,"^[0-9a-f]{32}$")) throw new ArgumentException("Expected a new lowercase probe ID.");
   return @"F:\fixtures\placement-"+id+@"\initialized.bin";
  }
  public static string VolumeName(string value) {
   Guid id;
   if(value==null || value.Length!=49 || !value.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase) || !value.EndsWith(@"}\",StringComparison.Ordinal) || !Guid.TryParseExact(value.Substring(11,36),"D",out id) || id==Guid.Empty) throw new ArgumentException("Expected a native volume GUID name.");
   return value.Substring(0,48);
  }
  public static byte[] Pattern(string id) {
   FixturePath(id); byte[] bytes=new byte[65536];
   for(int cluster=0;cluster<16;cluster++) {
    byte[] marker=Encoding.ASCII.GetBytes("N2R-INITIALIZED-MOVE-V1|"+id+"|cluster="+cluster.ToString("D2")+"|");
    for(int j=0;j<4096;j++) bytes[cluster*4096+j]=(byte)(1+((j*37+cluster*19)%255));
    Array.Copy(marker,0,bytes,cluster*4096,marker.Length);
   }
   return bytes;
  }
  public static string Hash(byte[] bytes) { using(SHA256 sha=SHA256.Create()) return Hex(sha.ComputeHash(bytes)); }
  static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant(); }
  public static PlacementExtent[] ParseExtents(byte[] bytes,int expectedClusters) {
   if(bytes==null || bytes.Length<32 || bytes.Length>16400 || expectedClusters<1 || expectedClusters>1024) throw new InvalidDataException("Bounded retrieval response required.");
   uint count=BitConverter.ToUInt32(bytes,0);
   if(count<1 || count>expectedClusters || bytes.Length!=16+16L*count || BitConverter.ToInt64(bytes,8)!=0) throw new InvalidDataException("Malformed retrieval extent header.");
   List<PlacementExtent> result=new List<PlacementExtent>();long next=0;
   for(int i=0;i<count;i++) {
    long end=BitConverter.ToInt64(bytes,16+i*16),lcn=BitConverter.ToInt64(bytes,24+i*16);
    if(end<=next || end>expectedClusters || lcn<0 || lcn>VolumeClusters-(end-next)) throw new InvalidDataException("Sparse, overflowing or out-of-profile extent.");
    result.Add(new PlacementExtent {startingVcn=next,nextVcn=end,lcn=lcn});next=end;
   }
   if(next!=expectedClusters) throw new InvalidDataException("Retrieval map does not cover the initialized stream.");
   return result.ToArray();
  }
  public static void ValidateExtents(PlacementExtent[] extents,int count) {
   if(extents==null || extents.Length<1 || extents.Length>count || count<1 || count>1024) throw new ArgumentException("Missing bounded extents.");
   long next=0;
   foreach(PlacementExtent e in extents) {
    if(e==null || e.startingVcn!=next || e.nextVcn<=next || e.nextVcn>count || e.lcn<0 || e.lcn>VolumeClusters-(e.nextVcn-next)) throw new InvalidDataException("Unqualified extent set.");
    next=e.nextVcn;
   }
   if(next!=count) throw new InvalidDataException("Incomplete extent set.");
  }
  public static bool Overlap(long a,long countA,long b,long countB) {
   if(a<0 || b<0 || countA<1 || countB<1 || a>VolumeClusters-countA || b>VolumeClusters-countB) throw new ArgumentOutOfRangeException("Overlap range");
   return a<b+countB && b<a+countA;
  }
  static bool Excluded(long lcn,PlacementExtent[] original,PlacementExtent[] probe) {
   foreach(PlacementExtent e in original) if(Overlap(lcn,16,e.lcn,e.nextVcn-e.startingVcn)) return true;
   foreach(PlacementExtent e in probe) if(Overlap(lcn,16,e.lcn,e.nextVcn-e.startingVcn)) return true;
   // Conservative raw-cluster-as-LCN neighborhoods are exclusions only,
   // not assertions that metadata and API LCN address spaces are equivalent.
   foreach(long anchor in new long[]{30,136348,1635808,13631485,13631486}) {
    long start=Math.Max(0,anchor-16),end=Math.Min(VolumeClusters,anchor+17);
    if(Overlap(lcn,16,start,end-start)) return true;
   }
   return false;
  }
  public static long SelectCandidate(byte[] bitmap,byte[] metadataBitmap,PlacementExtent[] original,PlacementExtent[] probe) {
   ValidateExtents(original,1024);ValidateExtents(probe,16);
   foreach(byte[] candidate in new byte[][]{bitmap,metadataBitmap}) if(candidate==null || candidate.Length<16+VolumeClusters/8 || candidate.Length>MaximumBitmapBytes || BitConverter.ToInt64(candidate,0)!=0 || BitConverter.ToInt64(candidate,8)!=VolumeClusters) throw new InvalidDataException("Complete exact-geometry legacy and metadata-flag bitmaps required; virtual or partial coverage is not truncated.");
   for(long lcn=65536;lcn<=VolumeClusters-16;lcn+=16) {
    if(Excluded(lcn,original,probe)) continue;
    bool free=true;for(long bit=lcn;bit<lcn+16;bit++) if(((bitmap[16+(int)(bit/8)]|metadataBitmap[16+(int)(bit/8)]) & (1<<(int)(bit%8)))!=0){free=false;break;}
    if(free) return lcn;
   }
   throw new InvalidDataException("No bounded aligned candidate was observed free.");
  }
  public static byte[] MoveInput(long handle,long vcn,long lcn,int count) {
   if(IntPtr.Size!=8 || handle<=0 || vcn!=0 || count!=16 || lcn<65536 || lcn%16!=0 || lcn>VolumeClusters-count) throw new ArgumentOutOfRangeException("Exact x64 single-move parameters");
   byte[] bytes=new byte[32];BitConverter.GetBytes(handle).CopyTo(bytes,0);BitConverter.GetBytes(vcn).CopyTo(bytes,8);BitConverter.GetBytes(lcn).CopyTo(bytes,16);BitConverter.GetBytes((uint)count).CopyTo(bytes,24);return bytes;
  }
  public static bool Same(PlacementObservation a,PlacementObservation b,bool mappings) {
   if(a==null || b==null || a.length!=b.length || a.fileId64!=b.fileId64 || a.volumeSerialHex!=b.volumeSerialHex || a.attributes!=b.attributes || a.sha256!=b.sha256) return false;
   if(!mappings) return true;
   if(a.extents.Length!=b.extents.Length) return false;
   for(int i=0;i<a.extents.Length;i++) if(a.extents[i].startingVcn!=b.extents[i].startingVcn || a.extents[i].nextVcn!=b.extents[i].nextVcn || a.extents[i].lcn!=b.extents[i].lcn) return false;
   return true;
  }
  static FileInformation Information(SafeFileHandle handle) { FileInformation info;if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());return info; }
  static void CheckHandle(SafeFileHandle handle,string path,bool directory) {
   FileInformation info=Information(handle);
   if((info.attributes&0x400)!=0 || ((info.attributes&0x10)!=0)!=directory || (!directory && ((info.attributes&(0x200|0x800|0x4000))!=0 || info.links!=1))) throw new IOException("Reparse, sparse, compressed, encrypted, multi-link or unexpected file type refused.");
   StringBuilder final=new StringBuilder(512);uint length=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);
   if(length==0) throw new Win32Exception(Marshal.GetLastWin32Error());
   if(length>=final.Capacity || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase)) throw new IOException("Resolved handle path differs.");
  }
  static SafeFileHandle Open(string path,bool directory,bool writable) {
   SafeFileHandle handle=CreateFile(path,directory?ReadAttributes:(Read|(writable?Write:0)),1,IntPtr.Zero,3,Reparse|(directory?Backup:0),IntPtr.Zero);
   if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
   try{CheckHandle(handle,path,directory);return handle;}catch{handle.Dispose();throw;}
  }
  static PlacementQuery Query(PlacementResult result,SafeFileHandle handle,string name,uint code,byte[] input,int capacity) {
   PlacementQuery query=new PlacementQuery {name=name,controlCode=code,inputHex=input==null?"":Hex(input),inputBytes=input==null?0:input.Length,outputCapacityBytes=capacity,startedUtc=DateTime.UtcNow.ToString("o")};
   result.queries.Add(query);byte[] bytes=capacity==0?null:new byte[capacity];uint returned;
   query.succeeded=DeviceIoControl(handle,code,input,input==null?0:(uint)input.Length,bytes,(uint)capacity,out returned,IntPtr.Zero);
   query.nativeError=query.succeeded?0:Marshal.GetLastWin32Error();query.nativeMessage=query.succeeded?"success":new Win32Exception(query.nativeError).Message;query.bytesReturned=returned;query.finishedUtc=DateTime.UtcNow.ToString("o");
   if(returned>capacity) throw new InvalidDataException("Native response exceeded its capacity.");
   query.bytes=new byte[returned];if(returned>0)Array.Copy(bytes,query.bytes,(int)returned);return query;
  }
  static PlacementObservation Observe(PlacementResult result,SafeFileHandle handle,FileStream stream,string prefix,int clusters) {
   FileInformation first=Information(handle);long length=((long)first.sizeHigh<<32)|first.sizeLow;
   if(length!=clusters*4096L) throw new IOException("Initialized file length differs.");
   PlacementQuery retrieval=Query(result,handle,prefix+"Extents",0x00090073,new byte[8],16+clusters*16);
   if(!retrieval.succeeded) throw new Win32Exception(retrieval.nativeError,"Native retrieval query failed.");
   PlacementExtent[] extents=ParseExtents(retrieval.bytes,clusters);
   stream.Position=0;string hash;using(SHA256 sha=SHA256.Create()) hash=Hex(sha.ComputeHash(stream));
   FileInformation last=Information(handle);
   if(stream.Position!=length || stream.Length!=length || first.volumeSerial!=last.volumeSerial || first.indexHigh!=last.indexHigh || first.indexLow!=last.indexLow || first.sizeHigh!=last.sizeHigh || first.sizeLow!=last.sizeLow || first.attributes!=last.attributes || first.write.dwHighDateTime!=last.write.dwHighDateTime || first.write.dwLowDateTime!=last.write.dwLowDateTime) throw new IOException("File identity or content length changed during observation.");
   return new PlacementObservation {length=length,sha256=hash,fileId64="0x"+first.indexHigh.ToString("x8")+first.indexLow.ToString("x8"),volumeSerialHex="0x"+first.volumeSerial.ToString("x8"),attributes=((FileAttributes)first.attributes).ToString(),extents=extents};
  }
  public static PlacementResult Run(string volumeName,string probeId,string originalHash,string originalFileId) {
   PlacementResult result=new PlacementResult();List<SafeFileHandle> pins=new List<SafeFileHandle>();
   try {
    string handleName=VolumeName(volumeName);result.fixturePath=FixturePath(probeId);
    if(Environment.MachineName!="N2R-WIN11" || Environment.GetEnvironmentVariable("SystemDrive")!="C:" || IntPtr.Size!=8 || !Regex.IsMatch(originalHash??"","^[0-9a-f]{64}$") || !Regex.IsMatch(originalFileId??"","^0x[0-9a-f]{16}$")) throw new InvalidOperationException("Guest-only identity and exact original fixture evidence required.");
    pins.Add(Open(@"F:\",true,false));pins.Add(Open(@"F:\fixtures",true,false));
    StringBuilder actualVolume=new StringBuilder(64);if(!GetVolumeNameForVolumeMountPoint(@"F:\",actualVolume,64)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if(!String.Equals(actualVolume.ToString(),volumeName,StringComparison.OrdinalIgnoreCase)) throw new IOException("Mounted volume GUID changed.");
    using(SafeFileHandle original=Open(@"F:\fixtures\nonresident.bin",false,false))
    using(FileStream originalStream=new FileStream(original,FileAccess.Read,65536,false)) {
     result.originalBefore=Observe(result,original,originalStream,"originalBefore",1024);
     if(result.originalBefore.sha256!=originalHash || result.originalBefore.fileId64!=originalFileId) throw new IOException("Original fixture identity/hash differs from preflight.");
     result.phase="create-initialized-fixture";string directory=Path.GetDirectoryName(result.fixturePath);
     result.targetWriteRequestsIssued=true;
     if(!CreateDirectory(directory,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Unique fixture directory could not be created.");
     result.fixtureDirectoryCreated=true;
     pins.Add(Open(directory,true,false));byte[] pattern=Pattern(probeId);result.expectedSha256=Hash(pattern);
     using(SafeFileHandle fresh=CreateFile(result.fixturePath,Write,0,IntPtr.Zero,1,Reparse|0x80000000,IntPtr.Zero)) {
      if(fresh.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());result.fixtureCreated=true;CheckHandle(fresh,result.fixturePath,false);
      using(FileStream stream=new FileStream(fresh,FileAccess.Write,65536,false)){stream.Write(pattern,0,pattern.Length);result.fixtureFullyInitialized=true;stream.Flush(true);result.creationFlushed=true;}
     }
     // The creation handle is closed before identity/hash and placement queries.
     using(SafeFileHandle fixture=Open(result.fixturePath,false,true))
     using(FileStream fixtureStream=new FileStream(fixture,FileAccess.ReadWrite,65536,false))
     using(SafeFileHandle volume=CreateFile(handleName,Read,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
      if(volume.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(),"Native volume open failed.");
      result.before=Observe(result,fixture,fixtureStream,"before",16);
      if(result.before.sha256!=result.expectedSha256 || result.before.volumeSerialHex!=result.originalBefore.volumeSerialHex) throw new IOException("New fixture pattern or volume identity differs.");
      result.phase="select-current-bitmap-candidate";
      PlacementQuery bitmap=Query(result,volume,"candidateBitmap",0x0009006f,new byte[8],MaximumBitmapBytes);
      if(!bitmap.succeeded) throw new Win32Exception(bitmap.nativeError,"Current bitmap query failed.");
      byte[] extended=new byte[16];extended[8]=1;
      PlacementQuery metadataBitmap=Query(result,volume,"candidateMetadataBitmap",0x0009006f,extended,MaximumBitmapBytes);
      if(!metadataBitmap.succeeded) throw new Win32Exception(metadataBitmap.nativeError,"Current metadata-flag bitmap query failed.");
      result.requestedLcn=SelectCandidate(bitmap.bytes,metadataBitmap.bytes,result.originalBefore.extents,result.before.extents);
      byte[] input=MoveInput(fixture.DangerousGetHandle().ToInt64(),0,result.requestedLcn,16);
      result.phase="single-native-move";result.moveAttempted=true;result.moveCallCount=1;
      PlacementQuery moved=Query(result,volume,"move",0x00090074,input,0);result.moveCompleted=true;
      fixtureStream.Flush(true);result.phase="post-move-observation";
      result.after=Observe(result,fixture,fixtureStream,"after",16);
      result.originalAfter=Observe(result,original,originalStream,"originalAfter",1024);
      result.contentPreserved=Same(result.before,result.after,false)&&result.after.sha256==result.expectedSha256;
      result.originalUnchanged=Same(result.originalBefore,result.originalAfter,true);
      result.requestedPlacementObserved=result.after.extents.Length==1&&result.after.extents[0].startingVcn==0&&result.after.extents[0].nextVcn==16&&result.after.extents[0].lcn==result.requestedLcn;
      result.status=!result.contentPreserved||!result.originalUnchanged?"integrity-check-failed":!moved.succeeded?"native-move-rejected":result.requestedPlacementObserved?"native-placement-observed-awaiting-remount":"native-move-returned-unexpected-mapping";
      result.phase="complete";
     }
    }
   } catch(Exception error){result.error=error.ToString();}
   finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
   return result;
  }
 }
}
