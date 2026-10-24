// Read-only native volume observations. Tests call only the pure parsers.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class DiscoveryQuery {
  public uint controlCode; public bool succeeded; public int nativeError;
  public uint bytesReturned; public byte[] bytes; public string nativeMessage, startedUtc, finishedUtc, inputHex;
  public int inputBytes, outputCapacityBytes;
 }
 public sealed class DiscoveryVolume {
  public bool opened; public int openNativeError; public string volumeName;
  public DiscoveryQuery baseBefore, bitmapBefore, bitmapExtendedFlags0, bitmapExtendedFlags1, baseAfter, bitmapAfter;
 }
 public sealed class DiscoveryBitmap {
  public long startingLcn, bitmapSize, representedClusters, allocatedClusters, freeClusters;
  public bool allDeclaredBitsPresent; public byte[] bytes;
 }
 public sealed class DiscoveryFreeRange {
  public long startingLcn, clusterCount;
  public bool freeInBothObservations=true, reservedForCaller=false, physicalMappingVerified=false;
 }
 public static class NativeExtentDiscovery {
  const uint GetRetrievalBase=0x00090234, GetVolumeBitmap=0x0009006f;
  const int MaximumBitmapBytes=2097152;
  const long MaximumClusters=13631488; // Measured 52 GiB / 4 KiB profile.
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  public static string ValidateVolumeName(string value) {
   Guid id;
   if(value==null || value.Length!=49 || !value.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase) || !value.EndsWith(@"}\",StringComparison.Ordinal) || !Guid.TryParseExact(value.Substring(11,36),"D",out id) || id==Guid.Empty) throw new ArgumentException("Expected the exact Storage provider volume GUID name.");
   return value.Substring(0,value.Length-1);
  }
  static DiscoveryQuery Query(SafeFileHandle handle,uint code,byte[] input,int capacity) {
   DiscoveryQuery result=new DiscoveryQuery {controlCode=code,startedUtc=DateTime.UtcNow.ToString("o"),inputBytes=input==null?0:input.Length,outputCapacityBytes=capacity,inputHex=input==null?"":BitConverter.ToString(input).Replace("-","").ToLowerInvariant()};
   byte[] bytes=new byte[capacity]; uint returned;
   result.succeeded=DeviceIoControl(handle,code,input,input==null?0U:(uint)input.Length,bytes,(uint)bytes.Length,out returned,IntPtr.Zero);
   result.nativeError=result.succeeded?0:Marshal.GetLastWin32Error(); result.bytesReturned=returned;
   if(returned>bytes.Length) throw new InvalidDataException("Native response exceeded its buffer.");
   result.bytes=new byte[returned]; Array.Copy(bytes,result.bytes,(int)returned);
   result.nativeMessage=result.succeeded?"success":new Win32Exception(result.nativeError).Message;
   result.finishedUtc=DateTime.UtcNow.ToString("o"); return result;
  }
  public static DiscoveryVolume Collect(string volumeName) {
   string handleName=ValidateVolumeName(volumeName);
   DiscoveryVolume result=new DiscoveryVolume {volumeName=volumeName};
   // Read access only, shared with mounted-volume activity. No lock,
   // dismount, raw read/write, allocation or movement control exists here.
   using(SafeFileHandle handle=CreateFile(handleName,0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
    if(handle.IsInvalid) { result.openNativeError=Marshal.GetLastWin32Error(); return result; }
    result.opened=true;
    result.baseBefore=Query(handle,GetRetrievalBase,null,8);
    result.bitmapBefore=Query(handle,GetVolumeBitmap,BitmapInput(false,0),MaximumBitmapBytes);
    result.bitmapExtendedFlags0=Query(handle,GetVolumeBitmap,BitmapInput(true,0),MaximumBitmapBytes);
    result.bitmapExtendedFlags1=Query(handle,GetVolumeBitmap,BitmapInput(true,1),MaximumBitmapBytes);
    result.baseAfter=Query(handle,GetRetrievalBase,null,8);
    result.bitmapAfter=Query(handle,GetVolumeBitmap,BitmapInput(false,0),MaximumBitmapBytes);
   }
   return result;
  }
  public static byte[] BitmapInput(bool extended,uint flags) {
   if(flags>1 || (!extended && flags!=0)) throw new ArgumentOutOfRangeException("Bitmap input flags");
   // Explicit x64 ABI: LARGE_INTEGER at 0, ULONG at 8, zero padding at 12.
   // The documented EX request is a separately measured user-mode experiment.
   byte[] input=new byte[extended?16:8];
   if(extended) BitConverter.GetBytes(flags).CopyTo(input,8);
   return input;
  }
  public static long ParseBase(byte[] bytes,long volumeBytes,int sectorBytes) {
   if(bytes==null || bytes.Length!=8 || sectorBytes!=512 || volumeBytes<512 || volumeBytes>55834574848L || volumeBytes%512!=0) throw new InvalidDataException("Invalid retrieval-base response or volume bounds.");
   long value=BitConverter.ToInt64(bytes,0);
   if(value<0 || value>=volumeBytes/sectorBytes) throw new InvalidDataException("Retrieval base is outside the volume sector bounds.");
   return value;
  }
  public static DiscoveryBitmap ParseBitmap(byte[] bytes,long expectedClusters) {
   if(bytes==null || bytes.Length<17 || bytes.Length>MaximumBitmapBytes || expectedClusters<1 || expectedClusters>MaximumClusters) throw new InvalidDataException("Invalid bitmap buffer or profile bound.");
   long start=BitConverter.ToInt64(bytes,0), size=BitConverter.ToInt64(bytes,8);
   if(start!=0 || size!=expectedClusters) throw new InvalidDataException("Full-volume bitmap does not match requested starting LCN or measured geometry.");
   long represented=Math.Min(size,(long)(bytes.Length-16)*8), used=0;
   for(long i=0;i<represented;i++) if((bytes[16+(int)(i/8)] & (1<<(int)(i%8)))!=0) used++;
   return new DiscoveryBitmap {startingLcn=start,bitmapSize=size,representedClusters=represented,allocatedClusters=used,freeClusters=represented-used,allDeclaredBitsPresent=represented==size,bytes=bytes};
  }
  public static bool AreAllocated(DiscoveryBitmap bitmap,long lcn,long count) {
   if(bitmap==null || !bitmap.allDeclaredBitsPresent || lcn<0 || count<1 || count>1024 || lcn>bitmap.bitmapSize-count) throw new ArgumentOutOfRangeException("LCN allocation observation");
   for(long i=lcn;i<lcn+count;i++) if((bitmap.bytes[16+(int)(i/8)] & (1<<(int)(i%8)))==0) return false;
   return true;
  }
  public static long CountDifferentBits(DiscoveryBitmap a,DiscoveryBitmap b) {
   if(a==null || b==null || !a.allDeclaredBitsPresent || !b.allDeclaredBitsPresent || a.bitmapSize!=b.bitmapSize) throw new ArgumentException("Complete equal-geometry bitmaps required.");
   long count=0;
   for(long i=0;i<a.bitmapSize;i++) if(((a.bytes[16+(int)(i/8)]^b.bytes[16+(int)(i/8)]) & (1<<(int)(i%8)))!=0) count++;
   return count;
  }
  public static DiscoveryFreeRange[] FindFreeRanges(DiscoveryBitmap a,DiscoveryBitmap b,long minimumLcn,int runClusters,int maximumRanges) {
   if(a==null || b==null || !a.allDeclaredBitsPresent || !b.allDeclaredBitsPresent || a.bitmapSize!=b.bitmapSize || minimumLcn<0 || minimumLcn>=a.bitmapSize || runClusters<1 || runClusters>16 || maximumRanges<1 || maximumRanges>8) throw new ArgumentOutOfRangeException("Bounded candidate search");
   List<DiscoveryFreeRange> ranges=new List<DiscoveryFreeRange>();
   long start=((minimumLcn+15)/16)*16;
   for(long lcn=start;lcn<=a.bitmapSize-runClusters;lcn+=16) {
    bool free=true;
    for(long i=lcn;i<lcn+runClusters;i++) { int mask=1<<(int)(i%8); if(((a.bytes[16+(int)(i/8)]|b.bytes[16+(int)(i/8)]) & mask)!=0) {free=false;break;} }
    if(free) {ranges.Add(new DiscoveryFreeRange {startingLcn=lcn,clusterCount=runClusters});if(ranges.Count==maximumRanges) break;}
   }
   return ranges.ToArray();
  }
  public static long CandidateVolumeOffset(long baseSectors,long lcn,long clusters,int sectorBytes,int clusterBytes,long volumeBytes) {
   if(baseSectors<0 || lcn<0 || clusters<1 || clusters>1024 || sectorBytes!=512 || clusterBytes!=4096 || volumeBytes<4096 || volumeBytes>55834574848L) throw new ArgumentOutOfRangeException("Address hypothesis");
   checked { long offset=baseSectors*sectorBytes+lcn*clusterBytes, length=clusters*clusterBytes; if(offset>volumeBytes-length) throw new InvalidDataException("Native address hypothesis lies outside the raw partition.");return offset; }
  }
 }
}
