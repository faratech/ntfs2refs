// Read-only guest acquisition. No initialization, disk setter or write authority.
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ntfs2RefsResearch {
 public sealed class IsolatedJournalReadQuery {
  public uint code;
  public int capacity, returnedBytes, error;
  public bool succeeded;
  public string inputHex, outputHex;
 }
 public sealed class IsolatedJournalReadObservation {
  public string beforeSnapshotSha256, afterSnapshotSha256, firmwareHex;
  public long bytesRead, readCalls;
  public bool complete, nativeReadHandle, writeAuthority, diskAttributesChanged;
  public IsolatedJournalReadQuery[] queries;
 }

 // Private construction prevents deserialized observations and managed test
 // streams from becoming native read leases. Host backing ownership is still
 // a separate acquisition requirement; firmware/NAA alone cannot prove it.
 public sealed class IsolatedJournalReader : Stream {
  const string DevicePath = @"\\.\PhysicalDrive2";
  const uint GenericRead = 0x80000000;
  const uint GetNumber=0x002d1080, GetLength=0x0007405c;
  const uint GetLayout=0x00070050, GetAttributes=0x000700f0;
  const uint GetScsi=0x00041018, QueryProperty=0x002d1400;
  SafeFileHandle handle;
  readonly string identityToken, beforeDigest;
  readonly byte[] machineEvidence;
  long position, bytesRead, readCalls;
  long queryBytes;
  readonly List<IsolatedJournalReadQuery> queries=new List<IsolatedJournalReadQuery>();
  bool scanAttempted, closed;
  IsolatedJournalReadObservation observation;

  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path,uint access,uint share,
      IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle disk,uint code,byte[] input,
      uint inputBytes,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool SetFilePointerEx(SafeFileHandle disk,long distance,out long actual,uint method);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool ReadFile(SafeFileHandle disk,IntPtr buffer,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern uint GetSystemFirmwareTable(uint provider,uint table,IntPtr buffer,uint size);

  IsolatedJournalReader(SafeFileHandle disk,string token,byte[] firmware) {
   handle=disk;identityToken=token;machineEvidence=firmware;beforeDigest=Snapshot();
  }
  public static string ExpectedIdentityToken() {
   string material="isolated-journal-zero-v1|8f7fc646-8c9f-41d0-b65a-ecfadccfc36a|"+
       @"\\?\Volume{fcccb0cc-ddbb-46a4-ab61-ab5f91c889ca}\"+
       "|0x000000000007c9c40000000000000010|600224806AAC261F021F249596F332FC|8589934592|512|4096";
   using(SHA256 sha=SHA256.Create()) {
    return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(material))).Replace("-","").ToLowerInvariant();
   }
  }
  // A dispatcher must separately acquire and hold the exact HOST ownership
  // binding. This method neither receives nor trusts a JSON write certificate.
  public static IsolatedJournalReader OpenReadOnly(Guid expectedVmId,string token) {
   if(expectedVmId!=new Guid(IsolatedJournalDeviceProfile.VmId) ||
      !String.Equals(token,ExpectedIdentityToken(),StringComparison.Ordinal))
    throw new InvalidDataException("Exact isolated VM and journal token required before native acquisition.");
   byte[] firmware=ReadFirmware();
   IsolatedJournalDeviceProfile.ValidateCaller(expectedVmId,Environment.MachineName,firmware);
   // No GENERIC_WRITE, share fallback, privilege adjustment or writable reopen.
   SafeFileHandle disk=CreateFileW(DevicePath,GenericRead,0,IntPtr.Zero,3,0,IntPtr.Zero);
   if(disk==null || disk.IsInvalid) {
    int error=Marshal.GetLastWin32Error();if(disk!=null)disk.Dispose();
    throw new Win32Exception(error,"Open isolated journal read-only with no sharing");
   }
   try {return new IsolatedJournalReader(disk,token,firmware);}
   catch {disk.Dispose();throw;}
  }
  static byte[] ReadFirmware() {
   const uint Rsmb=0x52534d42;
   uint size=GetSystemFirmwareTable(Rsmb,0,IntPtr.Zero,0);
   if(size<8 || size>65536)throw new InvalidDataException("Bounded SMBIOS evidence unavailable.");
   IntPtr buffer=Marshal.AllocHGlobal((int)size);
   try {
    uint actual=GetSystemFirmwareTable(Rsmb,0,buffer,size);
    if(actual!=size)throw new InvalidDataException("SMBIOS changed or was incomplete during acquisition.");
    byte[] bytes=new byte[(int)size];Marshal.Copy(buffer,bytes,0,bytes.Length);return bytes;
   } finally {Marshal.FreeHGlobal(buffer);}
  }
  void RequireOpen() {
   if(closed || handle==null || handle.IsClosed || handle.IsInvalid)
    throw new ObjectDisposedException("IsolatedJournalReader");
  }
  byte[] Query(uint code,byte[] input,int capacity) {
   RequireOpen();
   if(capacity<8 || capacity>65536 || queries.Count>=32 || queryBytes+capacity>262144)
    throw new InvalidDataException("Query capacity/evidence outside profile.");
   byte[] bytes=new byte[capacity];uint returned;
   bool ok=DeviceIoControl(handle,code,input,(uint)(input==null?0:input.Length),bytes,(uint)capacity,out returned,IntPtr.Zero);
   int error=ok?0:Marshal.GetLastWin32Error();
   if(returned>capacity)throw new InvalidDataException("Native query exceeds supplied buffer.");
   Array.Resize(ref bytes,(int)returned);queryBytes+=returned;
   queries.Add(new IsolatedJournalReadQuery {code=code,capacity=capacity,returnedBytes=(int)returned,
       error=error,succeeded=ok,inputHex=Hex(input??new byte[0]),outputHex=Hex(bytes)});
   if(!ok)throw new Win32Exception(error,"Read-only journal identity query 0x"+code.ToString("x"));
   return bytes;
  }
  byte[] Property(uint property,int capacity) {
   byte[] input=new byte[12];BitConverter.GetBytes(property).CopyTo(input,0);
   return Query(QueryProperty,input,capacity);
  }
  string Snapshot() {
   byte[] device=Query(GetNumber,null,12),length=Query(GetLength,null,8);
   byte[] alignment=Property(6,64),layout=Query(GetLayout,null,192);
   byte[] attributes=Query(GetAttributes,null,16),scsi=Query(GetScsi,null,8);
   byte[] header=Property(2,8);
   if(header.Length!=8)throw new InvalidDataException("Device-ID header incomplete.");
   uint size=BitConverter.ToUInt32(header,4);
   if(size<12 || size>65536)throw new InvalidDataException("Device-ID descriptor outside bound.");
   byte[] ids=Property(2,(int)size);
   if(ids.Length!=size || BitConverter.ToUInt32(ids,0)!=BitConverter.ToUInt32(header,0) ||
      BitConverter.ToUInt32(ids,4)!=size)
    throw new InvalidDataException("Device-ID descriptor changed or was incomplete.");
   return IsolatedJournalDeviceProfile.ValidateSnapshot(device,length,alignment,layout,attributes,scsi,ids);
  }
  // Only the existing opaque same-stream proof is returned, after actual
  // before/after device queries and full read coverage agree. No write lease.
  public ZeroProof ScanAndBind() {
   RequireOpen();
   if(scanAttempted)throw new InvalidOperationException("One scan attempt per native lease.");
   scanAttempted=true;
   try {
    if(!String.Equals(Snapshot(),beforeDigest,StringComparison.Ordinal))
     throw new InvalidDataException("Journal identity changed before the scan.");
    ZeroProof proof=IsolatedJournalZero.ScanJournal(this,identityToken);
    string after=Snapshot();byte[] firmware=ReadFirmware();
    IsolatedJournalDeviceProfile.ValidateCaller(new Guid(IsolatedJournalDeviceProfile.VmId),Environment.MachineName,firmware);
    if(!Same(machineEvidence,firmware) || !String.Equals(after,beforeDigest,StringComparison.Ordinal) ||
       bytesRead!=IsolatedJournalDeviceProfile.JournalBytes || position!=IsolatedJournalDeviceProfile.JournalBytes)
     throw new InvalidDataException("Native journal/guest identity or complete read coverage changed.");
    proof.AssertCurrent(this,identityToken);
    observation=new IsolatedJournalReadObservation {beforeSnapshotSha256=beforeDigest,
        afterSnapshotSha256=after,bytesRead=bytesRead,readCalls=readCalls,complete=true,
        nativeReadHandle=true,writeAuthority=false,diskAttributesChanged=false};
    return proof;
   } catch {Dispose();throw;}
  }
  static bool Same(byte[] a,byte[] b) {
   if(a.Length!=b.Length)return false;
   for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;
   return true;
  }
  static string Hex(byte[] bytes) {return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
  public IsolatedJournalReadObservation Observation {
   get {
    RequireOpen();
    if(observation==null)throw new InvalidOperationException("No completed native journal scan.");
    return new IsolatedJournalReadObservation {beforeSnapshotSha256=observation.beforeSnapshotSha256,
       afterSnapshotSha256=observation.afterSnapshotSha256,bytesRead=observation.bytesRead,
       readCalls=observation.readCalls,complete=true,nativeReadHandle=true,
       writeAuthority=false,diskAttributesChanged=false,firmwareHex=Hex(machineEvidence),queries=CopyQueries()};
   }
  }
  IsolatedJournalReadQuery[] CopyQueries() {
   var copy=new List<IsolatedJournalReadQuery>();
   foreach(IsolatedJournalReadQuery q in queries)copy.Add(new IsolatedJournalReadQuery {
       code=q.code,capacity=q.capacity,returnedBytes=q.returnedBytes,error=q.error,
       succeeded=q.succeeded,inputHex=q.inputHex,outputHex=q.outputHex});
   return copy.ToArray();
  }
  public override bool CanRead {get {return !closed;}}
  public override bool CanSeek {get {return !closed;}}
  public override bool CanWrite {get {return false;}}
  public override long Length {get {RequireOpen();return IsolatedJournalDeviceProfile.JournalBytes;}}
  public override long Position {get {RequireOpen();return position;}set {Seek(value,SeekOrigin.Begin);}}
  public override long Seek(long offset,SeekOrigin origin) {
   RequireOpen();long target;
   checked {
    if(origin==SeekOrigin.Begin)target=offset;
    else if(origin==SeekOrigin.Current)target=position+offset;
    else if(origin==SeekOrigin.End)target=Length+offset;
    else throw new ArgumentException("Unknown seek origin.");
   }
   if(target<0 || target>Length || target%512!=0)throw new IOException("Journal seek escapes sector-aligned bounds.");
   long actual;
   if(!SetFilePointerEx(handle,target,out actual,0))throw new Win32Exception(Marshal.GetLastWin32Error(),"Seek isolated journal");
   if(actual!=target)throw new IOException("Journal seek returned a different offset.");
   position=actual;return actual;
  }
  public override int Read(byte[] buffer,int offset,int count) {
   RequireOpen();
   if(buffer==null || offset<0 || count<0 || offset>buffer.Length-count)throw new ArgumentException("Invalid read buffer.");
   if(count==0 || position==Length)return 0;
   if(position%512!=0 || count%512!=0 || count>1048576 || count>Length-position)
    throw new IOException("Journal read escapes bounded sector-aligned scan.");
   GCHandle pinned=GCHandle.Alloc(buffer,GCHandleType.Pinned);
   try {
    uint actual;readCalls++;
    if(!ReadFile(handle,IntPtr.Add(pinned.AddrOfPinnedObject(),offset),(uint)count,out actual,IntPtr.Zero))
     throw new Win32Exception(Marshal.GetLastWin32Error(),"Read isolated journal");
    if(actual>count || actual%512!=0)throw new IOException("Journal read count is invalid.");
    checked {position+=actual;bytesRead+=actual;}
    return (int)actual;
   } finally {pinned.Free();}
  }
  public override void Write(byte[] b,int offset,int count) {throw new NotSupportedException("Read-only journal lease.");}
  public override void SetLength(long value) {throw new NotSupportedException("Read-only journal lease.");}
  public override void Flush() {throw new NotSupportedException("No storage mutation/flush in the read-only prerequisite.");}
  protected override void Dispose(bool disposing) {
   if(!closed) {closed=true;if(disposing && handle!=null)handle.Dispose();handle=null;}
   base.Dispose(disposing);
  }
 }
}
