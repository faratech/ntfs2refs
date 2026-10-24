// Explicit device protection plus bounded read evidence; no payload-write API.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class ProtectedMountedView {
  public string name,label,fileSystem,startedUtc,finishedUtc;public bool succeeded;public int nativeError;public uint flags,serial;
 }
 public sealed class ProtectedRangeResult {
  public string status="blocked",phase="preflight",error;
  public bool volumeOpened,diskOpened,lockAttempted,lockSucceeded,dismountAttempted,dismountSucceeded,offlineAttempted,offlineSucceeded,setAttributesAttempted,setAttributesSucceeded,onlineAttempted,onlineSucceeded,unlockAttempted,unlockSucceeded;
  public bool deviceStateMutationMayHaveBeenIssued,protectionEstablished,protectionVerifiedBefore,protectionVerifiedLocked,protectionVerifiedAfter,mountedReadOnlyBefore,mountedReadOnlyAfter;
  public bool volumeCloseAttempted,volumeCloseSucceeded,diskCloseAttempted,diskCloseSucceeded,handleCloseSucceeded,nativeOperationReturned,rawReadMayHaveBeenIssued;
  public bool samplingHandleCloseAttempted,samplingHandleCloseSucceeded,volumeReopenAttempted,volumeReopenSucceeded;
  public int samplingHandleCloseError,volumeReopenError;
  public int volumeOpenError,diskOpenError,volumeCloseError,diskCloseError,rangeReadCalls;
  public long? baseSectors;public bool? oldSourceFreeInBoth,destinationAllocatedInBoth;
  public bool[] sourceBitsLegacy,sourceBitsMetadata,destinationBitsLegacy,destinationBitsMetadata;
  public List<RangeQuery> queries=new List<RangeQuery>();public List<RangeBytes> reads=new List<RangeBytes>();public List<ProtectedMountedView> mountedViews=new List<ProtectedMountedView>();
 }
 public interface IProtectedRangeApi {
  bool VolumeOpened{get;}bool DiskOpened{get;}int VolumeOpenError{get;}int DiskOpenError{get;}
  RangeQuery Control(string name,bool disk,uint code,byte[] input,int capacity);
  ProtectedMountedView Mounted(string name);
  RangeBytes Read(string name,long offset,int count,int alignment);
  bool CloseVolume(out int error);bool ReopenVolume(out int error);bool CloseDisk(out int error);
 }
 public static class NativeProtectedRangeRead {
  public const uint DeviceCode=0x002d1080,LengthCode=0x0007405c,AlignmentCode=0x002d1400,LayoutCode=0x00070050,GetAttributesCode=0x000700f0,SetAttributesCode=0x0007c0f4,WritableCode=0x00070024,DismountCode=0x00090020,OfflineCode=0x0056c00c,OnlineCode=0x0056c008;
  public const long DiskBytes=68719476736L;
  public static bool IsOpenHandle(SafeFileHandle handle){return handle!=null&&!handle.IsClosed&&!handle.IsInvalid;}
  public static bool CanReopenReadOnlyHandle(SafeFileHandle handle,bool controlMode,bool attempted,bool confirmedClosed){return !controlMode&&!attempted&&confirmedClosed&&handle!=null&&handle.IsClosed;}
  public static byte[] SetReadOnlyInput(){byte[] b=new byte[40];BitConverter.GetBytes(40U).CopyTo(b,0);BitConverter.GetBytes(2UL).CopyTo(b,8);BitConverter.GetBytes(2UL).CopyTo(b,16);return b;}
  public static byte[] AlignmentInput(){byte[] b=new byte[12];b[0]=6;return b;}
  public static void ValidateDevice(byte[] b,int disk){if(b==null||b.Length!=12||BitConverter.ToUInt32(b,0)!=7||BitConverter.ToUInt32(b,4)!=(uint)disk||BitConverter.ToUInt32(b,8)!=0)throw new InvalidDataException("Physical device number/partition differs.");}
  public static void ValidateLength(byte[] b){if(b==null||b.Length!=8||BitConverter.ToInt64(b,0)!=DiskBytes)throw new InvalidDataException("Physical disk length differs.");}
  public static void ValidateAlignment(byte[] b){if(b==null||b.Length!=28||BitConverter.ToUInt32(b,0)!=28||BitConverter.ToUInt32(b,4)!=28||BitConverter.ToUInt32(b,16)!=512||BitConverter.ToUInt32(b,20)!=4096||BitConverter.ToUInt32(b,24)!=0)throw new InvalidDataException("Physical alignment descriptor differs.");}
  static Guid GuidAt(byte[] b,int offset){byte[] value=new byte[16];Array.Copy(b,offset,value,0,16);return new Guid(value);}
  public static void ValidateLayout(byte[] b){
   if(b==null||b.Length<48||b.Length>65536||BitConverter.ToUInt32(b,0)!=1||GuidAt(b,8)!=new Guid("b4ab4dbc-6bd7-4199-8e4a-01b828e98584"))throw new InvalidDataException("Physical GPT disk identity differs.");
   uint count=BitConverter.ToUInt32(b,4);if(count<1||count>128||b.Length!=48+count*144)throw new InvalidDataException("Incomplete bounded GPT layout.");
   long usable=BitConverter.ToInt64(b,24),usableLength=BitConverter.ToInt64(b,32);if(usable<512||usable%512!=0||usableLength<=0||usableLength%512!=0||usable>DiskBytes-usableLength)throw new InvalidDataException("Invalid GPT usable domain.");
   int targetCount=0;HashSet<uint> numbers=new HashSet<uint>();List<long[]> ranges=new List<long[]>();
   for(int i=0;i<count;i++){int p=48+i*144;uint style=BitConverter.ToUInt32(b,p),number=BitConverter.ToUInt32(b,p+24);long offset=BitConverter.ToInt64(b,p+8),length=BitConverter.ToInt64(b,p+16);Guid type=GuidAt(b,p+32),id=GuidAt(b,p+48);
    if(length==0&&number==0&&type==Guid.Empty)continue;
    if(style!=1||number==0||!numbers.Add(number)||length<=0||offset<usable||offset%512!=0||length%512!=0||offset>usable+usableLength-length||id==Guid.Empty)throw new InvalidDataException("Invalid physical GPT partition entry.");
    foreach(long[] range in ranges)if(offset<range[1]&&range[0]<offset+length)throw new InvalidDataException("GPT partition overlap.");ranges.Add(new long[]{offset,offset+length});
    if(number==2){if(offset!=NativeRangeRead.PartitionOffset||length!=NativeRangeRead.VolumeBytes||id!=new Guid("00c9f113-e0b9-49d8-b031-130aef8ef3fb")||type!=new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")||BitConverter.ToUInt64(b,p+64)!=0)throw new InvalidDataException("Target GPT partition differs.");targetCount++;}
    else if(type!=new Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae")||offset+length>NativeRangeRead.PartitionOffset)throw new InvalidDataException("Unreviewed additional GPT partition.");
   }
   if(targetCount!=1)throw new InvalidDataException("Expected one enrolled GPT target partition.");
  }
  public static void ValidateAttributes(byte[] b,bool protectedState){if(b==null||b.Length!=16||BitConverter.ToUInt32(b,0)!=16||BitConverter.ToUInt32(b,4)!=0||BitConverter.ToUInt64(b,8)!=(protectedState?2UL:0UL))throw new InvalidDataException("Disk protection/offline attributes differ.");}
  public static void ValidateMounted(ProtectedMountedView v){if(v==null||!v.succeeded||v.fileSystem!="ReFS"||v.label!="ntfs2refs-target"||v.serial!=0x08425382||(v.flags&0x00080000)==0)throw new InvalidDataException("Mounted volume is not the expected read-only ReFS volume.");}
  static RangeQuery Query(ProtectedRangeResult r,IProtectedRangeApi api,string name,bool disk,uint code,byte[] input,int capacity,bool writeProtectedExpected){
   RangeQuery q=api.Control(name,disk,code,input,capacity);if(q==null)throw new InvalidDataException("Missing native response.");r.queries.Add(q);
   if(q.name!=name||q.controlCode!=code||q.inputBytes!=(input==null?0:input.Length)||q.inputHex!=(input==null?"":BitConverter.ToString(input).Replace("-","").ToLowerInvariant())||q.outputCapacityBytes!=capacity||q.bytesReturned>capacity||q.bytes==null||q.bytes.Length!=q.bytesReturned)throw new InvalidDataException("Native response disagrees with exact bounded request.");
   if(writeProtectedExpected){if(q.succeeded||q.nativeError!=19||q.bytesReturned!=0)throw new InvalidDataException("Expected explicit ERROR_WRITE_PROTECT.");}
   else if(!q.succeeded)throw new Win32Exception(q.nativeError,"Native control refused: "+name);
   return q;
  }
  static RangeQuery Q(ProtectedRangeResult r,IProtectedRangeApi api,string name,bool disk,uint code,byte[] input,int capacity){return Query(r,api,name,disk,code,input,capacity,false);}
  static void PhysicalIdentity(ProtectedRangeResult r,IProtectedRangeApi api,string prefix,int disk){ValidateDevice(Q(r,api,prefix+"Device",true,DeviceCode,null,12).bytes,disk);ValidateLength(Q(r,api,prefix+"Length",true,LengthCode,null,8).bytes);ValidateAlignment(Q(r,api,prefix+"Alignment",true,AlignmentCode,AlignmentInput(),28).bytes);ValidateLayout(Q(r,api,prefix+"Layout",true,LayoutCode,null,65536).bytes);}
  static void Protection(ProtectedRangeResult r,IProtectedRangeApi api,string prefix,bool required){ValidateAttributes(Q(r,api,prefix.Replace("Writable","Attributes"),true,GetAttributesCode,null,16).bytes,required);Query(r,api,prefix,true,WritableCode,null,0,required);}
  static void Close(ProtectedRangeResult r,IProtectedRangeApi api){
   int error;
   if(r.samplingHandleCloseAttempted&&!r.volumeReopenSucceeded){r.volumeCloseSucceeded=r.samplingHandleCloseSucceeded;}
   else{r.volumeCloseAttempted=true;try{r.volumeCloseSucceeded=api.CloseVolume(out error);r.volumeCloseError=error;}catch(Exception e){r.error+=Environment.NewLine+e.ToString();}}
   r.diskCloseAttempted=true;try{r.diskCloseSucceeded=api.CloseDisk(out error);r.diskCloseError=error;}catch(Exception e){r.error+=Environment.NewLine+e.ToString();}
   r.handleCloseSucceeded=r.volumeCloseSucceeded&&r.diskCloseSucceeded;if(!r.handleCloseSucceeded)r.status="cleanup-failed";r.nativeOperationReturned=true;
  }
  static ProtectedRangeResult Start(IProtectedRangeApi api){return new ProtectedRangeResult{volumeOpened=api.VolumeOpened,diskOpened=api.DiskOpened,volumeOpenError=api.VolumeOpenError,diskOpenError=api.DiskOpenError};}
  static void Unlock(ProtectedRangeResult r,IProtectedRangeApi api,string name){r.unlockAttempted=true;Q(r,api,name,false,NativeRangeRead.UnlockCode,null,0);r.unlockSucceeded=true;}
  public static ProtectedRangeResult ProtectWith(IProtectedRangeApi api,int disk){
   if(api==null||disk<0||disk>255)throw new ArgumentException("Expected exact disk profile.");ProtectedRangeResult r=Start(api);
   try{
    if(!r.volumeOpened||!r.diskOpened){r.status="native-open-refused";return r;}
    r.phase="initial-identity";PhysicalIdentity(r,api,"p",disk);NativeRangeRead.ValidateExtents(Q(r,api,"pVolume",false,NativeRangeRead.ExtentsCode,null,64).bytes,disk);Protection(r,api,"pWritableBefore",false);
    r.phase="quiesce";r.lockAttempted=true;Q(r,api,"pLock",false,NativeRangeRead.LockCode,null,0);r.lockSucceeded=true;
    r.phase="dismount";r.deviceStateMutationMayHaveBeenIssued=true;r.dismountAttempted=true;Q(r,api,"pDismount",false,DismountCode,null,0);r.dismountSucceeded=true;
    r.phase="offline";r.offlineAttempted=true;Q(r,api,"pOffline",false,OfflineCode,null,0);r.offlineSucceeded=true;
    r.phase="protect-disk";r.setAttributesAttempted=true;Q(r,api,"pSetAttributes",true,SetAttributesCode,SetReadOnlyInput(),0);r.setAttributesSucceeded=true;
    Protection(r,api,"pWritableAfter",true);r.protectionEstablished=true;
    r.phase="online";r.onlineAttempted=true;Q(r,api,"pOnline",false,OnlineCode,null,0);r.onlineSucceeded=true;
    r.phase="release-control-handle";Unlock(r,api,"pUnlock");r.status="protection-established";r.phase="complete";
   }catch(Win32Exception e){r.status=r.deviceStateMutationMayHaveBeenIssued?"protection-transition-refused":(r.lockAttempted&&!r.lockSucceeded?"native-lock-refused":"native-query-refused");r.error=e.ToString();}
   catch(Exception e){r.status="blocked";r.error=e.ToString();}
   finally{
    // Offline/failed transitions are preserved. Close releases our lock; never
    // invent an ONLINE or clear-protection request as exception recovery.
    if(r.lockSucceeded&&!r.unlockAttempted&&!r.offlineAttempted){try{Unlock(r,api,"pUnlock");}catch(Exception e){r.status="cleanup-failed";r.error+=Environment.NewLine+e.ToString();}}
    Close(r,api);
   }
   return r;
  }
  static void Mounted(ProtectedRangeResult r,IProtectedRangeApi api,string name){ProtectedMountedView v=api.Mounted(name);r.mountedViews.Add(v);ValidateMounted(v);}
  static void Bitmaps(ProtectedRangeResult r,IProtectedRangeApi api,string suffix,bool initial){
   byte[] legacy=Q(r,api,"sBitmapLegacy"+suffix,false,NativeRangeRead.BitmapCode,new byte[8],NativeRangeRead.MaximumBitmapBytes).bytes;
   byte[] extended=new byte[16];extended[8]=1;byte[] metadata=Q(r,api,"sBitmapMetadata"+suffix,false,NativeRangeRead.BitmapCode,extended,NativeRangeRead.MaximumBitmapBytes).bytes;
   bool[] sourceLegacy=NativeRangeRead.BitmapBits(legacy,NativeRangeRead.OldLcn),sourceMetadata=NativeRangeRead.BitmapBits(metadata,NativeRangeRead.OldLcn),destLegacy=NativeRangeRead.BitmapBits(legacy,NativeRangeRead.NewLcn),destMetadata=NativeRangeRead.BitmapBits(metadata,NativeRangeRead.NewLcn);
   bool free=NativeRangeRead.All(sourceLegacy,false)&&NativeRangeRead.All(sourceMetadata,false),used=NativeRangeRead.All(destLegacy,true)&&NativeRangeRead.All(destMetadata,true);
   if(initial){r.sourceBitsLegacy=sourceLegacy;r.sourceBitsMetadata=sourceMetadata;r.destinationBitsLegacy=destLegacy;r.destinationBitsMetadata=destMetadata;r.oldSourceFreeInBoth=free;r.destinationAllocatedInBoth=used;}
   if(!free||!used)throw new InvalidDataException("Source/destination allocation gate failed in "+suffix+" epoch.");
  }
  public static ProtectedRangeResult ObserveWith(IProtectedRangeApi api,int disk){
   if(api==null||disk<0||disk>255)throw new ArgumentException("Expected exact disk profile.");ProtectedRangeResult r=Start(api);
   try{
    if(!r.volumeOpened||!r.diskOpened){r.status="native-open-refused";return r;}
    r.phase="protected-mounted-before";PhysicalIdentity(r,api,"s",disk);Protection(r,api,"sWritableBefore",true);r.protectionVerifiedBefore=true;NativeRangeRead.ValidateExtents(Q(r,api,"sVolumeBefore",false,NativeRangeRead.ExtentsCode,null,64).bytes,disk);
    Mounted(r,api,"mountedBefore");r.mountedReadOnlyBefore=true;r.baseSectors=NativeRangeRead.ParseBase(Q(r,api,"sBaseBefore",false,NativeRangeRead.BaseCode,null,8).bytes);Bitmaps(r,api,"Before",true);
    r.phase="protected-lock";r.lockAttempted=true;Q(r,api,"sLock",false,NativeRangeRead.LockCode,null,0);r.lockSucceeded=true;Protection(r,api,"sWritableLocked",true);r.protectionVerifiedLocked=true;NativeRangeRead.ValidateExtents(Q(r,api,"sVolumeLocked",false,NativeRangeRead.ExtentsCode,null,64).bytes,disk);
    r.phase="two-bounded-reads";string[] names={"oldSource","destination"};long[] lcns={NativeRangeRead.OldLcn,NativeRangeRead.NewLcn};
    for(int i=0;i<2;i++){long offset=NativeRangeRead.Offset(r.baseSectors.Value,lcns[i]);r.rawReadMayHaveBeenIssued=true;r.rangeReadCalls++;RangeBytes read=api.Read(names[i],offset,65536,4096);if(read==null)throw new InvalidDataException("Missing bounded read.");r.reads.Add(read);if(read.name!=names[i]||read.offset!=offset||read.requestedBytes!=65536||read.bytesReturned<0||read.bytesReturned>65536||read.bytes==null||read.bytes.Length!=read.bytesReturned||!read.seekSucceeded||read.actualSeekOffset!=offset||!read.readSucceeded||read.bytesReturned!=65536)throw new IOException("Incomplete bounded read; preserve partial evidence.");}
    r.phase="release-sampling-lock";Unlock(r,api,"sUnlock");
    r.phase="fresh-sampling-handle";int closeError;r.samplingHandleCloseAttempted=true;r.samplingHandleCloseSucceeded=api.CloseVolume(out closeError);r.samplingHandleCloseError=closeError;if(!r.samplingHandleCloseSucceeded)throw new IOException("Sampling handle close failed; no retry.");
    int reopenError;r.volumeReopenAttempted=true;r.volumeReopenSucceeded=api.ReopenVolume(out reopenError);r.volumeReopenError=reopenError;if(!r.volumeReopenSucceeded)throw new IOException("Fresh read-only sampling handle refused; no retry.");
    r.phase="protected-mounted-after";Protection(r,api,"sWritableAfter",true);r.protectionVerifiedAfter=true;NativeRangeRead.ValidateExtents(Q(r,api,"sVolumeAfter",false,NativeRangeRead.ExtentsCode,null,64).bytes,disk);Mounted(r,api,"mountedAfter");r.mountedReadOnlyAfter=true;
    long afterBase=NativeRangeRead.ParseBase(Q(r,api,"sBaseAfter",false,NativeRangeRead.BaseCode,null,8).bytes);if(afterBase!=r.baseSectors.Value)throw new InvalidDataException("Protected retrieval base changed.");Bitmaps(r,api,"After",false);
    r.status="ranges-read-awaiting-file-verification";r.phase="complete";
   }catch(Win32Exception e){r.status="native-query-refused";r.error=e.ToString();}
   catch(Exception e){r.status="blocked";r.error=e.ToString();}
   finally{if(r.lockSucceeded&&!r.unlockAttempted){try{Unlock(r,api,"sUnlock");}catch(Exception e){r.status="cleanup-failed";r.error+=Environment.NewLine+e.ToString();}}Close(r,api);}
   return r;
  }
  public static ProtectedRangeResult Protect(string volume,int disk,int logical,int physical){string path=NativeRangeRead.ValidateProfile(volume,disk,logical,physical);return ProtectWith(new NativeApi(path,disk,true),disk);}
  public static ProtectedRangeResult Observe(string volume,int disk,int logical,int physical){string path=NativeRangeRead.ValidateProfile(volume,disk,logical,physical);return ObserveWith(new NativeApi(path,disk,false),disk);}
  public static ProtectedMountedView GetMountedView(string name){
   if(name!="mountedBefore"&&name!="mountedAfter"&&name!="fixtureBefore"&&name!="fixtureAfter")throw new ArgumentException("Unreviewed mounted observation name.");
   ProtectedMountedView v=new ProtectedMountedView{name=name,startedUtc=DateTime.UtcNow.ToString("o")};StringBuilder label=new StringBuilder(261),fs=new StringBuilder(261);uint serial,maxComponent,flags;
   v.succeeded=GetVolumeInformationW(NativeRangeRead.ExpectedVolume,label,261,out serial,out maxComponent,out flags,fs,261);v.nativeError=v.succeeded?0:Marshal.GetLastWin32Error();v.serial=serial;v.flags=flags;v.label=label.ToString();v.fileSystem=fs.ToString();v.finishedUtc=DateTime.UtcNow.ToString("o");return v;
  }
  sealed class NativeApi:IProtectedRangeApi {
   SafeFileHandle volumeHandle,diskHandle;readonly bool controlMode;readonly string volumePath;bool reopenAttempted,volumeCloseConfirmed;public bool VolumeOpened{get{return IsOpenHandle(volumeHandle);}}public bool DiskOpened{get{return IsOpenHandle(diskHandle);}}
   public int VolumeOpenError{get;private set;}public int DiskOpenError{get;private set;}
   public NativeApi(string volume,int disk,bool control){
    controlMode=control;volumePath=volume;uint access=control?0xc0000000U:0x80000000U;
    try{diskHandle=CreateFileW(@"\\.\PhysicalDrive"+disk,access,3,IntPtr.Zero,3,0,IntPtr.Zero);if(diskHandle.IsInvalid){DiskOpenError=Marshal.GetLastWin32Error();diskHandle.Dispose();return;}
     volumeHandle=CreateFileW(volume,access,3,IntPtr.Zero,3,control?0U:0x20000000U,IntPtr.Zero);if(volumeHandle.IsInvalid){VolumeOpenError=Marshal.GetLastWin32Error();volumeHandle.Dispose();}
    }catch{if(volumeHandle!=null)volumeHandle.Dispose();if(diskHandle!=null)diskHandle.Dispose();throw;}
   }
   public RangeQuery Control(string name,bool disk,uint code,byte[] input,int capacity){
    if(capacity<0||capacity>2097152)throw new ArgumentException("Unbounded native output.");
    bool diskAllowed=code==DeviceCode||code==LengthCode||code==AlignmentCode||code==LayoutCode||code==GetAttributesCode||code==WritableCode||(controlMode&&code==SetAttributesCode);
    bool volumeAllowed=code==NativeRangeRead.ExtentsCode||code==NativeRangeRead.LockCode||code==NativeRangeRead.UnlockCode||(!controlMode&&(code==NativeRangeRead.BaseCode||code==NativeRangeRead.BitmapCode))||(controlMode&&(code==DismountCode||code==OfflineCode||code==OnlineCode));
    if((disk&&!diskAllowed)||(!disk&&!volumeAllowed))throw new ArgumentException("Unreviewed handle/control combination.");
    RangeQuery q=new RangeQuery{name=name,controlCode=code,inputBytes=input==null?0:input.Length,inputHex=input==null?"":BitConverter.ToString(input).Replace("-","").ToLowerInvariant(),outputCapacityBytes=capacity,startedUtc=DateTime.UtcNow.ToString("o")};byte[] output=capacity==0?null:new byte[capacity];uint returned;
    q.succeeded=DeviceIoControl(disk?diskHandle:volumeHandle,code,input,input==null?0:(uint)input.Length,output,(uint)capacity,out returned,IntPtr.Zero);q.nativeError=q.succeeded?0:Marshal.GetLastWin32Error();q.bytesReturned=returned;q.finishedUtc=DateTime.UtcNow.ToString("o");
    if(returned>capacity)throw new InvalidDataException("Native output exceeded capacity.");q.bytes=new byte[returned];if(returned>0)Array.Copy(output,q.bytes,(int)returned);return q;
   }
   public ProtectedMountedView Mounted(string name){
    if(controlMode)throw new InvalidOperationException("Mounted query cannot run during protection transition.");return GetMountedView(name);
   }
   public RangeBytes Read(string name,long offset,int count,int alignment){
    if(controlMode||(name!="oldSource"&&name!="destination")||offset<0||offset%4096!=0||offset>NativeRangeRead.VolumeBytes-65536||count!=65536||alignment!=4096)throw new ArgumentException("Bounded read-only range required.");
    RangeBytes r=new RangeBytes{name=name,offset=offset,requestedBytes=count,bytes=new byte[0],startedUtc=DateTime.UtcNow.ToString("o"),seekAttempted=true};long actual;
    r.seekSucceeded=SetFilePointerEx(volumeHandle,offset,out actual,0);r.seekError=r.seekSucceeded?0:Marshal.GetLastWin32Error();r.actualSeekOffset=actual;if(!r.seekSucceeded||actual!=offset){r.finishedUtc=DateTime.UtcNow.ToString("o");return r;}
    IntPtr allocation=Marshal.AllocHGlobal(checked(count+alignment-1));try{IntPtr aligned=new IntPtr(checked(allocation.ToInt64()+alignment-1)&~((long)alignment-1));uint returned;r.readAttempted=true;r.readSucceeded=ReadFile(volumeHandle,aligned,(uint)count,out returned,IntPtr.Zero);r.readError=r.readSucceeded?0:Marshal.GetLastWin32Error();if(returned>count)throw new InvalidDataException("Native read exceeded capacity.");r.bytesReturned=(int)returned;r.bytes=new byte[returned];if(returned>0)Marshal.Copy(aligned,r.bytes,0,(int)returned);}finally{Marshal.FreeHGlobal(allocation);r.finishedUtc=DateTime.UtcNow.ToString("o");}return r;
   }
   static bool CloseOne(SafeFileHandle handle,out int error){error=0;if(handle==null||handle.IsClosed||handle.IsInvalid)return true;bool closed=CloseHandle(handle.DangerousGetHandle());error=closed?0:Marshal.GetLastWin32Error();if(closed){handle.SetHandleAsInvalid();handle.Dispose();}return closed;}
   public bool CloseVolume(out int error){bool closed=CloseOne(volumeHandle,out error);volumeCloseConfirmed=closed&&volumeHandle!=null&&volumeHandle.IsClosed;return closed;}public bool CloseDisk(out int error){return CloseOne(diskHandle,out error);}
   public bool ReopenVolume(out int error){if(!CanReopenReadOnlyHandle(volumeHandle,controlMode,reopenAttempted,volumeCloseConfirmed))throw new InvalidOperationException("Only one fresh read-only reopen after confirmed close is allowed.");reopenAttempted=true;volumeCloseConfirmed=false;volumeHandle=CreateFileW(volumePath,0x80000000,3,IntPtr.Zero,3,0x20000000,IntPtr.Zero);error=volumeHandle.IsInvalid?Marshal.GetLastWin32Error():0;if(volumeHandle.IsInvalid){volumeHandle.Dispose();return false;}return true;}
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern bool GetVolumeInformationW(string path,StringBuilder label,uint labelSize,out uint serial,out uint maximumComponentLength,out uint flags,StringBuilder filesystem,uint filesystemSize);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputLength,[Out]byte[] output,uint outputLength,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFilePointerEx(SafeFileHandle handle,long distance,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(SafeFileHandle handle,IntPtr buffer,uint count,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
 }
}
