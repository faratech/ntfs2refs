// Separate read-only VHD attachment profile; existing helpers remain unchanged.
using System;using System.Collections.Generic;using System.IO;using System.Runtime.InteropServices;
namespace Ntfs2Refs {
 public sealed class ReadOnlyShadowDiskApi:IShadowDiskApi {
  readonly WindowsShadowDiskApi query=new WindowsShadowDiskApi();
  public static ShadowOpenParameters OpenParameters(){return new ShadowOpenParameters{Version=2,GetInfoOnly=0,ReadOnly=1};}
  public const uint AttachFlags=7;
  public uint Create(string path,Guid id,out IntPtr handle){handle=IntPtr.Zero;throw new NotSupportedException("Read-only attachment never creates a VHD.");}
  public uint Open(string path,out IntPtr h){ShadowStorageType s=new ShadowStorageType{DeviceId=3,VendorId=WindowsShadowDiskApi.MicrosoftVendor};ShadowOpenParameters p=OpenParameters();return OpenVirtualDisk(ref s,path,0,0,ref p,out h);}
  public uint Attach(IntPtr h){ShadowAttachParameters p=new ShadowAttachParameters{Version=1};return AttachVirtualDisk(h,IntPtr.Zero,AttachFlags,0,ref p,IntPtr.Zero);}
  public uint Query(IntPtr h,uint version,out byte[] b){return query.Query(h,version,out b);}public uint PhysicalPath(IntPtr h,out string p){return query.PhysicalPath(h,out p);}public uint Close(IntPtr h){return query.Close(h);}
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]static extern uint OpenVirtualDisk(ref ShadowStorageType s,string path,uint access,uint flags,ref ShadowOpenParameters p,out IntPtr handle);
  [DllImport("virtdisk.dll",ExactSpelling=true)]static extern uint AttachVirtualDisk(IntPtr h,IntPtr security,uint flags,uint provider,ref ShadowAttachParameters p,IntPtr overlapped);
 }
 public interface IShadowProtectionApi {uint Open(bool writable,out IntPtr h);uint Control(IntPtr h,uint code,byte[] input,int capacity,out byte[] output);uint Close(IntPtr h);}
 public sealed class WindowsShadowProtectionApi:IShadowProtectionApi {
  readonly WindowsMountBoundaryApi query=new WindowsMountBoundaryApi();
  public uint Open(bool writable,out IntPtr h){return query.OpenDisk(3,writable,out h);}public uint Control(IntPtr h,uint code,byte[] input,int capacity,out byte[] output){return query.Control(h,code,input,capacity,out output);}public uint Close(IntPtr h){return query.Close(h);}
 }
 public sealed class ShadowProtectionResult {
  public string status="blocked",phase="preflight",error,diskGuid,partitionGuid;
  public bool requestedEstablishExclusion,providerReadOnlyBefore,providerReadOnlyAfter,attributeOpenAttempted,attributeOpenReturned,attributeSetAttempted,attributeSetReturned,attributeSetSucceeded,exclusionObserved,operationCompletionKnown=true,cleanupComplete,rawPayloadWriteRequestsIssued,conversionQualified,persistenceQualified;
  public ulong? attributesBefore,attributesAfter;public List<MountCall> calls=new List<MountCall>();
 }
 public static class NativeShadowProtection {
  static bool Valid(IntPtr h){return h!=IntPtr.Zero&&h!=new IntPtr(-1);}static string Hex(byte[] b){return b==null?"":BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  public static byte[] ExclusionInput(){byte[] b=new byte[40];BitConverter.GetBytes(40U).CopyTo(b,0);b[4]=1;BitConverter.GetBytes(3UL).CopyTo(b,8);BitConverter.GetBytes(3UL).CopyTo(b,16);return b;}
  public static ShadowProtectionResult Observe(Guid disk,Guid partition,bool establish){return ObserveWith(new WindowsShadowProtectionApi(),disk,partition,establish);}
  public static ShadowProtectionResult ObserveWith(IShadowProtectionApi api,Guid disk,Guid partition,bool establish){
   if(api==null||disk==Guid.Empty||partition==Guid.Empty||disk==partition)throw new ArgumentException("Exact distinct shadow GPT required.");
   ShadowProtectionResult r=new ShadowProtectionResult{diskGuid=disk.ToString("D"),partitionGuid=partition.ToString("D"),requestedEstablishExclusion=establish};IntPtr read=IntPtr.Zero,write=IntPtr.Zero;bool active=false;HashSet<IntPtr> closeAttempts=new HashSet<IntPtr>();
   Func<string,MountCall> begin=delegate(string name){active=true;MountCall c=new MountCall{name=name,startedUtc=DateTime.UtcNow.ToString("o")};r.calls.Add(c);return c;};
   Action<MountCall,uint> end=delegate(MountCall c,uint e){c.error=e;c.succeeded=e==0;c.finishedUtc=DateTime.UtcNow.ToString("o");active=false;};
   Func<IntPtr,string,uint,byte[],int,MountCall> query=delegate(IntPtr h,string name,uint code,byte[] input,int capacity){MountCall c=begin(name);c.code=code;c.inputHex=Hex(input);c.capacity=capacity;byte[] b;uint e=api.Control(h,code,input,capacity,out b);if(b!=null&&b.Length<=capacity){c.outputHex=Hex(b);c.returned=b.Length;}end(c,e);if(b==null||b.Length>capacity)throw new InvalidDataException("Malformed native response.");return c;};
   Func<MountCall,byte[]> bytes=delegate(MountCall c){if(c.error!=0)throw new System.ComponentModel.Win32Exception((int)c.error,c.name);byte[] b=new byte[c.returned];for(int i=0;i<b.Length;i++)b[i]=Convert.ToByte(c.outputHex.Substring(i*2,2),16);return b;};
   Func<IntPtr,string,ulong> snapshot=delegate(IntPtr h,string label){byte[] b=bytes(query(h,label+"Device",NativeMountBoundary.DeviceCode,null,12));if(b.Length!=12||BitConverter.ToUInt32(b,0)!=7||BitConverter.ToUInt32(b,4)!=3||BitConverter.ToUInt32(b,8)!=0)throw new InvalidDataException("Physical route differs.");b=bytes(query(h,label+"Length",NativeMountBoundary.LengthCode,null,8));if(b.Length!=8||BitConverter.ToInt64(b,0)!=68719476736L)throw new InvalidDataException("Disk length differs.");byte[] input=new byte[12];input[0]=6;b=bytes(query(h,label+"Alignment",NativeMountBoundary.AlignmentCode,input,28));if(b.Length!=28||BitConverter.ToUInt32(b,0)!=28||BitConverter.ToUInt32(b,4)!=28||BitConverter.ToUInt32(b,16)!=512||BitConverter.ToUInt32(b,20)!=4096||BitConverter.ToUInt32(b,24)!=0)throw new InvalidDataException("Disk alignment differs.");NativeMountBoundary.ValidateLayout(bytes(query(h,label+"Layout",NativeMountBoundary.LayoutCode,null,65536)),disk,partition);b=bytes(query(h,label+"Attributes",NativeMountBoundary.GetAttributesCode,null,16));if(b.Length!=16||BitConverter.ToUInt32(b,0)!=16||BitConverter.ToUInt32(b,4)!=0||BitConverter.ToUInt64(b,8)>3)throw new InvalidDataException("Unexpected disk attributes.");return BitConverter.ToUInt64(b,8);};
   Action<IntPtr,string> protectedDisk=delegate(IntPtr h,string label){MountCall c=query(h,label,NativeMountBoundary.WritableCode,null,0);if(c.error!=19||c.returned!=0)throw new InvalidDataException("Require explicit provider ERROR_WRITE_PROTECT.");};
   try{
    r.phase="open-readonly";MountCall c=begin("OpenPhysicalDrive3ReadOnly");uint e=api.Open(false,out read);end(c,e);if(e!=0||!Valid(read))throw new IOException("Read-only physical open refused: "+e);
    r.phase="bind-provider-protection";r.attributesBefore=snapshot(read,"before");protectedDisk(read,"providerWritableBefore");r.providerReadOnlyBefore=true;r.status="provider-readonly-observed";
    if(establish&&r.attributesBefore!=3){r.phase="attribute-access-intent";r.attributeOpenAttempted=true;c=begin("OpenPhysicalDrive3AttributeAccess");e=api.Open(true,out write);end(c,e);r.attributeOpenReturned=true;
     if(e!=0){r.status="provider-readonly-attribute-access-refused";}else{if(!Valid(write))throw new InvalidDataException("Invalid attribute-access handle.");ulong attributes=snapshot(write,"preSet");if(attributes!=r.attributesBefore)throw new InvalidDataException("Attributes changed before explicit request.");protectedDisk(write,"providerWritablePreSet");r.phase="attribute-set-intent";r.attributeSetAttempted=true;c=query(write,"SetOfflineReadOnly",NativeMountBoundary.SetAttributesCode,ExclusionInput(),0);r.attributeSetReturned=true;r.attributeSetSucceeded=c.succeeded;r.status=c.succeeded?"provider-readonly-exclusion-request-returned":"provider-readonly-attribute-request-refused";}
    }
    r.phase="bind-after";r.attributesAfter=snapshot(read,"after");protectedDisk(read,"providerWritableAfter");r.providerReadOnlyAfter=true;r.exclusionObserved=r.attributesAfter==3;
    if(r.attributeSetSucceeded&&!r.exclusionObserved)throw new InvalidDataException("Successful attribute call did not establish exclusion.");if(!r.attributeSetAttempted&&r.attributesBefore!=r.attributesAfter)throw new InvalidDataException("Attributes changed without our request.");if(r.exclusionObserved)r.status="provider-readonly-and-offline-observed";r.phase="complete";
   }catch(Exception ex){r.status="blocked";r.error=ex.ToString();}
   finally{r.operationCompletionKnown=!active;if(!active){try{foreach(IntPtr h in new IntPtr[]{write,read}){if(!Valid(h))continue;if(!closeAttempts.Add(h))throw new IOException("Handle alias or repeated close.");MountCall c=begin("ClosePhysicalHandle");uint e=api.Close(h);end(c,e);if(e!=0)throw new IOException("Physical close refused: "+e);}r.cleanupComplete=true;}catch(Exception ex){r.status="cleanup-failed";r.error+=" "+ex.ToString();}}r.operationCompletionKnown=!active;}
   return r;
  }
 }
}
