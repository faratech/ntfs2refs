// Test boundary only: no Windows/device calls.
namespace Ntfs2Refs {
 public sealed class FakeVdlObservationApi:IVdlObservationApi {
  public string fault="";public int queryCount,identityCount,volumeCount;public bool opened,closed;
  public void Open(string volume){opened=true;if(fault=="open")throw new System.IO.IOException("open fault");}
  public VdlObservationIdentity Identity(){identityCount++;return new VdlObservationIdentity {fileId64=fault=="identity"&&identityCount>2?"0x3000000000009999":NativeVdlObservation.FileId,volumeSerialHex=NativeVdlObservation.VolumeSerial,length=65536,links=1,attributes=fault=="attributes"&&identityCount>3?128U:32U};}
  public VdlObservationVolume Volume(){volumeCount++;return new VdlObservationVolume {succeeded=fault!="volume",nativeError=fault=="volume"?21:0,filesystem="ReFS",label="ntfs2refs-target",serial=fault=="volume-identity"?123U:0x08425382U,flags=fault=="volume-change"&&volumeCount==2?0U:0x10000000U};}
  public static byte[] Standard(){byte[] b=new byte[24];System.BitConverter.GetBytes(65536L).CopyTo(b,0);System.BitConverter.GetBytes(65536L).CopyTo(b,8);System.BitConverter.GetBytes(1U).CopyTo(b,16);return b;}
  public static byte[] Region(uint usage){byte[] b=new byte[40];System.BitConverter.GetBytes(1U).CopyTo(b,4);System.BitConverter.GetBytes(1U).CopyTo(b,8);System.BitConverter.GetBytes(65536L).CopyTo(b,24);System.BitConverter.GetBytes(usage).CopyTo(b,32);return b;}
  public static byte[] Extents(){byte[] b=new byte[48];System.BitConverter.GetBytes(2U).CopyTo(b,0);System.BitConverter.GetBytes(1L).CopyTo(b,16);System.BitConverter.GetBytes(-1L).CopyTo(b,24);System.BitConverter.GetBytes(16L).CopyTo(b,32);System.BitConverter.GetBytes(1508352L).CopyTo(b,40);return b;}
  public VdlObservationQuery Query(string name,uint code,byte[] input,int capacity){
   queryCount++;if(fault=="throw"&&queryCount==3)throw new System.IO.IOException("native call threw");byte[] b=code==0?Standard():code==0x90073?Extents():Region(name.EndsWith("Cached")?1U:0U);
   if(fault=="refusal"&&queryCount==2)b=new byte[0];if(fault=="malformed"&&queryCount==4)b=new byte[17];if(fault=="changed"&&queryCount==8)System.BitConverter.GetBytes(1509000L).CopyTo(b,40);if(fault=="oversize"&&queryCount==1)b=new byte[25];
   bool ok=!(fault=="refusal"&&queryCount==2);return new VdlObservationQuery {name=name,api=code==0?"GetFileInformationByHandleEx":"DeviceIoControl",controlCode=code,informationClass=code==0?1U:0U,inputHex=input==null?"":System.BitConverter.ToString(input).Replace("-","").ToLowerInvariant(),inputBytes=input==null?0:input.Length,outputCapacityBytes=capacity,succeeded=ok,nativeError=ok?0:1,nativeMessage=ok?"success":"refused",bytes=b,bytesReturned=(uint)b.Length,startedUtc="2026-10-24T01:00:00Z",finishedUtc="2026-10-24T01:00:00Z"};
  }
  public void Close(){closed=true;if(fault=="close")throw new System.IO.IOException("close fault");}
 }
}
