// Pure byte validation only. No native calls, handles, paths, writes or device scan.
// These checks do not authenticate supplied bytes or grant initialization authority.
// Layout references (Microsoft Learn; little-endian Windows fields):
// https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_identifier
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_id_descriptor
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_access_alignment_descriptor
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_scsi_address
// SMBIOS Type 1 UUID/strings: DMTF DSP0134 3.6.0, sections 6.1.3 and 7.2.1;
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.6.0.pdf
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Ntfs2RefsResearch {
 public static class IsolatedJournalDeviceProfile {
  public const long JournalBytes=8589934592L;
  public const string MachineName="N2R-WIN11";
  public const string VmId="8f7fc646-8c9f-41d0-b65a-ecfadccfc36a";
  public const string FirmwareUuid="87d4c43a-4299-460e-b973-b241f239d33f";
  const int Cap=65536;
  static readonly byte[] Naa={0x60,0x02,0x24,0x80,0x6a,0xac,0x26,0x1f,0x02,0x1f,0x24,0x95,0x96,0xf3,0x32,0xfc};
  static void Need(bool value,string message){if(!value)throw new InvalidDataException(message);}
  static void Bounds(byte[] bytes,int minimum,int maximum,string name){Need(bytes!=null&&bytes.Length>=minimum&&bytes.Length<=maximum,name+" response length differs.");}
  static uint U32(byte[] b,int p){return (uint)b[p]|((uint)b[p+1]<<8)|((uint)b[p+2]<<16)|((uint)b[p+3]<<24);}
  static ushort U16(byte[] b,int p){return (ushort)(b[p]|b[p+1]<<8);}
  static ulong U64(byte[] b,int p){return U32(b,p)|((ulong)U32(b,p+4)<<32);}
  static void Zero(byte[] b,int start,int end,string name){for(int i=start;i<end;i++)Need(b[i]==0,name+" contains nonzero padding/reserved bytes.");}

  public static void ValidateCaller(Guid vmId,string machineName,byte[] rawSmbios){
   Need(vmId==new Guid(VmId)&&String.Equals(machineName,MachineName,StringComparison.Ordinal),"Isolated VM or machine identity differs.");
   Bounds(rawSmbios,14,Cap,"RAW_SMBIOS_DATA");
   Need(rawSmbios[1]>2||(rawSmbios[1]==2&&rawSmbios[2]>=6),"SMBIOS UUID byte order requires version 2.6 or later.");
   uint length=U32(rawSmbios,4);
   Need(length==rawSmbios.Length-8,"RAW_SMBIOS_DATA declared table length differs.");
   int end=rawSmbios.Length,pos=8,typeOne=0;
   while(pos<end){
    Need(end-pos>=6,"Truncated SMBIOS structure.");
    int type=rawSmbios[pos],formatted=rawSmbios[pos+1];
    Need(formatted>=4&&formatted<=end-pos-2,"SMBIOS formatted region exceeds table.");
    if(type==1){
     Need(++typeOne==1&&formatted>=25,"One complete SMBIOS Type 1 is required.");
     byte[] uuid=new byte[16];Array.Copy(rawSmbios,pos+8,uuid,0,16);
     Need(new Guid(uuid)==new Guid(FirmwareUuid),"Isolated SMBIOS firmware UUID differs.");
    }
    int strings=pos+formatted;
    while(strings+1<end&&(rawSmbios[strings]!=0||rawSmbios[strings+1]!=0))strings++;
    Need(strings+1<end,"SMBIOS string region lacks double NUL terminator.");
    if(type==127)Need(formatted==4&&strings==pos+formatted,"SMBIOS end marker shape differs.");
    pos=strings+2;
    if(type==127){Zero(rawSmbios,pos,end,"SMBIOS end marker");pos=end;}
   }
   Need(typeOne==1,"SMBIOS Type 1 is absent.");
  }

  static void Identifiers(byte[] bytes){
   Bounds(bytes,44,Cap,"STORAGE_DEVICE_ID_DESCRIPTOR");
   uint version=U32(bytes,0),declared=U32(bytes,4),count=U32(bytes,8);
   Need((version==12||version==16)&&declared>=44&&declared<=bytes.Length&&version<=declared,"Storage identifier header version/size differs.");
   Need(count>0&&count<=1024,"Storage identifier count is outside budget.");
   int limit=(int)declared,pos=12,deviceNaa=0;
   for(uint i=0;i<count;i++){
    Need(pos<=limit-16,"Truncated STORAGE_IDENTIFIER header.");
    uint code=U32(bytes,pos),type=U32(bytes,pos+4),association=U32(bytes,pos+12);
    int size=U16(bytes,pos+8),next=U16(bytes,pos+10);
    Need(code>=1&&code<=3&&type<=8&&association<=2&&size>0&&size<=limit-pos-16,"Invalid identifier enum or payload bounds.");
    int payload=pos+16,finish=payload+size;
    if(code==2){for(int j=payload;j<finish;j++)Need(bytes[j]>=0x20&&bytes[j]<=0x7e,"ASCII identifier contains nonprintable bytes.");}
    if(code==3){try{new UTF8Encoding(false,true).GetString(bytes,payload,size);}catch(DecoderFallbackException){throw new InvalidDataException("Invalid UTF-8 identifier.");}}
    if(association==0&&type==3){
     Need(++deviceNaa==1&&code==1&&size==Naa.Length,"Ambiguous or nonbinary device NAA identifier.");
     for(int j=0;j<Naa.Length;j++)Need(bytes[payload+j]==Naa[j],"Journal NAA identity differs.");
    }
    if(i+1==count){Need(next==0,"Last identifier continues beyond declared count.");Zero(bytes,finish,limit,"Last identifier");}
    else{
     Need(next>=16+size&&next%4==0&&next<=limit-pos-16,"Identifier chain overlaps, is unaligned or exceeds descriptor.");
     Zero(bytes,finish,pos+next,"Identifier chain");pos+=next;
    }
   }
   Need(deviceNaa==1,"Pinned device-associated NAA identifier is absent.");
   Zero(bytes,limit,bytes.Length,"Identifier response");
  }

  // Hash framing v1: ASCII domain then seven U32LE lengths plus each exact raw
  // response, ordered device,length,alignment,layout,attributes,scsi,identifiers.
  // This is a deterministic observation token, never a live-device certificate.
  public static string ValidateSnapshot(byte[] device,byte[] length,byte[] alignment,byte[] layout,byte[] attributes,byte[] scsi,byte[] identifiers){
   return ValidateSnapshotCore(device,length,alignment,layout,attributes,scsi,identifiers,false);
  }
  // Observation-only compatibility for the exact48-byte all-zero response
  // recorded by the owned device's successful layout query. It is not a RAW
  // initialization profile; callers separately observe current RAW/zero parts.
  public static string ValidateObservationSnapshot(byte[] device,byte[] length,byte[] alignment,byte[] layout,byte[] attributes,byte[] scsi,byte[] identifiers){
   return ValidateSnapshotCore(device,length,alignment,layout,attributes,scsi,identifiers,true);
  }
  static string ValidateSnapshotCore(byte[] device,byte[] length,byte[] alignment,byte[] layout,byte[] attributes,byte[] scsi,byte[] identifiers,bool observationOnly){
   Bounds(device,12,12,"STORAGE_DEVICE_NUMBER");
   Need(U32(device,0)==7&&U32(device,4)==2&&(U32(device,8)==0||U32(device,8)==UInt32.MaxValue),"Journal physical RAW device route differs.");
   Bounds(length,8,8,"GET_LENGTH_INFORMATION");Need(U64(length,0)==(ulong)JournalBytes,"Journal device length differs.");
   Bounds(alignment,28,64,"STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR");
   Need(U32(alignment,0)==28&&U32(alignment,4)==28&&U32(alignment,16)==512&&U32(alignment,20)==4096&&U32(alignment,24)==0,"Journal access alignment differs.");
   uint cache=U32(alignment,8),cacheOffset=U32(alignment,12);
   Need(cache==0?cacheOffset==0:cache<=1048576&&(cache&(cache-1))==0&&cacheOffset<cache,"Invalid cache alignment.");Zero(alignment,28,alignment.Length,"Alignment response");
   Bounds(layout,48,192,"DRIVE_LAYOUT_INFORMATION_EX");
   if(U32(layout,0)==2&&U32(layout,4)==0){Zero(layout,8,layout.Length,"RAW layout");}
   else{Need(observationOnly&&layout.Length==48,"Journal layout is outside the selected profile.");Zero(layout,0,layout.Length,"Exact observation-only MBR layout");}
   Bounds(attributes,16,16,"GET_DISK_ATTRIBUTES");Need(U32(attributes,0)==16&&U32(attributes,4)==0&&U64(attributes,8)==0,"Journal disk attributes differ.");
   Bounds(scsi,8,8,"SCSI_ADDRESS");Need(U32(scsi,0)==8&&scsi[4]==0&&scsi[5]==0&&scsi[6]==0&&scsi[7]==2,"Journal SCSI address differs.");
   Identifiers(identifiers);
   byte[][] responses={device,length,alignment,layout,attributes,scsi,identifiers};
   using(SHA256 sha=SHA256.Create()){
    byte[] domain=Encoding.ASCII.GetBytes("n2r-isolated-journal-device-v1\0");sha.TransformBlock(domain,0,domain.Length,null,0);
    foreach(byte[] response in responses){uint n=(uint)response.Length;byte[] size={(byte)n,(byte)(n>>8),(byte)(n>>16),(byte)(n>>24)};sha.TransformBlock(size,0,size.Length,null,0);sha.TransformBlock(response,0,response.Length,null,0);}
    sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
   }
  }
 }
}
