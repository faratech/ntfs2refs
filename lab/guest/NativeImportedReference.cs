// Original, bounded native observation of the imported REFSNT candidate.
// No attach, format, disk-attribute setter, raw write or recovery API exists.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Ntfs2RefsResearch {
 public sealed class ImportedQuery { public string name,outputHex; public uint code; public bool succeeded; public int error; public int returnedBytes; }
 public sealed class ImportedExtent { public long vcn,nextVcn,lcn; }
 public sealed class ImportedFile { public string path,sha256,fileId128; public long length,allocatedBytes; public ImportedExtent[] extents; }
 public sealed class ImportedMutation { public string directory,originalPath,renamedPath,sha256; public int bytesWritten,flushes; public bool directoryCreated,fileCreated,renamed,deleted,directoryRemoved; }
 public sealed class ImportedResult {
  public int schemaVersion=1,diskNumber; public string kind="imported-reference-native-verification",referencePath,volumeRoot,verificationId,phase="new",error;
  public string persistentVhdId="a0c231ef-a959-4a6e-8ae2-7d80363eebe6",startedUtc,finishedUtc;
  public bool mutationRequested,complete,cleanupComplete,rawWriteRequestsIssued=false,diskAttributesChanged=false,attachmentChanged=false;
  public List<ImportedQuery> queries=new List<ImportedQuery>(); public ImportedFile[] before,after; public ImportedMutation mutation;
 }
 [StructLayout(LayoutKind.Sequential)] struct ImportedStorage { public uint device; public Guid vendor; }
 [StructLayout(LayoutKind.Sequential)] struct ImportedOpen { public uint version; public int getInfoOnly,readOnly; public Guid resiliency; }

 public sealed class NativeImportedReference {
  public const long DiskBytes=68719476736L,PartitionOffset=16777216L,PartitionBytes=55834574848L;
  public const string PersistentId="a0c231ef-a959-4a6e-8ae2-7d80363eebe6";
  public const string AdoptedHash="6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786";
  public const string AdoptedName="adopted-existing.bin";
  readonly ImportedResult result; readonly string reference,root,id; readonly int number; readonly bool mutate;
  SafeFileHandle vhd,disk,volume,directory,fixtures;
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint OpenVirtualDisk(ref ImportedStorage storage,string path,uint access,uint flags,ref ImportedOpen parameters,out SafeFileHandle handle);
  [DllImport("virtdisk.dll",ExactSpelling=true)] static extern uint GetVirtualDiskInformation(SafeFileHandle handle,ref uint size,[In,Out]byte[] bytes,out uint used);
  [DllImport("virtdisk.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint GetVirtualDiskPhysicalPath(SafeFileHandle handle,ref uint size,StringBuilder path);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[] input,uint inputBytes,[Out]byte[] output,uint capacity,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int cls,[Out]byte[] bytes,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle,StringBuilder label,uint labelCount,out uint serial,out uint component,out uint flags,StringBuilder fs,uint fsCount);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool GetVolumeNameForVolumeMountPointW(string root,StringBuilder name,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool CreateDirectoryW(string path,IntPtr security);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool MoveFileW(string oldPath,string newPath);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool DeleteFileW(string path);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool RemoveDirectoryW(string path);
  static void Need(bool ok,string reason){if(!ok)throw new InvalidDataException(reason);}
  static void Win(bool ok,string operation){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),operation);}
  static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  static string Hash(byte[] b){using(SHA256 sha=SHA256.Create())return Hex(sha.ComputeHash(b));}
  static Guid GuidAt(byte[] b,int at){byte[] value=new byte[16];Array.Copy(b,at,value,0,16);return new Guid(value);}
  public static string ResolveRoot(string value){Need(Regex.IsMatch(value??"",@"\A(?:[A-Za-z]:\\|\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\)\z",RegexOptions.CultureInvariant),"Exact drive or volume-GUID root required.");StringBuilder name=new StringBuilder(64);Win(GetVolumeNameForVolumeMountPointW(value,name,64),"Resolve native volume root");string root=name.ToString();Need(Regex.IsMatch(root,@"\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z",RegexOptions.CultureInvariant),"Canonical volume root was not returned.");return root;}
  public static void ValidateArguments(string reference,string root,int number,string id){
   Need(Regex.IsMatch(reference??"",@"\AJ:\\ntfs2refs-reference\\[0-9a-f]{32}\\reference\.vhdx\z",RegexOptions.CultureInvariant),"Exact enrolled reference backing path required.");
   Need(Regex.IsMatch(root??"",@"\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z",RegexOptions.CultureInvariant),"Canonical volume GUID root required.");
   Guid guid;Need(Guid.TryParseExact(root.Substring(11,36),"D",out guid)&&guid!=Guid.Empty,"Nonempty volume identity required.");
   Need(number>=3&&number<=63&&Regex.IsMatch(id??"",@"\A[0-9a-f]{32}\z",RegexOptions.CultureInvariant),"Reference route excludes OS/source/journal disks and requires a fresh identifier.");
  }
  public static void ValidateLayout(byte[] b){
   Need(b!=null&&b.Length>=48&&b.Length<=65536&&BitConverter.ToUInt32(b,0)==1&&GuidAt(b,8)==new Guid("b4ab4dbc-6bd7-4199-8e4a-01b828e98584"),"Imported GPT disk identity differs.");
   uint count=BitConverter.ToUInt32(b,4);Need(count>=1&&count<=128&&b.Length==48+count*144,"Incomplete GPT layout.");
   long first=BitConverter.ToInt64(b,24),size=BitConverter.ToInt64(b,32);Need(first>=512&&first%512==0&&size>0&&size%512==0&&first<=DiskBytes-size,"Invalid GPT usable range.");
   int targets=0,reserved=0;HashSet<uint> numbers=new HashSet<uint>();HashSet<Guid> ids=new HashSet<Guid>();List<long[]> ranges=new List<long[]>();
   for(int i=0;i<count;i++){int at=48+i*144;uint n=BitConverter.ToUInt32(b,at+24);long offset=BitConverter.ToInt64(b,at+8),length=BitConverter.ToInt64(b,at+16);Guid type=GuidAt(b,at+32),guid=GuidAt(b,at+48);
    if(n==0&&length==0&&type==Guid.Empty)continue;
    Need(BitConverter.ToUInt32(b,at)==1&&n>0&&numbers.Add(n)&&guid!=Guid.Empty&&ids.Add(guid)&&offset>=first&&length>0&&offset%512==0&&length%512==0&&length<=size&&offset<=first+size-length,"Malformed or duplicate GPT entry.");
    foreach(long[] range in ranges)Need(offset>=range[1]||range[0]>=offset+length,"Overlapping GPT partitions.");ranges.Add(new long[]{offset,offset+length});
    if(n==2){Need(offset==PartitionOffset&&length==PartitionBytes&&guid==new Guid("00c9f113-e0b9-49d8-b031-130aef8ef3fb")&&type==new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")&&BitConverter.ToUInt64(b,at+64)==0,"Imported data partition differs.");targets++;}
    else {Need(type==new Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae")&&offset+length<=PartitionOffset,"Additional data/boot partition refused.");reserved++;}
   }Need(targets==1&&reserved<=1,"Exactly one imported data partition required.");
  }
  public static void ValidateRefs(byte[] b){
   Need(b!=null&&b.Length>=96&&b.Length<=256&&BitConverter.ToUInt32(b,0)>=96&&BitConverter.ToUInt32(b,0)<=b.Length,"Incomplete ReFS volume data.");
   Need(BitConverter.ToUInt32(b,4)==3&&BitConverter.ToUInt32(b,8)==14&&BitConverter.ToUInt32(b,12)==4096&&BitConverter.ToUInt64(b,16)==0x9808427608425382UL&&BitConverter.ToInt64(b,24)==PartitionBytes/512&&BitConverter.ToInt64(b,32)==PartitionBytes/4096&&BitConverter.ToUInt32(b,56)==512&&BitConverter.ToUInt32(b,60)==4096,"Imported ReFS3.14 geometry/serial differs.");
   Need(BitConverter.ToUInt32(b,88)==3&&BitConverter.ToUInt32(b,92)==14,"Unexpected native ReFS driver format profile.");
  }
  public static ImportedExtent[] ParseExtents(byte[] b,long length,bool adopted){
   Need(length>0&&length<=4194304&&b!=null&&b.Length>=16&&b.Length<=16400,"Bounded stream mapping required.");
   uint count=BitConverter.ToUInt32(b,0);long vcn=BitConverter.ToInt64(b,8);Need(count<=1024&&b.Length==16+16L*count&&vcn==0,"Incomplete retrieval pointers.");
   if(count==0){Need(!adopted&&length<=1024,"Only the small baseline file may have no physical extents.");return new ImportedExtent[0];}
   List<ImportedExtent> rows=new List<ImportedExtent>();long clusters=(length+4095)/4096;
   for(int i=0;i<count;i++){long next=BitConverter.ToInt64(b,16+i*16),lcn=BitConverter.ToInt64(b,24+i*16);Need(next>vcn&&next<=clusters&&lcn>=0&&lcn<=PartitionBytes/4096-(next-vcn),"Extent outside initialized file/partition bounds.");
    foreach(ImportedExtent old in rows)Need(lcn>=old.lcn+old.nextVcn-old.vcn||old.lcn>=lcn+next-vcn,"Self-overlapping physical extents.");if(!adopted)Need(lcn>10243||lcn+next-vcn<=10243,"Ordinary file overlaps the protected adopted cluster.");rows.Add(new ImportedExtent{vcn=vcn,nextVcn=next,lcn=lcn});vcn=next;
   }Need(vcn==clusters,"Incomplete stream coverage.");
   if(adopted)Need(rows.Count==1&&rows[0].vcn==0&&rows[0].nextVcn==1&&rows[0].lcn==10243,"Adopted physical LCN10243 was not preserved.");
   return rows.ToArray();
  }
  NativeImportedReference(string reference,string root,int number,string id,bool mutate){ValidateArguments(reference,root,number,id);this.reference=reference;this.root=root;this.number=number;this.id=id;this.mutate=mutate;result=new ImportedResult{referencePath=reference,volumeRoot=root,diskNumber=number,verificationId=id,mutationRequested=mutate,startedUtc=DateTime.UtcNow.ToString("o")};}
  static SafeFileHandle Open(string path,uint access,bool dir,uint creation){SafeFileHandle h=CreateFileW(path,access,3,IntPtr.Zero,creation,0x00200000U|(dir?0x02000000U:0U),IntPtr.Zero);if(h==null||h.IsInvalid){int e=Marshal.GetLastWin32Error();if(h!=null)h.Dispose();throw new Win32Exception(e,"Bounded native handle open: "+path);}return h;}
  byte[] Query(SafeFileHandle handle,string name,uint code,byte[] input,int capacity){Need(result.queries.Count<128&&capacity<=65536,"Native query budget exceeded.");byte[] b=new byte[capacity];uint used;bool ok=DeviceIoControl(handle,code,input,(uint)(input==null?0:input.Length),b,(uint)capacity,out used,IntPtr.Zero);int error=ok?0:Marshal.GetLastWin32Error();Need(used<=capacity,"Oversized native response.");byte[] bytes=new byte[used];Array.Copy(b,bytes,used);result.queries.Add(new ImportedQuery{name=name,code=code,succeeded=ok,error=error,returnedBytes=(int)used,outputHex=Hex(bytes)});if(!ok)throw new Win32Exception(error,name);return bytes;}
  byte[] Vhd(uint version){byte[] bytes=new byte[256];BitConverter.GetBytes(version).CopyTo(bytes,0);uint size=256,used;uint error=GetVirtualDiskInformation(vhd,ref size,bytes,out used);Need(error==0,"VHD information query failed: "+error);Need(used>=8&&used<=256&&BitConverter.ToUInt32(bytes,0)==version,"VHD information framing differs.");byte[] b=new byte[used];Array.Copy(bytes,b,used);return b;}
  void VhdProof(){byte[] b=Vhd(14);Need(b.Length>=24&&GuidAt(b,8)==new Guid(PersistentId),"Reference persistent VHD identity differs.");b=Vhd(1);Need(b.Length>=32&&BitConverter.ToInt64(b,8)==DiskBytes&&BitConverter.ToUInt32(b,24)==2097152&&BitConverter.ToUInt32(b,28)==512,"Reference VHD geometry differs.");b=Vhd(7);Need(b.Length>=12&&BitConverter.ToUInt32(b,8)==3,"Only independent thin VHDX references are enrolled.");b=Vhd(10);Need(b.Length>=12&&BitConverter.ToUInt32(b,8)==4096,"Reference physical-sector profile differs.");StringBuilder path=new StringBuilder(256);uint capacity=512;uint error=GetVirtualDiskPhysicalPath(vhd,ref capacity,path);Need(error==0&&String.Equals(path.ToString(),@"\\.\PhysicalDrive"+number,StringComparison.OrdinalIgnoreCase),"Provider physical route differs.");}
  void Prove(){VhdProof();byte[] b=Query(disk,"device",0x002d1080,null,12);Need(b.Length==12&&BitConverter.ToUInt32(b,0)==7&&BitConverter.ToUInt32(b,4)==number&&BitConverter.ToUInt32(b,8)==0,"Physical disk route differs.");b=Query(disk,"length",0x0007405c,null,8);Need(b.Length==8&&BitConverter.ToInt64(b,0)==DiskBytes,"Reference disk length differs.");byte[] input=new byte[12];input[0]=6;b=Query(disk,"alignment",0x002d1400,input,28);Need(b.Length==28&&BitConverter.ToUInt32(b,0)==28&&BitConverter.ToUInt32(b,4)==28&&BitConverter.ToUInt32(b,16)==512&&BitConverter.ToUInt32(b,20)==4096&&BitConverter.ToUInt32(b,24)==0,"Disk sector alignment differs.");ValidateLayout(Query(disk,"gpt",0x00070050,null,65536));b=Query(disk,"attributes",0x000700f0,null,16);Need(b.Length==16&&BitConverter.ToUInt32(b,0)==16&&BitConverter.ToUInt64(b,8)==(mutate?0UL:BitConverter.ToUInt64(b,8))&&(BitConverter.ToUInt64(b,8)&~2UL)==0,"Reference must be online; mutation requires writable storage.");
   b=Query(volume,"volume-extents",0x00560000,null,32);Need(b.Length==32&&BitConverter.ToUInt32(b,0)==1&&BitConverter.ToUInt32(b,8)==number&&BitConverter.ToInt64(b,16)==PartitionOffset&&BitConverter.ToInt64(b,24)==PartitionBytes,"Mounted volume escaped the imported partition.");StringBuilder label=new StringBuilder(128),fs=new StringBuilder(32);uint serial,component,flags;Win(GetVolumeInformationByHandleW(volume,label,128,out serial,out component,out flags,fs,32),"Mounted filesystem query");Need(fs.ToString()=="ReFS"&&label.ToString()=="ntfs2refs-target"&&serial==0x08425382&&(!mutate||(flags&0x80000)==0),"Mounted imported ReFS identity differs.");ValidateRefs(Query(volume,"refs-volume-data",0x000902d8,null,256));b=Query(volume,"retrieval-pointer-base",0x00090234,null,8);Need(b.Length==8&&BitConverter.ToInt64(b,0)==0,"Only the measured zero physical retrieval base is supported.");
  }
  static byte[] Info(SafeFileHandle h,int cls,int size){byte[] b=new byte[size];Win(GetFileInformationByHandleEx(h,cls,b,(uint)size),"File metadata query");return b;}
  static void PathProof(SafeFileHandle h,string path,bool dir){StringBuilder name=new StringBuilder(512);uint count=GetFinalPathNameByHandleW(h,name,512,1);Need(count>0&&count<512&&String.Equals(name.ToString(),path,StringComparison.OrdinalIgnoreCase),"Native file handle escaped its canonical imported volume path.");uint attrs=BitConverter.ToUInt32(Info(h,0,40),32);Need((attrs&(0x400U|0x800U|0x4000U|0x200U))==0&&((attrs&16)!=0)==dir,"Unsupported reparse/compressed/encrypted/sparse object.");}
  ImportedFile FileProof(string relative,long length,string expectedHash,bool adopted){string path=root+relative;using(SafeFileHandle h=Open(path,0x80000080,false,3)){PathProof(h,path,false);byte[] standard=Info(h,1,24),identity=Info(h,18,24);Need(BitConverter.ToInt64(standard,8)==length&&BitConverter.ToUInt32(standard,16)==1&&standard[20]==0&&standard[21]==0&&BitConverter.ToUInt64(identity,0)==0x9808427608425382UL,"Reference file lengths/identity/link state differs.");byte[] mapping;try{mapping=Query(h,"retrieval:"+relative,0x00090073,new byte[8],16400);}catch(Win32Exception e){if(e.NativeErrorCode!=38||length!=61||BitConverter.ToInt64(standard,0)!=0)throw;mapping=new byte[16];}ImportedExtent[] extents=ParseExtents(mapping,length,adopted);string hash;
    using(FileStream stream=new FileStream(h,FileAccess.Read,65536,false)){using(SHA256 sha=SHA256.Create()){byte[] bytes=new byte[65536];long left=length;while(left>0){int read=stream.Read(bytes,0,(int)Math.Min(left,bytes.Length));Need(read>0,"Unexpected early EOF.");sha.TransformBlock(bytes,0,read,bytes,0);left-=read;}sha.TransformFinalBlock(new byte[0],0,0);hash=Hex(sha.Hash);}Need(stream.Position==length&&stream.ReadByte()==-1,"Unexpected extra file data.");byte[] after=Info(h,1,24),afterId=Info(h,18,24);Need(Hex(after)==Hex(standard)&&Hex(afterId)==Hex(identity),"Reference file changed while read.");}
    Need(hash==expectedHash,"Logical hash differs: "+relative);byte[] idBytes=new byte[16];Array.Copy(identity,8,idBytes,0,16);return new ImportedFile{path=relative,length=length,allocatedBytes=BitConverter.ToInt64(standard,0),sha256=hash,fileId128=Hex(idBytes),extents=extents};
   }}
  ImportedFile[] Files(){return new ImportedFile[]{FileProof(@"fixtures\nonresident.bin",4194304,"ecbf557fb4d10cb9a59eb55645e2e154ff42e6f37cb7ca5a60eed2da1de0539d",false),FileProof(@"fixtures\small.txt",61,"060769a53319045a7aedad5277e4d5118695f2e62aa626100682a686ea143ca2",false),FileProof(AdoptedName,4096,AdoptedHash,true)};}
  void Mutate(){Prove();string relative="n2r-writer-mutation-"+id;string parent=root+relative;ImportedMutation m=new ImportedMutation{directory=parent,originalPath=parent+@"\created.bin",renamedPath=parent+@"\renamed.bin"};result.mutation=m;Need(!Directory.Exists(parent)&&!File.Exists(parent),"Fresh mutation path already exists.");Win(CreateDirectoryW(parent,IntPtr.Zero),"Create fresh owned mutation directory");m.directoryCreated=true;
   using(SafeFileHandle guard=Open(parent,0x80,true,3)){PathProof(guard,parent,true);byte[] bytes=new byte[1048576];uint state=0x6e327266;for(int i=0;i<bytes.Length;i++){state^=state<<13;state^=state>>17;state^=state<<5;bytes[i]=(byte)state;}m.sha256=Hash(bytes);using(SafeFileHandle h=Open(m.originalPath,0xc0000080,false,1)){m.fileCreated=true;PathProof(h,m.originalPath,false);using(FileStream stream=new FileStream(h,FileAccess.ReadWrite,65536,false)){stream.Write(bytes,0,bytes.Length);m.bytesWritten=bytes.Length;stream.Flush(true);m.flushes++;}}
    FileProof(relative+@"\created.bin",bytes.Length,m.sha256,false);Prove();Win(MoveFileW(m.originalPath,m.renamedPath),"Rename owned mutation file");m.renamed=true;FileProof(relative+@"\renamed.bin",bytes.Length,m.sha256,false);Prove();Win(DeleteFileW(m.renamedPath),"Delete owned mutation file");m.deleted=true;Need(!File.Exists(m.originalPath)&&!File.Exists(m.renamedPath),"Owned file remained after deletion.");
   }Prove();Win(RemoveDirectoryW(parent),"Remove fresh empty owned mutation directory");m.directoryRemoved=true;Need(!Directory.Exists(parent),"Owned directory remained after removal.");
  }
  ImportedResult Run(){try{result.phase="bind-reference";ImportedStorage storage=new ImportedStorage{device=3,vendor=new Guid("ec984aec-a0f9-47e9-901f-71415a66345b")};ImportedOpen parameters=new ImportedOpen{version=2,getInfoOnly=1,readOnly=1};uint error=OpenVirtualDisk(ref storage,reference,0,0,ref parameters,out vhd);Need(error==0&&vhd!=null&&!vhd.IsInvalid,"Read-only VHD information handle open failed: "+error);VhdProof();disk=Open(@"\\.\PhysicalDrive"+number,0x80000000,false,3);volume=Open(root.TrimEnd('\\'),0x80000000,false,3);Prove();directory=Open(root,0x80,true,3);PathProof(directory,root,true);fixtures=Open(root+"fixtures",0x80,true,3);PathProof(fixtures,root+"fixtures",true);result.phase="verify-before";result.before=Files();
    if(mutate){result.phase="native-mutation";Mutate();}result.phase="verify-after";Prove();result.after=Files();for(int i=0;i<result.before.Length;i++)Need(result.before[i].fileId128==result.after[i].fileId128&&result.before[i].sha256==result.after[i].sha256,"Protected reference identity or logical payload changed.");result.complete=true;result.phase="complete";
   }catch(Exception e){result.error=e.ToString();}finally{try{if(fixtures!=null)fixtures.Dispose();if(directory!=null)directory.Dispose();if(volume!=null)volume.Dispose();if(disk!=null)disk.Dispose();if(vhd!=null)vhd.Dispose();result.cleanupComplete=true;}catch(Exception e){result.error=(result.error??"")+"\nHandle cleanup: "+e;result.complete=false;}result.finishedUtc=DateTime.UtcNow.ToString("o");}return result;}
  public static ImportedResult Observe(string reference,string root,int number,string id,bool mutate){return new NativeImportedReference(reference,root,number,id,mutate).Run();}
 }
}
