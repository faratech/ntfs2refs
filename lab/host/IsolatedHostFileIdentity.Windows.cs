// Read-attributes namespace pins only; no content I/O, setters, privileges or writer fence.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2RefsResearch {
 public sealed class IsolatedHostFileObservation {
  readonly string path,root,fileId,serial;readonly long length;readonly uint links;readonly bool changed;
  internal IsolatedHostFileObservation(string path,string root,string fileId,string serial,long length,uint links,bool changed){
   this.path=path;this.root=root;this.fileId=fileId;this.serial=serial;this.length=length;this.links=links;this.changed=changed;
  }
  public string CanonicalFinalPath{get{return path;}}
  public string VolumeGuidRoot{get{return root;}}
  // Opaque native FILE_ID_128 byte order, never guessed fsutil display order.
  public string RawFileIdHex{get{return fileId;}}
  public string VolumeSerialHex{get{return serial;}}
  public long FileLength{get{return length;}}
  public uint HardLinkCount{get{return links;}}
  public bool Directory{get{return false;}}
  public bool NoReparseObserved{get{return true;}}
  // Held leaf/ancestor objects deny DELETE sharing, not DOS drive rebinding or
  // alias writers. Serialized observations do not extend the handle lifetime.
  public bool NamespaceIdentityPinned{get{return true;}}
  public bool LengthChangedSinceAcquisition{get{return changed;}}
  public bool ContentImmutable{get{return false;}}
  public bool DeniesHostWriters{get{return false;}}
 }
 public sealed class IsolatedHostFileIdentity:IDisposable {
  const uint ReadAttributes=0x80,ShareAccess=3,OpenExisting=3,OpenReparsePoint=0x00200000,BackupSemantics=0x02000000;
  const int FileStandardInfo=1,FileAttributeTagInfo=9,FileIdInfo=18,MaxComponents=64,MaxHeldHandles=8192,MaxPathChars=32768;
  const string InvalidPath="Absolute unambiguous local DOS file path required before native acquisition.";
  static int reservedHandles;
  readonly object gate=new object();readonly List<HeldPath> held;readonly int reservation;
  bool disposed;IsolatedHostFileObservation observation;
  sealed class Reply{internal string Path,Root,Id,Serial;internal long Length;internal uint Links;internal bool Directory;}
  sealed class HeldPath{internal SafeFileHandle Handle;internal Reply Initial;internal bool Directory;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)]
  static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,[Out]byte[] buffer,uint capacity);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
  static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,StringBuilder path,uint capacity,uint flags);
  private IsolatedHostFileIdentity(List<HeldPath> held,int reservation){this.held=held;this.reservation=reservation;}
  static void Require(bool good,string message){if(!good)throw new InvalidDataException(message);}
  static bool Component(string s){
   if(String.IsNullOrEmpty(s)||s.Length>255||s=="."||s==".."||s.EndsWith(" ",StringComparison.Ordinal)||s.EndsWith(".",StringComparison.Ordinal))return false;
   foreach(char c in s)if(Char.IsControl(c)||"<>:\"/\\|?*".IndexOf(c)>=0)return false;
   string stem=s.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
   if(stem=="CON"||stem=="PRN"||stem=="AUX"||stem=="NUL"||stem=="CONIN$"||stem=="CONOUT$"||stem=="CLOCK$")return false;
   if(stem.Length==4&&(stem.StartsWith("COM",StringComparison.Ordinal)||stem.StartsWith("LPT",StringComparison.Ordinal))){
    char c=stem[3];if((c>='0'&&c<='9')||c=='\u00b9'||c=='\u00b2'||c=='\u00b3')return false;
   }
   return true;
  }
  // Pure grammar. Invalid factory requests stop here before any native call.
  public static string ValidateDosPath(string path){
   bool good=path!=null&&path.Length>=4&&path.Length<MaxPathChars&&((path[0]>='A'&&path[0]<='Z')||(path[0]>='a'&&path[0]<='z'))&&path[1]==':'&&path[2]=='\\';
   if(good){string[] parts=path.Substring(3).Split('\\');good=parts.Length<=MaxComponents;foreach(string part in parts)if(!Component(part)){good=false;break;}}
   Require(good,InvalidPath);return Char.ToUpperInvariant(path[0])+path.Substring(1);
  }
  static string FinalPath(string path,bool directory,out string root){
   const string prefix=@"\\?\Volume{";
   Require(path!=null&&path.Length<MaxPathChars&&path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase),"Native final path is not a bounded volume-GUID path.");
   int end=path.IndexOf(@"}\",prefix.Length,StringComparison.Ordinal);Guid id=Guid.Empty;
   Require(end==prefix.Length+36&&Guid.TryParseExact(path.Substring(prefix.Length,36),"D",out id)&&id!=Guid.Empty,"Native final volume GUID differs from canonical grammar.");
   root=prefix+id.ToString("D")+@"}\";string suffix=path.Substring(end+2);
   if(suffix.Length==0){Require(directory,"Leaf handle is a volume root.");return root;}
   string[] parts=suffix.Split('\\');Require(parts.Length<=MaxComponents,"Native path exceeds depth bound.");
   foreach(string part in parts)Require(Component(part),"Native final path contains ambiguity.");return root+suffix;
  }
  public static void ValidateHandleBudget(int current,int requested){
   Require(current>=0&&current<=MaxHeldHandles&&requested>0&&requested<=MaxComponents+1&&requested<=MaxHeldHandles-current,
       "Held host namespace handle budget exceeded before native acquisition.");
  }
  static void Reserve(int count){
   while(true){int current=Volatile.Read(ref reservedHandles);ValidateHandleBudget(current,count);
    if(Interlocked.CompareExchange(ref reservedHandles,current+count,current)==current)return;}
  }
  static uint U32(byte[] b,int at){return(uint)b[at]|((uint)b[at+1]<<8)|((uint)b[at+2]<<16)|((uint)b[at+3]<<24);}
  static ulong U64(byte[] b,int at){return(ulong)U32(b,at)|((ulong)U32(b,at+4)<<32);}
  static bool Any(byte[] b,int at,int count){for(int i=at;i<at+count;i++)if(b[i]!=0)return true;return false;}
  static void IdentityBytes(byte[] b){Require(b!=null&&b.Length==24,"FileIdInfo must be exactly 24 bytes.");Require(U64(b,0)!=0&&Any(b,8,16),"Native file identity is empty.");}
  public static string FormatRawFileId(byte[] b){IdentityBytes(b);return"0x"+BitConverter.ToString(b,8,16).Replace("-","").ToLowerInvariant();}
  public static string FormatVolumeSerial(byte[] b){IdentityBytes(b);return"0x"+U64(b,0).ToString("x16");}
  static Reply ParseReply(string path,byte[] id,byte[] standard,byte[] tag,bool directory){
   IdentityBytes(id);Require(standard!=null&&standard.Length==24,"FileStandardInfo must be exactly 24 bytes.");
   Require(tag!=null&&tag.Length==8,"FileAttributeTagInfo must be exactly 8 bytes.");
   uint attributes=U32(tag,0),links=U32(standard,16);
   Require(U64(standard,0)<=Int64.MaxValue&&U64(standard,8)<=Int64.MaxValue&&links>0&&standard[20]==0&&standard[21]==(directory?1:0),
       "Native file is deleting, has invalid sizes/links or has wrong directory type.");
   Require((attributes&(0x40U|0x400U))==0&&U32(tag,4)==0&&((attributes&0x10U)!=0)==directory,
       "Native file is a device/reparse point or has inconsistent attributes.");
   string root;string final=FinalPath(path,directory,out root);
   return new Reply{Path=final,Root=root,Id=FormatRawFileId(id),Serial=FormatVolumeSerial(id),Length=(long)U64(standard,8),Links=links,Directory=directory};
  }
  // Synthetic reply validation cannot issue an observation or a live pin.
  public static void ValidateReply(string path,byte[] id,byte[] standard,byte[] tag,bool directory){ParseReply(path,id,standard,tag,directory);}
  static bool SameIdentity(Reply before,Reply after){
   Require(String.Equals(before.Path,after.Path,StringComparison.OrdinalIgnoreCase)&&before.Id==after.Id&&before.Serial==after.Serial&&before.Links==after.Links&&before.Directory==after.Directory,
       "Held namespace/file identity or link count changed.");
   return before.Length!=after.Length; // Running VM contents/length are mutable.
  }
  public static bool ValidateStableReplies(string beforePath,byte[] beforeId,byte[] beforeStandard,byte[] beforeTag,
      string afterPath,byte[] afterId,byte[] afterStandard,byte[] afterTag,bool directory){
   return SameIdentity(ParseReply(beforePath,beforeId,beforeStandard,beforeTag,directory),ParseReply(afterPath,afterId,afterStandard,afterTag,directory));
  }
  static byte[] Information(SafeFileHandle handle,int kind,int count){
   byte[] bytes=new byte[count];
   if(!GetFileInformationByHandleEx(handle,kind,bytes,(uint)count))throw new Win32Exception(Marshal.GetLastWin32Error(),"Read host file attributes");
   return bytes;
  }
  static Reply Query(SafeFileHandle handle,bool directory){
   StringBuilder path=new StringBuilder(MaxPathChars);
   uint count=GetFinalPathNameByHandleW(handle,path,(uint)MaxPathChars,1);
   if(count==0)throw new Win32Exception(Marshal.GetLastWin32Error(),"Read canonical host path");
   Require(count<MaxPathChars&&path.Length==count,"Native final path response exceeds bound or differs.");
   return ParseReply(path.ToString(),Information(handle,FileIdInfo,24),Information(handle,FileStandardInfo,24),Information(handle,FileAttributeTagInfo,8),directory);
  }
  static HeldPath Acquire(string path,bool directory){
   SafeFileHandle handle=CreateFileW(path,ReadAttributes,ShareAccess,IntPtr.Zero,OpenExisting,OpenReparsePoint|(directory?BackupSemantics:0),IntPtr.Zero);
   if(handle==null||handle.IsInvalid){int error=Marshal.GetLastWin32Error();if(handle!=null)handle.Dispose();throw new Win32Exception(error,"Open host identity with read attributes and no delete sharing");}
   try{Reply first=Query(handle,directory);SameIdentity(first,Query(handle,directory));return new HeldPath{Handle=handle,Directory=directory,Initial=first};}
   catch{handle.Dispose();throw;}
  }
  static void CloseAll(List<HeldPath> pins){
   Exception error=null;
   if(pins!=null)for(int i=pins.Count-1;i>=0;i--)try{pins[i].Handle.Dispose();}catch(Exception e){if(error==null)error=e;}
   if(error!=null)throw error;
  }
  // Holds directory objects and the leaf; no stable DOS mapping, all-alias
  // exclusion or immutable content follows. Consumers must reobserve routes.
  public static IsolatedHostFileIdentity Open(string absoluteDosPath){
   string path=ValidateDosPath(absoluteDosPath);string[] parts=path.Substring(3).Split('\\');
   int count=parts.Length+1;List<HeldPath> pins=new List<HeldPath>(count);Reserve(count);
   IsolatedHostFileIdentity pin=null;
   try{
    string current=path.Substring(0,3);HeldPath root=Acquire(current,true);pins.Add(root);
    for(int i=0;i<parts.Length;i++){
     if(i!=0)current+="\\";current+=parts[i];HeldPath part=Acquire(current,i+1<parts.Length);pins.Add(part);
     string expected=root.Initial.Root+String.Join("\\",parts,0,i+1);
     Require(String.Equals(part.Initial.Path,expected,StringComparison.OrdinalIgnoreCase),"Requested DOS ancestry differs from actual canonical host namespace.");
    }
    pin=new IsolatedHostFileIdentity(pins,count);pin.Revalidate();return pin;
   }catch{
    if(pin!=null)pin.Dispose();else try{CloseAll(pins);}finally{Interlocked.Add(ref reservedHandles,-count);}
    throw;
   }
  }
  void RequireOpen(){
   if(disposed)throw new ObjectDisposedException("IsolatedHostFileIdentity");
   foreach(HeldPath pin in held)if(pin.Handle.IsClosed||pin.Handle.IsInvalid)throw new ObjectDisposedException("IsolatedHostFileIdentity");
  }
  public IsolatedHostFileObservation Revalidate(){
   lock(gate){
    RequireOpen();Reply leaf=null;bool changed=false;
    foreach(HeldPath pin in held){Reply current=Query(pin.Handle,pin.Directory);bool differentLength=SameIdentity(pin.Initial,current);if(!pin.Directory){leaf=current;changed=differentLength;}}
    Require(leaf!=null,"Held ordinary host leaf is absent.");
    observation=new IsolatedHostFileObservation(leaf.Path,leaf.Root,leaf.Id,leaf.Serial,leaf.Length,leaf.Links,changed);return observation;
   }
  }
  public IsolatedHostFileObservation Observation{get{lock(gate){RequireOpen();return observation;}}}
  public void Dispose(){
   lock(gate){if(disposed)return;disposed=true;try{CloseAll(held);}finally{if(reservation!=0)Interlocked.Add(ref reservedHandles,-reservation);GC.SuppressFinalize(this);}}
  }
  ~IsolatedHostFileIdentity(){try{Dispose();}catch{}}
 }
}
