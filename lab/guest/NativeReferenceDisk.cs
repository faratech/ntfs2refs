// Separate enrollment for disposable reference imports. The existing shadow
// path/identity contract remains unchanged; only its Win32 interop is reused.
namespace Ntfs2RefsResearch {
 public sealed class NativeReferenceDisk {
  public readonly string Path;
  public readonly System.Guid Identifier;
  public readonly System.Collections.Generic.List<Ntfs2Refs.ShadowCall> Calls = new System.Collections.Generic.List<Ntfs2Refs.ShadowCall>();
  public bool Created,Attached,Closed;
  private readonly Ntfs2Refs.WindowsShadowDiskApi api=new Ntfs2Refs.WindowsShadowDiskApi();
  private System.IntPtr handle=System.IntPtr.Zero;
  private bool started,closeAttempted;
  public NativeReferenceDisk(string path,System.Guid id) {
   if(!System.Text.RegularExpressions.Regex.IsMatch(path??"",@"\AJ:\\ntfs2refs-reference\\[0-9a-f]{32}\\reference\.vhdx\z")||id==System.Guid.Empty)
    throw new System.ArgumentException("Fresh reference path and creation identity required.");
   Path=path;Identifier=id;
  }
  private void Check(string operation,uint error) {
   Calls.Add(new Ntfs2Refs.ShadowCall{name=operation,succeeded=error==0,error=error,finishedUtc=System.DateTime.UtcNow.ToString("o")});
   if(error!=0)throw new System.ComponentModel.Win32Exception((int)error,operation);
  }
  private byte[] Query(uint version) {
   byte[] bytes;uint error=api.Query(handle,version,out bytes);Check("GetVirtualDiskInformation:"+version,error);return bytes;
  }
  private Ntfs2Refs.ShadowInfo Observe() {
   Ntfs2Refs.ShadowInfo info=Ntfs2Refs.NativeShadowDisk.ParseInfo(Query(1),Query(2),Query(7),Query(10),Query(14),Identifier);
   if(info.physicalBytes>128UL*1024*1024)throw new System.IO.InvalidDataException("Fresh reference backing exceeds128MiB.");
   return info;
  }
  private void CloseCurrent(string operation) {
   if(handle==System.IntPtr.Zero||handle==new System.IntPtr(-1))return;
   if(closeAttempted)throw new System.InvalidOperationException("Indeterminate handle close is not retried.");
   closeAttempted=true;Check(operation,api.Close(handle));handle=System.IntPtr.Zero;
  }
  public Ntfs2Refs.ShadowInfo CreateAndAttach() {
   if(started)throw new System.InvalidOperationException("Reference creation is single-attempt.");started=true;
   if(System.IO.File.Exists(Path))throw new System.IO.IOException("Reference file already exists.");
   string parent=System.IO.Path.GetDirectoryName(Path);
   while(!System.String.IsNullOrEmpty(parent)) {
    System.IO.FileAttributes attributes=System.IO.File.GetAttributes(parent);
    if((attributes&System.IO.FileAttributes.Directory)==0||(attributes&System.IO.FileAttributes.ReparsePoint)!=0)
     throw new System.IO.InvalidDataException("Ordinary reference ancestry required.");
    string next=System.IO.Path.GetDirectoryName(parent);if(next==parent)break;parent=next;
   }
   System.IntPtr created;uint error=api.Create(Path,Identifier,out created);
   if(error==0)handle=created;Check("CreateVirtualDisk:reference",error);Created=true;
   if(handle==System.IntPtr.Zero||handle==new System.IntPtr(-1))throw new System.IO.InvalidDataException("No valid creation handle.");
   CloseCurrent("CloseHandle:creation");
   System.IntPtr opened;error=api.Open(Path,out opened);if(error==0)handle=opened;Check("OpenVirtualDisk:reference",error);
   closeAttempted=false;
   if(handle==System.IntPtr.Zero||handle==new System.IntPtr(-1))throw new System.IO.InvalidDataException("No valid reference handle.");
   Observe();Check("AttachVirtualDisk:reference-no-letter",api.Attach(handle));Attached=true;
   Ntfs2Refs.ShadowInfo info=Observe();string physical;Check("GetVirtualDiskPhysicalPath:reference",api.PhysicalPath(handle,out physical));
   if(Ntfs2Refs.NativeShadowDisk.ParseDiskNumber(physical)<3)throw new System.IO.InvalidDataException("Reference disk collides with OS/source/journal slots.");
   info.physicalPath=physical;return info;
  }
  public void Close() {
   if(Closed)return;
   CloseCurrent("CloseHandle:reference");
   Closed=true;
  }
 }
}
