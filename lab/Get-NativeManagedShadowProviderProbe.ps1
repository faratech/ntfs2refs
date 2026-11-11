# Read-only provider probe for the one original owned managed VHDX. Root alone
# runs this in the guest. It never attaches, detaches or changes privileges,
# attributes, ACLs, source/journal data or filesystem mount state.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-NativeManagedVhdObservation([string]$Path){
 # Microsoft: V2 GetInfoOnly limits the handle to information queries and
 # ReadOnly opens the backing store read-only. Access/flags remain NONE.
 # https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-open_virtual_disk_parameters
 # https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-get_virtual_disk_info_version
 # https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-get_virtual_disk_info
 # https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-getvirtualdiskphysicalpath
 if(-not('N2RPowerManagedVhdInfoV1'-as[type])){
  $nativeSource=@"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class N2RPowerManagedVhdObservationV1 {
    public uint OpenStatus;
    public uint? SizeStatus, LoadedStatus, VirtualDiskIdStatus, PhysicalSectorStatus, PhysicalPathStatus;
    public uint? SizeUsed, LoadedUsed, VirtualDiskIdUsed, PhysicalSectorUsed;
    public ulong? VirtualSize, PhysicalSize;
    public uint? BlockSize, LogicalSectorSize, VhdPhysicalSectorSize, IsLoadedRaw;
    public Guid? VirtualDiskId;
    public bool? IsLoaded;
    public string PhysicalPath;
    public bool PhysicalPathQueried, QueriesComplete;
    public uint OpenVersion=2, AccessMask=0, OpenFlags=0;
    public bool GetInfoOnly=true, ReadOnly=true;
}

public static class N2RPowerManagedVhdInfoV1 {
    [StructLayout(LayoutKind.Explicit, Size=20)]
    private struct StorageType {
        [FieldOffset(0)] public uint DeviceId;
        [FieldOffset(4)] public Guid VendorId;
    }
    [StructLayout(LayoutKind.Explicit, Size=28)]
    private struct OpenParametersV2 {
        [FieldOffset(0)] public uint Version;
        [FieldOffset(4)] public int GetInfoOnly;
        [FieldOffset(8)] public int ReadOnly;
        [FieldOffset(12)] public Guid ResiliencyGuid;
    }
    // GET_VIRTUAL_DISK_INFO's ULONGLONG-containing union begins at offset8.
    [StructLayout(LayoutKind.Explicit, Size=32)]
    private struct DiskInfo {
        [FieldOffset(0)] public uint Version;
        [FieldOffset(8)] public ulong VirtualSize;
        [FieldOffset(16)] public ulong PhysicalSize;
        [FieldOffset(24)] public uint BlockSize;
        [FieldOffset(28)] public uint SectorSize;
        [FieldOffset(8)] public uint UInt32Value;
        [FieldOffset(8)] public Guid GuidValue;
    }
    [DllImport("virtdisk.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    private static extern uint OpenVirtualDisk(ref StorageType storage, string path, uint access,
        uint flags, ref OpenParametersV2 parameters, out IntPtr handle);
    [DllImport("virtdisk.dll", ExactSpelling=true)]
    private static extern uint GetVirtualDiskInformation(SafeFileHandle handle, ref uint bytes,
        ref DiskInfo info, out uint used);
    [DllImport("virtdisk.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    private static extern uint GetVirtualDiskPhysicalPath(SafeFileHandle handle, ref uint bytes,
        [Out] char[] path);
    private static uint Query(SafeFileHandle handle, uint version, out DiskInfo info, out uint used) {
        info=new DiskInfo(); info.Version=version;
        uint bytes=32;
        return GetVirtualDiskInformation(handle, ref bytes, ref info, out used);
    }
    public static N2RPowerManagedVhdObservationV1 Observe(string path) {
        N2RPowerManagedVhdObservationV1 result=new N2RPowerManagedVhdObservationV1();
        StorageType storage=new StorageType(); storage.DeviceId=3;
        storage.VendorId=new Guid("ec984aec-a0f9-47e9-901f-71415a66345b");
        OpenParametersV2 parameters=new OpenParametersV2();
        parameters.Version=2; parameters.GetInfoOnly=1; parameters.ReadOnly=1;
        IntPtr raw=IntPtr.Zero;
        result.OpenStatus=OpenVirtualDisk(ref storage,path,0,0,ref parameters,out raw);
        // The output handle is undefined on failure; never close that value.
        if(result.OpenStatus!=0) return result;
        if(raw==IntPtr.Zero || raw==new IntPtr(-1)) throw new InvalidOperationException("OpenVirtualDisk succeeded without a valid handle");
        using(SafeFileHandle handle=new SafeFileHandle(raw,true)) {
            DiskInfo info; uint used;
            result.SizeStatus=Query(handle,1,out info,out used); result.SizeUsed=used;
            if(result.SizeStatus==0) {
                result.VirtualSize=info.VirtualSize; result.PhysicalSize=info.PhysicalSize;
                result.BlockSize=info.BlockSize; result.LogicalSectorSize=info.SectorSize;
            }
            result.LoadedStatus=Query(handle,13,out info,out used); result.LoadedUsed=used;
            if(result.LoadedStatus==0) {
                result.IsLoadedRaw=info.UInt32Value;
                if(info.UInt32Value==0 || info.UInt32Value==1) result.IsLoaded=(info.UInt32Value==1);
            }
            result.VirtualDiskIdStatus=Query(handle,14,out info,out used); result.VirtualDiskIdUsed=used;
            if(result.VirtualDiskIdStatus==0) result.VirtualDiskId=info.GuidValue;
            result.PhysicalSectorStatus=Query(handle,10,out info,out used); result.PhysicalSectorUsed=used;
            if(result.PhysicalSectorStatus==0) result.VhdPhysicalSectorSize=info.UInt32Value;
            if(result.IsLoaded==true) {
                result.PhysicalPathQueried=true;
                char[] pathBuffer=new char[512]; uint pathBytes=1024;
                result.PhysicalPathStatus=GetVirtualDiskPhysicalPath(handle,ref pathBytes,pathBuffer);
                if(result.PhysicalPathStatus==0) {
                    if(pathBytes>1024 || (pathBytes&1)!=0) throw new InvalidOperationException("Native virtual disk path size is invalid");
                    result.PhysicalPath=new string(pathBuffer).TrimEnd('\0');
                }
            }
            result.QueriesComplete=(result.SizeStatus==0 && result.LoadedStatus==0 &&
                result.VirtualDiskIdStatus==0 && result.PhysicalSectorStatus==0 && result.IsLoaded.HasValue &&
                (result.IsLoaded==false || (result.PhysicalPathStatus==0 && !String.IsNullOrEmpty(result.PhysicalPath))));
        }
        return result;
    }
}
"@
  Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
 }
 return [N2RPowerManagedVhdInfoV1]::Observe($Path)
}

if($env:COMPUTERNAME-cne'N2R-WIN11'-or-not[Environment]::Is64BitProcess){throw 'Exact owning64-bit guest required.'}
$path='C:\ntfs2refs\ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e\managed-shadow\shadow.vhdx'
$image=Get-Item -LiteralPath $path -Force
if($image.PSIsContainer-or$image.Length-le0){throw 'Original ordinary image required.'}
$cursor=$image;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse image ancestry refused.'};if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
$observed=Get-NativeManagedVhdObservation $path
[pscustomobject][ordered]@{schema_version=1;kind='native-managed-shadow-read-only-provider-probe';image_path=$path;image_file_bytes=$image.Length;queries=$observed;expected_virtual_disk_id='afd68132-7ad8-4a23-83a4-1cdcc20b927d';expected_virtual_bytes=55901683712;expected_logical_sector_bytes=512;expected_physical_sector_bytes=4096;attach_detach_or_attribute_changes_performed=$false;privileges_changed=$false;query_error_is_absence=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 8
