<# Read-only metadata diagnostic for the enrolled, recovered NTFS source.
   Emits JSON to stdout; the caller archives it outside the source volume. #>
[CmdletBinding()]
param([string]$Volume = 'D:')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-Source {
    $disk = Get-Disk -Number 0
    $part = Get-Partition -DiskNumber 0 -PartitionNumber 3
    $volumes = @($part | Get-Volume)
    $running = @(Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':'))
    if ($volumes.Count -ne 1 -or $running.Count -ne 1 -or $running[0].DiskNumber -eq 0 -or -not $running[0].IsBoot -or
        [guid]$disk.Guid -ne [guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26' -or $disk.PartitionStyle -cne 'GPT' -or
        $disk.IsOffline -or $disk.IsReadOnly -or $disk.IsBoot -or $disk.IsSystem -or $part.IsBoot -or $part.IsSystem -or
        [guid]$part.Guid -ne [guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f' -or
        $part.Offset -ne 331350016L -or $part.Size -ne 66236448768L) { throw 'Recovered source/current Windows disk identity differs.' }
    $v = $volumes[0]
    if ($v.FileSystem -cne 'NTFS' -or [string]$v.HealthStatus -cne 'Healthy' -or
        $v.Path -notmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z') { throw 'Healthy mounted NTFS volume GUID required.' }
    if ($Volume.TrimEnd('\') -ieq 'D:') {
        $letter = @(Get-Partition -DriveLetter D)
        if ($letter.Count -ne 1 -or $letter[0].DiskNumber -ne 0 -or $letter[0].PartitionNumber -ne 3) { throw 'D: is not the enrolled source.' }
    } elseif ($Volume.TrimEnd('\') -ine $v.Path.TrimEnd('\')) { throw 'Requested volume GUID is not the enrolled source.' }
    [pscustomobject]@{ volume_guid=$v.Path; disk_number=$disk.Number; disk_guid=[string]$disk.Guid; partition_number=$part.PartitionNumber;
        partition_guid=[string]$part.Guid; offset=$part.Offset; length=$part.Size; filesystem=$v.FileSystem; current_windows_disk=$running[0].DiskNumber }
}
$before = Assert-Source
if (-not ('NtfsNameCountReadOnlyI30' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NtfsNameCountReadOnlyI30 {
    const ulong Mask = 0x0000ffffffffffffUL;
    [StructLayout(LayoutKind.Explicit, Size=24)] struct Id { [FieldOffset(0)] public uint Size; [FieldOffset(4)] public uint Type; [FieldOffset(8)] public ulong Value; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,byte[] i,uint n,[Out] byte[] o,uint m,out uint r,IntPtr z);
    [DllImport("kernel32.dll", SetLastError=true)] static extern SafeFileHandle OpenFileById(SafeFileHandle h,ref Id id,uint a,uint s,IntPtr z,uint f);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,[Out] byte[] o,uint n);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint n,uint f);
    static void Need(bool ok,string reason) { if (!ok) throw new InvalidDataException(reason); }
    static void Win(bool ok,string op) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),op); }
    static ushort U16(byte[] b,int p) { return BitConverter.ToUInt16(b,p); }
    static uint U32(byte[] b,int p) { return BitConverter.ToUInt32(b,p); }
    static ulong U64(byte[] b,int p) { return BitConverter.ToUInt64(b,p); }
    static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-","").ToLowerInvariant(); }
    static byte[] Io(SafeFileHandle h,uint code,byte[] input,int capacity) {
        byte[] output=new byte[capacity]; uint used;
        Win(DeviceIoControl(h,code,input,input==null?0:(uint)input.Length,output,(uint)capacity,out used,IntPtr.Zero),"Read-only metadata query "+code.ToString("x"));
        Need(used<=capacity,"Oversized metadata response"); Array.Resize(ref output,(int)used); return output;
    }
    static Dictionary<string,object> Ref(ulong value) { return new Dictionary<string,object>{{"reference_hex",value.ToString("x16")},{"record_number",value&Mask},{"sequence_number",value>>48}}; }
    static bool Same(ushort[] a,ushort[] b) { if(a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    static List<Dictionary<string,object>> Leaf(byte[] b,int value,int size,out bool nonleaf) {
        Need(size>=32 && U32(b,value)==0x30 && U32(b,value+4)==1,"I30 root type/collation differs");
        nonleaf=b[value+28]!=0; List<Dictionary<string,object>> rows=new List<Dictionary<string,object>>(); if(nonleaf) return rows;
        int first=checked((int)U32(b,value+16)), end=checked((int)U32(b,value+20));
        Need(first>=16 && first%8==0 && end>=first && end<=size-16 && U32(b,value+24)>=end,"I30 INDEX_HEADER bounds differ");
        bool last=false; for(int p=value+16+first;p<value+16+end;) {
            Need(value+16+end-p>=16,"Truncated leaf index entry"); int n=U16(b,p+8), key=U16(b,p+10), flags=U16(b,p+12);
            Need(n>=16 && n%8==0 && n<=value+16+end-p && key<=n-16 && (flags&~3)==0,"Leaf index entry bounds/flags differ");
            if((flags&1)!=0) { nonleaf=true; return rows; }
            if((flags&2)!=0) { Need(key==0 && p+n==value+16+end,"Leaf end marker differs"); last=true; break; }
            int v=p+16; Need(key>=66 && b[v+64]>0 && 66+b[v+64]*2<=key,"Leaf FILE_NAME key bounds differ");
            int chars=b[v+64]; ushort[] units=new ushort[chars]; for(int i=0;i<chars;i++) units[i]=U16(b,v+66+i*2);
            rows.Add(new Dictionary<string,object>{{"child",Ref(U64(b,p))},{"parent",Ref(U64(b,v))},{"namespace",b[v+65]},{"name",Encoding.Unicode.GetString(b,v+66,chars*2)},{"name_utf16",units}}); p+=n;
        }
        Need(last,"Leaf index lacks final entry"); return rows;
    }
    public sealed class Record {
        public ulong record_number, base_reference; public ushort sequence_number, header_links, flags;
        public uint used_bytes; public string usa_status, raw_record_sha256; public ushort[] observed_sector_tails, usa_replacements;
        public List<Dictionary<string,object>> names=new List<Dictionary<string,object>>(), attribute_list=new List<Dictionary<string,object>>();
        public List<ulong> referenced_records=new List<ulong>(); public bool nonresident_attribute_list;
        public bool resident_i30_root, i30_nonleaf, i30_allocation;
        public List<Dictionary<string,object>> index_entries=new List<Dictionary<string,object>>();
    }
    static Record Read(SafeFileHandle volume,ulong number,int recordBytes) {
        byte[] response=Io(volume,0x90068,BitConverter.GetBytes(number),recordBytes+12);
        Need(response.Length>=12 && (U64(response,0)&Mask)==number && U32(response,8)==recordBytes && response.Length>=recordBytes+12,"FSCTL returned a different/truncated FILE record");
        byte[] b=new byte[recordBytes]; Array.Copy(response,12,b,0,b.Length);
        Need(Encoding.ASCII.GetString(b,0,4)=="FILE","FILE signature differs");
        Record r=new Record(); r.record_number=number;
        using (SHA256 hash=SHA256.Create()) r.raw_record_sha256=Hex(hash.ComputeHash(b));
        int usa=U16(b,4), count=U16(b,6); Need(usa>=42 && usa%2==0 && count==recordBytes/512+1 && usa+count*2<=recordBytes,"USA geometry differs");
        ushort usn=U16(b,usa); bool raw=true, fixedUp=true;
        r.observed_sector_tails=new ushort[count-1]; r.usa_replacements=new ushort[count-1];
        for (int i=1;i<count;i++) { ushort tail=U16(b,i*512-2), replacement=U16(b,usa+i*2); r.observed_sector_tails[i-1]=tail; r.usa_replacements[i-1]=replacement; raw &= tail==usn; fixedUp &= tail==replacement; }
        Need(raw||fixedUp,"Mixed/torn USA sector trailers; refusing interpretation");
        r.usa_status=raw?(fixedUp?"identical-before-and-after-fixup":"raw-fixup-applied-in-memory"):"already-fixed-up";
        if (raw) for (int i=1;i<count;i++) { b[i*512-2]=b[usa+i*2]; b[i*512-1]=b[usa+i*2+1]; }
        r.sequence_number=U16(b,16); r.header_links=U16(b,18); r.flags=U16(b,22); r.used_bytes=U32(b,24); r.base_reference=U64(b,32);
        int at=U16(b,20), used=checked((int)r.used_bytes);
        Need(r.sequence_number!=0 && (r.flags&1)!=0 && U32(b,28)==recordBytes && used<=recordBytes && at>=usa+count*2 && at>=48 && at%8==0 && at+4<=used,"FILE header/bounds differ");
        if (usa>=48) Need(U32(b,44)==number,"FILE header record number differs");
        bool ended=false;
        while (at+4<=used) {
            uint type=U32(b,at); if (type==0xffffffff) { ended=true; break; }
            Need(at+16<=used,"Truncated attribute header"); int length=checked((int)U32(b,at+4));
            Need(length>=24 && length%8==0 && length<=used-at && b[at+8]<=1,"Attribute length/residency differs");
            ushort instance=U16(b,at+14);
            int attributeName=U16(b,at+10); bool i30=(type==0x90 || type==0xa0) && b[at+9]==4 && attributeName>=16 && attributeName<=length-8 && Encoding.Unicode.GetString(b,at+attributeName,8)=="$I30";
            if(type==0xa0 && i30) r.i30_allocation=true;
            if(type==0x90 && i30) {
                Need(b[at+8]==0 && !r.resident_i30_root,"I30 root residency/uniqueness differs"); int size=checked((int)U32(b,at+16)), start=U16(b,at+20);
                Need(start>=24 && start<=length && size<=length-start,"Resident I30 root escapes record"); r.resident_i30_root=true; r.index_entries=Leaf(b,at+start,size,out r.i30_nonleaf);
            }
            if (type==0x20 && b[at+8]!=0) r.nonresident_attribute_list=true;
            if ((type==0x30 || type==0x20) && b[at+8]==0) {
                int size=checked((int)U32(b,at+16)), start=U16(b,at+20); Need(start>=24 && start<=length && size<=length-start,"Resident attribute value escapes its record"); int value=at+start;
                if (type==0x30) {
                    Need(size>=66 && b[value+64]>0 && 66+b[value+64]*2<=size,"FILE_NAME value length differs"); int chars=b[value+64]; ushort[] units=new ushort[chars];
                    for(int i=0;i<chars;i++) units[i]=U16(b,value+66+i*2);
                    r.names.Add(new Dictionary<string,object>{{"origin_record",number},{"origin_sequence",r.sequence_number},{"attribute_instance",instance},{"parent",Ref(U64(b,value))},{"namespace",b[value+65]},{"name",Encoding.Unicode.GetString(b,value+66,chars*2)},{"name_utf16",units}});
                } else for (int p=value;p<value+size;) {
                    Need(value+size-p>=26,"Truncated resident ATTRIBUTE_LIST entry"); int n=U16(b,p+4), chars=b[p+6], nameAt=b[p+7];
                    Need(n>=26 && n%8==0 && n<=value+size-p && (chars==0 || nameAt>=26 && nameAt+chars*2<=n),"ATTRIBUTE_LIST entry bounds differ");
                    ulong reference=U64(b,p+16); Need((reference>>48)!=0,"ATTRIBUTE_LIST reference has no sequence"); r.referenced_records.Add(reference);
                    r.attribute_list.Add(new Dictionary<string,object>{{"type",U32(b,p)},{"lowest_vcn",U64(b,p+8)},{"reference",Ref(reference)},{"instance",U16(b,p+24)},{"name",chars==0?"":Encoding.Unicode.GetString(b,p+nameAt,chars*2)}}); p+=n;
                }
            }
            at+=length;
        }
        Need(ended,"FILE attributes lack an end marker"); return r;
    }
    public static object Observe(string root) {
        using(SafeFileHandle volume=CreateFileW(root.TrimEnd('\\'),0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero)) {
            Win(!volume.IsInvalid,"Open enrolled volume read-only");
            byte[] extents=Io(volume,0x560000,null,64);
            Need(extents.Length>=32 && U32(extents,0)==1 && U32(extents,8)==0 && U64(extents,16)==331350016UL && U64(extents,24)==66236448768UL,"Held volume extent is not enrolled disk0/partition3");
            byte[] geometry=Io(volume,0x90064,null,128); Need(geometry.Length>=96 && U32(geometry,40)==512,"Expected 512-byte NTFS sectors");
            int recordBytes=checked((int)U32(geometry,48)); Need(recordBytes>=512 && recordBytes<=65536 && recordBytes%512==0,"FILE record size outside diagnostic bound");
            Record first=Read(volume,48922,recordBytes); Need(first.base_reference==0,"Requested FILE is an extension"); ulong identity=48922UL|((ulong)first.sequence_number<<48);
            List<Record> records=new List<Record>(); Queue<Record> todo=new Queue<Record>(); Dictionary<ulong,ushort> seen=new Dictionary<ulong,ushort>();
            todo.Enqueue(first); seen.Add(48922,first.sequence_number); bool complete=true;
            while(todo.Count!=0) {
                Record r=todo.Dequeue(); records.Add(r); complete &= !r.nonresident_attribute_list;
                foreach(ulong reference in r.referenced_records) {
                    ulong n=reference&Mask; ushort seq=(ushort)(reference>>48), old;
                    if(seen.TryGetValue(n,out old)) { Need(old==seq,"Conflicting ATTRIBUTE_LIST sequences"); continue; }
                    Need(seen.Count<128,"ATTRIBUTE_LIST exceeds 128-record diagnostic bound"); Record next=Read(volume,n,recordBytes);
                    Need(next.sequence_number==seq && next.base_reference==identity,"Extension sequence/base reference differs"); seen.Add(n,seq); todo.Enqueue(next);
                }
            }
            List<object> parents=new List<object>(), comparisons=new List<object>();
            foreach(ulong parentNumber in new ulong[]{34563,4826}) {
                Record parent=Read(volume,parentNumber,recordBytes); Need(parent.sequence_number==1 && (parent.flags&2)!=0 && parent.base_reference==0,"Expected parent directory identity differs");
                bool leafComplete=parent.resident_i30_root && !parent.i30_nonleaf && !parent.i30_allocation && !parent.nonresident_attribute_list && parent.referenced_records.Count==0;
                parents.Add(new Dictionary<string,object>{{"parent_record",parentNumber},{"parent_sequence",parent.sequence_number},{"flags",parent.flags},{"usa_status",parent.usa_status},{"coverage_complete",leafComplete},{"has_index_allocation",parent.i30_allocation},{"nonleaf",parent.i30_nonleaf},{"entries",parent.index_entries}});
                foreach(Record record in records) foreach(Dictionary<string,object> name in record.names) {
                    Dictionary<string,object> expectedParent=(Dictionary<string,object>)name["parent"]; if((ulong)expectedParent["record_number"]!=parentNumber) continue;
                    Need((ulong)expectedParent["sequence_number"]==parent.sequence_number,"FILE_NAME parent sequence differs"); int matches=0;
                    foreach(Dictionary<string,object> entry in parent.index_entries) {
                        Dictionary<string,object> child=(Dictionary<string,object>)entry["child"], ep=(Dictionary<string,object>)entry["parent"];
                        if((ulong)child["record_number"]==48922 && (ulong)child["sequence_number"]==first.sequence_number && (ulong)ep["record_number"]==parentNumber && (ulong)ep["sequence_number"]==parent.sequence_number && (byte)entry["namespace"]==(byte)name["namespace"] && Same((ushort[])entry["name_utf16"],(ushort[])name["name_utf16"])) matches++;
                    }
                    comparisons.Add(new Dictionary<string,object>{{"expected_name",name},{"index_match_count",matches},{"coverage_complete",leafComplete},{"exactly_one_match",leafComplete && matches==1}});
                }
            }
            Dictionary<string,object> native=new Dictionary<string,object>(); Id id=new Id{Size=24,Type=0,Value=identity};
            using(SafeFileHandle file=OpenFileById(volume,ref id,0x80,7,IntPtr.Zero,0x02200000)) {
                if(file.IsInvalid) native.Add("error",new Win32Exception(Marshal.GetLastWin32Error(),"OpenFileById read-attributes/no-follow").Message);
                else { byte[] info=new byte[24]; if(GetFileInformationByHandleEx(file,1,info,24)) { native.Add("number_of_links",U32(info,16)); native.Add("delete_pending",info[20]!=0); native.Add("is_directory",info[21]!=0); } else native.Add("standard_info_error",Marshal.GetLastWin32Error());
                    StringBuilder path=new StringBuilder(32768); uint n=GetFinalPathNameByHandleW(file,path,(uint)path.Capacity,1);
                    if(n>0 && n<path.Capacity) { Need(path.ToString().StartsWith(root,StringComparison.OrdinalIgnoreCase),"Opened FILE escaped source volume GUID"); native.Add("final_path",path.ToString()); } else native.Add("final_path_error",n==0?Marshal.GetLastWin32Error():122);
                }
            }
            return new Dictionary<string,object>{{"record_number",48922},{"file_reference",Ref(identity)},{"record_bytes",recordBytes},{"resident_attribute_list_coverage_complete",complete},{"records",records},{"parent_indexes",parents},{"name_index_comparisons",comparisons},{"native_file_standard_info",native},{"payload_read_calls",0},{"source_write_calls",0}};
        }
    }
}
'@
}
$observation = [NtfsNameCountReadOnlyI30]::Observe($before.volume_guid)
$after = Assert-Source
if ($after.volume_guid -ine $before.volume_guid) { throw 'Source volume route changed during observation.' }
[ordered]@{schema_version=1;kind='readonly-enrolled-ntfs-file-name-count';observed_utc=[DateTime]::UtcNow.ToString('o');before=$before;observation=$observation;after=$after} | ConvertTo-Json -Depth 16
