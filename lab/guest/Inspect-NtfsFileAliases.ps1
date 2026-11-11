<# Read-only metadata diagnostic for an enrolled, recovered NTFS source.
   Run only after actual conversion cleanup is terminal and source restoration
   has been proved. Emits bounded JSON to stdout; archive outside source disk0.
   Does not change flags, mounts, names, payloads, boot selection or recovery. #>
[CmdletBinding()]
param([string]$Volume = 'D:', [ValidateRange(0,281474976710655)][UInt64]$RecordNumber = 35049)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-Source {
    $disk = Get-Disk -Number 0
    $part = Get-Partition -DiskNumber 0 -PartitionNumber 3
    $volumes = @($part | Get-Volume)
    $running = @(Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':'))
    if ($volumes.Count -ne 1 -or $running.Count -ne 1 -or $running[0].DiskNumber -eq 0 -or -not $running[0].IsBoot -or
        [guid]$disk.Guid -ne [guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26' -or $disk.PartitionStyle -cne 'GPT' -or
        [string]$disk.UniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or $disk.Size -ne 64GB -or
        $disk.IsOffline -ne $false -or $disk.IsReadOnly -ne $false -or $disk.IsBoot -ne $false -or $disk.IsSystem -ne $false -or
        $part.IsBoot -ne $false -or $part.IsSystem -ne $false -or $part.IsOffline -ne $false -or $part.IsReadOnly -ne $false -or
        [guid]$part.Guid -ne [guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f' -or
        $part.Offset -ne 331350016L -or $part.Size -ne 66236448768L) { throw 'Recovered source/current Windows disk identity differs.' }
    $v = $volumes[0]
    if ($v.FileSystem -cne 'NTFS' -or [string]$v.HealthStatus -cne 'Healthy' -or $v.AllocationUnitSize -ne 4096 -or
        $v.Path -notmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z') { throw 'Healthy mounted NTFS volume GUID/4KiB clusters required.' }
    if ($Volume.TrimEnd('\') -ieq 'D:') {
        $letter = @(Get-Partition -DriveLetter D)
        if ($letter.Count -ne 1 -or $letter[0].DiskNumber -ne 0 -or $letter[0].PartitionNumber -ne 3) { throw 'D: is not the enrolled source.' }
    } elseif ($Volume.TrimEnd('\') -ine $v.Path.TrimEnd('\')) { throw 'Requested volume GUID is not the enrolled source.' }
    [pscustomobject]@{ volume_guid=$v.Path; disk_number=$disk.Number; disk_guid=[string]$disk.Guid; disk_unique_id=[string]$disk.UniqueId;
        partition_number=$part.PartitionNumber; partition_guid=[string]$part.Guid; offset=$part.Offset; length=$part.Size;
        filesystem=$v.FileSystem; cluster_bytes=$v.AllocationUnitSize; current_windows_disk=$running[0].DiskNumber }
}
$before = Assert-Source
if (-not ('NtfsFileAliasesReadOnlyV1' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NtfsFileAliasesReadOnlyV1 {
    const ulong Mask=0x0000ffffffffffffUL;
    const uint ReadAttributes=0x80, NoFollowDirectory=0x02200000;
    static int fileRecordQueries, ioctlQueries, nativeOpens, mappingQueries;
    static UnicodeEncoding Unicode=new UnicodeEncoding(false,false,true);
    [StructLayout(LayoutKind.Explicit,Size=24)] struct Id { [FieldOffset(0)] public uint Size; [FieldOffset(4)] public uint Type; [FieldOffset(8)] public ulong Value; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,byte[] i,uint n,[Out] byte[] o,uint m,out uint r,IntPtr z);
    [DllImport("kernel32.dll",SetLastError=true)] static extern SafeFileHandle OpenFileById(SafeFileHandle h,ref Id id,uint a,uint s,IntPtr z,uint f);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,[Out] byte[] o,uint n);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint n,uint f);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetLongPathNameW(string p,StringBuilder o,uint n);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetShortPathNameW(string p,StringBuilder o,uint n);
    [DllImport("ntdll.dll")] static extern uint NtQueryEaFile(SafeFileHandle file,out IoStatus io,[Out] byte[] buffer,uint length,[MarshalAs(UnmanagedType.U1)] bool single,IntPtr list,uint listLength,IntPtr index,[MarshalAs(UnmanagedType.U1)] bool restart);
    static void Need(bool ok,string reason) { if(!ok) throw new InvalidDataException(reason); }
    static void Win(bool ok,string op) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),op); }
    static ushort U16(byte[] b,int p) { return BitConverter.ToUInt16(b,p); }
    static uint U32(byte[] b,int p) { return BitConverter.ToUInt32(b,p); }
    static ulong U64(byte[] b,int p) { return BitConverter.ToUInt64(b,p); }
    static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-","").ToLowerInvariant(); }
    static byte[] Io(SafeFileHandle h,uint code,byte[] input,int capacity) {
        Need(capacity>0 && capacity<=65548,"Metadata ioctl allocation exceeds bound"); ioctlQueries++;
        byte[] output=new byte[capacity]; uint used;
        Win(DeviceIoControl(h,code,input,input==null?0:(uint)input.Length,output,(uint)capacity,out used,IntPtr.Zero),"Read-only metadata query "+code.ToString("x"));
        Need(used<=capacity,"Oversized metadata response"); Array.Resize(ref output,(int)used); return output;
    }
    static Dictionary<string,object> Ref(ulong value) { return new Dictionary<string,object>{{"reference_hex",value.ToString("x16")},{"record_number",value&Mask},{"sequence_number",value>>48}}; }
    static bool Same(ushort[] a,ushort[] b) { if(a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    static bool Equal(byte[] a,byte[] b) { if(a==null || b==null || a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    static List<Dictionary<string,object>> Leaf(byte[] b,int value,int size,out bool nonleaf) {
        Need(size>=32 && U32(b,value)==0x30 && U32(b,value+4)==1,"I30 root type/collation differs");
        nonleaf=b[value+28]!=0; List<Dictionary<string,object>> rows=new List<Dictionary<string,object>>(); if(nonleaf) return rows;
        int first=checked((int)U32(b,value+16)),end=checked((int)U32(b,value+20));
        Need(first>=16 && first%8==0 && end>=first && end<=size-16 && U32(b,value+24)>=end,"I30 INDEX_HEADER bounds differ");
        bool last=false; for(int p=value+16+first;p<value+16+end;) {
            Need(value+16+end-p>=16,"Truncated leaf index entry"); int n=U16(b,p+8),key=U16(b,p+10),flags=U16(b,p+12);
            Need(n>=16 && n%8==0 && n<=value+16+end-p && key<=n-16 && (flags&~3)==0,"Leaf index entry bounds/flags differ");
            if((flags&1)!=0) { nonleaf=true; return rows; }
            if((flags&2)!=0) { Need(key==0 && p+n==value+16+end,"Leaf end marker differs"); last=true; break; }
            int v=p+16; Need(key>=66 && b[v+64]>0 && 66+b[v+64]*2==key && b[v+65]<=3,"Leaf FILE_NAME key bounds differ");
            int chars=b[v+64]; ushort[] units=new ushort[chars]; for(int i=0;i<chars;i++) units[i]=U16(b,v+66+i*2);
            rows.Add(new Dictionary<string,object>{{"child",Ref(U64(b,p))},{"parent",Ref(U64(b,v))},{"namespace",b[v+65]},{"name",Unicode.GetString(b,v+66,chars*2)},{"name_utf16",units}}); p+=n;
        }
        Need(last,"Leaf index lacks final entry"); return rows;
    }
    public sealed class Record {
        public ulong record_number,base_reference; public ushort sequence_number,header_links,flags;
        public uint used_bytes; public string usa_status,raw_record_sha256; public ushort[] observed_sector_tails,usa_replacements;
        public List<Dictionary<string,object>> names=new List<Dictionary<string,object>>(),attribute_list=new List<Dictionary<string,object>>(),attributes=new List<Dictionary<string,object>>();
        public List<ulong> referenced_records=new List<ulong>(); public bool nonresident_attribute_list,nonresident_file_name;
        public bool resident_i30_root,i30_nonleaf,i30_allocation; public string resident_i30_root_hex;
        public List<Dictionary<string,object>> index_entries=new List<Dictionary<string,object>>();
    }
    static Record Read(SafeFileHandle volume,ulong number,int recordBytes) {
        Need(++fileRecordQueries<=1024,"Diagnostic exceeds 1024 bounded FILE-record queries");
        byte[] response=Io(volume,0x90068,BitConverter.GetBytes(number),recordBytes+12);
        Need(response.Length>=12 && (U64(response,0)&Mask)==number && U32(response,8)==recordBytes && response.Length>=recordBytes+12,"FSCTL returned a different/truncated FILE record");
        byte[] b=new byte[recordBytes]; Array.Copy(response,12,b,0,b.Length); Need(Encoding.ASCII.GetString(b,0,4)=="FILE","FILE signature differs");
        Record r=new Record(); r.record_number=number; using(SHA256 hash=SHA256.Create()) r.raw_record_sha256=Hex(hash.ComputeHash(b));
        int usa=U16(b,4),count=U16(b,6); Need(usa>=42 && usa%2==0 && count==recordBytes/512+1 && usa+count*2<=recordBytes,"USA geometry differs");
        ushort usn=U16(b,usa); bool raw=true,fixedUp=true; r.observed_sector_tails=new ushort[count-1]; r.usa_replacements=new ushort[count-1];
        for(int i=1;i<count;i++) { ushort tail=U16(b,i*512-2),replacement=U16(b,usa+i*2); r.observed_sector_tails[i-1]=tail; r.usa_replacements[i-1]=replacement; raw &= tail==usn; fixedUp &= tail==replacement; }
        Need(raw||fixedUp,"Mixed/torn USA sector trailers; refusing interpretation"); r.usa_status=raw?(fixedUp?"identical-before-and-after-fixup":"raw-fixup-applied-in-memory"):"already-fixed-up";
        if(raw) for(int i=1;i<count;i++) { b[i*512-2]=b[usa+i*2]; b[i*512-1]=b[usa+i*2+1]; }
        r.sequence_number=U16(b,16); r.header_links=U16(b,18); r.flags=U16(b,22); r.used_bytes=U32(b,24); r.base_reference=U64(b,32);
        int at=U16(b,20),used=checked((int)r.used_bytes);
        Need(r.sequence_number!=0 && (r.flags&1)!=0 && U32(b,28)==recordBytes && used<=recordBytes && at>=usa+count*2 && at>=48 && at%8==0 && at+4<=used,"FILE header/bounds differ");
        if(usa>=48) Need(U32(b,44)==number,"FILE header record number differs"); bool ended=false;
        while(at+4<=used) {
            uint type=U32(b,at); if(type==0xffffffff) { ended=true; break; }
            Need(at+16<=used,"Truncated attribute header"); int length=checked((int)U32(b,at+4)); Need(length>=24 && length%8==0 && length<=used-at && b[at+8]<=1,"Attribute length/residency differs");
            ushort instance=U16(b,at+14); int attributeName=U16(b,at+10),attributeChars=b[at+9];
            Need(b[at+8]==0 || length>=64,"Nonresident attribute header is truncated");
            Need(attributeChars==0 || (attributeName>=(b[at+8]==0?24:64) && attributeName<=length-attributeChars*2),"Attribute name escapes its header");
            r.attributes.Add(new Dictionary<string,object>{{"type",type},{"instance",instance},{"nonresident",b[at+8]!=0},{"lowest_vcn",b[at+8]==0?0UL:U64(b,at+16)},{"name",attributeChars==0?"":Unicode.GetString(b,at+attributeName,attributeChars*2)}});
            bool i30=(type==0x90 || type==0xa0) && b[at+9]==4 && attributeName>=16 && attributeName<=length-8 && Unicode.GetString(b,at+attributeName,8)=="$I30";
            if(type==0xa0 && i30) r.i30_allocation=true;
            if(type==0x90 && i30) {
                Need(b[at+8]==0 && !r.resident_i30_root,"I30 root residency/uniqueness differs"); int size=checked((int)U32(b,at+16)),start=U16(b,at+20);
                Need(start>=24 && start<=length && size<=length-start,"Resident I30 root escapes record"); r.resident_i30_root=true;
                byte[] root=new byte[size]; Array.Copy(b,at+start,root,0,size); r.resident_i30_root_hex=Hex(root); r.index_entries=Leaf(b,at+start,size,out r.i30_nonleaf);
            }
            if(type==0x20 && b[at+8]!=0) r.nonresident_attribute_list=true;
            if(type==0x30 && b[at+8]!=0) r.nonresident_file_name=true;
            if((type==0x30 || type==0x20) && b[at+8]==0) {
                int size=checked((int)U32(b,at+16)),start=U16(b,at+20); Need(start>=24 && start<=length && size<=length-start,"Resident attribute value escapes its record"); int value=at+start;
                if(type==0x30) {
                    Need(size>=66 && b[value+64]>0 && 66+b[value+64]*2==size && b[value+65]<=3,"FILE_NAME value length differs"); int chars=b[value+64]; ushort[] units=new ushort[chars];
                    for(int i=0;i<chars;i++) units[i]=U16(b,value+66+i*2);
                    r.names.Add(new Dictionary<string,object>{{"origin_record",number},{"origin_sequence",r.sequence_number},{"attribute_instance",instance},{"parent",Ref(U64(b,value))},{"namespace",b[value+65]},{"name",Unicode.GetString(b,value+66,chars*2)},{"name_utf16",units}});
                } else for(int p=value;p<value+size;) {
                    Need(value+size-p>=26,"Truncated resident ATTRIBUTE_LIST entry"); int n=U16(b,p+4),chars=b[p+6],nameAt=b[p+7];
                    Need(n>=26 && n%8==0 && n<=value+size-p && (chars==0 || nameAt>=26 && nameAt+chars*2<=n),"ATTRIBUTE_LIST entry bounds differ"); ulong reference=U64(b,p+16); Need((reference>>48)!=0,"ATTRIBUTE_LIST reference has no sequence");
                    r.referenced_records.Add(reference); r.attribute_list.Add(new Dictionary<string,object>{{"type",U32(b,p)},{"lowest_vcn",U64(b,p+8)},{"reference",Ref(reference)},{"instance",U16(b,p+24)},{"name",chars==0?"":Unicode.GetString(b,p+nameAt,chars*2)}}); p+=n;
                }
            }
            at+=length;
        }
        Need(ended,"FILE attributes lack an end marker"); return r;
    }
    static List<Record> Gather(SafeFileHandle volume,Record first,int recordBytes,out bool complete) {
        Need(first.base_reference==0,"Requested FILE is an extension"); ulong identity=first.record_number|((ulong)first.sequence_number<<48);
        List<Record> records=new List<Record>(); Queue<Record> todo=new Queue<Record>(); Dictionary<ulong,ushort> seen=new Dictionary<ulong,ushort>();
        todo.Enqueue(first); seen.Add(first.record_number,first.sequence_number); complete=true;
        while(todo.Count!=0) {
            Record r=todo.Dequeue(); records.Add(r); complete &= !r.nonresident_attribute_list && !r.nonresident_file_name;
            foreach(ulong reference in r.referenced_records) {
                ulong n=reference&Mask; ushort seq=(ushort)(reference>>48),old;
                if(seen.TryGetValue(n,out old)) { Need(old==seq,"Conflicting ATTRIBUTE_LIST sequences"); continue; }
                Need(seen.Count<128,"ATTRIBUTE_LIST exceeds 128-record diagnostic bound"); Record next=Read(volume,n,recordBytes);
                Need(next.sequence_number==seq && next.base_reference==identity,"Extension sequence/base reference differs"); seen.Add(n,seq); todo.Enqueue(next);
            }
        }
        // For resident lists, establish exact FILE_NAME-entry/attribute
        // membership rather than treating a list of record references as proof.
        List<Dictionary<string,object>> listNames=new List<Dictionary<string,object>>();
        foreach(Record origin in records) foreach(Dictionary<string,object> entry in origin.attribute_list) {
            Dictionary<string,object> reference=(Dictionary<string,object>)entry["reference"]; int matches=0;
            foreach(Record r in records) if(r.record_number==(ulong)reference["record_number"] && r.sequence_number==(ulong)reference["sequence_number"])
                foreach(Dictionary<string,object> attribute in r.attributes)
                    if((uint)attribute["type"]==(uint)entry["type"] && (ushort)attribute["instance"]==(ushort)entry["instance"]
                        && (ulong)attribute["lowest_vcn"]==(ulong)entry["lowest_vcn"] && (string)attribute["name"]==(string)entry["name"]) matches++;
            entry["observed_attribute_match_count"]=matches; complete &= matches==1;
            if((uint)entry["type"]==0x30) listNames.Add(entry);
        }
        if(listNames.Count!=0) {
            foreach(Dictionary<string,object> entry in listNames) {
                Dictionary<string,object> reference=(Dictionary<string,object>)entry["reference"]; int matches=0;
                foreach(Record r in records) foreach(Dictionary<string,object> name in r.names)
                    if(r.record_number==(ulong)reference["record_number"] && r.sequence_number==(ulong)reference["sequence_number"]
                        && (ushort)name["attribute_instance"]==(ushort)entry["instance"] && (ulong)entry["lowest_vcn"]==0 && (string)entry["name"]=="") matches++;
                complete &= matches==1;
            }
            foreach(Record r in records) foreach(Dictionary<string,object> name in r.names) {
                int matches=0; foreach(Dictionary<string,object> entry in listNames) {
                    Dictionary<string,object> reference=(Dictionary<string,object>)entry["reference"];
                    if(r.record_number==(ulong)reference["record_number"] && r.sequence_number==(ulong)reference["sequence_number"]
                        && (ushort)name["attribute_instance"]==(ushort)entry["instance"] && (ulong)entry["lowest_vcn"]==0 && (string)entry["name"]=="") matches++;
                }
                complete &= matches==1;
            }
        } else if(records.Count!=1 || records[0].attribute_list.Count!=0) {
            foreach(Record r in records) if(r.names.Count!=0) complete=false;
        }
        return records;
    }
    static string FinalPath(SafeFileHandle file,string root,Dictionary<string,object> row,string key,uint flags) {
        StringBuilder path=new StringBuilder(32768); uint n=GetFinalPathNameByHandleW(file,path,(uint)path.Capacity,flags);
        if(n==0 || n>=path.Capacity) { row[key+"_error"]=n==0?Marshal.GetLastWin32Error():122; return null; }
        string value=path.ToString(); Need(value.StartsWith(root,StringComparison.OrdinalIgnoreCase) || value.Equals(root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase),"Opened metadata object escaped source volume GUID"); row[key]=value; return value;
    }
    static byte[] Native(SafeFileHandle file,string root,Dictionary<string,object> row) {
        byte[] identity=new byte[24]; if(GetFileInformationByHandleEx(file,18,identity,24)) { row["file_id_info_hex"]=Hex(identity); row["volume_serial_hex"]=U64(identity,0).ToString("x16"); row["file_id_low64"]=Ref(U64(identity,8)); }
        else { row["file_id_info_error"]=Marshal.GetLastWin32Error(); identity=null; }
        byte[] standard=new byte[24]; if(GetFileInformationByHandleEx(file,1,standard,24)) { row["number_of_links"]=U32(standard,16); row["delete_pending"]=standard[20]!=0; row["is_directory"]=standard[21]!=0; }
        else row["standard_info_error"]=Marshal.GetLastWin32Error();
        byte[] tag=new byte[8]; if(GetFileInformationByHandleEx(file,9,tag,8)) { row["file_attributes"]=U32(tag,0); row["reparse_tag"]=U32(tag,4); row["is_reparse_point"]=(U32(tag,0)&0x400)!=0; }
        else row["attribute_tag_info_error"]=Marshal.GetLastWin32Error();
        FinalPath(file,root,row,"normalized_path",1); FinalPath(file,root,row,"opened_path",9); return identity;
    }
    static Dictionary<string,object> Map(string path,bool shortPath) {
        Need(++mappingQueries<=4096,"Path mapping query bound exceeded"); StringBuilder buffer=new StringBuilder(32768);
        uint n=shortPath?GetShortPathNameW(path,buffer,(uint)buffer.Capacity):GetLongPathNameW(path,buffer,(uint)buffer.Capacity);
        Dictionary<string,object> row=new Dictionary<string,object>{{"input",path},{"api",shortPath?"GetShortPathNameW":"GetLongPathNameW"}};
        if(n==0 || n>=buffer.Capacity) row["error"]=n==0?Marshal.GetLastWin32Error():122; else row["result"]=buffer.ToString(); return row;
    }
    static Dictionary<string,object> QueryEa(SafeFileHandle volume,ulong identity,byte[] sourceId,string root) {
        Dictionary<string,object> row=new Dictionary<string,object>{{"api","NtQueryEaFile"},{"access_mask",ReadAttributes|8U},{"buffer_capacity",65536},{"return_single_entry",false},{"restart_scan",true},{"ea_name_filter",false},{"set_ea_calls",0}};
        Id id=new Id{Size=24,Type=0,Value=identity}; nativeOpens++;
        using(SafeFileHandle file=OpenFileById(volume,ref id,ReadAttributes|8U,7,IntPtr.Zero,NoFollowDirectory)) {
            if(file.IsInvalid) { row["open_error"]=Marshal.GetLastWin32Error(); return row; }
            byte[] actual=Native(file,root,row); bool same=Equal(actual,sourceId); row["same_file_id_info_as_base"]=same; Need(same,"EA-read handle differs from requested source FILE identity");
            byte[] buffer=new byte[65536]; IoStatus io; uint status=NtQueryEaFile(file,out io,buffer,(uint)buffer.Length,false,IntPtr.Zero,0,IntPtr.Zero,true);
            row["ntstatus_hex"]=status.ToString("x8"); row["io_status_hex"]=unchecked((uint)io.Status.ToInt64()).ToString("x8"); ulong used=io.Information.ToUInt64(); row["io_information_bytes"]=used;
            Need(used<=(ulong)buffer.Length,"NtQueryEaFile returned an impossible metadata byte count"); Array.Resize(ref buffer,(int)used); row["raw_returned_bytes_hex"]=Hex(buffer);
            row["success"]=status==0; row["all_eas_returned"]=status==0; List<object> entries=new List<object>();
            if(status==0) {
                try {
                    int at=0,count=0; while(at<buffer.Length) {
                        Need(++count<=1024 && buffer.Length-at>=8,"EA metadata entry count/header exceeds bound"); uint next=U32(buffer,at); int nameLength=buffer[at+5],valueLength=U16(buffer,at+6),minimum=checked(9+nameLength+valueLength);
                        Need(nameLength>0 && minimum<=buffer.Length-at && buffer[at+8+nameLength]==0,"EA metadata name/value escapes returned bytes");
                        if(next!=0) Need(next%4==0 && next>=minimum && next<=buffer.Length-at,"EA next-entry offset escapes returned bytes");
                        byte[] name=new byte[nameLength],value=new byte[valueLength]; Array.Copy(buffer,at+8,name,0,nameLength); Array.Copy(buffer,at+9+nameLength,value,0,valueLength);
                        entries.Add(new Dictionary<string,object>{{"offset",at},{"next_entry_offset",next},{"flags",buffer[at+4]},{"name",Encoding.ASCII.GetString(name)},{"name_bytes_hex",Hex(name)},{"value_bytes",valueLength},{"value_hex",Hex(value)}});
                        if(next==0) { row["trailing_bytes_after_last_entry"]=buffer.Length-at-minimum; at=buffer.Length; } else at=checked(at+(int)next);
                    }
                    row["parse_complete"]=true;
                } catch(Exception error) { row["parse_complete"]=false; row["parse_error"]=error.Message; }
                row["entries"]=entries;
            }
            return row;
        }
    }
    static bool Match(Dictionary<string,object> name,Dictionary<string,object> entry,ulong identity,ulong parent) {
        Dictionary<string,object> child=(Dictionary<string,object>)entry["child"],ep=(Dictionary<string,object>)entry["parent"];
        return (ulong)child["record_number"]==(identity&Mask) && (ulong)child["sequence_number"]==(identity>>48)
            && (ulong)ep["record_number"]==(parent&Mask) && (ulong)ep["sequence_number"]==(parent>>48)
            && (byte)entry["namespace"]==(byte)name["namespace"] && Same((ushort[])entry["name_utf16"],(ushort[])name["name_utf16"]);
    }
    public static object Observe(string root,ulong number) {
        fileRecordQueries=ioctlQueries=nativeOpens=mappingQueries=0; Need(number<=Mask,"FILE record exceeds NTFS reference width");
        using(SafeFileHandle volume=CreateFileW(root.TrimEnd('\\'),0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero)) {
            Win(!volume.IsInvalid,"Open enrolled volume read-only"); byte[] extents=Io(volume,0x560000,null,64);
            Need(extents.Length>=32 && U32(extents,0)==1 && U32(extents,8)==0 && U64(extents,16)==331350016UL && U64(extents,24)==66236448768UL,"Held volume extent is not enrolled disk0/partition3");
            byte[] geometry=Io(volume,0x90064,null,128); Need(geometry.Length>=96 && U32(geometry,40)==512 && U32(geometry,44)==4096,"Expected 512-byte sectors/4KiB NTFS clusters");
            int recordBytes=checked((int)U32(geometry,48)); Need(recordBytes>=512 && recordBytes<=65536 && recordBytes%512==0,"FILE record size outside diagnostic bound");
            Record first=Read(volume,number,recordBytes); bool complete; List<Record> records=Gather(volume,first,recordBytes,out complete); ulong identity=number|((ulong)first.sequence_number<<48);
            List<Dictionary<string,object>> names=new List<Dictionary<string,object>>(); foreach(Record record in records) names.AddRange(record.names);
            Need(names.Count>0 && names.Count<=1024,"FILE_NAME diagnostic count outside bound"); SortedDictionary<ulong,ushort> parentIds=new SortedDictionary<ulong,ushort>();
            foreach(Dictionary<string,object> name in names) { Dictionary<string,object> p=(Dictionary<string,object>)name["parent"]; ulong pn=(ulong)p["record_number"]; ushort seq=checked((ushort)(ulong)p["sequence_number"]),old; Need(seq!=0,"FILE_NAME parent has no sequence"); if(parentIds.TryGetValue(pn,out old)) Need(old==seq,"Conflicting FILE_NAME parent sequences"); else parentIds.Add(pn,seq); }
            Need(parentIds.Count<=128,"Parent count exceeds diagnostic bound"); Dictionary<string,object> native=new Dictionary<string,object>(); byte[] sourceId; Id id=new Id{Size=24,Type=0,Value=identity}; nativeOpens++;
            using(SafeFileHandle file=OpenFileById(volume,ref id,ReadAttributes,7,IntPtr.Zero,NoFollowDirectory)) { Win(!file.IsInvalid,"Open requested FILE by ID/read attributes"); sourceId=Native(file,root,native); Need(sourceId!=null && U64(sourceId,8)==identity && U64(sourceId,16)==0,"Opened source FileIdInfo does not match complete NTFS reference"); }
            Dictionary<string,object> nativeEa=QueryEa(volume,identity,sourceId,root);
            List<object> parents=new List<object>(),comparisons=new List<object>(),reverse=new List<object>(),paths=new List<object>(); List<Record> bookends=new List<Record>(records);
            foreach(KeyValuePair<ulong,ushort> parentId in parentIds) {
                ulong parentReference=parentId.Key|((ulong)parentId.Value<<48); Record parent=Read(volume,parentId.Key,recordBytes);
                Need(parent.sequence_number==parentId.Value && (parent.flags&2)!=0 && parent.base_reference==0,"Expected parent directory identity differs"); bool parentComplete;
                List<Record> parentRecords=Gather(volume,parent,recordBytes,out parentComplete); bookends.AddRange(parentRecords); int roots=0; bool allocation=false,nonleaf=false; List<Dictionary<string,object>> entries=new List<Dictionary<string,object>>();
                foreach(Record p in parentRecords) { if(p.resident_i30_root) { roots++; entries.AddRange(p.index_entries); } allocation |= p.i30_allocation; nonleaf |= p.i30_nonleaf; }
                bool leafComplete=parentComplete && roots==1 && !allocation && !nonleaf;
                Dictionary<string,object> parentNative=new Dictionary<string,object>(); string parentPath=null; Id pid=new Id{Size=24,Type=0,Value=parentReference}; nativeOpens++;
                using(SafeFileHandle file=OpenFileById(volume,ref pid,ReadAttributes,7,IntPtr.Zero,NoFollowDirectory)) {
                    if(file.IsInvalid) parentNative["open_error"]=Marshal.GetLastWin32Error(); else {
                        byte[] actual=Native(file,root,parentNative); Need(actual!=null && U64(actual,8)==parentReference && U64(actual,16)==0,"Opened parent FileIdInfo differs from FILE_NAME reference");
                        Need(parentNative.ContainsKey("is_directory") && (bool)parentNative["is_directory"] && parentNative.ContainsKey("is_reparse_point") && !(bool)parentNative["is_reparse_point"],"Native parent is not a plain directory");
                        if(parentNative.ContainsKey("normalized_path")) parentPath=(string)parentNative["normalized_path"];
                    }
                }
                parents.Add(new Dictionary<string,object>{{"parent_reference",Ref(parentReference)},{"attribute_list_coverage_complete",parentComplete},{"records",parentRecords},{"coverage_complete",leafComplete},{"resident_i30_roots",roots},{"has_index_allocation",allocation},{"nonleaf",nonleaf},{"entries",entries},{"native",parentNative},{"nonresident_i30_read",false}});
                foreach(Dictionary<string,object> name in names) {
                    Dictionary<string,object> expectedParent=(Dictionary<string,object>)name["parent"]; if((ulong)expectedParent["record_number"]!=parentId.Key) continue; int matches=0;
                    foreach(Dictionary<string,object> entry in entries) if(Match(name,entry,identity,parentReference)) matches++;
                    comparisons.Add(new Dictionary<string,object>{{"expected_name",name},{"index_match_count",matches},{"coverage_complete",leafComplete},{"exactly_one_match",leafComplete && matches==1}});
                    Dictionary<string,object> opened=new Dictionary<string,object>{{"name",name},{"access_mask",ReadAttributes},{"open_reparse_point",true},{"backup_semantics",true}};
                    if(parentPath==null) opened["path_unavailable"]=true; else {
                        string component=(string)name["name"]; Need(component.Length>0 && component!="." && component!=".." && component.IndexOfAny(new char[]{'\\','/',':','\0'})<0,"FILE_NAME cannot form a single native path component");
                        string path=parentPath.TrimEnd('\\')+"\\"+component; Need(path.Length<32768,"Native diagnostic path exceeds bound"); opened["path"]=path; nativeOpens++;
                        using(SafeFileHandle file=CreateFileW(path,ReadAttributes,7,IntPtr.Zero,3,NoFollowDirectory,IntPtr.Zero)) {
                            if(file.IsInvalid) opened["open_error"]=Marshal.GetLastWin32Error(); else { byte[] actual=Native(file,root,opened); opened["same_file_id_info_as_base"]=Equal(actual,sourceId); }
                        }
                        opened["long_path_mapping"]=Map(path,false); opened["short_path_mapping"]=Map(path,true);
                    }
                    paths.Add(opened);
                }
                foreach(Dictionary<string,object> entry in entries) { Dictionary<string,object> child=(Dictionary<string,object>)entry["child"]; if((ulong)child["record_number"]!=number || (ulong)child["sequence_number"]!=first.sequence_number) continue; int matches=0;
                    foreach(Dictionary<string,object> name in names) { Dictionary<string,object> p=(Dictionary<string,object>)name["parent"]; if((ulong)p["record_number"]==parentId.Key && (ulong)p["sequence_number"]==parentId.Value && Match(name,entry,identity,parentReference)) matches++; }
                    reverse.Add(new Dictionary<string,object>{{"index_entry",entry},{"file_name_match_count",matches},{"coverage_complete",leafComplete && complete},{"exactly_one_match",leafComplete && complete && matches==1}});
                }
            }
            List<object> closing=new List<object>(); bool unchanged=true; HashSet<ulong> checkedRecords=new HashSet<ulong>();
            foreach(Record original in bookends) { if(!checkedRecords.Add(original.record_number)) continue; Record after=Read(volume,original.record_number,recordBytes); bool same=original.raw_record_sha256==after.raw_record_sha256; unchanged &= same; closing.Add(new Dictionary<string,object>{{"record_number",original.record_number},{"before_sha256",original.raw_record_sha256},{"after_sha256",after.raw_record_sha256},{"unchanged",same}}); }
            return new Dictionary<string,object>{{"record_number",number},{"file_reference",Ref(identity)},{"record_bytes",recordBytes},{"resident_attribute_list_coverage_complete",complete},{"records",records},{"all_names",names},{"parent_indexes",parents},{"name_index_comparisons",comparisons},{"selected_index_name_comparisons",reverse},{"native_base_file",native},{"native_extended_attributes",nativeEa},{"native_name_paths",paths},{"record_bookends",closing},{"all_record_bookends_unchanged",unchanged},{"file_record_queries",fileRecordQueries},{"metadata_ioctl_queries",ioctlQueries},{"native_metadata_opens",nativeOpens},{"native_path_mapping_queries",mappingQueries},{"payload_read_calls",0},{"source_write_calls",0},{"nonresident_attribute_list_read",false},{"nonresident_i30_read",false},{"alias_partner_inferred",false}};
        }
    }
}
'@
}
$observation = [NtfsFileAliasesReadOnlyV1]::Observe($before.volume_guid,$RecordNumber)
$after = Assert-Source
if (($after|ConvertTo-Json -Compress) -cne ($before|ConvertTo-Json -Compress)) { throw 'Source binding changed during read-only observation.' }
$wire = [Text.UTF8Encoding]::new($false).GetBytes(([ordered]@{schema_version=1;kind='readonly-enrolled-ntfs-file-aliases';observed_utc=[DateTime]::UtcNow.ToString('o');before=$before;observation=$observation;after=$after}|ConvertTo-Json -Depth 24))
if ($wire.Length -gt 8MB) { throw 'Diagnostic output exceeds 8MiB metadata bound.' }
[Text.UTF8Encoding]::new($false).GetString($wire)
