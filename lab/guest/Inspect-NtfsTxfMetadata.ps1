<# Read-only exact-file TxF metadata observation. Execute only after actual conversion cleanup and healthy NTFS restoration. No source setters, RM changes or payload reads. #>
[CmdletBinding()]
param([string]$Volume='D:',[ValidateCount(1,64)][UInt64[]]$RecordNumbers=@(3012),[string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
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

if($RecordNumbers.Count-ne@($RecordNumbers|Select-Object -Unique).Count-or@($RecordNumbers|Where-Object{$_-gt281474976710655L}).Count){throw 'Unique bounded NTFS record numbers required'}
$before=Assert-Source
if($OutputPath){
    if(-not[IO.Path]::IsPathRooted($OutputPath)-or$OutputPath.Length-ge240-or[IO.Path]::GetFullPath($OutputPath)-ine$OutputPath-or-not$OutputPath.StartsWith('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)-or(Test-Path -LiteralPath $OutputPath)){throw 'Optional output must be a new absolute ordinary file below C:\ntfs2refs'}
    $parent=Split-Path -Parent $OutputPath;$directory=Get-Item -LiteralPath $parent -Force
    while($null-ne$directory){if(-not($directory-is[IO.DirectoryInfo])-or($directory.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Output ancestors must be ordinary existing directories'};$directory=$directory.Parent}
    $v=@(Get-Volume -FilePath $parent);$c=Get-Volume -DriveLetter C;$cp=@(Get-Partition -DriveLetter C)
    if($v.Count-ne1-or$cp.Count-ne1-or$cp[0].DiskNumber-ne1-or[string]$v[0].UniqueId-cne[string]$c.UniqueId){throw 'Output must reside on actual external control disk1 C'}
}
if(-not('NtfsTxfMetadataReadOnlyV1'-as[type])){
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NtfsTxfMetadataReadOnlyV1 {
    // Official host SDK: Windows Kits/10/Include/10.0.26100.0/um/winioctl.h
    // SHA256 2eea233e2d0d31b8d84658b8753197a2bbea23157133d99a5aae227c96bae7ae.
    // Lines11308/11317/11318/11343: CTL_CODE(FILE_DEVICE_FILE_SYSTEM,82/91/92/121,
    // METHOD_BUFFERED,FILE_READ_DATA). Structures13640,13986,14109,14207 onward.
    const ulong Mask=0x0000ffffffffffffUL;
    const uint QueryRm=(9U<<16)|(1U<<14)|(82U<<2),GetTxf=(9U<<16)|(1U<<14)|(91U<<2),GetVersion=(9U<<16)|(1U<<14)|(92U<<2),ListTransactions=(9U<<16)|(1U<<14)|(121U<<2);
    const uint OpenNoFollowDirectory=0x02200000;
    static int recordQueries,metadataQueries;
    static UnicodeEncoding Unicode=new UnicodeEncoding(false,false,true);
    [StructLayout(LayoutKind.Explicit,Size=24)] struct Id{[FieldOffset(0)]public uint Size;[FieldOffset(4)]public uint Type;[FieldOffset(8)]public ulong Value;}
    [StructLayout(LayoutKind.Sequential)] public struct TxfMetadata {public long TxfFileIdLowPart,TxfFileIdHighPart;public Guid LockingTransaction;public ulong LastLsn;public uint TransactionState;}
    [StructLayout(LayoutKind.Sequential)] public struct TransactedVersion {public uint ThisBaseVersion,LatestVersion;public ushort ThisMiniVersion,FirstMiniVersion,LatestMiniVersion;}
    [StructLayout(LayoutKind.Sequential)] public struct RmInformation {
        public uint BytesRequired;public ulong TailLsn,CurrentLsn,ArchiveTailLsn,LogContainerSize;public long HighestVirtualClock;
        public uint LogContainerCount,LogContainerCountMax,LogContainerCountMin,LogGrowthIncrement,LogAutoShrinkPercentage,Flags;
        public ushort LoggingMode,Reserved;public uint RmState;public ulong LogCapacity,LogFree,TopsSize,TopsUsed,TransactionCount,OnePCCount,TwoPCCount,NumberLogFileFull,OldestTransactionAge;
        public Guid RMName;public uint TmLogPathOffset;
    }
    [StructLayout(LayoutKind.Sequential)] public struct TransactionList {public ulong NumberOfTransactions,BufferSizeRequired;}
    [StructLayout(LayoutKind.Sequential)] public struct TransactionEntry {public Guid TransactionId;public uint TransactionState,Reserved1,Reserved2;public long Reserved3;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle h,uint c,byte[] i,uint n,[Out]byte[] o,uint m,out uint r,IntPtr z);
    [DllImport("kernel32.dll",SetLastError=true)]static extern SafeFileHandle OpenFileById(SafeFileHandle h,ref Id id,uint a,uint s,IntPtr z,uint f);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,[Out]byte[] o,uint n);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint n,uint f);
    static void Need(bool ok,string why){if(!ok)throw new InvalidDataException(why);}
    static ushort U16(byte[] b,int p){return BitConverter.ToUInt16(b,p);}static uint U32(byte[] b,int p){return BitConverter.ToUInt32(b,p);}static ulong U64(byte[] b,int p){return BitConverter.ToUInt64(b,p);}
    static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
    static string Hash(byte[] b){using(SHA256 h=SHA256.Create())return Hex(h.ComputeHash(b));}
    static byte[] Slice(byte[] b,int at,int n){byte[] result=new byte[n];Array.Copy(b,at,result,0,n);return result;}
    static Dictionary<string,object> Reference(ulong n){return new Dictionary<string,object>{{"reference_hex",n.ToString("x16")},{"record_number",n&Mask},{"sequence_number",n>>48}};}
    static byte[] RequiredIo(SafeFileHandle file,uint code,byte[] input,int cap){uint used;byte[] output=new byte[cap];metadataQueries++;bool ok=DeviceIoControl(file,code,input,input==null?0:(uint)input.Length,output,(uint)cap,out used,IntPtr.Zero);if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),"Read-only metadata FSCTL "+code.ToString("x"));Need(used<=cap,"Metadata response exceeds allocation");Array.Resize(ref output,(int)used);return output;}
    public sealed class Record {
        public ulong record_number,base_reference;public ushort sequence_number,header_links,flags;public string raw_record_sha256,usa_status;
        public bool nonresident_attribute_list;public List<ulong> references=new List<ulong>();
        public List<Dictionary<string,object>> attribute_list=new List<Dictionary<string,object>>(),attributes=new List<Dictionary<string,object>>(),names=new List<Dictionary<string,object>>(),txf_data=new List<Dictionary<string,object>>();
    }
    static Record ReadRecord(SafeFileHandle volume,ulong number,int recordBytes){
        Need(++recordQueries<=1024,"FILE-record metadata query bound exceeded");byte[] response=RequiredIo(volume,0x90068,BitConverter.GetBytes(number),recordBytes+12);
        Need(response.Length>=recordBytes+12&&(U64(response,0)&Mask)==number&&U32(response,8)==recordBytes,"FSCTL returned another/truncated FILE");byte[] b=Slice(response,12,recordBytes);
        Need(Encoding.ASCII.GetString(b,0,4)=="FILE","FILE signature differs");Record r=new Record();r.record_number=number;r.raw_record_sha256=Hash(b);
        int usa=U16(b,4),count=U16(b,6);Need(usa>=42&&usa%2==0&&count==recordBytes/512+1&&usa+count*2<=recordBytes,"FILE USA geometry differs");ushort usn=U16(b,usa);bool raw=true,fixedUp=true;
        for(int i=1;i<count;i++){raw&=U16(b,i*512-2)==usn;fixedUp&=U16(b,i*512-2)==U16(b,usa+i*2);}Need(raw||fixedUp,"Torn/mixed FILE trailers");r.usa_status=raw?"raw-fixed-in-memory":"already-fixed-up";
        if(raw)for(int i=1;i<count;i++){b[i*512-2]=b[usa+i*2];b[i*512-1]=b[usa+i*2+1];}
        r.sequence_number=U16(b,16);r.header_links=U16(b,18);r.flags=U16(b,22);r.base_reference=U64(b,32);int at=U16(b,20),used=checked((int)U32(b,24));
        Need(r.sequence_number!=0&&(r.flags&1)!=0&&U32(b,28)==recordBytes&&used<=recordBytes&&at>=48&&at>=usa+count*2&&at%8==0,"FILE header/bounds differ");if(usa>=48)Need(U32(b,44)==number,"FILE number differs");bool end=false;
        while(at+4<=used){uint type=U32(b,at);if(type==0xffffffff){end=true;break;}Need(at+16<=used,"Truncated attribute header");int length=checked((int)U32(b,at+4));byte nonresident=b[at+8],chars=b[at+9];ushort nameAt=U16(b,at+10),instance=U16(b,at+14);
            Need(length>=24&&length%8==0&&length<=used-at&&nonresident<=1&&(nonresident==0||length>=64),"Attribute header bounds differ");Need(chars==0||(nameAt>=(nonresident==0?24:64)&&nameAt<=length-chars*2),"Attribute name escapes record");string name=chars==0?"":Unicode.GetString(b,at+nameAt,chars*2);ulong vcn=nonresident==0?0:U64(b,at+16);
            r.attributes.Add(new Dictionary<string,object>{{"type",type},{"name",name},{"instance",instance},{"lowest_vcn",vcn},{"flags",U16(b,at+12)},{"nonresident",nonresident!=0},{"record_offset",at},{"record_length",length}});
            if(type==0x20&&nonresident!=0)r.nonresident_attribute_list=true;
            if(nonresident==0&&(type==0x20||type==0x30||(type==0x100&&name=="$TXF_DATA"))){int size=checked((int)U32(b,at+16)),valueAt=U16(b,at+20);Need(valueAt>=24&&valueAt<=length&&size<=length-valueAt,"Resident attribute value escapes record");int value=at+valueAt;
                if(type==0x100){byte[] bytes=Slice(b,value,size),header=Slice(b,at,valueAt),full=Slice(b,at,length);r.txf_data.Add(new Dictionary<string,object>{{"origin_record",number},{"origin_sequence",r.sequence_number},{"attribute_instance",instance},{"attribute_name",name},{"type",type},{"flags",U16(b,at+12)},{"resident",true},{"value_bytes",size},{"value_hex",Hex(bytes)},{"value_sha256",Hash(bytes)},{"resident_value_offset",valueAt},{"resident_indexed_flag",b[at+22]},{"attribute_header_hex",Hex(header)},{"attribute_header_sha256",Hash(header)},{"full_attribute_record_hex_after_usa_fixup",Hex(full)},{"full_attribute_record_sha256_after_usa_fixup",Hash(full)}});}
                else if(type==0x30){Need(size>=66&&b[value+64]>0&&66+b[value+64]*2==size&&b[value+65]<=3,"FILE_NAME bounds differ");r.names.Add(new Dictionary<string,object>{{"parent",Reference(U64(b,value))},{"namespace",b[value+65]},{"name",Unicode.GetString(b,value+66,b[value+64]*2)},{"name_utf16_hex",Hex(Slice(b,value+66,b[value+64]*2))}});}
                else for(int p=value;p<value+size;){Need(value+size-p>=26,"Attribute-list entry truncated");int n=U16(b,p+4),units=b[p+6],off=b[p+7];Need(n>=26&&n%8==0&&n<=value+size-p&&(units==0||(off>=26&&off+units*2<=n)),"Attribute-list entry bounds differ");ulong reference=U64(b,p+16);Need((reference>>48)!=0,"Attribute-list sequence missing");r.references.Add(reference);r.attribute_list.Add(new Dictionary<string,object>{{"type",U32(b,p)},{"lowest_vcn",U64(b,p+8)},{"reference",Reference(reference)},{"instance",U16(b,p+24)},{"name",units==0?"":Unicode.GetString(b,p+off,units*2)}});p+=n;}
            }at+=length;
        }Need(end,"FILE attributes lack end marker");return r;
    }
    static List<Record> Gather(SafeFileHandle volume,Record first,int bytes,out bool complete){
        Need(first.base_reference==0,"Selected FILE is an extension");ulong identity=first.record_number|((ulong)first.sequence_number<<48);List<Record> records=new List<Record>();Queue<Record> todo=new Queue<Record>();Dictionary<ulong,ushort> seen=new Dictionary<ulong,ushort>();todo.Enqueue(first);seen.Add(first.record_number,first.sequence_number);complete=true;
        while(todo.Count!=0){Record r=todo.Dequeue();records.Add(r);complete&=!r.nonresident_attribute_list;foreach(ulong reference in r.references){ulong n=reference&Mask;ushort seq=(ushort)(reference>>48),old;if(seen.TryGetValue(n,out old)){Need(old==seq,"Attribute-list sequence conflict");continue;}Need(seen.Count<128,"Attribute-list closure exceeds128records");Record next=ReadRecord(volume,n,bytes);Need(next.sequence_number==seq&&next.base_reference==identity,"Extension base/sequence differs");seen.Add(n,seq);todo.Enqueue(next);}}
        foreach(Record origin in records)foreach(Dictionary<string,object> entry in origin.attribute_list){Dictionary<string,object> reference=(Dictionary<string,object>)entry["reference"];int matches=0;foreach(Record r in records)if(r.record_number==(ulong)reference["record_number"]&&r.sequence_number==(ulong)reference["sequence_number"])foreach(Dictionary<string,object> attribute in r.attributes)if((uint)attribute["type"]==(uint)entry["type"]&&(ushort)attribute["instance"]==(ushort)entry["instance"]&&(ulong)attribute["lowest_vcn"]==(ulong)entry["lowest_vcn"]&&(string)attribute["name"]==(string)entry["name"])matches++;entry["observed_attribute_match_count"]=matches;complete&=matches==1;}
        return records;
    }
    static Dictionary<string,object> Identity(SafeFileHandle file,string root,ulong expected){
        byte[] id=new byte[24],standard=new byte[24],tag=new byte[8];Need(GetFileInformationByHandleEx(file,18,id,24),"NativeFileIdInfo query failed");Need(U64(id,8)==expected&&U64(id,16)==0,"NativeFileIdInfo differs from exact selected FILE reference");Need(GetFileInformationByHandleEx(file,1,standard,24),"Native standard query failed");Need(GetFileInformationByHandleEx(file,9,tag,8),"Native attribute/tag query failed");StringBuilder path=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(file,path,(uint)path.Capacity,1);Need(n>0&&n<path.Capacity&&(path.ToString().StartsWith(root,StringComparison.OrdinalIgnoreCase)||path.ToString().Equals(root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)),"Selected handle lacks enrolled volume GUID path");
        return new Dictionary<string,object>{{"file_id_info_hex",Hex(id)},{"expected_reference",Reference(expected)},{"number_of_links",U32(standard,16)},{"delete_pending",standard[20]!=0},{"directory",standard[21]!=0},{"file_attributes",U32(tag,0)},{"reparse_tag",U32(tag,4)},{"normalized_path",path.ToString()}};
    }
    static T Struct<T>(byte[] b,int at){int size=Marshal.SizeOf(typeof(T));Need(at>=0&&at<=b.Length-size,"Official structure exceeds returned bytes");IntPtr p=Marshal.AllocHGlobal(size);try{Marshal.Copy(b,at,p,size);return(T)Marshal.PtrToStructure(p,typeof(T));}finally{Marshal.FreeHGlobal(p);}}
    static Dictionary<string,object> Query(SafeFileHandle file,uint code,string name){
        byte[] b=new byte[65536];uint used;metadataQueries++;bool ok=DeviceIoControl(file,code,null,0,b,(uint)b.Length,out used,IntPtr.Zero);int error=ok?0:Marshal.GetLastWin32Error();Need(used<=b.Length,"TxF metadata return exceeds64KiB");Array.Resize(ref b,(int)used);
        Dictionary<string,object> row=new Dictionary<string,object>{{"api",name},{"control_code_hex",code.ToString("x8")},{"success",ok},{"win32_error",error},{"bytes_returned",used},{"raw_bytes_hex",Hex(b)},{"raw_sha256",Hash(b)},{"buffer_capacity",65536},{"input_bytes",0}};
        if(ok)try{
            if(code==GetTxf){TxfMetadata info=Struct<TxfMetadata>(b,0);row["official_structure_size"]=Marshal.SizeOf(typeof(TxfMetadata));row["decoded"]=info;}
            if(code==GetVersion){TransactedVersion info=Struct<TransactedVersion>(b,0);row["official_structure_size"]=Marshal.SizeOf(typeof(TransactedVersion));row["decoded"]=info;row["TXFS_TRANSACTED_VERSION_NONTRANSACTED_hex"]="fffffffe";row["TXFS_TRANSACTED_VERSION_UNCOMMITTED_hex"]="ffffffff";}
            if(code==QueryRm){RmInformation info=Struct<RmInformation>(b,0);row["official_structure_size"]=Marshal.SizeOf(typeof(RmInformation));row["decoded"]=info;if(info.TmLogPathOffset!=0){int at=checked((int)info.TmLogPathOffset);Need(at>=Marshal.SizeOf(typeof(RmInformation))&&at<b.Length&&at%2==0,"TMlogpath offset outside returned metadata");int end=at;while(end+1<b.Length&&U16(b,end)!=0)end+=2;Need(end+1<b.Length,"TMlogpath lacks bounded terminator");row["tm_log_path"]=Unicode.GetString(b,at,end-at);}}
            if(code==ListTransactions){TransactionList info=Struct<TransactionList>(b,0);row["official_structure_size"]=Marshal.SizeOf(typeof(TransactionList));row["decoded"]=info;int size=Marshal.SizeOf(typeof(TransactionEntry));row["official_entry_size"]=size;bool all=info.NumberOfTransactions<=1024&&16UL+info.NumberOfTransactions*(ulong)size<=(ulong)b.Length;row["complete_entries_in_returned_bytes"]=all;if(all){List<TransactionEntry> entries=new List<TransactionEntry>();for(ulong i=0;i<info.NumberOfTransactions;i++)entries.Add(Struct<TransactionEntry>(b,checked(16+(int)i*size)));row["entries"]=entries;}}
        }catch(Exception ex){row["decode_error"]=ex.Message;}
        return row;
    }
    public static object Observe(string root,ulong[] numbers){
        Need(numbers.Length>0&&numbers.Length<=64,"Record count bound differs");recordQueries=metadataQueries=0;List<object> results=new List<object>();
        using(SafeFileHandle volume=CreateFileW(root.TrimEnd('\\'),0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero)){
            Need(!volume.IsInvalid,"Read-only enrolled volume open failed");byte[] extents=RequiredIo(volume,0x560000,null,64);Need(extents.Length>=32&&U32(extents,0)==1&&U32(extents,8)==0&&U64(extents,16)==331350016UL&&U64(extents,24)==66236448768UL,"Enrolled volume extent differs");byte[] geometry=RequiredIo(volume,0x90064,null,128);Need(geometry.Length>=96&&U32(geometry,40)==512&&U32(geometry,44)==4096,"Enrolled NTFS sector/cluster differs");int size=checked((int)U32(geometry,48));Need(size>=512&&size<=65536&&size%512==0,"FILE-record geometry outside bound");
            foreach(ulong number in numbers){Need(number<=Mask,"FILE number outside48bits");Record first=ReadRecord(volume,number,size);bool complete;List<Record> records=Gather(volume,first,size,out complete);ulong reference=number|((ulong)first.sequence_number<<48);Id id=new Id{Size=24,Type=0,Value=reference};Dictionary<string,object> result=new Dictionary<string,object>{{"record_number",number},{"reference",Reference(reference)},{"record_bytes",size},{"resident_attribute_list_coverage_complete",complete},{"records",records},{"query_target","exact selected FILE handle; no default-volume or ancestor fallback"}};
                using(SafeFileHandle attributes=OpenFileById(volume,ref id,0x80,7,IntPtr.Zero,OpenNoFollowDirectory)){
                    if(attributes.IsInvalid)result["attribute_handle_open_error"]=Marshal.GetLastWin32Error();else try{
                    Dictionary<string,object> before=Identity(attributes,root,reference);result["native_before"]=before;
                    // Official controls require FILE_READ_DATA. This separate
                    // minimal read-data/read-attributes handle is used ONLY for
                    // these metadata FSCTLs; no ReadFile or payload APIs exist.
                    using(SafeFileHandle metadata=OpenFileById(volume,ref id,0x81,7,IntPtr.Zero,OpenNoFollowDirectory)){
                        if(metadata.IsInvalid)result["metadata_read_handle_open_error"]=Marshal.GetLastWin32Error();else{Dictionary<string,object> opened=Identity(metadata,root,reference);Need((string)opened["file_id_info_hex"]==(string)before["file_id_info_hex"],"Metadata query handle identity differs");result["metadata_read_handle_identity"]=opened;result["metadata_before"]=Query(metadata,GetTxf,"FSCTL_TXFS_GET_METADATA_INFO");result["transacted_version"]=Query(metadata,GetVersion,"FSCTL_TXFS_GET_TRANSACTED_VERSION");result["resource_manager_information"]=Query(metadata,QueryRm,"FSCTL_TXFS_QUERY_RM_INFORMATION");result["transaction_list"]=Query(metadata,ListTransactions,"FSCTL_TXFS_LIST_TRANSACTIONS");result["metadata_after"]=Query(metadata,GetTxf,"FSCTL_TXFS_GET_METADATA_INFO");Dictionary<string,object> metadataAfter=Identity(metadata,root,reference);result["metadata_read_handle_identity_after"]=metadataAfter;result["metadata_read_handle_identity_bookends_match"]=(string)opened["file_id_info_hex"]==(string)metadataAfter["file_id_info_hex"];}
                    }
                    Dictionary<string,object> after=Identity(attributes,root,reference);result["native_after"]=after;result["native_identity_bookends_match"]=(string)before["file_id_info_hex"]==(string)after["file_id_info_hex"];
                    }catch(Exception error){result["native_observation_error"]=error.Message;result["native_observation_error_type"]=error.GetType().FullName;}
                }
                List<object> bookends=new List<object>();bool stable=true;foreach(Record r in records){Record after=ReadRecord(volume,r.record_number,size);bool same=r.raw_record_sha256==after.raw_record_sha256;stable&=same;bookends.Add(new Dictionary<string,object>{{"record_number",r.record_number},{"before_sha256",r.raw_record_sha256},{"after_sha256",after.raw_record_sha256},{"unchanged",same}});}result["raw_record_bookends"]=bookends;result["all_raw_record_bookends_unchanged"]=stable;results.Add(result);
            }
        }
        return new Dictionary<string,object>{{"selected_records",results},{"source_write_calls",0},{"payload_read_calls",0},{"rm_start_shutdown_recovery_calls",0},{"metadata_ioctl_calls",metadataQueries},{"file_record_queries",recordQueries},{"nonresident_attribute_list_read",false},{"official_sdk","winioctl.h 10.0.26100.0"},{"official_sdk_sha256","2eea233e2d0d31b8d84658b8753197a2bbea23157133d99a5aae227c96bae7ae"}};
    }
}
'@
}
$observation=[NtfsTxfMetadataReadOnlyV1]::Observe($before.volume_guid,$RecordNumbers)
$after=Assert-Source
if(($before|ConvertTo-Json -Compress)-cne($after|ConvertTo-Json -Compress)){throw 'Enrolled source binding changed during observation'}
$json=[ordered]@{schema_version=1;kind='readonly-enrolled-NTFS-exact-file-TxF-metadata';observed_utc=[DateTime]::UtcNow.ToString('o');before=$before;observation=$observation;after=$after}|ConvertTo-Json -Depth 24
$wire=[Text.UTF8Encoding]::new($false).GetBytes($json)
if($wire.Length-gt8MB){throw 'TxF observation exceeds8MiB bounded metadata output'}
if($OutputPath){$file=[IO.File]::Open($OutputPath,'CreateNew','Write','Read');try{$file.Write($wire,0,$wire.Length);$file.Flush($true)}finally{$file.Dispose()}}
$json

