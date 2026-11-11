<# Disposable native ReFS feature observation, only on the actual disk1 boot
   control. Creates one new ordinary file and one receipt below a fresh external
   C:\ntfs2refs directory. Preserves both. Never opens source disk0 for writes.
   Exact kernel EA values come from actual FILE35049 proof SHA256
   cfb6e0186ea0f2b98e90badd607f1a3eef8b5257af2c630268d51ad566b87312. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Need([bool]$Ok,[string]$Reason) { if(-not$Ok) { throw $Reason } }
function State {
    $os=Get-CimInstance Win32_OperatingSystem
    $boot=[DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()
    $c=@(Get-Partition -DriveLetter C);Need ($c.Count-eq1) 'Actual running C must identify one partition'
    $control=Get-Disk -Number $c[0].DiskNumber;$cv=Get-Volume -DriveLetter C
    Need ($boot-eq1793995332223L-and$os.WindowsDirectory-ieq'C:\Windows'-and$os.SystemDrive-ieq'C:'-and$c[0].DiskNumber-eq1-and$control.IsBoot-eq$true-and$c[0].IsBoot-eq$true-and[guid]$control.Guid-eq[guid]'91dd2cc0-4ec1-4f92-a924-870e4f16c0fb') 'Actual alternate control1 Windows boot identity changed'
    Need ($control.IsOffline-eq$false-and$control.IsReadOnly-eq$false-and$c[0].IsOffline-eq$false-and$c[0].IsReadOnly-eq$false-and$cv.FileSystem-ceq'ReFS'-and$cv.AllocationUnitSize-eq4096-and[string]$cv.HealthStatus-ceq'Healthy') 'Writable healthy ReFS/4KiB disk1 control required'
    Need (Confirm-SecureBootUEFI) 'Secure Boot must remain enabled'
    $source=Get-Disk -Number 0;$p=Get-Partition -DiskNumber 0 -PartitionNumber 3;$v=@($p|Get-Volume)
    Need ($v.Count-eq1-and[guid]$source.Guid-eq[guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26'-and[string]$source.UniqueId-ceq'60022480BEA35BA9D496D5AFF633D768'-and$source.Size-eq64GB-and$source.PartitionStyle-ceq'GPT'-and$source.IsBoot-eq$false-and$source.IsSystem-eq$false-and$source.IsOffline-eq$false-and$source.IsReadOnly-eq$false) 'Recovered original source disk0 identity/availability changed'
    Need ([guid]$p.Guid-eq[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-and$p.Offset-eq331350016L-and$p.Size-eq66236448768L-and$p.IsBoot-eq$false-and$p.IsSystem-eq$false-and$p.IsOffline-eq$false-and$p.IsReadOnly-eq$false-and$v[0].FileSystem-ceq'NTFS'-and$v[0].AllocationUnitSize-eq4096-and[string]$v[0].HealthStatus-ceq'Healthy') 'Recovered original source0p3 healthy NTFS binding changed'
    Need (@(Get-Process -Name 'ntfs2refs' -ErrorAction SilentlyContinue).Count-eq0) 'Converter must be terminal before the control observation'
    [pscustomobject]@{boot_ms=$boot;control_disk=$control.Number;control_guid=([guid]$control.Guid).ToString('D');control_unique_id=[string]$control.UniqueId;
        control_partition_guid=([guid]$c[0].Guid).ToString('D');control_volume_guid=[string]$cv.UniqueId;control_filesystem=[string]$cv.FileSystem;
        source_disk=$source.Number;source_guid=([guid]$source.Guid).ToString('D');source_partition_guid=([guid]$p.Guid).ToString('D');source_offset=$p.Offset;source_bytes=$p.Size;
        source_filesystem=[string]$v[0].FileSystem;source_volume_guid=[string]$v[0].UniqueId;source_healthy_ntfs=$true;secure_boot=$true}
}
$before=State
Need ([IO.Path]::IsPathRooted($OutputDirectory)-and$OutputDirectory.Length-lt240) 'A bounded absolute new output directory is required'
$full=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
Need ($full-ieq$OutputDirectory.TrimEnd('\')-and$full.StartsWith('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)-and$full.Substring(3).IndexOf(':')-lt0-and-not(Test-Path -LiteralPath $full)) 'Output must be a new ordinary absolute directory below C:\ntfs2refs'
$parent=Split-Path -Parent $full;$directory=Get-Item -LiteralPath $parent -Force
while($null-ne$directory) { Need (($directory-is[IO.DirectoryInfo])-and-not($directory.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Output ancestors must be existing ordinary directories';$directory=$directory.Parent }
$volumes=@(Get-Volume -FilePath $parent);Need ($volumes.Count-eq1-and[string]$volumes[0].UniqueId-ceq$before.control_volume_guid) 'Output parent must be the actual disk1 C control volume'
$null=New-Item -ItemType Directory -Path $full
$fixture=Join-Path $full 'native-ea-control.bin';$receiptPath=Join-Path $full 'receipt.json'
$result=[ordered]@{schema_version=1;kind='actual-ReFS-usermode-kernel-purge-EA-control-v1';status='observing';actual_feature_observation=$true;before=$before;
    measured_source_evidence_sha256='cfb6e0186ea0f2b98e90badd607f1a3eef8b5257af2c630268d51ad566b87312';source_write_calls=0;source_payload_reads=0;
    output_directory=$full;fixture_path=$fixture;fixture_retained=$true;cleanup_deletes=0;conversion_or_recovery_calls=0;boot_changes=0;created_utc=[DateTime]::UtcNow.ToString('o')}
$failure=$null
try {
if(-not('ReFSKernelPurgeEaControlV1'-as[type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class ReFSKernelPurgeEaControlV1 {
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(SafeFileHandle file,byte[] data,uint n,out uint written,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle file,[Out] byte[] data,uint n,out uint read,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFilePointerEx(SafeFileHandle file,long distance,out long position,uint method);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle file);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int c,[Out] byte[] output,uint n);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,StringBuilder path,uint n,uint flags);
    [DllImport("ntdll.dll")] static extern uint NtQueryEaFile(SafeFileHandle file,out IoStatus io,[Out] byte[] buffer,uint length,[MarshalAs(UnmanagedType.U1)] bool single,IntPtr list,uint listLength,IntPtr index,[MarshalAs(UnmanagedType.U1)] bool restart);
    [DllImport("ntdll.dll")] static extern uint NtSetEaFile(SafeFileHandle file,out IoStatus io,byte[] buffer,uint length);
    static void Need(bool ok,string reason) { if(!ok) throw new InvalidDataException(reason); }
    static void Win(bool ok,string operation) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),operation); }
    static uint U32(byte[] b,int at) { return BitConverter.ToUInt32(b,at); }
    static ushort U16(byte[] b,int at) { return BitConverter.ToUInt16(b,at); }
    static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-","").ToLowerInvariant(); }
    static string Hash(byte[] b) { using(SHA256 h=SHA256.Create()) return Hex(h.ComputeHash(b)); }
    static byte[] Bytes(string hex) { Need(hex.Length%2==0 && hex.Length<=131072,"Hex input bound differs"); byte[] b=new byte[hex.Length/2]; for(int i=0;i<b.Length;i++) b[i]=Convert.ToByte(hex.Substring(i*2,2),16); return b; }
    static Dictionary<string,object> Snapshot(SafeFileHandle file,string expectedVolume,string expectedPath,int expectedBytes) {
        byte[] id=new byte[24],standard=new byte[24],tag=new byte[8];
        Win(GetFileInformationByHandleEx(file,18,id,24),"FileIdInfo"); Win(GetFileInformationByHandleEx(file,1,standard,24),"FileStandardInfo"); Win(GetFileInformationByHandleEx(file,9,tag,8),"FileAttributeTagInfo");
        StringBuilder path=new StringBuilder(32768); uint n=GetFinalPathNameByHandleW(file,path,(uint)path.Capacity,1); Win(n!=0,"GUID normalized file path"); Need(n<path.Capacity,"Native path exceeds bound");
        string final=path.ToString(); Need(final.Equals(expectedVolume.TrimEnd('\\')+expectedPath.Substring(2),StringComparison.OrdinalIgnoreCase),"Fixture escaped the actual external control volume/path");
        Need(BitConverter.ToInt64(standard,8)==expectedBytes && U32(standard,16)==1 && standard[20]==0 && standard[21]==0 && (U32(tag,0)&0x410)==0 && U32(tag,4)==0,"Fixture type, EOF, link or no-reparse contract differs");
        return new Dictionary<string,object>{{"file_id_info_hex",Hex(id)},{"file_bytes",BitConverter.ToInt64(standard,8)},{"number_of_links",U32(standard,16)},{"delete_pending",false},{"directory",false},{"file_attributes",U32(tag,0)},{"reparse_tag",U32(tag,4)},{"normalized_path",final}};
    }
    static List<Dictionary<string,object>> Parse(byte[] b) {
        List<Dictionary<string,object>> rows=new List<Dictionary<string,object>>(); int at=0;
        while(at<b.Length) {
            Need(rows.Count<1024 && b.Length-at>=8,"EA entry/header exceeds bound"); uint next=U32(b,at); int names=b[at+5],values=U16(b,at+6),minimum=checked(9+names+values);
            Need(names>0 && minimum<=b.Length-at && b[at+8+names]==0,"EA name/value escapes returned bytes"); if(next!=0) Need(next%4==0 && next>=minimum && next<=b.Length-at,"EA offset escapes returned bytes");
            byte[] name=new byte[names],value=new byte[values]; Array.Copy(b,at+8,name,0,names); Array.Copy(b,at+9+names,value,0,values);
            rows.Add(new Dictionary<string,object>{{"offset",at},{"next_entry_offset",next},{"flags",b[at+4]},{"name",Encoding.ASCII.GetString(name)},{"name_hex",Hex(name)},{"value_bytes",values},{"value_hex",Hex(value)}});
            if(next==0) break; at=checked(at+(int)next);
        }
        return rows;
    }
    static Dictionary<string,object> Query(SafeFileHandle file) {
        byte[] b=new byte[65536]; IoStatus io; uint status=NtQueryEaFile(file,out io,b,(uint)b.Length,false,IntPtr.Zero,0,IntPtr.Zero,true);
        ulong used=io.Information.ToUInt64(); Need(used<=(ulong)b.Length,"EA query returned impossible byte count"); Array.Resize(ref b,(int)used);
        Dictionary<string,object> row=new Dictionary<string,object>{{"api","NtQueryEaFile"},{"ntstatus_hex",status.ToString("x8")},{"io_status_hex",unchecked((uint)io.Status.ToInt64()).ToString("x8")},{"io_information_bytes",used},{"raw_bytes_hex",Hex(b)},{"buffer_capacity",65536},{"return_single_entry",false},{"restart_scan",true},{"success",status==0}};
        row["entries"]=new List<Dictionary<string,object>>();
        if(status==0) { try { row["entries"]=Parse(b); row["parse_complete"]=true; } catch(Exception error) { row["parse_complete"]=false; row["parse_error"]=error.Message; } }
        return row;
    }
    static byte[] Encode(string[] names,byte[][] values) {
        Need(names.Length==values.Length && names.Length==3,"Exactly the two measured kernel EAs and one ordinary EA are required");
        int size=0; for(int i=0;i<names.Length;i++) { Need(names[i].Length>0 && names[i].Length<=255 && values[i].Length<=65535,"EA input exceeds native width"); int length=checked(9+names[i].Length+values[i].Length); size=checked(size+(i+1==names.Length?length:(length+3)&~3)); }
        Need(size<=65536,"EA setter buffer exceeds bound"); byte[] b=new byte[size]; int at=0;
        for(int i=0;i<names.Length;i++) { byte[] name=Encoding.ASCII.GetBytes(names[i]); int length=9+name.Length+values[i].Length,next=i+1==names.Length?0:(length+3)&~3;
            Array.Copy(BitConverter.GetBytes((uint)next),0,b,at,4); b[at+4]=0; b[at+5]=(byte)name.Length; Array.Copy(BitConverter.GetBytes((ushort)values[i].Length),0,b,at+6,2);
            Array.Copy(name,0,b,at+8,name.Length); Array.Copy(values[i],0,b,at+9+name.Length,values[i].Length); if(next!=0) at+=next;
        }
        return b;
    }
    static Dictionary<string,object> Find(Dictionary<string,object> query,string name) {
        Dictionary<string,object> found=null; foreach(Dictionary<string,object> row in (List<Dictionary<string,object>>)query["entries"]) if((string)row["name"]==name) { Need(found==null,"Duplicate exact EA name in native response"); found=row; } return found;
    }
    public static object Observe(string path,string volume) {
        string[] names={"$KERNEL.PURGE.ESBCACHE","$KERNEL.PURGE.APPXFICACHE","N2R.USER.EA.CONTROL"};
        byte[][] values={Bytes("45000000030002065f92ac112963dd0100472fc29610dd0102800000270027040c80000020f057d4a75792b0e3ee1f832ad42d11fea7f9f22ce1d7d6e9415490f34842e162"),Bytes("5f92ac112963dd017037030b000000000000000000000000"),Encoding.ASCII.GetBytes("ntfs2refs-native-ReFS-EA-roundtrip-v1")};
        byte[] content=Encoding.ASCII.GetBytes("ntfs2refs ReFS kernel-purge EA control v1\r\n");
        Dictionary<string,object> result=new Dictionary<string,object>{{"created_file_count",1},{"create_disposition","CREATE_NEW"},{"fixture_content_bytes",content.Length},{"fixture_content_sha256",Hash(content)},{"native_set_ea_calls",0},{"source_write_calls",0},{"cleanup_deletes",0}};
        // Only this fresh control file is write-opened. Hold it without write
        // or delete sharing through all native observations and readback.
        using(SafeFileHandle file=CreateFileW(path,0xc0000000,1,IntPtr.Zero,1,0x80200000,IntPtr.Zero)) {
            Win(!file.IsInvalid,"Create one new external ReFS control file"); result["identity_after_create_before_payload"]=Snapshot(file,volume,path,0);
            uint written; Win(WriteFile(file,content,(uint)content.Length,out written,IntPtr.Zero),"Write bounded control content"); Need(written==content.Length,"Short control content write"); Win(FlushFileBuffers(file),"Flush control content");
            Dictionary<string,object> before=Snapshot(file,volume,path,content.Length),queryBefore=Query(file); result["identity_before"]=before; result["query_before"]=queryBefore;
            Need((bool)queryBefore["success"] || (string)queryBefore["ntstatus_hex"]=="c0000052","Fresh-file EA query failed instead of observing EAs or NO_EAS_ON_FILE");
            Need(Find(queryBefore,names[2])==null,"Fresh control file unexpectedly has the ordinary control EA");
            byte[] set=Encode(names,values); IoStatus io; uint status=NtSetEaFile(file,out io,set,(uint)set.Length); result["native_set_ea_calls"]=1;
            List<object> requested=new List<object>(); for(int i=0;i<names.Length;i++) requested.Add(new Dictionary<string,object>{{"name",names[i]},{"flags",0},{"value_bytes",values[i].Length},{"value_hex",Hex(values[i])}});
            result["requested_eas"]=requested; result["set_result"]=new Dictionary<string,object>{{"api","NtSetEaFile"},{"ntstatus_hex",status.ToString("x8")},{"io_status_hex",unchecked((uint)io.Status.ToInt64()).ToString("x8")},{"io_information_bytes",io.Information.ToUInt64()},{"raw_input_bytes_hex",Hex(set)},{"caller_mode","user-mode PowerShell Add-Type P/Invoke"}};
            Win(FlushFileBuffers(file),"Flush control EA observation"); Dictionary<string,object> queryAfter=Query(file),after=Snapshot(file,volume,path,content.Length); result["query_after"]=queryAfter; result["identity_after"]=after;
            bool identity=(string)before["file_id_info_hex"]==(string)after["file_id_info_hex"]; result["identity_bookends_match"]=identity; Need(identity,"Control file native identity changed");
            long position; Win(SetFilePointerEx(file,0,out position,0),"Rewind tiny control file"); byte[] read=new byte[content.Length+1]; uint count; Win(ReadFile(file,read,(uint)read.Length,out count,IntPtr.Zero),"Read back tiny control file"); Need(count==content.Length,"Control payload length differs"); Array.Resize(ref read,(int)count); result["fixture_content_after_sha256"]=Hash(read); result["control_payload_read_calls"]=1; result["control_payload_write_calls"]=1; Need(Hash(read)==Hash(content),"Control payload changed during EA calls");
            Dictionary<string,object> ordinary=Find(queryAfter,names[2]); bool ordinaryExact=(bool)queryAfter["success"] && queryAfter.ContainsKey("parse_complete") && (bool)queryAfter["parse_complete"] && ordinary!=null && (string)ordinary["value_hex"]==Hex(values[2]); result["ordinary_user_ea_roundtrip"]=ordinaryExact;
            List<object> observed=new List<object>(); int beforeKernel=0,afterKernel=0,exactKernel=0;
            for(int i=0;i<2;i++) { Dictionary<string,object> old=Find(queryBefore,names[i]),current=Find(queryAfter,names[i]); if(old!=null) beforeKernel++; if(current!=null) afterKernel++; bool exact=current!=null && (string)current["value_hex"]==Hex(values[i]); if(exact) exactKernel++;
                observed.Add(new Dictionary<string,object>{{"name",names[i]},{"before",old},{"after",current},{"after_matches_requested_value",exact}}); }
            result["kernel_purge_observations"]=observed; result["kernel_purge_before_count"]=beforeKernel; result["kernel_purge_after_count"]=afterKernel; result["kernel_purge_exact_requested_count"]=exactKernel;
            result["set_status_success"]=status==0; result["observation_valid"]=status==0 && ordinaryExact && identity;
            result["classification"]=status!=0?"native-set-refused":!ordinaryExact?"ordinary-user-EA-roundtrip-failed":beforeKernel!=0?"existing-kernel-EAs-observed-review-before-and-after":afterKernel==0?"kernel-purge-EAs-ignored-user-EA-preserved":exactKernel==2?"both-kernel-purge-EAs-preserved-user-EA-preserved":"kernel-purge-EA-result-differs-review-actual-values";
            return result;
        }
    }
}
'@
}
    $result.native=[ReFSKernelPurgeEaControlV1]::Observe($fixture,$before.control_volume_guid)
    $after=State;$result.after=$after
    Need (($before|ConvertTo-Json -Compress)-ceq($after|ConvertTo-Json -Compress)) 'Control/source storage identity changed during feature observation'
    Need ($result.native.observation_valid-eq$true) 'Native EA observation did not prove ordinary user-EA roundtrip and unchanged file identity'
    $result.status='actual-control-feature-observation-complete'
} catch { $failure=$_;$result.status='refused';$result.error=($_|Out-String) }
$wire=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 24))
Need ($wire.Length-le1MB) 'Control receipt exceeds bounded metadata size'
$file=[IO.File]::Open($receiptPath,'CreateNew','Write','Read')
try{$file.Write($wire,0,$wire.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]@{receipt_path=$receiptPath;receipt_sha256=(Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant();status=$result.status;fixture_path=$fixture;fixture_preserved=$true}|ConvertTo-Json -Compress
if($null-ne$failure){throw $failure}
