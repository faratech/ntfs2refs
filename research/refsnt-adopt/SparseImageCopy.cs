// Original research utility: exact ordinary-file image copy with sparse zeros.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Numerics;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2RefsResearch {
 public sealed class SparseCopyResult {
  public string source,destination,sha256; public long logicalBytes,nonzeroBytesWritten,allocatedBytes;
 }
 public static class SparseImageCopy {
  const long MinFree=64L*1024*1024*1024,MaxWritten=16L*1024*1024*1024;
  [StructLayout(LayoutKind.Sequential)] struct Standard {public long AllocationSize,EndOfFile;public uint Links;public byte DeletePending,Directory;public ushort Padding;}
  [StructLayout(LayoutKind.Sequential)] struct Identity {public ulong Serial,A,B;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,IntPtr input,uint inputSize,IntPtr output,uint outputSize,out uint returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int cls,out Standard data,uint size);
  [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")] static extern bool GetIdentity(SafeFileHandle h,int cls,out Identity data,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetDiskFreeSpaceExW(string path,out ulong available,out ulong total,out ulong free);
  static void Check(bool valid,string message){if(!valid)throw new IOException(message+" (Win32 "+Marshal.GetLastWin32Error()+")");}
  static void Reserve(string root){ulong a,t,f;Check(GetDiskFreeSpaceExW(root,out a,out t,out f)&&a>=(ulong)MinFree,"D volume reserve would fall below64GiB");}
  static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
  public static SparseCopyResult Run(string source,string destination,long bytes,string pin) {
   source=Path.GetFullPath(source);destination=Path.GetFullPath(destination);
   Check(Path.GetPathRoot(destination).Equals("D:\\",StringComparison.OrdinalIgnoreCase),"research target must be on D");
   Check(!File.Exists(destination)&&bytes>0&&bytes<=128L*1024*1024*1024&&pin.Length==64,"fresh bounded destination required");
   Check((File.GetAttributes(source)&(FileAttributes.Directory|FileAttributes.ReparsePoint))==0,"ordinary source required");
   Reserve("D:\\");long written=0,at=0;Identity original=new Identity(),current;Standard allocation;
   using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,1024*1024,FileOptions.SequentialScan))
   using(var output=new FileStream(destination,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,1024*1024,FileOptions.WriteThrough))
   using(var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) {
    Check(input.Length==bytes&&GetIdentity(input.SafeFileHandle,18,out original,24),"source length/identity differs");
    uint returned;Check(DeviceIoControl(output.SafeFileHandle,0x000900c4,IntPtr.Zero,0,IntPtr.Zero,0,out returned,IntPtr.Zero),"sparse flag failed");
    output.SetLength(bytes);byte[] buffer=new byte[1024*1024];
    while(at<bytes) {
     int wanted=(int)Math.Min(buffer.Length,bytes-at),got=0;
     while(got<wanted){int read=input.Read(buffer,got,wanted-got);Check(read>0,"short image read");got+=read;}
     hash.AppendData(buffer,0,wanted);bool nonzero=false;
     int index=0;for(;index<=wanted-Vector<byte>.Count;index+=Vector<byte>.Count){if(!Vector.EqualsAll(new Vector<byte>(buffer,index),Vector<byte>.Zero)){nonzero=true;break;}}
     if(!nonzero)for(;index<wanted;index++)if(buffer[index]!=0){nonzero=true;break;}
     if(nonzero){Check(written+wanted<=MaxWritten,"sparse copy nonzero write limit exceeded");Reserve("D:\\");output.Position=at;output.Write(buffer,0,wanted);written+=wanted;}
     at+=wanted;
     if(at%(1024L*1024*1024)==0){Reserve("D:\\");Console.WriteLine("copied logical {0} GiB; wrote {1} MiB",at/(1024*1024*1024),written/(1024*1024));}
    }
    string actual=Hex(hash.GetHashAndReset());Check(actual.Equals(pin,StringComparison.OrdinalIgnoreCase),"full source SHA-256 differs");
    output.Flush(true);Check(GetFileInformationByHandleEx(output.SafeFileHandle,1,out allocation,24)&&allocation.AllocationSize<=MaxWritten,"actual target allocation exceeds16GiB");
    Check(input.Length==bytes&&GetIdentity(input.SafeFileHandle,18,out current,24)&&original.Serial==current.Serial&&original.A==current.A&&original.B==current.B,"source identity changed");
    Reserve("D:\\");return new SparseCopyResult {source=source,destination=destination,sha256=actual,logicalBytes=bytes,nonzeroBytesWritten=written,allocatedBytes=allocation.AllocationSize};
   }
  }
 }
}
