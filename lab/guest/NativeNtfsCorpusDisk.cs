// Disposable NTFS oracle fixture staging; never part of conversion or its I/O API.
using System;using System.IO;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.Cryptography;using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public static class NativeNtfsCorpusDisk {
  const long Offset=16777216,Length=1073741824;const int Chunk=1048576;
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inputBytes,byte[] output,uint capacity,out uint used,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFilePointerEx(SafeFileHandle h,long offset,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool WriteFile(SafeFileHandle h,IntPtr b,uint n,out uint used,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(SafeFileHandle h,IntPtr b,uint n,out uint used,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool FlushFileBuffers(SafeFileHandle h);
  static byte[] Query(SafeFileHandle h,uint code,int count){byte[] b=new byte[count];uint used;if(!DeviceIoControl(h,code,null,0,b,(uint)count,out used,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());if(used>count)throw new IOException("Oversized response.");Array.Resize(ref b,(int)used);return b;}
  static Guid GuidAt(byte[] b,int at){byte[] a=new byte[16];Array.Copy(b,at,a,0,16);return new Guid(a);}
  static void Validate(SafeFileHandle h,Guid disk,Guid part,ulong attrs){
   byte[] a=Query(h,0x700f0,16),n=Query(h,0x7405c,8),b=Query(h,0x70050,65536);
   if(a.Length!=16||BitConverter.ToUInt64(a,8)!=attrs||n.Length!=8||BitConverter.ToInt64(n,0)!=68719476736||b.Length<48||BitConverter.ToUInt32(b,0)!=1||GuidAt(b,8)!=disk)throw new IOException("Owned GPT disk or attribute state differs.");
   uint count=BitConverter.ToUInt32(b,4);if(count<2||count>128||b.Length!=48+count*144)throw new IOException("Incomplete layout.");int found=0;
   for(int i=0;i<count;i++){int p=48+i*144;if(BitConverter.ToUInt32(b,p+24)==2&&GuidAt(b,p+48)==part&&GuidAt(b,p+32)==new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")&&BitConverter.ToInt64(b,p+8)==Offset&&BitConverter.ToInt64(b,p+16)==Length)found++;}
   if(found!=1||disk==Guid.Empty||part==Guid.Empty)throw new IOException("Exact 1 GiB corpus partition absent.");
  }
  static SafeFileHandle Open(bool write){SafeFileHandle h=CreateFileW(@"\\.\PhysicalDrive1",0x80000000U|(write?0x40000000U:0),3,IntPtr.Zero,3,0x20000000U|(write?0x80000000U:0),IntPtr.Zero);if(h.IsInvalid){int e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e);}return h;}
  static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  static void Seek(SafeFileHandle h){long p;if(!SetFilePointerEx(h,Offset,out p,0)||p!=Offset)throw new Win32Exception(Marshal.GetLastWin32Error(),"Seek corpus partition");}
  public static string Hash(Guid disk,Guid part,ulong attrs){
   using(SafeFileHandle h=Open(false)){Validate(h,disk,part,attrs);Seek(h);IntPtr allocation=Marshal.AllocHGlobal(Chunk+4095);try{IntPtr aligned=new IntPtr((allocation.ToInt64()+4095)&~4095L);byte[] b=new byte[Chunk];using(SHA256 sha=SHA256.Create()){for(long at=0;at<Length;at+=Chunk){uint used;if(!ReadFile(h,aligned,Chunk,out used,IntPtr.Zero)||used!=Chunk)throw new IOException("Short corpus disk read.");Marshal.Copy(aligned,b,0,Chunk);sha.TransformBlock(b,0,Chunk,null,0);}sha.TransformFinalBlock(new byte[0],0,0);Validate(h,disk,part,attrs);return Hex(sha.Hash);}}finally{Marshal.FreeHGlobal(allocation);}}
  }
  public static long Restore(string source,string expected,Guid disk,Guid part){
   if(!System.Text.RegularExpressions.Regex.IsMatch(source??"",@"\AC:\\ntfs2refs\\ntfs-attestation\\[0-9a-f]{32}\\control\.raw\z")||expected!="86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727")throw new ArgumentException("Only frozen owned native NTFS corpus accepted.");
   using(FileStream input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read)){if(input.Length!=Length)throw new IOException("Corpus length differs.");using(SHA256 sha=SHA256.Create()){if(Hex(sha.ComputeHash(input))!=expected)throw new IOException("Corpus hash differs.");}input.Position=0;
    using(SafeFileHandle h=Open(true)){Validate(h,disk,part,1);Seek(h);IntPtr allocation=Marshal.AllocHGlobal(Chunk+4095);try{IntPtr aligned=new IntPtr((allocation.ToInt64()+4095)&~4095L);byte[] b=new byte[Chunk];for(long at=0;at<Length;at+=Chunk){int n=0;while(n<Chunk){int read=input.Read(b,n,Chunk-n);if(read==0)throw new EndOfStreamException();n+=read;}Marshal.Copy(b,0,aligned,Chunk);uint used;if(!WriteFile(h,aligned,Chunk,out used,IntPtr.Zero)||used!=Chunk)throw new IOException("Short corpus disk write; preserve branch.");}if(!FlushFileBuffers(h))throw new Win32Exception(Marshal.GetLastWin32Error());Validate(h,disk,part,1);}finally{Marshal.FreeHGlobal(allocation);}}
   }
   if(Hash(disk,part,1)!=expected)throw new IOException("Restored corpus differs; preserve branch.");return Length;
  }
 }
}
