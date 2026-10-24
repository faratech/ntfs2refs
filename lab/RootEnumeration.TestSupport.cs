// Mock only; no device or VM calls.
using System;using System.Collections.Generic;using System.Text;using Ntfs2Refs;
public sealed class RootEnumerationFake:IRootEnumerationApi {
 public string Root=@"F:\",VolumeGuid=@"\\?\Volume{9022a6b7-7462-4834-8400-7099267b2ec2}\";
 public int Disk=1,Enumerations,Closes,Opens;public long Offset=16777216,Length=55834574848;
 public uint[] Results=new uint[]{0,18};public bool ThrowQuery,ThrowClose,WrongPath,WrongVolume,WrongExtent,Reparse,Malformed,InvalidOpen,ThrowOpen;
 public uint OpenError,ExtentError,AttributeError,CloseError;public List<int> Classes=new List<int>();
 public uint Open(string path,bool directory,out IntPtr h){Opens++;h=IntPtr.Zero;if(ThrowOpen)throw new Exception("unknown open");if(OpenError!=0)return OpenError;h=InvalidOpen?new IntPtr(-1):new IntPtr(directory?1:2);return 0;}
 public uint Info(IntPtr h,int cls,byte[] buffer){Classes.Add(cls);if(cls==9){BitConverter.GetBytes(Reparse?0x410U:0x10U).CopyTo(buffer,0);return AttributeError;}if(cls==0)return 0;if(cls!=10&&cls!=11)throw new Exception("Unexpected class");int at=Enumerations++;if(ThrowQuery)throw new Exception("unknown query");uint code=Results[Math.Min(at,Results.Length-1)];if(code!=0){buffer[4000]=0x5a;return code;}if(!Malformed){byte[] name=Encoding.Unicode.GetBytes("marker.bin");BitConverter.GetBytes(32U).CopyTo(buffer,56);BitConverter.GetBytes((uint)name.Length).CopyTo(buffer,60);BitConverter.GetBytes(1L).CopyTo(buffer,40);BitConverter.GetBytes(4096L).CopyTo(buffer,48);name.CopyTo(buffer,104);}return 0;}
 public uint Extents(IntPtr h,byte[] b,out uint used){used=32;BitConverter.GetBytes(1U).CopyTo(b,0);BitConverter.GetBytes((uint)(WrongExtent?Disk+1:Disk)).CopyTo(b,8);BitConverter.GetBytes(Offset).CopyTo(b,16);BitConverter.GetBytes(Length).CopyTo(b,24);return ExtentError;}
 public uint Path(IntPtr h,out string path){path=WrongPath?@"\\?\Z:\":@"\\?\"+Root;return 0;}
 public uint Volume(string root,out string volume){volume=WrongVolume?@"\\?\Volume{00000000-0000-0000-0000-000000000001}\":VolumeGuid;return 0;}
 public uint Close(IntPtr h){Closes++;if(ThrowClose)throw new Exception("unknown close");return CloseError;}
}
