// Mock-only support; none of these methods opens a device.
using System;using System.Collections.Generic;using Ntfs2Refs;
public sealed class MountFake:IMountBoundaryApi {
 public Guid Id=Guid.NewGuid(),Tg=Guid.NewGuid(),Tp=Guid.NewGuid(),Sg=Guid.NewGuid(),Sp=Guid.NewGuid();public ulong TargetAttributes=1,ShadowAttributes=3;
 public int Detaches,Sets,Closes,Opens,Queries;public uint DetachError,SetError,AbsenceError=2;public bool Attached=true,KeepAttached,IgnoreProtect,IgnoreOnline,ThrowDetach,ThrowSet,WrongTarget,WrongVhd,WrongRoute,CloseFailure,ProtectedWritable;
 public List<string> Trace=new List<string>();
 public uint OpenDisk(int number,bool writable,out IntPtr h){Opens++;Trace.Add("open:"+number+":"+writable);h=IntPtr.Zero;if(number==3&&!Attached)return AbsenceError;h=new IntPtr(number);return 0;}
 public uint OpenVhd(string path,out IntPtr h){Trace.Add("vhd");h=new IntPtr(100);return 0;}
 public uint QueryVhd(IntPtr h,uint v,out byte[] b){b=new byte[32];BitConverter.GetBytes(v).CopyTo(b,0);if(v==1){BitConverter.GetBytes(64UL*1024*1024*1024).CopyTo(b,8);BitConverter.GetBytes(4194304UL).CopyTo(b,16);BitConverter.GetBytes(2097152U).CopyTo(b,24);BitConverter.GetBytes(512U).CopyTo(b,28);}else if(v==2||v==14)(WrongVhd&&v==14?Guid.NewGuid():Id).ToByteArray().CopyTo(b,8);else BitConverter.GetBytes(v==7?3U:4096U).CopyTo(b,8);return 0;}
 public uint VhdPath(IntPtr h,out string p){p=WrongRoute?@"\\.\PhysicalDrive1":@"\\.\PhysicalDrive3";return 0;}
 public uint Detach(IntPtr h){Detaches++;Trace.Add("detach");if(ThrowDetach)throw new Exception("unknown detach activity");if(DetachError!=0)return DetachError;if(!KeepAttached)Attached=false;return 0;}
 public uint Close(IntPtr h){Closes++;Trace.Add("close:"+h);return CloseFailure?6U:0;}
 public static byte[] Layout(Guid disk,Guid partition){byte[] b=new byte[336];BitConverter.GetBytes(1U).CopyTo(b,0);BitConverter.GetBytes(2U).CopyTo(b,4);disk.ToByteArray().CopyTo(b,8);BitConverter.GetBytes(17408L).CopyTo(b,24);BitConverter.GetBytes(68719441920L).CopyTo(b,32);for(int i=0;i<2;i++){int p=48+i*144;BitConverter.GetBytes(1U).CopyTo(b,p);BitConverter.GetBytes(i==0?17408L:16777216L).CopyTo(b,p+8);BitConverter.GetBytes(i==0?16759808L:55834574848L).CopyTo(b,p+16);BitConverter.GetBytes((uint)(i+1)).CopyTo(b,p+24);new Guid(i==0?"e3c9e316-0b5c-4db8-817d-f92df00215ae":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").ToByteArray().CopyTo(b,p+32);(i==0?Guid.NewGuid():partition).ToByteArray().CopyTo(b,p+48);}return b;}
 public uint Control(IntPtr h,uint code,byte[] input,int capacity,out byte[] b){Queries++;int disk=h.ToInt32();b=new byte[capacity];ulong attrs=disk==1?TargetAttributes:ShadowAttributes;
  if(code==NativeMountBoundary.DeviceCode){BitConverter.GetBytes(7U).CopyTo(b,0);BitConverter.GetBytes((uint)disk).CopyTo(b,4);}
  else if(code==NativeMountBoundary.LengthCode)BitConverter.GetBytes(68719476736L).CopyTo(b,0);
  else if(code==NativeMountBoundary.AlignmentCode){BitConverter.GetBytes(28U).CopyTo(b,0);BitConverter.GetBytes(28U).CopyTo(b,4);BitConverter.GetBytes(512U).CopyTo(b,16);BitConverter.GetBytes(4096U).CopyTo(b,20);}
  else if(code==NativeMountBoundary.LayoutCode)b=Layout(disk==1?(WrongTarget?Guid.NewGuid():Tg):Sg,disk==1?Tp:Sp);
  else if(code==NativeMountBoundary.GetAttributesCode){BitConverter.GetBytes(16U).CopyTo(b,0);BitConverter.GetBytes(attrs).CopyTo(b,8);}
  else if(code==NativeMountBoundary.WritableCode)return (attrs&2)!=0&&!ProtectedWritable?19U:0U;
  else if(code==NativeMountBoundary.SetAttributesCode){if(disk!=1)throw new Exception("shadow mutation forbidden");Sets++;if(ThrowSet)throw new Exception("unknown attribute activity");if(SetError!=0)return SetError;ulong mask=BitConverter.ToUInt64(input,16),value=BitConverter.ToUInt64(input,8);Trace.Add("set:"+value+":"+mask);if(!(mask==2&&IgnoreProtect)&&!(mask==1&&IgnoreOnline))TargetAttributes=(TargetAttributes&~mask)|(value&mask);}
  else throw new Exception("Unexpected native code");return 0;
 }
}
