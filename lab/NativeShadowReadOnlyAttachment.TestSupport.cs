// Mock-only physical-device responses; this class never opens a device.
using System;using System.Collections.Generic;using Ntfs2Refs;
public sealed class ShadowProtectionFake:IShadowProtectionApi {
 public Guid Disk=Guid.NewGuid(),Partition=Guid.NewGuid();public ulong Attributes;
 public int Opens,WriteOpens,Sets,Closes,Queries;public uint OpenError,WriteOpenError,SetError,CloseError,WritableError=19;
 public bool IgnoreSet,ThrowOpen,ThrowSet,ThrowClose,WrongDevice,WrongLength,WrongAlignment,WrongLayout,WrongPreSetLayout,ChangeUnrequested,AliasHandles,Malformed;
 public int ThrowQuery,FailQuery;public uint QueryError=21;public readonly List<string> Trace=new List<string>();
 public uint Open(bool writable,out IntPtr h){Opens++;Trace.Add(writable?"open-write":"open-read");h=IntPtr.Zero;if(ThrowOpen)throw new Exception("unknown open");uint e=writable?WriteOpenError:OpenError;if(writable)WriteOpens++;if(e==0)h=new IntPtr(writable&&!AliasHandles?31:30);return e;}
 public uint Close(IntPtr h){Closes++;Trace.Add("close:"+h);if(ThrowClose)throw new Exception("unknown close");return CloseError;}
 public uint Control(IntPtr h,uint code,byte[] input,int capacity,out byte[] b){Queries++;Trace.Add("query:"+code);b=new byte[capacity];if(ThrowQuery==Queries)throw new Exception("unknown query");if(FailQuery==Queries){b=new byte[0];return QueryError;}if(Malformed){b=new byte[capacity+1];return 0;}
  if(code==NativeMountBoundary.DeviceCode){BitConverter.GetBytes(7U).CopyTo(b,0);BitConverter.GetBytes(WrongDevice?1U:3U).CopyTo(b,4);}
  else if(code==NativeMountBoundary.LengthCode)BitConverter.GetBytes(WrongLength?1L:68719476736L).CopyTo(b,0);
  else if(code==NativeMountBoundary.AlignmentCode){if(capacity!=28||input.Length!=12||input[0]!=6)throw new Exception("wrong alignment request");BitConverter.GetBytes(28U).CopyTo(b,0);BitConverter.GetBytes(28U).CopyTo(b,4);BitConverter.GetBytes(512U).CopyTo(b,16);BitConverter.GetBytes(WrongAlignment?512U:4096U).CopyTo(b,20);}
  else if(code==NativeMountBoundary.LayoutCode)b=MountFake.Layout(WrongLayout||(WrongPreSetLayout&&h==new IntPtr(31))?Guid.NewGuid():Disk,Partition);
  else if(code==NativeMountBoundary.GetAttributesCode){BitConverter.GetBytes(16U).CopyTo(b,0);BitConverter.GetBytes(ChangeUnrequested&&Queries>6?3UL:Attributes).CopyTo(b,8);}
  else if(code==NativeMountBoundary.WritableCode){if(capacity!=0||input!=null)throw new Exception("wrong writability request");return WritableError;}
  else if(code==NativeMountBoundary.SetAttributesCode){Sets++;Trace.Add("set");if(h!=new IntPtr(31)&&!AliasHandles)throw new Exception("SET without attribute handle");if(input.Length!=40||BitConverter.ToUInt32(input,0)!=40||input[4]!=1||BitConverter.ToUInt64(input,8)!=3||BitConverter.ToUInt64(input,16)!=3)throw new Exception("wrong explicit exclusion request");if(ThrowSet)throw new Exception("unknown SET");if(SetError!=0)return SetError;if(!IgnoreSet)Attributes=3;}
  else throw new Exception("unexpected native request");return 0;
 }
}
