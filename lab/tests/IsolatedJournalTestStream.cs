// Pure lazy stream fixture. No files/devices/native methods or large allocations.
using System;
using System.IO;
public sealed class IsolatedJournalTestStream : Stream {
 public long Bytes,Cursor,Generated,ReadCalls,NonzeroAt=-1,EarlyEnd=-1,FailAt=-1;
 public int MaximumRead=Int32.MaxValue;
 public bool Writable,Readable=true,Seekable=true,ExtraByte,ChangeLengthAtEnd,BadReadCount;
 bool disposed;
 public IsolatedJournalTestStream(long bytes){Bytes=bytes;}
 public override bool CanRead{get{return !disposed&&Readable;}}
 public override bool CanWrite{get{return !disposed&&Writable;}}
 public override bool CanSeek{get{return !disposed&&Seekable;}}
 public override long Length{get{if(disposed)throw new ObjectDisposedException("fixture");return Bytes+(ChangeLengthAtEnd&&Cursor>=Bytes?512:0);}}
 public override long Position{get{return Cursor;}set{Cursor=value;}}
 public override int Read(byte[] buffer,int offset,int count){
  ReadCalls++;
  if(!CanRead)throw new InvalidOperationException("Fixture cannot read.");
  if(BadReadCount)return count+1;
  if(FailAt>=0&&Cursor+count>FailAt)throw new IOException("Injected read failure.");
  long limit=EarlyEnd>=0?Math.Min(Bytes,EarlyEnd):Bytes;
  if(Cursor>=limit){if(ExtraByte&&Cursor==Bytes){buffer[offset]=1;Cursor++;Generated++;return 1;}return 0;}
  int n=(int)Math.Min(Math.Min((long)count,(long)MaximumRead),limit-Cursor);
  Array.Clear(buffer,offset,n);
  if(NonzeroAt>=Cursor&&NonzeroAt<Cursor+n)buffer[offset+(int)(NonzeroAt-Cursor)]=0x7b;
  Cursor+=n;Generated+=n;return n;
 }
 public override long Seek(long offset,SeekOrigin origin){if(!CanSeek)throw new InvalidOperationException("Fixture cannot seek.");Cursor=origin==SeekOrigin.Begin?offset:origin==SeekOrigin.Current?Cursor+offset:Bytes+offset;return Cursor;}
 public override void Flush(){}
 public override void SetLength(long value){throw new NotSupportedException();}
 public override void Write(byte[] buffer,int offset,int count){throw new NotSupportedException();}
 protected override void Dispose(bool disposing){disposed=true;base.Dispose(disposing);}
}
