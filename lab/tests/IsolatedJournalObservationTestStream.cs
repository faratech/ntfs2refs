// Lazy managed bytes for observation tests. No files, devices or native APIs.
using System;
using System.IO;
public sealed class IsolatedJournalObservationTestStream : Stream {
 public long Bytes,NonzeroAt=-1,EarlyEnd=-1,FailAt=-1,Generated,ReadCalls;
 public int MaximumRead=Int32.MaxValue;
 public bool ExtraByte,ChangeLengthAtEnd,ChangeAccessAtEnd,CloseAtEnd,BadCount,WrongPosition,WrongSeek,Writable;
 public bool Readable=true,Seekable=true;
 long position;bool closed;
 public IsolatedJournalObservationTestStream(long bytes){Bytes=bytes;}
 void Open(){if(closed)throw new ObjectDisposedException("managed observation test stream");}
 public override bool CanRead {get{return !closed&&Readable;}}
 public override bool CanSeek {get{return !closed&&Seekable;}}
 public override bool CanWrite {get{return !closed&&Writable;}}
 public override long Length {get{Open();return Bytes;}}
 public override long Position {get{Open();return position;}set{Seek(value,SeekOrigin.Begin);}}
 public override long Seek(long offset,SeekOrigin origin){Open();if(!Seekable)throw new NotSupportedException();position=origin==SeekOrigin.Begin?offset:origin==SeekOrigin.Current?position+offset:Bytes+offset;if(WrongSeek)position++;return position;}
 public override int Read(byte[] buffer,int offset,int count){
  Open();ReadCalls++;if(!Readable)throw new IOException("unreadable test stream");
  if(FailAt>=0&&position>=FailAt)throw new IOException("injected observational read failure");
  if(BadCount)return count+1;
  if(EarlyEnd>=0&&position>=EarlyEnd)return 0;
  if(position>=Bytes){
   if(ChangeLengthAtEnd)Bytes+=512;if(ChangeAccessAtEnd)Readable=false;if(CloseAtEnd)Dispose();
   if(ExtraByte){buffer[offset]=0;position++;return 1;}return 0;
  }
  int n=(int)Math.Min((long)Math.Min(count,MaximumRead),Bytes-position);
  if(EarlyEnd>=0)n=(int)Math.Min(n,Math.Max(0,EarlyEnd-position));
  Array.Clear(buffer,offset,n);
  if(NonzeroAt>=position&&NonzeroAt<position+n)buffer[offset+(int)(NonzeroAt-position)]=0xff;
  position+=n+(WrongPosition?1:0);Generated+=n;return n;
 }
 public override void Flush(){throw new NotSupportedException();}
 public override void Write(byte[] b,int offset,int count){throw new NotSupportedException();}
 public override void SetLength(long value){throw new NotSupportedException();}
 protected override void Dispose(bool disposing){closed=true;base.Dispose(disposing);}
}
