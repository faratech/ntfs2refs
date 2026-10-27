// Pure bounded observational hashing. Reports contain no stream, handle or
// ZeroProof and cannot authorize initialization, import, repair or raw writes.
using System;
using System.IO;
using System.Security.Cryptography;

namespace Ntfs2RefsResearch {
 public sealed class IsolatedJournalStreamObservation {
  public readonly string identityToken,contentSha256,startedUtc,finishedUtc;
  public readonly long requestedBytes,bytesRead,readCalls,nonzeroBytes,firstNonzeroOffset;
  public readonly bool complete,allZeroObserved;
  public bool informationalOnly {get{return true;}}
  public bool grantsInitializationAuthority {get{return false;}}
  public bool grantsWriteAuthority {get{return false;}}
  public bool atomicImmutabilityClaimed {get{return false;}}
  internal IsolatedJournalStreamObservation(string identity,string hash,string started,string finished,long requested,long count,long calls,long nonzero,long first){
   identityToken=identity;contentSha256=hash;startedUtc=started;finishedUtc=finished;requestedBytes=requested;
   bytesRead=count;readCalls=calls;nonzeroBytes=nonzero;firstNonzeroOffset=first;complete=true;allZeroObserved=nonzero==0;
  }
 }
 public static class IsolatedJournalObservation {
  public const long JournalBytes=8589934592L;
  public const int ChunkBytes=1048576,MaximumReadCalls=1048576;
  static bool Identity(string value){
   if(value==null||value.Length!=64)return false;
   foreach(char c in value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
   return true;
  }
  public static IsolatedJournalStreamObservation ObserveJournal(Stream source,string identityToken){return ObserveRange(source,JournalBytes,identityToken);}
  // The native entry uses only ObserveJournal. Small managed ranges exist for
  // pure error/boundary checks and carry no native-device observation claim.
  public static IsolatedJournalStreamObservation ObserveRange(Stream source,long expectedBytes,string identityToken){
   if(source==null||!source.CanRead||source.CanWrite||!source.CanSeek||!Identity(identityToken)||
      expectedBytes<=0||expectedBytes>JournalBytes||expectedBytes%512!=0||source.Length!=expectedBytes)
    throw new InvalidDataException("Bounded read-only observational stream, exact length and identity required.");
   string started=DateTime.UtcNow.ToString("o");
   if(source.Seek(0,SeekOrigin.Begin)!=0||source.Position!=0)throw new IOException("Observation did not begin at offset zero.");
   byte[] buffer=new byte[ChunkBytes];long count=0,calls=0,nonzero=0,first=-1;string hash;
   using(SHA256 sha=SHA256.Create()){
    while(count<expectedBytes){
     int wanted=(int)Math.Min((long)ChunkBytes,expectedBytes-count),filled=0;
     while(filled<wanted){
      if(++calls>MaximumReadCalls)throw new IOException("Observational read-call budget exhausted.");
      int read=source.Read(buffer,filled,wanted-filled);
      if(read<=0||read>wanted-filled)throw new EndOfStreamException("Incomplete observational read.");
      filled+=read;
      if(source.Position!=count+filled)throw new IOException("Observational stream position changed.");
     }
     for(int i=0;i<wanted;i++)if(buffer[i]!=0){nonzero++;if(first<0)first=count+i;}
     sha.TransformBlock(buffer,0,wanted,buffer,0);count+=wanted;
    }
    if(++calls>MaximumReadCalls)throw new IOException("Observational EOF budget exhausted.");
    if(source.ReadByte()!=-1||source.Length!=expectedBytes||source.Position!=expectedBytes||!source.CanRead||source.CanWrite||!source.CanSeek)
     throw new InvalidDataException("Observational stream length/access/EOF changed.");
    sha.TransformFinalBlock(new byte[0],0,0);hash=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
   }
   return new IsolatedJournalStreamObservation(identityToken,hash,started,DateTime.UtcNow.ToString("o"),expectedBytes,count,calls,nonzero,first);
  }
 }
}
