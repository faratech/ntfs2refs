// Pure stream checks only: no native methods, device/path opens, writes or initialization.
// A caller must independently acquire and attest the live owned device/handle.
using System;
using System.IO;
using System.Security.Cryptography;

namespace Ntfs2RefsResearch {
 public sealed class ZeroProof {
  readonly Stream source;
  readonly long requested,checkedBytes;
  readonly string identity,hash;
  readonly bool journalScope;
  private ZeroProof(Stream source,long requested,long checkedBytes,string identity,string hash,bool journalScope) {
   this.source=source;this.requested=requested;this.checkedBytes=checkedBytes;
   this.identity=identity;this.hash=hash;this.journalScope=journalScope;
  }
  internal static ZeroProof Create(Stream source,long requested,long checkedBytes,string identity,string hash,bool journalScope) {
   return new ZeroProof(source,requested,checkedBytes,identity,hash,journalScope);
  }
  public long RequestedBytes { get {return requested;} }
  public long CheckedBytes { get {return checkedBytes;} }
  public string IdentityToken { get {return identity;} }
  public string ContentSha256 { get {return hash;} }
  public bool IsJournalScope { get {return journalScope;} }
  // This proves only the supplied stream's read. It is never native write authority.
  public bool GrantsWriteAuthority { get {return false;} }
  public void AssertCurrent(Stream candidate,string token) {
   if(!Object.ReferenceEquals(source,candidate)||candidate==null||!candidate.CanRead||candidate.CanWrite||!candidate.CanSeek
      ||candidate.Length!=requested||checkedBytes!=requested||!String.Equals(identity,token,StringComparison.Ordinal))
    throw new InvalidDataException("Zero proof is not current for the same held read-only stream and identity.");
  }
 }
 public static class IsolatedJournalZero {
  public const long JournalBytes=8589934592L;
  const int ChunkBytes=1048576;
  static bool Identity(string token) {
   if(token==null||token.Length!=64)return false;
   foreach(char c in token)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
   return true;
  }
  public static ZeroProof ScanJournal(Stream source,string identityToken) {
   return Scan(source,JournalBytes,identityToken,true);
  }
  // Small pure fixtures can exercise every error/boundary path. These proofs
  // cannot satisfy the journal-scope gate, even if expectedBytes equals 8 GiB.
  public static ZeroProof ScanRange(Stream source,long expectedBytes,string identityToken) {
   return Scan(source,expectedBytes,identityToken,false);
  }
  static ZeroProof Scan(Stream source,long expectedBytes,string identityToken,bool journalScope) {
   if(source==null||!source.CanRead||source.CanWrite||!source.CanSeek||!Identity(identityToken)
      ||expectedBytes<=0||expectedBytes>JournalBytes||expectedBytes%512!=0||source.Length!=expectedBytes)
    throw new InvalidDataException("Bounded held read-only stream, exact length and identity token required.");
   source.Seek(0,SeekOrigin.Begin);
   byte[] buffer=new byte[ChunkBytes];
   long checkedBytes=0;
   string digest;
   using(SHA256 sha=SHA256.Create()) {
    while(checkedBytes<expectedBytes) {
     int count=(int)Math.Min((long)ChunkBytes,expectedBytes-checkedBytes),filled=0;
     while(filled<count) {
      int read=source.Read(buffer,filled,count-filled);
      if(read<=0||read>count-filled)throw new EndOfStreamException("Incomplete journal zero verification.");
      filled+=read;
     }
     for(int i=0;i<count;i++)if(buffer[i]!=0)
      throw new InvalidDataException("Nonzero journal byte at offset "+(checkedBytes+i)+"; initialization refused.");
     sha.TransformBlock(buffer,0,count,buffer,0);
     checkedBytes+=count;
    }
    if(source.ReadByte()!=-1||source.Length!=expectedBytes||!source.CanRead||source.CanWrite)
     throw new InvalidDataException("Journal stream length/access changed or extra bytes remain.");
    sha.TransformFinalBlock(new byte[0],0,0);
    digest=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
   }
   return ZeroProof.Create(source,expectedBytes,checkedBytes,identityToken,digest,journalScope);
  }
 }
}
