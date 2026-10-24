// Read-only semantic verification after an independently completed native handoff.
// Depends only on the retained fixture's pure parsers; never invokes its backend.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
namespace Ntfs2Refs {
 public sealed class ConvertedExpected {
  public string runId,diskGuid,partitionGuid,volumeGuid,sourceSha256,shadowSha256,fileId128,volumeSerial64,ownerSid,fileSddl,directorySddl;
  public long retainedOffset;public uint volumeSerial32,volumeFlags,totalClusters;
 }
 public sealed class ConvertedSnapshot {
  public string name;public RetainedSnapshot file;public RetainedBasic directoryBasic;public RetainedSecurity directorySecurity;public RetainedIdentity directoryIdentity;
  public uint volumeFlags,volumeSerial32,totalClusters;public bool nativeDiskVerified,readOnlyVolumeVerified;public string[] namespaceEntries;
  public List<RetainedQuery> queries=new List<RetainedQuery>();
 }
 public sealed class ConvertedSecurityPrivilege {public string name="SeSecurityPrivilege";public bool ownProcessOnly=true,beforeCaptured,adjustmentAttempted,enabled,restorationAttempted,restored,tokenClosed;public uint beforeAttributes,enabledAttributes,restoredAttributes;}
 public sealed class ConvertedVerificationResult {
  public string status="blocked",phase="preflight",error,cleanupError;public ConvertedExpected expected;
  public bool complete,stable,cleanupComplete,privilegeRestored,targetWriteRequestsIssued,protectionChanged,mountRequested,explicitFlushRequested,conversionQualified,bootQualified;
  public int payloadReadRequests;public long payloadBytesRead;public List<string> payloadHashes=new List<string>();public List<ConvertedSnapshot> snapshots=new List<ConvertedSnapshot>();public List<RetainedQuery> openQueries=new List<RetainedQuery>();public ConvertedSecurityPrivilege securityPrivilege;
 }
 public interface IConvertedVerificationApi {
  ConvertedSecurityPrivilege SecurityPrivilege{get;}void Open(ConvertedExpected expected,List<RetainedQuery> queries);void Capture(ConvertedSnapshot snapshot);byte[] ReadPayload();void Reopen();void Close();
 }
 public static partial class NativeConvertedVerification {
  public const long DiskBytes=68719476736,PartitionBytes=55834574848,PartitionOffset=16777216;
  public static uint ObservationAccess(bool directory,bool security){return (directory?0x00020081U:0x80020080U)|(security?0x01000000U:0U);}
  public static void ValidateExpected(ConvertedExpected e){
   Guid g;if(e==null||!Regex.IsMatch(e.runId??"",@"\A[0-9a-f]{32}\z")||!Guid.TryParse(e.diskGuid,out g)||g==Guid.Empty||!Guid.TryParse(e.partitionGuid,out g)||g==Guid.Empty)throw new ArgumentException("Exact nonempty run/GPT identities required.");
   if(e.volumeGuid==null||e.volumeGuid.Length!=49||!e.volumeGuid.StartsWith(@"\\?\Volume{")||!e.volumeGuid.EndsWith(@"}\")||!Guid.TryParseExact(e.volumeGuid.Substring(11,36),"D",out g)||g==Guid.Empty)throw new ArgumentException("Fresh canonical volume GUID required.");
   if(e.retainedOffset<8L*1024*1024*1024||e.retainedOffset>9L*1024*1024*1024-65536||e.retainedOffset%65536!=0||e.sourceSha256!=NativeRetainedFixture.Hash(NativeRetainedFixture.Pattern(e.runId,"A"))||e.shadowSha256!=NativeRetainedFixture.Hash(NativeRetainedFixture.Pattern(e.runId,"B")))throw new ArgumentException("Exact retained range and deterministic A/B hashes required.");
   if(!Regex.IsMatch(e.fileId128??"",@"\A[0-9a-f]{32}\z")||e.fileId128==new string('0',32)||!Regex.IsMatch(e.volumeSerial64??"",@"\A0x[0-9a-f]{16}\z")||e.totalClusters!=13631488||(e.volumeFlags&0x80000)!=0)throw new ArgumentException("Pinned shadow identity/geometry/flags required.");
   NativeRetainedFixture.SecuritySddl(e.ownerSid,false);if(String.IsNullOrEmpty(e.fileSddl)||String.IsNullOrEmpty(e.directorySddl))throw new ArgumentException("Pinned complete security descriptors required.");
  }
  static Guid GuidAt(byte[] b,int at){byte[] v=new byte[16];Array.Copy(b,at,v,0,16);return new Guid(v);}
  public static void ValidateLayout(byte[] b,ConvertedExpected e){
   if(b==null||b.Length<48||b.Length>65536||BitConverter.ToUInt32(b,0)!=1||GuidAt(b,8)!=new Guid(e.diskGuid))throw new InvalidDataException("Target native GPT disk identity differs.");
   uint count=BitConverter.ToUInt32(b,4);if(count<2||count>128||b.Length!=48+144L*count)throw new InvalidDataException("Incomplete bounded GPT layout.");
   long first=BitConverter.ToInt64(b,24),length=BitConverter.ToInt64(b,32);if(first<512||first%512!=0||length<=0||length%512!=0||first>DiskBytes-length)throw new InvalidDataException("Invalid GPT usable domain.");
   int main=0,reserved=0;HashSet<uint> numbers=new HashSet<uint>();List<long[]> ranges=new List<long[]>();
   for(int i=0;i<count;i++){int p=48+i*144;uint style=BitConverter.ToUInt32(b,p),number=BitConverter.ToUInt32(b,p+24);long at=BitConverter.ToInt64(b,p+8),n=BitConverter.ToInt64(b,p+16);Guid type=GuidAt(b,p+32),id=GuidAt(b,p+48);
    if(n==0&&number==0&&type==Guid.Empty)continue;
    if(style!=1||number==0||!numbers.Add(number)||n<=0||at<first||at%512!=0||n%512!=0||at>first+length-n||id==Guid.Empty)throw new InvalidDataException("Invalid GPT entry.");
    foreach(long[] r in ranges)if(at<r[1]&&r[0]<at+n)throw new InvalidDataException("Overlapping GPT entries.");ranges.Add(new long[]{at,at+n});
    if(number==2){if(at!=PartitionOffset||n!=PartitionBytes||id!=new Guid(e.partitionGuid)||type!=new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")||BitConverter.ToUInt64(b,p+64)!=0)throw new InvalidDataException("Original target partition differs.");main++;}
    else if(number==1&&type==new Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae")&&at+n<=PartitionOffset)reserved++;else throw new InvalidDataException("Additional GPT partition unsupported.");
   }
   if(main!=1||reserved!=1)throw new InvalidDataException("Exact target and MSR required.");
  }
  public static void CheckSnapshot(ConvertedSnapshot s,ConvertedExpected e){
   if(s==null||!s.nativeDiskVerified||!s.readOnlyVolumeVerified||s.volumeFlags!=(e.volumeFlags|0x80000U)||s.volumeSerial32!=e.volumeSerial32||s.totalClusters!=e.totalClusters)throw new InvalidDataException("Protected native ReFS volume differs.");
   RetainedSnapshot f=s.file;if(f==null||f.basic==null||f.standard==null||f.identity==null||f.security==null||f.standard.eof!=65536||f.standard.allocation!=65536||f.standard.links!=1||f.standard.directory||f.basic.attributes!=32||f.identity.fileId128!=e.fileId128||f.identity.volumeSerial64!=e.volumeSerial64||f.security.sddl!=e.fileSddl||!f.security.saclEmpty)throw new InvalidDataException("Converted file metadata or shadow identity differs.");
   CheckBasic(f.basic,false);CheckBasic(s.directoryBasic,true);if(s.directorySecurity==null||s.directorySecurity.sddl!=e.directorySddl||!s.directorySecurity.saclEmpty||s.directoryIdentity==null||s.directoryIdentity.volumeSerial64!=e.volumeSerial64)throw new InvalidDataException("Converted directory metadata differs.");
   if(f.streams==null||f.streams.Length!=1||f.streams[0]!="::$DATA"||f.extents==null||f.extents.Length!=1||f.extents[0].vcn!=0||f.extents[0].nextVcn!=16||f.extents[0].lcn<0||f.baseSectors!=0||NativeRetainedFixture.Offset(f.baseSectors,f.extents[0].lcn)!=e.retainedOffset)throw new InvalidDataException("Retained mapping or unnamed stream differs.");
   if(!f.fullyCachedValid||!f.fullyStorageValid||!f.storageRegionQueryAttempted||f.storageValidityStatus!="native-full-storage-validity"||!f.integrityQueried||f.checksumAlgorithm!=0||f.integrityFlags!=0)throw new InvalidDataException("Native ReFS validity/integrity differs.");
   NativeRetainedFixture.CheckValidity(f.cached,1);NativeRetainedFixture.CheckValidity(f.onDisk,2);
   if(s.namespaceEntries==null||s.namespaceEntries.Length<1||s.namespaceEntries.Length>3)throw new InvalidDataException("Bounded root namespace required.");HashSet<string> names=new HashSet<string>();foreach(string name in s.namespaceEntries)if(!names.Add(name)||(name!="retained"&&name!="System Volume Information"&&name!="$RECYCLE.BIN"))throw new InvalidDataException("Unreviewed root namespace.");if(!names.Contains("retained"))throw new InvalidDataException("Retained namespace absent.");
  }
  static void CheckBasic(RetainedBasic b,bool directory){long t=NativeRetainedFixture.FixtureTime;if(b==null||b.creation!=t||b.access!=t||b.write!=t||b.change!=t||b.attributes!=(directory?16U:32U))throw new InvalidDataException("Frozen timestamp/attributes differ.");}
  static bool Equal(byte[] a,byte[] b){if(a==null||b==null||a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
  public static void CheckStable(ConvertedSnapshot a,ConvertedSnapshot b){
   if(a.directoryIdentity.fileId128!=b.directoryIdentity.fileId128||a.queries.Count!=b.queries.Count||a.queries.Count<1||a.queries.Count>40)throw new InvalidDataException("Observation identity or native query coverage changed.");
   for(int i=0;i<a.queries.Count;i++){RetainedQuery x=a.queries[i],y=b.queries[i];if(x.name!=y.name||x.api!=y.api||x.code!=y.code||x.inputHex!=y.inputHex||x.capacity!=y.capacity||x.succeeded!=y.succeeded||x.nativeError!=y.nativeError||x.bytesReturned!=y.bytesReturned||!Equal(x.bytes,y.bytes))throw new InvalidDataException("Native observation buffer changed: "+x.name);}
   if(a.namespaceEntries.Length!=b.namespaceEntries.Length)throw new InvalidDataException("Root namespace changed.");for(int i=0;i<a.namespaceEntries.Length;i++)if(a.namespaceEntries[i]!=b.namespaceEntries[i])throw new InvalidDataException("Root namespace changed.");
  }
  public static ConvertedVerificationResult RunWith(IConvertedVerificationApi api,ConvertedExpected expected){
   if(api==null)throw new ArgumentNullException("api");ValidateExpected(expected);ConvertedVerificationResult r=new ConvertedVerificationResult{expected=expected,securityPrivilege=api.SecurityPrivilege};
   try{r.phase="open-protected-target";api.Open(expected,r.openQueries);ConvertedSnapshot first=null;
    foreach(string name in new[]{"before","after","reopened","final"}){
     if(name=="reopened"){r.phase="reopen-read-only-handles";api.Reopen();}
     r.phase="capture-"+name;ConvertedSnapshot s=new ConvertedSnapshot{name=name};r.snapshots.Add(s);api.Capture(s);CheckSnapshot(s,expected);if(first==null)first=s;else CheckStable(first,s);
     if(name=="before"||name=="reopened"){r.phase="logical-read-"+name;r.payloadReadRequests++;byte[] bytes=api.ReadPayload();if(bytes==null||bytes.Length!=65536)throw new IOException("Bounded logical read incomplete.");r.payloadBytesRead+=bytes.Length;string hash=NativeRetainedFixture.Hash(bytes);r.payloadHashes.Add(hash);if(hash!=expected.sourceSha256||hash==expected.shadowSha256)throw new InvalidDataException("Converted native payload is not retained A.");}
    }
    r.complete=true;r.stable=true;r.status="retained-A-observed-through-protected-ReFS";r.phase="complete";
   }catch(Exception ex){r.error=ex.ToString();}
   finally{try{api.Close();if(r.securityPrivilege==null||r.securityPrivilege.name!="SeSecurityPrivilege"||!r.securityPrivilege.ownProcessOnly||!r.securityPrivilege.restored||!r.securityPrivilege.tokenClosed)throw new IOException("Own-process security privilege cleanup is incomplete.");r.cleanupComplete=true;r.privilegeRestored=true;}catch(Exception ex){r.cleanupError=ex.ToString();r.complete=false;r.status="cleanup-failed";}}
   return r;
  }
  public static ConvertedVerificationResult Observe(ConvertedExpected expected){return RunWith(new WindowsConvertedVerificationApi(),expected);}
 }
}
