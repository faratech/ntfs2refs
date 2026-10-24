// Construction and evidence for one retained-extent fixture; no conversion/raw writer.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class RetainedQuery { public string name,api,inputHex,startedUtc,finishedUtc;public uint code,bytesReturned;public int capacity,nativeError;public bool succeeded;public byte[] bytes; }
 public sealed class RetainedBasic { public long creation,access,write,change;public uint attributes; }
 public sealed class RetainedStandard { public long allocation,eof;public uint links;public bool directory; }
 public sealed class RetainedIdentity { public string fileId128,volumeSerial64; }
 public sealed class RetainedExtent { public long vcn,nextVcn,lcn; }
 public sealed class RetainedRegion { public long offset,length;public uint usage; }
 public sealed class RetainedBitmapCoverage { public long startingLcn,declaredClusters;public int meaningfulBytes,returnedBytes,trailingBytes,unusedBitsInLastByte; }
 public sealed class RetainedAccessPolicy {
  public string path,stage,api="SetFileTime",inputHex="ffffffffffffffff",startedUtc,finishedUtc;public bool writeAttributesAccessRequested,creationTimeNull,lastWriteTimeNull,succeeded;public int nativeError;
 }
 public sealed class RetainedSecurity { public string sddl,owner,group,daclSddl;public bool daclProtected,saclPresent,saclEmpty;public int saclAceCount;public byte[] bytes; }
 public sealed class RetainedDirectoryEntry { public string name,fileId64;public uint attributes;public long eof,allocation; }
 public sealed class RetainedNamespace { public string path,stage,initialNoMatchInterpretation;public bool expectedFixture,complete,emptyInitialNoMatchInterpreted;public string[] queryNames;public RetainedDirectoryEntry[] entries; }
 public sealed class RetainedSnapshot {
  public string name,sha256;public RetainedBasic basic;public RetainedStandard standard;public RetainedIdentity identity;public RetainedSecurity security;
  public string[] streams;public RetainedExtent[] extents;public RetainedRegion[] cached,onDisk;public long baseSectors,partitionOffset=-1;
  public ushort checksumAlgorithm;public uint integrityFlags;public bool integrityQueried,fullyCachedValid,fullyStorageValid,storageRegionQueryAttempted;public string storageValidityStatus;
 }
 public sealed class RetainedFixtureState {
  public string root,volume,role,path,expectedSha256,filesystem,initializationProof;public uint volumeFlags,volumeSerial32,nativeTotalClusters,payloadBytesWritten;public bool directoryCreated,fileCreated,payloadInitialized,creationFlushed,creationClosed,metadataSet;
  public bool moveAttempted,moveCompleted,moveSucceeded,requestedPlacementObserved;public int moveCallCount;
  public RetainedSnapshot before,after;public RetainedBasic directoryBasic;public RetainedSecurity directorySecurity;
 }
 public sealed class RetainedPairResult {
  public string status="blocked",phase="preflight",error,cleanupError,runId;public bool targetWriteRequestsIssued,cleanupComplete,privilegeRestored;
  public bool physicalMappingVerified,conversionQualified,sourceFrozen,pairSemanticsMatch,writeHandlesClosedBeforeFinalObservation;public long candidateLcn=-1;
  public RetainedFixtureState source,shadow;public List<RetainedQuery> queries=new List<RetainedQuery>();
  public bool lastAccessPolicyVerified;public List<RetainedAccessPolicy> lastAccessPolicies=new List<RetainedAccessPolicy>();
  public bool namespaceVerified;public List<RetainedNamespace> namespaces=new List<RetainedNamespace>();
 }
 public interface IRetainedFixtureApi {
  void Open(RetainedPairResult result,bool construct);
  void Create(RetainedFixtureState state);
  RetainedSnapshot Observe(RetainedFixtureState state,string name);
  byte[] Bitmap(RetainedFixtureState state,bool metadata,string name);
  bool Move(RetainedFixtureState state,long lcn);
  void SetMetadata(RetainedFixtureState state);
  void Seal();
  void Close();
 }
 public static partial class NativeRetainedFixture {
  public const long VolumeBytes=55834574848L,Clusters=13631488,FixtureBytes=65536;
  public const int BitmapCapacity=2097152;
  public static readonly long FixtureTime=new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc).ToFileTimeUtc();
  public static void ValidateProfile(string root,string volume,string runId,string role) {
   Guid id;if((root!=@"F:\"&&root!=@"S:\")||(root==@"F:\"&&role!="A")||(root==@"S:\"&&role!="B")||!Regex.IsMatch(runId??"","^[0-9a-f]{32}$"))throw new ArgumentException("Exact F:/S: root, role and run ID required.");
   if(volume==null||volume.Length!=49||!volume.StartsWith(@"\\?\Volume{",StringComparison.OrdinalIgnoreCase)||!volume.EndsWith(@"}\")||!Guid.TryParseExact(volume.Substring(11,36),"D",out id)||id==Guid.Empty)throw new ArgumentException("Native volume GUID required.");
  }
  public static byte[] Pattern(string runId,string role) {
   if(!Regex.IsMatch(runId??"","^[0-9a-f]{32}$")||(role!="A"&&role!="B"))throw new ArgumentException("Pattern run/role invalid.");byte[] b=new byte[65536],seed;
   using(SHA256 sha=SHA256.Create())seed=sha.ComputeHash(Encoding.ASCII.GetBytes("N2R-RETAINED-V1|"+runId));
   for(int i=0;i<b.Length;i++){byte x=(byte)(seed[i%32]^((i*37+i/4096*19)&255));b[i]=role=="A"?x:(byte)(x^255);}return b;
  }
  public static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
  public static string Hash(byte[] b){using(SHA256 sha=SHA256.Create())return Hex(sha.ComputeHash(b));}
  public static RetainedAccessPolicy AccessPolicy(string path,string stage){
   bool root=path==@"F:\"||path==@"S:\",folder=path==@"F:\retained"||path==@"S:\retained",file=path==@"F:\retained\payload.bin"||path==@"S:\retained\payload.bin";
   if(!(root&&stage=="root")&&!(folder&&(stage=="construction"||stage=="observation"))&&!(file&&(stage=="created"||stage=="construction"||stage=="observation")))throw new ArgumentException("Last-access suppression is limited to exact fixture handles.");
   return new RetainedAccessPolicy{path=path,stage=stage,writeAttributesAccessRequested=true,creationTimeNull=true,lastWriteTimeNull=true,startedUtc=DateTime.UtcNow.ToString("o")};
  }
  public static void CheckAccessPolicies(RetainedPairResult r,bool construct){
   if(r.lastAccessPolicies==null||r.lastAccessPolicies.Count!=(construct?12:6))throw new InvalidDataException("Every root/directory/file handle requires last-access suppression.");
   foreach(string root in new[]{@"F:\",@"S:\"})foreach(string suffix in new[]{"","retained","retained\\payload.bin"})foreach(string stage in new[]{"root","created","construction","observation"}){
    string path=root+suffix;bool expected=suffix==""?stage=="root":suffix=="retained"?(stage=="observation"||(construct&&stage=="construction")):(stage=="observation"||(construct&&(stage=="created"||stage=="construction")));
    int count=0;foreach(RetainedAccessPolicy p in r.lastAccessPolicies){
     if(p==null||p.api!="SetFileTime"||p.inputHex!="ffffffffffffffff"||!p.writeAttributesAccessRequested||!p.creationTimeNull||!p.lastWriteTimeNull||!p.succeeded||p.nativeError!=0||String.IsNullOrEmpty(p.startedUtc)||String.IsNullOrEmpty(p.finishedUtc))throw new InvalidDataException("Unqualified last-access handle policy.");
     AccessPolicy(p.path,p.stage);if(p.path==path&&p.stage==stage)count++;
    }
    if(count!=(expected?1:0))throw new InvalidDataException("Last-access policy handle coverage differs.");
   }
  }
  public static RetainedDirectoryEntry[] ParseDirectory(byte[] b){
   if(b==null||b.Length!=4096)throw new InvalidDataException("Exact bounded directory buffer required.");List<RetainedDirectoryEntry> entries=new List<RetainedDirectoryEntry>();int p=0;
   while(true){
    if(p<0||p>b.Length-104||entries.Count>=5)throw new InvalidDataException("Directory entry bounds exceeded.");uint next=BitConverter.ToUInt32(b,p),length=BitConverter.ToUInt32(b,p+60);int available=next==0?b.Length-p:checked((int)next);
    if(available<104||available>b.Length-p||(next!=0&&(next%8!=0||next<112))||length==0||length>510||length%2!=0||length>available-104||b[p+68]>24||b[p+68]%2!=0)throw new InvalidDataException("Invalid directory ABI offsets/name length.");
    string name=new UnicodeEncoding(false,false,true).GetString(b,p+104,(int)length);if(name.IndexOfAny(new[]{'\0','\\','/',':'})>=0)throw new InvalidDataException("Ambiguous directory name.");
    RetainedDirectoryEntry e=new RetainedDirectoryEntry{name=name,attributes=BitConverter.ToUInt32(b,p+56),eof=BitConverter.ToInt64(b,p+40),allocation=BitConverter.ToInt64(b,p+48),fileId64="0x"+BitConverter.ToUInt64(b,p+96).ToString("x16")};
    if(e.eof<0||e.allocation<0||(e.attributes&0x400)!=0)throw new InvalidDataException("Unsupported directory object.");entries.Add(e);if(next==0)break;p=checked(p+(int)next);
   }return entries.ToArray();
  }
  public static void CheckNamespace(RetainedNamespace n){
   bool root=n.path==@"F:\"||n.path==@"S:\",folder=n.path==@"F:\retained"||n.path==@"S:\retained";
   if((!root&&!folder)||n.entries==null||n.entries.Length>(root?5:3)||(folder&&!n.expectedFixture))throw new InvalidDataException("Exact namespace profile required.");HashSet<string> seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int fixture=0;
   foreach(RetainedDirectoryEntry e in n.entries){
    if(e==null||String.IsNullOrEmpty(e.name)||!seen.Add(e.name)||(e.attributes&0x400)!=0)throw new InvalidDataException("Duplicate/reparse namespace entry.");
    if(e.name=="."||e.name==".."){if((e.attributes&16)==0)throw new InvalidDataException("Dot entry is not directory.");continue;}
    if(root){if(e.name!="retained"&&e.name!="System Volume Information"&&e.name!="$RECYCLE.BIN")throw new InvalidDataException("Unexpected root object.");if((e.attributes&16)==0)throw new InvalidDataException("Root entry must be directory.");if(e.name=="retained")fixture++;}
    else{if(e.name!="payload.bin"||e.attributes!=32||e.eof!=65536||e.allocation!=65536)throw new InvalidDataException("Only initialized ordinary64KiB payload permitted.");fixture++;}
   }if(fixture!=(n.expectedFixture?1:0))throw new InvalidDataException("Fixture namespace presence differs.");
  }
  public static void CheckNamespaces(RetainedPairResult r,bool construct){
   if(r.namespaces==null||r.namespaces.Count!=10)throw new InvalidDataException("All pinned root/folder observations required.");
   foreach(string root in new[]{@"F:\",@"S:\"})foreach(string stage in new[]{"OpenRoot","BeforeRoot","BeforeFolder","AfterRoot","AfterFolder"}){
    string path=root+(stage.EndsWith("Folder")?"retained":"");int matches=0;
    foreach(RetainedNamespace n in r.namespaces){if(n.path!=path||n.stage!=stage)continue;matches++;CheckNamespace(n);if(!n.complete||n.expectedFixture!=(stage!="OpenRoot"||!construct)||n.queryNames==null||n.queryNames.Length<1||n.queryNames.Length>4)throw new InvalidDataException("Incomplete directory enumeration.");
     bool interpreted=n.emptyInitialNoMatchInterpreted;if(interpreted?(!construct||stage!="OpenRoot"||n.expectedFixture||n.entries.Length!=0||n.queryNames.Length!=2||n.initialNoMatchInterpretation!="documented-first-empty-search-not-reproduced-by-lab-diagnostic"):!String.IsNullOrEmpty(n.initialNoMatchInterpretation))throw new InvalidDataException("Initial empty-search interpretation outside construction profile.");
     List<RetainedDirectoryEntry> parsed=new List<RetainedDirectoryEntry>();for(int i=0;i<n.queryNames.Length;i++){RetainedQuery q=null;int count=0;foreach(RetainedQuery candidate in r.queries)if(candidate.name==n.queryNames[i]){q=candidate;count++;}bool end=i==n.queryNames.Length-1,initial=interpreted&&i==0;
      if(count!=1||q.name!=(root==@"F:\"?"A":"B")+stage+"Directory"+i||q.api!="GetFileInformationByHandleEx"||q.code!=(i==0?11U:10U)||q.capacity!=4096||q.inputHex!=""||(initial?(q.succeeded||q.nativeError!=2||q.bytesReturned!=0):end?(q.succeeded||q.nativeError!=18||q.bytesReturned!=0):(!q.succeeded||q.nativeError!=0||q.bytesReturned!=4096)))throw new InvalidDataException("Directory query sequence evidence differs.");if(!end&&!initial)parsed.AddRange(ParseDirectory(q.bytes));
     }
     if(parsed.Count!=n.entries.Length)throw new InvalidDataException("Directory raw/summary count differs.");for(int i=0;i<parsed.Count;i++){RetainedDirectoryEntry a=parsed[i],b=n.entries[i];if(a.name!=b.name||a.attributes!=b.attributes||a.eof!=b.eof||a.allocation!=b.allocation||a.fileId64!=b.fileId64)throw new InvalidDataException("Directory raw/summary differs.");}
    }if(matches!=1)throw new InvalidDataException("Namespace observation coverage differs.");
   }
  }
  public static RetainedBasic ParseBasic(byte[] b,bool directory) {
   if(b==null||b.Length!=40)throw new InvalidDataException("Exact basic information required.");RetainedBasic x=new RetainedBasic{creation=BitConverter.ToInt64(b,0),access=BitConverter.ToInt64(b,8),write=BitConverter.ToInt64(b,16),change=BitConverter.ToInt64(b,24),attributes=BitConverter.ToUInt32(b,32)};
   if(x.creation<=0||x.access<=0||x.write<=0||x.change<=0||x.attributes!=(directory?16U:32U))throw new InvalidDataException("Unsupported timestamps/attributes.");return x;
  }
  public static RetainedStandard ParseStandard(byte[] b,bool directory) {
   if(b==null||b.Length!=24)throw new InvalidDataException("Exact standard information required.");RetainedStandard x=new RetainedStandard{allocation=BitConverter.ToInt64(b,0),eof=BitConverter.ToInt64(b,8),links=BitConverter.ToUInt32(b,16),directory=b[21]!=0};
   if(b[20]!=0||b[21]!=(directory?1:0)||x.links!=1||(!directory&&(x.eof!=65536||x.allocation!=65536)))throw new InvalidDataException("Unsupported length/allocation/link/type.");return x;
  }
  public static RetainedIdentity ParseIdentity(byte[] b) {
   if(b==null||b.Length!=24)throw new InvalidDataException("128-bit identity required.");byte[] id=new byte[16];Array.Copy(b,8,id,0,16);string hex=Hex(id);if(hex==new string('0',32))throw new InvalidDataException("Empty file ID.");return new RetainedIdentity{fileId128=hex,volumeSerial64="0x"+BitConverter.ToUInt64(b,0).ToString("x16")};
  }
  public static string[] ParseStreams(byte[] b) {
   if(b==null||b.Length<38||b.Length>4096)throw new InvalidDataException("Bounded stream information required.");uint next=BitConverter.ToUInt32(b,0),n=BitConverter.ToUInt32(b,4);
   if(next!=0||n!=14||24+n>b.Length||new UnicodeEncoding(false,false,true).GetString(b,24,(int)n)!="::$DATA"||BitConverter.ToInt64(b,8)!=65536||BitConverter.ToInt64(b,16)!=65536)throw new InvalidDataException("Only exact initialized unnamed data stream supported.");return new string[]{"::$DATA"};
  }
  public static RetainedExtent[] ParseExtents(byte[] b) {
   if(b==null||b.Length<32||b.Length>272||BitConverter.ToInt64(b,8)!=0)throw new InvalidDataException("Bounded mapping required.");uint n=BitConverter.ToUInt32(b,0);if(n<1||n>16||b.Length!=16+16*n)throw new InvalidDataException("Extent count invalid.");List<RetainedExtent> rows=new List<RetainedExtent>();long v=0;
   for(int i=0;i<n;i++){long end=BitConverter.ToInt64(b,16+16*i),lcn=BitConverter.ToInt64(b,24+16*i);if(end<=v||end>16||lcn<0||lcn>Clusters-(end-v))throw new InvalidDataException("Negative/incomplete/out-of-volume map.");rows.Add(new RetainedExtent{vcn=v,nextVcn=end,lcn=lcn});v=end;}if(v!=16)throw new InvalidDataException("Map must cover16 clusters.");return rows.ToArray();
  }
  public static byte[] RegionInput(uint usage){if(usage!=1&&usage!=2)throw new ArgumentException("Validity usage required.");byte[] b=new byte[24];BitConverter.GetBytes(65536L).CopyTo(b,8);BitConverter.GetBytes(usage).CopyTo(b,16);return b;}
  public static RetainedRegion[] ParseValidRegions(byte[] b,uint usage) {
   RegionInput(usage);if(b==null||b.Length<40||b.Length>400)throw new InvalidDataException("Bounded regions required.");uint total=BitConverter.ToUInt32(b,4),n=BitConverter.ToUInt32(b,8);if(n<1||n>16||n!=total||b.Length!=16+24*n)throw new InvalidDataException("Incomplete region reply.");List<RetainedRegion> rows=new List<RetainedRegion>();long offset=0;
   for(int i=0;i<n;i++){long o=BitConverter.ToInt64(b,16+i*24),length=BitConverter.ToInt64(b,24+i*24);uint u=BitConverter.ToUInt32(b,32+i*24);if(o!=offset||length<=0||length>65536-o||(u&~31U)!=0||(u&usage)==0)throw new InvalidDataException("Every byte must have requested native validity.");rows.Add(new RetainedRegion{offset=o,length=length,usage=u});offset+=length;}if(offset!=65536)throw new InvalidDataException("Incomplete validity coverage.");return rows.ToArray();
  }
  public static long ParseBase(byte[] b){if(b==null||b.Length!=8)throw new InvalidDataException("Exact base reply required.");long n=BitConverter.ToInt64(b,0);if(n<0||n>VolumeBytes/512-128)throw new InvalidDataException("Base outside volume.");return n;}
  public static long Offset(long sectors,long lcn){if(sectors<0||lcn<0||sectors>VolumeBytes/512||lcn>Clusters-16)throw new InvalidDataException("Address exceeds geometry.");long o=checked(sectors*512+lcn*4096);if(o>VolumeBytes-65536)throw new InvalidDataException("Range exceeds partition.");return o;}
  public static void CheckCandidate(long lcn){if(lcn<65536||lcn%16!=0||lcn>Clusters-16)throw new ArgumentException("Aligned bounded16-cluster candidate required.");}
  public static RetainedBitmapCoverage DescribeBitmap(byte[] b){
   if(b==null||b.Length<16||b.Length>BitmapCapacity||BitConverter.ToInt64(b,0)!=0)throw new InvalidDataException("Complete bounded bitmap required.");
   long bits=BitConverter.ToInt64(b,8);if(bits<2359296||bits>Clusters)throw new InvalidDataException("Bitmap declares unsupported coverage.");int meaningful=checked(16+(int)((bits+7)/8));
   if(b.Length<meaningful)throw new InvalidDataException("Bitmap declared coverage is incomplete.");
   // Some native ReFS replies return the full output capacity. Extra bytes do
   // not describe extra clusters; retain them as evidence and never scan them.
   return new RetainedBitmapCoverage{startingLcn=0,declaredClusters=bits,meaningfulBytes=meaningful,returnedBytes=b.Length,trailingBytes=b.Length-meaningful,unusedBitsInLastByte=(int)((8-bits%8)%8)};
  }
  public static void CheckBitmap(byte[] b){DescribeBitmap(b);}
  public static bool IsFree(byte[] b,long lcn){CheckCandidate(lcn);CheckBitmap(b);if(lcn>BitConverter.ToInt64(b,8)-16)throw new InvalidDataException("Candidate exceeds returned bitmap coverage.");for(long i=lcn;i<lcn+16;i++)if((b[16+(int)(i/8)]&(1<<(int)(i%8)))!=0)return false;return true;}
  public static long SelectCandidate(byte[] ntfs,byte[] refsLegacy,byte[] refsMetadata) {
   CheckBitmap(ntfs);CheckBitmap(refsLegacy);CheckBitmap(refsMetadata);
   // Bounded 8 GiB..9 GiB search; never scan indefinitely or infer metadata coverage.
   for(long lcn=2097152;lcn<2359296;lcn+=16)if(IsFree(ntfs,lcn)&&IsFree(refsLegacy,lcn)&&IsFree(refsMetadata,lcn))return lcn;throw new InvalidDataException("No common free range in bounded candidate window.");
  }
  public static byte[] MoveInput(long handle,long lcn){CheckCandidate(lcn);if(handle<=0||IntPtr.Size!=8)throw new ArgumentException("Pinned x64 file handle required.");byte[] b=new byte[32];BitConverter.GetBytes(handle).CopyTo(b,0);BitConverter.GetBytes(lcn).CopyTo(b,16);BitConverter.GetBytes(16U).CopyTo(b,24);return b;}
  public static void CheckNotMapped(long lcn,RetainedExtent[] map){CheckCandidate(lcn);if(map==null||map.Length<1||map.Length>16)throw new InvalidDataException("Missing current source map.");foreach(RetainedExtent e in map){if(e==null||e.lcn<0||e.nextVcn<=e.vcn)throw new InvalidDataException("Invalid exclusion map.");if(lcn<e.lcn+e.nextVcn-e.vcn&&e.lcn<lcn+16)throw new InvalidDataException("Candidate overlaps an existing initialized file extent.");}}
  public static string SecuritySddl(string sid,bool directory) {
   if(!Regex.IsMatch(sid??"",@"^S-1-5-21-(\d+-){3}\d+$"))throw new ArgumentException("Local guest SID required.");string f=directory?"OICI":"";return "O:"+sid+"G:BAD:P(A;"+f+";FA;;;SY)(A;"+f+";FA;;;BA)(A;"+f+";FA;;;"+sid+")S:P";
  }
  public static RetainedSecurity ParseSecurity(byte[] b,string sid,bool directory) {
   SecuritySddl(sid,directory);if(b==null||b.Length<20||b.Length>16384)throw new InvalidDataException("Bounded full security descriptor required.");RawSecurityDescriptor sd=new RawSecurityDescriptor(b,0);
   if(sd.Owner==null||sd.Owner.Value!=sid||sd.Group==null||sd.Group.Value!="S-1-5-32-544"||(sd.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0||sd.DiscretionaryAcl==null||sd.DiscretionaryAcl.Count!=3||(sd.SystemAcl!=null&&sd.SystemAcl.Count!=0))throw new InvalidDataException("Owner/group/DACL or empty SACL profile changed.");
   HashSet<string> allowed=new HashSet<string>(new string[]{sid,"S-1-5-18","S-1-5-32-544"});AceFlags expected=directory?(AceFlags.ObjectInherit|AceFlags.ContainerInherit):AceFlags.None;
   foreach(GenericAce item in sd.DiscretionaryAcl){CommonAce ace=item as CommonAce;if(ace==null||ace.AceType!=AceType.AccessAllowed||ace.AccessMask!=0x1f01ff||ace.AceFlags!=expected||!allowed.Remove(ace.SecurityIdentifier.Value))throw new InvalidDataException("Unsupported ACL entry.");}
   return new RetainedSecurity{sddl=sd.GetSddlForm(AccessControlSections.All),owner=sd.Owner.Value,group=sd.Group.Value,daclSddl=sd.GetSddlForm(AccessControlSections.Access),daclProtected=true,saclPresent=(sd.ControlFlags&ControlFlags.SystemAclPresent)!=0,saclEmpty=true,saclAceCount=0,bytes=b};
  }
  public static bool SameBasic(RetainedBasic a,RetainedBasic b){return a!=null&&b!=null&&a.creation==b.creation&&a.access==b.access&&a.write==b.write&&a.change==b.change&&a.attributes==b.attributes;}
  public static bool SameSecurity(RetainedSecurity a,RetainedSecurity b){return a!=null&&b!=null&&a.owner==b.owner&&a.group==b.group&&a.daclSddl==b.daclSddl&&a.sddl==b.sddl&&a.saclEmpty&&b.saclEmpty&&a.saclPresent==b.saclPresent;}
  public static void CheckValidity(RetainedRegion[] rows,uint usage){if(rows==null||rows.Length<1||rows.Length>16)throw new InvalidDataException("Missing validity rows.");long next=0;foreach(RetainedRegion row in rows){if(row==null||row.offset!=next||row.length<=0||row.length>65536-next||(row.usage&~31U)!=0||(row.usage&usage)==0)throw new InvalidDataException("Incomplete native validity rows.");next+=row.length;}if(next!=65536)throw new InvalidDataException("Validity gap.");}
  public static void CheckSnapshot(RetainedFixtureState f,RetainedSnapshot s) {
   if(s==null||s.standard==null||s.standard.eof!=65536||s.standard.allocation!=65536||s.standard.links!=1||s.standard.directory||s.basic==null||s.basic.attributes!=32||s.identity==null||!Regex.IsMatch(s.identity.fileId128??"","^[0-9a-f]{32}$")||s.security==null||!s.security.saclEmpty||s.streams==null||s.streams.Length!=1||s.streams[0]!="::$DATA"||s.sha256!=f.expectedSha256||!s.fullyCachedValid||s.extents==null||s.extents.Length<1||s.extents.Length>16)throw new InvalidDataException("Fixture semantic or initialized-data evidence incomplete.");
   long v=0;foreach(RetainedExtent e in s.extents){if(e==null||e.vcn!=v||e.nextVcn<=v||e.nextVcn>16||e.lcn<0||e.lcn>Clusters-(e.nextVcn-v))throw new InvalidDataException("Invalid complete positive extent mapping.");v=e.nextVcn;}if(v!=16)throw new InvalidDataException("Incomplete fixture mapping.");
   CheckValidity(s.cached,1);
   if(f.filesystem=="ReFS"){if(!s.fullyStorageValid||!s.storageRegionQueryAttempted||s.storageValidityStatus!="native-full-storage-validity")throw new InvalidDataException("ReFS storage validity must be measured.");CheckValidity(s.onDisk,2);if(!s.integrityQueried||s.checksumAlgorithm!=0||s.integrityFlags!=0)throw new InvalidDataException("Shadow must have measured integrity NONE, flags zero.");}
   else if(s.fullyStorageValid||s.storageRegionQueryAttempted||s.onDisk!=null||s.storageValidityStatus!="not-queried-NTFS-storage-validity-unknown")throw new InvalidDataException("Do not relabel NTFS cached validity as independent storage validity.");
   if(s.baseSectors!=0)throw new InvalidDataException("First fixture requires observed zero retrieval base on both filesystems.");
  }
  public static void CheckStable(RetainedSnapshot a,RetainedSnapshot b,bool mapping) {
   if(a.identity.fileId128!=b.identity.fileId128||a.identity.volumeSerial64!=b.identity.volumeSerial64||a.sha256!=b.sha256||!SameSecurity(a.security,b.security)||!SameBasic(a.basic,b.basic)||a.baseSectors!=b.baseSectors)throw new InvalidDataException("Pinned fixture identity/content/metadata changed.");
   if(mapping){if(a.extents.Length!=b.extents.Length)throw new InvalidDataException("Mapping changed.");for(int i=0;i<a.extents.Length;i++)if(a.extents[i].vcn!=b.extents[i].vcn||a.extents[i].nextVcn!=b.extents[i].nextVcn||a.extents[i].lcn!=b.extents[i].lcn)throw new InvalidDataException("Mapping changed.");}
  }
  static RetainedFixtureState State(string root,string volume,string id,string role){ValidateProfile(root,volume,id,role);return new RetainedFixtureState{root=root,volume=volume,role=role,path=root+@"retained\payload.bin",filesystem=root==@"S:\"?"ReFS":"NTFS",expectedSha256=Hash(Pattern(id,role))};}
  public static RetainedPairResult RunWith(IRetainedFixtureApi api,string sourceVolume,string shadowVolume,string runId,bool construct) {
   if(api==null)throw new ArgumentNullException("api");RetainedPairResult r=new RetainedPairResult{runId=runId,source=State(@"F:\",sourceVolume,runId,"A"),shadow=State(@"S:\",shadowVolume,runId,"B")};
   if(String.Equals(sourceVolume,shadowVolume,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Independent volume identities required.");
   try {
    r.phase="open";api.Open(r,construct);
    if(construct){r.phase="create-initialized-pair";r.targetWriteRequestsIssued=true;api.Create(r.source);api.Create(r.shadow);foreach(RetainedFixtureState f in new[]{r.source,r.shadow})if(!f.fileCreated||!f.payloadInitialized||f.payloadBytesWritten!=65536||!f.creationFlushed||!f.creationClosed)throw new InvalidDataException("Complete ordinary write, flush and close proof required.");}
    r.phase="observe-before";foreach(RetainedFixtureState f in new[]{r.source,r.shadow}){f.before=api.Observe(f,f.role+"Before");CheckSnapshot(f,f.before);}
    if(construct){
     r.phase="select-common-free-range";r.candidateLcn=SelectCandidate(api.Bitmap(r.source,false,"ntfsCandidate"),api.Bitmap(r.shadow,false,"refsCandidate"),api.Bitmap(r.shadow,true,"refsMetadataCandidate"));
     CheckNotMapped(r.candidateLcn,r.source.before.extents);CheckNotMapped(r.candidateLcn,r.shadow.before.extents);
     // A fresh per-volume bitmap immediately precedes each request. The native allocator arbitrates races.
     foreach(RetainedFixtureState f in new[]{r.source,r.shadow}){
      if(!IsFree(api.Bitmap(f,false,f.role+"FreshBitmap"),r.candidateLcn)||(f.role=="B"&&!IsFree(api.Bitmap(f,true,"BFreshMetadataBitmap"),r.candidateLcn)))throw new InvalidDataException("Candidate no longer free.");
      r.phase="move-"+f.role;f.moveAttempted=true;f.moveCallCount=1;f.moveSucceeded=api.Move(f,r.candidateLcn);f.moveCompleted=true;if(!f.moveSucceeded)throw new IOException("Native placement rejected; no second request or source retry.");
      r.phase="finalize-"+f.role;api.SetMetadata(f);
     }
     r.phase="close-writable-handles";api.Seal();r.writeHandlesClosedBeforeFinalObservation=true;
    }
    r.phase="observe-after";foreach(RetainedFixtureState f in new[]{r.source,r.shadow}){
     f.after=api.Observe(f,f.role+"After");CheckSnapshot(f,f.after);CheckStable(f.before,f.after,!construct);
     if(f.after.extents.Length!=1)throw new InvalidDataException("Final fixture must be contiguous.");long lcn=f.after.extents[0].lcn;
     f.after.partitionOffset=Offset(f.after.baseSectors,lcn);f.requestedPlacementObserved=construct?lcn==r.candidateLcn:true;if(!f.requestedPlacementObserved)throw new InvalidDataException("Native request returned a different mapping.");
    }
    if(!SameBasic(r.source.after.basic,r.shadow.after.basic)||!SameSecurity(r.source.after.security,r.shadow.after.security)||!SameBasic(r.source.directoryBasic,r.shadow.directoryBasic)||!SameSecurity(r.source.directorySecurity,r.shadow.directorySecurity)||r.source.after.partitionOffset!=r.shadow.after.partitionOffset||r.source.after.identity.volumeSerial64==r.shadow.after.identity.volumeSerial64)throw new InvalidDataException("Pair metadata, placement or independent identity differs.");
    CheckAccessPolicies(r,construct);r.lastAccessPolicyVerified=true;CheckNamespaces(r,construct);r.namespaceVerified=true;
    r.pairSemanticsMatch=true;r.status=construct?"constructed-awaiting-raw-proof":"pair-observed";r.phase="complete";
    // This is a construction boundary, not disk isolation or authenticated physical mapping.
    r.sourceFrozen=construct;
   }catch(Exception e){r.error=e.ToString();}
   finally{try{api.Close();r.cleanupComplete=true;r.privilegeRestored=true;}catch(Exception e){r.cleanupError=e.ToString();r.status="cleanup-failed";r.sourceFrozen=false;}}
   return r;
  }
  public static RetainedPairResult ConstructPair(string sourceVolume,string shadowVolume,string runId){return RunWith(new WindowsRetainedFixtureApi(),sourceVolume,shadowVolume,runId,true);}
  public static RetainedPairResult InspectPair(string sourceVolume,string shadowVolume,string runId){return RunWith(new WindowsRetainedFixtureApi(),sourceVolume,shadowVolume,runId,false);}
 }
}
