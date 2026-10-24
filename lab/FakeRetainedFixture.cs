using System;
using System.IO;
using System.Security.AccessControl;
using System.Collections.Generic;
using System.Text;
using Ntfs2Refs;
public sealed class FakeRetainedFixture:IRetainedFixtureApi {
 public string fault;public int creates,moves,sets,observes,bitmaps,closes,seals;public bool constructing;
 public long candidate=2097152;RetainedPairResult result;
 const string Sid="S-1-5-21-1-2-3-1001";
 void Policy(string path,string stage){if(fault=="missing-access-policy")return;RetainedAccessPolicy p=NativeRetainedFixture.AccessPolicy(path,stage);p.succeeded=fault!="access-policy-failure";p.nativeError=p.succeeded?0:5;p.finishedUtc=p.startedUtc;result.lastAccessPolicies.Add(p);if(!p.succeeded)throw new IOException("fake handle suppression refusal");}
 public static byte[] DirectoryBuffer(string name,bool directory){byte[] b=new byte[4096];BitConverter.GetBytes(directory?16U:32U).CopyTo(b,56);byte[] text=Encoding.Unicode.GetBytes(name);BitConverter.GetBytes(text.Length).CopyTo(b,60);text.CopyTo(b,104);b[96]=1;if(!directory){BitConverter.GetBytes(65536L).CopyTo(b,40);BitConverter.GetBytes(65536L).CopyTo(b,48);}return b;}
 void Namespace(RetainedFixtureState f,string stage,bool expected){bool folder=stage.EndsWith("Folder");string prefix=f.role+stage+"Directory";byte[] bytes=DirectoryBuffer(folder?"payload.bin":expected?"retained":"System Volume Information",!folder);RetainedDirectoryEntry[] entries=NativeRetainedFixture.ParseDirectory(bytes);
  RetainedNamespace n=new RetainedNamespace{path=f.root+(folder?"retained":""),stage=stage,expectedFixture=expected,complete=true,queryNames=new[]{prefix+"0",prefix+"1"},entries=entries};result.namespaces.Add(n);
  result.queries.Add(new RetainedQuery{name=prefix+"0",api="GetFileInformationByHandleEx",code=11,capacity=4096,inputHex="",succeeded=true,bytesReturned=4096,bytes=bytes});result.queries.Add(new RetainedQuery{name=prefix+"1",api="GetFileInformationByHandleEx",code=10,capacity=4096,inputHex="",nativeError=18,bytes=new byte[0]});
  if(fault=="empty-root"&&stage=="OpenRoot"){n.emptyInitialNoMatchInterpreted=true;n.initialNoMatchInterpretation="documented-first-empty-search-not-reproduced-by-lab-diagnostic";n.entries=new RetainedDirectoryEntry[0];RetainedQuery q=result.queries[result.queries.Count-2];q.succeeded=false;q.nativeError=2;q.bytesReturned=0;q.bytes=new byte[0];}
  if(fault=="namespace-extra")n.entries[0].name="unexpected";if(fault=="namespace-incomplete")n.complete=false;if(fault=="namespace-eof-error")result.queries[result.queries.Count-1].nativeError=5;NativeRetainedFixture.CheckNamespace(n);
 }
 public void Open(RetainedPairResult r,bool construct){result=r;constructing=construct;if(fault=="open")throw new IOException("fake open");foreach(RetainedFixtureState f in new[]{r.source,r.shadow}){Policy(f.root,"root");Namespace(f,"OpenRoot",!construct);if(!construct){Policy(f.root+"retained","observation");Policy(f.path,"observation");}}}
 public void Create(RetainedFixtureState f){creates++;Policy(f.root+"retained","construction");Policy(f.path,"created");Policy(f.path,"construction");f.fileCreated=true;f.directoryCreated=true;f.payloadInitialized=true;f.payloadBytesWritten=65536;f.creationFlushed=true;f.creationClosed=true;f.metadataSet=true;if(fault=="partial-write")f.payloadBytesWritten=32768;if(fault=="unclosed")f.creationClosed=false;if(fault=="unflushed")f.creationFlushed=false;if(fault=="create")throw new IOException("fake create");}
 public static RetainedSecurity Security(bool directory){RawSecurityDescriptor sd=new RawSecurityDescriptor(NativeRetainedFixture.SecuritySddl(Sid,directory));byte[] b=new byte[sd.BinaryLength];sd.GetBinaryForm(b,0);return NativeRetainedFixture.ParseSecurity(b,Sid,directory);}
 public static RetainedBasic Basic(bool directory){long time=NativeRetainedFixture.FixtureTime;return new RetainedBasic{creation=time,access=time,write=time,change=time,attributes=directory?16U:32U};}
 public RetainedSnapshot Observe(RetainedFixtureState f,string name){
  observes++;bool after=name.EndsWith("After");long lcn=constructing&&!after?(f.role=="A"?3000000:3100000):candidate;
  Namespace(f,(after?"After":"Before")+"Root",true);Namespace(f,(after?"After":"Before")+"Folder",true);
  RetainedSnapshot s=new RetainedSnapshot{name=name,sha256=f.expectedSha256,basic=Basic(false),standard=new RetainedStandard{allocation=65536,eof=65536,links=1},identity=new RetainedIdentity{fileId128=f.role=="A"?"11111111111111111111111111111111":"22222222222222222222222222222222",volumeSerial64=f.role=="A"?"0x0000000000000001":"0x0000000000000002"},security=Security(false),streams=new string[]{"::$DATA"},baseSectors=0,extents=new RetainedExtent[]{new RetainedExtent{vcn=0,nextVcn=16,lcn=lcn}},cached=new RetainedRegion[]{new RetainedRegion{offset=0,length=65536,usage=1}},onDisk=new RetainedRegion[]{new RetainedRegion{offset=0,length=65536,usage=2}},fullyCachedValid=true,fullyStorageValid=true,integrityQueried=f.role=="B",checksumAlgorithm=0};
  f.directoryBasic=Basic(true);f.directorySecurity=Security(true);
  if(f.role=="A"){s.onDisk=null;s.fullyStorageValid=false;s.storageRegionQueryAttempted=false;s.storageValidityStatus="not-queried-NTFS-storage-validity-unknown";}else{s.storageRegionQueryAttempted=true;s.storageValidityStatus="native-full-storage-validity";}
  if(fault=="invented-NTFS-storage"&&f.role=="A")s.fullyStorageValid=true;
  if(fault=="storage"&&f.role=="B")s.fullyStorageValid=false;
  if(fault=="validity-hole"&&f.role=="B")s.onDisk[0].length=61440;
  if(fault=="negative")s.extents[0].lcn=-1;
  if(fault=="integrity"&&f.role=="B")s.checksumAlgorithm=2;
  if(fault=="enforcement"&&f.role=="B")s.integrityFlags=1;
  if(fault=="base")s.baseSectors=1;
  if(fault=="hash"&&after)s.sha256=new string('0',64);
  if(fault=="identity"&&after)s.identity.fileId128=new string('3',32);
  if(fault=="times"&&after)s.basic.change++;
  if(fault=="access-time"&&after)s.basic.access++;
  if(fault=="wrong-map"&&after)s.extents[0].lcn=candidate+16;
  if(fault=="sacl")s.security.saclEmpty=false;
  if(fault=="pair-dir"&&f.role=="B")f.directoryBasic.change++;
  if(fault=="overlap"&&f.role=="A")s.extents[0].lcn=candidate;
  return s;
 }
 public static byte[] Map(long bits){byte[] b=new byte[16+(bits+7)/8];BitConverter.GetBytes(bits).CopyTo(b,8);return b;}
 public byte[] Bitmap(RetainedFixtureState f,bool metadata,string name){bitmaps++;byte[] b=Map(NativeRetainedFixture.Clusters);if(fault=="stale"&&name=="AFreshBitmap")b[16+(int)(candidate/8)]=1;if(fault=="no-free")for(long i=2097152/8;i<2359296/8;i++)b[16+(int)i]=255;return b;}
 public bool Move(RetainedFixtureState f,long lcn){moves++;if(fault=="throw-move")throw new IOException("fake transport completion unknown");return fault!="reject";}
 public void SetMetadata(RetainedFixtureState f){sets++;if(fault=="setter")throw new IOException("fake setter");}
 public void Seal(){seals++;if(fault=="seal")throw new IOException("fake close/reopen");foreach(RetainedFixtureState f in new[]{result.source,result.shadow}){Policy(f.root+"retained","observation");Policy(f.path,"observation");}}
 public void Close(){closes++;if(fault=="cleanup")throw new IOException("fake cleanup");}
}
