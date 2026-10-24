using System;
using System.Collections.Generic;
using System.IO;
using Ntfs2Refs;
public sealed class FakeConvertedVerification:IConvertedVerificationApi {
 public string fault;public int opens,captures,reads,reopens,closes;ConvertedExpected expected;
 readonly ConvertedSecurityPrivilege audit=new ConvertedSecurityPrivilege();public ConvertedSecurityPrivilege SecurityPrivilege{get{return audit;}}
 public static ConvertedExpected Expected(){string run="0123456789abcdef0123456789abcdef";return new ConvertedExpected{runId=run,diskGuid="11111111-1111-1111-1111-111111111111",partitionGuid="22222222-2222-2222-2222-222222222222",volumeGuid=@"\\?\Volume{33333333-3333-3333-3333-333333333333}\",sourceSha256=NativeRetainedFixture.Hash(NativeRetainedFixture.Pattern(run,"A")),shadowSha256=NativeRetainedFixture.Hash(NativeRetainedFixture.Pattern(run,"B")),fileId128="44444444444444444444444444444444",volumeSerial64="0x0000000000001234",ownerSid="S-1-5-21-1-2-3-1001",fileSddl=FakeRetainedFixture.Security(false).sddl,directorySddl=FakeRetainedFixture.Security(true).sddl,retainedOffset=8589934592,volumeSerial32=0x1234,volumeFlags=0x10040008,totalClusters=13631488};}
 public void Open(ConvertedExpected e,List<RetainedQuery> queries){opens++;expected=e;audit.beforeCaptured=true;audit.adjustmentAttempted=true;audit.enabled=true;if(fault=="open")throw new IOException("fake open failure");}
 public void Capture(ConvertedSnapshot s){captures++;s.volumeFlags=expected.volumeFlags|0x80000;s.volumeSerial32=expected.volumeSerial32;s.totalClusters=expected.totalClusters;s.nativeDiskVerified=true;s.readOnlyVolumeVerified=true;s.namespaceEntries=new[]{"retained"};
  s.file=new RetainedSnapshot{basic=FakeRetainedFixture.Basic(false),standard=new RetainedStandard{allocation=65536,eof=65536,links=1},identity=new RetainedIdentity{fileId128=expected.fileId128,volumeSerial64=expected.volumeSerial64},security=FakeRetainedFixture.Security(false),streams=new[]{"::$DATA"},extents=new[]{new RetainedExtent{vcn=0,nextVcn=16,lcn=expected.retainedOffset/4096}},cached=new[]{new RetainedRegion{offset=0,length=65536,usage=1}},onDisk=new[]{new RetainedRegion{offset=0,length=65536,usage=2}},fullyCachedValid=true,fullyStorageValid=true,storageRegionQueryAttempted=true,storageValidityStatus="native-full-storage-validity",integrityQueried=true};
  s.directoryBasic=FakeRetainedFixture.Basic(true);s.directorySecurity=FakeRetainedFixture.Security(true);s.directoryIdentity=new RetainedIdentity{fileId128="55555555555555555555555555555555",volumeSerial64=expected.volumeSerial64};s.queries.Add(new RetainedQuery{name="Basic",api="GetFileInformationByHandleEx",code=0,inputHex="",capacity=40,bytesReturned=40,succeeded=true,bytes=new byte[40]});
  if(fault=="disk")s.nativeDiskVerified=false;if(fault=="protection")s.readOnlyVolumeVerified=false;if(fault=="flags")s.volumeFlags^=1;if(fault=="volume")s.volumeSerial32++;
  if(fault=="identity")s.file.identity.fileId128=new string('6',32);if(fault=="mapping")s.file.extents[0].lcn+=16;if(fault=="negative")s.file.extents[0].lcn=-1;if(fault=="base")s.file.baseSectors=1;
  if(fault=="storage")s.file.fullyStorageValid=false;if(fault=="hole")s.file.onDisk[0].length=61440;if(fault=="cached")s.file.fullyCachedValid=false;if(fault=="integrity")s.file.checksumAlgorithm=2;if(fault=="integrity-flags")s.file.integrityFlags=1;
  if(fault=="sacl")s.file.security.saclEmpty=false;if(fault=="security")s.directorySecurity.sddl="foreign";if(fault=="ads")s.file.streams=new[]{"::$DATA",":extra:$DATA"};if(fault=="links")s.file.standard.links=2;if(fault=="namespace")s.namespaceEntries=new[]{"retained","foreign"};
  if(fault=="access"&&captures==2)s.file.basic.access++;if(fault=="directory-time")s.directoryBasic.change++;if(fault=="raw-instability"&&captures==2)s.queries[0].bytes[0]=1;if(fault=="directory-id"&&captures>=3)s.directoryIdentity.fileId128=new string('7',32);
 }
 public byte[] ReadPayload(){reads++;if(fault=="read")throw new IOException("fake read refusal");if(fault=="short")return new byte[1];return NativeRetainedFixture.Pattern(expected.runId,fault=="B"?"B":"A");}
 public void Reopen(){reopens++;if(fault=="reopen")throw new IOException("fake reopen refusal");}
 public void Close(){closes++;audit.restorationAttempted=true;audit.restored=fault!="privilege";audit.tokenClosed=true;if(fault=="cleanup")throw new IOException("fake close failure");}
}
