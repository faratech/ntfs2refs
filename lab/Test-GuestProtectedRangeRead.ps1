<# Pure parsers, fake device calls and guest guards; never opens a real disk. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$nativePath=Join-Path $workspace 'lab\guest\NativeProtectedRangeRead.cs'
$fake=@'
namespace Ntfs2Refs {
 public sealed class FakeProtectedApi:IProtectedRangeApi {
  public string Failure="";public bool Protected,Locked,Offline;public int Reads,VolumeCloses,DiskCloses,Reopens;public System.Collections.Generic.List<string> Calls=new System.Collections.Generic.List<string>();
  public bool VolumeOpened{get{return Failure!="volume-open";}}public bool DiskOpened{get{return Failure!="disk-open";}}public int VolumeOpenError{get{return VolumeOpened?0:5;}}public int DiskOpenError{get{return DiskOpened?0:5;}}
  public static byte[] Device(){byte[] b=new byte[12];System.BitConverter.GetBytes(7U).CopyTo(b,0);System.BitConverter.GetBytes(1U).CopyTo(b,4);return b;}
  public static byte[] Alignment(){byte[] b=new byte[28];System.BitConverter.GetBytes(28U).CopyTo(b,0);System.BitConverter.GetBytes(28U).CopyTo(b,4);System.BitConverter.GetBytes(512U).CopyTo(b,16);System.BitConverter.GetBytes(4096U).CopyTo(b,20);return b;}
  public static byte[] Attributes(bool value){byte[] b=new byte[16];b[0]=16;b[8]=(byte)(value?2:0);return b;}
  public static byte[] Layout(){byte[] b=new byte[336];b[0]=1;b[4]=2;new System.Guid("b4ab4dbc-6bd7-4199-8e4a-01b828e98584").ToByteArray().CopyTo(b,8);System.BitConverter.GetBytes(17408L).CopyTo(b,24);System.BitConverter.GetBytes(NativeProtectedRangeRead.DiskBytes-34304L).CopyTo(b,32);b[40]=128;
   int p=48;b[p]=1;System.BitConverter.GetBytes(17408L).CopyTo(b,p+8);System.BitConverter.GetBytes(NativeRangeRead.PartitionOffset-17408L).CopyTo(b,p+16);b[p+24]=1;new System.Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae").ToByteArray().CopyTo(b,p+32);new System.Guid("11111111-1111-1111-1111-111111111111").ToByteArray().CopyTo(b,p+48);
   p+=144;b[p]=1;System.BitConverter.GetBytes(NativeRangeRead.PartitionOffset).CopyTo(b,p+8);System.BitConverter.GetBytes(NativeRangeRead.VolumeBytes).CopyTo(b,p+16);b[p+24]=2;new System.Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").ToByteArray().CopyTo(b,p+32);new System.Guid("00c9f113-e0b9-49d8-b031-130aef8ef3fb").ToByteArray().CopyTo(b,p+48);return b;
  }
  public static byte[] Volume(){byte[] b=new byte[32];b[0]=1;b[8]=1;System.BitConverter.GetBytes(NativeRangeRead.PartitionOffset).CopyTo(b,16);System.BitConverter.GetBytes(NativeRangeRead.VolumeBytes).CopyTo(b,24);return b;}
  public static byte[] Bitmap(){byte[] b=new byte[2097152];System.BitConverter.GetBytes(NativeRangeRead.ClusterCount).CopyTo(b,8);for(long i=NativeRangeRead.NewLcn;i<NativeRangeRead.NewLcn+16;i++)b[16+(int)(i/8)]|=(byte)(1<<(int)(i%8));return b;}
  public RangeQuery Control(string name,bool disk,uint code,byte[] input,int capacity){
   Calls.Add(name);if(!disk&&Offline&&code!=NativeProtectedRangeRead.OnlineCode)throw new System.Exception("Unexpected request to offline volume");bool ok=Failure!=name;int error=ok?0:5;byte[] b=new byte[0];
   if(code==NativeProtectedRangeRead.DeviceCode)b=Device();if(code==NativeProtectedRangeRead.LengthCode)b=System.BitConverter.GetBytes(NativeProtectedRangeRead.DiskBytes);if(code==NativeProtectedRangeRead.AlignmentCode)b=Alignment();if(code==NativeProtectedRangeRead.LayoutCode)b=Layout();if(code==NativeProtectedRangeRead.GetAttributesCode)b=Attributes(Protected);if(code==NativeRangeRead.ExtentsCode)b=Volume();if(code==NativeRangeRead.BaseCode)b=System.BitConverter.GetBytes(Failure=="base-change"&&name=="sBaseAfter"?8L:0L);if(code==NativeRangeRead.BitmapCode)b=Bitmap();
   if(code==NativeProtectedRangeRead.WritableCode){ok=!Protected;error=Protected?19:0;if(Failure==name){ok=false;error=21;}}
   if(Failure=="missing-readonly"&&name=="sAttributesLocked")b=Attributes(false);if(Failure=="source-used"&&name=="sBitmapMetadataBefore")b[16+(int)(NativeRangeRead.OldLcn/8)]=1;if(Failure=="dest-free"&&name=="sBitmapLegacyBefore")b[16+(int)(NativeRangeRead.NewLcn/8)]&=254;if(Failure=="after-source-used"&&name=="sBitmapMetadataAfter")b[16+(int)(NativeRangeRead.OldLcn/8)]=1;
   if(Failure=="partial-bitmap"&&name=="sBitmapMetadataBefore")b=new byte[32];if(Failure=="bad-disk"&&code==NativeProtectedRangeRead.DeviceCode)b[4]=2;if(Failure=="wrong-route"&&name=="sVolumeLocked")b[8]=2;
   if(ok&&code==NativeRangeRead.LockCode)Locked=true;if(ok&&code==NativeRangeRead.UnlockCode)Locked=false;if(ok&&code==NativeProtectedRangeRead.OfflineCode){if(!Locked)throw new System.Exception("Offline without lock");Offline=true;}if(ok&&code==NativeProtectedRangeRead.SetAttributesCode){if(!disk||!Offline||!Locked)throw new System.Exception("Unprotected transition order");Protected=Failure!="set-ineffective";}if(ok&&code==NativeProtectedRangeRead.OnlineCode)Offline=false;
   return new RangeQuery{name=name,controlCode=code,inputBytes=input==null?0:input.Length,inputHex=input==null?"":System.BitConverter.ToString(input).Replace("-","").ToLowerInvariant(),outputCapacityBytes=capacity,succeeded=ok,nativeError=error,bytes=b,bytesReturned=(uint)b.Length};
  }
  public ProtectedMountedView Mounted(string name){Calls.Add(name);if(Offline||Locked)throw new System.Exception("Mounted query after lock/offline");if(name=="mountedAfter"&&Reopens!=1)throw new System.Exception("After view lacks fresh handle");return new ProtectedMountedView{name=name,succeeded=Failure!=name,nativeError=Failure==name?21:0,label="ntfs2refs-target",fileSystem="ReFS",serial=0x08425382,flags=Failure=="missing-mounted-flag"?0U:0x00080000U};}
  public RangeBytes Read(string name,long offset,int count,int alignment){Calls.Add(name);if(!Protected||!Locked||Offline)throw new System.Exception("Read without established protection");Reads++;if(Failure=="read-throw")throw new System.IO.IOException("Injected read failure");bool seek=Failure!="seek";int returned=Failure=="short"?512:65536;return new RangeBytes{name=name,offset=offset,actualSeekOffset=offset,requestedBytes=count,bytesReturned=seek?returned:0,bytes=new byte[seek?returned:0],seekAttempted=true,seekSucceeded=seek,readAttempted=seek,readSucceeded=seek&&Failure!="read",seekError=seek?0:5,readError=Failure=="read"?5:0};}
  public bool CloseVolume(out int error){Calls.Add("closeVolume");VolumeCloses++;error=Failure=="closeVolume"||(Failure=="final-close"&&Reopens==1)?5:0;if(error==0)Locked=false;return error==0;}
  public bool ReopenVolume(out int error){Calls.Add("reopenVolume");if(VolumeCloses!=1||Reopens!=0)throw new System.Exception("Unexpected reopen order");Reopens++;error=Failure=="reopen"?5:0;return error==0;}
  public bool CloseDisk(out int error){Calls.Add("closeDisk");DiskCloses++;error=Failure=="closeDisk"?5:0;return error==0;}
 }
}
'@
$base=[IO.File]::ReadAllText((Join-Path $workspace 'lab\guest\NativeRangeRead.cs'))
$native=[IO.File]::ReadAllText($nativePath)
$combined='using System.Text;'+[Environment]::NewLine+$base+[Environment]::NewLine+([regex]::Replace($native,'(?m)^using [^;]+;\r?\n',''))+[Environment]::NewLine+$fake
Add-Type -TypeDefinition $combined
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 18|ConvertFrom-Json}
$inputBytes=[Ntfs2Refs.NativeProtectedRangeRead]::SetReadOnlyInput()
Check ($inputBytes.Length -eq 40 -and [BitConverter]::ToUInt32($inputBytes,0) -eq 40 -and $inputBytes[4] -eq 0 -and [BitConverter]::ToUInt64($inputBytes,8) -eq 2 -and [BitConverter]::ToUInt64($inputBytes,16) -eq 2) 'SET input size/mask/persistence differs.'
foreach($index in @(5,6,7,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39)){Check ($inputBytes[$index] -eq 0) 'Reserved SET bytes nonzero.'}
[Ntfs2Refs.NativeProtectedRangeRead]::ValidateDevice([Ntfs2Refs.FakeProtectedApi]::Device(),1);$checks++
[Ntfs2Refs.NativeProtectedRangeRead]::ValidateLength([BitConverter]::GetBytes([long]64GB));$checks++
[Ntfs2Refs.NativeProtectedRangeRead]::ValidateAlignment([Ntfs2Refs.FakeProtectedApi]::Alignment());$checks++
[Ntfs2Refs.NativeProtectedRangeRead]::ValidateLayout([Ntfs2Refs.FakeProtectedApi]::Layout());$checks++
foreach($index in @(0,4,8)){$bad=[Ntfs2Refs.FakeProtectedApi]::Device();$bad[$index]++;Reject {[Ntfs2Refs.NativeProtectedRangeRead]::ValidateDevice($bad,1)} 'Changed physical device binding accepted.'}
foreach($index in @(0,4,16,20,24)){$bad=[Ntfs2Refs.FakeProtectedApi]::Alignment();$bad[$index]++;Reject {[Ntfs2Refs.NativeProtectedRangeRead]::ValidateAlignment($bad)} 'Changed alignment descriptor accepted.'}
foreach($index in @(0,4,8,24,32,192,200,208,216,224,240,256)){$bad=[Ntfs2Refs.FakeProtectedApi]::Layout();$bad[$index]++;Reject {[Ntfs2Refs.NativeProtectedRangeRead]::ValidateLayout($bad)} 'Changed GPT layout accepted.'}
foreach($size in @(0,15,47,335,337,65537)){Reject {[Ntfs2Refs.NativeProtectedRangeRead]::ValidateLayout((New-Object byte[] $size))} 'Malformed layout accepted.'}
foreach($value in @($false,$true)){[Ntfs2Refs.NativeProtectedRangeRead]::ValidateAttributes([Ntfs2Refs.FakeProtectedApi]::Attributes($value),$value);$checks++;Reject {[Ntfs2Refs.NativeProtectedRangeRead]::ValidateAttributes([Ntfs2Refs.FakeProtectedApi]::Attributes(-not $value),$value)} 'Wrong protection accepted.'}
$api=New-Object Ntfs2Refs.FakeProtectedApi;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ProtectWith($api,1)
Check ($result.status -ceq 'protection-established' -and $result.deviceStateMutationMayHaveBeenIssued -and $result.protectionEstablished -and $result.onlineSucceeded -and $result.unlockSucceeded -and $result.handleCloseSucceeded -and $result.nativeOperationReturned -and $api.Reads -eq 0) 'Protection success state differs.'
Check (($api.Calls -join ',') -ceq 'pDevice,pLength,pAlignment,pLayout,pVolume,pAttributesBefore,pWritableBefore,pLock,pDismount,pOffline,pSetAttributes,pAttributesAfter,pWritableAfter,pOnline,pUnlock,closeVolume,closeDisk') 'Same-handle protection call order differs.'
foreach($failure in @('volume-open','disk-open','pDevice','pLength','pAlignment','pLayout','pVolume','pAttributesBefore','pWritableBefore','pLock','bad-disk')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ProtectWith($api,1);Check (-not $result.deviceStateMutationMayHaveBeenIssued -and -not $result.dismountAttempted -and $api.Reads -eq 0 -and $api.VolumeCloses -eq 1 -and $api.DiskCloses -eq 1) 'Preflight refusal mutated device or leaked a handle.'}
foreach($failure in @('pDismount','pOffline','pSetAttributes','pAttributesAfter','pWritableAfter','pOnline','pUnlock','set-ineffective','closeVolume','closeDisk')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ProtectWith($api,1);Check ($result.status -cne 'protection-established' -and $result.deviceStateMutationMayHaveBeenIssued -and $api.Reads -eq 0 -and $api.VolumeCloses -eq 1 -and $api.DiskCloses -eq 1) 'Transition failure qualified or lost possible mutation.';Check (@($api.Calls|Where-Object {$_ -ceq 'pSetAttributes'}).Count -le 1 -and @($api.Calls|Where-Object {$_ -ceq 'pOnline'}).Count -le 1 -and @($api.Calls|Where-Object {$_ -ceq 'pUnlock'}).Count -le 1) 'Failed transition retried a control.'}
$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1)
Check ($result.status -ceq 'ranges-read-awaiting-file-verification' -and $api.Reads -eq 2 -and $api.VolumeCloses -eq 2 -and $api.Reopens -eq 1 -and $result.samplingHandleCloseSucceeded -and $result.volumeReopenSucceeded -and $result.protectionVerifiedBefore -and $result.protectionVerifiedLocked -and $result.protectionVerifiedAfter -and $result.mountedReadOnlyBefore -and $result.mountedReadOnlyAfter -and $result.handleCloseSucceeded -and $result.nativeOperationReturned) 'Protected read success differs.'
Check (($api.Calls -join ',') -ceq 'sDevice,sLength,sAlignment,sLayout,sAttributesBefore,sWritableBefore,sVolumeBefore,mountedBefore,sBaseBefore,sBitmapLegacyBefore,sBitmapMetadataBefore,sLock,sAttributesLocked,sWritableLocked,sVolumeLocked,oldSource,destination,sUnlock,closeVolume,reopenVolume,sAttributesAfter,sWritableAfter,sVolumeAfter,mountedAfter,sBaseAfter,sBitmapLegacyAfter,sBitmapMetadataAfter,closeVolume,closeDisk') 'Protected read order differs.'
foreach($failure in @('volume-open','disk-open','sDevice','sLength','sAlignment','sLayout','sAttributesBefore','sWritableBefore','sVolumeBefore','mountedBefore','sBaseBefore','sBitmapLegacyBefore','sBitmapMetadataBefore','sLock','sAttributesLocked','sWritableLocked','sVolumeLocked','bad-disk','missing-readonly','source-used','dest-free','partial-bitmap','wrong-route','missing-mounted-flag')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1);Check ($result.status -cne 'ranges-read-awaiting-file-verification' -and $api.Reads -eq 0 -and $api.VolumeCloses -eq 1 -and $api.DiskCloses -eq 1 -and $api.Reopens -eq 0) 'Read preceded a required gate or handle cleanup was lost.'}
foreach($failure in @('sUnlock','sAttributesAfter','sWritableAfter','sVolumeAfter','mountedAfter','sBaseAfter','sBitmapLegacyAfter','sBitmapMetadataAfter','base-change','after-source-used','final-close','closeDisk')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1);Check ($result.status -cne 'ranges-read-awaiting-file-verification' -and $api.Reads -eq 2 -and $result.rawReadMayHaveBeenIssued -and $api.VolumeCloses -le 2 -and $api.DiskCloses -eq 1) 'Post-read failure qualified or lost read state.'}
foreach($failure in @('closeVolume','reopen')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1);Check ($result.status -cne 'ranges-read-awaiting-file-verification' -and $api.Reads -eq 2 -and $api.VolumeCloses -eq 1 -and $api.Reopens -eq [int]($failure -ceq 'reopen') -and @($api.Calls|Where-Object {$_ -ceq 'sBaseAfter'}).Count -eq 0) 'Failed close/reopen retried or continued filesystem queries.'}
foreach($failure in @('seek','short','read','read-throw')){$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$api.Failure=$failure;$result=[Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1);Check ($result.status -ceq 'blocked' -and $api.Reads -eq 1 -and $result.unlockSucceeded -and $result.handleCloseSucceeded -and $result.rawReadMayHaveBeenIssued) 'Failed raw read continued or cleanup failed.'}

$path=Join-Path $workspace 'lab\guest\Capture-GuestProtectedRangeRead.ps1';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'Guest script parse failed.'
foreach($name in @('Get-ProtectedRangeReadProfile','Assert-ProtectedRangeReadControl','Get-ProtectedRangeReadFixture','Test-ProtectedRangeReadSameMapping','Assert-ProtectedRangeReadPlacement','Assert-ProtectedRangeReadAllocation')){$definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false);Invoke-Expression $definition.Extent.Text}
$profile=Get-ProtectedRangeReadProfile
$root=Join-Path $workspace '.lab\hyperv\extent-placement\win11-20261024T000401422Z'
$placement=Get-Content -LiteralPath ($root+'\guest\placement.json') -Raw|ConvertFrom-Json
$remount=Get-Content -LiteralPath ($root+'\remount\identity.json') -Raw|ConvertFrom-Json
$allocation=Get-Content -LiteralPath ($root+'\remount\allocation-remount.json') -Raw|ConvertFrom-Json
$control=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\devdrive\win11-20261023T230635404Z\after\verify.json') -Raw|ConvertFrom-Json
Assert-ProtectedRangeReadControl $control $profile.controlRunId;Assert-ProtectedRangeReadPlacement $placement $remount $control $profile;Assert-ProtectedRangeReadAllocation $allocation $control.target.guest $placement $profile;$checks+=3
foreach($field in @('status','probeId','controlRunId','controlEvidenceSha256','capturedAllocationSha256','expectedSha256','requestedLcn')){$bad=Clone $placement;$bad.$field=if($field -ceq 'requestedLcn'){1}else{'wrong'};Reject {Assert-ProtectedRangeReadPlacement $bad $remount $control $profile} 'Changed placement profile accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $remount;$bad.partition.$field='wrong';Reject {Assert-ProtectedRangeReadPlacement $placement $bad $control $profile} 'Changed remount geometry accepted.'}
foreach($phase in @('before','after')){foreach($field in @('length','sha256','fileId64','volumeSerialHex')){$bad=Clone $placement;$bad.$phase.$field=if($field -ceq 'length'){1}else{'wrong'};Reject {Assert-ProtectedRangeReadPlacement $bad $remount $control $profile} 'Changed range proof accepted.'};$bad=Clone $placement;$bad.$phase.extents[0].lcn++;Reject {Assert-ProtectedRangeReadPlacement $bad $remount $control $profile} 'Unreviewed LCN accepted.'}
foreach($index in @(0,1)){foreach($field in @('complete','stableDuringObservation','sha256','fileId64')){$bad=Clone $allocation;$bad.files[$index].observation.$field=if($field -cin @('complete','stableDuringObservation')){$false}else{'wrong'};Reject {Assert-ProtectedRangeReadAllocation $bad $control.target.guest $placement $profile} 'Changed fixture accepted.'};$bad=Clone $allocation;$bad.files[$index].observation.extents[0].lcn++;Reject {Assert-ProtectedRangeReadAllocation $bad $control.target.guest $placement $profile} 'Changed current mapping accepted.'}
foreach($attribute in @('SparseFile','Compressed','Encrypted','ReparsePoint')){$bad=Clone $allocation;$bad.files[1].observation.attributes=$attribute;Reject {Assert-ProtectedRangeReadAllocation $bad $control.target.guest $placement $profile} 'Nonordinary fixture accepted.'}
foreach($name in @('Get-ProtectedRangeReadBufferLimit','Get-ProtectedRangeReadNativeSummary','Test-ProtectedRangeReadEarlyRestore','Get-ProtectedRangeReadTarget')){$definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false);Invoke-Expression $definition.Extent.Text}
$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Failure='pLock';$early=Get-ProtectedRangeReadNativeSummary ([Ntfs2Refs.NativeProtectedRangeRead]::ProtectWith($api,1))
Check (Test-ProtectedRangeReadEarlyRestore $early) 'Complete early refusal cannot restore.'
foreach($field in @('nativeOperationReturned','handleCloseSucceeded')){$bad=Clone $early;$bad.$field=$false;Check (-not (Test-ProtectedRangeReadEarlyRestore $bad)) 'Unknown early cleanup allowed restore.'}
foreach($field in @('deviceStateMutationMayHaveBeenIssued','dismountAttempted','offlineAttempted','setAttributesAttempted','onlineAttempted','lockSucceeded')){$bad=Clone $early;$bad.$field=$true;Check (-not (Test-ProtectedRangeReadEarlyRestore $bad)) 'Mutation/unclean lock allowed early restore.'}
$bad=Clone $early;$bad.status='blocked';Check (-not (Test-ProtectedRangeReadEarlyRestore $bad)) 'Blocked preflight automatically restored.'
$api=New-Object Ntfs2Refs.FakeProtectedApi;$api.Protected=$true;$summary=Get-ProtectedRangeReadNativeSummary ([Ntfs2Refs.NativeProtectedRangeRead]::ObserveWith($api,1))
Check ($summary.volumeReopenSucceeded -and $summary.samplingHandleCloseSucceeded -and @($summary.queryNames).Count -eq 21 -and @($summary.mountedViews).Count -eq 2 -and @($summary.PSObject.Properties.Name) -cnotcontains 'queries') 'Native summary lost fresh-handle or bounded-query evidence.'
foreach($name in @('pDevice','pLength','pAlignment','pLayout','pVolume','pAttributesBefore','pAttributesAfter','sDevice','sLength','sAlignment','sLayout','sAttributesBefore','sVolumeBefore','sBaseBefore','sBitmapLegacyBefore','sBitmapMetadataBefore','sAttributesLocked','sVolumeLocked','sBaseAfter','sBitmapLegacyAfter','sBitmapMetadataAfter','sVolumeAfter','sAttributesAfter','oldSource','destination')){Check ((Get-ProtectedRangeReadBufferLimit $name) -ge 8) 'Expected artifact missing.'}
foreach($name in @('other','pLock','PDevice','../pDevice','oldSource.bin')){Reject {Get-ProtectedRangeReadBufferLimit $name} 'Unreviewed buffer accepted.'}
Check ((Get-ProtectedRangeReadBufferLimit 'sBitmapLegacyBefore') -eq 2MB -and (Get-ProtectedRangeReadBufferLimit 'pLayout') -eq 64KB -and (Get-ProtectedRangeReadBufferLimit 'destination') -eq 65536) 'Buffer bounds changed.'
$script:mockDisk=[pscustomobject]@{Number=1;UniqueId=$control.target.guest.uniqueId;SerialNumber=$control.target.guest.serialNumber;Size=64GB;Location=$control.target.guest.location;IsOffline=$false;IsReadOnly=$true;IsBoot=$false;IsSystem=$false;Guid=$control.partition.diskGuid;LogicalSectorSize=512;PhysicalSectorSize=4096;PartitionStyle='GPT';IsClustered=$false}
$script:mockPart=[pscustomobject]@{DiskNumber=1;PartitionNumber=2;Guid=$control.partition.guid;Offset=16MB;Size=52GB;DriveLetter='F';IsBoot=$false;IsSystem=$false}
$script:mockVolume=[pscustomobject]@{UniqueId=$placement.volumeUniqueId;FileSystem='ReFS';FileSystemLabel='ntfs2refs-target';AllocationUnitSize=4096;Size=52GB}
$script:duplicateDisk=$false;$script:hasPagefile=$false
function Get-Disk {if($script:duplicateDisk){@($script:mockDisk,$script:mockDisk)}else{$script:mockDisk}}
function Assert-LabGuestDisk($Disk){if($Disk.IsBoot -or $Disk.IsSystem){throw 'Mock OS disk refused.'}}
function Get-Partition {param($DiskNumber,$DriveLetter);$script:mockPart}
function Get-Volume {param($DriveLetter);$script:mockVolume}
function Get-CimInstance {param($ClassName);if($script:hasPagefile){[pscustomobject]@{Name='F:\pagefile.sys'}}}
$good=Clone $script:mockDisk
Get-ProtectedRangeReadTarget $control.target.guest $control $true|Out-Null;$checks++
foreach($field in @('IsOffline','IsBoot','IsSystem','IsClustered')){$script:mockDisk=Clone $good;$script:mockDisk.$field=$true;Reject {Get-ProtectedRangeReadTarget $control.target.guest $control $true} 'Forbidden protected disk state accepted.'}
foreach($change in @(@('IsReadOnly',$false),@('Guid','bad'),@('Size',1),@('SerialNumber','bad'),@('Location','bad'),@('LogicalSectorSize',4096),@('PhysicalSectorSize',512),@('PartitionStyle','MBR'))){$script:mockDisk=Clone $good;$script:mockDisk.($change[0])=$change[1];Reject {Get-ProtectedRangeReadTarget $control.target.guest $control $true} 'Changed protected identity accepted.'}
$script:mockDisk=Clone $good;$script:duplicateDisk=$true;Reject {Get-ProtectedRangeReadTarget $control.target.guest $control $true} 'Duplicate target accepted.';$script:duplicateDisk=$false;$script:hasPagefile=$true;Reject {Get-ProtectedRangeReadTarget $control.target.guest $control $true} 'Pagefile target accepted.';$script:hasPagefile=$false
Check ($native -notmatch '\b(WriteFile|SetEndOfFile|SetFileValidData|AdjustTokenPrivileges)\s*\(' -and $native -notmatch '0x00090074|0x00090083') 'Forbidden native payload/move/privilege operation found.'
$dry=& $path -CaptureId ('a'*32) -WhatIf
Reject {& $path -CaptureId (('a'*32)+[Environment]::NewLine) -WhatIf} 'Trailing newline capture ID accepted.'
Check ($dry.DryRun -and $dry.MaximumRawReadBytes -eq 131072 -and $dry.MaximumLockCalls -eq 2 -and $dry.MaximumDiskAttributeChanges -eq 1 -and -not $dry.RawWriteRequestsIssued -and -not $dry.ConversionQualified) 'Protected WhatIf failed.'
# Exercise the actual SafeFileHandle close semantics on an ordinary temporary
# file, using the production CloseOne helper. No device/volume handle is opened.
$handleTestRoot=Join-Path ([IO.Path]::GetTempPath()) ('ntfs2refs-protected-handle-'+[guid]::NewGuid().ToString('N'))
$handleTestFile=Join-Path $handleTestRoot 'ordinary-empty.bin'
$ordinaryStream=$null;$reopenedStream=$null
try{
    [IO.Directory]::CreateDirectory($handleTestRoot)|Out-Null
    $ordinaryStream=[IO.File]::Open($handleTestFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $ordinaryHandle=$ordinaryStream.SafeFileHandle
    Check ([Ntfs2Refs.NativeProtectedRangeRead]::IsOpenHandle($ordinaryHandle)) 'Live ordinary handle not recognized.'
    Check (-not [Ntfs2Refs.NativeProtectedRangeRead]::CanReopenReadOnlyHandle($ordinaryHandle,$false,$false,$true)) 'Live handle permitted reopen.'
    $adapter=[Ntfs2Refs.NativeProtectedRangeRead].GetNestedType('NativeApi',[Reflection.BindingFlags]::NonPublic)
    $closeMethod=$adapter.GetMethod('CloseOne',([Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static))
    $closeArgs=[object[]]@($ordinaryHandle,[int]0)
    Check ([bool]$closeMethod.Invoke($null,$closeArgs) -and $closeArgs[1] -eq 0) 'Production CloseOne failed on ordinary file.'
    Check ($ordinaryHandle.IsClosed -and -not $ordinaryHandle.IsInvalid) 'Expected actual SetHandleAsInvalid closed/non-invalid semantics.'
    Check (-not [Ntfs2Refs.NativeProtectedRangeRead]::IsOpenHandle($ordinaryHandle)) 'Closed handle still reported open.'
    Check ([Ntfs2Refs.NativeProtectedRangeRead]::CanReopenReadOnlyHandle($ordinaryHandle,$false,$false,$true)) 'Confirmed closed handle cannot reopen.'
    foreach($case in @(@($true,$false,$true),@($false,$true,$true),@($false,$false,$false))){Check (-not [Ntfs2Refs.NativeProtectedRangeRead]::CanReopenReadOnlyHandle($ordinaryHandle,$case[0],$case[1],$case[2])) 'Control/repeated/unconfirmed reopen accepted.'}
    $closeAgainArgs=[object[]]@($ordinaryHandle,[int]0)
    Check ([bool]$closeMethod.Invoke($null,$closeAgainArgs) -and $closeAgainArgs[1] -eq 0) 'Already-closed handle was passed to CloseHandle again.'
    $ordinaryStream.Dispose();$ordinaryStream=$null
    $reopenedStream=[IO.File]::Open($handleTestFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    Check ([Ntfs2Refs.NativeProtectedRangeRead]::IsOpenHandle($reopenedStream.SafeFileHandle)) 'New read-only ordinary handle is not live.'
    Check (-not [Ntfs2Refs.NativeProtectedRangeRead]::CanReopenReadOnlyHandle($reopenedStream.SafeFileHandle,$false,$false,$true)) 'New live handle accepted stale close confirmation.'
    Check (-not [Ntfs2Refs.NativeProtectedRangeRead]::IsOpenHandle($null) -and -not [Ntfs2Refs.NativeProtectedRangeRead]::CanReopenReadOnlyHandle($null,$false,$false,$true)) 'Missing handle accepted.'
}finally{
    if($reopenedStream){$reopenedStream.Dispose()};if($ordinaryStream){$ordinaryStream.Dispose()}
    if(Test-Path -LiteralPath $handleTestFile){Remove-Item -LiteralPath $handleTestFile -Force}
    if(Test-Path -LiteralPath $handleTestRoot){Remove-Item -LiteralPath $handleTestRoot}
}
"Guest protected range read: $checks checks passed."
