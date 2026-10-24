<# Pure parsers, mocked native ordering and guest guards; never native Collect. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$nativePath=Join-Path $workspace 'lab\guest\NativeRangeRead.cs'
$fake=@'
namespace Ntfs2Refs {
 public sealed class FakeRangeReadApi:IRangeReadApi {
  public string Failure="";public int Locks,Unlocks,Reads,Closes;public bool Locked;public System.Collections.Generic.List<string> Calls=new System.Collections.Generic.List<string>();
  public static byte[] Volume(){byte[] b=new byte[32];System.BitConverter.GetBytes(1U).CopyTo(b,0);System.BitConverter.GetBytes(1U).CopyTo(b,8);System.BitConverter.GetBytes(NativeRangeRead.PartitionOffset).CopyTo(b,16);System.BitConverter.GetBytes(NativeRangeRead.VolumeBytes).CopyTo(b,24);return b;}
  public static byte[] Bitmap(){byte[] b=new byte[2097152];System.BitConverter.GetBytes(NativeRangeRead.ClusterCount).CopyTo(b,8);for(long l=NativeRangeRead.NewLcn;l<NativeRangeRead.NewLcn+16;l++)b[16+(int)(l/8)]|=(byte)(1<<(int)(l%8));return b;}
  public RangeQuery Control(string name,uint code,byte[] input,int capacity){Calls.Add(name);if(name=="lock")Locks++;if(name=="unlock")Unlocks++;bool ok=Failure!=name;byte[] b=new byte[0];if(code==NativeRangeRead.BaseCode)b=System.BitConverter.GetBytes(Failure=="base-change"&&name=="baseLocked"?8L:0L);if(code==NativeRangeRead.ExtentsCode)b=Volume();if(code==NativeRangeRead.BitmapCode)b=Bitmap();if(Failure=="bad-volume"&&name=="volumeBefore")b[8]=2;if(Failure=="partial-bitmap"&&name=="bitmapMetadata")b=new byte[32];if(Failure=="source-allocated"&&name=="bitmapMetadata")b[16+(int)(NativeRangeRead.OldLcn/8)]=1;if(Failure=="destination-free"&&name=="bitmapMetadata")b[16+(int)(NativeRangeRead.NewLcn/8)]&=254;if(name=="lock"&&ok)Locked=true;if(name=="unlock"&&ok)Locked=false;return new RangeQuery{name=name,controlCode=code,inputBytes=input==null?0:input.Length,inputHex=input==null?"":System.BitConverter.ToString(input).Replace("-","").ToLowerInvariant(),outputCapacityBytes=capacity,succeeded=ok,nativeError=ok?0:5,bytes=b,bytesReturned=(uint)b.Length};}
  public RangeBytes Read(string name,long offset,int count,int alignment){if(!Locked)throw new System.Exception("Raw read without lock");Calls.Add(name);Reads++;if(Failure=="read-throw")throw new System.IO.IOException("Injected read fault");bool seek=Failure!="seek";int n=Failure=="short"?4096:count;return new RangeBytes{name=name,offset=offset,actualSeekOffset=offset,requestedBytes=count,bytesReturned=seek?n:0,bytes=new byte[seek?n:0],seekAttempted=true,seekSucceeded=seek,readAttempted=seek,readSucceeded=seek&&Failure!="read",seekError=seek?0:5,readError=Failure=="read"?5:0};}
  public bool Close(out int error){Calls.Add("close");Closes++;error=Failure=="close"?5:0;if(error==0)Locked=false;return error==0;}
 }
}
'@
Add-Type -TypeDefinition ([IO.File]::ReadAllText($nativePath)+[Environment]::NewLine+$fake)
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 18|ConvertFrom-Json}
$volume=[Ntfs2Refs.NativeRangeRead]::ExpectedVolume
Check ([Ntfs2Refs.NativeRangeRead]::ValidateProfile($volume,1,512,4096) -ceq $volume.TrimEnd('\')) 'Volume handle normalization failed.'
foreach($values in @(@('\\.\C:',1,512,4096),@($volume,-1,512,4096),@($volume,256,512,4096),@($volume,1,4096,4096),@($volume,1,512,512))){Reject {[Ntfs2Refs.NativeRangeRead]::ValidateProfile($values[0],$values[1],$values[2],$values[3])} 'Invalid volume profile accepted.'}
Check ([Ntfs2Refs.NativeRangeRead]::Offset(0,1508352) -eq 6178209792) 'Old-source offset incorrect.'
Check ([Ntfs2Refs.NativeRangeRead]::Offset(0,1508384) -eq 6178340864) 'Destination offset truncated above 4 GiB.'
Check ([Ntfs2Refs.NativeRangeRead]::Offset(8,1508384) -eq 6178344960) 'Sector-base units incorrect.'
foreach($values in @(@(-1,1508384),@(1,1508384),@(0,0),@([long]::MaxValue,1508384),@(100000000,1508384))){Reject {[Ntfs2Refs.NativeRangeRead]::Offset($values[0],$values[1])} 'Invalid range arithmetic accepted.'}
Check ([Ntfs2Refs.NativeRangeRead]::ParseBase([BitConverter]::GetBytes([long]0)) -eq 0) 'Base zero refused.'
foreach($bytes in @([byte[]]@(0),[BitConverter]::GetBytes([long]-1),[BitConverter]::GetBytes([long](52GB/512)))){Reject {[Ntfs2Refs.NativeRangeRead]::ParseBase($bytes)} 'Malformed base accepted.'}
$extent=[Ntfs2Refs.FakeRangeReadApi]::Volume();[Ntfs2Refs.NativeRangeRead]::ValidateExtents($extent,1);$checks++
foreach($index in @(0,8,16,24)){$bad=[byte[]]$extent.Clone();$bad[$index]++;Reject {[Ntfs2Refs.NativeRangeRead]::ValidateExtents($bad,1)} 'Wrong extent domain accepted.'}
Reject {[Ntfs2Refs.NativeRangeRead]::ValidateExtents([byte[]]@(0),1)} 'Truncated volume extent accepted.'
$bitmap=[Ntfs2Refs.FakeRangeReadApi]::Bitmap()
Check ([Ntfs2Refs.NativeRangeRead]::All([Ntfs2Refs.NativeRangeRead]::BitmapBits($bitmap,1508352),$false)) 'Old source free bits parsed incorrectly.'
Check ([Ntfs2Refs.NativeRangeRead]::All([Ntfs2Refs.NativeRangeRead]::BitmapBits($bitmap,1508384),$true)) 'Destination allocated bits parsed incorrectly.'
$bitmap[$bitmap.Length-1]=255
Check ([Ntfs2Refs.NativeRangeRead]::All([Ntfs2Refs.NativeRangeRead]::BitmapBits($bitmap,1508352),$false)) 'Trailing response bytes influenced source allocation.'
$bitmap[16+[int](1508352/8)]=1
Check (-not [Ntfs2Refs.NativeRangeRead]::All([Ntfs2Refs.NativeRangeRead]::BitmapBits($bitmap,1508352),$false)) 'One occupied source bit ignored.'
Reject {[Ntfs2Refs.NativeRangeRead]::BitmapBits((New-Object byte[] 32),1508352)} 'Incomplete bitmap accepted.'
Reject {[Ntfs2Refs.NativeRangeRead]::BitmapBits($bitmap,1)} 'Unreviewed bitmap range accepted.'
$pattern=New-Object byte[] 65536;$pattern[65535]=255
Check ([Ntfs2Refs.NativeRangeRead]::Equal($pattern,[byte[]]$pattern.Clone())) 'Full byte match failed.'
$bad=[byte[]]$pattern.Clone();$bad[65535]=0
Check (-not [Ntfs2Refs.NativeRangeRead]::Equal($pattern,$bad)) 'Last-byte mismatch ignored.'
Check (-not [Ntfs2Refs.NativeRangeRead]::Equal($pattern,(New-Object byte[] 65535))) 'Partial pattern accepted.'
$api=New-Object Ntfs2Refs.FakeRangeReadApi;$result=[Ntfs2Refs.NativeRangeRead]::CollectWith($api,1)
Check ($result.status -ceq 'ranges-read-awaiting-file-verification' -and $api.Locks -eq 1 -and $api.Unlocks -eq 1 -and $api.Reads -eq 2 -and $api.Closes -eq 1 -and $result.nativeOperationReturned -and $result.handleCloseSucceeded) 'Successful bounded flow incorrect.'
Check (($api.Calls -join ',') -ceq 'baseBefore,volumeBefore,lock,baseLocked,volumeLocked,bitmapLegacy,bitmapMetadata,oldSource,destination,unlock,close') 'Native operation order differs.'
foreach($failure in @('baseBefore','volumeBefore','lock','baseLocked','volumeLocked','bitmapLegacy','bitmapMetadata','bad-volume','base-change','partial-bitmap')){
 $api=New-Object Ntfs2Refs.FakeRangeReadApi;$api.Failure=$failure;$result=[Ntfs2Refs.NativeRangeRead]::CollectWith($api,1)
 Check ($api.Reads -eq 0 -and $api.Closes -eq 1 -and $result.nativeOperationReturned -and $result.status -cne 'ranges-read-awaiting-file-verification') 'Read continued after failed native precondition.'
 Check ($api.Locks -le 1 -and $api.Unlocks -eq [int]$result.lockSucceeded) 'Lock retried or cleanup omitted.'
}
foreach($failure in @('seek','short','read','read-throw')){$api=New-Object Ntfs2Refs.FakeRangeReadApi;$api.Failure=$failure;$result=[Ntfs2Refs.NativeRangeRead]::CollectWith($api,1);Check ($api.Reads -eq 1 -and $api.Unlocks -eq 1 -and $api.Closes -eq 1 -and $result.status -ceq 'blocked' -and $result.rawReadMayHaveBeenIssued) 'Failed read continued or lost possible-read state.'}
foreach($failure in @('unlock','close')){$api=New-Object Ntfs2Refs.FakeRangeReadApi;$api.Failure=$failure;$result=[Ntfs2Refs.NativeRangeRead]::CollectWith($api,1);Check ($result.status -ceq 'cleanup-failed' -and $api.Closes -eq 1) 'Failed cleanup was qualified.'}
foreach($case in @(@('source-allocated','source-range-not-free'),@('destination-free','destination-range-not-allocated'))){$api=New-Object Ntfs2Refs.FakeRangeReadApi;$api.Failure=$case[0];$result=[Ntfs2Refs.NativeRangeRead]::CollectWith($api,1);Check ($result.status -ceq $case[1] -and $api.Reads -eq 0 -and $api.Unlocks -eq 1 -and $api.Closes -eq 1) 'Conflicting allocation bits allowed raw reads or omitted cleanup.'}

$path=Join-Path $workspace 'lab\guest\Capture-GuestRangeRead.ps1';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'Guest script parse failed.'
foreach($name in @('Get-RangeReadProfile','Assert-RangeReadControl','Get-RangeReadFixture','Test-RangeReadSameMapping','Assert-RangeReadPlacement','Assert-RangeReadAllocation')){$definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false);Invoke-Expression $definition.Extent.Text}
$profile=Get-RangeReadProfile
$root=Join-Path $workspace '.lab\hyperv\extent-placement\win11-20261024T000401422Z'
$placement=Get-Content -LiteralPath ($root+'\guest\placement.json') -Raw|ConvertFrom-Json
$remount=Get-Content -LiteralPath ($root+'\remount\identity.json') -Raw|ConvertFrom-Json
$allocation=Get-Content -LiteralPath ($root+'\remount\allocation-remount.json') -Raw|ConvertFrom-Json
$control=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\devdrive\win11-20261023T230635404Z\after\verify.json') -Raw|ConvertFrom-Json
Assert-RangeReadControl $control $profile.controlRunId;Assert-RangeReadPlacement $placement $remount $control $profile;Assert-RangeReadAllocation $allocation $control.target.guest $placement $profile;$checks+=3
foreach($field in @('status','probeId','controlRunId','controlEvidenceSha256','capturedAllocationSha256','expectedSha256','requestedLcn')){$bad=Clone $placement;$bad.$field=if($field -ceq 'requestedLcn'){1}else{'wrong'};Reject {Assert-RangeReadPlacement $bad $remount $control $profile} 'Changed placement profile accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $remount;$bad.partition.$field='wrong';Reject {Assert-RangeReadPlacement $placement $bad $control $profile} 'Changed remount geometry accepted.'}
foreach($phase in @('before','after')){foreach($field in @('length','sha256','fileId64','volumeSerialHex')){$bad=Clone $placement;$bad.$phase.$field=if($field -ceq 'length'){1}else{'wrong'};Reject {Assert-RangeReadPlacement $bad $remount $control $profile} 'Changed range proof accepted.'};$bad=Clone $placement;$bad.$phase.extents[0].lcn++;Reject {Assert-RangeReadPlacement $bad $remount $control $profile} 'Unreviewed LCN accepted.'}
foreach($index in @(0,1)){foreach($field in @('complete','stableDuringObservation','sha256','fileId64')){$bad=Clone $allocation;$bad.files[$index].observation.$field=if($field -cin @('complete','stableDuringObservation')){$false}else{'wrong'};Reject {Assert-RangeReadAllocation $bad $control.target.guest $placement $profile} 'Changed fixture accepted.'};$bad=Clone $allocation;$bad.files[$index].observation.extents[0].lcn++;Reject {Assert-RangeReadAllocation $bad $control.target.guest $placement $profile} 'Changed current mapping accepted.'}
foreach($attribute in @('SparseFile','Compressed','Encrypted','ReparsePoint')){$bad=Clone $allocation;$bad.files[1].observation.attributes=$attribute;Reject {Assert-RangeReadAllocation $bad $control.target.guest $placement $profile} 'Nonordinary fixture accepted.'}
$nativeText=[IO.File]::ReadAllText($nativePath)
Check ($nativeText -notmatch 'WriteFile|SetEndOfFile|SetFileValidData|0x00090020|0x00090074|0x00090083') 'Forbidden native write/dismount/move operation found.'
$dry=& $path -CaptureId ('a'*32) -WhatIf
Reject {& $path -CaptureId (('a'*32)+[Environment]::NewLine) -WhatIf} 'Trailing newline capture ID accepted.'
Check ($dry.DryRun -and $dry.MaximumRawReadBytes -eq 131072 -and $dry.MaximumLockCalls -eq 1 -and -not $dry.RawWriteRequestsIssued -and -not $dry.ConversionQualified) 'Guest WhatIf failed.'
"Guest range read: $checks checks passed."
