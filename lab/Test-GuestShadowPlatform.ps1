<# Pure/mock preparation tests plus ordinary temporary file/ACL checks; no VHD or VM actions. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'guest\Prepare-GuestShadowPlatform.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
$fake=@'
namespace Ntfs2Refs {
 public sealed class FakeShadowApi:IShadowDiskApi {
  public System.Guid Id,ContentId;public string FailName,ThrowName;public uint Error=123,Subtype=3;public ulong PhysicalBytes=4194304;public string DevicePath=@"\\.\PhysicalDrive3";
  public int Creates,Opens,Attaches,Closes;public bool InvalidHandle;
  public FakeShadowApi(System.Guid id){Id=id;ContentId=id;}
  private uint Code(string n){if(ThrowName==n)throw new System.IO.IOException("injected transport/native exception");return FailName==n?Error:0U;}
  public uint Create(string p,System.Guid id,out System.IntPtr h){Creates++;h=InvalidHandle?System.IntPtr.Zero:new System.IntPtr(101);return Code("Create");}
  public uint Open(string p,out System.IntPtr h){Opens++;h=InvalidHandle?System.IntPtr.Zero:new System.IntPtr(102);return Code("Open");}
  public uint Attach(System.IntPtr h){Attaches++;return Code("Attach");}
  public uint Close(System.IntPtr h){Closes++;return Code("Close");}
  public uint PhysicalPath(System.IntPtr h,out string p){p=DevicePath;return Code("Physical");}
  public byte[] Information(uint v){byte[] b=new byte[32];System.Array.Copy(System.BitConverter.GetBytes(v),b,4);
   if(v==1){System.Array.Copy(System.BitConverter.GetBytes(NativeShadowDisk.VirtualBytes),0,b,8,8);System.Array.Copy(System.BitConverter.GetBytes(PhysicalBytes),0,b,16,8);System.Array.Copy(System.BitConverter.GetBytes((uint)2097152),0,b,24,4);System.Array.Copy(System.BitConverter.GetBytes((uint)512),0,b,28,4);}
   if(v==2)System.Array.Copy(ContentId.ToByteArray(),0,b,8,16);
   if(v==14)System.Array.Copy(Id.ToByteArray(),0,b,8,16);
   if(v==7)System.Array.Copy(System.BitConverter.GetBytes(Subtype),0,b,8,4);
   if(v==10)System.Array.Copy(System.BitConverter.GetBytes((uint)4096),0,b,8,4);return b;
  }
  public uint Query(System.IntPtr h,uint v,out byte[] b){b=Information(v);return Code("Query"+v);}
 }
 public sealed class FakeShadowPrivilegeApi:IShadowPrivilegeApi {
  public bool Assigned=true,CloseFail,ThrowAdjust;public uint Attributes;public int AdjustCount,QueryCount,CloseCount,ErrorAtAdjust,ErrorAtQuery;
  public uint Open(out System.IntPtr token){token=new System.IntPtr(200);return 0;}
  public uint Lookup(out long luid){luid=28;return 0;}
  public uint Query(System.IntPtr token,out byte[] bytes){QueryCount++;bytes=new byte[Assigned?16:4];if(Assigned){System.Array.Copy(System.BitConverter.GetBytes(1U),bytes,4);System.Array.Copy(System.BitConverter.GetBytes(28L),0,bytes,4,8);System.Array.Copy(System.BitConverter.GetBytes(Attributes),0,bytes,12,4);}return QueryCount==ErrorAtQuery?5U:0U;}
  public uint Adjust(System.IntPtr token,long luid,uint attributes,out ShadowPrivilegePrevious previous){
   AdjustCount++;if(ThrowAdjust)throw new System.IO.IOException("unknown adjustment completion");uint old=Attributes;Attributes=(Attributes&~2U)|(attributes&2U);
   previous=new ShadowPrivilegePrevious{Count=old==Attributes?0U:1U,Luid=luid,Attributes=old,ReturnedBytes=old==Attributes?4U:16U};return AdjustCount==ErrorAtAdjust?1300U:0U;
  }
  public uint Close(System.IntPtr token){CloseCount++;return CloseFail?6U:0U;}
 }
}
'@
if(-not ('Ntfs2Refs.FakeShadowApi' -as [type])){Add-Type -TypeDefinition ((Get-Content (Join-Path $PSScriptRoot 'guest\NativeShadowDisk.cs') -Raw)+[Environment]::NewLine+$fake)}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Value){$d=$Value|ConvertTo-Json -Depth 12|ConvertFrom-Json;if($d -is [array]){foreach($i in $d){$i}}else{$d}}
$id=[guid]::NewGuid();$backing='J:\ntfs2refs-shadow\'+('a'*32)+'\shadow.vhdx'
$parameters=[Ntfs2Refs.WindowsShadowDiskApi]::CreateParameters($id)
Check ($parameters.Version -eq 2 -and $parameters.Version2.UniqueId -eq $id -and $parameters.Version2.MaximumSize -eq 64GB) 'Wrong create identity/capacity.'
Check ($parameters.Version2.ParentPath -eq [IntPtr]::Zero -and $parameters.Version2.SourcePath -eq [IntPtr]::Zero -and $parameters.Version2.OpenFlags -eq 0) 'Source clone/parent/open flags appeared.'
Check ($parameters.Version2.BlockSizeInBytes -eq 2MB -and $parameters.Version2.SectorSizeInBytes -eq 512 -and $parameters.Version2.PhysicalSectorSizeInBytes -eq 4096) 'Wrong VHDX geometry.'
Check ([Runtime.InteropServices.Marshal]::SizeOf([type][Ntfs2Refs.ShadowCreateParameters]) -eq 128 -and [Runtime.InteropServices.Marshal]::OffsetOf([Ntfs2Refs.ShadowCreateParameters],'Version2').ToInt64() -eq 8) 'Create v2 x64 ABI differs.'
Check ([Runtime.InteropServices.Marshal]::OffsetOf([Ntfs2Refs.ShadowCreateV2],'ParentPath').ToInt64() -eq 40 -and [Runtime.InteropServices.Marshal]::OffsetOf([Ntfs2Refs.ShadowCreateV2],'SourcePath').ToInt64() -eq 48) 'Create pointer offsets differ.'
Check ([Runtime.InteropServices.Marshal]::SizeOf([type][Ntfs2Refs.ShadowOpenParameters]) -eq 28 -and [Runtime.InteropServices.Marshal]::SizeOf([type][Ntfs2Refs.ShadowAttachParameters]) -eq 8) 'Open/attach ABI differs.'
foreach($bad in @('C:\shadow.vhdx','J:\ntfs2refs-shadow\..\shadow.vhdx',($backing+[char]10),$backing.Replace('shadow.vhdx','source.raw'))){Reject {New-Object Ntfs2Refs.NativeShadowDisk($bad,$id)} 'Unsafe backing path accepted.'}
Reject {[Ntfs2Refs.WindowsShadowDiskApi]::CreateParameters([guid]::Empty)} 'Empty VHD GUID accepted.'
foreach($bad in @('F:','\\.\PhysicalDrive-1','\\.\PhysicalDrive99999','\\.\PhysicalDrive3\',('\\.\PhysicalDrive3'+[char]10))){Reject {[Ntfs2Refs.NativeShadowDisk]::ParseDiskNumber($bad)} 'Unsafe device path accepted.'}
Check ([Ntfs2Refs.NativeShadowDisk]::ParseDiskNumber('\\.\PhysicalDrive3') -eq 3) 'Valid device number refused.'
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$native=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api)
$native.Create();Check ($native.Created -and $native.HandleCloseSucceeded -and $api.Creates -eq 1 -and $api.Closes -eq 1) 'Creation close lifecycle failed.'
$info=$native.OpenOwned();Check ($info.virtualDiskId -ceq $id.ToString('D') -and $info.virtualDiskIdQueryVersion -eq 14 -and $info.identifierQueryVersion -eq 2 -and $info.providerSubtype -eq 3) 'Open stable identity verification failed.'
$info=$native.Attach();Check ($native.Attached -and $info.physicalPath -ceq '\\.\PhysicalDrive3' -and $api.Attaches -eq 1) 'Persistent attachment lifecycle failed.'
Reject {$native.Create()} 'Repeated create accepted.';Reject {$native.OpenOwned()} 'Repeated open accepted.';Reject {$native.Attach()} 'Repeated attach accepted.'
$native.Close();$native.Close();Check ($api.Closes -eq 2 -and $native.HandleCloseSucceeded -and $native.Attached) 'Close repeated native close or lost attachment fact.'
Check (@($native.Calls|Where-Object{-not $_.succeeded -or -not $_.finishedUtc}).Count -eq 0) 'Success calls incomplete.'
Check (@($native.Calls|Where-Object{$_.name -clike 'GetVirtualDiskInformation:*' -and $_.outputHex.Length -eq 64}).Count -ge 4) 'Native query bytes not retained.'
foreach($failure in @('Create','Open','Attach','Query1','Query14','Physical')){
 $api=New-Object Ntfs2Refs.FakeShadowApi($id);$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);$api.FailName=$failure
 Reject {if($failure -ceq 'Create'){$n.Create()}elseif($failure -cin @('Open','Query1','Query14')){$n.OpenOwned()}else{$n.OpenOwned()|Out-Null;$n.Attach()|Out-Null}} 'Native refusal accepted.'
 Check (-not $n.OperationActive -and @($n.Calls|Where-Object error -EQ 123).Count -eq 1) 'Native error state not preserved.'
 $n.Close()
}
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$api.ThrowName='Create';$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);Reject {$n.Create()} 'Thrown native operation accepted.';Check $n.OperationActive 'Indeterminate native operation lost.'
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$api.FailName='Close';$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);Reject {$n.Create()} 'Close failure accepted.';Reject {$n.Close()} 'Close failure retried.';Check ($api.Closes -eq 1 -and -not $n.HandleCloseSucceeded) 'Close failure retried native call.'
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$api.InvalidHandle=$true;$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);Reject {$n.Create()} 'Invalid success handle accepted.';Check ($api.Closes -eq 0) 'Invalid returned handle was closed.'
Check ($n.Calls[0].succeeded -and $n.Calls[0].error -eq 0) 'Malformed success was mislabeled as a native API error.'
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$api.Subtype=4;$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);Reject {$n.OpenOwned()} 'Differencing VHD accepted.';Check ($api.Attaches -eq 0) 'Unqualified VHD attached.';$n.Close()
$api=New-Object Ntfs2Refs.FakeShadowApi($id);$api.PhysicalBytes=6GB+1;$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);Reject {$n.OpenOwned()} 'Over-budget VHD accepted.';Check (@($n.Calls|Where-Object{$_.name -ceq 'GetVirtualDiskInformation:1' -and $_.outputHex}).Count -eq 1) 'Budget failure lost native size bytes.';$n.Close()
$api=New-Object Ntfs2Refs.FakeShadowApi($id)
Check ([Runtime.InteropServices.Marshal]::SizeOf([type][Ntfs2Refs.WindowsShadowPrivilegeApi+TokenPrivileges]) -eq 16) 'Single privilege ABI differs.'
foreach($initial in @(0,1,2,3)){
 $pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.Attributes=$initial;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa)
 $scope.Enable();Check ($scope.Audit.assigned -and $scope.Audit.beforeAttributes -eq $initial -and $pa.Attributes -eq ($initial -bor 2)) 'Own privilege assignment/enable audit differs.'
 Reject {$scope.Enable()} 'Repeated privilege enable accepted.'
 $scope.Restore();$scope.Restore();Check ($scope.Audit.restored -and $scope.Audit.tokenCloseSucceeded -and $scope.Audit.restoredAttributes -eq $initial -and $pa.Attributes -eq $initial -and $pa.CloseCount -eq 1) 'Previous privilege state not restored exactly.'
}
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.Assigned=$false;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);Reject {$scope.Enable()} 'Unassigned privilege accepted.';$scope.Restore();Check ($pa.AdjustCount -eq 0 -and $scope.Audit.restored -and $scope.Audit.tokenCloseSucceeded) 'Unassigned privilege was changed or token leaked.'
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.ErrorAtAdjust=1;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);Reject {$scope.Enable()} 'Partial adjustment error accepted.';$scope.Restore();Check ($pa.Attributes -eq 0 -and $scope.Audit.restored -and $pa.AdjustCount -eq 2) 'Failed adjustment did not restore audited state.'
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.ErrorAtAdjust=2;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);$scope.Enable();Reject {$scope.Restore()} 'Restore refusal accepted.';Check (-not $scope.Audit.restored -and $scope.Audit.tokenCloseSucceeded) 'Restore failure falsely qualified.';Reject {$scope.Restore()} 'Failed restoration retried.';Check ($pa.AdjustCount -eq 2) 'Restoration issued extra native retry.'
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.ErrorAtQuery=3;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);$scope.Enable();Reject {$scope.Restore()} 'Unverified restored state accepted.';Check (-not $scope.Audit.restored) 'Missing restored-state query qualified.'
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.ThrowAdjust=$true;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);Reject {$scope.Enable()} 'Unknown privilege completion accepted.';Reject {$scope.Restore()} 'Unknown operation speculatively restored.';Check ($scope.Audit.operationActive -and $pa.CloseCount -eq 0) 'Indeterminate privilege state not preserved.'
$pa=New-Object Ntfs2Refs.FakeShadowPrivilegeApi;$pa.CloseFail=$true;$scope=New-Object Ntfs2Refs.ShadowManageVolumePrivilege($pa);$scope.Enable();Reject {$scope.Restore()} 'Token close failure accepted.';Reject {$scope.Restore()} 'Token close retried.';Check ($pa.CloseCount -eq 1 -and -not $scope.Audit.tokenCloseSucceeded) 'Failed token close lost evidence.'
Reject {[Ntfs2Refs.ShadowManageVolumePrivilege]::FindPrivilege((New-Object byte[] 3),28)} 'Short token buffer accepted.'
# Exercise the real token-query ABI read-only. No privilege is adjusted here.
$tokenApi=New-Object Ntfs2Refs.WindowsShadowPrivilegeApi;[IntPtr]$tokenHandle=[IntPtr]::Zero;[long]$volumeLuid=0;[byte[]]$tokenBytes=@()
try{
 Check ($tokenApi.Open([ref]$tokenHandle) -eq 0 -and $tokenHandle -ne [IntPtr]::Zero) 'Read-only token audit open failed.'
 Check ($tokenApi.Lookup([ref]$volumeLuid) -eq 0) 'Native privilege lookup failed.'
 Check ($tokenApi.Query($tokenHandle,[ref]$tokenBytes) -eq 0) 'Native token privilege query failed.'
 $assignment=[Ntfs2Refs.ShadowManageVolumePrivilege]::FindPrivilege($tokenBytes,$volumeLuid);Check ($assignment[0] -in @(0,1)) 'Actual token buffer failed bounded parsing.'
}finally{if($tokenHandle -ne [IntPtr]::Zero){Check ($tokenApi.Close($tokenHandle) -eq 0) 'Token audit handle close failed.'}}
$duplicate=New-Object byte[] 28;[BitConverter]::GetBytes([uint32]2).CopyTo($duplicate,0);[BitConverter]::GetBytes(28L).CopyTo($duplicate,4);[BitConverter]::GetBytes(28L).CopyTo($duplicate,16);Reject {[Ntfs2Refs.ShadowManageVolumePrivilege]::FindPrivilege($duplicate,28)} 'Duplicate token privilege accepted.'
$fakeProcess=[pscustomobject]@{ExitCode=0;waitResult=$false;milliseconds=0};$fakeProcess|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($milliseconds);$this.milliseconds=$milliseconds;$this.waitResult}
$event=[pscustomobject]@{nativeExitObserved=$false;exitCode=$null};$taskSource=New-Object 'Threading.Tasks.TaskCompletionSource[string]';$taskSource.SetResult('done');$task=$taskSource.Task
Reject {Complete-ShadowQueryProcess $fakeProcess $task $task $event} 'Unbounded native query wait accepted.';Check ($fakeProcess.milliseconds -eq 30000 -and -not $event.nativeExitObserved) 'Query deadline changed.'
$fakeProcess.waitResult=$true;$captured=Complete-ShadowQueryProcess $fakeProcess $task $task $event;Check ($event.nativeExitObserved -and $captured.stdout -ceq 'done') 'Bounded native query completion failed.'
$slowTask=[pscustomobject]@{milliseconds=0};$slowTask|Add-Member -MemberType ScriptMethod -Name Wait -Value {param($milliseconds);$this.milliseconds=$milliseconds;$false}
Reject {Complete-ShadowQueryProcess $fakeProcess $slowTask $task $event} 'Incomplete query output accepted.';Check ($slowTask.milliseconds -eq 5000) 'Output deadline changed.'
foreach($which in @(1,7,10,14)){$a=$api.Information(1);$b=$api.Information(2);$c=$api.Information(7);$d=$api.Information(10);$e=$api.Information(14);switch($which){1{$a[8]=1}7{$c[8]=2}10{$d[8]=1}14{$e[8]=$e[8] -bxor 1}};Reject {[Ntfs2Refs.NativeShadowDisk]::ParseInfo($a,$b,$c,$d,$e,$id)} 'Changed native identity/geometry accepted.'}
Reject {[Ntfs2Refs.NativeShadowDisk]::ParseInfo((New-Object byte[] 12),$api.Information(2),$api.Information(7),$api.Information(10),$api.Information(14),$id)} 'Short native buffer accepted.'
foreach($version in @(2,14)){foreach($length in @(0,8,23)){$bad=New-Object byte[] $length;if($length -ge 4){[BitConverter]::GetBytes([uint32]$version).CopyTo($bad,0)};$generation=if($version -eq 2){$bad}else{$api.Information(2)};$stable=if($version -eq 14){$bad}else{$api.Information(14)};Reject {[Ntfs2Refs.NativeShadowDisk]::ParseInfo($api.Information(1),$generation,$api.Information(7),$api.Information(10),$stable,$id)} 'Incomplete generation/stable GUID buffer accepted.'}}
$api.ContentId=[guid]::NewGuid();$changed=[Ntfs2Refs.NativeShadowDisk]::ParseInfo($api.Information(1),$api.Information(2),$api.Information(7),$api.Information(10),$api.Information(14),$id)
Check ($changed.virtualDiskId -ceq $id.ToString('D') -and $changed.identifier -ceq $api.ContentId.ToString('D') -and $changed.identifierSemantics -ceq 'vhdx-content-generation') 'Content change was mistaken for stable identity replacement.'
$n=New-Object Ntfs2Refs.NativeShadowDisk($backing,$id,$api);$n.OpenOwned()|Out-Null;$n.Attach()|Out-Null;$api.ContentId=[guid]::NewGuid();$observed=$n.Observe($true);Check ($observed.virtualDiskId -ceq $id.ToString('D') -and $observed.identifier -ceq $api.ContentId.ToString('D')) 'Attached content generation change lost evidence.'
$api.Id=[guid]::NewGuid();Reject {$n.Observe($true)} 'Changed persistent query14 identity was re-enrolled.';$n.Close()
# Native Windows11 diagnosis18818a9d...466ea3: query2 changed, query14 stayed the creation GUID.
$measuredApi=New-Object Ntfs2Refs.FakeShadowApi([guid]'0dcb07bc-a937-4fd4-8d31-7dc7c1c5d3d5');$measuredApi.ContentId=[guid]'ad9ad71c-d01a-45ea-8d54-b0ea4dcd61c4';$measuredApi.PhysicalBytes=36MB
$measured=[Ntfs2Refs.NativeShadowDisk]::ParseInfo($measuredApi.Information(1),$measuredApi.Information(2),$measuredApi.Information(7),$measuredApi.Information(10),$measuredApi.Information(14),$measuredApi.Id)
Check ($measured.identifier -ceq 'ad9ad71c-d01a-45ea-8d54-b0ea4dcd61c4' -and $measured.virtualDiskId -ceq '0dcb07bc-a937-4fd4-8d31-7dc7c1c5d3d5') 'Measured content/stable identifier distinction regressed.'
$identity=[pscustomobject]@{schemaVersion=1;role='journal';uniqueId='600224806AAC261F021F249596F332FC';serialNumber='';sizeBytes=8GB;location='Integrated : Bus 0 : Device 10738 : Function 51055 : Adapter 0 : Port 0 : Target 0 : LUN 2'}
Assert-ShadowJournalManifest $identity;$script:checks++
foreach($field in @('schemaVersion','role','uniqueId','serialNumber','sizeBytes','location')){$b=Clone $identity;$b.$field='wrong';Reject {Assert-ShadowJournalManifest $b} 'Changed journal enrollment accepted.'}
$journal=[pscustomobject]@{Number=2;UniqueId=$identity.uniqueId;Size=8GB;PartitionStyle='RAW';IsBoot=$false;IsSystem=$false;IsReadOnly=$false;IsOffline=$false;LogicalSectorSize=512;PhysicalSectorSize=4096}
Assert-ShadowJournalBlank $journal @();$script:checks++
foreach($field in @('UniqueId','Size','PartitionStyle','LogicalSectorSize','PhysicalSectorSize')){$b=Clone $journal;$b.$field='wrong';Reject {Assert-ShadowJournalBlank $b @()} 'Unsafe journal accepted.'}
foreach($field in @('IsBoot','IsSystem','IsReadOnly','IsOffline')){$b=Clone $journal;$b.$field=$true;Reject {Assert-ShadowJournalBlank $b @()} 'Protected/OS journal accepted.'}
Reject {Assert-ShadowJournalBlank $journal @([pscustomobject]@{PartitionNumber=1})} 'Nonempty journal accepted.'
$original=@([pscustomobject]@{Number=0;UniqueId='os'},[pscustomobject]@{Number=1;UniqueId='target'},[pscustomobject]@{Number=2;UniqueId=$identity.uniqueId})
$shadow=Clone $journal;$shadow.Number=3;$shadow.UniqueId='shadow';$shadow.Size=64GB
Assert-ShadowNewDisk $shadow $original '\\.\PhysicalDrive3' @();$script:checks++
foreach($field in @('Number','UniqueId','Size','LogicalSectorSize','PhysicalSectorSize','PartitionStyle')){$b=Clone $shadow;$b.$field=if($field -ceq 'UniqueId'){'target'}elseif($field -ceq 'Number'){1}else{'wrong'};Reject {Assert-ShadowNewDisk $b $original '\\.\PhysicalDrive3' @()} 'Wrong shadow disk accepted.'}
foreach($field in @('IsBoot','IsSystem','IsReadOnly','IsOffline')){$b=Clone $shadow;$b.$field=$true;Reject {Assert-ShadowNewDisk $b $original '\\.\PhysicalDrive3' @()} 'Unsafe shadow state accepted.'}
Reject {Assert-ShadowNewDisk $shadow $original '\\.\PhysicalDrive2' @()} 'Different native physical path accepted.'
Reject {Assert-ShadowNewDisk $shadow $original '\\.\PhysicalDrive3' @([pscustomobject]@{PartitionNumber=1})} 'Nonblank shadow accepted.'
$shadow|Add-Member Guid ([guid]::NewGuid().ToString('D'))
$part=[pscustomobject]@{DiskNumber=3;Offset=16MB;Size=52GB;DriveLetter='S';IsBoot=$false;IsSystem=$false;GptType='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}';Guid=[guid]::NewGuid().ToString('D')}
Assert-ShadowPartition $shadow $part 52GB S;$script:checks++
foreach($field in @('DiskNumber','Offset','Size','DriveLetter','GptType','Guid')){$b=Clone $part;$b.$field='wrong';Reject {Assert-ShadowPartition $shadow $b 52GB S} 'Wrong partition accepted.'}
foreach($field in @('IsBoot','IsSystem')){$b=Clone $part;$b.$field=$true;Reject {Assert-ShadowPartition $shadow $b 52GB S} 'OS partition accepted.'}
Assert-ShadowCapacity 6GB 6GB 6GB 1280MB;$script:checks++
foreach($bytes in @(0,(6GB+1))){Reject {Assert-ShadowCapacity $bytes 4MB 4MB 2GB} 'Unsafe native size accepted.';Reject {Assert-ShadowCapacity 4MB $bytes 4MB 2GB} 'Unsafe logical file size accepted.';Reject {Assert-ShadowCapacity 4MB 4MB $bytes 2GB} 'Unsafe allocated file size accepted.'}
Reject {Assert-ShadowCapacity 4MB 4MB 4MB (1280MB-1)} 'Insufficient journal reserve accepted.'
Check (Test-ShadowDevDrive 'The volume is formatted as a developer volume but is not trusted on this machine.') 'Native DevDrive designation refused.'
Check (-not (Test-ShadowDevDrive 'The volume is not formatted as a developer volume.')) 'Ordinary volume accepted as DevDrive.'
$measuredDevDrive="This is a trusted developer volume.`r`n`r`nDeveloper volumes are protected by antivirus filter.`r`n`r`nFilters currently attached to this developer volume:`r`n    WdFilter`r`n"
Check (Test-ShadowDevDrive $measuredDevDrive) 'Measured trusted native stdout refused.'
foreach($affirmative in @('This volume is a trusted developer volume.','The volume is a trusted developer volume.','This is an untrusted developer volume.','This volume is an untrusted developer volume.','The volume is an untrusted developer volume.','The volume is formatted as a developer volume.')){Check (Test-ShadowDevDrive $affirmative) 'Explicit affirmative designation refused.'}
foreach($negative in @('This is not a developer volume.','This is not a trusted developer volume.','This is an ordinary volume.','This is a trusted developer volume but validation failed.',($measuredDevDrive+"`r`nDeveloper volumes are disabled."),($measuredDevDrive+"`r`nThe volume is not formatted as a developer volume."))){Check (-not (Test-ShadowDevDrive $negative)) 'Negative or unknown designation accepted.'}
$script:jobState='Completed';$script:removed=0
function Format-Volume {param($Partition,[switch]$DevDrive,$FileSystem,$AllocationUnitSize,$NewFileSystemLabel,[switch]$Confirm,[switch]$AsJob);$script:formatArgs=$PSBoundParameters;[pscustomobject]@{State=$script:jobState}}
function Wait-Job {param($Job,$Timeout);if($script:jobState -cne 'Running'){$Job}}
function Receive-Job {param($Job,$ErrorAction);if($Job.State -ceq 'Failed'){throw 'Native format refused.'}}
function Remove-Job {param($Job,[switch]$Force);$script:removed++}
Invoke-ShadowFormat $part -DevDrive;Check ($script:formatArgs.DevDrive -and $script:formatArgs.FileSystem -ceq 'ReFS' -and $script:formatArgs.AllocationUnitSize -eq 4096 -and $script:formatArgs.NewFileSystemLabel -ceq 'n2r-retained-shadow' -and -not $script:formatIndeterminate) 'Shadow native format profile changed.'
Invoke-ShadowFormat $part;Check ($script:formatArgs.FileSystem -ceq 'NTFS' -and $script:formatArgs.NewFileSystemLabel -ceq 'ntfs2refs-journal') 'Journal native format profile changed.'
$script:jobState='Running';$before=$script:removed;Reject {Invoke-ShadowFormat $part -DevDrive} 'Timed-out format accepted.';Check ($script:formatIndeterminate -and $script:removed -eq $before) 'Timed-out format lost active state or removed job.'
$script:jobState='Failed';Reject {Invoke-ShadowFormat $part -DevDrive} 'Native failure accepted.';Check (-not $script:formatIndeterminate) 'Returned native failure falsely indeterminate.'
$script:jobState='Stopped';Reject {Invoke-ShadowFormat $part -DevDrive} 'Stopped format accepted.';Check $script:formatIndeterminate 'Stopped format qualified completion.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('n2r-shadow-guards-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
try{
 $private=Join-Path $temp 'private';New-ShadowPrivateDirectory $private;Check (Get-Acl -LiteralPath $private).AreAccessRulesProtected 'Private directory ACL inherited.'
 $rules=@((Get-Acl -LiteralPath $private).GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));Check ($rules.Count -eq 2 -and @($rules|Where-Object{$_.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544')}).Count -eq 0) 'Unexpected private directory access grant.'
 Reject {New-ShadowPrivateDirectory $private} 'Existing private directory adopted.'
 $file=Join-Path $private 'ordinary.bin';[IO.File]::WriteAllBytes($file,[byte[]](1,2,3,4));Assert-ShadowOrdinaryPath $file|Out-Null;$script:checks++
 Check ([Ntfs2Refs.WindowsShadowDiskApi]::AllocatedFileBytes($file) -ge 4) 'Native ordinary-file allocation query failed.'
 Reject {Assert-ShadowOrdinaryPath $file -Directory} 'File accepted as directory.';Reject {Assert-ShadowOrdinaryPath $private} 'Directory accepted as file.'
}finally{
 $full=[IO.Path]::GetFullPath($temp);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
 if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $full -Leaf) -cnotmatch '\An2r-shadow-guards-[0-9a-f]{32}\z'){throw 'Unsafe test cleanup target.'};Remove-Item -LiteralPath $full -Recurse -Force
}
$dry=& $path -RunId ('a'*32) -JournalManifestPath 'unused.json' -WhatIf;Check ($dry.Status -ceq 'what-if' -and -not $dry.SourceTargetWrites -and -not $dry.PayloadCopy) 'WhatIf invoked preparation.'
[pscustomobject]@{Checks=$script:checks;Passed=$true;VhdOperations=$false;VMOperations=$false}
