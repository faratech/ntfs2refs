<# Pure guards and fake native API only; no virtual disk or VM actions. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'guest\Restore-GuestShadowAttachment.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Value){$copy=$Value|ConvertTo-Json -Depth 20|ConvertFrom-Json;if($copy -is [array]){foreach($item in $copy){$item}}else{$copy}}
$run='a'*32;$hash='b'*64;$id=[guid]::NewGuid().ToString('D');$jg=[guid]::NewGuid().ToString('D');$jp=[guid]::NewGuid().ToString('D');$sg=[guid]::NewGuid().ToString('D');$sp=[guid]::NewGuid().ToString('D')
$proof=[pscustomobject]@{schemaVersion=1;kind='guest-local-shadow-platform';status='shadow-platform-prepared';runId=$run;nativeSourceSha256=$hash;backingPath=('J:\ntfs2refs-shadow\'+$run+'\shadow.vhdx');attachmentRetained=$true;handleCloseSucceeded=$true;nativeOperationCompletionKnown=$true;privilegeRestored=$true;sourceTargetWriteRequestsIssued=$false;payloadCopied=$false;conversionQualified=$false;bootQualified=$false;vhdIdentifier=$id;vhdIdentityQueryVersion=14;vhdContentGenerationQueryVersion=2;
 journalIdentity=[pscustomobject]@{uniqueId='600224806AAC261F021F249596F332FC';role='journal';sizeBytes=8GB};
 journal=[pscustomobject]@{diskNumber=2;diskGuid=$jg;partitionNumber=2;partitionGuid=$jp;offset=16MB;length=(8GB-32MB);letter='J';filesystem='NTFS';allocationUnitSize=4096;volumeGuid=('\\?\Volume{'+[guid]::NewGuid().ToString('D')+'}\')};
 shadow=[pscustomobject]@{physicalPath='\\.\PhysicalDrive3';diskNumber=3;diskUniqueId='SHADOW-OWNED';diskGuid=$sg;partitionNumber=2;partitionGuid=$sp;offset=16MB;length=52GB;logicalSectorSize=512;physicalSectorSize=4096;letter='S';filesystem='ReFS';allocationUnitSize=4096;volumeGuid=('\\?\Volume{'+[guid]::NewGuid().ToString('D')+'}\')};
 finalVhd=[pscustomobject]@{identifier=[guid]::NewGuid().ToString('D');virtualDiskId=$id;identifierQueryVersion=2;virtualDiskIdQueryVersion=14;identifierSemantics='vhdx-content-generation';physicalPath='\\.\PhysicalDrive3';virtualBytes=64GB;blockBytes=2MB;logicalSectorBytes=512;physicalSectorBytes=4096;providerSubtype=3}}
Assert-AttachmentPreparation $proof $run $hash;$script:checks++
foreach($field in @('schemaVersion','kind','status','runId','nativeSourceSha256','backingPath','vhdIdentifier','vhdIdentityQueryVersion','vhdContentGenerationQueryVersion')){$b=Clone $proof;$b.$field='wrong';Reject {Assert-AttachmentPreparation $b $run $hash} ('Changed preparation accepted: '+$field)}
foreach($field in @('attachmentRetained','handleCloseSucceeded','nativeOperationCompletionKnown','privilegeRestored')){foreach($bad in @($false,'true',1)){$b=Clone $proof;$b.$field=$bad;Reject {Assert-AttachmentPreparation $b $run $hash} ('Unqualified completion accepted: '+$field)}}
foreach($field in @('sourceTargetWriteRequestsIssued','payloadCopied','conversionQualified','bootQualified')){foreach($bad in @($true,'false',0)){$b=Clone $proof;$b.$field=$bad;Reject {Assert-AttachmentPreparation $b $run $hash} ('False boundary accepted: '+$field)}}
foreach($section in @('journal','shadow','finalVhd')){foreach($field in $proof.$section.PSObject.Properties.Name){$b=Clone $proof;$b.$section.$field=if($field -ceq 'diskUniqueId'){''}else{'wrong'};Reject {Assert-AttachmentPreparation $b $run $hash} ('Changed pinned field accepted: '+$section+'.'+$field)}}
foreach($field in $proof.journalIdentity.PSObject.Properties.Name){$b=Clone $proof;$b.journalIdentity.$field='wrong';Reject {Assert-AttachmentPreparation $b $run $hash} 'Changed journal enrollment accepted.'}
foreach($bad in @('','{}','00000000-0000-0000-0000-000000000000',($id+[char]10))){Reject {Assert-AttachmentGuid $bad} 'Malformed/empty GUID accepted.'}
$ids=@('60022480BEA35BA9D496D5AFF633D768','60022480D091C4251B5FFD619706C2B5','600224806AAC261F021F249596F332FC')
$disks=@(for($i=0;$i -lt 3;$i++){[pscustomobject]@{Number=$i;UniqueId=$ids[$i];Size=$(if($i -eq 2){8GB}else{64GB});LogicalSectorSize=512;PhysicalSectorSize=4096}})
Assert-AttachmentOriginalDisks $disks;$script:checks++
Reject {Assert-AttachmentOriginalDisks @($disks[0],$disks[1])} 'Missing original accepted.';Reject {Assert-AttachmentOriginalDisks @($disks+$disks[2])} 'Extra original accepted.'
foreach($i in 0..2){foreach($field in @('Number','UniqueId','Size','LogicalSectorSize','PhysicalSectorSize')){$b=@(Clone $disks);$b[$i].$field='wrong';Reject {Assert-AttachmentOriginalDisks $b} 'Changed original disk accepted.'}}
$jd=[pscustomobject]@{Number=2;UniqueId=$ids[2];Guid=$jg;Size=8GB;PartitionStyle='GPT';IsBoot=$false;IsSystem=$false;IsOffline=$false;IsReadOnly=$false;LogicalSectorSize=512;PhysicalSectorSize=4096}
$part=[pscustomobject]@{DiskNumber=2;PartitionNumber=2;Guid=$jp;Offset=16MB;Size=(8GB-32MB);GptType='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}';IsBoot=$false;IsSystem=$false;DriveLetter='J'}
$jvol=[pscustomobject]@{UniqueId=$proof.journal.volumeGuid;FileSystem='NTFS';FileSystemLabel='ntfs2refs-journal';AllocationUnitSize=4096;SizeRemaining=1280MB}
Assert-AttachmentJournal $jd $part $jvol $proof;$script:checks++
foreach($field in $jd.PSObject.Properties.Name){$b=Clone $jd;$b.$field=if($field -clike 'Is*'){$true}else{'wrong'};Reject {Assert-AttachmentJournal $b $part $jvol $proof} ('Changed journal disk accepted: '+$field)}
foreach($field in $part.PSObject.Properties.Name){$b=Clone $part;$b.$field=if($field -clike 'Is*'){$true}else{'wrong'};Reject {Assert-AttachmentJournal $jd $b $jvol $proof} ('Changed journal partition accepted: '+$field)}
foreach($field in $jvol.PSObject.Properties.Name){$b=Clone $jvol;$b.$field=if($field -ceq 'SizeRemaining'){1280MB-1}else{'wrong'};Reject {Assert-AttachmentJournal $jd $part $b $proof} 'Changed journal volume accepted.'}
$sd=Clone $jd;$sd.Number=3;$sd.UniqueId=$proof.shadow.diskUniqueId;$sd.Guid=$sg;$sd.Size=64GB
$spt=Clone $part;$spt.DiskNumber=3;$spt.Guid=$sp;$spt.Size=52GB;$spt.DriveLetter='S'
$svol=Clone $jvol;$svol.UniqueId=$proof.shadow.volumeGuid;$svol.FileSystem='ReFS';$svol.FileSystemLabel='n2r-retained-shadow'
Assert-AttachmentShadow $sd $spt $proof Prepared;Assert-AttachmentVolume $spt $svol $proof;$script:checks+=2
foreach($field in $sd.PSObject.Properties.Name){$b=Clone $sd;$b.$field=if($field -clike 'Is*'){$true}else{'wrong'};Reject {Assert-AttachmentShadow $b $spt $proof Prepared} ('Changed shadow disk accepted: '+$field)}
$excluded=Clone $sd;$excluded.IsOffline=$true;$excluded.IsReadOnly=$true;Assert-AttachmentShadow $excluded $spt $proof Excluded;$script:checks++
foreach($state in @(@($false,$false),@($true,$false),@($false,$true))){$b=Clone $excluded;$b.IsOffline=$state[0];$b.IsReadOnly=$state[1];Reject {Assert-AttachmentShadow $b $spt $proof Excluded} 'Incomplete exclusion accepted.'}
Reject {Assert-AttachmentShadow $sd $spt $proof ignored} 'Unknown mode accepted.'
foreach($field in @('UniqueId','FileSystem','FileSystemLabel','AllocationUnitSize')){$b=Clone $svol;$b.$field='wrong';Reject {Assert-AttachmentVolume $spt $b $proof} 'Wrong mounted shadow accepted.'}
$msr=[pscustomobject]@{DiskNumber=3;PartitionNumber=1;GptType='{e3c9e316-0b5c-4db8-817d-f92df00215ae}';Offset=17408;Size=(16MB-17408);IsBoot=$false;IsSystem=$false}
$matched=Assert-AttachmentLayout @($msr,$spt) $sd $proof.shadow;Check ($matched.Guid -ceq $sp) 'Layout did not select exact partition.'
foreach($offset in @(0,16896,17409)){$b=Clone $msr;$b.Offset=$offset;Reject {Assert-AttachmentLayout @($b,$spt) $sd $proof.shadow} 'Unqualified reserved partition offset accepted.'}
Reject {Assert-AttachmentLayout @($spt) $sd $proof.shadow} 'Missing MSR accepted.';Reject {Assert-AttachmentLayout @($msr,$spt,$spt) $sd $proof.shadow} 'Extra partition accepted.'
foreach($field in $msr.PSObject.Properties.Name){$b=Clone $msr;$b.$field=if($field -clike 'Is*'){$true}else{'wrong'};Reject {Assert-AttachmentLayout @($b,$spt) $sd $proof.shadow} 'Changed MSR layout accepted.'}
$commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
foreach($forbidden in @('Format-Volume','Initialize-Disk','New-Partition','Set-Disk','Set-Partition','Dismount-DiskImage','Mount-DiskImage','Remove-Item','Start-VM','Stop-VM','Restore-VMSnapshot')){Check ($forbidden -cnotin $commands) ('Unexpected mutation command: '+$forbidden)}
$text=Get-Content -LiteralPath $path -Raw;Check ($text -notmatch '\$native\.Create\(') 'VHD creation appeared in reattachment.';Check ($text -match '\$native\.OpenOwned\(\)') 'Owned existing VHD open missing.'
# Reuse the tested native API through a fresh fake: attach existing must never Create.
$fake=@'
namespace Ntfs2Refs {
 public sealed class AttachmentFake:IShadowDiskApi {
  public System.Guid Id;public int Creates,Opens,Attaches,Closes;
  public AttachmentFake(System.Guid id){Id=id;}
  public uint Create(string p,System.Guid id,out System.IntPtr h){Creates++;h=System.IntPtr.Zero;throw new System.Exception("Creation forbidden");}
  public uint Open(string p,out System.IntPtr h){Opens++;h=new System.IntPtr(123);return 0;}
  public uint Attach(System.IntPtr h){Attaches++;return 0;}
  public uint Close(System.IntPtr h){Closes++;return 0;}
  public uint PhysicalPath(System.IntPtr h,out string path){path=@"\\.\PhysicalDrive3";return 0;}
  public uint Query(System.IntPtr h,uint v,out byte[] b){b=new byte[32];System.Array.Copy(System.BitConverter.GetBytes(v),b,4);if(v==1){System.Array.Copy(System.BitConverter.GetBytes(64UL*1024*1024*1024),0,b,8,8);System.Array.Copy(System.BitConverter.GetBytes(4194304UL),0,b,16,8);System.Array.Copy(System.BitConverter.GetBytes(2097152U),0,b,24,4);System.Array.Copy(System.BitConverter.GetBytes(512U),0,b,28,4);}else if(v==2||v==14)System.Array.Copy(Id.ToByteArray(),0,b,8,16);else System.Array.Copy(System.BitConverter.GetBytes(v==7?3U:4096U),0,b,8,4);return 0;}
 }
}
'@
Add-Type -TypeDefinition ((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest\NativeShadowDisk.cs') -Raw)+[Environment]::NewLine+$fake)
$api=New-Object Ntfs2Refs.AttachmentFake([guid]$id);$n=New-Object Ntfs2Refs.NativeShadowDisk($proof.backingPath,([guid]$id),$api);$n.OpenOwned()|Out-Null;$n.Attach()|Out-Null;$n.Close()
Check ($api.Creates -eq 0 -and $api.Opens -eq 1 -and $api.Attaches -eq 1 -and $api.Closes -eq 1 -and $n.HandleCloseSucceeded) 'Existing-only attach lifecycle differs.'
$wrongApi=New-Object Ntfs2Refs.AttachmentFake([guid]::NewGuid());$n=New-Object Ntfs2Refs.NativeShadowDisk($proof.backingPath,([guid]$id),$wrongApi);Reject {$n.OpenOwned()} 'Wrong VHD identifier accepted.';Check ($wrongApi.Attaches -eq 0 -and $wrongApi.Creates -eq 0) 'Unqualified existing VHD attached.';$n.Close()
Assert-AttachmentProtectionPins Prepared '' '';Assert-AttachmentProtectionPins Excluded $hash ('c'*64);$script:checks+=2
Check (Test-AttachmentCloseAllowed $false $false $false $true $false) 'Known completed operations must permit single cleanup.'
foreach($flags in @(@($true,$false,$false,$true,$false),@($false,$true,$false,$true,$false),@($false,$false,$true,$true,$false),@($false,$false,$false,$false,$false),@($false,$false,$false,$true,$true))){Check (-not(Test-AttachmentCloseAllowed @flags)) 'Unknown native/privilege activity or failed protection cleanup allowed VHD close.'}
foreach($values in @(@('Excluded','',''),@('Excluded',$hash,''),@('Excluded','wrong',$hash),@('Prepared',$hash,''))){Reject {Assert-AttachmentProtectionPins $values[0] $values[1] $values[2]} 'Unpinned/wrong profile accepted.'}
$td=Clone $sd;$td.Number=1;$td.UniqueId=$ids[1];$td.Guid=[guid]::NewGuid().ToString('D');$td.IsOffline=$true;$tp=Clone $spt;$tp.DiskNumber=1;$tp.Guid=[guid]::NewGuid().ToString('D');$tm=Clone $msr;$tm.DiskNumber=1
$before=Assert-AttachmentTarget $td @($tm,$tp);$after=Assert-AttachmentTarget $td @($tm,$tp) $before;Check ($after.diskGuid-ceq$td.Guid-and$after.partitionGuid-ceq$tp.Guid) 'Original target binding lost.'
foreach($field in $td.PSObject.Properties.Name){$b=Clone $td;$b.$field=if($b.$field-is[bool]){-not$b.$field}else{'wrong'};Reject {Assert-AttachmentTarget $b @($tm,$tp) $before} ('Changed original target accepted: '+$field)}
$b=Clone $tp;$b.Guid=[guid]::NewGuid().ToString();Reject {Assert-AttachmentTarget $td @($tm,$b) $before} 'Changed original target partition accepted.'
$b=Clone $td;$b.IsOffline='true';Reject {Assert-AttachmentTarget $b @($tm,$tp)} 'Nonboolean target state accepted.'
# Frozen successful diagnostic, plus semantic corruptions of its exact native proof.
$diagnosticRoot=Join-Path (Split-Path $PSScriptRoot -Parent) '.lab\hyperv\shadow-readonly-attachment\win11-20261024T041957683Z-df922bc4b13e46339c8c938a4f5a7742'
$diagnosticPath=@(Get-ChildItem -LiteralPath $diagnosticRoot -Filter attachment.json -File -Recurse);Check ($diagnosticPath.Count-eq1) 'One archived attachment proof required.'
Check ((Get-FileHash $diagnosticPath[0].FullName).Hash.ToLowerInvariant()-ceq'28d41711e761553a39938479f82b265470ca988d63b4a077d6ba0aee848913c0') 'Diagnostic pin differs.'
$diagnostic=Get-Content $diagnosticPath[0].FullName -Raw|ConvertFrom-Json;$pp=[pscustomobject]@{shadow=$diagnostic.expectedShadow};$protected=$diagnostic.physical;Assert-AttachmentProtection $protected $pp;$script:checks++
foreach($field in @('status','phase','diskGuid','partitionGuid','attributesBefore','attributesAfter')){$b=Clone $protected;$b.$field='wrong';Reject {Assert-AttachmentProtection $b $pp} ('Changed protection identity accepted: '+$field)}
foreach($field in @('requestedEstablishExclusion','providerReadOnlyBefore','providerReadOnlyAfter','exclusionObserved','operationCompletionKnown','cleanupComplete','attributeOpenAttempted','attributeOpenReturned','attributeSetAttempted','attributeSetReturned','attributeSetSucceeded')){foreach($value in @($false,'true',1)){$b=Clone $protected;$b.$field=$value;Reject {Assert-AttachmentProtection $b $pp} ('Unqualified protection accepted: '+$field)}}
foreach($field in @('rawPayloadWriteRequestsIssued','conversionQualified','persistenceQualified')){$b=Clone $protected;$b.$field=$true;Reject {Assert-AttachmentProtection $b $pp} 'Unsupported native claim accepted.'}
foreach($name in @('providerWritableBefore','providerWritableAfter','providerWritablePreSet','SetOfflineReadOnly')){foreach($field in @('code','error','capacity','returned','succeeded')){$b=Clone $protected;$c=$b.calls|Where-Object name -CEQ $name;$c.$field=if($field-ceq'succeeded'){-not$c.$field}else{123};Reject {Assert-AttachmentProtection $b $pp} 'Changed provider/control record accepted.'};$b=Clone $protected;($b.calls|Where-Object name -CEQ $name).succeeded='false';Reject {Assert-AttachmentProtection $b $pp} 'Nonboolean native result accepted.'}
$b=Clone $protected;($b.calls|Where-Object name -CEQ 'SetOfflineReadOnly').inputHex='00';Reject {Assert-AttachmentProtection $b $pp} 'Changed exclusion input accepted.'
$b=Clone $protected;$b.attributeSetSucceeded=$false;($b.calls|Where-Object name -CEQ 'SetOfflineReadOnly').error=19;Reject {Assert-AttachmentProtection $b $pp} 'Refused SET promoted by later attributes3.'
$b=Clone $protected;$names=@($b.calls.name);$first=[array]::IndexOf($names,'providerWritableBefore');$set=[array]::IndexOf($names,'SetOfflineReadOnly');$tmp=$b.calls[$first];$b.calls[$first]=$b.calls[$set];$b.calls[$set]=$tmp;Reject {Assert-AttachmentProtection $b $pp} 'Protection-after-SET order accepted.'
foreach($mode in @('Prepared','Excluded')){$dry=& $path -RunId $run -ObservationId ('c'*32) -PreparationEvidenceSha256 $hash -NativeSourceSha256 $hash -Mode $mode -WhatIf;Check ($dry.Status -ceq 'what-if' -and -not $dry.SourceTargetWrites -and -not $dry.ConversionQualified) 'WhatIf entered attachment.'}
Reject {& $path -RunId ($run+[char]10) -ObservationId ('c'*32) -PreparationEvidenceSha256 $hash -NativeSourceSha256 $hash -Mode Prepared -WhatIf} 'Newline run identifier accepted.'
Reject {& $path -RunId $run -ObservationId ('c'*32) -PreparationEvidenceSha256 ($hash+[char]10) -NativeSourceSha256 $hash -Mode Excluded -WhatIf} 'Newline proof hash accepted.'
[pscustomobject]@{Checks=$script:checks;Passed=$true;VhdOperations=$false;VMOperations=$false}
