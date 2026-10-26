# Pure argument/layout/extent tests; no native disk functions are called.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'guest\NativeImportedReference.cs')
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$rejected=$false;try{&$Action|Out-Null}catch{$rejected=$true};Check $rejected $Message}
function Put32([byte[]]$B,[int]$At,[uint32]$Value){[BitConverter]::GetBytes($Value).CopyTo($B,$At)}
function Put64([byte[]]$B,[int]$At,[long]$Value){[BitConverter]::GetBytes($Value).CopyTo($B,$At)}
function PutGuid([byte[]]$B,[int]$At,[guid]$Value){$Value.ToByteArray().CopyTo($B,$At)}
Check ([Ntfs2RefsResearch.NativeImportedReference]::AdoptedName-ceq'adopted-existing.bin') 'Strict-writer filename differs from its USHORT array.'
$path='J:\ntfs2refs-reference\0123456789abcdef0123456789abcdef\reference.vhdx'
$root='\\?\Volume{00112233-4455-6677-8899-aabbccddeeff}\'
$id='0123456789abcdef0123456789abcdef'
[Ntfs2RefsResearch.NativeImportedReference]::ValidateArguments($path,$root,3,$id)
foreach($number in @(0,1,2,64)){Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateArguments($path,$root,$number,$id)} 'Protected/oversized disk route accepted.'}
foreach($bad in @('F:\','\\server\share\','\\.\PhysicalDrive3',($root+'adopted.bin'),($root+[char]10),'\\?\Volume{00000000-0000-0000-0000-000000000000}\')){Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateArguments($path,$bad,3,$id)} 'Noncanonical or empty volume identity accepted.'}
foreach($bad in @('C:\reference.vhdx',$path.Replace('reference.vhdx','shadow.vhdx'),($path+[char]10),$path.Replace($id,'..'))){Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateArguments($bad,$root,3,$id)} 'Foreign or traversal backing accepted.'}
$layout=New-Object byte[] 336
Put32 $layout 0 1;Put32 $layout 4 2;PutGuid $layout 8 'b4ab4dbc-6bd7-4199-8e4a-01b828e98584';Put64 $layout 24 17408;Put64 $layout 32 (64GB-34304)
Put32 $layout 48 1;Put64 $layout 56 17408;Put64 $layout 64 (16MB-17408);Put32 $layout 72 1;PutGuid $layout 80 'e3c9e316-0b5c-4db8-817d-f92df00215ae';PutGuid $layout 96 '11111111-2222-3333-4444-555555555555'
Put32 $layout 192 1;Put64 $layout 200 16MB;Put64 $layout 208 52GB;Put32 $layout 216 2;PutGuid $layout 224 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';PutGuid $layout 240 '00c9f113-e0b9-49d8-b031-130aef8ef3fb'
[Ntfs2RefsResearch.NativeImportedReference]::ValidateLayout($layout)
Check $true 'Native GPT fixture refused.'
foreach($at in @(0,4,8,200,208,216,240,256)){$bad=[byte[]]$layout.Clone();$bad[$at]=$bad[$at]-bxor1;Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateLayout($bad)} 'Changed GPT/profile accepted.'}
$bad=[byte[]]$layout.Clone();PutGuid $bad 80 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateLayout($bad)} 'Additional data partition accepted.'
$refs=New-Object byte[] 152
Put32 $refs 0 152;Put32 $refs 4 3;Put32 $refs 8 14;Put32 $refs 12 4096
[Convert]::ToUInt64('9808427608425382',16).ToString()|Out-Null
[BitConverter]::GetBytes([Convert]::ToUInt64('9808427608425382',16)).CopyTo($refs,16)
Put64 $refs 24 (52GB/512);Put64 $refs 32 (52GB/4096);Put32 $refs 56 512;Put32 $refs 60 4096;Put32 $refs 88 3;Put32 $refs 92 14
[Ntfs2RefsResearch.NativeImportedReference]::ValidateRefs($refs)
foreach($at in @(0,4,8,12,16,24,32,56,60,88,92)){$bad=[byte[]]$refs.Clone();$bad[$at]=$bad[$at]-bxor1;Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateRefs($bad)} 'Changed ReFS version/serial/geometry accepted.'}
$mapping=New-Object byte[] 32;Put32 $mapping 0 1;Put64 $mapping 16 1;Put64 $mapping 24 10243
$extent=[Ntfs2RefsResearch.NativeImportedReference]::ParseExtents($mapping,4096,$true)
Check ($extent.Count-eq1-and$extent[0].vcn-eq0-and$extent[0].nextVcn-eq1-and$extent[0].lcn-eq10243) 'Adopted exact physical mapping refused.'
foreach($at in @(0,8,16,24)){$bad=[byte[]]$mapping.Clone();$bad[$at]=$bad[$at]-bxor1;Reject {[Ntfs2RefsResearch.NativeImportedReference]::ParseExtents($bad,4096,$true)} 'Changed adopted mapping accepted.'}
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ParseExtents($mapping,8192,$true)} 'Incomplete adopted mapping accepted.'
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ParseExtents($mapping,4096,$false)} 'Ordinary allocation overlapping adopted data accepted.'
$baseline=[byte[]]$mapping.Clone();Put64 $baseline 16 1024;Put64 $baseline 24 1507328
Check ([Ntfs2RefsResearch.NativeImportedReference]::ParseExtents($baseline,4MB,$false).Count-eq1) 'Ordinary baseline mapping refused.'
Check ([Ntfs2RefsResearch.NativeImportedReference]::ParseExtents((New-Object byte[] 16),61,$false).Count-eq0) 'Resident small-file mapping refused.'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest\Test-ImportedReference.ps1'),[ref]$tokens,[ref]$errors)|Out-Null
Check ($errors.Count-eq0) 'Guest verifier syntax failed.'
[pscustomobject]@{checks=$script:checks;nativeDiskOperations=0;passed=$true}
