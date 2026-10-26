<# Pure baseline profile/proof tests. No native disk or VM operation is called. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'guest/NativeImportedReference.cs')
$checks=0
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$no=$false;try{&$Action|Out-Null}catch{$no=$true};Check $no $Message}
function Put32([byte[]]$B,[int]$At,[uint32]$Value){[BitConverter]::GetBytes($Value).CopyTo($B,$At)}
function Put64([byte[]]$B,[int]$At,[long]$Value){[BitConverter]::GetBytes($Value).CopyTo($B,$At)}
function PutGuid([byte[]]$B,[int]$At,[guid]$Value){$Value.ToByteArray().CopyTo($B,$At)}
$baseline=@([Ntfs2RefsResearch.NativeImportedReference]::ExpectedFiles($true));$writer=@([Ntfs2RefsResearch.NativeImportedReference]::ExpectedFiles($false))
Check ($baseline.Count-eq2-and@($baseline|Where-Object adopted).Count-eq0) 'Baseline unexpectedly contains adopted-file expectations.'
Check (($baseline.path-join'|')-ceq'fixtures\nonresident.bin|fixtures\small.txt') 'Original fixture namespace changed.'
Check ($writer.Count-eq3-and@($writer|Where-Object adopted).Count-eq1-and$writer[2].path-ceq'adopted-existing.bin') 'Legacy writer expectations changed.'
$path='J:\ntfs2refs-reference\0123456789abcdef0123456789abcdef\reference.vhdx';$root='\\?\Volume{00112233-4455-6677-8899-aabbccddeeff}\';$id='0123456789abcdef0123456789abcdef';$fresh=[guid]'6b19c23a-296f-459d-8c77-7e28a0e15da4'
[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineArguments($path,$root,4,$id,$fresh);Check $true 'Fresh baseline identity refused.'
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineArguments($path,$root,4,$id,[guid]::Empty)} 'Empty baseline identity accepted.'
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineArguments($path,$root,4,$id,[guid]'a0c231ef-a959-4a6e-8ae2-7d80363eebe6')} 'Rejected writer candidate reused as baseline.'
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineArguments($path,$root,1,$id,$fresh)} 'Primary source route accepted.'
[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineAbsence($false,2);Check $true 'Exact FILE_NOT_FOUND refused.'
foreach($error in @(0,3,5,21,1167)){Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineAbsence($false,$error)} 'Failure mistaken for absent adopted name.'}
Reject {[Ntfs2RefsResearch.NativeImportedReference]::ValidateBaselineAbsence($true,0)} 'Present adopted name accepted by baseline.'
Check ([Ntfs2RefsResearch.NativeImportedReference]::InlineSmallMapping('fixtures\small.txt',61,64,$false,38)) 'Pinned inline allocation was mistaken for a physical extent.'
Check ([Ntfs2RefsResearch.NativeImportedReference]::InlineSmallMapping('fixtures\small.txt',61,0,$false,38)) 'Legacy inline reporting form refused.'
foreach($allocation in @(1,60,80,4096)){Check (-not[Ntfs2RefsResearch.NativeImportedReference]::InlineSmallMapping('fixtures\small.txt',61,$allocation,$false,38)) 'Unmeasured inline allocation accepted.'}
Check (-not[Ntfs2RefsResearch.NativeImportedReference]::InlineSmallMapping('adopted-existing.bin',61,64,$true,38)) 'Adopted payload treated as inline data.'
Check (-not[Ntfs2RefsResearch.NativeImportedReference]::InlineSmallMapping('fixtures\small.txt',61,64,$false,5)) 'Read error treated as resident mapping.'
$layout=New-Object byte[] 336
Put32 $layout 0 1;Put32 $layout 4 2;PutGuid $layout 8 'b4ab4dbc-6bd7-4199-8e4a-01b828e98584';Put64 $layout 24 17408;Put64 $layout 32 (64GB-34304)
Put32 $layout 48 1;Put64 $layout 56 17408;Put64 $layout 64 (16MB-17408);Put32 $layout 72 1;PutGuid $layout 80 'e3c9e316-0b5c-4db8-817d-f92df00215ae';PutGuid $layout 96 '11111111-2222-3333-4444-555555555555'
Put32 $layout 192 1;Put64 $layout 200 16MB;Put64 $layout 208 52GB;Put32 $layout 216 2;PutGuid $layout 224 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';PutGuid $layout 240 '00c9f113-e0b9-49d8-b031-130aef8ef3fb'
function State([long]$Attrs){
 $device=New-Object byte[] 12;Put32 $device 0 7;Put32 $device 4 4
 $length=[BitConverter]::GetBytes([long]64GB);$alignment=New-Object byte[] 28;Put32 $alignment 0 28;Put32 $alignment 4 28;Put32 $alignment 16 512;Put32 $alignment 20 4096
 [pscustomobject]@{disk_attributes=$Attrs;device=$device;length=$length;alignment=$alignment;layout=$layout;vhd=[pscustomobject]@{persistent_vhd_id=$fresh.ToString('D');physical_path='\\.\PhysicalDrive4';backing_bytes=512MB}}
}
$data=[pscustomobject]@{
 request=[pscustomobject]@{schema_version=1;binding=[pscustomobject]@{experiment_id=$id;vhd_path=$path;persistent_vhd_id=$fresh.ToString('D');disk_number=4};packet_sha256='585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b'}
 import=[pscustomobject]@{blank_bytes_checked=64GB;reference_bytes_written=68157440;disk_sha256='ea08681ba795322529e395febea156af8ec97687ed2bf192b6e6d0bc17f5af07';payload_sha256='6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786'}
 prepared=[pscustomobject]@{profile='baseline_only';baseline_only=$true;adopted_file_expected=$false;patches=@();import_disk_sha256='ea08681ba795322529e395febea156af8ec97687ed2bf192b6e6d0bc17f5af07';payload_sha256='6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786';native_mount_qualified=$false;binding=$null;state=(State 3)}
 handoff=(State 0)
 result=[pscustomobject]@{kind='restricted-reference-import';success=$true;baseline_only=$true;overlay_inputs_consumed=$false;adopted_file_expected=$false;writer_metadata_pages=0;writer_metadata_bytes=0;writer_payload_writes=0;reference_bytes_written=68157440;imported_disk_sha256='ea08681ba795322529e395febea156af8ec97687ed2bf192b6e6d0bc17f5af07';payload_sha256='6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786';handoff_performed=$true;native_writer_qualified=$false;ntfs_conversion_qualified=$false}
}
$data.prepared.binding=$data.request.binding
$parseErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest/Test-ImportedBaseline.ps1'),[ref]$null,[ref]$parseErrors);Check ($parseErrors.Count-eq0) 'Baseline guest syntax failed.'
$function=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Assert-BaselineProofs'},$true);. ([scriptblock]::Create($function.Extent.Text))
$binding=Assert-BaselineProofs $data.request $data.import $data.prepared $data.handoff $data.result $path 4
Check ([guid]$binding.persistent_vhd_id-eq$fresh) 'Exact baseline proof refused.'
foreach($case in 0..15){
 $bad=$data|ConvertTo-Json -Depth 16|ConvertFrom-Json
 switch($case){
 0{$bad.prepared.baseline_only=$false} 1{$bad.prepared.profile='writer_overlay'} 2{$bad.prepared.patches=@([pscustomobject]@{length=16384})}
 3{$bad.result.adopted_file_expected=$true} 4{$bad.result.writer_metadata_pages=8} 5{$bad.result.overlay_inputs_consumed=$true}
 6{$bad.result.handoff_performed=$false} 7{$bad.import.disk_sha256='0'*64} 8{$bad.import.payload_sha256='0'*64}
 9{$bad.import.blank_bytes_checked=64GB-4096} 10{$bad.handoff.disk_attributes=3} 11{$bad.handoff.device[4]=1}
 12{$bad.handoff.vhd.persistent_vhd_id=[guid]::NewGuid().ToString('D')} 13{$bad.request.binding.disk_number=1}
 14{$bad.prepared.binding.vhd_path=$path.Replace('reference.vhdx','writer.vhdx')} 15{$bad.prepared.native_mount_qualified=$true}
 }
 Reject {Assert-BaselineProofs $bad.request $bad.import $bad.prepared $bad.handoff $bad.result $path 4} ('Foreign/writer/incomplete baseline proof accepted: '+$case)
}
$dispatchErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../scripts/Dispatch-LabImportedBaselineVerification.ps1'),[ref]$null,[ref]$dispatchErrors);Check ($dispatchErrors.Count-eq0) 'Baseline dispatcher syntax failed.'
[pscustomobject]@{checks=$checks;passed=$true;nativeDiskOperations=0;vmOperations=0}
