<# Build an ordinary source tree BEFORE converter invocation. No extent queries,
   moves, source-space shaping or native ReFS shadow are used here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PlatformSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root='C:\ntfs2refs\existing-tree\'+$RunId
$platformPath='C:\ntfs2refs\retained-source\'+$RunId+'\prepare.json'
if((Get-FileHash -LiteralPath $platformPath).Hash.ToLowerInvariant()-cne$PlatformSha256){throw 'Source platform pin differs.'}
$p=Get-Content -LiteralPath $platformPath -Raw|ConvertFrom-Json
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$computer.Model-cne'Virtual Machine'-or$p.status-cne'ntfs-source-prepared'-or-not$p.operationCompletionKnown){throw 'Expected owned prepared source.'}
function Assert-Source {
 $d=Get-Disk -Number 1;$part=Get-Partition -DriveLetter F;$v=Get-Volume -DriveLetter F
 if($d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or$d.IsOffline-or$d.IsReadOnly-or[guid]$d.Guid-ne[guid]$p.partition.diskGuid-or$part.DiskNumber-ne1-or$part.PartitionNumber-ne2-or$part.Offset-ne16MB-or$part.Size-ne52GB-or[guid]$part.Guid-ne[guid]$p.partition.guid-or$v.FileSystem-cne'NTFS'-or$v.FileSystemLabel-cne'n2r-retained-source'-or$v.AllocationUnitSize-ne4096){throw 'Exact writable source platform changed.'}
}
function Save-New([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20));if($b.Length-gt1MB){throw 'Bounded artifact required.'};$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Assert-Source
foreach($a in @('C:\','C:\ntfs2refs','C:\ntfs2refs\existing-tree',$root)){ $i=Get-Item -LiteralPath $a -Force;if(-not$i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary artifact ancestry required.'} }
foreach($name in @('source0.bin','archive','notes')){if(Test-Path -LiteralPath ('F:\'+$name)){throw 'Source tree path already exists.'}}
Save-New 'population.intent.json' ([ordered]@{schemaVersion=1;kind='existing-tree-population-intent';runId=$RunId;platformSha256=$PlatformSha256;extentPlacementOperations=0;conversionInvoked=$false})
$sections=[Security.AccessControl.AccessControlSections]::Owner-bor[Security.AccessControl.AccessControlSections]::Group-bor[Security.AccessControl.AccessControlSections]::Access
foreach($name in @('archive','archive\nested','notes')){
 $path='F:\'+$name;[void][IO.Directory]::CreateDirectory($path)
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',$sections)
 [IO.Directory]::SetAccessControl($path,$acl)
}
$items=@(@('source0.bin',65536),@('archive\doc1.bin',131072),@('archive\nested\doc2.bin',65536),@('notes\doc3.bin',262144))
$files=@();$random=[Security.Cryptography.RandomNumberGenerator]::Create()
try{foreach($item in $items){
 Assert-Source
 $path='F:\'+$item[0];$remaining=[long]$item[1];$buffer=[byte[]]::new(65536)
 $f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{while($remaining-gt0){$random.GetBytes($buffer);$count=[int][Math]::Min($remaining,$buffer.Length);$f.Write($buffer,0,$count);$remaining-=$count};$f.Flush($true)}finally{$f.Dispose()}
 $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',$sections)
 [IO.File]::SetAccessControl($path,$acl)
 $i=Get-Item -LiteralPath $path -Force
 $files+=@([ordered]@{relativePath=[string]$item[0];length=$i.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();sddl=([IO.File]::GetAccessControl($path)).GetSecurityDescriptorSddlForm($sections)})
}}finally{$random.Dispose()}
Assert-Source
$volume=[guid](($p.volume.guid-replace '^\\\\\?\\Volume\{','')-replace '\}\\$','')
$request=[ordered]@{schema_version=1;experiment_id=$RunId;source=[ordered]@{disk_number=1;volume_guid=$volume.ToString();identity=[ordered]@{disk_guid=[string]$p.partition.diskGuid;partition_guid=[string]$p.partition.guid;partition_number=2;disk_bytes=64GB;partition_offset=16MB;partition_bytes=52GB;logical_sector_bytes=512;physical_sector_bytes=4096}}}
Save-New 'freeze-request.json' $request
Save-New 'population.json' ([ordered]@{schemaVersion=1;kind='existing-ntfs-tree';runId=$RunId;status='populated-before-converter';platformSha256=$PlatformSha256;directories=@('archive','archive\nested','notes');files=$files;logicalBytes=524288;extentPlacementOperations=0;sourceFileDataCopiedToShadow=$false;conversionInvoked=$false;createdUtc=[DateTime]::UtcNow.ToString('o')})
[pscustomobject]@{status='populated-before-converter';runId=$RunId;files=$files.Count;logicalBytes=524288;requestSha256=(Get-FileHash -LiteralPath (Join-Path $root 'freeze-request.json')).Hash.ToLowerInvariant()}
