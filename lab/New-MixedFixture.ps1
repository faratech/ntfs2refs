# Replace the lab VM's current source F: with an independently generated mixed
# NTFS fixture: same partition, NTFS 64 KiB clusters, label and disabled short
# names as the original fixture, but ~800 seeded-random files in ~120 nested
# directories (resident, empty, small, large, Unicode names) written in waves
# with deletions so NTFS allocation is fragmented. Root restores/boots the NTFS
# checkpoint first. Ordinary formatting and file I/O inside the guest only; the
# checkpoints are untouched. Writes an independent hash manifest on the host.
[CmdletBinding()]param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [int]$Seed=20261029
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('mixed-fixture-20261029-'+$run)
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
$v=Get-VM -Id $id;Need ($v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and@(Get-VMNetworkAdapter -VM $v).Count-eq0) 'Lab VM must be running on the expected parent.'
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
New-Item -ItemType Directory -Path $root|Out-Null
$result=Invoke-Command -VMId $id -Credential $cred -ArgumentList $Seed -ScriptBlock {param($Seed)
 $ErrorActionPreference='Stop'
 if(@(Get-CimInstance Win32_Process|Where-Object Name -Match '^(ntfs2refs(?:-.+)?|lab-.+)\.exe$').Count){throw 'project worker active'}
 $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
 if([guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$d.IsOffline-or$d.IsReadOnly-or$p.DiskNumber-ne1-or$p.PartitionNumber-ne2-or$p.Size-ne52GB-or$v.FileSystem-cne'NTFS'){throw 'Exact NTFS source1 F: required.'}
 Format-Volume -Partition $p -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel 'n2r-stream-source' -Confirm:$false -Force|Out-Null
 $null=(fsutil.exe 8dot3name set F: 1 2>&1);if($LASTEXITCODE -ne 0){throw '8dot3 disable failed'}
 $rng=[Random]::new($Seed)
 # Directory tree: nested up to depth 5, some Unicode names.
 $names=@('alpha','beta','gamma','delta','données','資料','Ünïcode','projects','archive','media','logs','temp-keep','reports','src','näme with spaces')
 $dirs=[Collections.Generic.List[string]]::new();$dirs.Add('F:\')
 for($i=0;$i-lt120;$i++){$parent=$dirs[$rng.Next($dirs.Count)];$depth=($parent.TrimEnd('\') -split '\\').Count-1;if($depth-ge5){$parent='F:\'};$path=Join-Path $parent ('{0}-{1:D3}'-f $names[$rng.Next($names.Count)],$i);New-Item -ItemType Directory -Path $path|Out-Null;$dirs.Add($path)}
 function Size([Random]$r){$x=$r.NextDouble();if($x-lt0.02){0}elseif($x-lt0.17){$r.Next(1,700)}elseif($x-lt0.57){$r.Next(700,61440)}elseif($x-lt0.87){$r.Next(65536,2MB)}elseif($x-lt0.985){$r.Next(4MB,64MB)}else{$r.Next(200MB,600MB)}}
 function Write-File([string]$Path,[long]$Length,[Random]$R){$fs=[IO.File]::Open($Path,'CreateNew','Write','None');try{$buf=[byte[]]::new(1MB);$left=$Length;while($left-gt0){$n=[int][Math]::Min($left,$buf.Length);$R.NextBytes($buf);$fs.Write($buf,0,$n);$left-=$n};$fs.Flush($true)}finally{$fs.Dispose()}}
 $wave1=[Collections.Generic.List[string]]::new()
 for($i=0;$i-lt520;$i++){$dir=$dirs[$rng.Next($dirs.Count)];$p=Join-Path $dir ('file-{0:D4}.bin'-f $i);Write-File $p (Size $rng) $rng;$wave1.Add($p)}
 # Delete about 30% of wave 1 to leave holes in the NTFS allocation.
 $deleted=0;foreach($p in @($wave1)){if($rng.NextDouble()-lt0.30){Remove-Item -LiteralPath $p;$deleted++}}
 # Wave 2 refills the holes; four large files grow round-robin to fragment them.
 for($i=0;$i-lt420;$i++){$dir=$dirs[$rng.Next($dirs.Count)];Write-File (Join-Path $dir ('wave2-{0:D4}.dat'-f $i)) (Size $rng) $rng}
 $interleaved=@(0..3|ForEach-Object {[IO.File]::Open((Join-Path $dirs[$rng.Next($dirs.Count)] ('interleaved-{0}.bin'-f $_)),'CreateNew','Write','None')})
 try{$buf=[byte[]]::new(1MB);for($round=0;$round-lt96;$round++){foreach($fs in $interleaved){$rng.NextBytes($buf);$fs.Write($buf,0,$buf.Length);$fs.Flush($true)}}}finally{$interleaved|ForEach-Object {$_.Dispose()}}
 Write-VolumeCache -DriveLetter F
 # Skip System Volume Information before recursing: enumerating it is denied.
 $top=@(Get-ChildItem -LiteralPath 'F:\' -Force|Where-Object {$_.Name -cne 'System Volume Information'})
 $topDirs=@($top|Where-Object {$_.PSIsContainer})
 $files=@($top|Where-Object {-not $_.PSIsContainer})+@($topDirs|ForEach-Object {Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force})
 $dirCount=$topDirs.Count+@($topDirs|ForEach-Object {Get-ChildItem -LiteralPath $_.FullName -Recurse -Directory -Force}).Count
 $manifest=foreach($f in $files){[pscustomobject]@{path=$f.FullName;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant()}}
 $frag=0;foreach($f in $files|Where-Object Length -gt 1MB|Select-Object -First 200){$ext=@(fsutil.exe file queryextents $f.FullName 2>$null).Count;if($ext-gt1){$frag++}}
 $vol=Get-Volume -DriveLetter F
 @{files=$files.Count;directories=$dirCount;wave1=520;deleted_from_wave1=$deleted;wave2=420;interleaved=4;total_bytes=($files|Measure-Object Length -Sum).Sum;fragmented_files_among_first_200_over_1MiB=$frag;filesystem=$vol.FileSystem;cluster=$vol.AllocationUnitSize;label=$vol.FileSystemLabel;manifest=$manifest}
}
$json=$result|ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $root 'fixture.json'),$json,[Text.UTF8Encoding]::new($false))
$result|Select-Object files,directories,deleted_from_wave1,total_bytes,fragmented_files_among_first_200_over_1MiB,filesystem,cluster,label|ConvertTo-Json -Compress
"fixture manifest: $(Join-Path $root 'fixture.json')"
