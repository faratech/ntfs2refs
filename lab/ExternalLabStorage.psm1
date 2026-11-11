# Account for explicitly relocated project test storage without rebasing the
# existing D: lab epoch or treating C: capacity as free space on D:.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-ExternalLabStorageCharge {
 [CmdletBinding()]
 param([Parameter(Mandatory)][string]$WorkspaceRoot)
 $workspace=[IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\')
 $path=Join-Path $workspace '.lab\development\external-retirement-archive-enrollment.json'
 if(-not(Test-Path -LiteralPath $path)){
  return [ordered]@{actual_bytes=0L;reserved_maximum_bytes=0L;root=$null;epoch_reset=$false}
 }
 $entry=Get-Item -LiteralPath $path -Force
 if($entry-isnot[IO.FileInfo]-or$entry.Length-gt1MB-or($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary bounded external-storage enrollment required'}
 $value=Get-Content -LiteralPath $path -Encoding UTF8 -Raw|ConvertFrom-Json
 if($value.schema_version-ne1-or$value.kind-cne'live-relocated-old-lab-storage'-or$value.maximum_bytes-ne17179869184L-or$value.epoch_reset-ne$false-or$value.source_authority-ne$false-or$value.created_actual_bool-ne$true){throw 'External project-storage policy differs'}
 $root=[IO.Path]::GetFullPath([string]$value.root).TrimEnd('\')
 if($root-cne[string]$value.root-or$root-cnotmatch'\AC:\\Users\\mfara\\ntfs2refs-archive\\relocated-lab-storage-[0-9a-f]{32}\z'){throw 'External storage is outside the explicit project archive root'}
 $item=Get-Item -LiteralPath $root -Force
 for($parent=$item;$null-ne$parent;$parent=$parent.Parent){
  if($parent-isnot[IO.DirectoryInfo]-or($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'External storage ancestry must remain ordinary directories'}
 }
 $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($root)
 $sum=0L;$count=0
 while($queue.Count){
  foreach($child in Get-ChildItem -LiteralPath $queue.Dequeue() -Force -ErrorAction Stop){
   $count++;if($count-gt50000-or($child.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'External storage inventory is unbounded or follows a reparse point'}
   if($child-is[IO.DirectoryInfo]){$queue.Enqueue($child.FullName)}else{
    if($child-isnot[IO.FileInfo]-or$child.Length-lt0-or$sum-gt[long]::MaxValue-$child.Length){throw 'External storage byte accounting overflow'}
    $sum += [long]$child.Length
   }
  }
 }
 $free=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).AvailableFreeSpace
 if($sum-gt$value.maximum_bytes-or$free-lt17179869184L){throw 'External storage exceeds its reserved share or C: free-space reserve'}
 return [ordered]@{actual_bytes=$sum;reserved_maximum_bytes=[long]$value.maximum_bytes;root=$root;host_free_bytes=$free;minimum_free_bytes=17179869184L;epoch_reset=$false;source_authority=$false}
}
Export-ModuleMember -Function Get-ExternalLabStorageCharge
