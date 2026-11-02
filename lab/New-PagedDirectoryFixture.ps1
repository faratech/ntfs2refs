# Root-invoked fixture only: add 450 directories, without payload preparation.
# This controller never starts/stops/restores/checkpoints the VM.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$golden=[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('paged-directory-fixture-'+$run);$stage='C:\ntfs2refs\paged-directory-fixture-'+$run
$session=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));Need ($b.Length-le1MB) 'Bounded fixture receipt required.';$f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Guard{
 $v=Get-VM -Id $vmId -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $v|ForEach-Object {$_.Id.ToString('D')});$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
 Need ($ExpectedParent-eq$golden-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.State.ToString()-ceq'Running'-and$v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$ids.Count-gt0-and$ids.Count-eq@($ids|Sort-Object -Unique).Count-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0-and$ExpectedParent.ToString('D')-in$ids) 'Exact idle running golden laboratory source/checkpoint inventory required.'
}
try{
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.'
 Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
 Guard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh fixture host stage required.';New-Item -ItemType Directory -Path $root|Out-Null
 $sourceSha=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
 Save 'intent.json' @{schema_version=1;kind='paged-directory-fixture-intent';run_id=$run;source_parent_checkpoint=$ExpectedParent;checkpoint_ids=$ExpectedCheckpointIds;controller_sha256=$sourceSha;created_directories_requested=450;file_payload_writes_authorized=$false;extent_moves_authorized=$false;vm_power_actions_authorized=$false;capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes}
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
 $receipt=Invoke-Command -Session $session -ArgumentList $stage,$run,$ExpectedParent.ToString('D'),$sourceSha -ScriptBlock {
  param($Stage,$Run,$Parent,$ControllerSha)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
  function SourceGuard{
   Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Elevated owning disposable guest required.'
   Need (@(Get-Disk).Count-eq6-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0-and@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0) 'No other project task or disk fixture may be active.'
   $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
   Need (-not$d.IsBoot-and-not$d.IsSystem-and-not$d.IsOffline-and-not$d.IsReadOnly-and[guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$p.DiskNumber-eq1-and$p.PartitionNumber-eq2-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Offset-eq16MB-and$p.Size-eq52GB-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source') 'Exact existing NTFS64K F: laboratory partition required.'
   return @{disk_number=1;disk_guid=$d.Guid;partition_number=2;partition_guid=$p.Guid;partition_offset=$p.Offset;partition_bytes=$p.Size;volume_unique_id=$v.UniqueId;filesystem=$v.FileSystem;cluster_bytes=$v.AllocationUnitSize;label=$v.FileSystemLabel}
  }
  $before=SourceGuard;Need (-not(Test-Path -LiteralPath $Stage)) 'Fresh ordinary C fixture stage required.'
  $a=Get-Item -LiteralPath 'C:\ntfs2refs';while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Fixture stage reparse ancestry refused.';$a=$a.Parent}
  New-Item -ItemType Directory -Path $Stage|Out-Null
  $fixture='F:\n2r-paged-450';Need (-not(Test-Path -LiteralPath $fixture)) 'Directory fixture already exists; no retry or replacement allowed.'
  $paths=[Collections.Generic.List[string]]::new();$success=$false;$failure=$null
  try{
   $null=[IO.Directory]::CreateDirectory($fixture);$paths.Add($fixture)
   for($i=0;$i-lt449;$i++){$path=Join-Path $fixture ('d{0:D4}'-f$i);Need (-not(Test-Path -LiteralPath $path)) 'Directory fixture collision.';$null=[IO.Directory]::CreateDirectory($path);$paths.Add($path)}
   $entries=@(Get-ChildItem -LiteralPath $fixture -Force);Need ($entries.Count-eq449-and@($entries|Where-Object {-not$_.PSIsContainer-or($_.Attributes-band[IO.FileAttributes]::ReparsePoint)}).Count-eq0) 'Exactly 449 ordinary child directories required.'
   foreach($path in $paths){$item=Get-Item -LiteralPath $path -Force;Need ($item.PSIsContainer-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Created fixture is not an ordinary directory.'}
   $after=SourceGuard;$success=$true
  }catch{$failure=$_.Exception.ToString();$after=$null}
  $value=@{schema_version=1;kind='ntfs-paged-directory-object-fixture';run_id=$Run;success=$success;source_parent_checkpoint=$Parent;controller_sha256=$ControllerSha;source_before=$before;source_after=$after;fixture_root=$fixture;created_directories=$paths.Count;created_payload_files=0;original_payload_writes=0;original_payload_bytes_read=0;extent_moves=0;created_paths=$paths.ToArray();failure=$failure;automatic_cleanup_retry_restore=$false;source_admitted=$false;conversion_authorized=$false;replay_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 32));Need ($bytes.Length-le1MB) 'Bounded closed fixture result required.'
  $file=[IO.File]::Open((Join-Path $Stage 'result.json'),'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  [pscustomobject]@{success=$success;guest_stage=$Stage;result_path=(Join-Path $Stage 'result.json');result_sha256=(Get-FileHash -LiteralPath (Join-Path $Stage 'result.json')).Hash.ToLowerInvariant();created_directories=$paths.Count;error=$failure}
 }
 Save 'guest-result.json' $receipt
 Copy-Item -FromSession $session -LiteralPath $receipt.result_path -Destination (Join-Path $root 'result.json')
 Need ((Get-FileHash -LiteralPath (Join-Path $root 'result.json')).Hash.ToLowerInvariant()-ceq$receipt.result_sha256) 'Closed fixture result copy differs.'
 Guard;Need ($receipt.success-and$receipt.created_directories-eq450) 'Actual directory fixture failed; preserve without retry.'
 Save 'complete.json' @{success=$true;result_path=(Join-Path $root 'result.json');result_sha256=$receipt.result_sha256;created_directories=450;created_payload_files=0;vm_power_restore_checkpoint_actions=$false;source_admitted=$false;conversion_authorized=$false}
 Get-Content -LiteralPath (Join-Path $root 'complete.json') -Raw
}finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
