# Explicit user override: delete redundant checkpoints using Hyper-V merges.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$keep=@('9e63e9d2-a0e4-408f-87b5-26d31fbdcc24','219e3abf-4289-4e16-b27f-2b4d32ac619c')
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\checkpoint-cleanup-20261029'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Need (-not(Test-Path -LiteralPath $root)) 'Cleanup has state; inspect its job rather than repeat deletions.'
$vm=Get-VM -Id $id;$all=@(Get-VMSnapshot -VM $vm)
Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0 -and $all.Count -eq 50 -and $vm.ParentSnapshotId -eq [guid]$keep[0]) 'Exact stopped partial VM/all50 required.'
Need (-not(Test-Path -LiteralPath (Join-Path $workspace '.lab\hyperv\managed-recovery-fork-20261029'))) 'An external fork exists; inspect dependencies first.'
$map=@{};foreach($s in $all){$map[$s.Id.ToString('D')]=$s};foreach($key in $keep){Need ($map.ContainsKey($key)) 'Required recent anchor missing.'}
$plan=@(foreach($s in $all){$key=$s.Id.ToString('D');if($key -in $keep){continue};$depth=0;$cursor=$s;$seen=@{};while($null -ne $cursor.ParentSnapshotId -and [guid]$cursor.ParentSnapshotId -ne [guid]::Empty){$parent=([guid]$cursor.ParentSnapshotId).ToString('D');Need (-not$seen.ContainsKey($parent) -and $map.ContainsKey($parent) -and $depth -lt 64) 'Invalid ancestry.';$seen[$parent]=$true;$depth++;$cursor=$map[$parent]};[pscustomobject]@{id=$key;name=$s.Name;depth=$depth;created=$s.CreationTime.ToUniversalTime().ToString('o')}})|Sort-Object -Property @{Expression='depth';Descending=$true},@{Expression='created';Descending=$true}
Need ($plan.Count -eq 48) 'Expected48 redundant checkpoints.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$config=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $config
Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed50GB epoch differs.'
New-Item -ItemType Directory -Path $root|Out-Null
Save 'intent.json' @{vm_id=$id.ToString();user_authorization='Delete most of the checkpoints its junk. Do not preserve them.';keep_ids=$keep;delete=$plan;before=$capacity;raw_file_deletion=$false;utc=[datetime]::UtcNow.ToString('o')}
$deleted=@();$activeJob=$null
try{foreach($item in $plan){
 $vm=Get-VM -Id $id;$fresh=@(Get-VMSnapshot -VM $vm);$ids=@($fresh.Id|ForEach-Object {$_.ToString('D')})
 Need ($vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0 -and $vm.ParentSnapshotId -eq [guid]$keep[0] -and @($keep|Where-Object {$_ -notin $ids}).Count -eq 0) 'Stopped VM/recent anchors changed.'
 $selected=@($fresh|Where-Object Id -eq ([guid]$item.id));Need ($selected.Count -eq 1 -and $item.id -notin $keep) 'Exact redundant checkpoint required.'
 $charge=[long]256MB
 if(@($fresh|Where-Object ParentSnapshotId -eq ([guid]$item.id)).Count){foreach($path in @(Get-VMHardDiskDrive -VMSnapshot $selected[0]|ForEach-Object Path|Sort-Object -Unique)){$charge+=(Get-Item -LiteralPath $path -Force).Length}}
 Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $config) -AdditionalBytes $charge
 $index=$deleted.Count+1;Save ('remove-'+$index+'-intent.json') @{id=$item.id;name=$item.name;temporary_growth_forecast=$charge;include_children=$false;issued_at_most_once=$true;utc=[datetime]::UtcNow.ToString('o')}
 $activeJob=Remove-VMSnapshot -VMSnapshot $selected[0] -Confirm:$false -AsJob -ErrorAction Stop
 Save ('remove-'+$index+'-job.json') @{checkpoint_id=$item.id;job_id=$activeJob.Id;job_instance_id=$activeJob.InstanceId.ToString();utc=[datetime]::UtcNow.ToString('o')}
 while($activeJob.State.ToString() -in @('Running','NotStarted')){Wait-Job -Job $activeJob -Timeout 1|Out-Null}
 $state=$activeJob.State.ToString();$output=@(Receive-Job -Job $activeJob -ErrorAction Stop);Need ($state -ceq 'Completed') 'Hyper-V removal job did not complete.'
 $fresh=@(Get-VMSnapshot -VM (Get-VM -Id $id));$ids=@($fresh.Id|ForEach-Object {$_.ToString('D')})
 Need ($item.id -notin $ids -and @($keep|Where-Object {$_ -notin $ids}).Count -eq 0) 'Deletion did not settle; no deletion retry.'
 $deleted+=@{id=$item.id;name=$item.name};Save ('remove-'+$index+'-complete.json') @{id=$item.id;job_state=$state;remaining=$fresh.Count;utc=[datetime]::UtcNow.ToString('o')};Write-Output ('Removed '+$deleted.Count+'/48: '+$item.name);$activeJob=$null
}
 $vm=Get-VM -Id $id;$last=@(Get-VMSnapshot -VM $vm);$ids=@($last.Id|ForEach-Object {$_.ToString('D')})
 Need ($vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0 -and $last.Count -eq 2 -and @($keep|Where-Object {$_ -notin $ids}).Count -eq 0) 'Final two-checkpoint state differs.'
 foreach($drive in @(Get-VMHardDiskDrive -VM $vm)){Need (Test-VHD -Path $drive.Path) 'Hyper-V reports invalid active disk chain.'}
 $after=Get-LabCapacity -Configuration $config;Save 'result.json' @{success=$true;vm_id=$id.ToString();deleted=$deleted;remaining_ids=$ids;remaining_count=2;state='Off';memory_assigned=0;before=$capacity;after=$after;host_free_bytes_increase=($after.FreeBytes-$capacity.FreeBytes);raw_file_deletions=$false;utc=[datetime]::UtcNow.ToString('o')};Get-Content -LiteralPath (Join-Path $root 'result.json') -Raw
}catch{Save 'failed.json' @{success=$false;error=$_.Exception.ToString();deleted=$deleted;active_job_id=$(if($null -ne $activeJob){$activeJob.Id}else{$null});automatic_retry=$false;utc=[datetime]::UtcNow.ToString('o')};throw}
