# Preserve only a completed cancel/rollback branch. Never replays recovery,
# forces disk state, retries a reboot, deletes evidence or restores a snapshot.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$CaseId,
      [Parameter(Mandatory)][ValidateSet('Cancel','RollbackWithoutShadow')][string]$Case,
      [switch]$ResumeBeforeReboot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$alpha=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$caseRoot=Join-Path $alpha ('fault-cases\'+$CaseId)
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$baseId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$manifest=Get-Content -LiteralPath (Join-Path $alpha 'manifest.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $caseRoot 'dispatch.json') -Raw|ConvertFrom-Json
$fixture=Get-Content -LiteralPath (Join-Path $alpha 'guest-fixture.json') -Raw|ConvertFrom-Json
if([guid]$dispatch.vm_id-ne$vmId-or$dispatch.case-cne$Case-or$dispatch.run_id-cne$CaseId-or
 [guid]$dispatch.checkpoint_id-ne$baseId-or$dispatch.engine_commit-cne'96720eff89c7e808983c8d5c9800d475fe62515c'-or
 [guid]$manifest.vm_id-ne$vmId-or$manifest.root-cne$alpha-or@($fixture.files).Count-ne7){throw 'Exact frozen alpha recovery case required.'}
$proof=if($Case-ceq'Cancel'){'cancel-availability-verified.json'}else{'rollback-availability-verified.json'}
if(-not(Test-Path -LiteralPath (Join-Path $caseRoot $proof))){throw 'Completed recovery availability evidence required.'}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20))
 $f=[IO.File]::Open((Join-Path $caseRoot $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function Owned([string[]]$States){
 $v=Get-VM -Id $vmId
 if($v.Name-cne'ntfs2refs-shadow-alpha-20261026'-or-not$v.Path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or
  $v.State.ToString()-cnotin$States-or[guid]$v.ParentSnapshotId-ne$baseId-or@(Get-VMNetworkAdapter -VM $v).Count){throw 'Alpha VM state/branch/isolation differs.'}
 $drives=@(Get-VMHardDiskDrive -VM $v);$expected=if($Case-ceq'Cancel'){4}else{3}
 if($drives.Count-ne$expected){throw 'Recovered branch backing count differs.'}
 foreach($drive in $drives){
  $rows=@($manifest.disks|Where-Object {$_.controller-ceq$drive.ControllerType.ToString()-and$_.controller_number-eq$drive.ControllerNumber-and$_.controller_location-eq$drive.ControllerLocation})
  if($rows.Count-ne1){throw 'Unexpected backing route.'};$row=$rows[0];$path=[string]$drive.Path;$seen=@{}
  while($true){
   if(-not$path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)-or$seen.Count-ge128){throw 'Backing ancestry escapes alpha.'}
   $seen[$path]=$true;$item=Get-Item -LiteralPath $path -Force
   if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary alpha backing required.'}
   $disk=Get-VHD -Path $path;if($disk.Size-ne$row.virtual_bytes){throw 'Backing geometry differs.'}
   if([string]::IsNullOrEmpty([string]$disk.ParentPath)){break};$path=[string]$disk.ParentPath
  }
  if(-not[string]::Equals($path,$row.path,[StringComparison]::OrdinalIgnoreCase)-or[guid]$disk.DiskIdentifier-ne[guid]$row.vhd_id){throw 'Backing root differs.'}
 }
 $v
}
$verify={
 param($FilesJson,$CaseName)
 Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
 if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State.ToString()-in@('Running','Queued')}).Count-or
  @(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Active/unknown lab worker blocks preservation.'}
 $disk=Get-Disk -Number 1;$partition=Get-Partition -DiskNumber 1 -PartitionNumber 2;$mounted=Get-Partition -DriveLetter F;$volume=Get-Volume -DriveLetter F
 if($disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
  [guid]$disk.Guid-ne[guid]'82df7109-d6a1-4535-852a-9f1abb52966f'-or
  [guid]$partition.Guid-ne[guid]'f8bdd003-1df4-45d1-9798-338e57d76414'-or$partition.Offset-ne16MB-or$partition.Size-ne52GB-or
  $mounted.DiskNumber-ne1-or$mounted.PartitionNumber-ne2-or[guid]$mounted.Guid-ne[guid]$partition.Guid-or
  $volume.FileSystem-cne'NTFS'-or$volume.FileSystemLabel-cne'n2r-alpha-source'){throw 'Recovered original NTFS identity/availability differs.'}
 $rows=$FilesJson|ConvertFrom-Json;if(@($rows).Count-ne7){throw 'Exact seven-file fixture required.'}
 foreach($row in $rows){$item=Get-Item -LiteralPath $row.path -Force
  if($item.PSIsContainer-or$item.Length-ne$row.bytes-or(Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Recovered payload differs.'}}
 if($CaseName-ceq'RollbackWithoutShadow'-and@(Get-Disk|Where-Object {[guid]$_.Guid-eq[guid]'7be34433-b62d-453a-a8ce-fd70f5a6c663'}).Count){throw 'Shadow unexpectedly returned.'}
 $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
 [pscustomobject]@{source_ntfs=$true;source_online=$true;original_label=$true;seven_user_payload_hashes_matched=$true;
  boot_utc=$boot.ToUniversalTime().ToString('o');boot_ticks=$boot.ToUniversalTime().Ticks;full_postmount_image_equality_claimed=$false;full_security_timestamp_audit=$false}
}
$null=Owned @('Running')
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
if($ResumeBeforeReboot){
 $prior=Get-Content -LiteralPath (Join-Path $caseRoot 'recovery-preservation-intent.json') -Raw|ConvertFrom-Json
 if($prior.case-cne$Case-or$prior.case_id-cne$CaseId-or[guid]$prior.vm_id-ne$vmId-or
  (Test-Path -LiteralPath (Join-Path $caseRoot 'recovery-before-reboot.json'))-or
  (Test-Path -LiteralPath (Join-Path $caseRoot 'recovery-reboot-intent.json'))){throw 'Only pre-reboot preservation preflight may continue.'}
 Save ('recovery-preflight-resumed-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json') @{case=$Case;case_id=$CaseId;previous_reboot_requested=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}
}else{Save 'recovery-preservation-intent.json' @{case=$Case;case_id=$CaseId;vm_id=$vmId.ToString('D');checkpoint_parent=$baseId.ToString('D');capacity=$capacity;force=$false;created_utc=[DateTime]::UtcNow.ToString('o')}}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vmId -Credential $credential
 $before=Invoke-Command -Session $session -ScriptBlock $verify -ArgumentList ($fixture.files|ConvertTo-Json -Compress),$Case
 Save 'recovery-before-reboot.json' $before
 Save 'recovery-reboot-intent.json' @{before_boot_ticks=$before.boot_ticks;force=$false;requested_utc=[DateTime]::UtcNow.ToString('o')}
 try{Invoke-Command -Session $session -ScriptBlock {Restart-Computer -ErrorAction Stop}|Out-Null}catch{Save 'recovery-reboot-transport.json' @{error=$_.Exception.Message;completion_not_inferred=$true}}
 Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
 do{
  $null=Owned @('Running','Starting','Stopping','Off');$candidate=$null
  try{$candidate=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
   $after=Invoke-Command -Session $candidate -ScriptBlock $verify -ArgumentList ($fixture.files|ConvertTo-Json -Compress),$Case
   if([long]$after.boot_ticks-gt[long]$before.boot_ticks){$session=$candidate}else{Remove-PSSession $candidate -ErrorAction SilentlyContinue}
  }catch{if($candidate){Remove-PSSession $candidate -ErrorAction SilentlyContinue}}
  if($null-eq$session){Start-Sleep -Seconds 5}
 }while($null-eq$session-and[DateTime]::UtcNow-lt$deadline)
 if($null-eq$session){throw 'Clean reboot/payload verification not established; do not retry reboot.'}
 Save 'recovery-after-reboot.json' $after
 Save 'recovery-shutdown-intent.json' @{force=$false;requested_utc=[DateTime]::UtcNow.ToString('o')}
 try{Invoke-Command -Session $session -ScriptBlock {Stop-Computer -ErrorAction Stop}|Out-Null}catch{Save 'recovery-shutdown-transport.json' @{error=$_.Exception.Message;off_not_inferred=$true}}
 Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(3)
 do{$off=Owned @('Running','Stopping','Off');if($off.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds 3}while([DateTime]::UtcNow-lt$deadline)
 if($off.State.ToString()-cne'Off'){throw 'Clean OFF unconfirmed; no forced power action.'}
 $name='alpha-'+$Case.ToLowerInvariant()+'-passed-'+$CaseId
 Save 'recovery-checkpoint-intent.json' @{vm_id=$vmId.ToString('D');name=$name;parent_checkpoint=$baseId.ToString('D');state='Off'}
 Checkpoint-VM -VM $off -SnapshotName $name|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do{$saved=@(Get-VMSnapshot -VM (Get-VM -Id $vmId)|Where-Object Name -CEQ $name);$final=Get-VM -Id $vmId
  if($saved.Count-eq1-and$final.State.ToString()-ceq'Off'-and[guid]$final.ParentSnapshotId-eq$saved[0].Id){break};Start-Sleep -Seconds 1
 }while([DateTime]::UtcNow-lt$deadline)
 if($saved.Count-ne1-or[guid]$saved[0].ParentSnapshotId-ne$baseId-or[guid]$final.ParentSnapshotId-ne$saved[0].Id-or$final.State.ToString()-cne'Off'){throw 'Actual recovered OFF checkpoint not established.'}
 Save 'recovery-preserved-checkpoint.json' @{case=$Case;vm_id=$vmId.ToString('D');checkpoint_id=$saved[0].Id.ToString('D');name=$name;parent_checkpoint=$baseId.ToString('D');state='Off';payload_reboot_verified=$true;power_loss_qualified=$false}
 Write-Host ('Recovered branch reboot-verified and preserved OFF: '+$saved[0].Id)
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
