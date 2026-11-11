# Preserve the already completed resume/finalize/mutation/reboot branch.
# No replay, second reboot, forced power action, detach, restore or deletion.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$CaseId)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$alpha=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$caseRoot=Join-Path $alpha ('fault-cases\'+$CaseId)
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$baseId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$engine='96720eff89c7e808983c8d5c9800d475fe62515c';$session=$null;$lease=$null;$phase='host-preflight'
function Ordinary([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force
 if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary preservation path required.'}
 $parent=if($item.PSIsContainer){$item.Parent}else{$item.Directory}
 while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Preservation ancestry is a reparse point.'};$parent=$parent.Parent}
}
function Read-Record([string]$Path){
 Ordinary $Path $false;if((Get-Item -LiteralPath $Path).Length-gt2MB){throw 'Bounded preservation JSON required.'}
 Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
}
function True($Value){($Value-is[bool])-and$Value}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20))
 if($bytes.Length-gt2MB){throw 'Preservation record exceeds bound.'}
 $f=[IO.File]::Open((Join-Path $caseRoot $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$manifest=Read-Record (Join-Path $alpha 'manifest.json')
$dispatch=Read-Record (Join-Path $caseRoot 'dispatch.json')
$fixture=Read-Record (Join-Path $alpha 'guest-fixture.json')
$controller=Read-Record (Join-Path $caseRoot 'resume-controller-intent.json')
if($controller.controller_id-cnotmatch'\A[0-9a-f]{32}\z'){throw 'Recorded completion controller identity required.'}
$postRoot=Join-Path $caseRoot ('resume-postcheck-'+$controller.controller_id)
if($controller.kind-cne'native-shadow-alpha-resume-controller-intent'-or$controller.case_id-cne$CaseId-or
 [guid]$controller.vm_id-ne$vmId-or$controller.engine_commit-cne$engine-or$controller.postcheck_root-cne$postRoot-or
 $controller.dispatch_sha256-cne(Get-FileHash -LiteralPath (Join-Path $caseRoot 'dispatch.json') -Algorithm SHA256).Hash.ToLowerInvariant()-or
 [guid]$manifest.vm_id-ne$vmId-or$manifest.name-cne'ntfs2refs-shadow-alpha-20261026'-or$manifest.root-cne$alpha-or@($manifest.disks).Count-ne4-or
 [guid]$dispatch.vm_id-ne$vmId-or[guid]$dispatch.checkpoint_id-ne$baseId-or$dispatch.case-cne'Resume'-or$dispatch.run_id-cne$CaseId-or$dispatch.engine_commit-cne$engine-or
 @($fixture.files).Count-ne7){throw 'Frozen alpha resume preservation binding differs.'}
$resultPath=Join-Path $postRoot 'result.json';$result=Read-Record $resultPath
$reboot=Read-Record (Join-Path $postRoot 'reboot-observed.json')
if($result.kind-cne'native-shadow-alpha-resume-completed'-or-not(True $result.success)-or-not(True $result.native_verified)-or
 -not(True $result.mutation_verified)-or-not(True $result.reboot_verified)-or-not(True $result.checkpoint_preservation_pending)-or
 $result.case_id-cne$CaseId-or$result.controller_id-cne$controller.controller_id-or[guid]$result.vm_id-ne$vmId-or
 $result.request_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$result.ticket_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$result.expectation_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or
 [long]$reboot.boot_ticks-le0-or(Test-Path -LiteralPath (Join-Path $postRoot 'failed-preserved.json'))){throw 'Completed native/mutation/reboot evidence is required.'}
function Owned([string[]]$States){
 $v=Get-VM -Id $vmId
 if($v.Name-cne'ntfs2refs-shadow-alpha-20261026'-or-not$v.Path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or
  $v.State.ToString()-cnotin$States-or[guid]$v.ParentSnapshotId-ne$baseId-or@(Get-VMNetworkAdapter -VM $v).Count-or$v.AutomaticCheckpointsEnabled){throw 'Alpha VM state/branch/isolation differs.'}
 $drives=@(Get-VMHardDiskDrive -VM $v);if($drives.Count-ne4){throw 'Exactly four owned alpha backings required.'}
 foreach($drive in $drives){
  $rows=@($manifest.disks|Where-Object {$_.controller-ceq$drive.ControllerType.ToString()-and$_.controller_number-eq$drive.ControllerNumber-and$_.controller_location-eq$drive.ControllerLocation})
  if($rows.Count-ne1){throw 'Unexpected backing route.'};$row=$rows[0];$path=[string]$drive.Path;$seen=@{}
  while($true){
   if(-not$path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)-or$seen.Count-ge128){throw 'Backing ancestry escapes alpha ownership.'}
   $seen[$path]=$true;Ordinary $path $false;$disk=Get-VHD -Path $path
   if($disk.Size-ne$row.virtual_bytes){throw 'Backing geometry differs.'}
   if([string]::IsNullOrEmpty([string]$disk.ParentPath)){break};$path=[string]$disk.ParentPath
  }
  if(-not[string]::Equals($path,$row.path,[StringComparison]::OrdinalIgnoreCase)-or[guid]$disk.DiskIdentifier-ne[guid]$row.vhd_id){throw 'Backing root differs.'}
 }
 $v
}
$verify={
 param($FilesJson,$BootTicks)
 Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
 if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State.ToString()-in@('Running','Queued')}).Count-or
  @(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Active/unknown lab worker blocks preservation.'}
 $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
 if($env:COMPUTERNAME-cne'N2R-WIN11'-or$version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or
  (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'-or
  (Get-FileHash -LiteralPath 'C:\ntfs2refs\alpha\native-shadow-alpha-20261026\ntfs2refs.exe' -Algorithm SHA256).Hash.ToLowerInvariant()-cne'714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'){throw 'Frozen native engine/build differs.'}
 $disk=Get-Disk -Number 1;$partition=Get-Partition -DiskNumber 1 -PartitionNumber 2;$mounted=Get-Partition -DriveLetter F;$volume=Get-Volume -DriveLetter F
 if($disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
  [guid]$disk.Guid-ne[guid]'82df7109-d6a1-4535-852a-9f1abb52966f'-or[guid]$partition.Guid-ne[guid]'f8bdd003-1df4-45d1-9798-338e57d76414'-or
  $partition.Offset-ne16MB-or$partition.Size-ne52GB-or$mounted.DiskNumber-ne1-or$mounted.PartitionNumber-ne2-or
  $volume.FileSystem-cne'ReFS'-or$volume.FileSystemLabel-cne'n2r-alpha-source'){throw 'Original converted ReFS identity/availability differs.'}
 $rows=$FilesJson|ConvertFrom-Json;if(@($rows).Count-ne7){throw 'Exact seven-file fixture required.'}
 foreach($row in $rows){$item=Get-Item -LiteralPath $row.path -Force
  if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$row.bytes-or
   (Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Converted payload differs.'}}
 $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
 if($boot-isnot[DateTime]-or$boot.ToUniversalTime().Ticks-ne[long]$BootTicks){throw 'Actual boot differs from completed strict verification boot.'}
 [pscustomobject]@{source_refs=$true;source_online=$true;original_label=$true;seven_user_payload_hashes_and_lengths_matched=$true;active_n2r_workers=0;
  boot_utc=$boot.ToUniversalTime().ToString('o');boot_ticks=$boot.ToUniversalTime().Ticks;full_postmount_image_equality_claimed=$false}
}
$null=Owned @('Running')
$snapshotName='alpha-resume-passed-'+$CaseId
if(@(Get-VMSnapshot -VM (Get-VM -Id $vmId)|Where-Object Name -CEQ $snapshotName).Count){throw 'Preservation checkpoint name already exists; inspect without retry.'}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
$leasePath=Join-Path $alpha 'active-alpha-controller.lock'
if(Test-Path -LiteralPath $leasePath){Ordinary $leasePath $false;if((Get-Item -LiteralPath $leasePath).Length-ne0){throw 'Controller lease shape differs.'}}
$lease=[IO.File]::Open($leasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try{
 Save 'resume-preservation-intent.json' @{case_id=$CaseId;controller_id=$controller.controller_id;vm_id=$vmId.ToString('D');engine_commit=$engine;result_sha256=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant();checkpoint_name=$snapshotName;checkpoint_parent=$baseId.ToString('D');capacity=$capacity;force=$false;repeat_reboot=$false;created_utc=[DateTime]::UtcNow.ToString('o')}
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
 $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $phase='native-preservation-preflight';$before=Invoke-Command -Session $session -ScriptBlock $verify -ArgumentList ($fixture.files|ConvertTo-Json -Compress),([long]$reboot.boot_ticks)
 Save 'resume-preservation-native.json' $before
 $null=Owned @('Running');$phase='clean-shutdown-once'
 Save 'resume-preservation-shutdown-intent.json' @{vm_id=$vmId.ToString('D');force=$false;requested_utc=[DateTime]::UtcNow.ToString('o')}
 try{Invoke-Command -Session $session -ScriptBlock {Stop-Computer -ErrorAction Stop}|Out-Null}catch{Save 'resume-preservation-shutdown-transport.json' @{error=$_.Exception.Message;off_not_inferred=$true}}
 Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(3)
 do{$off=Owned @('Running','Stopping','Off');if($off.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds 3}while([DateTime]::UtcNow-lt$deadline)
 if($off.State.ToString()-cne'Off'){throw 'Clean shutdown is unconfirmed; no retry/forced power action.'}
 $phase='checkpoint-once';$prior=@(Get-VMSnapshot -VM $off|ForEach-Object {$_.Id.ToString('D')})
 Save 'resume-preservation-checkpoint-intent.json' @{vm_id=$vmId.ToString('D');name=$snapshotName;parent_checkpoint=$baseId.ToString('D');prior_checkpoint_ids=$prior;state='Off'}
 Checkpoint-VM -VM $off -SnapshotName $snapshotName -ErrorAction Stop|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do{$final=Get-VM -Id $vmId;$all=@(Get-VMSnapshot -VM $final);$saved=@($all|Where-Object Name -CEQ $snapshotName)
  if($saved.Count-eq1-and$final.State.ToString()-ceq'Off'-and[guid]$final.ParentSnapshotId-eq$saved[0].Id){break};Start-Sleep -Seconds 1
 }while([DateTime]::UtcNow-lt$deadline)
 if($saved.Count-ne1-or$saved[0].Id-eq[guid]::Empty-or$prior-contains$saved[0].Id.ToString('D')-or
  [guid]$saved[0].ParentSnapshotId-ne$baseId-or[guid]$final.ParentSnapshotId-ne$saved[0].Id-or$final.State.ToString()-cne'Off'){throw 'Fresh actual resume OFF checkpoint was not established.'}
 foreach($id in $prior){if(@($all|Where-Object {$_.Id-eq[guid]$id}).Count-ne1){throw 'Prior checkpoint missing after preservation.'}}
 Save 'resume-preserved-checkpoint.json' @{case_id=$CaseId;controller_id=$controller.controller_id;vm_id=$vmId.ToString('D');engine_commit=$engine;checkpoint_id=$saved[0].Id.ToString('D');name=$snapshotName;parent_checkpoint=$baseId.ToString('D');state='Off';result_sha256=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant();request_sha256=$result.request_sha256;ticket_sha256=$result.ticket_sha256;expectation_sha256=$result.expectation_sha256;native_verified=$true;mutation_verified=$true;reboot_verified=$true;all_prior_checkpoints_preserved=$true;power_loss_qualified=$false;preserved_utc=[DateTime]::UtcNow.ToString('o')}
 Write-Host ('Completed resume branch preserved OFF: '+$saved[0].Id)
}catch{Save ('resume-preservation-failed-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json') @{phase=$phase;error=$_.Exception.ToString();stop_or_checkpoint_retry_authorized=$false;recorded_utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($lease){$lease.Dispose()}}
