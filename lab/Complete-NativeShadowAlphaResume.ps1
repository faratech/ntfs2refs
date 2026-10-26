# Frozen alpha recovery controller. Never retries a worker, forces disk state,
# detaches storage, restores checkpoints or overwrites existing evidence.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$CaseId,
      [ValidateRange(1,240)][int]$MaximumWaitMinutes=120,
      [ValidateRange(1,30)][int]$PollSeconds=15)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$alphaRoot=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$packageRoot=Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026'
$caseRoot=Join-Path $alphaRoot ('fault-cases\'+$CaseId)
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$vmName='ntfs2refs-shadow-alpha-20261026'
$baselineId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$stage='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
$session=$null;$phase='host-preflight';$controllerId=[guid]::NewGuid().ToString('N');$hostLease=$null
$evidenceRoot=Join-Path $caseRoot ('resume-evidence-'+$controllerId)
$postRoot=Join-Path $caseRoot ('resume-postcheck-'+$controllerId)
$guestPost='C:\ntfs2refs\alpha\recovery-results\'+$controllerId
function Assert-Ordinary([string]$Path,[bool]$Directory){
    $item=Get-Item -LiteralPath $Path -Force
    if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw ('Ordinary path required: '+$Path)}
    $parent=Split-Path -Path $item.FullName -Parent
    while($parent){$entry=Get-Item -LiteralPath $parent -Force
        if(-not$entry.PSIsContainer-or($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Reparse/non-directory ancestry refused.'}
        $next=Split-Path $parent -Parent;if($next-ceq$parent){break};$parent=$next}
}
function Read-HostJson([string]$Path){
    Assert-Ordinary $Path $false
    if((Get-Item -LiteralPath $Path).Length-gt2MB){throw 'Bounded host JSON required.'}
    return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)
}
function Save-Record([string]$Path,$Value){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32))
    if($bytes.Length-gt16MB){throw 'Controller JSON exceeds bound.'}
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Assert-AlphaVm([string[]]$States=@('Running')){
    $owned=Get-VM -Id $vmId -ErrorAction Stop
    if($owned.Name-cne$vmName-or-not$owned.Path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or
       $owned.State.ToString()-cnotin$States-or[guid]$owned.ParentSnapshotId-ne$baselineId){throw 'Exact alpha VM, path, state or baseline ancestry differs.'}
    if(@(Get-VMNetworkAdapter -VM $owned).Count-ne0-or$owned.AutomaticCheckpointsEnabled){throw 'Alpha isolation/checkpoint policy differs.'}
    $drives=@(Get-VMHardDiskDrive -VM $owned)
    if($drives.Count-ne4){throw 'Alpha backing count differs.'}
    foreach($spec in $manifest.disks){
        $drive=@($drives|Where-Object {$_.ControllerType.ToString()-ceq$spec.controller-and$_.ControllerNumber-eq$spec.controller_number-and$_.ControllerLocation-eq$spec.controller_location})
        if($drive.Count-ne1){throw 'Alpha backing route differs.'}
        $path=[string]$drive[0].Path;$seen=@{}
        while($true){
            if(-not$path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)){throw 'Alpha backing escapes ownership or cycles.'}
            $seen[$path]=$true;Assert-Ordinary $path $false;$disk=Get-VHD -Path $path
            if($disk.Size-ne$spec.virtual_bytes){throw 'Alpha backing geometry differs.'}
            if([string]::IsNullOrEmpty([string]$disk.ParentPath)){break};$path=[string]$disk.ParentPath
        }
        if(-not[string]::Equals($path,[string]$spec.path,[StringComparison]::OrdinalIgnoreCase)){throw 'Alpha backing root differs.'}
    }
    return $owned
}
function Capacity-Record([string]$Name){
    $capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
    Save-Record (Join-Path $postRoot ($Name+'-capacity.json')) $capacity
}
# Every guest command targets only the already acquired session for the exact VM.
$guestReadiness={
    Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or$version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or
       [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID-ne[guid]'87d4c43a-4299-460e-b973-b241f239d33f'-or
       (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Frozen alpha guest identity differs.'}
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    if($boot-isnot[DateTime]){throw 'Preserved DateTime boot observation required.'}
    [pscustomobject]@{boot_utc=$boot.ToUniversalTime().ToString('o');boot_ticks=$boot.ToUniversalTime().Ticks;observed_utc=[DateTime]::UtcNow.ToString('o')}
}
function Observe-Task($Step){
    return (Invoke-Command -Session $session -ArgumentList $Step.task_name,$Step.binary,$Step.arguments -ScriptBlock {
        param($RecordedTaskName,$RecordedBinary,$RecordedArguments);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $scheduled=Get-ScheduledTask -TaskName $RecordedTaskName -ErrorAction Stop
        $info=Get-ScheduledTaskInfo -TaskName $RecordedTaskName -ErrorAction Stop
        $actions=@($scheduled.Actions)
        if($actions.Count-ne1-or$actions[0].Execute-cne$RecordedBinary-or$actions[0].Arguments-cne$RecordedArguments-or
           $scheduled.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$scheduled.Principal.RunLevel.ToString()-cne'Highest'){throw 'Recorded SYSTEM task action differs.'}
        $other=@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.TaskName-cne$RecordedTaskName-and$_.State.ToString()-in@('Running','Queued')})
        if($other.Count){throw 'Another guest lab worker is active.'}
        $processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-ceq[IO.Path]::GetFileName($RecordedBinary)-and
            ([string]::IsNullOrEmpty([string]$_.ExecutablePath)-or[string]::Equals([string]$_.ExecutablePath,$RecordedBinary,[StringComparison]::OrdinalIgnoreCase))}|ForEach-Object {
            [pscustomobject]@{pid=$_.ProcessId;path=$_.ExecutablePath;command_line=$_.CommandLine;read_bytes=$_.ReadTransferCount;written_bytes=$_.WriteTransferCount}})
        $live=$scheduled.State.ToString()-in@('Running','Queued')
        [pscustomobject]@{task_name=$RecordedTaskName;state=$scheduled.State.ToString();last_task_result=[long]$info.LastTaskResult;
            last_run_utc=$info.LastRunTime.ToUniversalTime().ToString('o');has_run=$info.LastRunTime.Year-ge2000;
            terminal=(-not$live-and$info.LastRunTime.Year-ge2000-and$processes.Count-eq0);processes=$processes;observed_utc=[DateTime]::UtcNow.ToString('o')}
    })
}
function Wait-Step($Step,[string]$Label){
    $deadline=[DateTime]::UtcNow.AddMinutes($MaximumWaitMinutes)
    while($true){
        $null=Assert-AlphaVm;$observed=Observe-Task $Step
        Write-Host ($Label+': '+$observed.state+'; matching processes='+@($observed.processes).Count+'; result='+$observed.last_task_result)
        if($observed.terminal){Save-Record (Join-Path $postRoot ($Label+'-terminal.json')) $observed
            if($observed.last_task_result-ne0){throw ($Label+' failed; preserve evidence without recovery or redispatch.')};return}
        if([DateTime]::UtcNow-ge$deadline){Save-Record (Join-Path $postRoot ($Label+'-observation-timeout.json')) $observed;throw ($Label+' observation timed out; worker termination is unproven. Do not redispatch.')}
        Start-Sleep -Seconds $PollSeconds
    }
}
function Read-GuestJson([string]$Path,[long]$Limit=16MB){
    return (Invoke-Command -Session $session -ArgumentList $Path,$Limit -ScriptBlock {
        param($EvidencePath,$MaximumBytes);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $item=Get-Item -LiteralPath $EvidencePath -Force
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt$MaximumBytes){throw 'Bounded ordinary guest JSON required.'}
        $parent=$item.Directory
        while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Guest evidence ancestry is a reparse point.'};$parent=$parent.Parent}
        $text=Get-Content -LiteralPath $EvidencePath -Raw
        [pscustomobject]@{path=$EvidencePath;bytes=[long]$item.Length;sha256=(Get-FileHash -LiteralPath $EvidencePath -Algorithm SHA256).Hash.ToLowerInvariant();value=($text|ConvertFrom-Json)}
    })
}
function Copy-JsonTree([string]$GuestDirectory,[string]$HostDirectory){
    if(Test-Path -LiteralPath $HostDirectory){throw 'Fresh evidence collection directory required.'}
    $null=[IO.Directory]::CreateDirectory($HostDirectory)
    $rows=@(Invoke-Command -Session $session -ArgumentList $GuestDirectory -ScriptBlock {
        param($TreeRoot);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($TreeRoot);$result=@();$total=0L;$dirs=0
        while($pending.Count){$directory=$pending.Pop();$rootItem=Get-Item -LiteralPath $directory -Force
            if(-not$rootItem.PSIsContainer-or($rootItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-or++$dirs-gt128){throw 'Evidence directory profile exceeded.'}
            foreach($item in Get-ChildItem -LiteralPath $directory -Force){
                if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Evidence tree contains a reparse point.'}
                if($item.PSIsContainer){if($item.FullName.Substring($TreeRoot.Length).Split('\').Count-gt10){throw 'Evidence directory depth exceeded.'};$pending.Push($item.FullName);continue}
                if($item.Extension-cne'.json'){continue}
                $total+=$item.Length;if($item.Length-gt16MB-or$total-gt64MB-or$result.Count-ge512){throw 'Bounded JSON evidence collection exceeded.'}
                $result+=[pscustomobject]@{path=$item.FullName;relative=$item.FullName.Substring($TreeRoot.Length).TrimStart('\');bytes=[long]$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
            }
        };$result
    })
    foreach($row in $rows){
        if($row.relative.Contains('..')-or[IO.Path]::IsPathRooted($row.relative)){throw 'Evidence relative path differs.'}
        $destination=Join-Path $HostDirectory $row.relative;$null=[IO.Directory]::CreateDirectory((Split-Path $destination -Parent))
        Copy-Item -LiteralPath $row.path -Destination $destination -FromSession $session
        Assert-Ordinary $destination $false
        if((Get-Item -LiteralPath $destination).Length-ne$row.bytes-or(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Exported evidence differs from guest.'}
    }
    Save-Record (Join-Path $HostDirectory '_export-pins.json') ([ordered]@{guest_root=$GuestDirectory;files=$rows;journal_copied=$false;captured_utc=[DateTime]::UtcNow.ToString('o')})
}
function Start-Step([string]$Label,[string]$Executable,[string]$Arguments,[string]$GuestOutput){
    $null=Assert-AlphaVm
    $row=@($package.executables|Where-Object {$_.name-ceq$Executable})
    if($row.Count-ne1){throw 'Frozen executable is absent/ambiguous.'}
    $step=[pscustomobject]@{label=$Label;task_name=('N2R-AlphaPost-'+[guid]::NewGuid().ToString('N'));binary=(Join-Path $stage $Executable);arguments=$Arguments;output=$GuestOutput;binary_sha256=$row[0].sha256;started_utc=[DateTime]::UtcNow.ToString('o')}
    Save-Record (Join-Path $postRoot ($Label+'-intent.json')) $step
    $null=Invoke-Command -Session $session -ArgumentList $step,$row[0].bytes,$requestPath,$requestPin,$treePath,$treePin,$ticketPath,$ticketPin,$guestPost -ScriptBlock {
        param($RecordedStep,$BinaryBytes,$RequestPath,$RequestPin,$TreePath,$TreePin,$TicketPath,$TicketPin,$FreshRoot);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State.ToString()-in@('Running','Queued')}).Count-or
           @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Active/unknown guest worker blocks a new recovery/postcheck task.'}
        foreach($pin in @(@($RecordedStep.binary,$RecordedStep.binary_sha256),@($RequestPath,$RequestPin),@($TreePath,$TreePin),@($TicketPath,$TicketPin))){
            $item=Get-Item -LiteralPath $pin[0] -Force
            if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or(Get-FileHash -LiteralPath $pin[0] -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin[1]){throw 'Frozen postcheck input changed.'}
        }
        if((Get-Item -LiteralPath $RecordedStep.binary).Length-ne$BinaryBytes-or(Test-Path -LiteralPath $RecordedStep.output)-or(Get-ScheduledTask -TaskName $RecordedStep.task_name -ErrorAction SilentlyContinue)){throw 'Fresh task/output and frozen executable required.'}
        if(-not(Test-Path -LiteralPath $FreshRoot)){$null=[IO.Directory]::CreateDirectory($FreshRoot)}
        $rootItem=Get-Item -LiteralPath $FreshRoot -Force;if(-not$rootItem.PSIsContainer-or($rootItem.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary postcheck output directory required.'}
        $ancestor=$rootItem.Parent;while($ancestor){if($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Postcheck ancestry is a reparse point.'};$ancestor=$ancestor.Parent}
        $intent=Join-Path $FreshRoot ($RecordedStep.label+'-dispatch-intent.json')
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($RecordedStep|ConvertTo-Json -Depth 8))
        $file=[IO.File]::Open($intent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        $action=New-ScheduledTaskAction -Execute $RecordedStep.binary -Argument $RecordedStep.arguments
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        $null=Register-ScheduledTask -TaskName $RecordedStep.task_name -Action $action -Principal $principal -Settings $settings
        Start-ScheduledTask -TaskName $RecordedStep.task_name
    }
    return $step
}
function Assert-Verification([string]$Path,[bool]$AfterMutation){
    $record=Read-GuestJson $Path;$value=$record.value
    if($value.kind-cne'general-post-handoff-refs-verification'-or-not$value.success-or-not$value.ordinary_tree_verified-or
       -not$value.observation_complete-or$value.diagnostic_only-or$value.filesystem-cne'ReFS'-or$value.request_sha256-cne$requestPin-or
       $value.expected_tree_sha256-cne$treePin-or[bool]$value.post_mutation_root_policy-ne$AfterMutation-or
       ($AfterMutation-and$value.mutation_report_sha256-cne$mutationPin)-or($null-ne$value.error)){throw 'Strict native verification did not pass exact expected policy.'}
    Save-Record (Join-Path $postRoot ([IO.Path]::GetFileNameWithoutExtension($Path)+'-verified.json')) $record
}

$manifest=Read-HostJson (Join-Path $alphaRoot 'manifest.json')
$package=Read-HostJson (Join-Path $packageRoot 'alpha.json')
$frozenExecutables=@{
    'ntfs2refs.exe'=@(4927488L,'714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841')
    'lab-verify-general-converted.exe'=@(1457664L,'b81990282876a4bd2a8de1ab13f748588d623a3f5e36123ad225c9112a54564a')
    'lab-general-refs-mutation.exe'=@(1097728L,'f35175710403be6140bb668709a14ce3408b6513c18d3419a233c7232affe18c')
}
$dispatch=Read-HostJson (Join-Path $caseRoot 'dispatch.json')
$guestRun='C:\ntfs2refs\alpha\fault-runs\'+$CaseId
if([guid]$manifest.vm_id-ne$vmId-or$manifest.name-cne$vmName-or$manifest.root-cne$alphaRoot-or
   $package.tag-cne'alpha-native-shadow-20261026'-or$package.engine_commit-cne'96720eff89c7e808983c8d5c9800d475fe62515c'-or
   [guid]$dispatch.vm_id-ne$vmId-or[guid]$dispatch.checkpoint_id-ne$baselineId-or$dispatch.run_id-cne$CaseId-or
   $dispatch.case-cne'Resume'-or$dispatch.expected_exit_code-ne86-or$dispatch.guest_output-cne$guestRun-or
   $dispatch.task_name-cne('N2R-AlphaFault-Resume-'+$CaseId)-or$dispatch.entrypoint-cne'lab-controlled-interruption'-or
   $dispatch.binary_sha256-cne'129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'-or
   $dispatch.engine_commit-cne$package.engine_commit){throw 'Exact frozen alpha resume case binding differs.'}
Assert-Ordinary $caseRoot $true
if(Test-Path -LiteralPath (Join-Path $caseRoot 'resume-controller-intent.json')){throw 'Resume controller already has an intent; observe its existing tasks without redispatch.'}
$leasePath=Join-Path $alphaRoot 'active-alpha-controller.lock'
if(Test-Path -LiteralPath $leasePath){Assert-Ordinary $leasePath $false;if((Get-Item -LiteralPath $leasePath).Length-ne0){throw 'Alpha controller lease shape differs.'}}
$hostLease=[IO.File]::Open($leasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try{
    $null=Assert-AlphaVm
    foreach($name in @('ntfs2refs.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')){
        $row=@($package.executables|Where-Object {$_.name-ceq$name})
        $fixed=$frozenExecutables[$name]
        if($row.Count-ne1-or$row[0].bytes-ne$fixed[0]-or$row[0].sha256-cne$fixed[1]){throw 'Frozen executable row differs from this candidate.'}
        $path=Join-Path (Join-Path $packageRoot 'bin') $name;Assert-Ordinary $path $false
        if((Get-Item -LiteralPath $path).Length-ne$row[0].bytes-or(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row[0].sha256){throw 'Frozen host executable differs.'}
    }
    $null=[IO.Directory]::CreateDirectory($evidenceRoot);$null=[IO.Directory]::CreateDirectory($postRoot)
    Save-Record (Join-Path $caseRoot 'resume-controller-intent.json') ([ordered]@{schema_version=1;kind='native-shadow-alpha-resume-controller-intent';controller_id=$controllerId;case_id=$CaseId;vm_id=$vmId.ToString('D');engine_commit=$package.engine_commit;dispatch_sha256=(Get-FileHash -LiteralPath (Join-Path $caseRoot 'dispatch.json')).Hash.ToLowerInvariant();evidence_root=$evidenceRoot;postcheck_root=$postRoot;guest_postcheck=$guestPost;no_worker_retry=$true;no_checkpoint_restore=$true;started_utc=[DateTime]::UtcNow.ToString('o')})
    $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
    $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
    $ready=Invoke-Command -Session $session -ScriptBlock $guestReadiness;Save-Record (Join-Path $postRoot 'guest-before.json') $ready
    $phase='wait-controlled-first-write-producer';$deadline=[DateTime]::UtcNow.AddMinutes($MaximumWaitMinutes)
    while($true){
        $null=Assert-AlphaVm;$producer=Observe-Task $dispatch
        Write-Host ('Controlled producer: '+$producer.state+'; matching processes='+@($producer.processes).Count+'; result='+$producer.last_task_result)
        if($producer.terminal){Save-Record (Join-Path $postRoot 'producer-terminal.json') $producer
            if($producer.last_task_result-ne86){throw 'Producer did not exit at its controlled first-flushed-write point.'};break}
        if([DateTime]::UtcNow-ge$deadline){Save-Record (Join-Path $postRoot 'producer-observation-timeout.json') $producer;throw 'Producer status remains live/unknown; do not recover or redispatch.'}
        Start-Sleep -Seconds $PollSeconds
    }
    $phase='pin-existing-recovery-inputs';$requestPath=Join-Path $guestRun 'request.json';$ticketPath=Join-Path $guestRun 'ticket.json';$treePath=Join-Path $guestRun 'expectation.json'
    $request=Read-GuestJson $requestPath 128KB;$ticket=Read-GuestJson $ticketPath 64KB;$tree=Read-GuestJson $treePath
    $location=Read-GuestJson (Join-Path $guestRun 'journal-location.json') 128KB
    $interruption=Read-GuestJson (Join-Path $guestRun 'interruption-intent.json') 128KB
    $requestPin=$request.sha256;$ticketPin=$ticket.sha256;$treePin=$tree.sha256;$journalPath=[string]$location.value.path
    $reference=Read-HostJson (Join-Path $caseRoot 'input.json')
    if($request.value.expected_tree_sha256-cne$treePin-or$request.value.experiment_id-cne$CaseId-or
       $request.value.pair.source.disk_number-ne1-or$request.value.pair.shadow.disk_number-ne3-or$request.value.journal.disk.disk_number-ne2-or
       $request.value.pair.source.identity.partition_bytes-ne52GB-or$ticket.value.schema_version-ne1-or$ticket.value.binding.experiment_id-cne$CaseId-or
       [long]$ticket.value.immutable_length+8192-ne[long]$ticket.value.journal_length-or$ticket.value.journal_length-gt$request.value.max_journal_bytes-or
       $interruption.value.kind-cne'controlled-conversion-interruption-intent'-or$interruption.value.interrupt_after_writes-ne1-or
       $interruption.value.expected_process_exit_code-ne86-or$interruption.value.ticket_sha256-cne$ticketPin-or$interruption.value.journal_path-cne$journalPath-or
       $interruption.value.handoff_authorized-or$interruption.value.ordinary_conversion_behavior_changed){throw 'Interrupted recovery artifacts are inconsistent.'}
    $expectedJournal=$reference.journal.disk.volume_guid
    if($journalPath-cne('\\?\Volume{'+$expectedJournal+'}\ntfs2refs-shadow\'+$CaseId+'\reconstruction.journal')){throw 'Journal path is not the exact independent enrolled run.'}
    foreach($pair in @(@($request.value.pair.source,$reference.pair.source),@($request.value.pair.shadow,$reference.pair.shadow),@($request.value.journal.disk,$reference.journal.disk))){
        foreach($key in @('disk_number','volume_guid')){if($pair[0].$key-cne$pair[1].$key){throw 'Derived recovery route differs from producer input.'}}
        foreach($key in @('disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){if($pair[0].identity.$key-cne$pair[1].identity.$key){throw 'Derived recovery geometry/identity differs.'}}
    }
    $excluded=Invoke-Command -Session $session -ArgumentList ($request.value|ConvertTo-Json -Depth 16 -Compress),$journalPath,$ticket.value.journal_length -ScriptBlock {
        param($RequestJson,$Journal,$JournalLength);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$r=$RequestJson|ConvertFrom-Json
        foreach($pair in @(@($r.pair.source,$false),@($r.pair.shadow,$true))){
            $binding=$pair[0];$disk=Get-Disk -Number $binding.disk_number;$part=Get-Partition -DiskNumber $binding.disk_number -PartitionNumber $binding.identity.partition_number
            if(-not$disk.IsOffline-or[bool]$disk.IsReadOnly-ne[bool]$pair[1]-or$disk.IsBoot-or$disk.IsSystem-or
               [guid]$disk.Guid-ne[guid]$binding.identity.disk_guid-or[guid]$part.Guid-ne[guid]$binding.identity.partition_guid-or$part.Offset-ne$binding.identity.partition_offset-or$part.Size-ne$binding.identity.partition_bytes){throw 'Actual recovery disk exclusion or identity differs.'}
        }
        $item=Get-Item -LiteralPath $Journal -Force
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$JournalLength){throw 'Journal shape differs.'}
        $parent=$item.Directory;while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Journal reparse ancestry refused.'};$parent=$parent.Parent}
        $file=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$marker=New-Object byte[] 4096;$count=0;while($count-lt4096){$read=$file.Read($marker,$count,4096-$count);if($read-eq0){throw 'Short journal marker read.'};$count+=$read}
            foreach($value in $marker){if($value-ne0){throw 'Nonzero HND/rollback marker permanently blocks this initial forward-recovery test.'}}
        }finally{$file.Dispose()}
        [pscustomobject]@{source_offline=$true;source_readonly=$false;shadow_offline=$true;shadow_readonly=$true;complete_marker_region_zero=$true;journal_bytes=$JournalLength;observed_utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-Record (Join-Path $postRoot 'before-resume-exclusion.json') $excluded
    Save-Record (Join-Path $postRoot 'recovery-input-pins.json') @{request=$request;ticket=$ticket;expectation=$tree;journal_location=$location;interruption=$interruption}
    Copy-JsonTree $guestRun (Join-Path $evidenceRoot 'producer')
    $recovery='--request "'+$requestPath+'" --request-sha256 '+$requestPin+' --ticket "'+$ticketPath+'" --ticket-sha256 '+$ticketPin+' --journal "'+$journalPath+'"'
    $phase='public-resume';Capacity-Record 'resume';$resumeOutput=Join-Path $guestPost 'resume'
    $step=Start-Step 'resume' 'ntfs2refs.exe' ('resume '+$recovery+' --output "'+$resumeOutput+'"') $resumeOutput
    Wait-Step $step 'resume';$resumed=Read-GuestJson (Join-Path $resumeOutput 'result.json');$execution=Read-GuestJson (Join-Path $resumeOutput 'execution.json')
    if($resumed.value.kind-cne'general-recovery'-or-not$resumed.value.success-or$resumed.value.operation-cne'resume'-or-not$resumed.value.target_remains_offline-or$resumed.value.rollback_closed-or
       $execution.value.result.target_sha256-cne$execution.value.expected_target_sha256-or-not$execution.value.result.retained_bytes_unchanged-or$execution.value.result.handoff_recorded){throw 'Public resume did not prove its exact excluded postimage.'}
    $state=Invoke-Command -Session $session -ArgumentList $journalPath -ScriptBlock {
        param($Journal);$ErrorActionPreference='Stop';$source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if(-not$source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Post-resume exclusion differs.'}
        $file=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$marker=New-Object byte[] 4096;if($file.Read($marker,0,4096)-ne4096){throw 'Short post-resume marker read.'};foreach($value in $marker){if($value-ne0){throw 'Resume unexpectedly closed raw replay.'}}}finally{$file.Dispose()}
        @{source_offline=$true;source_readonly=$false;shadow_offline_readonly=$true;marker_zero=$true}
    }
    Save-Record (Join-Path $postRoot 'resume-verified.json') @{result=$resumed;execution=$execution;disk_state=$state}
    $phase='public-finalize';$finalOutput=Join-Path $guestPost 'finalize'
    $step=Start-Step 'finalize' 'ntfs2refs.exe' ('finalize '+$recovery+' --expectation "'+$treePath+'" --expectation-sha256 '+$treePin+' --output "'+$finalOutput+'"') $finalOutput
    Wait-Step $step 'finalize';$final=Read-GuestJson (Join-Path $finalOutput 'result.json');$completion=Read-GuestJson (Join-Path $finalOutput 'completion.json')
    if($final.value.kind-cne'general-recovery'-or-not$final.value.success-or$final.value.operation-cne'finalize'-or-not$final.value.rollback_closed-or
       -not$completion.value.success-or-not$completion.value.rollback_closed-or$null-eq$completion.value.native){throw 'Finalization did not close replay and prove its native target.'}
    Save-Record (Join-Path $postRoot 'finalize-verified.json') @{result=$final;completion=$completion}
    $common='--request "'+$requestPath+'" --request-sha256 '+$requestPin+' --expectation "'+$treePath+'" --expectation-sha256 '+$treePin
    $phase='strict-before-mutation';$verifyPath=Join-Path $guestPost 'before-mutation.json'
    $step=Start-Step 'strict-before' 'lab-verify-general-converted.exe' ($common+' --output "'+$verifyPath+'"') $verifyPath
    Wait-Step $step 'strict-before';Assert-Verification $verifyPath $false
    $phase='bounded-native-mutation';Capacity-Record 'mutation';$mutationRun=[guid]::NewGuid().ToString('N');$mutationPath=Join-Path $guestPost 'mutation.json'
    $step=Start-Step 'mutation' 'lab-general-refs-mutation.exe' ('--request "'+$requestPath+'" --request-sha256 '+$requestPin+' --run-id '+$mutationRun+' --output "'+$mutationPath+'"') $mutationPath
    Wait-Step $step 'mutation';$mutation=Read-GuestJson $mutationPath 8MB;$m=$mutation.value
    if($m.kind-cne'general-refs-mutation-workload'-or$m.run_id-cne$mutationRun-or$m.initial_bytes-ne50MB-or$m.grown_bytes-ne80MB-or$m.truncated_bytes-ne10MB-or
       $m.directory_entries_created-ne128-or-not$m.mutation_directory_removed-or-not$m.only_new_test_paths_written){throw 'Bounded mutation report is incomplete.'}
    $mutationPin=$mutation.sha256;Save-Record (Join-Path $postRoot 'mutation-pins.json') $mutation
    $afterArgs=$common+' --mutation-report "'+$mutationPath+'" --mutation-report-sha256 '+$mutationPin
    $phase='strict-after-mutation';$afterPath=Join-Path $guestPost 'after-mutation.json'
    $step=Start-Step 'strict-after' 'lab-verify-general-converted.exe' ($afterArgs+' --output "'+$afterPath+'"') $afterPath
    Wait-Step $step 'strict-after';Assert-Verification $afterPath $true
    Copy-JsonTree $guestPost (Join-Path $postRoot 'pre-reboot')
    $phase='clean-reboot';$null=Assert-AlphaVm;$beforeBoot=Invoke-Command -Session $session -ScriptBlock $guestReadiness
    Save-Record (Join-Path $postRoot 'reboot-intent.json') @{vm_id=$vmId.ToString('D');before_boot=$beforeBoot;mutation_sha256=$mutationPin;force=$false;requested_utc=[DateTime]::UtcNow.ToString('o')}
    try{$null=Invoke-Command -Session $session -ScriptBlock {Restart-Computer -ErrorAction Stop}}catch{Save-Record (Join-Path $postRoot 'reboot-transport.json') @{error=$_.Exception.ToString();completion_not_inferred=$true}}
    Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        $null=Assert-AlphaVm @('Running','Off','Starting','Stopping');$candidate=$null
        try{$candidate=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop;$afterBoot=Invoke-Command -Session $candidate -ScriptBlock $guestReadiness
            if([long]$afterBoot.boot_ticks-gt[long]$beforeBoot.boot_ticks){$session=$candidate}else{Remove-PSSession $candidate -ErrorAction SilentlyContinue}}
        catch{if($candidate){Remove-PSSession $candidate -ErrorAction SilentlyContinue};$candidate=$null}
        if($null-eq$session){Start-Sleep -Seconds $PollSeconds}
    }
    if($null-eq$session){throw 'Reboot completion was not established; no restart retry.'}
    Save-Record (Join-Path $postRoot 'reboot-observed.json') $afterBoot
    if((Read-GuestJson $mutationPath 8MB).sha256-cne$mutationPin){throw 'Mutation report changed across reboot.'}
    $phase='strict-after-reboot';$rebootPath=Join-Path $guestPost 'after-reboot.json'
    $step=Start-Step 'strict-reboot' 'lab-verify-general-converted.exe' ($afterArgs+' --output "'+$rebootPath+'"') $rebootPath
    Wait-Step $step 'strict-reboot';Assert-Verification $rebootPath $true
    Copy-JsonTree $guestPost (Join-Path $postRoot 'post-reboot')
    Save-Record (Join-Path $postRoot 'result.json') @{schema_version=1;kind='native-shadow-alpha-resume-completed';success=$true;controller_id=$controllerId;case_id=$CaseId;vm_id=$vmId.ToString('D');request_sha256=$requestPin;ticket_sha256=$ticketPin;expectation_sha256=$treePin;native_verified=$true;mutation_verified=$true;reboot_verified=$true;controlled_process_fault_only=$true;power_loss_qualified=$false;checkpoint_preservation_pending=$true}
    Write-Host ('Alpha resume, finalize, mutation and reboot passed. Preserve this live branch before restore. Evidence: '+$postRoot)
}catch{
    if(Test-Path -LiteralPath $postRoot){Save-Record (Join-Path $postRoot 'failed-preserved.json') @{phase=$phase;error=$_.Exception.ToString();controller_id=$controllerId;worker_termination_inferred=$false;automatic_recovery_attempted=$false;redispatch_allowed=$false;recorded_utc=[DateTime]::UtcNow.ToString('o')}}
    throw
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($hostLease){$hostLease.Dispose()}}
