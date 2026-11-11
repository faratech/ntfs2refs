# Source-only until explicitly invoked by the alpha coordinator. One recorded
# conversion, direct frozen binary tasks, clean reboot, then an OFF checkpoint.
# Never retries a worker, restores a checkpoint, replays recovery or forces OFF.
[CmdletBinding()]
param([ValidateRange(1,240)][int]$MaximumWaitMinutes=120,
      [ValidateRange(1,30)][int]$PollSeconds=15)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$alphaRoot=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$packageRoot=Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026'
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$vmName='ntfs2refs-shadow-alpha-20261026'
$baselineId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$normalRun='4ad0147fdde044fbb9d5073e5bfdbe8d'
$stage='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
$guestRun='C:\ntfs2refs\alpha\runs\'+$normalRun
$session=$null;$controllerId=[guid]::NewGuid().ToString('N')
$evidenceRoot=Join-Path $alphaRoot ('normal-evidence\'+$controllerId)
$postRoot=Join-Path $alphaRoot ('postcheck\'+$controllerId)
$guestPost='C:\ntfs2refs\alpha\postcheck\'+$controllerId
$phase='host-preflight'

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
    $null=Invoke-Command -Session $session -ArgumentList $step,$row[0].bytes,$requestPath,$requestPin,$treePath,$treePin,$guestPost -ScriptBlock {
        param($RecordedStep,$BinaryBytes,$RequestPath,$RequestPin,$TreePath,$TreePin,$FreshRoot);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State.ToString()-in@('Running','Queued')}).Count){throw 'Active guest worker blocks new postcheck.'}
        foreach($pin in @(@($RecordedStep.binary,$RecordedStep.binary_sha256),@($RequestPath,$RequestPin),@($TreePath,$TreePin))){
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
$dispatch=Read-HostJson (Join-Path $alphaRoot 'normal-dispatch.json')
$baseline=Read-HostJson (Join-Path $alphaRoot 'baseline.json')
$package=Read-HostJson (Join-Path $packageRoot 'alpha.json')
if([guid]$manifest.vm_id-ne$vmId-or$manifest.name-cne$vmName-or$manifest.root-cne$alphaRoot-or
   [guid]$baseline.vm_id-ne$vmId-or[guid]$baseline.checkpoint_id-ne$baselineId-or
   [guid]$dispatch.vm_id-ne$vmId-or[guid]$dispatch.checkpoint_id-ne$baselineId-or$dispatch.run_id-cne$normalRun-or
   $dispatch.task_name-cne('N2R-AlphaConvert-'+$normalRun)-or$dispatch.guest_output-cne$guestRun-or
   $dispatch.guest_input-cne(Join-Path $stage ('request-'+$normalRun+'.json'))-or$dispatch.entrypoint-cne'public-convert'-or
   $dispatch.request_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or
   $dispatch.binary_sha256-cne'714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'-or
   $package.tag-cne'alpha-native-shadow-20261026'-or$package.engine_commit-cne'96720eff89c7e808983c8d5c9800d475fe62515c'){throw 'Recorded alpha run/package/baseline binding differs.'}
$null=Assert-AlphaVm
foreach($name in @('ntfs2refs.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')){
    $row=@($package.executables|Where-Object {$_.name-ceq$name});if($row.Count-ne1-or$row[0].sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Frozen package executable pin missing.'}
    $path=Join-Path (Join-Path $packageRoot 'bin') $name;Assert-Ordinary $path $false
    if((Get-Item -LiteralPath $path).Length-ne$row[0].bytes-or(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row[0].sha256){throw 'Frozen host executable changed.'}
}
$null=[IO.Directory]::CreateDirectory($evidenceRoot);$null=[IO.Directory]::CreateDirectory($postRoot)
Save-Record (Join-Path $alphaRoot 'normal-completion-intent.json') ([ordered]@{schema_version=1;kind='native-shadow-alpha-normal-completion-intent';controller_id=$controllerId;vm_id=$vmId.ToString('D');baseline_checkpoint=$baselineId.ToString('D');dispatch=$dispatch;package_sha256=(Get-FileHash -LiteralPath (Join-Path $packageRoot 'alpha.json')).Hash.ToLowerInvariant();evidence_root=$evidenceRoot;postcheck_root=$postRoot;automatic_recovery=$false;started_utc=[DateTime]::UtcNow.ToString('o')})
try{
    $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
    $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
    $ready=Invoke-Command -Session $session -ScriptBlock $guestReadiness;Save-Record (Join-Path $postRoot 'guest-before.json') $ready
    $guestPins=Invoke-Command -Session $session -ArgumentList $stage,($package.executables|ConvertTo-Json -Depth 4 -Compress),$dispatch.guest_input,$dispatch.request_sha256 -ScriptBlock {
        param($StageRoot,$ExecutableRows,$OriginalInput,$OriginalPin);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $pins=@()
        foreach($row in ($ExecutableRows|ConvertFrom-Json)){
            if($row.name-cnotin@('ntfs2refs.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')){continue}
            $path=Join-Path $StageRoot $row.name;$item=Get-Item -LiteralPath $path -Force
            if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$row.bytes){throw 'Frozen guest executable shape differs.'}
            $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if($hash-cne$row.sha256){throw 'Frozen guest executable pin differs.'};$pins+=[pscustomobject]@{name=$row.name;sha256=$hash;bytes=$item.Length}
        }
        $inputItem=Get-Item -LiteralPath $OriginalInput -Force
        if($inputItem.PSIsContainer-or($inputItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$inputItem.Length-gt128KB-or
           (Get-FileHash -LiteralPath $OriginalInput -Algorithm SHA256).Hash.ToLowerInvariant()-cne$OriginalPin){throw 'Original public input pin differs.'}
        [pscustomobject]@{executables=$pins;public_input_sha256=$OriginalPin}
    }
    Save-Record (Join-Path $postRoot 'guest-frozen-input-pins.json') $guestPins
    $phase='wait-original-conversion'
    $normalStep=[pscustomobject]@{task_name=$dispatch.task_name;binary=(Join-Path $stage 'ntfs2refs.exe');arguments=('convert --request "'+$dispatch.guest_input+'" --request-sha256 '+$dispatch.request_sha256+' --output "'+$guestRun+'"')}
    Wait-Step $normalStep 'normal-conversion'
    $result=Read-GuestJson (Join-Path $guestRun 'result.json')
    if($result.value.kind-cne'certificate-backed-ntfs-refs-conversion'-or-not$result.value.success-or-not$result.value.source_admitted-or-not$result.value.rollback_closed){throw 'Original task has no successful conversion result; no recovery is authorized.'}
    $requestPath=Join-Path $guestRun 'request.json';$treePath=Join-Path $guestRun 'expectation.json'
    $request=Read-GuestJson $requestPath 128KB;$tree=Read-GuestJson $treePath
    $requestPin=$request.sha256;$treePin=$tree.sha256
    if($request.value.expected_tree_sha256-cne$treePin-or$result.value.expected_tree_sha256-cne$treePin-or
       $request.value.pair.source.disk_number-ne1-or$request.value.pair.shadow.disk_number-ne3-or$request.value.journal.disk.disk_number-ne2-or
       $request.value.pair.source.identity.partition_bytes-ne52GB){throw 'Derived conversion request/tree binding differs.'}
    Save-Record (Join-Path $evidenceRoot 'completed-input-pins.json') ([ordered]@{request_sha256=$requestPin;expectation_sha256=$treePin;result_sha256=$result.sha256;public_input_sha256=$dispatch.request_sha256})
    Copy-JsonTree $guestRun (Join-Path $evidenceRoot 'conversion')
    $common='--request "'+$requestPath+'" --request-sha256 '+$requestPin+' --expectation "'+$treePath+'" --expectation-sha256 '+$treePin
    $phase='strict-before-mutation';$verifyPath=Join-Path $guestPost 'before-mutation.json'
    $step=Start-Step 'strict-before' 'lab-verify-general-converted.exe' ($common+' --output "'+$verifyPath+'"') $verifyPath
    Wait-Step $step 'strict-before';Assert-Verification $verifyPath $false
    $phase='bounded-native-mutation';Capacity-Record 'mutation';$mutationRun=[guid]::NewGuid().ToString('N');$mutationPath=Join-Path $guestPost 'mutation.json'
    $mutationArgs='--request "'+$requestPath+'" --request-sha256 '+$requestPin+' --run-id '+$mutationRun+' --output "'+$mutationPath+'"'
    $step=Start-Step 'mutation' 'lab-general-refs-mutation.exe' $mutationArgs $mutationPath;Wait-Step $step 'mutation'
    $mutation=Read-GuestJson $mutationPath 8MB;$m=$mutation.value
    if($m.kind-cne'general-refs-mutation-workload'-or$m.run_id-cne$mutationRun-or$m.initial_bytes-ne50MB-or$m.grown_bytes-ne80MB-or
       $m.truncated_bytes-ne10MB-or$m.directory_entries_created-ne128-or-not$m.mutation_directory_removed-or-not$m.only_new_test_paths_written){throw 'Bounded mutation report is incomplete.'}
    $mutationPin=$mutation.sha256;Save-Record (Join-Path $postRoot 'mutation-pins.json') $mutation
    $afterArgs=$common+' --mutation-report "'+$mutationPath+'" --mutation-report-sha256 '+$mutationPin
    $phase='strict-after-mutation';$afterPath=Join-Path $guestPost 'after-mutation.json'
    $step=Start-Step 'strict-after' 'lab-verify-general-converted.exe' ($afterArgs+' --output "'+$afterPath+'"') $afterPath
    Wait-Step $step 'strict-after';Assert-Verification $afterPath $true
    Copy-JsonTree $guestPost (Join-Path $postRoot 'pre-reboot')
    $phase='clean-reboot';$null=Assert-AlphaVm;$beforeBoot=Invoke-Command -Session $session -ScriptBlock $guestReadiness
    Save-Record (Join-Path $postRoot 'reboot-intent.json') ([ordered]@{vm_id=$vmId.ToString('D');before_boot=$beforeBoot;mutation_sha256=$mutationPin;requested_utc=[DateTime]::UtcNow.ToString('o');force=$false})
    try{$null=Invoke-Command -Session $session -ScriptBlock {Restart-Computer -ErrorAction Stop}}catch{Save-Record (Join-Path $postRoot 'reboot-transport.json') @{error=$_.Exception.ToString();completion_not_inferred=$true}}
    Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        $null=Assert-AlphaVm @('Running','Off','Starting','Stopping')
        $candidate=$null
        try{$candidate=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
            $afterBoot=Invoke-Command -Session $candidate -ScriptBlock $guestReadiness
            if([long]$afterBoot.boot_ticks-gt[long]$beforeBoot.boot_ticks){$session=$candidate}else{Remove-PSSession $candidate -ErrorAction SilentlyContinue}
        }catch{if($candidate){Remove-PSSession $candidate -ErrorAction SilentlyContinue};$candidate=$null}
        if($null-eq$session){Start-Sleep -Seconds $PollSeconds}
    }
    if($null-eq$session){throw 'Reboot completion was not established by greater UTC boot ticks; no restart retry.'}
    Save-Record (Join-Path $postRoot 'reboot-observed.json') $afterBoot
    if((Read-GuestJson $mutationPath 8MB).sha256-cne$mutationPin){throw 'Exact mutation report changed across reboot.'}
    $phase='strict-after-reboot';$rebootPath=Join-Path $guestPost 'after-reboot.json'
    $step=Start-Step 'strict-reboot' 'lab-verify-general-converted.exe' ($afterArgs+' --output "'+$rebootPath+'"') $rebootPath
    Wait-Step $step 'strict-reboot';Assert-Verification $rebootPath $true
    Copy-JsonTree $guestPost (Join-Path $postRoot 'post-reboot')
    $phase='clean-shutdown';$null=Assert-AlphaVm;Capacity-Record 'checkpoint'
    Save-Record (Join-Path $postRoot 'shutdown-intent.json') @{vm_id=$vmId.ToString('D');force=$false;requested_utc=[DateTime]::UtcNow.ToString('o')}
    try{$null=Invoke-Command -Session $session -ScriptBlock {Stop-Computer -ErrorAction Stop}}catch{Save-Record (Join-Path $postRoot 'shutdown-transport.json') @{error=$_.Exception.ToString();off_not_inferred=$true}}
    Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(3)
    do{$off=Assert-AlphaVm @('Running','Stopping','Off');if($off.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds $PollSeconds}while([DateTime]::UtcNow-lt$deadline)
    if($off.State.ToString()-cne'Off'){throw 'Clean shutdown is unconfirmed; do not force OFF or checkpoint.'}
    $phase='preserve-off-checkpoint';$snapshotName='alpha-normal-converted-passed-'+$controllerId
    Save-Record (Join-Path $postRoot 'checkpoint-intent.json') @{vm_id=$vmId.ToString('D');name=$snapshotName;state='Off';parent_checkpoint=$baselineId.ToString('D')}
    $null=Checkpoint-VM -VM $off -SnapshotName $snapshotName -ErrorAction Stop
    $saved=@(Get-VMSnapshot -VM $off|Where-Object {$_.Name-ceq$snapshotName});$finalVm=Get-VM -Id $vmId
    if($saved.Count-ne1-or$saved[0].Id-eq[guid]::Empty-or[guid]$saved[0].ParentSnapshotId-ne$baselineId-or
       $finalVm.State.ToString()-cne'Off'-or[guid]$finalVm.ParentSnapshotId-ne$saved[0].Id){throw 'Exact OFF checkpoint preservation was not established.'}
    Save-Record (Join-Path $postRoot 'preserved-checkpoint.json') ([ordered]@{vm_id=$vmId.ToString('D');checkpoint_id=$saved[0].Id.ToString('D');name=$snapshotName;parent_checkpoint=$baselineId.ToString('D');state='Off';request_sha256=$requestPin;expectation_sha256=$treePin;mutation_sha256=$mutationPin;completed_utc=[DateTime]::UtcNow.ToString('o')})
    Save-Record (Join-Path $postRoot 'result.json') @{kind='native-shadow-alpha-normal-completed';success=$true;controller_id=$controllerId;vm_id=$vmId.ToString('D');state='Off';native_verified=$true;mutation_verified=$true;reboot_verified=$true;checkpoint_id=$saved[0].Id.ToString('D');recovery_qualified=$false;power_loss_qualified=$false}
    Write-Host ('Alpha normal conversion verified, mutated, reboot-verified and preserved OFF: '+$saved[0].Id)
}catch{
    Save-Record (Join-Path $postRoot 'failed-preserved.json') @{phase=$phase;error=$_.Exception.ToString();controller_id=$controllerId;automatic_recovery_attempted=$false;worker_termination_inferred=$false;recorded_utc=[DateTime]::UtcNow.ToString('o')}
    throw
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
