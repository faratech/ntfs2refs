# Pinned native post-handoff checks only. Never replays a journal or restores a VM.
[CmdletBinding()]param([Parameter(Mandatory)][ValidateSet('BootVerify','Mutate','AfterMutation','RebootVerify','Preserve')][string]$Phase)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$parent=[guid]'f5adf4aa-ef43-4201-9ad1-8eec3b495405'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-postcheck-20261028'
$request='J:\n2r-compact-journal-a1aa7a957b094f7bbe9af154ee7270eb\request.json';$requestPin='33d18d9f77ebeba339feb71cc4471852bb2c3f3b6edc283fff93fc3f9d7e27d7'
$expected='C:\ntfs2refs\private-tree-3c9f174567bf48f5b9957e3f1ec48011\expectation.json';$treePin='1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215'
$converted='C:\ntfs2refs\compact-apply-c75ec9ec8a104f99b630c92343b44ca1\result'
$toolsRoot=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate12\rust-postcheck-tools-v2'
$tools=@(@{name='lab-verify-general-converted.exe';bytes=1596928;sha256='8f3675076a34bd977245744af702c82d7bf2b6c662e757246b153fcaf6840f9a'},@{name='lab-general-refs-mutation.exe';bytes=1112064;sha256='0c9fa6caaff35c2d56cc2e6f83db0d4a5ed0622fc2d98446e74f0c591e2485dd'})
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 28));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Previous([string]$Name){$v=Get-Content (Join-Path $root ($Name+'.json')) -Raw -Encoding UTF8|ConvertFrom-Json;if(-not$v.success){throw 'Successful prior phase required.'};return $v}
function Boot-UTC($Value){if($Value-is[DateTime]){if($Value.Kind-eq[DateTimeKind]::Unspecified){throw 'Boot timezone missing.'};return $Value.ToUniversalTime().ToString('o')};if($Value-is[DateTimeOffset]){return $Value.UtcDateTime.ToString('o')};if([string]$Value-cnotmatch'(Z|[+-][0-9]{2}:[0-9]{2})$'){throw 'Explicit boot timezone required.'};return [DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.ToString('o')}
$vm=Get-VM -Id $id;$ids=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.ParentSnapshotId-ne$parent-or$ids.Count-ne37-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact converted branch/all37 checkpoints required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes $(if($Phase-in@('BootVerify','RebootVerify')){1GB}else{256MB})
foreach($tool in $tools){$p=Join-Path $toolsRoot $tool.name;if((Get-Item $p).Length-ne$tool.bytes-or(Get-FileHash $p).Hash.ToLowerInvariant()-cne$tool.sha256){throw 'Toolset2 pin differs.'}}
if($Phase-ceq'BootVerify'){
    if($vm.State.ToString()-cne'Off'-or(Test-Path $root)){throw 'Fresh OFF branch/postcheck root required.'}
    New-Item -ItemType Directory -Path $root|Out-Null;$run=[guid]::NewGuid().ToString('N')
    Save-New 'intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$ids;tools=$tools;journal_replay_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
}else{$intent=Get-Content (Join-Path $root 'intent.json') -Raw -Encoding UTF8|ConvertFrom-Json;$run=$intent.run_id;if([guid]$intent.vm_id-ne$id-or@($intent.old_checkpoint_ids|Where-Object {$_-notin$ids}).Count){throw 'Enrollment differs.'}}
$stage='C:\ntfs2refs\compact-postcheck-'+$run
if(Test-Path (Join-Path $root ($Phase+'-intent.json'))){throw 'Phase has state; inspect without redispatch.'}
$prior=$null;if($Phase-cne'BootVerify'){$prior=Previous $(switch($Phase){'Mutate'{'BootVerify'}'AfterMutation'{'Mutate'}'RebootVerify'{'AfterMutation'}'Preserve'{'RebootVerify'}})}
Save-New ($Phase+'-intent.json') @{run_id=$run;phase=$Phase;capacity=$capacity;utc=[DateTime]::UtcNow.ToString('o')}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
if($Phase-in@('RebootVerify','Preserve')){
    if($vm.State.ToString()-cne'Running'){throw 'Completed running branch required for clean shutdown.'}
    Invoke-Command -VMId $id -Credential $credential -ScriptBlock {if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('lab-verify-general-converted.exe','lab-general-refs-mutation.exe','lab-apply-compact-fixture.exe')}).Count){throw 'Worker active; no shutdown.'}}
    Stop-VM -VM $vm;$vm=Get-VM -Id $id
    if($vm.State.ToString()-cne'Off'-or$vm.MemoryAssigned-ne0){throw 'Clean OFF not observed; do not stop twice.'}
    if($Phase-ceq'Preserve'){
        $cp=Checkpoint-VM -VM $vm -SnapshotName 'streaming-v2-compact-reboot-mutation-passed' -Passthru;$new=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
        if($new.Count-ne38-or@($ids|Where-Object {$_-notin$new}).Count){throw 'Checkpoint preservation differs.'}
        Save-New 'Preserve.json' @{success=$true;run_id=$run;checkpoint_id=$cp.Id.ToString();parent_id=$parent.ToString();checkpoint_count=$new.Count;all_prior_preserved=$true;state='Off';memory_assigned=0;utc=[DateTime]::UtcNow.ToString('o')}
        Write-Output 'Postcheck branch preserved OFF; all38 checkpoints retained.';return
    }
}
if($Phase-in@('BootVerify','RebootVerify')){Start-VM -VM $vm|Out-Null}elseif($vm.State.ToString()-cne'Running'){throw 'Use the existing running branch.'}
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot/session not ready; observe without another reboot.'};Start-Sleep -Seconds 3}}
try{
    if($Phase-ceq'BootVerify'){
        Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock {param($Stage);if(Test-Path $Stage){throw 'Fresh guest stage required.'};New-Item -ItemType Directory -Path $Stage|Out-Null}
        foreach($tool in $tools){Copy-Item -LiteralPath (Join-Path $toolsRoot $tool.name) -ToSession $s -Destination ([IO.Path]::Combine($stage,$tool.name))}
    }
    $mutation=if($Phase-in@('AfterMutation','RebootVerify')){Previous 'Mutate'}else{$null}
    $priorBoot=if($Phase-ceq'RebootVerify'){Boot-UTC $prior.guest_boot_utc}else{''}
    $result=Invoke-Command -Session $s -ArgumentList $Phase,$stage,$run,$request,$expected,$converted,$requestPin,$treePin,($tools|ConvertTo-Json -Compress),$priorBoot,($mutation|ConvertTo-Json -Compress -Depth 8) -ScriptBlock {
        param($Phase,$Stage,$Run,$Request,$Expected,$Converted,$RequestPin,$TreePin,$ToolsJson,$PriorBoot,$MutationJson);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        foreach($tool in ($ToolsJson|ConvertFrom-Json)){$p=Join-Path $Stage $tool.name;if((Get-Item $p).Length-ne$tool.bytes-or(Get-FileHash $p).Hash.ToLowerInvariant()-cne$tool.sha256){throw 'Guest tool pin differs.'}}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('lab-apply-compact-fixture.exe','lab-prepare-compact-journal.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')}).Count){throw 'Worker already active.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$volume=Get-Partition -DiskNumber 1|Where-Object Offset -eq 16MB|Get-Volume
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$volume.FileSystem-cne'ReFS'-or$volume.AllocationUnitSize-ne4096-or$volume.FileSystemLabel-cne'n2r-stream-source'){throw 'Converted source/frozen shadow differs.'}
        $handoff=Get-Content (Join-Path $Converted 'finalization.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if(-not$handoff.success-or-not$handoff.rollback_closed-or-not$handoff.handoff.handoff_recorded){throw 'Closed successful handoff required; never replay.'}
        if((Get-FileHash $Request).Hash.ToLowerInvariant()-cne$RequestPin-or(Get-FileHash $Expected).Hash.ToLowerInvariant()-cne$TreePin){throw 'Request/tree pins differ.'}
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        if($Phase-ceq'RebootVerify'-and[DateTimeOffset]::Parse($boot)-le[DateTimeOffset]::Parse($PriorBoot)){throw 'Fresh post-mutation boot required.'}
        $report=Join-Path $Stage ($Phase+'.json');if(Test-Path $report){throw 'Guest report already exists; do not repeat.'}
        $cli=@('--request',$Request,'--request-sha256',$RequestPin,'--output',$report)
        if($Phase-ceq'Mutate'){$binary=Join-Path $Stage 'lab-general-refs-mutation.exe';$cli+=@('--run-id',$Run)}else{
            $binary=Join-Path $Stage 'lab-verify-general-converted.exe';$cli+=@('--expectation',$Expected,'--expectation-sha256',$TreePin)
            if($Phase-in@('AfterMutation','RebootVerify')){$m=$MutationJson|ConvertFrom-Json;$cli+=@('--mutation-report',$m.guest_report,'--mutation-report-sha256',$m.report_sha256)}
        }
        $ErrorActionPreference='Continue';$log=@(& $binary @cli 2>&1);$exit=$LASTEXITCODE;$ErrorActionPreference='Stop'
        $log|Out-String|Set-Content (Join-Path $Stage ($Phase+'.log')) -Encoding UTF8
        if($exit-ne0){throw ('Native '+$Phase+' refused; preserve report/log without repeating.')}
        $value=Get-Content $report -Raw -Encoding UTF8|ConvertFrom-Json
        if($Phase-ceq'Mutate'){if($value.kind-cne'general-refs-mutation-workload'-or$value.request_sha256-cne$RequestPin-or-not$value.only_new_test_paths_written-or-not$value.mutation_directory_removed){throw 'Mutation result scope differs.'}}
        elseif(-not$value.success-or-not$value.ordinary_tree_verified-or$value.diagnostic_only-or$value.request_sha256-cne$RequestPin){throw 'Strict full-tree verification did not pass.'}
        Set-StrictMode -Off
        @{success=$true;phase=$Phase;run_id=$Run;guest_report=$report;report_sha256=(Get-FileHash $report).Hash.ToLowerInvariant();guest_boot_utc=$boot;request_sha256=$RequestPin;expectation_sha256=$TreePin;retained_position_proof_included=$false;native_report=$value;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New ($Phase+'.json') $result
    foreach($name in @($Phase+'.json',$Phase+'.log')){Copy-Item -FromSession $s -LiteralPath ([IO.Path]::Combine($stage,$name)) -Destination (Join-Path $root ('guest-'+$name))}
    if((Get-FileHash (Join-Path $root ('guest-'+$Phase+'.json'))).Hash.ToLowerInvariant()-cne$result.report_sha256){throw 'Archived native report differs.'}
    [pscustomobject]@{phase=$Phase;success=$true;report_sha256=$result.report_sha256;guest_boot_utc=$result.guest_boot_utc}|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
