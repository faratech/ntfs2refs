# Source/syntax only until explicitly invoked by the alpha coordinator. Dispatch
# ONE controlled producer after preserving the normal pass. Never stop a worker,
# detach a disk, run recovery, delete evidence or retry an uncertain dispatch.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Cancel','Resume','RollbackWithoutShadow')][string]$Case,
      [ValidatePattern('\A(?:[0-9a-f]{32})?\z')][string]$CaseId='',
      [ValidateRange(30,600)][int]$ReadinessTimeoutSeconds=240)
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
$engine='96720eff89c7e808983c8d5c9800d475fe62515c'
$publicPin='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'
$bindPin='6aa20fe55a47f34c8d360d95fa432e55ebc0b7e49d080d7bce09ea5d92126483'
$producerPin='129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'
$session=$null;$phase='host-preflight';$caseRoot=$null;$createdCaseRoot=$false;$startAttempted=$false;$hostLease=$null

function Assert-Ordinary([string]$Path,[bool]$Directory){
    $item=Get-Item -LiteralPath $Path -Force
    if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw ('Ordinary path required: '+$Path)}
    $parent=Split-Path $item.FullName -Parent
    while($parent){$entry=Get-Item -LiteralPath $parent -Force
        if(-not$entry.PSIsContainer-or($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Reparse/non-directory ancestry refused.'}
        $next=Split-Path $parent -Parent;if($next-ceq$parent){break};$parent=$next}
}
function Read-HostJson([string]$Path){
    Assert-Ordinary $Path $false
    if((Get-Item -LiteralPath $Path).Length-gt2MB){throw 'Bounded host JSON required.'}
    Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
}
function Save-Record([string]$Path,$Value){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24))
    if($bytes.Length-gt2MB){throw 'Bounded alpha record required.'}
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Assert-AlphaVm([string[]]$States,[guid]$Parent){
    $vm=Get-VM -Id $vmId -ErrorAction Stop
    if($vm.Name-cne$vmName-or-not$vm.Path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or
       $vm.State.ToString()-cnotin$States-or[guid]$vm.ParentSnapshotId-ne$Parent){throw 'Exact alpha VM state, path or checkpoint differs; no stop/reset fallback.'}
    if(@(Get-VMNetworkAdapter -VM $vm).Count-ne0-or$vm.AutomaticCheckpointsEnabled-or$vm.DynamicMemoryEnabled-or
       $vm.MemoryStartup-ne8GB-or(Get-VMProcessor -VM $vm).Count-ne4){throw 'Alpha isolation/resource profile differs.'}
    $drives=@(Get-VMHardDiskDrive -VM $vm)
    if($drives.Count-ne4){throw 'Exactly four owned alpha backing routes required.'}
    foreach($spec in $manifest.disks){
        $drive=@($drives|Where-Object {$_.ControllerType.ToString()-ceq$spec.controller-and$_.ControllerNumber-eq$spec.controller_number-and$_.ControllerLocation-eq$spec.controller_location})
        if($drive.Count-ne1){throw 'Alpha backing controller differs.'}
        $path=[string]$drive[0].Path;$seen=@{}
        while($true){
            if(-not$path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)-or$seen.Count-ge128){throw 'Backing ancestry escapes alpha ownership or is cyclic/unbounded.'}
            $seen[$path]=$true;Assert-Ordinary $path $false;$vhd=Get-VHD -Path $path -ErrorAction Stop
            if($vhd.Size-ne$spec.virtual_bytes){throw 'Alpha backing geometry differs.'}
            if([string]::IsNullOrEmpty([string]$vhd.ParentPath)){break};$path=[string]$vhd.ParentPath
        }
        if(-not[string]::Equals($path,[string]$spec.path,[StringComparison]::OrdinalIgnoreCase)-or[guid]$vhd.DiskIdentifier-ne[guid]$spec.vhd_id){throw 'Alpha backing root/container differs.'}
    }
    $vm
}
function Test-True($Value){($Value-is[bool])-and$Value}
function Capacity-Record([string]$Path){
    $capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes 2GB
    if($Path){Save-Record $Path $capacity}
}
$manifest=Read-HostJson (Join-Path $alphaRoot 'manifest.json')
$baseline=Read-HostJson (Join-Path $alphaRoot 'baseline.json')
$normalDispatch=Read-HostJson (Join-Path $alphaRoot 'normal-dispatch.json')
$completion=Read-HostJson (Join-Path $alphaRoot 'normal-completion-intent.json')
$package=Read-HostJson (Join-Path $packageRoot 'alpha.json')
if([guid]$manifest.vm_id-ne$vmId-or$manifest.name-cne$vmName-or$manifest.root-cne$alphaRoot-or@($manifest.disks).Count-ne4-or
   [guid]$baseline.vm_id-ne$vmId-or[guid]$baseline.checkpoint_id-ne$baselineId-or$baseline.name-cne'alpha-ntfs-baseline'-or$baseline.state-cne'Off'-or
   $package.tag-cne'alpha-native-shadow-20261026'-or$package.engine_commit-cne$engine-or
   [guid]$normalDispatch.vm_id-ne$vmId-or[guid]$normalDispatch.checkpoint_id-ne$baselineId-or$normalDispatch.run_id-cne$normalRun-or
   $normalDispatch.entrypoint-cne'public-convert'-or$normalDispatch.binary_sha256-cne$publicPin-or
   $completion.kind-cne'native-shadow-alpha-normal-completion-intent'-or[guid]$completion.vm_id-ne$vmId-or
   [guid]$completion.baseline_checkpoint-ne$baselineId-or$completion.controller_id-cnotmatch'\A[0-9a-f]{32}\z'-or
   $completion.dispatch.run_id-cne$normalRun){throw 'Frozen alpha ownership/baseline/normal completion identity differs.'}
$postRoot=Join-Path $alphaRoot ('postcheck\'+$completion.controller_id)
$normalEvidence=Join-Path $alphaRoot ('normal-evidence\'+$completion.controller_id)
if($completion.postcheck_root-cne$postRoot-or$completion.evidence_root-cne$normalEvidence-or
   (Get-FileHash -LiteralPath (Join-Path $packageRoot 'alpha.json') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$completion.package_sha256){throw 'Normal completion paths/package pin differ.'}
$normalResult=Read-HostJson (Join-Path $postRoot 'result.json')
$preserved=Read-HostJson (Join-Path $postRoot 'preserved-checkpoint.json')
$normalPins=Read-HostJson (Join-Path $normalEvidence 'completed-input-pins.json')
if($normalResult.kind-cne'native-shadow-alpha-normal-completed'-or-not(Test-True $normalResult.success)-or$normalResult.state-cne'Off'-or
   -not(Test-True $normalResult.native_verified)-or-not(Test-True $normalResult.mutation_verified)-or-not(Test-True $normalResult.reboot_verified)-or
   [guid]$normalResult.vm_id-ne$vmId-or$normalResult.controller_id-cne$completion.controller_id-or
   [guid]$normalResult.checkpoint_id-eq[guid]::Empty-or[guid]$preserved.checkpoint_id-ne[guid]$normalResult.checkpoint_id-or
   [guid]$preserved.vm_id-ne$vmId-or[guid]$preserved.parent_checkpoint-ne$baselineId-or$preserved.state-cne'Off'-or
   $preserved.request_sha256-cne$normalPins.request_sha256-or$preserved.expectation_sha256-cne$normalPins.expectation_sha256){throw 'Normal pass must be complete, natively checked, rebooted and preserved OFF before any fault case.'}
$passedId=[guid]$preserved.checkpoint_id
# This host copy survives restoring the older baseline. Never read the original
# normal-dispatch.guest_input after restore: that file did not exist at baseline.
$referencePath=Join-Path $normalEvidence 'conversion\request.json'
$reference=Read-HostJson $referencePath
if((Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$normalPins.request_sha256-or
   $reference.experiment_id-cne$normalRun-or$reference.pair.source.disk_number-ne1-or$reference.pair.shadow.disk_number-ne3-or
   $reference.journal.disk.disk_number-ne2-or$reference.max_journal_bytes-lt1-or$reference.max_journal_bytes-gt805306368){throw 'Exported original normal binding/request differs.'}
foreach($spec in @(@('ntfs2refs.exe',$publicPin),@('ntfs2refs-bind.exe',$bindPin),@('lab-convert-admitted-tree.exe',$producerPin))){
    $row=@($package.executables|Where-Object {$_.name-ceq$spec[0]})
    $path=Join-Path (Join-Path $packageRoot 'bin') $spec[0];Assert-Ordinary $path $false
    if($row.Count-ne1-or$row[0].sha256-cne$spec[1]-or(Get-Item -LiteralPath $path).Length-ne$row[0].bytes-or
       (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$spec[1]){throw 'Frozen host alpha executable changed.'}
}
Assert-Ordinary $alphaRoot $true
$lockPath=Join-Path $alphaRoot 'fault-dispatch.lock'
if(Test-Path -LiteralPath $lockPath){Assert-Ordinary $lockPath $false}
$hostLease=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$guestPreflight={
    param($FreshInputRoot,$FreshOutput,$ReferenceJson,$StageRoot,$PublicPin)
    Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    function Ordinary([string]$Path,[bool]$Directory){
        $item=Get-Item -LiteralPath $Path -Force
        if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest path required.'}
        $parent=Split-Path $item.FullName -Parent
        while($parent){$entry=Get-Item -LiteralPath $parent -Force;if(-not$entry.PSIsContainer-or($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest path ancestry differs.'};$next=Split-Path $parent -Parent;if($next-ceq$parent){break};$parent=$next}
    }
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or$version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or
       [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID-ne[guid]'87d4c43a-4299-460e-b973-b241f239d33f'-or
       (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Frozen alpha guest identity/build/driver differs.'}
    $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')})
    $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'-or([string]$_.CommandLine).IndexOf('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)-ge0})
    if($tasks.Count-or$processes.Count){throw 'Running/unknown N2R worker blocks fault dispatch; no stop/retry is allowed.'}
    $reference=$ReferenceJson|ConvertFrom-Json
    $bindings=@($reference.pair.source,$reference.pair.shadow,$reference.journal.disk)
    $roles=@(@('F','NTFS','n2r-alpha-source',1),@('R','ReFS','n2r-retained-shadow',3),@('J','NTFS','n2r-alpha-journal',2))
    for($i=0;$i-lt3;$i++){
        $role=$roles[$i];$expected=$bindings[$i];$parts=@(Get-Partition -DriveLetter $role[0] -ErrorAction Stop)
        if($parts.Count-ne1){throw 'Mounted alpha role is ambiguous.'};$part=$parts[0];$disk=Get-Disk -Number $part.DiskNumber -ErrorAction Stop;$volume=$part|Get-Volume -ErrorAction Stop
        if($part.DiskNumber-ne$role[3]-or$part.DiskNumber-ne$expected.disk_number-or$part.PartitionNumber-ne$expected.identity.partition_number-or
           [guid]$part.Guid-ne[guid]$expected.identity.partition_guid-or[guid]$disk.Guid-ne[guid]$expected.identity.disk_guid-or
           $part.Offset-ne$expected.identity.partition_offset-or$part.Size-ne$expected.identity.partition_bytes-or$disk.Size-ne$expected.identity.disk_bytes-or
           $disk.LogicalSectorSize-ne$expected.identity.logical_sector_bytes-or$disk.PhysicalSectorSize-ne$expected.identity.physical_sector_bytes-or
           $disk.PartitionStyle.ToString()-cne'GPT'-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
           $volume.FileSystem-cne$role[1]-or$volume.FileSystemLabel-cne$role[2]-or$volume.AllocationUnitSize-ne4096){throw 'Restored baseline F:/R:/J: binding or filesystem label differs.'}
    }
    Ordinary (Join-Path $StageRoot 'ntfs2refs.exe') $false
    if((Get-FileHash -LiteralPath (Join-Path $StageRoot 'ntfs2refs.exe') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$PublicPin){throw 'Baseline frozen public binary differs.'}
    if((Test-Path -LiteralPath $FreshInputRoot)-or(Test-Path -LiteralPath $FreshOutput)){throw 'Fresh guest case input/output required.'}
    Ordinary 'C:\ntfs2refs\alpha' $true
    foreach($parent in @('C:\ntfs2refs\alpha\fault-inputs','C:\ntfs2refs\alpha\fault-runs')){
        if(-not(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent)};Ordinary $parent $true
    }
    $null=New-Item -ItemType Directory -Path $FreshInputRoot;Ordinary $FreshInputRoot $true
    [pscustomobject]@{guest_identity_verified=$true;baseline_roles_matched=$true;running_n2r_workers=0;fresh_input_root=$FreshInputRoot;source_filesystem='NTFS';source_label='n2r-alpha-source';observed_utc=[DateTime]::UtcNow.ToString('o')}
}

try{
    $owned=Assert-AlphaVm @('Off') $passedId
    $saved=@(Get-VMSnapshot -VM $owned|Where-Object {$_.Id-eq$passedId})
    $base=@(Get-VMSnapshot -VM $owned|Where-Object {$_.Id-eq$baselineId})
    if($saved.Count-ne1-or$saved[0].Name-cne$preserved.name-or[guid]$saved[0].ParentSnapshotId-ne$baselineId-or
       $base.Count-ne1-or$base[0].Name-cne'alpha-ntfs-baseline'){throw 'Actual preserved normal/baseline checkpoint identity differs.'}
    Capacity-Record ''
    $run=if($CaseId){$CaseId}else{[guid]::NewGuid().ToString('N')}
    $cases=Join-Path $alphaRoot 'fault-cases'
    if(-not(Test-Path -LiteralPath $cases)){$null=[IO.Directory]::CreateDirectory($cases)};Assert-Ordinary $cases $true
    $caseRoot=Join-Path $cases $run
    if(Test-Path -LiteralPath $caseRoot){throw 'Case already exists; inspect its exact operation instead of redispatching.'}
    $null=New-Item -ItemType Directory -Path $caseRoot;$createdCaseRoot=$true;Assert-Ordinary $caseRoot $true
    $inputRoot='C:\ntfs2refs\alpha\fault-inputs\'+$run
    $guestInput=Join-Path $inputRoot 'request.json';$guestOutput='C:\ntfs2refs\alpha\fault-runs\'+$run
    $taskName='N2R-AlphaFault-'+$Case+'-'+$run
    $expectedExit=if($Case-ceq'Cancel'){87}else{86}
    Save-Record (Join-Path $caseRoot 'intent.json') ([ordered]@{schema_version=1;kind='native-shadow-alpha-fault-intent';case=$Case;vm_id=$vmId.ToString('D');run_id=$run;
        normal_controller_id=$completion.controller_id;preserved_normal_checkpoint=$passedId.ToString('D');restore_only_checkpoint=$baselineId.ToString('D');
        normal_result_sha256=(Get-FileHash -LiteralPath (Join-Path $postRoot 'result.json')).Hash.ToLowerInvariant();normal_checkpoint_sha256=(Get-FileHash -LiteralPath (Join-Path $postRoot 'preserved-checkpoint.json')).Hash.ToLowerInvariant();
        reference_request_sha256=$normalPins.request_sha256;guest_input=$guestInput;guest_output=$guestOutput;task_name=$taskName;expected_exit_code=$expectedExit;
        engine_commit=$engine;producer_sha256=$producerPin;recovery_attempted=$false;disk_detach_authorized=$false;deletions_authorized=$false;created_utc=[DateTime]::UtcNow.ToString('o')})
    Save-Record (Join-Path $caseRoot 'normal-binding-reference.json') $reference
    Capacity-Record (Join-Path $caseRoot 'before-restore-capacity.json')
    $phase='restore-owned-ntfs-baseline';$null=Assert-AlphaVm @('Off') $passedId
    Restore-VMSnapshot -VMSnapshot $base[0] -Confirm:$false -ErrorAction Stop
    $owned=Assert-AlphaVm @('Off') $baselineId
    if(@(Get-VMSnapshot -VM $owned|Where-Object {$_.Id-eq$passedId}).Count-ne1){throw 'Preserved normal checkpoint disappeared; no start is allowed.'}
    Save-Record (Join-Path $caseRoot 'baseline-restored.json') @{vm_id=$vmId.ToString('D');checkpoint_id=$baselineId.ToString('D');state='Off';normal_checkpoint_preserved=$true;observed_utc=[DateTime]::UtcNow.ToString('o')}
    $credentialPath=Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml';Assert-Ordinary $credentialPath $false
    $credential=Import-Clixml -LiteralPath $credentialPath
    $phase='start-baseline-once';Start-VM -VM $owned -ErrorAction Stop|Out-Null
    $phase='connect-owned-guest';$deadline=[DateTime]::UtcNow.AddSeconds($ReadinessTimeoutSeconds)
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        $null=Assert-AlphaVm @('Running','Starting') $baselineId
        try{$session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 3}
    }
    if($null-eq$session){throw 'Guest connection timed out; no second Start-VM or task redispatch.'}
    $phase='guest-baseline-bindings'
    $ready=Invoke-Command -Session $session -ArgumentList $inputRoot,$guestOutput,($reference|ConvertTo-Json -Depth 16 -Compress),$stage,$publicPin -ScriptBlock $guestPreflight
    Save-Record (Join-Path $caseRoot 'guest-preflight.json') $ready
    $phase='stage-frozen-fault-tools'
    $tools=@($package.executables|Where-Object {$_.name-cin@('ntfs2refs-bind.exe','lab-convert-admitted-tree.exe')})
    Save-Record (Join-Path $caseRoot 'staging-intent.json') @{guest_root=$inputRoot;executables=$tools;overwrite_existing=$false}
    foreach($tool in $tools){Copy-Item -LiteralPath (Join-Path (Join-Path $packageRoot 'bin') $tool.name) -Destination (Join-Path $inputRoot $tool.name) -ToSession $session -ErrorAction Stop}
    $phase='fresh-native-device-discovery'
    $bound=Invoke-Command -Session $session -ArgumentList $inputRoot,$guestInput,$guestOutput,$run,$bindPin,$producerPin,($reference|ConvertTo-Json -Depth 16 -Compress) -ScriptBlock {
        param($InputRoot,$InputFile,$Output,$Run,$BindPin,$ProducerPin,$ReferenceJson)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        function Ordinary([string]$Path){$item=Get-Item -LiteralPath $Path -Force
            if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary staged file required.'}
            $parent=$item.Directory;while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Staged file ancestry differs.'};$parent=$parent.Parent}}
        if(@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or
           @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Another N2R task/process is active or unknown.'}
        $binder=Join-Path $InputRoot 'ntfs2refs-bind.exe';$producer=Join-Path $InputRoot 'lab-convert-admitted-tree.exe'
        foreach($pin in @(@($binder,$BindPin),@($producer,$ProducerPin))){Ordinary $pin[0]
            if((Get-FileHash -LiteralPath $pin[0] -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin[1]){throw 'Frozen staged binary pin differs.'}}
        $evidence=Join-Path $InputRoot 'discovery.json'
        if((Test-Path -LiteralPath $InputFile)-or(Test-Path -LiteralPath $evidence)-or(Test-Path -LiteralPath $Output)){throw 'Fresh discovery input/evidence/output required.'}
        $original=$ReferenceJson|ConvertFrom-Json
        & $binder --source 'F:\' --shadow 'R:\' --journal 'J:\' --experiment-id $Run --max-journal-bytes ([long]$original.max_journal_bytes) --output $InputFile --evidence $evidence|Out-Null
        if($LASTEXITCODE-ne0){throw 'Frozen read-only binding discovery failed.'}
        Ordinary $InputFile;Ordinary $evidence
        if((Get-Item -LiteralPath $InputFile).Length-gt16384-or(Get-Item -LiteralPath $evidence).Length-gt8MB){throw 'Bounded fresh discovery output required.'}
        $fresh=Get-Content -LiteralPath $InputFile -Raw|ConvertFrom-Json
        if($fresh.schema_version-ne1-or$fresh.experiment_id-cne$Run-or$fresh.verify_existing_shadow-or$fresh.max_journal_bytes-ne$original.max_journal_bytes){throw 'Fresh producer input profile differs.'}
        $actual=@($fresh.pair.source,$fresh.pair.shadow,$fresh.journal.disk)
        $expected=@($original.pair.source,$original.pair.shadow,$original.journal.disk)
        for($i=0;$i-lt3;$i++){
            if($actual[$i].disk_number-ne$expected[$i].disk_number-or[guid]$actual[$i].volume_guid-ne[guid]$expected[$i].volume_guid){throw 'Fresh volume/disk routes differ from original baseline bindings.'}
            foreach($key in @('disk_guid','partition_guid')){if([guid]$actual[$i].identity.$key-ne[guid]$expected[$i].identity.$key){throw 'Fresh GPT identity differs.'}}
            foreach($key in @('partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){if($actual[$i].identity.$key-ne$expected[$i].identity.$key){throw ('Fresh device geometry differs: '+$key)}}
        }
        if($fresh.journal.externally_enrolled_disk_unique_id-cne$original.journal.externally_enrolled_disk_unique_id-or
           $fresh.journal.allow_additional_partitions-ne$original.journal.allow_additional_partitions){throw 'Independent journal enrollment differs.'}
        [pscustomobject]@{guest_input=$InputFile;input_bytes=(Get-Item -LiteralPath $InputFile).Length;
            request_sha256=(Get-FileHash -LiteralPath $InputFile -Algorithm SHA256).Hash.ToLowerInvariant();
            discovery_path=$evidence;discovery_sha256=(Get-FileHash -LiteralPath $evidence -Algorithm SHA256).Hash.ToLowerInvariant();
            binary=$producer;binary_sha256=$ProducerPin;binder_sha256=$BindPin;bindings_match_original=$true}
    }
    Save-Record (Join-Path $caseRoot 'binding-discovery.json') $bound
    foreach($file in @(@($guestInput,'input.json',$bound.request_sha256),@($bound.discovery_path,'discovery.json',$bound.discovery_sha256))){
        $destination=Join-Path $caseRoot $file[1]
        Copy-Item -LiteralPath $file[0] -Destination $destination -FromSession $session -ErrorAction Stop;Assert-Ordinary $destination $false
        if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()-cne$file[2]){throw 'Fresh discovery export changed.'}
    }
    $arguments='--request "'+$guestInput+'" --request-sha256 '+$bound.request_sha256+' --output "'+$guestOutput+'"'
    if($Case-ceq'Cancel'){$arguments+=' --interrupt-after-source-freeze'}else{$arguments+=' --interrupt-after-writes 1'}
    $dispatch=[ordered]@{schema_version=1;case=$Case;vm_id=$vmId.ToString('D');checkpoint_id=$baselineId.ToString('D');run_id=$run;
        task_name=$taskName;guest_output=$guestOutput;guest_input=$guestInput;request_sha256=$bound.request_sha256;binary_sha256=$producerPin;
        expected_exit_code=$expectedExit;entrypoint='lab-controlled-interruption';dispatched_utc=[DateTime]::UtcNow.ToString('o');
        binary=$bound.binary;arguments=$arguments;guest_input_root=$inputRoot;preserved_normal_checkpoint=$passedId.ToString('D');
        binder_sha256=$bindPin;engine_commit=$engine;dispatch_recorded_before_start=$true;recovery_authorized=$false;shadow_detach_authorized=$false}
    Capacity-Record (Join-Path $caseRoot 'before-dispatch-capacity.json')
    $null=Assert-AlphaVm @('Running') $baselineId
    Save-Record (Join-Path $caseRoot 'dispatch.json') $dispatch
    $phase='persist-guest-dispatch-register-only'
    $registration=Invoke-Command -Session $session -ArgumentList ($dispatch|ConvertTo-Json -Depth 8 -Compress) -ScriptBlock {
        param($DispatchJson);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$d=$DispatchJson|ConvertFrom-Json
        if(@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or
           @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Active/unknown lab worker prevents task registration.'}
        if((Test-Path -LiteralPath $d.guest_output)-or(Get-ScheduledTask -TaskName $d.task_name -ErrorAction SilentlyContinue)){throw 'Fresh fault task/output required.'}
        foreach($pin in @(@($d.binary,$d.binary_sha256),@($d.guest_input,$d.request_sha256))){
            $item=Get-Item -LiteralPath $pin[0] -Force;$parent=$item.Directory
            if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary frozen task input required.'}
            while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Task input ancestry differs.'};$parent=$parent.Parent}
            if((Get-FileHash -LiteralPath $pin[0] -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin[1]){throw 'Frozen task input changed.'}
        }
        $path=Join-Path $d.guest_input_root 'dispatch.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes($DispatchJson)
        $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        $action=New-ScheduledTaskAction -Execute $d.binary -Argument $d.arguments
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        $null=Register-ScheduledTask -TaskName $d.task_name -Action $action -Principal $principal -Settings $settings
        [pscustomobject]@{task_name=$d.task_name;guest_dispatch_path=$path;guest_dispatch_sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();registered=$true;start_requested=$false}
    }
    Save-Record (Join-Path $caseRoot 'registered.json') $registration
    $phase='start-recorded-task-once';$null=Assert-AlphaVm @('Running') $baselineId;$startAttempted=$true
    $started=Invoke-Command -Session $session -ArgumentList ($dispatch|ConvertTo-Json -Depth 8 -Compress) -ScriptBlock {
        param($DispatchJson);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$d=$DispatchJson|ConvertFrom-Json
        $task=Get-ScheduledTask -TaskName $d.task_name -ErrorAction Stop;$actions=@($task.Actions)
        if($task.State.ToString()-cne'Ready'-or$actions.Count-ne1-or$actions[0].Execute-cne$d.binary-or$actions[0].Arguments-cne$d.arguments-or
           $task.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$task.Principal.RunLevel.ToString()-cne'Highest'){throw 'Recorded direct SYSTEM task differs or is not Ready.'}
        if(@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$d.task_name-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or
           @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Another live/unknown N2R worker blocks start.'}
        if((Test-Path -LiteralPath $d.guest_output)-or(Get-FileHash -LiteralPath $d.binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.binary_sha256-or
           (Get-FileHash -LiteralPath $d.guest_input -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.request_sha256){throw 'Fresh output/frozen inputs differ immediately before task start.'}
        Start-ScheduledTask -TaskName $d.task_name -ErrorAction Stop
        [pscustomobject]@{task_name=$d.task_name;start_command_returned=$true;completion_inferred=$false;expected_exit_code=$d.expected_exit_code;observed_utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-Record (Join-Path $caseRoot 'start-returned.json') $started
    [pscustomobject]@{status='fault-producer-dispatched';case=$Case;dispatch_directory=$caseRoot;dispatch=$dispatch;completion_inferred=$false;recovery_attempted=$false}
}catch{
    if($createdCaseRoot-and(Test-Path -LiteralPath $caseRoot)){
        Save-Record (Join-Path $caseRoot 'failed-preserved.json') @{phase=$phase;error=$_.Exception.ToString();start_attempted=$startAttempted;
            worker_termination_inferred=$false;automatic_recovery_attempted=$false;redispatch_allowed=$false;recorded_utc=[DateTime]::UtcNow.ToString('o')}
    }
    throw
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($hostLease){$hostLease.Dispose()}}
