<# Pure host parser/policy checks. No VM access or native executables run. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$workspace=Split-Path -Parent $PSScriptRoot;$asts=@{}
foreach($relative in @('scripts/Dispatch-LabPublicPostcheck.ps1','scripts/Collect-LabPublicPostcheck.ps1')){
 $errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $relative),[ref]$null,[ref]$errors);if($errors){throw ($errors.Message-join'; ')};$asts[$relative]=$ast
 $commands=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
 foreach($name in @('Restore-VMSnapshot','Checkpoint-VM','Start-VM','Stop-VM','Restart-VM','Set-Disk','Format-Volume','Restart-Computer','Remove-Item','Move-Item','Mount-VHD','Dismount-VHD','Start-Process','Set-ExecutionPolicy','Set-AuthenticodeSignature','Add-Type','Invoke-Expression')){if($commands-contains$name){throw ('Forbidden transition/security command: '+$relative+'/'+$name)}}
 if($relative-like'*Collect-*'-and($commands-contains'Start-ScheduledTask'-or$commands-contains'Register-ScheduledTask')){throw 'Collector may not dispatch work.'}
 if($ast.Extent.Text.Contains('worker.ps1')-or$ast.Extent.Text.Contains('-ExecutionPolicy')-or$ast.Extent.Text.Contains('powershell.exe')){throw 'Guest script worker/security override is forbidden.'}
}
$dispatch=$asts['scripts/Dispatch-LabPublicPostcheck.ps1']
foreach($name in @('Test-ExpectedHandoff','Assert-NativePostcheckObservation','Assert-PostcheckMutation')){$functions=@($dispatch.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$false));if($functions.Count-ne1){throw 'Unique host policy helper absent.'};. ([scriptblock]::Create($functions[0].Extent.Text))}
$actions=@($dispatch.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-ceq'New-ScheduledTaskAction'},$true))
if($actions.Count-ne1-or-not$actions[0].Extent.Text.Contains('-Execute $Exe')){throw 'One direct native scheduled action required.'}
$immutable='12'*32;$target='ab'*32;$marker=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes('N2RHND01').CopyTo($marker,0);$marker[8]=3
for($i=0;$i-lt32;$i++){$marker[16+$i]=0x12;$marker[48+$i]=0xab}
$sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($marker,0,4064).CopyTo($marker,4064)}finally{$sha.Dispose()}
if(-not(Test-ExpectedHandoff $marker $immutable $target)){throw 'Complete HND refused.'}
$markerRefusals=0
foreach($case in @('magic','code','reserved','immutable','target','padding','digest','truncated','foreignTicket','foreignTarget')){
 $bad=[byte[]]$marker.Clone();$ih=$immutable;$th=$target
 switch($case){'magic'{$bad[0]=0};'code'{$bad[8]=4};'reserved'{$bad[9]=1};'immutable'{$bad[16]=0};'target'{$bad[48]=0};'padding'{$bad[800]=1};'digest'{$bad[4095]=$bad[4095]-bxor1};'truncated'{$bad=[byte[]]$bad[0..4094]};'foreignTicket'{$ih='0'*64};'foreignTarget'{$th='0'*64}}
 if(Test-ExpectedHandoff $bad $ih $th){throw ('Malformed/foreign HND accepted: '+$case)};$markerRefusals++
}
$disk={param($n,$g,$p,$bytes,$part)[ordered]@{number=$n;guid=$g;partitionGuid=$p;bytes=$bytes;partitionBytes=$part;offset=16MB;logical=512;physical=4096;offline=$false;readOnly=$false;boot=$false;system=$false;partitionBoot=$false;partitionSystem=$false;style='GPT'}}
$source=&$disk 1 'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa' '79eaccdf-38d3-4561-97cc-9276af5d223a' 64GB 52GB
$journal=&$disk 2 '04d5194b-f5db-43da-9b02-ed7a54325d56' '7435ee94-c435-403f-a515-dec1ccd5094e' 8GB (8GB-32MB)
$shadow=&$disk 3 '49dbc2d2-4120-4fbf-911d-0f8d58153598' 'e071a0c1-5f96-4327-85e8-da9b831e27d3' 64GB 52GB;$shadow.offline=$true;$shadow.readOnly=$true
$state=[ordered]@{computer='N2R-WIN11';systemDrive='C:';originalState='Ready';originalExit=0;originalRunYear=2026;activeTasks=@();activeWorkers=@();disks=@($source,$journal);driveLetter='F';letterDisk=1;letterPartition=2;filesystem='ReFS';clusterBytes=4096;labelUtf16=@(65);journalFilesystem='NTFS';shadowCount=1;shadow=$shadow;pins=@(@{name='verifier.exe';sha256='cd'*32});journalBytes=12288;markerBase64=[Convert]::ToBase64String($marker);bootUtcTicks=1000;prerequisite=$null}
$config=[ordered]@{operation='Verify';sourceOnlyAfterReboot=$false;sourceLabelUtf16=@(65);priorBootUtcTicks=0;journalLength=12288;immutableSha256=$immutable;expectedPostimageSha256=$target;pins=@(@{name='verifier.exe';sha256='cd'*32});prerequisiteTaskName=$null}
Assert-NativePostcheckObservation ([pscustomobject]$state) ([pscustomobject]$config)
$stateRefusals=0
foreach($case in @('liveTask','liveWorker','sourceIdentity','geometry','readonlySource','label','wrongMount','shadowWritable','missingShadow','journalLength','inputPin','bootContext')){
 $s=$state|ConvertTo-Json -Depth 10|ConvertFrom-Json;$c=$config|ConvertTo-Json -Depth 10|ConvertFrom-Json
 switch($case){'liveTask'{$s.activeTasks=@('N2R-other')};'liveWorker'{$s.activeWorkers=@(42)};'sourceIdentity'{$s.disks[0].guid='00000000-0000-0000-0000-000000000001'};'geometry'{$s.disks[0].offset=32MB};'readonlySource'{$s.disks[0].readOnly=$true};'label'{$s.labelUtf16=@(66)};'wrongMount'{$s.letterDisk=2};'shadowWritable'{$s.shadow.readOnly=$false};'missingShadow'{$s.shadowCount=0;$s.shadow=$null};'journalLength'{$s.journalBytes=8192};'inputPin'{$s.pins[0].sha256='00'*32};'bootContext'{$c.priorBootUtcTicks=999}}
 $refused=$false;try{Assert-NativePostcheckObservation $s $c}catch{$refused=$true};if(-not$refused){throw ('Unqualified state accepted: '+$case)};$stateRefusals++
}
$s=$state|ConvertTo-Json -Depth 10|ConvertFrom-Json;$c=$config|ConvertTo-Json -Depth 10|ConvertFrom-Json;$s.shadowCount=0;$s.shadow=$null;$c.sourceOnlyAfterReboot=$true;$c.priorBootUtcTicks=999
Assert-NativePostcheckObservation $s $c
$c.priorBootUtcTicks=1000;$refused=$false;try{Assert-NativePostcheckObservation $s $c}catch{$refused=$true};if(-not$refused){throw 'Same-boot source-only context accepted.'}
$before=[byte[]]::new(40);$m=[pscustomobject]@{kind='general-refs-mutation-workload';run_id='a'*32;initial_bytes=50MB;grown_bytes=80MB;truncated_bytes=10MB;directory_entries_created=128;mutation_directory_removed=$true;only_new_test_paths_written=$true;root_basic_before=$before;root_basic_after=[byte[]]$before.Clone()}
Assert-PostcheckMutation $m ('a'*32) ([Convert]::ToBase64String($before));$m.root_basic_after[32]=1;$refused=$false;try{Assert-PostcheckMutation $m ('a'*32) ([Convert]::ToBase64String($before))}catch{$refused=$true};if(-not$refused){throw 'Foreign root attribute change accepted.'}
[pscustomobject]@{syntaxFiles=$asts.Count;exactHandoffAccepted=$true;handoffRefusals=$markerRefusals;stateRefusals=$stateRefusals+1;rootPolicyRefusals=1;directNativeActions=$actions.Count;vmOperations=0;nativeExecutablesRun=0}
