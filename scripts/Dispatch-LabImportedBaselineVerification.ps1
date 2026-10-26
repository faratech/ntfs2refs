<# Dispatch one read-only baseline verifier. Does not create/import/attach disks,
   change attributes, restore checkpoints or retry an existing operation. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ImportDirectory,
 [Parameter(Mandatory)][string]$GuestImportDirectory,
 [Parameter(Mandatory)][guid]$ExpectedCheckpointId)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$vm=Get-OwnedLabVM $cfg (Read-LabManifest $cfg win11)
if($vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne$ExpectedCheckpointId){throw 'Exact running owned baseline branch required.'}
$import=Assert-LabPath $ImportDirectory $cfg.Root
if($GuestImportDirectory-cnotmatch'\AC:\\ntfs2refs\\[a-zA-Z0-9_.\\-]{1,500}\z'-or$GuestImportDirectory.Contains('..')-or$GuestImportDirectory.EndsWith('\')){throw 'Canonical C: guest import directory required.'}
$verifier=Join-Path $workspace 'lab/guest/Test-ImportedBaseline.ps1';$helper=Join-Path $workspace 'lab/guest/NativeImportedReference.cs'
$pins=@();$values=@{}
foreach($name in @('request.json','import.json','prepared.json','handoff.json','result.json')){
 $path=Join-Path $import $name;$f=Get-Item -LiteralPath $path -Force
 if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-lt1-or$f.Length-gt1MB){throw 'Bounded ordinary exported baseline proof required.'}
 $pins+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()};$values[$name]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
}
if('Ntfs2RefsResearch.NativeImportedReference'-as[type]){throw 'Fresh host process required for pinned proof validation.'}
Add-Type -Path $helper
$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($verifier,[ref]$null,[ref]$errors)
if($errors.Count){throw 'Baseline guest verifier syntax differs.'}
$validate=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Assert-BaselineProofs'},$true)
if(-not$validate){throw 'Baseline proof validator absent.'};. ([scriptblock]::Create($validate.Extent.Text))
$r=$values['request.json'];$binding=Assert-BaselineProofs $r $values['import.json'] $values['prepared.json'] $values['handoff.json'] $values['result.json'] $r.binding.vhd_path $r.binding.disk_number
$step=[guid]::NewGuid().ToString('N');$task='N2R-BaselineVerify-'+$step
$root='C:\ntfs2refs\baseline-verification-inputs\'+$step;$guestOutput=$root+'\evidence'
$directory=Assert-LabPath (Join-Path $cfg.Root ('baseline-native-verification/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $directory|Out-Null
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$file=[IO.File]::Open((Join-Path $directory $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$helperSha=(Get-FileHash -LiteralPath $helper).Hash.ToLowerInvariant();$verifierSha=(Get-FileHash -LiteralPath $verifier).Hash.ToLowerInvariant()
Save 'dispatch.json' ([ordered]@{schemaVersion=1;kind='unmodified-reference-native-verification-dispatch';stepId=$step;taskName=$task;vmId=[string]$vm.Id;checkpointId=[string]$ExpectedCheckpointId;importDirectory=$import;guestImportDirectory=$GuestImportDirectory;guestRoot=$root;guestOutput=$guestOutput;referencePath=$binding.vhd_path;persistentVhdId=$binding.persistent_vhd_id;diskNumber=$binding.disk_number;baselineOnly=$true;adoptedFileExpected=$false;helperSha256=$helperSha;verifierSha256=$verifierSha;importProofPins=$pins;startedUtc=[DateTime]::UtcNow.ToString('o')})
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $preflight=Invoke-Command -Session $session -ArgumentList @($GuestImportDirectory,$pins,$binding,$root) -ScriptBlock {
  param($Import,$Pins,$Binding,$Root);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Owned guest without active lab operation required.'}
  foreach($pin in $Pins){$path=Join-Path $Import $pin.name;$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt1MB-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Guest baseline proof differs from independently exported pin.'}}
  $n=[int]$Binding.disk_number;$d=Get-Disk -Number $n;$p=Get-Partition -DiskNumber $n -PartitionNumber 2
  if($n-lt3-or$n-gt63-or$d.IsBoot-or$d.IsSystem-or$d.IsOffline-or[guid]$d.Guid-ne[guid]'b4ab4dbc-6bd7-4199-8e4a-01b828e98584'-or[guid]$p.Guid-ne[guid]'00c9f113-e0b9-49d8-b031-130aef8ef3fb'-or$p.Offset-ne16MB-or$p.Size-ne52GB){throw 'Online baseline source route differs.'}
  $v=@($p|Get-Volume);if($v.Count-ne1-or[string]$v[0].UniqueId-cnotmatch'\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'){throw 'Canonical baseline volume root is unavailable; preserve native mount failure separately.'}
  if(Test-Path -LiteralPath $Root){throw 'Fresh guest verification root required.'};New-Item -ItemType Directory -Path $Root|Out-Null
  [pscustomobject]@{volumeRoot=[string]$v[0].UniqueId;fileSystem=[string]$v[0].FileSystem;diskNumber=$n;diskReadOnly=$d.IsReadOnly;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 Copy-Item -LiteralPath $helper -Destination ($root+'\NativeImportedReference.cs') -ToSession $session
 Copy-Item -LiteralPath $verifier -Destination ($root+'\Test-ImportedBaseline.ps1') -ToSession $session
 $map=@{};foreach($pin in $pins){$map[$pin.name]=$pin.sha256}
 # The canonical GUID root contains no whitespace. Keep it unquoted so its
 # trailing backslash cannot escape a closing quote in native argv parsing.
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$root+'\Test-ImportedBaseline.ps1" -ImportDirectory "'+$GuestImportDirectory+'" -RequestSha256 '+$map['request.json']+' -ImportSha256 '+$map['import.json']+' -PreparedSha256 '+$map['prepared.json']+' -HandoffSha256 '+$map['handoff.json']+' -ResultSha256 '+$map['result.json']+' -ReferencePath "'+$binding.vhd_path+'" -VolumeRoot '+$preflight.volumeRoot+' -DiskNumber '+$binding.disk_number+' -VerificationId '+$step+' -HelperSha256 '+$helperSha+' -OutputDirectory "'+$guestOutput+'"'
 $started=Invoke-Command -Session $session -ArgumentList @($root,$task,$arguments,$helperSha,$verifierSha) -ScriptBlock {
  param($Root,$Task,$Arguments,$HelperSha,$VerifierSha);$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath ($Root+'\NativeImportedReference.cs')).Hash.ToLowerInvariant()-cne$HelperSha-or(Get-FileHash -LiteralPath ($Root+'\Test-ImportedBaseline.ps1')).Hash.ToLowerInvariant()-cne$VerifierSha){throw 'Copied native verifier differs.'}
  if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another lab operation started before verification.'}
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $Arguments
  Register-ScheduledTask -TaskName $Task -Action $action -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null;Start-ScheduledTask -TaskName $Task
  [pscustomobject]@{taskName=$Task;state=[string](Get-ScheduledTask -TaskName $Task).State;guestOutput=$Root+'\evidence';dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'task.json' $started
 [pscustomobject]@{directory=$directory;taskName=$task;guestOutput=$guestOutput;state=$started.state;baselineOnly=$true;adoptedFileExpected=$false}
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
