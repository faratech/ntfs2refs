<# Parse and mock only. Never import the lab module or open a VM/device. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Detach-LabInterruptedShadow.ps1'),[ref]$tokens,[ref]$errors)
if($errors){throw ($errors|Out-String)}
$commands=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
foreach($forbidden in @('Restore-VMSnapshot','Checkpoint-VM','Start-VM','Stop-VM','Restart-VM','Remove-Item','Move-Item','Set-Disk','Format-Volume','Restart-Computer','Start-Process','Mount-VHD','Dismount-VHD','Register-ScheduledTask','Start-ScheduledTask')){if($commands-contains$forbidden){throw ('Forbidden detach-wrapper command: '+$forbidden)}}
$methods=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Expression.Extent.Text-ceq'$native'},$true)|ForEach-Object {$_.Member.Value})
if(($methods-join',')-cne'OpenAndBind,DetachShadow,ConfirmShadowAbsent,Close'){throw 'Only the reviewed detach-only native lifecycle is permitted.'}
$functions=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Pinned-Artifact'},$true))
if($functions.Count-ne1){throw 'One collected artifact pin guard required.'}
. ([scriptblock]::Create($functions[0].Extent.Text))
$origin=Join-Path $workspace ('.lab/development/interrupted-shadow-detach-guards-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $origin|Out-Null
$path=Join-Path $origin 'request.json';[IO.File]::WriteAllBytes($path,[byte[]]@(123,125))
$hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
$terminal=[pscustomobject]@{files=@([pscustomobject]@{name='request.json';length=2;sha256=$hash})}
$valid=Pinned-Artifact 'request.json' 128KB
if($valid.sha256-cne$hash-or$valid.path-cne$path){throw 'Exact collected pin was refused.'}
$pinRefusals=0
foreach($case in @('length','missing','duplicate','hash')){
 $terminal=[pscustomobject]@{files=@([pscustomobject]@{name='request.json';length=2;sha256=$hash})}
 if($case-ceq'duplicate'){$terminal.files+=@($terminal.files[0])};if($case-ceq'hash'){$terminal.files[0].sha256='0'*64}
 $refused=$false;try{if($case-ceq'length'){$null=Pinned-Artifact 'request.json' 1}elseif($case-ceq'missing'){$null=Pinned-Artifact 'ticket.json' 64KB}else{$null=Pinned-Artifact 'request.json' 128KB}}catch{$refused=$true}
 if(-not$refused){throw ('Collected pin failure accepted: '+$case)};$pinRefusals++
}
Add-Type -Path @((Join-Path $workspace 'lab/guest/NativeShadowDisk.cs'),(Join-Path $workspace 'lab/guest/NativeMountBoundary.cs'),(Join-Path $workspace 'lab/NativeMountBoundary.TestSupport.cs'))
function Boundary($Fake){New-Object Ntfs2Refs.NativeMountBoundary(('J:\ntfs2refs-shadow\'+('a'*32)+'\shadow.vhdx'),$Fake.Id,$Fake.Tg,$Fake.Tp,$Fake.Sg,$Fake.Sp,$Fake)}
$fake=New-Object MountFake;$native=Boundary $fake
$native.OpenAndBind();$native.DetachShadow();$native.ConfirmShadowAbsent([int[]]@(0,1,2));$native.Close()
if(-not$native.ShadowAbsent-or-not$native.CleanupComplete-or$native.OperationActive-or$native.ProtectAttempted-or$native.OnlineAttempted-or$fake.TargetAttributes-ne1-or$fake.Detaches-ne1-or$fake.Sets-ne0){throw 'Detach-only lifecycle changed the source or failed to prove absence.'}
if(-not$native.vhdOpenReadOnly-or$native.vhdOpenVersion-ne2-or$native.vhdOpenAccessMask-ne0){throw 'Read-only creation-identity-bound VHD reopen required.'}
$fake=New-Object MountFake;$fake.WrongVhd=$true;$native=Boundary $fake;$refused=$false
try{$native.OpenAndBind()}catch{$refused=$true};$native.Close()
if(-not$refused-or$fake.Detaches-ne0-or$fake.Sets-ne0){throw 'Foreign VHD creation identity reached detach.'}
[pscustomobject]@{syntaxValid=$true;nativeMethods=$methods;pinRefusals=$pinRefusals;mockDetachCount=1;mockSourceSetters=0;foreignVhdRefused=$true;vmOperations=0;artifacts=$origin}
