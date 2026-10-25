<# Pure parser/pin refusal checks; never imports Hyper-V or executes a runner. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;$parsed=@{}
foreach($name in @('Dispatch-LabPublicRecovery.ps1','Collect-LabPublicRecovery.ps1')){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
 if($errors){throw ($errors|Out-String)};$parsed[$name]=$ast
 $commands=@($ast.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
 foreach($forbidden in @('Restore-VMSnapshot','Start-VM','Stop-VM','Restart-VM','Remove-Item','Move-Item','Set-Disk','Format-Volume','Restart-Computer','Start-Process')){
  if($commands-contains$forbidden){throw ('Forbidden state mutation in '+$name+': '+$forbidden)}
 }
}
$functions=@($parsed['Dispatch-LabPublicRecovery.ps1'].FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq'Pinned-Artifact'},$true))
if($functions.Count-ne1){throw 'One pure pin-check function required.'}
$body=$functions[0].Body.Extent.Text
$check=[scriptblock]::Create('param([string]$Name,[long]$Limit)'+[Environment]::NewLine+$body.Substring(1,$body.Length-2))
$origin=Join-Path $workspace ('.lab/development/public-recovery-guard-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $origin|Out-Null
$path=Join-Path $origin 'request.json';[IO.File]::WriteAllBytes($path,[byte[]]@(123,125))
$pin=(Get-FileHash $path).Hash.ToLowerInvariant()
$terminal=[pscustomobject]@{files=@([pscustomobject]@{name='request.json';length=2;sha256=$pin})}
$valid=&$check 'request.json' 131072
if($valid.path-cne$path-or$valid.sha256-cne$pin){throw 'Valid collected input was not accepted.'}
$refusals=0
foreach($case in @('size','missing','duplicate','hash','changed')){
 $terminal=[pscustomobject]@{files=@([pscustomobject]@{name='request.json';length=2;sha256=$pin})}
 if($case-ceq'duplicate'){$terminal.files+=@($terminal.files[0])}
 if($case-ceq'hash'){$terminal.files[0].sha256='0'*64}
 if($case-ceq'changed'){[IO.File]::WriteAllBytes($path,[byte[]]@(123,120))}
 $failed=$false
 try{if($case-ceq'size'){$null=&$check 'request.json' 1}elseif($case-ceq'missing'){$null=&$check 'ticket.json' 131072}else{$null=&$check 'request.json' 131072}}catch{$failed=$true}
 if(-not$failed){throw ('Pin refusal failed: '+$case)};$refusals++
}
[pscustomobject]@{syntaxFiles=$parsed.Count;validPinAccepted=$true;pinRefusals=$refusals;vmOperations=0;artifacts=$origin}
