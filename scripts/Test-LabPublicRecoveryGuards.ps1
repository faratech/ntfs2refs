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
$markerFunctions=@($parsed['Collect-LabPublicRecovery.ps1'].FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq'Test-ExpectedRollbackMarker'},$true))
if($markerFunctions.Count-ne1){throw 'One pure complete rollback-marker verifier required.'}
. ([scriptblock]::Create($markerFunctions[0].Extent.Text))
$sourceHash='ab'*32;$immutableHash='12'*32
$marker=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes('N2RABT01').CopyTo($marker,0);$marker[8]=4
for($i=0;$i-lt32;$i++){$marker[16+$i]=0x12;$marker[48+$i]=0xab}
$sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($marker,0,4064).CopyTo($marker,4064)}finally{$sha.Dispose()}
if(-not(Test-ExpectedRollbackMarker $marker $sourceHash $immutableHash)){throw 'Exact rollback marker was refused.'}
$markerRefusals=0
foreach($case in @('magic','code','reserved','immutable','source','padding','digest','truncated','foreignSource','foreignJournal')){
 $changed=[byte[]]$marker.Clone();$sourcePin=$sourceHash;$journalPin=$immutableHash
 switch($case){
  'magic'{$changed[0]=0};'code'{$changed[8]=3};'reserved'{$changed[9]=1};'immutable'{$changed[16]=0};'source'{$changed[48]=0};'padding'{$changed[800]=1};'digest'{$changed[4095]=$changed[4095]-bxor1};'truncated'{$changed=[byte[]]$changed[0..4094]};'foreignSource'{$sourcePin='0'*64};'foreignJournal'{$journalPin='0'*64}
 }
 if(Test-ExpectedRollbackMarker $changed $sourcePin $journalPin){throw ('Complete rollback-marker refusal failed: '+$case)};$markerRefusals++
}
[pscustomobject]@{syntaxFiles=$parsed.Count;validPinAccepted=$true;pinRefusals=$refusals;exactRollbackMarkerAccepted=$true;markerRefusals=$markerRefusals;vmOperations=0;artifacts=$origin}
