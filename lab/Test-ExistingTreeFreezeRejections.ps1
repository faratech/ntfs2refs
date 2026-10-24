<# Mutate small copies of a verified evidence archive. No VM/disk operation,
   original artifact replacement or recursive deletion is performed. #>
param([Parameter(Mandatory)][string]$Directory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent;$verify=Join-Path $PSScriptRoot 'Test-ExistingTreeFreezeArchive.ps1'
& $verify -Directory $Directory|Out-Null
$root=Join-Path $workspace ('.lab/development/freeze-archive-rejections-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root|Out-Null
$files=@('freeze-request.json','population.json','freeze.json','reopen.json','freeze.inspection.json','reopen.inspection.json','foreign.json')
function Read-Json([string]$Name){Get-Content -LiteralPath (Join-Path $script:case $Name) -Raw|ConvertFrom-Json}
function Write-Json([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $script:case $Name),($Value|ConvertTo-Json -Depth 100),[Text.UTF8Encoding]::new($false))}
function Rehash-Inspection([string]$Phase){$r=Read-Json ($Phase+'.json');$r.inspection_sha256=(Get-FileHash -LiteralPath (Join-Path $script:case ($Phase+'.inspection.json'))).Hash.ToLowerInvariant();Write-Json ($Phase+'.json') $r}
$results=@()
function Reject([string]$Name,[scriptblock]$Mutation){
 $script:case=Join-Path $root $Name;New-Item -ItemType Directory -Path $script:case|Out-Null
 foreach($file in $files){Copy-Item -LiteralPath (Join-Path $Directory $file) -Destination (Join-Path $script:case $file)}
 & $Mutation
 $rejected=$false;$message=$null
 try{& $verify -Directory $script:case|Out-Null}catch{$rejected=$true;$message=$_.Exception.Message}
 if(-not$rejected){throw ('Invalid archive was accepted: '+$Name)}
 $script:results+=@([pscustomobject]@{case=$Name;rejected=$true;reason=$message})
}
Reject 'lost-readonly-exclusion' {$r=Read-Json 'freeze.json';$r.basis.after.disk_attributes=1;Write-Json 'freeze.json' $r}
Reject 'missing-native-lock' {$r=Read-Json 'freeze.json';$r.events=@($r.events|Where-Object operation -ne 'lock-volume');Write-Json 'freeze.json' $r}
Reject 'reopen-repairs-exclusion' {$r=Read-Json 'reopen.json';$first=Read-Json 'freeze.json';$r.events+=@($first.events|Where-Object control_code -eq 0x0007c0f4);Write-Json 'reopen.json' $r}
Reject 'incorrect-content' {$r=Read-Json 'population.json';$r.files[0].sha256='0'*64;Write-Json 'population.json' $r}
Reject 'omitted-file' {
 foreach($phase in @('freeze','reopen')){$r=Read-Json ($phase+'.inspection.json');$r.filesystem.details.files=@($r.filesystem.details.files|Where-Object record_number -ne 39);Write-Json ($phase+'.inspection.json') $r;Rehash-Inspection $phase}
}
Reject 'duplicate-path-hides-file' {
 foreach($phase in @('freeze','reopen')){
  $r=Read-Json ($phase+'.inspection.json');$first=$r.filesystem.details.files|Where-Object record_number -eq 39;$second=$r.filesystem.details.files|Where-Object record_number -eq 41
  $second.names=$first.names;$second.streams=$first.streams
  Write-Json ($phase+'.inspection.json') $r;Rehash-Inspection $phase
 }
}
Reject 'foreign-device-not-refused' {$r=Read-Json 'foreign.json';$r.success=$true;Write-Json 'foreign.json' $r}
[IO.File]::WriteAllText((Join-Path $root 'results.json'),($results|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
[pscustomobject]@{passed=$results.Count;directory=$root;vmOperations=0;sourceArtifactsModified=0}
