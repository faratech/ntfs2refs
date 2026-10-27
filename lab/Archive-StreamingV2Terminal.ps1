# Preserve terminal output without changing the guest or replaying its journal.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$observation=(& (Join-Path $PSScriptRoot 'Collect-StreamingV2Conversion.ps1') -Candidate $Candidate)|ConvertFrom-Json
if(-not$observation.terminal-or$observation.all_converter_count-ne0-or$observation.run_id-cne$dispatch.run_id){throw 'Matching terminal worker required.'}
$destination=Join-Path $root 'terminal-evidence'
if(Test-Path -LiteralPath $destination){throw 'Terminal archive exists; inspect rather than overwrite.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 256MB
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $dispatch.vm_id -Credential $credential
try{
    $pins=Invoke-Command -Session $session -ArgumentList $dispatch.guest_output,$dispatch.guest_stage,$dispatch.task_name -ScriptBlock {
        param($Output,$Stage,$Task);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if((Get-ScheduledTask -TaskName $Task).State.ToString()-in@('Running','Queued')-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count){throw 'Worker became active.'}
        $total=[long]0
        foreach($spec in @(@{kind='run';path=$Output},@{kind='stage';path=$Stage})){
            $base=Get-Item -LiteralPath $spec.path
            if(-not$base.PSIsContainer-or($base.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest evidence directory required.'}
            foreach($item in Get-ChildItem -LiteralPath $spec.path -Recurse -Force){
                if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Guest evidence contains a reparse point.'}
                if($item.PSIsContainer){continue}
                $total+=$item.Length
                if($total-gt256MB){throw 'Evidence archive exceeds budget.'}
                [pscustomobject]@{path=$spec.kind+'\'+$item.FullName.Substring($base.FullName.Length+1);
                    bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName).Hash.ToLowerInvariant()}
            }
        }
    }
    New-Item -ItemType Directory -Path $destination|Out-Null
    $pins|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $root 'terminal-guest-pins.json') -Encoding utf8
    # PS5's directory-transfer implementation assumes non-strict scalar Length
    # behavior. Evidence guards above are complete; use its default transport
    # scope, then verify every copied byte against the captured guest hashes.
    Invoke-Command -Session $session -ScriptBlock {Set-StrictMode -Off}
    Copy-Item -LiteralPath $dispatch.guest_output -FromSession $session -Destination (Join-Path $destination 'run') -Recurse
    Copy-Item -LiteralPath $dispatch.guest_stage -FromSession $session -Destination (Join-Path $destination 'stage') -Recurse
    foreach($pin in $pins){
        $path=Join-Path $destination $pin.path;$item=Get-Item -LiteralPath $path
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$pin.bytes-or
            (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Archived evidence differs from terminal guest.'}
    }
    $value=@{kind='streaming-v2-terminal-archive';run_id=$dispatch.run_id;files=@($pins);terminal_observation=$observation;verified=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $path=Join-Path $root 'terminal-evidence-manifest.json'
    $f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 20));$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
    [pscustomobject]@{verified=$true;run_id=$dispatch.run_id;files=@($pins).Count;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
}finally{Remove-PSSession $session}
