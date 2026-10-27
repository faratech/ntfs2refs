# Clean reboot and original-payload readback after the beta mutation workload.
# Never force power off, replay recovery, or operate on preserved alpha VMs.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace ('.lab\hyperv\shadow-large-beta-20261027\'+$Candidate)
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$mutation=Get-Content -LiteralPath (Join-Path $root 'mutation-result.json') -Raw|ConvertFrom-Json
if(-not$mutation.success-or$mutation.run_id-cne$dispatch.run_id){throw 'Matching successful mutation receipt required.'}
& (Join-Path $PSScriptRoot 'Verify-NativeShadowLargeBetaPayload.ps1') -Candidate $Candidate | Out-Null
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$before=Invoke-Command -VMId $id -Credential $credential -ScriptBlock {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
}
function Save-NewRecord([string]$Path,$Record){
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
Save-NewRecord (Join-Path $root 'reboot-intent.json') @{vm_id=[string]$id;run_id=$dispatch.run_id;before_boot_utc=$before;utc=[DateTime]::UtcNow.ToString('o');force_power_off=$false}
# A missing shutdown integration service is a refusal, not permission to force.
$shutdown=@(Get-VMIntegrationService -VM (Get-VM -Id $id)|Where-Object {$_.Id.ToString().EndsWith('\9f8233ac-be49-4c79-8ee3-e7e1985b2077',[StringComparison]::OrdinalIgnoreCase)})
if($shutdown.Count-ne1-or-not$shutdown[0].Enabled){throw 'Enabled guest shutdown integration required.'}
Stop-VM -VM (Get-VM -Id $id) -Confirm:$false -ErrorAction Stop
$deadline=[DateTime]::UtcNow.AddMinutes(5)
while((Get-VM -Id $id).State.ToString()-cne'Off'){
    if([DateTime]::UtcNow-ge$deadline){throw 'Clean shutdown not observed; VM preserved without forced power off.'}
    Start-Sleep -Seconds 2
}
Save-NewRecord (Join-Path $root 'reboot-off.json') @{vm_id=[string]$id;utc=[DateTime]::UtcNow.ToString('o');state='Off'}
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop | Out-Null
$deadline=[DateTime]::UtcNow.AddMinutes(8)
$after=$null
do{
    try{
        $after=Invoke-Command -VMId $id -Credential $credential -ErrorAction Stop -ScriptBlock {
            (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        }
    }catch{
        if([DateTime]::UtcNow-ge$deadline){throw 'Guest login did not return after the single clean boot; inspect the VM.'}
        Start-Sleep -Seconds 5
    }
}while(-not$after)
if([DateTimeOffset]::Parse($after)-le[DateTimeOffset]::Parse($before)){throw 'A newer guest boot was not established.'}
& (Join-Path $PSScriptRoot 'Verify-NativeShadowLargeBetaPayload.ps1') -Candidate $Candidate | Out-Null
$result=@{kind='native-large-beta-post-mutation-reboot';success=$true;vm_id=[string]$id;run_id=$dispatch.run_id;
    before_boot_utc=$before;after_boot_utc=$after;original_payloads_verified=$true;full_semantics_independently_rechecked=$false;
    power_loss_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
Save-NewRecord (Join-Path $root 'reboot-result.json') $result
$result|ConvertTo-Json -Depth 8 -Compress
