# Two separately observed phases. Restore never boots; Boot never restores.
# Only the preserved disposable pre-apply NTFS branch is eligible.
[CmdletBinding()]param([Parameter(Mandatory)][ValidateSet('Restore','Boot')][string]$Phase)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$passed=[guid]'49094105-ed4b-4447-9f23-86a3a22b394f';$baseline=[guid]'6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\retained-recovery-preparation'
$vm=Get-VM -Id $id;$snapshots=@(Get-VMSnapshot -VM $vm);$ids=@($snapshots|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$snapshots.Count-ne20-or$ids-notcontains$passed.ToString()-or$ids-notcontains$baseline.ToString()-or
    $vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact isolated preserved checkpoint set required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 16GB
function Save-New([string]$name,$value){$f=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 12));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
if($Phase-ceq'Restore'){
    if((Test-Path -LiteralPath $root)-or$vm.ParentSnapshotId-ne$passed){throw 'Fresh restore from the passed OFF branch required.'}
    $proof=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate12\rust-postcheck\AfterReboot.json') -Raw|ConvertFrom-Json
    if(-not$proof.success-or$proof.report_sha256-cne'4dd857a0f50b5a0fef42782680cfdcdd9cf5bf0fd504091932236abfb7292a7b'){throw 'Passed candidate12 proof differs.'}
    New-Item -ItemType Directory -Path $root|Out-Null
    Save-New 'restore-intent.json' @{vm_id=$id.ToString();passed_checkpoint=$passed.ToString();baseline_checkpoint=$baseline.ToString();all_checkpoint_ids=$ids;utc=[DateTime]::UtcNow.ToString('o');source_payload_writes=0}
    Restore-VMSnapshot -VMSnapshot ($snapshots|Where-Object Id -eq $baseline) -Confirm:$false
    Save-New 'restore-issued.json' @{issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    'Restore issued once. Confirm the OFF parent from a fresh host process before Boot.'
    return
}
$intent=Get-Content -LiteralPath (Join-Path $root 'restore-intent.json') -Raw|ConvertFrom-Json
if($vm.ParentSnapshotId-ne$baseline-or$intent.baseline_checkpoint-cne$baseline.ToString()-or
    @($intent.all_checkpoint_ids|Where-Object {$_-notin$ids}).Count-or(Test-Path -LiteralPath (Join-Path $root 'boot-issued.json'))){throw 'Exact restored and unbooted branch required.'}
Save-New 'boot-issued.json' @{issued_once=$true;parent_id=$baseline.ToString();utc=[DateTime]::UtcNow.ToString('o')}
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; do not restart.'};Start-Sleep -Seconds 3}}
try{
    $ready=Invoke-Command -Session $s -ScriptBlock {
        $ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe')}).Count-or
            @(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'A worker is live.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Exact excluded pre-apply pair required.'}
        if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Native driver changed.'}
        # Live NTFS is needed for a new coherent freeze. Shadow metadata will
        # receive only the existing explicit tiny-cache sync, never full copy.
        Set-Disk -Number 1 -IsReadOnly $false;Set-Disk -Number 1 -IsOffline $false
        Set-Disk -Number 3 -IsReadOnly $false;Set-Disk -Number 3 -IsOffline $false
        $f=Get-Volume -DriveLetter F;$r=Get-Volume -DriveLetter R;$j=Get-Volume -DriveLetter J
        if($f.FileSystem-cne'NTFS'-or$f.AllocationUnitSize-ne65536-or$r.FileSystem-cne'ReFS'-or$r.AllocationUnitSize-ne4096-or$j.FileSystem-cne'NTFS'){
            throw 'Restored volume geometry differs.'
        }
        Set-StrictMode -Off
        @{source_filesystem=$f.FileSystem;source_label=$f.FileSystemLabel;shadow_filesystem=$r.FileSystem;shadow_label=$r.FileSystemLabel;
            source_payload_writes_by_controller=0;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
    }
    Save-New 'ready.json' $ready
    $ready|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
