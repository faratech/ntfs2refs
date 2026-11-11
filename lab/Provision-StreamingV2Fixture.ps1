# Fresh VM, immutable archive OS parent, fresh data media in a later step.
# Never restores/deletes/modifies earlier VM/checkpoint configurations.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$name='ntfs2refs-streaming-v2-20261027'
$parent='C:\Users\mfara\ntfs2refs-archive\exports\win11-installed-clean\ntfs2refs-win11\Virtual Hard Disks\os.vhdx'
if((Test-Path -LiteralPath $root)-or(Get-VM -Name $name -ErrorAction SilentlyContinue)){throw 'Fresh fixture required; inspect prior provisioning.'}
function Earlier-Vms {
    @(Get-VM|Sort-Object Id|ForEach-Object {[ordered]@{id=[string]$_.Id;name=$_.Name;state=$_.State.ToString();parent=[string]$_.ParentSnapshotId;snapshots=@(Get-VMSnapshot -VM $_|Sort-Object Id|ForEach-Object {[string]$_.Id})}})
}
function Save-New([string]$Path,$Value){
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
$protected=Earlier-Vms
$parentItem=Get-Item -LiteralPath $parent
if($parentItem.PSIsContainer-or($parentItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$parentItem.Length-ne18022924288){throw 'Archive OS shape differs.'}
$parentVhd=Get-VHD -Path $parent
if($parentVhd.ParentPath-or$parentVhd.Size-ne64GB){throw 'Independent archive OS parent required.'}
$parentAcl=(Get-Acl -LiteralPath $parent).Sddl
$held=[IO.File]::Open($parent,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$pin=([BitConverter]::ToString($sha.ComputeHash($held))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    if($pin-cne'38483cb91279b90b6a053098d7b62903c18ea3873ab9023f382bb70ff545fe87'){throw 'Archive OS hash differs.'}
    New-Item -ItemType Directory -Path (Join-Path $root 'disks')|Out-Null
    Save-New (Join-Path $root 'intent.json') @{name=$name;root=$root;parent_path=$parent;parent_sha256=$pin;parent_acl_before=$parentAcl;capacity=$capacity;protected_before=$protected;data_media_created=$false;utc=[DateTime]::UtcNow.ToString('o')}
    $os=Join-Path $root 'disks\os-child.vhdx'
    New-VHD -Path $os -ParentPath $parent -Differencing -ErrorAction Stop|Out-Null
    $vm=New-VM -Name $name -Generation 2 -MemoryStartupBytes 4GB -VHDPath $os -Path (Join-Path $root 'vm') -ErrorAction Stop
    Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -AutomaticCheckpointsEnabled $false
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 4GB
    Set-VMProcessor -VM $vm -Count 4
    Get-VMNetworkAdapter -VM $vm|Remove-VMNetworkAdapter -Confirm:$false
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    $child=Get-VHD -Path $os
    if($child.ParentPath-cne$parent-or@(Get-VMHardDiskDrive -VM $vm).Count-ne1-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Fresh VM topology differs.'}
    $after=@(Earlier-Vms|Where-Object {$_.id-cne[string]$vm.Id})
    if(($after|ConvertTo-Json -Depth 10 -Compress)-cne($protected|ConvertTo-Json -Depth 10 -Compress)){throw 'Earlier VM state changed during provisioning; inspect.'}
    $aclAfter=(Get-Acl -LiteralPath $parent).Sddl
    Save-New (Join-Path $root 'manifest.json') @{kind='streaming-v2-disposable-vm';vm_id=[string]$vm.Id;name=$name;root=$root;os_child=$os;immutable_os_parent=$parent;parent_sha256=$pin;parent_acl_before=$parentAcl;parent_acl_after=$aclAfter;parent_acl_string_unchanged=($aclAfter-ceq$parentAcl);data_media_created=$false;state='Off';memory_bytes=4GB;processors=4;network_adapters=0;utc=[DateTime]::UtcNow.ToString('o')}
    [pscustomobject]@{vm_id=[string]$vm.Id;name=$name;state=(Get-VM -Id $vm.Id).State.ToString();parent_acl_string_unchanged=($aclAfter-ceq$parentAcl);data_media_created=$false}|ConvertTo-Json -Compress
}finally{$held.Dispose()}
