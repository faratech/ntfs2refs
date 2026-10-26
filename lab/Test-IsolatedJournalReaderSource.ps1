<# Compile and pure refusals only. Never pass a valid factory request here;
   no firmware, device, VM, credential or native operation is invoked. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Add-Type -Path @((Join-Path $PSScriptRoot 'guest/IsolatedJournalZero.cs'),
    (Join-Path $PSScriptRoot 'guest/IsolatedJournalDeviceProfile.cs'),
    (Join-Path $PSScriptRoot 'guest/IsolatedJournalReader.Windows.cs'))
Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Force
$script:checks=0
function Check([bool]$Condition,[string]$Message) {
    if(-not $Condition){throw $Message};$script:checks++
}
function RefuseBeforeNative([guid]$Vm,[AllowNull()][string]$Token) {
    $refused=$false
    try {[Ntfs2RefsResearch.IsolatedJournalReader]::OpenReadOnly($Vm,$Token)|Out-Null}
    catch {
        # Other failures cannot masquerade as this deliberate pre-native refusal.
        $refused=$_.Exception.InnerException -is [IO.InvalidDataException] -and
            $_.Exception.InnerException.Message -ceq 'Exact isolated VM and journal token required before native acquisition.'
    }
    Check $refused 'Factory reached a native path or accepted an unbound request.'
}
$policy=Get-IsolatedBaselinePolicy
$token=[Ntfs2RefsResearch.IsolatedJournalReader]::ExpectedIdentityToken()
$material='isolated-journal-zero-v1|'+$policy.vm_id+'|'+$policy.host_volume_root+'|'+
    $policy.journal_file_id+'|'+$policy.journal_unique_id+'|8589934592|512|4096'
$sha=[Security.Cryptography.SHA256]::Create()
try {$expected=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))).Replace('-','').ToLowerInvariant()}
finally {$sha.Dispose()}
Check ($token -ceq $expected) 'Native reader token differs from structural review token.'
Check ($policy.vm_id -ceq [Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::VmId) 'Native profile VM pin drifted.'
Check ([Ntfs2RefsResearch.IsolatedJournalDeviceProfile]::JournalBytes -eq $policy.journal_bytes) 'Native profile length drifted.'
$type=[Ntfs2RefsResearch.IsolatedJournalReader]
Check ($type.IsSealed -and $type.GetConstructors().Count -eq 0) 'A caller can construct/derive a native lease.'
$imports=@($type.GetMethods([Reflection.BindingFlags]'Static,NonPublic')|Where-Object {
    $_.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false).Count -gt 0
}|Select-Object -ExpandProperty Name)
$expectedImports=@('CreateFileW','DeviceIoControl','SetFilePointerEx','ReadFile','GetSystemFirmwareTable')
Check (@(Compare-Object ($imports|Sort-Object) ($expectedImports|Sort-Object)).Count -eq 0) 'Unexpected native API surface.'
foreach($vm in @([guid]::Empty,[guid]$policy.old_vm_id,[guid]'11111111-1111-1111-1111-111111111111')) {
    RefuseBeforeNative $vm $token
}
foreach($bad in @($null,'',('0'*64),$token.ToUpperInvariant(),($token+'0'))) {
    RefuseBeforeNative ([guid]$policy.vm_id) $bad
}
[pscustomobject]@{checks=$script:checks;passed=$true;compile_only_native_adapter=$true;
    native_calls=0;device_opens=0;vm_operations=0;credentials_accessed=0;large_images_created=0}
