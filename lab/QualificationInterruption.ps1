function Get-RunningRecoveryMode([string]$Report) {
    if ($Report -match 'The recovery finished: the volume is converted') { 'resume' }
    elseif ($Report -match 'The recovery finished: the run had not started writing') { 'cancel' }
    elseif ($Report -match 'The recovery put the NTFS volume back') { 'rollback' }
}

function Get-QualificationInterruption([string]$Route, [string]$Case, $Verdict) {
    if ($Route -eq 'running' -and $Verdict.cut) {
        $hold = if ($Verdict.cut.hold_at -ne 'none') { $Verdict.cut.hold_at }
        return @{
            hold = $hold
            reached_hold = if ($hold) { $Verdict.cut.hold_reported }
            kind = 'vm-turned-off'
            recovery = if ($Verdict.cut.recovered_after_it) { $Verdict.cut.recovery_mode }
        }
    }
    @{
        hold = if ($Verdict.interrupt) { $Verdict.interrupt.point } elseif ($Verdict.interrupted_at) { $Verdict.interrupted_at } elseif ($Route -eq 'restart') { $Verdict.lab_fail_at }
        reached_hold = if ($Verdict.interrupt) { [bool]$Verdict.interrupt.held } elseif ($Verdict.lab_fail_at) { $Verdict.reached_lab_fail_at } elseif ($Verdict.interrupted_at) { $true }
        kind = if ($Verdict.interrupt) { $Verdict.interrupt.kind } elseif ($Verdict.interrupted_at) { 'process-termination' } elseif ($Verdict.lab_fail_at) { 'injected failure' }
        recovery = if ($Verdict.recovery -is [System.Collections.IDictionary]) { $Verdict.recovery.mode } elseif ($Verdict.recover_mode) { $Verdict.recover_mode } elseif ($Case -eq 'restart-cancel') { 'rollback' }
    }
}
