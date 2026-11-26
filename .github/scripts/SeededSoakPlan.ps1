# A seed defines the same profile plan in the runner and the release gate.
function Get-SeededSoakPlan([int]$Seed, [string]$Profile, [int]$TargetClusterBytes) {
    # Both verification modes check the converted volume before handoff.
    $rollbackHolds = @('apply-activated', 'apply-mid-ranges', 'apply-ranges-written', 'apply-before-boot-granule', 'apply-boot-granule-written',
        'apply-before-handoff', 'apply-sealed', 'apply-seal-recorded', 'verify-authenticated', 'verify-source-readonly', 'verify-passed')
    $resumeHolds = $rollbackHolds + @('handoff-sealed', 'finalize-before-online', 'finalize-online')

    $draw = [Random]::new($Seed)
    # A VHDX made by diskpart has 4 KiB physical sectors.
    $ntfsCluster = @(4096, 4096, 4096, 8192, 16384, 32768, 65536)[$draw.Next(0, 7)]
    $refsCluster = @(4096, 65536)[$draw.Next(0, 2)]
    if ($TargetClusterBytes) { $refsCluster = $TargetClusterBytes }
    $gib = if ($Profile -eq 'many') { 8 } else { $draw.Next(2, 7) }
    # This mode uses the seed directly so the existing draws stay in order.
    $verify = if ($Seed % 4 -eq 0) { 'thorough' } else { 'fast' }
    $hold = switch ($Profile) {
        'resume' { $resumeHolds[$draw.Next(0, $resumeHolds.Count)] }
        'rollback' { $rollbackHolds[$draw.Next(0, $rollbackHolds.Count)] }
        default { '' }
    }
    $endAfter = if ($Profile -eq 'cancel') { [Math]::Round(0.5 + $draw.NextDouble() * 40, 1) } else { 0 }

    @{
        ntfs_cluster = $ntfsCluster; refs_cluster = $refsCluster; disk_gib = $gib
        verify = $verify; hold_at = $hold; end_after_seconds = $endAfter
    }
}
