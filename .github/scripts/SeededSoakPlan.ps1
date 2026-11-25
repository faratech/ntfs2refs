# A seed defines the same profile plan in the runner and the release gate.
function Get-SeededSoakPlan([int]$Seed, [string]$Profile, [int]$TargetClusterBytes) {
    # The points reached before and after the handoff differ by mode. A
    # rollback is held only before the handoff becomes durable.
    $holds = @{
        fast     = @('apply-activated', 'apply-mid-ranges', 'apply-ranges-written', 'apply-before-boot-granule', 'apply-boot-granule-written',
            'apply-before-handoff', 'apply-sealed', 'apply-seal-recorded', 'verify-authenticated', 'verify-source-readonly', 'verify-passed',
            'handoff-sealed', 'finalize-before-online', 'finalize-online')
        thorough = @('apply-activated', 'apply-mid-ranges', 'apply-ranges-written', 'apply-before-boot-granule', 'apply-boot-granule-written',
            'apply-before-handoff', 'apply-handoff-durable', 'handoff-sealed', 'finalize-authenticated', 'finalize-source-readonly',
            'finalize-before-online', 'finalize-online')
    }
    $rollbackHolds = @{ fast = $holds.fast[0..10]; thorough = $holds.thorough[0..5] }

    $draw = [Random]::new($Seed)
    # A VHDX made by diskpart has 4 KiB physical sectors.
    $ntfsCluster = @(4096, 4096, 4096, 8192, 16384, 32768, 65536)[$draw.Next(0, 7)]
    $refsCluster = @(4096, 65536)[$draw.Next(0, 2)]
    if ($TargetClusterBytes) { $refsCluster = $TargetClusterBytes }
    $gib = if ($Profile -eq 'many') { 8 } else { $draw.Next(2, 7) }
    # This mode uses the seed directly so the existing draws stay in order.
    $verify = if ($Seed % 4 -eq 0) { 'thorough' } else { 'fast' }
    $hold = switch ($Profile) {
        'resume' { $holds[$verify][$draw.Next(0, $holds[$verify].Count)] }
        'rollback' { $rollbackHolds[$verify][$draw.Next(0, $rollbackHolds[$verify].Count)] }
        default { '' }
    }
    $endAfter = if ($Profile -eq 'cancel') { [Math]::Round(0.5 + $draw.NextDouble() * 40, 1) } else { 0 }

    @{
        ntfs_cluster = $ntfsCluster; refs_cluster = $refsCluster; disk_gib = $gib
        verify = $verify; hold_at = $hold; end_after_seconds = $endAfter
    }
}
