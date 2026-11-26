# The deterministic runner and publication gate use the same case definitions.
$NativeRegressionCases = [ordered]@{
    convert = @{ Soak = @{ Seed = 315781002 }; Outcome = 'converted' }
    many = @{ Soak = @{ Profile = 'many'; Seed = 315782001 }; Outcome = 'converted' }
    'many-16k-to-64k' = @{
        Soak = @{ Profile = 'many'; Seed = 953062004; TargetClusterBytes = 65536 }
        NtfsClusterBytes = 16384; Verify = 'thorough'; Outcome = 'converted'
    }
    resume = @{ Soak = @{ Profile = 'resume'; Seed = 315783001 }; Outcome = 'converted'; Hold = 'verify-passed'; Recovery = 'resume' }
    'thorough-resume' = @{
        Soak = @{ Profile = 'resume'; Seed = 934383016; TargetClusterBytes = 65536 }
        NtfsClusterBytes = 8192; Verify = 'thorough'; Outcome = 'converted'; Hold = 'verify-passed'; Recovery = 'resume'
    }
    rollback = @{ Soak = @{ Profile = 'rollback'; Seed = 315784002 }; Outcome = 'ntfs-as-before'; Hold = 'apply-boot-granule-written'; Recovery = 'rollback' }
    cancel = @{ Soak = @{ Profile = 'cancel'; Seed = 315785001; CancelAtPreparation = $true }; Outcome = 'ntfs-as-before'; Hold = 'preparation-shadow-built'; Recovery = 'rollback' }
    'handled-preparation' = @{ Soak = @{ Scenario = 'handled-preparation' }; Outcome = 'ntfs-as-before' }
    'cancel-preparation' = @{ Soak = @{ Scenario = 'cancel-preparation' }; Outcome = 'ntfs-as-before'; Hold = 'preparation-shadow-built'; Recovery = 'rollback' }
    'tails-4k' = @{ Soak = @{ Scenario = 'tail-boundaries'; TargetClusterBytes = 4096 }; Outcome = 'converted' }
    'tails-64k' = @{ Soak = @{ Scenario = 'tail-boundaries'; TargetClusterBytes = 65536 }; Outcome = 'converted' }
    'tails-4k-limited' = @{ Soak = @{ Scenario = 'tail-boundaries'; TargetClusterBytes = 4096; MemoryLimitMiB = 4096; WriteTailsSingly = $true }; Outcome = 'converted' }
    'tails-64k-limited' = @{ Soak = @{ Scenario = 'tail-boundaries'; TargetClusterBytes = 65536; MemoryLimitMiB = 4096; WriteTailsSingly = $true }; Outcome = 'converted' }
}

function Assert-NativeRegressionVerdict([string]$Case, $Row) {
    $spec = $NativeRegressionCases[$Case]
    $soak = $spec.Soak
    if ($Row.profile -cne ($soak.Profile ?? 'convert') -or $Row.seed -ne ($soak.Seed ?? 315781002) -or
        $Row.scenario -cne ($soak.Scenario ?? 'seeded') -or ($soak.TargetClusterBytes -and $Row.refs_cluster -ne $soak.TargetClusterBytes)) {
        throw "Wrong profile, seed, scenario or target for $Case"
    }
    if (($spec.NtfsClusterBytes -and $Row.ntfs_cluster -ne $spec.NtfsClusterBytes) -or
        ($spec.Verify -and $Row.verify -cne $spec.Verify)) { throw "Wrong source geometry or verification mode for $Case" }
    if ($Row.outcome -cne $spec.Outcome -or $Row.manifest_matches -ne $true -or $Row.cleanup_ok -ne $true) {
        throw "Unexpected verdict for $Case"
    }
    if ($Row.hold_at -cne ($spec.Hold ?? '') -or $Row.reached_hold -ne [bool]$spec.Hold -or
        $Row.terminated -ne [bool]$spec.Hold -or $Row.end_after_seconds -ne 0) {
        throw "$Case missed its interruption"
    }
    if ($Row.recovery_mode -cne ($spec.Recovery ?? 'none')) { throw "$Case missed its recovery action" }
    if ($Case -eq 'handled-preparation' -and ($null -eq $Row.attached_before_cleanup -or @($Row.attached_before_cleanup).Count -ne 0)) {
        throw 'Handled preparation lacks proof that the shadow detached before cleanup'
    }
}
