# Hyper-V qualification lab

The current route is `Invoke-BootConversionAttempt.ps1`. It restores a disposable
NTFS baseline, runs the converter from a separate control OS, compares independent
before/after volume listings, and optionally boots the original source disk alone.
See [AGENTS.md](../AGENTS.md) for the VM identities and standing rules, and
[release qualification](../docs/release-0.0.1-alpha.md) for the frozen alpha.

## Existing checks

Build the converter and independent listing tool using one shared build directory:

```powershell
cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest
```

A thinned 1-in-10 fixture is the normal regression case:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name fixture-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture -NoBoot -KeepScratch
```

A full run includes the original-disk-only boot and desktop observation:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name full-check -KeepScratch
```

Supply `-Binary` and `-ManifestBinary` when verifying an already built package;
otherwise the harness uses `target/release`. `-VmId` selects the second lab VM.
`-SampleStacks` requires the matching PDB beside the executable and adds profiling.
Do not use it merely to claim an unmeasured speed change.

To finalize an existing saved after-apply state:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name recovery-check -Recover -Checkpoint N2R-Small-Applied -NoBoot -KeepScratch
```

A missing before-listing is `converted-not-compared`, not a successful independent
comparison. A run is complete only when its verdict and the applicable native
checks agree. Do not widen the manifest allow-list to make it pass.

## Storage and preservation

Each attempt writes `.lab/hyperv/attempts/<Name>/`. Choose a new name. The full
attempt requires at least 65 GiB free on the host; the fixture requires 40 GiB.
The harness sizes memory from available host RAM and uses a dynamic scratch disk.
These are laboratory requirements, not a universal product-space estimate.

`-KeepScratch` retains the scratch disk for inspection and evidence recovery.
Before any cleanup, preserve the verdict, progress, source and target listings,
comparison report, binary hashes, recovery output and boot evidence with hashes.
Do not delete the reference baseline checkpoint: the second VM's disks depend
on its parent chain. Ask before deleting `.lab` artifacts.

The earlier lab procedures and budgets are preserved in
[the historical guide](../docs/history/lab-README-before-boot-alpha-closeout-20261111.md).
