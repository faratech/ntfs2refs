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
`-SampleStacks` requires the matching PDB beside the executable and writes
`stacks.txt`: phase, step and stack per line, a hundred samples a second, helper
and digest threads included. Use it to find where unnamed time goes before
changing anything for speed, not merely to claim an unmeasured speed change.

Recovery is checked by stopping the converter at a named point of apply,
handoff or finalization (`crates/n2r-win32/src/lab_hold.rs` lists them), ending
its process there, and running the recovery command it printed:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name resume-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot -InterruptAt apply-mid-ranges
.\lab\Invoke-BootConversionAttempt.ps1 -Name rollback-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot -InterruptAt apply-mid-ranges -RecoverMode rollback
```

A resume ends `RESUMED-NOT-BOOTED` and is compared as a conversion is; a
rollback ends `ROLLED-BACK-NOT-BOOTED` and is compared with the listing taken
before in every field (`compare --exact`: nothing allowed).
`-RecoverMode none -CheckpointAfterConvert <name>` saves the interrupted state
instead, and `-RecoverFrom <attempt>` recovers it later from that attempt's own
records. `-TearMarker handoff`, with `-InterruptAt apply-handoff-durable`, leaves
the journal's handoff marker as a write that stopped part-way leaves it, so that
recovery has to settle it first. The lab ends a process; it cannot cut power to
the storage, and every verdict says so.

`-Diagnose` builds the shadow, lists every per-object failure and stops before
publication, writing nothing to the source. It ends `diagnose-clean` (exit 0) or
`diagnose-found-failures` (exit 3) only once the source is the same online NTFS
partition and lists exactly as before.

`-ShapeSource <script>` runs a script from `lab\guest` against the source
before it is listed, to give it objects a fresh Windows does not have:
`Add-NamedStreams.ps1` (the lab volumes have no named streams) and
`Add-DirectoryStream.ps1`, which the converter must refuse by name at admission.

`verdict.json` lists every piece of evidence an attempt retains with its size
and SHA-256, or the reason it is missing. A success without its required
evidence is `incomplete-evidence`.

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

## Older scripts

Most of the other scripts here were written for one VM or checkpoint of an
earlier stage, and that VM or checkpoint is gone. [RETIRED.md](RETIRED.md) lists
the 161 that cannot run; do not start from one. They are kept unchanged as the
record of those stages, and a test fails if a script names a retired VM without
being listed.

The earlier lab procedures and budgets are preserved in
[the historical guide](../docs/history/lab-README-before-boot-alpha-closeout-20261111.md).
