# Checks

**GitHub Actions runs the checks** (the owner's decision of 18 November 2026,
when the repository became public and hosted runners became free for it). A
pull request is merged when its checks have passed on its head. Every job
runs on `windows-2025`, Windows Server 2025 build 26100, a build the converter
has been shown on, with the toolchain `rust-toolchain.toml` pins (Rust 1.100.0,
x64 MSVC), installed by `scripts/Install-Toolchain.ps1`.

`lab\Invoke-Checks.ps1 -Commit <commit>` runs the same checks locally, in a
worktree of its own, for a machine without the hosted runners.

## The workflows

| Workflow | When | What |
|---|---|---|
| `workflows/ci.yml` | every push to main, every pull request, by hand | formatting and Clippy, all tests, release builds, and deterministic native conversions and recovery |
| `workflows/soak.yml` | every night at 03:17 UTC, by hand | real conversions on the runners, round after round (below) |
| `workflows/release.yml` | dispatch from main for an existing version tag | builds, signs, qualifies, packages and optionally publishes |

Clippy uses the repository's lint severities: warnings stay visible, an
error fails the job. It is not a zero-warning gate.

## The soak

`scripts/Invoke-Soak.ps1` converts NTFS volumes on virtual disks (VHDX) of the
runner itself, round after round, for the minutes it is given (240 at night).
Each round draws everything from its seed: the NTFS cluster size (4
to 64 KiB), the ReFS cluster size (4 or 64 KiB), the disk's size, and the
content (files of boundary sizes, a random tree or up to 100,000 small files,
names outside ASCII, named streams, hard links, a sparse file, a compressed
file, fragmented files, symbolic links and a junction, attributes, times,
security descriptors and object IDs). The volume is listed with
`lab-volume-manifest` before and after, and compared: with a conversion's
allowances when it is ReFS, exactly when it is NTFS again.

Five profiles, each on a runner of its own:

- `convert`: straight through.
- `many`: straight through, with 20,000 to 100,000 small files.
- `resume`: held at one of the laboratory hold points its run reaches, the
  process ended there, then the recovery command the run printed.
- `rollback`: held at a point before the handoff marker is durable, ended,
  then the recovery command with `--rollback`.
- `cancel`: ended at a random moment within 40 seconds, without a hold, then
  whatever the run had printed.

One round of four, by its seed, converts with `--verify thorough`, whose
apply step writes the handoff marker; the others with `--verify fast`, the
default, whose handoff follows the verification of the converted volume. The
two reach different hold points (`crates/n2r-win32/src/lab_hold.rs`): a fast
run's rollback rounds are held up to `verify-passed`, a thorough run's up to
`apply-before-handoff`. Each round prints its mode and records it in
`rounds.jsonl`.

A failed round stops its runner and keeps its records (the converter's
output, the listings' comparison) as the run's artifact. It is made again on
any elevated Windows machine with:

```powershell
.github\scripts\Invoke-Soak.ps1 -Binaries <dir> -Profile <profile> -Seed <seed> -Rounds 1
```

The soak complements the lab, which it does not replace: the lab's VMs turn
power off under a run, convert Windows boot volumes, take the restart route,
and run on Windows 11.

## The release

Push the version tag on main, then dispatch `workflows/release.yml` from
main for that tag. Leave `publish` off for a rehearsal through packaging.
Dispatch a fresh run to retry qualification after a failure.

1. It checks that the tag is a version, is on main, and equals the version
   in `Cargo.toml`.
2. It builds `ntfs2refs.exe`, `ntfs2refs-recovery.exe` and
   `lab-volume-manifest.exe` in release mode.
3. It signs each with Azure Artifact Signing, Fara Technologies LLC first
   and Mike Fara appended, SHA-256 digests and RFC 3161 time stamps, and
   verifies both signatures with `signtool`.
4. It qualifies those exact signed bytes with the deterministic cases, the
   five 240-minute hosted soak profiles and the private Hyper-V lab.
5. It checks the candidate commit and executable hashes against the native
   verdicts. It packages and attests the ZIP and executables and checks the
   executable hashes again inside the ZIP. `QUALIFICATION.json` carries the
   per-case evidence and `QUALIFICATION.md` carries the recovery matrix.
6. With `publish` enabled, it publishes using the classification in
   `.github/release-channel.txt`. The stabilization candidate uses `prerelease`.

Restrict the `release` and `lab-qualification` environments to main. The
signing credentials remain in `release`. Require the `native` workflow's
matrix checks alongside the existing CI checks in the main branch rules.

### Private Hyper-V runner setup

- Register the Windows runner only in a private qualification repository.
  Give it the `ntfs2refs-qualification` label, PowerShell 7, `gh`, Hyper-V
  access, and the VM fixtures described in `AGENTS.md`. Run it under the lab
  account that can use the guest credential and set `N2R_LAB_ROOT` to the
  host's dedicated `.lab` directory. Keep the private runner out of public
  pull request workflows.
- Install [the private workflow template](qualification/private-lab.yml) on
  the private repository's protected main branch as
  `.github/workflows/ntfs2refs-qualification.yml`. Give its `ntfs2refs-lab`
  environment a read-only `N2R_PUBLIC_ARTIFACT_TOKEN` for downloading the
  public signed candidate artifact. Set `LAB_QUALIFICATION_REPOSITORY` and a
  `LAB_QUALIFICATION_TOKEN` with Actions dispatch and artifact read access to
  that private repository in the public `lab-qualification` environment.
- The lab records native and converted ReFS acceptance runs at 4 KiB, under
  idle and host CPU load, including a guest reboot and subsequent mutation.
  Failed images, journals and full event XML stay on the private host.
  Hosted soak failures keep compact evidence. To retain images when replaying
  a hosted failure on a private machine, pass `-FailureStorage` with a new
  private directory and sufficient free space.
- The restart-route gate restores `N2R-Server-Baseline` before each case.
  Conversion and cancellation both use a separate NTFS working disk
  sized from the host's free space. A refusal case asserts that ReFS working
  storage is rejected before the converter creates a run.

```bash
gh attestation verify ntfs2refs-<version>-windows-x64.zip --repo faratech/ntfs2refs --signer-workflow faratech/ntfs2refs/.github/workflows/release.yml
```
