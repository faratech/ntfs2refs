# Checks

**GitHub Actions runs the checks** (the owner's decision of 18 November 2026,
when the repository became public and hosted runners became free for it). A
pull request is merged when its checks have passed on its head. The x64
checks run on `windows-2025`, Windows Server 2025 build 26100. A
`windows-11-arm` job builds all workspace executables in release mode and
starts the ARM64 converter with `--version`. Conversion and recovery on
ARM64 still require a separate lab qualification. Both jobs use the Rust
version pinned in `rust-toolchain.toml` through `scripts/Install-Toolchain.ps1`.

`lab\Invoke-Checks.ps1 -Commit <commit>` runs the x64 checks locally, in a
worktree of its own, for a machine without the hosted runners.

## The workflows

| Workflow | When | What |
|---|---|---|
| `workflows/ci.yml` | every push to main, every pull request, by hand | formatting and Clippy, all tests, x64 and ARM64 release builds, and deterministic x64 conversions and recovery |
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

One round of four, by its seed, converts with `--verify thorough`. The others
use `--verify fast`, the default. In both modes the handoff follows verification
of the converted volume, and rollback rounds can be held up to `verify-passed`.
Each round prints its mode and records it in `rounds.jsonl`.

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
   `lab-volume-manifest.exe` in release mode. The candidate artifact also
   carries the Cloud Files and ProjFS fixture providers for the private lab.
3. It signs each with Azure Artifact Signing, Fara Technologies LLC first
   and Mike Fara appended, SHA-256 digests and RFC 3161 time stamps, and
   verifies both signatures with `signtool`.
4. It qualifies those exact signed bytes with the deterministic cases, the
   five 240-minute hosted soak profiles and the private Hyper-V lab.
5. It checks the candidate commit and executable hashes against the native
   verdicts. It packages and attests the ZIP and executables and checks the
   executable hashes again inside the ZIP. `QUALIFICATION.json` carries the
   per-case evidence and `QUALIFICATION.md` carries the recovery and platform
   matrices. `capabilities` and `--check` report platform evidence from the
   adjacent `QUALIFICATION.json` when its schema, version and converter hash
   match. The profile table records the observed Windows build and edition
   (OS SKU), ReFS format, version and allocation unit for each listed case.
6. A read-only job downloads the uploaded package and verifies both ZIP
   attestations, the Windows ZIP checksum, and the separate report files
   against their ZIP entries. It also runs during an unpublished rehearsal.
7. With `publish` enabled, it publishes using the classification in
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
  Hosted soak failures keep compact evidence. Many-file rounds with larger
  ReFS clusters also keep the NTFS extents of `sparse.bin` and the preflight
  estimate of how much data can stay in place. Windows can allocate different
  extents when a run recreates the same seed. To retain images when replaying
  a hosted failure on a private machine, pass `-FailureStorage` with a new
  private directory and sufficient free space.
- The restart-route gate restores `N2R-Server-Baseline` before each case.
  Conversion and cancellation both use a separate NTFS working disk
  sized from the host's free space. A refusal case asserts that ReFS working
  storage is rejected before the converter creates a run.
- Run `Invoke-RestartRouteAttempt.ps1 -PostFlushRecovery resume` and
  `-PostFlushRecovery rollback` from separate baselines for the restart
  interruption cases. The host reads the WinPE console and turns off the VM
  only when the post-flush pause appears. The verdict requires the matching
  durable receipt and confirms that the discovery write had not been
  requested. The working image is retained as lab evidence.
- The Windows 11 restart cases use `Invoke-Windows11RestartAttempt.ps1` to
  restore the NTFS checkpoint on `ntfs2refs-reference-c` and boot its disk0.
  The lab takes the matching installation medium from `ntfs2refs-reference-b`
  and records the Windows build, revision and edition before preparation.
  The signed gate requires the resume and rollback results and the observed
  ReFS profile after resume.

```bash
gh attestation verify ntfs2refs-<version>-windows-x64.zip --repo faratech/ntfs2refs --signer-workflow faratech/ntfs2refs/.github/workflows/release.yml
```
