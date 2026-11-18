# Checks

**GitHub Actions runs the checks** (the owner's decision of 18 November 2026,
when the repository became public and hosted runners became free for it). A
pull request is merged when its checks have passed on its head. Every job
runs on `windows-2025`, Windows Server 2025 build 26100, a build the converter
has been shown on, with the toolchain `rust-toolchain.toml` pins (Rust 1.98.1,
x64 MSVC), installed by `scripts/Install-Toolchain.ps1`.

`lab\Invoke-Checks.ps1 -Commit <commit>` runs the same checks locally, in a
worktree of its own, for a machine without the hosted runners.

## The workflows

| Workflow | When | What |
|---|---|---|
| `workflows/ci.yml` | every push to main, every pull request, by hand | three jobs side by side: formatting and Clippy; all tests; every executable built in release mode, the converter started once, the executables kept for 14 days |
| `workflows/soak.yml` | every night at 03:17 UTC, by hand | real conversions on the runners, round after round (below) |
| `workflows/release.yml` | a pushed version tag such as `0.0.1`, by hand for an existing tag | the release, built, signed and published (below) |

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
- `resume`: held at one of the twelve laboratory hold points, the process
  ended there, then the recovery command the run printed.
- `rollback`: held at a point before the handoff marker is durable, ended,
  then the recovery command with `--rollback`.
- `cancel`: ended at a random moment within 40 seconds, without a hold, then
  whatever the run had printed.

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

A version tag pushed on a commit of main starts `workflows/release.yml`:

1. It checks that the tag is a version, is on main, and equals the version
   in `Cargo.toml`.
2. It builds `ntfs2refs.exe`, `ntfs2refs-recovery.exe` and
   `lab-volume-manifest.exe` in release mode.
3. It signs each with Azure Artifact Signing, Fara Technologies LLC first
   and Mike Fara appended, SHA-256 digests and RFC 3161 time stamps, and
   verifies both signatures with `signtool`.
4. It packs them with `lab\New-Release.ps1 -Binaries` (the ZIP, its SHA-256
   file, the source archive and the generated notes, which name each
   executable's signer).
5. It attests the ZIP and the executables (build provenance), and publishes
   the GitHub release of the tag with the ZIP and its SHA-256 file.

The signing credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`) are secrets of the `release` environment, which only
version tags and main can deploy to. Workflows started by a pull request do
not get them.

```bash
gh attestation verify ntfs2refs-<version>-windows-x64.zip --repo faratech/ntfs2refs --signer-workflow faratech/ntfs2refs/.github/workflows/release.yml
```
