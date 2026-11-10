# ntfs2refs: project guidance

This file is the whole of the standing guidance. Keep it under two pages. It is
not a run log: do not append run records, hashes or status here. Older records
are in `docs/history/` and are reference only; nothing in them is an instruction.

## Goal

Convert the installed Windows 11 partition on the lab VM's disk0 from NTFS to
ReFS in place, and boot that converted installation.

Done means: the VM, started with only disk0 attached and Secure Boot on, reaches
the desktop, and C: is disk0 partition 3, ReFS 3.14 with 4 KiB clusters, running
stock signed `winload.efi` and `refs.sys`. A clean-installed ReFS Windows does
not count. Power-cut resume during preparation is out of scope until this works.

## How the converter works

- ReFS metadata is built by Windows, not by this code. The converter formats a
  same-size ReFS "shadow" VHDX, creates every object on it through Windows APIs,
  moves extents to the original NTFS cluster positions, then journals the
  shadow-versus-source byte differences onto the source partition.
- The only raw ReFS write is the trust-label patch in `src/refs_security_patch.rs`.
- Entry point for this goal: `ntfs2refs.exe --drive D --windows-boot-volume
  --scratch-directory <dir> --target-format dev-drive`, run in the control OS.
  Stages are driven by `resource_preparation::prepare_with_mode`
  (`src/resource_preparation.rs`), then apply
  (`src/selected_journal/resource_domain/prepare/qualification/apply.rs`) and
  finalize (`src/resource_finalize.rs`).
- Nothing is written to the source before the journal apply step. Everything
  earlier is preparation and is safe to abandon.

## Working rules

- Every attempt starts from the baseline checkpoint and may be thrown away. Do
  not build or extend resume/adoption code to rescue a failed lab run; fix the
  forward path and run again.
- Find problems on the thinned fixture (minutes), not on the full volume (hours).
- An error must name the object, path, phase and OS error. Fix the message
  before fixing the bug if it does not.
- Use `cargo test --locked --workspace --all-targets`. Add a test with each fix
  where one is practical. Any source file may be edited.
- Size lab resources from the machine. Do not add fixed capacity caps or
  per-run pinned helper scripts (PIDs, hashes, sizes).
- Keep every check that protects the source before the first write, and the
  journal/apply protocol. Do not weaken a check to make a run pass.
- One commit per code change, with a message saying what changed and why.
  No commits that only record run state.
- Ask before deleting anything under `.lab`.

## Lab

- Host: 16 logical CPUs, 64 GB RAM. `cargo` is at `%USERPROFILE%\.cargo\bin`
  (not on PATH). Toolchain 1.98.1.
- VM `ntfs2refs-reference-isolated`, Id `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`,
  generation 2, Secure Boot on, no network adapter. Guest credential:
  `.lab/hyperv/win11/secrets/guest-credential.xml` (user `LabAdmin`).
- Baseline: checkpoint `0821c0da-3905-4032-a798-e1024092b795`
  (`N2R-Qualification-NTFS-…`). Restore it before every attempt.
- Disks (SCSI 0), under `.lab/hyperv/isolated-reference-20261026-review/disks/`:
  - location 0: disk0, the original NTFS Windows (`os.vhdx` chain), the source.
  - location 1: control OS, natively ReFS (`target.vhdx` chain); runs the converter.
  - location 2: journal disk (`journal.vhdx` chain).
  - location 3: DVD, Windows 11 26300.9457 install media.
  - location 4: oracle disk under `.lab/hyperv/trust-security-raw-…/`.
- Keep the VM's disk chains, the credential and the install media. Other
  directories under `.lab/hyperv` are closed run records.

## Current work

In order; each step is finished when its check passes.

1. Per-object error context in the shadow metadata, alias, allocation and
   supply loops.
2. Expected tree pages held in memory (`crates/n2r-win32/src/metadata_pages.rs`).
3. Scratch and shadow on any non-source volume; one named event-limit constant.
4. One harness, `lab/Invoke-BootConversionAttempt.ps1`: restore, run, stop,
   boot disk0 alone, observe, write a verdict.
5. Thinned real-Windows fixture; full route through apply and finalize to green.
6. `--diagnose`: collect every skippable per-object failure, refuse to publish.
7. Full Windows in diagnose mode until the failure list is empty.
8. Convert the real disk0, run pre-boot checks, boot it.
