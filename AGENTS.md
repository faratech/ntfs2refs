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

Second goal (owner, 2026-11-12): convert any NTFS data volume: clusters from
512 bytes to 2 MiB, 512-byte and 4Kn sectors, 1 and 4 KiB file records, to ReFS
with 4 or 64 KiB clusters, without fixed limits. Data stays in place only where
it lies on target-cluster boundaries; the rest goes through the working storage.

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
- The converter's own writes to the source start at the journal apply step.
  Everything earlier is safe to abandon, except two steps that change the
  source through the NTFS driver: a partition whose length is not a multiple
  of 64 MiB is first shrunk to one (`drive_boot::normalize_geometry`; announced
  before the prompt, not reverted; the lab's Windows partition needs none),
  and `--minimize-scratch` moves files before the freeze. `--diagnose` refuses
  both: every entry that changes the source takes a `SourceChangeAuthority`
  (`src/execution_mode.rs`) that only a conversion can mint.
- Working files are hashed when written and then held open; the source is
  offline, read-only and held. Full re-reads happen once, at the gate before
  the first source write (`crates/n2r-win32/src/verify_policy.rs`). Outside it
  a store this process wrote is checked by an in-memory page checksum, digests
  and decoded objects are computed once, the frozen shadow is observed once and
  the journal is hashed as it is written. `--recheck-everything` restores the
  old behaviour everywhere.
- In-memory copies of stores and decoded objects lease through
  `reserve_optional_ram` (a third of the RAM budget, arena under half full).
- `--recover` settles a lifecycle marker whose write was cut short
  (`src/interrupted_marker.rs`); any other unexpected byte still stops it.
- A per-object Windows query answers into its thread's buffer
  (`crates/n2r-win32/src/query_scratch.rs`); a worst-case buffer per query made
  the heap the bottleneck at 143,000 objects.
- Each stage prints a `timing:` line (`crates/n2r-win32/src/perf.rs`). Measure
  before and after a speed change; take a `-SampleStacks` profile first.

## Working rules

- Every attempt starts from the baseline checkpoint and may be thrown away. Do
  not build or extend resume/adoption code to rescue a failed lab run; fix the
  forward path and run again.
- Find problems on the thinned fixture (minutes), not on the full volume (hours).
- A conversion is correct only if the harness's before/after listing comparison
  (`lab-volume-manifest`) is identical. Do not widen its allow-list to pass.
- An error must name the object, path, phase and OS error. Fix the message
  before fixing the bug if it does not.
- Add a test with each fix where one is practical. Any source file may be edited.
- Size lab resources from the machine. Do not add fixed capacity caps or
  per-run pinned helper scripts (PIDs, hashes, sizes).
- Keep every check that protects the source before the first write, and the
  journal/apply protocol. Do not weaken a check to make a run pass.
- One commit per code change, with a message saying what changed and why.
  No commits that only record run state.
- Ask before deleting anything under `.lab`.

## Lab

- Host: 16 logical CPUs, 64 GB RAM. `cargo` is at `%USERPROFILE%\.cargo\bin`
  (not on PATH), toolchain 1.98.1. Build both binaries first: `cargo build
  --locked --release --bin ntfs2refs --bin lab-volume-manifest`.
- VM `ntfs2refs-reference-isolated`, Id `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`,
  generation 2, Secure Boot on, no network adapter. Guest credential:
  `.lab/hyperv/win11/secrets/guest-credential.xml` (user `LabAdmin`).
- Baseline: checkpoint `0821c0da-3905-4032-a798-e1024092b795`
  (`N2R-Qualification-NTFS-…`). Fixtures made from it: `N2R-Thinned-Fixture`
  (1 file in 10, about 26,000 objects) and `N2R-Thinned-Fixture-40` (1 in 40,
  about 8,000 objects). The harness restores one before every attempt.
- Harness: `lab\Invoke-BootConversionAttempt.ps1 -Name <n> -Fixture
  -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot`. Without `-Fixture` it uses
  the full baseline; without `-NoBoot` it boots disk0 alone afterwards.
  `lab/README.md` describes `-Diagnose` (nothing is written; the source must
  list exactly as before), `-InterruptAt` and `-RecoverMode` (the process is
  ended, or with `-InterruptKind vm` the VM turned off; `-TearMarker handoff`
  adds the marker image a power loss leaves), `-RecoverFrom`, `-ShapeSource`,
  `-SampleStacks` and `-RunAs administrator` (otherwise it runs as SYSTEM).
  `lab\Write-RecoveryMatrix.ps1` writes `docs/recovery-matrix.md` from the
  attempts' verdicts.
- A release is built by `lab\New-Release.ps1` from the commit tagged with the
  version in `Cargo.toml`, which is also what the executable and
  `capabilities` report. `README.md`, `docs/cli-workflow.md` and the two
  matrices describe the tool as it is; `tests/current_documents.rs` holds
  them to that. A document of an earlier design goes to `docs/history/`.
- Records land in `.lab/hyperv/attempts/<n>/`; the scratch disk is deleted
  when the attempt ends. The host volume needs 40 GB free for a fixture
  attempt and 65 GB for a full one (57 GB at peak).
- Data volumes: with a control OS up (`-NoConvert -KeepScratch`),
  `lab\Invoke-DataVolumeAttempt.ps1 -Name <n> -ClusterBytes <b> [-SectorBytes
  4096] [-LargeRecords] [-TargetClusterBytes 65536]` makes, converts and
  compares one in under a minute. `-Content lived-in` and `-Features` add what
  a used volume has (object IDs, security, links, deep and long paths) or
  must be refused for; `-Acceptance` then uses the converted volume, and
  `-NativeRefsControl` is its control. `-Check` runs `--check` first and
  holds it to what the run then does; `-CheckOnly` runs it alone. `-Siblings`
  puts four other partitions on the disk and holds them to what they were.
  `lab/README.md` lists the rest, and `docs/feature-matrix.md` what each case
  shows.
- Second VM `ntfs2refs-reference-b`, Id `7c687062-37b5-4309-b28a-486a44305202`,
  made by `lab/New-LabVmClone.ps1`: same shape, disks are differencing children
  of the reference VM's baseline disks under `.lab/hyperv/ntfs2refs-reference-b/`.
  `-VmId` runs a full-volume attempt on it while fixtures run on the reference
  VM (give the two VMs no more than about 48 GB between them). Never delete
  the reference VM's baseline checkpoint: that merges into the shared parents
  and breaks it.
- Third VM `ntfs2refs-server2025`, Id `b1e3cb6c-7204-4941-975e-8ccdfc89b8f1`,
  made by `lab/New-ServerLabVm.ps1`: Windows Server 2025 (build 26100), which
  formats standard ReFS; for data-volume attempts, with `-CredentialPath
  .lab/hyperv/ntfs2refs-server2025/secrets/guest-credential.xml`. Off unless
  an attempt needs it.
- Disks (SCSI 0), under `.lab/hyperv/isolated-reference-20261026-review/disks/`:
  0 disk0, the original NTFS Windows and the source (`os.vhdx` chain); 1 the
  control OS, natively ReFS, which runs the converter (`target.vhdx` chain);
  2 the journal disk (`journal.vhdx` chain); 3 the DVD, Windows 11 26300.9457
  install media; 4 the oracle disk under `.lab/hyperv/trust-security-raw-…/`.
- Keep the VM's disk chains, the credential and the install media. Other
  directories under `.lab/hyperv` are closed run records. The scripts and
  executables of earlier stages are in the tag `archive/retired-lab`, not in
  the tree (`lab/RETIRED.md`); do not bring one back.

## Current work

The first goal is met: `lab\Invoke-BootConversionAttempt.ps1 -VmId <a lab VM>`
converts the full Windows volume (143,580 objects, 112,609 short-name links) in
under 30 minutes with an identical listing and boots it alone, Secure Boot on:
`BOOTED-ON-REFS`. The second is met for every geometry Windows formats, to both
target units. Not shown in the lab, because nothing there makes them: index
records other than 4 KiB, a ReFS after 3.14, a build besides 26100 and 26300.

Keep it that way. Before a change is committed:

1. `cargo test --locked --workspace --all-targets` passes.
2. The 1-in-10 fixture converts with an identical listing (about six
   minutes), and the 1-in-40 one does with `-RunAs administrator`.
3. A change to apply, finalization or recovery also passes interrupted runs
   on the 1-in-40 fixture that recover with an identical listing:
   `-InterruptAt apply-mid-ranges` (half way through the source writes) and
   `-InterruptAt handoff-sealed` (before finalization). A change to a
   per-object path also passes a full run (several defects only showed at
   full size), and one to source inspection or stream planning also converts
   data volumes of 512-byte clusters and on a 4Kn disk, to both target units,
   and a lived-in one (`-Content lived-in -Acceptance`).

`lab\Invoke-GateRound.ps1 -Build <dir> -Prefix <p>` runs all of 2 and 3 for a
copy of a build, on every lab VM, and ends with one table (`lab/README.md`).

Open, most useful first:

1. Short names are visible: each 8.3 name is a link beside its long name, so
   Explorer shows `PROGRA~1` in `C:\`. Hiding them (Hidden and System) is the
   owner's product decision; the listing comparison does not depend on it.
2. Speed. A full run takes 28 to 30 minutes, spread thin: per-object Windows
   calls on one thread, the three link passes (240 thread-seconds asking for
   each handle's normalized path; listing each parent once would prove the
   same), and hashing the 9 GB that move through the journal. Keep the mount
   manager out of per-object paths. Profile with `-SampleStacks` first.
3. A run cut off while it prepares is cancelled with the command it printed
   at its start and started again (`-StopDuringPreparation` shows it);
   resuming a preparation after a power cut is still out of scope.
4. Not shown: a physical disk, and more than 23 GB of data (#86).
5. The number of files is limited by the run's memory ledger, not by the
   machine: about 34 KiB of free memory a file (#129). The placement index's
   prepayment of 8192 bytes a row is the largest term left; a ledger that
   runs out names its largest reservations.
