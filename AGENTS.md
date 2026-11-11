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
- Working files are hashed when written and then held open; the source is
  offline, read-only and held. Full re-reads happen once, at the gate before
  the first source write (`crates/n2r-win32/src/verify_policy.rs`), not at every
  checkpoint. Outside that gate a store this process wrote is opened without
  being re-read and its pages are checked by an in-memory checksum; a digest
  of an immutable tree is computed once; an expected object decoded once is
  kept and handed out as a copy; the frozen shadow is observed once during
  capture; the journal is hashed in file order as it is written.
  `--recheck-everything` restores the old behaviour everywhere.
- In-memory copies of stores and of decoded objects are optional: they lease
  through `reserve_optional_ram` (a third of the RAM budget in total, and only
  while the arena is under half full), so they cannot starve a required
  reservation.
- A per-object Windows query answers into its thread's buffer
  (`crates/n2r-win32/src/query_scratch.rs`) and copies out only the answer.
  Do not allocate a worst-case buffer per query: at 143,000 objects that
  made the heap the bottleneck of every walk.
- Each stage prints a `timing:` line to stderr (`crates/n2r-win32/src/perf.rs`).
  Measure before and after any speed change, and take a `-SampleStacks`
  profile before deciding what to change: most time was in places no timer
  named.

## Working rules

- Every attempt starts from the baseline checkpoint and may be thrown away. Do
  not build or extend resume/adoption code to rescue a failed lab run; fix the
  forward path and run again.
- Find problems on the thinned fixture (minutes), not on the full volume (hours).
- A conversion is correct only if the harness's before/after listing comparison
  (`lab-volume-manifest`) is identical. Do not widen its allow-list to pass.
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
  (`N2R-Qualification-NTFS-…`). Fixtures made from it: `N2R-Thinned-Fixture`
  (1 file in 10, about 26,000 objects) and `N2R-Thinned-Fixture-40` (1 in 40,
  about 8,000 objects). The harness restores one before every attempt.
- Harness: `lab\Invoke-BootConversionAttempt.ps1 -Name <n> -Fixture
  -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot`. Without `-Fixture` it uses
  the full baseline; without `-NoBoot` it boots disk0 alone afterwards.
  `-Diagnose` reports every per-object failure and writes nothing.
  `-CheckpointAfterConvert <name>` saves a run that stopped after apply;
  `-Recover -Checkpoint <name>` retries its finalization with `--recover`.
  Records land in `.lab/hyperv/attempts/<n>/`. The scratch disk is deleted when
  the attempt ends; the host volume needs 40 GB free for a fixture attempt
  and 65 GB for a full one (it uses about 57 GB at its peak).
  `-SampleStacks` records the worker's call stack a hundred times a second and
  writes `stacks.txt` (phase, step and stack per line) into the attempt folder:
  use it to find where unnamed time goes before changing anything for speed.
  Threads a walk hands objects to are sampled too (`stack_sampler::helper`),
  under the step's label followed by ` [helper threads]`.
- Second VM `ntfs2refs-reference-b`, Id `7c687062-37b5-4309-b28a-486a44305202`,
  made by `lab/New-LabVmClone.ps1`: same shape, disks are differencing children
  of the reference VM's baseline disks under `.lab/hyperv/ntfs2refs-reference-b/`.
  It has only the baseline checkpoint. Pass `-VmId` to the harness to run a
  full-volume attempt on it while fixtures run on the reference VM (give the
  two VMs no more than about 48 GB between them). Never delete the reference
  VM's baseline checkpoint: that merges into the shared parents and breaks the
  clone.
- Build both binaries first: `cargo build --locked --release --bin ntfs2refs
  --bin lab-volume-manifest`.
- Disks (SCSI 0), under `.lab/hyperv/isolated-reference-20261026-review/disks/`:
  - location 0: disk0, the original NTFS Windows (`os.vhdx` chain), the source.
  - location 1: control OS, natively ReFS (`target.vhdx` chain); runs the converter.
  - location 2: journal disk (`journal.vhdx` chain).
  - location 3: DVD, Windows 11 26300.9457 install media.
  - location 4: oracle disk under `.lab/hyperv/trust-security-raw-…/`.
- Keep the VM's disk chains, the credential and the install media. Other
  directories under `.lab/hyperv` are closed run records.

## Current work

The goal is met. One command, `lab\Invoke-BootConversionAttempt.ps1 -VmId <a
lab VM>`, restores the baseline, converts the full Windows volume (143,580
objects, 112,609 short-name links) in under 30 minutes with an identical
before/after listing, boots disk0 alone with Secure Boot on and signs in to
the desktop: outcome `BOOTED-ON-REFS`.

Keep it that way. Before a change is committed:

1. `cargo test --locked --workspace --all-targets` passes.
2. The 1-in-10 fixture converts with an identical listing (about six minutes).
3. A change to apply or finalization also passes `-Recover` on a run stopped
   after apply, and a change to a per-object path also passes a full run:
   several defects only showed at full size (a row that Windows fills on
   large volumes, hard links, memory held per batch).

Open, most useful first:

1. Short names are visible. Each 8.3 name is a link beside its long name
   with the long name's attributes, so Explorer shows `PROGRA~1` in `C:\` and
   `MICROS~1.LNK` on the desktop. Hiding them (Hidden and System) is a
   product decision for the owner; the listing comparison does not depend on
   the links' attributes.
2. Speed. A full run takes 28 to 30 minutes, spread thin: per-object Windows
   calls on one thread (source observation, extent placement, metadata
   restoration), the three link passes, and reading and hashing the 9 GB
   that move through the journal. The largest single item left is the link
   passes asking Windows for each handle's normalized path (240
   thread-seconds a run); listing each parent directory once would prove
   the same names and parents. Keep the mount manager out of per-object
   paths: its queries stall unpredictably. Take a `-SampleStacks` profile of
   a full run before choosing.
3. Power-cut resume during preparation is still out of scope.
