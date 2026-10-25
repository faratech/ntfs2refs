# ntfs2refs project guidance

## Objective and working approach

Build an offline NTFS-to-ReFS converter that runs on the machine owning the
volume and preserves eligible payload blocks in place. Prefer Rust. Hyper-V
is laboratory infrastructure; the converter must not depend on a hypervisor.
Focus on nonboot data volumes. Boot conversion remains deferred.

Continue the existing implementation. Prioritize concrete code and the next
bounded experiment over repeating general research or restarting the writer.
Run checks appropriate to the change; repeat expensive native scans only when
new changes, failures or unresolved evidence justify them. Never weaken source
admission, allocation evidence or recovery barriers to obtain a passing run.

On this Windows host, also read `C:\Users\mfara\.codex\RTK.md` when present.

## Verified baseline as of 2026-10-25

- Public `ntfs2refs convert --request` converted twelve existing objects,
  including a naturally allocated 128 MiB file, on the original 52 GiB NTFS
  partition. Native ReFS verification and strict verification after reboot
  passed. There were 106 patches, 346,841,088 target bytes written and a
  693,708,354-byte external journal.
- That run retained **zero payload bytes**: five ordinary payloads were
  relocated and 88 resident bytes materialized. The older prepared one-file
  run retained 64 KiB, but does not prove general retention of existing files.
- Native `complete-label` restored the original label, repeated successfully
  without a second setter call, and passed strict twelve-object verification
  after reboot. The shadow was absent. This test used an explicitly backfilled,
  separately pinned legacy request; a fresh whole conversion exercising the
  new capture-to-automatic-label path remains to be qualified.
- The separate REFSNT experiment adopted one existing 4 KiB physical cluster
  with eight metadata writes totaling 131,072 bytes and three real image
  flushes. The payload was unchanged and the small overlay passed independent
  Rust inspection. Microsoft acceptance of this writer output is unqualified.

Use the detailed reports rather than inferring broader support:

- [Native conversion results](docs/general-native-conversion-results.md)
- [Source labels and native completion](docs/source-volume-label.md)
- [Owning-machine CLI](docs/cli-workflow.md)
- [Device binding discovery](docs/device-binding-discovery.md)
- [Strict writer research](research/refsnt-adopt/README.md)

The bounded profile is NTFS 3.1, 512-byte logical sectors, 4 KiB clusters and
1 KiB MFT records, targeting ReFS 3.14 with 4 KiB clusters. Current admission
qualification targets Windows build 26300. Bounds include 128 ordinary files,
32 directories and 256 MiB logical contents, subject to exact space checks.
Parser support for a feature is not evidence that conversion preserves it.

## Code map and recovery contracts

- `src/general_conversion.rs`: live qualification, journal/ticket preparation,
  activation, apply and finalization in one process.
- `src/general_qualification.rs` and `src/general_source_admission.rs`: frozen
  source evidence and opaque admission authority; JSON success flags cannot
  substitute for actual device observations.
- `src/general_reconstruct.rs` and `src/lab_reconstruct.rs`: native adapter and
  durable old/new journal protocol, exact-image checks and handoff.
- `src/general_recovery.rs`: public raw resume, rollback and finalization.
- `src/general_label_completion.rs`: native-only post-handoff label completion.
- `src/source_volume_label.rs` and `crates/n2r-win32/src/volume_label*`:
  reconcile the exact frozen NTFS UTF-16 label and restore it through Windows.
- `crates/n2r-win32/src/shadow_native.rs`: native shadow construction, measured
  retention attempts and strict tree verification.

Preserve these distinctions:

1. Raw recovery requires the pinned request/ticket, actual journal identity,
   expected device state and its recorded shadow dependency.
2. `N2RHND01` closes raw replay and rollback before the writable ReFS mount.
   Never clear or repair a partial/foreign marker to reopen recovery.
3. Exact-image marker completion refuses a target changed by native ReFS use.
   A journal-only handoff receipt proves only the immutable journal and marker;
   it makes no assertion about the current raw image and grants no replay
   authority.
4. `complete-label` requires the original mounted ReFS partition, a pinned
   desired label and strict native tree verification before and after normal
   metadata restoration. It does not open the shadow, replay raw patches or
   change disk attributes.
5. Keep the shadow enrollment label `n2r-retained-shadow` enforced during
   construction. Converted-source verification uses the explicit restored
   label. Preserve legacy request serialization when optional fields are absent.

Retain both legacy and metadata-inclusive allocation evidence. Do not treat a
legacy-free region as safe when the metadata-inclusive view marks it occupied.
Do not invent dummy retained ranges for relocation-only conversion.

## Laboratory operation

Use `lab/Lab.psm1`, the manifest and existing dispatch/collect scripts. Verify
the actual owned VM, checkpoint branch, device GUIDs, geometry and task state
before mutations. Hyper-V Administrator access has been granted on this host;
probe management access before requesting elevation again.

The Windows 11 VM is `ntfs2refs-win11`, ID
`eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c`. The successful twelve-object branch is
saved as checkpoint `94091799-c19b-4e6a-ada0-fd87cbdb6ad0`. Verify current state
before using it; the guest has subsequently run label completion and rebooted.
Never restore, reboot or redispatch over a still-running or unknown operation.
An interrupted host observation does not prove that the guest worker stopped.

Dispatch long work once, retain its task handle and collect terminal evidence.
`Collect-LabAdmittedConversion.ps1` reports live phase and I/O counters; those
counters are not a completion percentage. The current full-image workflow can
read many multiples of the partition size. Guest-local shadow attachment may
disappear across reboot; raw recovery must restore its exact enrolled backing
through the existing helper when required.

Compare PowerShell timestamps using their preserved UTC kinds/ticks.
`ConvertFrom-Json` can return a `DateTime`; stringifying it before parsing can
lose timezone information. Do not reject a successful reboot because a local
and UTC timestamp were compared incorrectly.

## Storage, provenance and repository hygiene

`lab/lab.config.json` limits actual lab usage to 208 GiB and requires 64 GiB
host free space. Check actual free space and backing allocation before large
experiments. Sparse flags, logical lengths and reported sparse ranges alone
have not provided reliable capacity accounting on this ReFS host.

As of this baseline, automatic approval review still blocks deletion of the
disposable image at
`.lab/research/strict-adoption-image-81714d11aed444deab9fed82436e551c/refs.adopt-test.raw`,
including after explicit user authorization. It remains present. Its verified
131,280-byte `final-metadata.cow`, trace, results and evidence pins are retained.
Report the block accurately; do not assume cleanup succeeded or retry the same
deletion through another mechanism.

Keep `.lab`, images, VM/checkpoint chains, journals, ISOs, binaries and secrets
out of Git. Preserve source archives and recovery material needed by active
runs. Verify exact resolved paths before cleanup; use native PowerShell
`-LiteralPath` operations and avoid recursive deletion of computed targets.

REFSNT stays pinned under ignored `.lab/research/refsnt`. Its GPL engine is
external research, not a Rust product dependency. Commit original adapters,
provenance and measured results; do not copy upstream engine code into product
sources or claim native compatibility from its checker alone.

## Build and next work

The toolchain is pinned to Rust 1.98.1. If Cargo is not on PATH, use
`C:\Users\mfara\.cargo\bin\cargo.exe`. Run `cargo fmt --all --check`, focused
tests and appropriate release builds. Use the workspace suite for changes
spanning shared contracts. Inspect `$LASTEXITCODE` in PowerShell. Documentation
and guidance changes do not need another native conversion run.

Next work should improve retention on independently populated volumes, qualify
the restricted writer through Microsoft's driver once capacity permits, finish
native public interruption/recovery coverage, and exercise the fresh automatic
label path. Preserve completed fixture paths and add versioned profiles rather
than deleting their enrollment checks. Report payload retained, relocated and
materialized, actual scratch allocation, changed bytes and journal capacity
separately. Boot and broad production qualification remain separate objectives.
