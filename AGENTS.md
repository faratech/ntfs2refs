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

## Verified baseline as of 2026-10-26

- Public `ntfs2refs convert --request` completed a fourteen-object tree on the
  original 52 GiB partition, retaining 134,217,728 payload bytes at their original
  physical extent, relocating 8,933,376 and materializing 88. There were 134
  patches, 231,337,984 raw target bytes written and a 462,706,832-byte journal.
  The executable SHA-256 is `0a90d93c715e7ac9f2ad3b0560b5a1dadb5b4da9c879d3a5711bef81e0ad160c`,
  built from `f025c8b2a0e48605edac07f67af32968c8b9b33f`; later commits do not
  inherit this qualification. A separate strict native check matched all
  fourteen objects and the retained file's original LCN 2173673.
- This retention fixture used synthetic allocation history: an 8 GiB zero-written
  temporary file and normal NTFS creation of the 128 MiB file, with no source
  extent moves. It does not prove arbitrary or low-LCN placement. Shadow payload
  initialization was still 143,151,192 bytes; actual allocated scratch and full
  process I/O were not measured. The fourteen-object result passed a bounded
  native create/grow/truncate/rename/delete and 128-entry workload, strict
  verification afterward, and strict verification after clean reboot. The exact
  mutation report constrains the changed root basic-info record. The 128 MiB
  file's original LCN/hash and source label survived with the shadow absent.
  This does not establish arbitrary storage power-loss or broad workload safety.
- That fresh full conversion passed protected exact-frozen target semantics
  and automatic original-label restoration through capture/frozen reconciliation/
  finalization. The earlier separate `complete-label` repetition/reboot result
  used a backfilled legacy request and remains distinct historical evidence.
- The earlier twelve-object public conversion retained zero bytes, wrote
  346,841,088 target bytes with a 693,708,354-byte journal, and passed strict
  native verification after reboot. That older reboot and the prepared one-file
  64 KiB retention result do not qualify the fourteen-object run's later behavior.
- Public preactivation cancellation passed on the 52 GiB fixture. Public
  `rollback --without-shadow` also passed after a controlled first-flushed-write
  process exit with the exact shadow detached. It proved the complete original
  NTFS preimage before writable mounting, completed the version-4 rollback
  marker, and restored the original mount/label and four user-file hashes.
  Those four hashes and original NTFS availability/identity also matched after
  a clean reboot; full twelve-object security/timestamp semantics were not
  rechecked after boot, and post-mount whole-image equality is not claimed.
  This is one process-fault case; broader write/flush, power-loss and interrupted
  marker-completion qualification remain open. The producer passed integrated
  protected-target/source admission, but intentionally stopped before complete
  ReFS conversion and automatic label restoration.
- The separate REFSNT experiment adopted one existing 4 KiB physical cluster
  with eight metadata writes totaling 131,072 bytes and three real image
  flushes. The payload stayed unchanged and independent Rust checks passed.
  Microsoft rejected the imported writer candidate with a Medium Allocator
  structural error. A separate fresh unmodified reference import passed native
  read verification of its two original files, with zero overlay pages and the
  adopted name absent. That baseline has no mutation/reboot qualification and
  does not qualify the rejected writer; its specific defect remains unisolated.

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
- `src/preparation_progress.rs`: bounded diagnostic scan progress, outside the
  journal format and all admission/recovery authority.
- `src/general_recovery.rs`: public raw resume, rollback and finalization.
- `src/general_label_completion.rs`: native-only post-handoff label completion.
- `src/source_volume_label.rs` and `crates/n2r-win32/src/volume_label*`:
  reconcile the exact frozen NTFS UTF-16 label and restore it through Windows.
- `crates/n2r-win32/src/shadow_native.rs`: native shadow construction, measured
  retention attempts and strict tree verification.
- `crates/n2r-win32/src/bitmap_paging.rs`: bounded complete bitmap assembly,
  shared by live source, shadow and frozen allocation collection. Native report
  schema 6 replays original page responses; legacy reports reject continuations.
  Complete-map/page hashes have distinct contracts. See
  [native bitmap pagination](docs/native-bitmap-pagination.md). This source work
  has no native paging qualification and does not widen conversion authority.
- `crates/n2r-win32/src/retrieval_paging.rs`: bounded complete stream mappings
  and raw-page provenance. Report schema 7 replays retrieval continuations;
  legacy schemas retain their single-response rules. Shadow placement verifies
  the explicitly assembled map. See [retrieval pagination](docs/native-retrieval-pagination.md).
  This does not add NTFS attribute-list support or native conversion qualification.

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

The latest fourteen-object retained/mutated/reboot-verified branch is saved as
checkpoint `f6393f52-56ce-4847-bc24-7d5e019ac2e2`; its actual parent identity was
confirmed and the VM was running after preservation. Use the successful
`preserved-checkpoint.json` report, not the earlier empty-ID checkpoint attempt.
Follow the canonical [preservation record](lab/PRESERVATION.md). Specific user
approval is required for irreversible checkpoint/backing cleanup or reset of
the verified VM; blanket project authorization does not grant it. No further
disk experiment is authorized on this preserved branch. Read-only inventory
and source/test work may continue. No export or copy is currently needed.

Mike specifically approved removal of the independently reconstructible fixed
reference VHD and creation of a separate offline fixture on 2026-10-26. Only
`.lab/hyperv/corpus/devdrive-20261023T231918797Z/target-fixed.vhd` was removed,
after fresh hash, identity, attachment and complete registered-ancestry checks.
The packet, overlays, evidence, archive and all fifty original checkpoints remain.
The separate VM `ntfs2refs-reference-isolated`, ID
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`, has fixed 8 GiB RAM,
four vCPUs, no NIC and automatic checkpoints disabled. Its ownership record is
`.lab/hyperv/isolated-reference-20261026-review/manifest.json`. Its three standalone
VHDX files are independent copies whose hashes match the archive; container UUIDs
were preserved by copying, while host file identities are new. Do not use a VHD
UUID alone to infer backing-file aliasing. vTPM/Secure Boot settings were retained.
The provisioning manifest is a historical preboot record. The ejection cleared
the DVD's ISO path; the DVD device and boot order remain. An initial start was
denied access to the inherited ISO. The failed post-ejection SDDL string comparison
does not establish an access-rule change: the prior SDDL was held only in memory,
not persisted, so a rule delta cannot be distinguished from representation/order
changes. Do not claim that the pre-ejection ACL or a rule-level delta is known.
The retry dispatched at 2026-10-26 14:46:25.6485767 UTC booted normally and
authenticated through PowerShell Direct by this VM GUID using the existing
credential. Its authorization provenance needs the chronology in
[the preservation record](lab/PRESERVATION.md): the local `Approved.` entry has
no exposed sender/account/origin metadata, and its scope cannot be established
from the supported view. Mike's explicit main-room approval at 15:01:36 UTC came
later and must not be attributed retroactively to the 14:46 dispatch. Treat
approval wording in original receipts as actor claims, not independent proof.
The VM is now running without a NIC. The recorded post-ejection/current ISO SDDL
hash matched across the retry; this is separate from the missing earlier ACL
baseline. No explicit ACL repair was performed. Windows 11 Pro 26300.9457
and the expected `refs.sys` hash matched. The observed disk-role mapping and
resource margins are in
`.lab/hyperv/isolated-reference-20261026-review/readiness-20261026T144625632Z/binding-summary.json`.
OS disk 0 is GPT/NTFS; target disk 1 and journal disk 2 are RAW and uninitialized.
No J: volume, target NTFS source, or native-experiment enrollment is established.
No writer/native disk experiment has run on this fixture. The raw observation
JSON contains remoted service enum wrappers; read it with `ConvertFrom-Json
-AsHashtable`, or use the normalized binding summary. Later source serializes
those enum fields as strings; that serialization change has not been rerun here.
Do not dispatch helpers bound to the old `win11` manifest against this new VM.
The recorded later explicit approval covers normal boot/read-only guest readiness,
not formatting, reference import, a writer experiment, conversion or further cleanup.

Source-only baseline prerequisites are in `lab/IsolatedBaselineGuards.psm1` and
`lab/guest/IsolatedJournalZero.cs`; see
[the source boundary](docs/isolated-baseline-prerequisites.md). They validate
structural observations and a complete same-stream zero receipt, and return
review plans only. They neither attest a live native source nor grant write
authority. No journal initialization/import runner or live device scan has run.
Do not substitute these JSON plans for live ownership/handle acquisition. Their
fresh C: staging proposal preserves the old importer's C:-only guard and still
needs execution review. No old helper route constants were changed.

Dispatch long work once, retain its task handle and collect terminal evidence.
`Collect-LabAdmittedConversion.ps1` reports live phase and I/O counters; those
counters are not a completion percentage. The current full-image workflow can
read many multiples of the partition size. During journal preparation its
optional `journalProgress` shows the comparison/recheck subphase, combined scan
bytes and elapsed time even before the first journal write. Missing or partial
telemetry is ignored; see [the progress contract](docs/journal-preparation-progress.md).
Guest-local shadow attachment may
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

Windows CI passed at `381a8c1` (run `40264890298`): format, Clippy, workspace
tests and release builds. Do not transfer that result to later changes.
`evidence/qualification-registry.json` records bounded implementation/native
claims and their exact evidence pins; it never grants execution authority.

Next work should broaden source/placement coverage, reduce measured scratch and
I/O costs, extend the native interruption/marker-recovery matrix, and investigate
the rejected independent writer using the accepted baseline control. The
fourteen-object aged-layout conversion, automatic label path, mutation and
reboot now have bounded native evidence; do not repeat them without a concrete
new change or unresolved gate. Preserve completed fixture paths and add
versioned profiles rather than deleting their enrollment checks. Follow
[the preservation constraint](lab/PRESERVATION.md) before any lab operation.
Report payload retained, relocated and materialized, actual scratch allocation,
changed bytes and journal capacity separately. Boot and broad production
qualification remain separate objectives.
