# ntfs2refs

Rust tooling and a Hyper-V laboratory for researching offline, extent-preserving
NTFS-to-ReFS conversion. The current focus is data volumes; Windows OS-volume
conversion and build-specific boot qualification are deferred.

The drive-oriented Windows entry point is now available:

```powershell
ntfs2refs --list
ntfs2refs --drive d
ntfs2refs --drive d --partition 2
ntfs2refs --drive 3 partition 2
```

It lists disks and partition numbers, resolves the selected volume, and asks
for confirmation before creating working storage or starting conversion.
`--drive d partition 2` is also accepted. Conversion uses the existing native
engine and automatically prepares independent recovery storage. Current scope
is experimental data volumes; unsupported layouts and features are refused.
See [the workflow and current native results](docs/cli-workflow.md).

New runs also save a checksummed recovery bundle before activation:

```powershell
ntfs2refs --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion --recovery-sha256 ORIGINAL_CHECKSUM
```

Add `--rollback` to restore NTFS before handoff. The new recovery wrapper defaults
to No and keeps the existing native recovery gates. Sealed public build
`2cac76...` has now resumed a deliberately interrupted conversion after reboot,
using only its generated bundle and original printed checksum. Native ReFS
matched all 15 objects and 10 file hashes, with the original label and mount
preserved. See [the exact recovery result](evidence/bundle-cli-resume-20261029.json).
Separate rollback qualification is in progress. Later read optimizations and
completion-marker routing are release-built and do not inherit that native result.

The affirmative drive command has completed on the existing 52 GiB test
partition with automatic staging and an observed native exit 0. Native ReFS
verification passed, and all seven user files matched after cold boot.
See the [exact command, evidence and limits](evidence/drive-cli-native-20261028.json).

**The experimental source-backed native-shadow path converted a fresh15-object/
10-file tree on its original partition, then passed native mutation and reboot
checks.** It used genuine live source/target admission,157 patches/67.3MiB and a
134.6MiB recovery journal. Shadow user payload initialization was55 exception
bytes; normalized system streams added20,568 bytes. Peak converter working set
was68.8MiB in a4GiB VM. The nonzero4MiB file prefix retained its original physical
mapping. Most of the large zero-filled file changed mappings, so the small write
count does not establish payload-independent scratch for arbitrary nonzero data.
The frozen laboratory path has since passed same-build interruption, resume
and rollback. Newer managed staging has passed typed reboot recovery in both
directions and the public bundle Resume described above. Exact binaries and
scopes remain separate; see the [build provenance](docs/experimental-build-provenance.md)
and [pinned results](docs/native-composite-experimental.md).

**The public Rust CLI converted a fourteen-object tree on its original 52 GiB
partition while retaining a normally allocated 128 MiB payload extent.**
The exact `f025c8b` binary passed integrated protected-target/source admission,
applied 134 patches and automatically restored the original source label.
A separate strict native verifier matched all fourteen objects and confirmed
the large file at its original LCN. The fixture used synthetic 8 GiB allocation
history and no source extent moves; arbitrary or low-LCN placement remains open.
The run relocated 8,933,376 bytes and materialized 88 resident bytes. Raw target
writes were 231,337,984 bytes and the external journal was 462,706,832 bytes.
Shadow initialization remained payload-proportional; allocated scratch and full
process I/O were not measured. A bounded native mutation workload, strict
fourteen-object verification afterward and strict verification after clean
reboot also passed. The original 128 MiB mapping/hash and source label survived
with the shadow absent. See the [exact result and limits](docs/general-native-conversion-results.md#public-fourteen-object-conversion-with-a-retained-128-mib-extent).

The earlier twelve-object public run relocated every ordinary payload and
retained zero bytes; its strict native/reboot result remains separately pinned.

**A prepared one-file NTFS-to-ReFS conversion passed inside the Windows 11 VM.**
The same partition became readable through Microsoft's ReFS driver while the
64 KiB payload extent stayed unchanged. A clean reboot/remount and a native
50 MiB create/grow/truncate/rename/delete workload also passed. See the
[native result and its limits](docs/native-conversion-results.md).
**An existing four-file tree has now also converted on its original partition.**
Microsoft's ReFS driver matched all file contents, names, stored timestamps and
permissions. The source extents were never prearranged; all four payload ranges
required relocation because they conflicted with ReFS metadata. See the
[tree conversion result and its limits](docs/tree-conversion-results.md).
The Windows executable now exposes an experimental
[owning-machine conversion and recovery CLI](docs/cli-workflow.md). Conversion
requires live source/target qualification and an independent journal; image
feasibility plans remain non-executable. The current profile is bounded and
boot volumes remain excluded.
The [source-label path](docs/source-volume-label.md) passed fresh capture,
frozen reconciliation and automatic finalization in the fourteen-object run.
Separate native-only completion, repetition and reboot passed earlier on the
twelve-object tree; that command does not replay the raw journal.
Admission now requires [protected target semantics](docs/protected-target-semantics.md)
on the exact frozen image. Equal complete hashes across protected observation
passed both the earlier helper check and the fresh full conversion. Public
[operation state and preactivation cancel](docs/public-cancel-and-operation-state.md)
and explicit shadowless rollback are implemented; positive native recovery
qualification is recorded separately from unit tests. Public preactivation
cancellation passed on the 52 GiB fixture. Public `rollback --without-shadow`
also passed after a controlled first-flushed-write process exit with the shadow
detached: it proved the exact NTFS preimage before restoring writable NTFS,
the original mount/label and four known user files. Those four files and
original availability also matched after a clean reboot; complete postboot
metadata/security semantics were not rechecked. This is one process-fault
case; storage power-loss and broader interruption coverage remain open.
The [general guest conversion result](docs/general-native-conversion-results.md)
records a separate successful same-partition run, post-handoff mutation and
reboot, with its current source-admission and retained-extent limits.
The inspector now reconciles [raw NTFS directory indexes and MFT names](docs/ntfs-namespace-reconciliation.md)
on its initial profile, alongside allocation ownership diagnostics.
It also resolves [central and legacy security descriptors](docs/ntfs-security-reconciliation.md),
with independent Windows buffer-parser checks on the native captures.
The [Rust file-handle collector](docs/native-ntfs-file-attestation.md) now also
compares those bytes with native queries inside the VM. Kernel descriptors
matched 16 source objects; API inheritance views and cached root access time
exposed differences retained in the strict comparison. The
[paired security-view implementation](docs/paired-security-and-resident-data.md)
now records API projections separately and has reproduced both views on native
ReFS, including the two resident Windows cache files.
Native [stream/extent and bitmap reconciliation](docs/native-ntfs-stream-attestation.md)
now matches the full control-volume bitmap and every fixture object's stream
mapping, including ADS and sparse holes. Native [logical-stream hashing](docs/native-ntfs-logical-data.md)
also matches every supported fixture stream without changing the protected
source. The certificate-backed runs issued device-bound certificates with all
admission gates satisfied and completed its connected journal/cutover path.
The [source-admission work](docs/source-admission-progress.md) now includes
native directory observations, explicit object dispositions and actual backup
boot/MFT-mirror checks. It reports remaining refusals; an admission certificate
has not yet been issued for arbitrary existing volumes.
An [existing four-file tree now has a native post-exclusion source basis](docs/native-ntfs-source-freeze.md),
verified across restart and read-only Windows inspection. Its physical placement
was untouched. Same-partition conversion has passed. A separate first-write
interruption now resumes from the durable journal to a native ReFS mount and
survives a clean reboot; broader fault injection remains open.
An [independent native ReFS shadow](docs/existing-tree-shadow.md) now reproduces
that tree's contents, all four stored timestamps, permissions and names after a
clean restart. All four natural source locations conflict with ReFS metadata;
the diagnostic plan explicitly records relocation of all 512 KiB. The frozen
shadow was then journaled onto the original partition in the successful tree conversion.

## Build and run

The enrolled natural-tree experiment also has a single owning-machine entry
point, `lab-tree-convert`. It captures source expectations, prepares and flushes
the journal/ticket, applies the original partition and performs native ReFS
verification. It saves recovery paths and pins under `--artifacts`; native
`lab-tree-reconstruct resume` / `rollback` remain available before handoff.
This laboratory command accepts the pinned four-file profile and a versioned
ordinary-tree request assembled from a frozen native shadow. The latter has
converted the same four-file tree on its original partition and recovered from
loss of the host control process after apply. The public CLI now uses the
generic certificate-backed workflow described above.

The independent shadow builder accepts `--ordinary-files` for a broader
experimental source profile. It reads empty and resident streams from their
checked NTFS records, carries eligible fragmented runs and fully initialized
cluster prefixes into the retention plan, materializes incompatible ranges
from logical bytes, and restores inherited security descriptors on the native ReFS
shadow. It reports inline data separately from physical extents. The versioned
path passed native Windows qualification on the four cluster-aligned files in
the enrolled tree; the certificate-backed run also converted two resident
streams. Empty, fragmented and partial-cluster cases still need native
conversion runs. New ordinary verification manifests store stream
lengths and hashes, then check bytes through ReFS in bounded chunks instead of
embedding the full payload in the recovery artifact.
The optional `--stream-payload` path also constructs the independent shadow
with bounded NTFS reads; it is implemented but awaits a native VM run. Its
256 MiB logical-data and shadow-space limits still apply. It can be combined
with `--retain-eligible` so the placement attempt no longer requires keeping
payloads in memory; measured ReFS extents determine what was retained.

The toolchain is pinned in `rust-toolchain.toml`; use the installed MSVC toolchain.
Windows builds link the C runtime statically for fresh guests and recovery media.

```powershell
cargo build --release
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
.\target\release\ntfs2refs.exe capabilities
.\target\release\ntfs2refs.exe inspect --image volume.raw --output inspection.json
.\target\release\ntfs2refs.exe plan --image volume.raw --target win11 --target-build 26300.9457 --output plan.json
.\target\release\ntfs2refs.exe verify --image volume.raw --baseline inspection.json
.\target\release\ntfs2refs.exe diff --before control-before.raw --after control-after.raw --output changes.json
.\target\release\ntfs2refs.exe compare-retained --source source.raw --shadow native-shadow.raw --request retained-request.json --output retained-comparison.json
```

On this host Cargo is available through
`C:\Users\mfara\.cargo\bin\rustup.exe run stable cargo` if it is absent from PATH.
Image commands require a raw **partition** image; VHD/VHDX containers, whole
GPT disks, encrypted volumes and live devices are not accepted by those commands.
Native conversion instead uses the explicit device bindings in the
[CLI workflow](docs/cli-workflow.md). Reports are JSON and existing output files
are never overwritten. Exit codes are 0 for successful operations, 2 for a
blocked image conversion plan, and 1 for operation errors.

Inspection records the image SHA-256 before and after parsing. On Windows the
source handle denies concurrent writers/deletion. `verify` only checks byte
identity with its baseline; it does not certify a conversion or native mount.
The planner deliberately leaves space requirements unknown until a qualified
writer can calculate them. It never substitutes a guessed percentage.
Its schema-2 plan includes a schema-4 read-only source-stream classification
with retained and materialized byte candidates; those estimates do not grant
write authority or predict final ReFS placement.

The separate [retained-range comparator](docs/retained-range-comparison.md)
reports every differing sector outside explicitly pinned source ranges and
hashes the hypothetical reconstructed image. It produces no patch payloads or
write authority. This supports the [one-extent reconstruction milestone](docs/next-extent-preservation-milestone.md);
the prepared native result is separate from the later live-admission run. The
[laboratory journal core](docs/lab-reconstruction-journal.md) stores real old/new
bytes and passes file-based interruption, resume and rollback tests. Its trusted
ticket, persistent mount exclusion, raw Apply and protected native observation
passed the prepared fixture. A separate native first-write interruption/resume
run passed; broader interruption/recovery qualification remains.

The separate Windows-only `lab-native-probe` binary binds the exact laboratory
partitions, persists offline disk attributes and verifies retained bytes through
aligned raw reads. It deliberately leaves disks offline, including on failure,
and exposes no raw payload write command. Its platform boundary lives in
`crates/n2r-win32`; the main Rust crate continues to forbid unsafe code.
The separate `lab-native-reconstruct` binary exposes explicit journal preparation,
apply, resume, rollback and handoff operations for the exact enrolled offline
fixture. It can issue bounded raw writes; it is not a general converter. It
requires pinned requests and independently pinned recovery tickets, preserves
failure artifacts, and never brings a disk online. Its prepared-fixture
Prepare/Apply/Handoff path passed; it grants no general converter capability.
See [the journal contract](docs/lab-reconstruction-journal.md).
See [the ntfs2btrfs design review](docs/ntfs2btrfs-design-lessons.md) for the
allocation, collision and rollback concepts informing this work.
The [conversion architecture research](docs/research/conversion-architecture.md)
connects those concepts to ReFS's different metadata structures. It links the
[pinned implementation review](docs/research/refs-implementation-evidence.md),
[feature preservation contract](docs/research/ntfs-refs-preservation-contract.md)
and proposed [journaled relocation path](docs/research/journaled-relocation-design.md).
The [user-report reconciliation](docs/research/user-report-reconciliation.md)
checks the supplied research against pinned sources and the current implementation.
The [REFSNT evaluation](docs/research/refsnt-writer-evaluation.md) identifies its
extent-adoption primitive and records reproduced read-only corpus results.
The [native writer control](docs/native-refs-writer-acceptance.md) now distinguishes
the rejected overlay candidate from a separate accepted, unmodified two-file
reference import. The baseline has no writer overlay or adopted file and does
not establish writer acceptance, mutation or reboot qualification.
These notes distinguish documented behavior, native observations and untested
design proposals.

Supported NTFS DATA streams receive logical SHA-256 hashes, including sparse
zeros and uninitialized tails up to logical EOF. Unsupported layouts receive an
explicit status without a logical digest. Hashing defaults to a cumulative
1 GiB logical-byte budget; use `--stream-hash-budget-mib` with `inspect` or `plan`
to choose another bound. Exhausting the budget fails inspection rather than
returning an incomplete result. Supported metadata DATA streams count too. The
special unflagged `$BadClus:$Bad` layout is explicitly unsupported for hashing;
its observed flags and extents remain in the report. Hashes do not establish complete metadata
preservation or allocation ownership.
The [allocation reconciliation](docs/ntfs-allocation-reconciliation.md) now
compares decoded physical attribute intervals with the volume bitmap while
leaving native and semantic source admission as separate requirements.

## Laboratory

See [the lab runbook](lab/README.md) for ownership guards, media, checkpoints,
fixture generation and evidence capture. The checked-in configuration provisions
Generation 2 Windows 11 and Server lanes; only one runs at a time.

Codex can remain unelevated. A standard UAC helper performs a bounded host
operation and records its result under `.lab/hyperv/host-results`:

```powershell
Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -WorkingDirectory 'D:\code\ntfs2refs' -ArgumentList '-NoProfile -File "D:\code\ntfs2refs\scripts\Invoke-ElevatedLab.ps1" -Action Provision'
```

This helper uses normal Windows consent; it installs no persistent privileged
service and changes no account group membership. The Provision action uses the
reviewed, task-specific Windows 11 ISO path in the helper. All VM artifacts,
media extracts, logs and credentials stay under ignored `.lab` paths.

For the separately authorized one-time Hyper-V access grant, run
`scripts\Request-LabHyperVAccess.cmd` from the Windows desktop and approve its
UAC prompt. It invokes the reviewed group-membership helper, saves a verified
result under `.lab/development`, and requires signing out and back in before
new Hyper-V permissions appear in the session. This launcher is not run
automatically by the converter.
Each run records source hashes, and repeat actions archive the previous result.
`NativeResearch` captures native NTFS/ReFS data controls and prepares a separate
native ReFS OS control. Only successful, verified preparation can invoke the
guarded boot observer; failed boot observations retain the VM for diagnosis.
`NativeDevDrive` runs a separate guest data-volume experiment with temporary
8 GiB RAM and a 52 GiB partition, recording its Dev Drive provenance and checking
file hashes across a clean guest reboot. It does not qualify ordinary ReFS or OS boot.
`NativeDevDriveCorpus` exports an offline research image from that saved data
checkpoint. `NativeExtentDiscovery` runs read-only allocation queries inside the
guest, exports their exact buffers and restores the baseline. These actions
collect evidence; neither performs an NTFS-to-ReFS conversion.
`NativeExtentPlacement` creates one initialized 64 KiB file inside the guest,
requests one native extent move, checks both fixture hashes and mappings across
a clean reboot, and preserves the outcome in a checkpoint. This measures native
initialized-file placement; payload I/O was not traced, and data reuse and
conversion remain unqualified.
`NativeRangeRead` tests bounded guest-side raw reads under a volume lock; the
current build refused a required locked-volume query, so no raw sample qualified.
`NativeProtectedRangeRead` separately establishes disk read-only protection inside
the guest, checks the mounted allocation maps, and samples two fixed 64 KiB
ranges under a lock. It retains protection and preserves incomplete runs for
inspection. See [the protected-read results](docs/native-protected-range-read.md).
`NativeVdlProbe` measures valid-data length on the known initialized file, then
conditionally allocates one private 64 KiB file without payload I/O. It records
cached and on-disk valid-data regions and preserves any changed test branch.
`NativeVdlObservation` reopens that saved branch for metadata-only observation
after remount. The observed ReFS profile has sparse validity; cached and on-disk
region states differ. See [the validity implications](docs/sparse-validity-implications.md).
`RustRetainedCompare` checks the standalone Rust comparison command inside the
guest using two new 8 KiB files on its OS volume, verifies the exact report and
unchanged inputs, exports evidence, and restores the clean baseline.
This tests the comparison executable; it performs no filesystem conversion.
The installation resume action accepts only specifically recorded deployment
failures and preserves the already-applied Windows image. It uses signed host
deployment tools with the guest Windows directory as source, the guest EFI
partition as destination, and BCDBoot's documented offline servicing option.

## Research contract

- The converter must execute inside the machine owning the source disk. In this
  lab that means inside the guest; on physical hardware the same Rust program
  will use local Windows disk APIs. OS-volume conversion runs from an offline
  recovery environment on that machine. Hyper-V, host PowerShell, checkpoints
  and host-side corpus extraction are test infrastructure, never conversion
  dependencies or a substitute for guest-side extent-preserving conversion.
- Preserve the partition and reuse compatible file-data extents; work offline.
- Refuse unsupported source features and insufficient staging/journal capacity.
- Preserve supported file contents, streams, hard links and metadata semantics.
- Guarantee recovery only before the first writable ReFS mount once the journal
  implementation is qualified. Use VM checkpoints afterward.
- Qualify Server and Windows 11 builds independently with signed boot components.

[Research findings](docs/research.md) distinguish Microsoft documentation from
reverse-engineering hypotheses. [Qualification gates](docs/format-gates.md)
define the evidence still needed before enabling writes.
The [measured lab results](docs/lab-results.md) record native captures, stream
comparisons, formatter refusals and their remaining limits.

The recovery test model exercises durable/volatile state, torn writes, reordered
unflushed writes, journal capacity, foreign changes, and the mount handoff. It is
memory-only and does not qualify Windows storage durability or ReFS crash recovery.
