# Owning-machine conversion and recovery CLI

## Drive selection

```powershell
ntfs2refs --list
ntfs2refs --drive d
ntfs2refs --drive d --partition 2
ntfs2refs --drive d partition 2
ntfs2refs --drive 3 partition 2
```

`--list` shows disks, partition numbers, drive letters/mounts, filesystems,
sizes, labels and available status, including unmounted partitions and query
errors. Listing does not lock, dismount or modify a disk. Numeric disk selection
requires an explicit partition number. When a drive letter and partition are
both supplied, the number must match that letter's actual partition.

The drive workflow shows the selected identity and asks `[y/N]` before creating
working storage or starting conversion. No, empty input and EOF cancel. After
an affirmative response, the source identity is checked again. Eligible NTFS
data volumes use the same live source admission and compact conversion engine;
running Windows volumes and unsupported layouts/features still refuse.

Working storage is prepared automatically on the Windows OS volume under
`ProgramData\ntfs2refs\runs`: a new dynamic VHDX holds the native ReFS shadow,
and the journal/recovery artifacts stay independent of the selected source.
The native formatter receives only the partition on that newly created owned
virtual disk. [Windows format supports volume names and ReFS Dev Drives](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/format).
The provider and formatter must support the requested geometry; staging is kept
on failure for inspection. The isolated native staging smoke passed on the
current Windows11 guest: owned VHDX creation, attachment, empty-GPT/MSR setup,
native formatting and ReFS3.14/4KiB verification all succeeded for60GiB. Its
backing file was100MiB. This proves staging on that profile, independently of
the manually prepared shadow experiments. The complete affirmative
`--drive F --partition 2` workflow then passed on the existing 52 GiB NTFS
partition: actual native exit 0, automatic shadow/journal selection, 157 patches
writing 70,660,096 bytes, and a 141,354,590-byte recovery journal. Native ReFS
matched 15 objects and 10 stream hashes. All seven earlier user files
(8,594,391,095 logical bytes) matched again after cold boot, with the original
label and F: mount preserved. Both successful branches are saved and all 50
checkpoints remain. The [automatic CLI observation](../evidence/drive-cli-native-20261028.json)
pins the reports and exact executable. Most logical bytes are in a zero-filled
fixture file; this does not prove payload-independent scratch or arbitrary-volume
support. The current executable also shows phases and elapsed time; that later
display change is separate from the recorded run.

Run conversion from an elevated Windows terminal. `--scratch-directory` can
choose another ordinary working folder on the Windows OS volume. The current
experimental filesystem and resource limits remain visible through
`ntfs2refs-compact profile`; drive selection does not bypass them.

## Recovering a drive run

New compact conversions save `compact-recovery-bundle.json` before source
activation and print its **Recovery directory** and **Recovery checksum**.
Keep that original checksum with the recovery files. It pins the original
request, ticket, journal location, capture, packed backing, expectation and
optional managed-shadow identity; it cannot replace the native recovery checks.

```powershell
ntfs2refs --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion `
  --recovery-sha256 ORIGINAL_PRINTED_CHECKSUM

ntfs2refs --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion `
  --recovery-sha256 ORIGINAL_PRINTED_CHECKSUM --rollback
```

Recovery displays the pinned disk/partition identity and action, then defaults
to No. Declining or giving empty input creates no recovery directory and opens
no target or journal. A wrong checksum refuses before the prompt. After an
affirmative answer, the existing engine checks actual device identity, exclusion,
original input hashes, journal ownership and barriers. Managed staging is reopened
with its exact original provider and GPT identity. Default recovery resumes the
exact image, then finalizes ReFS only if resume succeeds; `--rollback` restores
NTFS instead. Failures do not trigger an alternate action.

HND/ABT close replay: a completed writable filesystem must not be recovered with
an old journal. Older runs without a bundle still require the explicit pinned
`ntfs2refs-compact` recovery inputs below. The new wrapper has release-build,
wrong-checksum and cancellation evidence; its affirmative native path is not yet
qualified. Those checks do not inherit the exact older CLI binary's results.

## Experimental compact backend

`ntfs2refs-compact` exposes native-shadow compact construction and its typed
recovery operations in a separate executable. It runs on the Windows machine
owning the disks and does not depend on Hyper-V. The original frozen laboratory
alpha and the older `ntfs2refs convert` backend remain separate.

The selected-device path replaces fixture computer names, disk numbers and GUIDs
with live construction enrollment from the original observed NTFS freeze. It
checks the selected shadow's actual GPT/volume route, root identity, writable
ReFS3.14/4KiB/512-byte geometry and zero retrieval base, then transfers its held
handles into the private constructor. It still requires a fresh prepared shadow
labelled `n2r-retained-shadow`, a separate journal disk, matching source/shadow
partition lengths, supported source semantics and the original source certificate.
Current Windows disks and incompatible dedicated-data GPT layouts remain refused.

After preparing those volumes, use the existing read-only binder with the
explicit streaming profile. These letters are placeholders for selected volumes:

```powershell
ntfs2refs-bind --source X:\ --shadow Y:\ --journal Z:\ `
  --experimental-large-journal --experimental-large-tree --experimental-streaming-payload `
  --experiment-id 0123456789abcdef0123456789abcdef --max-journal-bytes 1073741824 `
  --output C:\ntfs2refs\devices.json

$pin = (Get-FileHash -LiteralPath C:\ntfs2refs\devices.json).Hash.ToLowerInvariant()
ntfs2refs-compact convert --acknowledge-experimental-compact `
  --request C:\ntfs2refs\devices.json --request-sha256 $pin `
  --maximum-placement-bytes 1073741824 --output C:\ntfs2refs\runs\fresh-run
```

Use a new experiment ID and output paths for every operation. Placement and
journal ceilings are explicit budgets, not reservations or universal estimates.
`profile` prints the shared implementation bounds without opening devices.
Conversion checks live routing, filesystem and source geometry before freezing;
neither binder output nor an acknowledgment supplies source-write authority.

`resume`, `rollback`, `finalize`, `finalize-after-marker` and `finalize-rollback`
take the original request, ticket, capture, packed backing and expectation with
their independent SHA-256 pins, plus the actual journal and a fresh output path.
They use the existing compact recovery engine; none can activate a new Apply.
HND/ABT replay boundaries still apply. See `ntfs2refs-compact <operation> --help`
and [the recovery contract](native-composite-experimental.md#recovery).

If a reboot removed an automatically managed shadow's attachment, recovery can
also take the paired `--managed-shadow <original.vhdx>` and
`--managed-shadow-id <original-provider-GUID>` options. The original provider ID
is saved in `managed-shadow.json` by the drive workflow. Reattachment opens the
existing backing read-only and checks its provider identity, geometry, exact
original disk number and GPT layout. Windows can restore the provider's hardware
write protection without restoring the software disk attributes. The converter
therefore queries native write protection before adding any missing persistent
offline/read-only restrictions. It never clears protection bits, brings the
shadow online or changes an actually writable device to pass the gate. It
cannot create, format or rewrite a stale request/ticket.
All existing recovery inputs and independent pins are still required. This
reattachment path has release-build evidence; native recovery qualification
remains pending; a real post-reboot recovery run is now exercising this path.

The selected-device backend completed a separately prepared 60 GiB native
conversion, with five ordinary user files and a successful cold-boot hash
readback. The [selected native observation](../evidence/selected-native-compact-20261028.json)
pins the exact executable and closed reports, including the separate wrapper's
missing exit-code observation and terminal status 1. This result is separate from the automatic drive workflow
and the earlier pinned laboratory executables.
Boot volumes, arbitrary geometry and general low-scratch behavior are unfinished.

## Existing full-shadow backend

`ntfs2refs convert --request` runs the certificate-backed workflow on the
machine owning the disks. It has no Hyper-V dependency. Run it in an elevated
Windows process with the required volume/backup/security privileges.

```powershell
$pin = (Get-FileHash -LiteralPath .\devices.json -Algorithm SHA256).Hash.ToLowerInvariant()
ntfs2refs convert --request .\devices.json --request-sha256 $pin --output C:\ntfs2refs\runs\run-001
```

The output directory must be fresh, on the Windows OS volume, with ordinary
directory ancestry; missing parents are created and checked before use. The request is a bounded ordinary JSON file, at most
16 KiB, matching `general_conversion::Request`. Its fields are:

- `schema_version`: `1` for the existing journal profile, or `2` for the
  explicitly selected experimental large-journal profile.
- `experiment_id`: a fresh 32-character lowercase hexadecimal identifier.
- `pair`: actual source and shadow `GeneralDiskBinding` values, including disk
  number, volume GUID, GPT identities, partition bounds and sector geometry.
- `journal`: an independent `GeneralJournalStorageBinding`.
- `max_journal_bytes`: a positive journal ceiling within the current limit.
- `verify_existing_shadow`: normally `false`; `true` requires an existing
  shadow to match the newly frozen source through the complete native verifier.

Source and shadow partitions must have matching geometry on different data
disks. The shadow must already be a separately prepared ReFS volume with label
`n2r-retained-shadow`. Normal construction requires an empty shadow namespace
apart from the explicitly supported Windows system-cache entries. The journal
must be independent of both data disks. Native identities are checked against
the actual devices; a caller-provided success flag cannot qualify a source.

The current profile is deliberately bounded: NTFS 3.1 with 512-byte logical
sectors, 4 KiB clusters and 1 KiB records; ReFS 3.14 with 4 KiB clusters; up to
128 ordinary files, 32 directories and 256 MiB of logical contents. Source
policy qualification currently targets Windows build 26300. Unsupported
semantics and unknown layouts are refused. Boot/system volumes remain excluded.

The opt-in `--experimental-large-tree` binding profile raises the source tree
budget to 1,024 ordinary files, 256 directories including the root, and 4 GiB
of logical contents. It requires `--experimental-large-journal`. The source
geometry may use power-of-two clusters from 4 KiB through 2 MiB, with 512-byte
sectors, 1 KiB MFT records and 4 KiB index records. The default alpha still
requires 4 KiB source clusters. ReFS target clusters remain 4 KiB in both paths;
the source planner translates compatible physical byte ranges rather than
equating NTFS and ReFS cluster numbers. Backup admission checks the geometry-sized
MFT mirror completely with fixed record buffers. The four bootstrap records
remain byte-identical, while extra allocated slots must either match or be
recognized inactive format padding; unknown discrepancies still refuse. Both
complete regions remain hashed and all record/USA structures checked. See the
[actual larger-cluster observation](native-shadow-large-beta.md); allocated
stream length is not treated as a guarantee of live mirror synchronization.
The source profile is bound to the journal and recovery ticket; use the same executable
for conversion and recovery. Its partition routing budget is 2 PiB, derived from
the streaming 4 KiB target-bitmap budget. Default/unprofiled routes retain the
128 GiB limit. Other semantic, evidence and storage limits still apply. This larger-tree path has
not yet been qualified by a native conversion or interruption run.
The native shadow still initializes the logical file contents on separate
storage. Eligible source extents can remain in place during cutover, but
shadow I/O and scratch usage are not independent of payload size.

The converter does not yet support arbitrary volume sizes. In particular, the
default live partition limit is 128 GiB, the default source uses 4 KiB clusters, and the
full-image comparison reads both partitions twice. A 1,000 TB NTFS volume
requires larger source clusters under Windows' documented NTFS limits; merely
removing an internal size check would not make it convertible. The experimental
routing budget is not native large-volume qualification. It does
not remove tree/data, journal or scratch constraints, and full-image scans and
shadow construction remain expensive. All exact admission and recovery checks
still apply. A small or large volume can still be refused by format, layout or
capacity checks. See
[Microsoft's NTFS volume limits](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview).
The formatter and target profile must independently establish whether a small
volume, including a 10 MiB example, can hold a valid ReFS filesystem.

Journal profile 1 retains the existing 768 MiB journal ceiling. The opt-in
profile 2 permits a maximum journal budget up to 16 GiB, with the changed-byte
budget derived from that value after reserving metadata and both old and new
bytes. Select it with `ntfs2refs-bind --experimental-large-journal` and an
appropriate `--max-journal-bytes`. Conversion, resume, rollback and handoff bind
the request and immutable journal ticket to the same profile. Profile 2 has not
been qualified by a native VM conversion or interruption test; it does not raise
the source file/tree limits or imply broader filesystem feature support. Older
executables refuse its request/ticket version. Use the executable corresponding
to the run for every recovery operation.

The workflow captures a live source freeze, checks the semantic source model,
constructs or verifies the native ReFS shadow, freezes it, and creates the
source certificate. It then saves the external journal and trusted ticket,
applies the admitted patch set, records the handoff barrier and verifies the
mounted ReFS tree. The source remains persistently excluded while raw writes
are in progress. A failed run leaves phase diagnostics and any completed
recovery inputs under the output directory.

An image `plan` report remains non-executable. `convert --plan plan.json`
retains its refusal behavior; it cannot be used to bypass live qualification.

To inspect an existing public run, `operation-state` requires the intent file's
SHA-256 and the exact pins of any frozen-source, mount-path, reconstruction-request
and ticket artifacts already present. The separate Rust
[`ntfs2refs-state-command` helper](operation-state-command.md) prepares this
read-only command without executing it or changing the frozen alpha engine.
It hashes artifact files themselves; the source image hash inside
`source-frozen.json` is a different value. Run the prepared command in the owning
machine's elevated context and use its observed lifecycle report before considering
`cancel` or recovery. Preparing pins grants no mutation authority and does not
establish that a conversion worker stopped. `cancel` is limited to unchanged NTFS
before reconstruction activation; it cannot cancel an activated or handed-off run.

For recovery, use the run's generated `request.json`, `ticket.json` and the
journal location from `journal-location.json`. Each input is pinned separately:

```powershell
$requestPin = (Get-FileHash -LiteralPath C:\ntfs2refs\runs\run-001\request.json).Hash.ToLowerInvariant()
$ticketPin = (Get-FileHash -LiteralPath C:\ntfs2refs\runs\run-001\ticket.json).Hash.ToLowerInvariant()
ntfs2refs resume --journal J:\ntfs2refs-shadow\EXPERIMENT\reconstruction.journal `
  --request C:\ntfs2refs\runs\run-001\request.json --request-sha256 $requestPin `
  --ticket C:\ntfs2refs\runs\run-001\ticket.json --ticket-sha256 $ticketPin `
  --output C:\ntfs2refs\runs\resume-001
```

`rollback` uses the same pinned envelope and restores the exact admitted NTFS
preimage before completing its rollback marker. `finalize` additionally
requires `--expectation` and `--expectation-sha256`, matching the request's
expected-tree hash. `rollback --after-marker` and `finalize --after-marker`
complete an already durable marker after process death only while their existing
exact-image proof still passes. A writable ReFS mount or label update can change
the image; the old raw-recovery/finalization path must then refuse it.
Recovery never starts
a fresh apply, silently clears a foreign device's exclusion, or crosses the
closed rollback boundary. A shadow-backed recovery needs the bound shadow
available in its required protected state.

`rollback --without-shadow` explicitly selects journal-old-byte recovery when
the enrolled shadow is unavailable. It still requires the exact pinned request,
ticket, actual journal identity, expected target state and permitted pre-handoff
lifecycle. It grants no forward resume or finalization authority. This public
command passed a bounded native first-flushed-write interruption with the shadow
detached, exact NTFS preimage proof before writable mounting and original NTFS
availability afterward. A later clean-boot check matched four known user-file
hashes and the original mount/label/partition identity; it did not reverify all
twelve objects' security/timestamps or post-mount whole-image equality.
See [the result and limits](general-native-conversion-results.md#public-shadowless-rollback-after-one-flushed-write).

For a label-only failure after handoff and the first writable ReFS mount, use
the separate native-only command. Its pinned request must contain
`expected_source_label`:

```powershell
ntfs2refs complete-label --request request.json --request-sha256 REQUEST_SHA256 `
  --ticket ticket.json --ticket-sha256 TICKET_SHA256 --journal reconstruction.journal `
  --expectation expectation.json --expectation-sha256 TREE_SHA256 `
  --output C:\ntfs2refs\runs\label-completion-001
```

This command reads the journal exclusively and read-only to validate its native
file identity, full immutable contents, comparison binding and exact HND marker.
That receipt does not assert a current raw target hash or authorize replay.
The source must already be online/writable ReFS on the original bound hardware
partition, with the enrollment or desired label. The full strict native tree is
verified before and after guarded label restoration, flush and readback. It
does not open the old shadow, issue raw source writes, change disk attributes
or rewrite journal markers. Partial failures are saved in the fresh output
directory. An already-desired label is flushed and verified without a second
setter call. See [the label contract](source-volume-label.md).

`capabilities` reports command availability. It does not claim a production
qualification matrix or a standalone raw ReFS formatter/writer.

The separate, unqualified streaming-payload source profile is selected during
binding with `--experimental-streaming-payload --experimental-large-tree
--experimental-large-journal`. It serializes as
`experimental_streaming_tree_v2`; the existing larger-tree v1 profile retains
its 4 GiB payload budget. V2 bounds total/per-stream logical payload by the
existing 2 PiB partition-routing envelope, using fixed-size streaming copy/hash
buffers. Native/raw logical-read budgets allow four times that envelope for
source collection/internal streams, with separately bounded read-call counts.
The per-stream call guard scales for long streams rather than imposing the old
roughly 64 GiB full-read ceiling; unprofiled and v1 effective guards remain.

This is a resource envelope, not evidence that a volume of that size converts.
The 1,024-file/256-directory and metadata-evidence limits, supported semantics,
same-sized independent shadow, initialized shadow payload, complete image scans,
dual target bitmap checks, exact changed-byte/journal capacity, and recovery
barriers all still apply. The v2 journal still has a 16 GiB ceiling. A placement
requiring too much relocation or free-space replacement must refuse. Requests,
native observations, source/target certificates, expectation profiles, tickets
and recovery retain the exact selected resource profile; imported JSON cannot
substitute for live source/target capabilities. The new profile has compilation
evidence only and has not run in the native lab. The active candidate-3 beta
continues using v1 and its original executable.

On a machine with at least two CPUs, v2's shadow-backed apply/resume/rollback
preflight interleaves the complete shadow read with target normalization against
the old/new journal payloads. The shadow SHA-256 uses the bounded worker while
the owning thread reads storage, checks every affected byte and hashes the
normalized full target. Both complete image pins must pass before the existing
patch-writing path is entered. Shadowless recovery and older profiles retain
their sequential checks. This overlaps CPU work with a fixed extra buffer; it
removes no reads, pin checks, patch checks, flushes or handoff barriers. The
change has compilation/format evidence only and no measured native speedup.

The same streaming profile now overlaps the final target/shadow digests at
handoff for images of at least 64 MiB with two available CPUs. The target is
flushed before both complete images are read; their separately checked pins
still precede the irreversible handoff marker. All device reads remain on the
owning thread, with fixed-size buffers and one digest worker. Read/worker/pin
failures leave the marker unwritten. Legacy profiles and small/single-CPU paths
keep their existing order. This reduces serial CPU work without reducing image
reads or shadow allocation, and has compilation evidence only.

For streaming-payload v2, a wholly blocked placement plan now reuses its two
complete planning bitmap observations in no-submit diagnostics. Wider runs use
the same snapshots for their bounded diagnostic chunks. The native file mapping
is still captured, and both candidate ranges/domain sizes must match the exact
request. Reuse with a submitted move or an assembled-map path is rejected.
Every actual move still captures fresh legacy and metadata-inclusive views.
Final native semantics, actual mappings and frozen allocation/image checks stay
independent. This removes duplicate diagnostic bitmap queries without treating
their earlier observations as move authority. Alpha and larger-tree v1 retain
their existing query order. The change has compilation evidence only.

Expanded native shadow/converted-volume observation now obtains geometry from
the already checked ReFS volume-data query, keeping the total cluster count as
64 bits through retrieval-map bounds checking. The previous protected route
narrowed that count to a DWORD, imposing a roughly 16 TiB ceiling at 4 KiB;
the unprotected expanded route also relied on `GetDiskFreeSpaceW`'s DWORD count.
Both expanded routes now use the same exact version/sector/cluster/partition
checks. Unprofiled mounted access keeps its legacy query. This removes that
specific representational limit, not other metadata/resource/capacity limits;
volumes above the recorded native sizes remain unqualified.

The streaming-payload v2 profile also accepts well-formed Unicode names up to
255 UTF-16 code units per component, with the existing 16-component path bound.
The original strings are preserved; no normalization or case rewrite is applied
to filesystem paths. A conservative Unicode-uppercase key detects collisions
in both semantic-tree construction and expected-tree validation. It can refuse
pairs that Windows would distinguish; native CREATE_NEW remains the final
compatibility check before any source reconstruction. Controls, separators,
traversal/trailing-dot/space forms and reserved device names are refused.
Unpaired UTF-16 surrogates remain refused by the existing strict path decoder.
Alpha and larger-tree v1 keep their ASCII/100-byte naming policy. The pinned
streaming-v2 native composite run converted names including `café`, `資料`,
`Grüße` and an emoji, then passed native readback, mutation and reboot checks.
Maximum-length and maximum-depth boundary cases remain unqualified; see
[the recorded experiment](native-composite-experimental.md).
