# Dedicated data-disk binding

The initial journal path is deliberately pinned to one 64 GiB Hyper-V disk
and a 52 GiB partition. The new `GeneralDiskBinding` is a separate read-only
route toward running the converter on an ordinary Windows machine. It accepts
a bounded GPT disk with one basic-data target partition and at most one earlier
Microsoft Reserved partition. Geometry and GUIDs are supplied explicitly and
checked against the physical disk and the mounted volume. The disk containing
the running Windows installation is rejected.

`lab-probe-general` opens the named disk and volume read-only, queries native
device route, disk length, sector alignment, complete GPT layout, persistent
disk attributes and single-volume extents, and checks that disk attributes stay
unchanged. It never locks, dismounts, sets attributes or writes sectors. The
pure layout tests cover a second disk size, 512e and 4Kn, wrong routes,
overlapping partitions, another data partition and EFI/system partitions.
An optional independently pinned shadow binding probes a second dedicated disk
and requires distinct disk/partition/volume identities and matching source and
shadow partition geometry within the current 128 GiB comparison limit.

`lab-freeze-general-source` now performs the first source transition itself:
it locks and dismounts the bound non-system NTFS data disk, persists
offline/read-only attributes, then hashes and inventories the post-flush
partition. Its intent is durable before changing disk attributes. Before
journal activation, `lab-abort-general-source` can return that exact original
NTFS image online only after a complete hash matches a pinned frozen-source
report. It refuses a target that is already activated offline but writable.
These disk transitions have not yet had a native general-disk run.

`GeneralPartitionReader` now adds a partition-relative, 4 KiB-aligned,
read-only `Read + Seek` view over the same bound physical disk. The
`lab-inspect-general` command feeds that view to the existing raw NTFS
inspector, then rechecks the disk and volume route. Its output explicitly says
the mounted source was not frozen and is not admitted. A synthetic bounce-read
test covers unaligned requests and partition boundaries. Neither command has
a write method.

With `--ordinary-tree`, the inspection also derives the bounded file-tree model
used by native ReFS shadow construction. Unsupported source semantics produce
an `ordinary_tree_refusal` in the report. This projection uses the mounted
read-only view and remains diagnostic until a frozen source certificate binds
the same model to an excluded device.
With `--stream-plan`, it also classifies each user DATA stream as a physical
retention candidate, a logical materialization candidate, or rejected. Named
streams are identified but remain pending target reconstruction. These
classifications do not authorize writes.

`GeneralFrozenPartition` implements the offline/read-only transition:
after an exact online probe it locks and dismounts the bound volume, persists
offline/read-only disk attributes, closes the lock owner, reopens the physical
disk read-only, and checks identity again. It also has an explicit read-only
reopen path after interruption. The general CLI now uses this transition for
both the source and independent shadow, with a hash-checked abort route for
the unchanged source before activation. Synthetic tests cover aligned reads;
a real-device freeze has not been attempted.

The already-excluded read-only reopen is now public. `lab-inspect-frozen-general`
uses it to hash the entire partition before and after NTFS inventory, verify
the backup boot/MFT mirror, read both `$LogFile` restart pages when supported,
and emit stream dispositions and an optional ordinary tree. It cannot clear
write protection and never supplies a payload write handle. Its report
explicitly keeps source admission and conversion qualification false.
With `--native`, it records an intent, briefly publishes only a read-only NTFS
view, collects file, stream, namespace and security observations, restores
offline/read-only exclusion and rehashes the entire source. A killed process
can leave the volume mounted but still write-protected. The new
`lab-restore-general-exclusion` command accepts an independently pinned source
hash, locks/dismounts only that read-only volume, restores persistent
offline/read-only exclusion, and verifies the complete source bytes. It also
accepts an already excluded source without changing its attributes. Neither
the native observation nor the recovery command has been qualified on a real
general data disk.
The live observer now feeds the combined ordinary-source assessment through an
opaque native observation value and another complete excluded-device hash.
Its report records matching and refusing gates separately; it still issues no
admission certificate while volume-policy, internal replacement and target
preservation rules remain unresolved.
The same read-only observation window now queries native dirty state,
persistent short-name policy and TxF resource-manager/transaction state on the
bound general volume. The report preserves query refusals and the fact that
not every resource manager has been enumerated. These diagnostics do not clear
the unresolved on-disk `0x0080` meaning or TxF admission gate.

The general native I/O layer now also has a separate `GeneralJournaledPartition`
type. It can activate an unchanged offline/read-only handle while retaining
offline exclusion, reopen an already activated offline target after interruption,
and issue only aligned writes in an exact armed `WritePolicy`. Failed or short
writes poison that handle. The generic old/new journal engine accepts these
types as read-only preparation inputs and a durable target. The general CLI
still lacks the complete source-admission and recovery witnesses needed to
use this write route on an actual disk.

`lab-prepare-general-journal` is the first general journal command. Given two
already excluded, read-only dedicated data disks, a pinned request, and a fresh
file on a separately bound dedicated journal disk, it reads the NTFS and ReFS
headers, compares the full partitions, writes the durable old/new journal, and
saves its ticket as a separate file. It does not activate the target or issue
data-disk writes. Its ReFS check covers the 3.14 VBR geometry, not the complete
metadata graph or Windows mount behavior; the resulting preparation explicitly
does not authorize execution.
The general journal binding accepts independently measured GPT geometry and
file identity instead of the original disk-2/8 GiB fixture, while retaining a
768 MiB journal-file ceiling and a minimum 1 GiB journal partition.
Its optional additional-partitions profile permits the journal file on a
different physical Windows system disk. It still verifies the complete GPT
table for overlap and unique identities, requires the file's partition to be
the bound basic-data volume, and rejects reuse of the NTFS source or ReFS
shadow disk. The dedicated-disk profile remains the default.

The native shadow engine now has a separate general entry point for a
Windows-created ReFS data disk bound by `GeneralSourceShadowBinding`. It accepts
bounded streamed NTFS bytes, can attempt source-relative retention through
ReFS's native placement control, and reopens the resulting files to check
content, namespace and security. The legacy disk-3/guest entry points keep
their exact fixture checks. Native qualification of this new route is pending.

`lab-build-general-shadow` now invokes that entry point. It requires a frozen
NTFS source, an online independent ReFS 3.14 shadow disk with 4 KiB clusters
and the exact shadow label expected by the native adapter. It hashes the
source partition before and after construction, streams each admitted ordinary
file, verifies the native ReFS tree and records actual placement attempts.
`--verify-only` reobserves the same live shadow without creating files.
It does not freeze the shadow or authorize journal activation, and the general
native run has not yet been performed.

`lab-freeze-general-shadow` independently reopens the NTFS source, verifies the
live ReFS tree against it, saves the native evidence, then locks/dismounts only
the shadow disk and persists its offline/read-only state. It hashes the frozen
shadow and rehashes the source afterward. The measured stream mappings and
logical-range hashes produce a versioned retained/relocated comparison request
bound to those complete source and shadow hashes. A failure after exclusion
leaves the shadow offline; its durable intent identifies the attempted
transition. This command has not had a native run and does not authorize cutover.
For a nonempty retained set, the frozen-shadow report also checks every retained
cluster against the ReFS Medium and Small allocator trees at the same candidate
checkpoint. The journal-request assembler refuses retained ranges unless that
coverage succeeds. This is a local allocation check, not proof of unique
ownership, valid refcounts or complete ReFS metadata reachability.
Journal preparation repeats the allocator check on the actual frozen shadow
instead of trusting the report's serialized coverage field.

`lab-new-general-journal-request` combines the pinned frozen-shadow report
with a separately pinned journal-disk binding. It requires matching full-image
hashes, stable offline/read-only source/shadow states and a distinct journal
device, then emits the exact request consumed by
`lab-prepare-general-journal`. The preparation command reopens and rehashes
the actual disks; neither a copied success flag nor this request grants write
authority.

The library has general activation and apply/resume/rollback functions. They
rebind the separately pinned ticket to the actual GPT source, shadow and
journal file, inspect the immutable journal before changing disk attributes,
and arm only its listed patch ranges. They leave both data disks excluded and
do not perform handoff. Fresh activation and apply remain internal while
source admission and independent target verification are incomplete.

`lab-recover-general-journal` exposes only resume and rollback for an already
activated, persistently offline target. It requires separately pinned request
and ticket files, an existing exclusive journal and a frozen shadow; the
journal's zero handoff marker and exact patch list are checked before any
target write. It writes an intent before recovery, records actual disk states
afterward, and never brings the target online. It cannot initiate a new apply.
After an exact NTFS rollback, `lab-complete-general-rollback` separately
rechecks the original NTFS structures, backup and clean restart pages, verifies
the complete old image, writes a durable rollback-complete marker that rejects
future journal replay, then brings the original disk online and checks that
Windows mounts it as NTFS. A partial marker is treated as closing replay.
This transition has not had a native disk run.
If a process dies after either completion marker but before the disk becomes
online, explicit `--after-marker` (NTFS) or `finalize-after-marker` (ReFS)
rechecks the full 4 KiB marker, immutable journal, frozen shadow and exact
target image before finishing the mount. These modes never rewrite a marker;
partial or unknown marker bytes remain a hard refusal. The corresponding host
dispatchers and collectors record which completion route was used.
`lab-complete-general-handoff` exposes only the already-marked ReFS recovery
case on the disk-owning Windows machine. It requires separately pinned request,
ticket and pre-cutover tree files and does not write the journal marker again.
Fresh general apply/handoff remains unavailable outside the disposable lab.
`lab-verify-general-converted` is a repeatable read-only native verifier for the
original disk after handoff. It checks the current ReFS mount against the
separately pinned pre-cutover tree, including logical bytes, names, stored
timestamps and both security views, and saves an explicit failure report.
It is intended to run again after reboots and ordinary ReFS mutation workloads;
it does not reopen NTFS rollback.
The guest-only `lab-general-refs-mutation` workload creates a fresh temporary
directory on the converted ReFS disk, writes and hashes a 50 MiB file, grows
it across a zero-valid-data gap, truncates and renames it, then creates and
removes 128 small files. It removes only those new test paths. A subsequent
reboot and `lab-verify-general-converted` run must still match the original
tree; this mutation workload has not yet run in the VM.

The internal general finalizer now accepts the independently pinned pre-cutover
tree, checks the full journaled ReFS postimage, durably closes rollback, brings
the original data disk online and reads the expected files through `refs.sys`.
A partial handoff marker is treated as an irreversible boundary. No
unrestricted general CLI exposes this finalizer while source admission and
native qualification are unfinished.

For disposable qualification, `lab-general-experiment` exposes two guest-only
phases on the enrolled 64 GiB/52 GiB source and shadow disks plus the 8 GiB
journal disk. `apply` rederives the expected tree from the frozen NTFS bytes,
requires matching backup and clean restart evidence, activates the offline
target through the verified journal and leaves it offline after exact apply.
`finalize` records the irreversible handoff, mounts the original disk and
verifies its files through native ReFS. Separate pinned request, ticket and
expectation files are required. This path has compiled but has not run in the
VM and does not qualify general production conversion.
`lab-general-complete` now runs those stages in one owning-guest invocation.
It saves request and expectation copies on C:, prepares the external journal,
durably saves and reads back the ticket and recovery pins, then applies and
finalizes. If it stops during apply, the target remains excluded and the
separate general resume/rollback command uses the saved ticket. It has not
been run in the VM.
`--interrupt-after-writes N` deliberately exits 86 after the Nth flushed
target write, before journal handoff. The intent, prepared journal and
read-back ticket are saved first, so a new guest process can exercise the
general resume/rollback command against the persistently offline target.

`lab-replay-general-from-tree` can package the previously successful pinned
ordinary-tree freeze into this new guest experiment's request and expected-tree
files without touching any disk. It passed locally against the archived
eight-object freeze at
`.lab/development/general-tree-replay-20261025T061514857Z`:
request SHA-256 `15d5e32f88296fbd299951fef8a91be56d44bbaa9bf4f57fdb592a626bdcd8fa`,
expected-tree SHA-256 `043eab655db6c04ba321f184ab91dc01e5a31b77a0a0f342886f2e0b4c750af8`.
The ignored local artifacts are not a native run of the new engine.

`Dispatch-LabGeneralReplay.ps1` stages those pinned files and a pinned
`lab-general-complete.exe` into the owning VM, then launches one SYSTEM task
that survives host-controller loss. It checks the frozen shadow checkpoint,
actual guest disk exclusion and GPT identities, absence of a journal file and
absence of another converter before dispatch. It never restores a VM checkpoint
or changes a guest data disk itself. The current converted VM branch does not
meet its source-offline/read-only preflight. Initial dispatch also honors the
lab's host free-space reserve; the observed 2026-10-25 host D: free space of
64,804,052,992 bytes is below the configured 68,719,476,736-byte reserve.
`Collect-LabGeneralReplay.ps1` observes the scheduled task without restarting
it, exports each guest artifact with a guest-to-host SHA-256 comparison, and
records the source/shadow disk state and journal marker. It reports a completed
native handoff only when the full artifact set and ReFS finish report agree;
exit 86 with a zero handoff marker and offline writable target is classified
as requiring journal recovery.
`Dispatch-LabGeneralRecovery.ps1` can then launch exactly one pinned resume or
rollback task after confirming the original task is terminal, the handoff
sector is zero, and the target/shadow remain excluded. Its read-only companion
`Collect-LabGeneralRecovery.ps1` compares the recovered whole-image hash to
the requested NTFS or ReFS image and leaves the target offline for a separate
handoff or old-NTFS online transition.
For a successful resume, `Dispatch-LabGeneralFinalize.ps1` requires that
collected image proof, a terminal recovery task, zero handoff sector and the
offline ReFS postimage before scheduling a pinned guest finalizer.
`Collect-LabGeneralFinalize.ps1` exports its report with a matching hash and
checks the ReFS mount, original-disk state and durable handoff marker. It
conservatively treats a partial marker or already online source as closing
NTFS rollback, even when native verification fails.
For a successful rollback, `Dispatch-LabGeneralRollbackCompletion.ps1` instead
launches the pinned NTFS completion binary. The read-only
`Collect-LabGeneralRollbackCompletion.ps1` checks the `N2RABT01` marker, exact
old image hash, online NTFS mount and frozen shadow. It never retries journal
replay after the source becomes writable.

This is **not** a complete general conversion command. Source admission still
rejects unresolved Windows volume policy and filesystem-internal state, while
general activation, handoff and recovery remain unavailable from the CLI.
Native qualification on a non-VM dedicated data disk has not yet been run.
