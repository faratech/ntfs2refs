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
reopen path after interruption. The initial isolate transition is exposed only
for the independent shadow; source isolation remains outside the general CLI
until recovery/handoff is complete. Synthetic tests cover its aligned reads;
a real-device freeze has not been attempted.

The already-excluded read-only reopen is now public. `lab-inspect-frozen-general`
uses it to hash the entire partition before and after NTFS inventory, verify
the backup boot/MFT mirror, read both `$LogFile` restart pages when supported,
and emit stream dispositions and an optional ordinary tree. It cannot isolate
or bring a disk online and never supplies a write handle. Its report explicitly
keeps source admission and conversion qualification false.

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
file on the enrolled independent journal disk, it reads the NTFS and ReFS
headers, compares the full partitions, writes the durable old/new journal, and
saves its ticket as a separate file. It does not activate the target or issue
data-disk writes. Its ReFS check covers the 3.14 VBR geometry, not the complete
metadata graph or Windows mount behavior; the resulting preparation explicitly
does not authorize execution.

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
leaves the shadow offline; its durable intent identifies the attempted transition. This
command has not had a native run and does not authorize cutover.

The library now has internal general activation and apply/resume/rollback
functions. They rebind the separately pinned ticket to the actual GPT source,
shadow and journal file, inspect the immutable journal before changing disk
attributes, and arm only its listed patch ranges. They leave both data disks
excluded and do not perform handoff. These functions are intentionally not
reachable from the general CLI while source admission and independent target
verification remain incomplete.

This is **not** a general conversion command. The raw writer, journal, source
admission and ReFS target profile still use the narrower enrolled laboratory
route. A successful read-only probe cannot authorize switching a volume's
filesystem. Native qualification on a non-VM dedicated data disk has not yet
been run.
