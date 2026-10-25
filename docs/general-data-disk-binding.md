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

An internal `GeneralFrozenPartition` now implements the next source-only step:
after an exact online probe it locks and dismounts the bound volume, persists
offline/read-only disk attributes, closes the lock owner, reopens the physical
disk read-only, and checks identity again. It also has an explicit read-only
reopen path after interruption. It is **not exposed by a command** until a
versioned journal and recovery/handoff path can safely bring that disk back
online. Synthetic tests cover its aligned reads; a real-device freeze has not
been attempted.

This is **not** a general conversion command. The raw writer, journal, source
admission and ReFS target profile still use the narrower enrolled laboratory
route. A successful read-only probe cannot authorize switching a volume's
filesystem. Native qualification on a non-VM dedicated data disk has not yet
been run.
