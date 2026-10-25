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

This is **not** a general conversion command. The raw writer, journal, source
admission and ReFS target profile still use the narrower enrolled laboratory
route. A successful read-only probe cannot authorize switching a volume's
filesystem. Native qualification on a non-VM dedicated data disk has not yet
been run.
