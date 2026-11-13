# Native-shadow scale gaps

The resource-bounded profile removes the old fixture-sized collection limits.
That does not remove limits imposed by its current storage backend or establish
qualification at arbitrary sizes.

`ManagedShadow::create_with_profile()` currently creates one VHDX whose maximum
size is the source partition length plus 64 MiB. Microsoft's VHDX specification
limits the virtual disk to 64 TB. Therefore the present backend cannot construct
a source-sized shadow for the requested 1,000 TB volume. Formatting a smaller
seed and growing it cannot bypass this backend limit.

The raw NTFS boot decoder, paged inspection and index walker already understand
large clusters through 2 MiB. The packaged 814 alpha restricts extent-identity
fast evidence to 4–64 KiB clusters. Development commit `a2255ba` widens both
request construction and SDK validation to power-of-two clusters from 4 KiB
through 2 MiB, retaining alignment, complete retrieval, initialized-length and
allocation checks. Its focused compile passed; native qualification of the
new large-cluster path remains pending. This does not qualify conversion from
parser support alone. The active resource geometry still requires 512-byte
sectors, 1,024-byte file records and 4,096-byte index records.

Reaching the requested scale requires an owned shadow block provider that can
expose the complete logical address space beyond a single VHDX. Its persistent
identity, backing ownership, reattachment, flush behavior, resource accounting
and recovery routes must integrate with the existing native ReFS construction
and journal protocol. Storage Spaces thin provisioning is a candidate to
investigate, not an implemented or qualified replacement. Large-cluster fast
evidence must be extended consistently in its builder and SDK, then qualified
through native conversion and recovery.

A separate Rust lab diagnostic, `lab-shadow-format-growth`, now implements two
empty-volume cases: direct 240 GiB formatting, or a 50 GiB seed inside the same
final-sized dynamic VHDX followed by partition and ReFS extension. It records
streamed legacy and metadata-inclusive bitmap summaries, backing allocation,
native geometry and real flush outcomes. It cannot accept a source device or
authorize conversion. The native experiment did **not** preserve a small seed
reservation: direct 240 GiB formatting reported 26,373,816,320 bytes in the
metadata-inclusive bitmap union; the 50 GiB seed reported 5,905,612,800 bytes,
but after growth the union was 25,971,179,520 bytes. The grown filesystem was
239.9375 GiB inside a 240 GiB partition, so this is not a controlled comparison
of equal filesystem sizes. Its strict geometry check refused; a separate
read-only observer collected both complete declared bitmap domains without
relaxing product checks or growing again. Thin VHDX backing was only 100 MiB
in the initial snapshots, a different quantity from logical bitmap reservation.
No constant-reservation, speed, complete-ownership or consumed-set claim follows.
The normal formatter remains unchanged; metadata was archived, and disposable
images were discarded by the subsequent controlled fixture restore. See the
[exact native cohorts and scope](../../evidence/native-shadow-seed-growth-20261104.json).

The frozen 814 candidate remains unchanged. These are open requirements for
the broader project, not claims made by its bounded native results.

Primary references: [VHDX limits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/bb51c7bc-63be-4be6-a77c-f1684573033c),
[NTFS cluster/volume sizes](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview),
[ReFS deployment support](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview),
[ReFS volume extension](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_extend_volume).
