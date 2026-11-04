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
large clusters through 2 MiB. However, extent-identity request construction and
SDK validation currently restrict that fast evidence to 4–64 KiB clusters.
Larger supported geometries fall back to logical content hashing. Their parser
support is not evidence of fast or qualified conversion. The active resource
geometry profile also retains its 512-byte sectors, 1,024-byte file records and
4,096-byte index-record requirements.

Reaching the requested scale requires an owned shadow block provider that can
expose the complete logical address space beyond a single VHDX. Its persistent
identity, backing ownership, reattachment, flush behavior, resource accounting
and recovery routes must integrate with the existing native ReFS construction
and journal protocol. Storage Spaces thin provisioning is a candidate to
investigate, not an implemented or qualified replacement. Large-cluster fast
evidence must be extended consistently in its builder and SDK, then qualified
through native conversion and recovery.

A separate performance experiment can test formatting a 50 GiB seed inside a
final-sized shadow and extending the partition and ReFS afterward. Windows
supports ReFS volume extension. Whether this changes the final reserved or
consumed metadata ranges is unknown. A future disposable-image comparison must
capture both final geometry and complete allocation/consumption evidence; no
constant-reservation or speed claim follows from API support alone.

The frozen 814 candidate remains unchanged. These are open requirements for
the broader project, not claims made by its bounded native results.

Primary references: [VHDX limits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/bb51c7bc-63be-4be6-a77c-f1684573033c),
[NTFS cluster/volume sizes](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview),
[ReFS deployment support](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview),
[ReFS volume extension](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_extend_volume).
