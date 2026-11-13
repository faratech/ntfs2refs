# Bounded reparse-point preservation

This describes the native-shadow implementation at `439a55c`, not general
NTFS reparse compatibility. Public conversion `2ef04a07` and cold-boot readback
`7270a96c` passed. Fixture `5dc696e6` contributed ten identities, six supported
points and two ordinary payload files. All six point buffers/tags matched, and
four bounded functional routes worked on ReFS. Dangling and cyclic routes were
checked as metadata only, without traversal.

The combined tree had 36 objects, 24 default and eight named stream hashes,
seven EAs and three sparse layouts. Existing security vectors also matched.
The observed conversion took 90.88 seconds; this is not a controlled speedup.
All point buffers, prior file IDs, stream hashes and data mappings matched
after reboot. See [the native evidence](../../evidence/reparse-native-conversion-20261031.json).
Exact-build interruption/recovery, mutation, power loss and broader reparse
forms remain unqualified.

## Source evidence

The raw reader retains the complete `$REPARSE_POINT` (`0xC0`) value. It must
be unique, unnamed, unencoded, wholly initialized and start at VCN zero.
Resident bytes are bound to the attribute's retained bytes and digest.
Nonresident mappings must cover their allocation without gaps, overlaps,
sparse storage or out-of-volume runs. The retained `Point.buffer` is reparsed
on replay; a saved point alone is not a source certificate.

The complete `$Extend\$Reparse:$R` index must cross-match every supported point
by tag and full file reference, including its MFT sequence. The walker verifies
allocated index storage. Missing, extra or duplicate references, nonempty row
values and invalid ordering prevent the replacement proof. Keys are ordered as
successive little-endian ULONGs, not byte strings or ordinary 64-bit integers.

Streaming native report schema 11 records an explicit point, observed absence,
or query error on each present canonical file/directory snapshot. Handles use
`OPEN_REPARSE_POINT`; `FSCTL_GET_REPARSE_POINT` queries that same object.
Only `ERROR_NOT_A_REPARSE_POINT` establishes native absence. Failed queries
never become an empty point. Source comparison requires the complete raw/native
buffer, tag and `FILE_ATTRIBUTE_REPARSE_POINT` to agree. Legacy snapshots
without point evidence can replay absence, not establish link preservation.

## Supported representation

`IO_REPARSE_TAG_SYMLINK` and `IO_REPARSE_TAG_MOUNT_POINT` are supported. The
complete buffer is limited to Windows' 16 KiB bound. Validation checks the
declared data size, type header, UTF-16 path ranges and alignment, and relative
symlink flags. Paths are never resolved or normalized by the codec. Substitute
and print names, their placement, unused bytes and terminators remain in the
original buffer; native readback must match it exactly.

Mount points require directories. File links currently require an empty unnamed
DATA stream, with no ADS or sparse layout. Their link target is metadata;
conversion does not copy data from that target into the link's DATA stream.

## Native construction and verification

The canonical file identity owns the point once. Existing names continue to
refer to that identity. Expected-tree and input digests bind the point bytes;
report JSON cannot manufacture constructor ownership or source-write authority.

Construction first completes ordinary payload placement, parent-first ACL
restoration and EAs. It then installs points on the actual held, freshly owned
empty objects, before finalizing basic timestamps and attributes. Symbolic-link
creation uses an explicitly enabled `SeCreateSymbolicLinkPrivilege` lease,
restored by the owning tree. The setter cannot overwrite an existing point.

Native SET/GET readback checks the full buffer and held identity. Subsequent
metadata operations and protected/final observations recheck point bytes,
type and tag. Canonical or additional names descending through a point are
refused. Namespace verification does not enumerate a point's target directory.
The converter preserves the link object rather than inventorying its target.

## Fixture scope and limitations

The fixture covers relative/absolute file symlinks, a relative directory
symlink, an absolute junction, a dangling file link and a directory cycle.
Inventory opens each object without following points. Four functional reads
are restricted to independently reconstructed, known existing fixture routes.
Dangling and cyclic links are metadata-only and are never traversed.

Unknown provider/cloud tags, root-volume points, attribute-list spill and
unsupported DATA/encoding combinations remain refused. EAs and points are
mutually exclusive. Recognized filesystem-internal objects cannot carry a
point that would be silently discarded during metadata replacement.

Preserving an absolute target buffer does not prove its external destination
remains available. Volume-GUID aliases and mount targets require separate
post-conversion validation; the fixture's known drive paths do not qualify
arbitrary external mounts. No recovery, power-loss, boot-volume or unrestricted
feature/geometry compatibility follows from the fixture observation.
