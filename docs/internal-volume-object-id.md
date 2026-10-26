# Filesystem-internal NTFS volume identity

The NTFS `$Volume` record can have an object ID even when no user file uses
object IDs. The restricted converter treats one exact form as a
filesystem-internal identity to archive and replace. It does not claim that
ReFS preserves that NTFS ID or its application semantics.

`ntfs_internal::verify` can construct an opaque `InternalVolumeObjectId` only
when the complete supplied MFT inventory contains exactly one `0x40` attribute,
on recognized reserved record 3 (`$Volume`). The record must be a non-directory
base record with a nonzero sequence number, one link and no role issue. The
attribute must be plain, unnamed, resident, exactly 16 bytes and nonzero.

The separately reread `$Extend\$ObjId:$O` resident index must contain exactly
one entry. Its 16-byte key must equal the actual `$Volume` value; its 56-byte
value must consist of that record's current 64-bit MFT reference followed by
48 zero birth/domain bytes. Extra index trees, entries, user or other internal
object IDs, extended values and unknown identity state remain unsupported.
An empty index supports replacement only when there are no object-ID
attributes anywhere in the inventory.

Both resident values are reread from the source through the existing checked
MFT reader, which applies USA fixups and verifies record sequence/base identity
and the complete attribute report. Cached `resident_metadata_hex` and hashes
are not substituted for source bytes. The proof binds the canonical inspection
hash; the owning conversion flow must still bind that inspection to its actual
frozen source, full-image hash, allocation, namespace and native evidence.
This proof alone does not authorize conversion.

The source evidence stores the exact ID, its hash, current MFT reference,
attribute instance, index record identity and root/value hashes. Its disposition
is `replace-filesystem-internal-volume-identity`, and
`same_refs_object_id_preserved` is explicitly false. All user object-ID
refusals and independent quota/reparse policy gates remain in place. No source
attribute or index is deleted or edited.

The motivating recorded source was the failed qualification at
`.lab/hyperv/certificate-conversion/win11-20261026T025002875Z`. Its sole ID was
`d0fcc359a462874fb8f1baa21bc395b9`, SHA-256
`7e01ca45d8b66df4b0a422ea3e6e7972f34c4ecbac33ea30d0296733ad7e42e2`.
The index reference matched record 3, sequence 3, with the remaining 48 bytes
zero. These are recorded source observations, not native qualification of the
new replacement policy.

Synthetic-image tests cover the accepted form, altered or torn source reads,
forged inventory hex, stale sequence/record references, user IDs, additional
entries, zero/extended IDs and nonzero birth/domain bytes. They issue no native
disk operations.
