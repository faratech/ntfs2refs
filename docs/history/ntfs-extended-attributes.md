# Bounded Windows EA preservation

This describes the native-shadow EA implementation at `2aef493`. It is a
preservation contract, not a claim of full NTFS compatibility. Public conversion
and cold-boot readback passed on the bounded fixture. The native fixture `80607d54`
created and read back seven EAs on four new objects, including directory EAs,
an 8,192-byte binary value, `FILE_NEED_EA`, and a hard-link alias.

Public run `1a715809` converted the same partition using runtime `2aef493`:
17 objects, 11 default and eight named stream hashes, three sparse layouts,
and all seven EAs matched. The original fragmented 4 MiB stayed in place.
The observed runtime was 88.73 seconds; this is not a controlled speed comparison.
Cold-boot observer `737f994` then verified the same tree, EAs, identities and
data mappings through the public conversion's pinned read-only bundle inputs.
See [the native evidence](../../evidence/ea-native-conversion-20261031.json).
Mutation, interruption/recovery and physical power loss remain unqualified
for this exact runtime.

## Source evidence

- `$EA_INFORMATION` (`0xD0`) and `$EA` (`0xE0`) must occur together, once each,
  unnamed, unencoded, wholly initialized, and starting at VCN zero.
- Information is an eight-byte resident value. Data may be resident or
  nonresident and is limited to 65,536 logical bytes. Nonresident mappings must
  cover the complete allocation without holes, overlaps or out-of-volume runs.
- The inventory retains exact information/data bytes as hex. Replay reparses
  them and reconciles the packed size, unpacked size and required-EA count.
  Serialized canonical entries alone do not establish raw source evidence.
- EA allocations remain in ordinary source ownership reconciliation and the
  frozen-source digest; they are not excluded because they are metadata.
- Native source schema 10 collects EAs before and after on the same canonical
  file/directory handle. The complete set must agree with raw NTFS evidence.
  Named DATA-stream handles do not issue file-level EA queries.

See [raw inventory](../../src/ntfs_extended_attributes.rs),
[portable layouts](../../crates/n2r-win32/src/extended_attributes.rs), and
[source comparison](../../src/ntfs_attestation.rs).

## Semantics and native collection

An EA belongs to a file identity: hard-link names share it, and ADS do not get
independent copies. Entries retain raw name bytes, exact flags and binary values.
Names compare case-insensitively within the supported ASCII profile; entry order
is canonicalized. Flags are `0` or `FILE_NEED_EA` (`0x80`). Values may contain
zero bytes and non-UTF-8 bytes.

Native collection enumerates the complete set, checking synchronous completion,
page structure, duplicate names, size bounds and unchanged native identity.
Known no-EA/end-of-enumeration statuses are interpreted explicitly; an actual
query or decode error never becomes an empty set.

`Snapshot.extended_attributes = Some(empty)` means observed absence. `None`
means unobserved or failed, distinguished by `extended_attributes_error`.
Schema 10 requires an outcome for each present canonical snapshot. Fresh source
admission requires successful complete evidence. Missing fields in historical
reports remain readable but cannot support a new EA-preservation claim.

## Target construction and verification

The constructor sets EAs once on each fresh, held canonical file/directory
handle, after directory security propagation and before final basic metadata.
`restore_fresh_owned` refuses a target that already has EAs, requires the
appropriate EA handle access, verifies identity, and compares a complete native
readback with the expected set. It is not an existing-file replacement API.

Protected post-construction observations and final native verification require
the expected EA set with no missing/error outcome. The public lab observer also
compares the independent fixture with raw source, source snapshots, the expected
tree and target snapshots, while independently hashing ordinary payloads and
checking hard-link groups. The observer never repairs metadata.

NTFS can persist internal SI bit `0x40000` when EAs exist while Win32 omits it.
The projection clears this bit for files or directories only after validated,
nonempty paired EA evidence identifies its meaning. Raw SI is retained. The
same numeric `RECALL_ON_OPEN` bit is not globally masked; other flags and the
independent EA comparisons remain mandatory.

## Boundaries

The current profile refuses high-byte/non-ASCII or otherwise invalid EA names,
duplicate case-folded names, unknown flags, zero-length values (native SET means
deletion), excessive sizes, sparse/encoded/continued EA storage, and EAs requiring
attribute-list assembly. Root-directory EAs are outside the admitted root profile.
Recognized filesystem-internal objects must have empty EAs; their replacement
role cannot authorize dropping EA metadata. Missing or malformed paired evidence
also refuses admission. These scoped conversion/reboot results establish no
broader security, boot-volume, geometry, recovery or power-loss qualification.
