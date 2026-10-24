# Raw NTFS security reconciliation

The inspector now reports `security_reconciliation`: decoded descriptors and
one binding per allocated file identity. It handles central IDs in
`$STANDARD_INFORMATION` and legacy unnamed type 0x50 attributes. Our native
captures contain legacy descriptors on root, `$Boot` and reserved MFT records.

For record 9 `$Secure`, the reader reconciles `$SDS`, `$SII` and `$SDH`:

- The observed `$SDS` header is 20 bytes: hash at 0, ID at 4, primary offset at
  8, total length at 16. Records have matching backups 0x40000 bytes later;
  pairs advance by 0x80000. Position, bounds and duplicate bytes must agree.
- The rotate-left-three/add hash over little-endian descriptor words must
  match. Hash collisions are permitted; IDs remain distinct.
- `$SII` orders IDs; `$SDH` orders unsigned hash/ID pairs. Their 20-byte values
  must match the complete primary header. Counts, IDs and headers reconcile
  across all three structures, including descriptors with no current file use.
- The shared bounded walker in `src/ntfs_index.rs` checks allocation bitmaps,
  fixups, initialization and topology for filename and security indexes. Their
  key/value decoders and comparison rules remain separate.

Each central ID resolves to its validated descriptor. Legacy attributes must
be unnamed, fully initialized and unencoded, with a matching resident hash
when applicable. Ambiguous central/legacy sources, missing IDs, duplicates or
unassembled attribute lists/extensions refuse reconciliation. Failed results
contain no partially accepted descriptor/binding set.

Relative bytes are retained exactly as hex and SHA-256, alongside control/RM
flags, owner/group SIDs and ordered DACL/SACL entries. Absent, null and
present-but-empty ACLs stay distinct. SID, ACL, ACE and optional GUID bounds
are checked. Conditional/resource application bytes are retained by offset
and length, without evaluation or normalization. Compound and unknown ACE
types are refused by this initial decoder.

The profile uses 512-byte sectors and 4 KiB clusters/index records. Limits are
16 MiB of metadata reads, 4 MiB of descriptor bodies, 16,384 descriptors/files
and 65,536 ACEs in total. Descriptor hex, decoded entries and strings count
toward the inspector's shared 64 MiB report budget. Unsupported geometry,
initialization or bounds produce a rejected diagnostic. Older reports without
the optional field remain unverified.

## Validation and evidence

The independent initial byte observation checked eight descriptor hashes and
mirror copies under ignored `.lab/development/security-format-20261024T080921502Z`.
Its `format.json` SHA-256 is
`a9108aa1778bb86cc9f6c2377dd7b67ae660031b9568f5886aeeb2d476374371`.
These storage layouts are interoperability evidence, not a Microsoft write ABI.

The final optimized inspector rechecked both saved 1 GiB Windows-generated
captures, denying concurrent writers and verifying full image hashes before
and after. Namespace and allocation reconciliation also passed after the
shared-walker refactor. Frozen guest conversion binaries were not replaced.

| Capture | Central descriptors | Legacy descriptors | File bindings | ACEs | Security INDX pages |
| --- | ---: | ---: | ---: | ---: | ---: |
| Empty | 5 | 6 | 28 | 28 | 0 |
| Populated control | 8 | 6 | 36 | 44 | 1 |

`lab/Test-NtfsSecurityDescriptorOracle.ps1` checks buffers using native Windows
`IsValidSecurityDescriptor`, native length and .NET `RawSecurityDescriptor`.
It compares control flags, owner/group, ACL presence/revision/count, ACE
type/flags/mask/trustee and exact ACE bytes/order. Both captures pass in
PowerShell 5.1 and 7.6.7. These are buffer checks, with
`nativeFileSecurityQueried=false` and no volume/device operations.

The final evidence directory is ignored
`.lab/development/security-observation-20261024T130105835Z`:

| Artifact | SHA-256 |
| --- | --- |
| Summary with source/build pins | `3d2c7539c0ba8b03b2d7b71a0bb422bb76e0bc4e10e2ae1eac78a46b759f9e2a` |
| Archived inspector | `d41391033c6cf93a216500caef418d1960b774e15448fe07f86afc1b1791a97d` |
| Empty report | `d66cfebeeee22f2c2f78703c967a9becfb4221792d7f5c3cccd6ca9ad27b760f` |
| Empty oracle PS5 / PS7 | `daca5a1c11229204864b7658097a38c81e1c815c26c384d20be746daf8ba5be8` / `5831df6939ab5a17835c6a1506510f3478cd79d4f3b3415f1fb8fde5b97ac6b1` |
| Control report | `a1b25e0e0bcabe41455fd67a25c55b7017b6b8da9ac6437e0c062b7dc2b86baa` |
| Control oracle PS5 / PS7 | `2d923526bf7a02aac3bb7d830e3fae9c6ad2bfa713019c9b7154abd2ef29ae49` / `d77fd090ef6967f9b306a7d89da227fc4cee095407dbf3a2a3b60db9e5ef469c` |

Image hashes remain the original native capture pins recorded in
[namespace evidence](ntfs-namespace-reconciliation.md). Thirty-one pure security
tests and nine integration tests cover corruption, multiple mirror pairs,
internal keys, stale/missing IDs, ACL states, audit/object/callback ACEs,
malformed offsets, unsupported structures and old-report compatibility.
At that milestone the workspace passed 296 tests with five ignored native/child-process
cases. Formatting and clippy with warnings denied pass.
Audit/object/callback cases are synthetic parser tests; the captured buffers
do not qualify every optional ACE feature on Windows.

## Remaining admission work

Raw reconstruction and buffer validity do not establish effective access.
[Native file-handle observations](native-ntfs-file-attestation.md) now bind
both Windows security APIs to the 36 requested identities on a read-only guest
mount. Sixteen kernel descriptors match, while open/query refusals, API
inheritance differences and a cached root access-time difference remain visible.
This is incomplete source admission, not a blanket security certificate. Target
round-trip preservation, freeze/log/backup checks and general conversion remain
unfinished. `inventory_complete=false` and the security/admission blockers stay
in force; no access check or target ACL write occurs in this implementation.

Microsoft defines relative components in
[MS-DTYP 2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
the [ACL layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl)
and [object ACE fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace).
Its [native validity contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidsecuritydescriptor)
checks present components, without proving each ACE's meaning. No third-party
writer engine was incorporated.

## Dependency follow-up

GitHub reported [GHSA-r6v5-fh4h-64xc](https://github.com/advisories/GHSA-r6v5-fh4h-64xc)
for the locked `time 0.3.45`. The lockfile now selects patched `time 0.3.47`
and its required transitive updates. All 296 tests and clippy pass again.
`time` is optional in `ntfs` and absent from the active default Windows tree;
the rebuilt inspector is byte-identical to the archived binary above. Those
native observations therefore still apply. Their original lockfile archive
remains unchanged; a separate patch-provenance record binds the updated lockfile,
test logs and unchanged binary rather than rewriting historical evidence.
That record is `.lab/development/time-patch-provenance-20261024T131709562Z.json`,
SHA-256 `d8efaf06317e74c3c34d09ee7a385d1cdb88e1b9ffdec65fc29c05797604224e`.
