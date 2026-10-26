# Bounded ordinary NTFS DATA attribute-list assembly

The Rust source reader now handles an ordinary file whose unnamed nonresident
DATA is split between its base MFT record and extension records. This is wired
through inspection, allocation/namespace/security reconciliation, native mapping
comparison, ordinary shadow construction and the checked source stream reader.
It has synthetic source/test evidence, not a new native conversion qualification.

The initial profile requires:

- A nondirectory base record numbered at least 16, one link, one resident unnamed
  STANDARD_INFORMATION and FILE_NAME, and one complete unnamed ATTRIBUTE_LIST.
  An optional resident legacy security descriptor is preserved.
- One ordinary unnamed nonresident DATA attribute in the base at VCN zero.
  Extensions contain one ordinary unnamed DATA segment each and no other attrs.
- Current nonzero sequence references, allocated MFT bitmap bits, exact base-file
  references and unique record-local attribute instances. Every non-list
  attribute must have exactly one matching list entry. The list may explicitly
  include its own base attribute once; it need not do so.
- Contiguous VCN coverage through the base attribute's complete allocated size,
  including preallocation beyond EOF. Base logical/initialized/allocation lengths
  remain authoritative; undefined continuation length fields are not interpreted
  as stream sizes. Mapping-pair LCN deltas restart within each physical segment.
- Exclusive, aligned, in-volume payload extents, with no sparse or encoded data.
  Limits remain 1,024 DATA runs and 1,024 extensions per assembled file. All list
  bytes are bounded to 64 KiB. A resident list additionally fits its MFT record.
  Existing conversion bounds of 128 files/32 directories/256 MiB are unchanged.

The entry layout follows Microsoft's
[ATTRIBUTE_LIST_ENTRY description](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry).
The record-local instance at byte 24 is retained alongside the full file reference;
an instance alone cannot identify an attribute in another record. No upstream
filesystem implementation code is incorporated.

`NtfsInspection.files` is the canonical logical view. Its DATA mapping combines
the original segments exactly once, and its semantic attributes remain attached
to the base identity. `attribute_assemblies` retains each original base/extension
attribute report, raw record SHA-256 and exact logical list bytes. Extension records
are not published as additional files or additional payload ownership claims.
The inspector defers extension records so that physical record order does not
determine whether a base can resolve them. Unclaimed extensions retain the existing
incomplete-inventory refusal path; they are never silently dropped.

Ledger version 1 preserves the resident-list contract. Version 2 additionally
accepts a nonresident list whose complete mapping is in the base record. Before
reading its bytes, the reader requires initialized length equal to logical
length, exactly rounded allocation, contiguous logical coverage and aligned,
nonsparse, unencoded, in-volume physical runs. List storage cannot overlap DATA
or itself. Its metadata allocation is supplied separately to the global ownership
reconciler, so stripping the list from the canonical semantic view cannot hide
allocated clusters. Its storage is never counted as user payload or retained DATA.
Version-1 evidence cannot claim a nonresident list by changing a success flag.

`validate_record_coverage` replays that ledger, compares the resulting canonical
attributes, rejects reused/missing physical identities and conserves the complete
physical scan count. Native comparison replays this check when assemblies are
present; its legacy subset-diagnostic behavior is unchanged. Source admission,
internal-index checking and ordinary shadow derivation require complete counts
for every profile. Old complete reports without the optional field retain the old
one-record-per-file count contract. Neither
serialized counters nor a successful replay grants live conversion authority.

Before copying or range-hashing an assembled stream, the checked reader rereads
the actual base/list/extensions through the verified MFT mapping, checks their
current MFT allocation bits and reproduces the original physical-record evidence.
A changed list, sequence, mapping, continuation header or allocation bit refuses
the read. Full stream copies also compare their logical hash. Bytes beyond VDL
remain logical zeroes, even if those physical sectors contain nonzero data.

The tests construct a complete synthetic namespace/allocation/security model with
one base plus two extensions, including extensions with lower record numbers than
the base. They exercise logical hashing/copying, cross-segment range hashes,
ordinary shadow derivation, native retrieval-page replay, poisoned continuation
lengths, VDL zeroes, stale allocation, orphan records and counterfeit ledgers.
An additional 4 MiB fixture contains 129 extension records and a 4,224-byte list
in two nonadjacent clusters. All 130 DATA runs and both list-storage runs are
accounted for exactly once; checked copying and ordinary shadow derivation pass.
Incomplete list metadata is refused before any list-payload read, changed list
bytes fail reread, and allocated slack beyond list EOF is not interpreted as entries.
The pure assembler tests additionally cover malformed list entries, missing/extra
origins, duplicate identities, unsupported forms, physical overlaps and limits.

MFT bootstrap lists, filesystem-internal lists, directory-index assembly,
lists whose own mappings require further assembly, named streams, multiple links and encoded/sparse segments
remain outside this profile. No original VM/checkpoint, device, source image or
writer experiment was changed to establish these source results.
