# NTFS-to-ReFS preservation and admission contract

Research checked 2026-10-24 against Microsoft primary documentation. **Documented
facts** below describe published API or product contracts; **project requirements**
are engineering conclusions for this converter. They do not establish that an
unmeasured Windows build, feature or on-disk translation works. Boot remains
deferred. This document changes no runtime permissions or qualification gates.

## Qualify the actual build and volume

The current [ReFS overview](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview)
lists hard links, extended attributes, compression, named streams and ACLs; its
filesystem-encryption entry is qualified **Windows Server 2025 only**. Its scope
is Windows Server. Treating all those entries as either universally absent or
universally supported on Windows 11 would be incorrect.

There are material documentation differences:

| Topic | Documented difference | Project consequence |
| --- | --- | --- |
| Hard links | [CreateHardLinkW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw) still says NTFS-only; its ReFS “No” table explicitly concerns Windows 8/Server 2012. The current overview says “Yes.” | Require a native create/link/reopen/remount control on the exact target build; neither page alone qualifies this client. |
| Compression | [FSCTL_GET_COMPRESSION](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_compression) describes LZNT1 and an old ReFS “No” table. [refsutil compression](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/refsutil-compression) documents ReFS LZ4/ZSTD volume compression. | Shared terminology does not imply compatible per-stream APIs or disk encoding. |
| Size | The overview's NTFS limit remains 256 TB; the dedicated [NTFS overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview) documents up to 8 PB since Server 2019/Windows 10 1709, depending on cluster size. | Admit measured geometry and supported cluster sizes, never a copied generic maximum. |

[Dev Drive](https://learn.microsoft.com/en-us/windows/dev-drive/) requires Windows
11 build 22621.2338 or later, at least 8 GB RAM and 50 GB space. Its supported
setup assigns the designation during formatting; it supplies no existing-volume
conversion workflow. The same page says WSL's metadata mount option is unsupported
on ReFS despite the overview's general EA support. These are product/application
constraints, not proof that an independently engineered converter is impossible.

**Project requirement:** record OS edition/build, filesystem driver version/hash,
ReFS format version, sectors/clusters, native volume flags and exact API inputs,
outputs and errors. [GetVolumeInformation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)
exposes feature flags, but an advertised flag is only one admission observation.
Require independent semantic controls and clean-remount verification. Preserve
unknown/unsupported results instead of translating them to “absent.”
Sparse-VDL capability specifically permits noncontiguous valid clusters rather
than a single stored VDL; a derived valid prefix is only a summary of the observed
regions. Reparse capability also does not guarantee mount-point enumeration:
the same API page documents ReFS's missing reparse-point index.

## Object and metadata preservation

The right column states **project requirements and initial refusals**, not claims
that ReFS lacks the feature.

| Feature and documented fact | Required inventory/translation; first bounded profile |
| --- | --- |
| Hard links share one file and security descriptor; all links are on one volume. [API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw) | Inventory every name/parent, verified identity and link count; recreate one object with several names, not separate copies. Refuse until link-group completeness and native support are qualified. |
| Named `$DATA` streams can exist on both files and directories; enumeration distinguishes no streams from unsupported enumeration. [FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw) | Preserve raw names, contents, lengths, initialization and allocation for every stream. Default-stream hashing is insufficient. Refuse ADS initially; enumerate directory ADS too. |
| Reparse tags identify opaque data and associated filter behavior. [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points) | Open without following; inventory tag/data and required provider. Qualify each tag separately, including path/volume-identity translation. Never silently dereference a link or hydrate a placeholder into an ordinary file. Initially refuse reparse objects. |
| Handle-based security queries return owner, group, DACL and SACL; SACL access needs the caller's security privilege. Concurrent descriptor changes are not handled automatically. [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo) | Freeze objects; retain SID values, ACE order, inheritance/protection controls and absent/null/empty distinctions. Unreadable SACL is unknown, not absent. Recheck after final namespace creation. Limit privileges to the converter's process and restore them. |
| Names, timestamps and attributes are separately observable metadata; ordinary inspection changed NTFS access times in our [fixture experiments](../history/native-retained-fixture.md). | Preserve exact UTF-16 namespace and all admitted metadata; detect case/normalization collisions before creation. Keep observation nonmutating through the reviewed per-handle policy. Refuse unsupported attributes, EAs and ambiguous names; never substitute inherited defaults. |
| Sparse files and Sparse VDL are distinct from allocation/EOF. Cached and device-valid regions have different definitions. [FILE_REGION_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info) | Preserve logical zeros, holes, EOF and validity semantics; do not expose stale allocation. Initially admit only the fully initialized profile with independent logical/raw-byte correspondence. Refuse unresolved sparse/negative mappings. |
| NTFS compression and ReFS compression use distinct documented interfaces/algorithms, above. | Raw compressed NTFS runs cannot be assumed usable as ordinary ReFS payload. Refuse until decode/re-encode semantics and extra space are planned and tested; preserve requested behavior explicitly. |
| ReFS filesystem encryption is version-qualified; BitLocker is a separate feature in the overview. | Refuse EFS until key/recipient metadata, authenticated access and raw-versus-plaintext semantics are qualified on the actual target. Refuse protected/locked volume layouts outside the admitted profile. Never silently decrypt as “preservation.” |

The overview additionally lists object IDs, transactions, short names and quotas
as unavailable on ReFS. **Project policy:** detect dependencies and refuse when
preservation is required; no silent deletion. Numeric NTFS file IDs, USN history,
filesystem serials and recovery records are not automatically portable identity
contracts. An explicit old-to-new object map and fresh filesystem identity are
necessary; preserving the physical partition does not preserve those values.

## Extent retention is a separate proof

**Documented:** `FSCTL_MOVE_FILE` moves a file's clusters **within the same
volume**. Its stated granularity is one cluster for ordinary files and sixteen
for sparse/compressed files; a recently observed free bitmap can already be stale.
It is not a documented cross-filesystem extent-import interface.
[FSCTL_MOVE_FILE](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file).
The 16 KB relative-alignment advice in
[MOVE_FILE_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-move_file_data)
concerns VSS overhead, not a universal 64 KiB destination requirement.

**Project inference:** native shadow placement can construct a candidate ReFS
mapping, but moving initialized shadow payload is actual copying work, not proof
of payload-free adoption. Source retention needs separately verified equal
partition-relative addresses and exclusion of retained bytes from reconstruction.
Our test's 64 KiB-aligned placement gate is not yet a general ReFS requirement.
Any necessary source relocation belongs in an explicit journaled protocol with
old data protected until recovery is possible; it must be counted as relocation.

`FSCTL_GET_RETRIEVAL_POINTER_BASE` returns a **sector** offset; retrieval extents
use **clusters**. Convert units with checked arithmetic and bind the volume to the
physical partition. The documented `LCN=-1` sparse/compression interpretation is
specifically NTFS; preserve an unqualified ReFS negative value as unresolved.
[Base](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointer_base),
[retrieval buffer](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointers_buffer).

The WDK's
[STARTING_LCN_INPUT_BUFFER_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-starting_lcn_input_buffer_ex)
documents flag `GET_VOLUME_BITMAP_FLAG_MASK_METADATA=1` to include metadata. It
does not define an allocation-owner ledger or identify immovable metadata.
**Project requirement:** retain legacy/EX requests separately, exact ABI/status,
returned start/coverage and meaningful bits; do not turn buffer padding into
coverage. Our build accepted the 16-byte EX input, but that observation is not
all-build qualification. At original NTFS LCN6263, archived ReFS legacy bits are
free while metadata-inclusive bits are used: a concrete reason to refuse forced
placement there. [Pinned evidence and calculation](../history/bounded-converter-next-step.md).

ReFS block cloning requires both files on the **same ReFS volume**, cluster-aligned
ranges and matching integrity settings; it creates shared allocation with
allocate-on-write isolation. Documentation dates the ReFS API to Server 2016 and
automatic supported Windows copy operations to Windows 11 Moment 5/KB5034848.
[Block cloning](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning).
The Dev Drive page instead dates its block-cloning support to Windows 11 24H2/
Server 2025; preserve that product distinction in the capability manifest.
**Inference:** it cannot import an NTFS extent by itself. A converter must account
for allocation sharing/refcounts explicitly; the first ownership ledger may
refuse shared claims rather than misclassify them as corruption or free space.

For our differing A/B shadow payload method, require actual
`ChecksumAlgorithm=CHECKSUM_TYPE_NONE`, not merely enforcement disabled; those are
distinct fields. [Integrity query](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-fsctl_get_integrity_information_buffer).
**Inference:** retaining A underneath B's content checksums would invalidate the
shadow's content-dependent state. Other content-dependent features need their own
qualification before this method can admit them.
Disabling file-data integrity does not disable ReFS's mandatory metadata
checksums. [Integrity streams](https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams).

`FSCTL_QUERY_FILE_REGIONS` has filesystem-specific desired-usage requirements in
[MS-FSA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/acadee02-c40d-4f73-92d0-0f10e866e11f).
Do not demand an unsupported NTFS storage query and then invent its answer. Our
[remount observation](../history/native-vdl-observation.md) measured cached-valid 64 KiB,
storage-invalid 64 KiB and a partly unresolved map, so allocation success alone
never admits a retained range. Current initialized-source and shadow evidence
remain separate, strict contracts.

## Admission decision

**Proposed requirement:** before target writes, produce a complete namespace,
security/stream inventory and global allocation-ownership reconciliation; prove
every retained range's content and native address, classify every collision, and
budget shadow payload plus durable pre/postimage journal space. Refuse incomplete
inventory, unknown metadata/owners, incompatible semantics and insufficient space.
After reconstruction, verify the admitted contracts through a fresh native
read-only mount; a whole-volume hash before mount is not a substitute for those
checks. See the [bounded next increment](../history/bounded-converter-next-step.md) and
[architecture obligations](conversion-architecture.md). These requirements do
not expand the present single-fixture conversion qualification.
