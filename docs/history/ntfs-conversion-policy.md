# NTFS conversion policy

This describes the implemented resource-bounded conversion path in the frozen
`aef1ab3` alpha. Admission requires complete raw and native evidence for the
source. Unsupported semantics cause a refusal before conversion activation.
A readable NTFS record does not establish conversion support.

| Source feature | Implemented disposition |
| --- | --- |
| Ordinary nonresident data | Retain eligible aligned, initialized extents; relocate collisions and account for every retained or rewritten range. |
| Resident data and empty streams | Materialize resident logical bytes or create an empty stream. |
| Partial final clusters and uninitialized tails | Materialize necessary edge bytes while preserving logical length and zero-read semantics. |
| File alternate data streams | Preserve supported names and contents on the same object; refuse invalid or case-colliding names. |
| Directory alternate streams | Refuse. System Volume Information streams have additional restrictions. |
| Sparse data and valid-data length | Preserve supported physical islands and holes; materialize required edges and preserve logical zeroes. |
| NTFS LZNT1 compression | Decode supported 4 KiB-cluster streams into ordinary ReFS data. Compression inheritance is normalized away; encoded NTFS payload is not adopted. |
| EFS | Refuse. There is no implicit decrypt/re-encrypt operation. |
| File hard links | Preserve the complete supported name domain as aliases of one object. Refuse incomplete link domains and directory hard links. |
| Reparse points | Preserve supported symbolic-link and junction payloads; refuse unsupported provider/cloud tags and unsupported attribute combinations. |
| Extended attributes | Preserve supported complete EA sets; refuse unsupported encodings and combinations. |
| Owner, group, DACL and SACL | Preserve supported, independently verified self-relative security descriptors through native metadata reconstruction. |
| User Object IDs | Refuse. Recognized filesystem-internal identities have separate replacement obligations. |
| Existing DOS short-name aliases | Refuse. A disabled short-name policy does not preserve pre-existing aliases. |
| Active/nondefault NTFS quota state | Refuse. Recognized default internal quota indexes require a verified disabled-quota state. |

Source geometry admission accepts supported power-of-two cluster sizes from
4 KiB through 2 MiB, with 512-byte logical sectors, 1,024-byte MFT records and
4,096-byte index records. The target is 4 KiB ReFS. Other sector/MFT/index shapes
and unsupported filesystem/partition tails are refused. Compression has the
additional 4 KiB source-cluster restriction described above.

These are implementation policies, not a claim that every combination has
completed native qualification. The exact alpha's recorded conversion profile
is NTFS **64 KiB / 512e** to ReFS **3.14 Dev Drive / 4 KiB** on a dedicated GPT
data disk. See the [frozen alpha record](aef-experimental-alpha-20261104.md).
Its independent observer verified logical contents and namespace, but did not
independently recheck every original ACL/SACL/timestamp after conversion;
native metadata completion is separate evidence.

The principal policy code is [source admission](../../src/ntfs_admission.rs),
[paged admission](../../src/ntfs_admission/paged.rs),
[stream disposition](../../src/ntfs_stream_plan.rs),
[compression](../../src/ntfs_compression.rs), and
[native metadata reconstruction](../../crates/n2r-win32/src/shadow_native/private_tree/metadata.rs).
Broader geometry and feature-specific native cases remain work for the project;
the frozen executable and its existing evidence stay unchanged.
