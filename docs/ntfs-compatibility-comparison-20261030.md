# NTFS compatibility comparison — 2026-10-30

ntfs2refs does not yet provide general NTFS compatibility. ntfs2btrfs is a
useful, broader reference, but it also omits or transforms source features.
Matching its feature list would not establish lossless conversion of every
NTFS volume.

This is a source and evidence review, not a new native qualification run.
Our inspected revision is `bbe161c2ed2ba6acbeaf5270e995445e5d30e843`, with the
existing user-owned `src/main.rs` overlay left untouched. Native results belong
to the exact binaries in their receipts, not automatically to this revision.

## External implementations

| Project and pinned revision | Relevant capability | Boundary |
|---|---|---|
| [ntfs2btrfs](https://github.com/maharmstone/ntfs2btrfs/tree/433523abaff4015db0f473e4f256f9d5671c9cd5), `433523a` | Adopts ordinary NTFS payload extents; reconstructs names, links, security, streams and reparse information; handles NTFS/WOF compression through special paths. | Encrypted files, large ADS, legacy EAs and case-sensitivity preservation are incomplete. Some failures warn and skip rather than stop. |
| [btrfs-convert](https://github.com/kdave/btrfs-progs/tree/2229e1d7cbd6ce4c3085fd440e9c3275bc9a97c7), `2229e1d` | Converts ext2/3/4 and optionally ReiserFS using existing free space and a saved source image. | Its NTFS recommendation is the separate ntfs2btrfs tool. POSIX ACL/xattr handling does not establish Windows security preservation. |
| [fstransform](https://github.com/cosmos72/fstransform/blob/efc519736069b6808f1c0fe74e810626732d5799/README.md), `efc5197` | Linux filesystem migration through an image, file mover and extent remapper; limited spare space and remap recovery. | Upstream explicitly excludes NTFS. It copies payload, so it is not evidence of a metadata-only NTFS conversion. |
| [NTFS-3G](https://github.com/tuxera/ntfs-3g/blob/7f0f841fc52cf719106c5c93bafe465004e36816/README), `7f0f841` | Mature NTFS reader/writer, permissions, junctions, EAs and compressed-file handling; useful for understanding source semantics. | A filesystem driver, not an NTFS-to-ReFS converter. Plugin/configuration-dependent support must not be mistaken for native ReFS behavior. |

The [official btrfs-convert manual](https://btrfs.readthedocs.io/en/latest/btrfs-convert.html)
also requires compatible source geometry and a clean source. Balance can destroy
its rollback opportunity; `--no-xattr` drops xattrs and ACLs. Its
[ext converter](https://github.com/kdave/btrfs-progs/blob/2229e1d7cbd6ce4c3085fd440e9c3275bc9a97c7/convert/source-ext2.c#L631-L674)
can skip oversized xattrs. These are useful engineering precedents, not a
universal compatibility contract.

## What ntfs2btrfs actually preserves or loses

Its source provides more detail than the README's supported-feature list:

| Source feature | Observed conversion behavior |
|---|---|
| Ordinary nonresident data | Existing physical ranges become Btrfs extents; source allocation is read before construction. |
| Resident data, sparse/uninitialized regions | Separate construction paths; not simply arbitrary allocated bytes treated as initialized file data. |
| Hard links | Multiple names reference the reconstructed inode, rather than separate payload copies. Large same-directory link groups still encounter a target inode-reference limit. |
| Security | Windows descriptors are represented through `security.NTACL`; missing security lookup can warn and continue. |
| Ordinary ADS | Stored as Btrfs xattrs. Oversized values or names are skipped; encrypted/compressed ADS also have refusal-by-omission paths. |
| NTFS compression and WOF | Special decoding/materialization paths. Their physical encoding cannot be relabeled as ordinary target data; decompression can buffer the whole expanded file. |
| Symlinks and other reparse points | Recognized symlinks are translated; other payloads use a Windows-driver-specific representation. Unsupported WOF forms can warn and continue. |
| EFS-encrypted file | The file is skipped, not preserved as an equivalent encrypted target file. |
| Long names | The source includes truncation to the target UTF-8 byte limit. This is not exact preservation of every NTFS UTF-16 name. |
| Legacy EAs and directory case-sensitivity | Not preserved completely; recognized WSL EA metadata has special translation. |

Pinned source: [file and stream classification](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L2064-L2152),
[name handling](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L2219-L2225),
[security and WOF handling](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L2762-L2849),
and [ordinary extent adoption](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L2951-L2960).
The [reference limit](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1141-L1158)
and [compression reader](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L2646-L2716)
also matter when choosing an implementation suitable for very large sources.

Those metadata representations rely on the destination driver. For example,
[WinBtrfs documents](https://github.com/maharmstone/btrfs/blob/3fa5cf21dde2913d58d7b74e150625e18bd490bd/README.md#features)
ACLs in `security.NTACL` and ADS in `user.*` xattrs. A capability in WinBtrfs
does not prove that ntfs2btrfs imports it, or that Microsoft's ReFS driver would
interpret the same representation.

Performance is also separate: ntfs2btrfs normally reads data to create checksums.
Its explicit `--no-datasum` policy changes that contract. Extent adoption alone
does not imply metadata-only reads. See the pinned
[checksum path](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L3333-L3438).

## Current ntfs2refs compatibility

“Native evidence” below means the bounded fixtures in the linked receipts.
It does not mean every size, combination or Windows build is qualified.

| Feature | Current state and remaining boundary |
|---|---|
| Ordinary files/directories, empty/resident data, partial EOF tails | Native conversion evidence exists. Resident/tail bytes may be materialized rather than retained physically. |
| Hard links | Native conversion, alias mutation/reboot and controlled recovery evidence exist for earlier pinned builds. Preserve identity relationships, not the original numeric NTFS file ID. |
| File ADS, including large streams | Native evidence includes empty, Unicode, literal `$DATA`, multi-MiB, fragmented and sparse ADS. This exceeds ntfs2btrfs's documented large-ADS restriction. Directory ADS and ADS on System Volume Information objects remain refused. |
| Sparse default streams and ADS | Native conversion includes holes, allocated islands and an all-hole file; earlier pinned sparse build has controlled resume/rollback evidence. Sparse mutation remains pending. |
| ATTRIBUTE_LIST and extension records | Native conversion/reboot covers a base plus seven extensions, resident filenames/ADS and two 512-extent streams. Sparse/encoded multi-record assembly and directory-index spill remain outside the implemented assembly profile. |
| Owner, group and DACL | Supported preservation path; requires a present DACL. Absent and null DACLs are refused. A present empty ACL is a distinct state, not a null ACL. |
| SACL/auditing | Any present SACL is refused. Parser support is not conversion support. |
| NTFS compression, WOF and EFS | Not admitted as ordinary source data; no qualified normalization or encryption migration path. |
| Symlinks, junctions, mount points, other reparse points | User reparse attributes remain outside source admission. Add supported tag-specific paths; cloud/offline/dedup stubs must not be treated as ordinary local data. |
| NTFS EAs / WSL metadata | User EA attributes remain outside source admission. ReFS support alone does not preserve them. |
| Names, case and short aliases | Conservative UTF-16-to-Rust-string/Win32 name profile, bounded depth, no DOS-only aliases. No explicit live directory case-sensitivity preservation/gate was found. Collision checks do not prove flag preservation. |
| Object IDs, quotas and TxF | User object IDs and unsupported active state remain refused; recognized filesystem-internal defaults have explicit replacement rules. New native file IDs/journal state are not NTFS historical identity continuity. |
| VSS snapshots | Recorded design requires up-front refusal. This review found no explicit live VSS enumeration/refusal path in runtime source; treat this as an admission gap, not implemented support. |
| Disk layout | Dedicated basic GPT data disk with an optional preceding MSR. Other data/EFI/system partitions are refused. The entire disk holding Windows is excluded, including a separate D: partition on that disk. |
| Geometry and scale | Source profile requires 512-byte sectors, 1 KiB MFT records and 4 KiB index records; expanded cluster handling is experimental. Target is formatter-created ReFS 3.14/4 KiB with `/DevDrv`; actual formatter acceptance is required. Fixed resource limits remain; universal volume-size support is not established. |
| Boot/OS volume, BitLocker, clustered/tiered storage | No general conversion qualification; boot remains deferred. Do not infer support from either filesystem's own feature list. |

Source anchors: [admission and names](../src/ntfs_admission.rs),
[shadow security/metadata requirements](../src/shadow_tree.rs),
[multi-record assembly](../src/ntfs_attribute_list.rs),
[OS-disk exclusion](../crates/n2r-win32/src/discovery.rs),
[disk-layout constraints](../crates/n2r-win32/src/general_layout.rs),
and [stream limits](../crates/n2r-win32/src/stream_layout.rs).
The streaming profile still allows only 1,024 files, 256 directories, 64 streams
per file and 16,384 streams per tree. Those are implementation limits, not NTFS
or ReFS format limits; raising one constant does not remove coupled budgets.
The journal still has a 16 GiB cap. Multi-stream assembly also has a 64 KiB
list limit, 1,024 extension records and 1,024 aggregate DATA runs.

Native receipts:
[hard links](../evidence/hardlink-native-conversion-20261030.json),
[ADS](../evidence/ads-native-conversion-20261030.json),
[sparse conversion](../evidence/sparse-native-conversion-20261030.json),
[sparse recovery](../evidence/sparse-native-recovery-20261030.json),
[multi-record conversion](../evidence/attribute-list-native-conversion-20261030.json),
and [latest measured fragmented conversion](../evidence/bitmap-planning-performance-20261030.json).
The latest performance binary does not inherit earlier builds' reboot, mutation
or recovery qualification.

## ReFS imposes separate limits

Microsoft's [ReFS comparison](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview#feature-comparison)
lists native EAs, reparse points, named streams, sparse files, hard links and
ACLs. Encryption is version-dependent; the table limits EFS to Server 2025.
It excludes NTFS transactions, object IDs, native short names and quotas.
Boot is not officially supported there; experimental boot work is a separate
objective. These constraints prevent a promise of identical NTFS semantics
on every ReFS target.

Bind supported semantics to the actual Windows build and volume capabilities,
using [GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)
plus operation-specific evidence. A version number or feature bit alone does
not prove our converter handles a feature. Likewise,
[stream lengths and sparse/compression state are per-stream](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams),
so a file-level attribute cannot stand in for every ADS's semantics.

## Continuation priorities

1. Complete the explicit source-feature inventory: directory case flags, VSS,
   every unsupported attribute/tag, and precise refusal reasons. Never adopt
   warning-and-skip or name truncation under a lossless conversion claim.
2. Extend the native-shadow model for NTFS EAs, SACL/null-DACL preservation,
   symlinks and junctions. Bounded EA preservation appears to be the smallest
   next feature: resident EA inventory and native backup restoration already
   exist. That is an implementation estimate, not a completed capability.
   Keep exact metadata bytes and identity relationships;
   do not follow a link while enumerating it. Unknown reparse tags need their
   own policy because their data may live outside the file.
3. Add a distinct logical materialization path for NTFS LZNT1/WOF compression.
   Reuse the existing journal and stream model. Account rewritten bytes and
   scratch explicitly; never retain encoded compressed runs as plain data.
   Process bounded compression units instead of buffering a whole expanded file.
4. Remove coupled fixed limits through resource-based planning and broaden
   name/geometry/layout support. Supporting a data partition on the OS disk
   requires a partition-level exclusion/recovery design, not deleting the
   current whole-disk guard.
5. Keep EFS, legacy application identity requirements and boot conversion as
   explicit target-specific work. A sidecar can archive unsupported metadata,
   but cannot by itself reproduce its live filesystem behavior.

Keep the working Rust native-shadow engine. The useful reference pattern is
semantic reconstruction over retained extents with feature-specific transforms
and explicit refusal. No reference implementation source was copied, no unit
tests or VM operations were run for this review, and existing evidence remains
unchanged.
