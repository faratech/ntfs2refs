# What NTFS-to-ReFS conversion must rebuild

Research checked 2026-10-24, alongside the guest-native experiments. This is an
engineering synthesis, not a statement that the general converter is complete.

NTFS describes files through MFT records and attributes, including mappings to
storage outside the MFT. Streams separately track allocation, EOF and initialized
length. Recreating the visible directory tree alone would miss storage and
metadata obligations. [Microsoft MFT documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table),
[stream model](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams).

ReFS uses allocate-on-write metadata updates and always checksums metadata;
checksums for file contents are a separate integrity-stream policy. **Inference:**
changing a signature or directly reusing NTFS metadata cannot construct the
ReFS metadata graph and its integrity relationships. Our current approach asks
the native Windows driver to create that graph in a same-geometry shadow, then
experimentally validates reconstruction on the original partition.
[Metadata update semantics](https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/fix-heavy-memory-usage-refs),
[integrity streams](https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams).

Microsoft's original design explanation makes the difference concrete: ReFS
uses a key/value storage engine built from B+ trees, with directory tables,
embedded file/stream tables and hierarchical allocation tables. That2012
description explains the architecture; it is not a current on-disk writer
specification. [Original Microsoft design post](https://learn.microsoft.com/en-us/archive/blogs/b8/building-the-next-generation-file-system-for-windows-refs).

Address interpretation is another boundary. The primary2019 study of ReFS3.4
describes container-based translation for many stored addresses, with physical
bootstrap structures. Its layout cannot simply be assumed valid for our3.14
volume. **Design consequence:** a number labelled LCN is insufficient by itself
to authorize retention. Keep native mapping evidence, complete allocation
coverage and independently verified raw-byte correspondence; qualify additional
layouts explicitly. [Prade, Groß and Dewald, sections4.1.2 and4.2.4, especially
pages40–41](https://d-nb.info/1201551625/34).

| Source obligation | Conversion work |
|---|---|
| MFT objects, names and complete directory indexes | Establish a complete object/namespace inventory; create corresponding ReFS objects and indexes. Numeric source identifiers are not assumed portable. |
| Attributes, stream lengths and initialization | Translate supported semantics through native APIs; refuse unqualified forms. Preserve logical bytes, including required zeros, rather than exposing uninitialized allocation. |
| NTFS allocation bitmap and every nonresident owner | Reconcile global ownership before deciding which original blocks may survive or be overwritten. A bitmap alone does not identify owners. |
| File extents compatible with the shadow layout | Prove native ReFS mappings and raw content correspondence, then exclude those target bytes from reconstruction writes. |
| Extents conflicting with ReFS allocations | Build an explicit relocation plan; include real payload bytes in durable journal postimages and all overwritten bytes in preimages. This remains future profile work. |
| Security, links, streams and other features | Apply the separate [preservation contract](ntfs-refs-preservation-contract.md); a familiar Win32 feature name does not prove identical disk encoding or support on this client build. |
| Filesystem recovery metadata | Obtain a consistent native shadow. Keep the converter's external recovery journal separate from either filesystem's own recovery mechanism. |

The table states design requirements derived from the source model and
our experiments; Microsoft does not document this shadow-transplant procedure
as a supported conversion interface.

```mermaid
flowchart LR
    N[Offline NTFS inventory and ownership] --> S[Native ReFS shadow]
    N --> P[Retention and relocation plan]
    S --> P
    P --> J[Durable old/new journal and independent ticket]
    J --> W[Bounded offline reconstruction]
    W --> V[Native mount and preservation verification]
```

In-place means reconstructing the original partition while preserving its
admitted files. It does not require every byte to remain at its old address.
For example, our original file location LCN6263..6278 is occupied in the ReFS
metadata-inclusive bitmap, despite appearing free in the legacy view.
The [pinned evidence](../bounded-converter-next-step.md) supports relocation or
refusal for that location; it does not identify an immovable ReFS structure.

ReFS block cloning cannot serve as a cross-filesystem import operation: its
source and destination must already reside on the same ReFS volume and have
compatible integrity settings. Consequently the Btrfs reflink rollback image
in [ntfs2btrfs](../ntfs2btrfs-design-lessons.md) is not a drop-in ReFS recovery
scheme. Our external journal contains actual bytes and is independent of the
destination filesystem's allocator. [Microsoft block-cloning restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning).

The practical split remains Rust for inventory, planning, bounded raw I/O,
journaling and verification, with native Windows APIs generating ReFS metadata
inside the owning machine. Hyper-V provides snapshots and automation for tests;
the conversion algorithm does not require host-side VHD editing. Independent
[ReFS implementation research](refs-implementation-evidence.md) can improve
inspection and corroboration without being treated as a qualified writer.

Feature tables require version checks. For example, the current ReFS overview
and the dedicated NTFS overview give different NTFS size limits; the latter
explains newer Windows and cluster-size dependencies. We bind driver/build,
geometry and measured API behavior instead of adopting a generic table as an
admission rule. [ReFS overview](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview),
[NTFS size/version details](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview).

Current experiment boundaries remain one controlled retained extent, explicit
integrity NONE, an independent journal device and a fixed Windows/ReFS profile.
General source admission, native interruption recovery and boot conversion are
separate outstanding milestones. Consult [runtime status](../../IMPLEMENTATION_STATUS.md)
for actual completed phases; research conclusions do not promote a failed run.
