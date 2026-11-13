# Checked fragmented MFT bootstrap

`src/ntfs_mft_bootstrap.rs` resolves a bounded fragmented MFT before the normal
inventory or source-state readers use its mapping. The converter's geometry,
Windows-build, file-count and data limits remain unchanged. This is source and
synthetic integration coverage; no new native conversion has been qualified.

The loader starts at the boot sector's MFT LCN and validates record zero through
the existing FILE/USA parser. For the list profile, the base must contain exactly
STANDARD_INFORMATION, FILE_NAME, ATTRIBUTE_LIST, DATA and BITMAP, all unnamed and
unencoded. LIST and BITMAP must each have their entire initialized mapping in the
base record; either may be resident or nonresident. MFT DATA may have additional
segments, with the original VCN-zero sizes remaining authoritative.

The complete initialized MFT bitmap is read before extension records. Every
referenced extension must be allocated, have the current nonzero sequence, name
record zero's full base reference, and contain one matching ordinary DATA segment.
Record-local instances and list origins must agree. No filename or container UUID
is substituted for a physical record reference.

An extension is read only when its entire logical record range is already mapped
and initialized. Each validated segment adds known VCN ranges; these can form
noncontiguous islands. A later segment may therefore make an earlier segment's
record reachable. All learned logical/physical ranges are bounded and checked for
overlap. A circular or unreachable dependency produces a no-progress refusal;
there is no raw-cluster scan, guessed record location or synthesized zero record.
The final DATA mapping must cover the complete declared allocation without gaps.

The assembly ledger versions are separate from NTFS/ReFS format versions:

| Ledger | Base | List storage | Additional evidence |
|---|---|---|---|
| 1 | Ordinary file | Resident | Original records and list bytes |
| 2 | Ordinary file | Complete nonresident | Original records and list bytes |
| 3 | MFT record zero | Resident | Exact initialized MFT bitmap bytes |
| 4 | MFT record zero | Complete nonresident | Exact initialized MFT bitmap bytes |

The bitmap's allocated record set must equal the complete set of canonical files
plus uniquely owned physical extensions. It is insufficient to make two counters
equal. MFT extensions are not extra files or duplicate allocation owners. MFT
DATA owns their storage; nonresident LIST/BITMAP storage retains separate claims.
The ordinary profile still rejects record zero and other reserved base identities.

Checked stream copying/range hashing and resident-attribute reads rebuild this
bootstrap from actual source bytes. Backup, log and internal-index checks also
revalidate it before using inventory mappings. Actual base/extension records,
list bytes, bitmap bytes and canonical attributes must reproduce the original
ledger. A missing or counterfeit serialized ledger cannot grant read/write or
conversion authority; live source admission remains a separate requirement.

Synthetic integration fixtures place the user record beyond the initial MFT map.
They exercise ordinary and island-dependent bootstrap, resident/nonresident
auxiliaries, source copying, MFT DATA reads, namespace/allocation/security
reconciliation, ordinary shadow derivation and exact four-record mirror checks.
Negative cases cover unlearned reads, no progress, stale bitmap bytes, forged
record accounting and missing ledgers. Original native evidence is unchanged.

Bounds remain 1,024 assembled runs/extensions, 64 KiB list bytes and one million
MFT records with at most 125,000 bitmap bytes. Existing inspection/hash/allocation
budgets can refuse earlier. Split auxiliary LIST/BITMAP attributes, named system
lists and additional unsupported MFT attributes remain refused. Log recovery,
native compatibility and boot-volume conversion are not established by this work.
