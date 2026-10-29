# Selective conversion plan (ntfs2btrfs-style)

Goal: make conversion cost proportional to what changes, not to the volume size,
the way fast in-place converters do. This is a plan with measured inputs; the
projected figures are projections, not results.

## How the fast converters work

| Converter | Model | Reads |
|---|---|---|
| [ntfs2btrfs](https://github.com/maharmstone/ntfs2btrfs/) | Reads `$Bitmap` and `$MFT::$BITMAP`, maps data runs in place ("mapped directly"), copies only what cannot stay ("rewrote"/"inlined"), builds Btrfs trees in memory, writes them into free space, superblocks last. Rollback keeps the original image as a reflink. | NTFS metadata, plus one optional pass over data for checksums (`--no-datasum` skips it). |
| [btrfs-convert](https://btrfs.wiki.kernel.org/index.php/Conversion_from_Ext3) | Same model for ext2/3/4 via libe2fs; original saved as an image file. | Source metadata. |
| [fstransform](https://github.com/cosmos72/fstransform) | Copies files into a loop file in free space, then remaps blocks. About 1 min/GB; no NTFS support. | Everything, about twice. |

No open-source project writes ReFS 3.x. [Paragon's driver](https://www.phoronix.com/news/ReFS-Linux-Write)
is proprietary, and [libfsrefs](https://github.com/libyal/libfsrefs/blob/main/documentation/Resilient%20File%20System%20(ReFS).asciidoc)
and [forefst](https://github.com/xbqt/forefst) only read. So this project keeps
Windows as the ReFS metadata writer (the native shadow) rather than writing ReFS
trees itself, and applies the ntfs2btrfs model to *finding and journaling* the
write set.

## Where ntfs2refs already matches, and where it does not

Writes already match the model: the measured HEAD run wrote 70,615,040 bytes in
158 ranges to a 52 GiB volume and left file data in place. Reads do not: the
write set is found by comparing every byte of the source with a source-backed
shadow view, and the run re-reads both images several times, about 15 volume reads
(at least 816.6 GB) in 46m53s. See [the readiness notes](release-0.0.1-readiness.md).

## Measured basis for an allocation-driven write set

The HEAD run's own protected observation of the frozen shadow
(`target-preservation.json`, SHA-256
`6b3b67919feb718e683fd90745d31cd8684c11da2cc68afced10adc79077d512`, archived with
the run) records Windows' metadata-inclusive allocation of the shadow and
classifies every byte the full comparison found changed:

| Quantity | Bytes |
|---|---:|
| Shadow allocation (metadata-inclusive native bitmap, 5 ranges) | 14,768,467,968 |
| of which file-data routes (13) | 8,594,411,520 |
| of which neither anchors nor file data (metadata zone and the like) | 6,173,782,016 |
| Changed bytes found by the full comparison | 70,615,040 |
| Changed bytes inside the shadow allocation | 70,615,040 (100%) |
| Changed bytes outside it | 0 |
| Changed bytes inside file-data routes | 286,720 |

The 286,720 bytes inside file-data routes are not end-of-file slack. They are file
data that the shadow placed at physical locations other than the NTFS runs:
pieces that must be copied, as ntfs2btrfs "rewrites" what it cannot map. File-data
routes therefore cannot simply be skipped, and the selection must include them
unless location identity with the NTFS runs is proven.

One fixture is not a proof that changes never fall outside the allocation. Bytes
that ReFS's own allocator marks free are not part of the filesystem's state, which
is the same assumption every converter above makes about the target, but this
project has not yet authenticated that. The diagnostic stays false for
`allocation_graph_complete`.

## Proposed path

1. **Coarse selection from the frozen shadow's allocation.** Take the metadata
   allocation ranges and known anchors that the protected observation already
   holds inside its bracket, as `SelectedRange`s. No new device reads.
2. **Exact selection.** Run `selected_journal::changed_plan` with the frozen
   source as `source` and the existing source-backed shadow view as `candidate`,
   over only the coarse ranges. Projected reads on this fixture: about 14.8 GB
   from each side instead of whole images. A later refinement can drop file-data
   routes whose physical runs provably equal the NTFS runs, leaving about 6.2 GB.
3. **Device-bound selected journal.** Prepare the `N2RSEL01` journal on the
   existing independent recovery storage, apply to the source under the existing
   exclusion and write-policy handles, and hand off with the existing native
   mount verification (15 objects, 10 complete hashes on this fixture).
4. **Admission and recovery binding.** The live source certificate currently binds
   a whole-source SHA-256. A selective certificate must bind the NTFS metadata
   inventory, the selected old/new hashes and the frozen-device identity instead,
   without weakening "never recreate the certificate from JSON". Version the
   recovery bundle so `N2RSEL01` journals are recognized and the full-image API
   still refuses them.
5. **Qualify on the lab fixture**: normal conversion, then the
   interruption/resume/rollback matrix, comparing time and bytes read with the
   46m53s HEAD baseline.

Steps 1–2 are read-only. Steps 3–5 write to the disposable lab source only, behind
the checkpoint. Projected end-to-end reads are tens of GB rather than ~816 GB;
that remains a projection until step 5 measures it.
