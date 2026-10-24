# Lessons from the pinned ntfs2btrfs implementation

Reference: Mark Harmstone's ntfs2btrfs, commit
`433523abaff4015db0f473e4f256f9d5671c9cd5`, checked out read-only under
`.lab/research/ntfs2btrfs`. This note describes inspected source concepts; no GPL
source was copied into the Rust implementation. The source declares GPL version
2 or later. Any future source reuse needs an explicit licensing decision.
[Pinned source notice](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1-L16).

The project documents in-place NTFS-to-Btrfs conversion with an original-image
reflink at `image/ntfs.img`. Its Windows instructions exclude a currently used
boot drive or pagefile drive. Those are properties of this Btrfs implementation,
not evidence of ReFS conversion or boot support.
[Pinned README](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/README.md#L4-L30).

| Observed mechanism | Implication for our work |
|---|---|
| `convert` reads the NTFS allocation bitmap and constructs allocation runs before mapping inodes. | General conversion needs a complete source inventory and allocation model. A single retained fixture is insufficient. |
| `protect_cluster` relocates occupied clusters needed by fixed structures; `protect_superblocks` also protects the first megabyte. | Mandatory anchor collisions need explicit relocation or rejection. An allocation bitmap cannot waive a collision. |
| `create_image` records original allocated extents and resolves relocated ones into the image file; its containing subvolume is read-only. | Its rollback representation depends on Btrfs extent sharing and metadata. We cannot transplant that mechanism into ReFS. |
| Conversion writes trees, then superblocks, then clears the NTFS prefix. | Discovery writes deserve a distinct final phase. Source order alone is not a power-loss durability proof. |

These observations are in the pinned
[conversion routine](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L3691-L3877),
[anchor protection](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L3520-L3603),
[read-only image subvolume](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1218-L1225), and
[image extent construction](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1274-L1383).

The rollback implementation locates the image file, resolves its extent mappings
through Btrfs chunks and restores relocated extents. It rejects unsupported
extent forms and non-SINGLE chunk layouts. That mechanism is not an external
write-ahead journal, and this source inspection does not establish interruption
safety at every write or flush boundary.
[Pinned rollback](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/rollback.cpp#L385-L494).

Our current design therefore uses a separately bounded external journal of
every changed granule's old and new bytes. The exact comparison includes zero
and free regions, and excludes only explicitly pinned retained ranges. It makes
no inference that a differing sector is filesystem metadata. The journal and
trusted ticket must become durable before target mutation; both recovery
directions verify the whole normalized source, preserve retained bytes, flush
all other writes before the discovery granule, and verify the complete result.
A separate durable handoff barrier closes rollback before a writable native
mount. See [the journal contract](lab-reconstruction-journal.md).

Journal recovery evidence remains **ordinary-file testing**, including
interrupted writes, failed flushes, journal corruption, separate-process recovery
and torn handoff markers. Guest-native preparation and raw reads have separately
verified the one-extent fixture, its integrity policy, original-target offline
persistence and explicit provider-protected shadow reattachment. The complete
partition reads passed in probe case `win11-20261024T043618703Z`; its host runner
then failed a baseline-restoration check, which is preserved rather than promoted
to a completed run. Fresh probe `win11-20261024T045526178Z` subsequently
completed both native stages and host restoration successfully. See
[measured results](retained-preparation-results.md).
No actual native NTFS-to-ReFS reconstruction/remount or native power-loss
qualification has yet passed. Boot conversion remains deferred.

The original NTFS location also supplies a concrete collision example:
LCN6263..6278 is free in the ReFS legacy bitmap but occupied in its
metadata-inclusive view. This proves an admission conflict under our current
allocation rule, not the identity or immovability of its ReFS owner. The
[next-step plan](bounded-converter-next-step.md) records the pinned buffers and
distinguishes retained extents from future bounded, journaled relocation.
The reference supplies useful engineering concepts; it does not satisfy the
remaining ReFS-specific gates.
