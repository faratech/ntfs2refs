# Bounded physical container-tree reader

`src/refs_containers.rs` now walks the two physical container roots for each accepted checkpoint candidate. The production bootstrap inspector supplies roots only after their reference CRC, page header, self-location, table ID and root-node structure match. It retains each checkpoint/root result separately and never selects an authoritative copy. This module follows no virtual root and performs no writes; its agreeing complete maps now feed the separate [virtual-root reader](refs-virtual-roots.md).

## Bounds and checks

The supported profile is ReFS 3.14, 4096-byte clusters, 16 KiB pages, 48-byte CRC64/NVME references, and 160-byte container values. The defaults and hard ceilings are 32 page reads per tree, 128 reads across at most four roots/two checkpoints, 4096 decoded rows per tree, and depth four. The node parser separately caps an index at 256 rows. Pending work is counted before child traversal. Container reads total at most 2 MiB; bootstrap anchors/root probes add their existing ceiling of 143,360 bytes.

Root pages are reread and matched to both their supplied CRC and the SHA-256 recorded by the bootstrap probe. Every child requires a supported descriptor, four distinct nonzero in-volume LCNs, matching full-page CRC64, `MSB+` version 2, zero reserved header/table-high fields, matching volume signature, all four self-LCN slots, and the same table ID as its root. Its level must descend by one. A repeated child, cycle, partially overlapping page, or overlap with protected bootstrap/root clusters stops that tree before another read. Child clusters are assembled in reference order, including noncontiguous slots.

The [page-reference research](https://xbpt.gitlab.io/forefst/structures/page_references/) supplies the narrow descriptor layout. The [node research](https://xbpt.gitlab.io/forefst/structures/btree_node/) distinguishes root descriptors from per-page headers. Our first independently CRC-checked native child has an eight-byte prefix at `0x50`, locating its node header at `0x58`; unsupported child-prefix layouts are rejected. The root-node parser remains unchanged in scope and still reports root headers separately.

The [container-table research](https://xbpt.gitlab.io/forefst/structures/container_table/) supplies the 16-byte key and 160-byte value fields used here. Decoding checks the key's constant tag and echoed prefix, version 1, cluster count 16,384 and its trailing copy, and a complete physical range inside the volume. Duplicate keys or overlapping physical container ranges within one tree are rejected. Raw values, flags, the 64-bit free-count sentinel and the separate 32-bit free-count field are retained. No inferred flag meaning controls traversal, allocation or eligibility.

## Reports and limits of the evidence

`BootstrapProbe.container_tables` records read counts, every page's hash/checksum/header outcome, parent page and row provenance, decoded mappings, rejection reasons, and pair comparisons. Successful trees have `walk_finished=true`; malformed or budget-limited trees may retain partial mappings but always have `walk_finished=false` and a rejection. I/O failures propagate instead of returning a successful partial inspection.

Whole-table count agreement, decoded mapping equality and raw-value equality are separate observations. Count mismatches or differing failover maps do not select a winner. Global metadata, allocation and conversion qualification remain false. `PhysicalRootPage.children_traversed` now reports whether its separate container walk read any children; the standalone node parser's `children_traversed=false` still describes that parser's own lack of I/O.

This is a bounded container map, not proof that any cluster is free or safe to overwrite. Key ordering/separator routing, allocator ownership, virtual-root descendants, current-checkpoint selection, crash consistency and native writer acceptance remain unverified.

## Native result

The pinned full-capture inspection has SHA-256 `5a3bee79702c3c68bfa281786090e4000bf437f2e7574892c5a6714edfc16ece` and binds the existing 52 GiB Dev Drive corpus. The opt-in test rereads only the bounded referenced metadata, without rehashing the full image. It uses the previously verified root SHA/CRC values, then validates every newly followed edge and page.

| Checkpoint LCN | Root | Pages read | Leaf rows | Root count agrees |
| ---: | ---: | ---: | ---: | --- |
| 136348 | 7 | 11 | 832 | Yes |
| 136348 | 8 | 11 | 832 | Yes |
| 1635808 | 7 | 11 | 832 | Yes |
| 1635808 | 8 | 11 | 832 | Yes |

Both failover pairs have identical decoded mappings and full raw values. The direct four-tree probe reads 44 pages, **720,896 bytes**. The native test also exercises the production bootstrap integration in a second bounded pass. All source handles are read-only and exclude writers/deletion on Windows.

```powershell
$env:N2R_NATIVE_REFS_CORPUS='D:\code\ntfs2refs\.lab\hyperv\corpus\devdrive-20261023T231918797Z'
cargo test --test refs_containers native_container -- --ignored --nocapture
```

Eleven synthetic tests cover malformed references and values, checksum/identity failures, root-only leaves, nested indexes, noncontiguous slots, cycles/repeated children, page/extent overlaps, duplicate keys, budgets, pair disagreement, count mismatch and I/O failure. Release binaries are not rebuilt by this increment.
