# Bounded ReFS bootstrap root-node observations

`src/refs_node.rs` inspects an already assembled 16 KiB page from physical bootstrap roots 7, 8 or 12. It performs no image I/O and follows no row value as an address. `PhysicalRootPage.node` contains an observation when the structure passes; `node_rejection` records a refusal otherwise. These fields are independent of the existing reference checksum/header checks. A matching CRC can coexist with a rejected node layout, and a structurally readable node can coexist with a failed reference CRC.

The profile accepts `MSB+` header version 2, table ID high half zero, container IDs 11/12 with schema `0xe0c0`, and allocator ID 34 with schema `0xe010`. Every metadata/checksum/conversion qualification flag remains false, and no authoritative checkpoint is selected.

The primary [B+-tree research](https://xbpt.gitlab.io/forefst/structures/btree_node/) distinguishes the table's root descriptor at page `0x50` from the per-page node header reached through its relative offset. The descriptor size is a 16-bit value; its adjacent 16-bit auxiliary field must not be folded into the size. Table-wide and per-node row counts are separate. Index entries contain a relative row offset and an uninterpreted marker. The reader checks the researched index length/count invariant and the agreement between node level and the index flag, while retaining other flag bits and reserved fields. The [container-table research](https://xbpt.gitlab.io/forefst/structures/container_table/) documents rows whose key is a prefix of the value; such within-row overlap is permitted.

The implementation limits the index to 1024 bytes, hence at most 256 rows. It rejects out-of-bounds headers/arrays/rows, duplicate row offsets, overlap between rows, overlap with the pointer array or structural prefix, and nonempty key/value ranges inside the row header. Row order follows the pointer array rather than physical offsets. Complete row bytes, SHA-256, key/value hashes and raw unknown header regions are retained. Disjoint row ranges bound row hex storage to twice the input page length. The 40-byte node-header region is an explicit initial-profile boundary.

The standalone node parser does not verify key ordering, child-reference semantics, allocator ownership or container translation. The separate [bounded container-tree reader](refs-container-reader.md) now checks container child references and decodes leaf mappings. Counts remain observations; even a leaf count is not declared to prove whole-table completeness. Unknown marker values are preserved without treating zero as a universal rightmost-child indicator.

## Native validation

On 2026-10-23, the opt-in test read exactly **49,152 bytes** from the completed 52 GiB Dev Drive capture, using a read-only handle that excludes writers/deletion on Windows. Each page SHA-256 matched the earlier full-capture inspection, whose JSON hash is pinned as `5a3bee79702c3c68bfa281786090e4000bf437f2e7574892c5a6714edfc16ece`. This validates those ranges against existing capture evidence; it does not rehash or revalidate the rest of the 52 GiB file.

| Table ID | Schema | Whole-table rows | Node level | Node rows |
| ---: | ---: | ---: | ---: | ---: |
| 11 | `0xe0c0` | 832 | 1 | 10 |
| 12 | `0xe0c0` | 832 | 1 | 10 |
| 34 | `0xe010` | 2 | 0 | 2 |

All node headers are at page offset `0x278`. Both container roots have a final index entry with an empty key and marker zero; these remain raw observations. Allocator markers are `1` and `0x3fdd`; both allocator rows have overlapping key/value ranges. The allocator descriptor auxiliary field is `0xe010`, and its descriptor size still reads `0x28`.

```powershell
$env:N2R_NATIVE_REFS_CORPUS='D:\code\ntfs2refs\.lab\hyperv\corpus\devdrive-20261023T231918797Z'
cargo test --test refs_node native_roots -- --ignored
```

The native test and nine synthetic node tests passed, along with bootstrap integration tests. Synthetic tests cover bounds, arithmetic, duplicates/overlaps, profile mismatches, legal key/value overlap, unknown fields/markers, empty fields and distinct table/node counts. Release binaries were not rebuilt.
