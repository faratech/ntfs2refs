# Experimental compact container traversal

The larger-tree resource profile now selects a compact ReFS 3.14/4 KiB Container
Table reader through bootstrap inspection, virtual-root translation, Medium
allocator traversal and frozen target qualification/reconstruction. Default
inspection retains the detailed reader and its existing bounds and JSON shape.

The compact reader checks the actual checkpoint-bound root SHA-256 and CRC,
then validates every child's CRC, header, table/volume identity, physical self
slots and parent-derived level. It rejects cycles/shared clusters, bootstrap
overlap, duplicate or unsorted IDs, out-of-volume container ranges, mismatched
root counts and physical overlap between containers. I/O failures propagate;
malformed walks remain rejected and supply no usable lookup view.
Structural refusals retain a `refs-container-compact-partial-v1` digest/count
receipt for completed page reads, including a fully read bad-CRC page. This
rejected prefix has no live address data or root binding and cannot be used for
translation. CRC/header errors identify the failing physical page slots.

Each decoded leaf contributes only its container ID and physical starting LCN
to the live index: two `u64` values. Raw row values are discarded after updating
the mapping digest. Both copies must have identical address indexes and matching
mapping digests. That digest uses the existing ordered sequence of ID (`u64`),
physical start (`u64`), clusters per container (`u32`), and all 160 raw value
bytes, with little-endian integers. A separate page transcript hashes its version
prefix followed by each visited page's four physical LCNs, depth byte and complete
16 KiB page. CRC/reference checks remain mandatory independently of these hashes.

Bounds are one million pages per tree, four million pages across at most four
roots, depth eight, and at most 33,554,432 mappings per tree, further limited by
the volume's physical container capacity. These are explicit experimental
resource budgets, not a claim that every layout at that size is supported.
Address-index memory grows with mapped containers; it is not constant memory.
A transient vector of physical starts checks global overlap without retaining
raw diagnostic values or per-page observations for all descendants.

Compact diagnostics contain counts, mapping/page-transcript digests and the
actual root-page observation. They do not contain every descendant page receipt
or the address index. Private live lookup storage and its volume/checkpoint/root
binding are excluded from serialization. Deserializing a report cannot recreate
them; consumers must rebuild the index from the actual stable image. The
`compact` field is absent on legacy detailed tree reports. A fixture constructor
was mechanically updated with `compact: None`; no tests were added or run.

This implementation has compilation evidence only. It does not qualify a native
mount, whole-volume ownership, source admission from JSON, write-set omissions,
or arbitrary-volume conversion. The public 128 GiB partition ceiling, tree/data
budgets, allocator-row limits, journal ceiling and scratch/I/O costs remain.
The frozen alpha and its original evidence/executable pins are unchanged.
