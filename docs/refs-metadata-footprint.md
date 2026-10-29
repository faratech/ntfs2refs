# ReFS metadata footprint reader

`lab-refs-metadata-footprint` reads an ordinary raw ReFS 3.14 / 4 KiB / CRC64
volume image. It selects the unique highest valid checkpoint, requires matching
container copies, and follows the ten virtual system-root index trees. Compact
CRC64 Object Table rows must agree between both copies before their referenced
directory/system-object roots and index descendants are followed. Every
page must match its parent checksum, table, volume signature, self-address and
expected level. Physical cycles, shared page clusters, unknown reference forms
and exhausted budgets refuse. The original allocator/container node decoders
retain their stricter schema checks; the new system decoder observes schema IDs
without claiming their comparison rules have been verified.

```powershell
.\lab-refs-metadata-footprint.exe --input D:\lab\refs.raw --output D:\lab\footprint.json --max-pages 4096
```

The reader holds the input without write/delete sharing on Windows. It reads
metadata pages and records a page transcript; it does not compute a whole-image
hash. Its logical-read counter includes the initial bootstrap/container reads
and does not measure physical storage I/O. The page budget is at most 1,048,576,
depth at most eight, and the output is bounded to 16 MiB.

On the existing 52 GiB research image, all ten virtual system indexes and their
descendants completed: 12 pages, 192 KiB, five coalesced physical ranges. Total
reader input including bootstrap/container inspection was 1,340,432 bytes.
This is a read-only observation on that research image, not a conversion or a
measurement of all metadata needed by ReFS. The receipt is recorded in
[the evidence file](../evidence/refs-metadata-footprint-20261029.json).

The Medium and Small allocator readers also retain physical-page footprints
from their already checked addresses without additional reads. Those separate
receipts cover only their respective walks.

Selective conversion remains unavailable. Directory/file embedded trees,
log storage, failover generations and complete
allocator/refcount ownership still need reconciliation. These footprint
observations cannot authorize skipped reads or raw writes.

The Object Table extension completed on the same research image: 14 object
trees, 46 total pages, 12 physical ranges, and 1,897,488 total reader bytes.
Only compact 80/88-byte CRC64 Object Table values are decoded; legacy/upgraded
forms still refuse. Directory/file embedded leaf references, log storage and
the other omissions above are not yet resolved. See the
[expanded receipt](../evidence/refs-object-footprint-20261029.json).

The next reader version decodes inline filename records, follows supported
spilled attribute pages, and follows indexed DATA extent maps. It translates
supported allocated runs into physical ranges without reading their payloads;
sparse holes create no physical range. Data ranges must avoid visited metadata
and protected bootstrap/container pages. Queued roots retain page-budget
reservations while children are admitted.

The existing image exercised three inline attribute tables, two DATA versions,
68 extent records and 1,025 allocated clusters. Total reader input stayed at
1,897,488 bytes, with no external payload reads. It did not exercise spilled
attribute or extent pages; those paths remain unqualified. See the
[extent receipt](../evidence/refs-extent-footprint-20261029.json).

Only compact 3.14 DATA records and the documented plain/checksummed extent
forms are accepted. Cross-container data runs currently refuse rather than
assuming how they cross the virtual-address gap. Split own-record forms,
system log storage, complete stream inventory and all allocation/refcount
relationships remain unresolved. The converter still uses complete capture.

The generation-aware reader now walks each checksum-accepted checkpoint with
its own container mappings and Small Allocator tree. Shared physical addresses
between generations are unioned, while overlap inside one generation still
refuses. One page budget covers the bootstrap physical reads and all subsequent
container, Small, virtual and log-control reads. The detailed container profile
currently permits 32 pages and 4,096 map rows per tree; larger maps refuse.

Logfile Information OIDs 9/A must agree on the complete location-record value.
Their two 4 KiB MLog controls must pass the supported header, integrity,
instance and area-bound checks. The circular data region is included in the
required metadata ranges without scanning it. Transactions are not replayed
or certified, and the location record's trailing eight bytes remain unparsed.

On the existing image, both generations completed with 2,372,624 total reader
bytes and 145 charged page operations. The observed metadata union covered
538,177,536 bytes, including the 512 MiB circular log. Six declared own-record
attribute nodes were also parsed. The [receipt](../evidence/refs-generation-log-footprint-20261029.json)
does not establish complete ownership or authorize selective conversion.
