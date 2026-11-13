# NTFS compression normalization

The native-shadow converter at `a126b18` converted the combined Windows 11
fixture through the public `--drive H --partition 2` command. The native ReFS
driver accepted 44 objects, 30 default stream hashes, nine named stream hashes,
three sparse layouts, seven EAs, the prior security vectors and six reparse
points. The new compression fixture contributed eight identities and seven
logical streams. See [the pinned native evidence](../../evidence/compression-native-conversion-20261031.json).
Cold-boot readback `ccafd9f0` also passed: all 39 default/named stream hashes,
44 canonical IDs and retrieval maps, ten alias IDs and seven EA entries matched
the completed conversion. The separate compression observer again checked all
seven streams and ordinary target compression state. The normal conversion's
retention proof is inherited; this cold readback is not a new comparison with
the original NTFS source extents.

Four nonresident LZNT1 streams were decoded and rewritten as 2,687,224 bytes
of ordinary ReFS logical data. Two resident streams carrying compression
policy contributed another 64 bytes. Seven identities had their NTFS
compression policy normalized, including a directory and the file with a
compressed alternate stream. The directory's future-child compression policy
is intentionally removed. Compression ratios and NTFS physical encoding are
not preserved; logical contents and the admitted Windows metadata are.

The observed public conversion took 94.686 seconds. This single combined VM
run is not a controlled speed comparison or an estimate for a physical HDD.
All 1,024 original fragmented uncompressed extents, totaling 4 MiB, remained
at their original physical positions. Compressed physical bytes were never
adopted as ordinary target data.

## Source representation

The initial encoded profile accepts nonresident DATA with attribute flags
`0x0001`, compression-unit exponent four and 4 KiB source clusters. Each
compression unit covers 16 clusters, or 64 KiB of logical data. A fully
physical unit contains raw logical bytes; an all-hole unit reads as zero;
a physical prefix followed by padding contains LZNT1 bytes. Compression padding
is an encoding property, not a logical sparse-file layout.

The reader checks the complete run map, including coverage after EOF. Runs must
be contiguous in logical coordinates, cluster aligned, in the partition and
physically disjoint. Physical data cannot follow padding inside one unit.
`TotalAllocated`, retained from the nonresident header, must equal the physical
run sum. The raw `AllocatedLength` remains separate and must be consistent with
physical allocation and mapped coverage. Older reports without this field
cannot qualify encoded data.

Resident DATA can also carry flags `0x0001` with compression unit zero. Its
value remains ordinary resident bytes: extents and `TotalAllocated` must be
absent, and logical, initialized and allocated lengths must agree. The unit
reader refuses resident DATA; the checked resident-attribute reader supplies
the original value. A resident `$I30` root marker is accepted only through the
separate ordinary-directory policy checks. It does not authorize decompression
of filesystem metadata.

The pure Rust decoder implements Microsoft's public
[MS-XCA LZNT1 buffer format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/124d9696-a69c-409a-a055-2562fbe255f9),
[chunk headers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/cba0fa15-bd62-4eda-8838-8fc7ab406df1)
and [processing rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b1ba6d34-499c-4017-ab0c-fe2daee93efc).
It checks signatures, chunk/input/output bounds and match distances, including
overlapping matches. Random logical reads use a binary search of the validated
run map and cache one decoded 64 KiB unit. Bytes after initialized length read
as zero; requests beyond logical EOF fail. The implementation does not copy a
GPL writer or decoder.

## Planning and construction

Supported compressed streams are materialization candidates. Their canonical
target streams have no retained source offset, physical source extents or
sparse layout. Construction reads decoded bytes through the original checked
source reader and initializes ordinary ReFS storage. Target expectation records
`ntfs_compression_normalized`; only target attributes clear the NTFS compression
bit. Raw source attributes and native observations remain available and must
agree under the source-view rules.

The public confirmation discloses this normalization. Planning separately
reports the logical bytes that need rewriting; their space requirement follows
logical size, not compressed allocation. In the native fixture, the four
encoded streams occupied 1,126,400 physical source bytes but required 2,687,224
logical target bytes. The recorded recovery journal was 89,071,680 bytes and
packed backing was 6,701,056 bytes. Those are measured recovery artifacts for
this small tree, not a general scratch-space bound.

Source logical hashes are reconciled with native NTFS reads before activation.
Native ReFS target hashes and a separate read-only Rust fixture observer then
check the seven streams, including the named stream. The observer never sets
compression or repairs existing metadata. Windows' distinction between file
compression and directory inheritance policy is described in
[Compression State](https://learn.microsoft.com/en-us/windows/win32/fileio/compression-state).

## Native scope and remaining work

The fixture includes mixed compressed/raw/all-hole units, incompressible data,
partial EOF units, a resident 64-byte file, an empty resident file, inherited
directory policy and a compressed ADS beside an uncompressed default stream.
The initial source-admission refusal exposed the resident DATA and `$I30`
policy forms. Its closed evidence and historical checkpoint record remain
preserved. The obsolete failed checkpoint was removed through Hyper-V after
the successful conversion; the cleanup receipt is pinned. The fix does not
permit arbitrary encoded metadata.

This is bounded LZNT1 normalization. EFS, other compression encodings, WOF or
provider-specific compression, other source cluster geometries, compressed
attribute-list spill, arbitrary scale and boot-volume conversion are not
qualified. Exact-build interruption, resume, rollback, mutation and physical
power-loss behavior require separate evidence. Older recovery results do not
transfer automatically to this build. No unit tests were added or run.
