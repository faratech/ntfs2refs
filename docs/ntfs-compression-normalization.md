# NTFS compression normalization

The converter decodes supported NTFS LZNT1 streams in Rust and constructs
ordinary ReFS streams with the same logical bytes. NTFS compression policy is
cleared in the target expectation and recorded as
`ntfs_compression_normalized`; source metadata and native source observations
retain the original flags. This does not enable ReFS compression.

The initial encoded profile is nonresident DATA with method flag 1, compression
unit 4 and 4 KiB source clusters. Other methods, encryption and encoded metadata
remain refused. Ordinary resident data on a compression-policy file needs no
LZNT1 decoding. Directory compression policy is normalized after admission of
its contents, without following reparse points.

`src/ntfs_compression.rs` implements Microsoft's public
[MS-XCA LZNT1 description](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/124d9696-a69c-409a-a055-2562fbe255f9).
It validates the complete run map, volume bounds, physical overlap and the
compressed header's TotalAllocated. A compression unit is raw when fully
physical, zero when wholly unallocated, or decoded when a physical prefix is
followed by compression padding. Padding is not a sparse logical hole. Reads
are bounded by EOF and return zero beyond initialized length. A held reader
caches one 64 KiB decoded unit rather than expanding the entire file.

Compressed physical bytes are never adopted as ReFS data. Their stream-plan
disposition is materialize, with no retained physical source range or sparse
layout. Existing physical ownership checks still account for every compressed
allocation. Source logical hashes and native stream reads must agree before
source admission. Target logical hashes must agree after reconstruction.

The stream plan counts the full logical size of each compressed stream in
`materialized_candidate_bytes`. Shadow allocation and recovery capacity are
still measured before activation. Compression normalization can require much
more space than the source's compressed allocation; it is disclosed at the
interactive confirmation. Uncompressed eligible extents remain candidates for
retention. This support does not remove existing geometry, resource, disk-class
or recovery restrictions.

The disposable native fixture covers mixed compressible/raw/zero units,
incompressible data, partial EOF tails, resident and empty policy, inherited
directory policy and a compressed ADS. Its independent SHA-256 and XXH3
observations are distinct from the converter's decoder. Native conversion and
reboot qualification are pending for this implementation.
