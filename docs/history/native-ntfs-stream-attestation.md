# Native NTFS stream, extent and bitmap reconciliation

The Rust collector now binds native stream lists and VCN-to-LCN retrieval
pointers to the raw NTFS inventory. Inside the VM, the complete native volume
bitmap matched the raw allocation ledger, and every fixture object passed the
stream/extent checks. This supplies allocation and mapping evidence for source
admission; it does not enable conversion or qualify unsupported file semantics.

## Implemented checks

`crates/n2r-win32/src/stream_layout.rs` decodes `FILE_STREAM_INFO` and
`RETRIEVAL_POINTERS_BUFFER` with bounded counts, lengths and arithmetic. Stream
names retain UTF-16 code units, including unpaired surrogates. Only explicit
`:$DATA` forms are accepted; duplicate names, unknown types, invalid delimiters,
bad links, partial responses and invalid signed coordinates are refused.

For each successfully opened file identity, the collector enumerates streams
twice. A named ADS is opened through a volume-GUID path obtained from the source
handle, with `OPEN_REPARSE_POINT`. Its file and volume IDs must match the source
identity before and after retrieval. Unnamed streams use the original handle.
This avoids treating the path alone as proof of stream ownership.

`src/ntfs_stream_attestation.rs` reconciles exact name sets, logical sizes and
ordered byte mappings. Native retrieval-base units are **sectors**, multiplied
by the source sector size before adding LCN cluster offsets. Adjacent equivalent
runs can merge; sparse holes remain distinct from allocated data. Overflow,
out-of-volume references, incomplete attribute assembly and encoded/compressed/
encrypted layouts refuse the initial mapping profile.

Resident data requires the observed native `ERROR_HANDLE_EOF` with no retrieval
locations. Its stream allocation size is not mistaken for separately owned disk
clusters. Nonresident physical allocation is checked against the sum of mapped
physical runs, rather than NTFS's logical allocation-length field. This
distinction matters for sparse data.

Before and after file queries, the collector obtains retrieval base and volume
bitmap observations. Bitmap start/domain/length must cover the entire supplied
NTFS cluster domain; initialized bitmap bytes must have the raw ledger's exact
SHA-256, and the two native snapshots must agree. The raw ledger must already
reconcile every allocated cluster with its attribute owner. Padding is not
silently normalized to manufacture a digest match.

The profile bounds each file to 64 streams, each retrieval response to 1,024
extents, the bitmap to 2 MiB, and retained stream/allocation evidence to 8 MiB.
The existing 256-file and security limits still apply. Native errors and system
record refusals remain visible rather than becoming empty accepted inventories.

## Native result

The source was the same 1 GiB native NTFS control image, restored inside the
guest and protected read-only before its first mount. Both independent capture
runs, on separate restores of the prepared source checkpoint, kept the full
partition SHA-256 unchanged:
`86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727`.

| Check | Measured result |
| --- | --- |
| Native retrieval base | 0 sectors, stable |
| Bitmap domain | All 262,143 NTFS clusters |
| Bitmap response | 32,784 bytes: 16-byte header + 32,768 bitmap bytes |
| Bitmap/ledger digest | `1d1758918d1734d921a3dd990048edd9e1404f9a2da5c8693e73d24c8fa12dc4` |
| File identities requested / opened | 36 / 17 |
| Matching stream inventories | 16 identities, 13 data streams |
| Fixture coverage | All 8 fixture objects, including all 8 fixture data streams |
| Unsupported system observations | 19 explicit open refusals; `$Volume` query error 87 |
| Native source writes | 0 |

The ordinary 16 MiB stream at record 40 has one native run beginning at LCN
2003, covering 4,096 clusters. Its `named` ADS is resident: 19 logical bytes,
24 native allocation bytes, and no retrieval locations. Record 42 has 16 MiB
logical size but only 64 KiB physical allocation. Its native runs are a
2,048-cluster hole, 16 physical clusters at LCN 6340, then a 2,032-cluster hole.
These mappings agree with the independent raw NTFS decoder.

The matching identities include the root, several queryable NTFS internal
objects, the fixture directory and all seven fixture file identities. The
remaining records are accounted for in the raw ledger and bitmap comparison,
but their unavailable native file queries are not represented as passing.

The earlier [security and cached timestamp differences](native-ntfs-file-attestation.md)
remain separate observations. The final metadata comparator reports three
strict file matches; neither `all_requested_metadata_matched` nor
`all_mappings_matched` is true for the whole 36-record corpus. Matching stream
locations does not establish initialized-data behavior, logical file hashes,
native namespace completeness or target preservation of ADS/hard links/reparse
points/sparse files.

## Report size and replay

Native schema 3 includes the stream captures and allocation observations.
IOCTL binary buffers are serialized as hex strings; the decoder also accepts
the initial schema-3 byte arrays. This makes two maximum-size bitmap blobs fit
within 9 MiB of JSON, leaving room in the existing 16 MiB artifact limit for the
small inventories needed by the 52 GiB lab volume. Other report-budget limits
still apply; this is not unlimited-volume qualification.

The initial native array report was 1,024,216 bytes; the compact report is
422,334 bytes. Replaying the array report with the final binary produced the
identical comparison hash, and the second native run produced that same result.
The capture runner now accepts the exact prepared source checkpoint explicitly:

```powershell
.\scripts\Capture-LabNtfsFileAttestation.ps1 `
  -RunId 057cfe705cca456aa3e7c472dedc7dcc `
  -SourceCheckpointId c4f58c73-5ca5-4842-bc7b-6e980a8eabd7 `
  -BinaryPath <lab-ntfs-attest.exe> -BinarySha256 <sha256>
```

The final evidence is ignored
`.lab/hyperv/ntfs-attestation/file-handles-20261024T152601970Z`:

| Artifact | SHA-256 |
| --- | --- |
| Collector binary | `7f91c70e7356eefba48d1905be19999694ab4dc8b6153144b881bbf4b691c31c` |
| Host result | `e4b62cbd35411fb9f7ac9e6e847a62cc3a885365d7e561c731a20e409015c235` |
| Native report | `d8f0c81d24b53e913c3f157f53e5f13e7a660e73cae0728f007f49a8d8e0ade7` |
| Comparison | `a048301db84ed790772be0c73c74ef5a3f7dadcaf2fbc02c5d98bda78b3633f0` |

The initial array run remains in `file-handles-20261024T150004912Z` with native
SHA-256 `17ba2460d478f43474c929f6efab8a30d9c84bf44538ee1417d7d265119ac30b`.
Its checkpoint is `bfd2724f-68c2-4f59-897c-a73fd6320a3b`. The final compact run's
checkpoint is `85dbe56e-0b6f-4f32-9bbb-c86d05499aac`, named
`ntfs-stream-attestation-1e280bfbc06443ddb0cbd0c4cf138b57`. The VM was cleanly
stopped and restored to installed-clean, off at 4 GiB.

Retained snapshots reached the original 192 GiB lab budget. The configuration
now allows 196 GiB while retaining the independent 64 GiB host free-space
reserve. No existing disk image or checkpoint was deleted.

Twenty-eight new tests cover stream/retrieval decoding, ownership, sparse and
resident semantics, native-base units, bitmap corruption, partial responses and
report encoding. The workspace passes 340 tests with five ignored, plus clippy
and formatting; all 19 lab guard tests also pass. This describes the verified
stream milestone, preceding [native logical-data verification](native-ntfs-logical-data.md).
Complete native namespace reconciliation, source freeze/admission and the
existing-tree conversion path remain open. General conversion remains gated.

Microsoft contracts: [FILE_STREAM_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info),
[retrieval pointers](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers),
[retrieval base](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointer_base).
