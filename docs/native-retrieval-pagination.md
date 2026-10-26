# Complete retrieval-pointer pagination

Live NTFS stream observations and ReFS shadow mapping observations now share
`n2r_win32::retrieval_paging`. Each native response retains the existing maximum
of 1,024 extents. An explicitly assembled complete map has a separate maximum
of 65,536 extents, with at most 128 native calls and a total returned-byte budget.
Adjacent identical physical mappings or holes coalesce in the canonical map.
The existing 8 MiB aggregate file/stream evidence budget still applies; collection
also stops a file's stream pass when its retained page evidence exceeds that bound.

Continuation uses the previous response's final **NextVcn**, not an LCN or an
inferred logical EOF. Microsoft documents that the returned starting VCN may
round down to an extent's beginning. The assembler accepts that overlap only
when each logical position still resolves to the same adjusted physical mapping
or hole. See [RETRIEVAL_POINTERS_BUFFER](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointers_buffer)
and [FSCTL_GET_RETRIEVAL_POINTERS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers).

The collector preserves every raw source query and response, including native
errors. Schema 7 replays them through the shared assembler; schemas 2–6 reject
nonempty retrieval continuations. Bitmap pagination retains its existing schema-6
rules. Namespace, source identity, allocation reconciliation, logical content,
physical retrieval-base adjustment and exact before/after transcripts remain
required. Unsupported encodings and unassembled NTFS attribute lists still fail.
This does not establish support for highly fragmented NTFS attribute-list files.
The later [bounded ordinary DATA assembler](ntfs-attribute-list-assembly.md)
connects supported list segments to this same native mapping comparison;
it retains the source profile's run bounds and needs its own native qualification.

The legacy `parse_retrieval` decoder still accepts only one complete, zero-VCN
mapping with at most 1,024 extents. The new `parse_complete_retrieval` decoder is
used for digest-bound assembled maps. Shadow object and retention-attempt reports
name `assembled-zero-vcn-retrieval-v1` and retain separate original page headers,
status, lengths and digests. The canonical digest is not labeled a raw response
digest. Placement rejects missing/inconsistent assembly evidence for larger maps;
legacy maps without assembly proof retain the original bound.

Malformed counts, negative VCNs, LCNs below -1, gaps, nonprogress, changed overlap,
wrong query addresses, incomplete chains, unsupported errors, exhausted budgets
and additional pages after completion are refusals. A failed push poisons the
assembler. EOF error 38 never completes a partial mapping. NTFS resident streams
still require exact EOF38 with no data or continuation. The shadow's existing
successful zero-count empty-file form and eligible small resident form remain
separate; neither becomes a truncated mapping success.

Retrieval pointers describe allocation, not storage initialization or VDL. The
collector does not trim preallocation to logical EOF. Existing region/VDL, logical
hash, EOF and allocation-size checks are unchanged. Source sparse LCN -1 stays
distinct from physical LCN zero; shadow holes remain refused by the current
ordinary conversion profile. Geometry, file/tree byte bounds, retention
attempt-count/move scopes, supported-feature policy, journal limits and recovery
barriers remain. A new 8 MiB cumulative retention-evidence budget counts both
canonical-map capacities and nested page-proof storage. An attempt must fit
before a move is submitted and after its actual mapping is measured; no map is
truncated or partial retention result published when that budget is exhausted.

Pure tests cover 65,536 fragments across 64 pages, overlap with different extent
segmentation, holes, malformed/refused responses, quotas, legacy schemas, source
reconciliation and target assembly proofs using small in-memory records. No
guest volume, formatting, import or conversion is part of those checks. Native
retrieval-pagination qualification remains a separate lab gate.
