# Resource-based source and metadata admission

This development path replaces fixture cardinality limits with complete,
page-backed metadata and an explicit RAM/scratch budget. It does not enable a
general conversion path or inherit native qualification from source `7feb4c0`.
The previously qualified native-shadow candidate remains preserved separately.

`ResourceBoundedV4` binds the actual source pin and complete MFT, object and
stream counts to observed resources. Its pre-count state cannot authorize native
construction. The frozen owner accepts an explicit `ResourceBudget` before raw
inspection and retains that exact budget through native observation.

The active source producer streams canonical MFT rows, allocated-record and
extension evidence, directory entries, security records, and physical/logical
allocation ownership. External sorting and authenticated temporary-file
retirement bound working RAM and merge scratch. It returns its opaque owner
only after complete allocated-record, extension, namespace, security and bitmap
conservation checks close. A saved source manifest cannot recreate that owner.

Native request schemas 7/8 stream actual selectors from that source owner.
Report schemas 15/16 retain those selectors alongside complete native rows.
The observer preserves both complete stream maps and directory passes, both
allocation snapshots, protection/route checks, logical EOF or extent evidence,
security views, and source identity. Comparison results are streamed per object.
Recognized NTFS internals retain their individual results and explicit
replacement obligations; diagnostic success grants no conversion certificate.

The new owning-machine integration entry is:

```powershell
lab-observe-resource-source --binding source-binding.json `
  --binding-sha256 <pin> --output C:\independent-scratch\fresh-run `
  --acknowledge-resource-source-freeze --native
```

It freezes the explicitly bound dedicated data disk and leaves it offline and
read-only. It performs no conversion or payload writes. Its default metadata
budget uses half of sampled available RAM and one eighth of sampled scratch
availability; explicit resource shares are checked against the same actual
sample. Allocation and I/O failures remain errors. Fast verification preserves
absent content digests as absent; `--verify-full-content` reads every supported
logical stream. Resource observations reserve no memory or storage.

The paged expected-tree and native constructor interfaces also accept the
resource profile and require actual page ownership. Their source projection,
fresh conversion admission, full public orchestration and recovery integration
must be completed before the public command selects this profile by default.
Legacy schemas, entry points and their historical limits remain available for
existing recovery and qualification evidence.

Geometry and feature support remain explicit: the active raw namespace/security
walker still interprets 512-byte NTFS sectors and 4 KiB index records. Dedicated
GPT basic data disks remain required by whole-disk exclusion; a data partition
on an OS disk needs a partition-scoped exclusion design. Unsupported encodings
are refused. These implementation boundaries are not removed by deleting size
checks. The host lab's original additional-storage allowance remains unchanged.
