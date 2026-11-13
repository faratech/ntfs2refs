# Metadata observation after the VDL allocation outcome

This separate profile observes the saved outcome from
`vdl-probe/win11-20261024T004239424Z`. It does not relax the original probe's
qualification gate. Root owns review and native execution.

The original allocation and EOF requests both succeeded for 65,536 bytes. Its
immediate observation reported cached validity over the entire file, storage
validity over none of it, and two retrieval segments: VCN 0..1 has signed LCN
-1; VCN 1..16 starts at LCN 1,508,352. No explicit flush, move or valid-data
request followed. The file was closed and the guest shut down cleanly before
saving the outcome checkpoint. Native filesystem activity during close/shutdown
may have changed the state; this profile measures the remounted result.

## Exact source

- Measurement: `2780e16cd7bb4d12a5ba8070bac0a1e7`.
- Off-state 8 GiB checkpoint: `209475c5-c949-41aa-8887-997439f0f70e`, named
  `vdl-probe-data-2780e16cd7bb4d12a5ba8070bac0a1e7`.
- File: `F:\fixtures\vdl-2780e16cd7bb4d12a5ba8070bac0a1e7\uninitialized.bin`.
- File ID `0x3000000000002703`; volume serial `0x08425382`.
- Allocation JSON SHA-256:
  `cb484a4a92da8a72861ce4cd7f93ed8bffb1873236cc6c94d4c9efd6861c5fda`.
- Source host JSON SHA-256:
  `ae81d602f7806227a59fd8090215370703912891f506e3a30b2f80a2df416aaa`.
- Allocation export manifest SHA-256:
  `2377a5eb41afcf853fb797883362e4e694d45bc7f85f2b76dc9bd8795e5242ad`.

The host validates all eighteen source export files against that pinned
manifest, the source allocation/EOF success records, and the qualified
initialized control. The guest independently pins the source allocation,
control, placement and Dev Drive proofs. The owned 64 GiB disk / 52 GiB ReFS
partition, GPT identities, Windows build, driver and enrollment guards apply.
Original VDL probe sources and saved evidence remain unchanged.

## Native observation

`NativeVdlObservation.cs` opens pinned parent directories and the exact file
with `READ_CONTROL | FILE_READ_ATTRIBUTES` (`0x00020080`), `OPEN_EXISTING` and
reparse checks. The file has no sharing. Its protected ACL, owner, three
principals, final path, file ID, serial, length and link count are checked. The
helper contains no payload read/hash, setter, flush, movement, privilege or
volume-control entry point. If metadata-only access cannot issue a query on
this build, its returned refusal is evidence; no stronger-access retry occurs.

Two observations use the same file handle. Each records standard information,
cached regions, storage regions and signed retrieval pointers. Region requests
cover exactly 65,536 bytes, with at most sixteen returned entries.
`GetVolumeInformationW` records returned flags, including
`FILE_SUPPORTS_SPARSE_VDL` and `FILE_READ_ONLY_VOLUME`; neither must be true.
No disk protection or allocation changes are requested.

Microsoft defines cached validity using cache-manager VDL and noncached
validity using storage-device VDL. Its volume flags document that sparse VDL
can track validity per cluster without storing one scalar VDL or requiring
contiguous valid data. The helper retains every region. `prefixBytes` is a
summary only when complete coverage is prefix-shaped. A validity island keeps
its regions, `prefixShaped=false` and `prefixBytes=-1`. Missing or malformed
coverage never implies zero validity.
[Region semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info),
[volume flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)

Negative signed LCNs are retained verbatim as unresolved ReFS markers. They
are never converted into physical addresses. Microsoft's -1 interpretation
is explicitly scoped to NTFS; this observation does not extend it to ReFS.
Positive values remain native LCNs without a new physical-equivalence claim.
[Retrieval pointers](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointers_buffer)

`observationComplete` means both bounded observations were parsed. It does not
qualify zero VDL, complete physical allocation, adoption or conversion.
`stableDuringObservation` additionally compares all eight raw buffers, volume
flags and all file identity fields, including attributes. Original 4 MiB and
initialized 64 KiB fixtures are hashed/mapped before and after. The new file's
payload is never accessed. Automatic operating-system activity during boot,
close and shutdown is not a claim of a write-free storage stack.

## Artifact and lifecycle contract

Guest entry point:

```powershell
& C:\ntfs2refs\guest\Capture-GuestVdlObservation.ps1 -ObservationId <new-32-lowercase-hex>
```

Dependencies: `GuestLab.psm1`, `Capture-GuestAllocation.ps1`, and the new native
helper. Evidence is created under `C:\ntfs2refs\vdl-observation\<id>`.
Allowlist: `observation.json`, `original-before.json`, `original-after.json`
(each at most 1 MiB), and optional
`{before,after}{Standard,Cached,OnDisk,Extents}.bin` (respectively 24, 400, 400,
272 bytes maximum). Maximum eleven files and 3 MiB + 2,192 bytes. Native errors
and partial buffers are retained. The host checks exact query inputs/codes,
artifact paths/lengths/hashes and parsed metadata against exported native bytes.

`scripts/Invoke-LabVdlObservation.ps1` starts only from installed-clean off at
fixed 4 GiB, with disconnected networking, Secure Boot and three owned disk
chains. It restores the exact saved outcome at 8 GiB, archives/hash-verifies
sources, invokes the guest through a bounded PowerShell Direct job, and exports
to `.lab/hyperv/vdl-observation/win11-UTC`. It does not mount disks on the host.

`metadata-observed` or `native-query-unresolved` can proceed to clean shutdown
and baseline restoration only after validated export, verified file identity,
unchanged original controls and successful handle cleanup. Transport uncertainty,
identity change, cleanup failure, native/preflight exception or export
contradiction preserves the branch. Failure handling never shuts down, stops
the job, restores a checkpoint or changes memory. Success returns to the exact
off-state 4 GiB baseline, leaving the source checkpoint intact.

## Validation and source freeze

Pure parsers, fake native lifecycle, guard mutations, query refusals, identity
attribute changes, cleanup failures, saved source artifacts and ordinary temp
files are tested. No native device or VM calls are made by tests. `-WhatIf`
returns before dispatching guest operations.

- Guest tests: 76 ordinary checks; 84 with the saved source directory.
- Host tests: 95 ordinary checks; 106 with the saved source directory.
- Saved-source suites pass Windows PowerShell 5 and PowerShell 7. The host
  explicitly normalizes JSON-array enumeration for the PS5 pipeline behavior.

Frozen runtime source hashes:

- Native helper: `01e02275f5af48284b87523376c1a4a4cdb07519eaa65029bafb4d8f6b19c48a`.
- Guest script: `a3e2ddf074a9100f95295082fc01834a84f364212779794d23d96349f64dcb06`.
- Host script: `8012aa4010baf78c8a510f98133f3a69b0e45f208d53b96199adbd8178e999c1`.

## Native outcome, 2026-10-24

The reviewed run completed at `2026-10-24T01:02:11.5827927Z`, exported under
`.lab/hyperv/vdl-observation/win11-20261024T010103919Z`, observation ID
`c7e04c38351e407ca0860b760b65b0d6`. The host status is
`native-vdl-observation-exported`; the guest status is `metadata-observed`.
Both observations completed and were stable, identity and handle cleanup
checks passed, and the original initialized fixtures were unchanged. The
guest shut down cleanly and the exact baseline was restored off at 4 GiB.

Evidence SHA-256 values:

- `host-result.json`:
  `e67dd932bcc92b4a42567332eaf5353d0e5b866deb4f6d931062540dce6e02b9`.
- `guest/observation.json`:
  `2e76c2bcfe31df3b494dffe0d47a235095c8ea08db58cb87babe01fd8fa148d0`.
- `guest/exported-files.json`:
  `2aa8bf2b7cb048b237e2ee809310a1e5e2fad5e18673fde471fbb05e3e444efb`.

Both mounted-volume observations returned flags `1606825679`
(`0x5fc636cf`), including `FILE_SUPPORTS_SPARSE_VDL`; the read-only-volume
flag was false. Both file observations reported allocation and EOF of
65,536 bytes, attributes 32, one link and the same file/volume identities.

| File interval | Cached usage | Storage usage | Native retrieval mapping |
| --- | --- | --- | --- |
| 0..4,096 | 1 (part of the full-file cached region) | 0 | VCN 0..1, signed LCN -1, unresolved |
| 4,096..65,536 | 1 (same cached region) | 0 | VCN 1..16, LCN 1,508,352, 15 clusters |

The storage response retained two invalid regions at that boundary. Derived
prefix summaries were cached 65,536 and storage zero, exactly as before
shutdown. This demonstrates persistence of the observed region/mapping state
across the clean remount; it does not establish that both valid-data states
are zero or that all sixteen clusters have known physical addresses. The
metadata-only request restrictions were preserved. No new-file payload read,
payload hash, allocation, flush, move, valid-data advancement, protection change
or privilege change occurred in this observer. Zero-VDL, physical mapping,
payload-copy avoidance and conversion qualifications remain false.
