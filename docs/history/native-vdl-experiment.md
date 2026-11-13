# Measuring allocation while valid-data length is zero

The next experiment uses one new ordinary 64 KiB file on the owned disposable ReFS target. Sixteen 4 KiB clusters suffice to test API acceptance and exact valid-data state; they cannot establish conversion-scale cost. A 65 KiB file requires seventeen clusters and exceeds this cap. Current implementation scope is only measurement of a known initialized control and separately gated allocation/EOF changes. No move with VDL zero, valid-data advancement or privilege change is authorized in these stages.

## Measure VDL directly

`FILE_STANDARD_INFO` reports allocation and EOF, not valid-data length. Stream enumeration also lacks VDL. `FILE_VALID_DATA_LENGTH_INFORMATION` is documented as set-information input, not a supported `NtQueryInformationFile` query class. An unsupported field returning zero is not evidence of zero VDL. [Standard information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info), [VDL set structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_valid_data_length_information), [query classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile)

Use `FSCTL_QUERY_FILE_REGIONS` separately for usage 1 (cached valid data) and usage 2 (on-disk valid data), offset zero, length 65,536. The installed SDK confirms code `0x00090284`, a 24-byte input, and a 16-byte output header followed by 24-byte entries. Retain exact ABI bytes, errors and responses. Require complete counts and exact bounded interval coverage; derive a scalar VDL only from a valid prefix followed by an invalid suffix. Valid islands, missing regions, unknown bits or partial responses are unresolved. Zero entries do not establish VDL zero. Preserve alignment-related usage bits without interpreting them as validity. [Input](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_input), [region meanings](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info), [output](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_output)

## Current two-stage probe

1. Query the preserved initialized 64 KiB control, bound to placement evidence, original enrollment, GPT/volume, native driver, file identity and known hash. Its EOF/allocation and both valid-data boundaries must equal 65,536. Acquire evidence twice under a pinned read handle. Unsupported or ambiguous native results stop advancement.
2. Require a hash-bound qualified stage-one record. Create one new uniquely named directory/file with a protected ACL restricted to the current lab administrator, Administrators and SYSTEM. Request `FileAllocationInfo = 65536`, then `FileEndOfFileInfo = 65536`; perform no payload read or write. Measure standard information, retrieval mappings and both region variants immediately, after flush and after close/reopen. Require EOF 65,536, bounded sixteen-cluster mappings and both VDLs zero. Native writes caused by allocation, EOF changes, flush or close remain possible. [Set information classes and ReFS support](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle), [allocation structure](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_allocation_info)

The successful initialized control moved from LCN 1508352 to 1508384. Its old source may become a known-content future destination only if both current bitmap variants report it free and a separately reviewed exclusive raw read still matches the known probe pattern. Discard/TRIM and intervening allocation can invalidate it. Stage two may itself consume that range; record that possibility without assuming residual data survives. No arbitrary raw canary writes or reads of unrelated free-space contents belong to this experiment.

## Future separately gated operations

After raw attribution is established again following allocation, one future `FSCTL_MOVE_FILE` can test the VDL-zero file at the known destination. Record exact mappings and cached/on-disk VDL before and after, then obtain an exclusive raw destination observation. Stop on changed VDL or unknown data. Preserved nonzero bytes support content preservation for that sample, not absence of all I/O. [Move contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file)

Only a later attributed-data phase may call `SetFileValidData`. It needs `SeManageVolumePrivilege` enabled on the current guest process before opening the exact file with write access, saved/restored prior privilege state, a private ACL and no exposure of unknown contents. It must not read logical payload until all exposed bytes are attributable. The API expressly supports ReFS. Its parameter text says below EOF while its remarks and the WDK structure allow equality; an EOF-equal call should be recorded as an acceptance measurement, never silently enlarged or retried. [SetFileValidData](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilevaliddata), [privilege restoration](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)

## What establishes effective writes

Logical zeros can be synthesized for invalid data. Raw zeros can result from initialization, discard or copied zeros. Even unchanged nonzero bytes do not exclude rewriting identical bytes. Thus content checks alone never establish payload-write avoidance.

Record process I/O counters as supporting accounting, with their scope explicit: they do not enumerate every filesystem worker, delayed flush or lower-layer write. VHDX growth measures container allocation, not payload traffic. [Process counters](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessiocounters)

A stronger later measurement requires a separately reviewed, bounded guest disk-I/O trace spanning allocation, movement, valid-data advancement, flush, close and relevant remount intervals. Bind disk number and partition offset to enrollment, then examine all writes intersecting the source/destination payload ranges by byte offset and transfer size. Include system/background workers; filtering only by initiating PID can hide filesystem work. Require an initialized-move positive control and idle control. [Disk event fields](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1)

Record event and buffer loss. Lost events, missing intervals, unsupported offload/discard attribution or failed controls leave no-copy unqualified. Trace collection has its own reviewed lifecycle and privileges; these stages do not enable it. Even a complete trace is an observation at that guest storage layer, not a claim about all physical-media writes. [Trace flags and loss statistics](https://learn.microsoft.com/en-us/windows/desktop/ETW/event-trace-properties)

Successful tiny stages must be followed by a separately bounded size series before claiming payload-independent I/O or scratch growth. No metadata-transplant, conversion, recovery or boot gate is satisfied by these experiments.

## Implemented guest interface

`Invoke-GuestVdlProbe.ps1` takes `Phase` (`MeasureInitializedControl` or `AllocateZeroVdl`), `PlacementProbeId`, `PlacementEvidenceSha256` and a new `MeasurementId`. Allocation additionally requires `ControlEvidenceSha256`, the SHA-256 of the qualified first stage's `control.json`. The script and helper hashes must match those recorded by the control; a code change invalidates that qualification. It repeats the initialized control before allocation. The original native control/driver/placement identities are pinned to the reviewed case.

Dependencies are `GuestLab.psm1`, `Capture-GuestAllocation.ps1` and `NativeVdlProbe.cs`. Output is a new `C:\ntfs2refs\vdl-probe\<MeasurementId>\control` or `allocation` directory. The allocated file has the fixed path `F:\fixtures\vdl-<MeasurementId>\uninitialized.bin`. Existing directories/files are never reused or removed.

The control directory allows eleven files: `control.json`, `original-before.json`, `original-after.json`, and up to eight buffers named `control-{before|after}{Standard|Cached|OnDisk|Extents}.bin`. The allocation directory allows twenty-six files: `allocation.json`, `started.json`, both original observation JSON files, the eight repeated control buffers, `allocation-emptyStandard.bin`, `allocation-allocatedStandard.bin`, and twelve `allocation-{immediate|flushed|reopened}{Standard|Cached|OnDisk|Extents}.bin` buffers. JSON is bounded to 1 MiB, standard buffers to 24 bytes, region buffers to 400 bytes, and extent buffers to 272 bytes. The host additionally caps each export at 4 MiB plus 16 KiB. Zero-byte responses have no buffer file.

Statuses are `initialized-vdl-control-qualified`, `initialized-vdl-control-unresolved`, `allocation-zero-vdl-observed`, `allocated-vdl-state-unresolved`, `original-fixture-check-failed` or `blocked`. Only the qualified first-stage status allows allocation. A blocked or unresolved second-stage result can still contain an allocated file. Durable intent is written before native creation; transport uncertainty requires preserving the branch. No cleanup, reboot, remount, raw capture or privilege changes are performed by this guest script.

The helper obtains standard information, cached/on-disk valid regions and retrieval mappings. It creates protected ACLs through ordinary create calls and verifies owner, principals, full-control masks and protection on the opened handles. It hashes only the previously initialized control. No payload read/hash/write path exists in its allocation method. After the initial-state revision below, `lab/Test-GuestVdlProbe.ps1` passes 96 ordinary pure parser, ACL, evidence-gate and WhatIf checks, or 98 with `-PlacementDirectory` to validate saved placement evidence, in Windows PowerShell 5 and PowerShell 7. No native controls or VM actions run in those tests.

## First native result and initial-state revision

The run at `.lab/hyperv/vdl-probe/win11-20261024T003543704Z` qualified the initialized control: cached and on-disk region observations each covered the full 65,536-byte file, with unchanged identity, content and mapping. The allocation stage created the private directory and empty file and verified their ACLs, then stopped at its first standard-information observation. Neither `FileAllocationInfo` nor `FileEndOfFileInfo` was called.

The exact 24 native bytes were `000400000000000000000000000000000100000000000000`, SHA-256 `ffe7da604bdfd21ce08b4a825daba335858c833f0ba16ce56f16b0deaf646fa1`. They report allocation size 1,024 bytes, EOF zero, one link, no deletion pending and no directory flag. This is an observed API value; it does not establish a resident-data format or any physical storage interpretation.

`ParseInitialStandard` now accepts only allocation zero or 1,024 with EOF zero and the same ordinary-file link/type checks. It is used solely for the first observation of the newly created empty file. The normal parser retains cluster alignment and all bounds; the reservation step still requires allocation exactly 65,536 with EOF zero, and later qualification still requires EOF/allocation exactly 65,536 plus sixteen-cluster mappings and both zero VDLs. Regression tests include the exact native buffer, rejection of other initial sizes/nonzero EOF, and rejection of the 1,024-byte case by the normal parser.

The first outcome remains preserved as checkpoint `fd550b2c-f521-4fcf-bd67-8c817985f15c`, named `vdl-probe-data-1cfe7313f5ed4f94be3c22c59c75fe54`; the host returned to the off-state baseline with 4 GiB RAM. Original result and buffer files were not modified. The five source files recorded by that run were copied and hash-verified under its new `reviewed-sources` directory before editing the helper. The prior helper SHA remains `4fc87ab9e4b095a9421c0aa7f4ca3c95c3ce11def2a7e00afd9eba4d37b9ab27`. The helper revision changes source identity, so stage one must qualify again under the new hash; the old control record cannot authorize allocation with the revised helper.

## Implemented host interface

`scripts/Invoke-LabVdlProbe.ps1` takes bounded `BootTimeoutSeconds` (default 300) and `QueryTimeoutSeconds` (default 180), and supports `-WhatIf`. It restores only checkpoint `4b581541-4899-4f91-adc1-e4e784c7cacf`, named `extent-placement-data-d98ba93b850d4eababa84c445439868a`, from the exact powered-off `installed-clean` baseline at 4 GiB. The saved experimental branch must have fixed 8 GiB RAM, disconnected networking and unchanged Secure Boot. The original three disk roles and target VHD identity, placement/remount evidence hashes, initialized fixture identity/hash/mapping, and helper source hashes are checked before the experiment advances.

The host dispatches measurement first. It exports each bounded artifact to `.lab/hyperv/vdl-probe/win11-<UTC>/control`, verifies length and SHA-256, and validates query ABI, buffer provenance and initialized-control observations. Only the matching qualified record unlocks a separate allocation dispatch in the same guest session. The allocation dispatch receives the exported `control.json` hash; the guest verifies that hash and repeats the initialized control. Stage-two evidence is separately exported to `allocation` before any shutdown or checkpoint action.

`host-result.json` is persisted at stage boundaries and records allocation intent before dispatch. Actual target-write and file/directory-creation outcomes remain null until the returned native observation is validated. A timeout, transport failure, missing completion evidence, changed fixture, or failed export preserves the branch. A completed blocked query with unchanged original fixtures can be exported and followed by clean shutdown. Any definite target-write attempt, including directory-only creation, requires a new powered-off `vdl-probe-data-<MeasurementId>` checkpoint before baseline restoration. The successful cleanup path restores the exact baseline and fixed 4 GiB RAM. No forced VM/job stop, raw volume access, movement, valid-data advancement, privilege change or trace collection is included.

`lab/Test-LabVdlProbe.ps1` passes 140 checks in Windows PowerShell 5 and PowerShell 7. These exercise malformed and mismatched evidence, qualification gates, native buffer bounds/provenance, changed fixture state, nullable allocation outcomes, checkpoint requirements, mocked transport failures and `-WhatIf`. They read the pinned local lab evidence but execute no VM actions or native filesystem controls. Review and tests establish orchestration behavior; native VDL support and payload-copy avoidance remain unmeasured until the guest experiment runs, and conversion/boot qualifications remain false.

## Revised allocation and read-only remount results

The revised allocation run at
`.lab/hyperv/vdl-probe/win11-20261024T004239424Z` completed at
`2026-10-24T00:43:56.1044758Z`. The initialized API control qualified again.
For new measurement `2780e16cd7bb4d12a5ba8070bac0a1e7`, both
`FileAllocationInfo` and `FileEndOfFileInfo` requests succeeded at 65,536 bytes.
Immediate standard information reported allocation/EOF 65,536, but cached
regions covered the whole file as valid while storage regions reported no
valid bytes. Retrieval pointers returned VCN 0..1 at signed LCN -1 and VCN
1..16 at LCN 1,508,352. The ordinary complete-physical-mapping gate rejected
the negative marker. No explicit flush, move or valid-data call followed.

The outcome was saved off at checkpoint
`209475c5-c949-41aa-8887-997439f0f70e`, named
`vdl-probe-data-2780e16cd7bb4d12a5ba8070bac0a1e7`. Its allocation JSON SHA-256
is `cb484a4a92da8a72861ce4cd7f93ed8bffb1873236cc6c94d4c9efd6861c5fda`;
host JSON SHA-256 is
`ae81d602f7806227a59fd8090215370703912891f506e3a30b2f80a2df416aaa`.
The exact off-state baseline and 4 GiB memory were restored.

A separate metadata-only observer then restored that outcome and completed
at `2026-10-24T01:02:11.5827927Z`. Its case is
`.lab/hyperv/vdl-observation/win11-20261024T010103919Z`, observation ID
`c7e04c38351e407ca0860b760b65b0d6`. Guest status was `metadata-observed`;
both observations were complete/stable, identity/cleanup passed, and original
fixtures were unchanged. Allocation/EOF, attributes 32, both region results
and both signed extent segments persisted across clean shutdown/remount.
Mounted flags `1606825679` (`0x5fc636cf`) include sparse-VDL support. Guest
observation SHA-256 is
`2e76c2bcfe31df3b494dffe0d47a235095c8ea08db58cb87babe01fd8fa148d0`;
host JSON SHA-256 is
`e67dd932bcc92b4a42567332eaf5353d0e5b866deb4f6d931062540dce6e02b9`;
export manifest SHA-256 is
`2aa8bf2b7cb048b237e2ee809310a1e5e2fad5e18673fde471fbb05e3e444efb`.
Clean shutdown and restoration to the exact off-state 4 GiB baseline completed.
See [the observation contract and complete result](native-vdl-observation.md).

This result does not satisfy the original both-zero/full-physical-allocation
profile. The first negative ReFS marker remains unresolved, and the positive
fifteen-cluster segment has consumed most of the earlier freed-source candidate.
No payload was read or hashed from the new file. The observer performed no
allocation, explicit flush, move, valid-data, protection or privilege changes.
All conversion and payload-copy-avoidance qualifications remain false.

## Proposed next per-region experiment (design only)

First wait for the protected raw-pattern observation to establish whether the
known initialized fixture's former source still contains attributable bytes
and whether the reviewed protection/sampling lifecycle works. A result from
the initialized-placement checkpoint cannot establish contents on the separate
VDL outcome branch. Do not transplant its free-space observation or hash as a
current VDL-branch fact.

The next step on the VDL branch should remain read-only: bind the exact saved
file identity and repeat the whole-file controls, then request cached and
storage region information separately for offset 4,096 and length 61,440.
The API accepts an explicit file offset and length. Require complete bounded
coverage of this requested interval; retain exact responses/refusals. Do not
translate or raw-read VCN 0..1, whose native marker is unresolved.
[Region input contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_input)

If the protected sampling mechanism qualifies, a separately reviewed profile
can bind the positive fifteen-cluster segment on this same VDL checkpoint and
sample only its attributable old-control range. At retrieval base zero its
candidate volume-byte interval is `[6178209792, 6178271232)`, length 61,440.
Revalidate base, geometry, mappings, disk protection and both bitmap variants
in that protected epoch; all fifteen mapped clusters must be allocated in
both bitmaps. Protection establishment is a separate device-state mutation,
and its lock/dismount transition can flush native writes. It is not part of
the completed metadata-only observer. Compare to the corresponding first fifteen clusters
of the original uniquely patterned initialized file; do not assume the pattern
survived allocation. A zero/mismatch is a distinct outcome, not evidence of
write avoidance. No unrelated free-space scan or raw canary write is proposed.

A subsequent movement experiment would ask a narrower question: how does
native placement treat this **cached-valid, storage-invalid** positive-LCN
interval? It must not be labeled a both-zero-VDL move. A candidate single call
would use `StartingVcn=1`, `ClusterCount=15`, excluding the unresolved first
cluster. Documented movement granularity is one cluster for a non-sparse,
non-compressed file, versus sixteen for sparse/compressed files. Recheck actual
attributes and treat this ReFS build's acceptance/refusal as a measurement;
never widen or retry the request to encompass the unknown marker. Keep source
and destination displacement aligned to 16 KiB when selecting an attributable
candidate. [Move granularity](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file),
[move fields and alignment](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-move_file_data)

That call is not ready: the VDL outcome currently supplies no independently
qualified free destination with distinct known residual contents. It would
need a separately bounded ordinary initialized-file placement control to
produce such a range, followed by fresh free-bit and protected raw attribution
on the actual experimental branch. Use distinct source/destination patterns
so copying source bytes cannot masquerade as preservation of destination bytes.
Any setup can change allocation/validity, so repeat the region/mapping gates
after setup and immediately before the one move. The native allocator resolves
bitmap staleness; a returned rejection is an outcome, not a reason for retries.

After a future call, retain the whole-file signed map and both validity views,
then re-establish protected sampling before inspecting only the attributed
ranges. Destination bytes equal to its prior pattern, the source pattern or
zeros have different meanings; none alone proves absence of writes. Preserve
the branch on unknown completion, identity changes or contradictory evidence.
Complete guest disk-I/O trace/control work is still needed for an effective
write-avoidance claim. `SetFileValidData` remains deferred: it advances validity
for a file prefix and does not provide a safe way to expose just the fifteen
attributed clusters while the preceding region remains unresolved.

## Separate Rust private-prefix experiment, October 27–28

The earlier fifteen-cluster experiment and its unresolved leading marker remain
preserved. A new experiment used one fresh SYSTEM-only file on the separately
owned streaming-v2 shadow, with EOF/allocation 1,052,672 bytes and an explicit
1,048,576-byte SetFileValidData request. The NTFS source stayed offline/read-only.
The Rust tool made no payload read or write call and restored its temporary
manage-volume privilege. It retained the private file rather than exposing its
unwritten contents or deleting the result.

SetFileValidData succeeded. Before the call, VCN 0..1 had LCN -1 and storage
regions were invalid. After the call and file flush, all 256 prefix clusters
had physical mappings and storage usage 2. The extra 4 KiB tail remained storage
invalid. Initial result SHA-256:
`d3ac78c0abb021dc57c5ccac5d09c7a1f69e004439078f1b52b9f27ee707651e`.

After a clean reboot, a metadata-only observer on the read-only shadow confirmed
the same 24-byte FileIdInfo, EOF, stable standard information, physical prefix
mappings and valid-prefix/invalid-tail regions. It issued no payload read/write,
valid-data call or privilege change. Its result is
`dbbe0e26a4be5ea2b676cca71d7c8975a6322d5650f0be4643076361d35dd3e3`.
The first two reopen observers refused a writable-only volume helper; their
attempts are preserved and do not provide persistence evidence. The successful
observer uses a read-only volume handle and validates its disk extent.

Evidence is under the ignored
`.lab/hyperv/streaming-v2-20261027/candidate5/valid-data-probe` directory.
The oracle is refs.sys `10.0.26100.8875`, SHA-256
`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`,
on Windows build 26300. The initial producer is
`d9bd5df26ebbb9f8be58446497a61dbb256e034e22a695626947b7d5bb1204d1`;
successful observer `f07083a2c6d1c21a9f76a3f4124c7f0fe20ada4e08cebcf8b619e2a3178d1487`.
OFF checkpoints preserve both allocation and reboot observation; no previous
probe or converted branch was deleted.

This establishes a bounded allocation/validity primitive. Physical payload
I/O, persistence of known payload contents, arbitrary-extent adoption, secure
end-to-end no-copy construction and conversion remain separate requirements.
The source was not converted in this experiment. No unit tests ran.
