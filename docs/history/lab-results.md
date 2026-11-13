# Measured laboratory results

Recorded 2026-10-23. These results qualify the research harness and limited
read-only observations. No filesystem conversion or ReFS writer is qualified.

## Windows 11 profile

The isolated Generation 2 Hyper-V VM runs Windows 11 Pro 26300.9457 from the
hashed index-6 ISO. Secure Boot and vTPM remain enabled, the NIC is disconnected,
and the VM has four CPUs and 4 GiB RAM. Disk geometry is 512-byte logical and
4096-byte physical sectors. The observed ReFS driver is 10.0.26100.8875; its hash
and the formatter component hashes are retained with each experiment.

The stock NTFS OS booted, passed its native filesystem scan, and reported WinRE
enabled. Powered-off checkpoints and an independently exported, hashed baseline
were created. Checkpoint restoration has been exercised repeatedly. WinRE
entry/exit, servicing, ReFS boot and converted OS boot have not passed qualification.

## Native NTFS corpus

Run `win11-20261023T213403542Z` created an ordinary 1 GiB NTFS partition with 4 KiB
clusters, captured it empty and after the complete fixture batch, and exported
all eight artifacts with verified hashes. The guest shut down cleanly and the
installed baseline was restored.

| Image | SHA-256 |
|---|---|
| `empty.raw` | `ff992d648653a2730b1944ee1f0c2cc2a9e6de31a86089c87849b9ffb74c9278` |
| `control.raw` | `86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727` |

The release Rust reader inspected both images and verified their byte identity.
All nine captured path/stream observations matched Windows' native hashes:
empty, small resident, Unicode, 16 MiB nonresident, alternate streams, hard-link
aliases, 16 MiB sparse data and `acl.txt` contents. These represent seven unique
identity/stream pairs across six regular file identities. The symlink's reparse
payload was excluded; content agreement does not validate ACL or link semantics.

Both image diffs found 16,775,221 changed bytes. The 512-byte view has 33,228
changed blocks in 17 ranges; the 4 KiB view has 4,160 changed blocks in 15 ranges.
Neither range list was truncated. This is a fixture-batch comparison, so changes
cannot be attributed to individual operations.

The native volume-information subprocess returned error 3 because its quoted
root argument ended with a slash. This failure remains in the evidence and
`nativeEnumerationSucceeded` remains false. The comparison used structured
`Get-Volume` filesystem evidence and a capture sidecar bound to the image hash,
size, geometry and target identity. Future calls use a drive designator. The
current source retains its own script hash in new evidence records.

Both images have `dirty=false`, but volume flags `0x0080` remain a conversion
blocker pending native interpretation. Unsupported attributes, security/index
reconciliation, allocation ownership, log state and backup consistency remain
unqualified. The special unflagged `$BadClus:$Bad` stream is explicitly unsupported
for logical hashing; its raw flags and extents are retained.

Artifacts and the detailed comparison are under:

`../.lab/hyperv/corpus/win11-20261023T213403542Z/ntfs/analysis-20261023T214015406Z/`

Use `analysis-summary-utf8.json`; an earlier summary was superseded because of
PowerShell 5's default text decoding. The underlying comparison is unchanged.

An earlier partial fixture run, `win11-20261023T211635519Z`, is also retained.
Its alternate-stream creation failed and recursive export hit the installed
PowerShell 5 directory `Length` defect. The recovery helper exported and verified
both images before restoring baseline. All four streams present in that partial
fixture matched. The corrected exporter copies allowlisted files individually.

## Ordinary ReFS formatting

| Environment and operation | Result |
|---|---|
| Windows 11 Pro 26300.9457, `Format-Volume`, 1 GiB data partition, 4 KiB clusters | Refused: specified filesystem not supported |
| Same guest and formatter, 66,238,545,920-byte OS partition, 4 KiB clusters | Same refusal before image deployment |
| Same guest, stock `format.com`, 66,238,545,920-byte partition, ordinary ReFS 4 KiB request | Refused with exit 4: ReFS filesystem not supported on this device |

The large-partition refusal shows that the small fixture alone was not the
only failing configuration. These are formatter results, not failed ReFS boots:
no ReFS OS boot was attempted. The OS-preparation evidence is under
`../.lab/hyperv/refs-boot/win11-20261023T214143830Z/`.

The `format.com` result is retained in
`../.lab/hyperv/refs-boot/win11-20261023T225527573Z/`. The exact invocation was
`format.com G: /FS:ReFS /A:4096 /Q /V:N2R_REFSOS /Y`; DiskPart's preceding
read-only `filesystems` query listed only NTFS as supported for formatting.
Evidence export and baseline restoration passed. This is a second formatter
refusal, not a boot failure or a universal Windows 11 compatibility conclusion.

The preceding attempt `win11-20261023T225236696Z` stopped before partitioning
because the process wrapper quoted every argument. A local read-only reproduction
showed `format.com "/?"` exits 4 whereas `format.com /?` succeeds. The wrapper
now quotes only arguments requiring it; actual format help and ten bounded
process checks passed before the successful command invocation above.

The ordinary-format tests do not test Dev Drive. The supplied ISO's boot.wim
reports Windows PE/Setup 10.0.26100.9457; a same-media PE formatter would be a
separate recorded environment from the installed Pro OS. Server media remains
deferred at the user's request.

## Native ReFS Dev Drive data control

Run `win11-20261023T230635404Z` successfully formatted the guest's disposable
target as a 52 GiB Dev Drive using its native `Format-Volume -DevDrive`, with
4 KiB clusters and temporary 8 GiB VM memory. Windows reported ReFS 3.14,
metadata checksum type CRC64 and data checksum type NONE. The default trusted
Dev Drive retained the antivirus filter; no trust, filter or policy settings
were changed. This is a separate profile from ordinary ReFS formatting.

Both fixtures retained identical SHA-256 values across a clean guest shutdown
and reboot:

| Fixture | Logical bytes | SHA-256 |
|---|---:|---|
| `nonresident.bin` | 4,194,304 | `ecbf557fb4d10cb9a59eb55645e2e154ff42e6f37cb7ca5a60eed2da1de0539d` |
| `small.txt` | 61 | `060769a53319045a7aedad5277e4d5118695f2e62aa626100682a686ea143ca2` |

The allocation collector completed before and after reboot with no failures.
The large fixture returned one extent: VCN 0 through 1024, LCN 1507328. The
small fixture returned no nonresident mapping (native error 38); that observation
alone does not establish its metadata representation. The completed raw capture
subsequently confirmed the large fixture's single extent, as described below.

The partition begins at guest disk byte 16,777,216, is 55,834,574,848 bytes long,
and has GUID `00c9f113-e0b9-49d8-b031-130aef8ef3fb`. Verified native exports are
under `../.lab/hyperv/devdrive/win11-20261023T230635404Z/`. The after-reboot
`verify.json` SHA-256 is
`ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1`.

The powered-off checkpoint `devdrive-data-20261023T230635404Z`
(`2aa127e2-c875-4ca0-8629-dab784136448`) preserves the native control. All
evidence exports passed verification, and the VM was restored to installed-clean,
powered off, with its original 4 GiB RAM. This verifies the small data fixture's
format/remount behavior, not filesystem conversion or ReFS OS boot.

## Completed native ReFS corpus and reader validation

Corpus `devdrive-20261023T231918797Z` completed extraction from the saved,
powered-off Dev Drive checkpoint. All three source-chain files retained their
before/after hashes. The host did not mount the filesystem or change the VM.
The fixed VHD supplied the full 52 GiB partition range; the extractor verified
its source before/after and the output readback hash. The release reader then
independently reported the same full raw-image hash.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Fixed VHD transport copy | 68,719,477,248 | `b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7` |
| Complete `devdrive.raw` | 55,834,574,848 | `805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9` |

The fixed VHD reports 512-byte physical sectors, while the native guest reports
4096; it was never mounted or reformatted. Its container ID differs from the
original target VHD ID. The extractor does not independently authenticate GPT or
guest identity: selection is bound to the exact native `verify.json` hash and
host ownership/checkpoint evidence.

`analysis-20261023T233638844Z/inspection.json` reports matching ReFS 3.14
primary/backup headers and recognition checksum. The bounded candidate parser
matched CRC32-C self-checksums for three superblocks and both referenced
checkpoints (LCNs 136348 and 1635808), each with 13 root descriptors. Root indices
7, 8 and 12 resolve to three shared physical pages; all six references matched
CRC64/NVME, headers and candidate table IDs 11, 12 and 34. No authoritative
checkpoint was selected, and no child trees or general virtual-to-physical
translation were traversed. Complete metadata, allocation/refcount ownership
and filesystem health remain unqualified.

A new [evidence validation record](../../.lab/hyperv/corpus/devdrive-20261023T231918797Z/analysis-20261023T233638844Z/evidence-validation.json)
links the completed capture, reader and native evidence. It compared all 36
provisional bootstrap range entries with the completed raw image and reread
the 4 MiB payload sample, using 4,289,024 raw-image bytes total. It did not rehash
the full image or read the fixed VHD. Original provisional records remain
unchanged. The new record's SHA-256 is
`288292d38cb2684bbf59d9275a3add31871a85193a03a1978bd6f1629959a30a`.

For this one file, native LCN 1507328 times 4096 equals partition byte offset
6,174,015,488. The raw 4 MiB range matches the native logical SHA-256
`ecbf557fb4d10cb9a59eb55645e2e154ff42e6f37cb7ca5a60eed2da1de0539d`,
including its unique first-cluster marker. This validates that sampled extent's
address, not a universal address translation or an extent-adoption operation.

## Native retrieval-base and bitmap discovery

Run `extent-discovery/win11-20261023T234407044Z` restored the exact saved data
checkpoint and issued read queries against its target. Both retrieval-base
queries returned zero sectors. Fixture identity, mapping and logical hash
remained identical to the captured control before and after discovery. The new
validation record reconciles its proposed offset with the raw payload match;
the original guest report retains its awaiting-offline-match status.

The legacy before/after bitmaps were byte-identical. Extended input was accepted
with both flag values; counts cover only the declared 13,631,488 bits.

| Native bitmap request | Occupied clusters |
|---|---:|
| Legacy, before and after | 328,928 |
| Extended input, flags 0 | 328,928 |
| Extended input, metadata flag 1 | 1,508,360 |

The flag changes 1,179,432 declared bits. Each returned buffer is 2 MiB, with
393,200 bytes beyond the declared bitmap retained and excluded from allocation
counts. Sample bits corresponding to known superblocks, checkpoints and payload
were occupied in all four observations. This does not establish that every
metadata/reserved region is represented or that subtracting file extents yields
a complete metadata copy set.

All nine allowlisted artifacts passed export verification. The guest shut down
cleanly and the host restored installed-clean with its original 4 GiB RAM.
No movement, valid-data advancement, raw target writes, native extent adoption
or conversion occurred. Native reads may still cause filesystem access metadata
updates. Full metadata coverage, arbitrary placement and payload-copy avoidance
remain unqualified; boot work is deferred.

## Native initialized-file placement and clean remount

Run `extent-placement/win11-20261024T000401422Z` completed at
2026-10-24 00:06:09 UTC. Inside the guest, one new 65,536-byte file was fully
initialized and flushed. A single `FSCTL_MOVE_FILE` returned success with native
error zero. Its one 16-cluster extent moved from LCN 1508352 to requested LCN
1508384. File identity stayed `0x3000000000002702`; its SHA-256 remained
`9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78`.

After clean shutdown/reboot, the independent read-only collector returned the
same new-file identity, complete mapping and hash. The original 4 MiB fixture's
identity, LCN 1507328 and SHA-256 also remained unchanged. Exact GPT identities,
52 GiB geometry, 4 KiB clusters and native ReFS driver provenance matched.

| Retained artifact | SHA-256 |
|---|---|
| `host-result.json` | `125f812543ef56ea5d81f641797b1ac2d8b52b1f16d8f17d1ac03a726684d982` |
| `guest/placement.json` | `865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5` |
| `remount/identity.json` | `fe287b5536c1de6c816d4d4ba43e7d5fe9026361a8b91687279c770b5efb4414` |
| `remount/allocation-remount.json` | `9d7b537e885cde3c7b67c1a830dd2dfff27ccf4232d445e46baa4a3499002cbe` |

The second clean shutdown was followed by saved outcome checkpoint
`extent-placement-data-d98ba93b850d4eababa84c445439868a`, ID
`4b581541-4899-4f91-adc1-e4e784c7cacf`. The host then restored installed-clean,
off with 4 GiB RAM. Original placement and remount records remain distinct.
The reviewed host wrapper passed 222 guard/mock checks in PowerShell 5 and 7;
the guest probe passed 82.

This establishes one initialized-file native placement and its clean-remount
survival on this ReFS 3.14 Dev Drive. The file was deliberately initialized;
the experiment does not establish absence of payload copying, zero-VDL behavior,
arbitrary extent adoption or conversion. With retrieval base zero, the new and
old range offsets would be 6,178,340,864 and 6,178,209,792. Their raw bytes and
the old range's current free state have not yet been checked. See the
[bounded range-read design](native-range-read-design.md).

## Verification limits

At completed-corpus reader validation, 87 Rust tests, formatting and Clippy
passed. PowerShell
guard, process, alignment and comparison tests exercise individual failure paths;
their synthetic outcomes are separate from the native measurements above.

The recovery model is memory-only. Conversion, resume, rollback and finalize
writes remain unavailable. Complete native ReFS metadata and allocation/commit
ordering remain outstanding; boot work is deferred. See [qualification gates](format-gates.md)
and the [native allocation feasibility study](native-allocation-feasibility.md).

Normal UAC helpers provided host management access. No host account group,
application-control policy or Secure Boot policy was changed. Source amendments
made before later guest stages of `RecoverNativeResearch` are recorded in its
`source-update-before/after.json` companions; retain those alongside the helper's
start-time hashes and the executing guest-script hashes.

The user subsequently relaunched the agent with an elevated administrator token;
direct `Get-VM` calls and the reviewed helpers now work without another UAC launch.

## Locked-volume query result

The guest range-read run `range-read/win11-20261024T003149738Z` completed with
`native-query-refused`. The address-base and disk-extent queries succeeded before
locking. `FSCTL_LOCK_VOLUME` succeeded, but the next address-base query returned
Win32 error 21 (`ERROR_NOT_READY`). No raw range was read. Unlock and handle close
succeeded, and both original fixture hashes/mappings remained unchanged.

All returned evidence was exported before clean shutdown and baseline restoration
at 4 GiB. `guest/range.json` SHA-256 is
`7ce2fe1c0cb922ff9cd169945b0d2b5404992e396704c88a23abcebf9b197d4e`.
The three executing scripts/helpers are preserved under the case's `sources`
directory. This establishes a limitation of the locked-query protocol on the
measured driver; it does not establish that raw reads themselves are unsupported.

## Initial valid-data measurement

The first two-stage VDL run, `vdl-probe/win11-20261024T003543704Z`, qualified its
initialized 64 KiB control, then stopped after creating a new private empty file.
ReFS reported allocation 1,024 bytes and EOF zero; the initial probe had expected
zero allocation. No allocation-size or EOF request was issued. The changed branch
was checkpointed before baseline restoration, with both original fixtures intact.
See [the VDL experiment record](native-vdl-experiment.md) for exact native bytes,
source archives and the narrow initial-state correction. Neither this measurement
nor native extent placement establishes payload-copy avoidance or conversion.

## Protected range and validity observations

The revised allocation probe successfully allocated and extended its private
file to 64 KiB, but its requested both-zero-validity/full-physical profile did
not qualify. Metadata-only observation after remount confirmed the same region
states: cached valid prefix 64 KiB, on-disk valid prefix zero, and a negative
first-cluster retrieval marker followed by fifteen positive physical clusters.
ReFS reports sparse validity support; these prefixes are summaries of region
lists rather than an asserted scalar on-disk VDL. See [the post-remount
observation](native-vdl-observation.md) and [validity implications](sparse-validity-implications.md).

The separate protected range experiment completed on 2026-10-24 at 01:17:23 UTC,
case `protected-range-read/win11-20261024T011607181Z`. Guest-side protection,
exact bounded raw reads and all before/after checks passed. Both 64 KiB ranges
match the known initialized-file pattern: the former source remains free in
both native bitmap variants, while the destination remains allocated. The
initial incomplete run exposed a safe-handle lifecycle bug; its evidence and
checkpoint are preserved, and a real Windows handle regression test covers the
fix. See [the complete protected-read record](native-protected-range-read.md).

The clean baseline is restored, off at 4 GiB. These observations establish only
the measured native profile and ranges; no filesystem conversion has occurred.

The standalone Rust `compare-retained` release also passed a file-only guest
check at 2026-10-24 01:39:57 UTC. Two new 8 KiB files produced the expected two
512-byte change ranges and hypothetical complete-image hash while preserving
the retained interval and all input bytes. No patches were applied. Evidence,
binary and sources were retained before restoring the powered-off baseline.
See [the comparator runtime record](retained-range-comparison.md).

## Retained-preparation root enumeration diagnostic

The 2026-10-24 03:35 UTC diagnostic of failed preparation
`win11-20261024T031656056Z` completed with known operation completion and cleanup.
Both F: NTFS and S: ReFS roots enumerated only `System Volume Information`, then
returned `ERROR_NO_MORE_FILES`. A new empty C: directory returned dot entries;
the nonempty control also returned its one-byte marker. All 28 exported native
buffers were hash-checked. No source/shadow write request was issued.

The earlier initial `ERROR_FILE_NOT_FOUND` was **not reproduced**, and the
diagnostic does not establish the earlier root contents. The failed case remains
failed; a source-informed first-error-2 followed immediately by error-18 path is
documented only as a proposed bounded preconstruction interpretation. Exact
evidence pins, limits and results are in the
[root enumeration record](root-enumeration-diagnostic.md). No conversion is
qualified by this observation.
