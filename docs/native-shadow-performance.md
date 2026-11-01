# Native-shadow performance continuation

The converter keeps Microsoft's formatter/driver as its ReFS metadata builder.
These changes reduce redundant reads and recovery storage; they do not replace
the native shadow, reduce the ReFS required write set, or qualify arbitrary disk
sizes, file counts, features, faults, or power loss.

## COPY read reuse

`PlainStreamRangeSession` can issue an opaque receipt only after an actual direct
physical read successfully fills the output slice. Resident data, decompression,
sparse holes and uninitialized zeros issue no direct-read receipt.
`SourceBackedShadow` binds the receipts to the immutable candidate chunk. A COPY
whose complete source interval matches those actual reads can reuse those bytes
instead of reading them a second time merely to compare them with themselves.

Each chunk has at most 1,024 coalesced receipt spans. Missing coverage, overflow,
or receipt allocation/budget exhaustion falls back to the previous read and
comparison. The fallback buffer is allocated lazily. Candidate/original digests,
original destination reads, earlier-old COPY coverage, checked sessions, frozen
device brackets and journal/target checks remain. Reused bytes are reported as
`source_reference_bytes_reused`, separately from actual `source_reference_bytes`.
The strict saved-capture reader accepts the optional counter and bounds their
combined value; neither counter supplies write authority.

A subsequent native run of58be22c measured all5,659,303,936 bytes reused with
zero fallback COPY rereads. Native conversion exited0/HND and independent hashes
matched all811 streams. Native-verified process reads were99,711,691,009 bytes,
compared with105,470,433,073 in the earlier case. These are logical transfer
counters, not physical traffic or a controlled timing comparison. Observed
native wall time was285.8896735s, versus276.7805697s previously; a speedup has
not been established. CPU/hash work remains a major cost.
[Exact native scope and archived pins](../evidence/native-capture-copy-reuse-20261101.json).

That source's free destinations were all canonically zero after fine-grained
capture, so the planner correctly retained exact-restoration format4. Journal
storage was5,773,344,392 bytes. The format5 native path remains unqualified.

The next preparation candidate uses the same construction fact inside the actual
`DifferenceImage`: two real native readers must name the same frozen partition,
and every COPY must resolve to that view's direct original-source branch. Its
candidate read already reads the source bytes, so it omits the second identical
source read. Actual candidate hashing, complete post-flush resolved journal
validation, and every fresh/recovery target gate remain. Generic readers keep
the original comparison. This later candidate is not qualified by the58be run.

The later c2c1ef3 native run qualified that preparation path: it reused another
5,659,303,936 source bytes, exited0/HND, and passed all811 independent hashes.
Native-verified logical reads were94,053,323,457 bytes. The two construction
optimizations therefore removed two measured duplicate5.66-GB source passes.
This remains a logical-I/O result, not a controlled wall-time speedup claim.
[Exact paired-preparation result and pins](../evidence/native-paired-preparation-copy-reuse-20261101.json).

[NTFS-managed collision preparation](ntfs-owned-preparation.md) is now implemented
for the explicit scratch-minimizing mode. The scoped native run moved5.64GB
through385 verified NTFS requests and passed all811 independent hashes. A fresh
frozen raw/native baseline also passed. The subsequent conversion passed with
positive format5 free-space elision and all811 independent postconversion hashes.
This does not establish released CLI or arbitrary-volume support.

The prepared-source case reduced journal storage from5,773,273,160 to131,301,000
bytes (97.73%), and selected writes from11,393,306,624 to544,784,384 bytes.
Native-verified logical process reads fell from94,053,323,457 to27,643,861,313;
writes fell from17,368,271,656 to878,482,576. The separate NTFS relocation moved
5,643,501,568 bytes and entails kernel-managed payload I/O outside those converter
counters. Native wall time was62.2871679s plus18.5202009s preparation, versus the
previous280.3918824s conversion. Full lab baseline/observer time is excluded;
formatter epochs and cache conditions were not controlled.

Actual journal format wasN2RFRE01 with402,669,568 hash-only free bytes and a
1,572,928-byte hash table. This qualifies the recorded fresh conversion and native
mount, with scoped free-space rollback semantics. Native interruption/Resume/
Rollback still require separate qualification. The result is preserved at051b650a;
the older unprepared31d7 checkpoint was retired after verifying both archives.
[Exact result and pins](../evidence/prepared-source-performance-native-20261101.json).

## Closing-buffer reuse candidate

The next Rust candidate feeds actual closing-bracket read buffers directly into
the existing allocation comparison. Each buffer is read, checked for required
zeros and included in the unchanged framed hash before its immutable bytes are
reused. Both complete opening and closing brackets, original-source reads,
granule comparisons and final native/route/allocation/state gates remain.
Unqualified capture output cannot mint execution authority if a closing gate
fails. Unsupported or backward requests retain actual-read fallback.

The provider needs one extra1-MiB buffer and keeps the existing4-MiB comparison
reducer. `shadow_bytes_reused_from_closing` distinguishes reused closing bytes
from actual capture shadow reads; the strict saved-artifact reader defaults
historical reports to zero and includes the new value in exact read accounting.
Full/generic paths retain their previous behavior. This is compiled and source
reviewed; native qualification and any measured read reduction remain pending.
The6be case had6,176,772,096 potentially reusable third-pass shadow bytes.

## Source-free recovery storage

`--minimize-scratch` explicitly selects `source_free_actual_bytes_v1` for fresh,
fast, allocation-bounded conversion. Full-content/whole-image modes retain their
existing contracts and cannot combine with this option. Existing requests and
journal formats 1–4 retain their previous semantics.

The private planning witness requires the reconciled NTFS allocation model,
complete record coverage, its bitmap pin and the exact partition domain. It
uses the existing allocation helper and rounds partial 4 KiB ownership outward.
Its inventory pin must match the frozen inspection bound by the live source
certificate. Optional changed-class diagnostics are not authority.

The planner splits at ownership boundaries, preserves new-zero/COPY mappings,
and protects the discovery first 4 KiB and every original COPY source. Actual
old zeros keep their existing canonical-zero representation. A nonzero old
destination becomes hash-only only when the complete granule is NTFS-free.
The planner keeps the original format if the exact new encoding is not smaller.

Format 5 (`N2RFRE01`) stores a 16-byte XXH3 digest per omitted old 4 KiB granule.
Its 104-byte descriptors, digest tables, preserved old payload and new literal
payload are authenticated by the complete immutable journal SHA-256 pin.
Tables are streamed in the binary journal, not expanded into plan JSON.

The actual full original selected SHA-256 remains the fresh target gate. During
that same gate, actual free granules must also match their stored digests. A
loader cannot reconstruct omitted original bytes from hashes: its separate
restoration digest covers only records whose original bytes remain recoverable.
This distinction is explicit in the ticket and rollback result.

Resume checks each hash-only granule against its original digest or exact new
bytes. Neither-old-nor-new, including torn 4 KiB mixtures, refuses. Rollback checks
these granules but leaves them unwritten, restores every required old record,
and verifies the restoration digest. ABT verification has the same scope. HND
still requires the full selected new digest and permanently closes old replay.
Legacy formats keep their previous per-byte interrupted-write membership rule.

The resulting rollback contract preserves the admitted NTFS filesystem's live
allocations, not the previous contents of unused space. It does not preserve
deleted-file recovery contents or provide rollback after writable ReFS use.

## Capacity and reads

For selected changed bytes `D`, actual canonical old zeros `O`, hash-only free
old bytes `F`, new literal bytes `L`, and metadata `M`:

```text
journal = (D - O - F) + L + F/256 + M
```

`O` and `F` are disjoint. The live capture guard charges the hash table in
addition to the existing metadata reserve, before accepting/appending a run.
It checks the same frozen allocation union used by final refinement; COPY
origins must be allocated. Exact final encoding size and independent native
write-capacity admission remain mandatory. A smaller journal never omits a new
ReFS target write or authorizes a larger source/data feature set.

## VSS admission

The new policy observes snapshot presence and hosted storage before freeze, then
snapshot presence inside the existing physically read-only native NTFS lease.
Both observations must name the same source and complete provider inventory.
Persistent exclusion is restored before return, and the source fingerprint
brackets that lease. This adds no extra mount or payload scan. A disposable 2 GiB
NTFS probe demonstrated that VSS cannot resolve a fully offline volume GUID and
that its storage query refuses physical read-only publication. Consequently the
full storage query stays before freeze; the protected lease repeats the supported
snapshot-presence query, never fabricating a second storage observation.
It requires requester-level `IsVolumeSnapshotted` to report successful,
initialized false/zero results and requires an empty hosted diff-area collection.
Unknown providers and query/partial-enumeration errors refuse. Supported provider
inventory is the Microsoft system provider, optionally with the exact observed
Hyper-V host-integration provider. The latter is reported separately rather than
represented as a guest differential-storage query.

The native Windows 11 probe observed the Microsoft differential-management query
returning `S_FALSE` with a real empty enumerator. This compatibility form requires
that nonnull enumerator and exact empty completion; null/partial/nonempty outputs
refuse. Its actual HRESULT remains recorded. This is an observed compatibility
form, not a success value listed by the Learn method page. Aggregate snapshot
`Query`'s ambiguous `S_FALSE` is not used to establish absence.

Catalog observations provide no global VSS serialization or raw write authority.
The existing owning freeze and no-concurrent-admin/mutable-alias contract remain
required. Reports explicitly leave in-flight exclusion and global snapshot counts
unproved. Additional providers and adversarial VSS races remain unqualified.

Primary contracts: [snapshot presence](https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-isvolumesnapshotted),
[hosted storage](https://learn.microsoft.com/windows/win32/api/vsmgmt/nf-vsmgmt-ivssdifferentialsoftwaresnapshotmgmt-querydiffareasonvolume),
[Hyper-V integration](https://learn.microsoft.com/windows-server/virtualization/hyper-v/integration-services).

## Current evidence and remaining work

[Recorded scope, artifact pins and results](../evidence/native-shadow-performance-20261101.json).

Focused builds and owned ordinary-file experiments cover the new format5 and
existing legacy copy/old-zero encoding. Native capture-read reuse and clean
format4 fallback passed the earlier converted-volume/811-stream run. The later
prepared source passed positive format5 conversion and all811 streams; native
format5 interruption and recovery remain pending. The owning
Windows VSS API probes and the native run exercised the supported admission
scopes without a global VSS exclusion claim.

The final optimized owned-file case omitted 8,192 old bytes using 32 hash-table
bytes, reducing its existing format-4 journal from 41,848 to 33,688 bytes. It
exercised interrupted Resume/Rollback and a separate complete Apply followed by
Rollback before HND. In that latter case, a foreign free-granule edit refused
Resume with zero target/journal writes; after restoring the actual new byte,
Rollback left 8,175 free bytes differing from their originals while independently
verifying exact new free contents and exact original restore-required contents.
Closed ABT verification passed. Legacy full old-byte restoration also passed.

The disposable NTFS probe separately confirmed snapshot-presence observation
under physical READ_ONLY publication. Its report explicitly does not claim a
second hosted-storage enumeration. No unit tests were added or run.

Sizing the saved, previously qualified grown-F plan preserves its selected bytes
and existing old-zero choices. It changes journal storage from 5,850,442,832 to
5,780,851,832 bytes: 69,591,000 bytes saved. The omitted 69,865,472 free bytes need
272,912 bytes of hashes and 15 additional descriptors. This is exact sizing of
that saved plan, not a native timing or physical-I/O measurement. Fresh capture
may have different boundaries and actual old-zero counts.

Most remaining old payload in that case is live source data overwritten by the
required target layout. Omitting free garbage alone cannot eliminate that cost.
Actual COPY reuse and NTFS-owned relocation now have the scoped native evidence
above. Next are native format5 interruption/recovery and reuse of already-read
closing metadata buffers while retaining both metadata brackets. Paged
source/evidence records and bounded handle windows
remain necessary for broad scale. Required-zone zero skipping remains disabled;
any smaller footprint needs independently authenticated ownership evidence.
