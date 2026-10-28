# Candidate ReFS target write set

## Compact resumed conversion passed

After controlled interruption and a clean reboot, run5c9045e3a4c44e46a7d25751939d1b15
passed persistent exclusion, normalized source/full candidate checks, resume,
exact2b2a postimage, HND and native all14 objects/9 full file hashes. Label/mount
paths were preserved. Saved OFF/9e25f048-a121-4317-997c-c4dee0810b16, parentb6b2,
all40 snapshots retained. Never replay that operational resumed ReFS journal.
Execution90c77b31ecf154f531c975930057abe6c789f2260f0f5c5adca298db83dc7763;
finalizationafd2f8ba8f3ae8595507fe9c537d93dea83e6dbc3f3ad988c5ceed1c473bc761;
result055bc95334af585905dc5ed3a6eb9943962faa3102f3c0b92ec399405583c917.
Evidence compact-recovery-20261028/resume; guest output
C:\ntfs2refs\compact-recovery-5c9045e3a4c44e46a7d25751939d1b15\result.
This proves process recovery, not physical power-loss/general qualification.

The user explicitly approved cap256→258 GiB when rollback1.5-GiB allowance
exceeded667-MiB cap headroom. Configured cap is277,025,390,592;64-GiB host reserve
retained. Only the separately saved partialb6b2 was restored for rollback.
Native rollback outcome pending. No checkpoints/evidence were deleted.

## Opaque complete composite target proof

`general_composite_target::verify_and_capture` builds a non-deserializable proof
from actual frozen devices: fresh source hash/inventory/live views/tree,
protected native metadata/maps plus source-derived small/tail slice hashes,
complete-address-space delta, held backing identity/hash and complete reopened
composite hash, final source/shadow brackets. The residual observer never reads
full placeholder prefixes; the zero-payload layout API remains separate.

`LiveAssessment::qualify_composite_target` accepts it only with the ORIGINAL
live source context and all existing source gates. No saved JSON or reopened
diagnostic recreates a certificate. Existing full-shadow qualification stays
intact. Build passed; generic orchestration/native qualification pending. Dirty
free space can enlarge full-address-space deltas and remains budget-admitted.
No unit tests added/run.

## Compact interruption reached recovery boundary

Run4539fe2de48e4c33a8db4d733fe859a7 exited86 after the first complete flushed
source write. The worker ended; source remained offline/writable and shadow
offline/read-only. A real post-terminal read found all4,096 handoff bytes zero
and a durable N2RINT01 operation intent. No native handoff, completed execution
or final result existed. An earlier attempt to open the exclusively held live
journal failed and its unfilled buffer is not evidence; only terminal reads
were used for this disposition.

Partial journal SHA-256:
424f0434e236b1644f62b527393f951848511f33d399e490daa4f2f0f4f5cc92.
Saved OFF atb6b2a81a-23d9-48ec-aa1c-366b7486cbcf, parent5971d348, all39 snapshots
retained/RAM released. Host archive:
`.lab/hyperv/streaming-v2-20261027/compact-recovery-20261028/interrupt`.
Resume/rollback native qualification remains pending. This is a process-exit
boundary, not physical power-loss or exhaustive write-boundary qualification.
No unit tests added/run.

## Post-freeze layout and complete-address-space path

The root `ProtectedTargetLayout` verifier now brackets that actual native
observation with unchanged complete raw-shadow hashes and exact frozen state,
tree hash and resource profile. CLI `--protected-postfreeze-layout` opts into
this after source metadata restoration and freeze, replacing pre-lock routes
with witness-derived routes before capture. It remains a layout witness: no
logical payload, source certificate or general conversion authority is invented.
Build passed; native generic-path integration remains to be qualified.

An opaque native protected layout observation now checks namespace, metadata,
file IDs, sizes, complete mappings, storage validity and disabled integrity
under the existing read-only lease without reading placeholder contents.
`SourceBackedRoutes::from_protected_layout` derives post-freeze routes from that
live witness. The ordinary full semantic verifier remains strict and hashes
contents. Callers still must bracket raw-image equality, bind source/tree/data
proofs and supply genuine live source admission; the observation alone grants
none of those properties.

The new `--compare-complete-native-image` difference-capture option compares the
entire native address space with its proved payload substitutions. It stores
only differing4-KiB clusters, eliminating reliance on a before-lock allocation
bitmap to omit bytes. This provides a sound comparison scope for later general
qualification, at the cost that dirty free space can increase output. Hard
changed-byte admission remains. The earlier selective67.1-MiB fixture evidence
is preserved, not reclassified as a general frozen graph proof. Build passed;
native protected-layout/whole-address-space integration pending. No unit tests.

## Compact native reboot and mutation passed

The saved compact conversion passed strict native readback after a clean boot,
the existing50→80→10-MiB create/grow/truncate/rename/delete and128-entry directory
workload, strict readback after mutation, and another clean boot/readback.
Pins: BootVerify86586f40728f9d8e48dde5768aeb314960e4c0cc073cdba0b79c4f5edc698f76;
mutationef37293d35a3afa0f0d6596e26d5be15da90a14a42038b5ecbf982cffd498218;
after-mutationd1f19b44bf7130e0010086b18e2ec7bd4d5d4d1249c73cfdc59ea6481f3fb6d7;
after-reboot4f4177a394d2bc8d5a90b9fc428f29a9a5aebc75da5a55e2acf3ff1819dc928e.
Evidence: `.lab/hyperv/streaming-v2-20261027/compact-postcheck-20261028`.
Saved OFF at34c29917-13b9-4719-bd7b-e39a2602dab6, parentf5adf4aa, all38
checkpoints preserved/RAM released. No journal replay occurred. The source
comparison has no explicit retained-range list, so this postcheck does not
claim an additional original-position proof. No unit tests added/run.

## Native compact in-place fixture conversion passed

Canonical runc75ec9ec8a104f99b630c92343b44ca1 completed raw apply, durable HND
and native ReFS verification on the original NTFS source disk/partition. The
source was not copied to another filesystem. The shadow supplied metadata and
small materialized streams; large prefixes were supplied on demand from the
frozen original. Only70,406,144 source bytes were journal-written in138 patches.
Before native mount, the entire52-GiB result matched
2b2aa8c51a0ed3676a31255f6121152fedfb29b459c20246c1546135fe769391.

Microsoft's driver subsequently mounted disk1 as ReFS/4-KiB with original label
`n2r-stream-source` and original mount paths. Native verification passed all14
objects' metadata/namespace and9 complete file hashes totaling8,590,217,322
logical bytes. Verifier payload writes were zero. The durable handoff recorded
`rollback_closed=true`; the old journal must not replay over this operational
ReFS branch. Ordinary writable mount/label restoration may change metadata
after the exact pre-mount image hash; that is outside NTFS rollback.

Producer78d881524aa5a3d9edfabc6b01d41e85389a1e13ac076866d53c0560f1357aa2
was built from29f989e plus the pre-existing main.rs change. Execution report:
ae9a061e03d818d3cf0b05cb1e38312629fe4d5c87aa474b577470483e06157e.
Finalization7c02dcf584fb170ff9abcbba81e9753bbe996340555b9fed31606e4d4a0cd196;
result4ec0ae18b07a8a879ff21c2d802ddc365433f9f67e00881bcf6f762410f01e8d;
event0b80e152ed952fd8e922021089b10c98d67bf813ab0310615de785ce78fe90c4.
Full post-HND journal:
afcbe92a85f9ec409547ea7c04557676df1c62f5eaaff69c2f58cc3bb27bf6e4.
Host evidence:
`.lab/hyperv/streaming-v2-20261027/compact-fixture-apply-20261028/canonical-identity`.
Guest output is
`C:\ntfs2refs\compact-apply-c75ec9ec8a104f99b630c92343b44ca1\result`.

Cleanly stopped and saved atf5adf4aa-ef43-4201-9ad1-8eec3b495405, parent5971d348,
all37 checkpoints preserved and4-GiB RAM released. New child backing was
OS732/source227/journal17/shadow4 MiB (980 MiB total), excluding all parents,
base images, host reports and physical device I/O. The source child includes
subsequent normal native ReFS metadata writes; it is not the raw writer count.
No reserve/cap was raised. No unit tests added/run.

This is an exact explicitly acknowledged disposable-fixture experiment with a
large zero-filled file. Production source-admission/general-conversion flags
remain false; this is not arbitrary-volume/large-nonzero/boot qualification.
Next gates are native reboot/mutation and compact interrupted resume/rollback,
then replacing the exact fixture gate with genuine general source/target
admission. The existing SourceCertificate was not weakened or reconstructed
from old success JSON. Preserve this converted branch before restoring only
the separate preapply5971d348 branch for recovery tests.

## Exact-fixture cutover experiment

The first native launch did not start its PowerShell wrapper under the guest's
default execution policy. It was replaced by a direct native scheduled task,
with no policy change. That exact acknowledged task matched the full source hash
then refused before activation: artifact pins were serialized in different key
orders by preparation versus execution. A single canonical Value-map identity
method now serves preparation, activation, recovery and finalization, reproducing
the existing prepared journal identity instead of changing the immutable ticket.
Source stayed read-only and no data writes occurred. A fresh continuation is
limited to this proved preactivation failure, with a new output and full source
hash check; original artifacts remain preserved. New native outcome pending.

Compact native finalization now uses the same durable HND/full-image checks
and native verification helpers as the original path, with the composite backing
binding and exact delta policy. The attrs1 read view closes before mounting.

The existing SourceCertificate cannot be recreated by reopening a frozen disk:
its original live transaction-freeze/target witnesses remain required. A new
frozen-source diagnostic gathers current facts but grants no certificate. Those
rules were not weakened. The immediate native cutover command is explicitly an
enrolled disposable-fixture experiment, requiring an acknowledgment plus exact
machine/GPT identities, full source/target/tree/artifact/ticket/driver pins. It
hashes the entire source before clearing read-only protection. It cannot select
an arbitrary existing volume or claim production source admission. Successful
results must still keep general-conversion flags false.

The host controller preserves all36 saved checkpoints and boots the already
prepared5971 branch, without formatting or reconstructing another shadow. Build
and controller syntax passed; native apply/handoff outcome pending. No unit
tests added/run. General admission and compact rollback completion still need
work before a usable general-drive converter can be claimed.

## Native compact journal preparation passed

Runa1aa7a957b094f7bbe9af154ee7270eb successfully reopened the metadata-complete
candidate, checked actual capture/backing hashes and file identities, hashed
the complete52-GiB target, and prepared/reinspected a durable external journal.
The original source remained NTFS/offline/read-only; native shadow stayed
offline/read-only. Source was clean, target header3.14, and all admission,
activation and conversion flags remain false.

The journal contains138 patches,70,406,144 old bytes and70,406,144 new bytes,
plus31,356 overhead bytes: total140,843,644 bytes (134.3 MiB). Its patch coverage
was checked against the exact compact delta before publishing ticket/report.
The existing full comparison/rechecks scanned223,338,299,392 bytes; progress
elapsed443,153 ms excludes the preceding complete target-hash pass and some
other reads. This is space qualification, not an optimized I/O claim.

Source full SHA-256:
ec5b89de85e24bbb0cdc5f99e907450dc847228ca997465961ab22f89d983dac.
Candidate/expected postimage:
2b2aa8c51a0ed3676a31255f6121152fedfb29b459c20246c1546135fe769391.
Journal immutable length140,835,452/SHA-256:
4b1353889efb1ee328286da224e105733d4f622f8ebca4a46f4147ecc0d56c94.
Full journal SHA-256:
a2a2271ef9a4d382147103d40f6bb5a16289e063cce6dc77c963548391fa6e9f.
Preparation report:
c8f7d7d838a8994f190db468d77a68458285e751b5f23a8dd41b920602b1f1ad.
Request33d18d9f77ebeba339feb71cc4471852bb2c3f3b6edc283fff93fc3f9d7e27d7;
ticketc07d1a49e8ba36b843214dab822ab8c335dfd51146f144bd5f64d2c37fc5f2c4.

Host evidence: `.lab/hyperv/streaming-v2-20261027/compact-journal-20261028`.
Guest journal/materials remain at
`J:\n2r-compact-journal-a1aa7a957b094f7bbe9af154ee7270eb`, alongside the original
candidate still onC:. No redundant host payload copies were made. Producer
7fa4bb96c86edfaca675c8b5458b1be291ac2a397430de59f5fbbb0a0d31a5f6
was from658a09a plus the pre-existing main.rs change; later private execution
plumbing was not used in this run.

After clean shutdown, checkpoint5971d348-3f8b-4696-bef6-4c1f164fbf64 retained
all36 snapshots, parent43cc982a, and released4-GiB RAM. New child backing was
OS638/source4/journal91/shadow4 MiB (737 MiB total), excluding all parents/base,
host reports and physical device I/O. The configured256-GiB cap/64-GiB host
reserve were retained. Source admission, compact native finalization, actual
apply and interruption/recovery still need connection. No unit tests added/run.

## Compact journal preparation

Internal compact activation/execution plumbing now repeats exact journal/delta
coverage and composite backing binding checks before arming any source range.
Apply/resume/rollback share the existing engine, using the separately derived
offline read-only source view for invariant complement bytes. Its full target
hash and normalized-source checks remain intact; current bytes are never
assumed to equal the original after a partial apply. This compiles but has no
public source-write entry point yet. Source admission and compact native
handoff/finalization remain to be integrated and exercised.

`lab-prepare-compact-journal` now reopens the pinned persisted difference report
and backing under read-only handles, validates actual backing hashes/lengths
and held-file identities, generates the complete candidate target hash, and
feeds `DifferenceImage` into the existing journal comparison/preparation core.
Source/native-shadow device states remain separately bracketed and excluded.
The journal's shadow identity uses a new compact domain including both native
partition identity and exact artifact pins. An ordinary raw-shadow ticket does
not become a compact ticket, or vice versa. Preparation requires journal ranges
to cover exactly the changed-cluster set, protecting the source-backed complement.
Outputs still grant no admission, activation or conversion authority.

For subsequent execution/recovery, `GeneralJournalReadView` derives a separate
bounded read-only handle/cursor from an activated offline target (attrs1).
Reusing a `GeneralFrozenPartition` with stale attrs3 state is explicitly avoided.
Existing full target hash/normalized-source checks and handoff barrier must stay
in the compact execution path. The full-shadow wrappers retain their behavior.
Release build/controller syntax passed; native preparation pending. No unit
tests added/run. Existing journaled cutover/recovery still needs connection.

## Source-backed difference representation

The native low-scratch experiment now constructs private unwritten user
prefixes, supplies their logical NTFS bytes through a read-only target view,
freezes the shadow and compares the conservative selected set against the
frozen original. It stores only differing4-KiB clusters. Equal candidate bytes
are proved by comparison and stay in the original partition; reservations are
not discarded by guessing their purpose.

The native52-GiB/8-GiB-prefix case compared14,764,498,944 selected bytes and
stored70,168,576 bytes in136 changed ranges. `DifferenceImage` reconstructed
the seekable target view and its bootstrap inspection passed. It did not mount
that view or apply it to the source. See [the full scope and pinned evidence](private-tree-allocation.md).

Mounted bitmaps are explicitly tagged before-lock observations because the
tested ReFS profile rejected bitmap queries after successful LOCK/flush.
They do not become frozen graph certificates. Source metadata restoration,
required-byte reconciliation and compact journal/cutover/recovery integration
remain. The full-shadow workflow remains preserved; older descriptions below
record the earlier implementation stages. No unit tests added/run.

## Compact candidate backing

`refs_hybrid::packed` now streams selected shadow ranges into a dense scratch
file using a 64 KiB buffer. Its index is bounded by the candidate's 65,536-range
limit rather than partition capacity. `PackedShadow` exposes their original
partition addresses to `CandidateHybrid`; reads into omitted ranges fail unless
the hybrid supplies the original source bytes. Omitted ranges are never
implicitly zero-filled. The compact file has a SHA-256 receipt, exact byte
count and `executable: false`. Caller-owned durable storage and authenticating
the exact plan remain necessary.

`lab-refs-write-set` accepts optional `--shadow <frozen-raw-image>
--packed-output <new-file> --max-packed-bytes <budget>`. It refuses excessive
selected bytes before opening the scratch destination, requires ordinary image
input, creates outputs exclusively, flushes the compact file, and only then
writes its completion report. Failure preserves partial artifacts rather than
presenting a success receipt. Optional `--original <raw-ntfs-image>` connects
the compact backing to the existing read-only hybrid ReFS inspector.

This eliminates unselected bytes from the compact artifact, not from initial
native shadow construction. Selected ranges still include allocated payload;
the module does not establish metadata completeness or independently authorize
retained-payload subtraction. The existing full-shadow conversion/recovery
path is unchanged. Initial evidence is a release build, not native compact
conversion qualification. No unit tests were added or run.

The subsequent retained-range path also omits supplied retained payload from
the compact artifact. `--retained-request` accepts the existing comparison
request (or the `comparison` member of its owning request) and requires both
ordinary original/shadow images. It validates range coverage/alignment,
non-overlap, the 1,024-range budget, equal pinned source/shadow range hashes,
actual hashes from both input images, and no overlap with observed metadata
anchors. Evidence reads are bounded at16 MiB before JSON decoding. Scratch
admission uses selected bytes **after** retention subtraction.

`PackedShadow::with_retained` routes retained reads to the original image;
packed offsets cover only the remaining selected ranges. The original
filesystem allocation plan is unchanged: retained clusters remain allocated
to their ReFS streams. `retained_source_bytes` reports omitted payload
separately from packed bytes. Hash agreement and known-anchor exclusion do
not prove the complete metadata graph or preservation of file identity;
these remain diagnostic candidates with `executable: false`.

This path has release-build/CLI evidence only. It has not yet been used for a
native compact conversion. Initial native shadow construction still allocates
the placeholder payload and remains the next independent storage problem.

The current journal compares every sector of a frozen NTFS partition with a
native ReFS shadow. On a previously used volume, stale bytes in free sectors
can make the journal much larger than the ReFS metadata and live payloads.

The new `refs_write_set` planner unions the native ReFS metadata-inclusive
allocation bitmap with observed VBR, superblock, checkpoint and physical-root
anchors, plus successfully checked container-tree and translated-root pages.
The bounded anchor profile requires the three expected superblock locations,
two matching checkpoint locations and valid self checksums. Rejected observed
pages prevent a candidate instead of silently disappearing from its range set.
It computes the complement as source bytes to preserve. The shadow
collector records compact allocated intervals and the bitmap SHA-256; the
freeze report records a diagnostic write-set candidate or the reason it could
not be formed. `lab-refs-write-set` can also build that diagnostic from saved
ReFS inspection and allocation evidence. It never authorizes writes.

`payload_coverage` separately checks supplied measured target retrieval ranges
against that candidate, reports uncovered bytes and rejects overlapping,
unaligned or out-of-volume extents. This range check proves neither that every
payload was supplied nor that the remaining metadata graph is complete.

A parser smoke run on the Windows-created 3.14 corpus found 19 anchor ranges,
coalesced into eight intervals. That run used an **artificially empty**
allocation map solely to exercise anchor parsing; its 100 KiB write-set total
does not describe the real volume.

The native bitmap is read before shadow dismount and flush. ReFS may change its
allocation graph during that transition. Before using this plan to omit any
journal patch, an independent reader must reconcile the **frozen raw image**
against the captured bitmap, all reachable metadata and data extents, and
fixed bootstrap locations. The journal then needs a hybrid postimage hash:
shadow bytes in target-owned ranges and original NTFS bytes in preserved
ranges, followed by native ReFS mutation qualification.

The Rust allocator reader now validates the checkpoint/container route and
decodes every Medium row plus the physical Small allocator root on the pinned
Windows-generated 3.14 corpus. Both tiers' free counts agree with REFSNT
before and after one isolated extent adoption. Block refcounts, other
reservations and the whole metadata/data reference graph remain outside that
reader's proof.

The later experimental larger-tree path adds a multilevel Medium allocator
walk, connected to retained-payload coverage checks. It decodes each leaf as
it arrives, retaining allocated ranges, row/page counts and digests instead of
all decoded rows. Bounds are 1,048,576 pages including the root, 33,554,432 leaf rows and eight
levels below the root. Every child must match its parent CRC, virtual self
locations, table, volume signature and expected level. Repeated/overlapping
physical page clusters, incomplete row counts and gaps in full-volume coverage
refuse the entire observation. The default one-level reader is preserved.

This expanded walk has compilation evidence only; the historical corpus results
above do not qualify it. Default container-table traversal retains its existing bounds,
and the default 128 GiB partition ceiling remains. No write-
set omission, whole-volume ownership or native conversion claim is added.

The experimental Small allocator reader now also supports multilevel trees,
with separate 4,096-page, 65,536-leaf-row and depth-eight bounds. It uses direct
physical child addresses, consistent with the [Small tier's documented address
class](https://xbpt.gitlab.io/forefst/structures/allocators/). It validates each
child's CRC, table/volume identity, physical self-address and parent-derived
level, rejects reused physical clusters and enforces ordered non-overlapping
managed ranges. It compares total leaf count with the root descriptor without
pretending that Small covers the entire volume. Leaves are decoded incrementally.

This Small-tier expansion has compilation evidence only. Its default entry
still uses the original root-only profile, with no new field in legacy JSON
when there are no child pages. Larger-volume routing
remains unfinished; native qualification and default routing are unchanged.

Container lookup now borrows the validated, sorted mapping rows and uses binary
search instead of constructing duplicate B-tree indexes in Medium/virtual-root
readers. Container traversal retains rows in index order, rejecting duplicate
or unsorted IDs; physical-overlap checks sort a compact vector of starts. The
default detailed reader retains raw diagnostic values and its original budgets.

The experimental Small reader also uses a physical-bootstrap-only inspection,
avoiding an extra container/virtual-root scan. This still reads the redundant
headers, anchors, checkpoints and physical root pages needed for Small's own
bindings. Skipped descendants are explicitly absent and remain unverified;
retained coverage independently requires the Medium/container checks. Default
inspection keeps its full bounded bootstrap path. These changes have compilation
evidence only, with no new unit tests or native execution.

Valid 160-byte container values now use fixed-size byte storage rather than a
heap-allocated 320-character hex string. Copy comparison and mapping digests
read those bytes directly, avoiding repeated hex decoding. JSON still emits the
same `value_bytes_hex` string field. Imported malformed diagnostic strings remain
representable and are explicitly refused before they can supply mapping bytes.
This removes one retained heap allocation per valid detailed mapping; it does not
qualify larger volumes. Existing
fixture assignments were adapted to the value type without adding or running tests.

The larger-tree profile now uses a separate [compact container walk](refs-compact-containers.md),
retaining only live ID/address indexes while hashing all page and row-value data.
Serialized summaries cannot recreate those indexes. It is connected to bootstrap,
virtual-root and allocator checks plus frozen reconstruction qualification; native
qualification remains unchanged. Default routing retains 128 GiB, while the
explicit experimental profile propagates a 2 PiB routing budget through the
streaming paths. This is not a guarantee that format, data, metadata-complexity
or journal/scratch limits admit a particular volume.

The streamed Medium result marks `rows` as an empty diagnostic collection and
adds `streamed` accounting. `child_pages` contains at most the first 32 child
addresses; `streamed.pages_read` counts the entire walk including the root.
The leaf digest covers a version prefix followed by each actual row's 32-byte
SHA-256 in traversal order. The page digest covers its version prefix, then
each page's four physical LCNs, validated level byte and complete 16 KiB bytes.
Default one-level results retain all original rows/pages and omit `streamed`.
Allocated-range storage retains its existing 65,536-interval bound. No larger
volume or native execution qualification follows from these resource changes.
