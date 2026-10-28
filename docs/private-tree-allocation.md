# Allocation-only canonical tree staging

## Source-backed logical hybrid verification

`general_shadow::verify_private_hybrid_contents` now verifies each user
stream from the live supply plan without a duplicate payload image. It reads
original-coordinate ranges at their measured physical offsets from the actual
excluded source and reads only initialized materialization ranges through the
private shadow file handles. Every logical byte must be covered once, within
EOF, and the complete stream SHA-256 must match the canonical source digest.
An empty stream still requires its canonical empty hash. Buffer size is64 KiB.

Native path/length/type/link/deletion and tracked mappings bracket each file;
the complete live supply plan and excluded-source state bracket the pass.
Read accounting must equal the plan's reference/materialization totals. Shadow
reads intersecting source references or exceeding its initialized prefix are
refused, so the verifier cannot accidentally authenticate garbage placeholder
bytes instead of retained source bytes. Dedicated verification-read counters
remain separate from materialization readback. Source VDL/encoding mismatch
that makes raw referenced bytes differ from canonical logical data fails the
whole-stream digest; this function does not silently normalize those cases.

The staging CLI selects this only with explicit `--verify-logical-hybrid`
after `--materialize-relocations`. This is a logical payload proof, **not** a
frozen on-disk ReFS graph or source-admission certificate. System metadata,
source ACL/time restoration, complete required-byte capture, storage admission
and recoverable cutover remain pending. Release build passed; native execution
of the whole-tree mixed path remains unqualified. No unit tests added/run.

## Live payload-supply plan and relocation streaming

The private tree now retains original-coordinate ranges as internal state
derived from successful native moves, rather than consuming serialized
`success` flags. A complete placement attempt creates a non-deserializable
`SupplyPlan`; subsequent placement invalidates it. Planning rechecks all native
mappings and accounts for every user logical byte as either an original-source
reference or materialization. Partial final clusters always remain in the
materialization set. Bounds/overlaps and at most4,096 supply ranges are checked.
Failure/partial placement cannot produce a complete plan.

`materialize_private_supply_plan` admits an explicit materialization-byte
budget before data writes, advances every fully tracked prefix (including
fully referenced files), then streams only the materialization gaps through
the64-KiB checked-source/private-readback path. Writes overlapping live
original-coordinate references are refused. Source binding/exclusion and
native placement are checked around the operation. The output retains up to32
sample receipts plus a length-delimited ordered SHA-256 receipt digest, rather
than storing all chunk receipts or file-sized buffers. It does not claim that
the unfilled shadow references contain source bytes: source-backed hybrid
verification and canonical source admission are still pending.

The CLI requires explicit `--materialize-relocations --place-source-prefixes`
and a `--max-materialize-bytes` budget (default256 MiB). This replaces the
small-only loop for that mode and does not duplicate retained payload.
Metadata/physical IO can exceed selected logical-byte accounting; the current
source reader revalidates metadata per chunk. Source/system metadata
restoration and recoverable required-byte cutover remain incomplete.

Release build passed; native whole-tree placement/materialization has not yet
been executed. Admission must forecast possible internal move traffic and
actual backing growth, preserving the64-GiB host reserve and all snapshots.
No unit tests added/run. The working full-shadow path is unchanged.

## Tree-wide unwritten placement implementation

`PrivateTree::place_source_prefixes` now parks every user-file full-cluster
prefix before submitting any final original-coordinate move. Scratch selection
uses both complete native bitmap views, excludes all desired source ranges and
the first/last MiB, and requires a sufficiently large free span. No source
disk is moved. Before IO it checks exact file names/lengths/zero-prefix state,
source-run alignment/coverage, non-overlapping desired physical ownership and
global range/move budgets. Partial tails are handled by the separate range
materializer rather than reinterpreted as complete clusters.

Parking and final moves use512-MiB-or-smaller chunks, at most1,024 submissions
globally, with16-MiB retained move evidence. Final candidates come from the
fresh two-view free-subrun planner. Each actual move again checks live occupancy
and all expected file mappings through the tested unwritten constructor.
Refusal or incomplete evidence stops the operation; no force/retry path or
original NTFS mutation exists. The output distinguishes original-coordinate
byte ranges from payload-content verification, which remains false.

The staging CLI exposes this only with explicit `--place-source-prefixes`.
It runs placement before small data writes; when combined with tail staging,
it requires complete placed-prefix coverage instead of the unplaced-scratch
preparation path. Temporary ranges still require actual data supply and the
original-coordinate ranges need source-backed hybrid handling. Source metadata
restoration and required-byte/cutover/recovery qualification remain pending.

Release build passed. This tree-wide path has not yet been run natively; the
prior1-MiB reposition result does not qualify whole-tree parking. Whole-workflow
physical movement/scratch forecasting must be admitted before a new native
run, retaining the host reserve and all evidence. No unit tests added/run.

## Native partial-tail staging result

Sourcec079e47 adds explicit `--prepare-large-tails` staging. Before a selected
partial-tail write, the constructor can advance an **unplaced private scratch
prefix** without copying its bytes. It refuses this option if placed-prefix
coverage would be bypassed. The result explicitly marks original positions and
source prefix contents unverified. Files remain protected SYSTEM-only; this
option cannot be treated as retained-data proof or source write authority.
Real retained placement must precede validity advancement/materialization.

Native run`cc4109eec29a4643ae5a7e4d1021f8e6` passed with producer
`98868f9f27d863e6b98af39305292a91e233bf05b08ac2aaf543255b64a2388c`.
The command read the actual source byte at logical offset8,589,934,592 in the
8,589,934,593-byte file, wrote only that byte and verified readback after flush.
That zero byte's SHA-256 is
`6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`.
The source range proof correctly says `whole_stream_hash_matched: false`;
neither the source-range read nor target readback scans/validates its prefix.
The empty file and17-byte café file also passed, giving18 target payload
bytes written/read back,36 source logical-byte charges including preflight,
and8,589,934,592 private prefix bytes made storage-valid without a payload copy.

Full result SHA-256:
`1629301c5b19af272f5436258c1a072f8771fc758a71ffd9b8f1a74b65562694`.
Request:`5303d42d780c119b381d51992fe5d92f63ba3922ba92e9ba82f1ffed26ed8dfd`.
Inspection/tree pins remain the matching candidate11 inputs documented below.
Evidence:`.lab/hyperv/streaming-v2-20261027/private-tree-tail-materialization-20261028`.
After clean shutdown the non-sparse new shadow child measured157,286,400 bytes
(150 MiB), excluding shared parents/OS/journal/evidence; physical-device IO and
whole-workflow scratch remain unmeasured. OFF checkpoint
`1da04080-dceb-4127-9540-c6826e45c543`, parent
`6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`, preserves the result. All25 snapshots
remain and VM RAM is released. No unit tests added/run. Native large-prefix
placement/content supply, source metadata restoration and compact recoverable
cutover still need integration. The working converter path is unchanged.

## Native small-stream materialization result

The staging command now explicitly selects `--materialize-small` with pinned
`--inspection`/`--inspection-sha256`. It checks selected source records before
creating a namespace, then copies only ordinary user streams of at most4 KiB
through the checked range reader. Empty files are included; system streams
remain pending. The8-MiB cumulative budget covers preflight plus transfer for
at most1,024 such files. Large-stream initialization is not selected.

Native run`7221c22bb02641cebf1b4db6ac4d4aad` passed with producer
`34542fc824f0459703581d25bb3d2c6b2a8e1420eab836c428d86fb26b33e049`.
The producer uses the ee6cdca implementation and separately recorded controller
source. It used the matching candidate11 source/tree from its saved frozen
NTFS branch. Inspection file SHA-256
`307c396b8449831618f96d34a4bfcd60443c58197f3cb6221ea076df37d259d3`;
tree`1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215`;
request`bacdf35c36c9ba477eefd33de9a3ae34709507ccfab3918716268c53a7b2c313`.

The empty stream matched SHA-256e3b0...b855 without data transfer. The17-byte
`notes/café.txt` source matched
`f031f647ec5e176ec8131de1d6024e2447b5d75597bb320fd097fb4cc10783bf`,
was written/flushed to its same named private target, and read back identically.
Source logical-byte charges were34 (preflight plus transfer); destination
payload writes were17 and readback17. All six user files were allocated,
including8 GiB+1, while large payload initialization remained disabled.
The source stayed offline/read-only and received no payload writes. Source
image admission and metadata restoration are still not established by this run.

Original result SHA-256:
`3ebb5fab6db1f34d9f865a560fc01b43e3db9253f01caf05d5699662e4c9c799`.
Evidence root:`.lab/hyperv/streaming-v2-20261027/private-tree-small-materialization-20261028`.
After clean shutdown, the new non-sparse shadow child measured121,634,816 bytes
(116 MiB), excluding shared parents, OS, journal and other evidence. This is
not a full-workflow scratch bound or physical-write measurement. OFF checkpoint
`a6fd7138-6e44-46cb-89a9-883e360bd00e`, parent
`6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`, preserves the outcome; all24 checkpoints
remain and VM RAM is released. No unit tests added/run. Tail-gap behavior,
large payload mapping/supply, source ACL/time restoration and recoverable
low-scratch cutover still need integration/qualification.

## Bounded exception materialization

The subsequent implementation adds
`ntfs_inspect::read_plain_stream_range_into` and
`general_shadow::materialize_private_range`. A caller-owned64-KiB-or-smaller
buffer receives only the selected logical range. Before and after the read,
the existing checked-attribute path revalidates geometry, MFT bootstrap,
file identity, run mapping, lengths and inspected stream digest. Holes and
bytes beyond initialized length still return logical zeros. Selected bytes
are charged to the existing cumulative transfer budget; metadata IO remains
separate. A whole-stream small read must match its inspected digest. A partial
range proof explicitly does not claim whole-stream content verification.

The owning-source wrapper requires the actual excluded source binding to
match the private template, binds canonical file length/hash/name/index, and
checks source state around both reading and materialization. The native file
can accept only a bounded write no later than its tracked valid prefix; a
write beyond that prefix is rejected before IO. Thus a final byte at8 GiB
cannot implicitly zero-fill an uninitialized8-GiB gap. Placement must happen
before initialization; complete placed-prefix coverage is still required for
the one-time VDL advancement.

Each materialized range is explicitly sought, written, flushed, read back and
compared. EOF/type/link-count and all previously placed mappings are rechecked.
Failure poisons the private file and retains it for diagnosis. Permissions
remain protected SYSTEM-only; no source metadata is restored early. Empty
ranges do not authenticate a nonempty stream. Materialized and readback byte
counters are reported separately with checked aggregation; ordinary template
allocation still reports zero. No raw source writer or conversion authority
is introduced.

These APIs have release-build evidence, not native materialization/conversion
qualification. They are not selected by the working full-shadow converter or
the allocation-only CLI yet. Next connect them to the process-lifetime
placement/materialization/freeze workflow and qualify actual resident/tail
data. Full payload supply, root/system metadata, source metadata restoration
and complete required-byte coverage remain pending. No unit tests added/run.

Sourceb3c7d3f connects the canonical `shadow_tree` to the native private
constructor through `general_shadow::allocate_private_tree`. The separate
`lab-allocate-private-tree` command stages the original Unicode user paths and
file lengths without copying their contents. It is not a conversion command.
All file and user-directory DACLs are protected SYSTEM-only. Root/system data,
source ACLs, timestamps, attributes and payload supply remain explicitly pending.

The native template owns its file handles and exposes placed-prefix operations
through the unwritten constructor. It requires the enrolled isolated guest,
excluded source, independent writable ReFS/4-KiB shadow, fresh user namespace,
bounded paths/counts and complete parent ordering. No source write handle is
available. Existing formatter-cache handling uses the earlier narrow preflight;
unknown system entries refuse rather than disappear. Source-image hash and
complete admission are not established by supplying canonical JSON.

## Native outcome

Run`29abdc44bbcf42e69783c3736c1fb349`, producer SHA-256
`df1c5f22ee4a17b800e61b59a555c6df7a7d272774543e5ae7bded165a35a4d5`,
constructed the namespace but exited1 during reporting: the reporter wrongly
requested a nonresident retrieval map for an empty file. Original refusal
SHA-256`116cb2579eaec82fae50ff81f4b3c5702b0044656dcecdfa5df1bea0b7601c92`
is preserved. Construction/formatting were not repeated over that run.

Source3535d78 distinguishes empty/subcluster allocations and adds a separate
metadata-only observation command. Observer
`f0f7140b4eb8419ea3dd910de69770ad`, producer
`d6d47037644788208f5013d304fe396e339629a03b32bb44c221b97e6d80ded8`,
exited0 and verified the exact user namespace, distinct single-link file
identities, lengths and applicable retrieval maps. Its144,473-byte result is
SHA-256`21d2253c40e0be83c8ab431e4351130e3963183be7dcad78e4a4531cf9d3ec2c`.

Six user files total8,590,196,754 logical bytes, including8,589,934,593 bytes
in the large file, plus three user directories. The empty file has0 allocation;
the17-byte file has24-byte subcluster allocation. Large-file allocation is
8,589,938,688 bytes. The canonical13-object input also accounts for root/SVI
and its system files; these are pending rather than claimed reconstructed.
Both construction and observation issued zero user-payload read/write calls.
Stored descriptors independently confirm SYSTEM owner/group and one protected
SYSTEM full-access ACE for all six files and three user directories.

The NTFS source remained offline/read-only. This establishes allocation-only
user namespace staging, not payload contents, stored-validity after reboot,
source admission, metadata restoration or conversion of the original partition.
No unit tests were added or run. Evidence is under
`.lab/hyperv/streaming-v2-20261027/private-tree-allocation-20261028`.

## Storage observation and preservation

After clean shutdown the new shadow child used140,509,184 filesystem storage
bytes (134 MiB), despite the8-GiB logical file. The metadata-only Rust observer
uses [GetCompressedFileSizeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew)
and checks stable file identity/length/time. Here the child is non-sparse and its
file length equals the reported storage size. This includes the child's format
and allocation work, excludes shared parent images/OS/journal/evidence, and is
not a total scratch bound or physical-device I/O measurement. Parent-independent
construction and a complete required-byte capture remain unproven.

OFF checkpoint`ebb2feb4-dc0f-4551-93ee-9a031f96b7ca`, parent
`524c530e-2f6e-4ff6-849d-3bf7a9af71bf`, preserves this state. All18 earlier
checkpoints remain (19 total), including converted candidate12. The VM was
cleanly stopped and its4-GiB RAM released before returning to candidate12's
already-authorized acceptance sequence. Do not redispatch either template task.
