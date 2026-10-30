# 0.0.1 release readiness — 2026-10-29

## Update — 2026-10-30

The reference-aware native-shadow build at `156241e` has now converted the
independently populated mixed fixture: 808 user files, 120 directories and
9.9 GB of data. Native exit was zero, final handoff closed, and native
verification accepted 933 objects and 811 complete file hashes. The outer
wrapper failed afterward on its obsolete 4 MiB JSON limit; the complete
22.9 MB report was preserved and accepted by the bounded archive observer.
See [the recorded result](../evidence/payload-reference-native-mixed-20261030.json).

The journal used 13.71 GB and the packed backing 1.18 GB. This clears the
previous mixed-tree storage refusal, but the run took about 25 minutes, so
it does not establish superior runtime performance. Exact-build mutation,
reboot, and independent recovery remain outstanding. Existing recovery
harnesses need mixed-fixture counts and capacity settings. A copied-payload
interruption would begin at write 6,135, beyond this build's 4,096-write fault
hook limit; that stronger test requires a new pinned build. A completed HND
journal must never be used to roll back the operational ReFS volume.
The [exact-build gate assessment](../evidence/payload-reference-native-gates-20261030.json)
records the remaining harness changes and evidence requirements. No new
mutation, reboot or recovery experiment was started during the archive review.

The sections below preserve earlier milestone observations and their original
qualification scope; their old "not wired" statements are historical.

The revised validation build `9099110` now stops after the first actual copied
payload write rather than relying on a numeric count. It passed that controlled
interruption, a reboot and public resume (933 objects/811 hashes), mutation and
cold reboot (808 originals, two retained test files and 128 entries), and
independent public rollback from the same interrupted checkpoint. After
rollback, all 808 user-file SHA-256 hashes and 120 directory names matched.
See [the exact-build matrix](../evidence/revised-copy-validation-20261030.json).
The original build's result remains separate. These tests do not establish
physical power-loss safety, arbitrary-volume compatibility, maximum performance,
or an uninterrupted public conversion on the revised binary.

Status: **not ready as "stable" or "maximum performance".** No 0.0.1 tag, version
bump or release was created. `Cargo.toml` is `0.1.0`; the existing tags are
`alpha-native-shadow-20261026` and `alpha-native-shadow-20261029-fb5548`.

## What exists and may be described

The frozen experimental Windows x64 executable
(`fb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c`,
[package notes](frozen-drive-alpha-20261029.md)) converted one 52 GiB
NTFS 64 KiB-cluster data partition to ReFS 4 KiB through the public
`--drive F --partition 2` command, and survived ordinary mutation, reboot, one
controlled interruption, public resume, and public rollback. Scope: one fixture,
one Windows build, disposable data volumes, no boot volume.

## What it cannot claim

| Claim | Evidence |
|---|---|
| Stable | One fixture; other sizes, builds and features unqualified; physical power loss untested. |
| Quick | The conversion took about 55m52s (terminal-observed, includes observation overhead) and read almost 1 TB, on the order of 18 volume-sized passes. Most bytes were a zero-filled file, so this is not payload-independent. |
| Maximum performance | The converter reads whole images. The later read/hash optimizations are now measured once end to end (below): 16.1% faster, still at least 816.6 GB read for a 52 GiB volume. |
| Reproducible | The frozen build included an uncommitted `src/main.rs` edit; no clean tree or reproducible build is claimed. A clean-tree 0.0.1 would be a different binary and would not inherit the alpha's qualification. |

## Measured HEAD build

The sealed HEAD build (`da13331`, public CLI `fa4ab753…`, launched by
`lab/Start-HeadDriveMeasurement.ps1`) converted the same fixture through the same
public command: native and task exit 0, HND, 15 native objects with 10 complete
hashes, label and mount verified, F: now ReFS 4 KiB. See
[the receipt](../evidence/head-drive-measurement-20261029.json).

| Measure (same method for both) | Frozen `fb5548` | HEAD `da13331` |
|---|---:|---:|
| Process start to exit | 3,351.7 s (55m52s) | 2,813.3 s (46m53s) |
| Verify-target phase | 1,686 s | 1,048 s |
| Journal-preparation phase | 530 s | 634 s |
| Bytes read, last sample | ≥ 996.1 GB (58 s before exit) | ≥ 816.6 GB (104 s before exit) |
| Bytes written | 285.7 MB | 285.7 MB |

HEAD's exact read total was not observed; it is at most 862.3 GB if its last
104 s never exceeded the fastest sampled rate (441 MB/s). The gain is almost
entirely the shorter target verification; journal preparation got slower. One
run per build on a shared host is not a benchmark distribution. This HEAD binary
has no mutation, reboot or interruption/resume/rollback results of its own.

### Where HEAD's reads go

Bytes read per CLI phase, interpolated from process I/O samples about 2 minutes
apart (approximate):

| Phase | Seconds | Read | 52 GiB volumes |
|---|---:|---:|---:|
| Inspect and build ReFS metadata | 430 | 134 GB | 2.4 |
| Verify target | 1,048 | 346 GB | 6.2 |
| Prepare journal | 634 | 177 GB | 3.2 |
| Apply | 294 | 111 GB | 2.0 |
| Verify files | 401 | ≥ 47 GB | ≥ 0.8 |

The verify-target phase (`general_composite_target::verify_and_capture`) makes
about six volume-sized reads: the protected native observation is bracketed by two
complete shadow hashes (`general_target_preservation::bracket_image_with_resource_profile`),
the complete difference capture reads the source plus a source-backed candidate,
the shadow is hashed again, and the final pair hash reads the source. The
candidate serves payload ranges from the NTFS source streams and only the
remaining ranges from the shadow (`general_shadow::source_backed`), so the
capture does not read the shadow's payload placeholders.

That rules out folding a shadow integrity hash into the capture read: the capture
never sees every shadow byte. No consolidation in this phase was found that keeps
every check; the remaining shadow hashes are deliberate freshness checks on a
persistently frozen device and are not removed. The dominant cost, about 15
volume reads in total, only goes away with the selective path.

## Allocation-bounded mode (experimental)

Under the user-chosen ntfs2btrfs-style guarantee, the hidden
`--experimental-allocation-bounded` mode converted the same fixture in 952.9 s
(15m53s) with at least 295.0 GB read, against 2,813.3 s and at least 816.6 GB for
the whole-image HEAD build: same 15 objects / 10 hashes, label and mount
verified. See [the receipt](../evidence/allocation-bounded-conversion-20261029.json)
and [the plan](selective-conversion-plan.md). Since then, one controlled
interruption, a restart, and both public `--recover` directions from the same
interrupted state passed: resume to ReFS (15 objects / 10 hashes) and rollback to
NTFS (7/7 user file hashes). See
[the recovery receipt](../evidence/allocation-bounded-recovery-matrix-20261029.json).
A second conversion (772.8 s) then passed an ordinary mutation workload and a
clean restart: 7/7 original user files, both new files and 128 entries verified
after the restart, no ReFS warnings or errors logged. See
[the mutation receipt](../evidence/allocation-bounded-mutation-restart-20261029.json).
It is still not release-ready: other interruption points and physical power loss
are untested, it is one fixture on one Windows build, and the mode sits behind a
hidden experimental flag.

## Where the performance work stands

Selective capture is the route to a large speedup. Done so far, all read-only or
ordinary-file, none wired to the drive command:

- Metadata-driven footprint reader for ReFS (both checkpoint generations, log
  area, indexed data extents). On the research image it needs about 2.4 MB of reads.
- Native allocation observation through a protected read-only mount. On the
  converted 52 GiB volume the required union is 14.77 GB (26.5% of the partition)
  with 3.8 MB of collection reads; see
  [the receipt](../evidence/native-required-ownership-protected-readonly-20261029.json).
- Selected-range journal core plus `changed_plan`, which journals only differing
  4 KiB granules ([receipt](../evidence/selected-journal-changed-plan-20261029.json)).

Missing: a complete and authenticated footprint (opaque leaf references, stream
inventory, refcount ownership), binding the journal to an actual device,
exclusion and write policy, source admission, recovery-bundle versioning, and a
native run. A speedup figure for the selective path would be a projection until
that run exists; none is claimed here.

## Order of work to a defensible 0.0.1

1. Finish and qualify the selective path on the lab VM.
2. Measure end-to-end time and bytes read on the final build, against the 55m52s
   baseline and the 46m53s HEAD measurement above.
3. Build from a clean committed tree and re-run the interruption, resume and
   rollback matrix on that exact binary.
4. Only then set the version, tag, and publish with the qualified scope stated.

If an earlier, honestly labeled release is wanted, the defensible form is the
existing frozen alpha re-announced as an experimental pre-release with the scope
above, not a "stable" or "maximum performance" 0.0.1.

## Compatibility research and implementation priorities — 2026-10-30

The comparison below distinguishes a converter's output from a driver's ability
to read source metadata. None of these projects establishes full NTFS-to-ReFS
compatibility. Upstream comparison was refreshed on 2026-10-30. Our native
results cover bounded ordinary files, hard links and file ADS, including their
recorded recovery cases. Source `5aeaf40` subsequently passed a sparse-file/ADS
conversion, cold boot, controlled interruption, public resume and independent
rollback. Sparse mutation remains pending. Reparse points, compressed/encrypted files, arbitrary
security descriptors, short-name aliases and boot conversion remain outside
that evidence. The research-only refresh is separate from the later native run.

| Project and pinned source | Actual role and preservation boundary |
|---|---|
| [ntfs2btrfs `433523ab`](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/README.md) | NTFS-to-Btrfs converter. Documents files/directories, security descriptors, reparse points, bounded ADS, DOS attributes and WSL metadata; compression/sparse handling appears in its changelog. Also documents unsupported EFS, old Windows EAs, case-sensitivity flags, ADS above its xattr capacity and clusters above 1 MiB. Its Windows command cannot convert the running boot/pagefile volume; Quibble boot is a separate project. |
| [btrfs-convert manual](https://btrfs.readthedocs.io/en/latest/btrfs-convert.html), [source `afdc3a65`](https://github.com/kdave/btrfs-progs/blob/afdc3a65e33f4d42f768ad50dca20c32e5ee1496/convert/source-ext2.c) | Converts ext2/3/4 and optional ReiserFS; NTFS is delegated to ntfs2btrfs. Reuses original extents and source free space. Preserves supported POSIX metadata/xattrs/ACLs, inode links and symlinks, subject to limits; oversized xattrs can be skipped and `--no-xattr` explicitly discards xattrs/ACLs. Requires a clean source and supported block size. This is not Windows security or ADS conversion support. |
| [fstransform `efc51973`](https://github.com/cosmos72/fstransform/blob/efc519736069b6808f1c0fe74e810626732d5799/README.md) | Linux file-copy/move into a sparse loop filesystem followed by physical remapping; tested ext2/3/4, JFS, ReiserFS and XFS. README excludes NTFS/FAT/exFAT. Its [launcher](https://github.com/cosmos72/fstransform/blob/efc519736069b6808f1c0fe74e810626732d5799/fstransform/fstransform-sh#L50-L54) contains experimental NTFS plumbing but records I/O errors and poor FUSE performance. This is not supported full-NTFS conversion. |
| [NTFS-3G manual](https://github.com/tuxera/ntfs-3g/wiki/Manual), [attribute reader `7f0f841f`](https://github.com/tuxera/ntfs-3g/blob/7f0f841fc52cf719106c5c93bafe465004e36816/libntfs-3g/attrib.c) | NTFS driver/reader oracle, not an NTFS-to-another-filesystem converter. Supports named streams, sparse/compressed logical reads and hard links; follows attribute lists into extension MFT records. These abilities do not prove that another target preserves their semantics. |

ntfs2btrfs is deliberately less strict than the preservation contract we should
claim. Its [pinned converter source](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp)
can skip encrypted files, encrypted/compressed ADS and ADS that exceed name or
item limits. ADS occupy xattrs: their actual size ceiling is below 16 KiB after
leaf/name overhead, and the complete `user.<name>` must fit 255 bytes. It omits
DOS-only names and truncates filenames exceeding 255 UTF-8 bytes, with a collision
FIXME. Oversized legacy security descriptors have a skip path. Its hard-link
output uses one inode and multiple namespace links. Relative Windows/LX symlinks
are translated; other file reparse buffers become file contents, while directory
reparse buffers become `user.reparse`. Keeping those bytes is not universal
native reparse behavior. NTFS compression/WOF decoding and sparse/VDL handling
exist. Its
[attribute iterator](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2.cpp)
follows attribute-list records. Reuse the identity/extent design, not its
warning-and-skip policy: a conversion reporting success must preserve every
admitted user object or refuse before source writes.

The [ntfs2btrfs manual](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/ntfs2btrfs.8.in)
also qualifies rollback: it restores conversion-time NTFS state, discards later
changes, and requires the preserved image and unchanged extent layout. The
btrfs-convert manual likewise warns that balance can prevent rollback. Neither
is a precedent for unlimited rollback after target filesystem use.

NTFS-3G's [internal metadata interfaces](https://github.com/tuxera/ntfs-3g/wiki/Using-Extended-Attributes)
are useful inventory references: raw owner/group/DACL/SACL, reparse data, EAs,
Object IDs and EFS backup data are separate from ordinary file bytes. Standard
copy tools do not enumerate these internal attributes by default. EFS raw mode
is ciphertext-plus-metadata backup, not automatic decryption. The documented
short-name interface discontinues operations on hard-linked files; four times
are readable but only the first three are settable through that interface.

Current Rust conversion boundaries, confirmed in source:

| Source feature | Current admission/construction behavior |
|---|---|
| Ordinary unnamed data | Resident/empty files, fragmented plain extents and partial/uninitialized tails have semantic materialization/retention paths; mixed-fixture conversion is recorded separately above. |
| Hard links and DOS-only aliases | Ordinary hard links now share one canonical payload object plus additional names. The bounded native result below verifies three names per file; hard-link files requiring unsupported attribute-list assembly remain refused. DOS-only aliases remain refused. |
| ADS and directory streams | Ordinary file ADS now use one canonical file plus per-stream names, mappings, lengths and hashes. Native tests cover five ADS through hard links, including empty, Unicode and 2 MiB data. Directory and System Volume Information ADS remain refused; the existing limit is64 streams per file. |
| Sparse files and sparse file ADS | Source island/hole/VDL modeling and native dense-carrier construction passed bounded conversion, cold boot and controlled first-write resume/rollback on `5aeaf40`. This includes an all-hole file, sparse ADS, hard-link alias and partial EOF. Mutation and arbitrary sparse layouts are not qualified. |
| NTFS compression, WOF, EFS | Compression/encryption flags and WOF reparse semantics remain refused. Compressed content needs logical decoding and rewritten extents. EFS needs a separate encryption-preservation path. |
| Reparse points and Windows EAs | Outside the admitted attribute whitelist; no target preservation claim. |
| ACLs | Owner/group/present DACL plus observed API/kernel views are represented. Construction requires absent SACL; even a present empty SACL is outside this profile. Missing/null DACL is also outside the construction profile. |
| Attribute lists | Versioned assembly supports ordinary hard links, named streams and resident metadata in owned extension records. A schema-5 file with seven extensions, three names and three streams passed native conversion and reboot. Directory, encoded/sparse DATA assembly and lists needing their own continuation remain refused. Schema-6 combinations still need native coverage. |
| Object IDs, quotas, transaction state | User Object IDs/nondefault quotas remain refused. Recognized filesystem-internal state has narrowly bound replacement policies, not user-semantic preservation. |
| Times and names | Four stored times are represented. Names preserve supported UTF-16 spelling, but reserved Win32 names, trailing dot/space, invalid characters and conservative case collisions are refused. Case-sensitive NT namespaces are not fully supported. |
| Geometry and resource limits | Depth is capped at 16, streaming profile at 1,024 files/256 directories, with 64 streams/file and 16,384 streams/tree. Source geometry requires 512-byte sectors, 1,024-byte file records and 4 KiB indexes; experimental cluster admission extends from 4 KiB to 2 MiB. Target is 4 KiB ReFS 3.14. The 16 GiB journal limit remains. Parser/address bounds are not capacity qualification. |
| Boot | Public drive selection rejects the running Windows partition. Boot conversion is unqualified. |

Relevant implementations are [admission](../src/ntfs_admission.rs),
[canonical tree](../src/shadow_tree.rs), [stream planning](../src/ntfs_stream_plan.rs)
and [internal replacement](../src/ntfs_internal.rs). Fixed resource caps remain
implementation restrictions, despite the intended resource-bounded scale design.

The hard-link follow-up on source `7b1c8df` converted an independently created
NTFS4KiB partition through the public CLI, preserving three user-file identities
and nine names (ordinary, resident-sized and empty files; nested Unicode aliases).
Native ReFS verified six alias identity/link-count snapshots. After a cold boot,
all nine hashes and IDs remained correct; a write through one alias was visible
through the other names, and restoring the byte through another name recovered
the original hashes. The run took16.658s for this small fixture and relocated its
payload; it is not a large-volume performance measurement. See
[the recorded native result](../evidence/hardlink-native-conversion-20261030.json).
The same converter source/public binary subsequently passed a controlled first
flushed-write interruption, restart and public resume, plus independent public
rollback from the same interrupted checkpoint. Each direction preserved all
nine paths, hashes and link groups; rollback also recovered the original NTFS
file IDs. This qualifies the bounded recovery case, not physical power loss or
arbitrary feature combinations. See
[the recovery matrix](../evidence/hardlink-native-recovery-20261030.json).
The first attempt exposed and led to removal of an unnecessary requirement for
the source to contain `IndexerVolumeGuid`; absence is now preserved explicitly.
Source `3ba75be` subsequently connected named-stream range reads, canonical
stream identities, native allocation/placement and mounted verification. Its
public conversion preserved five ADS across three hard-linked files, including
an empty stream, a Unicode name, a literal `$DATA` name and 2 MiB+19 bytes of
content. The 15 alias/stream views and all nine default paths matched. Cold-boot
checks and a named-stream write through one alias, followed by restoration
through another, passed without changing the default streams. The source still
uses bounded resources. See [the native ADS result](../evidence/ads-native-conversion-20261030.json).
The same ADS converter subsequently passed first-flushed-write interruption,
restart, public resume and separate public rollback from the original AP
journal. Both directions preserved all nine paths and15 named-stream views;
rollback also recovered the original NTFS identities. See
[the ADS recovery matrix](../evidence/ads-native-recovery-20261030.json).

A separate native sparse experiment now establishes the carrier approach:
clone initialized ranges from a nonsparse carrier into sparse logical offsets,
then retire the carrier through the filesystem. The256MiB test retained32KiB
of mapped ranges (16KiB shared data), valid cloned contents and zero-hole
samples after carrier deletion. Payload writes were64 bytes; metadata and
scratch-volume overhead are separate. This is a primitive proof, not yet
sparse NTFS conversion. See [the native sparse-carrier evidence](../evidence/sparse-carrier-native-20261030.json).

Source `5aeaf40` then completed public conversion of the sparse fixture with
12 canonical objects, 8 default and 6 named stream hashes, and 3 exact sparse
allocation/storage-validity observations. Independent mounted reads matched
all 4 sparse paths plus the old hard-link/ADS fixture. Cold boot preserved
contents, sparse flags, extent listings and file IDs. The original wrapper's
10-object assumption rejected two additional admitted SVI files after native
success; a corrected read-only observation verified the complete expectation.
The 16.651-second runtime is only this small fixture. Journal plus packed backing
used81,408,000 bytes. See [the scoped result](../evidence/sparse-native-conversion-20261030.json).

The same runtime then passed a controlled first-flushed-write stop, guest
restart with the partial source still offline, public resume and independent
NTFS rollback from the original interrupted checkpoint. Both directions verified
the old9names/15ADS views and4sparse paths; rollback restored the original file
IDs and exact sparse mappings. See [the recovery matrix](../evidence/sparse-native-recovery-20261030.json).
This does not establish physical power-loss or arbitrary failure-point safety.

The attribute-list follow-up on `4c58d38` passed native conversion and cold boot
for a file assembled from seven extensions. Its two 2 MiB streams retained all
1,024 physical extents; all three streams matched through three hard-link names.
The surrounding tree verified13 objects/9 default/8 named hashes and3 sparse
layouts. The run took138.754 seconds for this intentionally fragmented fixture;
there is no valid speed comparison against earlier failed builds. See
[the evidence](../evidence/attribute-list-native-conversion-20261030.json).

Source `940f4e2` then converted the same NTFS checkpoint in 92.959 s compared
with 138.754 s on `4c58d38`, a 33.0% reduction in this single VM fixture. All
13 objects/9 default/8 named hashes, 3 sparse layouts and 1,024 original payload
extents matched. Movement/phase counts also matched. The change reuses opaque
first-page evidence and immutable phase planners; complete native acquisition
and per-move checks remain. It reduces repeated CPU work, with no measured
physical-I/O reduction. See [the scoped comparison](../evidence/bitmap-planning-performance-20261030.json).
Reboot, mutation and recovery coverage for this exact build remain pending.

Continue in concrete slices: (1) address large-volume bitmap acquisition and
remaining fixed resource limits; (2) qualify sparse mutation and broader
extension-record forms, which expands practical fragmentation, link and stream coverage;
(3) preserve SACL/null/empty security distinctions and native reparse/EAs;
(4) materialize compressed/WOF logical content with exact space forecasts;
(5) expand geometry and remove coupled fixed caps with bounded working memory.
File ADS already exceed ntfs2btrfs's documented size limit in our 2 MiB native
fixture, but directory ADS and broader combinations still need implementation.
Each slice needs a small native feature fixture and resume/rollback coverage on its exact
binary, without restarting the writer or adding another broad unit-test campaign.
Short names, Object IDs, quotas, EFS and boot require an explicit target-version
capability/preservation policy before admission changes; a sidecar is not native
semantic equivalence. Keep unsupported features as pre-write refusals until the
corresponding preservation path exists.

The [Microsoft ReFS feature comparison](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview#feature-comparison)
lists named streams, hard links, sparse files, EAs, reparse points and ACLs as
target capabilities, so those are implementation gaps rather than a reason to
drop their source data. It lists transactions, Object IDs, short names and quotas
as unavailable on ReFS, with a short-name simulation caveat; EFS availability is
limited to Server 2025 in that table. These are target-version boundaries, not
permission to infer support from the format number or discard metadata. The
running Windows boot/pagefile exclusion and experimental boot feasibility remain
separate from Microsoft's supported boot configuration.
