# 0.0.1 release readiness — 2026-10-29

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
It is still not release-ready: other interruption points, physical power loss,
and mutation/reboot of the converted volume are untested, and it is one fixture.

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
