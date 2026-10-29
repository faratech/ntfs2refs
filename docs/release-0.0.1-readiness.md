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
| Maximum performance | The converter reads whole images. Later commits (`7e318ce`, `541f76f`, `46e0dcc`, `7f6d93e`, `a4419ca`) remove redundant reads and parallelize hashing, but no end-to-end native time was measured for them. The only throughput figure is an in-memory hashing benchmark that is explicitly not a storage measurement. |
| Reproducible | The frozen build included an uncommitted `src/main.rs` edit; no clean tree or reproducible build is claimed. A clean-tree 0.0.1 would be a different binary and would not inherit the alpha's qualification. |

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
   baseline above.
3. Build from a clean committed tree and re-run the interruption, resume and
   rollback matrix on that exact binary.
4. Only then set the version, tag, and publish with the qualified scope stated.

If an earlier, honestly labeled release is wanted, the defensible form is the
existing frozen alpha re-announced as an experimental pre-release with the scope
above, not a "stable" or "maximum performance" 0.0.1.
