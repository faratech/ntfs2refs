# Strict existing-extent adoption experiment

This standalone research harness is original adapter code for the external
`ages2001/REFSNT` engine pinned at
`bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a`. The GPL-3.0 engine remains in
ignored `.lab/research/refsnt`; no engine implementation is copied here or
linked into the Rust product. A linked research executable combines this
adapter with that GPL engine; it is not a product distribution artifact.

`build.ps1` checks the exact upstream revision and clean checkout, builds into
a new ignored directory, and records source/executable hashes. It never
installs a driver, opens a volume, or mounts an image.

`backend-contract.exe NEW_DIRECTORY` checks only fresh 1 MiB ordinary files:
sharing denial; successful write/flush/readback/reopen; payload blacklist;
bounds and short-read failure without zero filling; changed length refusal;
and wrong input hash refusal. Six cases passed without invoking the engine.

The backend accepts only a local, exclusive regular file whose name ends in
`refs.adopt-test.raw`. It requires the exact file length and complete input
SHA-256 before enabling engine writes. Reads cannot zero-fill short I/O.
Writes are bounded, sector-aligned, traced before execution, read back, and
refused if they overlap the protected pre-existing payload. Every engine flush
calls `FlushFileBuffers` on the actual image, followed by a durable trace
record. Identity, length, regular-file type and link count are checked again.
I/O failures poison future writes. There is no device/raw-volume mode.

Invocation:

```text
adopt-existing.exe IMAGE\refs.adopt-test.raw BYTES IMAGE_SHA256 PLCN CLUSTERS PAYLOAD_SHA256 TRACE.jsonl RESULT.json
```

Use only a newly made disposable copy of a Windows-formatted ReFS 3.14/4 KiB
**raw partition** image. The harness does not clone, seed, format or select a
payload. Before invoking it, independently prove the requested physical range
is free of live metadata/data across allocator tiers; optionally place a known
source payload into that independently free range while the image is offline,
then hash the resulting entire before-image and payload. Existing overlay
research used LCN 10,243 for one cluster; that observation is not an ownership
guarantee for a different image or a larger range.

The experiment reserves exactly `[PLCN, PLCN+CLUSTERS)` with `RfsAllocIn` and
requires its returned position/count to match. It verifies contiguous virtual
translation, creates an empty file, calls `RfsFileAdopt`, commits and flushes,
then discards engine caches and mounts read-only through the engine. Every
logical cluster must map back to the requested physical range and logical
reads must hash to the original protected bytes. The I/O layer prevents any
engine payload rewrite. Allocation refusal is evidence; the harness never
changes allocator bits behind the engine's back.

A zero result is only an offline mechanism result. The next gate is independent
Rust/forefst decoding, full allocation/reference reconciliation and a native
Windows read/mutation/remount test on a disposable virtual disk. No native mount
or crash-consistency qualification is claimed by this harness. The external
trace contains old/new hashes rather than a rollback payload; the disposable
before-image must remain available separately. Failed/partial images must not
be mounted as successful output.

## Recorded ordinary-file run

The strict harness completed one offline adoption at physical LCN 10,243 for
one 4 KiB cluster in a disposable sparse copy of the archived Windows image.
The exact requested allocator position/count were returned. After commit and
real image flushes, a cache-discard/read-only engine remount recovered the same
physical mapping and logical bytes. There were eight host writes totaling
131,072 bytes, three successful image flushes and no attempted payload writes.
Payload before/after/logical SHA-256 all equal
`6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786`.
This is not native `refs.sys` qualification.

Ignored evidence:

- Build/provenance/contracts: `.lab/research/refsnt-strict-20261025T211214103Z`.
- Image/copy/result/trace: `.lab/research/strict-adoption-image-81714d11aed444deab9fed82436e551c`.
- Repeated independent Medium/Small precheck:
  `.lab/research/refsnt-adoption-precheck-761a3d000c9d45d981e7f60ff4434778`.

The sparse copier scanned and hashed all 55,834,574,848 source bytes, preserved
the captured full-image hash
`805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9`,
and wrote/allocated 66,060,288 bytes while checking at least 64 GiB host free
space. During the later adoption experiment, reported D free space dropped
from roughly 88 GiB to roughly 35 GiB, although the sparse flag/range queries
still indicate about 66 MiB allocation. The cause is unproven. These sparse
figures alone must not be treated as a reliable host-capacity estimate, and no
further large-image allocations were made after the discrepancy was observed.

The eight final changed ranges were preserved in `final-metadata.cow`
(131,280 bytes, SHA-256
`d25e7b8ec70256a47159a30c78b436ffcd525c00fc4ec4c34f1a533c6feb7eaf`).
Each range matches the traced new hash. The existing independent Rust overlay
auditor accepted the resulting ReFS bootstrap and confirmed the untouched
payload. That small overlay can reproduce the final metadata over the archived
base without retaining a second full raw image.

Automatic tool review rejected the combined evidence/reduction/deletion
command with `blocked by policy` and no detailed reason. That command did not
run; deletion was not retried through another route. Non-destructive overlay
preservation succeeded separately. After the user explicitly authorized
deletion of this exact disposable image, a checked literal-path deletion was
attempted again. Automatic approval review again rejected it before execution
with only `blocked by policy`. The raw image remains in place, as do the
unchanged source archive and VM/checkpoint files. The preserved overlay and
result hashes were rechecked before that attempt.
