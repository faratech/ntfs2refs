# Journal-preparation progress

The public conversion writes a bounded `journal-progress.json` diagnostic in
its existing output directory. During `journal-preparation`, the lab collector
returns it as `journalProgress`, separately from `journalBytes` and process I/O
counters. A zero-length journal can therefore show an advancing input scan.

Subphases are `comparing`, `rechecking-source`, `rechecking-shadow`,
`writing-journal`, `verifying-journal` and `complete`. `bytes_scanned` is the
combined source/shadow bytes consumed by the comparison and its two full input
rechecks. `total_scan_bytes` is four times one input length: 208 GiB for two
52 GiB inputs scanned twice. These counters exclude payload copying, journal
validation and all earlier/later conversion reads. They are not a completion
percentage, throughput result, or execution authority.

`elapsed_ms` is monotonic elapsed time from the core preparation observer's
creation. Updates are limited to one per second, with bounded additional
notifications at subphase changes and completed scan boundaries. Each JSON
snapshot is at most 4 KiB. `complete` describes successful core journal
preparation; subsequent device-identity checks and ticket persistence still
apply.

The sidecar is best-effort and has no storage flush/durability contract. A
telemetry write failure disables that sink and emits one diagnostic; it cannot
hide an input/journal failure or change preparation's result. Readers ignore
missing, partial, oversized or invalid snapshots. Optional terminal export of
the sidecar does not participate in conversion acceptance. Old binaries with
no sidecar remain readable.

Existing core entrypoints retain no-op observers. The observed path keeps the
same sequential reads, seeks, digest updates, retained checks, patch ordering,
journal encoding and durability barriers. In-memory tests compare complete
comparison/patch reports, journal bytes, tickets and I/O order. Independent
pre-change `ceef114` source blobs provide these small-fixture golden pins:

- Comparison JSON SHA-256:
  `62527aaa882d4ae8de63bf6ad4e895be0e0018d0df6b856341bd92270c0c25fb`.
- Journal: 26,102 bytes, SHA-256
  `25bc934cbfb11719fad3ae9c8434b115f048b6253b00d5a2f6f4ea86ef7578af`.
- Immutable body SHA-256:
  `138a579099c2c98d91d456421c88bd82127c48a4485be0c774c7269e0d627368`.

Those pins use a memory backend whose successful `sync_all` is a no-op. They
establish byte compatibility, not physical durability. No native disk test or
speedup qualification is supplied by this source-only change.
