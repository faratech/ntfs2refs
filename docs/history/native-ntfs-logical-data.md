# Native logical-stream verification

The paused hashing change at `206a2f9` is now built and tested. This completes
the supported-stream logical-data check; it does not admit an entire source
volume or authorize conversion. Schema-2/3 observations still replay, but lack
the logical-data evidence required by the new source-admission gate.

## Implementation and checks

The existing Rust native collector now emits schema 4. It opens separate data
handles, checks file/volume identity and stream EOF around each read, seeks to
zero for each pass, hashes exactly the declared logical length and probes EOF.
Changed identities/lengths, read failures, early or extra EOF and exhausted
budgets have explicit outcomes without a successful digest. The aggregate
budget includes EOF probes. Metadata handles and their previous queries remain
separate from data handles.

The raw comparator requires exact stream coverage and matching native/raw
hashes, identities, lengths and stable before/after observations. Directories
with no streams require a successful native open and explicit end-of-enumeration
evidence. No failed open is treated as an empty object.

Tests cover resident/default/alternate streams, empty reads, sparse and
uninitialized logical zeroes, partial reads, read/seek failures, early and extra
EOF, changed identity/length, duplicate/missing streams and cumulative budgets.
The raw-reader fixture fills the uninitialized physical tail with `0xdd` and
forbids reading it; the new comparator test independently requires the logical
zero-tail hash and rejects a hash exposing those stale bytes.

Validation: 362 workspace tests pass, five remain ignored, formatting and
clippy with warnings denied pass, and the existing 19 lab guard checks pass.

## Protected native result

Observation `afc7eaa6ab47455eb40db0e4acf71851`, captured on 2026-10-24,
used source run `057cfe705cca456aa3e7c472dedc7dcc` and checkpoint
`c4f58c73-5ca5-4842-bc7b-6e980a8eabd7`. Windows 11 Pro build 26300.9457 ran
the collector inside the owning VM against the existing read-only NTFS corpus.

| Measurement | Result |
| --- | --- |
| Requested identities / successful opens | 36 / 17 |
| Matching logical identities / streams | 16 / 13 |
| Supported fixture objects / streams | All 8 / all 8 |
| Verified logical bytes per pass | 38,863,015 |
| Native file-data bytes read, both passes | 77,726,030 |
| Reserved bytes, including EOF probes | 77,726,056 |
| Read calls / EOF probes | 1,222 / 26 |
| Native conversion writes | 0 |

The complete 1 GiB source hash was unchanged before/after:
`86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727`.
The sparse fixture's 16 MiB logical stream includes holes and an uninitialized
tail; its native hash matches the raw zero interpretation. The resident ADS
also matches. Internal open/query refusals remain visible, so the whole-volume
`all_logical_data_matched` and `conversion_qualified` fields remain false.
Existing security-view and cached timestamp discrepancies are not masked.

Artifacts are retained under ignored
`.lab/hyperv/ntfs-attestation/file-handles-20261024T172811736Z`:

| Artifact | SHA-256 |
| --- | --- |
| Collector binary | `850da27572a24808ba7254749f317d350eea8ab404689aac66b45b6d664e0953` |
| Native report | `c4137a37ebf763a9350330b378cec05c9e8a50e40283b5ce4ca93f93c7d95675` |
| Comparison | `5d5d1d1dbbc481d9af5b7a183fd351c558ee736722f035e9bd128c93a448c56a` |

The source checkpoint and exported evidence are preserved. No additional
checkpoint was created for this capture. The VM was restored to installed-clean,
off at 4 GiB. Only obsolete root `target/debug` artifacts were cleaned; current
builds, release tools, disk images and checkpoints were retained.

Logical read equality is distinct from storage-validity and allocation-ownership
proof. Those remain necessary on the ReFS side. The next converter milestone
combines namespace, allocation, supported security and coherent freeze evidence
into source admission, then converts an existing tree with explicit retained
and relocated ranges and native interruption recovery.
