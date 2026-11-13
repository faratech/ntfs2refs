# Laboratory reconstruction journal

`src/lab_reconstruct.rs` performs actual writes through caller-owned IO traits.
It has no device opener, formatter or production conversion command. The
ordinary-file tests prove bounded byte reconstruction and recovery behavior,
not ReFS metadata semantics, native storage durability or converted-volume
acceptance. No code from the GPL ntfs2btrfs reference was copied.

The adapter implements `ReadSeek::byte_len()` and `DurableIo::sync_all()`. It must
independently bind the target, shadow and journal, hold exclusive handles, and
keep the physical target persistently offline across errors and restarts.
The source and shadow must be immutable throughout preparation. Successful
`sync_all` is assumed durable; corruption of already-flushed storage is outside
the tested failure model.

`prepare_journal` accepts the retained comparison request, three distinct
storage-identity hashes, an experiment ID and an explicit total journal budget.
The initial profile uses 4096-byte granules, at most 256 MiB of changed granules,
65,536 ranges and a 768 MiB hard journal ceiling. Full source/shadow comparisons
and retained-range hashes are mandatory. A complete journal needs twice the
changed bytes plus its recorded metadata overhead. Budget failure occurs before
journal preparation, and preparation never writes the source or target.

The returned `JournalTicket` binds the complete immutable journal body by SHA-256
and length. **The adapter must save and flush this ticket in independently
trusted storage before calling apply.** A ticket read from an untrusted JSON
file or recomputed from an unknown journal is not authorization. Recovery also
requires a separately observed storage binding matching the ticket. Device
binding, journal placement on external storage and trusted-ticket persistence
are adapter responsibilities.

`inspect_journal(journal, ticket, observed_binding)` validates the complete
immutable body, payload hashes, storage binding and zero handoff barrier using
only `ReadSeek`. It returns the request, exact patch offsets/lengths, total
changed bytes and expected postimage digest for the native adapter's bounded
write permit. The descriptor has no deserializer and is not itself permission
to write; the adapter establishes that policy independently.

The file layout is:

| Region | Contents |
|---|---|
| Bytes 0..4095 | Initially zero; permanent handoff barrier |
| Bytes 4096..8191 | Replaceable operation intent, flushed before target writes |
| Immutable header, 128 bytes | Version, bounded metadata/range/payload lengths and hashes |
| Bounded JSON metadata | Request pins, retained ranges, storage binding and expected postimage hash |
| Each range | 160-byte indexed/hash-chained header, all original bytes, all replacement bytes |
| Completion footer, 128 bytes | Final chain, header binding, exact end offset and checksum |

Integers are little endian. Every payload has a full SHA-256, and the external
ticket additionally pins the entire immutable body. No partially prepared,
truncated or digest-mismatched journal can reach a target write. The mutable
intent is not recovery authority: an interrupted intent may be replaced only
after validating the complete immutable journal and current target again.

`apply` and `resume` are the same idempotent operation. Before either direction,
the core verifies the complete shadow pin and scans the entire target. Within
each patch, every current byte must equal its recorded old or new byte; replacing
those ranges with old bytes must reproduce the pinned whole source hash. This
also protects all retained and unmanaged bytes. Foreign changes stop recovery.

Each operation flushes a journal intent before its first target write, checks
the current range, writes aligned chunks, flushes and verifies readback. A short
target write stops without an unaligned retry. All non-discovery bytes are
flushed before the first 4096 bytes, including the tail of a coalesced range
starting at zero. Discovery then receives its own write/flush boundary. The
completed target must match the whole expected hash: shadow bytes everywhere
except the explicitly retained source ranges, or the exact source for rollback.

`mark_handoff` requires that complete postimage and a target flush. It durably
writes and verifies the separate barrier before the adapter permits the first
writable native mount. **Any nonzero barrier byte, including a torn or invalid
marker, refuses apply, resume and rollback.** This core never clears the marker.
After handoff, recovery requires a separately defined policy; the lab checkpoint
is not an implementation of production post-handoff recovery.

Tests use real ordinary journal/target files and inject write prefixes, short
writes, flush failures, journal truncation/corruption, foreign bytes and damaged
handoff records. A parent test also starts a separate test process to resume and
roll back interrupted operations using only the reopened files and saved ticket.
These checks do not enable any production writer capability flag.

## In-memory NTFS rollback-complete publication faults

`tests/rollback_completion_faults.rs` exercises the actual
`mark_rollback_complete_without_shadow` API with immediately visible memory
buffers and recorded sync calls. It covers every marker write-error prefix
from 0 through 4096 bytes, zero/nonzero short writes followed by failure,
full-write sync failure, and readback error/mismatch armed only after
publication and a successful journal sync. A target-sync failure is also
checked before publication. Failed calls must return errors, leave the target
preimage and immutable journal body unchanged, and preserve target-flush-before-
marker ordering.

Reopening uses new memory handles without injected faults. A zero marker stays
retryable; any nonzero marker blocks normal apply/resume/rollback, including
shadowless rollback. Separate completed-marker inspection accepts only exact
stored ABT bytes with the correct target hash and binding. A full marker left
by an errored publication can pass that separate inspection in this memory
model; this does not establish physical persistence or native mount eligibility.

The existing completed/corrupt-marker tests remain separate. No production
behavior changes or stable/volatile crash model are introduced. Storage
power-loss qualification and repeated native interruptions remain open.

## After-marker durability before writable mount

The three public after-marker paths (NTFS rollback with/without shadow and
ReFS finalization) retain their existing exact image, required-shadow, native
storage/isolation and immutable-journal checks. They now use the same shared
journal guard immediately before their synchronous `bring_online` call:

1. Reobserve the held journal's binding/length and validate the complete pinned
   immutable body, proof scope and exact expected lifecycle marker.
2. Successfully `sync_all` that same exclusively opened journal handle.
3. Reobserve its binding/length and repeat complete journal/marker validation.
4. Only then invoke the existing mount transition, retaining the journal lease.

Partial, foreign and unknown markers are refused before synchronization. Any
sync, readback, binding or content error returns no gate and leaves the target
excluded. The guard issues no journal writes and never clears, rewrites or
repairs a marker. Synchronization requests persistence of existing bytes.
Read-only completed-marker inspection continues to prove readable consistency
only; it is not a durable receipt or mount authority.

Cost: two additional completed-journal validations, four 4 KiB barrier reads
(including each loader's barrier read) and native identity observations. Each
validation rehashes the immutable body and
its per-record payloads using the existing loader (roughly four journal-sized
read passes across the two validations, plus framing/identity reads). The
journal remains capped at 768 MiB. No additional full target/shadow image scan
is added; all existing scans remain. Flush latency is storage-dependent and
unmeasured by this source-only change.

The preserved native fixture remains qualified only for its original tested
binary. Volatile/stable memory tests exercise this new guard's ordering and
failure refusal; they do not establish hardware power-loss behavior or native
acceptance of the new guard.
