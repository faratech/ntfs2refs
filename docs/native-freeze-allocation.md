# Allocation observations across native ReFS freeze

`GeneralFrozenPartition::isolate_with_allocation(binding, events)` returns a
read-only frozen partition and a `GeneralAllocationFreezeWitness`. This is an
optional observation path. Existing `isolate()` and the public conversion
workflow retain their previous behavior.

The new path validates the dedicated data-disk identity and volume extent,
checks ReFS through the retained volume handle, locks the volume, and requires
an explicit successful flush. Only then does it query complete legacy and
metadata-inclusive `FSCTL_GET_VOLUME_BITMAP` responses through that same
handle. Either required query failing, returning partial coverage, or exceeding
the bounded profile prevents a successful witness.

After dismount, the path attempts a second bitmap pair through the retained
handle. This is diagnostic: its failure remains explicit in
`post_dismount_error`, and its successful result is labeled `post-dismount`.
The disk then becomes persistently offline and read-only. Device identity,
geometry and attributes are checked again through the reopened read-only disk
handle before returning.

Neither bitmap phase proves that its allocation map equals the final frozen
metadata graph. The serialized witness explicitly records
`post_lock_equals_frozen_graph: false` and `raw_write_authority: false`.
Independent target-preservation work must bind the witness to the raw image
hash and establish any relationship required between the maps and that image.

The opaque witness has no `Deserialize` implementation. It exposes
`binding()`, `post_lock()`, `post_dismount()`, `post_dismount_error()` and
`frozen_state()`. Each snapshot exposes `phase()`, `legacy()` and
`metadata_inclusive()`. The two maps preserve every declared cluster as
allocated ranges, plus the original response SHA-256, cluster counts and
allocated counts. Response lengths are also serialized. Bitmap query events
explicitly end in `-header-only`; their output contains only the actual
response header rather than duplicating the bitmap in JSON.

`frozen.validate_allocation_witness(&witness, events)` checks a private
in-process token, the original binding, and the actual current excluded-device
state. A reopened partition has no token and cannot regain this witness by
loading its JSON. Validation still grants no graph or raw-write authority.

The current profile assumes 4 KiB allocation units and requires bitmap
coverage to equal the whole partition. Each response is bounded to 2 MiB,
including its 16-byte header, so a 64 GiB partition already exceeds this
single-query bound. There is no `ERROR_MORE_DATA` or legacy-only fallback.
Pretty-serialized witnesses are bounded to 8 MiB. Ordinary management-control
and audit-event bounds remain unchanged.

Focused tests cover complete distinct bitmap views, query inputs and phase,
truncated and failed required queries, token/route/state mismatches, and opaque
serialization. These tests perform no disk operations.

## Native refusal on the current Windows profile

The owning-machine `lab-freeze-refs-allocation` probe was run against the
converted twelve-object ReFS data volume. Lock and explicit flush succeeded,
but the post-lock legacy query returned Win32 error 21, `device not ready`.
A second version attempted both views independently, confirming the same
error for the metadata-inclusive query. It produced no allocation witness and
did not continue to persistent exclusion. Closing the lock left the disk
online/writable with its original label. A strict native verification of all
twelve objects then passed.

This rules out assuming that post-lock bitmap queries work on this Windows
build. The optional path remains experimental and fails closed. It is not
used by the public conversion workflow, and no pre-lock-map fallback was
introduced. A frozen-map optimization still needs a different proven capture
contract or complete raw allocation/metadata reconciliation.

Ignored evidence directories are
`.lab/hyperv/freeze-allocation/win11-20261025T224632508Z` and
`.lab/hyperv/freeze-allocation/win11-20261025T225509704Z`. The latter records
both failed controls explicitly. Its `verified.json` SHA-256 is
`8f894ed6cdbe7e1a4190c022ce2a798d5dc8667e0f5932eb7504ec3f101bae9a`.
