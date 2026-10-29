# Selected-range journal core

`selected_journal` is the reconstruction core for a future selective conversion
path. It operates on caller-owned `ReadSeek`/`DurableIo` handles and opens no
devices. The caller must supply an authenticated required write set, exact
device/storage binding, exclusion, native write policy and independently held
trusted ticket. A plan or ticket is not a source certificate. The drive CLI
does not currently use this core.

Preparation reads only the declared ranges from source and candidate and stores
both versions in a new external journal. It flushes and independently verifies
the immutable journal and every payload before returning a ticket. Hashes of
selected bytes include each range's offset and length. They are never described
as whole-image hashes; unselected contents are not verified by this core.

The separate format begins with `N2RSEL01` and cannot be replayed through the
full-image v1/v2 journal API. A fresh apply requires clear markers and the exact
old selected hash. Resume requires an existing apply intent. Rollback requires
a prior apply or rollback intent. Replay validates the complete journal and
all selected actual bytes before writing. A byte can be either its old or new
value during recovery, allowing a torn target write. Writes are bounded,
flushed and read back, with the discovery granule at offset zero written last.
The final selected hash and immutable journal pin must match before completion.
Durable HND or ABT markers permanently close replay; foreign/torn markers refuse.

The checked journal length is:

```text
8192 marker bytes + 80 header bytes + 80 × range_count
  + 2 × selected_bytes + 80 footer bytes
```

The first format permits at most 65,536 aligned disjoint ranges and streams
payloads through fixed 1 MiB buffers. Geometry and positions use checked u64
arithmetic. Caller-specified selected-byte and journal-byte budgets are enforced.
It journals all selected bytes, including equal bytes, so a caller should not hand it a footprint-sized selection.
`changed_plan` narrows a coarse selection first: it validates the coarse ranges
with the same geometry rules, reads source and candidate once over only those
ranges, and returns a plan holding just the 4 KiB granules that differ (adjacent
ones coalesced). It refuses when nothing differs or the caller's byte or journal
budget is exceeded. The result holds only while both inputs stay unchanged under
the caller's exclusion until the apply completes; the function authenticates
neither the coarse selection nor its completeness. Work depends on the selected
and journal bytes rather than the unselected image length. The core cannot
determine whether a filesystem footprint is complete or detect an external change
to unselected contents.

`lab-selected-journal --directory D:\lab\fresh-directory` creates only its own
ordinary 8 MiB files and two small journals. The I/O adapter rejects every core
image access outside three selected ranges totaling 16 KiB. One persisted short
write is followed by resume/HND and independent rollback/ABT. Both closed journals
reject further replay. Separate handles then compare the selected bytes and ten
outside sentinel blocks. Setup and verification I/O are reported separately.

The same command also plans from a 3 MiB + 64 KiB coarse selection with reads
fenced to those ranges. It found exactly the three differing runs (16,384 bytes,
including one straddling an internal 1 MiB read chunk), read exactly the coarse
bytes from each input with zero denied reads, and needed a 41,360-byte journal
instead of 6,431,040. The pruned plan then applied and handed off, the whole
coarse region matched the candidate, and five outside blocks were unchanged. See
the [planning receipt](../evidence/selected-journal-changed-plan-20261029.json).

The [recorded integration](../evidence/selected-journal-integration-20261029.json)
passed. It is an ordinary-file observation, not Windows device, power-failure,
filesystem-ownership or native conversion qualification. No unit tests were
added or run.
