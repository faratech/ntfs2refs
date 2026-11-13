# Selected-range journal core

`selected_journal` is the reconstruction core used by the allocation-bounded
drive conversion path. It operates on caller-owned `ReadSeek`/`DurableIo` handles and opens no
devices. The caller must supply an authenticated required write set, exact
device/storage binding, exclusion, native write policy and independently held
trusted ticket. A plan or ticket is not a source certificate.

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

## Zero-payload storage (2026-10-30)

The allocation-bounded capture now distinguishes changed bytes from physically
stored backing bytes. It splits ranges at zero/literal boundaries, records every
changed zero range in its version-2 layout, and omits only its stored payload.
`DifferenceImage` synthesizes those zeros. Required zero ranges remain selected
and are still written to the target; this does not skip the ReFS reserved zone.

When the pinned plan contains `new_zero_ranges`, the journal uses `N2RZERO1`
with 88-byte records. Each zero entry must exactly match a selected range, and
preparation verifies the actual candidate bytes. Every old byte remains in the
journal. New zero bytes are synthesized during validation, apply and recovery.
The exact journal length is:

```text
8192 + 80 + 88 * range_count
  + 2 * selected_bytes - new_zero_bytes + 80
```

An empty zero map preserves the `N2RSEL01` encoding. The recovery bundle pins the
plan (including the zero map) and ticket. Both codecs preserve the existing
intent, readback and handoff/abort rules. This is not the proposed staged
`N2RSEL02-H` protocol: it introduces no in-volume recovery dependency or new
rollback guarantee.

Native encoded-journal arming checks the exact journal length against the
storage profile instead of assuming two payload copies per changed byte. The
legacy arming path is unchanged. Exact plan sizing and a fresh free-space check
precede journal creation and source activation. The existing 16 GiB native
journal ceiling still applies; this change does not claim unbounded capacity.

The [owned-file integration](../evidence/zero-payload-journal-20261030.json)
stored 16 KiB of selected changes using a 29,096-byte journal versus 41,360
bytes with the legacy format. It omitted 12 KiB of new zero payload and retained
all old bytes. Short-write resume/rollback and false-zero rejection passed;
the legacy output matched the preserved journals byte for byte. This result
does not establish native-volume or physical power-loss qualification.

The [native conversion observation](../evidence/zero-payload-native-20261030.json)
then passed the public drive conversion on the 52 GiB fixture: 15 objects and
10 full file hashes, label/mount preserved, N2RZERO1 and closed HND. It stored
2,887,680 bytes of packed payload and 73,559,152 bytes of journal. Dense storage
of the same selected changes would require 211,965,696 bytes combined; the
encoded representation requires 76,446,832 bytes (about 64% less). The run took
60.82 seconds, so this establishes storage reduction, not a timing improvement.
The same662f4ae build subsequently passed controlled one-write interruption,
guest restart, public resume to ReFS15 objects/10 hashes and an independent
public rollback to NTFS with7/7 user-file hashes matching. Both directions
started from the same interrupted snapshot; see the
[native recovery record](../evidence/zero-payload-recovery-20261030.json).
Mutation/reboot and physical power loss on this build remain unverified. The
initial pre-activation capacity-query refusal is retained in the conversion
evidence record. These native results do not qualify later loader changes.

## Single-pass journal authentication

The loader computes the immutable journal SHA-256 while parsing the header,
records, literal payloads and footer. It also verifies every per-range and
framed digest before returning any record to an execution path. Synthesized
zeros contribute only to the logical digests. Each lifecycle boundary still
performs its required fresh verification; this removes the duplicate read
within that verification, not the boundary itself.

The [focused integration](../evidence/journal-single-pass-20261030.json) observed
41,360 instead of 74,528 bytes read for one legacy lifecycle check, and 29,096
instead of 50,000 bytes for the zero encoding. All four completed journals
matched the preserved earlier bytes, with interrupted resume and rollback
passing. This is a journal I/O result, not a native end-to-end speed claim.

## Journal-old payload references

`N2RCPY01` adds 96-byte records whose new contents may refer to immutable old
payloads elsewhere in the same journal. Every original selected byte is still
stored. Copy origins must be aligned and completely covered by the selected
write ranges; references never follow a new value or consult the changed
device during replay. Preparation compares each proposed copy against the
actual frozen source. Loading authenticates stored payloads before resolving
the copies and verifying the complete new selected digest.

The native capture derives possible copies from the admitted NTFS stream
inventory and protected ReFS routes. It clips them to initialized whole
clusters and emits a reference only when its origin is already part of the
captured changed set. It compares the raw origin with the logical candidate
before omitting that payload. Other ranges retain literal or zero encoding.

The version-3 backing layout reconstructs references from the frozen original
only during preparation. Activated-target paired views reject this layout;
recovery uses the self-contained journal instead. These are not the staged
in-volume rollback references proposed in the hybrid design.

The exact journal size is:

```text
8192 + 80 + 96 * range_count
  + 2 * selected_bytes - new_zero_bytes - new_copy_bytes + 80
```

The [ordinary-file integration](../evidence/payload-reference-integration-20261030.json)
includes forward and backward copies spanning old records, overwritten
origins, interruption, resume, rollback, and rejection of an incorrect copy.
It used 58,176 journal bytes instead of 82,640. Earlier journal encodings
remained byte-identical. Native results must be established separately.
