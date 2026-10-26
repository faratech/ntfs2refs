# Aged allocation-history fixture helper

`lab/guest/Add-AgedRetentionProbe.ps1` prepares a separate retention test on the
enrolled writable NTFS laboratory source. It reserves 8 GiB through ordinary
file allocation at EOF zero, writes and verifies an 8 MiB probe, then removes
only that temporary reservation through its original exclusive handle. It
records native file identities and complete bounded retrieval mappings.

The explicit `-SequentialZeroReservation` mode instead grows a fresh exclusive
reservation with 8,192 sequential ordinary 1 MiB zero writes. It performs no
upfront allocation setter, flushes once, and requires both EOF and allocation
to equal 8 GiB before creating the probe. Its bounded report aggregates the
writes into one operation with attempted/completed counts and actual bytes;
`reservationMode` and `reservationPayloadBytesWritten` distinguish this from
the default allocation-only mode. Both modes use the original DELETE handle
for the same guarded cleanup and preserve files on failure. Account for the
8 GiB initialized temporary write and host backing capacity separately.

A positive placement result requires every probe extent to start at or above
8 GiB relative to the partition. Unsuitable placement is reported explicitly;
the helper never moves source extents or deletes the probe to force success.
Failures preserve the created files and evidence for inspection. Live
conversion/recovery workers prevent execution.

The initial default-mode native run reserved 8 GiB at EOF zero but Windows
placed the probe at LCN 6408 (partition offset 26,247,168), below the threshold.
It reported unsuitable placement, removed only its owned reservation, and kept
the probe. The sequential-zero mode has pure-check coverage; its native run
and subsequent measured conversion remain pending. This synthetic allocation
history can qualify only an aged-layout fixture, not arbitrary source
placement or low-LCN retention.

# Next milestone: one retained NTFS extent under native ReFS metadata

This is a bounded lab design, not a writer or conversion qualification. The
[read-only Rust retained-range comparator](retained-range-comparison.md) supplies
the byte-comparison core. The native fixture, semantic evidence and subsequent
reconstruction executor described here remain unimplemented.

## Decision: correctness before allocation optimizations

The measured allocation/EOF sequence does not produce the proposed
both-zero-VDL, fully physically mapped file. After clean remount it still has
cached validity over 65,536 bytes, storage validity over none, and an unresolved
negative first-cluster marker followed by fifteen positive-LCN clusters.
That profile remains failed. Retaining raw bytes would not expose them as
logical data while the relevant ReFS validity metadata marks them invalid.
[Measured result](native-vdl-observation.md),
[validity implications](sparse-validity-implications.md)

The corrected protected-range run
`protected-range-read/win11-20261024T011607181Z` completed at
2026-10-24 01:17:23 UTC. Both 64 KiB samples matched the known initialized
pattern; protection, fresh-handle after-observations, fixture checks, cleanup,
verified export and restoration to baseline/off/4 GiB completed. The earlier
partial run `win11-20261024T010715182Z` remains incomplete and preserved.
The successful result establishes that bounded sampling lifecycle for the
initialized-placement branch; it neither reserves its free range nor establishes
contents on the separate VDL branch.
[Protected-range result and evidence hashes](native-protected-range-read.md)

Additional invalid-region moves and `SetFileValidData` trials should leave this
milestone's critical path. A fully initialized 64 KiB shadow file already
supplies valid native metadata, at a deliberately tiny payload cost. Whether
shadow generation avoids payload-proportional I/O remains a later efficiency
question; it is not the sole possible route to source-extent preservation.

## Why native copying does not by itself defeat a shadow

`FSCTL_MOVE_FILE` relocates existing file clusters within one volume. Its
parameters select VCN, LCN and cluster count; they supply no import-NTFS-extents
or no-copy option. Conservatively account for copying initialized data. Block
cloning remaps existing ReFS file regions, not arbitrary NTFS/raw allocations.
[Move contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file),
[move parameters](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-move_file_data),
[block cloning](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning)

Let `T` be the frozen NTFS partition, `S` a separate frozen native ReFS shadow
with matching geometry, and `P` the exact source payload interval. The desired
fixture result is:

```text
R[P]     = T[P]
R[not P] = S[not P]
```

All formatting and native placement happen on `S`, inside the converter's
Windows environment. Copying shadow placeholders therefore affects scratch
cost, but does not touch `T`. Preserving the source requires that the target
write plan never intersects `P`, and that the native shadow's file metadata
names the corresponding extent with valid contents. Native-formatting `T`,
moving shadow data onto `T[P]`, or copying placeholder bytes through `P` would
violate this design. Native local virtual-disk APIs do not require Hyper-V;
host management remains lab infrastructure.
[Native virtual-disk creation](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk)

This equivalence construction is an architectural hypothesis, not a documented
transplant interface. ReFS always checksums metadata; optional file-data
integrity stores additional data checksums. Require the fixture's measured
`CHECKSUM_TYPE_NONE`, not merely disabled checksum enforcement. Any unknown
content-dependent metadata remains a possible native-test failure.
[Integrity behavior](https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams),
[integrity result](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-fsctl_get_integrity_information_buffer)

## Exact fixture and identity contract

Use the measured 52 GiB partition length on an owned 64 GiB basic GPT data disk,
partition offset 16 MiB, 512-byte logical sectors, 4 KiB physical sectors and
4 KiB clusters. Native shadow geometry must be measured, not inferred from its
virtual capacity. The shadow is independent, with no parent/source dependency,
on separately identified storage outside the source partition.

Require a clean, coherently captured NTFS source. The only retained user
object is one ordinary fully initialized 65,536-byte
NTFS stream, one contiguous sixteen-cluster extent, one link, no alternate
streams, and no resident, sparse, compressed, encrypted or shared-allocation
semantics. Other user objects or unsupported metadata block this fixture.
Record the exact name, EOF, allocation, valid-data coverage, attributes,
timestamps, owner/group/DACL, and verified SACL absence or explicit supported
handling. Preserve supported namespace/security/standard metadata on the shadow
through native APIs; do not silently drop fields to make the fixture pass.

Pin independent native evidence for each input: file identity, stream identity,
logical hash, raw hash of `P`, retrieval/base translation, physical disk identity,
GPT disk/partition identities, filesystem serial, format/build/driver hashes,
full region validity and integrity settings. The source and shadow must have
different disk identities. The final target preserves its original disk and
GPT partition identity/geometry; its intended ReFS filesystem serial and file
identity come from the native shadow and are recorded as changes. Do not copy
the shadow GPT or assume native file IDs are equal across filesystems.

Use distinct patterns: source `A`, shadow placeholder `B`, different in every
cluster. The shadow file must have complete positive native mappings at the
same verified partition-relative bytes `P`, full cached/storage validity, and
integrity NONE. At most one initialized native placement request is allowed on
the shadow. A metadata collision or address ambiguity rejects the case; do not
move the original source extent to accommodate the shadow. The failed VDL file
and its negative marker are not inputs to this fixture.

## First code increment: a fixture-specific equivalence plan

The new Rust core should be a generic read-only retained-range comparator over
immutable ordinary image files, with full input and retained-range hash pins.
It emits only a bounded report, not patch payloads or write authority. The
52 GiB / one-64-KiB native fixture and semantic attestations belong to an
external profile; small sector-aligned synthetic ranges exercise the core.
It must not accept device paths, mutate inputs, or invoke Windows management
APIs. Retain the production planner's `executable=false`, writer/recovery
blockers and all current gates.

Read every logical sector of both partitions. Outside `P`, emit a proposed
patch for every differing sector, including zero-valued sectors and sectors
that either filesystem calls free. Coalesce adjacent changes only within the
declared bounds. Inside `P`, allow the expected `A`/`B` disagreement, record both
hashes, and emit no write. The expected result's complete hash is computed by
streaming `S` with `T[P]` substituted at that interval.

The generic comparison report should contain only facts derived from its
ordinary image inputs and hash pins:

- Exact input lengths, hashes and ordinary-file identities; retained intervals
  and source/shadow retained-byte hashes.
- Every proposed target interval, old/new hashes and source-of-new-bytes offset;
  an exact exclusion/collision result against `P`.
- Complete comparison coverage, changed/unchanged/retained byte counts,
  interval count and changed-sector data size. That size is also a lower bound
  for saving all preimages; it is not a journal-size or overhead estimate.
- Expected complete mosaic hash, applied comparison bounds and explicit
  comparison blockers. No native filesystem or recovery qualification.

A future native-fixture attestation wrapper must separately bind native proof
hashes, validate the namespace/security/standard metadata and volume identity
contract, declare source-versus-expected-target identity changes, and produce
the fixture-specific equivalence/collision certificate. The generic comparator
neither carries nor validates that entire contract. Mathematical byte
equivalence is conditional on those external native claims; hashing an
attestation JSON does not authenticate its claims or confer write authority.

This whole-partition comparison avoids guessing that `bitmap minus payload`
contains all required ReFS metadata. Identical sectors may be omitted because
their bytes were compared. A sparse-known-zero optimization is permitted only
with independently established byte-equivalent zero evidence; container holes,
filesystem free bits, zero signatures or lack of writes alone are not that
proof. The first implementation should simply read all sectors.

The current Rust reader validates selected bootstrap/container/virtual-root
structures but not every namespace, validity or allocation reference. The new
plan does not promote that partial decoder into a complete metadata model.
[Current reader scope](refs-virtual-roots.md), [unchanged gates](format-gates.md)

## Fixed bounds and later native acceptance

Accept exactly one aligned 64 KiB retained interval and the exact geometry
above. Use at most 1 MiB streaming buffers. Cap changed-byte patches at 256 MiB,
old-byte preimage data at 256 MiB and coalesced patch intervals at 65,536. The
initial report counts changed-sector bytes only; it does not claim to know
journal overhead or complete future storage costs. A later executor
must use a separately fixed total recovery budget including journal indexes,
headers and flush records; payload-size accounting must not hide overhead. Reject
overflow, overlap, changing/incomplete inputs, extra source features or any
exceeded cap before a write plan can advance. The initial native profile may
exceed 256 MiB and be rejected; that is a valid bounded outcome, with no
automatic cap increase.

Budget at most two complete pair passes before any executor verification:
208 GiB of combined input reads. Report later verification separately. Measure
actual shadow backing and reserve patch/recovery capacity on independent guest
storage before creating artifacts. A dynamic virtual size is not a storage
ceiling. The current host capacity cap still applies. If independent capacity
is unavailable, finish the ordinary-file planner and retain that runtime blocker.
This small initialized shadow does not generalize bounded scratch to arbitrary
source-sized files; their placeholder copying may be unacceptable.

Only a separately reviewed later lab executor may apply the complete plan to
the original disposable NTFS partition. It must isolate the target, persist
and flush preimages/recovery state before changes, never format the target,
and keep its explicit write ledger disjoint from `P`. Verify `R[not P]=S[not P]`
and raw `R[P]=A` before native handoff. The exact native handle/isolation and
recovery lifecycle needs its own review; a VM checkpoint is secondary
containment and cannot qualify production recovery.

The finite native success criterion is: the same target partition is recognized
as the intended ReFS state; its fixture reads as `A`, not `B` or zeros; native
mapping and raw bytes remain at original `P`; namespace/security/standard
metadata match the supported source contract; identities match the declared
changes; and one clean remount plus one bounded new allocation preserves these
results without unexpected repair. Record native writable activity explicitly.
Unchanged bytes alone do not prove absence of identical rewrites.

| Result | Decision |
| --- | --- |
| Shadow cannot represent `P`, or native/raw addresses disagree | Reject this placement profile; no source relocation or guessed address fallback. |
| Plan exceeds fixed write/storage limits | Stop with the concrete capacity report; do not convert it into a full-copy migration. |
| Fully valid integrity-NONE shadow plus retained `P` fails recognition, reads `B`/zeros, or violates metadata semantics | Stop this transplant profile. Resolve one concrete address/metadata discrepancy before a new attempt. |
| Native reads `A` at unchanged `P` and all bounded checks pass | One native-state substitution preserving one source extent is demonstrated. General conversion, complete-format, recovery, efficiency and boot gates remain open. |

After a correctness result, choose the next investment deliberately: independent
metadata coverage for a smaller write set, or one bounded scaling experiment
for shadow I/O/scratch. Original target extents can remain in place even when
shadow generation is inefficient or makes a full placeholder copy elsewhere.
Source retention and shadow efficiency are separate claims. If native
generation requires resources beyond the accepted budget, reject that design
against the efficiency requirement and choose a validated direct ReFS writer
or explicitly revised storage/performance requirements. Do not weaken validity
gates or conceal copying of the original target payload behind a retention
claim.
