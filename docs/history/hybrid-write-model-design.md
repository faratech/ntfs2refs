# Hybrid write model (drafts, not adopted)

Status (2026-10-29): two designs for the user's "Hybrid" moved-data decision
(stage relocated data in NTFS-free space, journal old+new only where NTFS-
allocated bytes are overwritten), from read-only workflow wf_e1246bb5-f73.
Both adversarial verifiers returned sound=false. Shared findings:
- No crash point loses NTFS-ALLOCATED data under the user's allocation
  guarantee; the core ordering (free-destination writes before allocated-
  destination writes, a durable barrier, old+new kept for allocated
  destinations) holds.
- Gaps: free-destination ranges lose their per-byte old-or-new content check
  (E-1/E2) so a stale journal could replay onto an NTFS that was onlined and
  used outside the tool; no Volume Shadow Copy gate (raw writes bypass
  volsnap); torn-marker rows strand the volume under the proposed default;
  class map / NTFS-allocated set not stored in the journal; resolver and
  native ordering described inconsistently; 65,536-range caps unlifted.
- Required measurement first (Q0): on the 808-file fixture, the split of
  changed bytes into NTFS-free vs NTFS-allocated destinations, the share of
  relocated origins inside the ReFS metadata prefix, zero-content share, and
  whether an exactly sized external journal alone would fit.
Decisions the user must make before implementation: E-1/E2 (per-granule
old/new digest table vs full payload for free destinations), E-2 (rollback
leaves staged data in NTFS free space), E3 (torn-marker completion).
===== DESIGN 1: Stage-then-commit hybrid journal (N2RHYB01): staged writes into NTFS-free space using derivable references, with journaled payload only over NTFS-allocated destinations
WRITE PHASES: CLASSIFICATION RULE (decided before any write, bound by the live certificate)
- Every changed 4 KiB granule of compared = selection - in_place (general_composite_target.rs:707-717) is assigned to one record.
- Destination class decides the phase:
  - Phase A: destinations NTFS-free (outside raw.allocated_byte_ranges, ntfs_inspect.rs:202-254).
  - Phase B: destinations NTFS-allocated. This set includes $Boot granule 0 and the past-domain backup boot (ntfs_inspect.rs:250-252).
- Content decides only where the new value comes from: a reference (relocated route payload), zero, or journal payload.
- Deviation from the angle's wording: ReFS metadata that lands on NTFS-free bytes is phase A with new bytes only. Its old bytes are NTFS free space, which the user's allocation guarantee does not restore. Only bytes that overwrite NTFS-allocated data get journaled old bytes, which is the user's Hybrid wording (AGENTS.md:265-270).

P0 (pre-activation; source at attributes 3)
- Writes only OS-volume artifacts (packed backing, preallocated journal, pins, capacity-plan.json) and the shadow VHDX.
- Zero source writes.

P1 (activation)
- Changes attributes 3 -> 1, then RegFlushKey (native.rs:2530-2571, 396-425).
- Arms one WritePolicy with two ordered stages, [A dests] then [B dests]. Only stage A is current.

P2 (SA intent)
- Writes the SA marker to write-once slot 2, then sync and readback (the pattern of selected_journal.rs:494-509).
- No target write happens before SA is durable.

P3 (stage A)
- Writes only A destinations. These are NTFS-free bytes, so NTFS stays fully valid and mountable.
- Per record, the new value is resolved from its pinned source:
  - A-COPY: concatenated segments. A device-ref is NTFS-allocated physical bytes outside every write range; it is read through the activated handle and its SHA-256 must equal record.new_sha256 before use. A journal-ref is the immutable old payload of a B record.
  - A-ZERO: zeros.
  - A-NEW: journal new payload.
- Chunks already equal to the new value are skipped, as in write_span (selected_journal.rs:556-603).
- P3 may overwrite only NTFS-free bytes. It never overwrites a COPY source.

P4 (barrier)
- target.sync_all, then read back every A destination. The framed new_a digest must equal the ticket.
- Then the journal immutable region is rechecked.

P5 (AP intent)
- Writes the AP marker to slot 3, with sync and readback.
- AP commits new_a: it means "staged copies verified; NTFS originals may now be destroyed".

P6 (commit B)
- advance_stage: the native policy moves to B. A is no longer writable in this handle.
- Every B record is written except partition granule 0, keeping the per-byte old-or-new check. The new value comes from payload, zero or reference; the old value from payload or zero.
- Then sync, granule 0, sync. This is today's order (selected_journal.rs:645-660).
- Then new_b and new_a are verified and the immutable region is rechecked.
- P6 may overwrite NTFS-allocated bytes, including relocated origins. Their content now exists at verified A destinations and, when the origin is a B record, as that record's old payload.

P7 (handoff)
- Verifies new_a and new_b, then writes HND to slot 0 (as selected_journal.rs:823-857 does today).
- Then bring_online (native.rs:2682-2699) and verify_native_scoped (allocation.rs:253-265).

ROLLBACK
- Writes RB to slot 4.
- Arms a single-stage policy over B destinations only. Rollback can never write an A destination or a device-ref source.
- Restores old bytes over B from payload or zero, keeping the per-byte check, with granule 0 last.
- Then sync, verify old_b, recheck the immutable region, write ABT to slot 1, bring_online, and check the NTFS mount.
- A destinations keep staged or ReFS bytes. That is NTFS free space, and the evidence records it as not restored.

ABANDON (no SA durable)
- Arms no policy.
- Verifies old_a and old_b, then writes ABT.

ORDER INDEPENDENCE
Every source a write reads is immutable (the journal) or never armed (a device-ref outside A∪B). So writes within a phase are independent of order, and a relocation chain needs no copy-before-overwrite ordering beyond the A-then-B barrier.
JOURNAL: NEW FORMAT N2RHYB01 (format 3)
- The N2RSEL01 reader and writer stay unchanged, so schema-1 bundles from earlier runs still recover (selected_journal.rs:10-17, 294-463).
- All counts are u64, so this format can also serve the unbounded-range role that docs/history/unbounded-scale-design.md:110 gives N2RSEL02.

LAYOUT
- [0, 32 KiB): eight write-once 4 KiB marker slots, each with a fixed kind.
  - Slot 0: HND N2RHHN01, commits SHA-256(new_a‖new_b).
  - Slot 1: ABT N2RHAB01, commits old_b. An abandon ABT commits SHA-256(old_a‖old_b).
  - Slot 2: SA N2RHSA01, commits SHA-256(old_a‖old_b).
  - Slot 3: AP N2RHAP01, commits new_a.
  - Slot 4: RB N2RHRB01, commits old_b.
  - Slots 5-7: must be zero.
  - Each marker is kind ‖ immutable_sha256 ‖ committed digest ‖ zero padding ‖ self SHA-256 (same construction as selected_journal.rs:465-473).
  - A slot is only ever written with its own kind, so today's RB overwrite of AP in the same 4 KiB slot (selected_journal.rs:639-644) disappears.
- At 32 KiB, a 128 B header: magic, format 3, image_length, record_count, segment_count, a_bytes, b_bytes, old_payload_bytes, new_payload_bytes, journal_length, payload_area_at, ntfs_allocated_ranges_sha256 (the canonical classification input).
- The record table: one 128 B record per range.
  - Fields: kind (phase A|B; old_side digest|payload|zero; new_side payload|zero|ref), dest offset, length, old_payload_at, new_payload_at, segment_first, segment_count, old_sha256, new_sha256.
- The segment table, 32 B per entry: kind (1 = journal old payload of record r at offset w, 2 = device physical offset, 3 = zero), source, within, length.
- Padding to 4 KiB, then the payload area (old payloads, then new payloads, only where the record kind has them).
- A 192 B footer N2RHEND1: journal_length, records_sha256, old_a, new_a, old_b, new_b.
  - All four are framed (offset‖length‖bytes) SHA-256 digests over the target bytes of the A or B destinations in offset order.
- The immutable pin is SHA-256 over [32 KiB, end).
- The record and segment tables come first, so recovery takes its ranges from the journal (docs/history/unbounded-scale-design.md:315).

WHAT IS JOURNALED PER RANGE CLASS
- A-COPY (relocated payload on NTFS-free): the 128 B record + 32 B per segment, plus an old-bytes digest only. No payload.
- A-ZERO: the 128 B record + old-bytes digest. No payload.
- A-NEW (ReFS metadata, tails, SVI on NTFS-free): new payload only.
- B (destination NTFS-allocated, including every relocated origin and granule 0):
  - Old: payload, or zero kind when the frozen bytes are all zero.
  - New: payload; or zero; or a reference to another B record's old payload or to an unwritten NTFS-allocated device range. The reference case is the fallback for relocated data placed on NTFS-allocated bytes, and it removes the double counting of origin and destination.
- Length: J = 32768 + 128 + 128·R + 32·S + pad + Σold_payload + Σnew_payload + 192.
  - Today: 8192 + 80 + 80X + 2B + 80 (selected_journal.rs:135-140).
- Per relocated byte, today stores up to 4 copies: old and new at the destination, plus old and new at the origin when the origin is changed. Hybrid stores at most 1 (the origin's old payload), plus 0 when the shadow content at the origin is zero.

DIGEST ROLES
- old_a: checked only before fresh apply and by abandon.
- new_a: checked at the barrier, at resume, at handoff and by VerifyHandoff.
- old_b: checked by rollback, ABT and VerifyAborted.
- new_b: checked after commit and at handoff.
- load() reverifies the immutable pin, header, records_sha256, every payload hash and the footer. It never needs the device, the shadow, the routes or the packed backing.

SCHEMA AND VERSION CHANGES
- Request schema 3 carries a capacity policy (reserve fraction, recorded) instead of a measured byte count, and no constant ceiling.
- Plan v3 (HybridPlan) holds the records, the segments, max_journal_bytes, max_written_bytes and ntfs_allocated_ranges_sha256.
- The hybrid ticket holds journal_length, immutable_sha256, records_sha256, the four digests, a_bytes, b_bytes and the pinned maxima.
- Bundle schema 2 holds {sha256, bytes} pins for request, plan v3, ticket, expectation, verification and capacity-plan, plus the journal path and format.
- JournalProfile gains PinnedV3 { max_journal_bytes, max_written_bytes }, built only from the pinned plan and never from a constant or a new measurement. This replaces the 16 GiB V2 ceiling used at journal_file.rs:39-47 and native.rs:293-299.
SIZING: PRINCIPLE
- The staging location is the final ReFS destination itself (the ntfs2btrfs model). There is no separate staging area and no second copy.
- How much stays in-volume is decided per range by where placement puts each relocated piece:
  - NTFS-free destination: class A.
  - NTFS-allocated destination: class B, the external old+new fallback.
- External capacity comes from the OS volume's measured free space, re-observed at each gate. Every bound is pinned in plan v3, the ticket and capacity-plan.json, and recovery never re-measures (docs/history/unbounded-scale-design.md:821).

GATES (all before activation)

H0, drive_cli:
- Measure OS-volume free space F0, record it and the policy.
- There is no fixed /4 reserve and /3 split, and no 16 GiB cap (replaces drive_cli.rs:448-457). The request is schema 3 with no max_journal_bytes constant (general_conversion.rs:71, 86-90).

H1, placement (steering, before shadow freeze):
- Scratch and evacuation take first-fit from tier 1 = ReFS-free in both views ∩ outside desired runs and margins ∩ NTFS-free.
- They fall back to tier 2, today's set (placement.rs:345-412; shadow_evacuation.rs:224-291).
- ReFS's initial placeholder runs that sit on NTFS-allocated non-desired bytes may be evacuated to tier 1 under the same per-move proofs.
- Placement records per-tier bytes.
- Projection from private.source_backed_routes ∩ raw.allocated_byte_ranges, recorded in capacity-plan.json:
  - R_free: relocated bytes landing NTFS-free (0 journal bytes).
  - R_alloc: relocated bytes landing NTFS-allocated (1× old, new by reference).
  - O_sel: origins inside the shadow selection (1× old; new zero or payload).
- Refuse here, before shadow freeze, if packed_lower + journal_lower > F1 - reserve.

H2, pre-capture (shadow frozen, so the VHDX no longer grows):
- Upper bounds, by intersecting compared with the NTFS-allocated set and the COPY-eligible route pieces:
  - U_B: compared ∩ NTFS-allocated.
  - U_copy: COPY-eligible pieces.
  - U_new: the remainder.
- Re-observe F2. Available C = F2 - reserve, where reserve = the post-commit artifact bound + a recorded policy fraction of OS-volume capacity.
- The capture budget is a cost function, not one changed-byte number (replaces source_backed.rs:517-521 and lab_reconstruct.rs:40-68):
  - packed cost 4096 per changed granule (H2-H3; 0 for COPY in H4);
  - journal cost up to 8192 per B granule (less for zero or ref);
  - 4096 per A-NEW granule, 0 per A-COPY or A-ZERO granule;
  - plus 128 B per record and 32 B per segment.
- If the H2 upper bound fits C, the capture cannot refuse on space. Otherwise it refuses at the exact granule where the cost exceeds C, still before activation.

H3, post-capture:
- The exact classified plan gives the exact journal_length; the capture loop detects zero old and new values at no extra cost.
- Require packed + journal_length <= C.
- Preallocate the journal with FileAllocationInfo before writing.
- Pin max_journal_bytes = journal_length and max_written_bytes = Σa_bytes + Σb_bytes in plan v3 and the ticket.
- WritePolicy and recovery check these pinned values instead of profile.max_changed_bytes (native.rs:293-299; general_recovery/allocation.rs:124).

H4, before activation:
- Re-observe free space and reserve the post-commit artifacts, then activate.

OS-VOLUME PEAK
packed + J + VHDX. In H4, COPY bytes leave the packed file, so the peak drops by R_free.

808 FIXTURE (inference, unmeasured)
- About 6.43 GB relocated against about 42 GB NTFS free and about 39.7 GB OS free.
- Today: up to about 4 journal copies per relocated byte.
- Hybrid: at most about 1 copy (the origin's old payload, mostly inside the 6.17 GB ReFS metadata prefix), plus non-zero ReFS-metadata new bytes.
- Expected peak is roughly 13-20 GB, which fits, but the class split must be measured first (Q0).
INVARIANTS: I1 Classification:
- The A and B destination sets are disjoint and cover every changed granule exactly once.
- A ∩ NTFS-allocated = ∅ and B ⊆ NTFS-allocated, where the NTFS-allocated set is raw.allocated_byte_ranges under ConsistentRawModel (ntfs_inspect.rs:202-254), cross-checked against the native bitmap at admission.
- Granule 0 and the backup boot sector are in B.
- Device-ref sources ⊆ NTFS-allocated \ (A∪B).
- Journal-refs point only into B old payloads.
- Admission requires a clean volume (ntfs_admission.rs:294, 950-953), so the NTFS bitmap is authoritative.

I2 Derivability:
- Every forward value, and every backward value of B, comes from the immutable journal region, zeros, or device bytes that no stage ever arms.
- Resume and rollback therefore need no shadow, routes or packed backing, and are independent of write order.
- Rollback never reads an A destination or a device-ref.

I3 Ordering:
- No A write happens before SA is durable.
- No B write happens before A is flushed, new_a is verified and AP is durable.
- The native stage policy makes this a mechanism, not only a convention.
- Rollback arms B only.
- Granule 0 is written last in both directions.

I4 Markers:
- Each marker has its own fixed, write-once slot.
- A torn slot means that write never completed (write_marker syncs and reads back before anything proceeds). It is completed only with its own kind, or counts as absent, per the crash table.
- HND and ABT close replay. HND and RB are mutually exclusive.

I5 Fresh Apply:
- Fresh Apply, including stage A, runs only in the converting process and only after certificate.binds(proof), which now also binds classification and capacity.
- Recovery never moves forward from PreparedClear or a torn SA.

I6 Recovery never clears protection:
- Recovery requires attributes 1 (native.rs:2610-2625).
- It changes attributes only by bring_online after a durable HND or ABT.
- It never moves 3 to 1 and never repairs a lost OFFLINE.

I7 Pinned capacity:
- journal_length, max_journal_bytes and max_written_bytes are pinned in plan v3 and the ticket and re-checked from those pins.
- Nothing is re-measured in recovery.

I8 Rollback exactness:
- After ABT, every NTFS-allocated byte equals its frozen value: old_b covers every written NTFS-allocated byte, and the policy proves no other NTFS-allocated byte was written.
- A destinations may hold staged or ReFS bytes. This matches the user's guarantee and is recorded.

I9 Resume exactness:
- After HND, every written byte equals the certificate-bound candidate (new_a and new_b).
- The per-byte old-or-new rule is kept on B.

I10 Self-containment:
- The journal and pinned plan alone are enough for recovery.
- The packed backing stays pinned until handoff, per AGENTS.md:283-285.
SCOPE CHANGES: E1. Covered by the MOVED-DATA decision and the allocation guarantee (AGENTS.md:146-155, 265-270); evidence must record it. Phase-A destinations store only an old-bytes digest, so rollback does not restore NTFS-free bytes overwritten by staged data or ReFS metadata. Results record ntfs_free_bytes_not_restored_by_rollback. VerifyAborted after a rollback ABT checks only old_b. | E2. Needs user confirmation. After SA, resume and rollback no longer apply the per-byte old-or-new foreign-byte check to A destinations: any prior free-space content is accepted and overwritten. new_a is still fully verified before AP and before HND. Optional mitigation: a per-4 KiB XXH3-64 old/new table (16 B per granule) keeps a granule-level detector. | E3. Needs user decision. A torn write-once marker slot means its transition did not complete; it is completed only in its own direction, or counts as absent. Today a torn marker refuses both directions (selected_journal.rs:475-492, 732-757). Without approval, keep refusal on any torn slot; the separate slots still remove the RB-over-AP hazard. | E4. No scope change. These change storage, location and derivation, but every changed byte is still compared and its final value verified:
- placement steering into NTFS-free space;
- zero-kind and reference-kind payload elimination;
- record table first;
- pinned free-space capacity;
- the directory flush. | D-H1. NOT ADOPTED. A relocated origin's old side would point at its verified staged copy in an A destination instead of journaling it. Relocated data would then need no journal bytes at all, but rollback would depend on device bytes the converter wrote. Needs an explicit user decision. | D-H2. NOT ADOPTED. Accept foreign (torn-sector) bytes in B ranges under power loss. The journal holds both sides, but this widens the exclusion-breach tolerance.
CRASH TABLE (23 rows):
  - Before activation: freeze, shadow construction, hybrid-steered placement, the pre-capture gate, capture/classification, and journal preallocation and preparation, including refusals (general_qualification.rs:229; compact_construction.rs:146-212; general_composite_target.rs:707-736; allocation.rs:88-156) => durable: Source attributes 3 (hive-flushed); zero source writes. OS-volume artifacts may be partial (packed backing, journal, capacity-plan). No bundle exists. | resume: None. drive --recover finds no bundle (drive_recovery.rs:99-105). A fresh Apply would need the dead process's live certificate. | rollback: No data rollback is needed because NTFS bytes are unchanged. The source stays stranded at attributes 3, as today; recovery never clears protection, so the operator path is unchanged.
  - Pin publication: ticket, plan v3, capacity-plan, request, verification and bundle v2, each create_new+sync_all, then a new directory flush (general_qualification.rs:77-93; allocation.rs:158-185) => durable: Attributes 3. Journal PreparedClear (all 8 slots zero). The bundle may be absent, present but undurable, or durable; the directory flush makes 'bundle durable' imply a durable directory entry. | resume: Refused: PreparedClear forward would be a fresh apply (general_recovery/allocation.rs:213-215). | rollback: Refused at reopen, which requires attributes 1 (native.rs:2620-2625). NTFS is unchanged and stranded read-only offline, as today.
  - Activation in flight: set_attributes(OFFLINE), then RegFlushKey (native.rs:2548, 396-425) => durable: Attributes 3 or 1. No target write. Journal PreparedClear. | resume: Refused (PreparedClear). | rollback: If attributes are 1: Abandon. Full load, framed old_a and old_b over the target, write ABT to slot 1, bring_online, check the NTFS mount. If attributes are 3: as the previous row.
  - Activated with the stage-A policy armed; SA (slot 2) not yet durable, or torn => durable: Attributes 1. Slot 2 is zero or torn. Target unchanged, because the first target write follows write_marker's sync and readback. | resume: Refused. No durable SA means forward would be a fresh apply. | rollback: Abandon as in the previous row. A torn SA counts as absent and is never rewritten; the slot set {SA~, ABT} classifies as Aborted.
  - SA durable; phase-A writes in flight (A-COPY, A-ZERO, A-NEW into NTFS-free destinations), including a hard power-off mid-chunk => durable: Attributes 1. A destinations hold any mix of old, new and torn bytes. Every NTFS-allocated byte (all B destinations and every device-ref source) is untouched, because only stage A was armed. NTFS is fully valid. | resume: load; check B per byte (it must equal old_b); arm [A, B]. For each A record: resolve the new value; require each device-ref's hash to equal record.new_sha256; rewrite, skipping equal chunks (no per-byte check on A; see E2). Then flush, verify new_a, write AP, advance, run P6, then HND, bring_online and verify. | rollback: RB to slot 4; arm a B-only policy; check_target over B equals old_b, so there is nothing to restore; immutable recheck; ABT; bring_online; NTFS mount. A destinations keep staged bytes: NTFS free space, recorded as not restored (E1).
  - Phase A writes complete; target flush, A readback (new_a) or immutable recheck in flight => durable: As the previous row. A may still differ from new if the flush was lost. | resume: As the previous row: idempotent redo, then verify. | rollback: As the previous row.
  - AP (slot 3) write in flight, or torn => durable: The A barrier passed in-process but A's durability is unproven after the crash. B is untouched. Slot 3 is zero or torn. | resume: A torn or zero AP counts as 'commit not started'. Redo A (skipping equal chunks), flush, verify new_a, write slot 3 with AP (its own kind, deterministic bytes), then continue with P6. | rollback: As the phase-A rows. The slot set {SA, AP~, RB, ABT} classifies as Aborted.
  - AP durable; policy advanced to B; B writes in flight (everything except partition granule 0) => durable: A equals new (verified before AP). B is old or new per byte. NTFS-allocated bytes, including relocated origins, are partly overwritten. Neither filesystem is mountable. Attributes 1. | resume: load; arm [A, B]. Re-verify A and repair it if needed from the pinned sources: journal-refs are immutable and device-refs lie outside every write range. This is exact even if staged writes were lost. Then flush, new_a, advance. check_target per byte on B (a foreign byte refuses). write_span forward, taking the new value from payload, zero or reference. Then flush, granule 0, flush, verify new_b and new_a, immutable recheck, HND. | rollback: RB; B-only policy; per-byte check; restore old values from payload or zero, granule 0 last; flush; verify old_b; immutable recheck; ABT; NTFS mount. Rollback never reads A destinations or device-refs.
  - B spans done and flushed; granule-0 write in flight => durable: As the previous row. Granule 0 is old or new per sector. | resume: As the previous row. | rollback: As the previous row; granule 0 is restored last.
  - Fresh apply returned (final flush, new_a and new_b verified, immutable recheck); HND not started => durable: Target is new everywhere. Slots: SA and AP. | resume: Resume (all chunks equal, no writes), verify, HND, mount. | rollback: Allowed: RB, restore B, ABT, as today.
  - HND (slot 0) write in flight, or torn => durable: Target is new. Slot 0 is torn. Attributes 1, because bring_online follows only after a successful readback. | resume: Forward completion only: verify new_a, new_b and the immutable region; rewrite slot 0 with HND; bring_online; verify_native_scoped. | rollback: Refused. A torn HND locks the forward direction, because handoff may already have been decided (conservative).
  - HND durable; bring_online not yet durable => durable: Journal Handoff. Attributes 1. | resume: VerifyHandoff: verify_closed checks new_a and new_b with no writes; then bring_online and verify. | rollback: Refused: HND closes replay.
  - bring_online durable (attributes 0); verify_native_scoped, label, mount paths or result.json in flight => durable: ReFS is online and the journal is in Handoff. | resume: Refused at reopen, which requires attributes 1. Label and mount-path completion is not retried; that gap is unchanged. There is no replay over a mounted volume (AGENTS.md:286-287). | rollback: Refused (HND).
  - Recovery --rollback: RB (slot 4) write in flight, or torn => durable: Slot 4 is torn. A and B are in whatever state rollback started from (the phase-A through fresh-apply rows). | resume: Refused: a torn RB locks the rollback direction. | rollback: Rewrite slot 4 with RB (its own kind), then continue rollback.
  - RB durable; B restore writes in flight (granule 0 last) => durable: B is old or new per byte; A is any value. RB closes forward. | resume: Refused: RB closes forward, as in selected_journal.rs:627-630. | rollback: Rerun (idempotent; per-byte check); flush; granule 0; flush; verify old_b; ABT.
  - Restore verified; ABT (slot 1) write in flight, or torn => durable: Every B byte is old. Slot 1 is torn. | resume: Refused. | rollback: Verify old_b and the immutable region; rewrite slot 1 with ABT; bring_online; NTFS mount check.
  - ABT durable; NTFS not yet online => durable: Journal Aborted. Attributes 1. | resume: Refused. | rollback: VerifyAborted. After a rollback ABT, verify old_b only; after an abandon ABT, verify old_a and old_b. Then bring_online and check the NTFS mount.
  - NTFS online after ABT => durable: NTFS is mounted. Staged and ReFS bytes remain in NTFS free space (recorded byte count). | resume: Refused at reopen. | rollback: Refused at reopen; nothing remains to do.
  - Recovery's own run crashes during its A redo, B writes, or its input copies (general_recovery/allocation.rs:165-169) => durable: The same states as the SA-through-fresh-apply rows; input copies have no device effect. | resume: The same rows apply; every write is idempotent and resolved from pinned sources. | rollback: The same rows apply.
  - Fault: a foreign byte (torn sector, neither old nor new) in a B range after a power loss => durable: Attributes 1; the journal is intact. | resume: Refused before any write (unchanged conservative rule, selected_journal.rs:536-543). Protection stays. | rollback: Refused before any write. Accepting it needs decision D-H2.
  - Fault: a device-ref source changed (exclusion breach on NTFS-allocated bytes outside every write range) => durable: Attributes 1. | resume: Refused before writing that record (source hash differs from record.new_sha256). | rollback: Unaffected, because rollback never reads device-refs; NTFS is restored.
  - Fault: journal payload or immutable region damaged on the OS volume => durable: Attributes 1. | resume: load refuses before lifecycle selection. Protection stays. | rollback: load refuses before lifecycle selection. Protection stays.
  - Hard power-off (Hyper-V TurnOff or physical) at any row from 'Activated' through 'ABT durable' => durable: State is defined by the flush points. Target writes use NO_BUFFERING|WRITE_THROUGH plus FlushFileBuffers at each barrier (native.rs:375-382, 2672-2678). Markers use sync_all and readback. Attributes are hive-flushed. So the disk is in one of the rows above, or its writes are lost: lost A writes are repaired by resume, lost B writes read as old, and a lost marker counts as absent or torn per the table. | resume: As the matching row. | rollback: As the matching row. Physical power loss remains untested (TurnOff keeps host-cached VHDX writes).
CHANGES (16):
  - src/hybrid_journal.rs (new; src/selected_journal.rs unchanged): N2RHYB01 plan, ticket, record, segment and footer types with checked-arithmetic validate. Covers validation for class disjointness, granule 0 in B, device-refs outside A∪B and journal-refs into B old payloads. Functions: prepare, which reads old values from the frozen source, new values from DifferenceImage, and device-ref sources by physical coordinate with hash equality to the capture's candidate hash. Also load (full reverification, no device needed), the multi-slot classify with the torn-slot table, execute_stage (P3/P4), execute_commit (P6), rollback (B only), abandon, verify_closed and handoff. Reuses the per-byte rule of selected_journal.rs:513-603 for B and the marker construction of :465-509.
  - src/general_shadow/source_backed.rs:421-588: Classify inside the capture loop. Binary-search each changed run against raw NTFS-allocated ranges and route relocation pieces; detect zero old and new values from the buffers already in hand; compute the SHA-256 of COPY candidate bytes per run. Replace the single max_changed_bytes refusal (:517-521) with the per-class cost budget. Lift the 65,536-range cap (:533-536) together with set C from the scale design. In H2-H3 the packed backing stays complete.
  - src/general_composite_target.rs:516-534, 557-632, 672-787: Generalize in_place_payload_ranges into a route-origin map of (shadow_physical, ntfs_physical, length) pieces, where in-place pieces are those with equal coordinates. verify_and_select passes raw.allocated_byte_ranges and the route-origin map into the capture and keeps a HybridClassification plus classification_sha256 in the proof. proof.plan becomes proof.hybrid_plan.
  - src/general_source_admission.rs:74-103, 167-175: AllocationCertificate also binds classification_sha256, ntfs_allocated_ranges_sha256, a_bytes, b_bytes and the capacity-plan pin, and binds() compares them. A fresh Apply (stage A included) still requires certificate.binds(proof) on the original object (allocation.rs:189-192).
  - src/general_conversion/allocation.rs:45-50, 84-156, 158-185, 195-238: Replace changed_byte_budget_for_profile with the H2/H3 capacity gates and preallocate the journal. Prepare N2RHYB01 and publish bundle v2, with capacity-plan.json pinned and the directory flushed. Arm a two-stage WritePolicy, write SA, run execute_stage, write AP, advance_stage, run execute_commit, then the hybrid handoff. Add result fields: staged bytes, journal payload bytes, ntfs_free_bytes_not_restored_by_rollback, free_space_contents_compared=false.
  - src/general_recovery/allocation.rs:21-34, 109-128, 195-289: Bundle v2 with {sha256, bytes} pins. Limits come from plan v3 and the ticket, never from a profile constant or a new measurement. The lifecycle table is extended with StageIntent and torn-slot completions. Policies: Resume arms [A, B] and Rollback arms [B]; Abandon checks old_a and old_b; VerifyAborted distinguishes abandon from rollback. Reopen still requires attributes 1 (:234-241), and nothing clears protection.
  - crates/n2r-win32/src/native.rs:266-313, 2656-2670, 2714-2766: WritePolicy gains ordered disjoint stages, each with its own maximum, plus a pinned total. It is validated against PinnedV3, not journal_profile.max_changed_bytes (:293-299). advance_stage() is monotonic, one-way, and rechecks attributes == OFFLINE. write() permits only the current stage. permits() uses partition_point instead of a linear any (:308-310).
  - crates/n2r-win32/src/journal_file.rs:25-58, 252-271: JournalProfile::PinnedV3 { max_journal_bytes, max_written_bytes }, built from the pinned plan. The journal-file observation checks against that value. V1 and V2 stay unchanged for old runs.
  - src/lab_reconstruct.rs:40-68; src/general_conversion.rs:71, 86-90; src/general_qualification/composite.rs:267-282: Schema-3 validation with no constant ceiling, and a capacity cost function. The V1/V2 budget function stays for legacy requests.
  - src/drive_cli.rs:448-457, 512-530: Schema-3 request: record F0 and the reserve policy, with no /3 split and no 16 GiB cap. The recovery checksum is also written to the run directory, as a locator only.
  - crates/n2r-win32/src/shadow_native/private_tree/placement.rs:345-412, 615-687; crates/n2r-win32/src/shadow_evacuation.rs:224-291; src/general_qualification/compact_construction.rs:140-150: Pass the NTFS-allocated ranges into placement, using tier-1 then tier-2 first-fit for scratch and evacuation. Optionally evacuate ReFS initial runs that sit on NTFS-allocated non-desired bytes. Add per-tier byte counters to construction-placement.json. Every move keeps its full native proof.
  - src/general_qualification.rs:77-93: Flush the directory handle after the final pin (or use MOVEFILE_WRITE_THROUGH), so the published bundle is durable before activation (verifier item 8).
  - src/general_reconstruct.rs:807-845; src/bin/lab-convert-native-composite.rs; lab/Start-AllocationInterruption.ps1; lab/Start-AllocationRecovery.ps1: Lab-only faults: --interrupt-phase A|B|RB --after-writes N, and --interrupt-marker SA|AP|HND|RB|ABT --torn-bytes K, which writes K bytes of the marker, flushes, then exits 86.
  - src/bin/lab-hybrid-journal.rs (new): Ordinary-file integration harness, like lab-selected-journal. It covers every write boundary, torn slots, device-refs and journal-refs, and zero kinds. No unit tests.
  - src/drive_recovery.rs:99-103: Route schema-2 allocation bundles to the hybrid recovery path. Schema-1 bundles keep the N2RSEL01 path.
  - src/refs_hybrid/delta.rs:24-60 (stage H4 only): HybridDeltaLayout: COPY ranges are not stored in the packed file, and DifferenceImage serves them from source-physical segments.
QUALIFICATION: Unit tests are excluded by the user. Each step uses focused release builds plus native or ordinary-file integration.

Q0, measurement, no writes beyond today's behaviour:
- Add non-gating classification counters to the capture, plus a lab count-only mode that keeps classifying after the budget would refuse and then refuses before journal preparation.
- Run it on the 808 fixture after a fresh restore of 5f30f4a1 (state verified from a new PowerShell process; storage-epoch check with lab/Lab.psm1).
- Record: bytes per class (A-COPY, A-ZERO, A-NEW, B with old payload or zero, B with new payload, zero or ref); origins inside [0, 6,174,015,488); evacuation_remaining_blocked_bytes.
- Separately, compute host-side the split of the 52 GiB run's 159 ranges against the archived inspection; no VM needed.

Q1, src/bin/lab-hybrid-journal on ordinary files:
- Interrupt at every write boundary in the crash table: write N in A (first, middle, last), barrier, torn AP, B (first, middle, granule 0), before HND, torn HND, torn RB, middle of the restore, torn ABT, torn SA plus abandon.
- From each preserved state, run resume and rollback separately.
- Require: exact digests, refusal of closed replay, and refusal for foreign B bytes and changed device-refs.

Q2, native 52 GiB fixture:
- Conversion: 15/10 objects and hashes, label and mount verified.
- The same interruption matrix through lab/Start-AllocationInterruption.ps1 and Start-AllocationRecovery.ps1, each followed by guest restart, then --recover (ReFS 15/10) and, from a temporary checkpoint, --recover --rollback (NTFS, 7/7 XXH3).
- TurnOff hard power-off during A, just after AP, during B, during RB, and right after bundle publication. Attributes must stay 1 (or 3 before activation); then recover.
- Mutation plus cold restart (lab/Invoke-AllocationMutationReboot.ps1).

Q3, 808 fixture with placement steering:
- End-to-end conversion.
- Resume and rollback, verified with XXH3 originals via src/bin/lab-content-digest.rs.
- Mutation plus restart.
- Record measured journal_length and peak OS-volume use against the projection.

Q4 (optional H4):
- Run the packed backing without COPY bytes on both fixtures.

Throughout:
- Record each result as a scoped observation in evidence/ and AGENTS.md. Nothing transfers to other builds.
- Claim nothing about physical power loss.
RISKS:
  - Misclassification: an NTFS-allocated byte classified as A would be silently left unrestored by rollback. Mitigations:
- Classify only from ConsistentRawModel ranges (cross-checked with the native bitmap, and digest-rechecked at protected_prefix, general_composite_target.rs:843-848).
- Re-validate A ∩ NTFS-allocated = ∅ at prepare and before activation.
- Bind classification_sha256 in the certificate.
Recovery cannot re-check this against NTFS and trusts the pin.
  - The class split on the 808 fixture is unmeasured. If most changed bytes are origins inside the ReFS metadata prefix with non-zero new content, the journal is about 2x those bytes and the savings are smaller. Only D-H1 removes the origin's old copy.
  - Placement steering adds FSCTL_MOVE_FILE moves (about 105 ms each, measured) and needs the NTFS-allocated ranges inside the scratch and bitmap interval caps (placement.rs:366-371; set D of the scale design), so it may raise placement time or refuse earlier.
  - Extra source reads:
- device-ref hashing at prepare;
- the copy reads in stage A;
- the A readback at the barrier and again at resume and handoff.
That is roughly 3-4x the staged bytes in random I/O on the source disk.
  - Range and record growth from zero and reference splitting. The hybrid format uses u64 counts, but the 16 MiB plan read cap (general_recovery/allocation.rs:116) and the DeltaLayout and capture caps of 65,536 must lift together (set C), or a refusal moves downstream. It must still land before activation.
  - Torn-slot completion (E3) is only as sound as the 'write_marker syncs and reads back before anything proceeds' premise on an ordinary NTFS file, which is not write-through. It is untested under physical power loss, and it is not adopted without a user decision.
  - Pre-activation stranding is unchanged. Refusals or crashes leave the source at attributes 3 with no automated release, and the hybrid adds more pre-activation work. Any release that clears protection would need its own user decision.
  - The reference-import and managed-shadow attribute setters still do not flush (AGENTS.md:235-237). TurnOff keeps host-cached VHDX writes, so a lying-cache device can lose flushed B writes. Those read as old and stay recoverable, but this is unproven physically.
  - N2RHYB01 runs change every journal and ticket pin. Earlier recovery and power-off evidence (N2RSEL01) does not transfer, and the full matrix must be requalified.
  - A capacity policy reserve and a measured free space mean the same volume can pass on one run and refuse on another. That outcome is recorded, never a post-activation failure. Recovery may refuse on a machine with less RAM, but it needs no extra disk beyond copies of its inputs.
----- VERDICT 1: sound=False
VIOLATIONS:
  - E-1 removes recovery's only content check on the F ranges (N and R records), so stale F records can be replayed onto a changed source. Recovery ties the source to the bundle only by disk identity plus attributes == 1 (src/general_recovery/allocation.rs:236-241; crates/n2r-win32/src/native.rs:2610-2625). Nothing else checks source content except the journal's per-byte old-or-new rule (src/selected_journal.rs:536-543, 575-582), which v1 applies to every changed byte. Under E-1, Resume accepts any byte already on an F destination and overwrites it. Scenario: an NTFS that was brought online outside the tool, used, and later set back to attributes 1 can lose user data that NTFS wrote into clusters that were free at freeze time. Resume does check the A ranges byte by byte first, but that catches the change only if the NTFS metadata it touched ($Bitmap, $MFT, $LogFile) happens to lie in an A record. The hybrid makes this path more likely. Every state before BAR leaves NTFS fully intact and mountable. Once F writes exist, no tool path brings it back: source_cancel needs attributes 3 and an unchanged whole-source hash (crates/n2r-win32/src/source_cancel.rs:74-106), and recovery needs attributes 1. A manual Set-Disk online becomes the obvious way out. This breaks the AGENTS.md:286-287 rule that nothing authorizes replay over a mounted or later-changed filesystem.
  - E-1 and E-2 narrow what is checked. AGENTS.md:261-262 requires a separate user decision before any such change. The plan builds them and runs them natively with v2 forced (Q2-Q4) before the user confirms. It asks for confirmation only before auto mode becomes the default. The decision has to come before implementation and native qualification.
  - There is no gate for VSS snapshots on the source. Writes go straight to \\.\PhysicalDrive at the partition offset (native.rs:2739-2747), below volsnap, so nothing is copied before it is overwritten. Under E-2, a v2 rollback does not restore F ranges written into NTFS-free clusters that a shadow copy still references, so those snapshots are silently corrupted. A v1 rollback restores every changed byte. Today the 1 MiB per-file cap on System Volume Information streams (src/general_shadow.rs:134-137) probably keeps diff-area files out, but only by accident. docs/history/unbounded-scale-design.md:707 deletes that cap. The draft names VSS only under risks: there is no gate in code_changes, the invariants or the qualification plan.
  - Invariant I1 claims recovery can do something it cannot. load() is supposed to check that every segment lies inside NTFS-allocated bytes, and that the class map is re-checked in load(). But neither the NTFS-allocated set nor the class map is stored in the N2RSEL02 immutable region or in any recovery input (the bundle fields are at general_recovery/allocation.rs:23-34). Recovery can check only that segments are disjoint from N and R destinations. Either store the class map or allocated set in the journal, or restate I1 as trust in the immutable pin.
  - The resolver is described two ways. P3 and the BAR rationale say origins are read from the device before BAR, and that BAR provides 'the fast device-read path'. I2 says resolved bytes come only from A old payloads, or from device bytes outside every armed range. If the source is picked by BAR state, there is a failure case. The OS volume loses BAR to a flush that did not reach the medium, while A writes did land. Origins that A overwrote are then read from the device, fail new_sha256, and Resume refuses. That is safe, but the volume is stranded. The resolver must use A old payloads for overlapping origins in every phase.
  - The draft says the native one-way WritePolicy phase also enforces the F-before-A order. That overstates it. The native layer cannot see whether BAR is durable. arm_writes is single-use (native.rs:2661-2663), and validate() ties maximum_bytes to journal_profile.max_changed_bytes (native.rs:293-294). A new phased-arming API is needed, and the BAR-before-A guarantee holds only inside the writing process.
  - Stage H1 keeps the 65,536-range caps (selected_journal.rs:16; delta.rs:30; source_backed.rs:533-536), against the SCALE DECISION (AGENTS.md:258-262). Splitting changed runs at class and route boundaries makes the v2 record count X larger than the capture's run count. The draft does not say whether the 65,536 cap applies to runs or to records after the split. As written, a fragmented fixture could pass capture and DeltaLayout and then fail validate() late. That is still before activation, so it is safe, but it is late.
CRASH GAPS:
  - HND written (valid or torn) while an F range does not match new_all. This can happen when the source device drops F writes it reported as flushed, and the verification read was served from cache. CompleteHandoff and VerifyHandoff refuse, and rollback is closed, so the volume is stranded. Rewriting F from N payloads and the resolver would be safe, because F is NTFS-free and the resolver does not depend on device state, but the draft offers no such path.
  - ABT torn, or valid, with old_A not matching. This can happen when the device drops part of the rollback's A restore. CompleteAbort and VerifyAborted only verify, and forward replay is closed, so the volume is stranded. Re-running the idempotent A restore from a valid RB would reach the NTFS state.
  - A torn sector in an A range that matches neither old nor new still refuses both directions (selected_journal.rs:536-543; H-D2 not adopted), even though the journal holds both copies. This is realistic under physical power loss.
  - The OS volume loses AP to a flush that did not reach the medium, after F writes (or some A writes) landed on the source. The lifecycle reads PreparedClear or ApplyAttempted, Abandon refuses on old_F, and Resume is refused. source_cancel needs attributes 3 and the original whole-source hash, which F writes have broken. No tool path is left. Before any A write NTFS is intact, but the only way out is a manual online, which then opens the E-1 replay.
  - The OS disk loses the SYSTEM-hive write recording activation (attributes back to 3) after F writes. Recovery needs attributes 1 and cancel needs the whole-source hash, so neither works and the volume is stranded with no tool path. v1 has the same outcome.
  - The lifecycle table leaves some marker combinations undefined: HND (valid or torn) with BAR absent when F is non-empty; BAR or RB present after both AP copies are later corrupted; and the order in which ABT, RB and AP take precedence. Each needs an explicit refuse or action.
  - Existing gaps the hybrid keeps:
- bring_online leaves attributes at 0, so label and mount-path completion are never retried.
- The source is stranded before activation when recovery sees attributes 3.
- The bundle checksum exists only on stdout until result.json is written.
MISSING:
  - Run Q0 first and make its result a gate. The class split (B_A, B_N, B_R) on the 808-file fixture is not measured, and neither is whether exact v1 sizing alone converts it. The draft's savings claims rest on those numbers. Whether relocated origins sit mostly in the ReFS prefix [0, 6,174,015,488) is also unverified.
  - Give Resume back a content check on F without storing payloads. Two options:
- Store per-512 B-sector old and new digests (for example XXH3-64, about 3% of the F bytes) and require every F sector to be old or new before overwriting it. This is the existing rule at device-atomic granularity.
- Or pin a witness digest of the NTFS metadata ranges not covered by A ($MFT, $MFTMirr, $LogFile restart pages, $Bitmap, $Volume) and check it before any resume write.
Add a native test that mounts NTFS outside the tool, changes it, sets it back to attributes 1, then runs --recover and expects a refusal.
  - Add a gate that refuses hybrid mode, or falls back to v1, when VSS snapshots exist on the source: shadow-copy catalog or diff-area files ({3808876b-c176-4e48-b7ae-04046e6cc752}) in System Volume Information. Add a fixture that has a snapshot.
  - Store the class map, or the NTFS-allocated set, in the N2RSEL02 immutable region so recovery's load() can recheck I1. Otherwise drop that claim.
  - Make the resolver independent of phase: origin bytes that overlap an A record always come from that record's old payload; device reads only cover bytes outside every armed range. Verify per chunk with new-byte hashes, so multi-GB R records are not read twice and written in a separate pass.
  - Specify the new native phased-arming API. It replaces the single-use arm_writes and the profile ceiling in validate(), and the draft should say which ordering is enforced natively and which only in-process.
  - Define how the 65,536 cap counts records after the class split, consistently across capture, DeltaLayout and the v2 record table, or lift the caps together.
  - Fill out the lifecycle: CompleteAbort falls back to re-running the A restore when RB is valid; optionally allow an F-only repair under HND; define the remaining marker combinations.
  - Get explicit user decisions on E-1 and E-2 before implementing them or running them natively. That covers rollback leaving ReFS structures and file copies in NTFS free space, and resume overwriting unchecked F bytes.
  - Qualification also needs:
- a chkdsk /scan (read-only) after a v2 rollback;
- a fixture with 4 KiB clusters, where ReFS end structures may fall outside the NTFS tail past the last cluster and land in class N;
- a TurnOff right after bundle publication;
- recording that physical power loss and flushes the device acknowledges but does not persist remain untested.
  - Fix a factual error in drive_cli: the current minimum is 4 GiB of available space (drive_cli.rs:449-451), not '16 GiB'.
RECOMMENDATION: Do not adopt N2RSEL02 as written. Most of the crash table holds:
- dual-copy markers;
- separate RB and AP slots;
- F written before A, with a barrier;
- A kept old+new;
- R rebuilt from A old payloads or from untouched device bytes, with hash checks.
Old A payloads plus invariant I1 do protect NTFS-allocated bytes for rollback. Under the user's allocation guarantee, no crash point found loses NTFS-allocated data.

The draft is not sound for three reasons:
1. E-1 removes recovery's only content check on F ranges, so a stale journal can replay N and R records over a changed NTFS. Recovery binds the source only by disk identity and attributes 1. The hybrid also makes NTFS-intact strandings, with no tool exit, more common.
2. There is no VSS gate, and rollback under E-2 leaves snapshot-referenced free clusters overwritten.
3. Invariant I1's recovery-time check cannot be implemented, the resolver is described inconsistently, and the native ordering guarantee is overstated.

Required facts are also unverified: the 808-file class split, and whether exact v1 sizing alone would convert that fixture.

Next steps:
- Run Q0 first. If exact v1 sizing fits, ship that and defer the hybrid.
- Otherwise revise: add per-sector old/new digests for F (or a pinned NTFS-metadata witness), a VSS-absence gate, the class map stored in the journal, a resolver that does not depend on phase, a complete lifecycle table (including CompleteAbort falling back to an A restore), and an explicit native phased-policy API.
- Get the user's E-1 and E-2 decisions before implementing anything or running anything natively.
===== DESIGN 2: N2RSEL02 range-class journal: hybrid in-volume staging, with an exact-size external old+new fallback
WRITE PHASES: This is a read-only design; I edited, built and ran nothing. File:line citations refer to HEAD on codex/isolated-journal-observation.

Three range classes. Every changed 4 KiB granule of the capture layout (the ranges the source_backed.rs:476-556 capture loop finds changed) gets exactly one class. Classification happens in-process from raw.allocated_byte_ranges (ntfs_inspect.rs:197-254). That is the same set whose XXH3 admission digests and rechecks before capture (general_composite_target.rs:839-848).
- **A (allocated destination).** The granule intersects NTFS-allocated bytes, or nothing else applies. The journal stores old and new bytes.
- **N (free destination, new bytes stored).** The granule does not intersect NTFS-allocated bytes. It holds ReFS metadata, zeros, residual tails, SVI, or route data with no eligible copy map. The journal stores new bytes only, plus a SHA-256 of the old bytes.
- **R (free destination, new bytes by source reference).** The granule is NTFS-free, lies inside a relocated payload route, and has an eligible copy map:
  - a single unnamed $DATA attribute with flags 0 and lowest_vcn 0 (the filter at general_composite_target.rs:577-587);
  - every origin extent physical, with no sparse hole;
  - 4 KiB-aligned origins.
  The journal stores no payload. It stores the origin segments (physical NTFS coordinates), new_sha256, and old_sha256 without a payload.

Fixed class rules:
- Partition granule 0 and the post-domain tail are always A.
- R origins are inside NTFS-allocated bytes, so they are disjoint from every N or R destination.

Ordered phases. Each phase lists what it may overwrite.

**P0. Pre-activation (attributes 3).** May overwrite:
- the shadow VHDX, through shadow-only FSCTL_MOVE_FILE during placement. Scratch and evacuation prefer NTFS-free space.
- fresh create_new files on the OS volume: the changed-clusters.bin backing, the preallocated selected.journal, the pins and bundle v2.
- No source byte.

**P1. Activation, attributes 3 to 1.** activate_for_journal plus RegFlushKey (native.rs:2530-2571, 396-425). No content write.

**P2. Apply intent.** The journal slots AP.1, then AP.2, are written, each synced and read back. Only those two zeroed slots are written. A fresh Apply first requires:
- a LiveApplyToken issued from the original certificate;
- load() over the whole journal;
- exact old_A and old_F digests.

**P3. Staging, phase F.** The native WritePolicy is in its staged phase, so only N and R destination ranges are armed. These are NTFS-free bytes only.
- N bytes come from the journal.
- R bytes come from the resolver. Before BAR the resolver reads origins from the device. Each record's bytes are checked against new_sha256 before any write.
- Chunks already equal to new are skipped.
- Then target.sync_all, the complete new_F digest, and an immutable-region recheck.

**P4. Class barrier, BAR.** BAR.1 and BAR.2 are written to the journal, each synced and read back. BAR is written only after every F byte has been flushed and new_F verified.

**P5. Allocated, phase A.** The policy advances one way to the allocated phase: A ranges become armed and F ranges are disarmed.
- write_span works as today (selected_journal.rs:556-603): each byte must be old or new, and the desired side comes from the journal.
- All A ranges except granule 0 are written, then sync, then granule 0, then sync (selected_journal.rs:645-660).
- Then check new_A, new_F and new_all, and recheck the immutable region.
- Before the first A write, every NTFS-allocated byte is untouched.

**P6. Handoff.** HND.1 and HND.2 are written after full verification against new_all.

**P7. Online.** bring_online sets attributes 1 to 0 (native.rs:2682-2699). Then verify_native_scoped, finalization and result.json.

Rollback, from AP or RB:
1. RB.1 and RB.2 are written in their own slots. AP is never overwritten, unlike the shared intent slot today (selected_journal.rs:639-644).
2. Only A is armed. A is restored backward with granule 0 last.
3. sync, then verify old_A exactly.
4. ABT.1 and ABT.2, then bring_online NTFS.
5. F ranges are never written by rollback. They keep staged ReFS bytes, which the allocation guarantee allows.

Abandon, before any valid AP: verify old_A and old_F exactly, then write ABT, with no target write.

Resume, from AP:
- A is checked byte by byte as old or new, as today.
- F is rewritten or repaired from the resolver at any phase, then verified against new_F.
- If BAR is not yet durable, BAR is written.
- Then P5 and P6.

Why ordering does not depend on BAR durability. The resolver reads only two things:
- the journal's immutable region: the A old payloads, which cover any origin bytes that A overwrites;
- device bytes outside every armed range, which no phase ever writes (native.rs:303-312, 2729-2738).

So R new bytes can be rebuilt in any state, including after BAR or with a lost BAR. BAR provides three things:
- the in-process ordering (all F durable and verified before the first A write, also enforced natively);
- the fast device-read path for origins;
- clean lifecycle evidence.

Fallback (full old+new): N2RSEL01 is used byte-identically to today when any of these holds:
- hybrid is not enabled, which is the default until qualified;
- B_N + B_R = 0 after capture;
- a hybrid precondition fails, such as a missing native NTFS bitmap cross-check.

Per range, any relocated destination that lands on NTFS-allocated bytes because in-volume room ran out is class A, so it gets old+new.
JOURNAL: The new format is N2RSEL02 (format 2). It sits beside N2RSEL01; the old code (selected_journal.rs:1-857) and the bundle v1 readers stay unchanged.

**Layout**
- **[0, 64 KiB): marker body.** 16 slots of 4 KiB:
  - slots 0-1: HND (N2RSHN02)
  - slots 2-3: ABT (N2RSAB02)
  - slots 4-5: AP (N2RSAP02)
  - slots 6-7: BAR (N2RSBR02)
  - slots 8-9: RB (N2RSRB02)
  - slots 10-15: reserved; must be zero, otherwise refuse.
  A marker contains its kind, format, copy index, immutable_sha256, the kind digest (AP/BAR/HND carry new_all; RB/ABT carry old_A), the SHA-256 of the canonical ticket bytes, zero padding, and a self-SHA-256 in its last 32 bytes. This is the scheme at selected_journal.rs:465-473, extended.
- **[64 KiB, +256): header.** Fields:
  - N2RSEL02, format 2, image_length;
  - u64 record_count and segment_count;
  - bytes and record counts per class (A, N, R), plus zero-payload byte counts;
  - journal_length;
  - offsets of the record table, segment table, payload area and footer;
  - class_map_sha256 (equal to the value the certificate binds);
  - the pinned max_journal_bytes ceiling;
  - a header SHA-256.
- **Record table.** 128 B per record, sorted and disjoint by offset. Fields:
  - offset, length (u64);
  - class (A, N or R);
  - old_kind (Payload / Zero / HashOnly) and new_kind (Payload / Zero / Reference);
  - old_at, new_at;
  - seg_first, seg_count;
  - old_sha256 and new_sha256, each 32 B.
  A records have old_kind Payload or Zero. N and R records have old_kind HashOnly. Only A and N records have a new payload.
- **Segment table.** 32 B per entry: source_offset, length, kind (Physical or Zero). A record's segments are ordered and their lengths sum to the record length. Every segment must lie inside NTFS-allocated bytes and outside every N or R destination; this is validated at plan time and in load().
- **Payload area.** For each A record, old then new; for each N record, new. A payload of all zeros is stored as a Zero kind with no bytes. That changes encoding only; check_target still compares against the zeros byte for byte.
- **Footer (256 B).** N2RSEND2, then old_A, new_A, old_F, new_F and new_all (framed SHA-256, as frame() at selected_journal.rs:94-97), journal_length, record_table_sha256 and segment_table_sha256.
- **Immutable pin.** SHA-256 over [64 KiB, end).

**Marker classification.** Each kind has a slot pair: copy 1 is written, synced and read back, then copy 2 the same way.
- **Valid:** either copy equals the expected marker.
- **Attempted:** no copy is valid, but at least one copy is non-zero.
- **Absent:** both copies are zero.
- A slot holding another kind's marker, or any non-zero reserved slot, refuses.

**Lifecycle**

| Combination | State |
|---|---|
| No markers | PreparedClear |
| AP attempted | ApplyAttempted, treated as PreparedClear for authority |
| AP valid | ApplyIntent |
| AP valid, BAR attempted | BarrierAttempted |
| AP valid, BAR valid | BarrierPassed |
| RB valid or attempted | Rollback |
| HND attempted or valid | Handoff |
| ABT attempted or valid | Aborted |

Invalid combinations refuse: HND together with RB or ABT, BAR without a valid AP, and HND without a valid AP.

**Per-class journaling**
- **A:** old and new payloads. Byte-wise check that each byte is old or new.
- **N:** new payload only; the old bytes are kept as a hash (old_sha256) with no payload.
- **R:** no payload. Origin segments, the new hash and the old hash only.

The fresh-Apply check needs the old_F digest. Abandon also checks old_F. Rollback and ABT verify old_A only.

**Schema and version changes**
- **Request schema 3.** JournalProfile::ResourceBoundedV3 { max_journal_bytes } is built by from_request, not from_schema. Its ceiling is the value pinned in request.json, replacing the 16 GiB constant at journal_file.rs:23 and 39-47.
- **SelectedPlanV2.** Carries the per-class totals, record_table_sha256 and class_map_sha256. Recovery takes the ranges from the verified journal record table, so the 16 MiB plan read at general_recovery/allocation.rs:116 cannot strand recovery.
- **SelectedTicketV2.** Carries the per-class bytes and counts, journal_length, immutable_sha256, the five digests, class_map_sha256, the pinned max_journal_bytes and total_write_bytes.
- **allocation-recovery-bundle.json schema 2.** Adds journal_format and the ticket v2 pin; schema 1 keeps its reader (general_recovery/allocation.rs:74-78).
- **AllocationCertificate.** Gains class_map_sha256 and the per-class bytes.
- **Range caps.** In stage H1, MAX_RANGES stays 65,536 (selected_journal.rs:16; delta.rs:30; source_backed.rs:533-536). Lifting them belongs with coupled set C.
SIZING: **Symbols**, all known exactly after capture:
- B_A, B_N, B_R: changed bytes per class.
- X: record count; S: R segment count.
- Z: zero-kind payload bytes.
- P: post-commit reserve. A derived bound covering finalization, completion, result and events.
- Q: recovery-process reserve. Recovery copies the bundle, request, plan and ticket into its own output before acting (general_recovery/allocation.rs:165-169), plus P.
- K: backing bytes. In stage H1, K = B_A + B_N + B_R, because changed-clusters.bin still holds every changed granule. In stage H2, K = B_A + B_N, once a DeltaLayout SourceReferenced range kind drops R from the backing.

**Journal sizes**
- J_v2 = 65,536 + 256 + 128·X + 32·S + 2·B_A + B_N − Z + 256.
- J_v1 = 8192 + 80 + 80·X + 2·(B_A + B_N + B_R) + 80. This is unchanged (selected_journal.rs:135-140).
- Need_m = K + J_m + P + Q, for m = v1 or v2.

**OS-volume capacity.** Cap = observe_volume_space(journal volume).available − safety_reserve.
- safety_reserve is a recorded policy (default max(1 GiB, 2% of the volume)). Its lab knob can only raise it.
- Cap is re-observed at every gate. Nothing is computed from a fixed /3 split or a 16 GiB cap; this replaces drive_cli.rs:453-457 and lab_reconstruct.rs:54-62.

**Gates.** All run before activation, and every refusal happens with source attributes still 3.

1. **Drive start.** request.max_journal_bytes (schema 3) = available − safety_reserve. It is only a ceiling. It is pinned and recovery never re-measures it, which fixes the R5/C5 contradiction (unbounded-scale-design.md:821).
2. **G-P, after placement, before shadow freeze.** Record-only projection: R_proj is the relocated route bytes on NTFS-free space with an eligible copy map. This is the in-volume (staging) capacity actually achieved.
   - Placement decides in-volume room by tiered first-fit. Spans that are free in both ReFS views and also NTFS-free come first. NTFS-allocated, ReFS-free spans are used only when those run out.
   - Anything placed on NTFS-allocated bytes becomes class A, which is the per-range fallback.
3. **G-C, after the protected observation, before capture.** compared is intersected with raw.allocated_byte_ranges and the eligible routes. This gives exact per-class upper bounds U_A, U_N and U_R, and from them Need_upper.
   - The shadow is frozen here, so the VHDX no longer grows.
   - If Need_upper ≤ Cap, the capture cannot refuse on capacity.
   - Otherwise the capture's in-loop class accountant replaces the single max_changed_bytes check (source_backed.rs:517-521). For each changed run it splits by class with partition_point, charges the running Need (A costs 3 per byte in H1, N costs 2, R costs 1 or 0, plus record and segment bytes), and refuses when Need > Cap. On refusal it writes class-split counters.
4. **G4, after capture, before the journal file exists.** Uses the exact B_A, B_N, B_R, X and S, and re-observes Cap. Mode selection:
   - **v1** when the hybrid is not enabled (the pre-qualification default) or B_N + B_R = 0.
   - **v2** otherwise, once qualified, or when a lab flag forces it.
   - The chosen mode's Need must be ≤ Cap, or the run refuses.
   - The journal is then preallocated to exactly J_m with FileAllocationInfo. EOF stays 0, so the existing empty-file checks hold (allocation.rs:116-121; selected_journal.rs:304).
   - The ticket pins journal_length and max_journal_bytes.
5. **G5, before activation.** Re-observe Cap ≥ P + Q.

**Recovery limits** come only from pins: journal length equals ticket.journal_length and is ≤ request.max_journal_bytes. The WritePolicy maximum equals ticket.total_write_bytes, which is ≤ the partition size. Recovery never takes a new free-space reading.

**WritePolicy.** For V3, the cap at native.rs:293-294 that ties write bytes to the journal changed-byte ceiling is replaced by maximum_bytes == sum(staged ∪ allocated) ≤ length. This is needed because R and N writes are not, or only partly, journaled.

**808-file fixture (inference; the split is unmeasured).** With about 39.7 GB available:
- v1 needs about 3B plus reserves.
- If most of the ~6.43 GB of relocated data lands NTFS-free (R), H1 v2 needs about B + 2·B_A and H2 needs about 3·B_A.
- Q0 measures the real split first. Exact v1 sizing alone may already fit.
INVARIANTS: I1, class soundness.
- An N or R granule never intersects raw.allocated_byte_ranges at granule granularity. That set is the digest-bound one (general_composite_target.rs:839-848; ntfs_inspect.rs:197-254).
- Anything undetermined is class A, and granule 0 and the post-domain tail are always A.
- The class map is derived in process, bound by the live certificate, and re-checked in prepare and load.

I2, resolver closure.
- R origins lie inside NTFS-allocated bytes and outside every N or R destination.
- Resolved bytes come only from the journal's immutable region or from device bytes outside every armed range. WritePolicy makes those device bytes unwritable (native.rs:303-312).
- Resolved bytes are SHA-256-verified before every write. R reconstruction therefore never depends on device write state or on BAR durability.

I3, old coverage. Every NTFS-allocated byte that any phase writes has its old bytes, or a Zero kind, in the journal. Rollback therefore restores the complete NTFS-allocated set.

I4, ordering.
- In each process, no A write is issued until that process's F writes are flushed, new_F is verified and BAR has been read back.
- This is enforced in sj2 and natively by the one-way WritePolicy phase.
- Granule 0 is written last in both directions.

I5, fresh Apply authority.
- A fresh Apply needs a LiveApplyToken. Only the original in-memory AllocationCertificate can issue one, after binds(proof) plus the ticket's class map and totals.
- Recovery cannot construct a token. PreparedClear and ApplyAttempted never resume.

I6, recovery never clears protection.
- Reopen requires attributes exactly 1 (native.rs:2620-2625).
- The only attribute change is the existing bring_online after a closed HND or ABT lifecycle.
- There is no attribute repair, identity change or rebinding.

I7, HND and ABT close replay.
- Any non-zero HND slot closes rollback, and any non-zero ABT slot closes forward replay.
- Both at once refuse.
- Completing an attempted terminal marker verifies the committed side (new_all or old_A) and writes no target byte.

I8, markers. Markers are write-once per kind, with two copies. A slot only ever holds zero, a tear of its own kind, or its own kind. AP is never overwritten by RB.

I9, capacity.
- The journal length is exact and preallocated before activation.
- Recovery limits come only from pins: ticket.journal_length, request.max_journal_bytes and the record table. Free space is never re-measured.

I10, write authority.
- Armed ranges equal exactly the record table for each phase.
- Cumulative requested bytes per handle are at most total_write_bytes.
- A short or failed write poisons the handle.

I11, scope honesty. Evidence states:
- free_space_contents_compared=false;
- free_destination_restored_by_rollback=false;
- the per-class bytes;
- that NTFS-free bytes were not proven unchanged.

I12, compatibility. When v1 is selected, the N2RSEL01 bytes, ticket and bundle v1 are byte-identical to today, and v1 recovery is unchanged.
SCOPE CHANGES: E-1 (implied by the Hybrid decision; I recommend confirming it explicitly). On resume, and on a rollback that leaves them untouched, bytes on N and R destinations are not checked byte by byte against old or new before they are overwritten, because no old payload exists. Today write_span and check_target check every changed byte (selected_journal.rs:536-543, 575-582). A fresh Apply and Abandon still require the exact old_F digest, and every F range must equal new_F after its writes. | E-2 (consistent with the allocation guarantee; state it in evidence). Rollback restores, and ABT/VerifyAborted verify, only A ranges against old_A. N and R destinations keep the staged ReFS bytes in NTFS free space. Today rollback restores every changed range, including NTFS-free ones. | E-3 (recovery input change; it does not narrow any check). Resume can read unwritten source bytes (R origins) outside the write set, each hash-verified. Today recovery reads only the journal and the target ranges. | E-4 (encoding only). An all-zero old or new payload is stored as a Zero kind, and check_target still compares byte for byte against zeros. | Placement steering toward NTFS-free scratch changes which destinations are chosen, not what is checked. Every per-move check stays, as the PER-MOVE CHECKS decision requires. | NOT ADOPTED (H-D1): store the old bytes of origin A ranges by reference to the staged R copy instead of in the journal. This would leave a single copy on the same device during phase A, so a lost or corrupted staged copy means permanent data loss on rollback. It needs its own user decision. | NOT ADOPTED (H-D2): accept a foreign or torn byte in an A range and rewrite it from the journal. Today's refusal in both directions is kept. | NOT ADOPTED (H-D3): let Abandon close with an old_F mismatch, which would only help when the journal disk loses a flushed AP.
CRASH TABLE (23 rows):
  - Before freeze. Covers drive selection, request/devices JSON, and shadow VHDX creation (drive_cli.rs:448-532). => durable: Source online, attributes 0, and unchanged. The run directory, dynamic shadow VHDX and drive-selection.json exist. No bundle exists. | resume: Not applicable. There is no bundle, and drive_recovery.rs:99-103 finds nothing. A new conversion is a fresh run. | rollback: Not applicable. No source state needs undoing.
  - Freeze through shadow placement. Placement is shadow-only FSCTL_MOVE_FILE, including the hybrid's tiered NTFS-free-first scratch and evacuation. Also includes metadata completion and shadow freeze. => durable: Source OFFLINE|READ_ONLY (3), flushed. NTFS bytes are unchanged. The shadow is partially placed and its placement artifacts exist. No backing, journal or bundle. | resume: Refused. No bundle, and recovery reopen requires attributes 1 (native.rs:2620-2625). | rollback: No automated path. This is the existing pre-activation stranding: the operator uses lab-abort or Set-Disk. The hybrid adds no source write here.
  - Capture with the class accountant. This includes an accountant refusal because Need exceeds Cap, which the hybrid adds at the same site as source_backed.rs:517-521. => durable: Attributes 3. The changed-clusters.bin backing is partial. class-split.json holds counters only and is never pinned. NTFS is unchanged. | resume: Refused, as in the previous row. | rollback: No automated path. Unchanged NTFS stays protected.
  - G4 exact sizing and refusal, journal FileAllocationInfo preallocation, and N2RSEL02 immutable-region writes plus sync (the counterpart of selected_journal.rs:294-367). => durable: Attributes 3. The journal file exists, partial or complete, with an all-zero marker body. No ticket or bundle. A journal without a pinned ticket and bundle is never a recovery input. | resume: Refused, as in the earlier pre-activation rows. | rollback: No automated path. NTFS is unchanged.
  - Pin publication: ticket v2, plan v2, request, verification, then bundle v2. Each is synced, and the hybrid adds a directory flush (or write-through rename) before activation. Compare general_conversion/allocation.rs:158-185. => durable: Attributes 3. Some or all pins exist. After a hard power-off with no directory flush, the bundle name may be missing (verifier item, unbounded-scale-design.md:832). The journal is PreparedClear. | resume: Refused. Reopen needs attributes 1, and PreparedClear never resumes (general_recovery/allocation.rs:213-215). | rollback: Refused at reopen because attributes are 3. This is the existing stranding; protection stays set.
  - Activation in flight: set_attributes(OFFLINE) followed by RegFlushKey(HKLM\SYSTEM) (native.rs:396-425, 2548). => durable: Either attributes 3, because the hive was not flushed (TurnOff evidence, AGENTS.md:226-234), or attributes 1. Journal PreparedClear. Target equals the full old state. | resume: Attributes 3: as the publication row. Attributes 1: refused, because a fresh Apply needs the live certificate. | rollback: Attributes 3: refused at reopen. Attributes 1: Abandon verifies old_A and old_F exactly, writes ABT.1 and ABT.2, then brings NTFS online and mounts it.
  - Activated, in-memory policy armed, fresh-Apply prechecks in progress (load(), old_A and old_F exact), before AP.1 is issued. => durable: Attributes 1. All marker slots are zero. Target equals the full old state. | resume: Refused (PreparedClear). | rollback: Abandon: verify old_A and old_F exactly, write ABT, mount NTFS.
  - AP write in flight. Two cases: AP.1 torn with AP.2 zero (ApplyAttempted), or AP.1 valid with AP.2 zero or torn. => durable: Attempted: no target write has happened, because writes start only after both AP copies are read back. AP.1 valid: intent is durable, the target is still fully old, and AP.2 is rewritten on resume. | resume: Attempted: refused, treated as PreparedClear, since resuming would be a fresh Apply. AP.1 valid: Resume, as in the phase F row. | rollback: Attempted: Abandon with old_A and old_F exact, then ABT. Valid: Rollback as in the phase F row. Today a torn single-slot intent refuses both directions (selected_journal.rs:487-490).
  - AP durable, phase F in progress: partial or torn sectors on N/R destinations, and possibly lost device cache. => durable: Attributes 1 and AP. F destinations hold an arbitrary mix of old and new. A is exactly old, since no A write has happened. R origins are intact. | resume: 1. load() and the marker check.
2. A byte-wise old/new check; exact old is recorded.
3. Rewrite F: N from the journal, R through the resolver, each hash-verified before writing. Any pre-write byte on an F destination is accepted (E-1).
4. sync, then verify new_F.
5. Write BAR.
6. Phase A, then HND, mount ReFS and verify_native_scoped. | rollback: 1. Write RB.1 and RB.2.
2. Arm A only. Nothing differs, so every chunk is skipped.
3. Verify old_A exactly.
4. Write ABT and mount NTFS.
F is left staged. Evidence records free_destination_restored=false and the observed F digest.
  - F synced and new_F verified, with BAR not yet written or BAR.1 torn (BarrierAttempted). => durable: AP present. F equals new if the device honoured the flush. A is exactly old. | resume: Re-verify new_F and repair it through the resolver on mismatch. Rewrite BAR.1 and BAR.2, then continue with phase A and HND. | rollback: As the phase F row: RB, verify old_A, ABT, mount NTFS. No target writes are needed.
  - BAR durable, before the first A write. This is a lab pause point for TurnOff. => durable: AP and BAR present. F equals new_F. A is exactly old. | resume: 1. Verify new_F. On mismatch, repair it in the staged write phase: origins outside armed ranges come from the device, and origins overlapping A come from the A old payload.
2. Advance the policy to the allocated phase.
3. Write A, then granule 0 last, then HND. | rollback: RB. A is untouched, so verify old_A, write ABT and mount NTFS.
  - Phase A in progress, excluding granule 0, with partial or torn writes. => durable: AP and BAR present. F equals new_F, unless a lying flush lost part of it. Each A byte is old or new, or a torn sector holds foreign bytes. | resume: 1. Verify or repair F through the resolver.
2. A byte-wise check. A foreign byte refuses both directions, which is the existing conservative rule (selected_journal.rs:536-543).
3. Write A forward, sync, granule 0, sync.
4. Check new_all, then HND. | rollback: 1. RB.
2. Restore A backward from the old payload, granule 0 last.
3. sync, then verify old_A exactly.
4. ABT, mount NTFS. F stays staged.
A foreign byte in A refuses.
  - A synced except granule 0, with the granule-0 write in flight. => durable: As the phase A row. The boot sector is still NTFS until this last write lands, so the volume never has a ReFS identity before the final write. | resume: As the phase A row. | rollback: As the phase A row. Granule 0 is restored last.
  - All writes synced and the final new_all check running, before HND.1 is issued. => durable: AP and BAR present. Target equals new_all. | resume: Resume skips every equal chunk, verifies, and writes HND. | rollback: RB, then A restored, old_A verified, ABT, NTFS.
  - HND.1 torn (HandoffAttempted). => durable: AP and BAR present. Target equals new_all, which was verified before the HND write. Attributes 1. | resume: CompleteHandoff:
1. Verify new_all with no target write.
2. Rewrite HND.1 and HND.2.
3. bring_online, then verify_native_scoped. | rollback: Refused. Any non-zero HND slot closes rollback.
  - HND durable, attributes still 1, before bring_online. => durable: HND valid. Target equals new_all. Offline. | resume: VerifyHandoff (verify_closed against new_all), then mount and verify_native_scoped. | rollback: Refused (general_recovery/allocation.rs:221-223).
  - bring_online in flight: set_attributes(0) plus RegFlushKey. => durable: Attributes 1 if the hive was not flushed, which falls back to the previous row. Attributes 0 means ReFS is mounted by Windows. | resume: Attributes 1: VerifyHandoff. Attributes 0: refused at reopen. Label and mount-path completion are not retried (existing gap). Recovery never re-protects and never replays. | rollback: Closed by HND.
  - verify_native_scoped, finalization.json or result.json writes after handoff. => durable: ReFS online. Journal HND. The OS-volume outputs may be partial. | resume: Refused at reopen. Post-commit verification has to be run manually. Raw replay is never authorized. | rollback: Closed by HND.
  - RB.1 torn (RollbackAttempted). RB has its own slots, so AP and BAR stay intact. => durable: AP (and possibly BAR) present, RB attempted. A is old or new byte-wise. | resume: Refused. Any non-zero RB closes forward replay. | rollback: Rewrite RB, restore A, verify old_A, write ABT. Today a torn AP-to-RB overwrite refuses every action.
  - RB durable, A restore in progress. => durable: RB present. A is a byte-wise mix. F is staged. | resume: Refused. | rollback: Re-run idempotently with the byte-wise check and granule 0 last, verify old_A, then write ABT.
  - ABT.1 torn (AbortAttempted), from either Rollback or Abandon. => durable: A equals old_A, verified before the ABT write. Attributes 1. | resume: Refused. Any non-zero ABT closes forward replay. | rollback: CompleteAbort: verify old_A with no target write, rewrite ABT.1 and ABT.2, mount NTFS.
  - ABT durable with attributes 1, or bring_online(NTFS) in flight. => durable: ABT valid. A equals old_A. Attributes 1, or 0 once the flush has landed. | resume: Refused. | rollback: Attributes 1: VerifyAborted, then mount NTFS. Attributes 0: refused at reopen; NTFS is already online.
  - Physical power loss with device or host cache loss. This is untested, because TurnOff keeps host-cached VHDX writes. => durable: Three cases:
- Source cache lost F writes after BAR was durable: F does not equal new.
- Lost A writes: those bytes are still old.
- OS-volume journal lost AP after F writes: the state reads PreparedClear while F differs from old_F. | resume: - F loss: repaired through the resolver, which is independent of device state.
- Lost A writes: accepted, since each byte is still old or new.
- AP lost: refused, because it looks like a fresh Apply. The volume is stranded with protection kept, the same class of outcome as N2RSEL01 today. | rollback: - F loss: irrelevant to rollback.
- Lost A writes: A is restored.
- AP lost: Abandon refuses on the old_F mismatch, so the volume is stranded with protection kept.
A durable marker copy that is later corrupted is still read from its other copy.
CHANGES (14):
  - src/selected_journal_v2.rs (new; selected_journal.rs left untouched): Implement N2RSEL02 with these parts:
- SelectedPlanV2 and SelectedTicketV2, and class and kind enums.
- validate() using checked u64 arithmetic for J_v2.
- prepare() reads old bytes from the frozen source handle, and A/N new bytes from DifferenceImage. For R records it resolves origins from the source and compares them byte for byte with the candidate (H1) or with the class-map XXH3 (H2), and computes old SHA-256 values without storing payloads.
- load() verifies the immutable pin, header, record and segment tables, A/N payload hashes and footer digests, and checks that every segment lies inside NTFS-allocated bytes and outside every N/R destination.
- After load(), prepare runs the recovery-mode resolver once, before the ticket is issued.
- Dual-copy write-once markers with valid, attempted and absent classification.
- Lifecycle states and the phase-ordered execute (F, sync, new_F, BAR, A excluding granule 0, sync, granule 0, sync, new_all).
- apply(token), resume, rollback (RB slots, A only), abandon (old_A and old_F), handoff, verify_closed (HND against new_all, ABT against old_A), and complete_handoff/complete_abort for attempted terminal markers. These completion paths write no target bytes.
  - src/selected_journal_v2.rs: the resolver: Add a Resolver that serves R new bytes per segment. A Zero segment yields zeros. A Physical segment that overlaps an A record is read from that record's old payload in the journal. Any other Physical segment is read from the target device at an offset outside every armed range. The result is checked against the record's new_sha256 before any write.
  - src/general_shadow/source_backed.rs:421-588: capture_difference_ranges_with takes a ClassAccountant built from the sorted NTFS-allocated ranges, the eligible-route map and Cap. Each changed run is split at class and route boundaries. The accountant:
- charges per-class need and replaces the single max_changed_bytes check at :517-521;
- accumulates XXH3-128 of candidate bytes per R record;
- records class-split counters;
- refuses with an unpinned counters artifact.
H1 keeps the 65,536-range cap (:533-536).
  - src/general_composite_target.rs:672-787: In verify_and_select:
- Compute raw.allocated_byte_ranges, already done at :843, and pass it through.
- Derive R eligibility and copy maps for relocated route pieces with the attribute filter from :557-632, applied to relocated pieces instead of in-place ones.
- Build ClassMap and class_map_sha256 in process, and store them in FrozenAllocationTargetPreservation.
- Add plan_v2(); keep plan() at :516-534 for v1.
- Assert that granule 0 and the post-domain tail are class A.
  - src/general_source_admission.rs:73-103: Add to AllocationCertificate:
- class_map_sha256 and the per-class bytes, checked in binds();
- authorize_fresh_apply(&proof, &ticket_v2) -> LiveApplyToken, which requires binds() plus equality of the ticket's class map and totals.
The token constructor is crate-private and never reachable from general_recovery, so a fresh Apply stays possible only with the original live certificate.
  - src/general_conversion/allocation.rs:15-302: In the conversion:
- G4 re-observation and mode selection (v1/v2).
- Exact J_m and journal preallocation.
- Bundle schema 2 carrying journal_format, with a .partial file, sync, write-through rename and a directory flush before activation.
- Replace the binds check at :189-192 with authorize_fresh_apply.
- A phased WritePolicy (staged = N∪R, allocated = A).
- Lab interruption points by phase.
  - src/general_recovery/allocation.rs:21-376: In recovery:
- Dispatch on bundle schema 2.
- Use the v2 action table: attempted AP leads to Abandon only; attempted BAR is pre-BAR; attempted RB closes forward; attempted HND or ABT leads to complete_handoff or complete_abort.
- Build the WritePolicy from the verified journal record table, not the plan JSON (:116, :252-257).
- Take every limit from pins.
- Keep reopen requiring attributes 1 (:234-241) and keep bring_online only after a closed lifecycle. Add no attribute transitions.
  - crates/n2r-win32/src/native.rs:266-313, 2656-2766: WritePolicy gains a staged range set and a phase (Staged, then Allocated, one way only). It gets advance_to_allocated(), callable only after sj2's BAR readback. permits() checks only the current phase's set. validate() for V3 requires maximum_bytes == sum of the sets and ≤ the partition length.
  - crates/n2r-win32/src/journal_file.rs:19-58, 252-271: Add JournalProfile::ResourceBoundedV3 { max_journal_bytes }, built by from_request(schema, pinned value). validate_file_fields_for_profile uses that pinned ceiling. V1 and V2 are unchanged.
  - src/lab_reconstruct.rs:40-68; src/general_conversion.rs:53-92; src/general_qualification/composite.rs:278-282: Under schema 3, drop the profile max_changed_bytes range check and pass the ClassAccountant. Request.validate accepts schema 3 with the pinned ceiling.
  - src/drive_cli.rs:448-457, 512-531: Use request schema 3 with max_journal_bytes = available − safety_reserve, as a ceiling. Drop the /3 split and the 16 GiB minimum. Record the capacity policy in drive-selection.json.
  - crates/n2r-win32/src/shadow_native/private_tree/placement.rs:345-412 (Scratch), evacuation exclusions, and src/general_qualification/compact_construction.rs:140-150: Pass the digest-bound NTFS-allocated ranges into place_source_prefixes_with_limits. Scratch and evacuation use tiered first-fit: NTFS-free spans first, NTFS-allocated spans only when those run out. Count the NTFS intervals within the scratch interval budget, or use an uncapped sweep consistent with the scale decision. Every per-move check is kept.
  - src/general_reconstruct.rs:807-845 and src/bin/lab-convert-native-composite.rs: Lab-only options (src/main.rs untouched):
- --lab-journal-format auto|v1|v2;
- --interrupt-at F:N|BAR-before|BAR-after|A:N|HND-before;
- --lab-pause-at <boundary>, which syncs then sleeps for a TurnOff;
- --lab-tear-marker <kind>, which writes half a marker copy then exits 86;
- --lab-drop-staged-chunk, which simulates a lying flush before BAR.
  - lab/Start-AllocationInterruption.ps1, lab/Start-AllocationRecovery.ps1, new lab/Start-HybridPowerOff.ps1: Pass the phase points through to the binary. TurnOff the VM at the pause marker. Restore and recover from a temporary checkpoint in both directions.
QUALIFICATION: The coordinating agent owns all VM mutation. Each native step starts from a fresh restore of NTFS checkpoint 5f30f4a1, verified from a new PowerShell process, inside the storage epoch after a lab/Lab.psm1 capacity check. No unit tests are used; checks are lab integration binaries and native runs, as the user asked.

Q0. Measure before deciding; no behaviour change.
- Add a non-gating diagnostic that writes class-split.json:
  - before capture: U_A, U_N and U_R over compared, split by NTFS-allocated bytes and eligible routes, plus a zero-new estimate;
  - in the capture loop: the actual split until success or refusal.
- Run it on the 52 GiB fixture and on the regenerated 808 fixture (lab/New-MixedFixture.ps1, seed 20261029).
- Also run the 808 fixture with exact v1 sizing under schema 3. It may convert, since 3B could fit about 39.7 GB.
- Record B, B_A, B_N, B_R and R_proj.
- Report to the user whether the hybrid is needed for the 808 fixture.

Q1. Ordinary-file integration of N2RSEL02 through lab-selected-journal, as done before for N2RSEL01.
- The full lifecycle: prepare, apply, resume, rollback, abandon and handoff.
- A tear of every marker copy.
- An interruption at every phase boundary, and a persisted short write.
- R origins overlapping A records, resolved from the journal after A writes.
- A dropped staged chunk before BAR (lying flush), which resume must repair after BAR.
- Accept when every refusal and action matches the lifecycle table and HND/ABT replay is refused.

Q2. Native 52 GiB run with v2 forced (--lab-journal-format v2).
- One conversion that succeeds: exit 0, native 15/10, label and mount verified.
- Then, each time from a temporary checkpoint of the interrupted state, recover with --recover (expect ReFS 15/10) and with --recover --rollback (expect NTFS 7/7 user hashes, with the F digest observed and recorded). Interruption points:
  - --interrupt-at F:1, F:mid and F:last;
  - BAR-before and BAR-after;
  - A:1 and A:mid;
  - HND-before;
  - torn AP, BAR, RB, HND and ABT markers.
- Plus mutation and a cold restart (lab/Invoke-AllocationMutationReboot.ps1).
- Also run auto mode. If R+N=0 there, the v1 journal, ticket and bundle pins must be byte-identical in format to today's.

Q3. Hard power-off.
- Use TurnOff at these --lab-pause-at points: during F, right after BAR, during A, right after bundle publication (to prove the directory flush), after HND before bring_online, and during the activation flush.
- After each, confirm attributes are 1 (or 3 before activation) and recover in every allowed direction.
- Record in the evidence that physical power loss remains untested, because TurnOff keeps the host cache.

Q4. The 808 fixture in hybrid mode.
- End-to-end conversion, then mutation and restart.
- One interruption in F and one in A, each with resume and rollback.
- Record Need_v1 against Need_v2 and the per-class bytes.

Q5. Record scoped observations in evidence/*.json and AGENTS.md. Only after the user confirms E-1 and E-2 and Q2-Q4 pass does auto mode become the default.
RISKS:
  - A bug in the class map that marks NTFS-allocated bytes as free would make rollback lose those old bytes. Mitigations:
- derive the map only from the digest-bound raw set;
- recompute it at prepare and in load();
- cross-check F destinations against the native FSCTL_GET_VOLUME_BITMAP snapshot already matched at admission;
- refuse on any ambiguity, so the range falls to A.
  - VSS snapshots on the source NTFS are not detected. A grep of src found no VSS/volsnap check. Clusters that are free now but still referenced by a snapshot (freed after the snapshot) would be overwritten by F writes, and rollback would not restore them. Snapshot contents then differ, which today's full-journal rollback avoids for changed ranges. The hybrid needs a VSS-absence gate or a fallback to v1.
  - The 808-fixture class split is unmeasured. If most changed bytes are origin overwrites in the ReFS metadata prefix [0, 6,174,015,488) plus ReFS metadata on NTFS-allocated bytes, all class A, the hybrid saves little. Q0 may show that exact v1 sizing is enough.
  - Copy-map eligibility excludes attribute-list streams, sparse holes, compressed or encrypted streams and sub-4 KiB clusters, which become N and cost external new bytes. A VDL or initialization mismatch between logical and physical bytes is caught only by the byte or hash tie at prepare, which refuses before activation.
  - A torn A sector containing bytes that are neither old nor new still refuses both directions. Physical power loss and lying device flushes are untested on hardware. TurnOff keeps host-cached VHDX writes, so the F-repair path is exercised only by lab injection.
  - Recovery now reads R origins from the source device. A media error on an origin blocks F repair, so resume refuses, but it does not block rollback.
  - OS-volume space can shrink between G4 and the recovery process. The journal is preallocated, but the recovery process's own outputs are only reserved by policy, so recovery may refuse. Protection stays set.
  - H1 keeps fixed caps: 65,536 ranges (journal, DeltaLayout, capture), MAX_REFERENCE_FILE_BYTES for the backing, and the 16 MiB recovery plan read for v1. Fragmented NTFS-free destinations can raise X. Lifting these must land together as coupled set C, with recovery reading the journal's record table.
  - Tiered NTFS-free placement may increase the move count (about 105 ms per move today) or exhaust the scratch interval budget, and ReFS's own first allocations cannot be steered.
  - Pre-activation stranding (attributes 3 with no automated cancel), non-durable bundle publication until the directory flush lands, and a bundle checksum that exists only on stdout all remain. The hybrid adds no new pre-activation source state, but it depends on the bundle v2 flush being qualified (Q3).
  - After a rollback, NTFS free space holds staged plaintext copies of file data. This is consistent with the allocation guarantee, but ACL-protected content becomes readable through raw volume access.
  - The reference-import and managed-shadow attribute setters still do not flush (AGENTS.md:235-237). The hybrid does not use the shadow after activation, but a TurnOff before activation can still revert the shadow's protection.
----- VERDICT 2: sound=False
VIOLATIONS:
  - I2 and the device-ref fault row are self-contradictory. The design keeps today's per-byte old-or-new rule on B during rollback, and that rule needs each B record's NEW bytes: check_target and write_span compare actual==old||actual==new (src/selected_journal.rs:536-543, 575-582). B records may take their new side from a device-ref ('reference ... to an unwritten NTFS-allocated device range'). So rollback must read device-refs, which contradicts 'Rollback never reads A destinations or device-refs' (I2, ROLLBACK, AP-durable row). It also contradicts the fault row 'device-ref source changed -> rollback unaffected, NTFS is restored': if the device-ref changed and the B destination already holds the original new bytes, the rollback check sees bytes that are neither old nor (changed) new and refuses.
  - The 'refused before any write' rule for a foreign B byte (fault row; selected_journal.rs:631-638 today) is broken by the AP-durable resume order. That row says to re-verify and repair A (target writes), flush, advance, and only then run check_target on B. A resume that will refuse on a foreign B byte therefore writes A first.
  - E2 is not optional in this write model, yet the design says it 'needs user confirmation'. A destinations store only a framed old digest (no old payload, no per-granule hashes), so a partly written A cannot be checked byte-by-byte or granule-by-granule. Without E2 approval the SA-state and AP-state resume rows cannot run. AGENTS.md:261-262 says any change that narrows what is checked needs its own user decision, and this removes the foreign-byte detector on every A byte.
  - The crash table and I4 assume E3 (torn-slot completion), but the design says 'Without approval, keep refusal on any torn slot'. Under that default, the rows for torn SA ({SA~,ABT} -> Aborted), torn AP ('commit not started'), torn HND (forward completion), torn RB and torn ABT all refuse in both directions. The table does not hold in the configuration the design proposes to ship.
  - Abandon (no durable SA) requires old_a, a digest of NTFS free space that the user's allocation guarantee does not protect. NTFS validity needs only old_b. Requiring old_a turns a free-space difference (a lost SA marker with durable A writes, or non-deterministic read-after-TRIM) into a permanent refusal while NTFS is intact.
  - I1 overstates B. The backup boot sector and 'every relocated origin' are in B only when those granules changed. Origins outside the shadow selection, and unchanged granules, are never written and serve as device-ref sources.
  - The listed hybrid_journal validations omit 'every B old side is payload or zero, never digest-only', which rollback exactness (I8) depends on. They also omit a refusal for journal-refs or A-COPY segments that point at a zero-kind B old payload.
  - I3 says the native stage policy makes 'no B write before AP durable' a mechanism. advance_stage only orders A before B inside one handle. AP durability is still convention. Device-ref sources are not placed in WritePolicy.retained (native.rs:266-301), so 'never armed' is enforced only by plan validation, not by the native write gate.
  - The user's premise 'originals stay intact until handoff' does not hold for relocated origins inside B (for example the 6.17 GB ReFS metadata prefix), which phase B overwrites before handoff. The design compensates by journaling those origins' old payload. That matches 'only ranges that overwrite NTFS-allocated bytes need journaling', but the departure from the stated ntfs2btrfs model should be acknowledged to the user explicitly.
CRASH GAPS:
  - Lost SA (dishonest OS-volume flush) or torn SA after a crash in the write window, with some A writes durable on the source:
- No SA, so resume is refused.
- Abandon requires old_a, which no longer matches, so it refuses.
- NTFS is fully valid (only free space was written) but stays stranded at attributes 1 with no automated path.
  - Under the design's own default for E3 (refuse every torn slot), a crash during any marker write strands the volume:
- SA or AP: NTFS valid, stranded offline.
- HND: ReFS complete, unmounted.
- RB or ABT: a mixed or NTFS state.
Both resume and rollback are refused.
  - A device-ref source changes (exclusion breach) after a B record that takes its new bytes from it has been written:
- Resume refuses on the hash mismatch.
- Rollback's per-byte check reads the changed device-ref as the 'new' side, so it sees foreign bytes and refuses too.
The fault row's 'NTFS is restored' does not hold.
  - Resume after a durable AP when B contains a foreign byte: the design's order writes A repairs before check_target(B) refuses. Under E3 or E2 changes, partial resume writes happen in a state that was meant to be refused untouched.
  - Free-destination replay onto changed data:
- A run is stuck in the SA or AP state, for example after a refused recovery.
- The operator manually onlines NTFS (it is valid during phase A) and new files are allocated in A destinations.
- The disk is later set back to OFFLINE (attributes 1) and --recover runs.
- Resume checks only B. If NTFS's changes missed B, it silently overwrites the new NTFS allocations in A with no foreign-byte check (E2).
- Today's N2RSEL01 per-byte check over every changed range would detect this.
  - SA and AP both lost (dishonest flush) while B writes are durable:
- Classification is PreparedClear, so Abandon runs and refuses on the old_b mismatch.
- Resume is refused.
- The volume stays stranded half-written. This is the same class as today, but the hybrid adds marker windows.
  - Lost AP with B writes durable: the SA-row resume requires B == old_b exactly and refuses, even though forward completion would be safe. Rollback works, so a correct NTFS state is reachable, but ReFS resume is lost.
  - Unchanged gaps:
- Pre-bundle crashes and refusals, and post-bundle-before-activation crashes, leave attributes 3 with no automated release (drive_recovery.rs:99-105; general_recovery/allocation.rs:236-241).
- After bring_online makes attributes 0 durable, label and mount-path completion is never retried.
- A torn or foreign sector in B refuses both directions (D-H2 not adopted).
  - Rollback leaves A unrestored. Volume Shadow Copies of the source whose diff area is on another volume can still depend on clusters freed after the snapshot, and the raw-disk writes bypass volsnap, so such snapshots are silently corrupted after an otherwise successful rollback. No code inspects VSS. This is unverified, not tested.
  - Physical power loss: A writes, B writes and markers sit on different devices. Recovery correctness assumes FlushFileBuffers on the OS-volume journal is honest and that storage-level read-modify-write does not cause collateral damage to unwritten NTFS-allocated neighbours (RAID write hole, SSD paired-page corruption). Device-ref sources depend on that. TurnOff cannot exercise either case.
MISSING:
  - Make the device-ref dependency in rollback explicit. Either resolve device-refs in the rollback per-byte check, correcting I2 and the fault row, or store per-chunk new hashes for ref-sourced B records with a chunk-level old-or-new rule. The second option needs a user decision.
  - Reorder AP-durable resume: run load, then check_target over B (refuse on a foreign byte), then A repair, then flush, then verify new_a, then advance, then B writes.
  - Change Abandon (no durable SA, --rollback) to require old_b only. Record old_a as a non-blocking observation.
  - Get the user's E2 decision before adoption. Prefer the stated mitigation: a per-4 KiB XXH3 old/new table for A (16 B per granule). Resume then refuses any A granule that is neither old nor new, and rollback (B-only) stays available.
  - Get the user's E3 decision. Until then, rewrite every torn-slot crash row as 'refuse both directions' and test those strandings in Q1/Q2.
  - Add these hybrid_journal validations:
- every B old side is payload or zero;
- no journal-ref or A-COPY segment points at a zero-kind old payload;
- the backup boot sector is required in B only when it changed.
  - Put device-ref sources into WritePolicy.retained, with a sweep-line overlap check instead of the O(allowed x retained) loop at native.rs:283-292.
  - Buffer or pre-hash each device-ref-sourced record (or keep per-chunk hashes), so the bytes written are the bytes whose hash was verified.
  - At admission, check for and refuse, or explicitly record, Volume Shadow Copies of the source, including diff areas on other volumes.
  - Run Q0 first to measure:
- the A/B class split;
- the share of origins inside [0, 6,174,015,488);
- the share of origins with new==zero;
- evacuation_remaining_blocked_bytes on the 808 fixture.
None of these is measured yet, and they decide whether the hybrid fits.
  - Lift together:
- the 65,536-range caps in the capture, DeltaLayout and the selected MAX_RANGES;
- the 16 MiB plan read cap in general_recovery/allocation.rs:116;
- the u32 counts.
Otherwise record and segment splitting moves the refusal downstream.
  - Add a lab fault that drops a marker after a successful in-process readback (lost SA, lost AP), to qualify cross-device flush ordering that TurnOff cannot produce.
  - Document the operator path for attributes-3 and attributes-1 strandings. Warn that onlining an SA- or AP-state NTFS and re-offlining it invalidates resume.
RECOMMENDATION: Don't adopt N2RHYB01 as written. The core idea holds up. Every forward value and every B old value comes from the immutable journal, zeros, or never-written NTFS-allocated bytes. A writes only touch frozen-bitmap NTFS-free space (raw.allocated_byte_ranges, ntfs_inspect.rs:202-254, with source clusters >= 4 KiB per ntfs_admission.rs:53). B keeps old+new semantics. So I found no ordering hazard and no case where staged data overwrites NTFS-allocated bytes.

The design still contradicts itself in four places that decide recoverability:
1. Rollback's per-byte check on B needs new bytes that may be device-refs, which breaks I2 and the device-ref fault row.
2. AP-state resume writes A before it checks B for foreign bytes.
3. Abandon requires old_a (free space), so a lost SA strands an intact NTFS.
4. The crash table depends on E2 and E3, which the design itself leaves unapproved. Under their defaults, every torn-marker row and every A resume refuses or cannot run.

Before redesign or implementation:
- Run Q0 to measure the class split.
- Ask the user for the E2 and E3 decisions, presenting the per-granule A old/new table as the E2 option that keeps detection.
- Fix the four contradictions as listed in missing_steps.
- Add a VSS check.
- Lift the range and plan-size caps together.

Hard power-off and lost-marker qualification (Q1/Q2) must cover the corrected table, including the stranding rows. Make no physical power-loss claim.
