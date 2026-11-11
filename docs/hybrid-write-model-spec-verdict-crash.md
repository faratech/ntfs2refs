# N2RSEL02-H verdict 1: crash and rollback safety (2026-10-30)

Reviewer: read-only adversarial agent. **sound = false.** Core holds: class A
(staged, NTFS-free) writes cannot touch NTFS-needed bytes absent outside
interference; every B old byte is journaled; the resolver is phase-independent;
the per-4 KiB XXH3-128 table suffices for A (old bytes never written back).

Violations to fix before stage 0:
1. Outside-the-tool use (online, write, re-offline) is caught only by luck:
   store admission's per-4 MiB XXH3 digests of all NTFS-allocated ranges (plus a
   B-masked set) in the immutable journal; re-hash before the first marker or
   target write in Resume/Rollback/CompleteAbort/Abandon (B old-or-new, non-B
   exact); after rollback restore and before ABT require the unmasked digests.
2. Dual-copy rule contradicts E3: VALID if any copy valid; a copy is a tear if
   every 512 B sector is zero or the expected sector; read error = damaged copy;
   FOREIGN only when no copy is VALID; ticket_sha256 = pin of the saved bytes.
3. Marker readback goes through the cached journal handle (allocation.rs:109-115;
   selected_journal.rs:504-507): use a separate WRITE_THROUGH|NO_BUFFERING handle.
4. Lifecycle table is not a function: precedence FOREIGN/reserved > HND with RB
   or ABT > ABT > HND > RB > BAR > AP > clear.
5. Remove the zone-zero skip entirely (disproved; evidence/refs-zone-probe-20261030.json).

Crash gaps: 6 sub-4 KiB tears in B-Reference strand both directions (resolve
new bytes then per-byte old-or-new); 7 HND/ABT with dropped target writes
strand (forward repair safe when HND.2 not VALID; re-restore when ABT.2 not
VALID); 8 AP lost while a later marker survives (allow the implied direction;
intent-less rollback when every B byte passes old-or-new); 9 attribute revert
after writes (add rows; optional non-mountable poison boot granule after AP);
10 media-error rows; 11 VSS window between online query and freeze; 12 TRIM
non-deterministic reads in NTFS-free zone granules (gate on deterministic
zero-after-TRIM or verify zone zeros at handoff); 13 OS-volume VSS can roll the
journal back (pin journal file ID; refuse when the journal volume has shadow
copies). Missing: operator warning, lab cases for 1, 2, 6, 7, 9; state that the
full B check precedes RB.
