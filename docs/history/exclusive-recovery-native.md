# Exclusive journal recovery: native compatibility case

New public recovery runtime `adf08e9` / SHA-256 `34c9cc07` successfully resumed
and rolled back the unchanged journal produced by `e4ffb3a` / fault binary
`9140d57c`. The original producer, first-flushed-write exit86, request, plan,
ticket, bundle `cd919acd` and interrupted checkpoint `dea902f6` were preserved.
This qualifies recovery compatibility and the exercised journal-owner paths;
it does not qualify a new conversion or the separate 8 GiB capacity policy.

| Actual operation | Native result | Independent observation |
| --- | --- | --- |
| Resume `4b877c53` | PID 5516 / birth 1793499329262; exit0/HND in 218.9968846 s | All 811 hashes passed 335.3534852 s after native terminal |
| Rollback `104ca6aa` | PID 5548 / birth 1793500267757; exit0/ABT in 164.7104809 s | All 811 hashes passed 113.4508994 s later |

Both actual results report `exclusive_recovery_journal_used: true`, observed
`apply_intent`, and the requested Resume or Rollback action. The owner retains
the authenticated journal and its mutable borrow through action selection,
pin revalidation, target reopening and completion. The target still reopens
with sharing mode 3. Every mixed-state/per-span target check, exact post-write
check, and the full handoff target check after receipt persistence remains.
This is journal-only validation reuse, with no new global target-exclusion claim.

The pinned old-zero plan has 11,392,847,872 selected bytes / 3,547 ranges,
5,587,685,376 old-zero bytes and a 5,849,731,480-byte format-4 journal.
Rollback matched the original old-selected SHA-256
`037b39630d80ff88230dc22ccf0868d328ae0e69032569aaaed1bdeb7775c46d`.
Resume verified 1,084 complete map bindings plus 157 known full hashes /
119,009 payload bytes. Its 654 missing digests stayed missing, including 650
materialized tails / 1,371,388 bytes. The lab separately read and hashed all
811 streams against the fresh full baseline. The shadow was absent in both
cold recovery branches; no attachment or request rebinding occurred.

The lab used the same original interrupted VM checkpoint for each branch;
public recovery ran inside the owning Windows guest. Product Rollback checked
the NTFS mount. The lab independently verified NTFS 64 KiB, label/mount,
1,084-object / 811-file / 273-directory shape and content. No independent
post-rollback extent-map or timestamp equality is claimed. HND and ABT were
never replayed.

For this exact plan, code-path accounting removes 34,805,884,512 duplicate
logical journal read bytes on Resume and 17,402,942,256 on Rollback. **Final
native I/O and CPU counters were unavailable for both old and new cases.**
Live CIM samples are not final counters. These byte figures are static
accounting, and the single-VM timings establish no controlled causal speed,
physical-I/O or HDD claim.

The verified Resume/Rollback archives contain 55/53 closed metadata files,
88,769,148 / 62,133,832 bytes. After all workers/tasks were terminal, root
stopped normally and saved restored-NTFS checkpoint
`d40b4b41-be9c-4243-8f91-7f953085e3a3`, parent original `dea902f6`.
A fresh process confirmed Off / RAM0 / 48 checkpoints at
2026-11-01T02:37:17.1417575Z. Actual lab usage was 292,508,370,854 bytes and
host free space 52,696,043,520 bytes under the unchanged budget. New resumed
ReFS `8087814c`, the original interruption, old restored NTFS `35c9a8f8`,
normal `6bef3bd2` and sources remain preserved.

[Exact provenance, pins and limits](../../evidence/exclusive-recovery-native-20261031.json).
Arbitrary faults, physical power loss, broader scale and compatibility remain
unfinished. No unit tests were added or run.
