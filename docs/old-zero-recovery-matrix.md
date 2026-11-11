# Old-zero recovery matrix

Sealed runtime `e4ffb3a` / public SHA-256 `f8c07817` passed a controlled first
flushed-write interruption, clean guest restart, public Resume and a separate
public Rollback from the same saved interrupted state. The source was grown
NTFS checkpoint `83290a28`, with 1,084 objects, 811 files/streams and 273
directories. This is a controlled first-write case, not arbitrary fault or
physical power-loss qualification.

| Stage | Actual native result | Independent observation |
| --- | --- | --- |
| First write `d4f9c352` | PID 5208 / creation 1793495149312; exit 86 after the first successful target write was flushed | Source disk 1 offline writable, shadow disk 6 offline read-only; no Apply/HND publication |
| Resume `d1d45a31` | PID 5696 / creation 1793496097001; exit 0/HND in 398.8001963 s | ReFS and all 811 hashes; observer passed 327.5911427 s later |
| Rollback `52562132` | PID 5680 / creation 1793497274111; exit 0/ABT in 258.399068 s | NTFS 64 KiB, label/mount, 1,084-object shape and all 811 hashes; observer passed 122.2102642 s later |

The interrupted checkpoint is `dea902f6-7d3f-49ba-86d2-27ce6dbe9516`.
Resume was saved separately at `033e05bd-447b-450e-9acb-9413feaf00dc`.
For the Rollback case, the lab restored the original interrupted VM checkpoint,
then ran public Rollback inside the guest. The resumed HND branch and closed
ABT were never replayed.

The same pinned format-4 journal (`N2ROLD01`, 104-byte records) contains
5,849,731,480 serialized bytes for 11,392,847,872 selected bytes / 3,547 ranges.
Preparation reread and asserted 5,587,685,376 actual old-zero bytes across
1,775 complete ranges before omitting their stored payload. Rollback regenerated
their logical zeros and matched the original ticket's full old-selected SHA-256:

```text
037b39630d80ff88230dc22ccf0868d328ae0e69032569aaaed1bdeb7775c46d
```

Selected hashes still cover complete logical bytes. All mixed-state/per-span
target checks and exact final target checks remain. The first-write producer
used the actual prepared journal owner; this frozen recovery runtime performed
its existing journal authentication. Later capacity-policy `87a` and journal
recovery-owner `b88` changes were not used and gain no qualification here.

Resume verified 157 known full hashes / 119,009 payload bytes and 1,084 complete
map bindings. The other 654 digests remained absent, including 650 materialized
tails / 1,371,388 bytes. Each separate lab observer read and hashed all 811
streams against fresh full baseline `f5de156f`; those reads are not product
full-file verification. No source certificate or fresh replay authority was
recreated. Both cold recovery branches ran with the managed shadow absent and
without attachment or rebinding; the original shadow observation and required
request/plan/ticket/expectation/verification/map pins remained required.

Product Rollback checked the NTFS mount; label, 64 KiB geometry, canonical shape
and full content hashes were independent lab checks. No independent
post-rollback extent-map or timestamp equality is claimed. The primary route
gate and mutable-alias contracts do not establish global administrative or
volume-alias exclusion.

The verified closed archives contain 80/52/50 metadata files respectively,
186,303,850 / 88,764,681 / 62,129,359 bytes. After all tasks and workers were
terminal, root shut down normally and saved restored-NTFS checkpoint
`35c9a8f8-b646-4d3b-98e9-191b2f12a4a6`, parent original `dea902f6`.
A fresh process confirmed Off / RAM 0 / 50 checkpoints at
2026-11-01T01:50:19.9562642Z. Actual lab usage was 322,376,794,614 bytes and
host free space 22,809,677,824 bytes under the unchanged budget. Normal `6bef3bd2`,
interrupted `dea902f6`, resumed `033e05bd` and source branches remain preserved.
[Exact pins and scope](../evidence/old-zero-recovery-matrix-20261031.json).
No unit tests were added or run. Broader scale and compatibility remain unfinished.
