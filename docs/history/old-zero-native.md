# Old-zero normal native case

Sealed runtime `e4ffb3a` / public SHA-256 `f8c07817` passed normal conversion
`6d9b4cd5910c46ebb2f083b92e0fb7d6`, core `6e91f2320688c2a2df30b486194b3cbb`.
Actual PID 724 / creation 1793494088987 exited 0/HND at
2026-11-01T00:52:45.7675697Z after 276.7805697 seconds. The independent observer
passed all 811 default-stream hashes, with no named streams, 174.6023869 seconds
later. The actual product result records old-zero storage elision and prepared
journal owner reuse.

| Same actual selected plan | Bytes |
| --- | ---: |
| Selected target `D`, 3,534 ranges | 11,392,786,432 |
| Actual old-zero `O`, 1,770 whole ranges | 5,587,607,552 |
| Stored old payload `D−O` | 5,805,178,880 |
| New copy / new zero | 5,659,303,936 / 5,688,594,432 |
| New literal backing | 44,888,064 |
| Actual format-4 journal, 104-byte records | 5,850,442,832 |
| Same-plan copy-format reference, 96-byte records, `O=0` | 11,438,022,112 |
| Net serialized journal reduction `O−8N` | 5,587,579,280 |

The reference size is calculated from the same pinned plan, rather than a
second conversion. Old zeros were proved from actual capture bytes and reread
and asserted during preparation. Their original logical hashes and complete
selected framing remain. Only their stored journal payload is omitted; the
selected target write set and byte budget remain `D`. The native gate checked
the shorter `J` using the pinned old-zero count and unchanged profile ceiling.
The lab metadata observer did not replace the core source-zero check or read
raw journal payload.

The source was grown NTFS checkpoint `83290a28`, fresh full-source baseline
`f5de156f` and growth receipt `835b1196`: 1,084 objects, 811 files and 273
directories. Fast evidence retained 654 absent stream digests and 650 actual
materialized tails / 1,371,388 bytes. Complete target maps, selected checksums,
label and mount checks passed. The engine recorded no target stream content
hashes or admitted payload hash reads; the independent lab read all 811 streams.
Three access-time reconciliations used current source/target evidence without
changing product expectations or filesystem times.

Native-verified logical process counters were 105,470,433,073 bytes read and
17,446,733,391 written, with 253.421875 user / 22.359375 kernel CPU seconds.
Prepared-to-applied counters were 28,489,777,152 read / 11,392,842,308 written
and 47.28125 / 1.328125 CPU seconds. That read interval equals
`2D + copy + literal + 12,288` marker bytes; this plan's copies reference no
old-zero source bytes. These are logical process counters, not physical I/O or
a controlled timing comparison. The prior prepared-owner run had a different
plan and formatter metadata.

The 78 closed metadata files / 217,639,522 bytes were source/copy SHA-256
verified; all tasks and workers were idle before root's normal shutdown. One
checkpoint was saved at `6bef3bd2-db31-45fe-9e6c-939c812b7375`, parent `83290a28`.
A fresh process confirmed Off / RAM 0 / 47 checkpoints at
2026-11-01T01:00:04.6604012Z. Actual lab usage was 295,406,531,182 bytes and host
free space 49,858,801,664 bytes under the unchanged budget. Four reviewed
obsolete leaves were removed through Hyper-V after archive/dependency checks;
all host evidence, the prior prepared-owner case and recovery branches remain
preserved. Exact artifact pins and final state are recorded in
[the evidence](../../evidence/old-zero-native-20261031.json).

This qualifies one normal old-zero conversion. The earlier `0474927` manual
helper results concern owned ordinary files; the earlier `07b0164` native
recovery matrix belongs to its sealed binaries. The same `e4ffb3a` runtime later
passed controlled first-flushed-write interruption, clean restart, public Resume
and separate Rollback, with all 811 independent hashes in each direction.
[Exact recovery scope](old-zero-recovery-matrix.md). Arbitrary mutation and
physical power loss remain pending. Later capacity-policy and recovery-owner
candidates were not used in this matrix.
The existing no-mutable-alias contract and limits of primary-route exclusion
remain. No unit tests were added or run.
