# Prepared-owner normal native case

Sealed runtime `11e8963` / public SHA-256 `2ff60056` completed normal conversion
`79b22a2ffac94f42bec9a38291405beb`, core `b4135fc99aebb412a63a3d3554f215f3`.
Actual PID 3944 / creation 1793492056135 exited 0/HND at
2026-11-01T00:18:56.8852894Z after 280.7502894 seconds. Its actual result records
`prepared_journal_owner_reused: true`. The independent observer passed all 811
default-stream hashes, with no named streams, at 00:21:42.5767130Z,
165.6914236 seconds after native terminal.

The source was the same grown clean NTFS checkpoint `83290a28`, fresh full
baseline `f5de156f` and growth receipt `835b1196`: 1,084 objects, 811 files and
273 directories. Fast source evidence retains 654 absent digests, including
650 materialized tails / 1,371,388 bytes. The engine observed zero target content
hashes and zero admitted target payload hash reads; the lab's full reads remain
separate. Three access-time differences were reconciled against current raw,
native source and target evidence; product expectations and filesystem times
were not changed. The retained prepared owner
keeps complete independent post-flush authentication, the same journal borrow
and immutable plan/ticket through activation, clear markers, exact-old target
checking before intent, exact-new readback, receipt callback and durable HND.
The primary route gate and caller's no-mutable-alias obligation do not establish
global administrative or volume-alias exclusion.

| Actual plan or phase | Logical bytes |
| --- | ---: |
| Selected target, 3,537 ranges | 11,393,044,480 |
| Literal payload | 42,131,456 |
| Journal | 11,435,523,840 |
| Copy / zero new ranges | 5,659,303,936 / 5,691,609,088 |
| Native-verified process reads / writes | 111,031,478,753 / 23,029,158,576 |
| Journal-prepared to applied reads / writes | 28,487,536,640 / 11,393,100,340 |

Native-verified CPU counters were 270.4375 user / 26.546875 kernel seconds;
prepared-to-applied CPU was 47.71875 / 1.578125 seconds. The latter read delta
equals `2D + copy + literal + 12,288` marker bytes for this plan. The removed
duplicate load would read `(J - 8192) + copy + literal = 17,136,951,040` bytes.
Prior f2 process reads were 17,144,221,184 bytes higher; differing plans and
formatter metadata prevent controlled attribution or a speed claim. These are
logical process counters, not physical disk I/O or an HDD forecast.

The `07b0164` controlled recovery matrix belongs to its sealed binaries. Fault,
recovery, arbitrary mutation and physical power-loss qualification remain
pending for this prepared-owner candidate. No unit tests were added or run.

The 77 closed metadata files / 217,490,514 bytes were copy/source SHA-256
verified. After all tasks and workers were idle, root stopped the VM normally
and saved one ReFS checkpoint `ed6fe063-3a06-489a-8028-2a16929ce171`, parent
`83290a28`. A fresh process confirmed Off / RAM 0 / 50 checkpoints. Actual lab
usage was 279,038,846,111 bytes and free space 66,131,628,032 bytes under the
unchanged budget. Only obsolete `1c75c73f` was removed through Hyper-V after its
archive/dependency verification; all host evidence and the recovery matrix
branches remain preserved.

[Exact pins, phase timestamps and final state](../../evidence/prepared-owner-native-20261031.json).
