# Grown V3 recovery matrix

Sealed runtime `07b0164` passed a controlled first-flushed-write interruption,
clean guest restart, public Resume and a separate public Rollback from the same
saved interrupted state. The F: source used the admitted V3 envelope with
1,084 objects, 811 files/streams and 273 directories, above the former directory
split. This qualifies the exercised paths; arbitrary faults, physical power
loss, more than 1,024 files and broader scale remain unqualified.

| Stage | Actual native result | Independent observation |
| --- | --- | --- |
| First write `da2e9f6f` | PID 2272, creation 1793487784220; exit 86 after the first successful target write was flushed | Source disk 1 offline writable; managed shadow disk 6 offline read-only; saved checkpoint `307b65ff` |
| Resume `68203aa3` | PID 4512, creation 1793489287993; exit 0/HND in 552.2482827 s | ReFS, all 811 full stream hashes; observer passed 436.6603823 s after native terminal |
| Rollback `27abc45e` | PID 1856, creation 1793490822780; exit 0/ABT in 325.5027467 s | NTFS 64 KiB, label, 1,084-object shape and all 811 hashes; observer passed 112.6400947 s later |

The producer accepted schema-3 fast V3 planning-None, derived and pinned the
admitted descriptor, and used `prepare_exclusive` and the actual private fresh
exclusive writer through the interrupting target. Its preactivation diagnostic
grants no authority. The first write was the requested interruption; HND was
forbidden if that interruption was not reached. The primary PhysicalDrive gate
and continuous no-mutable-alias contract still do not establish global
administrative or volume-alias exclusion. Recovery retains its mixed-state
checks and complete journal authentication.

Resume checked 157 known full content hashes, reading 119,009 logical payload
bytes, plus complete pinned stream maps. The other 654 digests remain absent;
650 materialized tails account for 1,371,388 bytes with actual constructor
readback and protected-residual bindings. The independent lab observer read and
hashed all 811 streams against the fresh full-source baseline `f5de156f`.
That lab baseline and its historical 808-file content reference do not issue a
source certificate or replay authority, and do not mask fresh source metadata.

Both recovery directions ran with the cold-detached managed shadow absent.
Allocation journals contain the old/new literals and authenticated old bytes
needed for copies; zeros are generated. The original shadow binding and its
offline/read-only observation remain pinned. No shadow was attached or rebound.
Request, plan, ticket, expectation, verification and payload-map metadata remain
required. This result does not remove other recovery modes' shadow dependencies.

Rollback checked the original ticket's old selected SHA-256 over 11,392,921,600
bytes in 3,505 ranges and durably closed ABT. The product checked the NTFS mount;
the label, 64 KiB geometry, namespace and full hashes were independent lab
checks. No independent post-rollback extent-map or timestamp equality is claimed.
Neither HND nor ABT was replayed.

Pre-dispatch numeric-syntax and cold-shadow controller refusals remain recorded;
the latter never invoked public recovery. A duplicate Rollback launcher was
rejected by the idle guard while the first launch was staging: no second guest stage,
task or native invocation was created. These are separate from the successful
native matrix.

The closed first-write, Resume and Rollback archives contain respectively
79/50/48 metadata files, with all copy hashes verified. Final state is Off,
RAM 0, 50 checkpoints at restored-NTFS `5f07551f`, with interrupted `307b65ff`
and resumed-ReFS `1aedc3d5` preserved. Actual lab usage was 279,145,884,943 bytes
and host free space 66,088,849,408 bytes under the unchanged budget. One invalid
checkpoint parameter failed before creating a checkpoint; the corrected call
created the final checkpoint once. It was not a native recovery failure.

[Artifact pins and exact identities](../evidence/envelope-recovery-matrix-20261031.json).
No unit tests were added or run.
