# Current public-runtime recovery

The controlled first-write, Resume and Rollback matrix passed for public runtime
`65b117814aa8f187dfefed658b222650c72e08fe`, the runtime used by the successful
public `--drive F --partition 2 --minimize-scratch` conversion. The enrolled
owning Windows guest performed all conversion and recovery; Hyper-V supplied
separate disposable branches.

The prepared NTFS source contains 811 streams and 1,084 canonical objects. The
producer exited 86 after its first flushed selected write and left the source
offline. The original interruption is checkpoint
`6679708a-2171-4566-b660-312efaab9f73`, parent prepared NTFS
`cb802669-903c-48cc-99e5-57976b149e7d`.

| Operation | Native result | Independent content | Saved checkpoint |
|---|---|---|---|
| Resume | Exit 0, HND, ReFS; complete metadata/maps matched | All 811 streams matched | `19f5d614-e7a0-42d7-9d32-c8e1c55c1065` |
| Rollback, from a separate restore of the original interruption | Exit 0, ABT, NTFS; restore-required bytes matched | All 811 streams matched | `9a01516b-1279-4266-9923-fe17d2610090` |

Process-birth-to-terminal observations were 13.247 seconds and 8.089 seconds,
respectively. These include parent observation overhead. The lab's separate
PowerShell metadata comparisons and full-content observers take additional time;
these figures are neither end-to-end lab times nor physical-disk benchmarks.

The selected set is 547,229,696 bytes with a 133,757,040-byte format5 journal.
Source-free elision covers 402,669,568 bytes. Rollback verified the remaining
144,560,128 restore-required bytes against
`3f2be98dfc6a5cf8f12a818593fa8df8cc9a0e89c7aa3637891039b040588c22`.
The original complete old-selected digest remains the marker identity. Original
free-space contents and post-rollback timestamp/physical-map observations are
not claimed.

The first Resume harness refused before native launch because PowerShell 7
normalized a timestamp while embedding its receipt. That refusal is preserved.
The corrected host parser preserves timestamp strings; it neither changes pins
nor supplies source/replay authority. The successful directions used the actual
original bundle and journal, not saved JSON as a new source certificate.

Both result archives were length/SHA verified while source files were held for
reading: 59 files/88,491,263 bytes for Resume and 57 files/61,769,941 bytes for
Rollback. All project tasks and workers were terminal before normal shutdown.
The VM is off, with both completed branches and the original interruption saved.

See [the pinned evidence](../../evidence/current65b-recovery-matrix-20261102.json).
This proves controlled process recovery for this format5 corpus. It does not
qualify format6 markers, physical power loss, the later memory/artifact runtime,
or arbitrary volume sizes and counts. No unit tests were added or run.
