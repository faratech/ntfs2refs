# Mixed-tree exact journal verification

Sealed runtime `cc6cd28` passed the preserved F: corpus: native exit 0/HND,
933 objects and all 811 independent complete stream hashes. The corpus has
808 user files, 120 user directories and 9,885,781,381 user bytes. It converted
NTFS with 64 KiB clusters to ReFS with 4 KiB clusters, preserving label and mount.
This runtime includes bounded buffer reuse and exact selected-target checks.
Harness `9bbd1c4` is separate; later aggregate-SHA `60d2` and object-envelope
`f32c0f6` builds were not used.

Actual source evidence still has 654 absent initial content digests covering
9,885,682,940 logical bytes. The 650 partial streams have 1,371,388 tail bytes
with constructor/source/write-flush/readback/identity and protected-residual
bindings. Initial raw hashing was 94,077,273 bytes; other native logical source
reads were 22,204,741 bytes. The engine checked all 933 complete map bindings,
metadata and storage validity with zero target content hashes or payload reads.
Full fallbacks, selected-copy and journal reads remain. The separately pinned
lab baseline supplied all 811 independent hashes; three current access-time
reconciliations were recorded and all other canonical metadata remained exact.
Product expectations and filesystem times were not rewritten by the observer.

Native PID 5144/creation `1793478787506` exited 0 after 600.788 seconds from
creation to terminal publication. The observer passed another 141.877 seconds
later, using three hash batches. The last native process snapshot recorded
434.3125 seconds user CPU, 34.296875 seconds kernel CPU, 150,896,889,633 read
bytes and 23,002,013,682 write bytes. These are Windows process counters,
not physical disk I/O. Original guest artifact timestamps and every phase
snapshot are preserved. The principal snapshot deltas were:

| Native snapshot interval | Read GB | Write GB | CPU seconds |
| --- | ---: | ---: | ---: |
| Start to qualified | 42.513 | 0.149 | 38.984 |
| Qualified to journal prepared | 39.953 | 11.437 | 240.141 |
| Journal prepared to applied | 68.393 | 11.392 | 188.563 |
| Handoff to native verified | 0.038 | 0.023 | 0.891 |

The earlier sealed `18bdea8` case recorded 185,082,120,225 native read bytes;
this case recorded **34,185,230,592 fewer logical read bytes**. The plans and
formatter metadata differ slightly, so the complete difference is not assigned
causally to one change. This is not a controlled wall-time comparison or a
physical-I/O, 1 TB, or HDD timing promise.

The plan selected 11,391,942,656 bytes across 3,204 ranges, including
5,659,303,936 copy bytes and 5,694,500,864 zero bytes. Packed literal backing
was 38,137,856 bytes and the journal was 11,430,396,448 bytes. Source-backed
mapping retained 4,225,028,096 bytes at original coordinates (42.745% of the
combined original-plus-copy mapping). Placement submitted 2,424 moves totalling
13,580,988,416 bytes; submissions may repeat movement and are not physical I/O.

All 69 closed JSON/log files (155,572,595 bytes) were copied with exact length
and SHA-256 checks, within 64 MiB per file and 256 MiB combined. Tasks and workers
were terminal before normal shutdown. One checkpoint was issued; a fresh
process resolved its initially stale parent observation to
`42d684f8-1a63-4f7b-98ac-286d88289a63`. The VM is Off/RAM0 with 50 checkpoints.
At checkpoint, lab bytes were 285,720,877,776 and host free bytes 59,607,769,088,
inside the unchanged storage epoch. Only obsolete checkpoint `78513f35` was
removed after its closed archive and dependency pins were revalidated;
all host baseline and evidence files remain.

This qualifies one normal F: case for the sealed cc6 implementation. It does
not qualify cc6 recovery, arbitrary interruption, power loss, later mutation,
or the newer CPU/V3 candidates. No unit tests were added or run.
[Evidence and artifact pins](../../evidence/mixed-exact-journal-native-20261031.json).
