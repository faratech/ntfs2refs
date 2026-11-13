# Mixed-tree fast journal qualification

Sealed runtime `18bdea8` converted the preserved F: corpus from NTFS with
64 KiB clusters to ReFS with 4 KiB clusters. It has 808 user files, 120 user
directories and 9,885,781,381 user bytes. Including system objects, the native
tree contains 933 objects and 811 default streams. Native exit 0/HND and the
observer passed; all 811 independent complete stream hashes matched.

The product kept 654 initial content digests absent, covering 9,885,682,940
logical bytes. Its 650 partial streams have 1,371,388 actual tail bytes bound
by source reads, constructor write/flush/readback/identity receipts and frozen
protected-residual hashes. Initial raw hashing was 94,077,273 bytes, compared
with 9,979,760,213 bytes in the separately pinned old full-content baseline.
Other native logical source reads still totalled 22,204,741 bytes. Full
fallbacks and source/candidate/journal reads remain.

The engine reported `exclusive_preparation_readback_used=true`: its immutable
journal pin was issued during complete validating readback. It checked all
933 mounted map bindings, metadata and storage validity with zero target
content hash reads. Independent lab reads verified all 811 hashes in three
batches against the old baseline, without rewriting product expectations.
One recorded access-time reconciliation preserved every other canonical field.

Native creation to terminal publication took 632.865 seconds in this single
uncontrolled run. The last native snapshot recorded 426.359 seconds user CPU,
48.859 seconds kernel CPU, 185,082,120,225 read-transfer bytes and
23,003,814,097 write-transfer bytes. The observer completed a further 329.623
seconds later. These are Windows process counters, not physical disk I/O;
no general speed improvement is inferred. The exact phase snapshots are pinned
in the evidence. Their main deltas were:

| Native snapshot interval | Read GB | Write GB | CPU seconds |
| --- | ---: | ---: | ---: |
| Start to qualified | 42.514 | 0.150 | 34.844 |
| Qualified to journal prepared | 39.955 | 11.438 | 238.750 |
| Journal prepared to applied | 102.574 | 11.392 | 200.797 |
| Handoff to native verified | 0.039 | 0.024 | 0.797 |

The plan selected 11,391,897,600 bytes across 3,216 ranges. Source-backed mapped
payload includes 4,225,028,096 bytes at original coordinates (42.745%) and
5,659,303,936 bytes of selected copy ranges (57.255%). These percentages describe
that combined mapping, not all stream logical bytes. Zero ranges cover another
5,693,968,384 bytes. Packed literal backing is 38,625,280 bytes and the journal
is 11,430,839,968 bytes. Placement submitted 2,424 moves covering 13,580,988,416
bytes; submissions can include repeated movement and are not physical I/O.

All 71 closed metadata files (155,615,575 bytes) were copied with exact lengths
and SHA-256 checks before normal shutdown. Converted checkpoint
`ecd548f8-3237-44f5-b874-6de79c140997` is preserved; the VM is Off/RAM0 with
50 checkpoints. Actual lab bytes 285,593,776,923 and free host bytes
59,539,214,336 remained inside the unchanged storage epoch. Obsolete old
rollback checkpoint `b8091885` was removed through Hyper-V after archive
revalidation; every host archive and baseline remains.

Runtime `18bdea8` is separate from harness `05f511f`. Later buffer-reuse
`05b6d5e` and exact selected-target check `cc6cd28` builds were not used.
This is one normal F: corpus result; it does not qualify recovery for this
runtime, arbitrary interruption, physical power loss or subsequent mutation.
No unit tests were added or run. [Evidence and artifact pins](../evidence/mixed-fast-journal-native-20261031.json).
