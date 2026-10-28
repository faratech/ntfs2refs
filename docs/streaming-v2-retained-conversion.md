# Eight-GiB retained conversion: completed native acceptance

Run`cb25d12237454c3999f319547f48b057` converted the existing52-GiB NTFS/64-KiB
partition to native ReFS3.14/4-KiB on the same partition. The source tree was
not prearranged by moving its extents. Fourteen admitted objects include six
user files with Unicode names and an8,589,934,593-byte zero file. Total admitted
logical bytes are8,590,217,322. Converter source is
`3d4fb8217f88bc4001ebcc71436d8ff0bd24aed6`, executable SHA-256
`cc02ca4075e0d5bb5d95da964a8033d648d299704a80d77aceeccd3eebf7476b`.
The unchanged capabilities-only dirty patch is separately recorded; current
HEAD and later allocation-only code do not inherit this producer's result.

The plan retained2,721,431,552 bytes, relocated5,868,785,664 and materialized106.
470 patches wrote609,918,976 target bytes. The journal is1,219,922,842 bytes.
The frozen NTFS image SHA-256 is
`a228acd3cc509e21dc3261b1a76306c226bbf002d9cc9f6e84808fba9b82e170`;
expected applied image
`0fdc49384616a9ef20dd7d1742eec3d17769effb5bb1dccc71a2c5e7366897fb`;
semantic manifest
`36e1f5d1c34f15884d12a1919616fd5d7bfde45a7319f301527e9b00d56548cf`.
Rollback closed before native handoff. Never replay this journal afterward.

## Completed checks and full report pins

Windows11 build26300.9457, refs.sys10.0.26100.8875 (WinBuild.160101.0800),
driver SHA-256`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.
The separate verifier is
`8f3675076a34bd977245744af702c82d7bf2b6c662e757246b153fcaf6840f9a`;
mutator`0c9fa6caaff35c2d56cc2e6f83db0d4a5ed0622fc2d98446e74f0c591e2485dd`.
These are guest report hashes, distinct from wrapper hashes in the registry:

| Phase | Guest report SHA-256 |
| --- | --- |
| Before mutation | `ae22236dfe394aec136c8fb672f9d73adad167d3657afda08f21bf14b5cfebf0` |
| Preserved converted boot | `8aa4ed631fa4e8acfdb0807d94c132ff151b1308c6b13f514ec440bddc027ecd` |
| Mutation | `3a243987df1d82b4e069aae5f6fa316050c6e20ef870d2a88496693e5d54cfc9` |
| After mutation | `4800627116fb7ad0ef2708eb5ee1692e7177b12acea497fe1336c49deea3413e` |
| After mutation/reboot | `4dd857a0f50b5a0fef42782680cfdcdd9cf5bf0fd504091932236abfb7292a7b` |

The native workload created50 MiB, grew to80 MiB, truncated to10 MiB, renamed,
created128 directory entries and removed its test tree. Native verification
passed after mutation and after clean reboot at2026-10-28T04:48:53.0507570Z.
Both observations verified every admitted stream hash and the same original
physical positions for both retained ranges,2,721,431,552 bytes. The position
proof uses fresh native same-file/VCN mappings and the already collected full
stream hashes; it does not claim new per-range hash reads or grant writes.

Evidence root:`.lab/hyperv/streaming-v2-20261027/candidate12`. Thirteen guest
postcheck files/tool binaries were copied and rehashed into
`postcheck-terminal-evidence`; manifest SHA-256
`28b5628a0da13222621cf5d4c13bb6dd8cb6bd74f8a872c309c233ed9bb92d72`.
The passed OFF checkpoint is`49094105-ed4b-4447-9f23-86a3a22b394f`, parent
converted checkpoint`ae80bfd5-7b8d-4e60-80b4-6e236c841390`. All20 checkpoints
remain and VM RAM is released. No unit tests were added/run.

This is a bounded native conversion/mutation/reboot result, not a production
or low-scratch qualification. Initial shadow construction still initialized
payload; the separate134-MiB allocation-only child observation is not this
converter's total scratch cost. Nonzero over4-GiB data, broad geometry/build
coverage and retained8-GiB interruption recovery remain unqualified.

## Next acceptance gate: retained-data process recovery

Before more compact-shadow expansion, qualify the retained8-GiB path with
guest-local recovery. This plan is not permission to replay the completed run.

1. Keep candidate12 and every other checkpoint. Start only a new disposable
   branch from the saved **pre-apply NTFS** checkpoint
   `6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`. Reconfirm exact disk/partition IDs,
   no live worker, the64-GiB host reserve and capacity for a fresh journal.
2. Pin a controlled producer/recovery pair with the corrected streaming journal
   profile. Use a new run, journal path and ticket; never activate the old
   unticketed candidate11 journal. Reuse the protected shadow only after fresh
   source admission and target verification, including required tiny-cache sync.
   Derive new hashes from that operation, not candidate12's historical values.
3. Exit after one complete flushed target write, before handoff. Preserve the
   partial branch and immutable recovery material before changing availability.
4. Cleanly reboot and prove persistent source exclusion before recovery. Resume
   with the exact pinned inputs, prove the expected complete postimage, record
   handoff, then verify native contents/metadata and retained positions.
5. Preserve the resumed result. Restore only the saved partial branch for a
   separate rollback fork. Prove restoration of the exact newly admitted NTFS
   image and original user-file hashes through the converter's own recovery.
6. Preserve both outcomes and link their exact producer/report hashes. A
   process exit followed by a clean reboot is **not physical power loss**.
   Host/storage power-loss and torn-sector qualification remain separate gates.
