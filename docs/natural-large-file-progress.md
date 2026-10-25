# Naturally allocated 128 MiB file

The next source case adds `F:\natural-large.bin` through ordinary sequential
NTFS writes, without moving source extents. The guest script records its
`System.Random.NextBytes` seed, flushes the file and hashes it independently.
Its 134,217,728 bytes have SHA-256
`db7ba0d1de48a1ac100e6865d591ad68a3ebe53c5634c83b584fe9a9bc11b376`.
Windows reported one naturally allocated run: VCN 0, 32,768 clusters,
LCN `0x1908` (6408). The creation report is under ignored local path
`.lab/hyperv/natural-source/win11-20261025T195717349Z/source.json`, SHA-256
`d0cf0aab2a459d9db3deb1cc7c878753df6f88653ff3d2df423fe560a77e8d43`.

The public CLI run under
`.lab/hyperv/certificate-conversion/win11-20261025T200535472Z` qualified all
twelve objects and issued its source certificate, then refused journal
preparation at the old 256 MiB changed-byte ceiling. No raw patches were
applied; source and shadow remained excluded/read-only. The larger source
requires accounting for both the old random payload and its new location.

The journal-capacity calculation now reserves 16 MiB for metadata, budgets
both old/new payload copies, aligns to 4 KiB and caps changes at 376 MiB for
the existing 768 MiB journal ceiling. Exact serialized journal-size limits
still apply. The public-CLI retry is under
`.lab/hyperv/certificate-conversion/win11-20261025T203834359Z`; inspect its
terminal result before claiming conversion success.

Retention was **zero** in the measured twelve-object shadow. Its large stream
was placed at physical LCN 1,507,328. Reading those raw shadow bytes reproduced
the full file hash. None of the reported user extents overlapped the desired
source range. The metadata-inclusive bitmap marked that entire source range
allocated; its first allocation interval was LCN 0..1,540,096. This does not
justify clearing bits or assuming shadow user-data evacuation will help.
The new pure evacuation planner remains unwired research and plans no user
moves for metadata-only blockage.

Other changes support the next steps: read-only device-binding discovery,
controlled lab interruption after a flushed write, and equal-chunk comparison
for retained requests. Both comparison passes, every pin and mutation checks
remain in place. Missing ordinary artifact parents are now created on the
OS volume while reparse paths and existing output directories remain refused.
