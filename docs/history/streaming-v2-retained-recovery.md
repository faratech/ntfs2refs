# Retained eight-GiB process interruption, resume and NTFS rollback

Run`2fa6edb2e7ac464ca863a5db6dbd6f5c` completed the planned retained-data
process-recovery case. It used a fresh operation from the saved pre-apply NTFS
branch, not replay of the operational candidate12 journal. Source commit
`15f95f33f0039ac757a91499d20b973bc4f991cd` plus the unchanged capabilities
patch; controlled producer
`b83911c4e4d6c3e662e0f5907b928b8e6fc61335a3745db4d67a8891af1849e5`;
recovery helper
`5bd69d5bcda7015e37cca39dc3fad2df3c417458b4dc62a17d58fff01c6981b5`.
The same source/target admission and tiny-cache synchronization remained active.

The52-GiB NTFS/64-KiB source had14 admitted objects and8,590,217,322 logical
bytes, including an8-GiB+1 zero file. The target was ReFS3.14/4-KiB. The plan
retained2,721,431,552 bytes, relocated5,868,785,664 and materialized106.
468 patches contain609,972,224 changed target bytes. Journal length is
1,220,029,018, immutable length1,220,020,826 and immutable SHA-256
`f345f84664706def460e91352b61e3520ad87506a2800900be9721d390f32c3b`.

Fresh original NTFS image:
`d8fd89c7779af5304fc4e5d00fbc15ab61155830b6613842c962baae6d9661c1`.
Expected ReFS image:
`1e938b2038047af353a01953569fbf62edd4d53015a3c7460b32cec5f2a69710`.
Expected semantic tree:
`7ea83b428d71012870b58a14d02c25d4330f004618be68d990f3140b2ce74cf9`.
Reconstruction request:
`97cbe83234d7d36b5689fea9afee74963dd21bf9462f43f8ce034cbb02a558cd`.
Ticket:`44d005bb561a5fef20285fc20081f655c3208be21307d3d98ff57f1d7f2bdb2e`.

## Observed outcomes

The producer exited86 after one complete flushed write, before handoff. The
source remained persistently offline across clean reboot, with zero controller
mount attempts. Guest-local resume produced the exact expected ReFS image,
still excluded. Finalization then closed rollback before native handoff and
passed its native checks. The separately pinned8f3675 verifier independently
confirmed all admitted contents/metadata and both original retained ranges,
2,721,431,552 bytes, through Microsoft's driver.

That successful outcome was archived and saved before restoring **only** the
saved partial checkpoint for the rollback fork. Exclusion passed after another
clean boot. A management connection failed before rollback task registration;
a successful read-only probe proved no task/worker existed, and the operation
was then dispatched once. No credential reset or security change was used.

Rollback produced the exact original NTFS image, verified its NTFS backup/log
structures, closed replay and mounted as NTFS. Independent native readback
matched all six original user-file lengths and SHA-256 hashes. Source writes
were not performed by that observer. Full source-image equality is proved
before mounting; normal filesystem metadata can change after availability.

## Exact evidence pins

Root:`.lab/hyperv/streaming-v2-20261027/candidate13`.

| Artifact | SHA-256 |
| --- | --- |
| Initial terminal archive manifest | `da207bc560c0636509f09079ba77c1774f8b3d4172ab89924cf5ef9ba59ae1c3` |
| Resume result | `e23659bff751ebef9685b045e735b0f7fc7e7ced00a849dda574f600e65a454a` |
| Resume execution | `2b2fb05b47240c96a6529e0a67b2b2cebdac8094c16e39639af262fc02b3960a` |
| Finalize result | `4251ad39812f8815274456e3d53609b93fff2c1add7c74281859741aea54c057` |
| Independent native recovered tree | `65b35722b3faaaa4fd8ff34e906489876eac542c9e6c6ea9dd5aae8db22c3929` |
| Recovered-Refs archive manifest | `cc7804a893fab6f21863c053bc423efb4beb6dc0c03539cfcf2c31bed1f24221` |
| Rollback execution | `959f6cc9e014f0adb89768be9662da2e93ab31df0806683f4ea1c285ff3eea60` |
| Rollback completion | `925cec019060c071d939c5e60b66f972733a94011dbdc63ba765ac39839e6b3f` |
| Rollback result | `61e3eeb4cec3376d084dc12041de2a01b8ef0e9cf0064debd5c61d49ae4102a4` |
| Native NTFS user-payload readback | `ed49b99015f846cb16fe448b1d4016d93dbcf19447a5213ac4333bcb49c3d59f` |
| Rollback archive manifest | `8233de3e53684df501efa8a7c6278e7e83eae071dae0c9ff5554af62adb97695` |

Partial OFF checkpoint:`4d73dd8d-d105-4f90-a277-3cab79df9e55`.
Resumed/native-verified OFF checkpoint:`4aa9e176-decf-4cb1-85fb-6b3fe0aed0c4`.
Rollback/native-verified OFF checkpoint:`452c3211-cc0f-4c95-acc4-d9c4100627a7`.
All23 checkpoints remain. The VM is OFF and4-GiB RAM released; the64-GiB
host reserve remained protected. Nineteen recovered-Refs files and nine
rollback files were copied and rehashed. No unit tests were added or run.

This qualifies the exact one-flushed-write **process-interruption** case,
including persistent exclusion after reboot and guest-local recovery. It does
not qualify physical power loss, torn sectors, every interruption boundary,
nonzero over4-GiB streams, other builds/geometries or low-scratch conversion.
Initial full-shadow payload allocation still belongs to this workflow; the
separate allocation-only template is not yet a conversion backend. The next
implementation priority is integrating that template with payload supply,
source metadata restoration and a complete recoverable required-byte plan.
