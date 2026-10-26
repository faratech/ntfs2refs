# Native-shadow alpha results

Frozen engine `96720eff89c7e808983c8d5c9800d475fe62515c`, executable SHA-256
`714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841`,
completed the public conversion in the independent alpha VM on October 26, 2026.
Run `4ad0147fdde044fbb9d5073e5bfdbe8d` exited zero. This result belongs to that
binary and bounded fixture, not arbitrary NTFS volumes or another build.

The original 52 GiB NTFS partition became ReFS through Microsoft's driver. All
15 admitted objects passed independent native verification. The 128 MiB source
file remained at partition-relative offset 8,913,149,952 with SHA-256
`f7bde0f9bb2fa62cf17c8d89b63d5e15233023e4cb2c4f521e45952d5bdaf316`.
Its allocation followed an owned 8 GiB temporary zero-write history; no NTFS
extent move was requested. This is a synthetic aged-allocation case.

| Scoped measurement | Bytes |
|---|---:|
| Admitted logical contents | 143,171,672 |
| Retained source payload range | 134,217,728 |
| Raw target writes, 142 patches | 231,481,344 |
| External journal length | 462,994,832 |

The native-shadow backend still initializes payload-proportional contents.
These results do not establish payload-independent scratch or absence of all
physical payload I/O. Whole-image equality was proved before handoff; writable
mount, label restoration and later native operations can change metadata.

Independent strict verification passed before and after the 50→80→10 MiB
create/grow/truncate/rename/delete workload and 128-entry directory workload.
A clean reboot was observed using greater UTC boot ticks; strict verification
then passed with the exact mutation report's scoped root-basic-info policy.
The branch was preserved OFF as checkpoint `efa6117b-902f-4495-ba10-c3ac4f23553c`,
parent `7e5582a7-6b15-4531-b77f-9f19cb9e5d47`.

Pinned results:

- Public `result.json`: `9c4a23b2465d4184240beaeca282c9c3aa3e5fa6b5dbd7ff4a4f08a7d939db59`.
- Derived recovery request: `30826a0470721867693713d1bbb022da1a1396ddfb42a9f9e1be66c1ab9a7cb4`.
- Semantic expectation: `d6e25290b7d1ecb4ed908a27906b0ae0c61b41a015b057a59063a609cb801538`.
- Mutation report: `d03699ac1571ea3bf37cecb1f0892568f7829690c847e5786b8b9fc62d360489`.
- Frozen NTFS image: `8962e6ce594f181047d5183738b4ed3c2428769b3469a1efb8f834ab90428b05`.
- Exact pre-handoff ReFS image: `44801bbe4b8bb5b587e3e97ee72f942015c8925a2370ebc38a20252cb2113dff`.

Evidence is under ignored root `.lab/hyperv/shadow-alpha-20261026`, including
`normal-evidence/ef9e1456af154eb0b85645a2a094848c` and
`postcheck/ef9e1456af154eb0b85645a2a094848c`. Exported JSON hashes were compared
with guest hashes. The complete journal remains in the preserved VM branch.

The separate preactivation cancellation case
`fd23326c56424b7b94cc4a92658ccb19` also passed. Its controlled producer exited
87 after freezing the source. Public `operation-state` reported
`frozen_before_activation`; public `cancel` exited zero, checked the complete
partition against frozen SHA-256
`58b48267e752c7f93cb25cda61f9153c20e1f5ac92d080bea31e129829874b15`,
and restored original NTFS availability without journal or source-payload writes.
The cancellation result SHA-256 is
`2fa0561e3695b82587891189fb311d105973e62a8d6ffd1259524337cd247d45`.
Seven user-file lengths/hashes, the original partition, mount and label matched
before and after a clean reboot. Checkpoint
`1cd601b8-c87d-42a8-a105-b1771fdf2b38` preserves that branch OFF. Full
post-mount image equality and a complete security/timestamp audit are not claimed.
The case's bounded JSON evidence was exported and its hashes compared with the
guest. Two preservation harness preflights needed correction/metadata
re-observation; neither retried a converter, reboot or restore operation, and
their original receipts remain preserved.

The separate first-flushed-write interruption/resume case
`c2939b18b2fb4ee8836f859dcf1d13b8` passed. The producer exited 86, with the
source still offline/writable, shadow offline/read-only and complete handoff
marker region zero. Public `resume` exited zero and wrote 132 patch ranges,
231,374,848 bytes, proving exact postimage
`426d3dcadf01c9ae6ac879fb080e0587d2362c5e40eba473024f74088ffa25dd`.
The 128 MiB retained range stayed unchanged; raw replay remained open until
public `finalize` exited zero and recorded handoff before native ReFS use.
Strict verification of all 15 objects passed before and after the bounded
mutation workload, and after a clean reboot with greater UTC boot ticks.
The branch is preserved OFF as checkpoint
`072a065e-7f91-457f-ad27-709271b07014`; all prior checkpoints remained present.

This case's pins are separate from the normal run:

- Frozen NTFS image: `073500e7eafcb308f8dcb52d446db50192bc8fd02654c2f7836a0d4f230f0aec`.
- Derived recovery request: `6657ba2480ff5258c46b74812c520c1cbca85807a07f82ca1c75309ad7e79e95`.
- Ticket file: `98be15852cbda5f2f8007b6b9454a46a94f84da4a98fa666abbb775e64e312ce`.
- Semantic expectation: `5eb30e43c400cac1308a88eb25eaac89865f8bd5967add696d900a230d97c793`.
- Resume result: `e23659bff751ebef9685b045e735b0f7fc7e7ced00a849dda574f600e65a454a`.
- Finalize result: `4251ad39812f8815274456e3d53609b93fff2c1add7c74281859741aea54c057`.
- Mutation report: `8ad16a6bc59e1a8c47ad301ca1f0fe11fdfdbfb16cf85a5797fd70e0ea78b830`.
- Strict post-reboot report: `3e7aaf6f83b7cf629d488a9fd9d373c18134add7a7f26a12530982a182052878`.

Its journal length is 462,780,240 bytes. Host evidence is under
`fault-cases/c2939b18b2fb4ee8836f859dcf1d13b8`, with controller
`b5d5cc65c3ee437b96dfed9460fa72de`. The journal remains in the preserved branch.
The subsequent normal-branch restore completed, but the original management
process did not observe it within its timeout. Its failure receipt is preserved;
a fresh management observation confirmed the actual OFF normal branch before a
guarded continuation dispatched the separate rollback case. The restore and
successful resume operations were not repeated.

Shadowless rollback uses another separate baseline branch; its outcome remains
pending and is not inferred from resume. Standalone observed marker digests have
not yet been collected. Power-loss safety,
boot conversion, advanced source features and broader Windows compatibility
remain unqualified. Independent-writer research remains off the alpha path.
