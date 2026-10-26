# Native-shadow alpha: bounded normal path passed

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

Cancellation and interruption/recovery cases use separate baseline branches.
Their outcomes are not inferred from this normal-path result. Power-loss safety,
boot conversion, advanced source features and broader Windows compatibility
remain unqualified. Independent-writer research remains off the alpha path.
