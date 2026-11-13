# Native shadow for the independently populated tree

This work extends the native-shadow path. It does not convert the original
partition, issue source admission, or qualify native interruption recovery.
The original NTFS source remains persistently offline and read-only.

## Source and placement

The input is the four-file, three-directory tree recorded in
[the native source-freeze report](native-ntfs-source-freeze.md). Its 512 KiB of random file contents was created
before inspection, without retrieval-pointer queries or extent movement. The
source partition SHA-256 is
`798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.

`lab-tree-shadow` derives its semantic input from fresh raw reads of the actual
excluded source device. Before ordinary shadow construction or security
finalization it checks the complete partition hash, and repeats that check
afterward. The independent ReFS shadow is bound to its actual disk, GPT
identities, volume extent, geometry and filesystem. All conversion activity is
inside the owning guest; Hyper-V provides orchestration and checkpoints.

The first full construction reported matching logical bytes, storage-valid
regions, four stored timestamps, attributes and namespace identities for all
eight objects, including the root. Both complete source hashes matched and
native source writes were zero. It correctly failed overall qualification:
Windows creation cleared one stored security control bit on seven objects.

All four source payload candidates are free in the legacy ReFS bitmap but
allocated in the metadata-inclusive view:

| Source path | Original LCN | Clusters | Metadata-inclusive allocated clusters |
| --- | ---: | ---: | ---: |
| `source0.bin` | 6263 | 16 | 16 |
| `archive\doc1.bin` | 6280 | 32 | 32 |
| `archive\nested\doc2.bin` | 6328 | 16 | 16 |
| `notes\doc3.bin` | 6344 | 64 | 64 |

The placement diagnosis therefore records 524,288 relocated bytes and zero
retained bytes. It uses each stream's actual native destination mapping and
hashes every disposition range. It introduces no dummy retained range and does
not relax the existing single-file reconstruction fixture. The placement report
remains non-executable pending source admission, frozen-shadow validation,
exact capacity calculation and native recovery qualification.

## Security preservation

The comparisons retain owner/group SIDs, descriptor control bits, ACL
presence/null/empty distinctions, and ACE order and flags. Descriptor component
placement and padding are compared semantically using the existing parser.

Two native observations drove the implementation:

* Restoring root security through `SetSecurityInfo` with inheritance processing
  changed control `0x8004` to `0x8404`. The API view also differed from the stored
  descriptor. That experiment was refused; the comparator was not weakened.
* Creating the seven non-root objects with their supplied descriptors produced
  control `0x9004`, whereas the source stored `0x9404`. Other descriptor semantics
  matched. The missing `AUTO_INHERITED` bit remained a reported mismatch.

The root interoperability test instead submitted a 248-byte
`BACKUP_SECURITY_DATA` stream through
[BackupWrite](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite).
Windows accepted the entire stream; both native security views then matched the
source descriptor exactly. The backup context was released and the volume was
flushed. This isolated metadata experiment explicitly reports that it did not
verify the entire source image and cannot supply source admission.

The builder now performs the same restoration when creation changes a
descriptor, followed by exact comparisons and restoration of all four stored
timestamps. Its existing-shadow security finalizer first re-reads every file,
checks storage validity, streams, EOF, links, names, identities and basic
metadata, and accepts only the specifically observed missing-control-bit case
as a repairable security discrepancy. Final comparisons require the complete
original descriptor, with no control-bit normalization. It also checks that
payload mappings did not change during security restoration.

The finalizer operates exclusively on the independently bound shadow. It
cannot arm writes to the source. Native finalization passed for all eight
objects. A subsequent clean restart, native verification and offline freeze
also passed, preserving all four timestamps, both security views, data and
namespace identities. The entire source hash matched before and after every
full-tree run, with zero native source writes.

The unnamed backup-stream header uses the SDK offset of `cStreamName`, 20 bytes,
followed by the descriptor. This is checked against `WIN32_STREAM_ID`; using
the padded structure size would place the descriptor incorrectly. See
[WIN32_STREAM_ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id).

## Reproduction and evidence

* `scripts/Build-LabExistingTreeShadow.ps1` prepares only the enrolled blank
  journal and a new independent guest-local shadow.
* `scripts/Continue-LabExistingTreeShadow.ps1` operates on an already measured
  running branch; it cannot create, format or restore a VM. Every invocation
  pins its binary and request, exports terminal failures, and preserves a live
  or uncertain operation instead of retrying it.
* Root restore evidence:
  `.lab/hyperv/existing-tree-shadow-steps/win11-20261024T222115867Z`.
  Report SHA-256:
  `cd7e54a7be9b70466966a2912fa11131e2ad2f939bc968196f7db4a701585173`.
* Full construction with the explicit seven security refusals:
  `.lab/hyperv/existing-tree-shadow-steps/win11-20261024T222222090Z`.
  Report SHA-256:
  `6f7504942fd15bf1004b787d12fd83970e458691cdf6b6c0679ae4e2eb3b1e6d`.
* Successful existing-shadow security finalization, report SHA-256:
  `b054e408ec5db78d4d7da3c6834346ba10725cfc7b28b4bf9fb9fc4184753b5e`.
* Post-finalization restart, verification and freeze:
  `.lab/hyperv/existing-tree-shadow-steps/win11-20261024T235950079Z`.
  Report SHA-256:
  `00a45f71a63be1cb87650d839613e9e2b6c2b23d01f05ff7ecd284f0843a48b1`.
  Frozen 52 GiB shadow SHA-256:
  `da1e6cd1d676ce806e5937d934ab57ebed57fa6bf4c0f6593fb8d34859490e01`.

Both data disks were confirmed offline/read-only before shutdown. The off-state
8 GiB VM checkpoint is
`existing-tree-shadow-frozen-4cf7abc7c0174772868802161b563b7e`, ID
`7bcaf7f9-07a5-463b-bc88-3a4f88e0e5e1`. The host then returned to the stopped
4 GiB clean baseline. ReFS header version 3.14 and a matching backup header were
observed after exclusion. Header/bootstrap inspection is not a complete
independent ReFS metadata validator.

These ignored laboratory artifacts are locally measured evidence, not artifacts
included in the Git repository. General source admission still needs explicit
internal-state/transaction policy, source namespace visibility and timestamp
policy, and a live capability bound to the final frozen source. No serialized
success field authorizes conversion.

The shadow-freeze value has no deserializer. Its constructor isolates the actual
device, checks its binding and measured format profile, then reads the complete
partition while disk attributes remain 3. It binds the native observation, tree
and placement digests. Execution must independently revalidate the actual
frozen device; reading the exported freeze report does not grant authority.

## Resource accounting

The VM's OS differencing data can grow by several GiB even though the shadow
backing initially uses about 100 MiB. The lab budget now accounts for that
observed overhead and retains the 64 GiB host free-space requirement. The
owned guest's paging file is bounded to 512 MiB for subsequent boots. A
read-only, full Hyper-V compaction of its OS differencing disk completed but
reclaimed zero bytes; source and journal disks were excluded from that action.

Package-scoped `cargo clean -p ntfs2refs --profile dev` reclaimed 10.5 GiB of
generated artifacts. All four release executables retained their exact hashes;
source images, checkpoints and experiment records were preserved. Development
builds now use limited debug information and disable incremental compilation
to bound subsequent cache growth. The direct recursive cache-deletion attempts
were blocked by automatic approval review, including after explicit user
authorization; those attempts deleted nothing.

This is not yet a low-scratch converter. Shadow payload initialization, the
whole-partition comparison, journal old/new bytes and operational reserves must
still be budgeted separately.
