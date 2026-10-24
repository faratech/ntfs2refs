# Native NTFS file-handle observations

The Rust lab collector now queries the saved populated NTFS corpus through
Windows file handles inside `ntfs2refs-win11`. It does not grant source admission
or enable the general converter. The native run found two differences that a
complete source-admission protocol must account for.

`crates/n2r-win32/src/attestation_native.rs` opens every requested record by its
64-bit record/sequence identity using `OpenFileById`, with backup semantics and
`OPEN_REPARSE_POINT`. It requests read attributes, read control and system
security access. Two snapshots retain basic/standard information, 128-bit file
identity, attributes/reparse tag, and owner/group/DACL/SACL/mandatory-label
queries from both `GetSecurityInfo` and `GetKernelObjectSecurity`.

Before and after, it checks the exact single volume-to-disk extent, NTFS serial
and geometry, online/read-only disk attributes and native `ERROR_WRITE_PROTECT`.
The standalone process enables backup/security privileges, queries their
enabled states, restores the original states and queries them again. The report
retains those values. `SE_PRIVILEGE_USED_FOR_ACCESS` is recorded but excluded
from the restoration equality check; enabled/default/removed state must agree.

Requests are limited to 256 unique identities, 64 KiB per security query and
4 MiB of retained security bodies. The source inspection and request are hash
pinned; output files are created new. Successful comparisons remain diagnostic.
The comparator preserves control flags, SID values, ACL absent/null/empty state,
ACL revision, ACE order and complete ACE bytes, while allowing different
component offsets and padding.

## Measured result

The corpus was restored inside the VM onto its enrolled blank target disk, in
a new 1 GiB GPT data partition at 16 MiB. That fixture setup wrote exactly 1 GiB
and is separate from conversion. The disk was made read-only before its first
NTFS mount. Full partition reads before and after subsequent observations kept
SHA-256 `86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727`.
No host mount or host filesystem conversion was used.

| Observation | Result |
| --- | ---: |
| Allocated MFT identities requested | 36 |
| Successful `OpenFileById` calls | 17 |
| Explicit open refusals | 16 with error 5; 3 with error 2 |
| Successful kernel security queries matching the raw descriptor semantics | 16 |
| Successful opens with unsupported file/security queries | 1 (`$Volume`, error 87) |
| Kernel/API security differences | 13 |
| Complete strict per-file matches in the final capture | 2 |

The 16 matching kernel descriptors include all eight outside-`$Extend`
candidate objects in the fixture: its directory and seven file identities.
This includes resident data, Unicode, ADS, hard-link, sparse and reparse test
objects. Opening them does not qualify conversion of those features: stream
enumeration, extent/data verification and target preservation remain separate.
No refusal is silently dropped from the report.

For 13 identities, `GetSecurityInfo` returned a different inheritance view from
the stored descriptor and `GetKernelObjectSecurity`. Observed differences include
`SE_SACL_PROTECTED` when the raw SACL is absent and `INHERITED_ACE` flags on
the fixture's inherited DACL entries. All controls and flags remain in the
evidence; the comparator does not mask them to manufacture a match. The cause
and ReFS round-trip behavior need qualification. A stored descriptor alone is
insufficient evidence for equality of both Windows API views.

The root directory's native last-access time also advanced in memory during
the observation session, while the protected raw partition hash stayed unchanged.
The final native value was `134373242780019986`; the raw value remained
`134372649002659763`. Creation, modification and MFT-change times still matched.
The initial capture matched the root timestamps. Read-only storage therefore
does not, by itself, prove that all cached native metadata equals the frozen
disk image. The comparator reports this discrepancy rather than accepting it.

The guest was Windows 11 Pro 26300.9457 (26H2), AMD64, PowerShell 5.1.26100.9444.
Its `ntfs.sys` file version was `10.0.26100.1`, SHA-256
`64835fa4bd4a4202d29500f337ebf71704d5b6dea135de40d3dbd52717475b53`.
Backup and security privileges both recorded `0 -> 2 -> 0`.

## Reproduction and evidence

`lab/guest/Invoke-GuestNtfsAttestation.ps1` stages only the pinned corpus on the
enrolled blank target. It refuses existing partitions and never clears a disk.
`NativeNtfsCorpusDisk.cs` independently checks the newly assigned GPT identities,
fixed offset/length and offline attribute before aligned writes; it hashes the
restored partition before any mount. It is a fixture helper, outside the Rust
converter's native I/O API.

`scripts/Capture-LabNtfsFileAttestation.ps1` was executed successfully against
that already staged, read-only source. It verifies VM/disk ownership, pins and
archives the collector/helpers, runs the collector in the guest, exports hashed
observations, and invokes the Rust comparator. It performs no raw writes or disk
state transitions. For an existing prepared run:

```powershell
.\scripts\Capture-LabNtfsFileAttestation.ps1 -RunId <32-hex-run-id> `
  -BinaryPath <built-lab-ntfs-attest.exe> -BinarySha256 <sha256>
```

The final capture is ignored
`.lab/hyperv/ntfs-attestation/file-handles-20261024T141927203Z`:

| Artifact | SHA-256 |
| --- | --- |
| Collector binary | `6f36d88da1e8505b3b91c173c0168e0a4646694adfb354d42f001c8809002437` |
| Host result | `83c11a16a7d0cf368c08f06e756467bd4bc70151939dc7631f4cf9605f5e543f` |
| Native schema-2 report | `d9d27b87bf283dfebc60fe62d52c68e292a83c8ed31cc8c4132433c7ddabd519` |
| Comparison | `9aadfef1382a83fbac4e5e56ab634ef37fcb5ddd8406800ee92a3d28fc1630e9` |
| Bound raw inspection | `a1b25e0e0bcabe41455fd67a25c55b7017b6b8da9ac6437e0c062b7dc2b86baa` |

Earlier schema-1 observations remain under ignored
`.lab/development/native-attestation-20261024T135015609Z`, including the original
staging result and the intermediate second-API experiment. Their binaries and
reports remain archived; the final schema-2 comparator requires the new
privilege audit and kernel queries.

Outcome checkpoint `c4f58c73-5ca5-4842-bc7b-6e980a8eabd7` is named
`ntfs-source-attestation-057cfe705cca456aa3e7c472dedc7dcc`. The VM was cleanly
stopped, checkpointed, then restored to `installed-clean`, off at 4 GiB.

Sixteen new tests cover missing/stale observations, security repacking,
owner/ACL/control/ACE differences, native protection and privilege failures.
At this milestone the workspace passed 312 tests with five ignored, formatting
and clippy. [Stream/retrieval-pointer and bitmap checks](native-ntfs-stream-attestation.md)
have since passed natively. Native namespace/logical-data reconciliation, coherent
freeze/log/backup admission, general metadata construction and recovery testing
remain unfinished. `conversion_qualified=false` and `inventory_complete=false`
remain in force.

Microsoft contracts used here: [OpenFileById](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid),
[file information queries](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[GetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getkernelobjectsecurity),
[NTFS volume data](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer),
and [privilege attributes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges).
