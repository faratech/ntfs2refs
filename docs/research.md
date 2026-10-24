# NTFS to ReFS conversion research

Research baseline: 2026-10-23. This file distinguishes published behavior, external research, and the design proposed for this project. No native ReFS writer or converted boot volume has been qualified by this project yet.

Current priority: same-partition, extent-preserving data-volume conversion,
executed inside the guest or on the physical machine that owns the source disk.
Boot experiments below are deferred. A support restriction is not evidence that
ReFS boot is technically impossible; eventual acceptance remains build-specific.

## Product contract

The target is an offline conversion of the same partition that reuses ordinary nonresident file-data extents. Temporary on-volume staging and an explicitly bounded external recovery journal are allowed. A complete backup followed by formatting and restoring is not an implementation of this contract.

Windows 11 and Windows Server have independent research lanes. Windows 11 is the active lab lane; the user has deferred obtaining Server media. Windows 11 experiments may change configuration while retaining Microsoft-signed components. Custom boot loaders, custom filesystem drivers, and transplantation of a Server boot chain are outside the agreed scope. Unsupported source features must be reported and refused before destructive writes. The first version will not silently decompress, decrypt, discard, or reinterpret metadata.

Converter rollback covers the interval before handoff to the first writable ReFS mount. Hyper-V checkpoints provide the experiment's recovery mechanism after that handoff. Initial qualification targets unencrypted basic GPT disks, 4 KiB clusters, and fully shut-down sources. Broader geometries can be inspected without being accepted for conversion.

## Boot feasibility

Microsoft documents ReFS OS volumes for Windows Server Insider Preview from build 29531. The documented installation uses UEFI/GPT with a FAT32 EFI partition, an MSR, a ReFS Windows partition, and a separate NTFS WinRE partition. Recovery must be allocated in advance because ReFS does not support shrinking. This is preview support, not a general statement about released Windows versions. [Microsoft deployment guide](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-boot-windows-server-unattend)

Use available, unexpired Server media. Build 29659 is a documented example that retains ReFS boot and offers ISO/VHDX media; capture the exact build and expiration of the acquired image instead of treating the minimum build as the desired installation. [Microsoft build announcement](https://techcommunity.microsoft.com/discussions/windowsserverinsiders/announcing-windows-server-vnext-preview-build-29659/4554949)

The historical Windows 11 ReFS installation experiment is a lead, not a current compatibility guarantee. The Rufus maintainer discussed the undocumented experiment and declined to support it. Do not assume a 2023 feature identifier applies to the downloaded ISO. [Original maintainer discussion](https://github.com/pbatard/rufus/issues/2206)

The Windows 11 lane must first boot a clean NTFS control, then attempt a freshly formatted ReFS control using the same build's signed components. Failure of the latter blocks converted-OS acceptance for that build. Record which stage fails: firmware, boot manager, OS loader, kernel/driver initialization, or servicing. Reading ReFS from an already-running Windows instance does not establish boot support. [Microsoft startup-stage explanation](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/windows-boot-issues-troubleshooting)

### Windows 11 26300.9457 control experiments

The current ordinary ReFS data-control design uses a 1 GiB partition and a VM with 4 GiB RAM. Capture the native formatter's result, error code, edition, geometry, and component versions. A refusal on that fixture alone does not distinguish edition policy from size or other constraints. The native NTFS first boot passed on 2026-10-23; native ReFS boot remains unverified. Neither a successful format nor an applied Windows image proves ReFS OS boot.

Dev Drive is a separate data-control option. Microsoft documents availability on all Windows SKUs from build 22621.2338, a minimum 50 GB volume, and at least 8 GB RAM. The current small control does not meet those requirements. A Dev Drive corpus must retain that provenance and its filter policy; `untrust` changes policy rather than establishing an ordinary-format volume. A future large control also needs an export destination large enough for the raw partition, since the lab's 8 GiB journal disk cannot hold it. [Dev Drive requirements](https://learn.microsoft.com/en-us/windows/dev-drive/), [Dev Drive controls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-devdrv)

UUPAssistant commit `a750c1955d7e37b70c609bbecad471ad929682d1` (2026-08-11) provides a newer primary implementation lead. Its experimental ReFS installation path uses native VDS formatting, WIM extraction, boot files from the installed image, and BCD creation. Its UI requires UEFI and describes client-build compatibility as conditional. The inspected path supplies no evidence that a historical feature ID or a ReFS service-start change is necessary. This is not qualification of build 26300.9457, and the third-party installer has not been executed by this project. [Formatting source](https://github.com/Lourdle/UUPAssistant/blob/a750c1955d7e37b70c609bbecad471ad929682d1/src/UUPAssistant/DiskPart.cpp), [Installation source](https://github.com/Lourdle/UUPAssistant/blob/a750c1955d7e37b70c609bbecad471ad929682d1/src/UUPAssistant/InstallThread.cpp), [Conditional-support strings](https://github.com/Lourdle/UUPAssistant/blob/a750c1955d7e37b70c609bbecad471ad929682d1/src/UUPAssistant/Resources/UUPAssistant.rc)

The bounded boot experiment is a separate blank VHDX with FAT32 ESP, MSR, a native ReFS OS partition, and a preallocated NTFS recovery partition. Apply the same Pro image using stock DISM without CompactOS/WOF options, retain stock driver configuration, and construct the boot chain with the same image's signed components. Keep Secure Boot enabled. If native formatting fails in the installed guest, a matching-media Setup/WinPE format attempt can test that environment separately; record both outcomes. The Server guide's unattend `Format=REFS` support must not be assumed to apply to this Windows 11 image. [Server-only Setup constraint](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-boot-windows-server-unattend)

BCDBoot documents `/s` for preparing a disk for another machine and `/offline` for explicit offline boot-file selection on recent builds. Record the selected boot binaries and inspect BCD device references so the control boots the VM's partition. Capture hashes, versions, and signature results for the formatter, `bootmgfw.efi`, `winload.efi`, and `refs.sys`. A successful session with the OS volume reported as ReFS establishes only observed boot for that exact configuration. Repeated cold boots, recovery, pagefile operation, preservation checks, and servicing remain separate acceptance gates. [BCDBoot options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11)

## Why a metadata writer is required by the proposed design

ReFS block cloning shares storage between files on the same ReFS volume. It is not an API for adopting an arbitrary NTFS extent. Therefore formatting a volume and calling block cloning does not provide this project's conversion algorithm. [Microsoft block-cloning restrictions](https://learn.microsoft.com/en-us/windows-server/storage/refs/block-cloning)

The proposed algorithm constructs target metadata while retaining compatible source data allocations. There is precedent for this style of conversion in Btrfs tooling: conversion uses source free space, and rollback has layout-dependent limits. This is an architectural analogy, not evidence that ReFS has equivalent mechanisms or that a ReFS conversion is already feasible. [Btrfs conversion documentation](https://btrfs.readthedocs.io/en/latest/btrfs-convert.html)

The implementation must establish ReFS allocation, reference counting, directory and object indexing, metadata checksums, checkpoint selection, and mandatory-anchor behavior. ReFS's own recovery protocol starts from an already-valid ReFS filesystem; it does not automatically protect an NTFS-to-ReFS transition. A filesystem signature change must not be treated as an atomic commit.

## Reusable components and evidence quality

| Source | Useful contribution | Limit for this project |
|---|---|---|
| [`ntfs` Rust crate](https://github.com/ColinFinck/ntfs) | Reading NTFS attributes, streams, and indexes | Its documented unsupported areas include writes, compression, encryption, journaling, reparse-point interpretation, and security descriptors. It is a foundation, not a preservation-complete converter. |
| [`libfsrefs`](https://github.com/libyal/libfsrefs) | Experimental ReFS format analysis and documented header fields | The project's stated reader support is ReFS v1; v2/v3 support is incomplete. |
| [`refsprogs`](https://github.com/unsound/refsprogs) | Independent tools for listing, inspecting, and extracting ReFS data | Upstream describes incomplete format knowledge. The advertised tools do not establish a qualified filesystem creator or converter. |
| [`forefst`](https://xbpt.gitlab.io/forefst/about/) | Recent forensic tools and a reference covering ReFS 3.4–3.14 and an Insider corpus | Independent research rather than a vendor format specification; use claims as hypotheses until confirmed against this project's captured native corpus. |

No complete, tested modern ReFS writer suitable for this conversion was identified in these sources. This is a research result with a bounded search scope, not a claim that no such implementation can exist.

Modern research reports that the version in the volume header is insufficient to distinguish freshly formatted and upgraded layouts. Pin formatter build, driver build, creation history, geometry, and measured metadata behavior together. Never select write layouts solely from a `3.x` version number. [Format evolution research](https://xbpt.gitlab.io/forefst/concepts/version_evolution/)

The ReFS inspector decodes common volume geometry and a bounded ReFS 3.14
bootstrap profile. It checks the recognition checksum, candidate SUPB/CHKP
self-checksums and three physical root types against their referenced CRC64
checksums. See the [implemented reader scope](refs-bootstrap-reader.md) and
[native evidence](lab-results.md). It does not establish complete metadata,
allocation consistency, native/upgraded provenance or boot eligibility. Matching
headers and selected checksums are not a filesystem health certificate.

The Rust implementation is original code informed by format facts. Before importing third-party implementation code, review its license separately: the referenced ReFS projects use copyleft licenses, while the `ntfs` crate offers MIT/Apache-2.0 licensing.

## Conversion and recovery design

1. Read and inventory the clean source; identify blockers and estimate all space requirements. Produce a report before any mutation.
2. Allocate a staging file through the native NTFS driver, query its extents, then lock/dismount and revalidate the source. This lets NTFS reserve the space without implementing another NTFS allocator. [Allocation API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_allocation_info), [extent-query API](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers)
3. Build a complete target allocation and write plan. Reuse compatible data; materialize resident data; relocate only collisions with required target structures. Include metadata, relocation, padding, original-sector journal records, and journal overhead in bounds. Reject insufficient staging or journal capacity; no universal free-space percentage is promised.
4. Persist each overwritten source range's original bytes before the corresponding destructive write. Use explicit durable ordering and an external journal tied to source identity and the immutable plan. Recovery must be idempotent after interruption at every boundary.
5. Verify target bytes offline. Mark the irreversible handoff before exposing the target to a writable filesystem mount. The rescue environment must retain boot control until that handoff; absence of a drive letter alone does not prevent mounting.

Logical NTFS rollback restores source file data and semantics and removes the temporary reservation through NTFS. It does not promise byte-identical unused space. After native writes begin, source and target may diverge; the conversion journal must refuse to advertise rollback. A VM checkpoint is the post-handoff recovery mechanism.

## Preservation requirements

The target must preserve streams, hard-link relationships, exact security descriptors, timestamps, names, supported attributes, sparse ranges, and supported reparse/EA data. Raw metadata collection is not proof that a target writer can reproduce the behavior.

Microsoft's current feature matrix distinguishes support by feature and release: hard links, named streams, ACLs, EAs, sparse files, and pagefiles appear in the supported set, while public object IDs, short names, quotas, and transactions have limitations or no direct support. File-level encryption is version-specific. Interpret this matrix for the exact tested build. [Microsoft ReFS feature comparison](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview)

Compression/WOF/CompactOS, encryption, hibernated state, unknown reparse tags, short names with unresolved semantics, and other unimplemented preservation requirements are blockers. Do not silently convert compressed content merely because a decompressor is available. A clean boot-control fixture may be prepared separately to exclude blockers; that does not qualify arbitrary existing installations.

## Host baseline and current prerequisites

The inspected host is Windows 11 Pro 26H2 build 26300.9711 with 16 logical processors and 64 GiB RAM. D: is ReFS with approximately 261 GiB free at inspection. Hyper-V services and its PowerShell module are installed. Rust 1.98.1 and MSVC build tools are available; Rust's directory is absent from the inherited process PATH.

The completed Windows 11 media is `C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso`, 9,047,330,816 bytes. Its SHA-256 identity has been recorded, and image index 6 has been inspected as Windows 11 Pro build 10.0.26300.9457. The Codex process remains unelevated; the user-approved UAC helper can manage the provisioned Hyper-V lab. Native NTFS first boot, the independent baseline export, and checkpoint restoration have passed. See `format-gates.md` and `.lab/hyperv/win11/firstboot` for measured evidence. Server media acquisition is deferred at the user's request.

Use the lab harness to record current preflight results rather than relying on these point-in-time numbers. Keep existing host volumes and the existing VMware VM outside the test. Checkpoints revert attached disks, including journals; export artifacts before restoring them and retain an independent clean baseline. [Hyper-V checkpoint behavior](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints)
