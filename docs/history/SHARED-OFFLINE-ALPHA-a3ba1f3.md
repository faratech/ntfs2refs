# ntfs2refs — shared-disk experimental alpha

**Experimental alpha. This exact build completed same-partition conversion, mutation/reboot, interrupted resume and independent interrupted rollback on the finite profile below. Package manifests identify the shipped bytes and supporting resource records.**

This Rust utility converts a supported NTFS data partition to ReFS on the same partition. Eligible file-data extents stay at their physical locations. New filesystem metadata and any necessary rewritten data are protected by an independent recovery journal.

The converter runs on the Windows machine that owns the disk. It prepares the conversion in Windows, boots its recovery environment, performs the offline conversion, restores normal boot and the original volume label and mount paths, and returns to Windows. Hyper-V was used for qualification; it is not part of the conversion mechanism.

## Build and qualification

The candidate is Cargo package version `0.1.0`, source commit `a3ba1f30b2428fcfb7975220d7b400b3c4c54be9`. Later evidence-only commits do not change these binaries.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `ntfs2refs.exe` | 20,783,616 | `160f64460edb4857837063c64508d0381ef8f571535f5ad8984fa429dd660379` |
| `ntfs2refs-recovery.exe` | 4,594,176 | `6246764f06d4312b46d64f0b291505b73682fcd5a5eb71ecff61b946041efca3` |

The exact candidate has completed these native cases:

| Case | Observed result |
| --- | --- |
| Public conversion | One command prepared the independently populated tree, booted recovery, converted the same partition and returned automatically to Windows. Native metadata and retained mappings passed; all eight files and four directories matched the source checks. |
| Mutation and reboot | A native 513-file mutation workload completed. After an ordinary reboot, all 513 entries persisted and the original eight source files still matched. |
| Interrupted resume | After positive flushed writes before the discovery-sector switch, the VM was turned off once and started unchanged. The original sealed runner acquired fresh restart protection, accepted `R`, resumed and returned automatically to Windows. All eight original files passed again. |
| Interrupted rollback | A separate conversion was interrupted after flushed writes, then started unchanged. The original sealed runner accepted `B`, restored NTFS and returned automatically to Windows. All eight files, original NTFS file identities and volume serial, original 512-byte boot sector, owner/group/DACL and partition layout matched the independent source record. |
| Resources | Upfront RAM/scratch admissions were recorded for normal conversion, resume and rollback. The package records aggregate reservation limits and separately named staging/image limits; it does not claim an unmeasured physical scratch peak. |

These are finite observations against the profile below. The interruption case used a Hyper-V hard stop; physical storage power-loss behavior at every write boundary is not qualified.

Earlier builds demonstrated the same-partition mechanism and native ReFS use. A recovery case also combined an earlier writer with this updated helper. Those records are preserved as diagnostic history; they are not inherited qualification for this candidate. The successful cases above belong to this exact build. The package qualification and supporting records identify each independent case and its resource evidence.

## Demonstrated profile

This is a finite experimental profile, not maximum NTFS compatibility or a stable general release:

- Windows 11 x64 build 26300 on the owning machine, with its Windows installation ISO available locally.
- A GPT disk containing Windows and a separate nonboot, nonsystem NTFS data partition. The laboratory data partition is disk 0, partition 6, mounted as `D:`, 52 GiB, with 512-byte logical and 4096-byte physical sectors.
- NTFS 4096-byte clusters, 1024-byte MFT records, 4096-byte index buffers, and disabled short-name creation; a 4096-byte-cluster native ReFS target using the Windows Dev Drive target-format profile.
- Ordinary files and directories, including empty/small and nonresident files and Unicode names. The demonstrated security scope is owner, group and DACL; no SACL qualification is claimed.
- An independent NTFS recovery disk. The laboratory recovery volume is `J:` on another physical disk. Recovery material must remain available through conversion and recovery.

The laboratory used a 4 GiB, four-CPU VM. Its partition size and eight-file tree describe the demonstrated case; they do not establish behavior on every size, geometry, Windows release or NTFS feature combination. The program's source admission and resource checks still apply.

Windows boot-volume conversion is deferred. This alpha does not claim qualified preservation of compression, EFS, alternate streams, sparse files, reparse points, hard links, quotas, deduplication or other untested combinations. Inspection support does not establish conversion support. Do not bypass a refusal for unsupported source semantics.

## Convert a data partition

Keep both executables in the same directory and open an elevated Windows terminal there. Mount the Windows installation ISO; the example below assumes its media is `E:`. The package does not distribute Microsoft's WIM, SDI, drivers or DLLs; image creation uses the owning Windows installation and the supplied media.

List drives and partitions, then select the intended nonboot data volume. Create an existing directory on the independent NTFS recovery disk for this run:

```powershell
.\ntfs2refs.exe --list
New-Item -ItemType Directory -Path J:\n2r-recovery
.\ntfs2refs.exe --drive D --scratch-directory J:\n2r-recovery --offline-media E:\
```

Use the actual drive letters on your machine. The program prints the selected disk/partition and its resource plan, then asks for one confirmation. Confirming authorizes the owning-machine preparation, recovery boot and conversion workflow. The program creates its own fresh run directory beneath the scratch directory.

Keep the recovery disk connected. The normal workflow returns to Windows with the selected partition formatted as ReFS and its original label and drive letter restored. A successful preparation or boot-installation message alone is not conversion completion; the native conversion and terminal finalization must also succeed.

## Resource use and verification

The resource plan reports RAM, shadow staging, preparation scratch and recovery-image working space before confirmation. These are admitted budgets, not promises that every byte will be consumed. Resource checks remain active throughout the workflow.

The successful public case reported a 1,942,831,104-byte RAM admission and 4,747,978,585 bytes of required recovery-space headroom before starting. The independent resume and rollback cases admitted 1,828,327,424 and 1,876,844,544 RAM bytes respectively.

Source-metadata scratch limits were 171,718,656 bytes for normal conversion, 180,036,608 for resume and 169,916,416 for rollback. Each is a sublimit within that case's aggregate arena, not extra storage to add again. Journal and other artifact reservations share their aggregate accounting. Native shadow backing and recovery-image construction have separate named limits outside that arena; recovery-image checks verify post-command growth and the required free-space floor.

The recorded normal Windows-process peak working set was 144,375,808 bytes. This measures one process; aggregate Windows, kernel and cold recovery-environment peaks were not measured. Scratch reservations and named phase limits establish the recorded accounting bounds; a continuous physical scratch high-water measurement was not captured. The package keeps these unknown peaks null and identifies the scope of its observations. These accounting controls are not an operating-system memory quota or a continuous disk-allocation quota for external Windows tools.

Default verification uses metadata and physical-extent identity for retained data rather than repeatedly hashing all retained payload. Relocated or materialized data and recovery artifacts remain subject to their required integrity checks. Independent qualification hashes the small test tree separately.

Requirements depend on the filesystem metadata, allocation and collisions, rewritten data, available resources and media. These measurements are not a capacity or timing estimate for a full multi-terabyte drive. Keep the run directory and its recovery artifacts until the completed result has been checked.

## Recovery after interruption

Both independent native interruption cases passed on this exact build. Each used its own prepared source, saved journal and sealed recovery image. After each actual interruption, the source and recovery artifacts were preserved; the machine started unchanged and the original runner performed the selected recovery.

Leave the original recovery disk and saved run files intact, then start the owning machine normally. The persistent recovery boot entry is intended to enter the prepared recovery environment while the conversion is incomplete. That environment authenticates the saved artifacts and the actual selected disk and journal again.

When it detects an interrupted conversion, it prompts for a recovery direction:

- Enter `R` and press Enter to resume conversion to ReFS.
- Enter `B` and press Enter to restore the saved NTFS state.

Recovery uses the original source partition and saved journal. It does not require a VM snapshot, reformatting, a new preparation, manual boot rearming, or editing a sealed request. Keep the original artifacts; if identity or integrity checks refuse recovery, preserve the displayed error and run directory rather than creating a replacement run.

NTFS rollback closes at the committed ReFS handoff. After ordinary writable ReFS use begins, the old journal cannot be used to undo later filesystem changes. A completed ReFS volume is not a candidate for replaying an earlier NTFS rollback.

Both finite fault cases interrupted after flushed non-discovery writes and before the discovery-sector switch. Fresh recovery-boot protection was observed before selecting `R` or `B`. These controlled Hyper-V hard stops do not establish arbitrary physical power-loss behavior at every possible write boundary.

## Package contents and evidence

The package contains the exact two executables above, hash/provenance manifests, a committed-source archive, this README and the finite observational qualification evidence. Check its archive receipt and file manifest for exact lengths and hashes. Microsoft binaries and installation media are supplied locally by the machine owner.

The previously qualified separate-disk experimental alpha and its evidence are preserved separately. This shared-disk package does not replace their historical records or treat them as qualification for this candidate.
