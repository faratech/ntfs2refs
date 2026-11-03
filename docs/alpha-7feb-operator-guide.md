# ntfs2refs — frozen 7feb experimental alpha

This is an experimental Windows x64 converter for backed-up data volumes. It is
not a stable or production release. It does not establish arbitrary-volume,
arbitrary-hardware or physical power-loss safety. The separate resource-cap
development branch is not part of this executable.

The executable reports version **0.1.0**. Preserve the exact binary below; a
rebuild or version-string change creates a different, unqualified executable.

## Before starting

- Have a complete independent backup of the selected source. Keep that backup
  read-only and outside the source disk. The conversion journal is recovery
  material for this operation, not a substitute for a backup.
- Use a dedicated, fixed GPT data disk with one basic data partition and, where
  present, the supported Microsoft Reserved partition. Boot/system volumes and
  the disk containing the running Windows installation are excluded. An ordinary
  data partition on that same Windows disk is also outside this alpha's
  whole-disk exclusion model.
- Run from an elevated Windows terminal on the machine that owns the disk.
  Close applications using the source. Hyper-V is not a runtime requirement.
- Keep adequate independent working space on the Windows OS volume. The program
  creates its native ReFS shadow and recovery files under
  C:\ProgramData\ntfs2refs\runs by default; the actual OS-volume path may differ.
  Scratch must remain independent of the selected source. Capacity admission can
  refuse a run; a nearly full source or fragmented layout is not guaranteed to fit.
- Review the selected disk, partition, filesystem, size and requested target type
  before answering the confirmation prompt. The qualified target is the default
  **Dev Drive ReFS 3.14 with 4 KiB clusters**. Standard ReFS formatting is not
  qualified by this release candidate; no automatic fallback is promised.
  A Dev Drive designation does not establish that Windows trusts the volume.

## Convert a drive

From the extracted package directory:

    .\ntfs2refs.exe --list
    .\ntfs2refs.exe --drive D --partition 2 --minimize-scratch

Use the actual drive letter and partition number reported by --list. The letter
D and partition 2 above are examples. Numeric disk selection requires an explicit
partition number, for example:

    .\ntfs2refs.exe --drive 3 --partition 2 --minimize-scratch

The confirmation defaults to No. Empty input or EOF cancels. Do not run two
conversions or recovery processes against the same disk.

The --minimize-scratch command above is the public path exercised by the exact
7feb qualification. It constructs a native ReFS shadow, retains eligible existing
payload extents, relocates conflicting allocations and journals the admitted
changes before cutover. It does not simply reformat the source, and it does not
promise that every payload extent remains in place.

Fast verification uses complete metadata and physical-extent identity for
eligible retained data, and verifies moved/materialized bytes through their
defined checks. It does not repeatedly hash every retained payload. The
laboratory's independent full-content comparisons are separate qualification
evidence. --verify-full-content requests the stronger full-content policy, with
additional reads; use it instead of --minimize-scratch, since the options conflict. Other modes can have tighter limits and are not qualified by
the particular fast-path result below.

Keep the terminal output, printed recovery directory and original recovery
checksum. Preserve the entire run directory, including its journal, backing,
page manifests and shadow file when present.

## If conversion is interrupted

Keep the source excluded and retain the original recovery material. Use the
printed directory and its original checksum, not an example laboratory bundle:

    .\ntfs2refs.exe --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion --recovery-sha256 ORIGINAL_CHECKSUM

For rollback, when the journal lifecycle still permits it:

    .\ntfs2refs.exe --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion --recovery-sha256 ORIGINAL_CHECKSUM --rollback

The program checks the actual journal, original inputs, device identity and
lifecycle. A saved JSON claim does not authorize replay. Do not substitute another
bundle, delete working files, force disk attributes online or retry concurrently
to bypass a refusal.

Rollback ends at ReFS handoff. An old NTFS journal must not be replayed over an
operational ReFS filesystem. Keep the independent backup available after handoff.

## Exact observed scope

The normal public run used Windows 11 build **26300**, a 64 GiB virtual disk
with a **52 GiB nonboot NTFS 3.1 data partition**, **64 KiB source clusters**,
512-byte logical sectors, 4 KiB physical sectors and 1 KiB MFT records. The target
was native ReFS 3.14 with 4 KiB clusters.

The independently populated source contained **811 files and 723 directories
(1,534 user objects)**, with 1,561 canonical raw identities including NTFS
internals. Native conversion completed in 129.4563482 seconds, and the independent
observer matched all 811 stream hashes. This is one VM observation, not a speed
estimate for another disk or evidence of physical-device throughput.

Journal plus literal backing used 211,314,480 bytes in that normal case. This
number excludes total shadow allocation and other working/evidence files; it is
not a universal scratch-space requirement.

The same frozen binary subsequently passed controlled first-flushed-write
interruption and separate public Resume and Rollback from the preserved original
interrupted state, with independent comparisons of all 811 streams and the
1,534-object tree. This establishes those recorded process-interruption paths,
not arbitrary crash points or physical power-loss qualification.

The exact 7feb build also passed the mutation workload and a later cold boot.
All 811 original streams and 1,534 original namespace/type/length objects
matched; 258 new files and 256 directory entries were checked. ACL, SACL and
timestamp byte-for-byte checks and physical cluster reuse were not established
by that particular post-boot observation.

## Limits and compatibility

The alpha still has enforced limits. They include **2,048 canonical raw
identities**, counting NTFS internal records; a 1,000,000-record MFT domain,
including unused slots; 16,384 DATA-stream slots; 34,056 projected owning handles;
a 16 MiB expected-tree semantic budget; and separate 64 MiB
inspection/report/map budgets. Fragmentation, namespace, stream, path, placement
and recovery constraints can refuse a source before any one count is reached.
The admitted user-object count is smaller than the raw identity count.

Supported source forms are determined by complete admission, not by drive
selection. The repository has separate bounded results for ADS, sparse files,
hard links, extended attributes, supported Microsoft reparse points, LZNT1
compression materialization and complex security descriptors. Many of those
feature results use earlier binaries; this package does not claim maximum NTFS
compatibility or exact-7feb qualification of every combination.

EFS/encrypted source semantics, unsupported reparse/attribute forms, boot/system
conversion and unqualified storage layouts remain refused or outside scope.
Other Windows builds, sector/cluster configurations, larger file trees, larger
volumes and different storage hardware need separate qualification. No claim of
10 MiB-to-1,000 TB support is made for this frozen alpha.

## Binary identity

- Source commit: 7feb4c06d21e9de73bb88961197f5b745463e490
- Public executable: ntfs2refs.exe, 11,580,928 bytes
- Executable SHA-256:
  c7b5809f4456f55e71f19b47d4e4cb9b7ee6cad86c4ff0fac36c1db5a5b909d1
- Clean build manifest SHA-256:
  d4afec214f672fe4eb3b12c5e82a5315ccbee25f92f9222ef426605948f54814

Check the packaged executable before use:

    Get-FileHash -LiteralPath .\ntfs2refs.exe -Algorithm SHA256

The clean build is pinned; independently reproducible output was not established.
The package must identify itself as an experimental prerelease and include its
own file manifest and archive checksum.
