# ntfs2refs: aef experimental candidate

This package contains the unchanged `aef1ab3` executable. Its Cargo/CLI version
is **0.1.0**. It is an experimental, finite-profile candidate, not a stable
release or completion of the broader compatibility and performance project.

Use recoverable test data and an independent backup. Conversion and recovery
run on the Windows machine owning the disk; Hyper-V is test infrastructure.

## Observed profile

The qualification concerns a dedicated, nonboot basic GPT data disk in the
Windows 11 lab: a 52 GiB partition, NTFS with 64 KiB clusters, 512-byte logical
and 4 KiB physical sectors, and a ReFS 3.14 Dev Drive target with 4 KiB clusters.
The fixture contains 811 streams and 9,885,801,949 logical bytes. Consult the
included `qualification.json` and pinned case receipts for exact scope.

Boot/system conversion and a data partition sharing the running Windows disk
are unsupported. Unknown NTFS features and unsupported geometry are refused.
Larger private formatting/addressability experiments do not qualify large-volume
conversion. Physical power loss, arbitrary hardware and maximum NTFS
compatibility are outside this candidate's claims.

The default staging backend is VHDX. The separately qualified thin backend is
an explicit experimental option; its nominal pool capacity is not physical
storage capacity. Do not infer a general 1,000 TB conversion capability.

## Select and convert

Open an elevated PowerShell on the owning Windows machine. Native ReFS/Dev Drive
formatting and the Windows Storage tooling must be available.

```powershell
.\ntfs2refs.exe --version
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive D --partition 2 --minimize-scratch
```

Replace the drive and partition with the exact entry shown by `--list`. A drive
letter must identify the selected partition. The equivalent selection syntax is
`--drive D partition 2`. The program shows the selection and asks for confirmation
before conversion. Read the admission/refusal message; a refusal grants no
permission to force the operation.

Eligible payload extents remain in place. Metadata, relocation, rewritten data
and recovery artifacts still need storage. Capacity depends on their actual
allocation and the source features, rather than a fixed free-space percentage.
Keep the printed recovery directory and SHA-256, and preserve all recovery files.
The default working location is on the Windows OS volume.

`--minimize-scratch` uses allocation-based recovery: unused NTFS free-space bytes
may change after rollback. Volumes with VSS snapshots or hosted diff areas are
refused in this mode. Extent-based fast verification is the default; retained
data is proved through exact identity/mapping and moved or rewritten data is
checksummed during I/O.

For a full logical-content scan, use `--verify-full-content` without
`--minimize-scratch`:

```powershell
.\ntfs2refs.exe --drive D --partition 2 --verify-full-content
```

Logical stream digests use XXH3-128. Recovery and metadata integrity pins use
SHA-256. Full scanning adds reads; this command's availability does not extend
the finite qualification profile.

The explicit thin qualification command was:

```powershell
.\ntfs2refs.exe --drive D --partition 2 --minimize-scratch --experimental-thin-shadow --experimental-thin-backing-bytes 11811160064
```

That bound belongs to the observed case. It is not a universal scratch estimate.
Actual admission checks remain mandatory.

## Recover an interrupted operation

Use the **original directory and checksum printed by that same operation**.
Preserve its files and source-device identity; do not substitute another run's
paths, hashes or journal.

```powershell
.\ntfs2refs.exe --recover "C:\ProgramData\ntfs2refs\runs\<original-run>\conversion" --recovery-sha256 "<original-printed-sha256>"
.\ntfs2refs.exe --recover "C:\ProgramData\ntfs2refs\runs\<original-run>\conversion" --recovery-sha256 "<original-printed-sha256>" --rollback
```

The first command requests resume; the second requests rollback or preparation
cancellation before handoff. Run one direction for the admitted state.
HND and ABT terminal states permanently close the old raw replay path. After
successful handoff, the saved conversion journal cannot undo ordinary ReFS changes;
terminal reconciliation must preserve current contents.

The package's controlled interruption used an owned native-thread pause and
one Hyper-V TurnOff, followed by independent journal authentication. It does
not establish physical power-loss safety or every write/flush failure mode.

## Package provenance

The ZIP ships only the public executable, this README, the external finite
qualification, small pinned case receipts and source/build provenance. It ships
no laboratory executables, disk images, journals or credentials. The source
archive is provenance, not an additional executed tool.

The packager refuses incomplete qualification. Its required default-normal and
public-low-space gates must be completed before a package is created; an
unexecuted draft or a successful build does not satisfy those gates. No tag,
publication or stable-release approval is implied by local packaging.
