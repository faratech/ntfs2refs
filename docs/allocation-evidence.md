# Native allocation observations

`lab/guest/Capture-GuestAllocation.ps1` collects read-only observations from
explicitly selected unnamed file streams under the enrolled target's `fixtures`
directory. The target must be the existing 64 GiB disposable virtual data disk,
with one mounted NTFS/ReFS partition labeled `ntfs2refs-target`.

```powershell
& C:\ntfs2refs\guest\Capture-GuestAllocation.ps1 `
  -ManifestPath C:\ntfs2refs\target.json `
  -FixtureRelativePath @('empty.bin','nonresident.bin','sparse.bin') `
  -OutputPath C:\ntfs2refs\allocation.json
```

The report destination must be a different volume, with an existing ordinary
parent directory. It is created without overwriting any existing file. A host
orchestrator must separately authenticate the VM and validate VHD attachment
ownership; this guest collector does not replace those checks.

Each source file is opened for read access without write/delete sharing. Parent
directories are pinned and reparses refused. Two bounded
`FSCTL_GET_RETRIEVAL_POINTERS` observations bracket a SHA-256 logical-content
read. Native error codes, empty/nonresident distinctions, VCN ranges and LCN
sentinels remain explicit. Build, driver hash/version, disk identity, volume and
partition geometry accompany the observations. At most 32 files, 256 MiB logical
hash bytes, 4,096 extents per file and 8,192 retained extents overall are allowed.
The default cumulative hash budget is 64 MiB.

These are native API addresses, not verified raw offsets. The collector does
not query the retrieval-pointer base or perform offline payload matching;
`physicalMappingVerified`, `conversionQualified` and `bootQualified` remain
false. ReFS can expose file identity wider than the recorded 64-bit observation.
Two identical mapping responses do not establish crash consistency, and reads
on a mounted filesystem may update access metadata.

Microsoft documents retrieval pointers for nonresident ReFS/NTFS data and defines
the returned VCN/LCN ranges. A returned starting VCN can be rounded down; this
initial collector refuses unexpected boundaries rather than silently merging
ambiguous responses. LCN -1 is retained without independently interpreting
compression or sparse allocation. [Retrieval pointers](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers),
[response structure](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointers_buffer).

`lab/Test-GuestAllocation.ps1` passes 62 checks on malformed buffers, bounded
pagination, ambiguous/device paths, logical hash bounds, empty files, concurrent
writers, symlinks/junctions and create-new reports. Native calls use only isolated
ordinary test files; no VM or volume handles are opened. This validates the
collector, not any lab ReFS conversion capability.
