# Read-only conversion-request discovery

`ntfs2refs-bind` discovers the mounted source, prepared shadow and external
journal volumes through Rust Win32 queries. It creates the device-bound
request consumed by `ntfs2refs convert --request`; GPT identifiers and sector
bounds do not need to be entered manually.

```powershell
ntfs2refs-bind --source F:\ --shadow R:\ --journal J:\ `
  --experiment-id 0123456789abcdef0123456789abcdef `
  --output C:\ntfs2refs\devices.json --evidence C:\ntfs2refs\devices.evidence.json
```

Use a fresh experiment identifier and fresh output files. Their parent
directories must already exist on the Windows OS volume without reparse-point
ancestry. The shadow must already be a separately prepared ReFS volume labeled
`n2r-retained-shadow`; this command does not format or clear it. The source and
shadow must use the current 512-byte logical-sector/4 KiB-cluster profile.

Arguments must be exact local volume roots: a drive root, volume-GUID root or
mounted-folder root. Ordinary subdirectories, relative/UNC/device paths,
ambiguous components and alternate streams are rejected. Windows resolves the
roots using [GetVolumePathName](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew)
and [GetVolumeNameForVolumeMountPoint](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumenameforvolumemountpointw).

Discovery requires a single complete volume extent and an unambiguous GPT
basic-data partition. It records native device number, disk length, storage
alignment, partition identities, attributes and filesystem geometry, then
repeats the observations before returning. Source and shadow exclude the
current Windows OS disk and require the dedicated data-disk layout. Journal
storage on a disk with other partitions, including the OS disk, requires
`--journal-additional-partitions`. That flag applies only to journal storage;
it cannot make an OS source or shadow valid.

The journal's informational enrollment label defaults to `gpt-<disk-guid>`.
It is explicitly a derived label, not an observation of
`MSFT_Disk.UniqueId`. `--journal-enrollment-label` accepts an independently
recorded label. Native execution still verifies GPT, volume, disk and journal
file identities; that string alone has no authority.

The generated JSON is at most 16 KiB and its SHA-256 is printed for the
conversion command. `--evidence` saves the bounded read-only observations.
Discovery uses no locks, dismounts, disk-attribute setters or payload writes.
It does not admit the source, assert that the shadow is empty, or calculate
final capacity requirements; the live conversion workflow performs those
checks again.
