# Native journal file identity observer

`n2r_win32::journal_file::observe_journal_file(&File, &JournalStorageBinding)`
observes an already open ordinary journal file and returns a serializable
`JournalFileSnapshot`. It performs no creation, content read/write, disk-attribute
change, locking, privilege change, or formatting. Native execution has not yet
been measured; the tests use synthetic buffers and SDK type-layout assertions.

The caller must open the journal on the enrolled J: volume with Windows sharing
mode zero, keep that handle open, and exclude concurrent activity through its own
handles. The API cannot query the sharing mode. The caller must separately verify
the external `MSFT_Disk.UniqueId` enrollment; the snapshot explicitly reports both
`sharing_mode_verified` and `external_unique_id_verified` as false.

The fixed profile is disk route 2, 8 GiB, GPT partition 2 at 16 MiB with length
8 GiB minus 32 MiB, 512-byte logical and 4096-byte physical sectors. Volume, disk
and partition GUIDs come from independently enrolled platform evidence. The
volume GUID input is the GUID alone, optionally enclosed in braces. The actual
partition number must match the platform's returned number; this observer will
refuse a different layout rather than infer a replacement profile.

The file handle supplies its normalized volume-GUID path, 128-bit file ID,
64-bit volume serial, standard information and attribute tag information. The
observer rejects alternate streams, multiple links, deleting files, directories,
reparse points, sparse, compressed and encrypted files. Empty preparation files
are accepted; EOF is bounded at 768 MiB. Allocation is separately bounded and is
not required to have cluster alignment, because resident files can report smaller
allocation units. The final path is bounded at fewer than 4096 UTF-16 units.

The resolved volume is opened for read access, then its single physical extent
is checked against the enrolled partition. Read-only physical-disk queries bind
the route to device number, disk size, alignment and the complete GPT layout.
Only the journal partition and optional preceding MSR are accepted. Queries have
fixed capacities; at most 128 GPT entries and 64 KiB of layout output are accepted.
File and storage observations are repeated on the held handles and must agree.
An error returns no successful snapshot and performs no recovery mutation.

`snapshot.identity` is the ticket's stable serializable subset: file ID, volume
serial, canonical GUID bytes and geometry. It excludes path, disk route, length,
allocation, timestamps and external enrollment claims, so journal preparation
does not change it. File identity does not prove content, durability, exclusivity,
or filesystem conversion. The journal's independent immutable-byte hash and
durable ticket remain necessary. `conversion_qualified` is always false.

ABI sources: Microsoft's [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info),
[FILE_STANDARD_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info),
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
and [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew),
cross-checked against SDK 10.0.26100.0. Fixed aligned byte buffers avoid constructing
Rust `bool` values directly from native `BOOLEAN` bytes.

`observe_ordinary_file_handle(&File)` reuses the bounded file-information and final
path observations without opening a disk or volume. It supports the separate lab
CLI's C: request, ticket, intent and result files: multiple links are refused and
volume serial plus the full 128-bit file ID detect aliases. This helper supplies
no storage enrollment or durability claim. Both observations must agree; the
caller still chooses and holds the file's sharing mode.
