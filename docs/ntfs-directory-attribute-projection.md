# NTFS directory attributes in the native-shadow model

The first full baseline attempt for the 1,534-object source stopped at MFT record
1120 with `unsupported attributes or missing standard information`. The capture
exited 1 before any conversion, certificate or journal creation. Its failed
outputs remain under the closed `a6c0728f0fc741e0a403d9be992956be` lab archive.

A separate read-only frozen-record probe found that records 1120 and 1121 are the
new empty `n2r-paged-450/d0000` and `d0001` directories. Each has an MFT directory
flag, SI attributes `0x10000000`, no DATA streams and one resident `$I30` root with
48-byte logical/initialized/allocated lengths. Root record 5 uses the older
observed SI value `0x00000006` instead. The probe opened the already excluded
source, requested fast metadata inspection, read 109,121,536 bytes and hashed
94,863,957 required stream bytes. It requested no full payload scan, native
content observation, freeze or source writes. Its output is diagnostic, not an
admission certificate.

NTFS's raw directory marker differs from the Win32 directory attribute. The
primary Linux NTFS driver defines the disk marker as `0x10000000`; Microsoft's
Win32 attribute contract uses `0x10`. These constants corroborate the observed
form; no filesystem implementation code was copied.
([NTFS driver definitions](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h),
[Microsoft file attributes](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants))

Previously, source observation stripped the SI high nibble and added the Win32
directory bit, while source admission and tree construction rejected/copied raw
SI flags. The shared `ntfs_file_attributes` projection closes that disagreement:

- Accept the known disk marker only on a complete MFT directory with one coherent
  resident `$I30` root. Existing raw namespace and native type checks still apply.
- Remove that marker from the existing source-policy bits and emit the Win32
  directory bit for the target. Preserve older directories without the marker.
- Reject other high user flags. Keep the existing low-bit, Normal, compression,
  EA, sparse and reparse policies. Recognized filesystem-internal observation
  retains its separate existing treatment.

The focused four-binary check passed; no unit tests were added or run. The
corrected 1,534-object baseline and subsequent native conversion/recovery runs
remain pending. The earlier 1,084-object result does not qualify this fix.
