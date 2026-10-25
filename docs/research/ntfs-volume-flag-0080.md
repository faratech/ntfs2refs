# NTFS `$VOLUME_INFORMATION` flag `0x0080`

The frozen Windows 11 lab NTFS images are clean according to the native dirty
query and the on-disk dirty bit, but their `$VOLUME_INFORMATION` flags equal
`0x0080`. This is not the `$DATA` attribute type number or a Windows volume
capability flag; it is the 16-bit value at byte offset 10 of the resident
`$VOLUME_INFORMATION` value in MFT record 3.

Primary open-source NTFS implementations do not establish a reliable meaning
for this bit. The Linux NTFS driver enumerates its recognized volume-state
bits through `0x0020` plus the chkdsk bits and excludes `0x0080` from its
known mask. Libyal's byte-level NTFS format notes list `0x0080` as unknown.
An older secondary source associates it with disabled short-name generation,
which is consistent with the lab's native 8dot3 setting, but correlation does
not prove the bit has no other conversion consequence.

The admission gate therefore continues to refuse `0x0080`. A future change
should be based on a controlled Windows experiment that toggles only the
relevant per-volume policy, captures the before/after `$VOLUME_INFORMATION`
bytes, and compares native short-name behavior on the same build. The source
namespace also must have no DOS-only aliases to preserve.

Sources:

- Linux NTFS `layout.h` volume flags:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/865730eec5435ce40a5dc3c615077d04c8f95098/fs/ntfs/layout.h>
- Libyal NTFS on-disk format, section 6.9.1:
  <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc>
