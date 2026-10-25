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

On 2026-10-25, a controlled differential in the enrolled Windows 11 build
26300.9457 guest confirmed the mapping. With the global setting already at 2
(per-volume), the experiment changed only F:'s creation policy and used the
Rust `lab-ntfs-policy-probe` to hold a volume lock while parsing raw NTFS.

| Native creation policy | Raw flags | Exact 12-byte value |
| --- | --- | --- |
| Disabled before | `0x0080` | `000000000000000003018000` |
| Enabled | `0x0000` | `000000000000000003010000` |
| Disabled restored | `0x0080` | `000000000000000003018000` |

All captures were clean, passed backup boot/MFT-mirror checks and explicitly
released the lock. The four user streams retained their names, mappings and
complete logical hashes. No short names were stripped or global policy
changed. The original per-volume policy was restored, and the VM returned to
its saved recovered ReFS checkpoint afterward.

Evidence is under
`.lab/hyperv/ntfs-shortname-differential/win11-20261025T145523275Z`.
The exported result SHA-256 is
`d08565e8aaadfcedc8f00f9ef26a45304fcdc5671686313b6290d5e468705b2e`.
Each of the three raw observations read 99,409,920 bytes rather than hashing
the entire 52 GiB partition. This narrow experiment is not a full frozen-source
certificate.

The live general admission path now recognizes this policy only on native
build 26300, with a bound unchanged frozen-source observation, stable native
short-name-disable replies and no DOS-only aliases. Replay reports cannot
clear the gate. The new binding still needs a native live-admission run;
unknown bits and TxF/internal replacement remain separate refusals.

Sources:

- Linux NTFS `layout.h` volume flags:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/865730eec5435ce40a5dc3c615077d04c8f95098/fs/ntfs/layout.h>
- Libyal NTFS on-disk format, section 6.9.1:
  <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc>
