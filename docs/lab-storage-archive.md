# Local lab storage archive (2026-10-25)

The Windows 11 lab remains in `D:\code\ntfs2refs\.lab\hyperv`. To preserve
the host's free-space reserve, two inactive artifacts were moved intact to
`C:\Users\mfara\ntfs2refs-archive`:

| Artifact | Archived location | Verification |
| --- | --- | --- |
| Installed-clean VM export | `C:\Users\mfara\ntfs2refs-archive\exports\win11-installed-clean` | All six files matched their pre-move lengths and SHA-256 hashes. |
| Windows-generated 52 GiB ReFS raw corpus | `C:\Users\mfara\ntfs2refs-archive\corpus\devdrive-20261023T231918797Z\devdrive.raw` | SHA-256 `805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9` matched the recorded corpus digest. |

Relocation manifests remain at the original paths under `.lab/hyperv`. The
export can be restored to its original folder before using historical
baseline-completion records. Read-only ReFS corpus tests can instead set
`N2R_NATIVE_REFS_CORPUS` to the archived corpus directory. The original
`target-fixed.vhd` stays in the lab corpus.

After the moves, `Get-LabCapacity` reported 151,964,072,580 actual lab bytes
and 121,345,216,512 free bytes on D:. `Assert-LabCapacity` passed with a
1 GiB additional-byte allowance. Hyper-V management permission is still
required to resume native VM work.
