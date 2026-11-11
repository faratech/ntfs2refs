# Frozen Windows drive alpha — 2026-10-29

This package contains the exact experimental Windows x64 executable that passed
same-partition conversion, ordinary file mutation and reboot verification.
Run it on the Windows machine owning the disk; Hyper-V is laboratory infrastructure.
Use disposable or backed-up data volumes. Boot/system volumes remain excluded.

From an elevated PowerShell terminal in the extracted folder:

```powershell
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive D
.\ntfs2refs.exe --drive D --partition 2
.\ntfs2refs.exe --drive 3 --partition 2
```

Select the disk/partition shown by `--list`. The drive command displays its
identity and asks for confirmation, defaulting to No. It prepares its own native
ReFS staging and independent recovery storage. Unsupported layouts, features or
resource requirements refuse; drive selection does not bypass admission.

Keep the printed recovery directory and original checksum with the complete
run directory and its backing files:

```powershell
.\ntfs2refs.exe --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion --recovery-sha256 ORIGINAL_CHECKSUM
.\ntfs2refs.exe --recover C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion --recovery-sha256 ORIGINAL_CHECKSUM --rollback
```

Rollback closes at ReFS handoff. An old journal cannot be replayed over an
operational filesystem. Preserve recovery material after an interruption; do not
substitute another bundle or force storage attributes to bypass a refusal.

## Exact candidate and evidence

- Executable SHA-256: `fb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c`.
- Source checkpoint: `2ff5f017c03977c5e6ba9d31ba64dc634bfa2fe7`.
- The build included the existing uncommitted capabilities edit in `src/main.rs`.
  A packaging-time snapshot is included under `provenance/packaging-main.rs`.
  This does not attest a clean historical tree or a reproducible build.
- Actual `--drive F --partition 2`, affirmative stdin and automatic staging:
  native and wrapper exit 0; 152 patches / 70,631,424 bytes; HND; native
  15 objects / 10 complete hashes; source label and F: preserved.
- Independent strict verification before and after a 50→80→10 MiB workload,
  rename/delete and 128 directory entries passed. All temporary paths were removed.
- A clean stop/start of that same working branch, without checkpoint restore,
  passed strict native 15-object / 10-hash verification again.

The fixture was a 52 GiB, 512-byte-sector, 64 KiB-cluster NTFS data partition;
the target used ReFS 3.14 / 4 KiB clusters on Windows 11 build 26300.9457.
The observed conversion took about 55m52s with a monitored peak working set near
68.2 MiB. It still read almost 1 TB across full-volume passes. Most logical bytes
were in a zero-filled file; these results do not establish payload-independent
scratch for arbitrary nonzero data.

Public resume/finalize on this exact candidate passed after its controlled
one-write interruption and reboot: native/task0, exact target hash, HND, native
15 objects/10 complete hashes, and preserved label/mount. Its recovered branch
was saved separately. See the [resume receipt](../evidence/optimized-drive-alpha-resume-20261029.json).
Independent public rollback on this candidate also passed from the saved
interrupted state: native/task0, exact frozen NTFS image restored before mount,
ABT, NTFS64K, original label/F preserved. No post-mount file hashes are claimed.
See the [rollback receipt](../evidence/optimized-drive-alpha-rollback-20261029.json).
These results apply to one controlled one-write interruption; other failure
points and physical power loss remain unqualified.
The same-source controlled converter subsequently reached its intended exit86
after one flushed write, published its original native recovery bundle, and
preserved the interrupted branch. That branch booted with its source still
offline; public resume then passed as recorded above. See the
[interruption receipt](../evidence/optimized-drive-alpha-interruption-20261029.json).

Other sizes, Windows builds and features need their own qualification.
Arbitrary-size conversion, boot conversion and physical power-loss recovery
are not established. ADS, hard links, reparse points, compression, encryption
and other unsupported source semantics remain refused by the current profile.
Later allocation-map diagnostics in the repository are outside this frozen binary.
