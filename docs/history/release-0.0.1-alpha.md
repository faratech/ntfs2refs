# 0.0.1-alpha: release and qualification

The private [0.0.1-alpha release](https://github.com/faratech/ntfs2refs/releases/tag/0.0.1-alpha)
contains the Windows boot-volume converter qualified by the recorded full-16
run. The source tag resolves to `3aaaf11bb4e5a4891942feeabc974d4188916e98`.
The executable reports `0.1.0`; that existing version string is disclosed rather
than changing the qualified executable during release closeout.

## Frozen artifacts

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 ZIP | `4966456f4c0bac93095cd6112a0eb5f06262842b3965ae6c7e86845cf17d713e` |
| Source ZIP | `25bca3be312f3235334c5803cc6453236cddaa31cc8f537f02b33112409d72ca` |
| `ntfs2refs.exe` | `e057c9e69554977167f47665c2a56425d0b77ab6f3a317f9174ed348af214492` |
| `lab-volume-manifest.exe` | `61b509b7b71aa9fc9d99cb15464ac1a3c0ceef2af8e89992037b78562b3bce92` |
| Recovered qualification ZIP | `6d7819d61cb0bfaa5b0cffbc73c137d876f31cc83bde811c3bc0eca29b9ab720` |

The ZIPs and both executable hashes were independently checked during closeout.
The original source and binary assets and tag are preserved unchanged. The
[qualification bundle](https://github.com/faratech/ntfs2refs/releases/download/0.0.1-alpha/ntfs2refs-0.0.1-alpha-qualification.zip)
is an additional asset, not a replacement package.

The frozen source ZIP retains the documentation that existed at its tag. Use
the current operating guide linked here for the corrected release instructions.
Documentation corrections do not rewrite the original archive.

## Original full-16 observation

The source was an existing Windows 11 build 26300 installation on a 64 GiB disk,
using disk0 partition 3. Release notes identify 22.9 GB used and 143,580 source
objects. The lab used a Hyper-V generation 2 VM with 24 GB RAM and eight vCPUs.

The retained original command launched the converter through the one-command
harness, using the independently copied binaries under `.lab/hyperv/bin/final`.
The recovered output establishes:

- Converter exit 0 in 1,680.1796823 seconds (28.0 minutes).
- A healthy ReFS 3.14 source partition after conversion; no ReFS warnings or
  errors were reported by the harness's driver-log check.
- Independent listings with 191,101 rows before and 303,710 rows after;
  zero unexpected differences and no unreadable objects in the after-listing.
- 112,609 additional short-name links, explaining the row-count difference.
- Boot with only original disk0 attached and Secure Boot enabled; C: uses
  partition 3, ReFS 3.14, 4 KiB clusters, and is healthy.
- Valid signatures on `winload.efi` and `refs.sys`, followed by desktop sign-in
  as the lab account. The harness reported `BOOTED-ON-REFS`.

The listing tool is independent of the converter's verifier. It enumerates
through Windows, hashes logical streams, and compares reported security,
timestamps, names, link relationships, reparse data and supported EAs.
"Identical" means zero unexpected differences under its explicit comparison
rules, not a byte-identical filesystem or preservation of every NTFS encoding.

| Recorded normalization | Count |
| --- | ---: |
| Short names represented as links | 112,609 |
| NTFS compression flag removed | 218 |
| System Volume Information content | 8 |
| Kernel cache attributes dropped | 17,140 |

These rules were not widened during closeout. The source listing can contain
multiple names for one file, so its row count differs from the converter's
object count.

## Evidence provenance and limits

The original `.lab/hyperv/attempts/full-16` directory was unavailable during
closeout. Original command results were recovered from retained local session
`954366ca-7256-4d96-a061-ffdbe10fea23`, with source-line numbers, timestamps,
content hashes and the session-file hash. The original retained task output is
included unchanged. No conversion was rerun to manufacture these records.

The bundle does **not** reconstruct the missing full before/after JSONL files,
`verdict.json`, raw trust-patch records or desktop screenshot. It preserves the
actual original console observations and states their limits.

The original workspace test log and exit file were also recovered unchanged.
Their result lines total **713 passed, zero failed, 52 ignored**. Ignored tests
were not executed and are not claimed as coverage.

The separate `rec-04` output records recovery exit 0 and healthy ReFS after a
saved after-apply state. It explicitly reports `converted-not-compared` because
there was no before-listing. This is evidence for post-apply finalization, not
an independently verified full-content recovery, arbitrary write interruption,
physical power-loss tolerance or a Windows boot-volume rollback matrix.

## Operating scope

Use the [operating guide](cli-workflow.md). The demonstrated path runs from a
separate Windows installation, with the source not in use, and creates a ReFS
Dev Drive shadow. It used about 30 GB of independent working storage for the
recorded source. The final boot uses the original disk alone.

Physical hardware, different Windows builds, BitLocker, other partition layouts,
all NTFS feature combinations and arbitrary volume sizes are not qualified by
this run. Short-name links remain visible. Preparation after a power cut is
started again; it is not a universally resumable transaction.

## Maintaining this release

The published executable remains the reference artifact. Subsequent formatting,
documentation and integration commits do not replace its hashes or imply new
native qualification. Code changes that alter conversion, apply or finalization
need the checks described in [AGENTS.md](../AGENTS.md). Hosted CI checks building
and ordinary tests; it does not exercise Hyper-V, source-disk writes or boot.
