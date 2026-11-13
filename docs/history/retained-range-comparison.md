# Read-only comparison with retained source ranges

`compare-retained` measures the byte changes for a proposed reconstruction.
It does not convert a filesystem, emit patch payloads, open live devices or
authorize writes. The input files are frozen raw partition images with equal,
sector-aligned lengths. The generic comparator does not certify that a supplied
range belongs to a file or that either image is a valid filesystem.

For each explicitly retained range, the hypothetical result keeps the source
bytes. Everywhere else it uses the shadow bytes. The report lists every
differing non-retained sector as bounded, coalesced ranges, with hashes of the
original and replacement bytes. It also computes the complete hypothetical
result's SHA-256 without creating that image.

```powershell
.\target\release\ntfs2refs.exe compare-retained `
  --source source.raw --shadow native-shadow.raw `
  --request retained-request.json --output retained-comparison.json
```

The request is JSON, at most 128 KiB, with these required fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `sector_size` | `512` or `4096` bytes |
| `expected_length` | Exact length of each raw input |
| `source_sha256`, `shadow_sha256` | Expected full-input hashes |
| `retained_ranges` | Sorted, non-overlapping ranges; each has `offset`, `length`, `source_sha256` and `shadow_sha256` |
| `max_change_bytes` | Maximum complete-sector byte count outside retained ranges that may differ |
| `max_ranges` | Maximum coalesced change ranges |

Every retained offset and length must be sector aligned and inside the input.
Full-image and retained-range pins must match the observed bytes. Unknown JSON
fields, incomplete reads, malformed pins and exceeded limits are errors. The
comparison does not truncate its change list. Output uses create-new semantics;
an existing report is never overwritten.

The core accepts images up to 128 GiB, at most 1,024 retained ranges and at most
65,536 change ranges. The CLI request-size limit may impose a lower retained
range count. Two complete passes read both inputs; the report accounts for
those reads and the small container-signature probes separately. These are
comparator limits, not qualified conversion limits.

Read all sectors, including sectors described as free by either filesystem and
sectors containing zeros. Free-space bitmaps and sparse container allocation
are not substitutes for this comparison. Input stability is checked again
before returning the report. Windows image handles deny concurrent writers and
deletion while open.

## What this contributes to in-place conversion

The [next native milestone](next-extent-preservation-milestone.md) proposes one
fully initialized 64 KiB NTFS file and a separate native ReFS shadow with the
same file extent locations. Source and placeholder contents deliberately differ.
The planned target must keep the original payload and reproduce the shadow
everywhere else. This comparator supplies the exact byte accounting for that
experiment, without assuming a complete ReFS metadata classifier.

Native file ownership, validity, integrity settings, names, security metadata,
partition identity and address translation require separate evidence. A caller
can supply a byte range containing metadata; its hashes do not make it safe to
retain. No supplied JSON field or successful comparison removes those blockers.

Changed-sector bytes are only the proposed replacement and recovery-preimage
payload sizes. They are not a complete journal-space estimate: journal indexes,
headers, durability records and storage alignment are unimplemented. The tool
has no recovery executor or first-writable-mount handoff. All conversion and
recovery commands remain unavailable.

## Verified standalone guest execution

The release executable ran successfully inside Windows 11 Pro 26300.9457 in
case `retained-compare/win11-20261024T013857976Z`, completed at
2026-10-24 01:39:57 UTC. It compared two new 8 KiB ordinary files on the enrolled
guest OS disk. It retained bytes 1,024..1,535 and reported exactly two 512-byte
change ranges, at offsets zero and 1,536. Full input hashes remained unchanged.
The expected complete-result hash matched the independently generated host
fixture:
`cd7bc20c910b64f9ae66f23dd3ee71d6054ca1e712cfae92536f9ccbd67e1aba`.

No patch was applied. All native-semantic and conversion qualifications remain
false. This establishes standalone execution of the byte comparator, not native
NTFS/ReFS reconstruction. Six bounded guest artifacts were exported and checked
before clean shutdown and restoration to installed-clean/off/4 GiB.

| Artifact | SHA-256 |
| --- | --- |
| Release executable | `a3d3f0ca1c00e01ee481811eac81d3f592f829367e25e20140a10a1437a1155f` |
| Guest comparison | `dba914f25ed69da0f31ca84d4c9730c2fe6d1b1678fda160240d74cb58d36ec5` |
| Guest runtime evidence | `321ef64802d72759cd300a1553a057a5e05a948b8f7a7f48f6fde67d99a5380c` |
| Host result | `105f215f344d0d0e65e834ee421cdd630a9e492539fd85229e4d4b1e7c26d438` |

All 151 ordinary Rust tests, formatting and Clippy pass. The bounded lab wrapper
passes 162 checks in PowerShell 5.1 and 7. The case retains the exact binary,
inputs, executing wrapper and lab module. The release provenance record is
`.lab/builds/release-20261024T013013347Z.json`.
