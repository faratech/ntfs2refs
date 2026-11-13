# Frozen aef experimental alpha

The public `aef1ab3` executable is packaged without another rebuild. Cargo/CLI
version is **0.1.0**. This is an experimental data-volume alpha with nine
recorded cases on one finite Windows 11 profile; broader stability and hardware
qualification remain incomplete.

Local ZIP:

```text
D:\code\ntfs2refs\.lab\packages\experimental-aef-public-3e15ac0829db452dbbb5d9c8b4c9d7e1\ntfs2refs-aef-public-experimental.zip
```

ZIP: 19,254,647 bytes, SHA-256
`00016d67e5580416f08a73c585c934b811fdd113d0325b24e17da9d42fda5514`.
All 12 entries were checked against their lengths and hashes. The only
executable is `ntfs2refs.exe`; source/build provenance and small case receipts
are included. No laboratory executables, disk images, journals or credentials
are packaged. No tag or publication was performed.

The qualified fixture is a dedicated basic GPT disk with a 52 GiB data
partition, NTFS 64 KiB clusters, 512-byte logical / 4 KiB physical sectors,
converted to ReFS 3.14 Dev Drive with 4 KiB clusters. Its independent oracle
covers 811 streams, 9,885,801,949 logical bytes, 1,534 baseline objects and
1,024 additional directory paths.

| Case | Recorded result |
| --- | --- |
| Default VHDX conversion | Native exit 0 in 843.06 seconds; handoff, owned backing cleanup and independent content checks passed. |
| Experimental thin conversion | Native exit 0 in 664.25 seconds; cleanup and content checks before/after reboot passed. |
| Controlled interruption | Actual single Hyper-V TurnOff followed by persistent exclusion and independent recovery authentication. |
| Public rollback | Exit 0; original NTFS oracle matched. |
| Public resume | Exit 0; ReFS oracle matched. |
| Mutation and reboot | 513 additional/mutated files and the original oracle matched after reboot. |
| Terminal reconciliation | Exit 0 without replaying the old raw journal. |
| Exclusive journal refusal | Actual sharing error 32; journal and observed contents preserved. |
| Low-space admission refusal | Actual public exit 1 in 0.0313 seconds at about 3.75 GiB caller-available working space, before staging; observed source state preserved and reservation released. |

The low-space harness consumed 5,337,570,325 additional host bytes across boot,
execution and shutdown, within its 6 GiB forecast. Earlier allocation samples
were smaller; they are neither a peak nor a hard quota. This is a lab-case
cost, not a conversion scratch estimate.

Use the included [README](../../userdocs/experimental-aef-candidate.md) for selection,
conversion and recovery commands. Preserve independent backups and the exact
recovery directory/checksum printed by each operation. Conversion runs on the
machine owning the disk; Hyper-V is test infrastructure.

The [qualification](../../evidence/public-aef-experimental-qualification-20261104.json)
and [package record](../../evidence/public-aef-experimental-package-20261104.json)
bind the unchanged executable and all case receipts. Boot/system conversion,
data partitions sharing the running Windows disk, arbitrary geometry/features,
physical power loss and actual ENOSPC/write/flush failures remain outside this
alpha's qualification. The broader project goal remains active.
