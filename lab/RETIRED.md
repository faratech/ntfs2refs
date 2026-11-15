# Retired lab stages

The scripts and executables of the earlier qualification stages (the
streaming, shadow and paged routes of October and early November 2026) are no
longer in the tree. Each was written for one virtual machine, or one
checkpoint, that no longer exists on the lab host, and could not run. The last
commit that has them is tagged `archive/retired-lab`:

```
git show archive/retired-lab:lab/RETIRED.md      # the list of what was retired
git checkout archive/retired-lab -- lab scripts  # the scripts themselves
```

Evidence in `evidence/qualification-registry.json` is bound to two of them by
digest (`lab/Complete-NativeShadowAlphaRollback.ps1`,
`lab/Collect-NativeShadowAlphaMarker.ps1`), and the historical guide in
`docs/history/` refers to others by name: all of them are in that tag.

The current route is `Invoke-BootConversionAttempt.ps1`; see [README.md](README.md).
To repeat an old stage, carry its steps over to the current harness.

`tests/lab_retired_scripts.rs` holds the scripts in this directory to the
tables below: a script that names a retired VM must be one of the exceptions
at the end, and every exception must exist.

## Live virtual machines

| VM id | Name |
|---|---|
| `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a` | `ntfs2refs-reference-isolated` |
| `7c687062-37b5-4309-b28a-486a44305202` | `ntfs2refs-reference-b` |

## Retired virtual machines

| VM id | Name in its scripts |
|---|---|
| `2401593c-4b30-472e-9b6d-c9534cbaa599` | `ntfs2refs-streaming-v2-20261027` |
| `0d9bfa66-c66c-4ead-86b7-e72cb5f7e040` | `ntfs2refs-shadow-alpha-20261026` |
| `6c4793d2-cdee-468b-bf3b-1c11cae0b501` | `ntfs2refs-shadow-large-beta-20261027` |
| `eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c` | (the first reference VM; its name now belongs to a live VM) |

Retired VM names that appear without an id: `ntfs2refs-native-shadow-alpha-20261026`, `ntfs2refs-native-shadow-beta-20261027`.

## Not retired, though they name a retired VM

- `IsolatedBaselineGuards.psm1`: refuses that VM id by name: it is the guard against using the old VM.
- `Provision-IsolatedReference.ps1`: built the present reference VM; it names the first one only to leave it untouched.
- `Test-IsolatedReferenceReadiness.ps1`: checks the present reference VM; it names the first one only to leave it untouched.
