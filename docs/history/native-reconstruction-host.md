# One-phase native reconstruction laboratory harness

`scripts/Invoke-LabNativeReconstruct.ps1` runs one explicitly selected operation
through the frozen guest `Invoke-GuestNativeReconstruct.ps1` wrapper. It is a
laboratory harness for the owned Windows VM; the Rust reconstruction core and
native partition adapter do not depend on Hyper-V.

The host requires independent SHA-256 pins for the request, its `.pin.json`
provenance from `New-LabNativeReconstructRequest.ps1`, and a reviewed-source
manifest. It re-derives the request from the pinned completed native probe,
including its restart/whole-partition reports and original preparation. It
does not infer current disk state from that evidence: the guest and Rust
adapter revalidate native identities and current exclusion when run. Each new
shadow attachment uses provider read-only protection, verifies it, and explicitly
establishes offline/read-only attributes. It does not assume shadow attributes
persist across detach or reboot.

The reviewed manifest has `schemaVersion: 1`,
`kind: "native-reconstruction-reviewed-sources"`, and exactly these `files`
entries, each with `path` and lowercase `sha256`:

- `lab/guest/Invoke-GuestNativeReconstruct.ps1`
- `lab/guest/Restore-GuestShadowAttachment.ps1`
- `lab/guest/NativeShadowDisk.cs`
- `lab/guest/NativeShadowReadOnlyAttachment.cs`
- `lab/guest/NativeMountBoundary.cs`
- `lab/Lab.psm1`
- `scripts/New-LabNativeReconstructRequest.ps1`
- `scripts/Invoke-LabRetainedNativeProbe.ps1`
- `scripts/Invoke-LabNativeReconstruct.ps1`
- `target/release/lab-native-reconstruct.exe`

These sources are copied into the new host case before starting the VM. Only
explicitly named function definitions are loaded from reviewed helpers; their
top-level orchestration is not executed.

`-Operation prepare` restores the exact quiescent, powered-off 8 GiB checkpoint
recorded by the successful probe. Other operations require
`-PriorResultPath`, `-PriorResultSha256`, and a separate `-TicketSha256`. The
prior phase must have completed, exported its ticket and reports, saved an
off-state checkpoint, and returned to the baseline. Its run ID, request hash,
request provenance hash, and ticket hash must match.

| Selected operation | Accepted completed predecessor |
| --- | --- |
| `apply` | `prepare`, `rollback` |
| `resume` | `prepare`, `apply`, `resume` |
| `rollback` | `apply`, `resume` |
| `handoff` | `apply`, `resume` |

This harness does not automatically recover a failed or uncertain VM branch.
That branch requires separate investigation and an explicit recovery decision.
The journal core's interrupted-write recovery is tested independently on
ordinary files.

The host reattaches the already excluded shadow, stages a new guest phase
directory, invokes one bounded process wrapper, and exports the phase's exact
nine-file artifact set plus the independently pinned ticket. The host checks
process completion, arguments, durable intent, native report, journal and
partition bindings, write counts, retained-range invariants, and all relevant
hashes before requesting a clean shutdown. It then saves a uniquely named
`reconstruct-<operation>-<phaseId>` checkpoint and restores the baseline off
with 4 GiB RAM. Any failure preserves the active branch and session; unknown
process completion never permits shutdown or cleanup.

The journal stays on the guest's independently enrolled J: volume and is
included in the VM's disk checkpoint. It is not copied to the host. The ticket
and reports are exported to the host for review. Handoff still leaves the data
disks offline; mounting, shadow detachment, and post-conversion observation are
separate operations.

`lab/Test-LabNativeReconstruct.ps1` exercises pure schema, predecessor, artifact,
completion, durable-intent and WhatIf guards in PowerShell 5 and 7. Its 160
checks do not operate on a VM or native disk. Passing them is not evidence that
native conversion, recovery after power loss, or boot conversion has succeeded.
