# Host validation of protected shadow reattachment

The saved diagnostic `win11-20261024T041957683Z-df922bc4b13e46339c8c938a4f5a7742`
showed raw disk attributes 0 while the provider returned ERROR_WRITE_PROTECT
(19) and Get-Disk reported IsReadOnly true. One explicit SET_DISK_ATTRIBUTES
request for attributes 3, mask 3 and Persist true then established exclusion.
The complete backing-file hash stayed unchanged. This is a new protected
attachment and transition, not proof that the prior attachment's attributes
survived restart.

The native-probe, reconstruction and converted-verification host runners pin
`NativeShadowReadOnlyAttachment.cs` and `NativeMountBoundary.cs` alongside the
existing `NativeShadowDisk.cs`. Their source manifests now have 8, 10 and 17
entries respectively. The original preparation helper remains unchanged, so the
existing prepared fixture remains usable. Prepared attachment keeps its former
behavior; only Excluded attachment receives the two additional independent pins.

The shared `Assert-RetainedProbeProtection` guard validates the raw physical call
sequence independently: 23 calls when attributes must be established, or 14
when attributes 3 are already observed. It checks device number, disk length,
sector alignment, complete GPT layout, before/after attribute buffers, provider
ERROR_WRITE_PROTECT before write-access open and before/after the setter, and
the exact 40-byte SET request. Missing, reordered, extra or malformed calls fail.
Both target snapshots must match the independently pinned target GPT/geometry
and remain offline/read-write. The full backing hash/length must match before
and after, with the guest's 256 MiB bound. Known completion and complete cleanup
are mandatory. Any persistence or conversion qualification claim is refused.

The generator requires the new protected source inventory/profile and the
excluded attachment hash in the pinned completed host result. It still produces
only an explicitly unqualified request and keeps its existing ten provenance
inputs; it does not turn JSON attestations into current device authority.

New probe outcome checkpoint names use `retained-isolated-<firstProbeId>` and
`retained-quiescent-<secondProbeId>`. The prepared checkpoint continues to use
`retained-prepared-<runId>`. Exact names are verified by the generator, and
existing historical checkpoints remain untouched when the same prepared fixture
is tested again.

`lab/Test-LabShadowProtectionEvidence.ps1` validates the independently pinned
native diagnostic bytes, mutates every native call field, tests ordering and
identity failures, and constructs an explicitly synthetic already-excluded
variant. It also exercises both direct-probe and reconstruction request shapes
through the complete attachment guard. Tests do not invoke VM or native APIs.
