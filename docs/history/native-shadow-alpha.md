# 2026-10-26 native-shadow alpha candidate (historical)

This page records the earlier candidate and its original laboratory policy.
Its preserve-all checkpoint and storage-cap instructions are historical. Current
work follows [AGENTS.md](../../AGENTS.md), the user's later checkpoint-cleanup
authorization and the fixed additional 50 GB budget. Use the [current CLI
workflow](../cli-workflow.md) and exact build evidence for newer candidates.

The active priority is end-to-end native-shadow conversion and recovery. The
engine source checkpoint is `96720eff89c7e808983c8d5c9800d475fe62515c`, tagged
`alpha-native-shadow-20261026`. Its Rust production tree is unchanged from
`daea5eb`; the current release executable SHA-256 is
`714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841`.
Formatting, Clippy, release builds and 665 workspace tests passed (13 ignored).
This is a candidate freeze, not new native qualification.
The later [normal-path result](native-shadow-alpha-results.md) records its bounded
native conversion/mutation/reboot pass; recovery cases remain separate evidence.

No additional filesystem features or independent-writer experiments belong on
this path. Preserve old evidence and binaries. If native failures require an
engine change, create another candidate and retain the failed candidate's pins.

Use a fresh independent archive copy named `ntfs2refs-shadow-alpha-20261026`
under `.lab/hyperv/shadow-alpha-20261026`. Original VM `eebbfd4e-...` and its
fifty checkpoints, and independent-writer fixture `8f7fc646-...`, remain untouched.
Bind every action to the new recorded VM GUID and fresh backing identities.
Conversion and recovery execute inside the guest. No old-lane dispatcher applies.

The alpha profile remains the bounded ordinary NTFS 3.1 data-volume profile:
512-byte sectors, 4 KiB clusters, 1 KiB records, ReFS 3.14, single unnamed
uncompressed/unencrypted streams, ASCII names and the existing file/data limits.
New parser cases are not advertised as native qualified without their own runs.

Qualification sequence: baseline snapshot; public conversion; native verification;
bounded mutation; reboot verification; preactivation cancellation; controlled
first-flushed-write interruption followed by public resume/finalization; and a
separate interrupted branch followed by public shadowless rollback. Preserve
each branch's exact executable/request/tree/journal/marker/result pins before
restoring the disposable baseline. Process-fault tests do not prove power-loss safety.

`lab/Collect-NativeShadowAlphaMarker.ps1` collects additional marker bytes only
from an already restored, running preserved branch after the matrix controller
has released its leases. It reads the journal without write access, checks the
canonical completed marker and immutable journal body, and saves the 8 KiB
prefix with hashes outside the guest. It does not restore/boot a VM, verify the
current target image, attest the native journal file ID, or grant replay
authority. Its implementation and pure checks do not count as a native capture;
link the actual capture report when those pins have been collected.

The initial capacity plan charges the 18,035,647,136-byte archive copy plus
16 GiB for source/shadow/journal/OS/checkpoint growth, retaining 64 GiB free and
the existing 208 GiB lab ceiling. Recheck actual capacity at each large stage.
No evidence deletion, security/credential change, billing change or CI rerun is
part of alpha qualification.
