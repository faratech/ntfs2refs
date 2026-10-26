# Frozen native-shadow alpha

The active priority is end-to-end native-shadow conversion and recovery. The
engine source checkpoint is `96720eff89c7e808983c8d5c9800d475fe62515c`, tagged
`alpha-native-shadow-20261026`. Its Rust production tree is unchanged from
`daea5eb`; the current release executable SHA-256 is
`714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841`.
Formatting, Clippy, release builds and 665 workspace tests passed (13 ignored).
This is a candidate freeze, not new native qualification.

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

The initial capacity plan charges the 18,035,647,136-byte archive copy plus
16 GiB for source/shadow/journal/OS/checkpoint growth, retaining 64 GiB free and
the existing 208 GiB lab ceiling. Recheck actual capacity at each large stage.
No evidence deletion, security/credential change, billing change or CI rerun is
part of alpha qualification.
