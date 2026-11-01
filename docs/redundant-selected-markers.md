# Redundant selected-journal markers

The generic journal engine has an explicit experimental format6 opt-in:
`prepare_redundant_source_free` and `validate_redundant_source_free`, with
`SelectedTicket.marker_profile = RedundantSourceFreeV1`. Existing preparations
and formats1–5 retain their prior layout and behavior.

N2RFRE02 reserves32768 bytes before the immutable body. Separate4-KiB slots hold
two copies each of AP, RB, HND and ABT. Self-hashed copies bind their kind/copy,
version, immutable journal pin, original full-old selected checksum and new
checksum. Source-free rollback still checks only restore-required bytes; marker
identity is not changed to that scoped digest.

An exact authenticated copy can establish state despite a zero or damaged peer.
A valid but wrong identity/kind/copy, conflicting lifecycle state, two invalid
copies, or zero plus unauthenticated damage refuses. All pairs are checked
before terminal-state precedence. Peer repair never rewrites the intact copy;
both write/flush/readback steps precede fresh target writes or online handoff.

This is generic format mechanics, not native durable-sector qualification.
Production native recovery explicitly refuses marker profiles before opening a
target. No production native path creates format6. Enabling it requires a private
backend binding retained file/device ownership, actual alignment and independently
allocated marker granules, ordered flushes and uncached readback. Ordinary cached
File readback and distinct logical offsets cannot establish those claims.

Source review and focused compilation passed. Native backend integration,
single-peer read-error policy, terminal-peer online policy and VM/hardware
power-loss qualification remain pending. No unit tests were added or run.

The pending Win32 adapter now owns an exclusive NO_BUFFERING|WRITE_THROUGH NTFS
file, bounded aligned body cache and exact logical EOF. Its sealing step binds
actual file/device identity, actual storage granules, retrieval/base mappings,
eight disjoint marker granules and handle-local protected allocation. Scoped
volume-management privilege is restored after handles close. Sealed writes are
limited to full marker slots and read back through the uncached handle.

This adapter is compiled and source-reviewed, with its native-qualified flag
still false. It is not wired into production creation or recovery. Retaining the
existing prepared-journal proof requires an in-place sealing hook; generic
format6 support alone cannot authorize a buffered native backend. These checks
bound reported storage-interface granules, not hardware FTL separation or host
power-failure behavior.
