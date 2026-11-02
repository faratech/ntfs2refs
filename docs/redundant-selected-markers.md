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

Source review and focused compilation passed. The native backend is now wired
only into the explicit `lab-selected-marker-native` entry. It requires both
`--acknowledge-enrolled-disposable-devices` and
`--acknowledge-unqualified-native-markers`. Its `fresh` command uses the real
source admission and allocation conversion path; `recover` uses the actual
pinned recovery journal. Production creation and recovery defaults are unchanged.
No native or hardware power-loss qualification is claimed. No unit tests were
added or run.

The pending Win32 adapter now owns an exclusive NO_BUFFERING|WRITE_THROUGH NTFS
file, bounded aligned body cache and exact logical EOF. Its sealing step binds
actual file/device identity, actual storage granules, retrieval/base mappings,
eight disjoint marker granules and handle-local protected allocation. Scoped
volume-management privilege is restored after handles close. Sealed writes are
limited to full marker slots and read back through the uncached handle.

The native-qualified flag remains false. A fallible sealing hook runs after
the full flushed body readback, clear-marker checks and paired-source checks,
before publishing the prepared journal owner. It retains the same exclusive
native handle. Native online exposure additionally requires both terminal peers
to authenticate through uncached readback. One intact terminal still closes raw
replay; degraded terminal storage stays offline rather than reopening replay.
A read I/O error refuses instead of treating an unread peer as a zero slot.
These checks bind reported storage-interface granules, not hardware FTL
separation or host power-failure behavior. The next required evidence is an
owning-guest format6 normal/fault/recovery run and hard-power interruption matrix.
