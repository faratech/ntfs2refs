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
