# Raw extent recovery qualification

Runtime `7ced37b` passed one controlled interruption after the first flushed
target write. The actual converter exited 86; source disk 6 remained offline
writable and the managed ReFS shadow remained offline/read-only. The original
bundle pins two unread 2 MiB streams and the 53-binding recovery map manifest.
The lab saved that interrupted state, then used two independent branches:

- Resume observed `apply_intent`, completed ReFS and closed HND. Native recovery
  fully hashed all 37 streams with known digests (64,869,591 bytes) and checked
  the two unread streams through the pinned complete maps. It did not invent
  their missing initial hashes. All 39 independent lab stream hashes matched.
- Rollback restored NTFS and closed ABT. The old-selected checksum matched the
  original ticket; H: mounted with its 4 KiB geometry and original label. All
  39 independent stream hashes matched, including NTFS-compressed streams.

The initial Resume observer failed after native success because Windows
PowerShell did not enumerate the helper's JSON array as intended. The original
failure is preserved. A separate read-only receipt validates the already completed
helper's PID/creation identity, exit 0, stdout hash and all 39 actual digests.
Recovery was not rerun, and no raw replay occurred after HND. The tracked parser
now explicitly enumerates the array.

The old full-content lab baseline stays separate from product expectations.
Access-time differences are recorded against the original frozen source views.
Resume also checks actual recovered target times; Rollback relies on the closed
old-selected-byte proof and makes no independent post-rollback timestamp claim.
No product expectation or filesystem timestamp is rewritten by the observer.

The interrupted, resumed ReFS and restored NTFS checkpoints remain preserved as
`9ce156c3`, `9bb675b9` and `b8091885`. Closed archives contain 71, 32 and 35
metadata files respectively, with every length and SHA-256 checked. The VM is
normally stopped at the restored NTFS checkpoint.

This qualifies one controlled exit plus clean restart, not arbitrary interruption
points, hard power-off, physical power loss or subsequent mutation. No unit tests
were added or run. [Evidence and artifact pins](../../evidence/raw-extent-recovery-matrix-20261031.json).
