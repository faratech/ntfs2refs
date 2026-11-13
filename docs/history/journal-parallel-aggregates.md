# Journal aggregate SHA-256 scheduling

Journal preparation and validating readback calculate independent per-record,
selected-side and immutable-body SHA-256 digests. Updating all of them on the
reader thread serializes CPU work even when spare cores are available.

The implementation sends only aggregate digest updates through the existing
bounded, recycling digest pipeline. Per-record hashes, all reads, equality
checks and write ordering stay on the caller. Each aggregate receives exactly
the original ordered framing and bytes. The serial CNG or Rust backend is
constructed inside its worker; native handles never cross threads. Machines
with fewer than three available cores keep the serial path.

Preparation has at most two aggregate workers. Validating readback has at most
three, with one 1 MiB reusable data buffer per worker. The copy format does not
start an unused new-side worker during its descriptor pass. Its resolved-copy
pass still hashes every resolved new byte and checks both record and selected
digests. Working memory remains independent of payload size.

Every required worker must finish successfully before its digest is accepted.
The existing pipeline closes its channels and joins on error or drop, including
when a worker is returning a buffer. No records, ticket or replay authority are
issued on an incomplete or failed aggregate. No filesystem or journal format,
checksum algorithm, selected range, content verification scope or barrier changes.

Focused library/CLI checks and independent code review pass. Sealed `f32c0f6`,
including these aggregates and the V3 envelope, passed one normal F: case:
1,084 objects, 273 directories and all 811 independent hashes, native0/HND.
Native elapsed time was 384.724 seconds, with the observer passing 163.489
seconds later. This is not a controlled timing comparison; process transfer
counters are not physical disk I/O. The later zero-digest cache was not used
in that normal f32 case. Sealed `07b0164`, including both changes, subsequently
passed the grown V3 controlled first-flushed-write interruption, clean restart,
public Resume and separate Rollback; each recovery observer matched all 811
stream hashes. Arbitrary faults and physical power loss remain unqualified.
[Recovery scope](envelope-recovery-matrix.md).
[Native evidence](../../evidence/object-envelope-native-20261031.json).
No unit tests were added or run.
