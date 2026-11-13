# Bounded journal working buffers

Preparation previously allocated a 1 MiB buffer for each old/literal/zero range
and two buffers for each copy comparison. Apply and rollback allocated three
1 MiB buffers every time `write_span` was called. Fragmented plans multiplied
that allocation and zero-initialization work by their range count.

Preparation now reuses two buffers throughout the range loop. They are dropped
before the validating journal readback. Mixed replay reuses one three-buffer working
set for all ranges and the final discovery-region write, then drops it before
the complete post-write target check. Reuse therefore does not add a second
working set to the verification phase.

The subsequent [fresh exclusive writer](journal-fresh-exclusive-writes.md) uses
one desired-byte buffer after exact-old verification. Legacy, fault and recovery
replay retain the three-buffer path described here.

Every slice is completely populated by the current source/candidate/journal or
target read before hashing, comparing or writing. Synthetic zero ranges are
explicitly filled. Only the current `count` bytes are inspected; trailing bytes
from a previous chunk are never used. Short reads/writes, old/new mixed-byte
validation, hashes, write order, markers and flushes retain their checks.

This is a CPU/allocation change. It does not remove any data read, digest,
comparison, capacity guard or recovery check. Journal formats and content remain
unchanged. The earlier `18bdea8` case used the preceding implementation.

Focused library/CLI checks, independent code review and public, bind, digest and
fault-helper release builds pass. Sealed `cc6cd28`, including this buffer reuse
and exact selected-target checks, passed one normal F: case: native0/HND,
933 objects and all 811 independent hashes. Native elapsed time was 600.788
seconds; the independent observer finished 141.877 seconds later. This single
case does not measure allocation counts or establish a controlled speed gain,
and it does not qualify rollback/recovery or arbitrary faults. Later CPU/V3
builds were not used. [Native evidence](../../evidence/mixed-exact-journal-native-20261031.json).
No unit tests were added or run.
