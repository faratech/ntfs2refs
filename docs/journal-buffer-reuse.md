# Bounded journal working buffers

Preparation previously allocated a 1 MiB buffer for each old/literal/zero range
and two buffers for each copy comparison. Apply and rollback allocated three
1 MiB buffers every time `write_span` was called. Fragmented plans multiplied
that allocation and zero-initialization work by their range count.

Preparation now reuses two buffers throughout the range loop. They are dropped
before the validating journal readback. Replay reuses one three-buffer working
set for all ranges and the final discovery-region write, then drops it before
the complete post-write target check. Reuse therefore does not add a second
working set to the verification phase.

Every slice is completely populated by the current source/candidate/journal or
target read before hashing, comparing or writing. Synthetic zero ranges are
explicitly filled. Only the current `count` bytes are inspected; trailing bytes
from a previous chunk are never used. Short reads/writes, old/new mixed-byte
validation, hashes, write order, markers and flushes retain their checks.

This is a CPU/allocation change. It does not remove any data read, digest,
comparison, capacity guard or recovery check. Journal formats and content remain
unchanged. The running 18bdea8 larger-tree case uses the earlier sealed binary
and does not qualify this later buffer implementation.

Focused library/CLI checks, independent code review and public, bind, digest and
fault-helper release builds pass. Native qualification is pending. No unit tests
were added or run.
