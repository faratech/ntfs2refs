# Bounded NTFS logical-stream copy

`ntfs_inspect::copy_plain_stream` now re-reads the NTFS boot/MFT chain and the
file's current DATA attribute, compares them with the inspected identity, and
streams its logical bytes through a fixed 64 KiB buffer to a caller-supplied
writer. It emits zeroes for sparse holes and beyond valid-data length, then
compares the streamed SHA-256 with the inspection. The caller must discard
partial output if the copy fails. No source write is possible through this
function.

`copy_plain_named_stream` uses the same checked path for an explicitly selected
NTFS named DATA stream and records the UTF-16 stream name in its copy proof.
The current ordinary-tree shadow still rejects ADS; this reader does not yet
provide ReFS named-stream reconstruction or conversion admission.

The streaming placement path now hashes each materialized logical subrange
through `hash_plain_stream_range`, which applies sparse-hole and NTFS
valid-data zero semantics. Per-range digests remain diagnostic until source
admission and the native reconstruction path use the same frozen basis.

The existing bounded `read_plain_stream` API uses that same checked streaming
path and collects into memory for the small native-shadow experiment. The
ordinary Windows shadow creator now accepts `--stream-payload`, which passes
each file directly from the checked NTFS reader to a native ReFS file through
the 64 KiB buffer. Native readback checks the declared length and SHA-256.
It can be combined with `--retain-eligible` to ask native ReFS to place
eligible shadow extents at their original physical offsets; the recorded
mapping and allocation evidence still decide which ranges were actually
retained.
The host `Build-LabExistingTreeShadow.ps1` switch `-StreamPayload` records and
forwards this mode, and `Continue-LabExistingTreeShadow.ps1` preserves it.

This path has compiled and passed focused unit tests, but has not yet run in
the native VM. The 256 MiB logical-data ceiling and payload-proportional ReFS
shadow backing still apply; streaming reduces process memory, not scratch disk
use or the journal size.
