# Bounded NTFS logical-stream copy

`ntfs_inspect::copy_plain_stream` now re-reads the NTFS boot/MFT chain and the
file's current DATA attribute, compares them with the inspected identity, and
streams its logical bytes through a fixed 64 KiB buffer to a caller-supplied
writer. It emits zeroes for sparse holes and beyond valid-data length, then
compares the streamed SHA-256 with the inspection. The caller must discard
partial output if the copy fails. No source write is possible through this
function.

The existing bounded `read_plain_stream` API uses that same checked streaming
path and collects into memory for the small native-shadow experiment. The
Windows shadow creator has **not** yet been converted to accept streamed
payloads, so its 256 MiB logical-data ceiling and payload-proportional shadow
backing remain. A direct streaming sink and its native round trip are required
before expanding those limits.
