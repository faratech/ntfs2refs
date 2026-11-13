# Measuring payload writes

Native placement and unchanged hashes do not establish absence of payload I/O.
The successful initialized 64 KiB move is a useful positive control, but no
trace was captured during that run. Zero-copy and bounded scratch remain
unqualified.

Windows ships the WPR command-line recorder; installing the ADK is not required
for that executable. A guest must still record its exact recorder version and
available profile before a test. Host availability does not qualify the guest.
[Microsoft WPR overview](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/introduction-to-wpr)

The initial `lab/guest/N2R-DiskIo.wprp` profile requests 8 MiB of system buffers
and 1 MiB for markers/control events, with disk I/O, initiation and split-I/O
keywords. It has no stack capture. These are requested buffer bounds, not an
assertion about total process memory or final ETL size. The native host's built-in
DiskIO profile requested 3,272 one-MiB system buffers; it was inspected/exported,
never started. The small custom profile also has not been used for recording.

The intended measurement protocol is:

1. Run inside the owned guest with the exact target identity, disk number,
   partition offset, sector geometry and current file mapping recorded. Refuse
   to interfere with an existing recording. Start a uniquely owned recording;
   retain its identity and exact profile hash. No host tracing is needed.
2. Record explicit begin and end markers around each allocation, EOF change,
   move, valid-length change, flush, handle close and controlled remount. Retain
   timestamps independently. A normal in-memory session does not survive a
   reboot; do not claim that it does. Boot tracing would be a separate test.
3. Stop and save only the owned recording to a new bounded evidence directory.
   Export collector/loss statistics and preserve the ETL even when validation
   fails. Recording ownership uncertainty prevents automatic stop/cancel of an
   unrelated session. File-size overflow fails the evidence gate.
4. Require both boundary markers and continuous coverage of the operation.
   Memory-mode wrap can remove the beginning without a conventional dropped-event
   error. A zero loss counter alone therefore does not establish coverage.
5. Decode supported event versions and pointer widths explicitly. Keep all
   target-disk writes regardless of issuing process; kernel/background writes
   must not disappear through PID filtering. Reject unknown/truncated events
   that could affect the target range.
6. Repeat the known initialized-file move under the same trace configuration.
   Its destination write coverage must be visible before treating a later
   absence of recorded writes as meaningful. Independently compare raw bytes,
   allocation maps and file hashes before/after the tested operation.

Disk read/write events expose a disk number, disk-relative byte offset and
transfer length. For this single-partition basic-disk profile, map a measured
partition-relative payload interval into that disk address space by adding the
verified partition offset. Sum overlapping bytes and retain the actual intervals;
do not infer the target from a filename or a process ID.
[Microsoft DiskIo event definition](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1)

ETW session properties distinguish lost events, lost log buffers and lost
real-time buffers. Preserve each applicable counter, start/stop status and
actual buffer allocation. A partial or lossy trace cannot qualify absence of
writes. WPR exposes collector status and markers, but saved event decoding and
coverage validation remain unimplemented here.
[ETW session properties](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties),
[WPR command-line contract](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options)

Even a complete disk-I/O trace has an observation-layer limit: it is not a proof
about drive firmware, every discard/offload control, or scratch growth on all
file sizes. Record discard/offload limitations explicitly. Subsequent scale
tests must measure actual scratch allocation and cumulative I/O independently.
