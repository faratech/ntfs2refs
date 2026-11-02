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

The first owning-guest run of runtime `f707d75` refused during native journal
construction with Windows error 1. The new journal remained empty; no ticket,
recovery bundle or source activation was reached. Its metadata archive is
preserved. This is a refusal, not native qualification.

Constructor failures now carry their native operation name and original error
chain. The explicit lab tool also has a `probe` command that creates a new empty
journal and diagnostic report under an enrolled C: lab directory. It exercises
the actual constructor without reading source/shadow data, constructing ReFS,
writing journal payload, sealing markers or acquiring volume privileges. This
isolates setup failures without repeating the full source and shadow work.
It creates filesystem metadata and therefore is not a disk-write-free operation.
Unsupported queries supply no affirmative absence evidence; probe output
supplies no storage capability.

The constructor probe isolated the failure to `FSCTL_GET_EXTERNAL_BACKING`.
Windows returned error 1, which describes an unavailable backing service rather
than a negative backing observation. The backend now requires an affirmative
same-handle `FSCTL_GET_REPARSE_POINT` result of `ERROR_NOT_A_REPARSE_POINT`, on
the already verified NTFS volume, with unchanged non-reparse attributes and zero
tag before and after. This excludes the documented WOF/dedup reparse forms.
Only then may external-backing status 1 proceed; it remains recorded as
unsupported with `external_backing_absence_reported = false`. All other errors
still refuse, and all ordinary-file, compression, geometry, mapping and marker
checks remain. Sealed-storage revalidation compares the new observation too.
See Microsoft's [reparse reply](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d86a4c4d-a996-403a-8b92-9c0e1a300e22),
[provider status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-get-external-backing)
and [WOF/dedup tags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4).

The lab dispatcher now starts the native process through an owned
`System.Diagnostics.Process`, retaining its original process handle even for
very short failures. It drains raw stdout/stderr concurrently with fixed 64 KiB
buffers and synchronizes the log files before terminal hashing. This avoids
depending on a later PID lookup to observe a short-lived constructor probe.
The first standalone probe's observation parent stalled after writing its actual
constructor result; that metadata-only observer was retired with its exact PID
and creation identity. Its native exit code remains explicitly unobserved.

The explicit lab CLI now accepts paired `--pause-after-marker-copy` and
`--pause-signal` options for VM power interruption. Copies AP1/AP2, RB1/RB2,
HND1/HND2 and ABT1/ABT2 can be selected. Production callers pass no pause request.
The signal must be `marker-pause.json` directly inside the fresh C0 lab output.
Its 32 KiB file, buffer and process identity are reserved before source
construction or activation; the existing read-only device preflight runs first.
Sealing completes its bounded receipt before activation.

The hook runs only after the actual selected 4 KiB copy's write, flush, uncached
readback equality and storage revalidation. It fills the actual marker digest,
synchronizes the signal, closes only that signal handle and parks indefinitely
with journal/source owners retained. Already-intact copies produce no signal.
Signal write/sync failure parks with the signal still locked, so it cannot
publish a readable receipt claiming successful synchronization.

The host must verify the actual live process ID and creation identity plus the
closed synchronized receipt before deliberately powering off the disposable VM.
A timeout, receipt flag or missing output alone never authorizes power action.
This is the specific intentional-fault exception to the ordinary requirement
that every project worker be terminal before VM power operations. It grants no
fresh source or replay authority. Source review and focused compilation passed;
native power-interruption qualification remains pending.
