# Parked independent-writer journal prerequisite

This work is off the native-shadow alpha's critical path. No host identity
collector, guest raw scan, initialization or writer trial was executed.

The source collector joins current/checkpoint attachments and every VHD ancestor
by native volume/file identity, retaining read-attributes handles and rechecking
the original paths. Fsutil display IDs and native opaque file-ID bytes are kept
separate. Parent paths and copied VHD UUIDs are not ownership keys. Pure graph and
injected-provider tests cover aliases, cycles, changing routes and failure cleanup.

Those handles allow host writes and prove no content immutability. The guest's
no-sharing PhysicalDrive2 handle also does not establish exclusion of all host or
lower-storage writers. A stable snapshot or `ZeroProof.AssertCurrent` does not
recheck content or survive loss of a cross-host fence. No reviewed durable fence
backend exists. Correct guest identity arguments therefore now refuse before
native access; JSON claims cannot enable the scan.

That refusal belongs to the initialization-proof path, not to ordinary
read-only measurement. The separate source-only
`IsolatedJournalReader.ObserveReadOnly(Guid, string)` entry returns a report,
closes its private `GENERIC_READ`/no-sharing handle and never exposes a stream,
handle or `ZeroProof`. It observes exactly 8 GiB, hashes the bytes, records
informational zero/nonzero counts, and checks native identity before/after.
It trusts Windows/Hyper-V and needs ordinary project-worker and route checks;
it does not require a malicious-kernel/admin exclusion mechanism to report what
was read. Matching identity/timestamp observations still do not prove an atomic
immutable snapshot. No live observation has run from this source checkpoint.

The existing `OpenReadOnly` and `ScanAndBind` initialization-proof APIs retain
their pre-native durable-fence refusal. An observational all-zero report cannot
satisfy that gate or authorize formatting, initialization, import or writes.

The proposed `lab/Read-IsolatedJournalPrerequisite.ps1 -RequireZeroScan` command
is retained for separate review. It can collect identity observations but must
refuse the zero-scan request. It opens no guest session or credentials. It is
not an alpha conversion/recovery launcher and must not delay those tests.

Source-only checks: 79 native-pin compile/refusal checks, 91 graph checks,
32 injected collection checks and 15 guest pre-native refusals passed, including
Windows PowerShell 5.1. These are not live acquisition or exclusion qualification.
The separate observation helper adds 68 pure completeness/hash/refusal checks;
its tests invoke no native observation entry, device or VM operation.
