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

The proposed `lab/Read-IsolatedJournalPrerequisite.ps1 -RequireZeroScan` command
is retained for separate review. It can collect identity observations but must
refuse the zero-scan request. It opens no guest session or credentials. It is
not an alpha conversion/recovery launcher and must not delay those tests.

Source-only checks: 79 native-pin compile/refusal checks, 91 graph checks,
32 injected collection checks and 15 guest pre-native refusals passed, including
Windows PowerShell 5.1. These are not live acquisition or exclusion qualification.
