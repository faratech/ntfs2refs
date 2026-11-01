# Admission by stored journal bytes

The optional request policy `old_zero_actual_bytes_v1` separates logical changed
bytes from actual journal storage. Omitted policy retains `conservative_v1`,
including its previous serialized shape and admission bounds. The public drive
CLI and binder continue to choose the conservative policy until qualification.

The new policy requires schema 3, CapacityPinnedV3, fast allocation conversion,
a fresh shadow, streaming resources and explicit literal/combined scratch
bounds. It is pinned in the admitted request used by recovery. A policy field
does not issue a source certificate, authenticate a journal or permit raw writes.

Capture bounds its logical changed set by the partition, while each proposed
append must fit:

```text
projected journal = changed - whole-range old zeros + literal + metadata reserve
projected scratch = projected journal + literal
```

The existing metadata reserve, 104-byte record check, range and metadata limits,
literal budget, combined budget, actual free-space guard and reserve remain.
Every old-zero byte is still observed during capture and rechecked during
preparation. No source reads are removed.

Whole-range credit is updated in constant time. A new zero range adds its
length. Extending a zero range with more zero bytes adds those bytes. Extending
it with any nonzero byte revokes the entire previous range's credit. A range
already containing nonzero bytes never receives credit from a later zero suffix.
The provisional count and capacity checks run before accepting the run or
appending backing data; changed/range/credit state publishes only after a
successful append. There is no scan of the accumulated range table.

The final profitable encoding decision is followed by exact plan validation.
A changed set beyond the previous ceiling requires the explicit new policy,
positive old-zero bytes and format 4. Clearing unprofitable compression hints
cannot admit an expanded set through a legacy format.

A separate native entry point checks the exact pinned V3 journal ceiling,
actual journal length, positive aligned old-zero count, checked `D <= J + O`
and the partition/range bounds. Existing native entry points retain their old
ceilings. Recovery selects the new entry only from the pinned request, after
the existing complete journal/lifecycle authentication. It does not rederive
limits from current free space or grant fresh Apply authority.

The implementation and independent code review are complete. Focused library,
public CLI, fault-helper and binder compilation passed. Native qualification is
pending. The owning-guest controller `lab/Start-ActualByteCapacityExperiment.ps1`
uses 8 GiB journal / 256 MiB literal / 10 GiB combined bounds and requires the
actual changed set to exceed the former conservative ceiling while format-4
journal storage fits. Normal conversion uses the explicit fresh V3 entry;
first-write mode uses the existing flushed-write interruption entry. Its full
baseline and independent 811-stream observer remain. Capacity observations
are sampled free-space queries, not a complete rolling-credit ledger.
Host and assembled-guest PowerShell 5 syntax and independent review passed;
no native execution of this capacity case has occurred. Current file-count,
metadata, geometry and feature
limits remain; this is not unbounded-volume qualification. No unit tests were
added or run.

`lab/Start-ActualByteCapacityRecovery.ps1` is a separate reviewed recovery
controller for this budget. It requires pinned helper-source hashes and a real
future `actual-byte-capacity-interrupted-checkpoint` receipt containing the
observed producer PID/creation/exit86/first flush/no HND, final idle, checkpoint
and actual parent, bundle path/checksum and five original metadata pins. The
actual checkpoint node must join the saved receipt and clean source8329.
It reads the actual new producer fields and managed receipt; it does not
manufacture legacy fields. The shadow may remain absent after cold restart.
Host and assembled guest pass PowerShell 5.1 syntax and independent review.
No such interrupted receipt has been created, and no 8 GiB recovery has run.
