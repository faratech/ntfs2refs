# Native marker fault qualification

The enrolled lab recovery command can exercise a damaged second marker copy
or a synthetic I/O failure through the actual sealed journal owner. Production
and fresh conversion callers cannot request this facility. It does not change
the compiled production qualification gate.

`lab-selected-marker-native recover` requires both existing lab acknowledgments
and all three options:

```
--marker-fault-copy AP2|RB2|HND2|ABT2
--marker-fault-kind corrupt-peer|write-error|flush-error|readback-error
--marker-fault-signal <fresh-recovery-output>\marker-fault.json
```

Only an already degraded matching pair is eligible: the actual first copy must
equal the engine's canonical authenticated image and the second must be zero.
The sealed owner checks both before target opening and repeats those checks
immediately before the selected marker write. Other lifecycle states refuse.
There are no arbitrary byte, offset, journal path or device-write parameters.

Corrupt-peer writes the canonical second copy with one fixed self-hash bit
flipped, flushes, reads back uncached, verifies the intact first peer, publishes
a synced 32 KiB receipt, and parks with journal/target ownership retained. Only
the host controller can then power off the disposable VM. It cannot continue
automatically or perform another target write.

The three error cases deliberately skip the selected WriteFile,
FlushFileBuffers or ReadFile call and return synthetic ERROR_IO_DEVICE (1117)
through the actual journal poison path. Their receipts explicitly distinguish
issued operations, unobserved bytes, injected errors and actual OS errors.
These are failure-path checks, not hardware fault evidence. Signal resources
are reserved before journal/target opening. A signal publication failure parks
with the signal handle still exclusive rather than exposing partial evidence.

Focused Windows builds of the public, marker and composite entry points passed.
No unit tests were added or run. Native fault executions remain a separate
qualification requirement; source inspection and a successful build do not
qualify recovery or enable format six in production.
