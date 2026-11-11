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
No unit tests were added or run. Source inspection and a successful build do
not qualify recovery or enable format six in production.

The clean committed runtime at `70c10cc` then exercised actual AP2 corruption
from the original AP1 interruption. Native5068/birth1793641119368 wrote and
verified the corrupted peer, retained the owners, and was interrupted by an
actual Hyper-V TurnOff. The same damaged branch rebooted without restoration.
Ordinary recovery through the unchanged dispatcher exited0 in17.272784s,
reached ReFS handoff, and verified1084 stream/directory bindings. Its closed
result is saved at checkpoint2c7ff0ea-8fe8-4fe9-bce9-0a3fbb4883a1.
See [the pinned case](../evidence/native-marker-ap2-corruption-20261102.json).

The readback-error case deliberately skipped the selected ReadFile after
actual marker write/flush. Native5556/birth1793641538060 exited1 in7.3740063s,
reported the LAB-INJECTED1117 failure through the existing recovery error path,
left the source offline and created no success output. The observer completed
Ready/0 because the expected failure was observed; it did not claim successful
native recovery. See [its receipt](../evidence/native-marker-ap2-readback-error-20261102.json).
Ordinary recovery on that same active branch then exited0 in14.8922902s and
verified HND/ReFS with1084bindings. Its42file metadata archive is pinned in the
same case receipt. The remaining fault kinds are separate evidence.

These cases do not qualify physical power loss, other storage geometries or a
stable general release. The production gate remains false.

The remaining AP2 API-failure cases also passed. A deliberately skipped
WriteFile returned native1 in9.273028s with neither marker write nor flush
issued; ordinary recovery then completed in17.4603415s. A deliberately skipped
FlushFileBuffers returned native1 in8.0022936s after the marker write; ordinary
recovery then completed in15.3704614s. Both failure paths poisoned the journal,
left the source offline and created no success outputs. Both follow-ups used
their same active branches and verified HND/ReFS with1084bindings.

The [write case](../evidence/native-marker-ap2-write-error-20261102.json) and
[flush case](../evidence/native-marker-ap2-flush-error-20261102.json) pin their
native processes and independently copied metadata archives. They do not extend
AP2 results to RB2, HND2 or ABT2.

The other three marker states subsequently passed actual self-hash corruption,
VM TurnOff/reboot and ordinary recovery on the same damaged active branches.
No checkpoint restore occurred between each corruption and its recovery.

| Damaged peer | Ordinary recovery action | Native seconds | Result |
|---|---|---:|---|
| HND2 | verify_handoff | 9.264905 | ReFS handoff verified;1084 map bindings |
| RB2 | rollback | 9.4060466 | selected source restored and NTFS mounted |
| ABT2 | verify_aborted | 6.5163473 | closed rollback verified and NTFS mounted |

The [HND2](../evidence/native-marker-hnd2-corruption-20261102.json),
[RB2](../evidence/native-marker-rb2-corruption-20261102.json) and
[ABT2](../evidence/native-marker-abt2-corruption-20261102.json) receipts preserve
actual producer/recovery PID births, signal and power pins, result scope and
closed metadata archives. Rollback checks do not claim an additional semantic
re-enumeration or preservation of source-free bytes.

Together with AP2, all four second-peer corruption states now have native VM
results on clean runtime70c10cc. Synthetic WriteFile/FlushFileBuffers/ReadFile
failure coverage belongs to AP2 and the shared poison path. This does not enable
the production flag or qualify a later public build automatically.
