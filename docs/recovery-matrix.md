# Recovery matrix

Written by `lab\Write-RecoveryMatrix.ps1` from the verdicts of the lab's interrupted
attempts (929 verdicts read, 125 of them interrupted and recovered). Do not edit it by hand:
run an attempt and write it again.

Each attempt stops the converter at a named point (`--lab-hold-at`), ends it, runs
the recovery command the run printed, and compares the volume's listing: after a
resume with the listing before the conversion (the converted volume must be
identical under the allowances a conversion has), after a rollback with `--exact`
(the NTFS volume must list exactly as before). A cell counts the attempts that
ended that way, by what was converted and how it was interrupted.

| Hold point | State of the source there | Resume | Rollback |
|---|---|---|---|
| `apply-activated` | The apply marker is durable and the source is writable; nothing written. | Windows fixture, process-termination: 1 (latest `m1-apply-activated-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-activated-rollback-01`) |
| `apply-mid-ranges` | Half of the changed ranges are written, none of them flushed. | data volume on a shared disk, process-termination: 4 (latest `d9s-shared-apply-resume`)<br>data volume, process-termination: 17 (latest `c7-casemark-resume`)<br>Windows fixture, process-termination: 17 (latest `d9-apply-mid-resume-01`)<br>Windows fixture, vm-turned-off: 3 (latest `r2-vm-off-apply-mid-resume-01`)<br>Windows, full volume, vm-turned-off: 1 (latest `r2-full-vm-off-apply-mid-resume-02`)<br>did not recover: 1, listed below | data volume on a shared disk, process-termination: 4 (latest `d9s-shared-apply-rollback`)<br>data volume, process-termination: 12 (latest `c7-casemark-rollback`)<br>Windows fixture (shaped), process-termination: 2 (latest `g2-used-windows-rollback-01`)<br>Windows fixture, process-termination: 6 (latest `r2-apply-mid-rollback-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-apply-mid-rollback-01`)<br>Windows, full volume, vm-turned-off: 1 (latest `g2-full-vm-off-apply-mid-rollback-01`)<br>did not recover: 1, listed below |
| `apply-ranges-written` | Every range but the boot granule is written, not yet flushed. | Windows fixture, process-termination: 1 (latest `m1-apply-ranges-written-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-ranges-written-rollback-01`) |
| `apply-before-boot-granule` | Those ranges are flushed; the NTFS boot sector is still in place. | Windows fixture, process-termination: 1 (latest `m1-apply-before-boot-granule-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-before-boot-granule-rollback-01`) |
| `apply-boot-granule-written` | The boot granule is written, not yet flushed. | Windows fixture, process-termination: 1 (latest `m1-apply-boot-granule-written-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-boot-granule-written-rollback-01`) |
| `apply-before-handoff` | Every new byte is written, flushed and read back; no handoff marker. | Windows fixture, process-termination: 1 (latest `m1-apply-before-handoff-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-before-handoff-rollback-01`) |
| `apply-handoff-durable` | The handoff marker is durable; the source is still writable. | Windows fixture, process-termination: 1 (latest `m1-apply-handoff-durable-resume-01`)<br>Windows fixture, process-termination, marker torn: 2 (latest `y-torn-handoff-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-handoff-durable-resume-01`)<br>did not recover: 1, listed below | Windows fixture, process-termination, marker torn: 1 (latest `y-torn-handoff-rollback-01`) |
| `handoff-sealed` | The source is sealed read-only again; finalization has not started. | data volume on a shared disk, process-termination: 4 (latest `d9s-shared-handoff-resume`)<br>data volume, process-termination: 12 (latest `c9-plain-handoff-resume`)<br>Windows fixture, process-termination: 15 (latest `d9-handoff-sealed-resume-01`)<br>did not recover: 1, listed below | did not recover: 1, listed below |
| `finalize-authenticated` | Finalization has authenticated the handoff; the source is still sealed. | Windows fixture, process-termination: 1 (latest `q-finalize-authenticated-resume-01`) | not run |
| `finalize-source-readonly` | The converted source is mounted read-only for its verification. | Windows fixture, process-termination: 1 (latest `t-finalize-readonly-resume-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-finalize-readonly-resume-01`)<br>did not recover: 1, listed below | not run |
| `finalize-before-online` | Verification passed and the source is sealed again; not yet online. | Windows fixture, process-termination: 1 (latest `q-finalize-before-online-resume-01`) | not run |
| `finalize-online` | The converted source is online; its label and mount paths are not yet restored. | Windows fixture, process-termination: 1 (latest `q-finalize-online-resume-01`) | not run |

## The full Windows volume

The rows above count these too. An outcome ending in `BOOTED-ON-REFS` or `BOOTED-ON-NTFS` means that,
after the recovery, the disk was started alone with Secure Boot on and reached the desktop on that
file system; `NOT-BOOTED` means the attempt was run without its boot step.

| Attempt | Hold point | Interrupted by | Recovery | Ended as |
|---|---|---|---|---|
| `g2-full-vm-off-apply-mid-rollback-01` | `apply-mid-ranges` | vm-turned-off | rollback | ROLLED-BACK-BOOTED-ON-NTFS |
| `r2-full-vm-off-apply-mid-resume-02` | `apply-mid-ranges` | vm-turned-off | resume | RESUMED-BOOTED-ON-REFS |

## Stopped during preparation

Until a run prints its recovery command it has written nothing to the source, but it holds the
volume offline and read-only. These attempts end the converter's process in a named phase of
preparation and then do one of two things. "cancel" runs what the run printed for this case at its
start, `--recover <directory> --recovery-sha256 <preparation checksum> --rollback`; the NTFS volume
must then be back and list exactly as before. "restart" starts the same conversion again as if
nothing had happened.

| Phase | The stop left the volume | Then | Ended as | Attempts |
|---|---|---|---|---|
| `payload_supply` | offline or read-only | cancel | preparation-cancelled | 10 (latest `d9s-shared-stop-cancel`) |
| `payload_supply` | offline or read-only | restart | restart-refused-then-cancelled | 3 (latest `p5-stop-supply-restart`) |
| `recovery_journal` | offline or read-only | cancel | preparation-cancelled | 3 (latest `p5-stop-journal-cancel`) |
| `recovery_journal` | offline or read-only | restart | restart-refused-then-cancelled | 3 (latest `d9-shared-stop-restart`) |

Attempts that ended otherwise:

| Attempt | Phase | Then | Outcome | Note |
|---|---|---|---|---|
| `r1-stop-supply-cancel` | `payload_supply` | cancel | harness-error | a fault of the harness, which put the cancel command together on the host; r2-stop-supply-cancel is the same row with the command the run prints |
| `r1-stop-journal-cancel` | `recovery_journal` | cancel | harness-error | the same fault of the harness; r2-stop-journal-cancel is the same row without it |
| `r1-stop-supply-restart` | `payload_supply` | restart | restart-refused-source-not-returned | the build before the fix of issue #95: the new run was refused with "letter has absent/ambiguous/unsupported volume mapping" and nothing named the way back; r2-stop-supply-restart is the same row after it |

## Attempts that did not recover

| Attempt | Hold point | Recovery | Outcome | Note |
|---|---|---|---|---|
| `q-finalize-readonly-resume-01` | `finalize-source-readonly` | resume | recover-failed | reproduced issue #43 before its fix; t-finalize-readonly-resume-01 is the same row after it |
| `y-torn-handoff-older-build-01` | `apply-handoff-durable` | resume | recover-failed | ran the build from before the fix of issue #1 on purpose, to show that the fix is what recovers a torn marker |
| `d5-shared-apply-resume` | `apply-mid-ranges` | resume | resumed-but-siblings-changed | a fault of the harness: the recovery finished and the volumes beside the source were back with identical bytes, but the harness looked for its earlier listing of one of them in the recovery's working folder; d6-shared-apply-resume is the same row without it |
| `d5-shared-apply-rollback` | `apply-mid-ranges` | rollback | rolled-back-but-siblings-changed | the same fault of the harness; d6-shared-apply-rollback is the same row without it |
| `d5-shared-handoff-resume` | `handoff-sealed` | resume | resumed-but-siblings-changed | the same fault of the harness; d6-shared-handoff-resume is the same row without it |
| `d5-shared-handoff-rollback` | `handoff-sealed` | rollback | rollback-failed | asked for what recovery refuses by design: after the handoff a rollback is closed, and the run said so ("Run the recovery command without --rollback to finish the conversion") |

## What these attempts do not show

- How the converter was interrupted: process-termination; vm-turned-off. The lab cannot cut power to the storage
  itself. A marker write cut short is made by hand (`-TearMarker`) once the process has ended; other
  torn writes are covered by the model tests (`tests\recovery_model.rs` and its siblings) only.
- A machine that loses power while a run prepares: the stops during preparation end the converter's
  process, and the guest's unflushed writes survive that.
