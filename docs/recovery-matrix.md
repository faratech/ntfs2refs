# Recovery matrix

Written by `lab\Write-RecoveryMatrix.ps1` from the verdicts of the lab's interrupted
attempts (431 verdicts read, 75 of them interrupted and recovered). Do not edit it by hand:
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
| `apply-mid-ranges` | Half of the changed ranges are written, none of them flushed. | data volume, process-termination: 7 (latest `g2-lived-in-apply-mid-resume`)<br>Windows fixture, process-termination: 14 (latest `g2-apply-mid-resume-01`)<br>Windows fixture, vm-turned-off: 2 (latest `g2-vm-off-apply-mid-resume-01`) | data volume, process-termination: 5 (latest `g2-lived-in-apply-mid-rollback`)<br>Windows fixture (shaped), process-termination: 2 (latest `g2-used-windows-rollback-01`)<br>Windows fixture, process-termination: 5 (latest `z2-admin-rollback-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-apply-mid-rollback-01`) |
| `apply-ranges-written` | Every range but the boot granule is written, not yet flushed. | Windows fixture, process-termination: 1 (latest `m1-apply-ranges-written-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-ranges-written-rollback-01`) |
| `apply-before-boot-granule` | Those ranges are flushed; the NTFS boot sector is still in place. | Windows fixture, process-termination: 1 (latest `m1-apply-before-boot-granule-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-before-boot-granule-rollback-01`) |
| `apply-boot-granule-written` | The boot granule is written, not yet flushed. | Windows fixture, process-termination: 1 (latest `m1-apply-boot-granule-written-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-boot-granule-written-rollback-01`) |
| `apply-before-handoff` | Every new byte is written, flushed and read back; no handoff marker. | Windows fixture, process-termination: 1 (latest `m1-apply-before-handoff-resume-01`) | Windows fixture, process-termination: 1 (latest `m1-apply-before-handoff-rollback-01`) |
| `apply-handoff-durable` | The handoff marker is durable; the source is still writable. | Windows fixture, process-termination: 1 (latest `m1-apply-handoff-durable-resume-01`)<br>Windows fixture, process-termination, marker torn: 2 (latest `y-torn-handoff-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-handoff-durable-resume-01`)<br>did not recover: 1, listed below | Windows fixture, process-termination, marker torn: 1 (latest `y-torn-handoff-rollback-01`) |
| `handoff-sealed` | The source is sealed read-only again; finalization has not started. | data volume, process-termination: 5 (latest `g2-lived-in-handoff-sealed-resume`)<br>Windows fixture, process-termination: 12 (latest `g2-handoff-sealed-resume-01`) | not run |
| `finalize-authenticated` | Finalization has authenticated the handoff; the source is still sealed. | Windows fixture, process-termination: 1 (latest `q-finalize-authenticated-resume-01`) | not run |
| `finalize-source-readonly` | The converted source is mounted read-only for its verification. | Windows fixture, process-termination: 1 (latest `t-finalize-readonly-resume-01`)<br>Windows fixture, vm-turned-off: 1 (latest `g2-vm-off-finalize-readonly-resume-01`)<br>did not recover: 1, listed below | not run |
| `finalize-before-online` | Verification passed and the source is sealed again; not yet online. | Windows fixture, process-termination: 1 (latest `q-finalize-before-online-resume-01`) | not run |
| `finalize-online` | The converted source is online; its label and mount paths are not yet restored. | Windows fixture, process-termination: 1 (latest `q-finalize-online-resume-01`) | not run |

## Attempts that did not recover

| Attempt | Hold point | Recovery | Outcome | Note |
|---|---|---|---|---|
| `q-finalize-readonly-resume-01` | `finalize-source-readonly` | resume | recover-failed | reproduced issue #43 before its fix; t-finalize-readonly-resume-01 is the same row after it |
| `y-torn-handoff-older-build-01` | `apply-handoff-durable` | resume | recover-failed | ran the build from before the fix of issue #1 on purpose, to show that the fix is what recovers a torn marker |

## What these attempts do not show

- How the converter was interrupted: process-termination; vm-turned-off. The lab cannot cut power to the storage
  itself. A marker write cut short is made by hand (`-TearMarker`) once the process has ended; other
  torn writes are covered by the model tests (`tests\recovery_model.rs` and its siblings) only.
- Interrupted runs of the full Windows volume that recovered: 0.
- A stop during preparation is not in this matrix: nothing has been written to the source then, and
  the run is started again.
