# Public run status and preactivation cancel

`operation-state` reads the public conversion run's pinned artifacts and
actual disk/journal observations. It changes no disk attributes, mounts,
source payloads or journal bytes. `state.json` distinguishes frozen source,
activated recovery, completed markers, mounted native filesystems and
unresolved/contended evidence. A successful status invocation means a report
was written; `can_request` lists commands whose own remaining checks must
still pass. The report grants no execution authority or current-image proof.

The pinned artifacts are validated before anything is created. A wrong pin or
a missing run directory fails the command (exit 1) and leaves no output
directory behind; only an artifact held by another process still yields a
report, with state `busy`.

```powershell
ntfs2refs operation-state --run-directory C:\ntfs2refs\runs\run-001 `
  --intent-sha256 INTENT_FILE_SHA256 --frozen-source-sha256 FREEZE_FILE_SHA256 `
  --mount-paths-sha256 MOUNT_PATHS_FILE_SHA256 `
  --output C:\ntfs2refs\status\run-001
```

Paths are derived from the run directory: `conversion-intent.json`,
`qualification/source-frozen.json`, `qualification/source-mount-paths.json`,
and `request.json`/`ticket.json` when present. Every present input requires its
own file pin; add `--request-sha256` and `--ticket-sha256` for those later
artifacts. Use the independently retained trusted pins. The freeze-file pin is
different from the complete NTFS image hash recorded inside it. Legacy lab
abort schemas cannot replace the public `observed-frozen-source-identity`
artifact's actual `binding`, `state` and `source_sha256` fields.

`cancel` accepts the same envelope and a fresh output directory. It supports a
source still persistently offline/read-only (attributes 3) before activation.
It acquires the exact journal exclusively if present, rejects any mutable
reconstruction intent or handoff, and holds all pinned artifact handles open.
An exclusive physical source handle must then exclude an existing worker.
Through that same handle it verifies hardware identity, NTFS boot identity,
the full unchanged source hash and exclusion before restoring availability.
Only then can it clear exclusion, close the exclusive handle and restore/check
the original NTFS mount paths. Foreign occupied mount roots are refused.

```powershell
ntfs2refs cancel --run-directory C:\ntfs2refs\runs\run-001 `
  --intent-sha256 INTENT_FILE_SHA256 --frozen-source-sha256 FREEZE_FILE_SHA256 `
  --mount-paths-sha256 MOUNT_PATHS_FILE_SHA256 `
  --output C:\ntfs2refs\cancel\run-001
```

Worker failure or a JSON success flag alone cannot authorize cancellation.
Activated sources, changed bytes, ambiguous markers and unavailable evidence
remain refused. Failures preserve diagnostics and never trigger automatic
online retry, raw replay or rollback. Unit/schema/sharing tests cover these
contracts; native cancellation qualification must be recorded separately.

## Observed native handoff state and cancellation refusal

The public commands were exercised against the completed twelve-object public
run. `operation-state` exited 0 and reported `mounted_refs_after_handoff`.
`cancel` exited 1 with `postactivation artifacts prevent cancellation`.
The source remained online/writable ReFS at its original mount with label
`n2r-retained-source`. This qualifies that status/refusal case, not positive
preactivation cancellation or missing-shadow rollback.

Ignored evidence is
`.lab/hyperv/public-state/win11-20261026T012027660Z/observed.json`, SHA-256
`c53933167c5c7a73af3bf0e0144c44547deced23f0cd2d0549209b0a76ffb032`.
Future native cancellation tests must preserve before/after source hashes and
availability, and separately exercise wrong-device and activated-handoff
refusals on identified disposable fixtures.

## Positive native preactivation cancellation

On October 25, 2026, the enrolled 52 GiB NTFS fixture was exercised through the
current conversion core. A lab-only `--interrupt-after-source-freeze` worker
saved and flushed the actual public freeze artifact and interruption intent,
then exited87 before inspection, target construction, journal preparation or
activation. This is process-interruption qualification, not arbitrary storage
power-loss qualification. The production conversion command exposes no such
fault switch.

The exact task was observed terminal with no remaining process. Source disk
`a01574d5-2a5c-4136-958a-dcf0d0e0f7aa`, partition
`79eaccdf-38d3-4561-97cc-9276af5d223a`, remained attributes3. The frozen artifact
was the public `observed-frozen-source-identity` schema. There was no derived
request, ticket, journal-location, apply or handoff artifact; the shadow was
absent. Public status classified `frozen_before_activation` and allowed a
request for cancellation subject to its remaining checks.

The actual public `ntfs2refs cancel` command exited0. It acquired the exclusive
source lease, read all 55,834,574,848 partition bytes and matched the frozen
source SHA-256:

`27a9fec374c60679c7272b7f9aa3679603c0ceb10e9a3a6b730434e8ef71f348`.

It restored attributes3 to0, closed the source handle and verified the original
NTFS mount `F:\` and label `n2r-retained-source`. All four known user-file
lengths and logical hashes matched their pre-freeze manifest after writable
mounting. The whole-source hash scope is immediately before returning the
partition to writable NTFS; no whole-image-equality claim is made after NTFS
resumes its normal metadata writes.

A separate negative case changed the expected disk identity in clearly labeled
test artifacts while selecting the same owned source disk. The public command
exited1 with `GPT header or disk identity differs`; actual source attributes
remained3. Those altered artifacts are not producer evidence. The activated
handoff cancellation refusal recorded above remains a distinct tested case.

Ignored evidence:

- Original worker and durable exit87:
  `.lab/hyperv/certificate-conversion/win11-20261026T015735035Z`.
- Public cancellation and before/after logical-file comparison:
  `.lab/hyperv/public-cancel/win11-20261026T022520948Z`.
- Wrong-identity negative case:
  `.lab/hyperv/certificate-conversion/win11-20261026T015735035Z/wrong-identity-7b8a3c5b74dd42dcb7355c21217cc72a`.

`cancel/result.json` SHA-256 is
`4e8b7aafc6ce8309d1374d18a6c7d5d5d02d351224dd400ca81ed2fde11ebf93`;
`cancel/source-restored.json` SHA-256 is
`2a3a1bb47ba7ec6de821b3329c64e79d49cd4f1177ec69541cbefebabe9a243f`.

The public-cancel dispatch/collect scripts preserve exact artifact pins,
specific task identity, source state, original mount paths and the four-file
manifest for repetition. The run above used a separately recorded manual
dispatch; it is not retroactively claimed as a run of the new scripts.
The later public shadowless rollback qualification is recorded in
[the native results](general-native-conversion-results.md#public-shadowless-rollback-after-one-flushed-write).

## Cancellation after a real qualification refusal

The dispatch harness also accepts explicit `-Mode QualificationFailure` for a
collected shadow-construction refusal with a pinned zero-source-write report.
The default remains the exit87 source-freeze test. Both modes refuse any
derived request, journal, ticket, certificate or activation artifact, recheck
the original terminal task and use the ordinary public status/cancel commands.

This harness mode passed against the actual `tracking.log` source-profile
refusal from run `f912011005344294b2c9608990d9eb73`. Cancellation verified all
55,834,574,848 bytes against frozen SHA-256
`c777e66173998fba77dc588329a896edac5700d2a19889ed19febee3ef26c35e`
before restoring writable NTFS, `F:\`, the original label and all four user
file hashes. It did not modify the ReFS shadow or perform raw reconstruction.

Ignored evidence is
`.lab/hyperv/public-cancel/win11-20261026T035306614Z`:

- `collected.json`: `35f623aca9df8af398eecb67a797c67fa2b216ba29c30bbde23b05d3cabb29cf`.
- `cancel/result.json`: `3b0b9e0ebf6b5eb68f67baefd3883a57578dc8b6a3b320f35dbd2a2fbd5ddd23`.
- `cancel/source-restored.json`: `e2336640a193669a82d1b6f9b5768d09227d580e5e8f8b6ef26e5982562caf8d`.

Whole-image equality after the writable mount is not claimed. The later
missing-shadow rollback case is a separate qualification, recorded in
[the native results](general-native-conversion-results.md#public-shadowless-rollback-after-one-flushed-write).
