# Public run status and preactivation cancel

`operation-state` reads the public conversion run's pinned artifacts and
actual disk/journal observations. It changes no disk attributes, mounts,
source payloads or journal bytes. `state.json` distinguishes frozen source,
activated recovery, completed markers, mounted native filesystems and
unresolved/contended evidence. A successful status invocation means a report
was written; `can_request` lists commands whose own remaining checks must
still pass. The report grants no execution authority or current-image proof.

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
