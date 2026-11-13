# Preparing the read-only operation-state command

The optional Rust helper `ntfs2refs-state-command` removes the manual hashing
needed to inspect a public conversion run. It reads existing run JSON, prints
the exact present-file pins and a PowerShell command, and executes nothing.
It does not modify the frozen alpha executable or inherit its native qualification.

Run on Windows with an existing OS-volume run and a fresh state-output path
outside that preserved run:

```powershell
ntfs2refs-state-command --run-directory C:\ntfs2refs\runs\run-001 `
  --state-output C:\ntfs2refs\state\inspection-001 `
  --executable C:\ntfs2refs\bin\ntfs2refs.exe
```

The JSON's `powershell_command` calls only `operation-state`. Review it, then
run it with the reviewed converter in the elevated Windows context required
by [the public workflow](../cli-workflow.md). Each supplied pin hashes the artifact
file itself, including `qualification/source-frozen.json`; it is not the raw
partition hash recorded inside that file. Optional pins are included exactly
when their artifacts are present. Missing, malformed, oversized or redirected
artifacts refuse preparation; an existing output path is never reused.

The helper checks JSON syntax and file bounds, without interpreting device,
schema or lifecycle claims. The real `operation-state` command rechecks those
inputs against the owning machine. Command preparation authorizes no cancellation,
resume, rollback or finalization and cannot tell whether a worker has stopped.
If artifacts change before inspection, the pinned command must refuse; preserve
the run and determine the existing operation's status before preparing again.

The helper writes no files and does not verify or launch the executable supplied
with `--executable`. The state-output directory is created only by the later
`operation-state` invocation. Build this separate helper with
`cargo build --bin ntfs2refs-state-command`; the staged frozen alpha remains intact.
