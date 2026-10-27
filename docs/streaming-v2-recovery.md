# Streaming interruption and recovery branch

The passed Unicode/4 GiB+1 conversion remains preserved OFF at
`157284d6-91fc-4b2b-ba6c-3052a0c413bc`, with converted parent
`8d4b9eaa-d814-4a3a-aa89-056e817d47d2`. All five original streaming checkpoints
remain. Only this owned VM was returned to its own NTFS baseline
`775f4db8-8635-486c-b6eb-7098426b51a6` for a separate recovery branch.
`Prepare-StreamingV2RecoveryBranch.ps1` recorded the preserved IDs and capacity
before a single restore. A fresh process confirmed OFF/baseline afterward.

Candidate 4 is run `61d60b73d23b48dcb7e777328169ddc9`, task
`N2R-StreamingV2Convert-61d60b73d23b48dcb7e777328169ddc9`. It was dispatched
once at 20:26:30 UTC. Request SHA-256 is
`eeb8e225804146a9f3937b7260b7a985dea463a64d098f9a585eb92a078f0599`.
Its source is `caf9853d3f2b3aab05f5db954ec9a8cfefe45b21` plus the unchanged
capabilities-only dirty patch digest
`d99591b5f26b887b513260cf01b8e89d114cb173fa86d40869a1053518d313e9`.

| Executable | SHA-256 |
| --- | --- |
| Controlled producer | `a5e557d422fa73faba8e6a2683182a3b60536be61714f9e38684c891366a44e8` |
| Public converter | `90564c534d41a6fd58b7f01d1e758dd7b7fde070bd1a79e3c79d84729316ad19` |
| Binder | `b306ea3f2a0474c4e0612369d8f233ed4acd4a6023d92b5967a23232341d7db1` |
| Recovery | `595b5138a03076a7d4453df51c2a54697a27d018ee25daca58dcdf72f0e99f22` |

This producer includes the CNG source/target brackets and journal-comparison
hashing, with full Rust comparison rechecks. It does not include the later
tree-wide planning-bitmap cache. The controlled guest-only entry will exit 86
after one complete, flushed target write, before handoff. That endpoint exists
only in the lab executable; ordinary conversion does not expose this switch.
Task registration and host dispatch/request pinning now precede task start.
An uncertain start must be observed through that same task, never redispatched.

PID 4120 was observed live, first in source admission and then target
preservation, with its actual creation time, I/O, CPU and working-set counters.
The dedicated collector recognizes the controlled executable. No interruption,
resume, rollback or power-loss outcome has been established yet.

After actual exit 86 and terminal evidence collection, preserve the partial
excluded branch before recovery. Verify exclusion through a guest restart.
`Dispatch-StreamingV2Recovery.ps1` is a separate explicit dispatcher for Resume,
Finalize or Rollback. It uses the interrupted run's original staged/pinned
recovery executable and independently pinned archived request/ticket/expectation
and journal locator. It requires the exact source offline/writable, shadow
offline/read-only, independent journal online, and no active worker. Finalize
additionally requires a completed excluded Resume. Each operation uses fresh
outputs and a dispatch record persisted before start; no retry, disk-attribute
repair, detach, checkpoint restore or automatic fallback is provided.
Native recovery itself revalidates journal state, complete hashes and actual
device identities; the dispatcher's JSON checks confer no raw write authority.
Do not run recovery over any branch that crossed handoff.

No unit tests were added or run. Source syntax/build checks are not native
interruption/recovery qualification. Keep the completed native conversion case
separate from this experiment and from subsequent builds.

The same producer subsequently completed source/target qualification and entered
journal preparation. Its native CNG comparison pass completed and the existing
Rust full-source recheck was observed live; no recovery result or interruption
is inferred from that intermediate state. Use the recorded task/PID, not a new
dispatch, until it becomes terminal.

`Preserve-StreamingV2Interruption.ps1` requires exit 86, the verified terminal
archive, no completed apply/handoff and the expected persistent disk flags. It
performs only a clean shutdown and OFF checkpoint. The new
`Restart-StreamingV2Interrupted.ps1` records a single boot and confirms the same
excluded source/shadow and terminal producer afterward, without source mount
attempts by the controller. Resume and snapshot-forked rollback use separate
reboot receipts. The 2 GiB restart/recovery forecast creates no new shadow or
payload and is based on roughly 1 GiB observed growth for the same VM's earlier
two-boot/mutation child; the global 224 GiB cap and 64 GiB free reserve remain.

Recovery dispatch additionally requires that matching successful exclusion
receipt. Observe an already dispatched operation with
`Collect-StreamingV2Recovery.ps1`; it reads the recorded task, process counters,
terminal results and live disk protection without restarting or repairing it.
These controllers have syntax checks only until actual execution. No unit
tests were added or run.

The producer reached its controlled boundary: task Ready, exit 86 and no worker.
The complete terminal archive contains 32 hash-verified files, manifest SHA-256
`08a9c88f2dd948c027e259b0390ae76fb9be0f470269eef9050a0084fbc1a3ed`.
The partial pre-handoff branch was shut down cleanly and saved OFF as checkpoint
`713e5fad-45fe-4200-9f6c-dabb669cc9ad`, parent the original NTFS baseline.
The interrupted source stayed offline/writable and shadow offline/read-only.
The journal is 679,651,453 bytes, immutable SHA-256
`f044017d8e76428e6c1f1ed889804e59623657ecebab4d9111eba171d83af75f`;
314 patches cover 339,795,968 bytes. Source preimage is
`097e11106a058e6a8acc0238bad00347761173161c95f11ea86fab081b6517c0`,
expected target `6fa71cb5281c1af88334260bd453eb8887996596f83f9f08498efe7493a08383`.

A single new guest boot at 20:55:14 UTC preserved both exclusion states and
producer exit 86 without another worker. The controller attempted no source
mount or flag change. The first resume-dispatch invocation stopped on a
PowerShell shorthand filter error before task registration/start; the filter
was fixed and no boot was repeated. Resume was then dispatched once at
20:56:58 UTC using recovery binary
`595b5138a03076a7d4453df51c2a54697a27d018ee25daca58dcdf72f0e99f22`.
Task `N2R-StreamingV2Recover-Resume-61d60b73d23b48dcb7e777328169ddc9`,
PID 5052 created 20:56:59 UTC, was observed live validating journal/normalized
target and shadow. No completed resume, finalize or rollback outcome is claimed.
Observe that exact task with `Collect-StreamingV2Recovery.ps1 -Operation Resume`.

Resume subsequently exited 0. Its complete target hash matched
`6fa71cb5281c1af88334260bd453eb8887996596f83f9f08498efe7493a08383`;
the source remained offline and the shadow offline/read-only. The result hash
is `e23659bff751ebef9685b045e735b0f7fc7e7ced00a849dda574f600e65a454a`.
Its execution/result artifacts are retained under `recovery-resume/Resume-terminal`.
The execution report records 314 patches/339,795,968 bytes written and no
handoff. This proves completed excluded resume, not a mounted ReFS result.

Explicit Finalize was dispatched once at 21:05:13 UTC with the same original
recovery executable, qualified request pin
`a1bef54f9077bf5cec9602f5ef98a25b56cdd228b0cfe7c94f45b20044395d25`,
ticket `947f6398ebd729ce11ab8f0eee6a0a881a833ddbba7e817222bf6a8e1575fd4b`
and expectation `bdfd26773a07cd54e365eebaff2170d65b9b6ecd6e038d446b5eea23bd2342e7`.
Task `N2R-StreamingV2Recover-Finalize-61d60b73d23b48dcb7e777328169ddc9`,
PID 580 created 21:05:14 UTC, was observed live in finalization validation.
No final handoff/native result is claimed until that task becomes terminal.
Never replay the old journal after a successful handoff; preserve this branch
before any separate snapshot-forked rollback case.
