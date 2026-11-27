# Completion tracker

The finish line is the owner's functional goal in [#148](https://github.com/faratech/ntfs2refs/issues/148). The first release milestone is a signed, unpublished evaluation package with complete evidence. Publication, licensing and expansion of supported profiles are owner decisions.

## Reconciled baseline

`8249357cf492676204980bd82a95a25310fa9930` is the audited commit and the commit behind the existing `0.0.5` tag. The [main CI](https://github.com/faratech/ntfs2refs/actions/runs/45898738526) passed 16 jobs, including 13 deterministic native cases. That evidence applies to its own binaries.

The [signed rehearsal](https://github.com/faratech/ntfs2refs/actions/runs/45937912198) passed signing and all deterministic native cases. The public coordinator dispatched the [private job](https://github.com/faratech/ntfs2refs-qualification/actions/runs/45939700725) before failing on an unquoted JSON field list. The private job separately stopped because `reference-b` was running. Preserve both failures under their original request. Verify the new candidate's tag, commit and executable hashes throughout a fresh rehearsal.

The substantive work from #287, #288 and #291 is already on the audited `main`. Adapt the remaining integrity sampling change from [#301](https://github.com/faratech/ntfs2refs/pull/301) by its current diff. Keep the deterministic thorough-resume regression for seed `934383016`. Both ordinary verification modes already verify before handoff, and both major native walk reports already spill.

The plumbing change passed the workflow and private-coordinator checks, the existing release-evidence validator tests, and all locked workspace tests. Standing runs `rpl0036-fixture10` and `rpl0036-admin-fixture40` used the unchanged signed executables from rehearsal `45929856792-1` and matched their listings. A complete signed rehearsal still needs a new candidate and a reserved lab.

The hosted-verdict change shares its pass policy across the runner and consumers. The archive checks the four-hour campaign receipt and all 111 ordinary Hyper-V gate cases. In disposable Server run `hosted-verdict-005012`, the clean signed-binary round matched its listing and passed with a completed event query. The deliberate event-query failure exited 1 after an identical listing, with before/after manifests and verified private failure material retained by the runner. The public release evidence tests exercise event and cleanup failures, missing gate cases, and incomplete or modified soak logs. Both standing fixtures in `hrv0100` matched their listings using the shared case inventory and signed executables from `45929856792-1`.

## Work and evidence

| Package | Depends on | Remaining acceptance |
| --- | --- | --- |
| Baseline and scope | | Reconcile current main, native evidence, route contracts, and open owner choices. Update this tracker before claiming a package complete. |
| Release plumbing | Baseline | Full action pins, one argument for the CLI JSON field list, exact request matching, preserved private failure diagnostics, and a reserved idle lab. |
| Test verdicts and retention | Baseline | Soak, native and release consumers agree on integrity, observation, cleanup and retention, with complete exact-build evidence. |
| Transformation recovery facts | Baseline | Authenticated immutable dispositions, journal-proven rollback despite damaged optional reports, legacy compatibility and separate-process interruption cases. |
| Transformation acceptance | Verdicts, recovery facts | Exact content, consent, resource failure and recovery for each claimed provider and feature. Synthetic fixtures establish only their tested properties. |
| Lifecycle completion | Verdicts, recovery compatibility | Versioned partition late handoff with read-only verification, durable interruption proof, and preserved sibling and boot restoration. |
| Integrity controls | Verdicts | Valid matched controls, retained failures, and confirmed workload overlap. Keep native crash [#324](https://github.com/faratech/ntfs2refs/issues/324) distinct from historical event 131 [#253](https://github.com/faratech/ntfs2refs/issues/253). |
| Bounded resources | Stable baseline, measured workloads | Matched 100k, 500k and 2m results, including separate-process recovery, at a stated finite floor. Bound required memory and handles while preserving identity, exclusion and complete validation. |
| Platform and physical storage | Applicable feature, lifecycle, integrity and resource gates | Candidate-bound profile evidence, larger workloads, and controlled tests on owner-designated disposable physical devices. |
| Product and release | All applicable prerequisite packages | Accurate user contract, generated candidate-specific matrices, complete signed gates, and a verified unpublished package. |

### Transformation recovery evidence

Server 2025 attempts `rfacts-013304-v4-svi-resume` and `rfacts-013304-v4-svi-rollback`
matched their independent listings after new-process recovery with a malformed
optional report. The v4 resume recorded three SVI omissions. A separate
`rfacts-damage-014127` worker refused a truncated authoritative artifact and
resumed after the original bytes were restored. Legacy publication attempts
`rfacts-013304-v1-ordinary-resume` and `rfacts-013304-v1-svi-rollback` also matched
their independent listings. The development converter SHA-256 was
`ad386e88ec2c9f388dbed77b2304eb729aefc5d177ea48211e261e3368040305`.
The Server fixture refused to create WOF content through `compact.exe`.
Windows fixture round `arf0136` passed all five cases with the same converter.
It included separate workers at mid-apply, the recorded apply seal, and
the sealed handoff.

Windows 11 attempts `rfacts-wof-015451-resume` and
`rfacts-wof-015451-rollback` used the same build. They passed strict
listing comparison with a malformed optional report. The resume verified
all four WOF compression algorithms, and rollback restored exact NTFS.

### Integrity evidence

The development run `completion-integrity-020116-event-131` matched its
independent listing, ran the 4,000-entry workload, remounted five times
and verified post-reboot writes. Completed host hash batches fell inside
both the fill-and-delete and remount windows after applying measured clock
bounds. Windows reported no serious ReFS events or guest bugcheck in this
run. The disposable guest rebooted with its small-dump configuration and
a system-volume pagefile. Actual dump retention still needs a bugcheck
sample. Native idle control `completion-native-control-032528-idle`
also passed five remounts and the reboot checks. The historical event 131
and earlier native control failures remain open.

### Payload and resource evidence

Windows 11 build 26300 converted all 500,511 objects in
`completion-scale-client-500k-042355` to a 4 KiB Dev Drive with an identical
listing. The baseline converter SHA-256 was
`ad386e88ec2c9f388dbed77b2304eb729aefc5d177ea48211e261e3368040305`.
Conversion took 1,809.6 seconds. Its samples reached 986,651 handles,
4,024 MiB private bytes, 3,657 MiB working set and 17,871 MiB of logical
working files. The host ran other engineering work during the experiment.
The result confirms native correctness for this sample and records its
resource use. Matched timing and explicit-ceiling recovery are still due.

The single-file payload development build used SHA-256
`68c28a9eab5e7ae3da27c1cd14e91dd95a88bcf83a181dbc1892603ab3e70d27`.
Round `completion-payload-043148` passed WOF resume and rollback, Cloud
Files resume, provider-down refusal and resume with two approved omissions.
The recovered listings matched, including the cases with a malformed
optional report. This build removes the per-copy handle and repeated
disposition-map clones. Required namespace and constructor state still
grow with the object count.

Windows gate `pp0441` matched the listings for both baseline fixtures,
the lived-in data case, 512-byte NTFS clusters and 4Kn sources to both
target cluster sizes, and the full Windows volume. The original Windows
installation reached the desktop from disk 0 alone with Secure Boot on.
C: was partition 3 on ReFS 3.14 with 4 KiB clusters, and both the loader
and ReFS driver had valid Microsoft signatures.

## Execution and verification

- Preserve the Windows-built shadow, source ownership and read-only boundaries, prewrite checks, byte comparison, strict manifests, and journal flush and readback order. Use the authenticated marker bytes and recorded lifecycle to decide rollback eligibility.
- For transformation recovery, bind the canonical affected object and stream identities and their source, consent and frozen-list commitments through the authenticated publication. Use a versioned, reopenable artifact and verify it before it can affect coverage. The human report is separate. Legacy forward recovery needs independently proven coverage, and rollback retains its journal and source checks.
- The dedicated recovery opener currently calls `new_tree_objects()` while validating the publication, before it branches into resume or rollback. That count uses declared omissions. Move authority off the CLI report loader and separate the transform-dependent target checks from the legacy rollback path, keeping the published envelope, expected-store, source, locator and journal checks intact. Cover omitted objects as well as dropped streams in the interruption cases.
- For each case record the commit and executable hashes, route and platform, verification mode, requested and reached hold, recovered result, manifest and integrity outcomes, cleanup result and retained evidence. Keep pre-preparation state, authorized preparation changes and the frozen rollback baseline distinct.
- Run locked workspace tests and the standing fixture gates before commits, and CI on the PR head before merging. Exercise native interruption boundaries on affected paths. Keep failed workload and resource observations, including admission refusals.
- Protect the lab's shared disk chains and checkpoints. Get approval for removal under `.lab` and for destructive physical tests on a designated device. Keep credentials in the established environments.
- A passing rehearsal requires the exact signed candidate to pass deterministic native checks, five full hosted soak profiles, private Hyper-V qualification, archive verification and provenance. Leave publication disabled for that milestone. Document remaining unqualified profiles and preserve historical evidence under its original build and mode.
