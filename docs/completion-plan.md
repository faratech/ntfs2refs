# Completion tracker

The finish line is the owner's functional goal in [#148](https://github.com/faratech/ntfs2refs/issues/148). The first release milestone is a signed, unpublished evaluation package with complete evidence. Publication, licensing and expansion of supported profiles are owner decisions.

## Reconciled baseline

`8249357cf492676204980bd82a95a25310fa9930` is the audited commit and the commit behind the existing `0.0.5` tag. The [main CI](https://github.com/faratech/ntfs2refs/actions/runs/45898738526) passed 16 jobs, including 13 deterministic native cases. That evidence applies to its own binaries.

The [signed rehearsal](https://github.com/faratech/ntfs2refs/actions/runs/45937912198) passed signing and all deterministic native cases. The public coordinator dispatched the [private job](https://github.com/faratech/ntfs2refs-qualification/actions/runs/45939700725) before failing on an unquoted JSON field list. The private job separately stopped because `reference-b` was running. Preserve both failures under their original request. Verify the new candidate's tag, commit and executable hashes throughout a fresh rehearsal.

The substantive work from #287, #288 and #291 is already on the audited `main`. Adapt the remaining integrity sampling change from [#301](https://github.com/faratech/ntfs2refs/pull/301) by its current diff. Keep the deterministic thorough-resume regression for seed `934383016`. Both ordinary verification modes already verify before handoff, and both major native walk reports already spill.

The plumbing change passed the workflow and private-coordinator checks, the existing release-evidence validator tests, and all locked workspace tests. Standing runs `rpl0036-fixture10` and `rpl0036-admin-fixture40` used the unchanged signed executables from rehearsal `45929856792-1` and matched their listings. A complete signed rehearsal still needs a new candidate and a reserved lab.

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

## Execution and verification

- Preserve the Windows-built shadow, source ownership and read-only boundaries, prewrite checks, byte comparison, strict manifests, and journal flush and readback order. Use the authenticated marker bytes and recorded lifecycle to decide rollback eligibility.
- For transformation recovery, bind the canonical affected object and stream identities and their source, consent and frozen-list commitments through the authenticated publication. Use a versioned, reopenable artifact and verify it before it can affect coverage. The human report is separate. Legacy forward recovery needs independently proven coverage, and rollback retains its journal and source checks.
- For each case record the commit and executable hashes, route and platform, verification mode, requested and reached hold, recovered result, manifest and integrity outcomes, cleanup result and retained evidence. Keep pre-preparation state, authorized preparation changes and the frozen rollback baseline distinct.
- Run locked workspace tests and the standing fixture gates before commits, and CI on the PR head before merging. Exercise native interruption boundaries on affected paths. Keep failed workload and resource observations, including admission refusals.
- Protect the lab's shared disk chains and checkpoints. Get approval for removal under `.lab` and for destructive physical tests on a designated device. Keep credentials in the established environments.
- A passing rehearsal requires the exact signed candidate to pass deterministic native checks, five full hosted soak profiles, private Hyper-V qualification, archive verification and provenance. Leave publication disabled for that milestone. Document remaining unqualified profiles and preserve historical evidence under its original build and mode.
