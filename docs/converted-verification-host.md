# Host orchestration for protected native verification

The prepared fixture's first protected mount and subsequent clean reboot/remount
have passed; see [native results](native-conversion-results.md). Default mode is
`first-mount`. `-Mode clean-remount` additionally requires
`-PriorVerificationResultPath` and `-PriorVerificationResultSha256` for a completed
first native observation rooted in the same Prepare/Apply/Handoff chain.

Clean remount restores that observation's converted checkpoint and starts the
guest with its persistent target read-only state. It skips shadow attachment
and the first-mount boundary, then runs the unchanged native observer in a new
guest session. The old mount artifact supplies historical provenance; live
protection and disk/file identity are rechecked by the observer. The result
records `mountEvidenceReused:true`, `mountBoundaryInvoked:false` and separate
status `retained-A-clean-remount-readonly-checkpointed`. An observed mismatch
preserves the branch without repairing protection or replaying reconstruction.

Prior source archives are authenticated using `sourceHashes` inside the pinned
completed host result. The archived review manifest was reserialized by the
older runner, so its byte hash differs from the original review-input hash.
The latter remains recorded as provenance and is never substituted with a
normalized-byte hash. Current execution still requires its own exact reviewed
manifest. The remount mode/predecessor and actual-archive tests add 171 checks
in each PowerShell runtime to the existing host/decoding coverage.

`scripts/Invoke-LabConvertedVerification.ps1` runs one reviewed post-handoff
experiment. It performs no reconstruction, replay, rollback, filesystem format
or writable target mount. All target/virtual-disk operations remain inside the
guest's separately reviewed mount helper. Root alone executes this runner.

Required inputs are `PrepareResultPath`/`PrepareResultSha256`,
`ApplyResultPath`/`ApplyResultSha256`, `HandoffResultPath`/`HandoffResultSha256`,
and `ReviewedSourcesPath`/`ReviewedSourcesSha256`. Paths must be ordinary files
inside the workspace's lab tree. The source manifest is schema 1, kind
`converted-verification-reviewed-sources`, with exactly the seventeen
`{path,sha256}` entries returned by `Get-CVSources`; it pins the runner, shared
host/guest guards, lab module and guest implementations. Sources are archived
and rehashed before starting the VM. No guest script top-level code runs on the
host; shared guards are imported by exact function names.

The protected attachment helper and mount-native helper are pinned to the
completed probe's reviewed implementations. The shared host guard verifies
provider write protection before any new exclusion attribute request, the exact
request and final state, unchanged backing bytes, and preserved original target
identity/state. The mount evidence must also report a V2 read-only VHD opener.
These checks establish current protection; they do not qualify shadow attribute
persistence.

Only an explicit successful Prepare → Apply → Handoff chain is accepted. The
runner checks independent result/process/ticket/request hashes, each predecessor
checkpoint, the originally pinned source/shadow preparation and complete native
raw proof, and rederives the reconstruction request. It does not accept Resume
as an implicit substitute. The entire target must already have passed Apply's
postimage checks and the durable Handoff must already be complete. Evidence
cannot authorize reconstruction after this boundary.

Starting from the exact installed-clean VM off at 4 GiB, the runner requires
the pinned Handoff checkpoint off at 8 GiB, enrolled original three host disks,
Secure Boot and disconnected networking, with 2 GiB extra capacity reserved.
It restores only that checkpoint, starts the guest at its saved 8 GiB, and:

1. Reattaches the existing shadow in Excluded mode; exports completed evidence.
2. Closes that known-complete PowerShell Direct session and opens a fresh one.
   Runs the pinned read-only mount boundary; exports and verifies `mount.json`
   before proceeding. The guest detaches the shadow, proves its absence, and
   protects the original target before bringing it online.
3. Closes the completed mount session and opens another fresh session. Stages
   only a new hash-bound `input.json` in the verifier's unique C: evidence
   directory, then invokes the frozen native observer exactly once.
4. Exports all bounded artifacts and checks the full input/mount/phase linkage,
   two 64 KiB A hashes, original GPT/shadow filesystem identities, expected
   native snapshot coverage and stable raw query hashes across four snapshots.

The attachment export has one JSON file ≤1 MiB; mount has one JSON file ≤2 MiB.
Verification has at most 203 files: input ≤64 KiB, intent ≤16 KiB, result ≤2 MiB,
and up to 200 query buffers ≤64 KiB each and ≤4 MiB combined. Zero-length native
error responses are retained. Native query refusal status is preserved rather
than changed to success; expected error 19 protection and error 18 directory
termination remain part of the evidence. Every export is checked before and
after copying. No full partition capture occurs here.

Any failure preserves the running branch and session; unknown transport and
unknown native completion remain separate sticky states. There is no catch or
finally shutdown, restore, handle repair or journal recovery. Only complete
verified success permits clean guest shutdown, a new off-state 8 GiB checkpoint
`converted-readonly-<observationId>`, then restoration of the original off-state
4 GiB baseline. The changed outcome checkpoint remains available for explicit
follow-up testing.

Host success is `retained-A-observed-readonly-checkpointed`, with
`retainedNativeObservationVerified:true`, `conversionQualified:false` and
`bootQualified:false`. This would show native ReFS exposing the bounded fixture
on the original target after raw reconstruction. It would not qualify arbitrary
NTFS features, general conversion, crash recovery after handoff or bootability.
Clean remount and an independently reviewed allocation follow-up remain separate
experiments. See the [guest verification contract](native-retained-postconversion-verification.md).

`lab/Test-LabConvertedVerification.ps1` exercises pure predecessor, source,
artifact, snapshot/intent and failure-preservation guards and a mocked fresh
session boundary. It performs no VM or device operation. `-WhatIf` returns
before reading inputs, importing the lab module or creating evidence.
