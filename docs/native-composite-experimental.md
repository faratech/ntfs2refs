# Experimental native composite workflow

The entry remains confined to the enrolled disposable Windows11 machine/disks.
It is not arbitrary-drive or boot-volume support. Conversion and recovery run
inside the machine owning the volumes; Hyper-V is laboratory infrastructure.

`lab-convert-native-composite` derives the source tree in its owning process,
retains the original observed freeze/live assessment, builds private native
ReFS metadata, materializes system streams/residuals, and compares the complete
source-backed target before source admission. It persists the compact old/new
journal and trusted ticket, verifies exact ranges, then activates/applies and
completes native handoff. Serialized reports cannot recreate source admission.

The mover's single submission limit is1024. App validation now shares that rule
and runs before output, source freeze or namespace allocation. Refused2ba889b7
supplied4096; app validation incorrectly accepted65536. Original refusal and
evidence remain atcfe0b326, all42 checkpoints retained, no source reconstruction.
The next run reuses the existing15-object/10-file source and its4,194,341-byte
nonzero file without moving source extents. All qualification is freshly issued.

## Recovery

Preserve the complete output and independent journal, especially:

- `request.json`, `ticket.json`, `expectation.json` and their SHA-256 pins.
- `compact-backing.json`, `qualification/composite-capture.json`,
  `qualification/changed-clusters.bin` and their actual file identities/pins.
- The journal path from `journal-location.json` and exact executable/source/
  build/target-driver fingerprints.

`lab-recover-native-composite --help` lists the explicit pinned input arguments.
Recovery cannot initiate a new Apply:

| Mode | Required state and result |
|---|---|
| `resume` | Activated offline source1/frozen shadow3; finish writes, keep offline. |
| `rollback` | Pre-handoff source1/shadow3; exact original, ABT, native NTFS check. |
| `finalize` | Exact complete unmarked ReFS target; HND before native mount. |
| `finalize-after-marker` | Complete HND with exact image/durability before mount. |
| `finalize-rollback` | Complete ABT with exact original/durability before mount. |

HND/ABT close old raw replay. Never clear a marker, force source attributes,
or replay over a filesystem changed by native use. A failed observer after
handoff does not authorize old patches. Before activation, original-source
abort requires pinned binding/freeze, state3 and complete original hash before
making NTFS writable. A reopened report is not a conversion certificate.

## Resources and qualification

Failed-run OS child4,139,778,048 bytes versus shadow136,314,880 locates most growth
in the test OS; it is not evidence of an8-GiB shadow copy. Exact OS file cause
remains unknown; pagefile statistics alone do not prove it. Read-only7-Zip
inspection failed to resolve a recorded base locator; the actual base exists.
No image was modified.

`CompactCapacity.psm1` separates OS highwater/margin, shadow, packed changes,
journal, source/native growth, recovery and evidence. Revised forecast7GiB is
neither a hard reservation nor continuous enforcement. Lab file-length budget
and actual host free space are separate checks, including before dispatch.

One authorized50,000,000,000-byte additional budget starts at279,374,052,988 lab
bytes. Maximum329,374,052,988 and16-GiB host-free floor stay fixed across attempts;
starting another run must not reset the baseline.

Historical fixed-fixture results remain distinct. Fresh construction, ownership
transfer and all release gates on one pinned current build remain unqualified
until native runs pass. Startup refusals and compilation do not substitute.
