# Experimental native composite workflow

## Recorded fresh conversion and native checks

Run `ac098b7437e04d2d928bc2e18f3b5218`, converter
`5e156f089b0fc6a67788154e841a74daad4a61028b16ea41391dc8f84e06f524`,
passed genuine live admission,157 source patches/70,557,696 bytes, and exact
pre-mount ReFS image
`7c1486aec258e9d2d2075ec6e6cd7230f4ae011388b61a789aba1be4a00d67d1`.
Native ReFS verified15 objects/10 full file hashes, label and mount paths.
Journal141,149,789 bytes; peak converter working set68.8MiB, VM fixed4GiB.
Shadow supplied55 user exception bytes and20,568 system bytes; full-cluster
user payload came from the source-backed image.

Cold-boot readback,50→80→10MiB create/grow/truncate/rename/delete workload with
128 entries, after-mutation readback and post-mutation reboot readback passed.
Converted43=`66a34221-06d3-4042-8739-8e48a9977171`; final44=
`2720f72d-5565-4b7a-aff8-378d24b65a4d`. Both/all prior snapshots are preserved.
An initial reboot guard matched bare old PIDs and refused before observation;
the fix uses original-wrapper creation identity/worker names. The completed
existing boot was observed once; no extra reboot and no erased refusal.
Original checkpoint parent receipts have an authoritative lineage correction.

Pins under `compact-admitted-retry-20261028/admitted-postcheck`:

| Report | SHA-256 |
|---|---|
| finalization | `815faadbf6ad44ef03cf2aa70bc8ee0e04f9e903fe3072fdfa2c30fb80be500a` |
| cold boot | `e1f6982e0aa2cfc5d85e6b44c875ca1837820772cc12a856f691c32bbfdb3d34` |
| mutation | `f58faf21bf001490b8bb3e33a47639ada5ace1c6b18113bd397ba3a9ff026419` |
| after mutation | `ba4bdf795571aa84afb4a8907b4dfe1dc25e0246256b8443c057c4b94cad649f` |
| reboot after mutation | `6a92fd659966fa9f4b3ff3196fed334843e5d900ed08a397b7396381597c6686` |

Pinned-report byte accounting observed2,721,181,696 aligned user bytes at the
same physical locations and5,873,209,344 at different locations, plus17 resident/
38 tail bytes. The nonzero file retained all4,194,304 aligned bytes;37-byte tail
was materialized. SVI is excluded. Zero-filled content can change mappings
without payload rewriting when destination bytes match. The67.3MiB write count
therefore does not prove small scratch for arbitrary nonzero data. This mapping
report describes finalization's native observation before later label/activity,
not current layout, write history or recovery authority. Report SHA
`d6e2c2a2961df07d654c45719047483de9d69cbb55ac9c40be2672e45b80ed21`.
The controlled interruption and separate resume/rollback branches also passed;
their scope and pins are recorded below.

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

### Recorded controlled interruption and recovery

The same pinned converter stopped with exit86 after one flushed source patch
in run `949dbc98138e4514a1098081eb0226ef`. Both source and shadow stayed offline.
The saved partial checkpoint is `554482bb-f2a4-4185-8023-09d60465137f`.
This was deliberate process interruption, not a storage power-loss experiment.

Recovery executable
`d48a46b13d9a0c4dfc4c241d038e290a2feb571b1a368fbf54c86f3806302028`
resumed all160 patches/70,729,728 bytes to the complete expected ReFS image.
Separate finalization recorded durable HND before native mounting and verified
all15 objects/10 file hashes, the original label and mount paths. The saved
resumed branch is `ddc9226c-f0fc-43ee-b123-3d35f91508b9`.

A separate fork of the saved partial checkpoint rolled back to the exact
original NTFS image
`a90a9cd8f9fca6037b396127d161f56cc5698cae832c6bd3872d38378a367c6e`.
It recorded durable ABT before mounting NTFS. Independent native NTFS readback
then matched all10 complete file hashes/8,594,411,663 logical bytes using a1MiB
buffer. That readback does not attest stored metadata or a post-mount raw image.
The recovered branch is `c670839d-00d1-46cf-8544-6aad51bde364`; all47 checkpoints
are retained and the VM is OFF with no assigned RAM.

| Closed report | SHA-256 |
|---|---|
| resumed ReFS finalization | `4941b2d6e1b983e378f3352a901fb7c465d1587df96abfdddff27a78a1906c37` |
| NTFS rollback execution | `9b8e20d476cfecd3363e110215c3a6037e70d5fb1c3c103f65eed410e7eaee3e` |
| NTFS rollback completion | `5004ba099e422eacec5d248d2483dee1f838a1b6b59b338f63af7f0f95d067dd` |
| NTFS native file readback | `c5ba2ddf367fe5412374416d98b1c9a88b766d4e1912e4f78dd55b875c13365f` |

Converter and recovery are different executables recorded at `fe7b9bc` and
`d953baa`. Their committed Rust/dependency trees match; historical clean working
trees and reproducible builds are not established by that comparison. Neither
successful recovery nor packaging recreates source admission or permits replay
over either completed native branch.

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

Historical fixed-fixture results remain distinct. Fresh admitted construction,
native mutation/reboot and controlled process recovery now have the bounded
evidence above. The broader unsafe-source matrix, storage power loss, arbitrary
nonzero relocation costs and general-drive support remain unqualified.
`Freeze-NativeCompositeAlpha.ps1` copies the exact pinned executables and selected
evidence/instructions into a new small offline package; it neither runs the
tools nor grants permission or runtime admission to any device.
