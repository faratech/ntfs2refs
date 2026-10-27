# Disposable larger-volume beta

The separate VM is `ntfs2refs-shadow-large-beta-20261027`, ID
`6c4793d2-cdee-468b-bf3b-1c11cae0b501`, under
`D:\code\ntfs2refs\.lab\hyperv\shadow-large-beta-20261027`.
It has independent copied/archive-derived disks, no NIC, four CPUs and fixed
4 GiB RAM. It does not inherit the frozen alpha's 8 GiB qualification. The
provisioning before/after records preserve all three earlier VMs/checkpoint sets.

Its actual guest is Windows 11 build 26300.9457 with `refs.sys` SHA-256
`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.
The source partition is 240 GiB NTFS with 64 KiB clusters; the independent
shadow is 240 GiB ReFS with 4 KiB clusters. Six ordinary files total 134,479,889
logical bytes, including empty/resident files and one 128 MiB file. Their creation
used no source extent moves or artificial allocation-aging writes. The large
file's observed source run begins at NTFS LCN `0x19e` for `0x800` clusters.

The clean imported checkpoint is `971ecdc3-8eca-4abb-a77e-e028e7e54f7f`.
The separate clean NTFS baseline checkpoint is recorded in `baseline.json`.
Checkpoint enumeration initially lagged creation; the completed checkpoint was
observed before resuming, with no duplicate checkpoint or provisioning restart.
PowerShell-5 array and native-stderr handling fixes are recorded in the helpers;
existing staged binaries/discovery were reused rather than repeating disk work.

Initial candidate SHA-256 was
`f90974bf65abef903ec3be76b4462120b5d144f5b061ce3efc498bec733640eb`.
`candidate-pins.json` binds its staging to source commit
`f61011795566928b6db5de2734ffe272d31a4c33`, with a dirty runtime source tree and
patch digest `d99591b5f26b887b513260cf01b8e89d114cb173fa86d40869a1053518d313e9`.
That dirty state is not a clean-commit build claim. The still-present change was
the capabilities-rendering edit in `src/main.rs`.

Public conversion run `592d72139d3443dead6f7f947209c494` terminated with task
result 1, no surviving converter process, and `unsupported disk/partition
geometry` during source-freeze qualification. Collected failure output and
actual terminal disk/task state are under
`refusal-592d72139d3443dead6f7f947209c494`. All four guest disks remained online
and writable; journal preparation and raw source reconstruction were not reached.

The refusal exposed a general TxF path calling the old fixed 52 GiB binding's
`volume_path()` on a diagnostic proxy. The corrected helper takes the root path
from the separately validated general binding; the original fixed-fixture
validator remains unchanged. New candidates must use fresh stage/run paths,
preserve earlier binaries/artifacts and confirm prior workers are terminal.
This report records a refusal and a code fix, not a successful conversion.

Candidate 2 preserves the first stage and failure artifacts. Its converter
SHA-256 is `732932bd4e83c530c2562c93b8eb9863182d4125fa00dc8729a3d84a109dbbcb`,
staged from source commit `d8056bde7d80de2118244ca7cbbe6632d86221f2` with the same
recorded dirty capabilities patch. Run `76e37c16dfd4484e982ae21f44c4ed13` uses
the public `convert` entry point with a fresh request/output, reusing the existing
online fixture only after the earlier task was confirmed terminal. No reboot,
reformat or source extent move was performed for this new attempt.

The collector confirmed task `N2R-LargeBetaConvert-76e37c16dfd4484e982ae21f44c4ed13`
Running and process 5608 created at `2026-10-27T08:40:33.321712Z`. At
`2026-10-27T08:47:29.8151192Z`, cumulative process reads were 115,376,920,346
bytes and the source disk was persistently offline/read-only. The initial full
source hash was still in progress; no completed source-frozen artifact, journal
or conversion result was present. This is live progress evidence only. Use the
recorded task/process and current collector output rather than treating an
observation timeout or missing later report as termination.

Candidate 2 subsequently terminated with result 1 and no converter process.
It completed the full source hash but refused on `primary and mirror MFT record
24 differ`. No source payload writes or reconstruction were authorized. The full
failure output, staged candidate and read-only primary/mirror cluster captures
are retained under `candidate2/terminal-evidence`. Capture SHA-256 values are
`9f7881f1bdfdbb6d55ec60038eb394891c01e826ea10883896a12766db51a780`
(primary) and `342d2d35c6b0381f101484feead82b1624b4b0cb73f92b4cdc956c44532e859b`
(mirror), each 65,536 bytes. These are local captured-artifact observations,
not source-health or conversion-success claims.

The first four records match exactly. Divergent mirror slots from 24 onward
remain inactive, zero-LSN, nameless format templates while primary entries have
become live. Microsoft's [MFT mirror definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/8ac44452-328c-4d7b-a784-d72afd19bd9f)
specifies four bootstrap records. The corrected backup policy keeps those four
byte-identical, validates every declared slot's USA/record structure, hashes the
complete regions, and accepts extra-slot differences only for the narrow
inactive format template (zero flags/links/base/LSN, matching slot number,
resident unnamed standard-information/security/empty-data attributes, no name,
format timestamps/flags and valid security descriptor). Other extra differences
still refuse. Extended evidence identifies exact matches and recognized padding;
it does not falsely label the entire allocated cluster as synchronized records.

The refused beta branch is saved OFF as checkpoint
`cbd04cca-3117-4b25-8731-efa56a5e0ffd`. Only this disposable beta was returned to
its own baseline `506bf3fe-afac-40fb-bfe9-e357141506d2`, after terminal-worker
proof and archival. Hyper-V parent publication lag was observed without repeating
the completed restore. Earlier protected VMs/checkpoints were not restored.

Candidate 3 is converter SHA-256
`38b5b8d142e612000ee00385efc3b4414293b13abad23f71e576f1c5e412b5f2`,
run `dab1b80b92c2432e80a4052502f9165b`, task
`N2R-LargeBetaConvert-dab1b80b92c2432e80a4052502f9165b`. Process 2940 was
created at `2026-10-27T09:32:00.157116Z`. At `09:48:35Z` it remained Running
and had produced complete source-frozen, source-basis and native-source artifacts.
The backup check accepted four exact bootstrap mirror records, 32 equal extra
slots and 28 recognized inactive format-padding slots. This proves that the
previous mirror refusal was passed, not that conversion completed.

Read-only copies under `candidate3/source-observed` have SHA-256:

- `source-frozen.json`: `c64710d9916a0e985061ce8d238dedfb7583627a7f61437aba0b67b8996e9c18`.
- `source-basis.json`: `d2ebbb6dfa18704813aaaf1ca6a2cf8e6c62b5392b37718add432d811b46061c`.
- `native-source.json`: `c117653a6fa97a95d545b5494335ec986eefc6b0d20a110bcfa3147d9898e021`.

No raw reconstruction, native mount of the converted source, mutation, reboot
or recovery success is established by this milestone. Continue by observing
the same task and its actual terminal state.

`lab/Invoke-NativeShadowLargeBetaMutation.ps1` prepares the next bounded mounted
workload. It requires terminal successful handoff and the independent six-file
readback before creating a fresh run-owned directory. It grows a file to 16 MiB,
truncates and hashes it, renames it, creates 128 directory entries and deletes
only those newly created objects. It repeats the original payload readback
afterward. An exclusive durable host intent prevents accidental repetition.
This helper has not run; it does not establish mutation or reboot success.
The preserved alpha and other VM branches are outside its exact beta binding.

At `2026-10-27T10:57:39Z`, candidate 3 remained Running and had advanced
to journal preparation. The source/target certificate, expectation and request
were complete; comparison telemetry reported 123,102,822,400 of
1,030,792,151,040 planned scan-input bytes. This is a comparison/recheck I/O
budget, not an end-to-end completion percentage. No apply/result was present.
Read-only copies are retained under `candidate3/qualified-observed`:

- `certificate.json`: `25a357308fb5aca3772d6167db87946ffe9c27c48f6f8302b41f7605e2be31ff`.
- `expectation.json`: `08c1fb268e3115619ed7d5a68805a4a8d97dd07ffb5963f3f2ee393db89903ab`.
- `request.json`: `baa26a49238be1b7c8062d792f3bbfad656fe72f1600787800df9c645c28f770`.
- `journal-location.json`: `ee63f11f638d1d9d133cbabbeff338cd3f0b304f76eb9484022fd7cf60fdd8f2`.

The admitted comparison has **zero retained ranges**. This particular natural
placement exercises relocation/materialization on a larger source geometry;
it cannot prove unchanged payload extents or efficient low-scratch conversion.
Do not move source extents or change its active plan to manufacture retention.

The prepared `lab/Restart-NativeShadowLargeBetaVerified.ps1` requires the
matching successful mutation receipt and another original-payload readback.
It requests one guest-integrated clean shutdown, waits for Off, starts the same
beta VM once and requires a newer UTC guest boot followed by all six payload
hashes. It neither force-powers-off nor retries boot/recovery actions on an
observation failure. Create-new intent/result files preserve partial attempts.
This helper has syntax-check evidence only and has not rebooted the active VM.

The later source candidate also repairs the standalone Rust post-handoff
verifier's profile propagation: expected-tree validation, native observation
and strict post-mutation checking now use the pinned request's resource profile.
Legacy no-profile callers still select the alpha path. The Rust mutation
workload has a separate `--experimental-large-beta` enrollment requiring this
beta's exact 240 GiB partition/disk GUIDs, offset, source disk 1, guest name and
larger-tree profile; its default 52 GiB enrollment remains. It retains the
50/80/10 MiB create/grow/truncate workload, 128-entry directory workload and exact
root-basic-info capture. New mutation reports bind the request hash and resource
profile. Strict verification requires that binding on larger-profile reports;
legacy reports lacking it are accepted only for unprofiled requests.

These Rust helpers have release-build evidence, not execution evidence. No new
helper binary has replaced the active conversion executable or run a mutation.
At `2026-10-27T11:22:10Z`, the original candidate-3 converter was still live
and had completed comparison, advancing to `rechecking-source`. No apply or
conversion result existed. Continue observing the same process/run.

The postcheck executables from source `2d6fb355206e0499b1231aa3083b0009ee753fec`
are copied and pinned locally under `candidate3/rust-postcheck-tools`:

- `lab-verify-general-converted.exe`: `02d844f815a101cc0b1b4e16002ae1e35b50a79872ab3b2565802993bcd79ade`.
- `lab-general-refs-mutation.exe`: `7e0fdeb9762213a97ed0347997ae093f18dbe945b4891e759e4a5701f81faa65`.

`lab/Invoke-NativeShadowLargeBetaRustPostcheck.ps1` wires these through fresh,
separate guest tool paths and ordered `BeforeMutation`, `Mutate`, `AfterMutation`
and `AfterReboot` phases. Every phase first requires a terminal successful
conversion and independent original-payload readback; actual request/tree bytes
must match the preserved qualification pins. The mutation uses the enrolled
Rust workload above. Exact strict post-mutation success creates the receipt
consumed by the clean-reboot helper; strict verification runs again afterward.
Create-new intent and result files prevent blind phase repetition after errors.
The controller has syntax-check evidence only. These tools are not guest-staged,
no phase has executed, and the earlier PowerShell-only workload remains unused.
