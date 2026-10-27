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
