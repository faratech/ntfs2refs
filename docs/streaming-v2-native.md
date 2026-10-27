# Streaming-payload v2 native fixture

The next conversion case is a separate VM,
`ntfs2refs-streaming-v2-20261027`, ID
`2401593c-4b30-472e-9b6d-c9534cbaa599`, under
`.lab/hyperv/streaming-v2-20261027`. It has fixed 4 GiB RAM, four CPUs and no
NIC. Earlier VMs/checkpoints remain unchanged, including the passed beta OFF
at `cb6a32e9-f237-4d3f-a807-d97fc73f73a1`.

The OS disk is a new writable differencing child of the immutable installed
Windows archive, rather than another full archive copy. Data disks are fresh
independent VHDX files with no parents. This shares an OS dependency; it does
not share writable data media or establish independent physical failure domains.
The parent content hash was checked before and after provisioning:
`38483cb91279b90b6a053098d7b62903c18ea3873ab9023f382bb70ff545fe87`.
Hyper-V automatically added two file-generic-read ACL grants, for
`S-1-5-83-0` and the recorded capability SID. Rule comparison found no removed
rules or owner/group change; no manual ACL restoration was attempted. The
before/after descriptors and actual delta are retained with the fixture.

Readiness observed Windows 11 26300.9457 and refs.sys SHA-256
`3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.
The new data roles were enrolled as RAW by actual device ID, size, partition
count, protection flags and SCSI LUN before formatting. Only those three owned
RAW disks were initialized. Source and shadow partitions are 52 GiB at offset
16 MiB, NTFS/64 KiB and ReFS/4 KiB respectively; the journal has independent
8 GiB virtual media. The shadow uses the existing native Dev Drive profile.

The source contains six user files totaling 4,295,229,458 logical bytes. Names
include `資料`, `Grüße.bin`, `café.txt` and `emoji-🦊.bin`; the large ordinary
uncompressed file is 4,294,967,297 bytes of zeros, SHA-256
`fbb82f7b353676bb562eb82157fcf0ea42c36492ca13ee56dbf82c08b6802c5c`.
Its ordinary sequential creation used no source extent moves or allocation
aging. Windows reported two source runs, retained verbatim in `fixture.json`.
All six file hashes and actual partition identities are recorded there.

This is a setup/readiness result, not native conversion or recovery
qualification. It exercises payload size and Unicode, not a large partition
capacity or nonzero 4 GiB payload. Thin-zero behavior and physical I/O are
separate from the logical source manifest. At fixture completion the conservative
lab counter was 213,674,191,598 bytes of its 223,338,299,392-byte budget, with
131,887,734,784 host bytes free; no reserve/budget was raised. Recheck capacity
before construction or new snapshots. Preserve partial worker/intent records;
do not redispatch a setup or conversion based only on an observer timeout.

The completed source fixture was preserved OFF as checkpoint
`775f4db8-8635-486c-b6eb-7098426b51a6`,
`streaming-v2-ntfs-unicode-4g`. A clean guest-integrated shutdown preceded the
single checkpoint creation. Its new active child was then started for one
explicit streaming-profile conversion; the passed 240 GiB producer was not used.

Candidate 1 is run `8c9c50c1fc6c4fd3a0fc3aeadd61fb72`, task
`N2R-StreamingV2Convert-8c9c50c1fc6c4fd3a0fc3aeadd61fb72`, request SHA-256
`6052f162ae85b69ddb0a328b8e65f81f3a3fe66dcf37aab44db8006ec776ae36`.
Its producer is source `97010e083cbb1dd2fdf9498de4c00115775b8e02` with the
previous capabilities-only dirty patch digest
`d99591b5f26b887b513260cf01b8e89d114cb173fa86d40869a1053518d313e9`:

- `ntfs2refs.exe`: `624405d2517a4ae51ccf83270eecfdb83ebccb8f8d726e25f2dc651a116e4076`.
- `ntfs2refs-bind.exe`: `862617d623b8378cfdaccc71cfd2ade1c88ef3f49cb9160c21d597ad05c712eb`.
- `ntfs2refs-recover.exe`: `bd5fc321e2fe0ad33d3d7b6ddb142adac5c6f1d6d5e9a16f2fe04b6c0e64bdaf`.

PID 1552 was created at `2026-10-27T17:33:52.624051Z`. At `17:39:32Z` the same
process/task remained live in shadow/target qualification with complete
source-frozen, source-basis and native-source artifacts. Cumulative reads were
83,076,462,622 bytes; these counters are not a completion percentage. Lab usage
was 217,551,998,020 bytes with 128,010,690,560 host bytes free, within the
unchanged limits. No conversion/native-mount result is established yet.
Use `lab/Collect-StreamingV2Conversion.ps1`; it saves actual task/process,
artifact, protection-state and capacity observations. Do not use the old beta
collector or infer termination from an observer timeout.

Candidate 1 subsequently refused at 17:42:42 UTC with `target system-volume
namespace contains unknown or unexpected data`. A later live observation found
the task Ready, exit 1, and no converter process. Qualification explicitly
records zero source payload writes and no execution authorization; no journal
or apply was produced. Its complete staged/run artifacts and per-file hashes
are archived in `candidate1/terminal-evidence` and the adjacent manifest.
The failed branch is preserved OFF as checkpoint
`2a265703-70bc-44fd-a0c5-49999384b9db`.

The raw source inventory contains SVI/WPSettings.dat and tracking.log, but no
IndexerVolumeGuid. Backup-mode read-only directory listing found only the
76-byte IndexerVolumeGuid and 12-byte WPSettings.dat in the target SVI. The
original reuse rule required both cache files to exist in the source. The
streaming-only correction recognizes the extra indexer identity cache by exact
name, permitted attributes, pinned file ID, one link, no pending deletion, one
unnamed stream, and exactly 76 bytes containing a UTF-16 braced GUID. It validates
the entire SVI before deleting that cache through a DELETE-authorized handle
that denies competing data writes/deletion. Its native construction event
retains the ID and original cache bytes. The frozen NTFS source is untouched;
unknown entries, extra streams, malformed contents and unsupported profiles
continue to refuse. This is a construction fix, not conversion evidence.

Mike approved increasing the saved-lab cap to 216 GiB for the next attempt,
retaining every checkpoint and the 64 GiB host-free reserve. The prior 208 GiB
counter would not admit another 6 GiB growth allowance after preservation.

Candidate 2 was dispatched once at 17:56:43 UTC, run
`b82e5dbbdd1d4ae899315954c37a2609`, request SHA-256
`335dd9072ecee03bc8cbdd93c96ecfd9c3aa1a7baf2d10b132c899e324d83d7a`.
The producer source is `f6feddc64f14453be0743a7893119b8a9747b52c`
plus the same existing capabilities-only dirty patch. Converter SHA-256 is
`9f6619aa74ba07cac302b69f88f930ffee0e71eac4743b1efe545188c2bf4b2b`;
binder `46f9951071ed24b753ec01384a779f4defe861bec0feb380c903e652883b6f6d`,
recovery `bba657ec1006f5005784b373b2db1ea451046ee6b8f89cb0651302a4da772bb1`.
PID 3524 was observed live in source qualification; no outcome is claimed yet.

Postcheck orchestration reuses the beta's strict Rust verification/mutation
phases through an explicit `-StreamingV2` switch. That switch enrolls only this
VM, its 52 GiB original partition GUID and V2 request, and does not expand the
old beta route. `Stage-StreamingV2Postcheck.ps1` pins the two host-built Rust
executables without guest execution. After successful terminal collection and
archival into `candidate2/terminal-evidence/run`, use
`Invoke-NativeShadowLargeBetaRustPostcheck.ps1 -Candidate candidate2 -StreamingV2`
with its ordered phases. Preserve the successful converted branch before
mutation. Use `Restart-NativeShadowLargeBetaVerified.ps1 -StreamingV2` only
after successful mutation and its strict readback. No unit tests were run.
