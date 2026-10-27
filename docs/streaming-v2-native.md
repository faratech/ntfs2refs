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

Candidate 2 terminated before raw apply with `Access is denied. (os error 5)`
in native-shadow construction. All source-only admission gates passed, including
native/raw logical bytes, Unicode namespace, allocation and full frozen-source
identity; target security/preservation gates remained pending. No conversion
certificate or execution authorization issued. Its generic error did not retain
the individual failed syscall. Code inspection found that the new DELETE/read
handle lacked FILE_WRITE_ATTRIBUTES required by per-handle SetFileTime
suppression; this was corrected and open/suppression/deletion errors now name
their operation. No source or target admission condition was removed.

Twenty terminal/staged files (10,258,288 bytes) were copied and hash-verified;
manifest SHA-256 is
`a4d92ec8fc1b24386371ede9c72e03e356b3e59d121d45fb371b5edc5b6275a8`.
The first archive transfer encountered a PS5 internal scalar Length error after
strict mode had been enabled in that remoting session. A fresh default-mode
transfer session completed the copy against the original guest pins; the
archive helper now resets only its transport session's PowerShell strict mode
after evidence guards, with complete hash readback afterward. No Windows ACL,
UAC or security policy was changed.

The refused branch is preserved OFF as
`beddfbe8-f40d-4903-9c2c-c6162b3b4349`. A single restore returned this VM to
its enrolled clean NTFS baseline; in-process Hyper-V observations stayed stale
through the post-restore wait, but a fresh process confirmed OFF and baseline
`775f4db8-8635-486c-b6eb-7098426b51a6`. No second restore was issued.

Candidate 3 was dispatched once at 18:10:37 UTC, run
`e5d4b7dfa9474dedb3e19b67c1b03f24`, request SHA-256
`6b2d9eef8030430e8a9f564f93318e2aa6b2d953ba6152ee6a1beb8f9697cfa1`.
Producer source is `98d02a4f698d44d7ba89c5a45c24b49422eae363` plus the
unchanged capabilities-only dirty patch. Converter SHA-256 is
`a28a4a5b74839754181f4cc9a44d97aab383b665f2249746418457c8bcde6f39`,
binder `1260d6be04cb606e69de10d7132e25094b85beaf48d165c52c8af07f0f952cc5`,
recovery `24c92454dd69c69dc9a7b9538e95722a1ce36936f6f418a866470a55709a2231`.
PID 2540 remained live at 18:12 UTC in source qualification. The updated
collector distinguishes source observation/admission from actual construction
and records process working-set counters. It does not infer completion from I/O.
Postcheck executables were built/pinned separately from the same source:
verifier `7fb8d16a4a31009d2c054e09bc786a2d3747db20187104d7fdd4763d8f1b8957`,
mutator `f73a8ad55923dcf88c58385de70a496ba85c9a1151b2c6aa9f8ab85fcd374517`.
No outcome or expanded qualification is claimed for this live attempt.

The same PID subsequently completed native shadow construction: 13 objects,
4,295,249,950 payload bytes initialized, and one successful target-only indexer
cache normalization event. The immutable construction report was copied to
`candidate3/native-shadow-observed.json`, SHA-256
`1f3ceb7db217264643bfeb4f2aaca82ebb44e8a1cf79237cb156ace0e94f35ec`.
All six retention candidates were blocked by metadata-inclusive allocations;
none was submitted or proved retained. Do not claim payload retention from this
case. The live process then entered target preservation. That stage and the
eventual journal/cutover/native readback are still pending in this observation.
