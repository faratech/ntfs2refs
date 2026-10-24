# Implementation handoff

Latest implementation: Rust raw namespace reconciliation now validates I30
root/allocation pages, bitmap reachability, USA fixups, B-tree key order,
MFT/index membership and sequence references, link counts and root reachability.
The empty/populated native NTFS captures reconcile 24/33 entries respectively;
their raw allocation models also reconcile. See
[namespace evidence and limits](docs/ntfs-namespace-reconciliation.md).
There are 32 new tests; the workspace passes 256 tests with five ignored,
plus clippy with warnings denied and formatting checks. General admission
still needs native enumeration/identity and allocation cross-checks, security
descriptor resolution, stable freeze, clean log state and backup validation.
The general converter remains gated. Next resolve security metadata and bind
native source observations to the raw model, then build the multi-file path.

Latest native follow-up: the controlled allocation/mutation workload passed in
`allocation-workload/win11-20261024T072530927Z`. Host result SHA-256 is
`2028495b74c16b6242b2c73e771b8dd477b3d8bb665a5976a035589b3fd75a5c`;
native result SHA-256 is
`ddae11eddd1af6c611fe8a5e5c6415d8bc1494bdf3431adaa026e05c10ed19e2`.
Windows created 40 files, grew/truncated 32, renamed 16 and deleted 40, with 50 MiB
normal file writes. Four native allocation snapshots preserved A's exact 16
clusters; before/after protected observers preserved its data, identity,
security and all timestamps. An independent archive reader verified 18,496
payload-cluster entries and 32 mutation identities. The 54 pure boundary/bitmap
checks and archive validation pass in PowerShell 5/7. No Rust source changed.
Outcome checkpoint `751d896d-6d03-4efb-9530-e5dc209ed0ba` is named
`converted-allocation-9f1bc0d1cb444fcc8390e263ff38e96d`. The VM is off at 4 GiB
on installed-clean, with no unknown operation/session. See
[native results](docs/native-conversion-results.md) for pins and failed-case
dispositions. Next qualify native interruption/recovery and allocation after
another reboot; arbitrary-source admission and general conversion remain open.

Previous native follow-up: clean reboot/remount passed in
`converted-verification/win11-20261024T064141050Z`. Host result SHA-256 is
`a84cf8826fbfea4f081a8ad0dfb4e76fa776bb071bf8e0958bc71b97445bf18c`.
The target stayed online/read-only across startup, shadow attachment and the
first-mount helper were skipped, and the unchanged native observer returned A's
original hash twice across four stable mapping/validity/security/time snapshots.
The remount checkpoint is `8a87b135-d133-4eb1-a326-b6fa65cfc085`, named
`converted-remount-2a92538b0b0b4392b7e4f7513a00ff88`. The VM is verified off
at4GiB on installed-clean; no operation/session remains live or unknown.
General source admission, native power-loss/recovery and the general converter remain
unfinished. The remount runner SHA-256 is
`968318fee5793a3de2c74e2d1524d4533c74c12b17ccb114b5bd7df8727dae7f`;
its manifest `.lab/hyperv/converted-remount-review-20261024T064121678Z.json`
is pinned by `c9a0b96919e63ca3cda8b1cb8e6b466558a17e52ca16e2acfef4198cabd37f71`.
The first remount preflight stopped before VM actions because an archived
manifest had been reserialized. Prior source bytes are now authenticated by the
completed host record's source hashes; original artifacts/pins were preserved.
133 mode/predecessor,38 actual-archive,174 host and103 input-decoding checks
passed in PowerShell5/7. No guest/native/Rust source changed for this follow-up.

The user authorized implementation of the researched NTFS-to-ReFS plan. This
session began implementation on 2026-10-23. Work is in progress, not a completed
converter. Resume implementation from the actual files and host-result records.

Latest verified state: 224 ordinary Rust tests pass across the workspace, with
five explicitly ignored native/child-process tests. The raw NTFS inspector now
reconciles a bounded attribute ownership model with initialized bitmap bytes;
this remains diagnostic and does not grant source admission. See
[allocation reconciliation](docs/ntfs-allocation-reconciliation.md). The
new journal core contains actual old/new payloads, pinned recovery and a durable
handoff barrier; file-based interruption/recovery tests pass. The bounded native
adapter and `lab-native-probe` now also passed both complete native phases in
`win11-20261024T045526178Z`, including restart, protected attachment, retained
reads and both52GiB partition hashes. The host result is complete, SHA-256
`f79b8996db0e617da19a2a0b52d854ccc6f82da61f567724cda69f9cce4ab9f8`.
Quiescent checkpoint `28b3fc07-33e0-4833-b5db-9897fb552178` is saved and the VM
is verified off4GiB at installed-clean. The host input decoders now accept one
leading UTF-8 BOM after authenticating the original bytes; 540 focused checks
passed in PowerShell 5 and 7 with independent review. The pure request builder
created the reconstruction request, SHA-256
`2e5c967abee35bb8fbdb3f8ac856cab614ad00c205569ec77ad36c647fd97026`,
and its pin, SHA-256
`d84023d404f8a11eda22e51a9011cd8401cfe1779ca18fbca070aff6f9945cdb`.
Native journal preparation then passed in
`native-reconstruct/prepare-20261024T052030708Z`:130 ranges,69,451,776 changed
bytes,138,933,772 journal bytes,zero target payload writes. Its complete host
SHA-256 is `a03b4228a520e76edc8e57c3edfd3e5295ed2d5938e4f426ff7c1544894cc76f`;
the independently persisted ticket SHA-256 is
`dd65983e8b73227bdad8eb649f10d58f9c0d1995b43a207b53c414a6d341816f`.
The expected reconstructed image SHA-256 is
`57b3fc2fb836c4091efd331e84b9c25488beff2af46886a45a86554e81a25443`.
Prepared checkpoint `4b7a4dc4-a74e-4996-9f31-a4b18d2444cb` is saved.
Apply passed in case `apply-20261024T054132656Z`. It wrote exactly69,451,776
bytes across130 patches, retained the64 KiB extent unchanged and verified the
complete expected partition hash. Apply host SHA-256 is
`111405c2a5239b1f4a76ef04fd909354e9a9673699554b3b4da1747760326610`;
checkpoint `960ba24f-1177-4d1f-9faf-e3d174adad47` is saved.
Handoff passed in `handoff-20261024T055719130Z`, host SHA-256
`e1048284f3729f00720394c69c63670267392fb338205082125de29a60f0dbe1`.
The protected native mount/observer then passed in
`converted-verification/win11-20261024T061408952Z`, host SHA-256
`ea53249c0f49be778a25cfa3aa2f7e3377ece25a874fc5c04e5ccc13dd40ac13`.
Microsoft's ReFS driver returned A's original hash twice; physical mapping,
validity, metadata and security matched across four stable snapshots. The
converted checkpoint is `e7fda999-ad2e-4792-9011-e9b4fdaebf21`, named
`converted-readonly-680c2833521a458b92560bf1dd1fd604`. The VM is verified off
at4GiB on installed-clean. No operation/session remains live or unknown.
The guest used the original frozen release; the224-test development build is in
a separate ignored target directory. See the
[native conversion result](docs/native-conversion-results.md) for scope and
remaining clean-remount, mutation, recovery and general-admission work.
Earlier, the target's offline state survived restart, but the original shadow
reattachment profile surfaced its fresh device online/read-write and was refused.
That failed branch remains preserved. The previous release comparator passed its
tiny file-only guest run; it is distinct from the newer lab binaries.
Guest-local preparation passed in case `win11-20261024T025713906Z`: both files
have matching supported metadata and a single extent at LCN2097152. Its saved
checkpoint is `46b1791d-9852-40f0-ab03-68bcb7d98c58`. The subsequent native-probe
case `win11-20261024T030135884Z` stopped during pre-isolation inspection: file
hashes/times/mappings survived restart, but uncontrolled directory enumeration
changed NTFS directory last-access time. Directory observation through owned
handles has been added and passed peer review. Fresh preparation case
`win11-20261024T031656056Z` then stopped before fixture creation: the first NTFS
root query (class11,4096-byte buffer) returned Win32 error2. A bounded diagnostic
later observed SVI on both roots and dot entries in an empty C: control; it did
not reproduce error2 or establish the earlier root's contents. The failed branch
is preserved in checkpoint `75a43928-64e5-408b-9182-5a3683d4ecd0`; the VM was
verified off4GiB at installed-clean. The lab's allocation ceiling is now192GiB,
with the64GiB host free-space reserve unchanged. Fresh preparation
`win11-20261024T034206826Z` passed with the narrow initial-empty-search handling:
both roots produced class11/error2 followed by class10/error18, then complete
fixture creation, native placement and strict metadata/content checks passed.
Its run is `94f6256f57424ad69147f58199387ee1`, prepared checkpoint
`730afa0a-4df7-4a18-830c-1f0381013c62`, and host-result SHA-256
`464bb9e4fccb6f2e014e3104801d546dbbbb48fc944454ccb060dcc3f9e22f13`.
The subsequent native probe `win11-20261024T034413955Z` passed restart inspection
and its Rust report passed the archived pure validator: target/shadow attributes
1/3, successful target flush, and both raw64KiB hashes match. Its guest launcher
reported known process completion but a null exit code, so the overall probe
failed and never reached the second restart/whole-partition hash phase. The
original failure is preserved in checkpoint `0a60b7b0-3833-4325-bda4-ea40eee509e5`;
the VM is verified off4GiB at installed-clean. No full native probe has yet
passed. The earlier inspection failure is preserved in checkpoint
`a581a9dd-d48b-46ec-a927-81a9f4f80cc3`.
Both process wrappers now retain managed process handles and bound asynchronous
capture;685 relevant checks pass per PowerShell5/7. Retry
`win11-20261024T035910091Z` passed inspection and first native isolation with exit0,
then saved isolated checkpoint `506ce18b-0b46-4e3e-8106-4b1f363f3105`.
After restart, target1 remained offline/read-write, while reattached shadow3 was
online/read-write. The Excluded guard refused before the second raw read.
The failed branch is preserved in checkpoint `6fa64f95-a03c-4bdd-b89b-e465f0aef5f1`;
baseline restoration off4GiB is recorded. A separate read-only shadow attachment
diagnostic subsequently passed in
`shadow-readonly-attachment/win11-20261024T041957683Z-df922bc4b13e46339c8c938a4f5a7742`.
V2 ReadOnly true / attach flags7 produced provider write protection while native
disk attributes were0; one explicit attributes3/mask3/Persist1 request succeeded.
Provider error19 remained before/after and the148897792-byte backing file hash
was unchanged. Original target1 remained offline/read-write. Known completion,
cleanup and privilege restoration passed. Outcome checkpoint
`f7de106a-6e94-4b2f-aef7-13c5b02d5df9` is preserved; baseline is off4GiB again.
Operational guest/host integration is reviewed and frozen. It uses provider
read-only attachment followed by explicit exclusion, independently checks the
native response buffers and unchanged backing bytes, and gives each probe
attempt unique checkpoint names. Relevant guest checks273/303/140 and host
checks878 passed in both PowerShell5 and7. Reviewed manifests are dated
`20261024T043533360Z`. Native probe `win11-20261024T043618703Z` passed both
native stages, including protected reattachment, retained hashes and complete
52GiB partition hashes. It saved quiescent checkpoint
`f89b4ab1-be82-4291-9e2f-8400385ee102`, then its immediate baseline-restoration
check failed. The original host result remains failed-preserved (SHA-256
`49610a9e4ba7381a6fbef436234ef44844ecb03ffd0d908b10fb22498df76136`).
A subsequent read-only observation verified the baseline off4GiB and is saved
as `baseline-observation.json`. All three runners now wait for bounded, observed
checkpoint readiness on both initial and final restores;1312 focused checks
passed in both PowerShell5/7 with independent review. Sources and manifests
dated `20261024T045513153Z` were frozen for the successful fresh probe
`win11-20261024T045526178Z`. All restore observations passed, and the complete
host/native probe passed. The reviewed BOM compatibility fix and request
generation are complete. Updated reconstruction/CV manifests dated
`20261024T052019110Z` are frozen; Prepare/Apply/Handoff and protected native
ReFS observation all passed the prepared fixture.
The completed probe and its source pins remain unchanged.
Failed branches/evidence are preserved; consult the latest host-result and
failure-preservation records for live state. See
[preparation measurements](docs/retained-preparation-results.md). Native journal
integration and its explicit CLI exist with file-tested recovery, but have not
run against a guest device. Release artifacts and source pins are archived in
`.lab/builds/release-20261024T025141160Z.json`; neither CLI performs an automatic
online transition.

## Host and access

- Workspace: `D:\code\ntfs2refs`.
- Windows 11 Pro 26H2 26300.9711, 64 GiB RAM, 16 logical CPUs.
- Hyper-V installed, `vmms` and `vmcompute` running.
- Original session: `SINGULARITY\mfara`, not elevated, Hyper-V Administrators
  group empty. `Get-VM` denies access. User could not relaunch elevated. A standard
  UAC PowerShell helper was launched and the user approved it. Provision completed;
  Codex was subsequently relaunched elevated by the user; the administrator token
  and direct Get-VM access were verified. No group membership was changed.
- Completed Windows ISO:
  `C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso`
  (9,047,330,816 bytes). SHA-256:
  `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`.
  WIM index 6 is Windows 11 Pro 26300.9457; the installer rechecks the hash.
- `C:\Program Files\7-Zip\7z.exe` is available for media inspection.
- Rust works via `C:\Users\mfara\.cargo\bin\rustup.exe run stable cargo ...`.
  Installed rustc/Cargo 1.98.1, MSVC Build Tools installed. Cargo dependencies
  fetched and lockfile generated. Cargo bin is absent from current PATH.
- Server Insider media and custom ADK/WinPE not yet supplied. User explicitly
  chose to continue Windows 11 now and supply Server media later.
- Existing `D:\vm\Win11` is VMware, not ours; leave it alone.
- The redundant 64 GiB fixed-VHD corpus transport copy remains at
  `.lab/hyperv/corpus/devdrive-20261023T231918797Z/target-fixed.vhd`.
  Automatic approval review rejected its bounded cleanup with "blocked by
  policy" before dispatch; no cleanup ran. Do not reroute that rejected removal.
  The verified raw image and source checkpoint also remain. After the successful
  read-only attachment diagnostic, measured lab usage was189941082150 bytes of
  its206158430208-byte cap, with103067500544 bytes free and a68719476736-byte
  host free-space reserve.

## Decisions the user already made

- Latest steering: DEFER BOOT experiments. User notes ReFS boot can work without
  official support; focus now on actual in-place NTFS-to-ReFS data conversion.
  Do not mistake a support restriction for proof of boot impossibility. The lab's
  exact-build boot behavior remains untested. Partial new Dev Drive OS-profile
  edits were archived under `.lab/deferred-boot-profile-20261023T231848521Z` and
  the three affected scripts restored byte-for-byte to their prior tested hashes.
- User explicitly reaffirmed that conversion must execute WITHIN the VM, so the
  same implementation works on nonvirtualized machines. Hyper-V operations and
  host-side offline image extraction are laboratory setup/recovery/analysis only;
  all filesystem conversion and recovery logic must run locally in the target
  machine (offline recovery environment for its OS volume).
- Equal Windows 11 and Server Insider research priority.
- True in-place conversion: same partition, reuse extents, offline operation and
  bounded scratch allowed. No backup/reformat substitute.
- Windows 11 configuration experiments using Microsoft-signed components allowed;
  custom loaders/drivers are outside scope.
- Journal resume/NTFS rollback only before first writable ReFS mount. Hyper-V
  checkpoints provide post-mount recovery.
- Unsupported source features: report and refuse. No silent normalization.
- Native ReFS writer must remain unavailable until native-format and native-driver
  experiments qualify it. Do not claim the current scaffolding can convert.

## Implementation and verification

- NTFS agent: `src/ntfs_inspect.rs`, `tests/ntfs_inspection.rs`, fixture support.
- ReFS/research agent: `src/refs_inspect.rs`, `tests/refs_inspection.rs`, `docs/`.
- Hyper-V agent: `lab/`, `scripts/`; initial provisioner and WhatIf check done.
- Root: Cargo project, CLI, read-only image I/O, feasibility planning, corpus
  comparison, integration and validation. The executable now works for inspect,
  plan, verify, diff, compare-retained and capabilities. Write commands remain unavailable.
- At completed-corpus reader validation, 87 Rust tests, cargo fmt and all-target
  Clippy passed; the release builds. Later inventory work may increase this count.
  An earlier static-CRT release ran inside the fresh guest; the current release
  inspected and verified native captured images on the host.
- Subsequent metadata-role and bounded root-node work passed 109 standard Rust
  tests, formatting and all-target Clippy. Both opt-in native checks passed:
  the pinned 1 GiB NTFS inventory and 48 KiB of ReFS root pages. Root rebuilt
  both release binaries and checked the CLI capability report; conversion,
  journal recovery and the native writer remain unavailable.
  PowerShell checks pass: 19 lab, 34 baseline recovery, 8 ownership,
  46 guest identity, 19 guest-session policy, 12 aligned capture, 3 ADS stream,
  19 export/recovery, 65 stream-comparison, 31 ReFS preparation, 111 boot-observer
  and 10 native-process checks. Distinguish these from native VM outcomes below.
  New suites pass: 62 native allocation collector checks, 83 Dev Drive control
  guard checks and 13 fixed-VHD extraction Rust tests (included in the 87 above).
  The read-only extent-discovery host suite passes 99 checks in PowerShell 5/7;
  its native runtime and complete export have now also passed.
  Fixed-VHD extraction is a separate lab-only executable; conversion still must
  run inside the guest/on the physical machine, without Hyper-V dependencies.
- Recovery tests are a memory-only model, including 4,374 write-order/tear
  combinations. There is no production journal or qualified ReFS writer.

## Next work

1. Native NTFS controls, the Dev Drive data control, complete ReFS corpus
   extraction and bounded reader validation are complete. Preserve their records;
   do not rerun one-off recovery/extraction into existing destinations.
2. Retrieval-base/bitmap discovery completed and its one payload extent was
   reconciled with the raw image. Next measure one initialized-file placement
   inside the guest on a separate checkpoint branch. That tests relocation,
   not no-copy adoption of NTFS payload.
3. Evaluate zero-VDL placement and guest-created native shadow metadata behind
   the bounded-space, address, coverage and reconstruction gates in
   `docs/native-allocation-feasibility.md`. Native formatting is confined to
   scratch; the original NTFS conversion target must never be formatted.
4. Implement same-partition conversion/recovery only after metadata completeness,
   collision planning and journal behavior are qualified. Boot work is deferred.
   Hyper-V recovery is not the production journal.

The `ntfs2refs-win11` VM has been created with all three disks. See
`.lab/hyperv/host-results/Provision.json` and the lane ownership manifest.
Native NTFS first boot passed at 20:34 UTC: Windows 11 Pro 26300.9457, fully
decrypted, hibernation disabled, filesystem scan NoErrorsFound, WinRE enabled,
and the Rust binary runs. The VM has powered-off Standard checkpoints
`applied-offline` (c22b80c0-2fc2-4118-b465-eca92506b908) and `installed-clean`
(eda059b3-6d50-46bb-bdf4-018b99b5b34f). The independent export under
`.lab/hyperv/exports/win11-installed-clean` was verified and hashed; checkpoint
restore passed. `firstboot/state.json` is complete at 20:51:59 UTC.

Measured compatibility fixes: Windows creates an implicit MSR; signed host
BCDBoot with documented `/offline` prepares the guest ESP without changing host
policy; the Storage provider returns null for the recovery partition's
NoDefaultDriveLetter, so native GPT flags are checked through DiskPart detail;
Hyper-V can briefly report stale snapshot/AVHDX associations after operations;
PowerShell 5 JSON arrays must be assigned before wrapping in `@()`; virtual SCSI
serials are absent, so exact UniqueId/location/size/host-attachment checks apply.
All failed attempts and their artifacts are retained under `.lab`.

The guest session policy fix passed at runtime: it uses RemoteSigned only in
the authenticated guest process when all policy scopes are Undefined and
refuses configured-policy overrides. The subsequent attempt stopped at the
disk bus guard before formatting. The approved storage probe measured SAS
(not the assumed SCSI string) on all three Msft Virtual Disk devices. Both
data disks remained RAW and the sole experiment directory was empty, so the
probe restored installed-clean successfully. Evidence:
`win11/storage-evidence-20261023T210821749Z/storage.json`, SHA-256
`3019f20b52acf3200ba90bd11e257a2357b43ed0c68063116d1da6b8ac33a0e2`.
Guest disk and boot-observer guards now accept only SCSI/SAS, with identity,
size, location, machine and boot-disk protections retained. Focused mocked
checks pass; later FormatCom changes expanded the preparation/observer suites.

Native evidence collection now captures fsutil stdout/stderr and exit status
through a Process object, avoiding PowerShell 5 NativeCommandError termination.
Read-only existing/missing-file queries passed. Aligned unmanaged raw reads
passed 12 ordinary-file checks, then captured both native NTFS images in guest.
Run `corpus/win11-20261023T211635519Z/ntfs` failed at export at 21:17:44 UTC:
PowerShell 5's installed remote directory-copy helper accesses DirectoryInfo.Length
under strict mode. The replacement exports allowlisted files individually with
size/hash verification; recovery preserves the original partial fixture batch.
The ADS fixture failed because .NET Framework rejects colon stream syntax;
provider-based creation and a read-only native stream reader passed local checks.

Logical NTFS hashing now handles supported resident/nonresident DATA, sparse
holes, initialized tails and EOF with bounded buffers and a configurable
cumulative budget. All 54 Rust tests, fmt, Clippy and release build passed.
The special unflagged `$BadClus:$Bad` metadata layout is explicitly unsupported
for hashing, preserving its extents/flags. Native captures confirmed that layout.
Comparison tooling now binds native identities/hashes to captured images and
keeps metadata/conversion qualification false.

`RecoverNativeResearch` completed at 21:42:55 UTC. It recovered/verified the older
partial corpus, then captured the full NTFS fixture under
`corpus/win11-20261023T213403542Z/ntfs`. All eight export hashes and both image
inspections/byte-verification checks passed. All nine path/stream observations
matched (seven distinct identity/stream pairs), including ADS, hard-link aliases
and sparse data. Symlink/ACL semantics remain unqualified. Detailed results:
`analysis-20261023T214015406Z/analysis-summary-utf8.json`.

Ordinary ReFS Format-Volume refused both the 1 GiB data control and the
66,238,545,920-byte OS partition with 'The specified file system is not supported'.
No ReFS boot was attempted. OS-preparation evidence is in
`refs-boot/win11-20261023T214143830Z`. Every completed case exported evidence,
shut down cleanly and restored installed-clean; the VM is off at baseline.
See `docs/lab-results.md` for hashes, limitations and source-update provenance.

Do not rerun Complete-LabBaseline against its now-complete state. Native
allocation APIs are a researched alternative to a handwritten writer, but
arbitrary placement/physical mapping/bounded shadow metadata remain unproven;
see `docs/native-allocation-feasibility.md`. No conversion writes are enabled.

`NativeDevDrive` completed successfully: `devdrive/win11-20261023T230635404Z`.
Native guest formatting produced ReFS 3.14, 4 KiB clusters. Both 4 MiB and 61-byte
fixture hashes matched across clean shutdown/reboot; native allocation reports
completed without failure before/after. Saved off-state checkpoint:
`devdrive-data-20261023T230635404Z`, ID `2aa127e2-c875-4ca0-8629-dab784136448`.
Baseline and original 4 GiB memory restored, VM off. Full native record:
`after/verify.json`, SHA256
`ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1`.
The distinct Dev Drive profile is not ordinary format, OS boot or conversion.
The immutable corpus extraction and release inspection completed under
`corpus/devdrive-20261023T231918797Z`, with unchanged source-chain hashes.
The 55,834,574,848-byte `devdrive.raw` SHA-256 is
`805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9`;
extractor readback and release-reader hashing agree. The bounded reader matched
three superblock and two checkpoint self-checksums plus all six references to
three physical root pages (indices 7, 8, 12). General address translation,
child traversal, authoritative checkpoint selection and full metadata remain
unqualified.

Native discovery `extent-discovery/win11-20261023T234407044Z` exported successfully,
shut down cleanly and restored baseline/4 GiB. It measured retrieval base zero,
stable fixture mapping/hash, legacy bitmap 328,928 occupied clusters and extended
metadata-flag bitmap 1,508,360 occupied clusters. Full metadata coverage is not
established. New `analysis-20261023T233638844Z/evidence-validation.json` binds
21 evidence artifacts, all 36 provisional range entries and the 4 MiB payload
sample to the completed capture. It confirms the sampled offset 6,174,015,488;
original provisional/discovery records remain unchanged. Validation read only
4,289,024 raw bytes and did not rehash the image or access the fixed VHD.
See `docs/lab-results.md` for its hash and limits. These are lab analysis results;
real conversion stays inside the target machine.

Native initialized-file placement completed at 2026-10-24 00:06:09 UTC under
`extent-placement/win11-20261024T000401422Z`. One guest-created, flushed 64 KiB
file moved successfully from native LCN 1508352 to requested LCN 1508384.
Its hash, identity and mapping survived clean shutdown/reboot; the original
4 MiB fixture stayed unchanged. Outcome checkpoint
`4b581541-4899-4f91-adc1-e4e784c7cacf` retains the post-remount branch.
The host restored installed-clean, off at 4 GiB. Host guard/mock tests pass 222
checks in PowerShell 5 and 7; guest probe tests pass 82. This measures initialized
native movement only: raw destination matching, zero-VDL movement, payload-copy
avoidance, metadata adoption and conversion remain unqualified. The next proposed
read-only measurement reads the old and new 64 KiB ranges inside the guest and
checks the old range's current free state. See `docs/native-range-read-design.md`
before implementation.

The preceding Rust release includes conservative NTFS metadata ancestry, bounded
ReFS root-node parsing and physical container-table traversal. All 120 standard
tests, formatting and Clippy checks pass. Native checks validate four container
walks (44 pages total), each with 832 entries; both failover maps agree in both
captured checkpoints. This does not select an authoritative checkpoint or
qualify allocation ownership, metadata writes or conversion. Release provenance
is recorded in `.lab/builds/release-20261024T002635899Z.json`; that build's main
binary SHA-256 is
`a6d78808a9fe58a109b58cb2926dd3c02cac299dd36ee0d40df8626ab212685f`.

`NativeRangeRead` completed with a determinate native refusal under
`range-read/win11-20261024T003149738Z`. ReFS accepted the single volume lock but
then refused `FSCTL_GET_RETRIEVAL_POINTER_BASE` with Win32 error 21
(`ERROR_NOT_READY`). The probe issued zero raw reads, unlocked and closed its
handle, verified both fixture mappings/hashes unchanged, exported evidence and
restored installed-clean/off/4 GiB. The frozen guest/native tests pass 109 checks
and host tests 172 in PS5 and PS7. This result does not validate either raw
range or residual-canary eligibility. A revised observation protocol is needed;
the original refusal evidence must remain unchanged.

The first `NativeVdlProbe` completed at 2026-10-24 00:37:01 UTC under
`vdl-probe/win11-20261024T003543704Z`. The initialized control qualified: both
cached and on-disk valid-data regions cover the entire 65,536-byte file.
Allocation then stopped after private file creation because the new empty
ReFS file reported allocation 1,024, EOF 0, link count 1. The probe's original
cluster-aligned/zero-allocation assumption rejected that observation. No
allocation-size, EOF, move or valid-data change was attempted, and no new-file
payload was read or written. Original fixture checks passed. The changed branch
was saved as `vdl-probe-data-1cfe7313f5ed4f94be3c22c59c75fe54`, checkpoint
`fd550b2c-f521-4fcf-bd67-8c817985f15c`, before restoring baseline/off/4 GiB.
The exact runtime sources are archived in that case's `sources` directory;
the range-read refusal sources are archived likewise. A corrected initial-state
check requires a fresh initialized-control qualification under its new code hash.

The corrected VDL run `vdl-probe/win11-20261024T004239424Z` completed at
2026-10-24 00:43:56 UTC. Both allocation and EOF requests succeeded. The immediate
state reported allocation/EOF 65,536, cached VDL 65,536 and on-disk VDL zero.
Retrieval pointers returned VCN 0..1 with LCN -1, then VCN 1..16 at LCN 1508352.
The probe rejected that mapping before explicit flush; no move, valid-data
advancement or new-file payload I/O occurred. ReFS semantics for the negative
LCN marker remain unresolved. The requested both-zero-VDL/full-physical profile
did not qualify and must not be relaxed merely to advance the experiment.
Outcome checkpoint `209475c5-c949-41aa-8887-997439f0f70e`
(`vdl-probe-data-2780e16cd7bb4d12a5ba8070bac0a1e7`) preserves the branch; baseline
is restored, off at 4 GiB. Allocation evidence SHA-256:
`cb484a4a92da8a72861ce4cd7f93ed8bffb1873236cc6c94d4c9efd6861c5fda`.
Executing sources are archived in the case's `sources` directory. The revised
guest tests pass 96 ordinary/98 with saved placement evidence in PS5 and PS7.

The 00:49 UTC Rust release adds bounded virtual-root translation, keeping each
checkpoint's agreeing container pair separate. All twenty native references
match full CRC64, header, self-virtual slots, table ID and independently captured
range hashes. The pass reads 327,680 bytes, including ten repeated physical
pages; it follows no virtual-root children. All 131 standard tests, the opt-in
native test, fmt and Clippy pass. Root reviewed and rebuilt the release, with
conversion/writer/recovery capability flags still false. Provenance:
`.lab/builds/release-20261024T004943649Z.json`; main binary SHA-256
`31c34c786ce229d8988783c47a3e0b872669fbc79cfa43292c84738db256a7d0`.
See `docs/refs-virtual-roots.md` for the exact profile and bounds.

`NativeVdlObservation` completed at 2026-10-24 01:02:11 UTC under
`vdl-observation/win11-20261024T010103919Z`. The metadata-only observer opened
the preserved file with READ_CONTROL/FILE_READ_ATTRIBUTES, performed no payload
access and recorded complete, stable before/after metadata. After clean remount,
allocation/EOF remain 65,536; cached valid-prefix summary remains 65,536, on-disk
summary remains zero, and the negative first-cluster marker plus fifteen-cluster
positive run are unchanged. Volume flags 1606825679 include
FILE_SUPPORTS_SPARSE_VDL. Treat region lists as evidence; these prefix summaries
do not assert an on-disk scalar VDL. Original fixtures remained unchanged;
baseline is restored, off/4 GiB. Observation SHA-256:
`2e76c2bcfe31df3b494dffe0d47a235095c8ea08db58cb87babe01fd8fa148d0`.
Runtime sources were archived before execution. Tests pass 84 guest/106 host
with saved source checks (76/95 ordinary) in PS5 and PS7. No move, valid-data
advancement, raw read, protection change or conversion occurred in this observer.

`NativeProtectedRangeRead` completed at 2026-10-24 01:17:23 UTC under
`protected-range-read/win11-20261024T011607181Z`. Both exact 64 KiB samples match
the initialized placement pattern, including the former source marked free in
both bitmap variants. Physical/mounted read-only protection, retrieval base,
bitmaps and known fixture identities/hashes/mappings passed before/after checks.
Two raw reads (131,072 bytes total) occurred inside the guest. Thirty evidence
files plus their manifest were exported and independently validated; baseline
was restored, off/4 GiB. Guest evidence SHA-256:
`06fde1ec5d3574bdf1886d1e27f6877db594096fcbce9872de33b7f356249dbd`.

The first protected run stopped after the reads because its safe-handle reopen
guard used IsInvalid instead of IsClosed. Its incomplete evidence remains
unchanged, with failed-branch checkpoint `1195b3f6-b1ba-4b64-84b2-4f657e2b0166`.
A fresh read-only inspection and reviewed clean shutdown preceded baseline
restoration. The narrow fix has actual Windows file-handle regression coverage;
247 guest and 251 host checks pass in PS5/PS7. No metadata writer, payload-copy
avoidance or conversion gate is promoted. See `docs/native-protected-range-read.md`.

The release at 2026-10-24 01:30 UTC adds `retained_compare.rs` and the
`compare-retained` CLI. It pins complete source/shadow images and every retained
range, compares every sector, excludes retained ranges from all reported
patches, rejects exceeded byte/range budgets without truncation, and hashes the
complete hypothetical result. A second full pass checks input stability.
It opens only ordinary local raw files read-only and emits no patch payloads.
Native semantics, allocation and conversion qualification remain false.

All 151 ordinary tests pass, including 256 tiny reconstruction patterns within
one exhaustive test, boundary coalescing, full retained-range digests, Windows
sharing behavior and CLI limits. Four previously available native opt-in tests
were not rerun; this change adds no native paired-image conversion evidence.
Fmt and Clippy pass. Root and an independent agent reviewed the changes, and
root built and smoke-checked the release. Provenance record:
`.lab/builds/release-20261024T013013347Z.json`; main executable SHA-256
`a3d3f0ca1c00e01ee481811eac81d3f592f829367e25e20140a10a1437a1155f`.
See `docs/retained-range-comparison.md` and the finite native fixture design in
`docs/next-extent-preservation-milestone.md`.

`RustRetainedCompare` completed at 2026-10-24 01:39:57 UTC under
`retained-compare/win11-20261024T013857976Z`, run
`2f0613d08dae473da76d376e769c8c37`. The exact new release executed inside the
guest against two new 8 KiB ordinary files on C:. It reported two 512-byte
patch ranges (offsets 0 and 1,536), excluded the retained 512 bytes at offset
1,024, matched the independent hypothetical result hash and preserved all
input hashes. No patch application, device control or target-volume write
occurred. All writer/semantic/conversion flags remain false.

Six bounded guest artifacts were exported and validated before clean shutdown
and baseline/off/4 GiB restoration. Guest comparison SHA-256:
`dba914f25ed69da0f31ca84d4c9730c2fe6d1b1678fda160240d74cb58d36ec5`.
Executing host helper SHA-256:
`1c1b103e84dd0fe23aa117147ae7e508d30ca51b6244a33f83b633a3ec73591a`;
162 focused checks pass in PS5/PS7. The case archives that helper, Lab.psm1,
release executable and all inputs. This runtime check establishes file-only
Rust comparison inside the guest; the native one-extent reconstruction remains
the next unimplemented experiment.
