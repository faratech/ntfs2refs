# Experimental build provenance — 2026-10-29

## Reconciled public build — 2026-10-30

The mixed recovery matrix used public executable SHA-256
`121d7dbb9977618af7790f4fcd78e69fee3c4274e9e2980c1a3d0709dd322f0b`.
Its effective source is commit `909911062106dbde6cf35fbcdccf4a45b2998671`
with `src/main.rs` replaced by the preserved `main.rs.snapshot`, SHA-256
`c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b`.
That snapshot is byte-identical to the user's current unstaged edit, which was
left untouched. The overlay removes two reported experimental capability
fields; it does not change the conversion or recovery implementation.

The [source/build record](../../evidence/public-build-provenance-9099110-20261030.json)
pins a Git source archive, the exact overlay, an 805-file source manifest,
the tested executable, and its matching PDB. The compiler is Rust 1.98.1;
the preserved configuration enables static CRT and release overflow checks.

Bit-for-bit rebuilding of this historical executable remains unproven. Its PE
contains wall-clock timestamp `1793356395` and CodeView GUID
`50d664d9-5744-4329-89dd-70d5065f023b`, with no REPRO debug entry. The original
linker environment was not fully sealed. An ordinary later relink is therefore
not claimed to reproduce the tested SHA-256. No binary was patched to remove
that difference, and no fresh build inherits the native qualification.

The original mixed-run duration summary was also corrected from its raw UTC
terminal string and creation epoch to 1511.1490251 seconds. The earlier summary
had lost the timestamp's UTC suffix and fractional seconds during reparsing;
the original native reports and their hashes are unchanged.

## Historical observations

The bounded native-shadow experiment has completed conversion, deliberate
interruption, reboot recovery in both directions, native file verification,
and a new post-recovery mutation workload followed by a genuine reboot check.
These results belong to the exact builds and corpus below. They do not establish
a generally safe release or support for arbitrary volumes.

The machine-readable index is
[experimental-build-provenance-20261029.json](../../evidence/experimental-build-provenance-20261029.json).
It records hashes of closed host-side reports. It grants no source admission,
attribute-change, formatting, or journal-replay authority. This reconciliation
read closed metadata and existing executables; it did not rerun the laboratory
or rehash source, journal, packed backing, or disk-image contents.

## Exact builds and observations

| Role | Recorded source commit | Executable SHA-256 | Scope |
|---|---|---|---|
| Affirmative public `ntfs2refs --drive F --partition 2` | `cfc48ff9ef54c30a672d312791a028d5e9732efd` | `866fc5bbf0f95ef5a091eb211e846573197f7b9bd27c9a1848f45e8ba6951627` | Actual affirmative stdin, automatic owned staging, source admission, apply/HND/native verification, then seven user-file hashes after cold boot. |
| Managed selected-device controlled converter | `cf19108364c180bec4d95f7efda0254a766e178d` | `48094c2b2f3fce10a5b64c5154c1a93837f1415709d611df105bb1a7b3b6735e` | Run `94eebb1101354d2ca42c2f8f0608f6a0`; deliberate exit 86 after one flushed source patch. |
| Managed typed recovery, `ntfs2refs-compact` | `5a9bae2859279aa3a40287a354d42a1502b26446` | `565fb0a70d03b3587417f326036e38ffe7f12c6d78fe48afe6fb99ea82f9d3f0` | Separate native Resume + Finalize and Rollback processes all exited 0 against that original managed journal. |
| Current native ReFS mutator | `f32b56333ec82c5de20a9ad8066b30a99b09110c` | `c71d2a6237c33623980fef10a1d66f8a8886efa7e271f2eff83c9d2a971da6b0` | New ordinary filesystem workload on the exact `565fb0...`-recovered ReFS branch. |
| Current strict native verifier | `f32b56333ec82c5de20a9ad8066b30a99b09110c` | `571e07b3ef79d397ebc77042bea5177e077df4ee4936648c8897cb9a727420c5` | Before/after that workload and again after clean stop/start without restoring the branch. |
| Later local `target/release/ntfs2refs.exe` | Source/build attestation not established by this index; observed at repository HEAD `f32b56333ec82c5de20a9ad8066b30a99b09110c` | `dbe90070d12f9fd544e380d220a79b54e7d4f220debe339a2c9bf272449f6580` | Different executable after the drive-inventory write-protection change. No inherited native qualification. |

The source commits are recorded build provenance, not proof of a clean historical
working tree or reproducible output. The public build manifest explicitly notes
the preserved working-tree capabilities change. Binary hashes identify the
artifacts that actually ran.

The public affirmative result is recorded separately in
[drive-cli-native-20261028.json](../../evidence/drive-cli-native-20261028.json).
It is **not** a test of the `866fc5...` binary with the `565fb0...` recovery
binary. The managed `48094c...` / `565fb0...` pair exercised the streaming-v2
reconstruction protocol with its own original source certificate, request,
ticket, compact capture and backing identities.

A scoped source comparison of `cfc48ff..cf191083` shows the added lab-only
selected-device interruption entry in `general_conversion/composite.rs`. The
public selected entry still passes no interruption request and retains the
original live-admission gates. That range also contains batching, progress and
managed-recovery wiring changes; it is not an assertion that the executables or
all runtime paths are identical. `Cargo.toml` and `Cargo.lock` are unchanged
across that range. No GPL reference writer/parser forms part of this product
runtime; the native-shadow path uses Windows' formatter and ReFS driver.

## Managed recovery evidence

All paths below are relative to
`.lab/hyperv/streaming-v2-20261027/managed-compact-interrupt-20261028-94eebb1101354d2ca42c2f8f0608f6a0/`.

| Closed report | SHA-256 |
|---|---|
| `partial-metadata-pins.json` | `0d173cdac2cd8caf11b629541d2661ee2eae9cc050b5d4ec9fb7fe16a9b53ef5` |
| `recovery-resume/closed-metadata-pins.json` | `12ff6f9445e60366305ddf55c12f556185a07c5b91e779d4371061d4e553621a` |
| `recovery-resume/preserved-checkpoint.json` | `1fb99f3c759b3c1346004198633e994b76f4d96e5fcdf2260cd9046f03574afe` |
| `recovery-rollback/closed-metadata-pins.json` | `203f518142da668a8cb5160450d1902a76df46e66491c9140dd1d354ca399e7f` |
| `recovery-rollback/preserved-checkpoint.json` | `7ce3e0f7791c4dc3dd30b13dd7174006765d556783041bfc2d0dbf773229e7ce` |
| `recovery-rollback/user-readback-4a804f0b0a6b4c41bd71f60f55a67dee/receipt.json` | `01b74c0757c91800e718a845d900e6d20e92fd7a6f390f4c7ed36c6a8734ddaf` |

Resume run `bc1f392dd42f4ab0af052e8235728cc8` recovered the complete excluded
ReFS image, then separate Finalize persisted HND before native mounting and
verified 15 objects and 10 full stream hashes, label and mount. The recorded
pre-mount target hash is
`1e6193b8f359d6df330c4073d7cc0fd10efa565549bd96906fe3b5e2ab012a6d`.
The patch plan contains 161 patches / 70,578,176 bytes.

Rollback run `95d490e280ac4b608bd118d63580a367` started from the separately
restored interrupted checkpoint. It proved the exact frozen original NTFS hash
`1bf93b0a7ea784fa04e9910a8e19fc3a94b36ee693b8404499fe45381a49c40e`,
persisted ABT, and mounted NTFS under the original label and path. Subsequent
native readback matched all seven user-file hashes / 8,594,391,095 logical bytes.
It also checked native attributes, creation/write times and Owner|Group|Access
SDDL for those files; all seven access times matched. This readback excluded
three SVI files, did not query MFT change time or SACLs, and is not an independent
post-mount raw-image, complete namespace/security, or storage-validity proof.

Recovery after reboot reattached the exact pinned managed VHDX read-only. When
Windows reported hardware write protection without software disk attributes,
native `IOCTL_DISK_IS_WRITABLE` had to return `ERROR_WRITE_PROTECT` before adding
only missing persistent protection bits. Exact provider identity, GPT/geometry,
disk number, Windows-disk exclusion and held-backing checks remained required.
Earlier refusals were archived; they did not enter core replay or write source
patches. Neither successful recovery recreated a source certificate or initiated
a fresh Apply.

## New post-recovery mutation and reboot evidence

Run `e82ae80ec6fd418a82c59cc09b90ade5` started on the actual recovered ReFS
branch `fe04b15b-14c4-48e0-ad8f-2a4752d86f8f`. The current strict verifier
passed 15 objects / 10 complete logical hashes before and after the current
mutator created a 50 MiB file, grew it to 80 MiB, truncated it to 10 MiB, exercised
128 directory entries and rename/delete operations, and removed its test tree.
All three native process exits were observed as 0. This was normal ReFS use,
without raw writes, journal replay, or new source admission.

Root then cleanly stopped and started the **same working branch**, without
restore. Post-boot run `4062fb95a3b446d4bbabede2cc79d223` observed guest boot
`2026-10-29T02:57:12.675199Z`, later than mutation completion
`2026-10-29T02:53:42.8488096Z`. The same current verifier exited 0 and again
passed all 15 objects / 10 complete logical hashes and supported metadata,
including the original label and mount. It used the exact request-bound
mutation root policy: ordinary mutation changes root metadata, so no claim is
made that every timestamp or the complete raw image remained unchanged.

Additional paths relative to the managed case root above:

| Closed report | SHA-256 |
|---|---|
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/closed-preboot/result.json` | `19be3f1155a36436d2419215b8d9b952e8a3b6f29aa7fb7cc37e34f7277d87d8` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/closed-preboot/mutation.json` | `5ce149f401c85389a97171bb10f5d764e97a9987e06bffe9b00d2e5668941b4a` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/closed-preboot/verify-before.json` | `50701c20ab969f9bca5382c854fef68bc95fbb34a5e96bc06c56a321da17bfb3` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/closed-preboot/verify-after.json` | `a88badd5c19912ab56868b0f9e3d9f5691982f6f9bbd48715053ab43bfc14a90` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/after-boot-4062fb95a3b446d4bbabede2cc79d223/closed-native-pins.json` | `2952d620a06f469c01729958f8daf958bbc72775fef05a7c64bc5835b70e048b` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/after-boot-4062fb95a3b446d4bbabede2cc79d223/closed-native/result.json` | `54232cd5a98179d200ca570ed975151a1fed2ae57b80dab2064cadfc7fb6dd12` |
| `recovered-mutation-e82ae80ec6fd418a82c59cc09b90ade5/after-boot-4062fb95a3b446d4bbabede2cc79d223/closed-native/native-after-boot.json` | `2aa41e372809057149a1c212dbd86cba4c1bb71cf4767bb029393fa526897037` |

The toolset manifest is
`.lab/hyperv/streaming-v2-20261027/managed-recovered-mutation-tools-20261029/manifest.json`,
SHA-256 `cd7df2d62ce8779980d8edc176ebe428026ace25c63a25ef286351d7b90a0690`.
These new measurements extend the managed `48094c...` / `565fb0...` case using
the separately pinned `c71d2a...` / `571e07...` observation tools. They do not
create a test of the separate public `866fc5...` binary with recovery `565fb0...`.

The older `5e156f...` mutation/reboot result in
[native-composite-alpha-20261028.json](../../evidence/native-composite-alpha-20261028.json)
and [native-composite-experimental.md](native-composite-experimental.md) remains
historical evidence for that build. It was not reused to qualify this new
post-recovery mutation/reboot result. Older observer reports retain their
original, then-pending status; this index adds the subsequently closed proof.

## Operating boundary

Conversion and recovery execute inside the Windows machine owning the volume;
Hyper-V provides disposable laboratory disks and branches. Current evidence is
a 52 GiB basic data partition with NTFS 64 KiB source clusters, ReFS 4 KiB target
clusters and 512-byte logical / 4096-byte physical sectors. It is a small
ordinary-file corpus, dominated in logical size by an 8 GiB-plus-one zero file.

Use the explicit experimental resource/profile and current native admission
rules from a privileged local process with the required raw-volume and
manage-volume access and the compatible native ReFS formatter available.
Only the new owned scratch volume enters that formatter. The streaming-v2
policy bounds files to 1024 and directories to 256;
addressing and bitmap bounds are not qualification of volumes at those limits.
Boot/system conversion, arbitrary NTFS features, arbitrary sector/cluster
geometries, 10 MB and 1000 TB volumes, near-full media and broad Windows/ReFS
version compatibility have not been established. No generally safe or
release-ready status follows from these runs.

The public CLI currently requires independent working storage on the Windows
OS disk and automatically creates an owned dynamic VHDX. Its virtual capacity
is not its actual allocated space. Keep the exact request, ticket, expectation,
capture, packed backing, journal, managed-shadow identity receipt, binaries and
hashes available through recovery. Recovery requires the original exact device
routes and actual exclusion state; JSON success flags cannot substitute for
native checks. See the [recovery contract](native-composite-experimental.md#recovery).

HND and ABT close old raw replay. Never replay the old journal after normal
filesystem use, reset its barrier, or clear protection to bypass a refusal.
The controlled exit-86 experiment does not qualify power loss, torn writes,
missing/corrupted recovery storage or every interruption point.

Small changed-byte counts in this largely zero-filled corpus do not prove
payload-independent scratch, physical retention of all source extents, or
constant total I/O/RAM for arbitrary data. Full-image verification passes remain;
large nonzero workloads, fragmented free space and scratch budgeting need their
own measured evidence.

## Checkpoint history

The user explicitly superseded the old preserve-all laboratory policy. Hyper-V
removed 48 of 50 old checkpoints and freed 35,042,988,032 bytes; the closed cleanup
receipt is pinned in the evidence index. The original attempted checkpoint 51
never existed. The actual post-cleanup partial checkpoint is
`48cf6276-fa77-4f35-b56e-8bdd6017b192`; resume and rollback receipts recorded four
and five total checkpoints respectively. A second authorized cleanup removed
three obsolete baseline/partial checkpoints and recorded only the recovered
ReFS `fe04b15b-14c4-48e0-ad8f-2a4752d86f8f` and rolled-back NTFS
`0872b74c-5b3d-43cf-9ccf-fc64fda0cd93` branches at
`2026-10-29T02:46:27.0921663Z`. Its receipt SHA-256 is
`6da9fdb597ce830216c463ea2a2db409690bf8a38309f05db645946a83aded04`.
These are historical capture counts, not a current checkpoint inventory or an
instruction to recreate old branches. Post-mutation checkpoint preservation
and later pruning are not asserted without their actual receipts; original
evidence is left unchanged.
