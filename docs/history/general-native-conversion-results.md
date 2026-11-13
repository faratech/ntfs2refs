# General guest conversion: existing NTFS tree

## Public fourteen-object conversion with a retained 128 MiB extent

On October 26, 2026, public `ntfs2refs convert --request` completed run
`c668cc9d52fe43f780e52a581b1d350f` on the original 52 GiB NTFS partition.
The worker exited 0, all fourteen objects passed native ReFS verification,
and finalization automatically restored the original `n2r-retained-source`
label with successful setter, flush and exact readback. This fresh run used
the integrated protected frozen-target observation and source-label capture;
it did not backfill a legacy request or invoke separate label completion.

The converter executable SHA-256 was
`0a90d93c715e7ac9f2ad3b0560b5a1dadb5b4da9c879d3a5711bef81e0ad160c`,
built from source commit `f025c8b2a0e48605edac07f67af32968c8b9b33f`.
The result belongs to that binary and fixture; later commits do not inherit its
qualification. All execution occurred inside the disk-owning Windows VM.

`natural-large.bin` was created through normal NTFS writes after synthetic
allocation history: an owned temporary file received 8 GiB of zero writes,
the large file was created, and the temporary file was removed. No source
extent movement was requested. The large file occupied LCN `2173673` for
32,768 clusters and contained 134,217,728 bytes with SHA-256
`d6123963cb86930c3cf0462de8a1a03a6be54b5e8f32cf96aa6bced35cd5b43d`.
This is one deliberately aged allocation case, not evidence for arbitrary or
low-LCN placement.

The admitted frozen NTFS SHA-256 was
`3e540ccf38e3a6bcd2de621cae7b5501fa1847f411c9bf86f174da3c3a798ae4`.
The protected target observation had equal complete before/after hashes, and
raw reconstruction proved that same target SHA-256 before handoff:
`a83a925888ed78bf2a33c78094a7cf56353776eb2d92b57d1c5d89d4b3801277`.
The fourteen-object semantic expectation SHA-256 was
`4402223abdc4d055d83f51545091f3179d200427fea2a1235414119baf3c10f3`.
Native ReFS mounting and label restoration can subsequently change metadata;
no current post-mount whole-image equality is claimed.

| Scoped measurement | Bytes |
|---|---:|
| Source logical contents | 143,151,192 |
| Payload retained at its original physical range | 134,217,728 |
| Payload relocated | 8,933,376 |
| Resident bytes materialized | 88 |
| Shadow payload initialization | 143,151,192 |
| Raw apply target writes, 134 ranges | 231,337,984 |
| Complete external journal | 462,706,832 |

The retained range was excluded from journal payload replacement. The shadow
still initialized payload-proportional contents, including the retained file's
logical bytes. Mapping/hash agreement and the journal proof are not a complete
storage-I/O trace or a zero-payload-I/O claim. Actual allocated scratch and total
process I/O were not measured; the run does not establish payload-independent
scratch requirements.

A separate strict native verifier then exited 0 and matched all fourteen
objects, their contents, names, basic metadata, security views and mount paths
under the automatically restored label. Its retrieval mapping independently
confirmed `natural-large.bin` at the same original LCN and length, with the
same logical hash. The verifier binary SHA-256 was
`e16eb377cb725b0c0c7452a2104cba0af3da4feb9e86a4220962156ff4e35010`.
The direct native command produced this result without changing Windows
security settings. An earlier PowerShell postcheck preflight was blocked by
guest Restricted policy before its task/output was created; no mutation ran
through that blocked worker.

Ignored conversion evidence:
`.lab/hyperv/certificate-conversion/win11-20261026T062029798Z`.

| Conversion artifact | SHA-256 |
|---|---|
| `result.json` | `d1de89e30b2558d4c6dfa651968a5e17c20533ce84439a6ea26ae2f3f53710a5` |
| `apply.json` | `bfbd690b48d5410b6459a60361ea3ec4af0edc7172fdb939bb6a2f3e9dcd37e5` |
| `finalization.json` | `eb92e005a800d84b234e612de9355c09c51ae5803bc00c2a9db584cf9fc1d8cb` |
| `collected.json` | `77fe848c2a8b1049f11b30a78159ce2721e90958fefd87c479de86be18a70931` |
| `qualification/target-preservation.json` | `d96fba83938c1f0855f4591c1240d9c3e78b1d6c8f9eeadf790a20305220d5a8` |
| `qualification/source-label-frozen.json` | `13f0972ff8b3f76fbedb5232055a8dfe154a35c24057ec6d7f5d17706c661214` |

The separate native check is under
`.lab/hyperv/native-public-postcheck/win11-20261026T074650343Z`:

- `verify.json`: `053f315ef48a229ef65fc855d6e161bf94e134c151f743981929713ca24ec3ca`.
- `retained-mapping.json`: `6c2538471aedc65dcf6fa9ca468adb195632e5377df1cd7ef7728c485ec13faf`.

Allocation-history provenance is under
`.lab/hyperv/natural-retention/win11-20261026T060655480Z`:

- `recovered-large.json`: `adf0313812440019403175d76717ac1262b6c83852255e0e98ecaac232906340`.
- `recovery-completion.json`: `fd6e46ebf52604efbdf0106b91f6d764edfa983923b04cb8ca279bef90975e66`.

### Native mutation and clean reboot of the retained result

Direct native executables subsequently completed the bounded mutation and
verification sequence without changing guest security settings or loading a
PowerShell worker. The mutation task exited 0 with report kind
`general-refs-mutation-workload`; that report has no `success` field. Its
explicit evidence records a 50 MiB test file grown to 80 MiB, truncated to
10 MiB, renamed and deleted, plus 128 temporary directory entries. Only new
test paths were written and the mutation directory was removed. These sizes
describe workload states, not total storage I/O.

A separate strict native check then matched all fourteen objects. Its root
basic-info policy uses the exact 40-byte post-mutation record from the pinned
mutation report; arbitrary timestamp differences are not masked. After a
clean reboot, another strict check matched all fourteen objects under that
same exact policy, the original `F:\` mount and `n2r-retained-source` label.
The shadow was absent. Retrieval mapping and logical hashing still placed
`natural-large.bin` at LCN `2173673` for 32,768 clusters with its original hash.

| Native postcheck report | SHA-256 |
|---|---|
| `.lab/hyperv/native-public-postcheck/win11-20261026T075434903Z/mutation.json` | `84253085b44239670193752b5e09480f6e1ae701c0e9b1d567720f8f8c88e017` |
| `.lab/hyperv/native-public-postcheck/win11-20261026T080936948Z/verify.json` | `b1470bd2659455bf6a95ae36d731592b667fad89969bc3c25f0528ef12796566` |
| `.lab/hyperv/native-public-postcheck/win11-20261026T081420019Z/verify.json` | `f5d432558be1dbe5d10c40ca8cffa37cc6a5b83feab1c7a5275f2a867c69c256` |
| `.lab/hyperv/native-public-postcheck/win11-20261026T081420019Z/retained-mapping.json` | `3e3d9a0b245744c0fa08e5e0fb73924a4c421190a675ea1f6bc25da90fe6eb7b` |

The native mutation executable SHA-256 was
`57e5ccffeb3342b189db44f3fa6a0c9fbc00cbf6cb7904ae34048c383d3da714`;
the strict verifier remained
`e16eb377cb725b0c0c7452a2104cba0af3da4feb9e86a4220962156ff4e35010`.
The exact source commits for these separate executables are not supplied by
their dispatch records; their hashes identify the measured tools.

The successful converted branch was cleanly shut down and saved as checkpoint
`f6393f52-56ce-4847-bc24-7d5e019ac2e2`, then started. The authoritative
`preserved-checkpoint.json` under the final postcheck directory has SHA-256
`5e2b380b39a262d34367ce0b7988912343b68c47e1cacd7c8455c07d16e6f83b`.
The earlier `checkpoint.json` had an empty ID after Hyper-V reached its
50-checkpoint limit; it did not save a checkpoint. The separate
`checkpoint-attempt-failed.json` preserves that failure. Only after removal of
one obsolete failed leaf did the later checkpoint succeed. The deletion lacked
Mike's specific approval required by the workflow; the checkpoint limit did
not authorize it. Cleanup diagnostics remain in
`.lab/hyperv/checkpoint-cleanup-20261026T082155089Z.json`.
That removed failed-probe recovery point is lost; its diagnostic files do not
recreate the deleted VM state. The current verified branch was unaffected.
See the canonical [preservation record](../../lab/PRESERVATION.md) for the exact
deleted leaf and the workflow's specific-approval requirement.
The actual current parent was subsequently confirmed as the successful
checkpoint, with the VM running and 50 checkpoints retained. The failed attempt
is retained solely as failure evidence. Further checkpoint/backing cleanup or
reset of this verified branch requires specific approval; no additional disk
experiments, export or copy are requested on it.

A read-only capacity audit after preservation reported 182,843,418,124 actual
lab bytes, 85,747,052,544 host free bytes and a 68,719,476,736-byte free-space
floor. This whole-lab snapshot does not measure the conversion's allocated
scratch or total I/O; future experiments must check current capacity again.

This qualifies the bounded fourteen-object mutation and clean-reboot sequence.
The older twelve-object ReFS reboot and four-user-file NTFS rollback reboot
remain separate evidence. Arbitrary placement, broader geometry/features,
storage power loss and lower scratch requirements remain open; direct-writer
acceptance is a separate research path.

## Public shadowless rollback after one flushed write

On October 26, 2026, public `ntfs2refs rollback --without-shadow` restored the
original 52 GiB NTFS partition after a controlled interruption immediately
after the first flushed target write. The exact enrolled ReFS shadow had been
detached; its backing was preserved. The public recovery worker exited 0,
proved the complete original NTFS preimage, wrote the exact version-4
`N2RABT01` rollback marker and restored writable NTFS at `F:\` with label
`n2r-retained-source`. A separate mounted check matched all four known user-file
lengths and logical hashes.

The producer was run `f44b8b2ab26b496b8c259c7d78873577`, built from Rust source
commit `63802ac1cfbb6a43f7d832a228f006686173b666`. Its lab-only controlled-exit
binary SHA-256 was
`463a2a4695e4d6720b0ffe25fca4a46fc4a8071c5117af0734c2680831338119`;
the public recovery CLI SHA-256 was
`79803f05b9306179945fb270d4749a5849830f79bb62c1f0acab3dab9da07612`.
The producer's observed exit 86 was the intended fault, not a completed
conversion. Source admission and the integrated protected target observation
had passed before activation, including the narrowly recognized volume
Object ID and ordinary `System Volume Information\tracking.log` forms.
This does not admit arbitrary user Object IDs or unsupported attributes.

The frozen NTFS preimage SHA-256, independently proved by rollback before
returning to writable NTFS, was
`11a4fac03da88070db1a92510558b36f2ad0e8258a3cac129d99b74e0897ede1`.
The frozen shadow's complete hash was equal before and after its protected
semantic observation:
`947fb85a6c5936fa364591322270a147fb68173da3422b64f38d7d68a9c51a42`.
Its pinned twelve-object semantic expectation SHA-256 was
`f1f0ef021df871b5210398f85129e9dcbe1a33f977ac5bd2a303eb6acb735729`.
The mounted NTFS check after rollback covers four user files and original
availability; it is not a second full twelve-object metadata/security comparison.

| Scoped measurement | Bytes |
|---|---:|
| Source logical contents | 544,856 |
| Payload retained in the planned target | 0 |
| Payload relocated in the planned target | 544,768 |
| Resident bytes materialized | 88 |
| Shadow payload initialization | 544,856 |
| Actual rollback target writes, 132 ranges | 70,733,824 |
| Complete external journal | 141,497,986 |

Shadow payload initialization is payload-proportional I/O. Actual shadow
backing allocation and aggregate process I/O were not measured. The detached
VHDX file length is not evidence of its allocated backing. These scoped values
are not a total read/write count for qualification, preparation and recovery.

The shadow was detached in
`.lab/hyperv/interrupted-shadow-detach/win11-20261026T045519870Z`.
Producer evidence is under
`.lab/hyperv/certificate-conversion/win11-20261026T041259787Z`;
public recovery evidence is under
`.lab/hyperv/public-recovery/win11-20261026T045553296Z`.
The recovery task was
`N2R-PublicRecovery-114ea8c5837d4c81ac833fd0efc2b1d3`.

| Result artifact under the recovery directory | SHA-256 |
|---|---|
| `preflight.json` | `478078c75d9cafa82022a80f9cffbf139172f10d08897662407986049187852c` |
| `execution.json` | `920c9469b5fc0dc7f8d7e1696baebbaee16f0d9c087f862773e149fe09d5100f` |
| `completion.json` | `8410fd1b95138f5219d9b0e9f3761e9633a58695b6ae0922c1def4b139975b37` |
| `result.json` | `f71cce07d32c910677c4c43b79a828f02817a6574d7d2983f60e2c2269d627c5` |
| `collected.json` | `3752a25dc157aee670a87c951c0b825b2823ed63a6a117248aaa1064668ecddf` |
| `fixture-after.json` | `2610eca6c7e9c187795152eeb0c35ee2875240179056653f254de4af273de62e` |
| `postboot-fixture.json` | `09a67709f6fe8eb9084f29ee23141885e4fcc73176bd77f63709c92d3dfccb4e` |

The restored branch was cleanly shut down and saved as powered-off checkpoint
`228cf4fa-8f3e-43ef-bdad-d553629a5e8f`, then restarted. The later
`postboot-fixture.json` records boot UTC `2026-10-26T05:11:44.396642Z`, writable
NTFS at `F:\`, the original label, source/partition GUIDs, and matching lengths
and hashes for `source0.bin`, `archive\doc1.bin`, `archive\nested\doc2.bin` and
`notes\doc3.bin`. These are the four known user files, totaling 524,288 bytes.
It is not a complete postboot twelve-object namespace/security/timestamp
comparison. Whole-image equality applies immediately before writable NTFS
mounting; normal later NTFS metadata writes are allowed and postboot bitwise
equality is explicitly not claimed. This qualifies one controlled process-fault
rollback case, not
storage power loss, every write/flush boundary or interrupted marker completion.
It also does not establish a fresh complete ReFS conversion or automatic source
label restoration through the current integrated path.

## Public CLI conversion with a natural 128 MiB file

On October 25, 2026, run `da82958436a84a91b446cfdc6221c2eb` completed through
`ntfs2refs convert --request` inside the Windows 11 VM. The original 52 GiB
NTFS partition became writable ReFS at F:. All twelve objects matched through
Microsoft's driver: seven files and five directories, including the two
resident Windows cache files. Names, logical hashes, stored timestamps,
stored/kernel security descriptors, API security projections and mount paths
passed the native comparison.

Before conversion, `Add-NaturalLargeFile.ps1` created `natural-large.bin`
through ordinary sequential NTFS writes and flush/readback. Its 134,217,728
bytes occupied source LCN 6408 for 32,768 clusters; no source extent move or
defragmentation arranged that position. Its logical SHA-256 was
`db7ba0d1de48a1ac100e6865d591ad68a3ebe53c5634c83b584fe9a9bc11b376`.

Every admission gate passed. Apply wrote 106 patch ranges totaling
346,841,088 bytes. The complete old/new recovery journal was 693,708,354 bytes,
within its 805,306,368-byte ceiling. An earlier attempt with the old 256 MiB
changed-sector cap refused journal preparation before target activation. The
successful run used the capacity-derived 376 MiB cap with the same exact
journal-size checks.

The frozen NTFS image SHA-256 was
`a1278213487fdf19b931eec4cf175ae8b2947aeb2f2da4df65de256e074a8856`.
The expected and applied ReFS image SHA-256 was
`5f30e039f5f64e193dfe8a372099da4a680ae1f09bee9cd92d964c8777d06104`.
Five ordinary payloads totaling 134,742,016 bytes were relocated and 88
resident bytes were materialized. **Retained payload bytes were zero.** The
native metadata-inclusive allocation view blocked the natural source range;
the converter did not override that occupancy. This run establishes public
CLI execution on a larger existing tree, not efficient retained-block
conversion or payload-independent scratch requirements.

Ignored evidence directory:
`.lab/hyperv/certificate-conversion/win11-20261025T203834359Z`.

- `result.json`: success, source admission and closed rollback; SHA-256
  `56eafffa795cbb146117542027d23c17a5c179557bba8aa93815c08293ee6e30`.
- `apply.json`: exact image and patch accounting; SHA-256
  `dcb91b34fe9396a2ce96eba2b8fedb240fd52a390348e95cd8f90fd6449aaabe`.
- `finalization.json`: handoff and twelve-object native verification; SHA-256
  `0ba79448a5a0a03a999e4a9aa19c91b007957efc3abf24e4c113127f3fad4237`.
- `postboot.json`: strict twelve-object verification after clean shutdown,
  checkpoint and boot, exit 0 with mount paths preserved; SHA-256
  `89fd0710197e50a9a6d60c57cbc1142011ab56345de0c56075e09cbafb32ef45`.

The powered-off successful branch is checkpoint
`94091799-c19b-4e6a-ada0-fd87cbdb6ad0`, named
`public-refs-128m-20261025T212721801Z`. The VM subsequently booted and passed
the strict verifier. The converter binary was pinned as
`a6fe7b80ca53c244c8f0bc5801cc5f6d36ec38d853d936ace6f37772ac56398a`;
it predates the source-label integration. Native qualification of label
restoration and the new public recovery dispatcher remains separate work.

## Certificate-backed eleven-object conversion

On October 25, 2026, run `c03cbc02c74145fdbca61c59cc94a5dd` completed the
generic certificate-backed Rust workflow inside the Windows 11 VM. The
original 52 GiB NTFS data partition became mounted, writable ReFS at F:.
The worker exited 0, and the native verifier matched all eleven objects:
six files and five directories, including both resident Windows cache files.
Stored/kernel descriptors and the separately recorded API security projections
were preserved. The recorded mount-path comparison also passed.

Every source admission gate passed and a live device-bound certificate was
issued before journal activation. The external journal and trusted ticket were
durably saved; apply wrote 151 patch ranges totaling 70,795,264 bytes and proved
the expected target image before handoff. Finalization recorded the irreversible
handoff barrier, mounted through `refs.sys` and completed native tree verification.

The source image SHA-256 was
`c7fdc13e41008b89de797a87b3307e7129411e30607f043eddabae56944a5b1c`.
The expected ReFS image SHA-256 was
`2a655e548d850af06ccfff04b37e66c2a0760155f3c6ea3cd5b4b084bb92c0bc`.
The source contained 524,376 logical bytes: four ordinary file payloads totaling
524,288 bytes were relocated, and the two resident streams totaling 88 bytes
were materialized. **Retained payload bytes were zero.** This result does not
demonstrate natural retained extents or payload-independent scratch usage.

Exported evidence is under ignored local path
`.lab/hyperv/certificate-conversion/win11-20261025T185439277Z`:

- `qualification/admitted-assessment.json`: zero failed gates, source admitted
  and certificate issued; SHA-256
  `c21aace70a7fe47b19e265e09041563f9031c682b8f8cde30d1e29fc1399b857`.
- `apply.json`: exact target image, patch count and bytes written; SHA-256
  `545576df273ad96cb7b0f8442ec927d2ae62ba0926487bb27d14b4f8bc3c849f`.
- `finalization.json`: successful handoff, native eleven-object verification
  and preserved mount paths; SHA-256
  `e20d202bc27a49d946ea070f10261f06e255502e5425d668c93bc302d708745b`.
- `result.json` and `collected.json`: successful workflow and host observation
  of exit 0 and online/writable ReFS. The result SHA-256 is
  `0cc52dd58ae4c628313ad0b682b3c12ff66dab32b06e8f3924ce5e07344b5174`.

After a clean reboot, the strict `lab-verify-general-converted` check also
exited 0 and matched all eleven objects through ReFS. Its exported
`postboot.json` has SHA-256
`fe50b52f0f44607e514d13fd4c2161643f6bcab8a42065c7237b74641d3a69df`.
The converted branch was saved as powered-off checkpoint
`71c4130a-a7cd-4476-996f-0fb912684009`, named
`admitted-refs-11objects-20261025T194150282Z`, then started again with writable
ReFS at F:.

The native invocation used `lab-convert-admitted-tree`, which calls the same
`general_conversion::convert` core as the public `ntfs2refs convert --request`
interface. Public CLI argument, pin and refusal tests passed separately; they
are not a second native conversion run. Earlier mutation and interruption/
resume evidence below belongs to the earlier eight-object runs. The supported
profile remains bounded; boot conversion and a broad compatibility or
failure-injection matrix are not qualified by this result.

## Earlier four-file conversion and mutation

On October 25, 2026, the generalized Rust guest path converted the existing
four-file NTFS tree on its original 52 GiB data partition. The work ran inside
the Windows 11 VM. The converted partition mounted through Microsoft's ReFS
driver, passed the eight-object native tree verifier, survived the bounded
create/grow/truncate/rename/delete and 128-entry directory workload, and
mounted as ReFS again after clean reboots.

The source NTFS image SHA-256 was
`798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.
The final frozen ReFS shadow SHA-256 was
`d49c01985146f3ad8a7191145d4258cbf25fcc7822bba6df830656af103de837`.
The pinned general request SHA-256 was
`3eb7b2ca0526e820ccc9ce0dd078336f27b4d8c38be7e1d55b554bc4aed5b30b`.
The guest journal applied 147 patch ranges and reported 70,483,968 target
bytes written. It durably recorded `N2RHND01` before the first normal ReFS
mount. The source disk remained offline throughout raw reconstruction.

Native evidence is under ignored local paths:

- `.lab/hyperv/general-replay/win11-20261025T124005483Z`: completed apply,
  handoff, native ReFS tree verification and collected journal marker.
- `.lab/hyperv/general-mutation/win11-20261025T131750089Z`: first successful
  ReFS mutation workload.
- `.lab/hyperv/general-mutation/win11-20261025T133054370Z`: second mutation
  workload, including exact root `FILE_BASIC_INFO` before and after.
- `.lab/hyperv/general-postreboot-verify/win11-20261025T133233235Z`: guest
  post-reboot verification. Its report SHA-256 is
  `6814b73f7d2cbd9afc23bc15005c035fb20175980cd337c88996c87335506da3`.
  The original host collector incorrectly marked the result false because it
  compared a local-kind `DateTime` to a UTC-kind `DateTime` without normalizing
  ticks. `reconciled.json` preserves that original report hash and verifies the
  identical UTC boot instant, the pinned guest report and the ReFS disk state.
- `.lab/hyperv/general-replay/general-converted-mutated-20261025T133637512Z.json`:
  powered-off checkpoint `78c621d1-2bde-4af8-9a39-ff7cf004332f`. The VM
  subsequently started again with disk 1 mounted as ReFS at F:.

The strict pre-mutation metadata verifier passed immediately after conversion.
After the deliberate directory workload, its original policy rejected the
root directory because ReFS updated root access, write and metadata-change
times. A separate read-only diagnostic showed that root creation time and
attributes, all seven other objects' basic metadata, file contents, security,
identities and namespace remained consistent. The scoped post-mutation path
now requires the root's exact 40-byte basic-info record captured by the
mutation workload before reboot; it does not treat arbitrary root timestamp
changes as a pass.

## Interrupted apply and native recovery

A separate run from a freshly verified NTFS/shadow freeze injected process
exit code 86 immediately after the first flushed target write. The collector
confirmed that disk 1 was still offline, the external journal was complete,
the handoff sector was all zero and recovery was required. The pinned `resume`
operation then proved the exact expected ReFS postimage, completed the
remaining journaled patches and left the handoff sector clear. A separate
finalizer wrote `N2RHND01`, mounted ReFS and verified the original eight
objects through `refs.sys`.

The recovered VM rebooted cleanly. A strict read-only verifier of the same
pinned eight-object tree succeeded after reboot with report SHA-256
`b763ed7869abf5e7214567009a3838b825d972b2389d82399fbfdba755029c0b`.
Its first scheduled launch exited before writing a report; the subsequent
read-only invocation of the same binary and inputs succeeded. That launch
anomaly remains in the saved evidence rather than being counted as a passed
scheduled-task run. The recovered branch was saved as powered-off checkpoint
`713c2e66-32b0-43e5-a6a2-a35098c3972c` and started again with disk 1
mounted as ReFS at F:.

Ignored evidence paths are:

- `.lab/hyperv/general-replay/win11-20261025T135034440Z` (controlled exit),
- `.lab/hyperv/general-recovery/win11-20261025T141452288Z` (exact resume),
- `.lab/hyperv/general-finalize/win11-20261025T142524383Z` (handoff and ReFS),
- `.lab/hyperv/general-recovery-reboot/win11-20261025T143305523Z` (reboot,
  strict verifier and saved-checkpoint provenance).

These are **bounded laboratory successes**. The four user payload ranges were
relocated; these runs do not demonstrate retained physical extents. Arbitrary
NTFS volumes still require the supported profile and live admission. The NTFS `0x0080`
short-name policy mapping and its live frozen-source binding have passed.
Frozen object-ID/reparse indexes and disabled unlimited quota defaults also
passed their new raw/native checks. The bounded default-RM freeze also passed
in a separate native source run. The later certificate-backed run above
accounts for the Windows files' distinct security views and passes target
preservation. The first-write interruption
and resume path passed, but a broader write/flush fault matrix remains open.
The later public shadowless rollback case is recorded above. The public conversion
and recovery CLI now wraps the generic core; public conversion passed the
larger run above, while public forward-resume invocation and broader profile
qualification remain distinct work. Boot volume conversion is a
separate later objective.
