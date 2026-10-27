# Isolated unmodified-baseline source prerequisites

These case-specific guards prepare review plans for VM
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`, `ntfs2refs-reference-isolated`.
They do not operate a VM, open a device, initialize/format storage, import a packet
or grant native write authority. The old VM and all checkpoints remain forbidden
execution targets. Existing helpers and their global route constants are unchanged.

`lab/IsolatedBaselineGuards.psm1` validates captured structural observations:

- Exact VM GUID, configuration path, 8 GiB fixed RAM, four vCPUs, no NIC and
  preserved vTPM/Secure Boot settings.
- Each OS/target/journal backing's exact path, host volume GUID and host file ID,
  standalone parent state, single-link path and sole current-controller owner.
  A container UUID or guest computer name alone never establishes ownership.
  A live inventory must include every current/checkpoint/ancestor file by host
  volume/file identity; an input `inventory_complete` claim is not a native proof.
- The copied journal at controller 0/location 2, guest disk 2, UniqueId
  `600224806AAC261F021F249596F332FC`, 8 GiB and 512/4096 sectors. RAW state,
  empty partition inventory, nonboot/nonsystem flags and unoccupied J: are required.
  Guest SCSI LUN/location and the actual Windows-disk route must agree.
- Fresh J: GPT, partition and mount-manager identities, refusing the old journal
  GUIDs and imported-reference identities. The volume GUID may equal the GPT
  partition GUID; each is still separately observed. The current review profile
  has one basic-data partition, number 1, at 16 MiB with length `8 GiB - 32 MiB`,
  NTFS/4 KiB, and exactly J: plus its canonical volume path. A different layout,
  including an MSR variant, needs an explicitly reviewed profile before execution.
- A fresh reference creation identity and J: backing path. The post-creation
  review additionally joins provider physical path, disk number >=3, fresh file
  identity, J: volume identity, standalone dynamic VHDX geometry and exactly one
  new guest device. The actual device number may be discovered after creation;
  it is not inferred from the disk count.
- Baseline-only mode with packet SHA-256
  `585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b`,
  zero writer pages/bytes/payload writes, no overlay inputs and no adopted file.

`lab/guest/IsolatedJournalZero.cs` scans a caller-provided held read-only seekable
stream. `ScanJournal` requires exactly 8,589,934,592 bytes, checks every byte,
completes legitimate short reads, verifies end/length and records SHA-256. Any
nonzero byte, early EOF, read error, extra data or changed access/length refuses.
Its opaque proof has no public constructor, is tied to that same held stream and
identity token, and grants no write authority. `ScanRange` is a pure-test entry;
its proof cannot pass the production journal gate, even for an 8 GiB range.
The initialization **review plan** requires a complete production-scope proof;
JSON `allZero`/success fields and proofs for another/closed/changed stream fail.

The scanner does not attest native handle origin, exclude external writers,
collect live device identity or open a device. A reviewed live acquisition adapter
must still bind the exact owned native handle, its length and exclusion to the
host/guest observations. No mutating initialization/import runner is supplied by
these predicates. A serialized plan/proof cannot replace that execution boundary.

`lab/guest/IsolatedJournalReader.Windows.cs` now supplies the **guest-side read-only
acquisition code**, with a private lease constructor. Before opening a physical
device it checks the exact expected VM token, computer name and actual SMBIOS
type-1 UUID. It then requests `GENERIC_READ`, `OPEN_EXISTING` and no sharing on
`\\.\PhysicalDrive2`, with no writable fallback, privilege adjustment or disk setter.
Actual handle queries must identify disk 2, 8 GiB, 512/4096 geometry, RAW/zero
partitions, unchanged attributes, the recorded SCSI route and the device-associated
binary NAA. Header/full descriptor reads are bounded and must agree. The scanner
uses that held lease; native snapshots before and after the read, firmware and
exact byte counts must agree before a zero proof is returned. Raw query replies
are retained in a bounded transcript for independent replay.

The initialization-proof entry remains blocked before native access. The separate
observation-only entry has now read the enrolled device; its completed guest read
and subsequent host refusal are recorded below. This guest adapter does not itself
acquire host VHDX file/ancestry ownership, prove absence of other workers or establish
exclusion across every storage-stack alias. A no-sharing device open is not a
substitute for those obligations. The existing initialization review still grants
no native write authority. Unexpected native replies must refuse rather than
trigger a fallback.

The pure snapshot parser follows Microsoft's
[device-ID descriptor](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_id_descriptor),
[identifier chain](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_identifier),
[SCSI address](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_scsi_address)
and [disk attribute](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-get_disk_attributes)
layouts. Access/sharing requests use the documented
[CreateFile contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

The source plan uses a fresh `C:\ntfs2refs\isolated-baseline\<run>` staging directory
for bounded helpers, packet and reports, preserving the existing importer's C:-only
input guard. J: holds `J:\ntfs2refs-reference\<experiment>\reference.vhdx`.
This is an explicit proposed adjustment from J:-only staging, not permission to
write C: now. Such ordinary guest file staging must be named in execution review.
The old dispatcher remains unsuitable: it selects the protected win11 lane and
uses execution-policy bypass. No fallback endpoint, Library transfer retry,
permission or execution-policy change is added here.

Future reference import must retain the existing whole-64-GiB zero check, exact
full disk/disk-plus-footer/payload hashes, GPT layout, flush/prepared/handoff proofs
and native two-file/absence checks. RAW alone proves neither journal nor reference
blankness. A successful baseline control would not qualify the independent writer.

Pure checks use synthetic observations and lazy generated zero streams with one
1 MiB buffer, including an 8 GiB virtual read. They create no giant image and call
no VM/device/credential/native mutation API. Original evidence is retained.

The separately admitted operation was fresh owned identity acquisition and a
read-only complete journal observation only, with all other disks excluded.
Its terminal outcome is recorded below. No initialization, formatting, reference
creation, packet import or native mount was authorized. A failed observation
does not authorize an automatic retry or removal of its refusal condition.

Budget admission must be rechecked from actual free space. Conservatively charge
8 GiB plus 128 MiB for journal-parent growth and another 16 GiB allowance, retaining
64 GiB free: at least **88.125 GiB** initially. The child reference's 64 GiB is a
virtual size; its enforced <=6 GiB backing lives within the 8 GiB journal, so do not
add it again as independent host allocation. This allowance is not a hard cap;
monitor actual host/J: capacity and stop before a reserve breach.

The bitmap patch is `216e9af`; local checks passed. Windows CI run
[40351404204](https://github.com/faratech/ntfs2refs/actions/runs/40351404204)
failed before runner assignment with zero steps. Its exact
[check-run annotation](https://api.github.com/repos/faratech/ntfs2refs/check-runs/121672129718/annotations)
states that the job did not start because recent account payments failed or the
spending limit needs increasing; this does not identify a code/test failure.
No CI rerun, billing or runner-policy change was performed. Chronology/ACL evidence
correction `9684ae5` remains committed with original records untouched.

## Separate observation-only entry and original proposal

`lab/Read-IsolatedJournalObservation.ps1` is a one-shot observer for
the existing isolated VM only. It does not initialize storage or obtain an
initialization proof. The original `Read-IsolatedJournalPrerequisite.ps1
-RequireZeroScan`, `IsolatedJournalReader.OpenReadOnly` and `ScanAndBind` retain
their durable-fence refusal. The original proposal below preceded the separately
admitted attempts in the chronology; it is not an instruction to dispatch again.

The original proposed command was:

```powershell
& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoProfile -File D:\code\ntfs2refs\lab\Read-IsolatedJournalObservation.ps1 `
  -OutputDirectory ("D:\code\ntfs2refs\.lab\hyperv\isolated-reference-20261026-review\journal-observation-review-" + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
```

The VM GUID is fixed to `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`; the device is
fixed to guest `PhysicalDrive2`, 8,589,934,592 bytes, NAA
`600224806AAC261F021F249596F332FC`. No caller-selected disk or old-VM route,
execution-policy bypass, elevation, privilege setter or guest-file staging is
available. The VM must already be running with the recorded 8 GiB/four-CPU,
no-NIC configuration; the launcher cannot boot or reconfigure it.

The launcher pins its source/framework inputs and compiles the reader into a
fresh host-only CLR 4-compatible DLL for Windows PowerShell 5.1. This host has
.NET Framework 4.8.1 (Release 534296, version 4.8.10008); the retained
`v4.0.30319` directory name does not identify the obsolete 4.0 product release.
[Microsoft's support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-framework)
continues to support 4.8.1 with its supported Windows parent. The converter and
recovery engine remain Rust. A fresh PowerShell process is required;
preloaded host-identity types are refused. Default host identity acquisition
joins all current/checkpoint attachments and ancestors by held native file
identity, checks sole ownership of the isolated leaves, and retains those pins
through the read. Known project leases and host/guest worker inventories are
checked; unknown inventory errors refuse rather than become empty inventories.
The DLL is hashed, sent through the exact VM-ID PowerShell Direct session and
loaded in memory. There is exactly one `ObserveReadOnly(Guid, string)` invocation.

The private native reader opens only `PhysicalDrive2` with `GENERIC_READ`,
`OPEN_EXISTING` and no sharing. It reuses the native route/geometry/RAW-state/NAA
and SMBIOS checks, observes the full length using one 1 MiB buffer, hashes every
byte, and records informational zero/nonzero counts. Native identities and UTC
timestamps are recorded before/after, then the private handle closes before
the data-only report returns. Host namespace/controller/ancestor identities,
known workers, and the journal backing's length/mtime are checked again.

The trust boundary is Windows/Hyper-V plus ordinary project concurrency guards.
This measurement does not require proving exclusion of a malicious kernel or
administrator. Matching observations nevertheless do not prove atomic content,
exclude every storage alias, or extend a durable writer fence. No `Stream`,
native handle or `ZeroProof` escapes; even an all-zero result grants no
initialization, format, import, repair or write authority.

Observation needs no new VHDX or 8 GiB allocation. It retains the 208 GiB lab
ceiling and 64 GiB host reserve with a 128 MiB allowance, bounds host output to
16 MiB and compiles a DLL no larger than 2 MiB. The current metadata inventory
found the isolated VM running, disk 1 RAW/64 GiB, disk 2 RAW/8 GiB, no J: and no
active N2R tasks/processes. RAW is not blankness. These observations must be
reacquired by the proposed command; they cannot substitute for its live checks.

Expected host-only artifacts include source/framework hashes, compiler
transcript, assembly hash, concurrency/worker reports, host identity graphs
before/after, journal backing metadata, the explicit observation intent,
guest hash/read/query/timestamp report, transcript and final result (or bounded
failure/cleanup receipts). Credentials are never serialized. No guest file,
scheduled task, layout, disk attribute or payload is created/changed by this path.

Source checks passed: 68 pure observation checks, 15 original pre-native reader
refusals and 111 launcher predicate/AST checks. An additional generated-stream
test completed all 8 GiB with 8,193 managed read calls, SHA-256
`ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25`
and no image/device/native call. Host CLR 4 compatibility compilation using the
installed framework also passed.
These initial checks established source behavior only. Subsequent native reply
refusals, their separately admitted corrections and the final completed guest
read with host refusal are recorded below. No automatic retry follows a failure.

## Admitted observation refusal and bounded metadata diagnosis

The original pinned launcher was invoked once at `2026-10-27T02:12:34Z`, under
`.lab/hyperv/isolated-reference-20261026-review/journal-observation-review-20261027T021234092Z`.
Host resource/worker checks and the fresh held identity graph passed; before/after
inventory fingerprints agreed across 194 nodes/references. The native reader
constructor then refused its layout response: `Journal must remain RAW with no
partitions.` It never entered the 8 GiB payload loop. Launcher exit code was 1;
no content hash, initialization proof, state setter or write followed.

The original guest failure is pinned by SHA-256
`70bac258f112e012858f322985e4ec59efc7330834e4526c0d8fbfa4d573132d`;
`failed.json` is
`2810c0f532ffe707e662cb138ba8b86cb2f288c42b5bfda2b01d2b67d98b825d`.
Journal host identity, 4 MiB backing length and last-write timestamp were
unchanged. File size and RAW state were not treated as blankness proofs.

A separately admitted metadata-only query retained its partial result under
`layout-metadata-review-20261027T022816440Z`. It decoded native style/count
0/0, but remoting reduced nested reply objects to type-name strings. Its receipt
is preserved. The one admitted diagnostic repeat fixed only serialization by
converting the complete guest result to bounded JSON before transport. The
diagnostic C# source stayed pinned to
`ddc90d5a55f92cf66964f80e39eccfae650fcd5786ebbd8c9f374d7a82ddc629`.

The complete response is under
`layout-metadata-review-serialization-20261027T023841134Z/metadata-query.json`,
SHA-256 `5cb7566f49288929d1e628a16ef8e9a23b56e2a823d61f222d9d3c9eae6453da`:

- `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` (`0x00070050`) succeeded, error 0.
- Capacity 192 bytes; exactly 48 bytes returned, every byte zero.
- Native DWORD offsets 0/4 decoded `PartitionStyle=0` / `PartitionCount=0`.
- Independently bound Storage Management reported RAW and zero partitions,
  before and after; its Disk 2 partition inventory was empty.
- Device-number, length, SCSI and attributes queries matched the enrolled route;
  no payload read, disk write, initialization, import or 8 GiB retry occurred.

The refusal is an observational-profile representation mismatch, not evidence
of a real partition or a marshalling-offset error. The existing Rust importer
already documents the same exact 48-byte all-zero MBR-style header for a new
VHDX; it never treats arbitrary MBR layouts as blank. Any observation correction
must remain specific to this exact response plus fresh RAW/zero-partition
Storage Management evidence, retain actual bytes in snapshot hashing, and
preserve the separate initialization gate. No content-blankness conclusion
follows from these metadata replies.

The reviewed source correction adds only an observational compatibility path:
`ValidateObservationSnapshot` accepts the exact 48-byte all-zero header in
addition to the existing RAW form. It hashes the actual reply bytes and keeps
the two representations distinct. The initialization `ValidateSnapshot`
remains strict; `OpenReadOnly`/`ScanAndBind` still refuse without their durable
proof capability. Fresh bound Storage Management RAW/zero-partition checks
bracket the native observation, and both native/host completion predicates
refuse nonzero or incomplete 8 GiB content. Those predicates issue no proof or
write authority even after success.

Focused source checks passed: 118 profile, 79 observation, 15 original-reader
refusal and 140 launcher checks. The corrected launcher SHA-256 is
`8285d58c92bdcb03b7036f3fa9ab09276395ea807250a32678d7e3c60ff81418`;
reader/profile source pins are recorded by each fresh run. The one corrected
observation is separately admitted after these checks. Original refusal and
partial/corrected metadata receipts remain unchanged; no old retry field is
rewritten and no automatic repeat is permitted on the corrected run's failure.

## Identifier reply correction and lossless observation transport

The corrected run at `2026-10-27T02:50:47Z`, under
`journal-observation-review-20261027T025047834Z`, passed the layout check but
refused `Last identifier continues beyond declared count.` Its constructor
again stopped before payload reading. The original `guest-observation.json`
SHA-256 is `957234876a5013ebd461abe61bc23e1d6a2884dfa6482799320092f89ca1fa44`;
`failed.json` is
`00cd0b8be113f861a26597fa17c32f27cecf1eeb8abe2396db1141a9f3570451`.
These receipts remain unchanged.

One separately admitted metadata-only query at
`identity-metadata-review-20261027T030108072Z` captured all identity responses.
Its `metadata-query.json` SHA-256 is
`730ad6e2dec558233cf43d5d96851ce9f9c3c5c331c02ecabf8146d4b13770f3`.
The 92-byte device-ID descriptor has two identifiers. The second starts at
offset 56, contains the enrolled 16-byte binary NAA, and has a relative
`NextOffset` of 36, ending exactly at the descriptor's declared size, 92.
Its four trailing padding bytes are zero. The observation-only parser now
accepts that aligned terminal boundary while retaining count, bounds, padding
and exact NAA checks. Initialization parsing still requires final offset zero.
The actual response bytes remain part of the snapshot hash.

A pure typed-DTO remoting fixture also reproduced loss of nested report fields
through default CLIXML serialization. The guest now serializes bounded JSON
before remoting; the host requires one UTF-8 JSON object no larger than 2 MiB
before saving or checking it. Query bytes, hashes and Boolean flags survive
the fixture round trip. This does not introduce another native invocation.

Fresh Windows PowerShell 5.1 checks passed: 140 device-profile, 79 observation,
15 original-reader refusal and 163 launcher/transport checks. No device was
opened by these tests. Corrected source SHA-256 pins:

- Launcher: `c4878421556a729bb1fe1749a2b299a19c1e49432fe638899cfa36d3010935f7`.
- Device profile: `55d30af92d830196d24012941f22f0c851a34aea7818c0c949564fd4b7132e47`.

Only one fresh corrected observation was admitted. Its terminal result follows;
initialization, formatting, reference import and writer experiments remained
outside that observation.

## Complete guest observation followed by host timestamp refusal

The one corrected run is preserved under
`.lab/hyperv/isolated-reference-20261026-review/journal-observation-review-20261027T031140034Z`.
It used the launcher/profile source pins above and in-memory assembly SHA-256
`febd5a1297df999967803c0ecde7b7c2078fc37bde1332b3c1d7861ed17ee71a`.
The guest made one observation invocation and completed the enrolled Disk 2 read
from `2026-10-27T03:14:09.7985674Z` to `2026-10-27T03:14:33.5518125Z`:

- All 8,589,934,592 bytes were read; zero nonzero bytes were observed.
- Content SHA-256 was
  `ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25`.
- There were 8,192 native reads and 8,193 managed read calls, including the end
  check. The report retained all 24 native query replies.
- Before/after native snapshot hashes matched
  `de0ccad300e3055548d86b40c0e9a330d19ca313bda0f817d4092e574fd162e0`.
  Independent Storage Management observations retained the exact Disk 2 NAA,
  8 GiB/512/4096 geometry, RAW state and zero partitions before and after.
- The guest report remained informational only: initialization/write authority,
  atomic immutability and durable writer-fence claims were all false.

The host then exited **1**, refusing during held-host-identity/worker
revalidation: `Enrolled journal backing length/mtime changed during observation;
preserved bytes are observations only.` The journal backing kept the same
recorded host file identity and 4,194,304-byte length, but its last-write time
changed from `2026-10-26T14:46:28.4210473Z` to
`2026-10-27T03:14:37.9340259Z`. The cause of that timestamp change is not
established. It is not evidence that guest logical bytes changed, and the
matching guest reads do not establish host-content immutability.

`guest-observation.json` SHA-256 is
`e135cbcdb24f1ac504c27566a053a59270d04d0c7c410a8d91905dd90a8e07f3`;
`failed.json` is
`7b91736d54a6146f19a63bfd316ccaf8d041f4f7ac45d0bbdbc216a34635f659`.
Both backing metadata observations, source/assembly pins, host graphs, worker
reports and transcript remain beside them. There is **no host success receipt,
initialization proof or write authority**. No initialization, formatting, import,
repair or automatic retry followed. Preserve this refusal and the earlier
attempts; do not relabel the completed guest read as an end-to-end pass.
