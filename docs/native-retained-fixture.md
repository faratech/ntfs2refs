# Native retained-extent fixture

This constructs the disposable NTFS source and independent native ReFS shadow
for the first actual conversion. It does not convert a volume or write raw
sectors. Root owns VM execution; earlier placement/VDL sources remain frozen.

## Interfaces

`Prepare-GuestRetainedSource.ps1 -RunId <32 lowercase hex> -HostTargetJson <JSON>`
requires original RAW target disk1, UniqueId
`60022480D091C4251B5FFD619706C2B5`, VHD ID
`25c491d0-5f1b-4205-9e6f-fd619706c2b5`. It enrolls that blank 64 GiB disk and
formats a 52 GiB basic GPT partition at 16 MiB, F:, NTFS, 4 KiB clusters,
label `n2r-retained-source`. It never clears/formats an existing filesystem.
This is source preparation before any retained payload exists.

Source evidence is `C:\ntfs2refs\retained-source\<RunId>\prepare.json`
(1 MiB maximum), enrollment `target.json`, and pre-mutation `started.json`.
Success is `ntfs-source-prepared`. The separate shadow platform prepares S:,
label `n2r-retained-shadow`, with matching geometry on an independent guest-local
VHDX backed by enrolled journal J:. Its input record is
`C:\ntfs2refs\shadow-platform\<RunId>\prepare.json`, kind
`guest-local-shadow-platform`, status `shadow-platform-prepared`.

`Invoke-GuestRetainedPair.ps1` takes `-Phase Construct|Inspect`, `-RunId`, a new
`-ObservationId`, `-SourceEvidenceSha256` and `-ShadowEvidenceSha256`. Inspect
also requires `-ConstructionObservationId` and `-ConstructionEvidenceSha256`.
It binds platform records, revalidates live identities and compiles both
`NativeRetainedFixture.cs` and `NativeRetainedFixture.Windows.cs`. The native
entry points are `ConstructPair(sourceVolumeGuid,shadowVolumeGuid,runId)` and
`InspectPair` with those same arguments. Inspect has no creation, sizing,
flushing, integrity setter, stored timestamp assignment or move path. Its file
handles explicitly suppress last-access updates as described below. It validates its
observations against the completed construction's identity, hash, metadata and
mapping evidence. It does not perform a remount itself.

Output is `C:\ntfs2refs\retained-pair\<RunId>\<ObservationId>\pair.json`
(2 MiB maximum), `started.json` (16 KiB maximum), and declared `query-NNN.bin`
artifacts: at most 192, each at most 2 MiB, at most 16 MiB aggregate binary data.
Zero-length replies are retained. The JSON records exact native inputs/status,
output bounds, lengths, hashes and decoded metadata. All artifacts use
create-new and explicit flush; JSON is UTF-8 without BOM. The host must export
the allowlist and preserve the branch on unknown completion. Stopped format
jobs are not classified as determinately completed.

## Semantics and source-specific validity proof

Each volume gets only the user directory `retained` and `payload.bin`, exactly
65,536 bytes. Pattern A is deterministic from RunId; B complements every byte.
Each file is written completely through ordinary WriteFile, flushed and closed
before observation. No valid-data-length setter or uninitialized payload is used.
NTFS source qualification requires recorded complete write/flush/close, full
logical A readback and native cached-validity coverage. Its independent storage
validity is explicitly `not-queried-NTFS-storage-validity-unknown`. A later
offline, quiescent raw A match is mandatory before any conversion target write.

This distinction follows the primary MS-FSA contract: NTFS DesiredUsage must
contain cached-validity bit1. Sending storage-only bit2 is a documented refusal;
adding both bits does not establish independent storage validity because that
protocol algorithm can echo the requested flags from one VDL. No predictable
refusal probe or fabricated storage measurement is needed. ReFS retains strict
separate cached and storage native measurements over every byte; that gate was
not relaxed. Unsupported or incomplete ReFS responses stop the fixture.
[Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/acadee02-c40d-4f73-92d0-0f10e866e11f),
[region meanings](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info)

Creation specifies local-user owner, Administrators group, protected full-control
DACL for that user/SYSTEM/Administrators, and an empty protected SACL. Security
queries include SACL and mandatory-label information; any SACL ACE blocks the
profile. Empty-present versus absent SACL is recorded and must match. Only the
current guest process's SeSecurityPrivilege is enabled, and its exact prior
state is restored. Failed restoration fails the result.
[SACL access](https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right),
[security query](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)

Supported metadata is Archive file attributes, Directory folder attributes,
four fixed FILETIME timestamps (2026-01-01 UTC), one link, EOF/allocation 65,536,
only `::$DATA`, 128-bit file ID plus volume serial, owner/group/DACL/SACL and
positive complete extents. File/folder metadata must match between filesystems.
Shadow integrity must be NONE, flags zero. Windows-managed root entries
`System Volume Information` and `$RECYCLE.BIN` are identified separately;
arbitrary content within those system namespaces is outside this fixture.
[Basic metadata](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info),
[streams](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info),
[128-bit identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info),
[integrity](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-fsctl_get_integrity_information_buffer)

## Placement, freeze and conversion handoff

After both files exist, complete bounded NTFS, ReFS legacy and ReFS EX-flags1
bitmaps select a common free sixteen-cluster interval in only the 8..9 GiB
window. The candidate must not overlap either existing file mapping. Complete
declared bitmap coverage and bounded returned length are checked; NTFS usable-cluster
count need not equal partition physical-cluster count. No bitmap classifies
the complete metadata write set.

The 2026-10-24 preparation case `win11-20261024T023655082Z` (run
`b17906899b1343d2a1dace072d4bb2db`, observation
`fdab61c352fe438f9d83e475cd17f1e3`) reached common-free selection after both
ordinary initialized write/flush/close sequences and the source/shadow validity
checks. It stopped before either move because the original parser required an
exact response length. NTFS declared 13,631,487 clusters and returned 1,703,952
bytes. Both successful ReFS bitmap views declared 13,631,488 clusters but
returned the complete 2,097,152-byte output capacity: 1,703,952 meaningful bytes
and 393,200 additional nonzero bytes. These saved artifacts remain unchanged.

The corrected bounded parser requires start LCN zero, supported declared
coverage, at least `16 + ceil(BitmapSize/8)` returned bytes, and no more than the
2 MiB request capacity. It records meaningful/returned/trailing lengths and the
unused bits in the last meaningful byte. Bytes or bits beyond declared coverage
never become cluster addresses, regardless of their values. This follows the
documented [VOLUME_BITMAP_BUFFER coverage definition](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-volume_bitmap_buffer),
with extra returned capacity retained as measured provenance. Pure parsing of
the saved three replies selects LCN 2,097,152; this is not a reservation or a
native placement result.

The same case exposed PowerShell serialization dropping extended `artifact` and
`sha256` notes attached to C# objects inside a typed list. Query export now builds
plain records containing all native fields and the explicit artifact mapping,
then replaces the JSON-facing query list. Original native buffers stay intact;
their complete bytes remain in hashed artifacts. Bitmap coverage metadata is
added separately, including a parse error for an unsupported reply without
discarding that reply. Tests round-trip a real typed native list through JSON,
including a padded reply and a zero-byte native failure. Updated suites pass
139 native parser/fake checks and 108 guest guard/file/serialization checks in
PowerShell 5 and 7; the current host preparation guard suite passes 54 checks.

A fresh per-volume bitmap precedes each VCN0/count16 native move. There is at
most one request per file; native rejection stops without another candidate or
retry. Native allocation arbitrates stale bitmap observations. This copies
initialized data during *fixture construction*, not production source relocation
or zero-copy conversion.
[Move contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file)

Metadata is finalized after moves. The payload-writing file/folder handles close,
stored-metadata setters become unavailable, and fresh payload-read-only handles
supply final observations. Those file handles retain only the narrowly required
FILE_WRITE_ATTRIBUTES right for the documented last-access suppression call.
The final single extent must cover the same partition-relative bytes on both
filesystems. Both measured retrieval bases must be zero for this first profile.
The bounded formula is `baseSectors*512 + LCN*4096`.
[Retrieval base](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointer_base)

Success is `constructed-awaiting-raw-proof`; `sourceFrozen=true` ends permitted
source-fixture placement, not an exclusive volume lock or physical protection.
Inspect reports `pair-observed`. Handle-scoped last-access suppression does not
claim absence of every possible filesystem bookkeeping write.
Clean-remount and raw proof remain mandatory. The actual journaled conversion
must exclude the frozen source interval from its write ledger and subsequently
read A through native ReFS, retaining identity and supported metadata as declared.

## Last-access observation correction

Preparation case `win11-20261024T024733077Z`, run
`78ecd0354ebb4b9caf54191e36e2ca21`, completed one native move per file to LCN
2,097,152. The first source observation after the moves stopped because the
logical read changed only NTFS LastAccessTime: `AAfterBasic` had all four times
`134116992000000000`, while `AAfterBasicAfter` reported access
`134372837118005111` and retained the other three times. The two native 128-bit
identity buffers were identical. The strict comparison correctly refused the
result. The preserved checkpoint is
`affd7763-f0df-4985-8f94-08ae9d563777`, named
`retained-prep-access-failed-78ecd0354ebb4b9caf54191e36e2ca21`;
failure preservation completed at 2026-10-24 02:51:03 UTC and the baseline was
restored off with 4 GiB. Previous artifacts were not rewritten.

The correction calls SetFileTime immediately after opening each exact fixture
file handle. Only the last-access FILETIME pointer is supplied, with both DWORDs
equal to `0xffffffff`; creation and last-write pointers are NULL. Microsoft
documents this special value as suppression of access-time updates caused by
operations on that handle, rather than a stored timestamp value. The call
requires FILE_WRITE_ATTRIBUTES, explicitly included even on observation handles.
There is no disk-wide last-access configuration change and no restoration of a
timestamp after a read. All four stored times must still compare exactly before
and after hashing and against frozen construction evidence.
[SetFileTime contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime),
[per-handle NTFS/ReFS timestamp semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_basic_information).

`lastAccessPolicies` records the API, exact path, open stage, attribute access,
NULL pointer choices, eight-byte sentinel, timestamps and native status/error.
Construction requires created/construction/observation coverage for both files;
Inspect requires only their observation handles. `lastAccessPolicyVerified`
requires that complete successful coverage. These calls are separate from the
raw query artifacts and stored-metadata mutation accounting. Final and Inspect
file handles have no payload-write access; they are not described as lacking
every possible write permission. The earlier
`writeHandlesClosedBeforeFinalObservation` field records closure of the original
construction handles, not a claim that subsequent handles omit attribute access.
Native acceptance of this fix remains an execution measurement, not something
proved by parser and fake-API tests.
The revised suites pass 153 native parser/ABI/fake checks, 116 guest guard and
serialization checks, and 54 host checks in both PowerShell 5 and 7. Regressions
reject the measured access-only change, missing/failed suppression, altered
sentinels or pointer choices, and unowned paths. No test invokes SetFileTime or
a VM/device API.

## Directory enumeration observation and correction

Preparation `win11-20261024T025713906Z`, run
`b3e2c6bd260747f88b7550cccd4e6c12`, passed with the file-handle suppression
policy and was saved as checkpoint `46b1791d-9852-40f0-ab03-68bcb7d98c58`.
Its subsequent native-probe inspection, in
`.lab/hyperv/retained-native-probe/win11-20261024T030135884Z/inspection/pair.json`,
stopped before raw isolation. Both payload hashes, mappings, and all file times
matched. The NTFS retained directory access time was
`134372845503312033`, rather than the frozen `134116992000000000`.
The observation at 03:02:30.331 preceded the native open at 03:02:30.643.
The wrapper's separate `Get-ChildItem` enumeration used uncontrolled directory
handles before inspection and after construction. The timing is consistent with
that enumeration changing last access, which the next native run will test.
The failed branch remains preserved as checkpoint
`a581a9dd-d48b-46ec-a927-81a9f4f80cc3` and baseline off/4 GiB was restored.

The wrapper no longer enumerates F: or S: through PowerShell. Root, retained
directory, and payload handles now receive the documented per-handle access-time
suppression immediately after open. Directory handles request
`FILE_LIST_DIRECTORY` and `FILE_WRITE_ATTRIBUTES`; the latter exists solely for
the suppression call during inspection. No directory timestamp is ignored or
repaired after freeze, and no global access-time setting changes. Construction
records twelve successful handle policies; inspection records six. The existing
strict four-timestamp and security comparisons remain.

Namespace enumeration uses `GetFileInformationByHandleEx` on those same pinned,
suppressed handles: class 11 restarts, class 10 continues, with a zero-initialized
4 KiB buffer per request and a maximum four requests per observation. Ten
observations cover each root at open and each root/directory before and after
payload reads. A complete observation must end with `ERROR_NO_MORE_FILES` (18).
Root inventory allows only the retained directory and the two explicitly allowed
system directories, with a maximum five records including dot entries; the
retained directory allows only the ordinary 64 KiB payload, with at most three
records including dot entries. Each successful raw buffer and the zero-length
terminal result are exported. The API has no returned-byte-count parameter;
successful query artifacts preserve the entire 4 KiB supplied buffer, while
parsing follows bounded `NextEntryOffset` and filename-length fields. Unused
buffer tail bytes are not directory records. The enumeration's 64-bit file ID
is recorded without an identity claim, including zero; separate `FILE_ID_INFO`
queries retain the required 128-bit payload identity.

The pure `Assert-RetainedQueryOutcome` guard permits error 18 only for the exact
directory API, name, class, empty-input and capacity contract. Other native
failures remain failures. `Assert-RetainedNamespaces` requires complete namespace
and query-sequence coverage; the native core also checks the raw buffers against
the recorded inventory. Windows PowerShell 5 and PowerShell 7 each pass 181
native/parser/mock checks and 132 guest guard/serialization/WhatIf checks for this
revision. Tests include the measured directory access-time disagreement,
missing suppression, incomplete enumeration, wrong EOF errors, malformed entry
offsets/names, duplicate objects, and reparse entries. They perform no VM or
native file/device calls. Native acceptance remains a subsequent measurement.

Primary API references: [SetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime)
documents the directory handle and suppression requirements;
[FILE_ID_BOTH_DIR_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_both_dir_info)
defines the aligned records;
[FILE_INFO_BY_HANDLE_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class)
defines restart and continuation behavior; and
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
defines the native output contract.

## First-search no-match interpretation

Preparation `win11-20261024T031656056Z`, run
`d391186e9f21450e92a8dc4711c4c747`, stopped before either fixture was created.
`AOpenRootDirectory0` returned false/error 2 with zero bytes for class 11,
capacity 4096 and empty input. Root suppression and native volume binding had
passed; completion and cleanup were known. The failure checkpoint is
`75a43928-64e5-408b-9182-5a3683d4ecd0`; baseline off/4 GiB was restored.
The later [root enumeration diagnostic](root-enumeration-diagnostic.md), under
`root-enumeration-0d08426554a74dcea47b21102e13cd42` in that case, did not
reproduce error 2: all first queries succeeded, then returned continuation error
18. Its host JSON SHA-256 is
`1568843308a7d2bee71989d1dc2ff5e0a7cce333ca90bf3485a6e2b229879609`.
Later System Volume Information entries do not prove the earlier root was empty.

[MS-FSA Directory Information Queries](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/fa8194e0-53ec-413b-8315-e8fa85396fd8)
specifies different no-record statuses for an initial query and continuation.
The implementation supports only this interpretation: Construct's `OpenRoot`,
with `expectedFixture=false`, may record class 11 false/error 2/zero bytes,
immediately followed by class 10 false/error 18/zero bytes on the same handle.
Exactly two queries and zero entries are required. The initial error is never
terminal or changed to success. Entries, other statuses, missing continuation,
populated stages and Inspect are rejected. The held root path and native volume
identity are rechecked before completing this preconstruction observation.
Create-new operations and full subsequent namespace checks remain mandatory.

That sequence alone sets `emptyInitialNoMatchInterpreted=true` and
`initialNoMatchInterpretation=\"documented-first-empty-search-not-reproduced-by-lab-diagnostic\"`.
Ordinary observations retain false/null. At implementation time this was a
source-supported interpretation, with no measured reproduction or historical
empty-root claim. The fresh preparation below subsequently measured the exact
sequence; it does not retroactively establish the state of the earlier root.
The query guard requires explicit construction context; the namespace guard
also requires the complete empty two-call sequence. Tests pass 195 native/mock
and 144 guest checks in PowerShell 5 and 7, including missing continuation,
wrong status/class/bytes, false success, entries, provenance and Inspect refusals.
No tests issue VM or native API calls.

## Fresh native preparation passed

The fresh run `94f6256f57424ad69147f58199387ee1`, in
`.lab/hyperv/retained-preparation/win11-20261024T034206826Z`, completed at
`2026-10-24T03:43:40.4147697Z` with host status
`retained-pair-prepared-awaiting-raw-proof`. Both initial roots measured the
exact bounded sequence: class 11 returned false/error 2/zero bytes, followed by
class 10 false/error 18/zero bytes, with no entries. Both calls used a 4096-byte
capacity and empty input. F: artifacts are `query-003.bin`/`query-004.bin`;
S: artifacts are `query-011.bin`/`query-012.bin`, in the exported `pair` directory.
The raw errors remain unchanged. This is fresh native evidence for the
preconstruction sequence, distinct from the earlier diagnostic that did not
reproduce it. The frozen implementation's interpretation string remains in the
record as implementation provenance; neither source nor prior evidence was
rewritten to relabel that history.

All later namespace, content, metadata, access-policy and extent checks passed.
Each fully initialized 64 KiB file was moved once during construction to
LCN `2097152` (partition-relative byte offset `8589934592`) and frozen there.
Both file and directory timestamps retain all four expected values
`134116992000000000`; their attributes remain 32 and 16 respectively. NTFS
cached validity passed, while its storage-only validity remains explicitly
unknown under the source-specific contract. ReFS cached/storage validity and
integrity NONE with flags zero passed. Source A SHA-256 is
`a8da4df80396fc29486e0cba10fb7525404e8fd56169e6885475789b10f31bb3`;
independent shadow B SHA-256 is
`d66b3369b58ea23563d72c1593b173fcb14dbd9899a14ef6a2c3d40c5518b584`.
Native cleanup and privilege restoration completed.

Evidence pins are `host-result.json` SHA-256
`464bb9e4fccb6f2e014e3104801d546dbbbb48fc944454ccb060dcc3f9e22f13`
and `pair/pair.json` SHA-256
`145398b640302197acbcf71e8b21dfaa629507ac916179971ea3e579b92c849d`.
The prepared checkpoint is `730afa0a-4df7-4a18-830c-1f0381013c62`, named
`retained-prepared-94f6256f57424ad69147f58199387ee1`; baseline and memory
restoration are recorded true. This completes fixture preparation only. Raw
physical mapping, clean-remount inspection and actual conversion are separate
subsequent observations; this preparation does not claim them.

## Reference architecture and tests

The reviewed local ntfs2btrfs checkout is commit
`433523abaff4015db0f473e4f256f9d5671c9cd5`: `create_data_chunks` inventories
allocation, `protect_superblocks` resolves target-bootstrap collisions, and
`create_inodes` reconstructs namespace. These support explicit allocation and
namespace inventory, collision handling and recovery as architectural concerns.
No GPL source was copied. This native-shadow fixture does not inherit that
project's target-format implementation or qualifications.

`Test-RetainedFixture.ps1` tests native byte parsers, all-byte pattern distinction,
address/bitmap bounds and fake-API sequencing/failures. `Test-RetainedFixtureGuest.ps1`
tests platform/live-identity guards, ordinary temporary evidence and WhatIf.
No test invokes a VM or device control.

## Reviewed host preparation harness

`scripts/Invoke-LabRetainedPreparation.ps1 -ReviewedSourcesPath <path>
-ReviewedSourcesSha256 <sha256>` runs the three guest stages in order: source
preparation, independent shadow preparation, then Construct. The review manifest
has schemaVersion 1, kind `retained-preparation-reviewed-sources`, and an exact
ten-file list of relative paths and SHA-256 pins. It includes the host harness,
Lab/GuestLab helpers, enrollment script and all six source/shadow/pair scripts
and native helpers. Files are archived before upload and the uploaded byte hashes
must match those reviewed copies. WhatIf performs no Hyper-V operation.

The only starting profile is the enrolled installed-clean checkpoint: VM off,
fixed 4 GiB RAM, original three VHD identities and slots, Secure Boot enabled and
network disconnected. The harness reserves 12 GiB under the existing 180 GiB
lab cap and 64 GiB host-free reserve, raises this disposable branch to 8 GiB,
and performs all filesystem construction inside the guest. Each guest dispatch
has a bounded completion wait; unknown completion preserves the branch.

Host output is `.lab/hyperv/retained-preparation/win11-<UTC>`. Create-new,
flushed progress records precede state transitions. Export verifies the flat
artifact allowlists, per-file bounds, SHA-256 values and unchanged guest inventory.
The host re-parses the native query bytes to check metadata, source-specific
validity, the common-free candidate, exact two move requests and final mapping;
it does not rely only on successful status strings. These host parsing calls
perform no native volume or device I/O.

After all proofs succeed, the guest shuts down cleanly. The harness saves an
off-state 8 GiB `retained-prepared-<RunId>` checkpoint, then restores the exact
installed-clean checkpoint and 4 GiB profile. Any failure preserves its branch;
failure cleanup does not stop, restore or change the VM. Success is
`retained-pair-prepared-awaiting-raw-proof`, with physical mapping, clean remount
and conversion qualification still false. The saved checkpoint retains the
guest-local VHDX bytes, but does not establish that S: automatically reattaches
after boot. A later guest-local reattachment must bind that exact VHD identity
and revalidate its physical/partition/volume identity before use.

The frozen host SHA-256 is
`e3de7630f95665c55a0cd782b782667d769aef8a79fe722bcbe75fdcf036b008`;
its test SHA-256 is
`6244f274f3ebda2673590014d0f9f22d901decf608657999d681da68a3c07ea5`.
`Test-LabRetainedPreparation.ps1` passed 48 focused checks in Windows PowerShell
5 and PowerShell 7. The tests include a complete synthetic exported native
corpus, changed metadata/identity/validity/mapping/hash refusals, bounded artifact
handling and create-new evidence, using ordinary temporary files only. This
records code validation; runtime preparation results are reported separately.
