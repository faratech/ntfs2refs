# Native verification after the retained-extent conversion

This is the implemented, unexecuted verification contract for the first 64 KiB
fixture. It introduces no writer and does not qualify a conversion before execution. The
existing Construct/Inspect pair helpers remain frozen: Inspect deliberately
expects F: NTFS and S: ReFS, so it cannot serve as the post-conversion observer.
A new bounded observer must accept ReFS on the enrolled original target.

## Evidence and handoff

The observer must pin the successful preparation, subsequent clean-remount
inspection, quiescent raw A/B proof, complete comparison report, trusted journal
ticket and completed whole-target postimage verification. The retained range
must equal the final native source mapping, contain exactly 65,536 bytes of A,
and be absent from every target write. B must differ from A in every byte.
Neither a native mapping alone nor a successful writer status proves this.

Before a native mount, the Rust adapter must finish its documented durable
handoff. Recovery through the reconstruction journal then remains closed; an
observer failure cannot authorize replay or rollback over a mounted filesystem.
Preserve the journal, branch and all failure evidence. A VM checkpoint supplies
the disposable experiment's external recovery boundary.

Close shadow handles and detach the exact independent guest-local shadow before
mounting the reconstructed target. This avoids keeping two copies of the same
transplanted filesystem identity mounted simultaneously. Detachment must itself
be an identity-bound guest operation with known completion; do not infer it from
an absent S: drive letter. A detached shadow can remain available as its pinned
backing file on J: without exposing it as a mounted filesystem.
[Microsoft's detach contract](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-detachvirtualdisk)
requires the other virtual-disk handles to be closed before detachment succeeds.
Avoiding simultaneous duplicate filesystem identities is this experiment's
conservative design rule, not a claim that every duplicate mount must fail.

The initial observation should use the separately measured physical-disk
read-only protection lifecycle, if the target can mount under that protection.
Recheck the native disk protection and FILE_READ_ONLY_VOLUME flag before file
queries. A failure to mount or disagreement in protection stops this profile;
the observer must not repair, clear protection, or mount writable to get a pass.
The transition into this state belongs to the reviewed native handoff adapter,
not to the read-only observer. Logical file reads otherwise can cause filesystem
bookkeeping, so read-only handles alone do not establish an absence of writes.

## Which identities must match

| Observation | Required provenance |
| --- | --- |
| Physical disk UniqueId, enrolled target role/slot, GPT disk and partition GUID | Original NTFS target |
| Partition offset 16 MiB, length 52 GiB, logical sector 512, physical sector and cluster 4096 | Both prepared geometries |
| Filesystem name, volume serial, ReFS capability flags and label | Native ReFS shadow; the read-only-volume flag separately reflects current protection |
| `retained/payload.bin` native 128-bit file ID and serial | Native ReFS shadow file |
| Namespace, payload A, four timestamps, attributes, link count, owner/group/DACL/empty SACL, sole unnamed stream | Frozen NTFS source; supported metadata already equal to shadow |
| Full cached/storage validity, integrity NONE and flags zero | Strict native ReFS profile |
| One positive 16-cluster extent, observed retrieval base and retained partition-relative byte range | Frozen pair plus independent raw mapping proof |

The source's NTFS file ID is not an expected ReFS file ID. The former NTFS volume
GUID and the shadow's mount-manager path are not substitutes for physical
identity. Discover the new volume on the original target partition, then pin
its handle and independently verify its single native volume extent. Record the
new mount-manager GUID as observed provenance rather than guessing its value.
Windows exposes the file's volume serial and 128-bit ID together through
[FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info),
and the actual volume-to-disk location through
[IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents).
The shadow identity expectation follows from the complete postimage construction;
it remains a measured native acceptance condition. Compare capability flags
exactly after accounting only for the explicitly required
[FILE_READ_ONLY_VOLUME flag](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw);
record every raw flag value and reject other unexplained changes.

## Bounded observer

The new native helper should expose one observation method with no create,
flush, move, allocation, integrity setter, timestamp setter or raw-write path.
It opens exactly the protected target volume, `retained` directory and
`retained/payload.bin`. It refuses reparse points, device aliases, extra user
namespace entries, unsupported streams or attributes, and every profile mismatch.
Windows-managed root namespaces remain explicitly outside this fixture's user
namespace claim; their arbitrary contents are not silently certified.

Before the first payload read, capture complete file and directory metadata,
128-bit file identity, standard information, streams, security descriptor,
retrieval base/extents, two independent cached/storage validity queries and
integrity information. Then read exactly 65,536 logical bytes and require A's
hash, explicitly rejecting B. Repeat the same observations on the pinned handles
and after closing/reopening read-only handles. Compare native raw outputs and
decoded semantics; differences fail stability rather than being normalized away.

The new helper can reuse the frozen pure parsers, but must not call Construct or
the existing NTFS/ReFS pair Open path. SACL queries may temporarily enable only
SeSecurityPrivilege in the observer's own guest process, with exact restoration
and handle-close results included in the outcome. It must not enable a disk
mutation capability. Export exact query inputs/status/bytes and logical-hash
evidence under an explicit fixed artifact allowlist and byte budget.

Initial success means that native ReFS on the original target exposes A and the
declared supported metadata at the retained source bytes. It does not establish
general filesystem conversion, bootability, arbitrary NTFS feature preservation,
crash safety after native handoff or bounded scratch for arbitrary file sets.

## Guest implementation and input contract

`Invoke-GuestConvertedVerification.ps1 -RunId <32 hex> -ObservationId <32 hex>
-InputSha256 <64 hex>` runs only in a fresh x64 PowerShell process inside the
owned guest. The process must not have loaded the retained-fixture or verifier
types previously. It compiles the pinned `NativeConvertedVerification.cs` and
`.Windows.cs` with the retained fixture's pure parsers; it never calls that
fixture's native construction/inspection backend.

Stage an ordinary UTF-8 `input.json` as the only file in
`C:\ntfs2refs\converted-verification\<RunId>\<ObservationId>`. Its fields are:

```text
schemaVersion: 1
kind: converted-retained-verification-input
runId, observationId: matching command parameters
constructionId, inspectionId, mountId: exact predecessor observation IDs
preparePhaseId, applyPhaseId, handoffPhaseId: distinct reconstruction phase IDs
evidence: exactly ten { role, path, sha256 } records
sources: exactly seven { name, sha256 } records
```

The evidence roles are `source`, `shadow`, `construction`, `inspection`, `mount`,
`request`, `ticket`, `prepare`, `apply`, and `handoff`. Paths are fixed from the
IDs: source/shadow preparation and pair observations use their existing guest
evidence roots; mount uses `converted-mount`; request uses the apply phase's
`native-reconstruct` directory; the ticket is at that run's root; the three CLI
results use their exact phase directories. No caller-selected arbitrary path is
accepted. The seven source names are the two `NativeRetainedFixture` files,
the two `NativeConvertedVerification` files, `Invoke-GuestRetainedPair.ps1`,
`Invoke-GuestReadOnlyMount.ps1`, and this verifier wrapper. Source/inspection and
mount script hashes must agree with the corresponding predecessor records.

The wrapper holds read handles denying writes/deletion for all pinned inputs and
source files throughout observation. It imports only named pure predecessor
guards. It verifies the source/shadow construction, clean-remount inspection,
durable preparation and ticket, completed apply/handoff and protected mount
boundary together. Native fixture hashes/mapping bind the reconstruction
request; original target GPT binds both the source preparation and request.
It never reopens the reconstruction journal after handoff.

Fresh discovery uses disk 1, partition 2, and that partition's current volume.
Both Storage cmdlets and the independent native helper verify the original disk
and GPT geometry, three-disk inventory with shadow absent, and physical read-only
state. Native `IOCTL_DISK_IS_WRITABLE` must return error 19. Namespace enumeration
uses bounded class 11/10 queries on pinned directory handles, terminating only
with error 18. No path-based directory enumeration is used on the target. The
observer has no `SetFileTime` import or `FILE_WRITE_ATTRIBUTES` access: the target
is already protected, and any observed timestamp disagreement fails verification.

The helper captures four snapshots around two 64 KiB logical reads and one
handle reopen. Each snapshot includes native GPT/protection, file and directory
metadata/security, namespace, mapping, cached/storage validity and integrity.
Handle close attempts are single-shot; even a failed native close disarms the
owning SafeHandle to prevent a finalizer retry, retains a cleanup failure, and
does not claim confirmed closure. SeSecurityPrivilege restoration is explicit.

Output is create-new `started.json` (at most 16 KiB), `verification.json` (at
most 2 MiB), and at most 200 `query-NNN.bin` artifacts (each at most 64 KiB,
aggregate at most 4 MiB). Including staged `input.json` (at most 64 KiB), the
directory allowlist contains at most 203 files. Exact native failures, including
expected protection and directory-end statuses, remain in the exported records.
The wrapper materializes query records as plain JSON objects with artifact
names/hashes, avoiding typed-list serialization loss. Failed/unknown native
completion is preserved; there is no stop, mount, online, detach or protection
cleanup action.

Success is `retained-A-observed-through-protected-ReFS`, with complete/stable
native observation and cleanup true, exactly 131,072 logical bytes read, and
all mutation/conversion/boot qualification flags false. `Test-ConvertedVerification.ps1`
passes 118 pure/fake/layout/access-mask checks; `Test-ConvertedVerificationGuest.ps1` passes
74 pure evidence-chain, serialization, ordinary-file and WhatIf checks. These
tests do not execute the helper's native APIs or any VM operation. They do not
establish native ReFS acceptance of a reconstructed target.

## Finite follow-up and stopping conditions

The next acceptance steps are a clean shutdown/remount with the same semantic
checks, followed by a separate bounded ordinary-file allocation on a disposable
branch. That allocation must preserve A, its native mapping and metadata and
must not reuse its allocated range. This is an explicit follow-up mutation,
not a hidden part of the read-only observer.

Any native mount refusal, payload B/zero/incorrect data, identity mismatch,
integrity/validity contradiction, negative extent or metadata difference is a
measured failure of the current profile. Preserve the outcome and investigate
that concrete failed invariant. Do not relax the prepared full-validity or
whole-partition comparison gates, repeat another VDL-zero probe, or claim success
from a readable directory listing alone.
