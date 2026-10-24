# Bounded root enumeration diagnostic

The failed preparation `win11-20261024T031656056Z` (run `d391186e9f21450e92a8dc4711c4c747`) returned Win32 error 2 from its first `GetFileInformationByHandleEx(FileIdBothDirectoryRestartInfo)` on the NTFS root, before creating the retained fixture. A later listing cannot establish the directory contents at that earlier instant. The existing fixture error guard remains unchanged.

Microsoft documents that the underlying [FltQueryDirectoryFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltquerydirectoryfile) can return `STATUS_NO_SUCH_FILE` on a first search with no matching entry, versus `STATUS_NO_MORE_FILES` at the end of enumeration. It also notes that contents can change between calls. This makes an initial empty search a plausible explanation, not a proven interpretation of the observed Win32 error. The [GetFileInformationByHandleEx contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex) supports classes 10 and 11 but does not explicitly guarantee error 2 for an empty root. It has no returned-byte-count parameter; a failed call's buffer is diagnostic evidence, not valid directory data.

`Capture-GuestRootEnumeration.ps1` and `NativeRootEnumeration.cs` issue only directory/file-information and volume-extent queries on F:/S:. They use the unchanged, hash-pinned `NativeRetainedFixture.ParseDirectory` to decode successful buffers. Directory access is `READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY`, share-read, open-existing, backup-semantics/open-reparse-point. The native volume handle is read-only and performs only `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`. Exact saved source/shadow proofs, all four disk identities, GPT identities, partition geometry, file systems, labels, allocation units and volume GUID routes are checked before/after. Directory handle final paths and native volume extents are checked on both sides of each enumeration.

Each root makes at most four enumeration calls: class 11 once, then class 10. The first error 2 is retained and followed by one continuation (and any subsequent successful continuations within the four-call cap), but never becomes a completed enumeration or proof of original emptiness. Other native errors stop that enumeration. Successful buffers that the frozen parser rejects remain exported and stop parsing. Every caller buffer is zero-initialized, captured at full capacity and hashed; the record distinguishes that capacity from a native reported byte count, which is null for file-information calls. [FILE_ID_BOTH_DIR_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_both_dir_info) supplies the decoded layout; no new file-ID interpretation is added.

Two explicit private C: controls are created beneath the unique evidence directory: `controls/empty` and `controls/nonempty/marker.bin` (one byte `0x4e`). Both use the same query implementation with a live binding to the enrolled OS partition. An ordinary empty directory may return dot entries, unlike a volume root; consequently even matching or differing control results do not prove the earlier root state. F:/S: receive no create, move, format, raw write, file-time setter or disk-state request. Read access may still trigger normal filesystem access-time bookkeeping. This is observation of a disposable failed branch, not metadata-stability evidence for conversion.

## Exact invocation and export

Stage these four files together in a new ordinary guest C: directory, and invoke in a fresh guest PowerShell process/session (the native types must not already exist):

- `Capture-GuestRootEnumeration.ps1`
- `NativeRootEnumeration.cs`
- `NativeRetainedFixture.cs` SHA `b1152679f8b581cace5114d7aa7ec6954bcf968300d1610015aa04607c7eb9df`
- `NativeRetainedFixture.Windows.cs` SHA `0304b0dd80ba633a11483dda2a56b46824a7ded75314801bb327b64c587f8932`

Parameters are `-RunId d391186e9f21450e92a8dc4711c4c747`, a new 32-lowercase-hex `-ObservationId`, `-SourceEvidenceSha256 7136491eb3cbeb5fc23dbcac3f62af78bd991dde8bb7997cbd4215c9e48e3208`, `-ShadowEvidenceSha256 55e3c20142b8b993cf69277866a0ee4b65d271580d915814a1ba1051d57d57f8`, and the independently reviewed `-DiagnosticSourceSha256` of the new C# file. Source and shadow proof paths are fixed to their original `C:\ntfs2refs\retained-source\<run>\prepare.json` and `C:\ntfs2refs\shadow-platform\<run>\prepare.json` locations. Inputs remain held read-only during the observation.

Output is `C:\ntfs2refs\root-enumeration\<run>\<observation>`. Export only `intent.json` and `root-enumeration.json` (each 1 MiB maximum), plus at most 36 raw files matching `(A|B|empty|nonempty)-0[0-8].bin`, each exactly the recorded capacity (8, 32, 40 or 4096 bytes), with matching SHA. Total raw capacity is at most 66,144 bytes; total evidence stays below 3 MiB. The explicit `controls` subdirectory is excluded from this artifact export. All output files use create-new, never overwrite.

The final schema is `schemaVersion:1`, `kind:native-root-enumeration-diagnostic`. `status:observed-no-guard-change` means all bounded observations and cleanup completed; inspect each observation's status to distinguish EOF, refusal, parse failure and call cap. It does not mean all native queries succeeded. Return fields are `Status`, `RunId`, `ObservationId`, `EvidenceDirectory`, `OperationCompletionKnown`, `CleanupComplete`, and `ConversionQualified:false`. Timeout, unknown operation, cleanup failure, export failure or identity mismatch must preserve the branch without speculative shutdown/restore. Root alone executes and exports the experiment. No runtime is performed by the diagnostic's tests.

## Measured result, 2026-10-24 03:35 UTC

The diagnostic completed and exported under `.lab/hyperv/retained-preparation/win11-20261024T031656056Z/root-enumeration-0d08426554a74dcea47b21102e13cd42`. The guest record spans `03:35:01.2743899Z` through `03:35:01.8392495Z`; host export finished at `03:35:04.114783Z`. Both the guest and all four observations report known completion and successful handle cleanup. The 28 exported native buffers (33,376 bytes total) match their recorded lengths and SHA-256 values.

| Directory | First class 11 result | Next class 10 result |
| --- | --- | --- |
| NTFS `F:\` | Success; `System Volume Information` only | Error 18, `ERROR_NO_MORE_FILES` |
| ReFS `S:\` | Success; `System Volume Information` only | Error 18 |
| New C: empty control | Success; `.` and `..` | Error 18 |
| New C: nonempty control | Success; `.`, `..`, `marker.bin` (EOF 1) | Error 18 |

`host-result.json` SHA-256 is `1568843308a7d2bee71989d1dc2ff5e0a7cce333ca90bf3485a6e2b229879609`; `root-enumeration.json` SHA-256 is `9859fe6f9a33a06e7fd76f299c513ce7ac7cc195a181c993162dac6f2127a9a7`. Executing sources are archived under `reviewed-sources`. The report explicitly records the single C: marker byte, no source/shadow write requests, and `initialEmptyStateProven:false` / `conversionQualified:false`.

This result **does not reproduce the earlier first error 2** and cannot establish what the root contained at `03:17:55Z`. The empty ordinary-directory control exposes dot entries and therefore is not an empty-volume-root control. No diagnostic observation changes the existing fixture guard or qualifies filesystem conversion.

## Narrow interpretation for a future fixture guard

The filesystem-layer documentation above supports testing a narrowly scoped empty-search path: during preconstruction root enumeration only, on the same independently bound open directory handle, an initial class 11 error 2 with no preceding successful entry may be followed by exactly one class 10 call. Only an immediate error 18 would establish that this particular enumeration produced no entries and terminated. Record both failures verbatim, retain their buffers, and keep the native calls themselves marked unsuccessful. A subsequent success, any other error, malformed output, changed binding or missing completion must not qualify this empty-search path.

This is a source-informed interpretation proposed for explicit review, not a native behavior reproduced by this diagnostic. It must not imply durable root emptiness or absence of filesystem metadata; native bookkeeping may create an entry later. It does not apply to the postconstruction namespace, where the expected retained directory and file must be positively enumerated, and it must not turn a lone error 2 into success. The observed failed preparation remains failed and preserved regardless of any future narrowly reviewed change.
