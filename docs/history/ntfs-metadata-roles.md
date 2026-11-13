# NTFS metadata-role candidates

The NTFS inventory now reports ancestry-based roles for allocated records outside the fixed system-record range. This addresses native `$Extend` descendants such as `$Quota`, `$ObjId`, `$Reparse` and the transaction metadata tree, which previously had `is_metadata=false` solely because their MFT numbers exceeded 15.

This classification does **not** authorize omitting, overwriting or freeing any extents. Every record, stream, hash, attribute and extent remains in the report. Directory-index validation, allocation ownership, security resolution, source-state validation and conversion qualification remain blocked.

## Report fields

| `metadata_role` | Meaning |
| --- | --- |
| `not_classified` | Legacy JSON lacks classification evidence. |
| `reserved_system_record` | MFT record number is 0 through 15. This identifies its reserved position, not valid contents. |
| `extend_descendant_candidate` | Every inventoried filename-parent path reaches a validated record-11 `$Extend` anchor. |
| `outside_extend_candidate` | Every inventoried filename-parent path reaches the root without traversing record 11. This does not prove ordinary user-data semantics. |
| `unresolved` | Available MFT references cannot establish a consistent candidate role. |

`metadata_role_issue` records the reason for unresolved ancestry, including missing or stale parents, invalid anchors, missing names, inconsistent link counts, mixed ancestry, cycles, unassembled attributes/extension records and the traversal depth limit. Affected records add `metadata_role_ancestry_unresolved` blockers. Invalid record-5 or record-11 anchors retain their reserved positional role while reporting an issue and blocker.

`is_metadata` is a compatibility convenience: true for reserved records and `$Extend` descendant candidates. False also includes unresolved and legacy states; it is not an assertion that the record is safe to preserve as an ordinary user file. Consumers must use the explicit role, issue and global blockers. No current planner or writer filters extents using this boolean. A future planner must retain every allocation until namespace, ownership and preservation semantics have been independently established.

## Validation and limits

The pass uses already-read MFT records and performs no additional source I/O. It validates the root as allocated record 5 with a single `.` self-reference to its current sequence number, directory status, no base extension reference and no unassembled attribute list. The `$Extend` anchor must be allocated directory record 11 with the exact UTF-16 `$Extend` name and a single current-sequence parent reference to that root. A user-created `$Extend` directory at another MFT number, or a user name beginning with `$`, gains no metadata role from its spelling.

For other records, every filename reference participates, including DOS aliases. Parent records must exist in the allocated inventory, have matching sequence numbers and be directories. A record with unassembled attribute lists or an extension-record base reference remains unresolved. Non-DOS filename count must match the hard-link count; DOS aliases do not increment that count but their parent references are still checked. Paths crossing both `$Extend` and ordinary ancestry are unresolved, even when one conflicting path is a DOS alias. No reparse target is followed.

The iterative traversal memoizes ancestry, avoids recursion and limits a pending chain to 4096 frames. Scratch state is bounded by the existing one-million-record inspection ceiling. Parent lookup uses the sorted inventory, so work scales with the number of recorded links rather than repeatedly walking resolved ancestors. An excessively deep chain produces an explicit unresolved role; it never produces a partially accepted ancestry path.

These checks reconcile MFT references only. Directory indexes may disagree, and even internally consistent MFT references are not permission to discard data. The existing `directory_indexes_unverified` and `allocation_ownership_unverified` blockers remain in all reports.

## Validation

`tests/ntfs_metadata_roles.rs` includes synthetic end-to-end cases for nested `$Extend` paths, user dollar names, a fake `$Extend` tree, mixed hard links and DOS aliases, missing/stale/non-directory parents, cycles, bad anchors, extension records, attribute lists, link-count inconsistencies, deep ancestry and conservative legacy deserialization. Candidate streams remain inventoried and hashed; synthetic source bytes are asserted unchanged.

The opt-in native test accepts only the full 1 GiB `control.raw` with SHA-256 `86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727`. It hashes the source, then performs read-only inspection. It expects records 24–35 to be `$Extend` descendant candidates, 36–43 to be outside candidates, and both names/streams of the native hard-linked fixture to remain present. Native source path is explicit; the test opens no devices or VM disks.

```powershell
$env:N2R_NATIVE_NTFS_CONTROL='D:\code\ntfs2refs\.lab\hyperv\corpus\win11-20261023T213403542Z\ntfs\control.raw'
cargo test --test ntfs_metadata_roles native_windows_control -- --ignored
```

Release executables are deliberately not rebuilt by this work.
