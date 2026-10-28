# Allocation-only canonical tree staging

## Bounded exception materialization

The subsequent implementation adds
`ntfs_inspect::read_plain_stream_range_into` and
`general_shadow::materialize_private_range`. A caller-owned64-KiB-or-smaller
buffer receives only the selected logical range. Before and after the read,
the existing checked-attribute path revalidates geometry, MFT bootstrap,
file identity, run mapping, lengths and inspected stream digest. Holes and
bytes beyond initialized length still return logical zeros. Selected bytes
are charged to the existing cumulative transfer budget; metadata IO remains
separate. A whole-stream small read must match its inspected digest. A partial
range proof explicitly does not claim whole-stream content verification.

The owning-source wrapper requires the actual excluded source binding to
match the private template, binds canonical file length/hash/name/index, and
checks source state around both reading and materialization. The native file
can accept only a bounded write no later than its tracked valid prefix; a
write beyond that prefix is rejected before IO. Thus a final byte at8 GiB
cannot implicitly zero-fill an uninitialized8-GiB gap. Placement must happen
before initialization; complete placed-prefix coverage is still required for
the one-time VDL advancement.

Each materialized range is explicitly sought, written, flushed, read back and
compared. EOF/type/link-count and all previously placed mappings are rechecked.
Failure poisons the private file and retains it for diagnosis. Permissions
remain protected SYSTEM-only; no source metadata is restored early. Empty
ranges do not authenticate a nonempty stream. Materialized and readback byte
counters are reported separately with checked aggregation; ordinary template
allocation still reports zero. No raw source writer or conversion authority
is introduced.

These APIs have release-build evidence, not native materialization/conversion
qualification. They are not selected by the working full-shadow converter or
the allocation-only CLI yet. Next connect them to the process-lifetime
placement/materialization/freeze workflow and qualify actual resident/tail
data. Full payload supply, root/system metadata, source metadata restoration
and complete required-byte coverage remain pending. No unit tests added/run.

Sourceb3c7d3f connects the canonical `shadow_tree` to the native private
constructor through `general_shadow::allocate_private_tree`. The separate
`lab-allocate-private-tree` command stages the original Unicode user paths and
file lengths without copying their contents. It is not a conversion command.
All file and user-directory DACLs are protected SYSTEM-only. Root/system data,
source ACLs, timestamps, attributes and payload supply remain explicitly pending.

The native template owns its file handles and exposes placed-prefix operations
through the unwritten constructor. It requires the enrolled isolated guest,
excluded source, independent writable ReFS/4-KiB shadow, fresh user namespace,
bounded paths/counts and complete parent ordering. No source write handle is
available. Existing formatter-cache handling uses the earlier narrow preflight;
unknown system entries refuse rather than disappear. Source-image hash and
complete admission are not established by supplying canonical JSON.

## Native outcome

Run`29abdc44bbcf42e69783c3736c1fb349`, producer SHA-256
`df1c5f22ee4a17b800e61b59a555c6df7a7d272774543e5ae7bded165a35a4d5`,
constructed the namespace but exited1 during reporting: the reporter wrongly
requested a nonresident retrieval map for an empty file. Original refusal
SHA-256`116cb2579eaec82fae50ff81f4b3c5702b0044656dcecdfa5df1bea0b7601c92`
is preserved. Construction/formatting were not repeated over that run.

Source3535d78 distinguishes empty/subcluster allocations and adds a separate
metadata-only observation command. Observer
`f0f7140b4eb8419ea3dd910de69770ad`, producer
`d6d47037644788208f5013d304fe396e339629a03b32bb44c221b97e6d80ded8`,
exited0 and verified the exact user namespace, distinct single-link file
identities, lengths and applicable retrieval maps. Its144,473-byte result is
SHA-256`21d2253c40e0be83c8ab431e4351130e3963183be7dcad78e4a4531cf9d3ec2c`.

Six user files total8,590,196,754 logical bytes, including8,589,934,593 bytes
in the large file, plus three user directories. The empty file has0 allocation;
the17-byte file has24-byte subcluster allocation. Large-file allocation is
8,589,938,688 bytes. The canonical13-object input also accounts for root/SVI
and its system files; these are pending rather than claimed reconstructed.
Both construction and observation issued zero user-payload read/write calls.
Stored descriptors independently confirm SYSTEM owner/group and one protected
SYSTEM full-access ACE for all six files and three user directories.

The NTFS source remained offline/read-only. This establishes allocation-only
user namespace staging, not payload contents, stored-validity after reboot,
source admission, metadata restoration or conversion of the original partition.
No unit tests were added or run. Evidence is under
`.lab/hyperv/streaming-v2-20261027/private-tree-allocation-20261028`.

## Storage observation and preservation

After clean shutdown the new shadow child used140,509,184 filesystem storage
bytes (134 MiB), despite the8-GiB logical file. The metadata-only Rust observer
uses [GetCompressedFileSizeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew)
and checks stable file identity/length/time. Here the child is non-sparse and its
file length equals the reported storage size. This includes the child's format
and allocation work, excludes shared parent images/OS/journal/evidence, and is
not a total scratch bound or physical-device I/O measurement. Parent-independent
construction and a complete required-byte capture remain unproven.

OFF checkpoint`ebb2feb4-dc0f-4551-93ee-9a031f96b7ca`, parent
`524c530e-2f6e-4ff6-849d-3bf7a9af71bf`, preserves this state. All18 earlier
checkpoints remain (19 total), including converted candidate12. The VM was
cleanly stopped and its4-GiB RAM released before returning to candidate12's
already-authorized acceptance sequence. Do not redispatch either template task.
