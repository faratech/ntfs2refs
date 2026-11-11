# Explicit native target format

The public drive command accepts `--target-format dev-drive|standard`. The
experimental default remains `dev-drive`, preserving the qualified alpha path.
The requested type is shown before confirmation. `standard` omits the formatter's
`/DevDrv` option; an unsupported format fails without switching profiles.

After native formatting, the newly owned shadow still has to satisfy the existing
ReFS3.14/4KiB geometry and label checks. A read-only persistent-volume query must
also positively match its developer designation to the request before source
preparation or freezing. Query errors, unsupported flags and malformed replies
retain unknown values and raw diagnostics. They do not become false/absence.

Requested and observed policy is recorded in separate sidecars. Existing managed
shadow descriptors and recovery schemas stay unchanged. After a completed
handoff, the source itself is queried independently; observation/report errors
cannot reopen raw replay or undo the completed filesystem.

Developer designation and trust are different flags. Trust is machine-specific,
so the source's trust is never inferred from its donor shadow. The implementation
issues only FSCTL_QUERY_PERSISTENT_VOLUME_STATE and exposes no setter, trust,
filter or registry operation. See Microsoft's [structure contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_fs_persistent_volume_information)
and [Dev Drive query documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-devdrv).

The saved4d8 converted source was actually queried as a developer volume that
was not trusted on the machine; see [the observation](../evidence/converted-volume-policy-4d8ca99-20261102.json).
This fact is not standard-ReFS qualification. The new native query's returned
mask behavior, both target choices and post-handoff reporting require native
execution before release claims. No unit tests were added or run.

The first native query returned success and16 bytes with VolumeFlags0x6000,
while its other three response DWORDs were zero. Requiring request mask/version
echoes incorrectly refused the fresh shadow before source preparation. The
reader now interprets only VolumeFlags from an exact successful response to its
fixed version1/mask0x6000 request. The query contract rejects invalid request
versions/masks; it does not promise echoes. Raw response fields remain recorded.
API errors, short/oversized replies and contradictory designation/trust remain
unknown. The failed attempt is preserved and the source remained online NTFS.

Clean05c1abd then passed native conversion and all811 independent stream hashes/
1084objects. The shadow was positively developer/trusted while the SOURCE was
independently developer/untrusted, with designation matching the request. See
[the corrected native case](../evidence/corrected-devdrive-public-05c1abd-20261102.json).

An explicit `--target-format standard` run on a separately restored source then
received format.com exit4 and “ReFS file system is not supported on this device.”
The source remained online NTFS and no source preparation, freeze, certificate
or journal was reached. No alternate format was attempted. This records the
device's formatter refusal, not a successful standard-ReFS conversion or a
universal claim about Windows editions. Standard qualification remains open.
See [the refusal](../evidence/standard-format-refusal-05c1abd-20261102.json).
