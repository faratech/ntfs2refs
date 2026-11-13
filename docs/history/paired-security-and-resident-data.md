# Stored security, API projections and small ReFS streams

The ordinary tree now carries the stored Windows descriptor and an optional
separate `GetSecurityInfo` projection. The stored descriptor still has to
match `GetKernelObjectSecurity`; both API observations must agree. The target
must reproduce each view against its own expectation. The strict source
comparison still reports differences; no ACE/control-bit masking was added.

The captured NTFS source contains eleven ordinary objects: its original
four files/four directories plus `System Volume Information` and its two
Windows-generated files. A pinned replay accounts for all eleven views and
records two API projections. Replay alone cannot bind a live source.

Native ReFS reconstruction of the protected system-directory/file descriptor
pair passed in the owning Windows 11 VM. Ignored evidence is under
`.lab/hyperv/security-projection/win11-20261025T164737463Z/result.json`,
SHA-256 `c372ebe1700f22166e224379aceb6d40e708bf0bbf11b62237a2287db9a6340c`.
The standalone probe initially copied its privilege audit before restoration;
that reporting order is fixed. Its descriptor snapshots and comparisons are
retained as originally recorded.

The full eleven-object native ReFS shadow subsequently passed contents,
namespace, basic metadata and both descriptor views. Its verification report is
`.lab/hyperv/general-qualification/win11-20261025T172128292Z/shadow-verify-resident.json`,
SHA-256 `4c5e8ae9505aabd5cfebb3b19ffbf5788fcacfe7587e8e9d2fea49c6c084e98a`.
Two streams are resident. ReFS reported 80 allocated bytes for the 76-byte
`IndexerVolumeGuid` stream and returned retrieval-pointer EOF. Resident data
has no physical extent map, as described in Microsoft's
[retrieval-pointer contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers).
The native reader now records subcluster resident allocation explicitly,
requires complete logical hashing and keeps these streams materialized in
metadata rather than inventing retained physical ranges.

A fresh empty ReFS root returned initial query error 2 followed by continuation
EOF 18. The namespace reader now requires that exact two-call sequence before
accepting this empty case. Lone errors, nonterminal responses, changed results
and other native failures remain refused. The observed calls are retained in
`.lab/hyperv/projection-shadow/win11-20261025T165750725Z/directory-root-calls.json`.

Construction can reuse only the formatter's known system directory and the
two expected bounded cache files, with stable native file identities. Unknown
system-directory contents remain refused. Ordinary existing user paths are
never reused by this rule.

The combined runner reached a source assessment with zero refused objects
and 27 explicit NTFS-internal replacement dispositions. Only target
preservation remained. Its first connected conversion attempt stopped before
raw writes because one accumulated control log reached its 128-call cap.
Audit logs are now durably saved in separate preflight/source/target batches;
the native per-batch limit remains unchanged. The retry is recorded under
`.lab/hyperv/certificate-conversion/win11-20261025T185439277Z`.
It must be inspected before claiming certificate issuance or completed cutover.

`general_conversion` now connects live qualification to the existing journal
engine in one owning-machine process: certificate/plan binding, journal
preparation, durable ticket readback, apply, irreversible handoff and native
ReFS verification. The new lab executable exercises this path inside the VM.
The general public CLI and broader recovery qualification remain unfinished.
