# Source directory case admission

Fresh source collection uses Request5/Report13 for full content and6/14 for
extent verification. It queries actual NTFS FileCaseSensitiveInfo(class23) before
and after every raw directory observation. Exact4-byte successful zero flags,
stable directory/delete state and full NTFS serial/file-reference/sequence
identity are required before the opaque source certificate can be issued.
Missing evidence, query errors, nonzero flags and mismatched identities refuse.

Some recognized NTFS internal directories cannot be opened with the ordinary
metadata/security access mask. New reports retain that original failure and may
add a held same-identity FILE_READ_ATTRIBUTES-only observation. Its explicit
`case_only_fallback` contains actual basic/standard/FileID and case queries on
both sides. It does not replace the failed security observation or waive any
user-object metadata/security requirement. Historical reports omit this field
and retain Unknown case state.

Only NTFS source queries change. ReFS target collection is unchanged. Old
diagnostic/recovery schemas remain readable; actual live assessment collectors
now request the new full-source protocol. Unprofiled Report13 retains legacy
paged bitmap reconciliation, while profiled13 and extent14 retain streaming.

Focused compilation passed. Native positive and refusal qualification remain
pending. No unit tests were added or run. The versioned performance observer can
require the exact14/6 pair and complete positive per-directory evidence without
equating it to the historical full-content baseline.
