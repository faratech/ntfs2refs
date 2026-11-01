# Source directory case admission

Fresh source collection uses Request5/Report13 for full content and6/14 for
extent verification. It queries actual NTFS FileCaseSensitiveInfo(class23) before
and after every raw directory observation. Every transferred directory requires
exact4-byte successful zero flags, stable directory/delete state and full NTFS
serial/file-reference/sequence identity before a source certificate is issued.
Missing evidence, query errors, nonzero flags and mismatched identities refuse.

Raw observations remain complete, including errors. Admission's exact directory
set is bound separately after existing index, transaction and source-state checks
produce a private internal-replacement proof. A raw metadata role or candidate
label cannot exclude anything. Only exact record/sequence/role identities from
that proof can be classed as replaced internal directories; the root and every
transferred directory remain required. Expanded profiles recompute this scope
independently before binding. `.assessment.directory_case_admission` records the
required/replaced partition; `.comparison.directory_case_sensitivity` retains
the original raw observations.

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

The actual2e20aa9 run observed278 raw directories,277 successful zero/zero pairs,
and actual query87 for internal `$Deleted` record29. It refused before certificate,
journal or conversion writes. That query remains Unknown; it is not converted to
false. The proof-bound applicability correction is compiled and source-reviewed;
native qualification remains pending. No unit tests were added or run. The versioned performance observer can
require the exact14/6 pair and complete positive per-directory evidence without
equating it to the historical full-content baseline.
