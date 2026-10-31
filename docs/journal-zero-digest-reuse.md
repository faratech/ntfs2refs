# Bounded zero digest reuse

Selected-journal preparation and validation now keep at most 64 canonical
`SHA256(0^length)` digests. The fixed array plus its count occupies 2,568 bytes
on the current target, with no heap allocation. It retains the largest lengths
because those save the most repeated per-record hashing across passes.

A candidate range still undergoes every actual read and every all-zero byte
assertion. Every byte and its original range framing still enters the selected
aggregate hash. A cache entry is issued only after the complete zero assertion
and successful finish of the existing failable SHA backend. A hit substitutes
only that mathematically identical, unframed per-record digest.

Validating readback may also seed an entry from freshly generated canonical
zeros after their digest matches the stored record. Each stored hash comparison
remains. Generated-zero slices and all selected aggregate updates remain in
both descriptor and resolved passes. Old payloads, literal data and copy
references always retain their actual per-record hashing; zero-valued old or
copy data is never inferred from this cache.

One cache spans preparation, its validating readback and resolved-new pass.
Each independent load starts an empty cache and shares it only between that
load's descriptor and resolved-new passes. Complete immutable validation and
trusted-pin comparison still precede copy resolution. Header/descriptor/footer
checks, source/candidate comparisons, target/recovery checks, write ordering,
flushes and lifecycle barriers are unchanged. No cache state or new trust is
persisted, and journal formats/digests are unchanged for identical inputs.

The completed earlier F plan had 633 zero ranges totalling 5,694,500,864 bytes,
with 263 distinct lengths. Its largest 64 lengths cover 5,038,911,488 bytes.
Across preparation's descriptor/resolved readback and one independent load's
resolved pass, reuse therefore avoids at least **15,116,734,464 per-record SHA
input bytes** for that plan. This is a metadata-derived work estimate, not an
I/O reduction or measured CPU/time result; all aggregate hash input remains.

Focused library/public-CLI compiler checks and independent correctness review
passed. No unit tests were added or run. Native qualification is pending.
This cache was **not used** in the completed sealed f32 V3 case with 273
directories and all 811 independent hashes.
