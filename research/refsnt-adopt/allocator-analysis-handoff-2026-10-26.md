# Allocator findings handoff

Abigail's personal analysis was conveyed by the coordinating chat on October
26, 2026. This note preserves that analysis; the proposed field semantics and
native causality have not been independently established here. No repair or
new test is implied by it. Preserve the original candidate and baseline.

The reported sum of Medium allocator row value `+0x16`, expanding `0xffff` to
the row range length, changes from 245,984 in the baseline to 247,009 in the
candidate. Root summary slot 4 at page `+0x98` remains 245,984. Baseline equality
is exact; the candidate discrepancy is 1,025.

The original 1,024 bitmap bits in row 18 reportedly describe the reference
`fixtures\nonresident.bin` at physical LCN 1,507,328. Row 18's `+0x16` changes
from 0 to 1,036 after twelve metadata allocations. Row 0 changes from 212 to
201 after twelve metadata clusters are freed and one data cluster is adopted.
The ordinary root free count and row bitmap/free counts reportedly remain
correct.

One hypothesis is that `SetCounts` in the external `rfsalloc.c` replaces a
class-specific statistic with total bitmap occupancy. Under the proposed
metadata/special-allocation interpretation, the candidate fields would be
200 and 12. Those values are hypotheses, not repair instructions. Changing root
slot 4 to force equality would not establish the intended semantics.

A separate reported fidelity difference is the first root index marker's
normalization from 1 to `0xffff` by `Encode`. Its validity is also unproved.
Current Rust structural checks do not establish either potential invariant.

The preserved candidate is under
`.lab/hyperv/writer-acceptance/win11-20261025T231634770Z`. The separate accepted
zero-overlay control is under
`.lab/hyperv/writer-baseline/win11-20261026T051439507Z` and
`.lab/hyperv/baseline-native-verification/win11-20261026T052857143Z`.
