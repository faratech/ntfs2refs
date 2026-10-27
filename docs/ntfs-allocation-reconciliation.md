# Raw NTFS allocation reconciliation

The Rust inspector now retains the exact bitmap domain long enough to compare
it with physical intervals from every decoded nonresident attribute. The new
`allocation_reconciliation` report field records the bitmap SHA-256, cluster
domain, interval count, status and diagnostic. Old serialized reports default
this additive field to absent.

The pure ledger in `src/ntfs_allocation.rs` checks per-attribute VCN overlaps,
global physical overlaps, claimed-but-free clusters and allocated-but-unowned
clusters. It includes allocation beyond logical EOF. System metadata receives
no exception. DATA attributes are supplied once from `attributes`; the duplicated
`streams` view creates no additional claim. Resident contents are already owned
through the MFT allocation, and sparse holes have no physical claim.

The inspector refuses to assess a partial model if any record has an unassembled
attribute list/extension or repeats an attribute instance. The later
[ordinary DATA assembly profile](ntfs-attribute-list-assembly.md) supplies one
canonical allocation claim per stream and a separate physical-record ledger;
extension origins are never counted a second time as payload owners. It also rejects MFT
bitmap allocations beyond MFT EOF. Bitmap bytes must be fully initialized,
unencoded and nonsparse for the requested domain; synthesized zeroes must never
hide allocated file records or volume clusters.

The standalone ledger's defaults are 4,096 physical intervals, 16,384
cumulative attribute-name units, 2 MiB of bitmap and 16,777,216 cluster
checks. The inspector supplies the full already-read bitmap and its actual
cluster domain instead of reapplying those last two defaults; its bitmap read
remains capped at 128 MiB. Reconciliation scans bitmap words across sorted
ownership intervals and reports the first mismatched cluster. Interval, name
and sorting limits still apply. Bits beyond the final cluster are padding and
never become domain allocation.

`consistent_raw_model` means the supplied decoded intervals reconcile with the
bitmap. It does not establish a complete NTFS namespace, security descriptors,
native bitmap/retrieval-pointer agreement, valid backups or a clean recovery
state. The existing allocation/source-admission blocker and
`inventory_complete=false` remain. No writer profile is expanded by this change.

Nineteen pure-ledger tests include all 65,536 eight-cluster bitmap/claim-set
combinations. Ten parser integration tests cover complete synthetic ownership,
metadata/data overlap, false-free and unowned allocation, allocation past EOF,
unassembled system attributes, ambiguous identities, out-of-MFT bitmap bits,
and uninitialized MFT/volume bitmaps. At that milestone the workspace passed
224 tests, with five explicitly ignored native/child-process tests. Its
build uses a separate ignored target directory; the running guest experiment
continues to use its original pinned release binaries.
