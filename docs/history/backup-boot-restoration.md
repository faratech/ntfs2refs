# Preserve the NTFS backup boot sector during rollback

Source-free journal formats omit old bytes only where rollback may leave free
space changed. The NTFS backup boot sector must survive independently of its
allocation-bitmap bit.

The accepted source geometry includes a bitmap cluster domain ending exactly at
the partition boundary. Previously, if its last cluster was free, the ownership
model could classify the selected backup boot granule as source-free. A shorter
cluster domain already protected that region through the conservative tail.

The ownership model now always covers the final 4 KiB as restore-required.
Existing tail or extent coverage is reused; otherwise an additional interval is
budgeted before allocation and added before normalization. Coarse capture and
final refinement use the same coverage.

Plan validation also rejects every source-free range reaching that final
granule. Recovery validates this before opening the native journal or target, so
an unsafe older format5/6 plan cannot silently discard backup boot bytes.
Formats1–4 retain their behavior. The existing tail-protected native fixture
retains its write set.

This is an accepted-domain code correction, not a reproduced corruption result
on the recorded fixture. Native qualification of the final release binary is
separate. No unit tests were added or run.
