# Reuse authenticated journal records during recovery

The new internal recovery owner retains the complete actual journal validation
and lifecycle classification while the caller keeps the same exclusive journal
borrow, plan and trusted ticket. It is created by reading the journal, never by
deserializing a lifecycle or accepting a Boolean. It exposes no mutable journal
accessor and is consumed by one recovery operation.

This owner concerns the journal only. The native recovery target keeps its
existing sharing mode. No new global target, administrative or volume-alias
exclusion is claimed. Every existing mixed target precheck, per-span old/current/
new read and comparison, exact post-write target checksum and final handoff
target checksum remains. Discovery-last writes, intent checks, flushes,
readbacks and durable HND/ABT markers remain.

Resume persists its receipt through a result-only callback before HND. Callback
failure leaves the operation unclosed. All metadata pins and resource-policy
checks still apply. Legacy public journal APIs retain their full independent
validation; no file format, ticket or verification policy changes. Successful
allocation recovery reports `exclusive_recovery_journal_used=true` only after
the owner was created and consumed; this diagnostic grants no replay authority.

Only duplicate authentication of the continuously owned immutable journal body
is removed. Caller obligations include excluding its own hidden mutable aliases;
the native journal file remains opened with sharing mode zero. Marker updates
are outside the immutable body. A reopened journal still requires complete
authentication.

For the frozen `e4ffb3a` interrupted plan, let `B=J−8192` be immutable stored
bytes, `P=D−O` stored old bytes, and `R=C+L−Q` resolved new physical reads.
Here B=5,849,723,288, P=5,805,162,496, R=5,703,495,680 and Q=0.

| Operation | Avoided duplicate logical journal reads |
|---|---:|
| Resume through HND: `4B + 2R` | 34,805,884,512 |
| Rollback through ABT: `2B + R` | 17,402,942,256 |

The old Resume path authenticates during lifecycle, resume and handoff, and
also rehashes the body after resume and after handoff verification. The owner
keeps the original authentication valid across those stages. These figures are
code-path accounting, not measured native or physical-I/O improvements.
Implementation and independent review are complete. Focused library/public/
fault-helper/binder compilation passed in 17.68 seconds. Native qualification
is pending; the frozen e4ff recovery matrix does not exercise this newer owner.
No unit tests were added or run.
