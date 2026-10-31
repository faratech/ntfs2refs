# Exact selected target verification

Selected journal consumers first validate the complete immutable body, plan,
ticket, descriptors, payloads, copy references and footer. The target verifier
then has two distinct obligations:

- An exact old or new state must match that independently authenticated selected
  digest, using the original range framing and SHA-256 over every target byte.
- A partially applied recovery state must contain only the recorded old or new
  value at every selected byte before replay is permitted.

The exact-state path now reads and hashes every selected actual target byte,
compares the same framed SHA-256 with the trusted ticket side and refuses any
mismatch. Rereading both journal sides merely to prove old-or-new membership is
redundant once that complete exact-side match succeeds. Mixed-state prechecks
retain all old/new reads and every original byte-membership comparison.

Target lengths and validated range coverage, failable hashes, write ordering,
flushes, intent/completion markers and immutable-body checks remain. No reader
depends on the journal cursor left by target verification. Journal formats,
framing and expected digest values are unchanged.

For two exact-side checks, avoided journal reads are up to `4*D - 2*Z`, where D
is selected bytes and Z is synthetic-zero new bytes. Zero data has no stored
new payload to read; copy references still resolve stored old bytes. This is
logical API accounting, not a physical-disk or elapsed-time measurement.

Focused checks, independent code review and public, bind, digest and fault-helper
release builds pass. Native qualification is pending. The active 18bdea8 F
conversion uses an earlier sealed binary and does not qualify this change.
No unit tests added or run.
