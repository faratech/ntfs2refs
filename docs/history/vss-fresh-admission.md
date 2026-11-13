# Fresh source VSS admission

Fresh conversion qualification now requires VSS evidence for every scratch and
verification policy. Previously, the pre-freeze catalog and protected native
observation were requested only for source-free scratch selection. Conservative
allocation and whole-image qualification could skip that admission check.

The common source-context constructor collects and saves the current hosted
storage catalog while the source is online, requires affirmative catalog
clearance, and binds its source volume GUID. The physically read-only native
observation then requires snapshot absence and the same source/provider
inventory before source assessment and certificate issuance. Unknown, failed or
nonempty observations refuse. Callers can no longer pass an optional observation
or select a scratch policy to bypass this requirement.

Whole-image qualification retains its two content passes. Allocation qualification
retains its single content pass and outer source brackets. Both reuse the existing
protected native view; no extra mount is added. Recovery continues to authenticate
its existing journal and does not request a new source certificate.

Focused Windows compilation of the public, marker and composite binaries passed,
and an independent source review covered all three fresh qualification callers.
No unit tests were added or run. This closes the identified policy bypass; it
does not claim global serialization against concurrent VSS activity or native
qualification of a newly built public executable.

The clean4d8ca99 public executable subsequently passed the positive refusal
case. SYSTEM created one actual persistent Microsoft ClientAccessible snapshot
on F:, then invoked `ntfs2refs --drive F --partition 2` with affirmative stdin.
The default/conservative command exited1 in3.546999s. Its saved catalog reported
source snapshot presence with HRESULT0 and a hosted diff area on the same source;
qualification stopped at `source-vss-catalog-before-freeze`. F: stayed online
NTFS, with no source certificate or journal preparation reached.

The original observer failed after the native refusal because it assumed six
disks; the product had correctly created its own empty shadow as disk6. A new
read-only completion verified that exact provider/receipt/GPT identity, the
original owned process and snapshot, and the refusal artifacts. It completed
Ready/0 without another converter process or VSS mutation. The original Ready/1
observer failure is preserved. The empty shadow used100MiB of backing storage;
its formatting preceded the gate and is not counted as zero total writes.
See [the pinned native case](../evidence/public-positive-vss-refusal-4d8ca99-20261102.json).
