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
