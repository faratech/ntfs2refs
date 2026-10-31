# Capacity-pinned journals and capture storage

Profile 3 replaces the public allocation converter's fixed 16 GiB journal
ceiling with an explicit ceiling derived from available independent storage.
It does not remove the remaining file, range, geometry or literal-file limits.

The request pins separate journal, literal-backing and combined-scratch limits.
Journal and backing share the measured pool; zeros and copy references can
leave the nominal backing allowance unused without stranding that space.
The initial working reserve remains outside the pool. Literal backing retains
its separate held-file bound. Whole-image conversion keeps its old profile.

During capture, `D` changed bytes and `L` literal bytes require at most
`D + L + metadata` journal bytes and `D + 2L + metadata` combined storage.
The existing 16 MiB metadata allowance covers the widest selected records.
Each prospective append is checked against all resource limits before writing.
Zero/copy runs also increase the future journal requirement and are checked.

The live guard verifies that backing and journal use the pinned storage volume.
It checks available space initially and at 4 MiB changed-byte intervals, tracks
its own intervening literal allocation conservatively, and refreshes immediately
when the cached estimate is insufficient. These observations remain advisory.
Exact encoded plan sizing and a fresh space check precede journal creation.
After the verified durable journal exists, another check requires only the
remaining working reserve, avoiding a second charge for existing allocations.

Profile 3's capacity is persisted in the journal binding inside the trusted
ticket and immutable manifest. Recovery derives it from pinned input, never
from current free space or observed file size. Selected recovery also requires
the plan's ceiling to equal the pinned request's ceiling. Source activation
still requires the original live source certificate and verified journal.

Historical schemas 1/2 omit the new fields and retain their existing bounds and
serialized form. Dense journal limits remain capacity/2; old-only bounds apply
to the separate zero/copy-aware selected path. Selected journal format numbers
and `N2RSEL01`/`N2RZERO1`/`N2RCPY01` encodings are unchanged. Fresh profile-3
capture is currently supported by the allocation-bounded backend only.

The checked NTFS reader now uses full typed equality instead of temporary JSON
serialization for geometry, attributes and assembly evidence. Owned parsed DATA
attributes move into sessions instead of cloning their run lists. Every raw
boot/MFT/physical extension-record reread and existing identity, mapping, VDL
and digest check remains.

The large d974efe run stopped before activation at the 16 GiB caller ceiling.
Its captured changed bytes were 15,139,008,512, literal backing 3,784,351,744,
and copy references 5,659,336,704. Old plus literal journal payload alone exceeds
18.9 GB. The source remains protected NTFS; its 43 closed metadata files and
failure checkpoint are preserved separately. This motivates the capacity change
but does not qualify profile 3. Focused library/release builds pass; native
profile-3 conversion and recovery remain pending. No unit tests added or run.
