# Fixed-length native ReFS trust-label repair

The Windows boot-conversion path must preserve process-trust labels. The
existing raw journal writer is reused; this is not an independent filesystem
formatter, allocator, or replacement ReFS implementation.

The measured source ACE is type `0x14`, flags `3`, length `24`, mask `001f01a9`,
SID `S-1-19-512-4096`. Native restore APIs omit or reject that label. A temporary
type `0x0d` audit-callback record has the same width, and its mask is calculated
from the actual descriptor prefix so the ReFS descriptor hash remains equal.
The native one-file experiment retained this placeholder exactly. Type `0x02`
was rejected as a strategy because Windows strips its required reserved mask bit.

Construction inputs and source digests retain the original security descriptor.
Only the explicitly named provisional Windows constructor uses temporary
restore/readback views. Source admission and final native comparisons stay strict.

The bounded planner starts at the frozen target VBR, authenticates both
checkpoints and Object Table copies, and follows the existing `0x530` security
table. Native descriptor packing may differ from NTFS: complete control, SID,
ACL-state, revision, ACE order and ACE bytes must still match the intended
placeholder. It restores only the selected ACE prefix in those exact native
bytes, requires the existing descriptor hash and SecurityId to remain valid,
and updates existing CRC references and checkpoint self-checks. It allocates no
filesystem pages and changes no data extents, record lengths, or security IDs.

The existing journal engine applies the selected metadata clusters with durable
intent, old/new verification, handoff and read-only reseal. Final target
observation must then recover the **original** trust label through Microsoft's
driver before the main in-place conversion may write the original partition.

The hidden `lab-refs-security-repair` tool is restricted to the separately
created data-only oracle. The one-file native raw-repair acceptance and the
original Windows installation's conversion/boot remain unproven until recorded.
No temporary shadow or secondary Windows disk is a permissible final boot
dependency; successful conversion publishes onto the original partition.
