# Isolated reference controls: execution plan only

The frozen native-shadow alpha is complete within its recorded profile. This
independent-writer control work does not block its delivery or change its engine.
No setup, initialization, formatting, import or writer run is authorized by this
plan or by an informational journal observation.

## Exact fixture and fresh enrollment

Use only existing VM `ntfs2refs-reference-isolated`, GUID
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`. Retain its current configuration/security.
Leave OS disk 0 and RAW target disk 1 untouched. Journal disk 2 is the existing
8 GiB device, NAA `600224806AAC261F021F249596F332FC`.

After separately admitted initialization, capture fresh GPT disk, partition and
mount-manager identities for J:. The proposed profile is one partition, number 1,
offset 16 MiB, length `8 GiB - 32 MiB`, NTFS with 4 KiB clusters. A different
layout needs a versioned profile. Do not reuse historical journal identities.

Each control gets independent fresh experiment/run IDs, persistent VHD ID and
actual backing-file identity at
`J:\ntfs2refs-reference\<fresh-experiment-id>\reference.vhdx`. Bind the discovered
provider device number (at least 3), not a guessed disk number. Use existing Rust
import/verification paths and narrowly versioned fixture bindings.

## Two separate controls

1. **Untouched reference:** import packet SHA-256
   `585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b`
   into a fresh 64 GiB virtual disk. The packet writes 68,157,440 bytes. Require
   the existing whole-disk blank scan, complete imported disk/footer/partition/
   payload hashes, GPT, flush and handoff proofs. Baseline-only mode has zero
   overlay pages or adopted-payload writes. Verify the two original files through
   Microsoft's driver and absence of the adopted name. Preserve and detach it.
2. **Original rejected control:** independently enroll another fresh disk and
   import the same packet. Replay only preserved `final-metadata.cow`, SHA-256
   `d25e7b8ec70256a47159a30c78b436ffcd525c00fc4ec4c34f1a533c6feb7eaf`:
   eight metadata writes, 131,072 bytes and three real flushes, with zero writes
   to the adopted 4 KiB payload. Retain old/new/readback and payload evidence.
   Attempt native acceptance once and collect events without repair or retry.
   Defect diagnosis and a replacement writer are outside this plan.

Both controls retain all original evidence, and get distinct fresh identifiers.
Pre-mount exact-image claims end at durable handoff/native mounting. These ReFS
reference controls supply no NTFS-conversion rollback guarantee. Preserve rejected
media offline/detached; do not reinterpret a failed observer as recovery authority.

## Execution blockers and capacity

`New-ReferenceImportDisk.ps1` retains old J: GUIDs;
`NativeImportedReference.cs` retains the original rejected VHD ID. The historical
host dispatcher selects the protected `win11` lane and bypasses execution policy.
Do not run these routes unchanged on the isolated VM or remove their old guards.
Only a separately reviewed, narrowly versioned isolated enrollment can use them.
The initialization proof gate remains closed; a read-only report cannot open it.

At the read-only capacity observation around 2026-10-27 03:46 UTC, actual lab
usage was 182,437,692,234 bytes against a 223,338,299,392-byte ceiling, and host
free space was 72,205,086,720 bytes against the 68,719,476,736-byte reserve.
Thus the smaller current headroom was 3,485,609,984 bytes; after the 128 MiB
observation allowance it was 3,351,392,256 bytes. These are observations, not
reservations or a mechanism that stops guest writes at the budget.

The existing conservative setup budget requires 94,623,498,240 bytes
(88.125 GiB) of initial free space: 8 GiB journal growth, 128 MiB overhead,
16 GiB growth allowance and the unchanged 64 GiB reserve. The measured shortfall
was 22,418,411,520 bytes (about 20.88 GiB). An 8 GiB dynamic journal can grow
beyond the measured headroom, and the prospective reference backings must fit
the journal together with its reserve; monitoring alone is not an enforceable
write quota. Reacquire capacity and establish an enforceable write/growth bound
before setup. No deletion, limit increase, VM snapshot or configuration/security/
credential change follows from this plan.

## Next bounded investigation (not dispatched)

The preserved observation contains one complete guest logical read and host
file identity, length and timestamps before/after. It does not contain a
before-and-after byte snapshot of the 4 MiB VHDX container. The preboot archive
hash is from a different time and cannot establish when any later container
change happened. These records alone therefore cannot distinguish a VHDX
metadata update from a change in guest-visible data, or establish the cause
of the changed last-write time.

The next useful investigation is a separately reviewed, capacity-admitted
test on the same isolated fixture: capture immutable full-container bytes while
the VM is offline, perform one controlled read-only guest observation, then
capture the complete container again while offline. Compare changed container
regions and independently resolve the before/after VHDX block mappings to the
guest-visible logical bytes. Record both guest and container hashes and retain
both copies. Use the exact VM/disk-2/file bindings above, prohibit unrelated
workers, and do not infer a durable writer fence from a matching comparison.
If mappings, logs or timestamps cannot be explained, retain the refusal.

That sequence would change the isolated VM's runtime state and repeat a disk
observation; this document does not authorize it. It is independent of, and
must not delay, the native-shadow converter. The reference-control setup still
needs the measured free-space shortfall addressed and a genuinely enforceable
growth bound before any formatting or import, not merely periodic monitoring.
