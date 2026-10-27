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

The last recorded free space was about 67.49 GiB. The existing conservative setup
budget requires 88.125 GiB: 8 GiB journal growth, 128 MiB overhead, 16 GiB growth
allowance and the unchanged 64 GiB reserve. That leaves a roughly 20.6 GiB deficit.
The 208 GiB actual-lab ceiling also remains enforced. Both reference backings must
fit J: together with its reserve; individual 6 GiB ceilings do not prove combined
fit. Reacquire capacity before setup. No deletion, limit increase, VM snapshot or
configuration/security/credential change follows from this plan.
