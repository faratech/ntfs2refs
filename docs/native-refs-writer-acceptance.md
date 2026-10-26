# Independent writer: native acceptance preparation

The strict REFSNT experiment produced a candidate ReFS image with an existing
4 KiB cluster adopted as `/adopted-existing.bin`. Microsoft acceptance is still
unqualified. This next experiment must preserve the already successful
converter branch and execute metadata import and native inspection inside the
disk-owning VM.

## Exact reference and small transport

The existing reference is
`.lab/hyperv/corpus/devdrive-20261023T231918797Z/target-fixed.vhd`.
Its 68,719,477,248 bytes have recorded SHA-256
`b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7`.
Its selected partition starts at 16 MiB, has length 52 GiB and SHA-256
`805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9`.
These pins come from the completed fixed-VHD extraction report.

Restoring the earlier checkpoint and booting its populated disk can allow
native ReFS changes before the experimental patches are applied. A new
reference disk prepared offline avoids that ambiguity. Do not create another
52 GiB raw copy or expose the immutable reference itself as writable storage.

`lab-pack-refs-reference` implements an original, bounded nonzero-chunk
transport. It reads a regular fixed VHD without writer/delete sharing, checks
the complete source, selected partition and payload pins, and emits only
nonzero 1 MiB chunks. It does not preallocate a sparse raw output. Packets are
limited to 256 MiB, use `.n2rref`, and are excluded from Git. Publication never
overwrites an existing file. Failed runs retain an incomplete `.partial`
that the decoder refuses.

After checking capacity, create a fresh parent directory and run:

```powershell
.\target\release\lab-pack-refs-reference.exe `
  --source .lab\hyperv\corpus\devdrive-20261023T231918797Z\target-fixed.vhd `
  --output .lab\research\NEW-RUN\reference.n2rref `
  --disk-bytes 68719476736 `
  --fixed-vhd-sha256 b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7 `
  --partition-offset 16777216 --partition-bytes 55834574848 `
  --partition-sha256 805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9 `
  --payload-offset 41955328 --payload-bytes 4096 `
  --payload-sha256 6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786
```

The previous sparse-copy observation suggests a small reference packet, but
actual packet size and native backing allocation must be measured. The host
was below the configured 64 GiB free reserve at implementation time. No real
reference packet or new disk was created by the initial codec implementation;
the later experiment below records both.

## Packet contract and restricted native importer

The packet is `N2RREF01`, a bounded JSON header, ordered `N2RRNG01` records
containing disk offsets, lengths, SHA-256 and bytes, then `N2REND01` with a
bounded JSON summary. Framing integers are little-endian. The header holds
the validated 512-byte fixed-VHD footer as hexadecimal; that footer is
provenance and must not be written beyond the virtual disk. The summary holds
the complete virtual-disk hash, fixed-VHD hash, partition/payload hashes and
chunk accounting. The builder reports the enclosing packet SHA-256, which
must be pinned across transfer.

`decode` validates bounds, order, record hashes, footer and complete framing.
It does not manufacture proof that record positions and omitted zeros match
the source. `verify_reconstructed_contents` performs that full virtual scan.
A native importer must instead or additionally verify the full imported disk
hash before any experimental writer metadata is applied.

`lab-import-refs-reference` implements the following restricted sequence:

1. Create a new thin VHDX with a fresh enrolled persistent VHD identity. Check
   actual backing allocation and guest/host reserves. Never select the OS or
   existing converted source disk for this operation.
2. Attach the initially blank RAW disk without a drive letter, bind the
   provider's actual physical path and identity, and establish persistent
   offline state before writing GPT or filesystem bytes. Refuse a populated,
   mounted or ambiguous disk. Zero holes are valid only on the new blank disk.
3. Verify the pinned packet and write only its bounded chunks at disk-relative
   offsets. Flush, read back and prove the complete imported disk hash and
   partition geometry. Keep the disk offline.
4. Validate the strict candidate's pinned `final-metadata.cow`, every old/new
   range hash and the protected payload. Apply only its eight metadata ranges
   at partition-relative offsets; never write the adopted payload. Flush and
   verify the changed ranges and payload again.
5. Mount through Microsoft's driver, read `/adopted-existing.bin`, check its exact hash,
   length and physical mapping, and verify the existing reference files.
   Native refusal is an experiment result, not permission to override
   checksums or allocator evidence.
6. Only after acceptance, test native mutation, dismount/remount and a clean
   reboot. This image experiment does not by itself prove conversion of an
   NTFS-owned extent or production crash safety.

`NativeShadowDisk.cs` demonstrates thin creation and persistent VHD identity
checking. The Rust frozen/journaled partition wrappers demonstrate state and
route checks. Reuse those contracts rather than adding an unrestricted
raw-write command. GPL engine code remains external research.

## Recorded native attempt

The real packet is 68,162,693 bytes, holding 65 nonzero 1 MiB chunks. SHA-256:
`585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b`.
The complete virtual-disk hash is
`ea08681ba795322529e395febea156af8ec97687ed2bf192b6e6d0bc17f5af07`.
The fixed-image, selected-partition and payload pins all matched.

A fresh thin disk was created inside the VM with persistent VHD identity
`a0c231ef-a959-4a6e-8ae2-7d80363eebe6`; initial backing was 4 MiB. The first
import refused before writes because Storage Management reported RAW while
the native layout response was an entirely zero 48-byte MBR-style header. The
corrected guard admits that exact empty shape and still requires a whole-disk
zero scan before writing.

The corrected import passed the whole blank scan, full imported/fixed-image
hashes, eight metadata old/new/readback checks and protected-payload proof.
It durably prepared and handed off the disk. Microsoft then refused the
filesystem with volume-repair failure. The first relevant System event was
Medium Allocator structural inconsistency (`0xC0000518`), followed by checksum,
repair and mount failures. No failing page address was supplied. Independent
Rust inspection still passes the exact overlay's Medium root/leaf checksums,
self-addresses, table IDs, bounds and free-count summary; those narrower checks
do not override the native refusal.

The rejected image was detached and retained; container SHA-256:
`2810d73163c9f41786ddd3df04641e94c9ec0d69f9c4d90197dce01720a104da`.
Ignored evidence: `.lab/hyperv/writer-acceptance/win11-20261025T231634770Z` and
`.lab/research/reference-transport-20261025T225304085Z`.

The clean unmodified reference control remains the next discriminator. The
separate lab `--baseline-only` mode imports the same packet without reading or
applying COW metadata, records zero writer pages and does not expect the adopted
file. All blank-disk, identity, full-image and handoff gates remain required.
Native writer acceptance, mutation and reboot qualification remain open. This
research outcome is separate from the successful native-shadow conversions.

## Separate unmodified-baseline native verifier

`lab/guest/Test-ImportedBaseline.ps1` is the read-only control after a successful
`--baseline-only --handoff` import. It requires five separately pinned import
artifacts (`request.json`, `import.json`, `prepared.json`, `handoff.json` and
`result.json`). The packet, complete imported disk, GPT route, protected raw
payload and persistent VHD identity must match the reference proofs. Baseline
preparation must have zero patches, zero writer bytes/pages, no consumed
overlay inputs and `adopted_file_expected: false`. A fresh VHD identity separate
from the rejected candidate is mandatory.

The baseline profile expects only the two original files under `fixtures`.
It brackets their reads with an exact `FILE_NOT_FOUND` check for
`adopted-existing.bin`; access-denied, path/device errors and a present object
cannot be reported as absence. It retains the original file IDs, lengths,
logical hashes and native extent observations. The 61-byte small reference
file may report zero or the decoded 64-byte inline allocation with EOF
retrieval pointers; no physical data extent is invented for it.

The raw 4 KiB payload hash belongs to the imported image proof **before the
first native mount**. It is not represented as an owned baseline file, and
the verifier does not claim that native mounting preserves free raw bytes.
The existing adopted-file verifier keeps its separate candidate profile and
exact adopted extent expectation.

The host dispatcher is:

```powershell
.\scripts\Dispatch-LabImportedBaselineVerification.ps1 `
  -ImportDirectory .lab\hyperv\writer-acceptance\NEW-BASELINE\imported `
  -GuestImportDirectory C:\ntfs2refs\reference-imports\NEW-BASELINE\artifacts `
  -ExpectedCheckpointId CURRENT_OWNED_CHECKPOINT_GUID
```

It verifies exported/live artifact pins and the exact owned VM branch, refuses
active lab operations, and dispatches one SYSTEM verification task. It never
creates or attaches a disk, changes its state, restores a checkpoint, applies
an overlay or retries a task. The returned handle identifies the task and its
fresh `verification.json` output. A baseline mount failure remains evidence to
collect separately; none of these scripts repair an imported filesystem.

Pure profile, identity, absence-error and import-proof tests cover this new
path. Native unmodified-baseline qualification remains pending.
