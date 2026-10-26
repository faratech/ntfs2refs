# Read-only reference reproducibility verification

`lab-verify-refs-reference` checks the current ordinary fixed-VHD file against
the pinned nonzero-chunk packet without creating a reconstructed disk. It is a
laboratory evidence tool, not a converter, cleanup command or permission grant.

```powershell
.\target\release\lab-verify-refs-reference.exe `
  --packet .lab\research\reference-transport-20261025T225304085Z\reference.n2rref `
  --source .lab\hyperv\corpus\devdrive-20261023T231918797Z\target-fixed.vhd
```

The packet must contain exactly 68,162,693 bytes and match SHA-256
`585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b`.
The current fixed file must contain exactly 68,719,477,248 bytes and match
`b671d327fba46dc371b65a0e20d631525db13af02fa85e9c797412cba58269b7`.
These are compiled pins, not user-supplied success assertions.

Both inputs remain open read-only with Windows write/delete sharing excluded.
Every existing path component must be ordinary; reparse, device, UNC and stream
paths are refused. The separate native reference-file observer obtains the
volume serial, 128-bit file ID, final path, length, attributes, link count and
allocation from each held handle. Its limit is 128 GiB plus 512 bytes. The
journal observer and its 768 MiB limit are unchanged.

The tool freshly hashes the packet, uses the existing transport decoder, then
calls `verify_reconstructed_contents`. That verifier hashes the complete 64 GiB
disk view including omitted zero chunks, verifies partition/payload pins, and
appends the exact stored 512-byte footer to the full-file hash. The tool also
hashes every byte of the current fixed file and compares its footer directly.
Before success, held identities, metadata and modification times must remain
unchanged, and the input paths must still resolve to those held identities.

Only the final small JSON report goes to stdout; bounded phase/progress messages
go to stderr. No reconstructed file, mount, device handle, journal, attribute
change or content write is requested. Failures return a nonzero exit status.
Ordinary conflicting opens are excluded while the handles are held. Pre-existing
writable mappings, kernel/storage actors and a hostile administrator are outside
that guarantee. Success describes the observed objects at this time; it does
not authorize later deletion or establish physical block exclusivity, reclaimable
space, VM ancestry, licensing, filesystem correctness or conversion qualification.

Tests use small ordinary fixtures and synthetic large-file metadata. They cover
content/length/pin failures, malformed packets, I/O failures, reparse/device
refusal, sharing exclusion and the unchanged journal bound. No giant or sparse
test image is generated.
