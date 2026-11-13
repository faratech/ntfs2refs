# Exact source volume-label preservation

The new `n2r_win32::volume_label` helper keeps labels separate from filesystem
serials, internal ReFS GUIDs and Mount Manager identities. Label data is stored
as at most 32 UTF-16 units without embedded NUL. Empty labels and Unicode are
preserved exactly; there is no trimming, case folding or lossy conversion.

`capture_source_label` reads mounted NTFS through a native volume handle. Both
label observations must agree, and the handle's single extent, disk identity,
GPT layout and writable state are checked before and after. The observation is
opaque and cannot be reconstructed by deserializing a success flag.
After freeze, `source_volume_label::verify` rereads the resident NTFS
`$Volume::$VOLUME_NAME` value and compares its exact UTF-16 units with the
capture. Missing and explicitly empty attributes both mean an empty label.
A changed label is refused before target construction; the frozen proof is
saved separately from the pre-freeze observation.

`restore_after_handoff` is intended to run only after the caller has verified
the durable irreversible handoff and native ReFS tree. It requires the same
original disk route, GPT partition and geometry, checks that the actual ReFS
label is the enrollment label or already the desired source label, and uses
the canonical volume-GUID root rather than a drive letter. A fresh root handle
is checked again immediately before [SetVolumeLabel](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setvolumelabela).
The retained handle is flushed and queried through
[GetVolumeInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew)
for exact readback. The report retains setter, flush and readback outcomes,
including partial failures after handoff. It never issues raw sector writes.

`restore_verified_label` can use separately pinned request data;
it repeats the same actual-device and enrollment-label guards. An already
restored label is completed without another setter call, but still flushed
before success so a prior setter/flush interruption cannot be mistaken for
durable completion. A foreign label or mismatched physical partition is refused
before mutation. This native metadata helper does not itself authorize old
journal replay.

The generic qualification path now persists both source-label observations,
and the computed reconstruction request carries an optional
`expected_source_label`. Its absent/default form preserves legacy request
serialization. Finalization first verifies the enrollment-labeled native ReFS
tree, then restores the source label. Marker-completion recovery can reach the
enrollment/already-desired label check only after the existing exact-image
marker proof passes. A first writable mount or label update can change that
image; in that case the old raw-recovery/exact-image finalizer remains refused.
The same journal can still serve as a read-only handoff receipt in the separate
native-only command; that use neither verifies the current raw image nor grants
replay authority. The label helper's
idempotence does not reopen that recovery or rollback boundary. The separate
native-only completion command below handles that post-mount case.
Later converted-source and postboot verification require the explicit desired
label; independent shadow enrollment remains `n2r-retained-shadow`.

The separate `ntfs2refs complete-label` command implements that native-only
completion path. It requires separately pinned request, ticket and expected-tree
files, the actual external journal file identity, its complete immutable body
and the exact durable HND marker receipt. The receipt grants no replay authority
and makes no current raw-target-image assertion. The pinned request must contain
`expected_source_label`; a legacy absent field is refused by this command.
The source must already be
online/writable ReFS on its original partition; the old shadow is not opened.
The strict expected tree is verified under the current enrollment-or-desired
label before restoration, and again under the desired label after flush/readback.
No raw source writes, journal mutations or disk-attribute changes are issued.
The ordinary writable volume handle used only for metadata durability remains
necessary for `FlushFileBuffers`.

```powershell
ntfs2refs complete-label --request request.json --request-sha256 REQUEST_SHA256 `
  --ticket ticket.json --ticket-sha256 TICKET_SHA256 --journal reconstruction.journal `
  --expectation expectation.json --expectation-sha256 TREE_SHA256 `
  --output C:\ntfs2refs\label-completion-001
```

The implementation has pure label/binding/guard tests, synthetic frozen-NTFS
reconciliation tests and marker-only receipt tests. Workspace compilation and
release builds passed. The native-only command also passed the bounded case
below. A subsequent fresh fourteen-object public conversion also passed label
capture, frozen reconciliation and automatic finalization, as recorded next.

## Fresh automatic restoration during public conversion

Run `c668cc9d52fe43f780e52a581b1d350f` completed the actual public conversion
path with original source-label producer artifacts. No legacy request field
was backfilled. Finalization restored `n2r-retained-source` with setter called,
setter successful, flush successful and exact readback. A separate direct
native verifier then matched the full fourteen-object tree, mount paths and
desired label. Subsequent strict fourteen-object checks passed after a bounded
native mutation workload and clean reboot, with the restored source label and
shadow absent. Automatic-path repetition/idempotence remains separate; the
older native-only completion evidence below does not qualify that repetition.

The converter was built from `f025c8b2a0e48605edac07f67af32968c8b9b33f`, SHA-256
`0a90d93c715e7ac9f2ad3b0560b5a1dadb5b4da9c879d3a5711bef81e0ad160c`.
Ignored evidence is under
`.lab/hyperv/certificate-conversion/win11-20261026T062029798Z`:

- `qualification/source-label.json`: `2a319f01a873bf093e9c1c70c48824bd27ddf2b69aee2ed39a5e496a54219ed1`.
- `qualification/source-label-frozen.json`: `13f0972ff8b3f76fbedb5232055a8dfe154a35c24057ec6d7f5d17706c661214`.
- `finalization.json`: `eb92e005a800d84b234e612de9355c09c51ae5803bc00c2a9db584cf9fc1d8cb`.

The separate native report is
`.lab/hyperv/native-public-postcheck/win11-20261026T074650343Z/verify.json`,
SHA-256 `053f315ef48a229ef65fc855d6e161bf94e134c151f743981929713ca24ec3ca`.
The strict post-mutation/reboot report is
`.lab/hyperv/native-public-postcheck/win11-20261026T081420019Z/verify.json`,
SHA-256 `f5d432558be1dbe5d10c40ca8cffa37cc6a5b83feab1c7a5275f2a867c69c256`.
See [the complete conversion result and limits](general-native-conversion-results.md#public-fourteen-object-conversion-with-a-retained-128-mib-extent).

## Native completion, repetition and reboot

On October 25, 2026, `complete-label` ran against the successful twelve-object
converted partition, including `natural-large.bin`. The old shadow was absent.
The command verified the entire expected native tree, restored
`n2r-retained-source`, flushed and read back that exact label, and verified the
tree again. The first result reported setter called, flush successful, twelve
objects and zero raw source writes. A second invocation succeeded with no
second setter call and a successful flush. Both runs produced the same
journal-only receipt; neither reopened replay or rollback.

After a clean reboot, the strict converted-tree verifier exited 0, matched all
twelve objects and original mount paths, and required the restored label.
The read-only volume-handle mode used by native verification also passed these
runs. The source remained writable ReFS on the original partition.

This test deliberately backfilled the new label field into a separate pinned
copy of the earlier run's legacy request. The desired label was independently
observed before conversion and its 38 UTF-16LE bytes matched the frozen NTFS
`$Volume::$VOLUME_NAME` hash
`809c351552f69ab57e1c7ea7ba143787cf154d9bb06c0b5f4e40ae76c13c843c`.
It qualifies native completion and idempotence, rather than claiming that the
earlier converter binary executed the new capture/finalization integration.

Ignored evidence: `.lab/hyperv/native-label-completion/win11-20261025T215220889Z`.

- First `result.json` SHA-256:
  `fa17f89c5ce7803d999ffe0557cfd7eda906d045b2b6b9199ee9ee8193cddf5f`.
- Repeated `result.json` SHA-256:
  `7e72d4371151b6b0fd3a5a5e108b7f6fb1c6d6c04163d6f4ca9700aadbbf6e04`.
- Shared `handoff-receipt.json` SHA-256:
  `d36da1a926081dba96e94f90cc5d8d3303d4dde2c94295aed270b96deb6ee36c`.
- `postboot.json` SHA-256:
  `26b5e1a4264948bf9900b31d18419bd4e680a33cd4aca5fad685e1e3fe08327c`.
