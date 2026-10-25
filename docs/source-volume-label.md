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
image; in that case the old journal remains refused. The label helper's
idempotence does not reopen that recovery or rollback boundary. A separate
native-only tree/label retry command would be needed after such a post-mount
failure; it is not provided by the old-journal finalizer.
Later converted-source and postboot verification require the explicit desired
label; independent shadow enrollment remains `n2r-retained-shadow`.

The implementation has pure label/binding/guard tests and synthetic frozen-NTFS
reconciliation tests. Native restoration and complete conversion/recovery
qualification with the label field remain pending.
