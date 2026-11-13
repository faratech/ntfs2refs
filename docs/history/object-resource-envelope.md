# Bounded object resource envelope

`ExperimentalObjectEnvelopeV3` removes the arbitrary split of 1,024 files and
256 directories for **fresh, fast allocation-bounded conversion only**. It keeps
the existing combined ceiling of 1,280 objects. For example, 1,100 files and
100 directories can fit that envelope; it does not admit an unbounded tree.
Alpha, large-tree V1 and streaming V2 retain their original serialization and
limits. Full-image, compact/non-allocation and cache-reuse conversion entrypoints
reject V3.

The public fast allocation path initially carries a planning profile without an
admission. After source isolation, complete MFT coverage, unique record order,
allocation, namespace and security reconciliation supply exact raw identity,
file, directory and DATA-stream counts. A versioned descriptor binds those facts
to the actual canonical inspection SHA-256. Internal records count toward raw
identities but not the semantic file/directory allocation. A serialized descriptor
does not supply source admission or write authority.

The raw identity count and inspection pin are equality-checked against the
native source request. File, directory and stream counts are equality-checked
against the complete semantic expectation, native observation input and owned
constructor input. The constructor conservatively projects owning handles as
`objects + 2 * DATA streams + 8`: metadata/system anchors cost at most one per
object, and each stream can own a native target plus a carrier. Fixed overhead
covers volume/root/carrier/temporary opens. Checked arithmetic and the unchanged
worst-case envelope of 34,056 slots bound this projection. It is not a claim
that one object consumes exactly one operating-system handle or a kernel-RAM
measurement.

Metadata has separate enforced byte budgets. Raw inspection retains its existing
64 MiB heap bound; its pretty-serialized raw metadata is also counted before
issuing the descriptor. The native report uses the admitted serialized ceiling,
capped at the existing 64 MiB. Expected-tree and constructor-input metadata are
counted with bounded streaming writers before construction, each capped at
16 MiB. Constructor metadata excludes supplied payload; existing payload and
exception budgets remain separate. Caller-supplied lower admitted ceilings are
honored, rather than replaced with larger defaults.

After qualification, the allocation orchestrator pins the **admitted** profile
in the request used by the recovery bundle. Planning-only V3 cannot enter native
attestation, construction or recovery. Recovery validates the pinned descriptor,
the exact expected-tree counts and its original byte ceiling, then passes the
same resource profile to the pinned payload-map parser and mounted observation.
It does not upgrade historical profiles or reconstruct an initial missing
content digest. Existing live certificates, selected-journal lifecycle and
checksum checks remain mandatory.

Unchanged ceilings include 2,048 raw identities, 16,384 DATA streams, namespace
and path rules, per-file stream/extent bounds, allocation ownership, placement
routes/transcripts and all current recovery readers. This change does not add
paged manifests, handle batching, arbitrary file counts or larger-volume
qualification. One sealed `f32c0f6` normal F: case now passed above the former
directory split: 1,084 objects, 273 directories and all 811 independent stream
hashes. Sealed `07b0164` subsequently passed controlled first-flushed-write
interruption, clean restart, public Resume and separate Rollback for the same
1,084-object/273-directory source. Resume preserved 654 missing digests and
checked pinned complete maps plus 157 known hashes / 119,009 payload bytes;
both lab observers independently matched all 811 hashes. More than 1,024 files,
arbitrary faults, physical power loss and broader scale remain unqualified.
[Recovery matrix](envelope-recovery-matrix.md).
No unit tests were added or run. [Native scope](object-envelope-native.md).

The V3 lab observer now explicitly validates the admitted descriptor and exact
raw/native/canonical counts against a fresh full-source baseline. Its full and
fast raw pins remain distinct; profile, root modified times and newly created
directories are preserved in exact comparisons. The old V2 observer branch is
unchanged. This is a lab observation contract, not source/write authority.
Sealed older cases remain attributed to their original runtime/profile.
