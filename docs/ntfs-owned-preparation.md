# NTFS-owned collision preparation

The experimental `--minimize-scratch` path now prepares NTFS placement after
creating the native ReFS shadow and before source freeze. This implementation
passed the scoped native move experiment below; post-preparation conversion and
recovery qualification are pending. The ordinary
alpha path remains available without this option.

The empty shadow's actual legacy and metadata-inclusive allocation bitmaps form
a conservative planning hint. The hint includes first/last-MiB avoidance and
does not assume a fixed percentage of filesystem metadata. Later ReFS metadata
growth can still cause collisions; final native placement and journal fallback
remain mandatory.

The source inspector has a preparation-only entry that reads metadata, not
nonresident DATA for logical hashing. Content hashes remain unavailable and an
explicit blocker prevents using that inventory as conversion admission. Source
ownership must still reconcile with the NTFS bitmap and complete record model.

The planner selects initialized whole clusters of plain unnamed user DATA. It
accounts for every skipped or unplanned collision: system, resident, named,
sparse, compressed, encrypted, readonly and other unsupported streams are not
silently dropped. Destinations were originally NTFS-free and lie outside the
observed target occupancy and bootstrap avoidance. Proposed moves cannot reuse
another move's vacated source space. Required outside headroom is reported.

Native owners independently open the volume and file by identity and validate
the actual basic GPT route, NTFS serial/geometry, current Windows-disk exclusion,
file ID/sequence, attributes, EOF, full retrieval mapping and live destination
bitmap window. File handles exclude writers/deletion and obtain an immediate
exclusive byte-range lock. Scoped volume-management privilege is restored.

`FSCTL_MOVE_FILE` is the only mutating primitive. NTFS owns allocation changes
and journaling; no raw volume writer edits NTFS data or metadata. Each successful
request is flushed and its actual file identity, information and complete map
are observed again. Native errors also retain independently observed post-state.
Unverified outcomes poison the native owner and stop preparation, with no
automatic retry or undo. Ordinary access/sharing refusals can leave a file on
the existing conversion/journal path.

Receipts are streamed to a bounded JSONL ledger rather than retained for all
moves in memory. Moves and bytes are explicitly budgeted; the initial drive
path uses 64-MiB move slices, 32,768 submissions and 64-MiB metadata/receipt
budgets. The payload ceiling comes from the selected partition. Existing full
retrieval and inventory limits still apply; this is not broad-scale qualification.
The subsequent compiled receipt fix reserves a reusable 32-MiB record buffer and
ledger headroom before any move. It serializes each complete JSONL record before
appending, preventing budget exhaustion from truncating a successfully moved
file's receipt. Exhausted headroom stops best-effort preparation before another
submission. This fix was not in the native runtime described below.

After preparation, the converter discards planning inventory and obtains a new
frozen raw/native inventory, fingerprint and opaque certificate. Raw rollback
therefore restores post-preparation NTFS. Cancellation does not promise the
original physical layout: NTFS-managed relocation remains a valid NTFS layout.

Moving M bytes requires approximately M reads plus M writes through NTFS, plus
metadata and later conversion work. A source needs free capacity outside the
target zone; a full volume may not have sufficient headroom. Kernel/System I/O
must not be omitted from physical traffic estimates merely because process
counters do not charge it to the converter.

Use `lab-prepare-ntfs` only in the owning disposable Windows lab with an explicit
pinned request, fresh output and preparation acknowledgement. It invokes no
formatter, raw cutover, source certificate or journal replay. Native success,
unchanged logical contents and the subsequent conversion/recovery still need
end-to-end evidence before release.

The first owning-Windows run of82e805b moved5,643,501,568 bytes in385 verified
requests over222 identities, with no sharing/access skips. Each request passed
identity, EOF, complete-map destination and outside-VCN preservation checks.
Observed native duration was18.5202009 seconds, without a controlled physical-I/O
benchmark. All811 independently read logical stream hashes matched the existing
full baseline. A subsequent frozen capture independently matched all811 raw and
native stream reads and reconciled the1084-object namespace/security model.
The prepared NTFS source/empty-shadow state is saved ascb802669. Wrapper path,
UTF8 and PS5 array-decoding failures are retained; their completion helpers only
read files and never repeated a move. See the
[exact evidence and artifact pins](../evidence/ntfs-owned-preparation-native-20261101.json).

The versioned `Start-PreparedSourcePerformanceExperiment.ps1` uses that prepared
checkpoint, its newly captured full baseline and the same owned empty shadow.
The source-free controller and prior evidence remain unchanged. A zero COPY set
is accepted as zero actual reuse; nonzero sets retain exact reuse/fallback
accounting. This is a lab-scenario change, not a reduced product check.
