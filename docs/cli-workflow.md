# Owning-machine conversion and recovery CLI

`ntfs2refs convert --request` runs the certificate-backed workflow on the
machine owning the disks. It has no Hyper-V dependency. Run it in an elevated
Windows process with the required volume/backup/security privileges.

```powershell
$pin = (Get-FileHash -LiteralPath .\devices.json -Algorithm SHA256).Hash.ToLowerInvariant()
ntfs2refs convert --request .\devices.json --request-sha256 $pin --output C:\ntfs2refs\runs\run-001
```

The output directory must be fresh, on the Windows OS volume, with ordinary
directory ancestry; missing parents are created and checked before use. The request is a bounded ordinary JSON file, at most
16 KiB, matching `general_conversion::Request`. Its fields are:

- `schema_version`: `1`.
- `experiment_id`: a fresh 32-character lowercase hexadecimal identifier.
- `pair`: actual source and shadow `GeneralDiskBinding` values, including disk
  number, volume GUID, GPT identities, partition bounds and sector geometry.
- `journal`: an independent `GeneralJournalStorageBinding`.
- `max_journal_bytes`: a positive journal ceiling within the current limit.
- `verify_existing_shadow`: normally `false`; `true` requires an existing
  shadow to match the newly frozen source through the complete native verifier.

Source and shadow partitions must have matching geometry on different data
disks. The shadow must already be a separately prepared ReFS volume with label
`n2r-retained-shadow`. Normal construction requires an empty shadow namespace
apart from the explicitly supported Windows system-cache entries. The journal
must be independent of both data disks. Native identities are checked against
the actual devices; a caller-provided success flag cannot qualify a source.

The current profile is deliberately bounded: NTFS 3.1 with 512-byte logical
sectors, 4 KiB clusters and 1 KiB records; ReFS 3.14 with 4 KiB clusters; up to
128 ordinary files, 32 directories and 256 MiB of logical contents. Source
policy qualification currently targets Windows build 26300. Unsupported
semantics and unknown layouts are refused. Boot/system volumes remain excluded.

The workflow captures a live source freeze, checks the semantic source model,
constructs or verifies the native ReFS shadow, freezes it, and creates the
source certificate. It then saves the external journal and trusted ticket,
applies the admitted patch set, records the handoff barrier and verifies the
mounted ReFS tree. The source remains persistently excluded while raw writes
are in progress. A failed run leaves phase diagnostics and any completed
recovery inputs under the output directory.

An image `plan` report remains non-executable. `convert --plan plan.json`
retains its refusal behavior; it cannot be used to bypass live qualification.

For recovery, use the run's generated `request.json`, `ticket.json` and the
journal location from `journal-location.json`. Each input is pinned separately:

```powershell
$requestPin = (Get-FileHash -LiteralPath C:\ntfs2refs\runs\run-001\request.json).Hash.ToLowerInvariant()
$ticketPin = (Get-FileHash -LiteralPath C:\ntfs2refs\runs\run-001\ticket.json).Hash.ToLowerInvariant()
ntfs2refs resume --journal J:\ntfs2refs-shadow\EXPERIMENT\reconstruction.journal `
  --request C:\ntfs2refs\runs\run-001\request.json --request-sha256 $requestPin `
  --ticket C:\ntfs2refs\runs\run-001\ticket.json --ticket-sha256 $ticketPin `
  --output C:\ntfs2refs\runs\resume-001
```

`rollback` uses the same pinned envelope and restores the exact admitted NTFS
preimage before completing its rollback marker. `finalize` additionally
requires `--expectation` and `--expectation-sha256`, matching the request's
expected-tree hash. `rollback --after-marker` and `finalize --after-marker`
complete an already durable marker after process death only while their existing
exact-image proof still passes. A writable ReFS mount or label update can change
the image; the old raw-recovery/finalization path must then refuse it.
Recovery never starts
a fresh apply, silently clears a foreign device's exclusion, or crosses the
closed rollback boundary. A shadow-backed recovery needs the bound shadow
available in its required protected state.

`rollback --without-shadow` explicitly selects journal-old-byte recovery when
the enrolled shadow is unavailable. It still requires the exact pinned request,
ticket, actual journal identity, expected target state and permitted pre-handoff
lifecycle. It grants no forward resume or finalization authority. This public
command passed a bounded native first-flushed-write interruption with the shadow
detached, exact NTFS preimage proof before writable mounting and original NTFS
availability afterward. A later clean-boot check matched four known user-file
hashes and the original mount/label/partition identity; it did not reverify all
twelve objects' security/timestamps or post-mount whole-image equality.
See [the result and limits](general-native-conversion-results.md#public-shadowless-rollback-after-one-flushed-write).

For a label-only failure after handoff and the first writable ReFS mount, use
the separate native-only command. Its pinned request must contain
`expected_source_label`:

```powershell
ntfs2refs complete-label --request request.json --request-sha256 REQUEST_SHA256 `
  --ticket ticket.json --ticket-sha256 TICKET_SHA256 --journal reconstruction.journal `
  --expectation expectation.json --expectation-sha256 TREE_SHA256 `
  --output C:\ntfs2refs\runs\label-completion-001
```

This command reads the journal exclusively and read-only to validate its native
file identity, full immutable contents, comparison binding and exact HND marker.
That receipt does not assert a current raw target hash or authorize replay.
The source must already be online/writable ReFS on the original bound hardware
partition, with the enrollment or desired label. The full strict native tree is
verified before and after guarded label restoration, flush and readback. It
does not open the old shadow, issue raw source writes, change disk attributes
or rewrite journal markers. Partial failures are saved in the fresh output
directory. An already-desired label is flushed and verified without a second
setter call. See [the label contract](source-volume-label.md).

`capabilities` reports command availability. It does not claim a production
qualification matrix or a standalone raw ReFS formatter/writer.
