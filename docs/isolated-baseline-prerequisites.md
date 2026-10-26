# Isolated unmodified-baseline source prerequisites

These case-specific guards prepare review plans for VM
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`, `ntfs2refs-reference-isolated`.
They do not operate a VM, open a device, initialize/format storage, import a packet
or grant native write authority. The old VM and all checkpoints remain forbidden
execution targets. Existing helpers and their global route constants are unchanged.

`lab/IsolatedBaselineGuards.psm1` validates captured structural observations:

- Exact VM GUID, configuration path, 8 GiB fixed RAM, four vCPUs, no NIC and
  preserved vTPM/Secure Boot settings.
- Each OS/target/journal backing's exact path, host volume GUID and host file ID,
  standalone parent state, single-link path and sole current-controller owner.
  A container UUID or guest computer name alone never establishes ownership.
  A live inventory must include every current/checkpoint/ancestor file by host
  volume/file identity; an input `inventory_complete` claim is not a native proof.
- The copied journal at controller 0/location 2, guest disk 2, UniqueId
  `600224806AAC261F021F249596F332FC`, 8 GiB and 512/4096 sectors. RAW state,
  empty partition inventory, nonboot/nonsystem flags and unoccupied J: are required.
  Guest SCSI LUN/location and the actual Windows-disk route must agree.
- Fresh J: GPT, partition and mount-manager identities, refusing the old journal
  GUIDs and imported-reference identities. The volume GUID may equal the GPT
  partition GUID; each is still separately observed. The current review profile
  has one basic-data partition, number 1, at 16 MiB with length `8 GiB - 32 MiB`,
  NTFS/4 KiB, and exactly J: plus its canonical volume path. A different layout,
  including an MSR variant, needs an explicitly reviewed profile before execution.
- A fresh reference creation identity and J: backing path. The post-creation
  review additionally joins provider physical path, disk number >=3, fresh file
  identity, J: volume identity, standalone dynamic VHDX geometry and exactly one
  new guest device. The actual device number may be discovered after creation;
  it is not inferred from the disk count.
- Baseline-only mode with packet SHA-256
  `585df94c07190bcd3476a596ee870d1c3e60d793d03d9d4d3bd545780f23df5b`,
  zero writer pages/bytes/payload writes, no overlay inputs and no adopted file.

`lab/guest/IsolatedJournalZero.cs` scans a caller-provided held read-only seekable
stream. `ScanJournal` requires exactly 8,589,934,592 bytes, checks every byte,
completes legitimate short reads, verifies end/length and records SHA-256. Any
nonzero byte, early EOF, read error, extra data or changed access/length refuses.
Its opaque proof has no public constructor, is tied to that same held stream and
identity token, and grants no write authority. `ScanRange` is a pure-test entry;
its proof cannot pass the production journal gate, even for an 8 GiB range.
The initialization **review plan** requires a complete production-scope proof;
JSON `allZero`/success fields and proofs for another/closed/changed stream fail.

The scanner does not attest native handle origin, exclude external writers,
collect live device identity or open a device. A reviewed live acquisition adapter
must still bind the exact owned native handle, its length and exclusion to the
host/guest observations. No mutating initialization/import runner is supplied by
these predicates. A serialized plan/proof cannot replace that execution boundary.

The source plan uses a fresh `C:\ntfs2refs\isolated-baseline\<run>` staging directory
for bounded helpers, packet and reports, preserving the existing importer's C:-only
input guard. J: holds `J:\ntfs2refs-reference\<experiment>\reference.vhdx`.
This is an explicit proposed adjustment from J:-only staging, not permission to
write C: now. Such ordinary guest file staging must be named in execution review.
The old dispatcher remains unsuitable: it selects the protected win11 lane and
uses execution-policy bypass. No fallback endpoint, Library transfer retry,
permission or execution-policy change is added here.

Future reference import must retain the existing whole-64-GiB zero check, exact
full disk/disk-plus-footer/payload hashes, GPT layout, flush/prepared/handoff proofs
and native two-file/absence checks. RAW alone proves neither journal nor reference
blankness. A successful baseline control would not qualify the independent writer.

Pure checks use synthetic observations and lazy generated zero streams with one
1 MiB buffer, including an 8 GiB virtual read. They create no giant image and call
no VM/device/credential/native mutation API. Original evidence is retained.

The next proposed operation for separate review is **fresh owned identity acquisition
and a read-only complete journal scan only**, with all other disks excluded. No
initialization, formatting, reference creation, packet import or native mount is
authorized by this source checkpoint. Stop on mismatch, nonzero/incomplete data,
uncertain ownership/worker state, failed exclusion, occupied J: or resource failure.

Budget admission must be rechecked from actual free space. Conservatively charge
8 GiB plus 128 MiB for journal-parent growth and another 16 GiB allowance, retaining
64 GiB free: at least **88.125 GiB** initially. The child reference's 64 GiB is a
virtual size; its enforced <=6 GiB backing lives within the 8 GiB journal, so do not
add it again as independent host allocation. This allowance is not a hard cap;
monitor actual host/J: capacity and stop before a reserve breach.

The bitmap patch is `216e9af`; local checks passed. Windows CI run
[40351404204](https://github.com/faratech/ntfs2refs/actions/runs/40351404204)
failed before runner assignment with zero steps. Its exact
[check-run annotation](https://api.github.com/repos/faratech/ntfs2refs/check-runs/121672129718/annotations)
states that the job did not start because recent account payments failed or the
spending limit needs increasing; this does not identify a code/test failure.
No CI rerun, billing or runner-policy change was performed. Chronology/ACL evidence
correction `9684ae5` remains committed with original records untouched.
