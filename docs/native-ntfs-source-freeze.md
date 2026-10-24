# Native freeze of an existing ordinary file tree

The next source is now independently populated, frozen and observed through
Windows. It has **not yet been converted**. The general converter remains gated.
Validation passes: 388 Rust workspace tests, five ignored, formatting/clippy,
19 lab guard checks and seven archive rejection cases. Native device refusal,
freeze/restart and read-only challenge are separate VM results recorded below.

## Core behavior

`src/ntfs_freeze.rs` constructs a `FrozenBasis` only from an actual native
`OfflinePartition`. There is no deserializer or constructor from a JSON success
flag. The existing native adapter locks/dismounts the volume and persists disk
attributes 3 (offline and read-only) before raw inspection. The basis then binds
actual device/GPT/partition/geometry, the entire source hash, raw NTFS inventory
and checked backups. A second complete hash must match. `revalidate()` checks
the actual device identity, persistent exclusion and another complete hash.

`lab-ntfs-freeze` records intent before isolation, writes bounded evidence to
the owning machine's separate C: volume, and leaves the source excluded on
success or failure. It has no payload-write or bring-online operation. The
separate `--reopen --verify-source-sha256` mode performs a fresh full read against
a pin, with native exclusion/identity checks before and after; it does not issue
an admission certificate. Existing fixture and reconstruction guards are unchanged.

The helper reuses the journal's bounded hash reader. Request generation for the
native metadata collector now runs in Rust, preserving unsigned 64-bit serials
and every file/sequence identity without PowerShell numeric conversion.

## Existing source and native result

Run `7196645139c2458ba3f2a47177d3bb7f` populated a fresh 52 GiB NTFS partition
inside the owning VM before invoking the freeze tool. Four files contain random
bytes; three directories form a nested tree. No extent queries, file moves,
space shaping, ReFS shadow, or convenient-position fixture was used in population.

| Path | Logical bytes | Natural source LCN |
| --- | ---: | ---: |
| `source0.bin` | 65,536 | 6263 |
| `archive\doc1.bin` | 131,072 | 6280 |
| `archive\nested\doc2.bin` | 65,536 | 6328 |
| `notes\doc3.bin` | 262,144 | 6344 |

All four independently recorded population hashes match the frozen raw stream
hashes. The allocation, namespace and security models reconcile across 35
allocated identities. The native full bitmap also matches all 13,631,487 clusters.

The initial freeze and a clean-restart reopen both produced source hash
`798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.
Their complete inspections are byte-identical, SHA-256
`29d97ef4498f33933ec3702a3e9aee6e81fc4084d60c797ff4d0018208b8ab5e`.
Each invocation read 167,603,122,176 bytes, including three full-partition passes
and metadata. Raw payload writes were zero. A wrong disk-GUID request refused
before source reads/isolation changes; the actual source remained excluded.

Artifacts: `.lab/hyperv/existing-tree/win11-20261024T195711446Z`.
The original collector binary has SHA-256
`814db98b21be1a53e5b1fb87fe10bce1c286dcc8c98f64200a02f19919d57c60`.
Initial/reopen report hashes are
`63f753179685520031916548777043b9d964fc5a1f61e0612366fae48929cbfe`
and `c147c04d8d72a5ac3b4b1fe28fb58f59770aa040b4fb13bfaad7fab8d3c7283b`.

Checkpoint `7c406068-a102-4367-90f0-6f891bfa99a1`, named
`existing-tree-frozen-7196645139c2458ba3f2a47177d3bb7f`, preserves the source
off at 8 GiB. The runner's first immediate post-restore check reported failure;
a fresh authoritative query confirmed installed-clean/off/4 GiB. The original
failure record is preserved beside `completion-review.json`. The runner now
uses bounded fresh state queries after restoration rather than repeating actions.

The read-only archive validator checks bindings, lock/dismount, exclusion,
restart equality, complete file/directory coverage, raw/native-read accounting,
payload hashes and foreign-device refusal. Seven negative archive cases pass,
including omitted/duplicate paths, changed content and lost exclusion. They
mutate small evidence copies only, never source images or original artifacts.

## Native read-only challenge

Observation `0c9ed638af7f4eb48fb18cc4d85d7149` restored the frozen source,
cleared only the offline bit, and confirmed physical read-only state before
native queries. After collection and read-only health queries it restored
offline/read-only state, reopened the actual device and verified the entire
52 GiB hash against the original pin. It then restored installed-clean/off/4 GiB.

All four user streams match logical bytes and physical mappings. The three user
directories match exact names/identities; the root still exposes the known
reserved-NTFS-name projection discrepancy. Kernel/stored and API security views
match all seven non-root user objects and root. The four file metadata comparisons
remain strict failures: only cached access time changes after their data reads.
Creation, write and change times stay stable, and the full stored image stays
identical. This supports a persisted-versus-cached timestamp policy; no mismatch
has been masked or expected timestamp rewritten.

Plain read-only CHKDSK returned 0 and reported no problems. Native queries report
global short-name policy 2, per-volume disabled state 1, and no dirty bit.
Quota query returns 1 with an explicit quotas-not-enabled message. Resource info
returns error 6801 (RM not active); that ambiguous result is **not** accepted as
proof of transaction/log cleanliness. The [volume-flag differential](ntfs-volume-flags.md)
and internal/log replacement rules remain unfinished.

Artifacts: `.lab/hyperv/existing-tree-attestation/win11-20261024T204728959Z`.

| Artifact | SHA-256 |
| --- | --- |
| Native report | `b5d5b2904077857a7b5ff3c280324b9d982f2577ab9d1b6df0615f177f315e86` |
| Comparison | `9ce1725716d98465343bd5f1c644ea5f0cc515032bb5307da36aa3aba6d99ad8` |
| State/health queries | `7236f0f140febbe5130cce021128d977ec66988ea2f18e582f1a8e4f13286455` |
| Full source revalidation | `2af7c2848751f5912031775bb2d1b7921fcd01df179e85c3adc5abfedfbf23f3` |

Next integrate the native frozen basis with explicit timestamp, visibility and
internal-state policies, then construct the new versioned retention/relocation
plan and qualify native interrupted reconstruction. These source results do not
establish target ReFS storage validity, an executable plan, or recovery success.
