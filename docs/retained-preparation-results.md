# Guest-local preparation measurements

These runs prepare a single retained-extent experiment. None performs a raw
filesystem reconstruction or establishes a successful conversion. All formatting,
fixture creation and shadow attachment runs inside the owned Windows 11 guest.
Hyper-V supplies checkpoints and evidence transport only.

## Completed native probe

Fresh probe `retained-native-probe/win11-20261024T045526178Z` completed both
native phases and host cleanup successfully at2026-10-24T05:05Z. The host result
SHA-256 is `f79b8996db0e617da19a2a0b52d854ccc6f82da61f567724cda69f9cce4ab9f8`.
The original target stayed offline across restart; the new shadow attachment
proved provider write protection, explicit exclusion and unchanged backing
bytes. Both retained64KiB hashes matched. The second native report SHA-256 is
`80d4ba8e91f93167baa16bcb0fa5e6acb63dd82ee4af3a4d43e9b022048ffb96`.

| Complete52GiB partition | SHA-256 |
|---|---|
| NTFS target | `ced3bf73419c7e05a070e36ee023b24c90201bfd60674d38b8ded653735c923b` |
| Native ReFS shadow | `728d4f1a8bcd3000c271af01830fa37fe6d01e8aee336b19d189f02c87cb7a30` |

Isolated checkpoint `50373d99-873c-4993-8755-51578ead4657` and quiescent
checkpoint `28b3fc07-33e0-4833-b5db-9897fb552178` are saved. The latter is named
`retained-quiescent-1558987e5aaf414980d10bc8b7c009b1`. The final host record has
known completion, no preserved session, baseline restored and memory restored;
the VM was independently observed off4GiB at installed-clean.
The request generator initially refused a BOM in the pinned shadow-platform
JSON. The reviewed input-decoding correction now accepts one leading UTF-8 BOM
after authenticating the original bytes; 540 focused checks passed in both
PowerShell 5 and 7. The archived bytes and pins are unchanged. The generated
request SHA-256 is `2e5c967abee35bb8fbdb3f8ac856cab614ad00c205569ec77ad36c647fd97026`;
its pin SHA-256 is `d84023d404f8a11eda22e51a9011cd8401cfe1779ca18fbca070aff6f9945cdb`.
No reconstruction ran.

## Complete native read evidence; host cleanup check failed

Probe case `retained-native-probe/win11-20261024T043618703Z` passed inspection,
first native isolation, clean restart, provider-read-only shadow reattachment,
explicit exclusion and the second native read. The shadow's attributes were0
before explicit exclusion and3 afterward; provider protection, unchanged full
backing bytes and the original target's offline state all passed. Both retained
64KiB hashes remained unchanged. The second native report has SHA-256
`57b8628307230002f03ef5a7a1dddf9a0c57b42f48edd162b3a85295608bf010`.

| Complete52GiB partition | SHA-256 |
|---|---|
| NTFS target | `23f4e387a1c1540dc40fe754091cb9c0925a426958aed56b492dbbcbf4680c6f` |
| Native ReFS shadow | `e29fa20f48c2e09fa1e7091eb546361af921da022a87538fd750c2c60b763a6b` |

The scan took about seven minutes. Quiescent checkpoint
`f89b4ab1-be82-4291-9e2f-8400385ee102` was saved before the host's immediate
baseline-restoration check failed. The host result remains failed-preserved,
SHA-256 `49610a9e4ba7381a6fbef436234ef44844ecb03ffd0d908b10fb22498df76136`.
Later observation found the VM correctly off4GiB at installed-clean, recorded
separately in `baseline-observation.json`. This does not rewrite the failed
host result or authorize reconstruction from it. A bounded completion wait
and fresh complete host run are pending. No target payload write occurred.

## Preparation history

| Case under `.lab/hyperv/retained-preparation/` | Observed result |
|---|---|
| `win11-20261024T022110550Z` | NTFS source/journal prepared and shadow attached. GPT initialization exposed an incorrect identity assumption. Stopped before shadow formatting. |
| `win11-20261024T023117338Z` | Persistent identity stayed bound through successful ReFS3.14 formatting. Stopped because our parser rejected the native trusted-developer-volume wording. |
| `win11-20261024T023655082Z` | Both platforms completed. Initialized64KiB files passed logical hash, metadata and applicable validity checks. Bitmap parsing stopped before any move request. |
| `win11-20261024T024733077Z` | Both native moves succeeded at LCN2097152. A logical NTFS read updated file last-access time, and strict metadata validation stopped construction. |
| `win11-20261024T025713906Z` | Preparation passed after per-handle file access-time suppression. Both initialized files have matching supported metadata and a single extent at partition offset8589934592. Saved checkpoint46b1791d-9852-40f0-ab03-68bcb7d98c58; baseline restored off4GiB. |
| `win11-20261024T031656056Z` | Controlled directory enumeration stopped before fixture creation: first NTFS root query returned Win32 error2. Later diagnosis did not reproduce2; both roots then contained SVI. Failure checkpoint75a43928-64e5-408b-9182-5a3683d4ecd0 preserved; baseline restored off4GiB. |
| `win11-20261024T034206826Z` | Preparation passed. Both initially empty roots returned class11/error2 then class10/error18; complete creation, placement and strict metadata/content checks subsequently passed. Prepared checkpoint730afa0a-4df7-4a18-830c-1f0381013c62 saved; baseline restored off4GiB. |

Each failure returned known native completion and successful cleanup. Original
host/guest evidence remains unchanged. A separate `failure-preservation.json`
records the later reviewed clean shutdown, off-state checkpoint and baseline
restoration when completed.

The latest successful run is `94f6256f57424ad69147f58199387ee1`, with host-result
SHA-256 `464bb9e4fccb6f2e014e3104801d546dbbbb48fc944454ccb060dcc3f9e22f13`.
Its retained range is partition offset8589934592, length65536; A hashes to
`a8da4df80396fc29486e0cba10fb7525404e8fd56169e6885475789b10f31bb3` and B to
`d66b3369b58ea23563d72c1593b173fcb14dbd9899a14ef6a2c3d40c5518b584`.
The new initial2-to18 observations are separate fresh native evidence; they do
not retrospectively prove the previous failed run's root was empty. The earlier
standalone diagnostic still did not reproduce2. Preparation alone remains
distinct from raw mapping proof, reconstruction and a native ReFS mount.

Its subsequent native-probe case `win11-20261024T034413955Z` passed restart
inspection, including file and directory timestamps. The Rust isolation report
then observed offline target/shadow attributes1/3, successful target flush and
matching raw64KiB A/B hashes. That report independently passed its archived pure
validator (SHA-256 `0fdb9aba66b450c43db5762bae17cf52dd5cbc4102c0c9c8711576f0c20fd112`).
The launcher returned known process completion but a null exit code, so the
overall host result remains failed; no second restart or whole-partition hashes
were performed. Failure checkpoint `0a60b7b0-3833-4325-bda4-ea40eee509e5` preserves
the isolated disks and original evidence; the clean baseline was restored.

Retry `win11-20261024T035910091Z` used the corrected managed process launchers.
Inspection and first isolation passed with exit0; the isolated checkpoint is
`506ce18b-0b46-4e3e-8106-4b1f363f3105`. After restart, the original target retained
offline/read-write state. The existing shadow helper opened its backing file
read/write and attached with flags6 (no drive letter plus permanent lifetime);
the fresh shadow device appeared online/read-write, and the Excluded guard
refused. No second raw read, full-partition hashes or attribute repair followed.
Read-only state observation SHA-256 is
`5bf8ef5895751417f4cb548c2030f1ce39612feaac6050386bdd2df8bc134c11`.
Failure checkpoint `6fa64f95-a03c-4bdd-b89b-e465f0aef5f1` preserves this branch,
with the baseline restored. The whole run remains failed (host-result SHA-256
`ad316d8665a3665d64623aa977a2e16ad133de2577a4e65c84dc9171e3502c3c`).

The separate read-only attachment diagnostic then passed from the clean isolated
checkpoint. Case `shadow-readonly-attachment/win11-20261024T041957683Z-df922bc4b13e46339c8c938a4f5a7742`
used V2 ReadOnly true and attach flags7. Provider writability returned error19
while GET_DISK_ATTRIBUTES initially reported0. One explicit SET for attributes3,
mask3/Persist1 succeeded; final attributes were3 and writability remained error19.
The148897792-byte VHDX hash stayed
`d7e7cb09c9b977ff0bc142a9ed069f5bd8c5bf88bd925db20982479561ba035d`.
The original target remained offline/read-write; completion and cleanup were known.
Guest evidence SHA-256 is `28d41711e761553a39938479f82b265470ca988d63b4a077d6ba0aee848913c0`,
host evidence `3e9b18e8179cdb9247d0679598885f821872daa3da2e039969e07b9fff84768a`.
Outcome checkpoint `f7de106a-6e94-4b2f-aef7-13c5b02d5df9` was saved and the baseline
restored. This establishes an explicit protected reattachment sequence, not
inheritance of attributes or a successful reconstruction.

The successful preparation's host-result SHA-256 is
`adc49925b37af5dd195df558b110616a9653ad657e370b4d8ba1c47cf5c333ec`.
This is not raw physical mapping or conversion proof. Subsequent probe case
`.lab/hyperv/retained-native-probe/win11-20261024T030135884Z` restored the prepared
checkpoint and reattached the exact guest-local shadow. Inspection confirmed both
file hashes, file times and mappings after restart, but stopped because the NTFS
directory last-access time changed to134372845503312033 while ReFS retained the
fixed time. The wrapper's uncontrolled directory enumeration is being replaced
with observation through owned native handles. No native isolation or raw probe
phase ran in that case.

The directory-query failure's host-result SHA-256 is
`ebc980adb024818d623773e077d7f698eb5b570d0e2e9d5e10a0381d34972dae`.
Its native completion, cleanup and privilege restoration are known. The failed
query occurred at03:17:55UTC. A later independent read at03:20:37UTC found only
`System Volume Information` in F:\; this does not prove what existed at the
earlier instant. The later observation is separately recorded in
`empty-root-diagnosis.json`, SHA-256
`9f3407b9d0cb6fc11d0bfdc463786a3f3ecc97694c6ac17293e0a845dc996530`.
It performs no payload write, but ordinary directory reads can cause access-time
bookkeeping. A bounded same-build native diagnostic is pending; the fixture
guard has not yet accepted this error as successful enumeration.

The first case's read-only follow-up used OpenVirtualDisk v2 GetInfoOnly/ReadOnly.
Query14 returned the original creation ID
`0dcb07bc-a937-4fd4-8d31-7dc7c1c5d3d5`. Query2 returned
`ad9ad71c-d01a-45ea-8d54-b0ea4dcd61c4`, matching DataWriteGuid in both CRC32C-valid
VHDX headers (sequences8/9). GPT disk GUID was a distinct value. Observation SHA:
`18818a9d7fd703af2190a124937a5139f2ba5a3d4fddf2e388e344492d466ea3`.
The corrected helper pins query14 throughout and records query2 as generation
evidence, without re-enrolling identity. Sources: Microsoft's
[VirtualDiskId member](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-get_virtual_disk_info)
and [VHDX header rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/39d641c2-093c-4d4a-8c9d-bd4b9fc2ff31).
The API-to-header correspondence was measured on this build.

The second case's three fsutil queries exited0. Dev Drive output began
`This is a trusted developer volume.`; ReFS info reported version3.14,
512/4096-byte sectors,4096-byte clusters and data checksum NONE. The corrected
text parser accepts this measured affirmative response and refuses contradictions.

The third shadow used104,857,600 physical bytes after formatting, leaving
8,417,464,320 journal bytes. Both payloads were written completely, flushed and
closed before logical readback. Their initial timestamps, security, one-link,
one-stream and allocation checks passed. ReFS cached/storage validity and
integrity NONE passed. NTFS independent storage validity remains unknown pending
raw proof. No move was dispatched.

NTFS returned1,703,952 bitmap bytes for13,631,487 declared clusters. Both ReFS
views returned2,097,152 bytes for13,631,488 declared clusters:1,703,952 meaningful
bytes plus393,200 trailing bytes. The exact-length assumption rejected those
responses. Reads must stay inside complete declared coverage; trailing bytes
cannot establish extra allocatable clusters. Microsoft defines coverage using
[BitmapSize](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-volume_bitmap_buffer).

The host now tracks guest-operation uncertainty independently of transport
completion. Successful evidence export cannot clear an unfinished native
operation or permit session teardown.
