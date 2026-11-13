# Native placement before valid-data advancement

## Planned second-stage repositioning

Sourcee778f7c adds `PrivateTree::reposition` and a distinct unwritten
constructor operation. It is not a retry after a failed move. It requires a
fully tracked logical range, rechecks every old native mapping, checks both
fresh destination bitmap views, and computes bounded left/right fragments
before IO. Both move submissions and resulting fragments are bounded at1,024.
All resulting native placements must match after the move, including untouched
fragments. Errors/partial or missing observations poison the file. Any VDL
advancement or materialized bytes prohibit further placement. The ordinary
single-placement checks remain. No source write authority is introduced.

Native experiment`6f48efa1de114dcbb1072f989bb86501` passed with producer
`549931b53bba0102dc23b534248f5c3be02a605a22b1ed94ef0149d458dc665d`.
The private1-MiB zero-VDL prefix first moved toLCN10,485,760 (40 GiB).
VCNs64..127 then moved toLCN11,010,048 (42 GiB). Final mapping after VDL
advancement/flush was VCN0..63 at10,485,760, VCN64..127 at11,010,048,
and VCN128..255 at10,485,888. Thus both unchanged outer fragments retained
their exact offset-adjusted physical addresses. Both calls and all-placement
checks succeeded. Tool payload reads/writes were zero; physical IO remains
unmeasured. This does not adopt NTFS data or validate prefix contents.

Result SHA-256:
`3bcc51898f70433582dd07332adf294f8d00f522c4d36eb97a3db8e343b932ee`.
Evidence:`.lab/hyperv/streaming-v2-20261027/unwritten-reposition-20261028`.
The controller's immediate post-restore inventory guard refused before boot;
the fresh-process reconciliation confirmed all25 prior snapshots and the
correct OFF baseline, then continued the same unstarted intent exactly once.
OFF checkpoint`4de54cba-235b-4d49-9b90-4508b9fcd44c`, parent
`6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`, preserves the outcome. All26 snapshots
remain, RAM released. No unit tests added/run. Tree-wide scratch planning,
source-coordinate retention, payload supply and cutover remain to integrate.

## Reusable constructor and two-run native result

Source4a58ed2 replaces the probe's duplicated creation/move code with
`shadow_native/unwritten.rs::PrivatePlaceholder`. It reserves an aligned
file, keeps it SYSTEM-only with sharing disabled, supports bounded multiple
placements, and exposes no payload interface outside the native shadow module.
The caller must already bind the independent shadow and enable the required
privilege. This internal constructor does not independently bind an arbitrary
volume or authorize conversion of the source.

Logical and physical overlaps, out-of-volume ranges and more than1,024 moves
are refused. A submitted move starts in a poisoned state: only a successful
native result and complete matching retrieval evidence clear it. A partial or
unobserved move prohibits further moves and VDL advancement. Construction can
require complete placed-prefix coverage before a single valid-data call;
flush and a fresh verification of every placed mapping are part of that
operation. The older allocation-only probe explicitly retains its separate
unplaced-prefix policy. Failure leaves the private file for diagnosis.

The new implementation passed native experiment
`354242846218460bb0f6ebc065d5b518`, executable SHA-256
`e9c7d1a9fe0dd714ba3079ee74721708d6ec5bd3d15451c29088708bbda2ee47`.
VCNs0..127 moved toLCN10,485,760 (40 GiB); VCNs128..255 moved toLCN11,010,048
(42 GiB). Both fresh bitmap views admitted each destination, both native calls
succeeded and the complete post-VDL/flush mapping retained both locations.
The1-MiB prefix became storage-valid, with its4-KiB tail still invalid. Tool
payload reads/writes remained zero; physical I/O and scratch cost were not
measured. This is the new reusable constructor's exact native scope.

The95,217-byte result SHA-256 is
`45bd03b3ad2504fb59b29f7c96b2f2540a326ee887d88aa80ed4b2b1d23b5d68`,
archived with decoded mapping/validity evidence under
`.lab/hyperv/streaming-v2-20261027/unwritten-placement-split-20261028`.
Clean OFF checkpoint`524c530e-2f6e-4ff6-849d-3bf7a9af71bf`, parent
`80907930-4a43-4cbc-b26b-dafd14dea4e8`, preserves it. All17 earlier checkpoints
remain (18 total); VM assigned RAM is0. No storage cap was increased.

This is not yet an admitted-tree constructor, native compact conversion,
reboot-readback qualification or a physical-space bound. Initial full-shadow
conversion still uses its working payload writer. No unit tests added/run.

The owning-guest experiment on2026-10-28 accepted a1 MiB extent placement
while its new private file was still storage-invalid. Windows then accepted
`SetFileValidData`, and the requested physical mapping survived the explicit
file flush. This supplies a native primitive for constructing shadow mappings
without an application-level duplicate payload write. It does not yet make
the converter's initial shadow construction payload-free.

Producer source119eb32, Rust executable SHA-256
`f505043f24455c0c13c7c50975a92d3631b72fc7f491a90f178b2d56281af598`,
experiment`fb2e6b960b224a58a7a588b591f57e52`. The unchanged pre-existing
capabilities patch remained outside the commit. The controller's original
checkpoint comparison refused after restore but before boot or dispatch.
All16 checkpoint IDs were independently reconciled; `-ContinueRestored`
requires the exact still-unstarted intent, producer pin, OFF parent and full
checkpoint inventory. It does not restore or dispatch an existing task again.

Evidence lives under
`.lab/hyperv/streaming-v2-20261027/unwritten-placement-20261028`.
The original83,885-byte result SHA-256 is
`4a8198cee059e28aeead8313b7cf36208ec9c17f5b21ba395bd2a81545c4691f`.
The SYSTEM task exited0; the probe result, rather than exit status alone,
establishes the successful native move and valid-data call.

## Observed sequence

1. Bind the enrolled independent ReFS shadow and excluded NTFS source. Verify
   the pinned Microsoft ReFS driver. The source stays offline/read-only.
2. Create a fresh SYSTEM-only file with sharing disabled, disable integrity
   on that file, reserve1,052,672 bytes and set EOF to that length. Both
   queried storage regions are invalid; no payload is read or written.
3. Capture both current allocation bitmap views. Require the entire requested
   destination to be free in both, including the metadata-inclusive view.
4. Submit `FSCTL_MOVE_FILE` once for VCN0..255 to LCN8,388,608, physical byte
   offset34,359,738,368. Require a successful native result and a fresh complete
   retrieval map proving that location before any valid-data advancement.
5. Advance VDL to1,048,576, leaving a4,096-byte invalid tail. Flush the file.
   The fresh retrieval map still places the prefix at the requested address.
   Storage-region queries mark0..4,096 and4,096..1,048,576 as usage2 (valid on
   storage), while1,048,576..1,052,672 remains usage0.

The result records zero tool payload reads and zero tool payload write calls.
This is **not a measurement of physical payload I/O**: `refs.sys`, the virtual
disk stack or storage could perform work inside an allocation/move operation.
No physical scratch-growth or payload-size-independent cost claim follows.
The file remains SYSTEM-only because marking unwritten bytes valid can expose
old scratch contents. No data-content preservation is claimed for this file.

## Preserved state and next integration

Clean shutdown was independently checked through Hyper-V and CIM. OFF
checkpoint`80907930-4a43-4cbc-b26b-dafd14dea4e8`, parent
`24cfdd12-9b9c-4bd0-8322-a94da6d98708`, preserves the placed file. All16
earlier checkpoints remain, including successful converted branch
`ae80bfd5-7b8d-4e60-80b4-6e236c841390`. Assigned VM RAM is0 after shutdown.

Next, reopen this file read-only after a clean boot and verify the same file
identity, physical prefix and storage validity. Then integrate an explicit
private allocation-only shadow construction path. It must preserve source
security without exposing uninitialized placeholders, handle partial cluster
tails, feed original retained bytes into the compact hybrid, and materialize
only necessary payload. Complete target-required byte coverage, bounded
scratch accounting, recovery and native hybrid conversion remain necessary.
The existing working full-shadow converter is unchanged. No unit tests were
added or run; this evidence is a release build and the exact native experiment.
