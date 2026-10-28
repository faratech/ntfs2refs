# Native placement before valid-data advancement

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
