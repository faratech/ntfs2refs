# Native NTFS volume flag 0x0080

Investigation date: 2026-10-23. Scope: read-only source eligibility research for data-volume conversion. No source-image changes, mounts, guest changes, or eligibility-rule changes were made.

## Finding

The `0x0080` value in our Windows 11 native NTFS corpus is real on-disk state, not a parsing, run-list, byte-order, or attribute-layout error. Primary reverse-engineering research identifies this bit as persistent state that disables short-name creation and the tunneling cache. It is distinct from the dirty bit (`0x0001`). Our current rule blocks every nonzero volume-flags value, so it also blocks this likely ordinary policy setting.

This investigation does **not** remove that blocker. The interpretation has not yet been checked with a native setting differential on our Windows build. Nor would allowing this bit establish clean journal state, complete inventory, or safe conversion.

## Independent native-byte verification

Sources are the existing full-volume captures under `.lab/hyperv/corpus/win11-20261023T213403542Z/ntfs`, formatted in the Windows 11 build 26300.9457 guest. The independent PowerShell probe opened each regular image with read-only access and sharing that excludes writers/deletion, recomputed its whole SHA-256, and matched the capture manifest. It read only the boot sector and three 1024-byte records after hashing; no production Rust parser was called.

| Capture | Length | SHA-256 |
| --- | ---: | --- |
| `empty.raw` | 1073741824 | `ff992d648653a2730b1944ee1f0c2cc2a9e6de31a86089c87849b9ffb74c9278` |
| `control.raw` | 1073741824 | `86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727` |

Both images give identical relevant results:

- Boot-sector geometry: 512-byte sectors, 4096-byte clusters, 1024-byte FILE records, `$MFT` LCN 87381, `$MFTMirr` LCN 2.
- MFT record 0's unnamed nonresident DATA attribute starts at VCN 0, with a first physical run at LCN 87381 spanning 64 clusters. Thus record 3 lies inside that confirmed run.
- MFT record 3 starts at image byte **357915648**. Its resident, unnamed type `0x70` attribute starts at record offset **312**, with a 12-byte value at attribute offset **24**.
- The value starts at image byte **357915984** and is exactly `000000000000000003018000`: reserved bytes, version 3.1, little-endian flags `0x0080`.
- FILE update-sequence fixups validate. The full raw record 3 matches its `$MFTMirr` copy at image byte **11264**, before and after fixup. This is a narrow record-3 check; it does not clear the broader `backup_boot_unverified` blocker.
- The raw record-3 SHA-256 is `06f33107f686c7f4f3be8361fa45e3c7611f2922b54a68db711dfb5e8c9d69b3`. The 12-byte value SHA-256 is `73fa509d14d9c3d00af39759042608c861295e109e6fd3a376a3145037b857e0`.

Reproduction script: `.lab/research/ntfs-volume-flags-20261023/extract-volume-flags.ps1`. It creates new output files and refuses existing output; the saved results are under `native-ranges/` in that directory. Evidence manifest: `volume-flags-evidence.json`, SHA-256 `ec369675dfbf05fd3067b40e7146f14f86e0378a31db303b7e77e2f25b8a0e7a`. Small raw ranges and hashes are retained there.

## Source interpretation and library cross-check

Maxim Suhanov's original [NTFS today research](https://dfir.ru/2019/01/19/ntfs-today/) lists `0x80` in `$VOLUME_INFORMATION` as disabling tunneling and short-name creation. The author explicitly states that these flags were reverse engineered. This is primary researcher evidence, not a Microsoft on-disk-format specification.

Microsoft's [fsutil 8dot3name documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name) confirms that short-name policy can be stored as a per-volume on-disk flag. It documents querying the global and per-volume states, and enabling/disabling a volume setting when the global setting is 2. It does not identify the on-disk bit number, so it independently supports the mechanism but does not prove the `0x0080` mapping.

The [`ntfs` 0.4.0 volume-information reader](https://docs.rs/ntfs/0.4.0/src/ntfs/structured_values/volume_information.rs.html) reads a 12-byte little-endian structure consisting of an eight-byte reserved field, major/minor bytes, then `u16` flags. This agrees with `src/ntfs_inspect.rs`, which reads flags at offset 10. However, the crate's public `flags()` calls `from_bits_truncate`, and its enum does not include `0x0080`. It therefore discards that bit. A zero result from that API must not be treated as independent evidence that the raw volume flags are zero.

The Linux NTFS3 [on-disk header](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h) likewise places the two-byte flags at offset `0x0A` in a 12-byte structure. Its limited flag definitions do not resolve the modern policy bit. Missing definitions in older readers are not evidence of corruption.

## Narrow native follow-up

Use only a disposable enrolled NTFS data volume inside the existing VM, protected by a checkpoint. Record `fsutil 8dot3name query` and the same query for that explicit volume; also retain native dirty-state output and identity evidence. Current capture evidence did not include the short-name query, and its unrelated `fsutil volumeinfo` call failed because of the path form, so it cannot answer this question retrospectively.

If the global short-name setting is 2, capture the explicit per-volume setting in three states: original disabled, enabled, restored disabled. After each change, obtain consistent locked/dismounted bytes using the existing capture path. Compare the exact 12-byte `$VOLUME_INFORMATION` values, the native query output, and `$MFTMirr`. The hypothesis predicts a `0x0080 -> 0x0000 -> 0x0080` transition when no other state bits intervene. Do not strip existing short names. If the global setting differs, retain that evidence and use a separate disposable test configuration rather than silently changing unrelated volume policy.

A successful differential would justify recognizing `0x0080` as a separately reported policy bit for that tested profile, while continuing to reject unknown bits and retain independent dirty/journal checks. It would not justify ignoring arbitrary nonzero flags or discarding existing DOS names. ReFS short-name compatibility and the treatment of existing names remain preservation-policy decisions.

## Source inventory priorities for preserving data extents

The control corpus already demonstrates why interpreting this one flag is insufficient. Existing reports still block directory reconciliation, security descriptors, allocation ownership, journal state, backup metadata, and unsupported feature semantics.

1. **Determine which records are filesystem metadata.** Records 24 through 35 in this native sample are `$Extend` descendants such as `$Quota`, `$ObjId`, `$Reparse`, and transaction metadata. At investigation time, `is_metadata` only marked records below 16; the subsequent [metadata-role reader increment](ntfs-metadata-roles.md) reports conservative MFT-ancestry candidates. Validated directory indexes and preservation semantics are still required before excluding metadata from user-file preservation or treating system streams as ordinary data. Filename text alone is insufficient.
2. **Finish the extent map before allocating ReFS metadata.** Assemble attribute lists/extension records or reject them, distinguish resident data that must be relocated from nonresident data that may retain physical positions, and reconcile all extents against `$Bitmap`, file sizes, initialized lengths, sparse regions, metadata reservations, overlaps, and bad clusters. Resident bytes cannot remain inside discarded NTFS MFT records. Matching cluster sizes alone does not establish valid ReFS extent semantics.
3. **Reconcile namespace and identity.** Validate directory index roots/allocation/bitmaps against all MFT filename links, parent sequence numbers, hard-link counts, raw UTF-16 and case rules. Preserve unnamed/named stream identity and distinguish existing DOS aliases from the policy for creating new ones.
4. **Resolve security and remaining metadata semantics.** Map security IDs through validated `$Secure` records and indexes; retain owner, group, DACL/SACL, timestamps, attributes, and link relationships. Reparse points, EAs, object IDs, compression/encryption and transaction metadata need explicit support or explicit rejection. Copying raw attribute bytes to an unrelated ReFS metadata layout is not a preservation strategy.
5. **Validate a stable source state.** Check `$LogFile` restart/clean-state evidence, backup boot geometry and all relevant `$MFTMirr` records under an offline or exclusive workflow. Dirty=false and the narrow record-3 equality above are insufficient.

These are investigation priorities, not newly implemented capabilities. Native guest validation must eventually demonstrate that retained data extents remain accessible with the expected namespace, streams and metadata after conversion.
