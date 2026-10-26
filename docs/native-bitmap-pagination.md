# Complete native bitmap pagination

The native source collector, shadow retention/verifier and locked ReFS allocation
capture now share `n2r_win32::bitmap_paging`. Each control call requests at most
2 MiB of bitmap payload plus its 16-byte header. The complete map is bounded to
4 MiB of payload, sufficient for the existing 128 GiB partition profile with
4 KiB clusters. Eight calls and a separate total-returned-byte budget bound
rounding/overlap overhead. Disk, tree, extent, feature and journal limits are
unchanged; this does not claim that every volume up to that size is convertible.

Microsoft documents that returned starting LCNs may be rounded down and that
`BitmapSize` describes the remaining cluster domain, not the amount of bitmap
payload actually returned. The collector advances using actual response bytes,
preserves metadata flags, and handles `ERROR_MORE_DATA` only as continuation.
See [FSCTL_GET_VOLUME_BITMAP](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_volume_bitmap),
[VOLUME_BITMAP_BUFFER](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-volume_bitmap_buffer)
and [the extended input](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-starting_lcn_input_buffer_ex).

The assembler refuses gaps, changed domain ends, conflicting rounded overlaps,
wrong query addresses/flags, native errors other than `ERROR_MORE_DATA`, missing
data, false completion, nonprogress, extra pages after completion and exhausted
budgets. A failed page poisons the assembler. The final partial byte is preserved
for NTFS's existing initialized-bitmap hash comparison. Legacy and metadata-inclusive
views are collected independently and never substituted for one another.

Native attestation report schemas 6 and later retain each original bitmap query and response;
replay reconstructs the complete map from those bytes and requires exact before/
after transcript equality. Schemas 2–5 retain their existing rules and reject
nonempty continuation transcripts. File/stream evidence keeps its original budget, while bitmap
pages have their own bounded budget. Saved native reports are capped at 64 MiB.
Schema 7 additionally carries [retrieval-pointer continuations](native-retrieval-pagination.md);
it does not weaken any bitmap completeness rule.

The flat map is explicitly identified as `assembled-zero-lcn-bitmap-v1`. Its
digest covers the zero-LCN header and assembled bitmap bytes. Page proofs retain
each exact input, native status, original response header/length and full response
digest, including response padding. An assembled digest is not presented as the
digest of a single native response. Shadow candidate/allocation reports and the
frozen allocation witness carry these proofs. Allocation intervals still have
their existing range budget and coalesce across page boundaries.

These are point-in-time observations. Paging does not make an online filesystem
atomic: source reconciliation, volume freezes, live witness tokens, move rechecks,
semantic verification and all reconstruction/recovery barriers remain required.
In particular, post-lock allocation does not prove the frozen ownership graph,
and the selective write-set path remains non-executable.

Pure checks exercise two-page 128 GiB geometry using only a 4 MiB in-memory
bitmap, exact 64 GiB header capacity, overlap/rounding, refusal paths, budgets,
NTFS tail hashes, old-report compatibility and raw-page serialization. Locked
capture checks preserve independent views and page provenance. No new large
image, guest volume, conversion or native paging qualification is implied by
these checks; the isolated guest's RAW disks have not been initialized.
