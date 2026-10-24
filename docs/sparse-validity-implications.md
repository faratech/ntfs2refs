# Validity is part of extent preservation

The second allocation experiment reported EOF/allocation 65,536 bytes, a cached
valid prefix covering all 65,536 bytes, and no valid on-disk regions. Retrieval
pointers separately reported a negative marker for VCN 0..1 and a positive
fifteen-cluster run for VCN 1..16. These are different observations and must not
be collapsed into a single claim that the file is fully allocated or initialized.
The exact case is `vdl-probe/win11-20261024T004239424Z`; its outcome is preserved
for a payload-free post-remount observation.

Microsoft defines cached and noncached region usage against the cache manager
and storage device respectively. A prefix boundary derived from complete region
coverage summarizes that response; it does not establish that the filesystem
stores one scalar valid-data-length field.
[Region usage](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info)

`FILE_SUPPORTS_SPARSE_VDL` explicitly describes per-cluster valid/invalid state,
including automatic zeros, without a requirement that valid data be contiguous.
The next observation must record this flag for the exact native volume. Preserve
the entire region list even when it has a convenient prefix shape.
[Volume capabilities](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)

The published negative-LCN interpretation in `RETRIEVAL_POINTERS_BUFFER` is
expressly scoped to NTFS. Do not infer a ReFS physical address or declare that
first cluster sparse, resident or compressed from that marker alone.
[Retrieval-pointer contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointers_buffer)

For conversion, retained bytes, logical file content, allocation ownership and
validity are separate obligations. The NTFS reader already synthesizes zeros for
uninitialized tails; a ReFS result must preserve those logical zeros rather than
exposing old raw contents. Conversely, retaining an initialized payload extent
will not preserve its content if the new metadata still marks its data invalid.
Partial-cluster boundaries, fragmented validity and sparse runs need explicit
tests before selecting any writer profile.

The immediate research step is observation after clean shutdown/remount, with
no payload read of the newly allocated file. Later movement or valid-data
advancement needs a separately reviewed profile based on the measured region
state and attributable bytes. Neither API success nor unchanged raw bytes alone
proves payload-write avoidance. The existing failed profile stays failed; no
conversion or metadata-writing capability follows from these observations.
