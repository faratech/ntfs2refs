# Fixed-VHD corpus extraction

`n2r-extract-fixed-vhd` is a separate **lab analysis utility**. It copies an
immutable native guest partition into a raw file so the Rust reader can inspect
it. It does not convert NTFS to ReFS and is not a deployment path. The eventual
filesystem converter must run inside the VM and on eligible bare-metal volumes;
this helper does not advance that qualification.

The host orchestrator first verifies ownership, an off-state checkpoint, guest
partition evidence, media/driver provenance and host capacity. Microsoft documents
`Convert-VHD` as an offline copy to a new virtual disk, with its format selected
by the output extension. Use an unattached, independently verified checkpoint
copy and `-VHDType Fixed`, never `-DeleteSource`. Do not mount the copy through the
host filesystem driver. [Microsoft Convert-VHD reference](https://learn.microsoft.com/en-us/powershell/module/hyper-v/convert-vhd?view=windowsserver2025-ps)

The helper accepts only regular local files. It validates the 512-byte fixed-VHD
v1.0 footer, checksum, type 2, all-ones data-offset sentinel, declared/actual
length and explicit expected disk size. Dynamic/differencing disks, VHDX,
saved-state images, temporary/unknown features and unknown reserved fields are
refused. The implementation follows the footer field sizes and checksum in the
[Microsoft VHD specification](https://www.microsoft.com/en-us/download/details.aspx?id=23850).
The downloaded source document's SHA-256 is
`f2aca9d584b41a2b83ec12190236befa33097b97a7296b1fccff6138438a062d`.
Only 512-byte logical sectors and disks up to 128 GiB are accepted by this lab
profile. The original-size field is retained as informational provenance.

Create a selection JSON from already exported, hash-verified guest evidence:

```json
{
  "schema_version": 1,
  "expected_disk_bytes": 68719476736,
  "offset_bytes": 17825792,
  "length_bytes": 55834574848,
  "logical_sector_size": 512,
  "guest_disk_unique_id": "60022480D091C4251B5FFD619706C2B5",
  "guest_partition_guid": "REPLACE-WITH-ACTUAL-GUID",
  "host_vhd_id": "25C491D0-5F1B-4205-9E6F-FD619706C2B5",
  "evidence_path": "guest-result.json",
  "evidence_sha256": "REPLACE-WITH-ACTUAL-SHA256"
}
```

The example is deliberately not executable until actual partition geometry,
GUID and evidence hash are supplied. Relative evidence paths resolve from the
selection file's directory. The selection is limited to 1 MiB, evidence to 16
MiB, and memory buffers to 1 MiB. UTF-8 JSON with or without BOM is accepted.
The referenced evidence is hashed as bytes; its schema is not interpreted.
The host orchestrator must independently check that the asserted identifiers and
geometry match its verified native evidence. The helper explicitly reports
`gpt_validated=false` and `guest_identity_authenticated=false`.

```powershell
.\target\release\n2r-extract-fixed-vhd.exe `
  --source <case>\target-fixed.vhd `
  --output <case>\devdrive.raw `
  --selection <case>\selection.json
```

The source opens read-only with Windows sharing that denies concurrent writers
and deletion. Every source byte is hashed before and after extraction. Every
selected partition byte, including zeros, is copied; the complete output is
read back and hashed. The selection and referenced evidence are rehashed before
publication. No sparse-prefix representation is substituted for a full image.
Allow roughly two complete source reads plus the selected-range read and output
readback, and reserve the full fixed-VHD and raw-image sizes in host capacity.

The raw image first exists as `<output>.partial`; successful extraction publishes
the requested `.raw` and `<output>.json` completion report. Existing final,
partial or report files cause refusal. Publication uses a new hard link, then
removes only its own partial name, because ordinary rename can overwrite a
concurrently created destination. The output filesystem must support hard links.
Any interruption or publication failure retains partial artifacts. A final raw
file without its successful completion report is not a verified capture.

Reparse paths, device namespaces, alternate streams, parent traversal and
ambiguous Windows device names are refused. Operate in the owned lab directory;
these checks are not a sandbox against another privileged process replacing
parent directories concurrently. Filesystem health, GPT integrity, native driver
acceptance, and conversion qualification remain false regardless of hash matches.
