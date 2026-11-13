# Fresh shadow attachment protection diagnostic

The isolated run `win11-20261024T035910091Z` passed its first native probe and saved off-state checkpoint `506ce18b-0b46-4e3e-8106-4b1f363f3105`. After restarting, the original target remained offline/read-write, but a newly attached shadow was online/read-write. The Excluded guard correctly stopped. The failed attachment is preserved as evidence; it does not qualify restart isolation or conversion.

The first probe requested persistent disk attributes correctly: target attributes 1, shadow attributes 3, mask 3 and Persist true. The existing shadow opener uses V2 ReadOnly false and attachment flags 6. Microsoft defines NO_DRIVE_LETTER as suppressing drive letters; it does not provide write protection. PERMANENT_LIFETIME separates attachment lifetime from handle lifetime. READ_ONLY is an independent flag. [Attach flags](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-attach_virtual_disk_flag).

The general disk attribute contract says Persist true retains settings across reboot. That statement does not establish that a newly attached VHD device inherits the former attachment's attributes. This distinction is an inference from the measured new attachment and the documented API scope, not a documented guarantee of reset behavior. [SET_DISK_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-set_disk_attributes).

## Bounded diagnostic

`lab/guest/Invoke-GuestShadowReadOnlyAttachment.ps1` and `NativeShadowReadOnlyAttachment.cs` are separate from frozen preparation/reattachment code. Execute only after the root operator restores the exact isolated checkpoint above and starts its existing 8 GiB guest. The current failed attachment branch must not be reused. Initial inventory must contain only the three enrolled disks; the original target must still be offline/read-write. The exact preparation and first probe SHA-256 values are pinned in the wrapper.

1. Hash the ordinary `J:\ntfs2refs-shadow\94f6256f57424ad69147f58199387ee1\shadow.vhdx`, bounded to 256 MiB. Its measured size was 148,897,792 bytes. Bind the journal GPT/partition/volume and original disk inventory.
2. Open that existing VHD with V2 GetInfoOnly false, ReadOnly true and access mask NONE. Own-process SeManageVolumePrivilege is enabled only from its existing assignment and then restored exactly. Attach once with flags 7: READ_ONLY, NO_DRIVE_LETTER, PERMANENT_LIFETIME. [Open parameters](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-open_virtual_disk_parameters), [Attach privilege](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-attachvirtualdisk).
3. Bind stable VHD query 14 (`9a5e7b31-ee6b-4c29-8a9e-f18c7ffb8e02`), retain query 2 as content-generation evidence, and bind new physical disk 3 by UID, GPT identities, partition layout and geometry. Open its physical handle read-only. Query exact GET_DISK_ATTRIBUTES and require IOCTL_DISK_IS_WRITABLE to return ERROR_WRITE_PROTECT (19), not an arbitrary failure. [Writability contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ni-ntdddisk-ioctl_disk_is_writable).
4. Only with separately selected `-EstablishExclusion`, and only after provider protection is proved, request one physical handle with attribute-control access. Rebind identity/protection, then make at most one SET_DISK_ATTRIBUTES request for attributes 3/mask 3/Persist true. Record access or request refusal directly; do not retry, change flags, or normalize refusal into success. Already observed attributes 3 require no SET.
5. Requery identity, attributes and provider protection; rehash the backing file and require the full before/after hash and length to match. Record Get-Disk state separately. Original target identity and offline/read-write state must remain unchanged.
6. Close known-completed handles, retain the attachment, and export evidence. Unknown native activity preserves handles/session; cleanup failure remains explicit. The helper never creates, formats, detaches, brings a disk online, reads raw payload, or issues source-target writes. Attribute establishment is a new explicit transition, never claimed as recovered persistence.

The baseline and successful attachment are not cleaned up by this guest helper. The root operator owns all subsequent VM decisions. A refusal is useful evidence but not permission to proceed into reconstruction.

## Staging and result contract

Use a fresh PowerShell process/session with these files together: the new wrapper/native helper and the pinned `NativeShadowDisk.cs`, `NativeMountBoundary.cs`, `Restore-GuestShadowAttachment.ps1`, `Invoke-GuestNativeProbe.ps1`. The latter scripts supply named pure guards only; their top-level code is never invoked by this diagnostic. Supply the independently reviewed new native helper hash:

```powershell
& C:\ntfs2refs\scripts\Invoke-GuestShadowReadOnlyAttachment.ps1 `
  -RunId 94f6256f57424ad69147f58199387ee1 `
  -ObservationId <new-32-lowercase-hex> `
  -DiagnosticNativeSourceSha256 <reviewed-64-lowercase-hex> `
  -EstablishExclusion
```

Output is exactly one bounded JSON file, `C:\ntfs2refs\shadow-readonly-attachment\<RunId>\<ObservationId>\attachment.json` (maximum 2 MiB). It contains pins, full backing-file hashes, VHD calls, physical query/control buffers and errors, privilege restoration, initial/attached/final inventories, transition stage, known-completion/cleanup flags, and explicit no-conversion/no-persistence qualification. `attributeChangeRequestsMayHaveBeenIssued` is persisted before entering the optional native attribute phase; a returned phase reports its precise attempt state.

Measured statuses include `provider-readonly-observed`, `provider-readonly-attribute-access-refused`, `provider-readonly-attribute-request-refused`, `provider-readonly-and-offline-observed`, and `failed-preserved`. Success for future exclusion integration requires explicit provider protection before/after, attributes 3, unchanged backing hash, original target preservation, known completion and complete cleanup. Default mode only observes protection; it does not establish exclusion.

`lab/Test-GuestShadowReadOnlyAttachment.ps1` exercises only mocks, archived JSON and WhatIf. It covers identity/protection guards, ordering, known refusals, unknown native completion, malformed responses, false native success and cleanup failures. No VM or device operations occur in tests.

## Measured result, 2026-10-24

The diagnostic passed in `.lab/hyperv/shadow-readonly-attachment/win11-20261024T041957683Z-df922bc4b13e46339c8c938a4f5a7742`. The host evidence SHA-256 is `3e9b18e8179cdb9247d0679598885f821872daa3da2e039969e07b9fff84768a`; exported guest attachment evidence is `28d41711e761553a39938479f82b265470ca988d63b4a077d6ba0aee848913c0`.

Provider writability returned error 19 before and after exclusion. Native attributes began at 0 although Get-Disk reported read-only, demonstrating that provider protection and the attribute mask are distinct observations. One SET request, attributes 3/mask 3/Persist 1, succeeded; the final attribute query returned 3. The source target stayed offline/read-write. Native completion, privilege restoration and cleanup were known and successful.

Both complete backing-file hashes were `d7e7cb09c9b977ff0bc142a9ed069f5bd8c5bf88bd925db20982479561ba035d` over exactly 148,897,792 bytes. Root saved off-state 8 GiB checkpoint `f7de106a-6e94-4b2f-aef7-13c5b02d5df9`, named `shadow-readonly-protected-df922bc4b13e46339c8c938a4f5a7742`, then restored the off-state 4 GiB baseline. This qualifies the explicit fresh-attachment protection sequence on this case; it does not prove that shadow attributes persist across future reattachment, whole-partition restart identity, or conversion.

## Operational integration

`Restore-GuestShadowAttachment.ps1` now keeps Prepared behavior and the original `NativeShadowDisk.cs` preparation pin. Excluded additionally requires independent `ProtectionNativeSourceSha256` (`NativeShadowReadOnlyAttachment.cs`) and `MountNativeSourceSha256` (`NativeMountBoundary.cs`) pins. It uses the measured read-only attachment followed by explicit exclusion. It refuses any attempted attribute access/SET failure, including a failed SET followed by an observed attribute mask of 3. No persistence claim is made.

Excluded evidence adds `protectionProfile=provider-readonly-explicit-exclusion`, the two source pins, `openReadOnly=true`, `attachFlags=7`, `physicalProtection`, `providerReadOnlyObserved`, `exclusionEstablished`, `shadowPersistenceQualified=false`, `originalTargetBefore/After`, `originalTargetStatePreserved`, `backingBefore/After`, `backingUnchanged`, `diskAttributeChangeRequestsMayHaveBeenIssued`, and `cleanupComplete`. Its existing `diskAttributeChangeRequestsIssued` now truthfully records the native attempt. Full backing hashes are bounded to 256 MiB in this lab profile. The host must compare the target GPT/partition snapshots with its independently pinned reconstruction/probe request before accepting the exported result.

The mount-boundary native helper now opens VHD backing read-only too, retaining its independent source pin and reporting `vhdOpenReadOnly`, `vhdOpenVersion`, and `vhdOpenAccessMask`. Microsoft warns that reopening a permanently attached disk must not request write access when its original open was read-only. The later detach remains a separate bounded operation with its existing guards. [OpenVirtualDisk remarks](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-openvirtualdisk).
