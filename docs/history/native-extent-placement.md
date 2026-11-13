# Bounded initialized-file placement experiment

This is a guest-only capability measurement on the saved Windows 11 Dev Drive data control. It deliberately initializes and may relocate 64 KiB of payload. It is neither a converter nor evidence that payload can be reused without copying. Rust remains the intended converter language; PowerShell/C# here provides a small Windows laboratory harness.

`lab/guest/Invoke-GuestExtentPlacement.ps1` uses the original control evidence, enrollment, GPT identities, 52 GiB partition, 4 KiB clusters, native driver hash, build and existing 4 MiB fixture. It requires the owned `N2R-WIN11` guest and elevated 64-bit process. The native helper independently restricts its writable path to `F:\fixtures\placement-<32 lowercase hex>\initialized.bin`. Reusing a directory or file is refused.

The native helper holds ordinary directory handles and the original fixture handle without write/delete sharing, rejects reparse points and unexpected resolved paths, and checks the mounted volume GUID. It creates a new directory and a new file, writes all sixteen uniquely marked 4 KiB clusters, flushes and closes the creation handle, then reopens the file for identity, mapping and full logical SHA-256 observations. Sparse, compressed, encrypted or multiply linked files are refused. No cleanup deletes the evidence or fixture.

After initialization it requests two fresh allocation bitmaps: legacy 8-byte input and extended 16-byte input with flag 1, including zero ABI padding. Both must succeed and cover exactly the measured partition's 13,631,488 clusters. It selects the first 16-cluster aligned range at LCN 65,536 or above that is free in both bitmaps and outside every current original/new-file extent and conservative neighborhoods around previously observed metadata anchors. Those exclusions do not establish equivalence between raw metadata addresses and API LCNs. A free observation does not reserve the range.

The helper issues exactly one `FSCTL_MOVE_FILE`, VCN 0, count 16, with the selected destination. The documented interface takes the file handle, source VCN, destination LCN and cluster count; it offers no no-copy mode. A competing allocation can invalidate the bitmap observation, so a native rejection is retained without retry. [Microsoft MoveFile contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file), [input structure](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-move_file_data)

Both file identities, mappings and hashes are collected afterward. `moveCompleted` means the control call returned, including an error; `requestedPlacementObserved` is separate from native success. A reported success with different mappings remains unresolved. Native failure, partial bitmap, unexpected identity or parameter disagreement never enables another writer. No privilege adjustment is made by this initial probe. It uses administrative volume access and records access failures rather than attributing them to universal filesystem incompatibility. [Microsoft defragmentation guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/defragmenting-files)

## Invocation and artifacts

Required guest parameters are `ControlRunId`, `ControlEvidenceSha256`, `CapturedAllocationSha256` and a new `ProbeId`. Dependencies are `GuestLab.psm1`, `Capture-GuestAllocation.ps1`, `NativeExtentPlacement.cs` and the new script. Control inputs remain under `C:\ntfs2refs\devdrive-control`. Output is a new `C:\ntfs2refs\extent-placement\<ProbeId>` directory.

The artifact allowlist has at most eleven files and a 10 MiB aggregate bound:

| Files | Individual limit |
| --- | --- |
| `started.json`, `placement.json`, `allocation-before.json`, `allocation-after.json` | 1 MiB |
| `expected-pattern.bin` | exactly 65,536 bytes |
| `originalBeforeExtents.bin`, `originalAfterExtents.bin` | 1–16,400 bytes |
| `beforeExtents.bin`, `afterExtents.bin` | 1–272 bytes |
| `candidateBitmap.bin`, `candidateMetadataBitmap.bin` | 1–2 MiB |

Zero-length native responses produce no buffer file. Every retained native buffer has input bytes, input hex, code, output capacity, status/error, timestamps and SHA provenance in `placement.json`. The move's exact 32-byte x64 input includes the process-local file handle and four zero alignment bytes. Only the buffer's numeric destination is portable; the handle is not reusable outside that call.

`started.json` is flushed before entering native code that may write. If execution or transport is indeterminate, the host must preserve the guest branch. A final response can be `blocked`, `integrity-check-failed`, `native-move-rejected`, `native-move-returned-unexpected-mapping` or `native-placement-observed-awaiting-remount`. A blocked response may still contain a newly created fixture or a completed move; inspect explicit write/attempt/completion fields and retain everything. No final JSON is promised when preflight fails before output creation or transport fails.

The experiment always reports clean-remount, physical mapping, payload-copy avoidance, conversion and boot qualification as false. Clean shutdown/reboot and read-only re-observation belong to the separately reviewed host wrapper. Offline raw marker matching is another separate measurement. No raw reads/writes, lock/dismount, formatting, valid-data advancement or policy changes exist in this helper.

`lab/Test-GuestExtentPlacement.ps1` exercises malformed retrieval buffers, bitmap completeness/domain checks, disagreement between bitmap variants, source/anchor overlap exclusions, ABI bounds/padding, deterministic distinct patterns and mocked/native-saved guest guards. It never calls the helper's `Run` method or native controls. The reviewed baseline passes 82 checks in Windows PowerShell 5 and PowerShell 7. The separate completed native run is described below.

## Host orchestration

`scripts/Invoke-LabExtentPlacement.ps1` restores only the exact saved Dev Drive checkpoint `2aa127e2-c875-4ca0-8629-dab784136448`, beginning from the exact off-state installed-clean baseline. It verifies all three owned disks, original target VHD identity, disconnected networking, Secure Boot and fixed memory. The data branch runs at 8 GiB; returning to the baseline restores 4 GiB while powered off. Hyper-V remains a test harness dependency only.

The wrapper hashes and verifies the four dispatched guest helpers. Before the bounded placement command it persists possible-write intent and sets attempt/completion fields to null until a validated exported final record establishes their values. Timeout, transport, export, blocked or integrity failures preserve the current branch. No failure handler forces shutdown, cancels native I/O or restores the baseline.

A completed observation, including a native rejection, may proceed only when the initialized file's hash and identity are unchanged and the original fixture's hash, identity and native mapping match the saved control. The wrapper exports at most eleven original artifacts totaling 10 MiB. It then cleanly shuts down and reboots, captures both files through the read-only collector, and separately exports `identity.json` plus `allocation-remount.json`, each at most 1 MiB. GPT disk/partition identity, geometry, native driver provenance and each post-operation file mapping are checked again. This step can qualify clean-remount survival; it does not qualify raw physical addresses or avoidance of payload copies.

After the second clean shutdown, the wrapper saves `extent-placement-data-<ProbeId>` as a new off-state outcome checkpoint and records its exact ID and name before restoring installed-clean. Native status and the new file's before/after mappings remain explicit in the host result, including when the driver rejects the move or returns a different mapping. The original Dev Drive data checkpoint remains intact. `lab/Test-LabExtentPlacement.ps1` passes 222 pure guard, mocked transport and `-WhatIf` checks in both Windows PowerShell 5 and PowerShell 7; it executes no VM actions.

## Completed native observation

`extent-placement/win11-20261024T000401422Z` completed at 00:06:09 UTC. The one native move returned success and changed the initialized file's 16-cluster mapping from LCN 1508352 to requested LCN 1508384. The file's identity and SHA-256 `9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78` survived clean shutdown/reboot with that mapping. The original 4 MiB fixture was unchanged. The host preserved outcome checkpoint `4b581541-4899-4f91-adc1-e4e784c7cacf`, then restored the off-state 4 GiB baseline. See [full evidence hashes and limits](lab-results.md#native-initialized-file-placement-and-clean-remount).

Raw bytes at the new and former source ranges remain unmeasured, as do zero-VDL movement and payload-copy avoidance. The [proposed bounded raw read](native-range-read-design.md) will check both ranges and fresh allocation bits without adding a writer.
