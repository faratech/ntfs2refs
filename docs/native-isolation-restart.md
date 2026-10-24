# Retained native isolation and restart control

`scripts/Invoke-LabRetainedNativeProbe.ps1` takes a successful retained-preparation `host-result.json` path and SHA-256, plus a reviewed source manifest path and SHA-256. Its scope is native isolation and read verification of an existing prepared pair. It never invokes reconstruction or enables payload writes.

The new manifest has schemaVersion1, kind `retained-native-probe-reviewed-sources`, and exactly these `files` entries (`path`, `sha256`):

- `lab/guest/Restore-GuestShadowAttachment.ps1`
- `lab/guest/Invoke-GuestNativeProbe.ps1`
- `lab/guest/NativeShadowDisk.cs`
- `lab/Lab.psm1`
- `scripts/Invoke-LabRetainedNativeProbe.ps1`
- `target/release/lab-native-probe.exe`

Original fixture scripts and C# helpers come from the preparation's independently pinned reviewed archive. The current NativeShadowDisk source must equal the source used to create that shadow. All executing sources and the binary are archived before VM actions. The initial VM must be the enrolled installed-clean checkpoint, off with4 GiB, Secure Boot enabled, all three host disks owned and networking disconnected. Additional host capacity of4 GiB is required.

The sequence is:

1. Restore the exact successful prepared off8 GiB checkpoint. Start the guest, initialize PowerShell Direct, copy and verify archived helpers.
2. Reattach the existing shadow in Prepared mode. Inspect the existing source/shadow fixture pair with a new observation ID and the original construction hash. Compare frozen hashes, mapping, metadata, directory metadata and security against construction.
3. Build the exact Rust request from measured GPT/partition/volume identities and the inspected64 KiB retained range. Stage only the pinned request and binary in a new guest C: directory. Run the native probe without reopen or whole-partition options.
4. Require source/shadow raw retained hashes,65,536 bytes read from each, target flush success and persistent target/shadow disk attributes1/3. Export all bounded reports before clean shutdown. Preserve an off8 GiB `retained-isolated-<RunId>` checkpoint.
5. Restart that branch. Reattach the shadow in Excluded mode, with no mount or attribute repair. Run the same request with a new probe ID and both reopen/whole-partition options. Require the same retained hashes, fresh full52 GiB partition SHA-256 values and unchanged isolation attributes. Native read accounting must be52 GiB plus65,536 bytes per partition.
6. Export, cleanly shut down and preserve `retained-quiescent-<RunId>` before restoring installed-clean off4 GiB. The quiescent checkpoint and whole-partition pins are inputs for later work, not conversion qualification.

Host output is a new `.lab/hyperv/retained-native-probe/win11-<UTC>` directory. Each attachment exports only `attachment.json` (≤1 MiB). Inspection exports `pair.json` (≤2 MiB), `started.json` (≤16 KiB), and up to192 bounded query buffers (≤19 MiB aggregate). Each native phase exports exactly nine files: the binary (≤16 MiB), request (≤16 KiB), native report and Rust `probe.intent.json` (≤1 MiB each), three process records and stdout/stderr (≤64 KiB each; ≤19 MiB aggregate). The Rust intent must contain the exact request/hash and phase options with no payload-write claim. Every file is hashed before and after transport.

The native process has a default900-second deadline; PowerShell Direct allows120 additional seconds to return a determinate report. Timeout does not kill the process. Guest operation uncertainty is sticky and separate from transport uncertainty. Any failure preserves the branch and session; the host does not shut down, restore, or close a failed session automatically. Success status is `native-isolation-and-restart-verified`; conversion qualification stays false.

Focused tests exercise pinned identities, checkpoint state, archive and artifact bounds, sticky uncertainty, process arguments/results and WhatIf without VM or device operations. They do not establish native success; only the subsequently exported runtime evidence can do that.
