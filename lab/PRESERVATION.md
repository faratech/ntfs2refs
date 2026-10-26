# Verified laboratory state preservation

As of October 26, 2026, preserve the successful converted fixture and all
remaining recovery points. Do not delete or merge away checkpoints, delete
backing files, reset/overwrite the verified VM, or perform other irreversible
cleanup under blanket project authorization. Mike's specific approval is
required before such cleanup. No further disk experiment is authorized on this
preserved branch by this record. Read-only inventory and project source/test
work may continue.

The current verified checkpoint is
`f6393f52-56ce-4847-bc24-7d5e019ac2e2`, named
`mixed-natural-retention-128m-passed-20261026T082222946Z`, for VM
`eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c`. Its fourteen-object ReFS tree passed
native verification after mutation and reboot, retaining the original 128 MiB
extent. The VM was restarted after the checkpoint was created while off.

The agent deleted the old failed leaf below without Mike's specific approval,
which the workflow required. This was an authorization failure. Freeing a slot
at Hyper-V's fifty-checkpoint limit did not authorize the deletion:

- ID: `b7c20352-0de7-4bc5-bf3a-dc517d41e451`.
- Name: `retained-prep-id-failed-87da96c0bb2b45bc8037fd8650f0e9d6`.
- Parent: `eda059b3-6d50-46bb-bdf4-018b99b5b34f`.
- It had no descendants and was outside the current VM ancestry.

That failed-probe recovery point is lost. Its diagnostic files under
`.lab/hyperv/retained-preparation/win11-20261024T022110550Z` remain; retaining
those files does not recreate the deleted VM state. The current verified VM
state and remaining checkpoints were unaffected. Do not attempt to reverse
the deletion through a reset, overwrite, or other destructive operation.

The cleanup record is
`.lab/hyperv/checkpoint-cleanup-20261026T082155089Z.json`. The successful final
save record is
`.lab/hyperv/native-public-postcheck/win11-20261026T081420019Z/preserved-checkpoint.json`.
The earlier `checkpoint.json` in that directory has an empty ID because the
first save failed at the limit; `checkpoint-attempt-failed.json` records that
failure. It must never be represented as a successful checkpoint.

No additional export/copy is needed to establish this recorded checkpoint.
Before any later copy, propose its destination, estimated size and free-space
margin without deleting recovery points, filling the host disk, changing
security settings or spending money.

## Specifically approved independent fixture, 2026-10-26

Mike answered `1. Yes 2. Yes` to the exact fixed-reference deletion and named
offline-VM provisioning request. That approval was relayed by the project manager.
Only `D:\code\ntfs2refs\.lab\hyperv\corpus\devdrive-20261023T231918797Z\target-fixed.vhd`
was permanently deleted. A fresh current-file SHA-256 matched `b671d327...269b7`,
the retained packet matched `585df94c...23df5b`, and the exact full reconstruction
proof was reused without repeating its virtual scan. File identity/length,
exclusive-read availability, attachments and all registered VM/checkpoint chains
were checked before removal. Free-space reclamation was delayed; measured space
subsequently rose to about 143.5 GiB before the independent copy.

The new VM `ntfs2refs-reference-isolated` has ID
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`. It is powered off, generation 2, with fixed
8 GiB RAM, four vCPUs, no NIC and zero checkpoints. Existing vTPM and Secure Boot
configuration was preserved. Its three copied VHDX files have no parents, have
new single-link host file identities, and matched the freshly verified archive
hashes before any boot. Their container UUIDs remain copied from the archive;
they are not evidence of a shared writable backing file. No boot or credential
login was attempted, and no writer/native experiment was authorized or run.
Preserve this fixture and its evidence too.

Ownership is recorded at `.lab/hyperv/isolated-reference-20261026-review/manifest.json`.
Detailed authorization, preflight, deletion outcome, delayed capacity check,
archive hashes, import and final ownership records are under
`.lab/hyperv/reference-isolation-approved-20261026T130646790Z`.
The original VM retained the exact fifty checkpoint IDs and current checkpoint
listed above. This follow-up approval does not authorize additional cleanup or
retroactively authorize the earlier failed-leaf checkpoint deletion.

## Approved normal boot/read-only readiness, 2026-10-26

An initial start of the isolated VM failed before guest boot because Hyper-V
could not read the inherited Downloads ISO at DVD controller 0/location 3.
Mike specifically approved clearing that media path and one normal boot/login
retry. The DVD device and boot order remain. The post-ejection guard reported
an ISO SDDL difference; its pre-ejection SDDL was not saved, so its exact ACL
delta is not reconstructible from that record. No explicit ACL correction was
performed. After the follow-up approval, the ISO remained ejected and the single
retry succeeded without another permission change. The ISO ACL hash was equal
before/after that retry; this does not prove pre-ejection ACL preservation.

VM `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a` is now running with 8 GiB assigned,
four vCPUs, no NIC, vTPM enabled and Secure Boot On. One PowerShell Direct login
through that exact VM GUID used the approved existing credential. Only read-only
OS/build, driver, storage and integration queries ran; the session then closed.
The profile matched Windows 11 Pro 26300.9457 and the expected ReFS driver hash.
Guest disk 0 is the GPT OS disk, disk 1 the RAW 64 GiB target, and disk 2 the RAW
8 GiB journal. Neither data disk has a partition/volume enrollment or J: route.
No format, reference import, conversion or writer experiment was performed or
authorized by this readiness step. The original VM and all fifty checkpoint
identities were preserved.

The successful run is
`.lab/hyperv/isolated-reference-20261026-review/readiness-20261026T144625632Z`.
Use its normalized `binding-summary.json` for disk-role mapping and actual
resource margins; the provisioning hashes describe the images before boot.
Keep the earlier failure and ejection records as well.
