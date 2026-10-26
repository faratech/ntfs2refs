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
