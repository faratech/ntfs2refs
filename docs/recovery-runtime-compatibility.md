# Qualifying a new recovery runtime against an existing journal

The laboratory recovery controller accepts an explicit schema-2 compatibility
toolset while retaining its original schema-1 path. The new public executable
is pinned separately from the actual historical producer. This allows recovery
qualification without creating another shadow, journal or conversion.

The compatibility manifest uses kind
`envelope-recovery-compatibility-toolset`, `source_commit_scope` equal to
`public-recovery-only`, and the new public runtime's source commit. Its producer
reference pins the unchanged original manifest, original source commit,
interrupted checkpoint, recovery directory and bundle checksum.

Each executable has explicit provenance:

| Role | Provenance |
|---|---|
| Public `ntfs2refs.exe` | New recovery-runtime revision and actual binary pin |
| Original fault executable | Original producer revision and original binary pin |
| Digest and managed-shadow helpers | Inherited bytes pinned by the original manifest; no invented build revision |

The host holds and rechecks both manifests and executable bytes. The original
manifest is staged unchanged. Guest checks bind the historical process PID,
creation identity, observed exit86, prepared-owner diagnostic and original
bundle to that producer. The new public binary is used only for recovery.
The observed action must be Resume or Rollback from actual ApplyIntent, and
the completed result must report actual exclusive recovery-journal use.
Checking a previously closed HND branch cannot satisfy this experiment.

This controller is restricted to the recorded e4ff source, interrupted
checkpoint `dea902f6-7d3f-49ba-86d2-27ce6dbe9516` and bundle `cd919acd…15f26`.
It neither reconstructs a source certificate nor manufactures old receipts.
All baseline, file/stream, namespace, security, selected-journal, device and
storage checks remain. Root alone owns VM restoration and checkpoints;
conversion and recovery still execute inside the owning guest.

Host/guest syntax checks and independent review pass. The public/fault release
build passes; native qualification of the new runtime is pending. The existing
8 GiB capacity experiment uses a separate fresh conversion entry and must not
inherit recovery-only qualification. No unit tests were added or run.
