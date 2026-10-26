# Semantics of the exact frozen target

The public admission path now freezes the ReFS shadow before its authoritative
semantic observation. `general_target_preservation::verify_frozen_tree` hashes
the complete frozen partition, observes the full expected native tree while the
physical disk remains read-only, returns it to offline/read-only, and hashes the
complete partition again. Both hashes and the original excluded-device state
must match. Placement is derived from this protected report.

The native operation returns a non-deserializable `GeneralLiveRefsObservation`.
It is issued only through an actual retained read-only volume handle and a
checked attributes `3 -> 2 -> 3` transition. Protected object handles omit
write-attributes access and the verifier issues no timestamp setters. Ordinary
writable shadow construction and the existing NTFS observation remain separate.
There is no fallback to the earlier writable report if protected verification
fails. Serialized reports do not issue this witness.

This closes the writable verification-to-freeze interval in target admission.
It does not prove a complete raw ReFS ownership graph, selective write-set
safety, arbitrary-volume compatibility or direct-writer acceptance.

## Native evidence

The standalone `lab-verify-frozen-refs` command exercises the same helper used
by admission. It verified all twelve objects of the saved native ReFS shadow,
including the 128 MiB file and both Windows cache files. Namespace, logical
hashes, measured mappings, basic metadata and both security views passed.
The actual disk attributes were 3 before, 2 during observation and 3 after.
The complete before/after partition hash was unchanged:

`f49b63207fb01c639ca0816ce7049da3233cd8d23d0dd7d0ed670552c4f45f0e`.

The expected semantic manifest SHA-256 was
`9655d3160e8f884ca326db522252094a6cfeb28a874debbd29accce2fee7b60f`.
The observer exited 0 and left the shadow offline/read-only. This is a native
qualification of the protected semantic helper; it is not a fresh complete
NTFS conversion through the newly integrated path.

Ignored evidence directory:
`.lab/hyperv/protected-target/win11-20261026T005646691Z`.

- Observer executable SHA-256:
  `47fbb9f9ebdebf0516cdfa1398d6d56270e1b73f802bdc76b5369dee1dd4e5ba`.
- `protected-semantics.json` SHA-256:
  `37202774e39f1d8149137283055de763a808b2a7aeefe75d47d8bf64ba73b680`.
- `result.json` SHA-256:
  `514c47f16c47389f332075da327de9390d9f8e884080a938c3f106b0cc6d8760`.
- Windows 11 Pro build 26300.9457; `refs.sys` file version 10.0.26100.8875,
  SHA-256 `3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4`.

The saved image changed during its earlier writable reattachment and ordinary
freeze, before this observation began. No claim equates this hash with the
older conversion shadow hash. The qualification binds the exact new frozen
image to the protected semantic report.

Two focused tests independently reject a late byte change after semantic
observation, a truncated final image and a failed semantic callback. Native
guards retain the normal writable-path requirements and refuse malformed or
wrong-state read-only capabilities.

The later controlled first-write producer exercised this helper in the actual
qualification path. Its complete target hash was unchanged across observation,
all twelve expected objects passed and live source admission issued a device-bound
certificate before activation. That producer intentionally exited after the first
flushed target write and was recovered by public shadowless rollback. It qualifies
the integrated admission stage, rather than a fresh complete ReFS conversion or
automatic label restoration. See [the exact run and pins](general-native-conversion-results.md#public-shadowless-rollback-after-one-flushed-write).
