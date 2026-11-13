# Release readiness

The current published build is [0.0.1-alpha](https://github.com/faratech/ntfs2refs/releases/tag/0.0.1-alpha),
a private experimental Windows x64 release. Its original Windows boot-volume
conversion and desktop result are documented in
[the release qualification](release-0.0.1-alpha.md).

The older readiness notes are preserved verbatim in
[the pre-closeout archive](release-readiness-before-boot-alpha-closeout-20261111.md).
Their statements that boot conversion is deferred refer to earlier builds.

## Closeout scope

- Preserve the existing source/binary archives and their hashes.
- Recover and retain original qualification output with explicit provenance.
- Make current operating instructions agree with the release.
- Pass the existing Windows CI and integrate the reviewed branch into main.

The release executable remains unchanged during this closeout. Source formatting
and documentation changes do not replace or silently requalify that executable.

## Qualification limits

The recorded success is one Windows 11 build and one Hyper-V configuration.
Broader hardware, operating-system versions, BitLocker, partition layouts and
scale need separate qualification. The existing single-VHDX construction backend
also does not establish the earlier arbitrary-size goal.

The recovered evidence distinguishes a full conversion and independent listing
comparison from the separate post-apply recovery observation, whose original
before-listing was unavailable. There is no claim of exhaustive physical
power-loss coverage or universal rollback.

Visible short-name links and the executable's internal `0.1.0` version are
known, documented properties of the `0.0.1-alpha` package. Any change to the
executable is a new candidate and must receive its own evidence.
