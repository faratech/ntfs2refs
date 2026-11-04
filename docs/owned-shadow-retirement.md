# Owned shadow retirement

The `b7d97fb` retirement primitive passed one native empty-image case. The probe
created a fresh 50 GiB Dev Drive shadow through `ManagedShadow`, retained its
constructor's provider and backing-file identity, isolated only that derived
disk, then released the raw owner before requesting retirement. Its actual
process exited 0 in 0.726818 seconds.

The original `CreateVirtualDisk` V2/`ACCESS_NONE` provider owner successfully
detached this permanent-lifetime attachment on the tested guest. Successful
provider queries observed `IS_LOADED` change from true to false. An exclusive
DELETE handle then revalidated the original volume/file identity, GUID path and
single-link ordinary-file state before deletion. The backing path was absent
afterward. A separate 4 KiB recovery sentinel outside the image retained its
identity, contents and path; metadata closure independently rechecked it.

This establishes the primitive's API behavior for this case. No NTFS conversion
or real V4 finalizer ran. The probe explicitly reports V4 integration as
unqualified; the normal conversion success path still needs its own native run.
The frozen 814 candidate is unchanged. Other attachment owners, sharing failures,
interruption behavior and general cleanup compatibility remain outside this
result.

The backing file reported 100 MiB of filesystem storage before isolation and
92 MiB immediately before deletion after provider closure. These are file-level
observations. Physical free-space reclamation, process/kernel RAM reduction and
conversion speed were not measured.

All 13 metadata/control files (97,323 bytes) were copied with source/host length
and SHA-256 verification. No executable, disk image or journal was copied. See
[the exact primitive evidence](../evidence/owned-shadow-retirement-primitive-20261104.json).
