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
unqualified. A separate public run below now exercises the V4 success path.
The frozen 814 candidate is unchanged. Other attachment owners, sharing failures,
interruption behavior and general cleanup compatibility remain outside this
result.

The backing file reported 100 MiB of filesystem storage before isolation and
92 MiB immediately before deletion after provider closure. These are file-level
observations. Physical free-space reclamation, process/kernel RAM reduction and
conversion speed were not measured.

All 13 metadata/control files (97,323 bytes) were copied with source/host length
and SHA-256 verification. No executable, disk image or journal was copied. See
[the exact primitive evidence](../../evidence/owned-shadow-retirement-primitive-20261104.json).

The separate `b7d97fb` public conversion used
`ntfs2refs --drive F --partition 2 --minimize-scratch` and exited 0 in
753.764701 seconds. Native finalization matched 2,558 map/metadata bindings,
hashed 157 known streams covering 119,009 bytes, retained extent-only evidence
for 654 streams, restored the original label/mount paths and closed HND.
After that real success return, retirement observed loaded true to false and
the constructor-owned backing path disappeared. This qualifies that integration
path on this fixture, beyond the empty-image primitive alone.

Closure independently resolved the preserved journal from the framed locator,
checked its file identity, volume and 181,991,240-byte length, and matched its
canonical 4 KiB HND marker to the locator ticket. It did not hash journal payload
or authorize replay. All 11 selected metadata files (666,871 bytes) were copied
with source/host length and SHA-256 checks.
The shadow's recorded allocation changed from 740 MiB before detach to 712 MiB
before deletion; these remain file-level observations, without a physical-space,
RAM or speed improvement claim. See
[the public integration evidence](../../evidence/public-owned-shadow-retirement-20261104.json).

Independent observers subsequently matched all 811 original XXH3-128 streams
(9,885,801,949 logical bytes), 1,534 baseline namespace/type/length objects and
all 1,024 additional UTF-16 directory paths against their original manifests.
Both the initial observation and the observation after a normal shutdown/start
completed 13 actual digest processes with owned PID/birth/exit-zero records.
Their digest passes took 11.6056366 and 11.5205084 seconds. The reboot used no
checkpoint or restore; the new boot was independently identified and F: was
operational ReFS after retirement. Each observer's 56 metadata files were closed
and source/host length/SHA-256 checked (106,462 and 106,467 bytes).

These observers establish retained contents and the stated namespace checks
before and after that reboot. They do not repeat a complete ACL/SACL/timestamp
audit or claim absence of every possible extra original-tree object. This case
also does not qualify a post-retirement mutation workload, AP interruption,
power loss, physical hardware, petabyte storage or a general stable release.
