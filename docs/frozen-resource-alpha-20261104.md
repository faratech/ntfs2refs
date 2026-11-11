ntfs2refs — frozen 814 experimental native-shadow alpha

Source: 814f380aa38be4d94e2a71ad221c779e5ab4dc7b
ntfs2refs.exe SHA-256:
0f5be1c72b05ff030aad85b21be2c37f32ecccbf214af1ee4d6f7afd4807fafb
Build manifest SHA-256:
ea6d55adaa40b1bf2bfd04cb7842bdef63b9cbffb0f038697d23ae9330af8f64

This is an experimental Windows data-volume converter. The observed 814 case
converted a dedicated basic GPT NTFS data volume with 64 KiB clusters to native
ReFS Dev Drive with 4 KiB clusters in the Windows 11 lab profile. Reboot and subsequent
file mutations were checked. This does not establish arbitrary-hardware,
filesystem-feature, size or physical-power-loss qualification.

Run in an elevated Windows terminal on the machine owning the source disk.
Hyper-V is lab infrastructure; the product does not require a VM. This build
requires a dedicated nonboot data disk separate from the running Windows disk.
Boot/system conversion and a D: partition sharing the C: disk are outside this
build's conversion profile. Use backed-up, disposable data for this alpha.

Select the source

  .\ntfs2refs.exe --list
  .\ntfs2refs.exe --drive D
  .\ntfs2refs.exe --drive D --partition 2 --minimize-scratch

D and 2 are examples: take the actual letter and partition number from --list.
A supplied partition number must agree with the letter's current partition.
The program shows the selected source and target format, then asks [y/N].
Only y or yes starts the workflow; declining does not start conversion.
After confirmation, staging, inspection and resource planning run before
conversion activation. Placement preparation can move files through NTFS.
Unsupported source state or insufficient resources causes refusal/error.

Working space and verification

The default target is the experimental Dev Drive ReFS profile. The real option
--target-format standard requests ordinary ReFS only where Windows can format
it; an unsupported format never silently falls back to another profile.
The standard profile is not qualified by the observed Dev Drive case.

Working and recovery files use the Windows OS volume on a different physical
disk from the source. The default parent is %SystemDrive%\ProgramData\ntfs2refs\runs.
To choose another ordinary parent on that same OS volume:

  .\ntfs2refs.exe --drive D --partition 2 --minimize-scratch --scratch-directory "C:\ntfs2refs-work"

Use the actual Windows OS drive if it is not C:. There is no --work-dir option.
The dynamic shadow represents the source address space; its allocated backing,
journal, metadata and rewritten data still need real free storage. Resource
plans reserve observed disk space and RAM; no fixed scratch percentage or
duration is guaranteed. NTFS-compressed streams require space for decoded data.

Allocation-bounded writes and extent-identity fast verification are defaults.
--minimize-scratch further reduces recovery storage; rollback then restores
allocated NTFS data/metadata, while unused-space bytes may change. This option
refuses VSS snapshots/hosted diff areas. --verify-full-content requests complete
logical-stream hashing. --whole-image-verification compares/journals complete
images. Those slower modes cannot be combined with --minimize-scratch.

Recovery

Save the exact printed recovery directory and checksum outside the source.
Keep the entire original run directory, including shadow, journal, backing and
recovery metadata, available until conversion or recovery is resolved. A saved
checksum alone is insufficient. An interrupted source can deliberately remain
offline/read-only; use recovery rather than manually clearing its exclusion.

Replace the directory and SHA placeholder below with the original printed pair:

  .\ntfs2refs.exe --recover "C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion" --recovery-sha256 ORIGINAL_PRINTED_SHA256

To restore NTFS before the irreversible handoff:

  .\ntfs2refs.exe --recover "C:\ProgramData\ntfs2refs\runs\RUN_ID\conversion" --recovery-sha256 ORIGINAL_PRINTED_SHA256 --rollback

Recovery asks for confirmation and verifies actual devices and protected state.
If only a Preparation recovery path and Preparation SHA-256 were printed, use
that file's containing directory and its preparation SHA with --rollback;
unfinished preparation can be cancelled, not resumed as a conversion.

The durable handoff marker (HND) closes old raw replay and NTFS rollback. After
handoff, normal recovery can reconcile the terminal ReFS state; it must not
replay the old journal over a filesystem already used through ReFS. Keep failure
records and resolve a refusal instead of substituting a new checksum or route.

Scale boundaries

The present shadow backend is one VHDX, limited to 64 TB virtual size. The source
partition plus its 64 MiB staging margin must fit that backend. A 1,000 TB source
is not supported. Large-cluster parsing does not establish conversion support:
extent-fast evidence currently covers 4–64 KiB clusters, while larger parsed
geometries fall back to logical hashing and remain unqualified. Other geometry,
Windows-build and feature combinations need their own native qualification.
There is no conversion-time guarantee.
