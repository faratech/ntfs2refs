# Hyper-V lab

These scripts manage only the two disposable VMs recorded in `.lab/hyperv`.
They do not grant the Rust converter permission to write a filesystem. A passing
native ReFS control and a qualified writer remain separate research gates.

## Host checks and media

From the repository root:

```powershell
.\scripts\Invoke-Lab.ps1 -Action Status
.\lab\Test-Lab.ps1
.\scripts\Get-IsoImageInfo.ps1 -IsoPath 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso'
.\scripts\Invoke-Lab.ps1 -Action Media -IsoPath 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso'
```

`Get-IsoImageInfo` reads the install WIM's header and XML through 7-Zip binary
stdout; it does not mount the ISO or extract its multi-gigabyte install image.
The supplied ISO was verified as build **10.0.26300.9457**. Image index **6** is
Windows 11 Pro; index **10** is Pro for Workstations. The latter may be useful
as a separate native ReFS formatting control, but must not be reported as Pro
compatibility. Image metadata does not certify the build after servicing.

`Media` records SHA-256, length, image metadata, setup executable version and
signature status. Only the small root `setup.exe` and an ISO directory listing
are extracted. Records and binaries are stored under the ignored `.lab` tree.
The original ISO stays in Downloads.

Hyper-V operations need an authorized administrative session. The research
session could read host facts but `Get-VMHost` was denied. The following dry run
works without those rights:

```powershell
.\scripts\Invoke-Lab.ps1 -Action Create -Lane win11 `
  -IsoPath 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso' -WhatIf
```

## Provisioning

Run the reviewed command from an elevated PowerShell session:

```powershell
.\scripts\Invoke-Lab.ps1 -Action Create -Lane win11 `
  -IsoPath 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso'
```

`Create` leaves the VM powered off and installs no OS itself. The separate
`scripts/Install-LabWindows.ps1` workflow installs the owned OS VHD. The Server
lane uses the same provisioner with `-Lane server -IsoPath <official ISO>`;
missing Server media does not prevent creating the Windows 11 lane. Use a
current unexpired Server Insider build supporting ReFS boot and record it.

The configuration is in `lab.config.json`: Generation 2, Secure Boot with the
Microsoft Windows template, vTPM, fixed 4 GiB RAM, four vCPUs, disconnected NIC,
64 GiB OS and target VHDXs, and an 8 GiB journal VHDX. VHDXs are dynamic. Only one
lab VM may run at once. The preflight limit is 180 GiB of actual lab files with
64 GiB left free on the host. This is checked before operations; it is not a
Windows storage quota. Check capacity between guest workloads as well.

Ownership is established by a manifest containing VM ID, configuration path,
VHD ID/size, and SCSI attachments. The harness walks checkpoint parent chains
back to the recorded VHDs. A coincidentally matching VM name is insufficient.
Paths must remain below the lab root and must not traverse reparse points.
An interrupted provisioning directory is left intact for inspection and is
never automatically deleted or adopted.

## Checkpoints and recovery

Create checkpoints only after a clean guest shutdown:

```powershell
.\scripts\Invoke-Lab.ps1 -Action Checkpoint -Lane win11 -CheckpointName installed-clean
.\scripts\Invoke-Lab.ps1 -Action ExportBaseline -Lane win11 -CheckpointName installed-clean
.\scripts\Invoke-Lab.ps1 -Action Start -Lane win11
# After preparing fixtures, shut down the guest cleanly.
.\scripts\Invoke-Lab.ps1 -Action Checkpoint -Lane win11 -CheckpointName fixtures-ready
.\scripts\Invoke-Lab.ps1 -Action Checkpoint -Lane win11 -CheckpointName before-conversion
```

All snapshots are Standard checkpoints with automatic checkpoints disabled.
`Stop` requests a normal guest shutdown; it does not inject a hard power loss.
Crash injection should be added only when the conversion journal is tested.

Copy evidence out of the guest before restoring. PowerShell Direct can transfer
logs from an installed Windows guest without networking; it is not assumed to
work in WinPE. Once logs are in a local host directory outside the lab tree:

```powershell
.\scripts\Invoke-Lab.ps1 -Action ExportLogs -Lane win11 -LogSource 'D:\captured-run-logs'
.\scripts\Invoke-Lab.ps1 -Action Restore -Lane win11 -CheckpointName before-conversion -WhatIf
.\scripts\Invoke-Lab.ps1 -Action Restore -Lane win11 -CheckpointName before-conversion
```

Restore requires a powered-off VM and one exact checkpoint name. Attached
journal disks revert with the VM. Keep the exported clean baseline; a checkpoint
is not an independent backup. Never delete AVHDX files directly.

## Native data controls inside a guest

Copy `lab/guest` to the guest, for example with PowerShell Direct. Scripts must
run in the disposable Microsoft Hyper-V VM as an administrator. Enumerate
`Get-Disk | Select Number,UniqueId,SerialNumber,Size,Location,IsBoot,IsSystem` and
cross-check SCSI location against the host manifest: location 1 is the target,
location 2 the journal. Enrollment records the observed UniqueId, serial, size,
and location. It accepts only a blank RAW disk of the configured role's size.

```powershell
.\Register-GuestDisk.ps1 -UniqueId '<observed target UniqueId>' -Role target -OutputPath C:\lab\target.json
.\Register-GuestDisk.ps1 -UniqueId '<observed journal UniqueId>' -Role journal -OutputPath C:\lab\journal.json
.\Prepare-GuestControl.ps1 -ManifestPath C:\lab\journal.json -Action FormatNTFS -Confirm:$false
.\Prepare-GuestControl.ps1 -ManifestPath C:\lab\target.json -Action FormatNTFS -Confirm:$false
.\Prepare-GuestControl.ps1 -ManifestPath C:\lab\target.json -Action Fixtures -Confirm:$false
.\Capture-GuestEvidence.ps1 -ManifestPath C:\lab\target.json -OutputPath '<journal drive>:\ntfs-evidence.json'
```

Create the blank checkpoint before formatting. Restore that checkpoint and use
`FormatReFS` to create a native ReFS control from the same blank disk. Formatting
an already initialized disk is refused. Failure to format on a particular SKU
is recorded as a compatibility result; scripts do not set hidden registry
switches automatically.

Fixtures cover resident/empty/nonresident streams, ADS, hard links, symbolic
links, sparse data, Unicode names, and an explicit ACL. Evidence contains stream
hashes, SDDL, file IDs, attributes, timestamps, native volume information, and
driver/build versions. Missing privileges and inaccessible files are recorded.
The evidence collector does not claim complete raw EA/reparse coverage and
does not follow reparse points recursively.

## Boot controls and qualification

First prove stock NTFS boot for each exact build. Then test a separately prepared
native ReFS OS volume with the same signed components. Keep the FAT32 ESP and
NTFS WinRE partition; ReFS OS conversion does not mean formatting every partition
as ReFS. Windows 11 native ReFS boot remains experimental until demonstrated.
Server success does not qualify Windows 11, and a data-volume mount does not
prove that the boot manager and loader can read ReFS.

During future conversion experiments, boot matching recovery media first and
keep the target unmounted until offline verification and `finalize`. Merely
removing a drive letter is insufficient. Before the first writable ReFS mount,
the converter's journal provides resume/rollback; after handoff use the VM
checkpoint. No recovery or conversion command should be run against host disks.

References: [Microsoft checkpoints](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints),
[Server ReFS boot](https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-boot-windows-server-unattend),
[PowerShell Direct](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-windows-virtual-machines-with-powershell-direct),
[WIM header format](https://github.com/ebiggers/wimlib/blob/master/include/wimlib/header.h).
