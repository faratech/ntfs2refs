# Next Windows 11 native controls

Research/design, 2026-10-23. These are proposed experiments, not measured
outcomes. The ordinary `NativeFormatCom` experiment was running when this
document was written. Do not modify its scripts or VM configuration in flight.

Subsequent direction: the Dev Drive data control passed, and the user deferred
OS boot experiments to prioritize same-partition in-place NTFS-to-ReFS conversion.
The PE/OS alternatives below remain future research, not the current work queue.

## Recommendation

If stock `format.com` also refuses ordinary ReFS, use a separately named **Dev
Drive data control** for the fastest native ReFS corpus opportunity. Continue
ordinary OS preparation through a **same-ISO WinPE control** separately. Neither
result substitutes for the other or for conversion/boot qualification.

Dev Drive has a documented native command-line path on all Windows 11 SKUs
from build 22621.2338. The published requirements include 8 GB RAM and at least
50 GB storage. Microsoft documents `Format-Volume -DriveLetter D -DevDrive`
and `format D: /DevDrv /Q`. The current 4 GiB VM and 1 GiB control do not meet
those requirements. [Microsoft Dev Drive guide](https://learn.microsoft.com/en-us/windows/dev-drive/)

## Smallest Dev Drive implementation

1. Require the owned VM off at `installed-clean`. Record the original 4 GiB
   memory setting, set only this experiment to 8 GiB, and restore/check that
   setting after the experiment. Keep the existing disk identities and
   disconnected network.
2. In the authenticated Pro guest, record `fsutil devdrv query` and the native
   formatter's help, version, signature and hash. Refuse an explicitly disabled
   or policy-blocked configuration; this experiment needs no policy mutation.
3. On the enrolled blank 64 GiB target only, create a GPT data partition of
   52 GiB with 4 KiB clusters. Revalidate disk identity, partition offset/size,
   volume binding and blank state immediately before the one format request.
   Use the documented `-DevDrive` parameter after checking it exists in the
   installed cmdlet. Preserve full output/errors and the exact invocation.
4. Record filesystem geometry and `fsutil devdrv query <letter>:`. Keep the
   native designation and filter/trust policy unchanged. Write a bounded,
   deterministic small-file fixture and collect logical hashes/identities.
   Close all handles, shut down cleanly, restart the existing NTFS OS, and
   compare the fixture and Dev Drive observations again.
5. Export allowlisted evidence with hashes, shut down, then restore baseline
   and its memory configuration. Initially this is a format/remount control;
   mark raw corpus, ordinary format, OS boot and conversion qualification false.

The query exposes designation, trust and filter observations. Untrusting a
volume changes its filter policy; it does not establish that the original
format was ordinary ReFS. [Microsoft fsutil devdrv reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-devdrv)

Raw capture is a separate implementation step. `Capture-RawControl.ps1` currently
has a fixed 1 GiB limit and writes to the 8 GiB journal disk. Do not truncate a
52 GiB partition or label a prefix as a whole-volume image. Options are a
separately enrolled sufficiently large export disk, or an explicitly verified
sparse logical-image capture that still reads and hashes every source byte.
Both require new capacity checks and tests; VHDX container bytes are not raw
partition bytes. A small range capture can support individual observations but
cannot qualify allocator or checkpoint completeness.

## Same-ISO WinPE ordinary-format path

The supplied ISO's `boot.wim` PE and Setup images report 10.0.26100.9457, while
the installed Pro image reports 10.0.26300.9457. Retain both versions, selected
WIM index, original ISO hash, and actual component hashes in provenance. A PE
result is a different formatter environment even though the ISO is shared.

WinPE supports Win32 applications, DiskPart and BCDBoot; PowerShell is optional.
The published overview does not promise ReFS formatting in this particular PE
image. Inspect available tools and `refs.sys` first, then measure the native
result without importing drivers from another image. [Microsoft WinPE overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11)

Do not reuse the existing PowerShell Direct transport by assumption. It requires
a running guest with a configured user profile and valid guest credentials;
the stock PE image has not been qualified for this transport. PowerShell support
requires optional components, and their architecture/build must match the PE
image. No matching WinPE add-on is currently present.
[PowerShell Direct requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct),
[WinPE PowerShell setup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-adding-powershell-support-to-windows-pe?view=windows-11),
[Optional-component matching rules](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-add-packages--optional-components-reference?view=windows-11)

An automation path without those packages is a separately reviewed native
user-mode lab helper launched by a custom `Startnet.cmd`, with `wpeinit` first.
Use a workspace copy of PE, retaining Microsoft boot/driver binaries and Secure
Boot. Microsoft documents startup-script customization and flat deployment of
PE via DISM and BCDBoot. The existing blank journal VHDX could serve as a
temporary PE boot/evidence disk in its own checkpoint branch; this requires a
new explicit role/partition contract, not reuse of the current journal format
assumptions. [Startup scripts](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wpeinit-and-startnetcmd-using-winpe-startup-scripts?view=windows-11),
[Flat WinPE deployment](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-install-on-a-hard-drive--flat-boot-or-non-ram?view=windows-11)

The helper must bind a per-run manifest to the enrolled target's device identity,
GPT GUID and partition geometry, refuse ambiguity/boot-disk selection, and
bound process time/output. Begin with inventory plus read-only DiskPart
`filesystems`; then attempt only ordinary ReFS on the blank target partition
using PE's own `format.com`. Keep its exit status and actual filesystem result.
Use the reviewed 4 KiB allocation request; Microsoft lists it as a valid ReFS
format size. [Format reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/format)

Persist logs to the independently bound evidence partition and shut down via
stock `wpeutil`. Export and hash logs before restoring the checkpoint. Missing
completion or export failures must preserve the branch for inspection. Only a
successful ordinary format should lead to a second reviewed phase that applies
the original Pro WIM and prepares its signed boot chain; do not transplant PE
or Server boot components into the installed OS.

The Dev Drive experiment is the smaller implementation because the current
guest transport and native evidence code already work. The PE path has more
setup work but answers the ordinary-format deployment question directly.
