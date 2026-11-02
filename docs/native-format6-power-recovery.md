# Native format6 power recovery

Status at 2026-11-02 UTC: actual AP1 VM power interruption has passed separate
Resume and Rollback runs with runtime `7cd6870`. Both are archived and saved
after normal stop. HND, RB and ABT power cases and qualification of the final exact release build remain open.
This is bounded owning-guest evidence, not hardware power-loss qualification.

## Actual interrupted state and results

The original producer was PID6000/birth1793589066968. After its actual AP1 write,
flush, uncached readback and storage revalidation, it closed the synchronized
32768-byte signal and parked with its owners retained. Root twice observed the
same live PID/birth and Running task before intentionally issuing
`Stop-VM -TurnOff`. No original native exit is claimed. The fresh Off/RAM0
checkpoint is `8d4192fe-003b-441f-8591-f0b271028841`, parent preparedcb802669.

The actual-power checkpoint receipt is under
`.lab/hyperv/streaming-v2-20261027/native-power-ap1-1495314df50e4df2bb76f74a0910da1b/checkpoint.json`,
SHA256 `8d63cbc34214475e8ceb51989b760137c8ab4bc3d2d7f6ff037a6ad7e7debc69`.
It pins the original process, closed signal, bundle, ticket and routes, without
fabricating controlled exit86 or fresh source authority.

| Direction from original8d | Native process | Actual result |
| --- | --- | --- |
| Resume `05572eb503ac4ca3bf5c4d1bec8eb19e` | PID3064/birth1793594871253/exit0;16.2593027s | HND/ReFS;1084 complete map bindings and built-in metadata/namespace/storage checks |
| Rollback `852e5069c4754f0987b5d23058974fbe` | PID2588/birth1793595236914/exit0;11.6591231s | ABT/NTFS;142004224 restore-required bytes, selected digest matched |

Both used the actual format6 `N2RFRE02` journal, 131175520 bytes, with 544673792
selected bytes. Resume verified 650 partial streams/1371388 tail bytes. Rollback
digest is `4a5cf5bcea90705f78e4546191954fc973fae7f2dfc643e22039fd237f0b6914`;
it does not claim restoration of formerly free contents. Neither run added an
independent 811-stream full-content scan. Process peak RAM remains unobserved.

Resume is saved Off/RAM0 at `fccec765-f271-4dd5-88c6-6e6e5bd29181`, parent8d.
Its 42-file/56785150-byte closed archive has receipt SHA256
`5da19ce805629cf9456215afe96888b60b234916053fc3412b35176cba7297a1`.
Root restored original8d separately for Rollback; never replay either result's
closed HND/ABT. Rollback's 40-file/29649071-byte archive has receipt SHA256
`531d904623d9911d75ebda89c34f0f9a3628abf7ea244ded0b7456f6fd2dbdd0`.
The current VM is fresh-confirmed Off/RAM0 at Rollback checkpoint
`44c0074b-b5c4-4614-b957-a96842436cbf`, parent8d, 20 snapshots.

## Native and host guard changes

`ExclusiveRecoveryJournal::verify_closed_and_repair` keeps target access
`ReadSeek`-only. It verifies the committed target and actual HND/ABT, repairs a
matching terminal peer, then repeats the complete target/digest/lifecycle checks.
The native two-peer barrier still precedes online exposure. Rollback repairs an
authenticated existing AP peer after its complete mixed-target precheck and
before RB/payload writes. Public `verify_closed` remains read-only; legacy markerless closed verification
retains its original single pass.

The actual-power helper is
[Start-NativeMarkerPowerRecovery.ps1](../lab/Start-NativeMarkerPowerRecovery.ps1),
SHA256 `df88c9d563d1abc488e67322c966dcaced0a332936490e83fc14658193ed2def`.
It checks the actual-power receipt, original process/argv, closed signal and
artifact pins before native recovery. SYSTEM preflight and main execution use
the same strict route checks. The main process retains its owned child handle,
drains raw logs concurrently and records the actual exit. Three PowerShell
`[ulong]` casts were corrected to PS5-compatible `[uint64]`; parser success alone
had not caught that pre-native failure. Earlier failures remain preserved.

For an absent original shadow, each caller validates a complete six-disk
inventory with known unique GUIDs, no original shadow GUID and no disk6. It
acquires one ordinary backing `FileStream` with Read/FileShare.None and retains
that actual handle through native recovery and terminal checks. Reentrant checks
reuse the same private owner and verify same-handle file ID/volume/length/mtime,
ordinary ancestry and a fresh identical validated inventory. Preflight and main
own separate handles and separately pinned diagnostic receipts. The absent image
is not read or used by self-contained allocation recovery. Its VHDX creator ID,
virtual geometry and log state are explicitly unqueried. Present-shadow checks
still require the exact attached provider and offline/read-only native binding.

Earlier `Get-DiskImage` queries returned AccessDenied even under SYSTEM. The
separate [read-only native probe](../lab/Get-NativeManagedShadowProviderProbe.ps1)
also returned actual `OpenVirtualDisk` error5 with all later queries unknown.
Those errors never establish absence. Raw headers showed a nonzero LogGuid,
consistent with a replay requirement, but their CRCs were not validated and the
cause of error5 is not established. No replay, attach, ACL, attribute or privilege
change was used to bypass that refusal.

## Release boundary

Commit `378860e` memory changes passed focused compilation. Separately, the
offline candidate `r378860e-c` successfully built six binaries from 283 clean
committed source files at `378860eb4356cb576a73213eed72a675032df906`.
Its manifest SHA256 is
`cbf9c8d8b328e7a6aa8cd42e62c895ce6f40e2c6c2fc53707565bde84a1091f3`;
workspace observation was 517209397 bytes. It used no working-tree source inputs,
ran no unit tests/native tools and inherits no qualification. The protected
working `src/main.rs` hunk remains unchanged and unstaged.

Actual AP1 evidence above belongs to 7cd binaries, not that newer candidate.
Complete HND/RB/ABT power cases and qualify the final exact binaries before any
release claim. Production creation still selects no marker profile; production
recovery still refuses format6 outside the explicit lab route, and
`MARKER_STORAGE_NATIVE_QUALIFIED` remains false. Broader storage/hardware,
resource-scale and NTFS compatibility requirements remain open.
