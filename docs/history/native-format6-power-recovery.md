# Native format6 power recovery

Status at 2026-11-02 UTC: actual AP1 VM power interruption has passed separate
Resume and Rollback runs with runtime `7cd6870`. Both are archived and saved
after normal stop. HND1, RB1 and ABT1 also passed after actual VM power cuts.
These complete the four first-copy/missing-peer lifecycle cases. Qualification
of the final exact public build and the wider release scope remains open.
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

## HND1 closed-handoff power case

Root confirmed the closed, synchronized HND1 signal and the same live native
PID6104/birth1793595917550 before `Stop-VM -TurnOff`. Original checkpoint
`bfd2dfbe-b497-455d-95dd-9d7347145691` is a child of preparedcb802669. No original
native exit is claimed. The restarted process selected `verify_handoff` with
actual lifecycle `handoff`; it did not reopen raw target replay or permit rollback.
The native process PID1752/birth1793596303139 exited0 in10.2369122 seconds,
with1084 complete map bindings and the native metadata/namespace/storage checks.

Result checkpoint `2d62e6da-38b0-4c88-972d-750b1fc8eb31` is saved Off/RAM0.
The41-file/56804081-byte archive receipt is
`4cad6c65852ae60a94835434f7a87fed9f39093db18476e364d7297eaed8c3d6`.
See [the interruption](../../evidence/native-format6-HND1-power-interruption-20261102.json)
and [the closed verification](../../evidence/native-format6-HND1-power-recovery-20261102.json).

## Rollback-intent and abort-completion power cases

The new [pause adapter](../../lab/Start-NativeRollbackMarkerPause.ps1) starts an
explicit rollback from original AP1 checkpoint8d. Root cuts power only after
the selected RB1 or ABT1 copy has been flushed/read back and its closed32KiB
signal matches the actual live process twice. The
[nested recovery helper](../../lab/Start-NativeRollbackPowerRecovery.ps1) binds
both power receipts and checkpoint ancestry, keeping the original AP1 bundle
separate from the new paused producer's process/configuration/signal.

| Cut | Original checkpoint | Recovery | Saved result |
| --- | --- | --- | --- |
| RB1, PID5948/birth1793596998366 |291c825f-3368-4039-ace3-2d9fbf10cc11 |PID3868/birth1793597267167/exit0,9.6930208s; rollback/rollback_intent |450eb572-db48-470d-9921-ccd9976e74e6 |
| ABT1, PID3060/birth1793597984026 |83354c86-1103-4b0d-a99a-e23a8a78fdc8 |PID2488/birth1793598793045/exit0,6.7257683s; verify_aborted/aborted |0a3a2a49-44cd-45a0-8817-41767231d7b2 |

Both originals are children of8d, which is a child of preparedcb. Original
producer exits remain unobserved. RB1 continues rollback; ABT1 verifies the
already closed old state using `verified-rollback.json`, without target replay.
The42-file archives contain29668035 and29663283 bytes, respectively. Recorded
proof covers selected restoration, NTFS mount/label/path and closed barriers;
it does not claim a separate semantic/content rescan or restoration of free
space. The first-copy cuts exercise missing peers, not actual damaged-peer
bytes, failing Win32 I/O calls or physical storage power loss.

See the [RB1 recovery](../../evidence/native-format6-RB1-power-recovery-20261102.json)
and [ABT1 verification](../../evidence/native-format6-ABT1-power-recovery-20261102.json).

## Native and host guard changes

`ExclusiveRecoveryJournal::verify_closed_and_repair` keeps target access
`ReadSeek`-only. It verifies the committed target and actual HND/ABT, repairs a
matching terminal peer, then repeats the complete target/digest/lifecycle checks.
The native two-peer barrier still precedes online exposure. Rollback repairs an
authenticated existing AP peer after its complete mixed-target precheck and
before RB/payload writes. Public `verify_closed` remains read-only; legacy markerless closed verification
retains its original single pass.

The actual-power helper is
[Start-NativeMarkerPowerRecovery.ps1](../../lab/Start-NativeMarkerPowerRecovery.ps1),
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
separate [read-only native probe](../../lab/Get-NativeManagedShadowProviderProbe.ps1)
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
working `src/main.rs` hunk was subsequently committed unchanged with explicit
user approval at `b87867e`.

Actual AP1 evidence above belongs to 7cd binaries, not that newer candidate.
Qualify the final exact public binaries before any release claim. Commit
`7abadeb` makes production creation and recovery share one
plan-aware compiled gate. It remains false: public creation still selects the
legacy profile and public recovery still refuses format6. Empty source-free
plans and plans without the extra marker budget retain legacy eligibility;
the explicit lab profile remains strict. Commit `1316ac9` retains a typed use
policy in the actual owner and binds production qualification to the observed
NTFS journal geometry:4KiB clusters,512-byte logical and4096-byte physical
sectors, with matching actual FileStorageInfo. The global flag remains false.
The [backup-boot correction](backup-boot-restoration.md) also requires a final
build; the recorded fixture was already protected by its conservative tail.
Broader storage/hardware,
resource-scale and NTFS compatibility requirements remain open.
