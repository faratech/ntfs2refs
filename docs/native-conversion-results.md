# First native extent-preserving conversion result

On 2026-10-24 the prepared one-file NTFS fixture was reconstructed as ReFS on
the same guest partition. Microsoft's ReFS driver then mounted it read-only and
returned the original NTFS file bytes. Preparation, raw reconstruction, handoff
and native filesystem observation all ran inside the Windows 11 VM. Hyper-V
provided checkpoints and evidence transport.

This is an experimental fixture result. Source and shadow extents were
deliberately positioned before the frozen conversion input was captured. The
general CLI still refuses conversion; arbitrary existing file trees, a standalone
ReFS serializer and production recovery remain unfinished.

## What passed

The original target GPT disk/partition identities were preserved. The 52 GiB
partition received 130 journaled patches totaling 69,451,776 bytes. The retained
64 KiB extent at partition offset 8,589,934,592 was excluded from every write.
The complete reconstructed partition matched SHA-256
`57b3fc2fb836c4091efd331e84b9c25488beff2af46886a45a86554e81a25443`.

After durable handoff, the guest detached the shadow and proved it absent. It
then brought the original target online with persistent read-only protection.
Independent native device queries confirmed write protection. Microsoft's
driver exposed ReFS and the expected file identity/metadata.

The observer made two 65,536-byte logical reads, separated by a handle reopen,
and captured four stable native snapshots. Both reads returned SHA-256
`a8da4df80396fc29486e0cba10fb7525404e8fd56169e6885475789b10f31bb3`,
the original source A hash. The shadow B hash was different:
`d66b3369b58ea23563d72c1593b173fcb14dbd9899a14ef6a2c3d40c5518b584`.
The checks covered the retained physical mapping, cached/storage validity,
integrity policy, security, timestamps, namespace and native disk identity.
Observation issued no target writes or protection changes. Cleanup and security
privilege restoration completed.

## Authoritative artifacts

| Phase | Host case | Host result SHA-256 |
| --- | --- | --- |
| Prepare | `native-reconstruct/prepare-20261024T052030708Z` | `a03b4228a520e76edc8e57c3edfd3e5295ed2d5938e4f426ff7c1544894cc76f` |
| Apply | `native-reconstruct/apply-20261024T054132656Z` | `111405c2a5239b1f4a76ef04fd909354e9a9673699554b3b4da1747760326610` |
| Handoff | `native-reconstruct/handoff-20261024T055719130Z` | `e1048284f3729f00720394c69c63670267392fb338205082125de29a60f0dbe1` |
| Native observation | `converted-verification/win11-20261024T061408952Z` | `ea53249c0f49be778a25cfa3aa2f7e3377ece25a874fc5c04e5ccc13dd40ac13` |

Paths are relative to ignored `.lab/hyperv`. The native observation artifact is
pinned by `2fc05009cd0b9c90f05ae23808be994e5d30d565c8bd440230f346b03cdefb5f`;
the mount artifact by
`134c384b01123b8ce6b3d472a6b0c031f0857ba402df25fc0d08f3ac044bb04f`.
The independent journal ticket remains
`dd65983e8b73227bdad8eb649f10d58f9c0d1995b43a207b53c414a6d341816f`.

The saved converted checkpoint is `e7fda999-ad2e-4792-9011-e9b4fdaebf21`,
named `converted-readonly-680c2833521a458b92560bf1dd1fd604`. The VM was returned
to installed-clean, powered off with 4 GiB memory. All four host phases have
known completion and no preserved/unknown session.

## Remaining acceptance work

The clean reboot/remount passed as recorded below. Next test a controlled native
allocation/mutation workload that preserves A and its ownership. Native power
loss, journal recovery, tree growth and arbitrary-source admission remain
unqualified. The current construction uses metadata produced in a native ReFS
shadow; [REFSNT writer evaluation](research/refsnt-writer-evaluation.md) is a
separate research path. These results do not establish a general no-recopy or
low-scratch converter, and boot conversion remains deferred.

## Clean reboot and remount passed

Case `converted-verification/win11-20261024T064141050Z` restored the saved
converted checkpoint, booted Windows, and observed the persistently read-only
target through Microsoft's driver. It did not reattach the shadow, invoke the
first-mount boundary, reconstruct the target or change its protection.
The old mount artifact was authenticated as historical provenance; the native
observer independently rechecked the live disk, partition, volume and file.

Both new 64 KiB reads returned the original A hash. Four new snapshots were
complete and stable, covering mapping, validity, timestamps and security.
Native cleanup and privilege restoration completed, followed by a clean
shutdown, a new checkpoint and restoration of the off-state 4 GiB baseline.

| Remount artifact | Binding |
| --- | --- |
| Host result SHA-256 | `a84cf8826fbfea4f081a8ad0dfb4e76fa776bb071bf8e0958bc71b97445bf18c` |
| Native evidence SHA-256 | `e79247b1e94771a32f23a9059d2cd8a9aa9d3d2557c013dba2cac6ae51c6e936` |
| Input SHA-256 | `8752a078df0210782b9a23360593b9d732fe39c3203a7e2e40192d90974aae9f` |
| Runner SHA-256 | `968318fee5793a3de2c74e2d1524d4533c74c12b17ccb114b5bd7df8727dae7f` |
| Reviewed manifest SHA-256 | `c9a0b96919e63ca3cda8b1cb8e6b466558a17e52ca16e2acfef4198cabd37f71` |
| Checkpoint ID | `8a87b135-d133-4eb1-a326-b6fa65cfc085` |
| Checkpoint name | `converted-remount-2a92538b0b0b4392b7e4f7513a00ff88` |

The earlier remount preflight case `win11-20261024T063625643Z` stopped before
VM actions: its attempted raw hash check used the original review-input hash on
a reserialized archive manifest. The corrected reader authenticates each source
using the source hashes in the independently pinned completed host record.
The original records and byte hashes were preserved. A 38-check actual-archive
regression and 133 mode/predecessor checks pass in PowerShell 5 and 7, alongside
174 existing host checks and 103 pinned-input checks. No new guest/native code
was needed for this remount.
