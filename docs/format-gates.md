# Qualification gates

No ReFS write profile is currently qualified. An inspection report, synthetic test, or manually edited configuration must not enable conversion. Native test artifacts must establish the following gates for each exact OS/format profile; Windows 11 and Server results remain separate.

The active milestone is data-volume conversion inside the owning machine.
Boot-control and converted-boot tests are deferred; they do not prevent work on
the data-volume gates. Unsupported boot status does not establish impossibility.

## Gate 0: reproducible laboratory

- [x] Hyper-V management access works through a standard UAC helper, and the Windows 11 VM/disk identities are recorded.
- [ ] ISO SHA-256, image index/edition, build, architecture, expiration where applicable, and installation provenance are recorded.
- [ ] Generation 2, Secure Boot, vTPM, boot order, disk geometry, and recovery media are recorded.
- [x] Windows 11 clean baseline and powered-off checkpoint restoration have been exercised.
- [ ] Log export is verified before a checkpoint restore; host capacity guards pass.
- [ ] Only disks identified by the experiment manifest can be targeted.

Windows 11 media has been hashed and its WIM metadata inspected: x64 Pro,
index 6, build 26300.9457. Offline installation and the native NTFS first-boot
checks passed. `applied-offline` and `installed-clean` checkpoints exist, and
an independent export has been hashed and verified, and restore validation passed.
The user relaunched the agent elevated; direct Hyper-V access and the bounded
helpers now work. Earlier runs used standard UAC helpers. Server
media and matching recovery tooling are deferred until supplied by the user.
See `.lab/hyperv/host-results`, the lane manifest, and installation logs for
the measured results; a started helper is not evidence that its task passed.

## Gate 1: native controls

For both OS lanes:

1. Install and verify a stock NTFS control. Record the Windows, boot manager, OS loader, ReFS driver, and recovery-tool versions and signatures.
2. Create a native ReFS data volume. Record the formatting command, options, cluster size, driver build, filesystem version, and whether the volume has ever been mounted by another build.
3. Deploy a clean native ReFS OS control using the same build's signed components. Keep the EFI partition FAT32 and recovery partition NTFS. Treat any configuration changes as explicit experiment inputs.
4. Record at least three cold boots, WinRE entry/exit, pagefile operation, component servicing checks, and a servicing/update cycle. Keep the pre-update and post-update profiles separate if the driver or format changes.

An unsuccessful ReFS OS control blocks boot-conversion acceptance for that build. Continue data-volume research and report the failing boot stage. Server success does not establish Windows 11 success. Retrying obsolete feature flags or transplanting another release's boot chain is not a substitute for this gate.

The Windows 11 NTFS first-boot control passed with no reported findings:
build 26300.9457, Professional, fully decrypted, hibernation disabled,
`Repair-Volume -Scan` returning `NoErrorsFound`, and WinRE enabled. This is
one normal NTFS boot, not ReFS boot or a WinRE entry/exit test. Evidence is in
`.lab/hyperv/win11/firstboot/native-ntfs-evidence.json`.

The observed signed components have distinct versions: `refs.sys`
10.0.26100.8875, `winload.efi` 10.0.26100.9444, and the image's
`bootmgfw.efi` 10.0.28000.342. Pin their recorded hashes as well as the OS
build; do not assume a common file-version number from the Windows build.

The native 1 GiB NTFS data control has also passed export/hash verification and
checkpoint restoration. Rust and Windows hashes matched all nine captured
path/stream observations from the complete fixture batch. Reparse payloads,
security semantics and full inventory consistency remain unqualified.

On Windows 11 Pro 26300.9457, ordinary `Format-Volume -FileSystem ReFS` refused
both the 1 GiB data partition and a 66,238,545,920-byte OS partition. No ReFS
boot was attempted. Stock `format.com` also refused the large partition with
exit 4, and DiskPart listed only NTFS as supported for formatting. These refusals
alone do not establish what another formatter environment or
edition supports. See [measured results](lab-results.md) for exact artifacts.

A separately identified native Dev Drive data control passed on the same Pro
guest: 52 GiB, 4 KiB clusters, ReFS 3.14, with two fixture hashes preserved across
a clean reboot. Native allocation observations and a powered-off checkpoint
were retained, and baseline/memory restoration passed. This qualifies only that
data-control observation; ordinary ReFS OS preparation and boot remain blocked
and untested respectively. It does not qualify a converter or writer.

## Gate 2: a verified ReFS format profile

Capture small native volume images with one operation per observation: empty format, one empty file, one resident/small file, one multi-extent file, directory creation, renamed file, deletion/reallocation, hard link, alternate stream, sparse range, security descriptor change, EA, and supported reparse point. Flush and cleanly dismount before each capture. Repeat key cases across 512e/4Kn and 4/64 KiB clusters; only the selected 4 KiB conversion profile may advance initially.

Every capture needs an artifact hash, parent-capture hash, the single operation performed, known file/stream hashes, extent observations, metadata observations, and native operation results. Compare images at logical-sector granularity and distinguish changed sector ranges from claims about their meaning. Write artifacts beneath the disposable lab tree, not into source control.

The profile must explain and independently validate:

- [ ] All discovery headers and their redundant locations, including behavior with stale or damaged copies.
- [ ] Virtual/physical address translation and every reserved metadata region.
- [ ] Directory/object indexes, file identities, stream extents, security descriptors, and hard-link representation.
- [ ] Allocation/free-space/refcount consistency after native writes and deletion.
- [ ] Metadata checksum algorithms and covered bytes, including references and redundant metadata.
- [ ] Checkpoint selection, generations, log initialization/replay, and the exact commit/flush sequence.
- [ ] Native-versus-upgraded distinctions and any boot/attestation metadata required for the selected build.

Then generate a new empty ReFS image and progressively add fixtures. It must survive native mount, reads, writes, deletion, allocation pressure, clean shutdown, and remount without unexpected repair or loss. A reader accepting its own writer's output is insufficient. Independently compare native reads and metadata results against the source fixture manifest.

Current status: the bounded Rust reader validates captured discovery headers,
superblock/checkpoint checksums, physical container roots and their children,
and twenty translated virtual-root references for the measured ReFS 3.14/4 KiB
profile. Both container copies agree on 832 entries for each checkpoint. It does
not select an authoritative checkpoint, follow the virtual roots' descendants,
or establish complete allocation/metadata coverage. Native initialized-file
placement survived remount, but the proposed both-zero-VDL allocation profile
did not qualify. Metadata writing, commit ordering and conversion remain
unimplemented/unqualified. These partial results do not complete the broader
checkboxes above; see [the measured results](lab-results.md) and
[virtual-root evidence](refs-virtual-roots.md).

## Gate 3: extent-preserving conversion and recovery

Execute the actual converter inside the guest against its local disk. The
production path must use the same Rust executable and local Windows storage
interfaces on bare metal, including an offline recovery environment for an OS
volume. Host-side VHD flattening or partition extraction may supply immutable
research images only; it cannot count as conversion or satisfy this gate.

Use deliberately small, disposable NTFS fixtures before any OS image. Required cases include multiple streams, resident/nonresident data, empty files, sparse ranges, fragmented runs, long/Unicode names, hard links, exact security descriptors, supported EAs/reparse points, and collisions with required ReFS anchors. Unsupported features must produce enumerated blockers before destructive writes.

Acceptance requires matching supported stream hashes and metadata semantics, unchanged partition identity, recorded reused/relocated extent counts, and measured I/O. The result must not hide a full-copy migration behind the term in-place. Space accounting must bound target staging and external journal storage before conversion begins.

Inject failures at every journal and target-write boundary, including journal corruption/truncation, short writes, failed flushes, interrupted relocation, partial discovery-header writes, process termination, and VM power loss. Test both resume and rollback from recovery media with the target unmounted. Verify source identity and reject a mismatched or unexpectedly modified disk. Repeat rollback and resume to establish idempotence. Check logical source equivalence after rollback, not unused-byte identity.

The handoff to the first writable mount must be explicit and durable. Journal rollback must refuse after handoff. Recovery after that point uses the recorded VM checkpoint. Deleting a drive letter or assuming that the dirty bit will prevent mounting is insufficient isolation.

Current status: no native conversion result or power-loss recovery result has been produced. A journal prototype on ordinary test files cannot qualify raw-volume crash recovery.

## Gate 4: converted boot volumes

Only profiles passing the preceding gates can be used for an eligible NTFS OS installation. Inventory the actual installed volume first; a successful clean control does not waive unsupported-feature checks.

- [ ] Preserve EFI/MSR/recovery partitions, disk and partition identities, and correct boot configuration references.
- [ ] Boot three times from a powered-off VM and complete login on each attempt.
- [ ] Verify streams, hard-link relationships, ACLs, supported metadata, services, pagefile operation, and component-store checks.
- [ ] Enter and exit WinRE successfully, then perform a servicing/update cycle.
- [ ] Capture filesystem and boot event logs and report deviations from the clean native ReFS control.
- [ ] Exercise checkpoint restoration after a post-handoff failure.

Current status: both converted Windows 11 boot and converted Server boot remain unproven. Publish results as exact-build compatibility entries, not a universal boot-support flag.

## Evidence and release discipline

Each gate report must name the code revision, VM manifest, media hashes, source/target image hashes, commands, exact results, and retained logs. Record failed attempts as well as successful ones. Unknown, failed, and untested are distinct statuses. Treat review of the measured format specification and implementation as a prerequisite to adding an accepted profile; never make a JSON `passed` field alone confer write authority.

The first usable research milestone is reproducible lab provisioning plus read-only inspection and comparison. The final product milestone remains actual native-accepted conversion and boot qualification. These must not be described interchangeably.
