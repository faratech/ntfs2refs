# Earlier designs, experiments and builds

These documents were written while ntfs2refs was being designed and are kept as they
were, as the record of how the present tool was reached. None of them describes the
current tool. For that, read the [README](../../README.md), the
[operating and recovery guide](../cli-workflow.md), the
[feature matrix](../feature-matrix.md) and the [recovery matrix](../recovery-matrix.md).

Words such as "current", "pending" and "not qualified" in them are of their date.
The records under `evidence/` and the retired lab scripts cite these documents by the
path they had when they were written, `docs/<name>.md`; they are now
`docs/history/<name>.md`. Those records are evidence and are not edited.

In the order they were last changed:

| Last changed | Document | Title |
|---|---|---|
| 2026-10-24 | [allocation-evidence.md](allocation-evidence.md) | Native allocation observations |
| 2026-10-24 | [bounded-converter-next-step.md](bounded-converter-next-step.md) | Next step: a bounded converter for an existing data-file tree |
| 2026-10-24 | [checkpoint-restore-readiness.md](checkpoint-restore-readiness.md) | Checkpoint restore observations |
| 2026-10-24 | [converted-read-only-mount.md](converted-read-only-mount.md) | Post-handoff read-only mount boundary |
| 2026-10-24 | [converted-verification-host.md](converted-verification-host.md) | Host orchestration for protected native verification |
| 2026-10-24 | [existing-tree-shadow.md](existing-tree-shadow.md) | Native shadow for the independently populated tree |
| 2026-10-24 | [fixed-vhd-extraction.md](fixed-vhd-extraction.md) | Fixed-VHD corpus extraction |
| 2026-10-24 | [format-gates.md](format-gates.md) | Qualification gates |
| 2026-10-24 | [guest-shadow-platform.md](guest-shadow-platform.md) | Guest-local native shadow platform |
| 2026-10-24 | [lab-results.md](lab-results.md) | Measured laboratory results |
| 2026-10-24 | [native-allocation-feasibility.md](native-allocation-feasibility.md) | Native ReFS allocation as a metadata generator |
| 2026-10-24 | [native-conversion-results.md](native-conversion-results.md) | First native extent-preserving conversion result |
| 2026-10-24 | [native-corpus-analysis.md](native-corpus-analysis.md) | Native ReFS corpus: next read-only work |
| 2026-10-24 | [native-extent-discovery.md](native-extent-discovery.md) | Native extent and bitmap discovery |
| 2026-10-24 | [native-extent-placement.md](native-extent-placement.md) | Bounded initialized-file placement experiment |
| 2026-10-24 | [native-isolation-restart.md](native-isolation-restart.md) | Retained native isolation and restart control |
| 2026-10-24 | [native-journal-file-identity.md](native-journal-file-identity.md) | Native journal file identity observer |
| 2026-10-24 | [native-ntfs-file-attestation.md](native-ntfs-file-attestation.md) | Native NTFS file-handle observations |
| 2026-10-24 | [native-ntfs-logical-data.md](native-ntfs-logical-data.md) | Native logical-stream verification |
| 2026-10-24 | [native-ntfs-source-freeze.md](native-ntfs-source-freeze.md) | Native freeze of an existing ordinary file tree |
| 2026-10-24 | [native-ntfs-stream-attestation.md](native-ntfs-stream-attestation.md) | Native NTFS stream, extent and bitmap reconciliation |
| 2026-10-24 | [native-partition-adapter.md](native-partition-adapter.md) | Native partition adapter qualification |
| 2026-10-24 | [native-process-capture.md](native-process-capture.md) | Native lab process lifetime and output capture |
| 2026-10-24 | [native-protected-range-read.md](native-protected-range-read.md) | Protected guest-side range observation |
| 2026-10-24 | [native-range-read-design.md](native-range-read-design.md) | Bounded native raw range read |
| 2026-10-24 | [native-range-read-lock-refusal.md](native-range-read-lock-refusal.md) | Protected mounted sampling after a locked-query refusal |
| 2026-10-24 | [native-reconstruction-host.md](native-reconstruction-host.md) | One-phase native reconstruction laboratory harness |
| 2026-10-24 | [native-retained-fixture.md](native-retained-fixture.md) | Native retained-extent fixture |
| 2026-10-24 | [native-retained-postconversion-verification.md](native-retained-postconversion-verification.md) | Native verification after the retained-extent conversion |
| 2026-10-24 | [native-vdl-observation.md](native-vdl-observation.md) | Metadata observation after the VDL allocation outcome |
| 2026-10-24 | [ntfs-metadata-roles.md](ntfs-metadata-roles.md) | NTFS metadata-role candidates |
| 2026-10-24 | [ntfs2btrfs-design-lessons.md](ntfs2btrfs-design-lessons.md) | Lessons from the pinned ntfs2btrfs implementation |
| 2026-10-24 | [payload-write-evidence.md](payload-write-evidence.md) | Measuring payload writes |
| 2026-10-24 | [protected-shadow-host-integration.md](protected-shadow-host-integration.md) | Host validation of protected shadow reattachment |
| 2026-10-24 | [refs-bootstrap-reader.md](refs-bootstrap-reader.md) | ReFS 3.14 bootstrap observations |
| 2026-10-24 | [refs-container-reader.md](refs-container-reader.md) | Bounded physical container-tree reader |
| 2026-10-24 | [refs-root-nodes.md](refs-root-nodes.md) | Bounded ReFS bootstrap root-node observations |
| 2026-10-24 | [refs-virtual-roots.md](refs-virtual-roots.md) | Bounded ReFS virtual-root translation |
| 2026-10-24 | [research.md](research.md) | NTFS to ReFS conversion research |
| 2026-10-24 | [retained-preparation-results.md](retained-preparation-results.md) | Guest-local preparation measurements |
| 2026-10-24 | [retained-range-comparison.md](retained-range-comparison.md) | Read-only comparison with retained source ranges |
| 2026-10-24 | [root-enumeration-diagnostic.md](root-enumeration-diagnostic.md) | Bounded root enumeration diagnostic |
| 2026-10-24 | [shadow-identity.md](shadow-identity.md) | Guest shadow identity investigation |
| 2026-10-24 | [shadow-readonly-attachment-diagnostic.md](shadow-readonly-attachment-diagnostic.md) | Fresh shadow attachment protection diagnostic |
| 2026-10-24 | [sparse-validity-implications.md](sparse-validity-implications.md) | Validity is part of extent preservation |
| 2026-10-24 | [windows11-next-native-controls.md](windows11-next-native-controls.md) | Next Windows 11 native controls |
| 2026-10-25 | [direct-adoption-plan.md](direct-adoption-plan.md) | Direct extent adoption candidates |
| 2026-10-25 | [general-data-disk-binding.md](general-data-disk-binding.md) | Dedicated data-disk binding |
| 2026-10-25 | [internal-volume-object-id.md](internal-volume-object-id.md) | Filesystem-internal NTFS volume identity |
| 2026-10-25 | [native-freeze-allocation.md](native-freeze-allocation.md) | Allocation observations across native ReFS freeze |
| 2026-10-25 | [ntfs-log-restart.md](ntfs-log-restart.md) | NTFS `$LogFile` restart evidence |
| 2026-10-25 | [ntfs-volume-flags.md](ntfs-volume-flags.md) | Native NTFS volume flag 0x0080 |
| 2026-10-25 | [paired-security-and-resident-data.md](paired-security-and-resident-data.md) | Stored security, API projections and small ReFS streams |
| 2026-10-25 | [streaming-ntfs-payload.md](streaming-ntfs-payload.md) | Bounded NTFS logical-stream copy |
| 2026-10-25 | [transaction-freeze-policy.md](transaction-freeze-policy.md) | Native default transaction-manager freeze |
| 2026-10-25 | [tree-conversion-results.md](tree-conversion-results.md) | Existing-tree conversion |
| 2026-10-26 | [general-native-conversion-results.md](general-native-conversion-results.md) | General guest conversion: existing NTFS tree |
| 2026-10-26 | [isolated-baseline-prerequisites.md](isolated-baseline-prerequisites.md) | Isolated unmodified-baseline source prerequisites |
| 2026-10-26 | [isolated-journal-writer-exclusion.md](isolated-journal-writer-exclusion.md) | Parked independent-writer journal prerequisite |
| 2026-10-26 | [isolated-reference-control-plan.md](isolated-reference-control-plan.md) | Isolated reference controls: execution plan only |
| 2026-10-26 | [lab-reconstruction-journal.md](lab-reconstruction-journal.md) | Laboratory reconstruction journal |
| 2026-10-26 | [lab-storage-archive.md](lab-storage-archive.md) | Local lab storage archive (2026-10-25) |
| 2026-10-26 | [native-refs-writer-acceptance.md](native-refs-writer-acceptance.md) | Independent writer: native acceptance and reference control |
| 2026-10-26 | [native-retrieval-pagination.md](native-retrieval-pagination.md) | Complete retrieval-pointer pagination |
| 2026-10-26 | [native-shadow-alpha-results.md](native-shadow-alpha-results.md) | Native-shadow alpha results |
| 2026-10-26 | [next-extent-preservation-milestone.md](next-extent-preservation-milestone.md) | Next milestone: one retained NTFS extent under native ReFS metadata |
| 2026-10-26 | [ntfs-mft-bootstrap.md](ntfs-mft-bootstrap.md) | Checked fragmented MFT bootstrap |
| 2026-10-26 | [ntfs-streaming-budget.md](ntfs-streaming-budget.md) | Explicit logical-stream transfer budget |
| 2026-10-26 | [operation-state-command.md](operation-state-command.md) | Preparing the read-only operation-state command |
| 2026-10-26 | [protected-target-semantics.md](protected-target-semantics.md) | Semantics of the exact frozen target |
| 2026-10-26 | [reference-reproducibility.md](reference-reproducibility.md) | Read-only reference reproducibility verification |
| 2026-10-26 | [source-admission-progress.md](source-admission-progress.md) | Source admission: current implementation and remaining gates |
| 2026-10-26 | [source-volume-label.md](source-volume-label.md) | Exact source volume-label preservation |
| 2026-10-27 | [device-binding-discovery.md](device-binding-discovery.md) | Read-only conversion-request discovery |
| 2026-10-27 | [journal-preparation-progress.md](journal-preparation-progress.md) | Journal-preparation progress |
| 2026-10-27 | [native-bitmap-pagination.md](native-bitmap-pagination.md) | Complete native bitmap pagination |
| 2026-10-27 | [native-bitmap-streaming.md](native-bitmap-streaming.md) | Streaming native allocation observations |
| 2026-10-27 | [native-sha256-performance.md](native-sha256-performance.md) | Native SHA-256 for streaming source scans |
| 2026-10-27 | [native-shadow-beta-handoff.md](native-shadow-beta-handoff.md) | Native-shadow beta bundle |
| 2026-10-27 | [native-shadow-large-beta.md](native-shadow-large-beta.md) | Disposable larger-volume beta |
| 2026-10-27 | [native-vdl-experiment.md](native-vdl-experiment.md) | Measuring allocation while valid-data length is zero |
| 2026-10-27 | [natural-large-file-progress.md](natural-large-file-progress.md) | Naturally allocated 128 MiB file |
| 2026-10-27 | [ntfs-allocation-reconciliation.md](ntfs-allocation-reconciliation.md) | Raw NTFS allocation reconciliation |
| 2026-10-27 | [ntfs-namespace-reconciliation.md](ntfs-namespace-reconciliation.md) | Raw NTFS namespace reconciliation |
| 2026-10-27 | [ntfs-security-reconciliation.md](ntfs-security-reconciliation.md) | Raw NTFS security reconciliation |
| 2026-10-27 | [refs-compact-containers.md](refs-compact-containers.md) | Experimental compact container traversal |
| 2026-10-27 | [shadow-user-evacuation.md](shadow-user-evacuation.md) | Shadow user-data evacuation |
| 2026-10-27 | [streaming-v2-native.md](streaming-v2-native.md) | Streaming-payload v2 native fixture |
| 2026-10-27 | [streaming-v2-recovery.md](streaming-v2-recovery.md) | Streaming interruption and recovery branch |
| 2026-10-28 | [AGENTS-through-20261029.md](AGENTS-through-20261029.md) | ntfs2refs project guidance |
| 2026-10-28 | [native-composite-experimental.md](native-composite-experimental.md) | Experimental native composite workflow |
| 2026-10-28 | [native-unwritten-placement.md](native-unwritten-placement.md) | Native placement before valid-data advancement |
| 2026-10-28 | [private-tree-allocation.md](private-tree-allocation.md) | Allocation-only canonical tree staging |
| 2026-10-28 | [streaming-v2-retained-conversion.md](streaming-v2-retained-conversion.md) | Eight-GiB retained conversion: completed native acceptance |
| 2026-10-28 | [streaming-v2-retained-recovery.md](streaming-v2-retained-recovery.md) | Retained eight-GiB process interruption, resume and NTFS rollback |
| 2026-10-29 | [AGENTS-native-recovery-20261029.md](AGENTS-native-recovery-20261029.md) | ntfs2refs project guidance |
| 2026-10-29 | [frozen-drive-alpha-20261029.md](frozen-drive-alpha-20261029.md) | Frozen Windows drive alpha — 2026-10-29 |
| 2026-10-29 | [hybrid-write-model-design.md](hybrid-write-model-design.md) | Hybrid write model (drafts, not adopted) |
| 2026-10-29 | [metadata-write-set.md](metadata-write-set.md) | Candidate ReFS target write set |
| 2026-10-29 | [native-shadow-alpha.md](native-shadow-alpha.md) | 2026-10-26 native-shadow alpha candidate (historical) |
| 2026-10-29 | [refs-metadata-footprint.md](refs-metadata-footprint.md) | ReFS metadata footprint reader |
| 2026-10-29 | [selective-conversion-plan.md](selective-conversion-plan.md) | Selective conversion plan (ntfs2btrfs-style) |
| 2026-10-29 | [unbounded-scale-design.md](unbounded-scale-design.md) | Unbounded-scale design (draft, not adopted) |
| 2026-10-30 | [experimental-build-provenance.md](experimental-build-provenance.md) | Experimental build provenance — 2026-10-29 |
| 2026-10-30 | [hybrid-write-model-spec-verdict-crash.md](hybrid-write-model-spec-verdict-crash.md) | N2RSEL02-H verdict 1: crash and rollback safety (2026-10-30) |
| 2026-10-30 | [hybrid-write-model-spec.md](hybrid-write-model-spec.md) | Hybrid write model specification N2RSEL02-H (draft, UNVERIFIED) |
| 2026-10-30 | [ntfs-attribute-list-assembly.md](ntfs-attribute-list-assembly.md) | Bounded ordinary NTFS DATA attribute-list assembly |
| 2026-10-30 | [selected-range-journal.md](selected-range-journal.md) | Selected-range journal core |
| 2026-10-31 | [AGENTS-through-20261101T0225.md](AGENTS-through-20261101T0225.md) | ntfs2refs project guidance |
| 2026-10-31 | [actual-byte-capacity.md](actual-byte-capacity.md) | Admission by stored journal bytes |
| 2026-10-31 | [capacity-pinned-journals.md](capacity-pinned-journals.md) | Capacity-pinned journals and capture storage |
| 2026-10-31 | [destination-bitmap-windows.md](destination-bitmap-windows.md) | Destination bitmap windows |
| 2026-10-31 | [envelope-recovery-matrix.md](envelope-recovery-matrix.md) | Grown V3 recovery matrix |
| 2026-10-31 | [exact-selected-target-verification.md](exact-selected-target-verification.md) | Exact selected target verification |
| 2026-10-31 | [exclusive-recovery-native.md](exclusive-recovery-native.md) | Exclusive journal recovery: native compatibility case |
| 2026-10-31 | [fast-verification.md](fast-verification.md) | Fast verification |
| 2026-10-31 | [fresh-exclusive-native.md](fresh-exclusive-native.md) | Fresh-exclusive normal native qualification |
| 2026-10-31 | [journal-buffer-reuse.md](journal-buffer-reuse.md) | Bounded journal working buffers |
| 2026-10-31 | [journal-exclusive-recovery.md](journal-exclusive-recovery.md) | Reuse authenticated journal records during recovery |
| 2026-10-31 | [journal-fresh-exclusive-writes.md](journal-fresh-exclusive-writes.md) | Fresh exclusive journal writes |
| 2026-10-31 | [journal-parallel-aggregates.md](journal-parallel-aggregates.md) | Journal aggregate SHA-256 scheduling |
| 2026-10-31 | [journal-preparation-readback.md](journal-preparation-readback.md) | One-pass validated journal pin issuance |
| 2026-10-31 | [journal-prepared-exclusive-owner.md](journal-prepared-exclusive-owner.md) | Retaining the verified journal through fresh apply |
| 2026-10-31 | [journal-zero-digest-reuse.md](journal-zero-digest-reuse.md) | Bounded zero digest reuse |
| 2026-10-31 | [mixed-exact-journal-verification.md](mixed-exact-journal-verification.md) | Mixed-tree exact journal verification |
| 2026-10-31 | [mixed-fast-journal-verification.md](mixed-fast-journal-verification.md) | Mixed-tree fast journal qualification |
| 2026-10-31 | [ntfs-compatibility-comparison-20261030.md](ntfs-compatibility-comparison-20261030.md) | NTFS compatibility comparison — 2026-10-30 |
| 2026-10-31 | [ntfs-compression-normalization.md](ntfs-compression-normalization.md) | NTFS compression normalization |
| 2026-10-31 | [ntfs-extended-attributes.md](ntfs-extended-attributes.md) | Bounded Windows EA preservation |
| 2026-10-31 | [ntfs-reparse-preservation.md](ntfs-reparse-preservation.md) | Bounded reparse-point preservation |
| 2026-10-31 | [ntfs-security-preservation.md](ntfs-security-preservation.md) | Windows security descriptor preservation |
| 2026-10-31 | [object-envelope-native.md](object-envelope-native.md) | Object-envelope normal native qualification |
| 2026-10-31 | [object-resource-envelope.md](object-resource-envelope.md) | Bounded object resource envelope |
| 2026-10-31 | [old-zero-journal.md](old-zero-journal.md) | Canonical old-zero journal encoding |
| 2026-10-31 | [old-zero-native.md](old-zero-native.md) | Old-zero normal native case |
| 2026-10-31 | [old-zero-recovery-matrix.md](old-zero-recovery-matrix.md) | Old-zero recovery matrix |
| 2026-10-31 | [partial-tail-extent-verification.md](partial-tail-extent-verification.md) | Extent verification for partial final clusters |
| 2026-10-31 | [partial-tail-recovery.md](partial-tail-recovery.md) | Partial-tail recovery qualification |
| 2026-10-31 | [planning-performance-20261031.md](planning-performance-20261031.md) | Planning work and prefetch memory |
| 2026-10-31 | [prepared-owner-native.md](prepared-owner-native.md) | Prepared-owner normal native case |
| 2026-10-31 | [raw-extent-recovery.md](raw-extent-recovery.md) | Raw extent recovery qualification |
| 2026-10-31 | [raw-extent-verification.md](raw-extent-verification.md) | Initial payload scan elimination |
| 2026-10-31 | [recovery-runtime-compatibility.md](recovery-runtime-compatibility.md) | Qualifying a new recovery runtime against an existing journal |
| 2026-11-01 | [AGENTS-through-20261101T2110.md](AGENTS-through-20261101T2110.md) | ntfs2refs project guidance |
| 2026-11-01 | [current65b-recovery-matrix.md](current65b-recovery-matrix.md) | Current public-runtime recovery |
| 2026-11-01 | [native-format6-controlled-matrix.md](native-format6-controlled-matrix.md) | Native format6 controlled recovery |
| 2026-11-01 | [ntfs-owned-preparation.md](ntfs-owned-preparation.md) | NTFS-owned collision preparation |
| 2026-11-01 | [public-min-scratch-native.md](public-min-scratch-native.md) | Public minimize-scratch native run |
| 2026-11-01 | [redundant-selected-markers.md](redundant-selected-markers.md) | Redundant selected-journal markers |
| 2026-11-01 | [scaling-budget-gaps.md](scaling-budget-gaps.md) | Scaling budget gaps |
| 2026-11-01 | [source-directory-case-admission.md](source-directory-case-admission.md) | Source directory case admission |
| 2026-11-01 | [source-free-native-recovery.md](source-free-native-recovery.md) | Source-free native recovery |
| 2026-11-02 | [backup-boot-restoration.md](backup-boot-restoration.md) | Preserve the NTFS backup boot sector during rollback |
| 2026-11-02 | [closing-source-fingerprint-reuse.md](closing-source-fingerprint-reuse.md) | Closing source fingerprint read reuse |
| 2026-11-02 | [metadata-memory-reduction.md](metadata-memory-reduction.md) | Streaming metadata and borrowed stream maps |
| 2026-11-02 | [native-format6-power-recovery.md](native-format6-power-recovery.md) | Native format6 power recovery |
| 2026-11-02 | [native-marker-fault-qualification.md](native-marker-fault-qualification.md) | Native marker fault qualification |
| 2026-11-02 | [ntfs-directory-attribute-projection.md](ntfs-directory-attribute-projection.md) | NTFS directory attributes in the native-shadow model |
| 2026-11-02 | [paged-resource-metadata.md](paged-resource-metadata.md) | Paged metadata in the native-shadow alpha |
| 2026-11-02 | [target-format-policy.md](target-format-policy.md) | Explicit native target format |
| 2026-11-02 | [vss-fresh-admission.md](vss-fresh-admission.md) | Fresh source VSS admission |
| 2026-11-03 | [AGENTS-through-20261103-before-partition-reader.md](AGENTS-through-20261103-before-partition-reader.md) | ntfs2refs: current handoff |
| 2026-11-03 | [AGENTS-through-20261103-resource-continuation.md](AGENTS-through-20261103-resource-continuation.md) | ntfs2refs project guidance |
| 2026-11-03 | [AGENTS-through-20261104-before-frozen-814-package.md](AGENTS-through-20261104-before-frozen-814-package.md) | ntfs2refs: current handoff |
| 2026-11-03 | [frozen-resource-alpha-20261104.md](frozen-resource-alpha-20261104.md) | frozen-resource-alpha-20261104.md |
| 2026-11-03 | [partition-scoped-source.md](partition-scoped-source.md) | Partition-scoped source development |
| 2026-11-03 | [resource-based-admission.md](resource-based-admission.md) | Resource-based source and metadata admission |
| 2026-11-04 | [AGENTS-through-20261104-aef-default.md](AGENTS-through-20261104-aef-default.md) | ntfs2refs: current handoff |
| 2026-11-04 | [AGENTS-through-20261104-before-aef-public-AP.md](AGENTS-through-20261104-before-aef-public-AP.md) | ntfs2refs: current handoff |
| 2026-11-04 | [AGENTS-through-20261104-before-public-thin-44cca72.md](AGENTS-through-20261104-before-public-thin-44cca72.md) | ntfs2refs: current handoff |
| 2026-11-04 | [aef-experimental-alpha-20261104.md](aef-experimental-alpha-20261104.md) | Frozen aef experimental alpha |
| 2026-11-04 | [native-shadow-scale-gaps.md](native-shadow-scale-gaps.md) | Native-shadow scale gaps |
| 2026-11-04 | [ntfs-conversion-policy.md](ntfs-conversion-policy.md) | NTFS conversion policy |
| 2026-11-04 | [owned-shadow-retirement.md](owned-shadow-retirement.md) | Owned shadow retirement |
| 2026-11-04 | [partition-current-critical-volume-policy.md](partition-current-critical-volume-policy.md) | Current critical-volume policy for partition conversion |
| 2026-11-04 | [private-thin-pool-addressability.md](private-thin-pool-addressability.md) | Private thin-pool addressability |
| 2026-11-05 | [AGENTS-through-20261105-shared-AP.md](AGENTS-through-20261105-shared-AP.md) | ntfs2refs: active handoff |
| 2026-11-06 | [SHARED-OFFLINE-ALPHA-a3ba1f3.md](SHARED-OFFLINE-ALPHA-a3ba1f3.md) | ntfs2refs — shared-disk experimental alpha |
| 2026-11-07 | [proactive-windows-metadata-audit-20261107.md](proactive-windows-metadata-audit-20261107.md) | Proactive Windows conversion audit |
| 2026-11-07 | [refs-trust-label-repair.md](refs-trust-label-repair.md) | Fixed-length native ReFS trust-label repair |
| 2026-11-09 | [native-shadow-performance.md](native-shadow-performance.md) | Native-shadow performance continuation |
| 2026-11-10 | [AGENTS-through-20261110-boot-volume-resume.md](AGENTS-through-20261110-boot-volume-resume.md) | ntfs2refs: current handoff |
| 2026-11-11 | [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Implementation handoff |
| 2026-11-11 | [README-before-boot-alpha-closeout-20261111.md](README-before-boot-alpha-closeout-20261111.md) | ntfs2refs |
| 2026-11-11 | [cli-workflow-before-boot-alpha-closeout-20261111.md](cli-workflow-before-boot-alpha-closeout-20261111.md) | Owning-machine conversion and recovery CLI |
| 2026-11-11 | [lab-README-before-boot-alpha-closeout-20261111.md](lab-README-before-boot-alpha-closeout-20261111.md) | Hyper-V lab |
| 2026-11-11 | [release-0.0.1-alpha.md](release-0.0.1-alpha.md) | 0.0.1-alpha: release and qualification |
| 2026-11-11 | [release-0.0.1-readiness.md](release-0.0.1-readiness.md) | Release readiness |
| 2026-11-11 | [release-readiness-before-boot-alpha-closeout-20261111.md](release-readiness-before-boot-alpha-closeout-20261111.md) | 0.0.1 release readiness — 2026-10-29 |
| 2026-11-12 | [public-cancel-and-operation-state.md](public-cancel-and-operation-state.md) | Public run status and preactivation cancel |
