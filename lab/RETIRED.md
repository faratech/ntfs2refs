# Retired lab scripts

161 of the scripts in this directory cannot run. Each was written for one
virtual machine, or one checkpoint, of an earlier qualification stage (the
streaming, shadow and paged routes of October and early November 2026), and
that VM or checkpoint no longer exists on the lab host. They are kept, byte
for byte, as the record of how those stages were run: evidence in
`evidence/qualification-registry.json` is bound to two of them by digest
(`Complete-NativeShadowAlphaRollback.ps1`, `Collect-NativeShadowAlphaMarker.ps1`),
and the historical guide in `docs/history/` refers to others by name.

The current route is `Invoke-BootConversionAttempt.ps1`; see [README.md](README.md).
Do not start from a script listed here. To repeat an old stage, carry its
steps over to the current harness.

`tests/lab_retired_scripts.rs` keeps this list true: a script in this directory
that names a retired VM must be listed below, as retired or as one of the
exceptions at the end, and every listed script must exist.

## Live virtual machines

| VM id | Name |
|---|---|
| `8f7fc646-8c9f-41d0-b65a-ecfadccfc36a` | `ntfs2refs-reference-isolated` |
| `7c687062-37b5-4309-b28a-486a44305202` | `ntfs2refs-reference-b` |

## Retired virtual machines

| VM id | Name in its scripts | Scripts |
|---|---|---|
| `2401593c-4b30-472e-9b6d-c9534cbaa599` | `ntfs2refs-streaming-v2-20261027` | 121 |
| `0d9bfa66-c66c-4ead-86b7-e72cb5f7e040` | `ntfs2refs-shadow-alpha-20261026` | 15 |
| `6c4793d2-cdee-468b-bf3b-1c11cae0b501` | `ntfs2refs-shadow-large-beta-20261027` | 9 |
| `eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c` | (the first reference VM; its name now belongs to a live VM) | none: scripts name it only as a VM to leave untouched |

Retired VM names that appear without an id: `ntfs2refs-native-shadow-alpha-20261026`, `ntfs2refs-native-shadow-beta-20261027`.

## Retired scripts

### ntfs2refs-streaming-v2-20261027 (121)

VM `2401593c-4b30-472e-9b6d-c9534cbaa599`.

- `AdmittedCompactPostcheck.ps1`
- `Attach-StreamingV2Media.ps1`
- `Collect-OptimizedDriveAlpha.ps1`
- `Collect-StreamingV2Conversion.ps1`
- `Collect-StreamingV2RecoveredTree.ps1`
- `Collect-StreamingV2Recovery.ps1`
- `CompactPostcheck.ps1`
- `Complete-SourceFreeHashObservation.ps1`
- `Create-SelectedCompactDisks.ps1`
- `Dispatch-StreamingV2Conversion.ps1`
- `Dispatch-StreamingV2Recovery.ps1`
- `Invoke-AdsMutation.ps1`
- `Invoke-AdsRecovery.ps1`
- `Invoke-AllocationMutationReboot.ps1`
- `Invoke-HardLinkRecovery.ps1`
- `Invoke-NativeShadowLargeBetaRustPostcheck.ps1`
- `Invoke-OptimizedDriveMutation.ps1`
- `Invoke-ReadOnlyExtentObservation.ps1`
- `Invoke-SparseRecovery.ps1`
- `Measure-StreamingV2Journal.ps1`
- `New-AdsFixture.ps1`
- `New-HardLinkFixture.ps1`
- `New-MixedFixture.ps1`
- `New-PagedDirectoryFixture.ps1`
- `Observe-ExactAlphaRecoveryAfterPower.ps1`
- `Observe-StreamingV2ValidityAfterBoot.ps1`
- `Prepare-SelectedCompactVolumes.ps1`
- `Prepare-StreamingRetention8G.ps1`
- `Prepare-StreamingV2CacheSyncRetry.ps1`
- `Prepare-StreamingV2Fixture.ps1`
- `Prepare-StreamingV2FrozenRetry.ps1`
- `Prepare-StreamingV2RecoveryBranch.ps1`
- `Prepare-StreamingV2RetainedRecovery.ps1`
- `Prepare-StreamingV2RetainedRollback.ps1`
- `Prepare-StreamingV2ValidityProbe.ps1`
- `Preserve-AdmittedInterruption.ps1`
- `Preserve-AdmittedRecovery.ps1`
- `Preserve-DriveCliAffirmative.ps1`
- `Preserve-DriveCliColdBoot.ps1`
- `Preserve-ManagedCompactPartial.ps1`
- `Preserve-ManagedCompactRecovered.ps1`
- `Preserve-SelectedCompactConversion.ps1`
- `Preserve-StreamingV2Interruption.ps1`
- `Provision-StreamingV2Fixture.ps1`
- `Readback-DriveCliColdBoot.ps1`
- `Readback-ManagedRecoveredUsers.ps1`
- `Remove-RedundantStreamingCheckpoints.ps1`
- `Restart-NativeShadowLargeBetaVerified.ps1`
- `Restart-StreamingV2Interrupted.ps1`
- `Retry-StreamingV2ValidityObservation.ps1`
- `Save-BundleCliCheckpoint.ps1`
- `Save-BundleCliRecovery.ps1`
- `Save-BundlePartial.ps1`
- `Save-ClosedAllocationEvidence.ps1`
- `Save-ManagedMutationAfterBoot.ps1`
- `Save-ManagedPartialAfterCleanup.ps1`
- `Save-OptimizedPartial.ps1`
- `Stage-StreamingV2Postcheck.ps1`
- `Start-ActualByteCapacityExperiment.ps1`
- `Start-ActualByteCapacityRecovery.ps1`
- `Start-AdmittedCompactConversion.ps1`
- `Start-AdmittedCompactRecovery.ps1`
- `Start-AdmittedCompactRetry.ps1`
- `Start-AdsConversion.ps1`
- `Start-AdsInterruption.ps1`
- `Start-AllocationBoundedConversion.ps1`
- `Start-AllocationInterruption.ps1`
- `Start-AllocationRecovery.ps1`
- `Start-AttributeListConversion.ps1`
- `Start-BundleCliRecovery.ps1`
- `Start-BundleCompactInterruption.ps1`
- `Start-CompactFixtureApply.ps1`
- `Start-CompactFixtureRecovery.ps1`
- `Start-CompactJournalPreparation.ps1`
- `Start-CurrentPublicMutation.ps1`
- `Start-CurrentPublicRecovery.ps1`
- `Start-DirectoryAttributeFullSourceBaseline.ps1`
- `Start-DriveCliAffirmative.ps1`
- `Start-EnvelopeInterruption.ps1`
- `Start-EnvelopeRecovery.ps1`
- `Start-ExactAlphaRecoveryFast.ps1`
- `Start-ExactAlphaRecoveryPowerCut.ps1`
- `Start-ExtentInterruption.ps1`
- `Start-ExtentRecovery.ps1`
- `Start-HardLinkConversion.ps1`
- `Start-HardLinkInterruption.ps1`
- `Start-HeadDriveMeasurement.ps1`
- `Start-ManagedCompactInterruption.ps1`
- `Start-ManagedCompactRecovery.ps1`
- `Start-ManagedRecoveredMutation.ps1`
- `Start-NativeMarkerExperiment.ps1`
- `Start-NativeMarkerPowerRecovery.ps1`
- `Start-NativeRequiredOwnership.ps1`
- `Start-NativeRollbackPowerRecovery.ps1`
- `Start-NtfsOwnedPreparation.ps1`
- `Start-OptimizedCompactInterruption.ps1`
- `Start-OptimizedDriveAlpha.ps1`
- `Start-OptimizedRecovery.ps1`
- `Start-PagedEnvelopeInterruption.ps1`
- `Start-PagedEnvelopeObservedRecovery.ps1`
- `Start-PagedEnvelopeRecovery.ps1`
- `Start-PagedFullSourceBaseline.ps1`
- `Start-PreparedSourcePerformanceExperiment.ps1`
- `Start-PreparedSourcePerformanceRecovery.ps1`
- `Start-PublicMinScratchExperiment.ps1`
- `Start-PublicVssRefusal.ps1`
- `Start-SelectedCompactConversion.ps1`
- `Start-SourceFreePerformanceExperiment.ps1`
- `Start-SparseCarrierProbe.ps1`
- `Start-SparseConversion.ps1`
- `Start-SparseFixture.ps1`
- `Start-SparseInterruption.ps1`
- `Start-StreamingV2PrivateTreeAllocation.ps1`
- `Start-StreamingV2SmallMaterialization.ps1`
- `Start-StreamingV2UnwrittenPlacement.ps1`
- `Verify-AdmittedRollbackPayload.ps1`
- `Verify-ManagedMutationAfterBoot.ps1`
- `Verify-NativeShadowLargeBetaPayload.ps1`
- `Verify-StreamingV2RecoveredTree.ps1`
- `Verify-StreamingV2RolledBackPayload.ps1`
- `Wait-StreamingV2RetainedInterruption.ps1`

### ntfs2refs-shadow-alpha-20261026 (15)

VM `0d9bfa66-c66c-4ead-86b7-e72cb5f7e040`.

- `Collect-NativeShadowAlpha.ps1`
- `Collect-NativeShadowAlphaMarker.ps1`
- `Complete-NativeShadowAlphaCancel.ps1`
- `Complete-NativeShadowAlphaNormal.ps1`
- `Complete-NativeShadowAlphaResume.ps1`
- `Complete-NativeShadowAlphaRollback.ps1`
- `Dispatch-NativeShadowAlphaFault.ps1`
- `Finish-NativeShadowAlphaRecoveryMatrix.ps1`
- `Package-NativeShadowAlpha.ps1`
- `Prepare-NativeShadowAlpha.ps1`
- `Preserve-NativeShadowAlphaNtfsRecovery.ps1`
- `Preserve-NativeShadowAlphaResume.ps1`
- `Provision-NativeShadowAlpha.ps1`
- `Start-NativeShadowAlpha.ps1`
- `Start-NativeShadowAlphaConversion.ps1`

### ntfs2refs-shadow-large-beta-20261027 (9)

VM `6c4793d2-cdee-468b-bf3b-1c11cae0b501`.

- `Collect-NativeShadowLargeBeta.ps1`
- `Complete-NativeShadowLargeBetaDispatch.ps1`
- `Dispatch-NativeShadowLargeBetaCandidate.ps1`
- `Invoke-NativeShadowLargeBetaMutation.ps1`
- `Prepare-NativeShadowLargeBeta.ps1`
- `Preserve-NativeShadowLargeBetaRefusal.ps1`
- `Provision-NativeShadowLargeBeta.ps1`
- `Start-NativeShadowLargeBeta.ps1`
- `Start-NativeShadowLargeBetaConversion.ps1`

### Pinned to a checkpoint or VM name only (16)

These name no VM id. Each names a checkpoint id, or a VM by name, that no
longer exists.

- `LargePagedBaselineSupport.ps1`
- `Package-NativeShadowLargeBeta.ps1`
- `PagedEnvelopeBaselineSupport.ps1`
- `SourceBaselineSupport.ps1`
- `Start-CleanCandidatePublicMinScratch.ps1`
- `Start-CleanCurrentPublicMinScratch.ps1`
- `Start-CorrectedProfilePublicMinScratch.ps1`
- `Start-FusedPublicMinScratch.ps1`
- `Start-LargePagedPublicMinScratch.ps1`
- `Start-MixedScaleConversion.ps1`
- `Start-NativeMarkerFaultRecovery.ps1`
- `Start-NativeTerminalMarkerFaultRecovery.ps1`
- `Start-PagedPublicMinScratch.ps1`
- `Start-PagedPublicMutation.ps1`
- `Start-ProfilePublicMinScratch.ps1`
- `Start-TargetProfilePublicMinScratch.ps1`

## Not retired, though they name a retired VM

- `IsolatedBaselineGuards.psm1`: refuses that VM id by name: it is the guard against using the old VM.
- `Provision-IsolatedReference.ps1`: built the present reference VM; it names the first one only to leave it untouched.
- `Test-DevDriveCorpusExport.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-IsolatedJournalDeviceProfile.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-IsolatedReferenceReadiness.ps1`: checks the present reference VM; it names the first one only to leave it untouched.
- `Test-LabBaselineReadiness.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-LabConvertedRemount.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-LabConvertedVerification.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-LabNativeReconstruct.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-LabRetainedNativeProbe.ps1`: a self-test; the id is a made-up value in its fixtures.
- `Test-NewLabNativeReconstructRequest.ps1`: a self-test; the id is a made-up value in its fixtures.
