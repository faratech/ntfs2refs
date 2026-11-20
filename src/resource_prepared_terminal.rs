//! Owning new-protocol terminal finalization; no old Windows live guard.
use crate::{
    general_composite_target::paged_memory::ArenaReportMemory,
    general_reconstruct::fast_verification::v4_maps::reopened::OfflinePreparedVerification,
    general_shadow::PagedInputs, ntfs_inspect::paged_storage::SourceScratch,
    resource_prepared_offline_apply::PreparedOfflineHandoff,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    NativeEvent, PagedRecoveryPins,
    offline_environment::{
        OfflinePreparedTerminalGuard, OfflinePreparedTerminalReceipt, OfflineTerminalKind,
    },
    partition_isolation::PartitionObservationBudget,
    partition_restoration::PartitionRestorationObserver,
};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};
fn open_role(
    bundle: &crate::resource_prepared_bundle::HeldWindowsPreparedBundle,
    role: &str,
) -> Result<File> {
    let pin = bundle
        .core()
        .artifacts
        .iter()
        .find(|a| a.role == role)
        .context("terminal authenticated artifact missing")?;
    let path = pin
        .snapshot
        .as_ref()
        .map(|s| Path::new(&s.final_path))
        .unwrap_or(&pin.path);
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    n2r_win32::file_storage::require_readonly_access(&file)?;
    Ok(file)
}
#[derive(Serialize)]
pub(crate) struct PreparedOfflineTerminalReceipt {
    pub kind: &'static str,
    pub restoration: OfflinePreparedTerminalReceipt,
    pub selected: crate::selected_journal::SelectedResult,
    pub native_bytes_written: u64,
    pub readonly_native_metadata_objects: u64,
    pub retained_map_bindings: u64,
    pub actual_native_and_maps_before_writable: bool,
    pub stable_release_qualified: bool,
}
pub(crate) fn finalize_prepared_offline(
    terminal: PreparedOfflineHandoff,
    scratch: &SourceScratch,
    output: &Path,
    budget: PartitionObservationBudget,
    observer: &mut impl PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> Result<PreparedOfflineTerminalReceipt> {
    observer.checkpoint_native_events("cold-terminal-before-availability", events)?;
    ensure!(events.is_empty(), "terminal observer did not drain");
    ensure!(!output.exists(), "fresh cold-terminal output required");
    std::fs::create_dir(output)?;
    let mut available = terminal.into_available(events)?;
    available.bundle.require_ready_artifacts()?;
    available.index_owner.revalidate()?;
    let arena = scratch
        .artifact_group()
        .context("terminal actual arena absent")?
        .arena()
        .clone();
    let owner = available.source.owner_token();
    let kind = available.source.terminal_kind();
    let metadata = if kind == OfflineTerminalKind::Handoff {
        Some(OfflinePreparedVerification::open(
            &available.bundle,
            scratch,
            &owner,
        )?)
    } else {
        None
    };
    let outer = available.bundle.outer_file().try_clone()?;
    let publication = open_role(&available.bundle, "publication")?;
    let intent = open_role(&available.bundle, "source-preparation-intent")?;
    let core = available.bundle.core();
    let ticket = core.ticket.clone();
    let shadow = core.shadow.clone();
    let admission = core.source_resource_admission;
    let selected = available.selected;
    let native_bytes_written = available.native_bytes_written;
    let (native, facts) = available.journal.split_for_observation()?;
    let pins = PagedRecoveryPins {
        journal_binding: facts.binding,
        journal_identity: facts.identity,
        journal_path: facts.path,
        journal_profile: facts.profile,
        digest: ticket.digest_algorithm(),
        immutable_sha256: ticket.immutable_sha256,
        old_selected_sha256: ticket.old_selected_sha256,
        old_restored_selected_sha256: ticket.old_restored_selected_sha256,
        new_selected_sha256: ticket.new_selected_sha256,
    };
    let guard = native.open_offline_terminal_guard(
        available.source,
        available.boot,
        &available.policy,
        pins,
        outer,
        publication,
        intent,
        budget,
        observer,
        events,
    )?;
    if let Some(metadata) = metadata {
        let proof = {
            let view = guard.readonly_volume();
            let pair = n2r_win32::general_layout::GeneralSourceShadowBinding {
                source: view.binding().clone(),
                shadow,
            };
            let proof = view.observe_converted_metadata_with_memory(
                pair,
                &PagedInputs(metadata.expected()),
                |a, b| {
                    crate::ntfs_attestation::same_security_null_sacl_as_absent(a, b)
                        .map_err(std::io::Error::other)
                },
                n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(admission)),
                &ArenaReportMemory(arena),
                events,
            )?;
            let count = metadata.compare(&proof)?;
            (proof, count)
        };
        let (proof, map_count) = proof;
        let object_count = proof.report().native.objects.len() as u64;
        observer.checkpoint_native_events(
            "cold-terminal-native-and-retained-maps-before-writable",
            events,
        )?;
        let restoration = guard.finish_handoff(
            proof,
            &output.join("boot-selection-restore"),
            observer,
            events,
        )?;
        Ok(PreparedOfflineTerminalReceipt {
            kind: "actual-cold-HND-native-before-writable-v1",
            restoration,
            selected,
            native_bytes_written,
            readonly_native_metadata_objects: object_count,
            retained_map_bindings: map_count,
            actual_native_and_maps_before_writable: true,
            stable_release_qualified: false,
        })
    } else {
        let proof = guard.observe_aborted(events)?;
        observer.checkpoint_native_events(
            "cold-terminal-actual-OLD-native-NTFS-before-writable",
            events,
        )?;
        let restoration = guard.finish_aborted(
            proof,
            &output.join("boot-selection-restore"),
            observer,
            events,
        )?;
        Ok(PreparedOfflineTerminalReceipt {
            kind: "actual-cold-ABT-native-before-writable-v1",
            restoration,
            selected,
            native_bytes_written,
            readonly_native_metadata_objects: 0,
            retained_map_bindings: 0,
            actual_native_and_maps_before_writable: true,
            stable_release_qualified: false,
        })
    }
}
