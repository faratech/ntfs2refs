//! Confirmed public V4 conversion. Planning uses observed local resources;
//! only the live issuer may activate, and completion uses reopened native proof.
#[path = "drive_preparation.rs"]
mod preparation;
#[path = "drive_resource_resume.rs"]
mod resumable;
use crate::{
    resource_preparation::{
        PreparationObserver, ResourcePreparationRequest, file_observer::FilePreparationObserver,
    },
    selected_capacity::SelectedCapacityPolicy,
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::{GeneralJournalStorageBinding, MarkerStorageUse},
    resource_native::AvailableResources,
    tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn aligned(bytes: u64) -> u64 {
    bytes / 4096 * 4096
}
fn reserve(bytes: u64) -> u64 {
    (bytes / 4).min(16 * 1024 * 1024 * 1024)
}

/// These are current hardware shares, not file/stream/volume-count limits.
fn budget(
    available: AvailableResources,
    scratch: u64,
    evidence_ram: u64,
) -> Result<ResourceBudget> {
    let total_ram = available.available_physical_bytes - available.available_physical_bytes / 3;
    let ram = total_ram
        .checked_sub(evidence_ram)
        .context("memory cannot cover the event ledger and metadata")?;
    let page = (ram / 512).clamp(256, n2r_win32::tree_resources::METADATA_PAGE_BYTES as u64) as u32;
    let result = ResourceBudget {
        schema_version: 1,
        ram_bytes: ram,
        scratch_bytes: scratch,
        page_bytes: page,
        max_row_bytes: (ram / 64).min(scratch / 16),
        retained_index_bytes: ram / 4,
        handle_slots: ram / 1024,
    };
    result.validate()?;
    available.validate_budget(result)?;
    Ok(result)
}

#[derive(Serialize)]
struct PublicPlan {
    observed: AvailableResources,
    resources: ResourceBudget,
    reserve_bytes: u64,
    provider_maximum_additional_backing_bytes: u64,
    provider_minimum_host_free_bytes: u64,
    evidence_allocation_bytes: u64,
    evidence_maximum_bytes: u64,
    evidence_ram_bytes: u64,
    capture_bytes: u64,
    maximum_journal_bytes: u64,
    maximum_combined_bytes: u64,
}

fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn convert_owned(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    run: &Path,
    verification_policy: VerificationPolicy,
    selected_capacity_policy: SelectedCapacityPolicy,
) -> Result<()> {
    convert_owned_with_provider_commitment(
        pair,
        journal,
        run,
        verification_policy,
        selected_capacity_policy,
        0,
        0,
        Ok(None),
        crate::execution_mode::ExecutionMode::Convert,
    )
}

/// Preserve the remaining maximum provider growth outside capture/journal
/// promises. The live owner supplies this value; it is never replay authority.
pub(crate) fn convert_owned_with_provider_commitment(
    pair: GeneralSourceShadowBinding,
    journal: GeneralJournalStorageBinding,
    run: &Path,
    verification_policy: VerificationPolicy,
    selected_capacity_policy: SelectedCapacityPolicy,
    provider_commitment: u64,
    provider_minimum_free_bytes: u64,
    staging_meter: std::io::Result<Option<n2r_win32::managed_shadow::StagingAllocationMeter>>,
    mode: crate::execution_mode::ExecutionMode,
) -> Result<()> {
    let first = n2r_win32::resource_native::observe_available_resources(run)?;
    let staging_meter = staging_meter.context("observe actual staging backing owner")?;
    let backing_guard = staging_meter
        .as_ref()
        .map(|meter| -> Result<_> {
            if meter.observe()?.backing_kind != "native-vhdx-outer-backing" {
                return Ok(None);
            }
            Ok(Some(std::sync::Arc::new(
                n2r_win32::managed_shadow::BackingResourceGuard::new(
                    meter.try_clone()?,
                    &pair.shadow,
                    provider_minimum_free_bytes,
                )?,
            )))
        })
        .transpose()?
        .flatten();
    // The legacy plan field denotes a complete maximum. Native VHDX has a
    // rolling allowance instead; its separate admission receipt states that
    // native metadata amplification has no established bound.
    let provider_maximum = if backing_guard.is_some() {
        0
    } else {
        provider_commitment
    };
    let provider_on_working_volume = backing_guard
        .as_ref()
        .map(|guard| guard.shares_volume_with(run))
        .transpose()?
        .unwrap_or(true);
    let working_provider_commitment = if provider_on_working_volume {
        provider_commitment
    } else {
        0
    };
    let working_provider_floor = if provider_on_working_volume {
        backing_guard
            .as_ref()
            .map(|guard| guard.minimum_free_bytes())
            .unwrap_or(provider_minimum_free_bytes)
    } else {
        0
    };
    let keep = reserve(first.scratch_available_bytes)
        .max(working_provider_floor)
        .checked_add(working_provider_commitment)
        .context("provider and working-storage reserve overflow")?;
    let usable = first
        .scratch_available_bytes
        .checked_sub(keep)
        .context("working storage reserve underflow")?;
    let log_path = run.join("native-events.log");
    let log_ram = FilePreparationObserver::required_ram(&log_path)?;
    let mut observer = FilePreparationObserver::create(
        &log_path,
        &pair,
        &journal,
        aligned(usable / 64),
        log_ram,
        keep,
    )?;
    observer.attach_staging_meter(Ok(staging_meter));
    if let Some(guard) = backing_guard {
        observer.note(
            &serde_json::json!({"kind":"native-shadow-backing-admission-v1",
            "backing":guard.observe(0)?,"shares_working_volume":provider_on_working_volume,
            "working_pending_provider_growth_bytes":working_provider_commitment,
            "virtual_capacity_reserved":false,"existing_allocation_charged_again":false}),
        )?;
        observer.attach_backing_guard(guard)?;
    }
    // The public CLI selects this policy for --minimize-scratch. Prealignment
    // runs on live NTFS before the final frozen source certificate exists.
    if selected_capacity_policy == SelectedCapacityPolicy::SourceFreeActualBytesV1 {
        // These moves happen on the live source, before any diagnose stop.
        let authority = mode.source_change_authority("NTFS prealignment (--minimize-scratch)")?;
        println!("Preparing NTFS file placement to reduce recovery storage.");
        let prepass = (|| -> Result<()> {
            let available = n2r_win32::resource_native::observe_available_resources(run)?;
            let scratch = aligned(
                available
                    .scratch_available_bytes
                    .checked_sub(keep)
                    .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
                    .context("prealignment cannot preserve free-space and evidence reserves")?,
            );
            let resources = budget(available, scratch, observer.ram_bytes())?;
            let evidence_remaining = observer.remaining_reservation_bytes();
            preparation::run(
                &pair,
                &journal,
                run,
                resources,
                keep,
                evidence_remaining,
                &mut observer,
                &authority,
            )
        })();
        if let Err(error) = prepass {
            if let Ok(evidence) = observer.finish() {
                if let Err(save_error) = save(&run.join("native-events-summary.json"), &evidence) {
                    eprintln!("Could not save event ledger summary: {save_error}");
                }
            }
            return Err(error.context("NTFS prealignment failed; conversion was not started"));
        }
    }
    // Only the first small chunk exists. Preserve the full independent log
    // ceiling outside the arena's promises before allowing later growth.
    // Resample after prealignment so the frozen conversion uses actual free
    // space and a fresh view of the source's post-move layout.
    let available = n2r_win32::resource_native::observe_available_resources(run)?;
    let scratch = aligned(
        available
            .scratch_available_bytes
            .checked_sub(keep)
            .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
            .context("working storage no longer covers reserve")?,
    );
    let resources = budget(available, scratch, observer.ram_bytes())?;
    let capture = aligned(scratch / 3);
    let journal_bytes = aligned(scratch - scratch / 3);
    let combined = aligned(scratch - scratch / 6);
    let plan = PublicPlan {
        observed: available,
        resources,
        reserve_bytes: keep,
        provider_maximum_additional_backing_bytes: provider_maximum,
        provider_minimum_host_free_bytes: provider_minimum_free_bytes,
        evidence_allocation_bytes: observer.allocation_bytes(),
        evidence_maximum_bytes: observer.maximum_bytes(),
        evidence_ram_bytes: observer.ram_bytes(),
        capture_bytes: capture,
        maximum_journal_bytes: journal_bytes,
        maximum_combined_bytes: combined,
    };
    save(&run.join("resource-plan.json"), &plan)?;
    // The checkpoint owns the exact live public envelope already written
    // above, including the real provider and independently paid evidence fields.
    observer
        .attach_parent_public_resources(serde_json::from_value(serde_json::to_value(&plan)?)?)?;
    let maximum_placement_bytes = pair
        .source
        .identity
        .partition_bytes
        .checked_mul(4)
        .context("placement-work byte format overflow")?;
    let request = ResourcePreparationRequest {
        pair: pair.clone(),
        journal: journal.clone(),
        resources,
        verification_policy,
        selected_capacity_policy,
        maximum_placement_bytes,
        maximum_placement_submissions: usize::try_from(maximum_placement_bytes / 4096)
            .context("placement operation format overflow")?,
        maximum_materialized_bytes: capture,
        maximum_source_read_bytes: None,
        capture_arena_bytes: capture,
        locator_arena_bytes: resources.scratch_bytes / 16,
        max_journal_bytes: journal_bytes,
        max_literal_backing_bytes: capture,
        max_combined_backing_and_journal_bytes: combined,
        minimum_free_bytes: keep,
        marker_profile: None,
        marker_use: MarkerStorageUse::QualifiedProduction,
    };
    request.validate()?;
    let prepared_output = run.join("conversion");
    // Working files are hashed when written and then held; the source is
    // offline, read-only and held. Re-read them in full once, at the gate
    // below, instead of at every checkpoint in between.
    if !crate::resource_preparation::recheck_everything() {
        n2r_win32::verify_policy::check_once();
    }
    let result = (|| -> Result<()> {
        let (publication, sha) = crate::resource_preparation::prepare_with(
            request,
            &prepared_output,
            &mut observer,
            |prepared, events, observer| {
                let path = prepared.publication_path().to_path_buf();
                let sha = parse_sha(prepared.publication_sha256())?;
                // Everything the apply step depends on is verified in full
                // here, immediately before the first write to the source.
                n2r_win32::perf::phase("source-activation");
                let gate = n2r_win32::verify_policy::Gate::enter();
                let fresh = prepared.into_fresh_apply(events, |batch| {
                    observer.native_events("source-activation", batch)
                })?;
                n2r_win32::perf::phase("source-apply-and-handoff");
                let mut applied = fresh.apply_and_handoff(
                    events,
                    |batch| observer.native_events("source-apply-and-handoff", batch),
                    |_| {
                        println!("Source changes verified; recording handoff.");
                        io::stdout().flush()?;
                        Ok(())
                    },
                )?;
                drop(gate);
                applied.seal_handoff_readonly(events, |batch| {
                    observer.native_events("source-handoff-readonly", batch)
                })?;
                ensure!(
                    applied.source() == &pair.source,
                    "completed apply source identity differs"
                );
                // Nothing of the preparation may outlive this point. Its arena
                // holds a read-only duplicate of the recovery journal, and the
                // finalizer reopens that journal exclusively. The alias ledger
                // built during preparation is paid from that arena, so it is
                // released too; the finalizer rebuilds it from the published
                // records, exactly as a restarted `--recover` does.
                drop(applied);
                Ok((path, sha))
            },
        )?;
        // Every original source/shadow/journal owner has dropped above. The
        // common finalizer reopens the independently pinned publication, proves
        // real HND/NEW bytes, and verifies native files before enabling normal use.
        let current = n2r_win32::resource_native::observe_available_resources(run)?;
        let remaining = current
            .scratch_available_bytes
            .checked_sub(keep)
            .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
            .context("finalization cannot preserve evidence and free-space reserves")?;
        let final_resources = budget(current, aligned(remaining / 2), observer.ram_bytes())?;
        let finalized =
            crate::resource_finalize::finalize_resource_handoff_with_windows_aliases_observer(
                pair,
                journal,
                &publication,
                sha,
                final_resources,
                &run.join("finalization"),
                &mut observer,
                None,
            )
            .context(
                "finalizing the applied conversion (the source already holds the ReFS image)",
            )?;
        if let Err(error) = observer.note(&finalized) {
            eprintln!("Conversion completed; the final evidence log could not be updated: {error}");
        }
        if let Err(error) = save(&run.join("resource-completion.json"), &finalized) {
            eprintln!("Conversion completed; the completion report could not be saved: {error}");
        }
        Ok(())
    })();
    // Evidence closing is observational after a successful native finalizer;
    // it cannot reopen replay or change an already completed handoff.
    match observer.finish() {
        Ok(evidence) => {
            if let Err(error) = save(&run.join("native-events-summary.json"), &evidence) {
                eprintln!("Could not save event ledger summary: {error}");
            }
        }
        Err(error) => eprintln!("Could not close event ledger evidence: {error}"),
    }
    result
}

fn parse_sha(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "original recovery SHA-256 required"
    );
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

fn recovery_metadata_limit() -> Result<u64> {
    let os = std::env::var("SystemRoot").context("Windows system directory unavailable")?;
    let root = os.get(..3).context("Windows system volume unavailable")?;
    let sampled = n2r_win32::resource_native::observe_available_resources(Path::new(root))?;
    Ok(sampled.available_physical_bytes / 64)
}

/// Read-only protocol selection from the independently supplied pin. This
/// neither classifies mutable guard state nor grants any native transition.
pub(super) fn preparation_intent_matches(directory: &Path, sha: &str) -> Result<bool> {
    let expected = parse_sha(sha)?;
    let old = directory.join("preparation-intent.json");
    let resumed = directory.join("resume-intent.json");
    ensure!(
        !(old.exists() && resumed.exists()),
        "ambiguous preparation recovery protocol"
    );
    let path = if resumed.exists() { resumed } else { old };
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
        "absolute preparation recovery directory required"
    );
    let maximum = recovery_metadata_limit()?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    ensure!(
        before.file_bytes > 0 && before.number_of_links == 1,
        "bounded ordinary preparation intent required"
    );
    let actual = n2r_win32::sha256_native::hash_range(&mut file, 0, before.file_bytes)?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before,
        "preparation route changed during protocol selection"
    );
    Ok(actual == expected)
}

/// Cancel only an authenticated, still-unconsumed pre-AP preparation. A final
/// publication, missing file, or serialized phase cannot recreate authority.
pub(super) fn recover_preparation(directory: &Path, sha: &str, rollback: bool) -> Result<u8> {
    recover_preparation_in_workspace(directory, sha, rollback, None)
}
pub(super) fn recover_preparation_in_workspace(
    directory: &Path,
    sha: &str,
    rollback: bool,
    workspace: Option<&Path>,
) -> Result<u8> {
    if !rollback {
        return resumable::resume_preparation_in_workspace(directory, parse_sha(sha)?, workspace);
    }
    ensure!(
        workspace.is_none(),
        "preparation cancellation uses its original workspace"
    );
    let (intent, checksum) = if directory.join("resume-intent.json").try_exists()? {
        let probe = crate::resource_preparation::resume_session_inputs::probe_resume_session(
            directory,
            parse_sha(sha)?,
            recovery_metadata_limit()?.min(8 << 20),
        )?;
        ensure!(
            probe.publication_file_observed.is_none() || probe.delegated_publication.is_some(),
            "publication observed without authenticated delegation; preserve state and use its independent publication pin"
        );
        (
            probe.intent.new_preparation_intent.path,
            parse_sha(&probe.intent.new_preparation_intent.sha256)?,
        )
    } else {
        (directory.join("preparation-intent.json"), parse_sha(sha)?)
    };
    let routes = crate::resource_preparation::early_guard::inspect_routes(
        &intent,
        checksum,
        recovery_metadata_limit()?,
    )?;
    if let Some(delegated) = &routes.delegated {
        let recovery_directory = delegated
            .path
            .parent()
            .context("delegated recovery publication has no parent directory")?;
        anyhow::bail!(
            "preparation cancellation is closed; use normal recovery: ntfs2refs --recover \"{}\" --recovery-sha256 {}",
            recovery_directory.display(),
            delegated.sha256
        );
    }
    println!(
        "Pinned source: disk {}, partition {}.\nPreparation directory: {}\nAction: cancel unfinished preparation and restore NTFS access.\nObserved preparation state: {}",
        routes.source.disk_number,
        routes.source.identity.partition_number,
        directory.display(),
        routes.phase
    );
    print!("Proceed with cancellation of this preparation? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(65).read_line(&mut answer)?;
    if answer.len() >= 65 || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Cancelled.");
        return Ok(0);
    }
    let pair = GeneralSourceShadowBinding {
        source: routes.source,
        shadow: routes.shadow,
    };
    let journal = routes.journal;
    for data in [&pair.source, &pair.shadow] {
        ensure!(
            journal.disk.disk_number != data.disk_number
                && n2r_win32::layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?,
            "preparation recovery journal aliases a data disk"
        );
    }
    let mounts = n2r_win32::capture_mount_paths_for_journal(&journal)?;
    let root = mounts
        .paths
        .iter()
        .find(|path| {
            path.len() == 3
                && path.as_bytes()[0].is_ascii_alphabetic()
                && path.as_bytes()[1] == b':'
                && path.as_bytes()[2] == b'\\'
        })
        .map(PathBuf::from)
        .context("the original preparation journal needs a mounted local drive letter")?;
    let space = n2r_win32::resource_native::observe_available_resources(&root)?;
    let mut hash = Sha256::new();
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .to_le_bytes(),
    );
    hash.update(std::process::id().to_le_bytes());
    let id = hex::encode(hash.finalize());
    let output = root.join(format!("ntfs2refs-preparation-cancel-{}", &id[..32]));
    let _ancestry = crate::resource_preparation::create_external_output(&output, &journal)?;
    let log = output.join("native-events.log");
    let log_ram = FilePreparationObserver::required_ram(&log)?;
    let keep = reserve(space.scratch_available_bytes);
    let mut observer = FilePreparationObserver::create(
        &log,
        &pair,
        &journal,
        aligned(space.scratch_available_bytes / 64),
        log_ram,
        keep,
    )?;
    let result = (|| -> Result<serde_json::Value> {
        let actual = n2r_win32::resource_native::observe_available_resources(&output)?;
        let scratch = actual
            .scratch_available_bytes
            .checked_sub(keep)
            .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
            .context("preparation cancellation cannot preserve evidence and free-space reserves")?;
        let resources = budget(actual, aligned(scratch / 2), observer.ram_bytes())?;
        let mut events = Vec::new();
        let cancelled = crate::resource_preparation::early_guard::cancel_preparation(
            &intent,
            checksum,
            resources,
            &mut events,
        );
        let recorded = observer.native_events("preparation-cancellation", &mut events);
        let cancelled = cancelled?;
        if let Err(error) = recorded {
            eprintln!(
                "Preparation cancellation completed; native evidence could not be recorded: {error}"
            );
        }
        Ok(cancelled)
    })();
    match observer.finish() {
        Ok(evidence) => {
            if let Err(error) = save(&output.join("native-events-summary.json"), &evidence) {
                eprintln!("Could not save preparation cancellation evidence: {error}");
            }
        }
        Err(error) => eprintln!("Could not close preparation cancellation evidence: {error}"),
    }
    let cancelled = result?;
    if let Err(error) = save(&output.join("result.json"), &cancelled) {
        eprintln!("Preparation cancellation completed; its result could not be saved: {error}");
    }
    println!(
        "Preparation cancellation completed. Records: {}",
        output.display()
    );
    Ok(0)
}

#[derive(Deserialize)]
struct RouteFile {
    path: PathBuf,
    sha256: String,
    bytes: u64,
}
#[derive(Deserialize)]
struct PublicationRoutes {
    schema_version: u32,
    kind: String,
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    locator: RouteFile,
    serialized_publication_grants_authority: bool,
}
#[derive(Deserialize)]
struct LocatorRoutes {
    source: GeneralDiskBinding,
    journal_binding: GeneralJournalStorageBinding,
    serialized_locator_grants_authority: bool,
}

/// Read-only pre-confirmation facts. These locate inputs and never create the
/// reopened native recovery owner or imply permission to write a device.
fn route_inputs(
    path: &Path,
    expected: [u8; 32],
    maximum: u64,
) -> Result<(GeneralSourceShadowBinding, GeneralJournalStorageBinding)> {
    fn pin(path: &Path, sha: [u8; 32], maximum: u64) -> Result<File> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
            "absolute recovery metadata path required"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() > 0
                && metadata.len() <= maximum,
            "recovery route metadata exceeds observed read budget"
        );
        let actual = n2r_win32::sha256_native::hash_range(&mut file, 0, metadata.len())?;
        ensure!(
            actual == sha,
            "recovery route does not match independently supplied checksum"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    let mut publication = pin(path, expected, maximum)?;
    let route: PublicationRoutes = serde_json::from_reader(&mut publication)?;
    ensure!(
        route.schema_version == 1
            && route.kind == "resource-allocation-recovery-envelope-v1"
            && !route.serialized_publication_grants_authority,
        "not a resource recovery envelope"
    );
    let mut locator = pin(
        &route.locator.path,
        parse_sha(&route.locator.sha256)?,
        maximum,
    )?;
    ensure!(
        locator.metadata()?.len() == route.locator.bytes,
        "locator length differs"
    );
    let mut header = [0u8; 64];
    locator.read_exact(&mut header)?;
    let bytes = u64::from_le_bytes(header[16..24].try_into()?);
    ensure!(
        &header[..8] == b"N2RANC01"
            && bytes > 0
            && bytes.checked_add(64) == Some(route.locator.bytes),
        "locator route frame differs"
    );
    let facts: LocatorRoutes = serde_json::from_reader(locator.take(bytes))?;
    ensure!(
        !facts.serialized_locator_grants_authority && facts.source == route.source,
        "locator source route differs"
    );
    let pair = GeneralSourceShadowBinding {
        source: route.source,
        shadow: route.shadow,
    };
    pair.source.validate()?;
    pair.shadow.validate()?;
    facts.journal_binding.validate()?;
    Ok((pair, facts.journal_binding))
}

pub(crate) fn recover(directory: &Path, sha: &str, rollback: bool) -> Result<u8> {
    let publication = directory.join("recovery-envelope.json");
    let checksum = parse_sha(sha)?;
    let os = std::env::var("SystemRoot").context("Windows system directory unavailable")?;
    let os_root = os.get(..3).context("Windows system volume unavailable")?;
    let sampled = n2r_win32::resource_native::observe_available_resources(Path::new(os_root))?;
    let (pair, journal) = route_inputs(
        &publication,
        checksum,
        sampled.available_physical_bytes / 64,
    )?;
    println!(
        "Pinned source: disk {}, partition {}.\nRecovery directory: {}\nAction: {}",
        pair.source.disk_number,
        pair.source.identity.partition_number,
        directory.display(),
        if rollback {
            "restore NTFS before handoff"
        } else {
            "resume or verify ReFS handoff"
        }
    );
    print!("Proceed with this resource-profile recovery? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(65).read_line(&mut answer)?;
    if answer.len() >= 65 || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Cancelled.");
        return Ok(0);
    }
    // Do not create even the recovery output directory until the actual
    // journal device is independently disjoint from both data devices.
    for data in [&pair.source, &pair.shadow] {
        ensure!(
            journal.disk.disk_number != data.disk_number
                && n2r_win32::layout::guid_bytes(&journal.disk.identity.disk_guid)?
                    != n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?,
            "journal route aliases a source or shadow disk"
        );
    }
    let mut route_events = Vec::new();
    let mounts = n2r_win32::capture_mount_paths_for_journal(&journal)?;
    let root = mounts
        .paths
        .iter()
        .find(|p| {
            p.len() == 3
                && p.as_bytes()[0].is_ascii_alphabetic()
                && p.as_bytes()[1] == b':'
                && p.as_bytes()[2] == b'\\'
        })
        .map(PathBuf::from)
        .context("the original journal needs a mounted local drive letter for recovery output")?;
    let space = n2r_win32::resource_native::observe_available_resources(&root)?;
    let mut hash = Sha256::new();
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .to_le_bytes(),
    );
    hash.update(std::process::id().to_le_bytes());
    let id = hex::encode(hash.finalize());
    let output = root.join(format!("ntfs2refs-recovery-{}", &id[..32]));
    let _ancestry = crate::resource_preparation::create_external_output(&output, &journal)?;
    let log = output.join("native-events.log");
    let log_ram = FilePreparationObserver::required_ram(&log)?;
    let mut observer = FilePreparationObserver::create(
        &log,
        &pair,
        &journal,
        aligned(space.scratch_available_bytes / 64),
        log_ram,
        reserve(space.scratch_available_bytes),
    )?;
    observer.native_events("recovery-journal-route", &mut route_events)?;
    let actual = n2r_win32::resource_native::observe_available_resources(&output)?;
    let resources = budget(
        actual,
        aligned(
            actual
                .scratch_available_bytes
                .checked_sub(reserve(space.scratch_available_bytes))
                .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
                .context("recovery cannot preserve evidence and free-space reserves")?
                / 2,
        ),
        observer.ram_bytes(),
    )?;
    let result = crate::resource_recovery::recover_resource_allocation_with_observer(
        pair,
        journal,
        &publication,
        checksum,
        resources,
        &output.join("recovery"),
        rollback,
        &mut observer,
    );
    let evidence = observer.finish();
    if let Ok(evidence) = evidence {
        let _ = save(&output.join("native-events-summary.json"), &evidence);
    }
    let result = result?;
    if let Err(error) = save(&output.join("result.json"), &result) {
        eprintln!("The native recovery result could not be saved: {error}");
    }
    if result
        .get("already_online_terminal")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        println!("The terminal recovery state is already online; raw replay was not performed.");
        println!("Current contents were not reverified against the conversion-time baseline.");
        let reconciliation = result
            .get("reconciliation")
            .unwrap_or(&serde_json::Value::Null);
        if reconciliation
            .get("reconciliation_complete")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            eprintln!(
                "Recovery reconciliation is incomplete. Missing original mount paths: {}; label action: {}.",
                reconciliation
                    .get("missing_original_mount_paths")
                    .unwrap_or(&serde_json::Value::Null),
                reconciliation
                    .get("label_action")
                    .unwrap_or(&serde_json::Value::Null)
            );
            println!("Recovery records: {}", output.display());
            return Ok(1);
        }
        println!(
            "Label and mount-path reconciliation verified. Records: {}",
            output.display()
        );
        return Ok(0);
    }
    if rollback
        && result
            .get("mount_paths_preserved")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    {
        eprintln!(
            "NTFS was restored, but its original drive letter or mount paths were not restored. Expected: {}; actual: {}.",
            result
                .get("expected_mount_paths")
                .unwrap_or(&serde_json::Value::Null),
            result
                .get("actual_mount_paths")
                .unwrap_or(&serde_json::Value::Null)
        );
    }
    println!("Recovery completed. Records: {}", output.display());
    Ok(0)
}
