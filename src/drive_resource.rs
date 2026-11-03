//! Confirmed public V4 conversion. Planning uses observed local resources;
//! only the live issuer may activate, and completion uses reopened native proof.
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
    let first = n2r_win32::resource_native::observe_available_resources(run)?;
    let keep = reserve(first.scratch_available_bytes);
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
    // Only the first small chunk exists. Preserve the full independent log
    // ceiling outside the arena's promises before allowing later growth.
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
        evidence_allocation_bytes: observer.allocation_bytes(),
        evidence_maximum_bytes: observer.maximum_bytes(),
        evidence_ram_bytes: observer.ram_bytes(),
        capture_bytes: capture,
        maximum_journal_bytes: journal_bytes,
        maximum_combined_bytes: combined,
    };
    save(&run.join("resource-plan.json"), &plan)?;
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
    let result = (|| -> Result<()> {
        let (publication, sha) = crate::resource_preparation::prepare_with(
            request,
            &prepared_output,
            &mut observer,
            |prepared, events, observer| {
                let path = prepared.publication_path().to_path_buf();
                let sha = parse_sha(prepared.publication_sha256())?;
                let fresh = prepared.into_fresh_apply(events, |batch| {
                    observer.native_events("source-activation", batch)
                })?;
                let mut applied = fresh.apply_and_handoff(
                    events,
                    |batch| observer.native_events("source-apply-and-handoff", batch),
                    |_| {
                        println!("Source changes verified; recording handoff.");
                        io::stdout().flush()?;
                        Ok(())
                    },
                )?;
                applied.seal_handoff_readonly(events, |batch| {
                    observer.native_events("source-handoff-readonly", batch)
                })?;
                ensure!(
                    applied.source() == &pair.source,
                    "completed apply source identity differs"
                );
                drop(applied);
                Ok((path, sha))
            },
        )?;
        // Every original source/shadow/journal borrow has dropped above. The
        // common finalizer reopens the independently pinned publication, proves
        // real HND/NEW bytes, and verifies native files before enabling normal use.
        let current = n2r_win32::resource_native::observe_available_resources(run)?;
        let remaining = current
            .scratch_available_bytes
            .checked_sub(keep)
            .and_then(|n| n.checked_sub(observer.remaining_reservation_bytes()))
            .context("finalization cannot preserve evidence and free-space reserves")?;
        let final_resources = budget(current, aligned(remaining / 2), observer.ram_bytes())?;
        let finalized = crate::resource_finalize::finalize_resource_handoff_with_observer(
            pair,
            journal,
            &publication,
            sha,
            final_resources,
            &run.join("finalization"),
            &mut observer,
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
    let mut route_events = Vec::new();
    let mounts = n2r_win32::capture_mount_paths_general(journal.disk.clone(), &mut route_events)?;
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
