//! Confirmed public routing to the actual partition-scoped owners. Metadata
//! selection and automatic resource budgets are never source/write authority.
use super::{DriveArgs, windows};
use crate::{
    resource_partition_alpha::{
        self, PartitionAlphaRequest, PartitionRecoveryDirection, PartitionRecoveryRequest,
    },
    selected_capacity::SelectedCapacityPolicy,
    selected_journal::resource_domain::source_scope::ResourceRecoverySourceScope,
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    discovery::{self, Role, VolumeDiscovery},
    drive_inventory::PartitionSelection,
    general_layout::GeneralDiskBinding,
    journal_file::GeneralJournalStorageBinding,
    managed_shadow::TargetFormatProfile,
    partition_isolation::{
        PartitionObservationBudget, PartitionScopedReader, PartitionSourceBinding,
    },
    partition_lifecycle::PartitionPreparationGuard,
    resource_native::{self, AvailableResources},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn align(bytes: u64) -> u64 {
    bytes / 4096 * 4096
}
/// Resolve current Windows from the SDK's GetWindowsDirectoryW-backed native
/// inventory, never mutable SystemRoot/SystemDrive process environment values.
fn native_windows_route() -> Result<(PathBuf, GeneralDiskBinding)> {
    let inventory = n2r_win32::drive_inventory::inventory_drives_readonly()?;
    let matches: Vec<_> = inventory
        .volumes
        .iter()
        .filter(|volume| volume.contains_running_windows == Some(true))
        .collect();
    ensure!(
        matches.len() == 1,
        "actual current Windows volume is unknown or ambiguous"
    );
    let volume = matches[0];
    let route = discovery::discover(
        &volume.volume_guid_path,
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        route.read_only
            && route.observed_twice_unchanged
            && route.source_write_requests == 0
            && route.disk_is_windows_disk
            && volume.extents.len() == 1
            && volume.extents[0].disk_number == route.binding.disk_number
            && volume.extents[0].offset_bytes == route.binding.identity.partition_offset
            && volume.extents[0].length_bytes == route.binding.identity.partition_bytes,
        "native current Windows volume and complete storage routing differ"
    );
    let mut roots: Vec<_> = volume
        .mount_paths
        .iter()
        .filter(|path| {
            let b = path.as_bytes();
            b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
        })
        .collect();
    roots.sort();
    let root = roots
        .first()
        .context("actual Windows volume has no ordinary local drive root")?;
    Ok((PathBuf::from(root.as_str()), route.binding))
}
fn require_parent_windows(path: &Path, windows: &GeneralDiskBinding) -> Result<()> {
    ordinary_existing(path)?;
    // Discovery accepts exact mounted volume roots, not ordinary directories.
    // Bind the actual held directory to its GUID volume instead of passing
    // its path spelling (which may contain forward separators) as a root.
    let directory = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(3)
        .custom_flags(0x0220_0000)
        .open(path)?;
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
        "held metadata parent must be an ordinary directory");
    let identity = n2r_win32::file_storage::file_id_info(&directory)?;
    let guid_path = n2r_win32::file_storage::final_path_guid(&directory)?;
    let root_end = guid_path.find("}\\").context("held parent GUID volume root absent")? + 2;
    let route = discovery::discover(
        &guid_path[..root_end],
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        route.read_only
            && route.observed_twice_unchanged
            && route.source_write_requests == 0
            && &route.binding == windows,
        "metadata parent is not the actual current Windows volume; no directories were authorized"
    );
    ensure!(n2r_win32::file_storage::file_id_info(&directory)? == identity,
        "held metadata parent identity changed during volume discovery");
    Ok(())
}
fn ordinary_existing(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|p| matches!(p, Component::ParentDir | Component::CurDir)),
        "absolute ordinary metadata path required"
    );
    for parent in path.ancestors() {
        let meta = fs::symlink_metadata(parent)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "metadata ancestry must be ordinary directories"
        );
    }
    Ok(())
}
fn parent_route(scratch: Option<&Path>) -> Result<(PathBuf, PathBuf, GeneralDiskBinding)> {
    let (os, windows) = native_windows_route()?;
    let parent = scratch
        .map(Path::to_path_buf)
        .unwrap_or_else(|| os.join("ProgramData").join("ntfs2refs").join("runs"));
    let text = parent.to_str().context("Unicode working path required")?;
    ensure!(
        parent.is_absolute()
            && text.len() >= 3
            && text.as_bytes()[0].is_ascii_alphabetic()
            && &text[1..3] == ":\\"
            && !text[3..].contains(':')
            && !parent
                .components()
                .any(|p| matches!(p, Component::CurDir | Component::ParentDir)),
        "partition-scoped working storage currently must be on the actual Windows volume; external journals are not supported"
    );
    let existing = parent
        .ancestors()
        .find(|p| p.exists())
        .context("working parent has no existing ancestor")?
        .to_path_buf();
    require_parent_windows(&existing, &windows)?;
    Ok((parent, existing, windows))
}
fn fresh(parent: &Path, role: &str) -> Result<PathBuf> {
    let mut hash = Sha256::new();
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .to_le_bytes(),
    );
    hash.update(std::process::id().to_le_bytes());
    let path = parent.join(format!(
        "partition-{role}-{}",
        &hex::encode(hash.finalize())[..32]
    ));
    ensure!(!path.try_exists()?, "fresh partition run already exists");
    Ok(path)
}
fn total_ram(available: AvailableResources) -> u64 {
    available.available_physical_bytes - available.available_physical_bytes / 3
}
fn observation_budget(total: u64) -> Result<PartitionObservationBudget> {
    let ram = total / 16;
    let budget = PartitionObservationBudget {
        ram_bytes: ram,
        // The existing critical-role native-control ABI admits64KiB layout
        // buffers. This preserves that implementation boundary, not a new
        // file/volume-size/count cap. Larger layouts remain an explicit refusal.
        native_layout_bytes: u32::try_from((ram / 64).clamp(192, 65536))?,
        gpt_entry_bytes: ram / 64,
        read_buffer_bytes: u32::try_from(align((ram / 16).min(4 * 1024 * 1024)))?,
    };
    budget.validate()?;
    Ok(budget)
}
struct Plan {
    total: u64,
    observation: PartitionObservationBudget,
    arena: u64,
    stage: u64,
    evidence: u64,
    keep: u64,
    planning_headroom: u64,
}
fn automatic(available: AvailableResources, ancestor: &Path, staging: bool, controlled_pause: bool) -> Result<Plan> {
    let total = total_ram(available);
    let observation = observation_budget(total)?;
    let keep = (available.scratch_available_bytes / 4).min(16 * 1024 * 1024 * 1024);
    let usable = available
        .scratch_available_bytes
        .checked_sub(keep)
        .context("working reserve underflow")?;
    let evidence = align(usable / 256);
    let intent = if staging {
        let parent = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(ancestor)?;
        PartitionPreparationGuard::maximum_intent_file_bytes()
            .checked_add(n2r_win32::file_storage::artifact_allocation_slack(&parent)?)
            .context("intent reserve overflow")?
    } else {
        0
    };
    let working = usable
        .checked_sub(evidence.checked_mul(2).context("evidence overflow")?)
        .and_then(|n| n.checked_sub(intent))
        .and_then(|n| n.checked_sub(if controlled_pause {
            resource_partition_alpha::CONTROLLED_POST_FLUSH_EVIDENCE_RESERVE_BYTES
        } else { 0 }))
        .context("space cannot cover independent intent/evidence and optional qualification control")?;
    // Availability is sampled before directory creation/formatting. Do not
    // promise every remaining byte: provider/control filesystem metadata and
    // unrelated Windows activity can consume space between those samples.
    // Keep all actual capacity checks and named reservations intact.
    let planning_headroom = align(working / 64);
    let working = working.checked_sub(planning_headroom)
        .context("planning headroom underflow")?;
    let stage = if staging { align(working / 3) } else { 0 };
    let arena = align(working - stage);
    ensure!(
        evidence > 0 && arena > 0 && (!staging || stage > 0),
        "insufficient observed working resources"
    );
    Ok(Plan {
        total,
        observation,
        arena,
        stage,
        evidence,
        keep,
        planning_headroom,
    })
}

pub(super) fn convert(
    args: &DriveArgs,
    selected: PartitionSelection,
    before: VolumeDiscovery,
) -> Result<u8> {
    ensure!(args.controlled_post_flush_pause_nonce.is_some()
        == args.acknowledge_controlled_post_flush_pause,
        "controlled qualification pause requires both nonce and separate acknowledgement");
    if let Some(nonce) = args.controlled_post_flush_pause_nonce.as_deref() {
        super::parse_controlled_pause_nonce(nonce).map_err(anyhow::Error::msg)?;
    }
    let controlled_pause = args.controlled_post_flush_pause_nonce.is_some();
    ensure!(
        before.disk_is_windows_disk
            && before.read_only
            && before.observed_twice_unchanged
            && before.filesystem == "NTFS",
        "actual readonly shared-disk NTFS routing required"
    );
    ensure!(
        !args.whole_image_verification,
        "whole-image verification is not implemented for partition-scoped conversion; use allocation-bounded conversion"
    );
    ensure!(
        !args.experimental_thin_shadow && args.experimental_thin_backing_bytes.is_none(),
        "thin staging is not implemented for partition-scoped conversion; this route uses owned native VHDX staging"
    );
    let format: TargetFormatProfile = args
        .target_format
        .as_deref()
        .unwrap_or("dev-drive")
        .parse()?;
    let (parent, ancestor, windows_binding) = parent_route(args.scratch_directory.as_deref())?;
    let plan = automatic(
        resource_native::observe_available_resources(&ancestor)?,
        &ancestor,
        true,
        controlled_pause,
    )?;
    let binding = PartitionSourceBinding {
        storage: before.binding.clone(),
    };
    let mut events = Vec::new();
    let mut reader = PartitionScopedReader::open(binding, plan.observation, &mut events)?;
    let mut boot = [0u8; 512];
    reader.read_exact(&mut boot)?;
    let geometry = crate::ntfs_inspect::inspect_boot_sector(&boot, reader.byte_len())?;
    ensure!(
        crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(None)
            .supports_source_geometry(&geometry),
        "selected NTFS geometry is not supported by the V4 profile"
    );
    let actual = reader.observation().windows_volume.clone();
    ensure!(
        windows_binding.disk_number == actual.disk_number
            && windows_binding.identity.partition_offset == actual.offset
            && windows_binding.identity.partition_bytes == actual.length,
        "Windows working-volume routing differs from actual native source observation"
    );
    drop(reader);
    println!(
        "Selected: disk {}, partition {} — NTFS, {:.2} GiB.",
        selected.disk_number,
        selected.partition_number,
        before.binding.identity.partition_bytes as f64 / 1073741824.0
    );
    println!(
        "Shared Windows disk: only the selected data partition is converted; boot/Windows/system/pagefile partitions remain refused."
    );
    println!("Experimental shared-disk path: native qualification is still in progress.");
    println!(
        "Target: {format}; allocation-bounded {} verification.",
        if args.verify_full_content {
            "full-content"
        } else {
            "extent-identity"
        }
    );
    if args.minimize_scratch {
        println!(
            "Reduced scratch: rollback preserves admitted allocated NTFS semantics; unused-space bytes may change. VSS snapshots/diff areas are refused."
        );
    }
    println!(
        "Working storage: {} (actual Windows volume only).",
        parent.display()
    );
    println!("Uncommitted planning headroom: {} bytes; this is not a disk reservation.", plan.planning_headroom);
    if controlled_pause {
        println!("Qualification control: wait up to120seconds after actual non-discovery source flush/readback, then Continue or timeout. This does not qualify a first write or physical power loss.");
    }
    if !windows::confirm(
        "Convert this partition to ReFS in place, preserving supported files? [y/N]",
    )? {
        println!("Cancelled. No conversion started.");
        return Ok(0);
    }
    let current = discovery::discover(
        &selected.volume_guid_path,
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        current.binding == before.binding
            && current.disk_is_windows_disk
            && current.filesystem == "NTFS",
        "selected partition changed while awaiting confirmation"
    );
    require_parent_windows(&ancestor, &windows_binding)?;
    windows::ordinary_parents(&parent)?;
    require_parent_windows(&parent, &windows_binding)?;
    let plan = automatic(
        resource_native::observe_available_resources(&parent)?,
        &parent,
        true,
        controlled_pause,
    )?;
    let output = fresh(&parent, "conversion")?;
    let request = PartitionAlphaRequest {
        schema_version: 1,
        source_root: selected.volume_guid_path,
        expected_source: current.binding,
        observation_budget: plan.observation,
        total_ram_bytes: plan.total,
        arena_scratch_bytes: plan.arena,
        maximum_staging_allocation_bytes: plan.stage,
        maximum_evidence_bytes: plan.evidence,
        minimum_free_bytes: plan.keep,
        verification_policy: if args.verify_full_content {
            VerificationPolicy::FullContent
        } else {
            VerificationPolicy::ExtentIdentityV1
        },
        target_format: format,
        selected_capacity_policy: if args.minimize_scratch {
            SelectedCapacityPolicy::SourceFreeActualBytesV1
        } else {
            SelectedCapacityPolicy::ConservativeV1
        },
    };
    println!("Conversion records: {}", output.display());
    let pause_nonce = args.controlled_post_flush_pause_nonce.clone();
    let pause_ack = args.acknowledge_controlled_post_flush_pause;
    let worker = std::thread::Builder::new()
        .name("public-partition-conversion".into())
        .stack_size(resource_partition_alpha::WORKER_STACK_BYTES)
        .spawn(move || match pause_nonce {
            Some(nonce) => resource_partition_alpha::run_with_controlled_post_flush_pause(
                request, &output, true, nonce, pause_ack),
            None => resource_partition_alpha::run(request, &output, true),
        })?;
    worker.join().map_err(|_| {
        anyhow::anyhow!(
            "partition conversion worker panicked; preserve the printed run and actual source state"
        )
    })??;
    Ok(0)
}

#[derive(Deserialize)]
struct FileRoute {
    path: PathBuf,
    sha256: String,
    bytes: u64,
}
#[derive(Deserialize)]
struct PublicationRoute {
    schema_version: u32,
    kind: String,
    source_scope: ResourceRecoverySourceScope,
    source: GeneralDiskBinding,
    shadow: GeneralDiskBinding,
    locator: FileRoute,
    serialized_publication_grants_authority: bool,
}
#[derive(Deserialize)]
struct LocatorRoute {
    schema_version: u32,
    kind: String,
    source_scope: ResourceRecoverySourceScope,
    source: GeneralDiskBinding,
    journal_binding: GeneralJournalStorageBinding,
    serialized_locator_grants_authority: bool,
}
struct Pinned {
    file: File,
    bytes: Vec<u8>,
    snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
    modified: SystemTime,
    sha: [u8; 32],
}
fn digest(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "original canonical recovery SHA256 required"
    );
    Ok(hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256 width differs"))?)
}
impl Pinned {
    fn open(path: &Path, sha: [u8; 32], maximum: u64) -> Result<Self> {
        ordinary_existing(path.parent().context("metadata parent absent")?)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        ensure!(
            snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
            "ordinary bounded single-link recovery metadata required"
        );
        let modified = file.metadata()?.modified()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(
                snapshot
                    .file_bytes
                    .checked_add(1)
                    .context("metadata length overflow")?,
            )
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == snapshot.file_bytes
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == sha,
            "recovery metadata does not match the independently supplied original pin; no fallback is permitted"
        );
        let mut owner = Self {
            file,
            bytes,
            snapshot,
            modified,
            sha,
        };
        owner.revalidate()?;
        Ok(owner)
    }
    fn revalidate(&mut self) -> Result<()> {
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes
            )? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held recovery metadata identity changed"
        );
        ensure!(
            n2r_win32::sha256_native::hash_range(&mut self.file, 0, self.snapshot.file_bytes)?
                == self.sha,
            "held recovery metadata checksum changed"
        );
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}

/// Returns None only when this directory has no partition-publication route.
/// Existing dedicated protocols retain their original selection and checks.
pub(super) fn try_recover(directory: &Path, checksum: &str, rollback: bool) -> Result<Option<u8>> {
    let candidates = [
        directory.join("recovery.json"),
        directory.join("arena/recovery.json"),
    ];
    let existing = candidates
        .iter()
        .filter_map(|p| match p.try_exists() {
            Ok(true) => Some(Ok(p)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    if existing.is_empty() {
        return Ok(None);
    }
    ensure!(
        existing.len() == 1,
        "ambiguous recovery publication; select the original arena directory"
    );
    let path = existing[0];
    let (parent, ancestor, windows_binding) = parent_route(None)?;
    let available = resource_native::observe_available_resources(&ancestor)?;
    let maximum = available.available_physical_bytes / 256;
    let mut publication = Pinned::open(path, digest(checksum)?, maximum)?;
    let route: PublicationRoute = serde_json::from_slice(&publication.bytes)?;
    route
        .source_scope
        .require_envelope_version(route.schema_version, &route.kind)?;
    route.source_scope.require_partition()?; let source_binding = route.source_scope.partition_binding().context("partition recovery binding absent")?;
    ensure!(
        !route.serialized_publication_grants_authority && source_binding.storage == route.source,
        "foreign partition recovery publication route"
    );
    route.source.validate()?;
    route.shadow.validate()?;
    let mut locator = Pinned::open(&route.locator.path, digest(&route.locator.sha256)?, maximum)?;
    let frame = &locator.bytes;
    ensure!(
        frame.len() >= 64
            && frame.len() as u64 == route.locator.bytes
            && &frame[..8] == b"N2RANC01"
            && u32::from_le_bytes(frame[8..12].try_into()?) == 1
            && frame[12..16] == [0; 4]
            && frame[56..64] == [0; 8]
            && u64::from_le_bytes(frame[16..24].try_into()?).checked_add(64)
                == Some(frame.len() as u64)
            && frame[24..56] == Sha256::digest(&frame[64..])[..],
        "actual framed locator checksum/length/header differs"
    );
    let routed: LocatorRoute = serde_json::from_slice(&frame[64..])?;
    routed
        .source_scope
        .require_locator_version(routed.schema_version, &routed.kind)?;
    ensure!(
        !routed.serialized_locator_grants_authority
            && routed.source == route.source
            && routed.source_scope == route.source_scope,
        "locator and independently pinned publication source scope differ"
    );
    routed.journal_binding.validate()?;
    route
        .source_scope
        .require_journal_route(&route.source, &routed.journal_binding)?;
    println!(
        "Pinned source: disk {}, partition {}. Recovery publication: {}.",
        route.source.disk_number,
        route.source.identity.partition_number,
        path.display()
    );
    println!(
        "Action: {}. Only actual private owner and authenticated original artifacts can authorize replay; closed HND/ABT are not replayable.",
        if rollback {
            "restore NTFS before handoff"
        } else {
            "resume interrupted partition conversion"
        }
    );
    if !windows::confirm("Proceed with this partition-scoped recovery? [y/N]")? {
        println!("Cancelled.");
        return Ok(Some(0));
    }
    publication.revalidate()?;
    locator.revalidate()?;
    require_parent_windows(&ancestor, &windows_binding)?;
    windows::ordinary_parents(&parent)?;
    require_parent_windows(&parent, &windows_binding)?;
    let plan = automatic(
        resource_native::observe_available_resources(&parent)?,
        &parent,
        false,
        false,
    )?;
    let output = fresh(&parent, "recovery")?;
    let request = PartitionRecoveryRequest {
        schema_version: 1,
        source: source_binding.clone(),
        shadow: route.shadow,
        journal: routed.journal_binding,
        publication: path.to_owned(),
        publication_sha256: checksum.to_owned(),
        observation_budget: plan.observation,
        total_ram_bytes: plan.total,
        arena_scratch_bytes: plan.arena,
        maximum_evidence_bytes: plan.evidence,
        minimum_free_bytes: plan.keep,
        direction: if rollback {
            PartitionRecoveryDirection::Rollback
        } else {
            PartitionRecoveryDirection::Resume
        },
    };
    println!("Recovery records: {}", output.display());
    let worker = std::thread::Builder::new()
        .name("public-partition-recovery".into())
        .stack_size(resource_partition_alpha::PARTITION_RECOVERY_WORKER_STACK_BYTES)
        .spawn(move || resource_partition_alpha::run_recovery(request, &output, true))?;
    worker.join().map_err(|_| {
        anyhow::anyhow!(
            "partition recovery worker panicked; preserve actual source and original artifacts"
        )
    })??;
    drop(locator);
    drop(publication);
    Ok(Some(0))
}
