//! Size source-free journal savings from saved ordinary JSON evidence only.
//! This diagnostic never opens a partition, grants source authority or replays.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{
    ntfs_inspect::NtfsInspection,
    selected_journal::SelectedPlan,
    selected_ownership::{Limits, ReconciledSourceAllocation},
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

const INSPECTION_LIMIT: u64 = 64 * 1024 * 1024;
const PLAN_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Size source-free journal encoding using saved ordinary JSON; no device I/O")]
#[command(group(clap::ArgGroup::new("source").required(true).args(["ntfs_inspection", "source_basis"])))]
struct Args {
    /// Standalone NtfsInspection JSON; alternative to --source-basis.
    #[arg(long)]
    ntfs_inspection: Option<PathBuf>,
    /// Saved qualification wrapper with ntfs and canonical_inspection_sha256.
    #[arg(long)]
    source_basis: Option<PathBuf>,
    #[arg(long)]
    selected_plan: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

/// Other historical basis observations grant no live source authority here.
#[derive(Deserialize)]
struct SourceBasis {
    ntfs: NtfsInspection,
    canonical_inspection_sha256: String,
}

#[derive(PartialEq, Eq)]
struct Fingerprint {
    length: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
}

fn fingerprint(file: &File) -> Result<Fingerprint> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "ordinary file handle required");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "reparse file handle refused"
        );
    }
    Ok(Fingerprint {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
    })
}

fn ordinary_json_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        path.extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("json")),
        "ordinary JSON path required"
    );
    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => {
                use std::path::Prefix;
                ensure!(
                    matches!(prefix.kind(), Prefix::Disk(drive) if drive.is_ascii_alphabetic()),
                    "device, UNC and verbatim paths refused"
                );
            }
            Component::RootDir => (),
            Component::Normal(value) => {
                let value = value.to_str().context("Unicode JSON path required")?;
                ensure!(
                    !value.contains(':') && !value.ends_with('.') && !value.ends_with(' '),
                    "alternate streams and ambiguous path components refused"
                );
            }
            _ => anyhow::bail!("path traversal refused"),
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "ordinary JSON ancestry required"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "reparse JSON ancestry refused"
            );
        }
    }
    Ok(path)
}

struct HeldInput {
    file: File,
    before: Fingerprint,
    bytes: Vec<u8>,
    sha256: String,
}

impl HeldInput {
    fn open(path: &Path, limit: u64) -> Result<Self> {
        let path = ordinary_json_path(path)?;
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit,
            "bounded ordinary JSON input required: {}",
            path.display()
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Hold writer/delete exclusion through planning and report flush.
            options.share_mode(1).custom_flags(0x0020_0000);
        }
        let mut file = options.open(&path)?;
        let before = fingerprint(&file)?;
        ensure!(
            before.length > 0 && before.length <= limit,
            "input length exceeds its JSON bound"
        );
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(before.length)?)
            .context("JSON input allocation failed")?;
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.length && fingerprint(&file)? == before,
            "ordinary JSON input changed while reading"
        );
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Ok(Self {
            file,
            before,
            bytes,
            sha256,
        })
    }

    fn revalidate(&self) -> Result<()> {
        ensure!(
            fingerprint(&self.file)? == self.before,
            "held JSON input metadata changed"
        );
        Ok(())
    }
}

fn sizing(plan: &SelectedPlan) -> Result<serde_json::Value> {
    let (selected, journal) = plan.validate()?;
    let free = plan.source_free_bytes()?;
    let zero = plan.old_zero_bytes()?;
    let literal = selected
        .checked_sub(plan.new_zero_bytes()?)
        .and_then(|n| n.checked_sub(plan.new_copy_bytes().ok()?))
        .context("literal byte sizing underflow")?;
    Ok(json!({
        "encoding":plan.encoding_name(), "encoding_version":plan.encoding_version(),
        "selected_bytes":selected, "journal_bytes":journal, "selected_ranges":plan.ranges.len(),
        "old_zero_bytes":zero, "source_free_bytes":free, "source_free_ranges":plan.source_free_ranges.len(),
        "old_restore_required_bytes":plan.old_restored_bytes()?, "old_granule_digest_table_bytes":free/256,
        "stored_old_payload_bytes":selected.checked_sub(zero).and_then(|n| n.checked_sub(free)).context("stored old sizing underflow")?,
        "new_literal_payload_bytes":literal,
    }))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let source_path = args
        .ntfs_inspection
        .as_deref()
        .or(args.source_basis.as_deref())
        .context("exactly one source metadata input is required")?;
    let inspection_input = HeldInput::open(source_path, INSPECTION_LIMIT)?;
    let plan_input = HeldInput::open(&args.selected_plan, PLAN_LIMIT)?;
    let (inspection, recorded_pin) = if args.source_basis.is_some() {
        let basis: SourceBasis = serde_json::from_slice(&inspection_input.bytes)
            .context("parse saved source-basis JSON")?;
        (basis.ntfs, Some(basis.canonical_inspection_sha256))
    } else {
        (
            serde_json::from_slice::<NtfsInspection>(&inspection_input.bytes)
                .context("parse NTFS inventory JSON")?,
            None,
        )
    };
    let plan: SelectedPlan =
        serde_json::from_slice(&plan_input.bytes).context("parse selected-plan JSON")?;
    let geometry = &inspection.geometry;
    let volume = geometry
        .total_sectors
        .checked_mul(u64::from(geometry.bytes_per_sector))
        .context("geometry volume overflow")?;
    ensure!(
        matches!(geometry.bytes_per_sector, 512 | 4096)
            && u32::from(geometry.bytes_per_sector).checked_mul(geometry.sectors_per_cluster)
                == Some(geometry.cluster_size)
            && geometry.cluster_size.is_power_of_two()
            && volume == geometry.volume_size
            && volume > 0
            && volume <= plan.image_length
            && (volume == plan.image_length
                || plan.image_length - volume == u64::from(geometry.bytes_per_sector))
            && geometry.total_clusters == volume / u64::from(geometry.cluster_size),
        "inventory and selected-plan partition geometry differ"
    );
    let allocation = ReconciledSourceAllocation::from_inspection(
        &inspection,
        plan.image_length,
        Limits::default(),
    )?;
    ensure!(
        recorded_pin
            .as_deref()
            .is_none_or(|pin| pin == allocation.source_inspection_sha256()),
        "saved source-basis canonical inspection pin differs from its inventory"
    );
    let refined = allocation.refine_selected_plan(&plan)?;
    let (_, before) = plan.validate()?;
    let (_, after) = refined.validate()?;
    let report = json!({
        "schema_version":1, "kind":"saved-evidence-source-free-journal-sizing",
        "source_input_kind":if args.source_basis.is_some() { "source-basis-wrapper" } else { "standalone-ntfs-inspection" },
        "ntfs_inspection_path":args.ntfs_inspection, "source_basis_path":args.source_basis,
        "source_metadata_file_sha256":inspection_input.sha256,
        "source_basis_file_sha256":args.source_basis.as_ref().map(|_| &inspection_input.sha256),
        "ntfs_inspection_file_sha256":args.ntfs_inspection.as_ref().map(|_| &inspection_input.sha256),
        "source_basis_canonical_inspection_sha256":recorded_pin,
        "ntfs_inspection_model_sha256":allocation.source_inspection_sha256(),
        "ntfs_bitmap_sha256":allocation.ntfs_bitmap_sha256(),
        "selected_plan_path":args.selected_plan, "selected_plan_file_sha256":plan_input.sha256,
        "partition_bytes":plan.image_length, "before":sizing(&plan)?, "refined":sizing(&refined)?,
        "theoretical_journal_bytes_saved":before.checked_sub(after).context("refined journal unexpectedly grew")?,
        "source_allocation_is_saved_evidence_only":true,
        "live_vss_admission_performed":false, "live_source_admission_performed":false,
        "raw_device_opened":false, "source_writes_authorized":false, "journal_replay_authorized":false,
        "native_conversion_qualified":false, "execution_time_estimated":false,
        "scope":"Exact journal encoding sizes from supplied saved metadata; no native conversion, physical I/O, duration or live source-admission claim.",
    });
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= 65536, "diagnostic report exceeds 64 KiB");
    inspection_input.revalidate()?;
    plan_input.revalidate()?;
    let path = ordinary_json_path(&args.output)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0).custom_flags(0x0020_0000);
    }
    let mut output = options.open(&path).context("create fresh sizing report")?;
    fingerprint(&output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    inspection_input.revalidate()?;
    plan_input.revalidate()?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}
