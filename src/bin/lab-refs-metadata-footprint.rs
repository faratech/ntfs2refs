//! Read-only ordinary raw-volume metadata traversal, never conversion authority.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{ntfs_admission::ResourceProfile, refs_inspect, refs_virtual_roots::walk};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
#[derive(Parser)]
struct Args {
    /// Ordinary raw ReFS volume image starting at byte zero, not VHD/VHDX.
    #[arg(long)]
    input: PathBuf,
    /// Fresh bounded JSON file under existing ordinary directories.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t=65536, value_parser=clap::value_parser!(u32).range(10..=1_048_576))]
    max_pages: u32,
}
fn ordinary(path: &Path, leaf: bool) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .to_str()
                .is_some_and(|s| s.encode_utf16().count() <= 32760),
        "bounded absolute path required"
    );
    for part in path.components() {
        match part {
            Component::ParentDir | Component::CurDir => anyhow::bail!("path traversal refused"),
            #[cfg(windows)]
            Component::Prefix(p) => ensure!(
                matches!(p.kind(), std::path::Prefix::Disk(_)),
                "device/UNC/verbatim path refused"
            ),
            Component::Normal(n) => {
                let n = n.to_str().context("Unicode file path required")?;
                ensure!(
                    !n.ends_with([' ', '.'])
                        && !n.chars().any(|c| c.is_control()
                            || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*')),
                    "ambiguous file component"
                );
                let stem = n.split('.').next().unwrap_or("").to_ascii_uppercase();
                ensure!(
                    !matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) && !(stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.as_bytes()[3].is_ascii_digit()),
                    "reserved device name refused"
                );
            }
            _ => {}
        }
    }
    for p in path
        .ancestors()
        .skip(if leaf { 0 } else { 1 })
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            !m.file_type().is_symlink() && if p == path { m.is_file() } else { m.is_dir() },
            "ordinary file/directory ancestry required"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                m.file_attributes() & (0x40 | 0x400) == 0,
                "device/reparse path refused"
            );
        }
    }
    Ok(())
}
fn stamp(file: &File) -> Result<(u64, std::time::SystemTime)> {
    let m = file.metadata()?;
    ensure!(m.is_file(), "ordinary raw image file required");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            m.file_attributes() & (0x10 | 0x40 | 0x400) == 0,
            "directory/device/reparse input refused"
        );
    }
    Ok((m.len(), m.modified()?))
}

struct CountedFile {
    file: File,
    bytes_read: u64,
    read_calls: u64,
    seek_calls: u64,
}
impl Read for CountedFile {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.read(bytes)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("read accounting overflow"))?;
        self.read_calls += 1;
        Ok(count)
    }
}
impl Seek for CountedFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.seek_calls += 1;
        self.file.seek(position)
    }
}
fn main() -> Result<()> {
    let args = Args::parse();
    ordinary(&args.input, true)?;
    ordinary(&args.output, false)?;
    ensure!(!args.output.exists(), "fresh output required");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let input = options
        .open(&args.input)
        .context("open ordinary image read-only")?;
    let before = stamp(&input)?;
    let mut input = CountedFile {
        file: input,
        bytes_read: 0,
        read_calls: 0,
        seek_calls: 0,
    };
    ensure!(before.0 >= 512, "raw image too short");
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    ensure!(
        &magic != b"vhdxfile" && &magic != b"conectix",
        "container is not a raw volume"
    );
    input.seek(SeekFrom::End(-512))?;
    input.read_exact(&mut magic)?;
    ensure!(&magic != b"conectix", "VHD footer is not a raw volume");
    let observation = refs_inspect::inspect_with_resource_profile(
        &mut input,
        before.0,
        ResourceProfile::ExperimentalStreamingTreeV2,
    )?;
    let bootstrap = observation
        .bootstrap
        .as_ref()
        .context("supported fresh bootstrap absent")?;
    ensure!(bootstrap.vbr_checksum_matches, "VBR checksum mismatch");
    let valid: Vec<_> = bootstrap
        .checkpoints
        .iter()
        .filter(|p| {
            p.rejection.is_none()
                && p.header.is_some()
                && p.self_checksum.as_ref().is_some_and(|c| c.matches)
                && !p.referenced_by_superblock_lcns.is_empty()
                && p.checkpoint.as_ref().is_some_and(|c| {
                    c.header_clock_matches
                        && c.major_version == 3
                        && c.minor_version == 14
                        && c.reference_size == 48
                        && c.roots.len() == 13
                })
        })
        .collect();
    let highest = valid
        .iter()
        .map(|p| p.checkpoint.as_ref().unwrap().virtual_clock)
        .max()
        .context("no valid checkpoint")?;
    let selected: Vec<_> = valid
        .iter()
        .filter(|p| p.checkpoint.as_ref().unwrap().virtual_clock == highest)
        .collect();
    ensure!(selected.len() == 1, "highest valid checkpoint is ambiguous");
    let checkpoint = selected[0];
    let geometry = &observation.geometry;
    let containers = bootstrap
        .container_tables
        .as_ref()
        .context("same-observation container maps absent")?;
    ensure!(
        geometry.bytes_per_cluster == 4096,
        "4KiB cluster profile required"
    );
    let mut protected = BTreeSet::from([0, observation.backup_probe_offset / 4096]);
    for p in bootstrap.superblocks.iter().chain(&bootstrap.checkpoints) {
        let end = p
            .byte_offset
            .checked_add(p.bytes_read as u64)
            .context("anchor range overflow")?;
        ensure!(
            end <= geometry.volume_bytes && p.byte_offset.is_multiple_of(4096),
            "anchor outside volume"
        );
        protected.extend(p.byte_offset / 4096..end.div_ceil(4096));
    }
    for p in &bootstrap.physical_root_pages {
        protected.extend(p.lcn_slots);
    }
    let footprint = walk::inspect(
        &mut input,
        geometry,
        checkpoint,
        containers,
        &protected,
        walk::WalkLimits {
            max_pages: args.max_pages,
            ..Default::default()
        },
    )?;
    let after = stamp(&input.file)?;
    ordinary(&args.input, true)?;
    ensure!(
        before == after,
        "held image metadata changed during traversal"
    );
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version":1,"kind":"raw-refs-metadata-footprint","input":args.input,
        "input_bytes":before.0,"input_modified":before.1,"input_metadata_unchanged":true,
        "input_sha256_computed":false,"windows_write_delete_sharing_denied":cfg!(windows),
        "logical_read_bytes":input.bytes_read,"read_calls":input.read_calls,"seek_calls":input.seek_calls,
        "accounting_scope":"Bytes returned by the ordinary file reader, including bootstrap and container inspection; not physical storage I/O.",
        "geometry":geometry,"selected_checkpoint_lcn":checkpoint.lcn,"selected_checkpoint_clock":highest,
        "valid_checkpoint_candidates":valid.len(),"bootstrap_protected_lcns":protected,"footprint":footprint,
        "conversion_authorized":false,"selective_capture_authorized":false,
        "scope":"Metadata-only page transcript, not a full-image content pin or complete allocation ownership proof. No conversion authority."
    }))?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "metadata report exceeds16MiB"
    );
    ordinary(&args.output, false)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}
