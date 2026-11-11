//! Read-only, bounded-memory native bitmap collection on a routed data volume.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use n2r_win32::{GeneralPartitionReader, bitmap_streaming, general_layout::GeneralDiskBinding};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::MetadataExt,
        path::PathBuf,
    };

    #[derive(Parser)]
    #[command(
        about = "Stream a dedicated NTFS data volume bitmap; no locking, disk setters or conversion"
    )]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        output: PathBuf,
        /// Explicit read budget; this does not allocate the whole bitmap.
        #[arg(long, default_value_t = 64 * 1024 * 1024 * 1024u64)]
        max_bitmap_bytes: u64,
        #[arg(long, default_value_t = 131072)]
        max_pages: u64,
        #[arg(long, default_value_t = 65536)]
        max_allocated_ranges: usize,
    }
    let args = Args::parse();
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 16384,
        "bounded regular binding file required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    let output_text = args.output.to_string_lossy();
    ensure!(
        output_text.to_ascii_uppercase().starts_with("C:\\") && !args.output.exists(),
        "fresh evidence output on the Windows OS volume required"
    );
    ensure!(
        args.max_allocated_ranges <= 1_000_000,
        "interval report budget exceeds bound"
    );
    for ancestor in args
        .output
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary output ancestry required"
        );
    }
    let max_returned_bytes = args
        .max_bitmap_bytes
        .checked_mul(2)
        .and_then(|n| {
            args.max_pages
                .checked_mul(16)
                .and_then(|headers| n.checked_add(headers))
        })
        .ok_or_else(|| anyhow::anyhow!("bitmap read budget overflow"))?;
    let mut events = Vec::new();
    let mut reader = GeneralPartitionReader::open(binding.clone(), &mut events)?;
    let mut boot = [0; 512];
    reader.read_exact(&mut boot)?;
    let geometry = ntfs2refs::ntfs_inspect::inspect_boot_sector(&boot, reader.byte_len())?;
    let mut observed_pages = 0u64;
    let summary = bitmap_streaming::capture_general(
        binding.clone(),
        geometry.total_clusters,
        &[0; 8],
        bitmap_streaming::Limits {
            max_bitmap_bytes: args.max_bitmap_bytes,
            max_pages: args.max_pages,
            max_returned_bytes,
            max_allocated_ranges: args.max_allocated_ranges,
        },
        &mut events,
        |_| {
            observed_pages += 1;
            Ok(())
        },
    )?;
    reader.revalidate_route(&mut events)?;
    ensure!(
        summary.pages == observed_pages,
        "native page observation count differs"
    );
    let report = serde_json::json!({"schema_version":1,"kind":"read-only-streamed-ntfs-bitmap",
        "binding":binding,"binding_sha256":args.binding_sha256,"geometry":geometry,
        "bitmap":summary,"events":events,"source_write_requests":0,
        "source_frozen":false,"allocation_stability_verified":false,
        "conversion_qualified":false,"execution_authorized":false});
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= 128 * 1024 * 1024,
        "bitmap report exceeds output budget"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("Saved {} bytes to {}", bytes.len(), args.output.display());
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("native bitmap collection requires Windows");
    std::process::exit(1);
}
