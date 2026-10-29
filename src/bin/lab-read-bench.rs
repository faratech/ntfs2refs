//! Raw sequential read benchmark for choosing request size and queue depth.
//! Reports the disk's storage profile and MB/s per (request size, depth). It
//! opens the disk read-only with write sharing, never writes, and never changes
//! disk attributes.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        disk: u32,
        /// Byte offset of the region to read (4 KiB aligned).
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        offset: u64,
        /// Bytes to read per measurement.
        #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024)]
        bytes: u64,
        #[arg(long, value_delimiter = ',', default_value = "1,2,4,8")]
        sizes_mib: Vec<usize>,
        #[arg(long, value_delimiter = ',', default_value = "1,2,4")]
        depths: Vec<usize>,
    }
    let args = Args::parse();
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(format!(r"\\.\PhysicalDrive{}", args.disk))?;
    let profile = n2r_win32::io_profile::for_disk(&handle);
    drop(handle);
    let mut results = Vec::new();
    // Each measurement reads its own fresh region so host or device caches
    // warmed by an earlier measurement do not inflate a later one.
    let mut region = 0u64;
    for &size_mib in &args.sizes_mib {
        for &depth in &args.depths {
            let offset = args.offset + region * args.bytes.next_multiple_of(4096);
            region += 1;
            let mb_per_second = n2r_win32::io_profile::read_throughput(
                args.disk,
                offset,
                args.bytes,
                size_mib * 1024 * 1024,
                depth,
            )?;
            eprintln!("{size_mib} MiB x QD{depth} at {offset}: {mb_per_second:.0} MB/s");
            results.push(serde_json::json!({
                "request_mib": size_mib, "queue_depth": depth, "offset": offset,
                "mb_per_second": mb_per_second
            }));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "kind": "raw-read-benchmark", "disk": args.disk, "offset": args.offset,
            "bytes_per_measurement": args.bytes, "profile": profile, "results": results,
            "writes": 0
        }))?
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows required");
    std::process::exit(2);
}
