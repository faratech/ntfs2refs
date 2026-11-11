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
        /// Measure single-thread SHA-256 backends in memory instead of reads.
        #[arg(long)]
        hash_only: bool,
    }
    let args = Args::parse();
    if args.hash_only {
        use sha2::Digest;
        let buffer: Vec<u8> = (0..4 * 1024 * 1024u32)
            .map(|i| i.wrapping_mul(2_654_435_761) as u8)
            .collect();
        let rounds = 256;
        let started = std::time::Instant::now();
        let mut soft = sha2::Sha256::new();
        for _ in 0..rounds {
            soft.update(&buffer);
        }
        let _ = soft.finalize();
        let soft_rate = (rounds * buffer.len()) as f64 / started.elapsed().as_secs_f64() / 1e6;
        let started = std::time::Instant::now();
        let mut native = n2r_win32::sha256_native::Sha256::new()?;
        for _ in 0..rounds {
            native.update(&buffer)?;
        }
        let _ = native.finish()?;
        let native_rate = (rounds * buffer.len()) as f64 / started.elapsed().as_secs_f64() / 1e6;
        let started = std::time::Instant::now();
        let mut xxh3 = xxhash_rust::xxh3::Xxh3::new();
        for _ in 0..rounds {
            xxh3.update(&buffer);
        }
        let _ = xxh3.digest128();
        let xxh3_rate = (rounds * buffer.len()) as f64 / started.elapsed().as_secs_f64() / 1e6;
        println!(
            "{}",
            serde_json::json!({"kind":"hash-backend-benchmark","bytes":rounds*buffer.len(),
                "sha2_software_mb_per_second":soft_rate,"cng_mb_per_second":native_rate,
                "xxh3_128_mb_per_second":xxh3_rate,
                "xxh3_avx2_compiled":cfg!(target_feature = "avx2")})
        );
        return Ok(());
    }
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
