//! Explicit memory/CPU benchmark, never part of conversion or recovery.
#[cfg(windows)]
#[path = "../retained_compare/digest_pipeline.rs"]
mod digest_pipeline;
#[cfg(windows)]
#[path = "../retained_compare/paired_digest.rs"]
mod paired_digest;
#[cfg(windows)]
#[path = "../retained_compare/stream_digest.rs"]
mod stream_digest;

#[cfg(windows)]
fn sequential(bytes: u64, source: &[u8], candidate: &[u8]) -> anyhow::Result<[[u8; 32]; 4]> {
    use stream_digest::StreamDigest;
    let mut hashes = [
        StreamDigest::new(true)?,
        StreamDigest::new(true)?,
        StreamDigest::new(true)?,
        StreamDigest::new(true)?,
    ];
    let mut prefix = [0u8; 16];
    prefix[..8].copy_from_slice(&0u64.to_le_bytes());
    prefix[8..].copy_from_slice(&bytes.to_le_bytes());
    hashes[1].update(&prefix)?;
    hashes[3].update(&prefix)?;
    let mut remaining = bytes;
    while remaining != 0 {
        let count = remaining.min(source.len() as u64) as usize;
        hashes[0].update(&source[..count])?;
        hashes[1].update(&source[..count])?;
        hashes[2].update(&candidate[..count])?;
        hashes[3].update(&candidate[..count])?;
        remaining -= count as u64;
    }
    let [source_raw, source_framed, candidate_raw, candidate_framed] = hashes;
    Ok([
        source_raw.finish()?,
        source_framed.finish()?,
        candidate_raw.finish()?,
        candidate_framed.finish()?,
    ])
}

#[cfg(windows)]
fn pipelined(bytes: u64, source: &[u8], candidate: &[u8]) -> anyhow::Result<[[u8; 32]; 4]> {
    let mut hash = paired_digest::PairHasher::new(bytes)?;
    let mut remaining = bytes;
    while remaining != 0 {
        let count = remaining.min(source.len() as u64) as usize;
        hash.update_pair(&source[..count], &candidate[..count])?;
        remaining -= count as u64;
    }
    let digest = hash.finish()?;
    Ok([
        digest.source_raw,
        digest.source_framed,
        digest.candidate_raw,
        digest.candidate_framed,
    ])
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use std::time::Instant;
    #[derive(Parser)]
    #[command(about = "Bounded CNG four-stream SHA-256 memory benchmark; no files/devices")]
    struct Args {
        /// Bytes per source/candidate stream, from one byte through 4GiB.
        #[arg(long, default_value_t = 256 * 1024 * 1024u64)]
        bytes: u64,
    }
    let args = Args::parse();
    ensure!(
        (1..=4 * 1024 * 1024 * 1024u64).contains(&args.bytes),
        "--bytes must be 1..=4GiB"
    );
    let mut source = vec![0u8; paired_digest::MAX_CHUNK_BYTES];
    let mut candidate = vec![0u8; paired_digest::MAX_CHUNK_BYTES];
    for (index, (left, right)) in source.iter_mut().zip(&mut candidate).enumerate() {
        *left = (index as u8).wrapping_mul(17).wrapping_add(29);
        *right = *left ^ 0x5a;
    }
    let cpus = std::thread::available_parallelism()
        .ok()
        .map(|value| value.get());
    let start = Instant::now();
    let serial = sequential(args.bytes, &source, &candidate)?;
    let serial_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let parallel = pipelined(args.bytes, &source, &candidate)?;
    let pipeline_seconds = start.elapsed().as_secs_f64();
    ensure!(
        serial == parallel,
        "sequential/pipeline four-stream digest mismatch"
    );
    let measurement = |seconds: f64| {
        serde_json::json!({
            "elapsed_seconds": seconds,
            "pair_input_mib_per_second": (args.bytes as f64 * 2.0) / seconds.max(1e-9) / 1048576.0,
            "sha256_input_mib_per_second": (args.bytes as f64 * 4.0 + 32.0) / seconds.max(1e-9) / 1048576.0,
        })
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "kind":"paired-hash-memory-benchmark", "bytes_per_stream":args.bytes,
            "input_buffer_bytes":source.len()+candidate.len(), "available_cpus":cpus,
            "pipeline_worker_policy":"two framed workers when at least 2 CPUs; serial fallback otherwise",
            "digest_order":["source_raw","source_framed","candidate_raw","candidate_framed"],
            "digests":serial.iter().map(hex::encode).collect::<Vec<_>>(), "all_four_match":true,
            "sequential":measurement(serial_seconds), "pipeline":measurement(pipeline_seconds),
            "order":"sequential then pipeline; repeated hot 1MiB buffers; not a storage benchmark",
            "files_or_devices_opened":false, "conversion_qualified":false,
        }))?
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "The actual CNG paired-hash benchmark requires Windows; no files/devices were opened."
    );
    std::process::exit(2);
}
