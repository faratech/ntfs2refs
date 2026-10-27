//! Read-only timing of both SHA-256 implementations over one pinned real file.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use std::{
        fs,
        io::Write,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
        time::Instant,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh timing report required");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&args.input)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.file_attributes() & 0x400 == 0
            && before.len() <= 8 * 1024 * 1024 * 1024,
        "bounded ordinary benchmark file required"
    );
    let start = Instant::now();
    let native = n2r_win32::sha256_native::hash_range(&mut file, 0, before.len())?;
    let native_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let rust = ntfs2refs::lab_reconstruct::hash_range(&mut file, 0, before.len())?;
    let rust_seconds = start.elapsed().as_secs_f64();
    let after = file.metadata()?;
    ensure!(
        native == rust
            && hex::encode(native) == args.expected_sha256
            && before.len() == after.len()
            && before.last_write_time() == after.last_write_time(),
        "benchmark digest or stable file identity differs"
    );
    let report = serde_json::json!({"kind":"read-only-sha256-backend-timing","input":args.input,
        "bytes":before.len(),"sha256":hex::encode(native),"native_seconds":native_seconds,
        "rust_seconds":rust_seconds,"sha_cpu_feature":std::is_x86_feature_detected!("sha"),
        "native_provider":"Microsoft Primitive Provider","all_bytes_read_by_both":true});
    let bytes = serde_json::to_vec_pretty(&report)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("{}", report);
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native backend timing requires Windows.");
}
