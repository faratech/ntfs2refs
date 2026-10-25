//! Guest-only ordinary ReFS mutation workload after journal handoff. No raw
//! partition writes, snapshots, journal replay or old-NTFS rollback exist.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{mounted_filesystem_general, rediscover_general_volume};
    use ntfs2refs::general_reconstruct;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    const CHUNK: usize = 65536;
    const INITIAL: u64 = 50 * 1024 * 1024;
    const GROWN: u64 = 80 * 1024 * 1024;
    const TRUNCATED: u64 = 10 * 1024 * 1024;

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        output: PathBuf,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "mutation report exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    fn hash_exact(file: &mut File, length: u64) -> Result<String> {
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; CHUNK];
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        Ok(hex::encode(hash.finalize()))
    }
    let args = Args::parse();
    ensure!(
        args.run_id.len() == 32
            && args
                .run_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !args.output.exists(),
        "mutation identity or fresh output differs"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 131072,
        "bounded ordinary request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        args.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "mutation request pin differs"
    );
    let request: general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
            && request.pair.source.disk_number == 1
            && request.pair.source.identity.partition_bytes == 52 * 1024 * 1024 * 1024,
        "mutation workload is restricted to the disposable owning guest"
    );
    let mut events = Vec::new();
    let mounted = rediscover_general_volume(request.pair.source.clone(), &mut events)?;
    ensure!(
        mounted_filesystem_general(mounted.clone(), &mut events)? == "ReFS",
        "converted source is not mounted as ReFS"
    );
    let root = PathBuf::from(format!("{}\\", mounted.volume_path()?));
    let directory = root.join(format!("n2r-mutation-{}", args.run_id));
    ensure!(
        !directory.exists(),
        "fresh ReFS mutation directory required"
    );
    let intent = args.output.with_extension("intent.json");
    ensure!(!intent.exists(), "fresh mutation intent required");
    save(
        &intent,
        &serde_json::json!({"schema_version":1,"kind":"general-refs-mutation-intent",
            "run_id":args.run_id,"request_sha256":args.request_sha256,
            "directory":directory,"ntfs_rollback_closed":true}),
    )?;
    fs::create_dir(&directory)?;
    let original = directory.join("grow.bin");
    let renamed = directory.join("renamed.bin");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&original)?;
    let mut full_hash = Sha256::new();
    let mut short_hash = Sha256::new();
    for index in 0..INITIAL / CHUNK as u64 {
        let pattern = Sha256::digest(index.to_le_bytes());
        let mut chunk = [0u8; CHUNK];
        for part in chunk.chunks_exact_mut(pattern.len()) {
            part.copy_from_slice(&pattern);
        }
        file.write_all(&chunk)?;
        full_hash.update(&chunk);
        if index < TRUNCATED / CHUNK as u64 {
            short_hash.update(&chunk);
        }
    }
    file.sync_all()?;
    ensure!(
        hash_exact(&mut file, INITIAL)? == hex::encode(full_hash.finalize()),
        "ReFS initial file readback differs"
    );
    file.set_len(GROWN)?;
    file.seek(SeekFrom::Start(GROWN - 1))?;
    file.write_all(&[0xa5])?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(INITIAL))?;
    let mut gap = [1u8; CHUNK];
    file.read_exact(&mut gap)?;
    ensure!(
        gap.iter().all(|byte| *byte == 0),
        "ReFS grown VDL gap is not zero"
    );
    file.set_len(TRUNCATED)?;
    file.sync_all()?;
    drop(file);
    ensure!(!renamed.exists(), "fresh ReFS rename target required");
    fs::rename(&original, &renamed)?;
    let mut renamed_file = File::open(&renamed)?;
    ensure!(
        hash_exact(&mut renamed_file, TRUNCATED)? == hex::encode(short_hash.finalize()),
        "ReFS truncated file contents differ"
    );
    drop(renamed_file);
    fs::remove_file(&renamed)?;
    for index in 0..128u32 {
        let path = directory.join(format!("entry-{index:03}.bin"));
        let mut small = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        small.write_all(&index.to_le_bytes())?;
        small.sync_all()?;
    }
    for index in 0..128u32 {
        fs::remove_file(directory.join(format!("entry-{index:03}.bin")))?;
    }
    fs::remove_dir(&directory)?;
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":"general-refs-mutation-workload",
            "run_id":args.run_id,"initial_bytes":INITIAL,"grown_bytes":GROWN,
            "truncated_bytes":TRUNCATED,"directory_entries_created":128,
            "mutation_directory_removed":true,"only_new_test_paths_written":true,
            "events":events,"production_conversion_qualified":false}),
    )?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ReFS mutation workload requires the disposable Windows guest");
    std::process::exit(1);
}
