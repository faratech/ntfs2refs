//! Create only new sparse fixture streams on the enrolled NTFS H: lab volume.
//! No formatting, raw-device writes, deletion, conversion or recovery occurs.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{discovery, file_storage, layout};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::OsString,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
        process::Command,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        probe_id: String,
        #[arg(long)]
        acknowledge_disposable_data_volume: bool,
    }
    fn output_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|e| e == "json"),
            "absolute fresh C JSON output required"
        );
        for component in path.components() {
            match component {
                Component::Prefix(p) => ensure!(
                    matches!(p.kind(), Prefix::Disk(b'C' | b'c')),
                    "output must be on the OS metadata volume"
                ),
                Component::RootDir => (),
                Component::Normal(p) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        p.to_str().context("Unicode output required")?
                    ),
                    "invalid output component"
                ),
                _ => anyhow::bail!("output traversal refused"),
            }
        }
        ensure!(!path.try_exists()?, "output already exists");
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary output ancestry required"
            );
        }
        Ok(())
    }
    fn source() -> Result<discovery::VolumeDiscovery> {
        let source = discovery::discover(r"H:\", discovery::Role::Source)?;
        ensure!(
            source.binding.disk_number == 6
                && layout::guid_bytes(&source.binding.identity.disk_guid)?
                    == layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
                && layout::guid_bytes(&source.binding.identity.partition_guid)?
                    == layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
                && source.binding.identity.partition_number == 2
                && source.binding.identity.partition_offset == 32 * 1024 * 1024
                && source.binding.identity.partition_bytes == 52 * 1024 * 1024 * 1024
                && source.binding.identity.disk_bytes == 56 * 1024 * 1024 * 1024
                && !source.disk_is_windows_disk
                && source.filesystem == "NTFS"
                && source.label == "n2r-links-source"
                && source.bytes_per_sector == 512
                && source.sectors_per_cluster == 8,
            "exact enrolled disk-6 NTFS H: fixture required"
        );
        Ok(source)
    }
    fn command(executable: &Path, arguments: &[OsString]) -> Result<Value> {
        let output = Command::new(executable).args(arguments).output()?;
        ensure!(
            output.stdout.len() <= 131072 && output.stderr.len() <= 131072,
            "fsutil output exceeded bound"
        );
        let record = json!({
            "executable":executable,"arguments":arguments.iter().map(|s|s.to_string_lossy()).collect::<Vec<_>>(),
            "exit_code":output.status.code(),"stdout":String::from_utf8_lossy(&output.stdout),
            "stderr":String::from_utf8_lossy(&output.stderr),
            "stdout_hex":hex::encode(&output.stdout),"stderr_hex":hex::encode(&output.stderr)
        });
        ensure!(output.status.success(), "fsutil failed: {record}");
        Ok(record)
    }
    fn fsutil(executable: &Path, words: &[&str], path: &Path) -> Result<Value> {
        let mut arguments: Vec<OsString> = words.iter().map(|word| OsString::from(*word)).collect();
        arguments.push(path.as_os_str().to_owned());
        command(executable, &arguments)
    }
    fn logical_hash(file: &mut File, length: u64) -> Result<(String, String)> {
        ensure!(
            length <= 33 * 1024 * 1024,
            "fixture stream exceeds bounded hash length"
        );
        ensure!(file.metadata()?.len() == length, "fixture EOF differs");
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut content = n2r_win32::content_digest::Hasher::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut remaining = length;
        while remaining != 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            content.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let mut extra = [0u8; 1];
        ensure!(file.read(&mut extra)? == 0, "fixture has extra bytes");
        Ok((hex::encode(hash.finalize()), content.finish()))
    }
    fn new_sparse(
        path: &Path,
        length: u64,
        islands: &[(u64, usize, u8)],
        executable: &Path,
        created: &mut Vec<Value>,
    ) -> Result<(File, Value)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(3)
            .open(path)?;
        created.push(json!({"path":path,"created":true,"completed":false}));
        let id = file_storage::file_id_info(&file)?;
        let sparse_flag = fsutil(executable, &["sparse", "setflag"], path)?;
        ensure!(
            file.metadata()?.file_attributes() & 0x200 != 0,
            "sparse flag not observed"
        );
        file.set_len(length)?;
        let mut data = Vec::new();
        let mut written = 0u64;
        let mut prior = 0u64;
        for &(offset, count, seed) in islands {
            let end = offset
                .checked_add(count as u64)
                .context("island overflow")?;
            ensure!(
                count != 0 && offset >= prior && end <= length,
                "invalid data island"
            );
            let payload: Vec<u8> = (0..count)
                .map(|i| ((i as u64 * 31 + u64::from(seed)) % 251) as u8)
                .collect();
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&payload)?;
            written += count as u64;
            prior = end;
            data.push(json!({"offset":offset,"length":count,"seed":seed,"sha256":hex::encode(Sha256::digest(&payload))}));
        }
        file.sync_all()?;
        ensure!(
            file_storage::file_id_info(&file)? == id,
            "sparse identity changed"
        );
        let hash = logical_hash(&mut file, length)?;
        let extents = fsutil(executable, &["file", "queryextents"], path)?;
        let snapshot = json!({"path":path,"length":length,"logical_sha256":hash.0,
            "content_digest":hash.1,"content_digest_algorithm":"xxh3-128","file_id_info":id,
            "file_attributes":file.metadata()?.file_attributes(),"data_islands":data,
            "payload_bytes_written":written,"logical_bytes_hashed":length,
            "set_sparse":sparse_flag,"query_extents":extents});
        *created.last_mut().unwrap() = snapshot.clone();
        Ok((file, snapshot))
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume
            && std::env::var("COMPUTERNAME").as_deref() == Ok("N2R-WIN11"),
        "explicit owning-guest fixture acknowledgement required"
    );
    ensure!(
        args.probe_id.len() == 32
            && args
                .probe_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase fixture ID required"
    );
    output_path(&args.output)?;
    let discovered = source()?;
    let executable = PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot absent")?)
        .join("System32")
        .join("fsutil.exe");
    ensure!(
        executable.is_absolute() && executable.is_file(),
        "absolute native fsutil required"
    );
    let parent = fs::symlink_metadata(r"H:\nested")?;
    ensure!(
        parent.is_dir() && parent.file_attributes() & 0x400 == 0,
        "ordinary enrolled alias parent required"
    );
    let islands_path = Path::new(r"H:\sparse-islands.bin");
    let alias_path = Path::new(r"H:\nested\sparse-link.bin");
    let holes_path = Path::new(r"H:\all-hole.bin");
    let ads_path = Path::new(r"H:\ordinary.bin:Sparse.Data:$DATA");
    for path in [islands_path, alias_path, holes_path, ads_path] {
        ensure!(
            !path.try_exists()?,
            "new sparse fixture path already exists: {}",
            path.display()
        );
    }
    let mut base = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(r"H:\ordinary.bin")?;
    let base_id = file_storage::file_id_info(&base)?;
    let base_length = base.metadata()?.len();
    ensure!(
        base_length == 1024 * 1024,
        "ordinary baseline file size differs"
    );
    let base_hash = logical_hash(&mut base, base_length)?;
    let mut created = Vec::new();
    let mut report = json!({"schema_version":1,"kind":"sparse-fixture","probe_id":args.probe_id,"success":false,
        "source":discovered,"formats_performed":0,"raw_writes":0,"deletions_performed":0,"automatic_retry":false});
    let attempt = (|| -> Result<()> {
        let (islands, island_report) = new_sparse(
            islands_path,
            8 * 1024 * 1024 + 123,
            &[
                (0, 8192, 17),
                (4 * 1024 * 1024, 16384, 29),
                (8 * 1024 * 1024, 123, 41),
            ],
            &executable,
            &mut created,
        )?;
        fs::hard_link(islands_path, alias_path)?;
        let alias = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(alias_path)?;
        ensure!(
            file_storage::file_id_info(&alias)? == file_storage::file_id_info(&islands)?,
            "new hard link has another identity"
        );
        let hardlinks = fsutil(&executable, &["hardlink", "list"], islands_path)?;
        let (_holes, hole_report) = new_sparse(
            holes_path,
            16 * 1024 * 1024 + 37,
            &[],
            &executable,
            &mut created,
        )?;
        let (ads, ads_report) = new_sparse(
            ads_path,
            32 * 1024 * 1024 + 91,
            &[(64 * 1024, 8192, 53), (2 * 1024 * 1024, 4096, 67)],
            &executable,
            &mut created,
        )?;
        ensure!(
            file_storage::file_id_info(&ads)? == base_id
                && file_storage::file_id_info(&base)? == base_id,
            "named sparse stream is not on the original base file identity"
        );
        ensure!(
            base.metadata()?.len() == base_length
                && logical_hash(&mut base, base_length)? == base_hash,
            "ordinary default stream changed while adding sparse ADS"
        );
        let after = source()?;
        ensure!(
            after.binding == discovered.binding,
            "source route changed around fixture creation"
        );
        report["source_after"] = serde_json::to_value(after)?;
        report["streams"] = json!([island_report, hole_report, ads_report]);
        report["hardlink"] = json!({"path":alias_path,"file_id_info":file_storage::file_id_info(&alias)?,"query":hardlinks});
        report["base_default"] = json!({"path":r"H:\ordinary.bin","file_id_info":base_id,"length":base_length,
            "sha256":base_hash.0,"content_digest":base_hash.1,"content_digest_algorithm":"xxh3-128","unchanged":true});
        report["fixture_logical_bytes_hashed"] = json!(56 * 1024 * 1024u64 + 251);
        report["fixture_payload_bytes_written"] = json!(36987);
        report["success"] = json!(true);
        Ok(())
    })();
    report["created_streams"] = json!(created);
    if let Err(error) = &attempt {
        report["error"] = json!(format!("{error:#}"));
    }
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= 1024 * 1024, "fixture report exceeds one MiB");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        json!({"success":attempt.is_ok(),"report":args.output,"report_sha256":hex::encode(Sha256::digest(&bytes)),"conversion_qualified":false})
    );
    attempt
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Sparse fixture creation requires the enrolled Windows guest");
    std::process::exit(2);
}
