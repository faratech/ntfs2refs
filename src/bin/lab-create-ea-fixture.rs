//! Creates only new EA-bearing files/directories on the enrolled NTFS H: disk.
//! No formatting, relocation, deletion or existing-file EA changes occur.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        discovery,
        extended_attributes::{Entry, Set},
        extended_attributes_native, file_storage, layout,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };

    const PAYLOAD_BYTES: usize = 65_536 + 37;
    const REPORT_LIMIT: usize = 4 * 1024 * 1024;
    const DIRECTORY_ACCESS: u32 = 0x0010_0198; // synchronize, attributes and READ/WRITE_EA
    const FILE_ACCESS: u32 = DIRECTORY_ACCESS | 3; // also READ/WRITE_DATA
    const READ_ALIAS_ACCESS: u32 = 0x0010_0089; // synchronize, attributes, READ_EA and READ_DATA

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        acknowledge_disposable_data_volume: bool,
    }

    fn report_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|v| v == "json"),
            "fresh absolute C: JSON report path required"
        );
        for part in path.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    "report must be on C: metadata storage"
                ),
                Component::RootDir => (),
                Component::Normal(value) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        value.to_str().context("Unicode metadata path required")?
                    ),
                    "invalid metadata component"
                ),
                _ => anyhow::bail!("report path traversal refused"),
            }
        }
        ensure!(!path.try_exists()?, "report already exists");
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary report ancestry required"
            );
        }
        Ok(())
    }

    fn source() -> Result<discovery::VolumeDiscovery> {
        let source = discovery::discover(r"H:\", discovery::Role::Source)?;
        let identity = &source.binding.identity;
        ensure!(
            source.binding.disk_number == 6
                && layout::guid_bytes(&identity.disk_guid)?
                    == layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
                && layout::guid_bytes(&identity.partition_guid)?
                    == layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
                && identity.partition_number == 2
                && identity.partition_offset == 32 * 1024 * 1024
                && identity.partition_bytes == 52 * 1024 * 1024 * 1024
                && identity.disk_bytes == 56 * 1024 * 1024 * 1024
                && !source.disk_is_windows_disk
                && source.read_only
                && source.source_write_requests == 0
                && source.observed_twice_unchanged
                && source.filesystem == "NTFS"
                && source.label == "n2r-links-source"
                && source.bytes_per_sector == 512
                && source.sectors_per_cluster == 8,
            "exact enrolled disk-6 NTFS H: fixture required"
        );
        Ok(source)
    }

    fn ordinary_directory(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "ordinary fixture parent directory required"
        );
        Ok(())
    }

    fn record_geometry(volume: &File) -> Result<Value> {
        let bytes = n2r_win32::lab_ntfs_fragmentation::read_ntfs_volume_data(volume)?;
        ensure!(
            (96..=128).contains(&bytes.len()),
            "NTFS geometry response length differs"
        );
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        ensure!(
            word(40) == 512 && word(44) == 4096 && word(48) == 1024,
            "fixture requires 512-byte sectors, 4 KiB clusters and 1 KiB MFT records"
        );
        Ok(
            json!({"bytes_per_sector":word(40),"bytes_per_cluster":word(44),
            "bytes_per_file_record":word(48),"native_response_hex":hex::encode(&bytes)}),
        )
    }

    fn create_directory(path: &Path, report: &mut Value) -> Result<File> {
        fs::create_dir(path)?;
        report["created_paths"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":path,"directory":true}));
        let file = OpenOptions::new()
            .access_mode(DIRECTORY_ACCESS)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "new directory handle type differs"
        );
        Ok(file)
    }

    fn create_file(path: &Path, payload: &[u8], report: &mut Value) -> Result<File> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(FILE_ACCESS)
            .create_new(true)
            .share_mode(7)
            .custom_flags(0x0020_0000)
            .open(path)?;
        report["created_paths"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":path,"directory":false}));
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.file_attributes() & 0x400 == 0,
            "new ordinary payload file required"
        );
        file.write_all(payload)?;
        file.sync_all()?;
        let old = report["new_payload_bytes_written"].as_u64().unwrap();
        report["new_payload_bytes_written"] = old
            .checked_add(payload.len() as u64)
            .context("fixture payload accounting overflow")?
            .into();
        Ok(file)
    }

    fn payload_hash(file: &mut File, length: u64) -> Result<Value> {
        ensure!(
            file.metadata()?.len() == length && length <= PAYLOAD_BYTES as u64,
            "bounded fixture payload length differs"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut sha = Sha256::new();
        let mut content = n2r_win32::content_digest::Hasher::new();
        let mut buffer = [0u8; 16_384];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            ensure!(total <= length, "fixture payload grew during readback");
            sha.update(&buffer[..n]);
            content.update(&buffer[..n]);
        }
        ensure!(
            total == length && file.metadata()?.len() == length,
            "fixture payload changed or ended early"
        );
        Ok(json!({"length":length,"sha256":hex::encode(sha.finalize()),
            "content_digest":content.finish(),"content_digest_algorithm":"xxh3-128"}))
    }

    fn install(
        path: &Path,
        file: &File,
        directory: bool,
        expected: &Set,
        report: &mut Value,
    ) -> Result<()> {
        let identity = file_storage::file_id_info(file)?;
        report["ea_attempts"].as_array_mut().unwrap().push(json!({"path":path,"directory":directory,
            "file_id_info":identity,"expected":expected,"setter_returned":false,"readback_matches":false}));
        let index = report["ea_attempts"].as_array().unwrap().len() - 1;
        let observed = match extended_attributes_native::restore_fresh_owned(file, expected) {
            Ok(set) => set,
            Err(error) => {
                report["ea_attempts"][index]["error"] = error.to_string().into();
                if let Ok(actual) = extended_attributes_native::capture(file) {
                    report["ea_attempts"][index]["observed_after_failure"] =
                        serde_json::to_value(actual)?;
                }
                return Err(error.into());
            }
        };
        report["ea_attempts"][index]["setter_returned"] = true.into();
        let again = extended_attributes_native::capture(file)?;
        ensure!(
            expected.equivalent(&observed)
                && expected.equivalent(&again)
                && file_storage::file_id_info(file)? == identity,
            "owned fixture EA readback or native identity differs"
        );
        report["ea_attempts"][index]["readback_matches"] = true.into();
        report["ea_attempts"][index]["observed"] = serde_json::to_value(&again)?;
        report["objects"].as_array_mut().unwrap().push(json!({"path":path,"directory":directory,
            "file_id_info":identity,"extended_attributes":expected,"observed_extended_attributes":again}));
        Ok(())
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume
            && std::env::var("COMPUTERNAME").as_deref() == Ok("N2R-WIN11")
            && args.experiment_id.len() == 32
            && args
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "explicit enrolled-guest acknowledgement and lowercase 32-character experiment ID required"
    );
    report_path(&args.output)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    let mut report = json!({"schema_version":1,"kind":"ntfs-ea-fixture",
        "experiment_id":args.experiment_id,"success":false,"created_paths":[],"objects":[],"ea_attempts":[],
        "new_payload_bytes_written":0,"existing_file_ea_set_calls":0,"raw_volume_write_calls":0,
        "move_file_calls":0,"formats_performed":0,"deletions_performed":0,
        "automatic_retry":false,"conversion_authorized":false,"source_admitted":false,
        "large_ea_value_bytes":8192,"ea_storage_independently_decoded":false});
    let mut phase = "source-discovery";
    let attempted = (|| -> Result<()> {
        let before = source()?;
        report["source"] = serde_json::to_value(&before)?;
        ordinary_directory(Path::new(r"H:\"))?;
        let volume = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(before.volume_guid_path.trim_end_matches('\\'))?;
        n2r_win32::bitmap_window_native::verify_route(&volume, &before.binding)?;
        report["ntfs_geometry"] = record_geometry(&volume)?;
        let directory = PathBuf::from(format!(r"H:\EaFixture-{}", args.experiment_id));
        let nested = directory.join("nested");
        let payload_path = directory.join("payload.bin");
        let empty_path = nested.join("empty.bin");
        let alias_path = nested.join("payload-link.bin");
        ensure!(
            !directory.try_exists()?,
            "fixture root already exists; no overwrite or reuse"
        );
        phase = "create-new-owned-objects";
        let root_handle = create_directory(&directory, &mut report)?;
        let nested_handle = create_directory(&nested, &mut report)?;
        let payload: Vec<u8> = (0..PAYLOAD_BYTES)
            .map(|i| (i as u8).wrapping_mul(73).wrapping_add(19))
            .collect();
        let mut data = create_file(&payload_path, &payload, &mut report)?;
        let mut empty = create_file(&empty_path, &[], &mut report)?;
        fs::hard_link(&payload_path, &alias_path)?;
        report["created_paths"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":alias_path,"hard_link_created":true}));
        let mut alias = OpenOptions::new()
            .read(true)
            .access_mode(READ_ALIAS_ACCESS)
            .share_mode(7)
            .custom_flags(0x0020_0000)
            .open(&alias_path)?;
        let data_id = file_storage::file_id_info(&data)?;
        ensure!(
            file_storage::file_id_info(&alias)? == data_id,
            "new alias is not the same owned payload identity"
        );
        let payload_before = payload_hash(&mut data, PAYLOAD_BYTES as u64)?;
        ensure!(
            payload_before["sha256"] == hex::encode(Sha256::digest(&payload)),
            "independent initialized payload SHA256 differs"
        );
        let empty_before = payload_hash(&mut empty, 0)?;
        report["payloads_before"] = json!([
            {"path":payload_path,"file_id_info":data_id,"hashes":payload_before},
            {"path":empty_path,"file_id_info":file_storage::file_id_info(&empty)?,"hashes":empty_before}]);
        let binary = vec![0, 255, 128, 0, 254, 1, 127];
        let data_eas = Set::new(vec![
            Entry {
                flags: 0,
                name: b"Binary.Value".to_vec(),
                value: binary.clone(),
            },
            Entry {
                flags: 0,
                name: b"Large.Binary".to_vec(),
                value: (0..8192).map(|i| (i as u8).wrapping_mul(29)).collect(),
            },
            Entry {
                flags: 0x80,
                name: b"Need.Ea".to_vec(),
                value: vec![255, 0, 129, 0, 42],
            },
        ])?;
        let root_eas = Set::new(vec![
            Entry {
                flags: 0,
                name: b"Directory.Binary".to_vec(),
                value: binary.clone(),
            },
            Entry {
                flags: 0,
                name: b"Directory.Note".to_vec(),
                value: b"fresh-root".to_vec(),
            },
        ])?;
        let nested_eas = Set::new(vec![Entry {
            flags: 0,
            name: b"Nested.Value".to_vec(),
            value: vec![0, 254, 253, 0],
        }])?;
        let empty_eas = Set::new(vec![Entry {
            flags: 0,
            name: b"Empty.File.Value".to_vec(),
            value: binary,
        }])?;
        phase = "set-only-fresh-owned-eas";
        install(&directory, &root_handle, true, &root_eas, &mut report)?;
        install(&nested, &nested_handle, true, &nested_eas, &mut report)?;
        install(&payload_path, &data, false, &data_eas, &mut report)?;
        install(&empty_path, &empty, false, &empty_eas, &mut report)?;
        data.sync_all()?;
        empty.sync_all()?;
        phase = "independent-alias-and-payload-readback";
        let alias_eas = extended_attributes_native::capture(&alias)?;
        ensure!(
            data_eas.equivalent(&alias_eas) && file_storage::file_id_info(&alias)? == data_id,
            "EA values/flags differ through the hard-link alias"
        );
        let data_after = payload_hash(&mut data, PAYLOAD_BYTES as u64)?;
        let alias_after = payload_hash(&mut alias, PAYLOAD_BYTES as u64)?;
        let empty_after = payload_hash(&mut empty, 0)?;
        ensure!(
            data_after == payload_before
                && alias_after == payload_before
                && empty_after == empty_before,
            "fixture payload changed during EA restoration"
        );
        report["hard_links"] = json!([{"path":payload_path,"file_id_info":data_id},
            {"path":alias_path,"file_id_info":data_id,"extended_attributes":alias_eas,"hashes":alias_after}]);
        report["payloads"] = json!([
            {"path":payload_path,"file_id_info":data_id,"hashes":data_after},
            {"path":empty_path,"file_id_info":file_storage::file_id_info(&empty)?,"hashes":empty_after}]);
        phase = "final-route-and-source-discovery";
        n2r_win32::bitmap_window_native::verify_route(&volume, &before.binding)?;
        let after = source()?;
        ensure!(
            before.binding == after.binding
                && before.volume_guid_path == after.volume_guid_path
                && before.evidence == after.evidence,
            "fixture source route changed"
        );
        report["source_after"] = serde_json::to_value(after)?;
        report["canonical_objects"] = 4.into();
        report["directories_with_eas"] = 2.into();
        report["file_identities_with_eas"] = 2.into();
        report["hardlink_names"] = 2.into();
        report["ea_entries"] = 7.into();
        report["need_ea_flag_readback_verified"] = true.into();
        report["large_value_exceeds_1024_byte_mft_record"] = true.into();
        Ok(())
    })();
    if let Err(error) = &attempted {
        report["failed_phase"] = phase.into();
        report["error"] = format!("{error:#}").into();
        report["partial_fixture_preserved"] = true.into();
    } else {
        report["success"] = true.into();
    }
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= REPORT_LIMIT,
        "EA fixture report exceeds four MiB"
    );
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        json!({"success":attempted.is_ok(),"report":args.output,
        "report_sha256":hex::encode(Sha256::digest(&bytes)),"conversion_authorized":false})
    );
    attempted
}

#[cfg(not(windows))]
fn main() {
    eprintln!("EA fixture creation requires the enrolled Windows guest");
    std::process::exit(2);
}
