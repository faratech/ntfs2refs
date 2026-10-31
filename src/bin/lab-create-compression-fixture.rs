//! Deterministic compression vectors confined to the enrolled disposable H:.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::lab_compression_fixture::FixtureSession;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };
    const LIMIT: usize = 8 * 1024 * 1024;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        acknowledge_disposable_data_volume: bool,
        #[arg(long, requires = "observe_manifest_sha256")]
        observe_manifest: Option<PathBuf>,
        #[arg(long, requires = "observe_manifest")]
        observe_manifest_sha256: Option<String>,
        #[arg(long, requires = "observe_manifest")]
        expected_filesystem: Option<String>,
    }
    #[derive(Clone)]
    struct Stream {
        name: Option<&'static str>,
        bytes: usize,
        pattern: u8,
        compressed: bool,
    }
    struct Object {
        name: &'static str,
        path: PathBuf,
        directory: bool,
        set_compression: bool,
        inherited: bool,
        streams: Vec<Stream>,
    }
    fn id_valid(id: &str) -> bool {
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn report_path(path: &Path, fresh: bool) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|s| s == "json"),
            "absolute C: JSON path required"
        );
        for part in path.components() {
            match part {
                Component::Prefix(p) => ensure!(
                    matches!(p.kind(), Prefix::Disk(b'C' | b'c')),
                    "C: metadata required"
                ),
                Component::RootDir => (),
                Component::Normal(n) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        n.to_str().context("Unicode metadata path required")?
                    ),
                    "invalid report component"
                ),
                _ => anyhow::bail!("report traversal refused"),
            }
        }
        if fresh {
            ensure!(!path.try_exists()?, "fresh report required");
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary C: metadata ancestry required"
            );
        }
        Ok(())
    }
    fn objects(id: &str) -> Result<Vec<Object>> {
        ensure!(id_valid(id), "original fixture ID required");
        let root = PathBuf::from(format!(r"H:\CompressionFixture-{id}"));
        let stream = |bytes, pattern, compressed| {
            vec![Stream {
                name: None,
                bytes,
                pattern,
                compressed,
            }]
        };
        Ok(vec![
            Object {
                name: "root",
                path: root.clone(),
                directory: true,
                set_compression: false,
                inherited: false,
                streams: vec![],
            },
            Object {
                name: "compressed-directory",
                path: root.join("compressed-directory"),
                directory: true,
                set_compression: true,
                inherited: false,
                streams: vec![],
            },
            Object {
                name: "mixed-compression-units",
                path: root.join("mixed.bin"),
                directory: false,
                set_compression: true,
                inherited: false,
                streams: stream(2 * 1024 * 1024 + 123, 0, true),
            },
            Object {
                name: "incompressible",
                path: root.join("incompressible.bin"),
                directory: false,
                set_compression: true,
                inherited: false,
                streams: stream(256 * 1024 + 55, 1, true),
            },
            Object {
                name: "resident-compression-policy",
                path: root.join("resident.bin"),
                directory: false,
                set_compression: true,
                inherited: false,
                streams: stream(64, 2, true),
            },
            Object {
                name: "empty-compression-policy",
                path: root.join("empty.bin"),
                directory: false,
                set_compression: true,
                inherited: false,
                streams: stream(0, 2, true),
            },
            Object {
                name: "inherited-compression",
                path: root.join("compressed-directory").join("inherited.bin"),
                directory: false,
                set_compression: false,
                inherited: true,
                streams: stream(65536 + 51, 2, true),
            },
            Object {
                name: "compressed-named-stream",
                path: root.join("named.bin"),
                directory: false,
                set_compression: false,
                inherited: false,
                streams: vec![
                    Stream {
                        name: None,
                        bytes: 65536 + 17,
                        pattern: 1,
                        compressed: false,
                    },
                    Stream {
                        name: Some("Encoded"),
                        bytes: 256 * 1024 + 19,
                        pattern: 2,
                        compressed: true,
                    },
                ],
            },
        ])
    }
    fn payload(stream: &Stream) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..stream.bytes)
            .map(|i| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                match stream.pattern {
                    0 => match (i / 65536) % 3 {
                        0 => (i % 19) as u8,
                        1 => state as u8,
                        _ => 0,
                    },
                    1 => state as u8,
                    _ => (i % 31) as u8,
                }
            })
            .collect()
    }
    fn digest(bytes: &[u8]) -> Value {
        json!({"length":bytes.len(), "sha256":hex::encode(Sha256::digest(bytes)), "content_digest":n2r_win32::content_digest::of(bytes), "content_digest_algorithm":"xxh3-128"})
    }
    fn read_payload(file: &mut fs::File, stream: &Stream) -> Result<Value> {
        ensure!(
            file.metadata()?.len() == stream.bytes as u64,
            "fixture logical size differs"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; stream.bytes];
        file.read_exact(&mut bytes)?;
        let mut tail = [0];
        ensure!(file.read(&mut tail)? == 0, "fixture EOF differs");
        let got = digest(&bytes);
        ensure!(
            got == digest(&payload(stream)),
            "fixture logical contents differ"
        );
        Ok(got)
    }
    fn check_observation(
        row: &Value,
        directory: bool,
        filesystem: &str,
        compressed: bool,
    ) -> Result<()> {
        let queries = row["snapshot"]["queries"]
            .as_array()
            .context("native queries missing")?;
        let tags: Vec<_> = queries
            .iter()
            .filter(|q| q["class"] == 9 && q["native_error"].is_null())
            .collect();
        ensure!(tags.len() == 1, "native tag query missing");
        let bytes: Vec<u8> = serde_json::from_value(tags[0]["bytes"].clone())?;
        ensure!(bytes.len() == 8, "tag bytes differ");
        let attr = u32::from_le_bytes(bytes[..4].try_into()?);
        ensure!(
            (attr & 16 != 0) == directory && attr & 0x400 == 0,
            "ordinary fixture type required"
        );
        if filesystem == "NTFS" {
            ensure!(
                row["compression"]["format"].as_u64() == Some(if compressed { 2 } else { 0 }),
                "NTFS compression state differs"
            );
        } else {
            ensure!(
                attr & 0x800 == 0,
                "target NTFS compression attribute was not normalized"
            );
            if !row["compression"]["format"].is_null() {
                ensure!(
                    row["compression"]["format"] == 0,
                    "ReFS compression state must be ordinary"
                );
            } else {
                ensure!(
                    row["compression"]["query"]["native_error"]
                        .as_i64()
                        .is_some_and(|e| matches!(e, 1 | 50)),
                    "compression query failed for an unexplained reason"
                );
            }
        }
        Ok(())
    }
    fn observe(session: &mut FixtureSession, object: &Object, filesystem: &str) -> Result<Value> {
        let file = session.open(&object.path, object.directory, None)?;
        let before = serde_json::to_value(file.observe()?)?;
        check_observation(
            &before,
            object.directory,
            filesystem,
            object.set_compression || object.inherited,
        )?;
        let mut streams = vec![];
        for stream in &object.streams {
            let mut opened = session.open(&object.path, false, stream.name)?;
            let stream_before = serde_json::to_value(opened.observe()?)?;
            check_observation(&stream_before, false, filesystem, stream.compressed)?;
            let hash = read_payload(opened.file_mut(), stream)?;
            let after = serde_json::to_value(opened.observe()?)?;
            ensure!(
                stream_before["file_id_info"] == after["file_id_info"]
                    && stream_before["compression"]["format"] == after["compression"]["format"],
                "stream identity/state changed"
            );
            streams.push(json!({"name":stream.name, "payload":hash, "source_compression_policy":stream.compressed, "before":stream_before, "after":after}));
        }
        let after = serde_json::to_value(file.observe()?)?;
        ensure!(
            before["file_id_info"] == after["file_id_info"],
            "fixture identity changed"
        );
        Ok(
            json!({"case":object.name, "path":object.path, "directory":object.directory, "file_id_info":before["file_id_info"], "streams":streams, "before":before, "after":after, "no_follow_metadata":true}),
        )
    }
    fn validate_manifest(fixture: &Value) -> Result<Vec<Object>> {
        ensure!(
            fixture["schema_version"] == 1
                && fixture["kind"] == "ntfs-compression-fixture"
                && fixture["success"] == true,
            "completed compression fixture required"
        );
        let expected = objects(
            fixture["experiment_id"]
                .as_str()
                .context("fixture ID missing")?,
        )?;
        let actual = fixture["objects"]
            .as_array()
            .context("fixture objects missing")?;
        ensure!(
            actual.len() == expected.len(),
            "complete eight-object fixture required"
        );
        for object in &expected {
            let rows: Vec<_> = actual
                .iter()
                .filter(|r| r["path"].as_str() == object.path.to_str())
                .collect();
            ensure!(
                rows.len() == 1
                    && rows[0]["case"] == object.name
                    && rows[0]["directory"] == object.directory
                    && rows[0]["no_follow_metadata"] == true,
                "fixture identity/case differs"
            );
            let streams = rows[0]["streams"]
                .as_array()
                .context("fixture streams missing")?;
            ensure!(
                streams.len() == object.streams.len(),
                "stream count differs"
            );
            for (actual, stream) in streams.iter().zip(&object.streams) {
                ensure!(
                    actual["name"].as_str() == stream.name
                        && actual["payload"] == digest(&payload(stream))
                        && actual["source_compression_policy"] == stream.compressed,
                    "fixture stream differs"
                );
            }
        }
        Ok(expected)
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume && id_valid(&args.experiment_id),
        "explicit disposable scope and ID required"
    );
    report_path(&args.output, true)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    let (mut report, attempt) = if let (Some(path), Some(pin)) =
        (&args.observe_manifest, &args.observe_manifest_sha256)
    {
        report_path(path, false)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= LIMIT as u64,
            "bounded ordinary manifest required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            pin.len() == 64 && hex::encode(Sha256::digest(&bytes)) == *pin,
            "fixture manifest checksum differs"
        );
        let fixture: Value = serde_json::from_slice(&bytes)?;
        let objects = validate_manifest(&fixture)?;
        let filesystem = args
            .expected_filesystem
            .as_deref()
            .context("expected filesystem required")?;
        ensure!(
            matches!(filesystem, "NTFS" | "ReFS"),
            "explicit supported filesystem required"
        );
        let mut report = json!({"schema_version":1,"kind":"compression-fixture-read-only-observation","experiment_id":args.experiment_id,"fixture_sha256":pin,"filesystem":filesystem,"success":false,"objects":[],"source_payload_writes":0,"compression_setters":0,"raw_volume_writes":0});
        let attempt = (|| -> Result<()> {
            let mut session = FixtureSession::begin(filesystem, false)?;
            for object in &objects {
                let row = observe(&mut session, object, filesystem)?;
                if filesystem == "NTFS" {
                    let original = fixture["objects"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["path"].as_str() == object.path.to_str())
                        .unwrap();
                    ensure!(
                        row["file_id_info"] == original["file_id_info"],
                        "original fixture identity changed"
                    );
                }
                report["objects"].as_array_mut().unwrap().push(row);
            }
            report["privilege_states"] = serde_json::to_value(session.finish()?)?;
            Ok(())
        })();
        (report, attempt)
    } else {
        let mut report = json!({"schema_version":1,"kind":"ntfs-compression-fixture","experiment_id":args.experiment_id,"filesystem":"NTFS","success":false,"objects":[],"created_paths":[],"compression_attempts":[],"source_payload_relocations":0,"raw_volume_writes":0,"existing_file_modified":false,"conversion_authorized":false,"source_admitted":false});
        let mut phase = "enroll";
        let attempt = (|| -> Result<()> {
            let mut session = FixtureSession::begin("NTFS", true)?;
            let objects = objects(&args.experiment_id)?;
            let mut owned = Vec::new();
            for object in &objects {
                phase = "create-only-new-owned-object";
                let mut file = session.create(&object.path, object.directory)?;
                report["created_paths"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"path":object.path,"directory":object.directory}));
                if object.set_compression {
                    phase = "set-owned-empty-compression-policy";
                    report["compression_attempts"].as_array_mut().unwrap().push(json!({"path":object.path,"stream":null,"observation":session.set_compression(&file)?}));
                }
                for stream in &object.streams {
                    phase = "initialize-owned-logical-stream";
                    if let Some(name) = stream.name {
                        let mut named = session.create_stream(&file, name)?;
                        if stream.compressed {
                            report["compression_attempts"].as_array_mut().unwrap().push(json!({"path":object.path,"stream":name,"observation":session.set_compression(&named)?}));
                        }
                        named.file_mut().write_all(&payload(stream))?;
                        named.file_mut().sync_all()?;
                        read_payload(named.file_mut(), stream)?;
                        owned.push(named);
                    } else {
                        file.file_mut().write_all(&payload(stream))?;
                        file.file_mut().sync_all()?;
                        read_payload(file.file_mut(), stream)?;
                    }
                }
                owned.push(file);
            }
            phase = "read-only-native-and-content-observation";
            for object in &objects {
                report["objects"].as_array_mut().unwrap().push(observe(
                    &mut session,
                    object,
                    "NTFS",
                )?);
            }
            report["privilege_states"] = serde_json::to_value(session.finish()?)?;
            drop(owned);
            report["canonical_objects"] = 8.into();
            report["default_streams"] = 6.into();
            report["named_streams"] = 1.into();
            Ok(())
        })();
        if attempt.is_err() {
            report["failed_phase"] = phase.into();
            report["partial_fixture_preserved"] = true.into();
        }
        (report, attempt)
    };
    if let Err(e) = &attempt {
        report["error"] = format!("{e:#}").into();
    } else {
        report["success"] = true.into();
    }
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= LIMIT, "fixture report exceeds eight MiB");
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        json!({"success":attempt.is_ok(),"report":args.output,"report_sha256":hex::encode(Sha256::digest(&bytes)),"conversion_authorized":false})
    );
    attempt
}
#[cfg(not(windows))]
fn main() {
    eprintln!("compression fixture requires enrolled Windows VM");
    std::process::exit(1);
}
