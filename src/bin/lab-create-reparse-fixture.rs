//! Fresh enrolled-H: link vectors and a no-follow read-only metadata observer.
//! Functional reads are restricted to four reconstructed known-safe routes;
//! dangling and cyclic links are never traversed.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        attestation::Snapshot,
        discovery,
        lab_reparse_fixture::FixtureSession,
        reparse_layout::{self, Point},
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };

    const REPORT_LIMIT: usize = 8 * 1024 * 1024;
    const REAL_BYTES: usize = 65_536 + 37;
    const CHILD_BYTES: usize = 4097;

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
    struct Object {
        name: &'static str,
        path: PathBuf,
        directory: bool,
        point: Option<Point>,
        payload_bytes: Option<usize>,
        payload_salt: u8,
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
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    "C: metadata file required"
                ),
                Component::RootDir => (),
                Component::Normal(name) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        name.to_str().context("Unicode metadata path required")?
                    ),
                    "invalid metadata component"
                ),
                _ => anyhow::bail!("metadata traversal refused"),
            }
        }
        if fresh {
            ensure!(!path.try_exists()?, "fresh output required");
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary C: metadata ancestry required"
            );
        }
        Ok(())
    }
    fn point(tag: u32, substitute: &str, display: &str, relative: bool) -> Result<Point> {
        ensure!(
            tag == reparse_layout::IO_REPARSE_TAG_SYMLINK
                || (!relative && tag == reparse_layout::IO_REPARSE_TAG_MOUNT_POINT),
            "supported point tag/flags required"
        );
        let substitute: Vec<u16> = substitute.encode_utf16().collect();
        let display: Vec<u16> = display.encode_utf16().collect();
        let substitute_bytes = u16::try_from(
            substitute
                .len()
                .checked_mul(2)
                .context("substitute length overflow")?,
        )?;
        let display_bytes = u16::try_from(
            display
                .len()
                .checked_mul(2)
                .context("display length overflow")?,
        )?;
        let display_offset = substitute_bytes
            .checked_add(2)
            .context("path offset overflow")?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&substitute_bytes.to_le_bytes());
        payload.extend_from_slice(&display_offset.to_le_bytes());
        payload.extend_from_slice(&display_bytes.to_le_bytes());
        if tag == reparse_layout::IO_REPARSE_TAG_SYMLINK {
            payload.extend_from_slice(&u32::from(relative).to_le_bytes());
        }
        for unit in substitute
            .iter()
            .chain(std::iter::once(&0))
            .chain(display.iter())
            .chain(std::iter::once(&0))
        {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        let mut bytes = tag.to_le_bytes().to_vec();
        bytes.extend_from_slice(&u16::try_from(payload.len())?.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&payload);
        Ok(reparse_layout::parse(&bytes)?)
    }
    fn objects(id: &str) -> Result<Vec<Object>> {
        ensure!(id_valid(id), "valid original fixture ID required");
        let root = PathBuf::from(format!(r"H:\ReparseFixture-{id}"));
        let file = root.join("real.bin");
        let directory = root.join("real-directory");
        let absolute_file = format!(r"\??\{}", file.display());
        let absolute_directory = format!(r"\??\{}", directory.display());
        let mut out = vec![
            Object {
                name: "root",
                path: root.clone(),
                directory: true,
                point: None,
                payload_bytes: None,
                payload_salt: 0,
            },
            Object {
                name: "real-file",
                path: file.clone(),
                directory: false,
                point: None,
                payload_bytes: Some(REAL_BYTES),
                payload_salt: 31,
            },
            Object {
                name: "real-directory",
                path: directory.clone(),
                directory: true,
                point: None,
                payload_bytes: None,
                payload_salt: 0,
            },
            Object {
                name: "directory-payload",
                path: directory.join("payload.bin"),
                directory: false,
                point: None,
                payload_bytes: Some(CHILD_BYTES),
                payload_salt: 73,
            },
        ];
        for (name, target, display, relative, directory, tag) in [
            (
                "relative-file",
                "real.bin".to_string(),
                "real.bin".to_string(),
                true,
                false,
                reparse_layout::IO_REPARSE_TAG_SYMLINK,
            ),
            (
                "absolute-file",
                absolute_file,
                file.display().to_string(),
                false,
                false,
                reparse_layout::IO_REPARSE_TAG_SYMLINK,
            ),
            (
                "relative-directory",
                "real-directory".to_string(),
                "real-directory".to_string(),
                true,
                true,
                reparse_layout::IO_REPARSE_TAG_SYMLINK,
            ),
            (
                "junction",
                absolute_directory,
                directory.display().to_string(),
                false,
                true,
                reparse_layout::IO_REPARSE_TAG_MOUNT_POINT,
            ),
            (
                "dangling-file",
                "missing.bin".to_string(),
                "missing.bin".to_string(),
                true,
                false,
                reparse_layout::IO_REPARSE_TAG_SYMLINK,
            ),
            (
                "directory-cycle",
                ".".to_string(),
                ".".to_string(),
                true,
                true,
                reparse_layout::IO_REPARSE_TAG_SYMLINK,
            ),
        ] {
            out.push(Object {
                name,
                path: root.join(name),
                directory,
                point: Some(point(tag, &target, &display, relative)?),
                payload_bytes: None,
                payload_salt: 0,
            });
        }
        Ok(out)
    }
    fn payload(bytes: usize, salt: u8) -> Vec<u8> {
        (0..bytes)
            .map(|i| (i as u8).wrapping_mul(salt).wrapping_add((i >> 9) as u8))
            .collect()
    }
    fn hash_bytes(bytes: &[u8]) -> Value {
        json!({"length":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes)),"content_digest":n2r_win32::content_digest::of(bytes),"content_digest_algorithm":"xxh3-128"})
    }
    fn hash_file(file: &mut File, length: usize) -> Result<Value> {
        ensure!(
            length <= REAL_BYTES && file.metadata()?.len() == length as u64,
            "normal payload length differs"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        let mut tail = [0];
        ensure!(file.read(&mut tail)? == 0, "normal payload EOF differs");
        Ok(hash_bytes(&bytes))
    }
    fn identity(snapshot: &Snapshot) -> Result<String> {
        let ids: Vec<_> = snapshot
            .queries
            .iter()
            .filter(|q| q.class == 18 && q.native_error.is_none() && q.bytes.len() == 24)
            .collect();
        ensure!(ids.len() == 1, "one held identity observation required");
        Ok(hex::encode(&ids[0].bytes))
    }
    fn check_snapshot(snapshot: &Snapshot, object: &Object) -> Result<()> {
        let tags: Vec<_> = snapshot
            .queries
            .iter()
            .filter(|q| q.class == 9 && q.native_error.is_none() && q.bytes.len() == 8)
            .collect();
        ensure!(tags.len() == 1, "native tag observation missing");
        let attributes = u32::from_le_bytes(tags[0].bytes[..4].try_into()?);
        let tag = u32::from_le_bytes(tags[0].bytes[4..].try_into()?);
        ensure!(
            (attributes & 16 != 0) == object.directory
                && (attributes & 0x400 != 0) == object.point.is_some()
                && tag == object.point.as_ref().map_or(0, Point::tag),
            "native type/tag differs from fixture"
        );
        Ok(())
    }
    fn observe_object(session: &mut FixtureSession, object: &Object) -> Result<Value> {
        let mut view = session.open(&object.path, object.directory)?;
        check_snapshot(view.snapshot(), object)?;
        ensure!(
            view.point() == object.point.as_ref(),
            "native point bytes differ at {}",
            object.path.display()
        );
        let before = view.snapshot().clone();
        let before_id = identity(&before)?;
        let hashes = match object.payload_bytes {
            Some(length) => Some(hash_file(view.file_mut(), length)?),
            None => None,
        };
        drop(view);
        let after = session.open(&object.path, object.directory)?;
        check_snapshot(after.snapshot(), object)?;
        ensure!(
            identity(after.snapshot())? == before_id && after.point() == object.point.as_ref(),
            "held fixture identity/point changed"
        );
        Ok(
            json!({"case":object.name,"path":object.path,"directory":object.directory,"point":object.point,"observed_point":after.point(),
            "file_id_info":before_id,"tag":object.point.as_ref().map_or(0,Point::tag),"payload":hashes,
            "point_bytes_match":true,"before":before,"after":after.snapshot(),"no_follow_metadata":true}),
        )
    }
    fn functional(id: &str) -> Result<Vec<Value>> {
        let root = PathBuf::from(format!(r"H:\ReparseFixture-{id}"));
        let mut out = Vec::new();
        for (name, suffix, length, salt) in [
            ("relative-file", None, REAL_BYTES, 31),
            ("absolute-file", None, REAL_BYTES, 31),
            ("relative-directory", Some("payload.bin"), CHILD_BYTES, 73),
            ("junction", Some("payload.bin"), CHILD_BYTES, 73),
        ] {
            let mut path = root.join(name);
            if let Some(suffix) = suffix {
                path.push(suffix);
            }
            let mut file = File::open(&path)?;
            let hash = hash_file(&mut file, length)?;
            ensure!(
                hash == hash_bytes(&payload(length, salt)),
                "known functional target differs"
            );
            out.push(json!({"path":path,"hashes":hash,"known_existing_target_only":true}));
        }
        Ok(out)
    }
    fn validate_manifest(fixture: &Value) -> Result<Vec<Object>> {
        ensure!(
            fixture["schema_version"] == 1
                && fixture["kind"] == "ntfs-reparse-fixture"
                && fixture["success"] == true,
            "completed source reparse fixture required"
        );
        let expected = objects(
            fixture["experiment_id"]
                .as_str()
                .context("original fixture ID missing")?,
        )?;
        let actual = fixture["objects"]
            .as_array()
            .context("fixture objects missing")?;
        ensure!(
            actual.len() == expected.len(),
            "complete ten-object fixture required"
        );
        for object in &expected {
            let rows: Vec<_> = actual
                .iter()
                .filter(|row| row["path"].as_str() == object.path.to_str())
                .collect();
            ensure!(rows.len() == 1, "one exact fixture path required");
            let row = rows[0];
            ensure!(
                row["directory"].as_bool() == Some(object.directory)
                    && row["case"].as_str() == Some(object.name),
                "fixture object case/type differs"
            );
            let point: Option<Point> = serde_json::from_value(row["point"].clone())?;
            ensure!(
                point == object.point
                    && row["point_bytes_match"] == true
                    && row["no_follow_metadata"] == true,
                "fixture point bytes differ from reconstructed vector"
            );
            let id = row["file_id_info"]
                .as_str()
                .context("fixture identity missing")?;
            ensure!(
                id.len() == 48 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                "fixture identity form differs"
            );
            if let Some(length) = object.payload_bytes {
                ensure!(
                    row["payload"] == hash_bytes(&payload(length, object.payload_salt)),
                    "fixture normal payload hash differs"
                );
            }
        }
        Ok(expected)
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume && id_valid(&args.experiment_id),
        "explicit disposable scope and experiment ID required"
    );
    report_path(&args.output, true)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    if let (Some(path), Some(pin)) = (&args.observe_manifest, &args.observe_manifest_sha256) {
        report_path(path, false)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= REPORT_LIMIT as u64,
            "bounded ordinary source manifest required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            pin.len() == 64 && hex::encode(Sha256::digest(&bytes)) == *pin,
            "source manifest checksum differs"
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
        let mut session = FixtureSession::begin(filesystem, false)?;
        let mut report = json!({"schema_version":1,"kind":"reparse-fixture-read-only-observation","experiment_id":args.experiment_id,
            "fixture_sha256":pin,"filesystem":filesystem,"success":false,"objects":[],"functional_reads":[],
            "source_payload_writes":0,"raw_volume_writes":0,"reparse_setters":0,"dangling_or_cycle_traversals":0});
        let attempt = (|| -> Result<()> {
            for object in &objects {
                let row = observe_object(&mut session, object)?;
                if filesystem == "NTFS" {
                    let original = fixture["objects"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["path"].as_str() == object.path.to_str())
                        .unwrap();
                    ensure!(
                        row["file_id_info"] == original["file_id_info"],
                        "original NTFS fixture identity changed"
                    );
                }
                report["objects"].as_array_mut().unwrap().push(row);
            }
            report["functional_reads"] =
                serde_json::to_value(functional(fixture["experiment_id"].as_str().unwrap())?)?;
            Ok(())
        })();
        report["privilege_states"] = serde_json::to_value(session.finish()?)?;
        if let Err(error) = &attempt {
            report["error"] = format!("{error:#}").into();
        } else {
            report["success"] = true.into();
        }
        let bytes = serde_json::to_vec_pretty(&report)?;
        ensure!(
            bytes.len() <= REPORT_LIMIT,
            "observer report exceeds eight MiB"
        );
        output.write_all(&bytes)?;
        output.sync_all()?;
        println!(
            "{}",
            json!({"success":attempt.is_ok(),"report":args.output,"report_sha256":hex::encode(Sha256::digest(&bytes)),"source_payload_writes":0})
        );
        return attempt;
    }
    let mut report = json!({"schema_version":1,"kind":"ntfs-reparse-fixture","experiment_id":args.experiment_id,
        "success":false,"objects":[],"created_paths":[],"point_attempts":[],"functional_reads":[],"source_payload_relocations":0,
        "raw_volume_writes":0,"existing_file_modified":false,"existing_file_reparse_setters":0,"dangling_or_cycle_traversals":0,
        "conversion_authorized":false,"source_admitted":false});
    let mut phase = "enroll";
    let attempt = (|| -> Result<()> {
        let source = discovery::discover(r"H:\", discovery::Role::Source)?;
        report["source"] = serde_json::to_value(&source)?;
        let mut session = FixtureSession::begin("NTFS", true)?;
        let objects = objects(&args.experiment_id)?;
        let mut owned = Vec::new();
        for object in &objects {
            phase = "create-only-new-owned-object";
            let mut file = if object.directory {
                session.create_directory(&object.path)?
            } else {
                session.create_file(&object.path)?
            };
            report["created_paths"]
                .as_array_mut()
                .unwrap()
                .push(json!({"path":object.path,"directory":object.directory}));
            if let Some(length) = object.payload_bytes {
                phase = "initialize-owned-normal-payload";
                let bytes = payload(length, object.payload_salt);
                file.file_mut().write_all(&bytes)?;
                file.file_mut().sync_all()?;
                ensure!(
                    hash_file(file.file_mut(), length)? == hash_bytes(&bytes),
                    "new initialized payload differs"
                );
            }
            if let Some(point) = &object.point {
                phase = "set-only-fresh-owned-reparse-point";
                let result = session.set_point(&file, point);
                report["point_attempts"].as_array_mut().unwrap().push(json!({"path":object.path,"point":point,
                    "observed_point":result.as_ref().ok(),"success":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}));
                ensure!(
                    result? == *point,
                    "native point readback differs from submitted buffer"
                );
            }
            owned.push(file);
        }
        phase = "no-follow-metadata-and-normal-payload-readback";
        for object in &objects {
            report["objects"]
                .as_array_mut()
                .unwrap()
                .push(observe_object(&mut session, object)?);
        }
        phase = "known-functional-targets-only";
        report["functional_reads"] = serde_json::to_value(functional(&args.experiment_id)?)?;
        phase = "restore-privileges";
        report["privilege_states"] = serde_json::to_value(session.finish()?)?;
        drop(owned);
        let after = discovery::discover(r"H:\", discovery::Role::Source)?;
        ensure!(
            source.binding == after.binding && after.filesystem == "NTFS",
            "fixture source route changed"
        );
        report["source_after"] = serde_json::to_value(after)?;
        report["canonical_objects"] = 10.into();
        report["normal_payload_files"] = 2.into();
        report["reparse_points"] = 6.into();
        report["file_reparse_points"] = 3.into();
        report["directory_reparse_points"] = 3.into();
        report["functional_existing_routes_verified"] = 4.into();
        Ok(())
    })();
    if let Err(error) = &attempt {
        report["failed_phase"] = phase.into();
        report["error"] = format!("{error:#}").into();
        report["partial_fixture_preserved"] = true.into();
    } else {
        report["success"] = true.into();
    }
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() <= REPORT_LIMIT,
        "fixture report exceeds eight MiB"
    );
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
    eprintln!("reparse fixture requires the enrolled disposable Windows VM");
    std::process::exit(1);
}
