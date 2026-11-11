//! Creates fresh ACL/SACL vectors on the enrolled disposable NTFS source.
//! Requested descriptors and actual Windows storage are recorded separately.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        attestation::Snapshot,
        discovery,
        lab_security_fixture::{FixtureSession, ObservationSession},
    };
    use ntfs2refs::{ntfs_attestation, ntfs_security};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };

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
    #[derive(Clone, Copy)]
    enum Acl<'a> {
        Absent,
        Null,
        Present(&'a [u8]),
    }
    fn sid(authority: u64, sub: &[u32]) -> Vec<u8> {
        let mut out = vec![1, sub.len() as u8];
        out.extend_from_slice(&authority.to_be_bytes()[2..]);
        for value in sub {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }
    fn ace(kind: u8, flags: u8, mask: u32, trustee: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, flags];
        out.extend_from_slice(&((8 + trustee.len()) as u16).to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(trustee);
        out
    }
    fn acl(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![2, 0];
        let length = 8 + entries.iter().map(Vec::len).sum::<usize>();
        out.extend_from_slice(&(length as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out
    }
    fn descriptor(
        dacl: Acl<'_>,
        sacl: Acl<'_>,
        protected_dacl: bool,
        protected_sacl: bool,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0; 20];
        out[0] = 1;
        let mut control = 0x8000u16
            | if protected_dacl { 0x1000 } else { 0 }
            | if protected_sacl { 0x2000 } else { 0 };
        if !matches!(dacl, Acl::Absent) {
            control |= 4;
        }
        if !matches!(sacl, Acl::Absent) {
            control |= 0x10;
        }
        out[2..4].copy_from_slice(&control.to_le_bytes());
        for (at, bytes) in [(4, sid(5, &[18])), (8, sid(5, &[32, 544]))] {
            let offset = out.len() as u32;
            out[at..at + 4].copy_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        for (at, value) in [(12, sacl), (16, dacl)] {
            if let Acl::Present(bytes) = value {
                let offset = out.len() as u32;
                out[at..at + 4].copy_from_slice(&offset.to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
        n2r_win32::security_descriptor::validate(&out)?;
        ntfs_security::parse_descriptor(&out)?;
        Ok(out)
    }
    fn kernel(snapshot: &Snapshot) -> Result<&[u8]> {
        ensure!(
            snapshot.security_error.is_none(),
            "API security capture failed"
        );
        let stored = snapshot
            .kernel_security
            .as_ref()
            .context("kernel descriptor missing")?;
        ensure!(
            stored.native_error.is_none(),
            "kernel descriptor query failed"
        );
        ntfs_security::parse_descriptor(&stored.bytes)?;
        Ok(&stored.bytes)
    }
    fn report_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|v| v == "json"),
            "fresh absolute C: JSON output required"
        );
        for part in path.components() {
            ensure!(
                match part {
                    Component::Prefix(p) => matches!(p.kind(), Prefix::Disk(b'C' | b'c')),
                    Component::RootDir | Component::Normal(_) => true,
                    _ => false,
                },
                "ordinary C: metadata path required"
            );
        }
        ensure!(!path.try_exists()?, "output already exists");
        for parent in path.ancestors().skip(1) {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "ordinary metadata ancestry required"
            );
        }
        Ok(())
    }
    fn record_object(
        report: &mut Value,
        name: &str,
        path: &Path,
        directory: bool,
        requested: &[u8],
        after_create: Snapshot,
        after: Snapshot,
        backup: Value,
        payload: Option<Value>,
    ) -> Result<()> {
        let stored = kernel(&after)?;
        let parsed = ntfs_security::parse_descriptor(stored)?;
        ensure!(
            ntfs_attestation::same_security(stored, kernel(&after_create)?).is_ok(),
            "descriptor semantics cannot be parsed"
        );
        let stable = ntfs_attestation::same_security(requested, stored)?;
        report["objects"].as_array_mut().unwrap().push(json!({"case":name,"path":path,"directory":directory,
            "requested_security_hex":hex::encode(requested),"requested_layout":n2r_win32::security_descriptor::validate(requested)?,
            "actual_security_hex":hex::encode(stored),"actual_layout":n2r_win32::security_descriptor::validate(stored)?,
            "requested_semantics_preserved":stable,"observed_dacl_state":parsed.dacl.state,"observed_sacl_state":parsed.sacl.state,
            "file_id_info":hex::encode(after.queries.iter().find(|q|q.class==18 && q.native_error.is_none()).context("fixture file ID missing")?.bytes.clone()),
            "payload":payload,"after_create":after_create,"backup":backup,"after":after}));
        Ok(())
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_disposable_data_volume
            && args.experiment_id.len() == 32
            && args
                .experiment_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "explicit disposable scope and experiment ID required"
    );
    report_path(&args.output)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&args.output)?;
    if let (Some(path), Some(pin)) = (&args.observe_manifest, &args.observe_manifest_sha256) {
        ensure!(
            path.is_absolute() && path.starts_with(r"C:\"),
            "C: manifest required"
        );
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && metadata.len() <= 8 * 1024 * 1024,
            "bounded ordinary fixture manifest required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            pin.len() == 64 && hex::encode(Sha256::digest(&bytes)) == *pin,
            "fixture manifest pin differs"
        );
        let fixture: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            fixture["schema_version"] == 1
                && fixture["kind"] == "ntfs-security-fixture"
                && fixture["success"] == true,
            "completed security fixture required"
        );
        let expected_fs = args
            .expected_filesystem
            .as_deref()
            .context("expected filesystem required")?;
        let session = ObservationSession::begin(expected_fs)?;
        let mut result = json!({"schema_version":1,"kind":"security-fixture-read-only-observation","fixture_sha256":pin,
            "experiment_id":args.experiment_id,"filesystem":expected_fs,"source_payload_writes":0,"raw_volume_writes":0,
            "security_setters":0,"success":false,"objects":[]});
        let attempted = (|| -> Result<()> {
            let objects = fixture["objects"]
                .as_array()
                .context("fixture objects missing")?;
            ensure!(
                objects.len() == 8,
                "complete eight-object security fixture required"
            );
            for object in objects {
                let object_path =
                    Path::new(object["path"].as_str().context("fixture path missing")?);
                let directory = object["directory"]
                    .as_bool()
                    .context("fixture type missing")?;
                let mut file = session.open_file(object_path, directory)?;
                let before = session.snapshot(&file);
                let expected = hex::decode(
                    object["actual_security_hex"]
                        .as_str()
                        .context("source descriptor missing")?,
                )?;
                ensure!(
                    ntfs_attestation::same_security(&expected, kernel(&before)?)?,
                    "stored/kernel security differs from fixture at {}",
                    object_path.display()
                );
                let expected_api: Vec<u8> =
                    serde_json::from_value(object["after"]["security"].clone())?;
                ensure!(
                    ntfs_attestation::same_security(&expected_api, &before.security)?,
                    "API security view differs from fixture"
                );
                let id = before
                    .queries
                    .iter()
                    .find(|q| q.class == 18 && q.native_error.is_none())
                    .context("identity missing")?
                    .bytes
                    .clone();
                if expected_fs == "NTFS" {
                    ensure!(
                        hex::encode(&id)
                            == object["file_id_info"]
                                .as_str()
                                .context("original identity missing")?,
                        "NTFS fixture identity changed"
                    );
                }
                let mut sha = None;
                if !directory {
                    let length = object["payload"]["length"]
                        .as_u64()
                        .context("fixture payload length missing")?;
                    ensure!(
                        length <= 65536 && file.metadata()?.len() == length,
                        "fixture payload length differs"
                    );
                    let mut payload = vec![0; length as usize];
                    file.read_exact(&mut payload)?;
                    let mut tail = [0];
                    ensure!(file.read(&mut tail)? == 0, "fixture EOF differs");
                    let value = hex::encode(Sha256::digest(&payload));
                    ensure!(
                        Some(value.as_str()) == object["payload"]["sha256"].as_str(),
                        "independent fixture SHA256 differs"
                    );
                    sha = Some(value);
                }
                let after = session.snapshot(&file);
                ensure!(
                    ntfs_attestation::same_security(&expected, kernel(&after)?)?
                        && ntfs_attestation::same_security(&expected_api, &after.security)?,
                    "security changed during readback"
                );
                ensure!(
                    after
                        .queries
                        .iter()
                        .find(|q| q.class == 18)
                        .is_some_and(|q| q.native_error.is_none() && q.bytes == id),
                    "held object identity changed"
                );
                result["objects"].as_array_mut().unwrap().push(json!({"path":object_path,"directory":directory,"file_id_info":hex::encode(&id),"sha256":sha,"before":before,"after":after,"source_security_semantics_match":true,"source_api_view_matches":true}));
            }
            Ok(())
        })();
        result["privilege_states"] = serde_json::to_value(session.finish()?)?;
        if let Err(error) = &attempted {
            result["error"] = format!("{error:#}").into();
        } else {
            result["success"] = true.into();
        }
        let bytes = serde_json::to_vec_pretty(&result)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "observer report exceeds bound"
        );
        output.write_all(&bytes)?;
        output.sync_all()?;
        println!(
            "{}",
            json!({"success":attempted.is_ok(),"report":args.output,"report_sha256":hex::encode(Sha256::digest(&bytes)),"source_payload_writes":0})
        );
        return attempted;
    }
    let mut report = json!({"schema_version":1,"kind":"ntfs-security-fixture","experiment_id":args.experiment_id,"success":false,
        "created_paths":[],"objects":[],"source_payload_relocations":0,"raw_volume_writes":0,"existing_file_security_modified":false,
        "audit_policy_modified":false,"conversion_authorized":false,"source_admitted":false});
    let mut phase = "enroll";
    let attempt = (|| -> Result<()> {
        let source = discovery::discover(r"H:\", discovery::Role::Source)?;
        report["source"] = serde_json::to_value(&source)?;
        let session = FixtureSession::begin()?;
        let system = sid(5, &[18]);
        let administrators = sid(5, &[32, 544]);
        let world = sid(1, &[0]);
        let medium = sid(16, &[8192]);
        let full = acl(&[
            ace(0, 0, 0x001f01ff, &system),
            ace(0, 0, 0x001f01ff, &administrators),
        ]);
        let audit = acl(&[ace(2, 0xc0, 3, &world), ace(17, 0, 1, &medium)]);
        let inheritable = acl(&[ace(2, 0xc3, 3, &world), ace(17, 3, 1, &medium)]);
        let empty = acl(&[]);
        let root = PathBuf::from(format!(r"H:\SecurityFixture-{}", args.experiment_id));
        let root_sd = descriptor(Acl::Present(&full), Acl::Present(&inheritable), true, true)?;
        phase = "create-new-directory";
        let directory = session.create_directory(&root, &root_sd)?;
        report["created_paths"]
            .as_array_mut()
            .unwrap()
            .push(json!(root));
        let directory_after = directory.snapshot();
        record_object(
            &mut report,
            "audited-directory",
            &root,
            true,
            &root_sd,
            directory_after.clone(),
            directory_after,
            Value::Null,
            None,
        )?;
        // Payload is initialized through the creator's held handle before any
        // restrictive DACL is installed. No access repair or existing-file open
        // is used to manufacture a successful restricted-file read.
        let cases = [
            (
                "audit-and-label.bin",
                descriptor(Acl::Present(&full), Acl::Present(&audit), true, true)?,
                false,
            ),
            (
                "null-dacl.bin",
                descriptor(Acl::Null, Acl::Present(&audit), true, true)?,
                false,
            ),
            (
                "empty-dacl.bin",
                descriptor(Acl::Present(&empty), Acl::Present(&audit), true, true)?,
                false,
            ),
            (
                "absent-dacl.bin",
                descriptor(Acl::Absent, Acl::Present(&audit), true, true)?,
                false,
            ),
            (
                "null-sacl.bin",
                descriptor(Acl::Present(&full), Acl::Null, true, true)?,
                false,
            ),
            (
                "empty-sacl.bin",
                descriptor(Acl::Present(&full), Acl::Present(&empty), true, true)?,
                false,
            ),
            (
                "inherited.bin",
                descriptor(Acl::Present(&full), Acl::Absent, false, false)?,
                true,
            ),
        ];
        for (index, (name, requested, inherited)) in cases.iter().enumerate() {
            phase = "create-new-file";
            let path = root.join(name);
            let source_layout = n2r_win32::security_descriptor::validate(requested)?;
            let sacl = match source_layout.sacl.offset {
                Some(at) => Acl::Present(&requested[at..at + source_layout.sacl.length]),
                None => {
                    if matches!(
                        source_layout.sacl.presence,
                        n2r_win32::security_descriptor::Presence::Null
                    ) {
                        Acl::Null
                    } else {
                        Acl::Absent
                    }
                }
            };
            let seed = descriptor(
                Acl::Present(&full),
                sacl,
                source_layout.dacl_protected(),
                source_layout.sacl_protected(),
            )?;
            let mut object = session.create_file(&path, &seed)?;
            report["created_paths"]
                .as_array_mut()
                .unwrap()
                .push(json!(path));
            let payload: Vec<u8> = (0..(4096 + index * 17 + 1))
                .map(|at| ((at * 31 + index * 11) & 255) as u8)
                .collect();
            object.file_mut().write_all(&payload)?;
            object.file().sync_all()?;
            let after_create = object.snapshot();
            phase = "restore-only-owned-security";
            let backup = if *inherited {
                Value::Null
            } else {
                serde_json::to_value(object.restore_security(requested)?)?
            };
            let after = object.snapshot();
            object.file_mut().seek(SeekFrom::Start(0))?;
            let mut actual = vec![0; payload.len()];
            object.file_mut().read_exact(&mut actual)?;
            ensure!(
                actual == payload,
                "fixture payload changed during security restoration"
            );
            let digest = json!({"length":payload.len(),"sha256":hex::encode(Sha256::digest(&actual)),"content_digest":n2r_win32::content_digest::of(&actual)});
            let actual_layout = n2r_win32::security_descriptor::validate(kernel(&after)?)?;
            if *name == "null-dacl.bin" {
                ensure!(
                    actual_layout.dacl.presence == n2r_win32::security_descriptor::Presence::Null,
                    "NULL DACL did not persist as NULL"
                );
            }
            if *name == "empty-dacl.bin" {
                ensure!(
                    actual_layout.dacl.presence
                        == n2r_win32::security_descriptor::Presence::Present
                        && actual_layout.dacl.ace_count == 0,
                    "empty DACL did not persist distinctly"
                );
            }
            if *name == "audit-and-label.bin" {
                ensure!(
                    actual_layout.sacl.ace_count >= 2,
                    "audit and mandatory-label SACL missing"
                );
            }
            record_object(
                &mut report,
                name,
                &path,
                false,
                requested,
                after_create,
                after,
                backup,
                Some(digest),
            )?;
        }
        phase = "restore-privileges";
        report["privilege_states"] = serde_json::to_value(session.finish()?)?;
        report["source_after"] =
            serde_json::to_value(discovery::discover(r"H:\", discovery::Role::Source)?)?;
        report["canonical_objects"] = json!(8);
        report["user_files"] = json!(7);
        report["directories"] = json!(1);
        report["requested_vs_observed_states_recorded"] = true.into();
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
        bytes.len() <= 8 * 1024 * 1024,
        "security fixture report exceeds bound"
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
    eprintln!("security fixture requires the enrolled Windows guest");
    std::process::exit(1);
}
