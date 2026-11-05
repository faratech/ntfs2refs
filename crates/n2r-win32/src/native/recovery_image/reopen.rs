//! Read-only reopening of a completed, independently pinned builder result.
//! No DISM/registry mutation, image copy/mount, current command or source writer.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedArtifact {
    role: String,
    path: PathBuf,
    snapshot: serde_json::Value,
    sha256: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedRecord {
    kind: String,
    artifacts: Vec<RecordedArtifact>,
    commands: Vec<serde_json::Value>,
    #[serde(rename = "SANpolicy")]
    san_policy: u32,
    #[serde(rename = "controlSets")]
    control_sets: Vec<u32>,
    #[serde(rename = "commitCommandExit0")]
    committed: bool,
    #[serde(rename = "coldBootQualified")]
    cold_qualified: bool,
    #[serde(rename = "noBCDorSourceWriter")]
    no_bcd_or_source_writer: bool,
}
fn bytes(artifact: &HeldArtifact, maximum: u64) -> io::Result<Vec<u8>> {
    need(
        artifact.pin.snapshot.file_bytes <= maximum,
        "completed image control exceeds admitted decode workspace",
    )?;
    let mut file = artifact
        .file
        .try_borrow_mut()
        .map_err(|_| bad("completed artifact already borrowed"))?;
    let before = crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    need(
        before == artifact.pin.snapshot,
        "same held completed control changed",
    )?;
    let mut out = vec![0; usize::try_from(before.file_bytes).map_err(io::Error::other)?];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut out)?;
    need(
        <[u8; 32]>::from(sha2::Sha256::digest(&out)) == artifact.pin.sha256
            && crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
                == before,
        "same held completed control bytes/identity changed",
    )?;
    Ok(out)
}
fn find_artifact<'a>(artifacts: &'a [HeldArtifact], role: &str) -> io::Result<&'a HeldArtifact> {
    artifacts
        .iter()
        .find(|p| p.pin.role == role)
        .ok_or_else(|| bad("required completed artifact missing"))
}
fn historical_commands(record: &CompletedRecord, request: &RecoveryImageRequest) -> io::Result<()> {
    need(
        record.commands.len() == 5,
        "unknown completed builder command protocol",
    )?;
    for command in &record.commands {
        need(
            command["actual_exit_observed"] == true
                && command["exit_code"] == 0
                && command["termination_requested"] == false
                && command["termination_error"].is_null()
                && command["monitor_error"].is_null()
                && command["pid"].as_u64().is_some_and(|p| p > 0),
            "historical image command did not close successfully",
        )?;
    }
    let command_args = |i: usize| -> io::Result<Vec<String>> {
        serde_json::from_value(record.commands[i]["args"].clone()).map_err(io::Error::other)
    };
    let root = &request.root;
    let mount = root.join("mount");
    let alias = format!("HKLM\\N2RRecovery_{}", request.run_id);
    let mut common = vec![
        "/English".into(),
        format!("/ScratchDir:{}", path_text(&root.join("dism-scratch"))?),
        format!("/LogPath:{}", path_text(&root.join("dism.log"))?),
    ];
    let mut expected = common.clone();
    expected.extend([
        "/Mount-Image".into(),
        format!("/ImageFile:{}", path_text(&root.join("boot.wim"))?),
        format!("/Index:{}", request.wim_index),
        format!("/MountDir:{}", path_text(&mount)?),
        "/CheckIntegrity".into(),
    ]);
    need(
        command_args(0)? == expected,
        "historical mount does not bind original WIM/index/root",
    )?;
    expected = common.clone();
    expected.extend([
        format!("/Image:{}", path_text(&mount)?),
        format!("/Apply-Unattend:{}", path_text(&root.join("san3.xml"))?),
    ]);
    need(
        command_args(1)? == expected,
        "historical SAN3 apply target differs",
    )?;
    need(
        command_args(2)?
            == vec![
                "load".to_owned(),
                alias.clone(),
                path_text(&mount.join("Windows/System32").join("config").join("SYSTEM"))?,
            ]
            && command_args(3)? == vec!["unload".to_owned(), alias],
        "historical mounted SYSTEM hive load/unload does not bind original root",
    )?;
    common.extend([
        "/Unmount-Image".into(),
        format!("/MountDir:{}", path_text(&mount)?),
        "/Commit".into(),
        "/CheckIntegrity".into(),
    ]);
    need(
        command_args(4)? == common,
        "historical complete commit of the owned WIM is absent",
    )
}
/// Return only an image/boot-install owner after actual held artifacts and
/// source/J native observations match the ORIGINAL independently pinned build.
/// Saved flags and commands are historical evidence, never current execution.
pub fn reopen_completed(
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    journal_volume: &File,
    request: &RecoveryImageRequest,
    expected_built_record_sha256: [u8; 32],
    events: &mut Vec<NativeEvent>,
) -> io::Result<OwnedRecoveryImage> {
    let b = request.budget;
    request.observation.validate()?;
    need(
        b.ram_bytes >= 16 * 1024 * 1024
            && b.maximum_evidence_bytes >= 65536
            && b.maximum_final_wim_bytes > 0
            && b.maximum_input_bytes > 0
            && b.minimum_free_bytes > 0
            && request.wim_index > 0
            && request.wim_index <= 16,
        "original bounded image budgets/index required",
    )?;
    need(
        request.run_id.len() == 32
            && request
                .run_id
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "original image run nonce invalid",
    )?;
    path_text(&request.root)?;
    let ancestors = parent_chain(&request.root)?;
    let root_handle = ancestors
        .first()
        .ok_or_else(|| bad("actual completed root absent"))?;
    let root_guid = crate::file_storage::final_path_guid(root_handle)?;
    let prefix = format!("{}\\", journal.disk.volume_path()?);
    need(
        root_guid
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)),
        "actual completed image root is not enrolled J",
    )?;
    enrollment(source, journal, journal_volume, request.observation, events)?;
    let resources = crate::resource_native::observe_available_resources(&request.root)?;
    need(
        resources.available_physical_bytes >= b.ram_bytes
            && resources.scratch_available_bytes >= b.minimum_free_bytes,
        "read-only image reopen requires its admitted RAM and original free floor; no image-copy reservation is charged",
    )?;
    let record = hold_artifact(
        "completed-build-record",
        request.root.join("recovery-image-built.json"),
        b.maximum_evidence_bytes,
    )?;
    need(
        record.pin.sha256 == expected_built_record_sha256,
        "completed build record differs from independent caller SHA",
    )?;
    need(
        record
            .pin
            .snapshot
            .file_bytes
            .checked_mul(32)
            .and_then(|n| n.checked_add(65536))
            .is_some_and(|n| n <= b.ram_bytes / 2),
        "completed record decoder exceeds original RAM budget",
    )?;
    let wire = bytes(&record, b.maximum_evidence_bytes)?;
    let completed: CompletedRecord = serde_json::from_slice(&wire).map_err(io::Error::other)?;
    drop(wire);
    need(
        completed.kind == "owned-SAN3-recovery-image-built-v1"
            && completed.san_policy == 3
            && completed.committed
            && !completed.cold_qualified
            && completed.no_bcd_or_source_writer
            && completed.artifacts.len() == 8,
        "unknown or incomplete original recovery-image completion record",
    )?;
    need(
        !completed.control_sets.is_empty()
            && completed.control_sets.len() <= 2
            && completed.control_sets.windows(2).all(|v| v[0] < v[1])
            && completed.control_sets.iter().all(|n| (1..=999).contains(n)),
        "historical selected IMAGE ControlSets invalid",
    )?;
    historical_commands(&completed, request)?;
    let shapes = [
        ("wim", "boot.wim", b.maximum_final_wim_bytes),
        ("sdi", "boot.sdi", b.maximum_input_bytes),
        ("runner", "runner.exe", b.maximum_input_bytes),
        ("bootstrap", "n2r-bootstrap.json", b.ram_bytes / 64),
        ("startup", "n2r-start.cmd", 65536),
        ("winpeshl", "winpeshl.ini", 65536),
        ("san3-unattend", "san3.xml", 65536),
        ("origin-marker", "ntfs2refs-recovery-origin.json", 65536),
    ];
    let mut artifacts = Vec::new();
    let mut pins = Vec::new();
    for (role, name, maximum) in shapes {
        let matches: Vec<_> = completed
            .artifacts
            .iter()
            .filter(|p| p.role == role)
            .collect();
        need(
            matches.len() == 1,
            "missing/duplicate completed image artifact role",
        )?;
        let expected = matches[0];
        let path = request.root.join(name);
        need(
            expected.path == path,
            "completed artifact does not belong to original owned root/path",
        )?;
        let artifact = hold_artifact(role, path, maximum)?;
        need(
            artifact.pin.sha256 == expected.sha256
                && serde_json::to_value(&artifact.pin.snapshot).map_err(io::Error::other)?
                    == expected.snapshot,
            "actual completed artifact native identity/EOF/allocation/attributes/links/path/SHA differ",
        )?;
        pins.push(artifact.pin.clone());
        artifacts.push(artifact);
    }
    need(
        find_artifact(&artifacts, "sdi")?.pin.sha256 == request.boot_sdi.sha256
            && find_artifact(&artifacts, "sdi")?.pin.snapshot.file_bytes == request.boot_sdi.bytes
            && find_artifact(&artifacts, "runner")?.pin.sha256 == request.runner.sha256
            && find_artifact(&artifacts, "runner")?.pin.snapshot.file_bytes == request.runner.bytes
            && find_artifact(&artifacts, "bootstrap")?.pin.sha256 == request.bootstrap.sha256
            && find_artifact(&artifacts, "bootstrap")?
                .pin
                .snapshot
                .file_bytes
                == request.bootstrap.bytes,
        "original SDI/embedded runner/bootstrap pins differ; never replace embedded helper with current installer",
    )?;
    need(bytes(find_artifact(&artifacts,"startup")?,65536)?==startup(&request.startup_args,request.prepared_bundle_sha256)?
        &&bytes(find_artifact(&artifacts,"winpeshl")?,65536)?==b"[LaunchApps]\r\n%SYSTEMROOT%\\System32\\cmd.exe, /d /s /c X:\\Windows\\System32\\n2r-start.cmd\r\n"
        &&bytes(find_artifact(&artifacts,"san3-unattend")?,65536)?==br#"<?xml version="1.0" encoding="utf-8"?><unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="offlineServicing"><component name="Microsoft-Windows-PartitionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><SanPolicy>3</SanPolicy></component></settings></unattend>"#,
        "actual held startup/SAN3 configuration differs from original protocol")?;
    let marker_expected = serde_json::json!({"kind":"ntfs2refs-owned-recovery-WIM-origin-v1","builder_nonce":request.run_id,
        "prepared_OUTER_bundle_sha256":hex::encode(request.prepared_bundle_sha256),"source":source,"journal":journal,
        "runner_sha256":hex::encode(request.runner.sha256),"startup_args":request.startup_args,"early_SAN_policy":3,
        "actual_IMAGE_ControlSets":completed.control_sets,"current_default_select_verified":true,"no_final_WIM_self_hash":true});
    need(
        bytes(find_artifact(&artifacts, "origin-marker")?, 65536)?
            == serde_json::to_vec(&marker_expected).map_err(io::Error::other)?,
        "actual origin marker does not bind original source/J/bundle/runner/run/SAN3",
    )?;
    #[derive(Deserialize)]
    struct BootstrapRoute {
        schema_version: u32,
        source: PartitionSourceBinding,
        journal: GeneralJournalStorageBinding,
        prepared_bundle_sha256: String,
    }
    let route: BootstrapRoute = serde_json::from_slice(&bytes(
        find_artifact(&artifacts, "bootstrap")?,
        b.ram_bytes / 64,
    )?)
    .map_err(io::Error::other)?;
    need(
        route.schema_version == 1
            && route.source == *source
            && route.journal == *journal
            && route.prepared_bundle_sha256 == hex::encode(request.prepared_bundle_sha256),
        "actual immutable bootstrap has another source/J/bundle",
    )?;
    let mount = request.root.join("mount");
    let m = fs::symlink_metadata(&mount)?;
    need(
        m.is_dir() && m.file_attributes() & 0x400 == 0 && fs::read_dir(&mount)?.next().is_none(),
        "completed owned mount directory is not ordinary/empty; no remount/discard attempted",
    )?;
    let alias = format!("N2RRecovery_{}", request.run_id);
    match open_key(&alias, KEY_QUERY_VALUE) {
        Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => (),
        Err(e) => return Err(e),
        Ok(_) => return Err(bad("original temporary IMAGE hive still loaded; no reopen")),
    }
    // Keep independently pinned build record open too, but preserve the
    // original public eight artifact pins and report ZERO current commands.
    artifacts.push(record);
    enrollment(source, journal, journal_volume, request.observation, events)?;
    for a in &artifacts {
        let file = a
            .file
            .try_borrow()
            .map_err(|_| bad("completed artifact already borrowed"))?;
        need(
            crate::reference_file::observe_reference_file_handle_with_limit(
                &file,
                a.pin.snapshot.file_bytes,
            )? == a.pin.snapshot,
            "same held image artifact changed during complete reopen",
        )?;
    }
    Ok(OwnedRecoveryImage {
        source: source.clone(),
        journal: journal.clone(),
        root: request.root.clone(),
        root_guid,
        wim: request.root.join("boot.wim"),
        sdi: request.root.join("boot.sdi"),
        runner: request.root.join("runner.exe"),
        startup_args: request.startup_args.clone(),
        bundle: request.prepared_bundle_sha256,
        control_sets: completed.control_sets,
        artifacts,
        pins,
        commands: Vec::new(),
        _ancestors: ancestors,
        budget: b,
        observation: request.observation,
        journal_volume: journal_volume.try_clone()?,
        origin_marker: request.root.join("ntfs2refs-recovery-origin.json"),
    })
}
