//! Read-only public run inspection. Reports are diagnostics, never write authority.
use crate::{
    general_conversion, general_reconstruct,
    lab_native_reconstruct::{identity_hash, partition_hash},
    lab_reconstruct,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, MountPathObservation, NativeEvent,
    general_layout::GeneralDiskBinding,
    journal_file::{
        JournalFileSnapshot, JournalProfile, observe_general_journal_file_with_profile,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Inputs {
    pub run_directory: PathBuf,
    pub intent_sha256: String,
    pub frozen_source_sha256: Option<String>,
    pub mount_paths_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub ticket_sha256: Option<String>,
}
pub(crate) fn canonical(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSource {
    pub schema_version: u32,
    pub kind: String,
    pub binding: GeneralDiskBinding,
    pub source_sha256: String,
    pub state: GeneralDiskState,
    pub freeze_observation: serde_json::Value,
    pub source_payload_writes: u64,
}
impl FrozenSource {
    pub fn validate(&self, intent: &general_conversion::Request) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            self.schema_version == 1
                && self.kind == "observed-frozen-source-identity"
                && self.binding == intent.pair.source
                && canonical(&self.source_sha256)
                && self.state.disk_attributes == 3
                && self.source_payload_writes == 0
                && self.freeze_observation.is_object(),
            "public frozen-source artifact differs"
        );
        ensure!(
            self.state.device.len() == 12
                && n2r_win32::layout::u32_at(&self.state.device, 0)? == 7
                && n2r_win32::layout::u32_at(&self.state.device, 4)? == self.binding.disk_number
                && n2r_win32::layout::u32_at(&self.state.device, 8)? == 0
                && self.state.disk_length.len() == 8
                && n2r_win32::layout::u64_at(&self.state.disk_length, 0)?
                    == self.binding.identity.disk_bytes,
            "frozen native route differs"
        );
        self.binding.validate_alignment(&self.state.alignment)?;
        self.binding.validate_layout(&self.state.gpt_layout)?;
        Ok(())
    }
}
pub(crate) struct RunArtifacts {
    pub inputs: Inputs,
    pub intent: general_conversion::Request,
    pub frozen: Option<FrozenSource>,
    pub mount_paths: Option<MountPathObservation>,
    pub request: Option<general_reconstruct::Request>,
    pub ticket: Option<lab_reconstruct::JournalTicket>,
    pub blocking_artifacts: Vec<String>,
    _files: Vec<File>,
}
pub(crate) fn ordinary_run(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .context("ordinary Unicode run directory required")?;
    let system = std::env::var("SystemRoot")?;
    ensure!(
        text.len() <= 512
            && text
                .get(..3)
                .zip(system.get(..3))
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            && !text[3..].contains(':')
            && !text.contains(['/', '\0'])
            && !text.contains(".."),
        "ordinary OS-volume run directory required"
    );
    for p in path.ancestors() {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "run has nonordinary ancestry"
        );
    }
    Ok(())
}
fn read_pinned<T: serde::de::DeserializeOwned>(
    path: &Path,
    pin: &str,
    max: u64,
    files: &mut Vec<File>,
) -> Result<T> {
    ensure!(canonical(pin), "canonical artifact SHA-256 required");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.len() <= max && m.file_attributes() & 0x400 == 0,
        "bounded ordinary pinned artifact required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.len() <= max && m.file_attributes() & 0x400 == 0,
        "opened artifact differs"
    );
    let mut b = vec![];
    (&mut f).take(max + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= max && hex::encode(Sha256::digest(&b)) == pin,
        "artifact SHA-256 differs: {}",
        path.display()
    );
    let value = serde_json::from_slice(&b)?;
    files.push(f);
    Ok(value)
}
fn optional<T: serde::de::DeserializeOwned>(
    root: &Path,
    name: &str,
    pin: &Option<String>,
    max: u64,
    files: &mut Vec<File>,
) -> Result<Option<T>> {
    let path = root.join(name);
    let present = match fs::symlink_metadata(&path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    ensure!(
        present == pin.is_some(),
        "{} {}",
        name,
        if present {
            "is present and requires its exact SHA-256 pin"
        } else {
            "is absent but a pin was supplied"
        }
    );
    pin.as_deref()
        .map(|p| read_pinned(&path, p, max, files))
        .transpose()
}
pub(crate) fn load(inputs: &Inputs) -> Result<RunArtifacts> {
    ordinary_run(&inputs.run_directory)?;
    let mut files = vec![];
    let intent: general_conversion::Request = read_pinned(
        &inputs.run_directory.join("conversion-intent.json"),
        &inputs.intent_sha256,
        16384,
        &mut files,
    )?;
    intent.validate()?;
    let frozen: Option<FrozenSource> = optional(
        &inputs.run_directory,
        "qualification/source-frozen.json",
        &inputs.frozen_source_sha256,
        64 << 20,
        &mut files,
    )?;
    if let Some(f) = &frozen {
        f.validate(&intent)?;
    }
    let mount_paths: Option<MountPathObservation> = optional(
        &inputs.run_directory,
        "qualification/source-mount-paths.json",
        &inputs.mount_paths_sha256,
        1 << 20,
        &mut files,
    )?;
    if let Some(m) = &mount_paths {
        ensure!(
            m.binding == intent.pair.source && m.all_paths_resolve_to_bound_volume,
            "captured source mount routes differ"
        );
        n2r_win32::source_cancel::validate_mount_paths(&m.paths)?;
    }
    ensure!(
        frozen.is_none() || mount_paths.is_some(),
        "frozen public run lacks pinned mount paths"
    );
    let request: Option<general_reconstruct::Request> = optional(
        &inputs.run_directory,
        "request.json",
        &inputs.request_sha256,
        131072,
        &mut files,
    )?;
    if let Some(r) = &request {
        r.validate()?;
        ensure!(
            r.schema_version == intent.schema_version
                && r.source_resource_profile == intent.source_resource_profile
                && r.experiment_id == intent.experiment_id
                && r.pair == intent.pair
                && serde_json::to_vec(&r.journal)? == serde_json::to_vec(&intent.journal)?
                && r.max_journal_bytes == intent.max_journal_bytes,
            "reconstruction request differs from public intent"
        );
        if let Some(f) = &frozen {
            ensure!(
                r.comparison.source_sha256 == f.source_sha256,
                "plan source hash differs from public freeze"
            );
        }
    }
    let ticket: Option<lab_reconstruct::JournalTicket> = optional(
        &inputs.run_directory,
        "ticket.json",
        &inputs.ticket_sha256,
        65536,
        &mut files,
    )?;
    ensure!(
        ticket.is_none() || request.is_some(),
        "ticket requires pinned reconstruction request"
    );
    if let Some(ticket) = &ticket {
        ensure!(
            ticket.schema_version == intent.schema_version
                && ticket.binding.source_resource_profile == intent.source_resource_profile,
            "journal ticket profile differs from public intent"
        );
    }
    let mut blocking_artifacts = vec![];
    for name in ["apply.json", "finalization.json", "result.json"] {
        match fs::symlink_metadata(inputs.run_directory.join(name)) {
            Ok(_) => blocking_artifacts.push(name.into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => blocking_artifacts.push(format!("{name}: cannot exclude artifact: {e}")),
        }
    }
    Ok(RunArtifacts {
        inputs: inputs.clone(),
        intent,
        frozen,
        mount_paths,
        request,
        ticket,
        blocking_artifacts,
        _files: files,
    })
}
pub(crate) fn same_hardware(a: &GeneralDiskBinding, b: &GeneralDiskBinding) -> Result<bool> {
    let x = &a.identity;
    let y = &b.identity;
    let guid = n2r_win32::layout::guid_bytes;
    Ok(a.disk_number == b.disk_number
        && guid(&a.volume_guid)? == guid(&b.volume_guid)?
        && guid(&x.disk_guid)? == guid(&y.disk_guid)?
        && guid(&x.partition_guid)? == guid(&y.partition_guid)?
        && x.partition_number == y.partition_number
        && x.disk_bytes == y.disk_bytes
        && x.partition_offset == y.partition_offset
        && x.partition_bytes == y.partition_bytes
        && x.logical_sector_bytes == y.logical_sector_bytes
        && x.physical_sector_bytes == y.physical_sector_bytes)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Missing,
    UnpreparedClear,
    PreparedClear,
    ApplyIntent,
    RollbackIntent,
    RefsHandoff,
    NtfsRollback,
    Busy,
    Unresolved,
}
#[derive(Clone, Debug, Serialize)]
pub struct JournalObservation {
    pub state: JournalState,
    pub path: PathBuf,
    pub file_bytes: Option<u64>,
    pub mutable_sectors_clear: bool,
    pub immutable_body_verified: bool,
    pub marker_verified: bool,
    pub source_image_verified: bool,
    pub detail: String,
    pub identity: Option<JournalFileSnapshot>,
}
pub(crate) struct JournalLease {
    pub observation: JournalObservation,
    pub file: Option<File>,
    pub prefix: Vec<u8>,
}
fn marker(
    magic: &[u8; 8],
    code: u8,
    ticket: &lab_reconstruct::JournalTicket,
    target_hash: &str,
) -> Result<[u8; 4096]> {
    ensure!(
        canonical(&ticket.immutable_sha256) && canonical(target_hash),
        "lifecycle marker hash is invalid"
    );
    let mut b = [0; 4096];
    b[..8].copy_from_slice(magic);
    b[8] = code;
    b[16..48].copy_from_slice(&hex::decode(&ticket.immutable_sha256)?);
    b[48..80].copy_from_slice(&hex::decode(target_hash)?);
    let h = Sha256::digest(&b[..4064]);
    b[4064..].copy_from_slice(&h);
    Ok(b)
}
pub(crate) fn journal_path(intent: &general_conversion::Request) -> Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{}\\ntfs2refs-shadow\\{}\\reconstruction.journal",
        intent.journal.disk.volume_path()?,
        intent.experiment_id
    )))
}
pub(crate) fn open_journal(run: &RunArtifacts) -> Result<JournalLease> {
    let root = format!("{}\\", run.intent.journal.disk.volume_path()?);
    let discovered = n2r_win32::discovery::discover(
        &root,
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: run.intent.journal.allow_additional_partitions,
        },
    )?;
    ensure!(
        same_hardware(&discovered.binding, &run.intent.journal.disk)?,
        "actual journal storage differs"
    );
    let path = journal_path(&run.intent)?;
    let mut observation = JournalObservation {
        state: JournalState::Missing,
        path: path.clone(),
        file_bytes: None,
        mutable_sectors_clear: true,
        immutable_body_verified: false,
        marker_verified: false,
        source_image_verified: false,
        detail: "derived journal is absent on verified storage".into(),
        identity: None,
    };
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                run.ticket.is_none(),
                "pinned journal ticket exists but journal is missing"
            );
            return Ok(JournalLease {
                observation,
                file: None,
                prefix: vec![],
            });
        }
        Err(e) => return Err(e.into()),
        Ok(m) => ensure!(
            m.is_file()
                && m.file_attributes() & 0x400 == 0
                && m.len() <= run.intent.max_journal_bytes,
            "derived journal is not a bounded ordinary file"
        ),
    }
    let mut f = match OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if matches!(e.raw_os_error(), Some(32 | 33)) => {
            observation.state = JournalState::Busy;
            observation.mutable_sectors_clear = false;
            observation.detail = "journal is held by another operation".into();
            return Ok(JournalLease {
                observation,
                file: None,
                prefix: vec![],
            });
        }
        Err(e) => return Err(e.into()),
    };
    let identity = observe_general_journal_file_with_profile(
        &f,
        &run.intent.journal,
        JournalProfile::from_schema(run.intent.schema_version)?,
    )?;
    let len = identity.file_bytes;
    observation.file_bytes = Some(len);
    observation.identity = Some(identity.clone());
    let mut prefix = vec![0; len.min(8192) as usize];
    f.read_exact(&mut prefix)?;
    observation.mutable_sectors_clear = prefix.iter().all(|v| *v == 0);
    if let (Some(plan), Some(ticket)) = (&run.request, &run.ticket) {
        let binding = lab_reconstruct::JournalBinding {
            experiment_id: plan.experiment_id.clone(),
            source_resource_profile: plan.source_resource_profile,
            target_identity_sha256: partition_hash(&plan.pair.source.identity)?,
            shadow_identity_sha256: partition_hash(&plan.pair.shadow.identity)?,
            journal_identity_sha256: identity_hash(
                b"ntfs2refs/general/journal-file-identity/v1",
                &identity.identity,
            )?,
        };
        ensure!(
            ticket.schema_version == plan.schema_version
                && ticket.binding == binding
                && ticket.journal_length == len,
            "journal ticket/storage differs"
        );
        let descriptor = lab_reconstruct::inspect_completed_journal(&mut f, ticket, &binding)?;
        ensure!(
            serde_json::to_vec(&descriptor.request)? == serde_json::to_vec(&plan.comparison)?,
            "immutable journal plan differs"
        );
        observation.immutable_body_verified = true;
        ensure!(
            prefix.len() == 8192,
            "complete journal mutable sectors absent"
        );
        let handoff = &prefix[..4096];
        let intent = &prefix[4096..];
        let zero = [0u8; 4096];
        let refs = marker(
            b"N2RHND01",
            3,
            ticket,
            &descriptor.expected_postimage_sha256,
        )?;
        let rollback = marker(b"N2RABT01", 4, ticket, &plan.comparison.source_sha256)?;
        let apply = marker(
            b"N2RINT01",
            1,
            ticket,
            &descriptor.expected_postimage_sha256,
        )?;
        let undo = marker(b"N2RINT01", 2, ticket, &plan.comparison.source_sha256)?;
        observation.state = if handoff == zero && intent == zero {
            JournalState::PreparedClear
        } else if handoff == zero && intent == apply {
            JournalState::ApplyIntent
        } else if handoff == zero && intent == undo {
            JournalState::RollbackIntent
        } else if handoff == refs && (intent == zero || intent == apply) {
            JournalState::RefsHandoff
        } else if handoff == rollback && (intent == zero || intent == undo) {
            JournalState::NtfsRollback
        } else {
            JournalState::Unresolved
        };
        observation.marker_verified = observation.state != JournalState::Unresolved;
        observation.detail=if observation.marker_verified{"immutable journal and exact lifecycle marker verified; current target image is not verified"}else{"partial, foreign or contradictory mutable marker"}.into();
    } else {
        observation.state = if observation.mutable_sectors_clear {
            JournalState::UnpreparedClear
        } else {
            JournalState::Unresolved
        };
        observation.detail=if observation.mutable_sectors_clear{"journal preparation has no mutable reconstruction intent; immutable body is unqualified"}else{"mutable journal bytes exist without a complete pinned ticket/plan"}.into();
    }
    Ok(JournalLease {
        observation,
        file: Some(f),
        prefix,
    })
}
pub(crate) fn require_no_activation(run: &RunArtifacts, journal: &JournalLease) -> Result<()> {
    ensure!(
        run.frozen.is_some() && run.mount_paths.is_some(),
        "cancel requires the actual pinned public freeze and mount paths"
    );
    ensure!(
        run.blocking_artifacts.is_empty()
            && journal.observation.mutable_sectors_clear
            && matches!(
                journal.observation.state,
                JournalState::Missing | JournalState::UnpreparedClear | JournalState::PreparedClear
            ),
        "reconstruction activation/intent or unresolved lifecycle prevents cancel"
    );
    for name in ["apply.json", "finalization.json", "result.json"] {
        ensure!(
            matches!(fs::symlink_metadata(run.inputs.run_directory.join(name)),Err(ref e)if e.kind()==std::io::ErrorKind::NotFound),
            "postactivation artifact exists or cannot be excluded: {name}"
        );
    }
    Ok(())
}
pub(crate) fn recheck_journal(run: &RunArtifacts, journal: &mut JournalLease) -> Result<()> {
    match &mut journal.file {
        Some(file) => {
            let observed = observe_general_journal_file_with_profile(
                file,
                &run.intent.journal,
                JournalProfile::from_schema(run.intent.schema_version)?,
            )?;
            let before = journal
                .observation
                .identity
                .as_ref()
                .context("journal identity absent")?;
            ensure!(
                observed.identity == before.identity
                    && Some(observed.file_bytes) == journal.observation.file_bytes,
                "journal identity/length changed during cancel"
            );
            let mut current = vec![0; journal.prefix.len()];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut current)?;
            ensure!(
                current == journal.prefix && current.iter().all(|v| *v == 0),
                "journal intent changed during cancel"
            );
        }
        None => ensure!(
            journal.observation.state == JournalState::Missing
                && matches!(fs::symlink_metadata(&journal.observation.path),Err(ref e)if e.kind()==std::io::ErrorKind::NotFound),
            "journal appeared or could not be excluded during cancel"
        ),
    }
    require_no_activation(run, journal)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    FrozenBeforeActivation,
    ActivatedBeforeHandoff,
    HandoffOfflineImageUnverified,
    MountedRefsAfterHandoff,
    RollbackOfflineImageUnverified,
    MountedNtfsAfterRollback,
    OnlineUnqualified,
    Busy,
    Unresolved,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub kind: &'static str,
    pub state: State,
    pub run_directory: PathBuf,
    pub source: Option<GeneralDiskState>,
    pub source_filesystem: Option<String>,
    pub shadow: Option<GeneralDiskState>,
    pub shadow_error: Option<String>,
    pub journal: Option<JournalObservation>,
    pub can_request: Vec<String>,
    pub required_further_proofs: Vec<String>,
    pub errors: Vec<String>,
    pub events: Vec<NativeEvent>,
    pub source_image_verified: bool,
    pub execution_authorized: bool,
    pub source_payload_writes: u64,
    pub disk_attributes_changed: bool,
}
pub fn classify(
    attrs: u64,
    journal: &JournalState,
    fs: Option<&str>,
    frozen_bound: bool,
    blocking: bool,
    shadow_verified: bool,
) -> (State, Vec<String>, Vec<String>) {
    let pending=vec!["each operation revalidates its own device, journal, current image and lifecycle requirements".into()];
    match journal {
  JournalState::Busy=>(State::Busy,vec![],vec!["wait for the existing operation; do not restart or cancel it from this report".into()]),
  JournalState::Unresolved=>(State::Unresolved,vec![],vec!["resolve the foreign/partial marker without clearing it".into()]),
  JournalState::Missing|JournalState::UnpreparedClear|JournalState::PreparedClear if attrs==3&&frozen_bound&&!blocking=>(State::FrozenBeforeActivation,vec!["cancel".into()],vec!["cancel must acquire an exclusive source lease, prove the complete unchanged NTFS image and recheck no mutable journal intent".into()]),
  JournalState::PreparedClear|JournalState::ApplyIntent|JournalState::RollbackIntent if attrs==1=>{let mut ops=vec!["rollback --without-shadow".into()];if shadow_verified{ops.extend(["resume".into(),"rollback".into()]);}(State::ActivatedBeforeHandoff,ops,pending)},
  JournalState::RefsHandoff if attrs==1&&shadow_verified=>(State::HandoffOfflineImageUnverified,vec!["finalize --after-marker".into()],pending),
  JournalState::RefsHandoff if attrs==0&&fs==Some("ReFS")=>(State::MountedRefsAfterHandoff,vec!["complete-label (requires a pinned desired label and expected tree)".into()],vec!["strict current native-tree and label checks; raw replay and rollback remain closed".into()]),
  JournalState::NtfsRollback if attrs==1=>(State::RollbackOfflineImageUnverified,vec!["rollback --without-shadow --after-marker".into()],pending),
  JournalState::NtfsRollback if attrs==0&&fs==Some("NTFS")=>(State::MountedNtfsAfterRollback,vec![],vec!["marker and mounted filesystem verified; current full raw image was not hashed".into()]),
  JournalState::Missing|JournalState::UnpreparedClear if attrs==0=>(State::OnlineUnqualified,vec![],pending),
  _=>(State::Unresolved,vec![],vec!["device attributes, artifacts and journal lifecycle do not establish a supported state".into()]),
 }
}
pub fn inspect(inputs: &Inputs, output: &Path) -> Result<Report> {
    crate::general_qualification::create_output(output)?;
    let mut report = Report {
        schema_version: 1,
        kind: "read-only-public-operation-state",
        state: State::Unresolved,
        run_directory: inputs.run_directory.clone(),
        source: None,
        source_filesystem: None,
        shadow: None,
        shadow_error: None,
        journal: None,
        can_request: vec![],
        required_further_proofs: vec![],
        errors: vec![],
        events: vec![],
        source_image_verified: false,
        execution_authorized: false,
        source_payload_writes: 0,
        disk_attributes_changed: false,
    };
    let attempt = (|| -> Result<()> {
        let run = load(inputs)?;
        let source = n2r_win32::observe_general_disk_state_readonly(
            run.intent.pair.source.clone(),
            &mut report.events,
        )?;
        // Retain actual observed facts even if a later journal or freeze
        // comparison leaves the operation unresolved.
        report.source = Some(source.clone());
        if let Some(f) = &run.frozen {
            let mut expected = f.state.clone();
            expected.disk_attributes = source.disk_attributes;
            ensure!(
                source == expected,
                "actual source hardware differs from pinned freeze"
            );
        }
        if source.disk_attributes == 0 {
            match n2r_win32::rediscover_general_volume(
                run.intent.pair.source.clone(),
                &mut report.events,
            )
            .and_then(|b| n2r_win32::mounted_filesystem_general(b, &mut report.events))
            {
                Ok(fs) => report.source_filesystem = Some(fs),
                Err(e) => report
                    .errors
                    .push(format!("mounted filesystem unverified: {e}")),
            }
        }
        let shadow = n2r_win32::observe_general_disk_state_readonly(
            run.intent.pair.shadow.clone(),
            &mut report.events,
        );
        let shadow_verified = shadow.as_ref().is_ok_and(|s| s.disk_attributes == 3);
        match shadow {
            Ok(s) => report.shadow = Some(s),
            Err(e) => report.shadow_error = Some(e.to_string()),
        };
        let journal = open_journal(&run)?;
        let (state, ops, proofs) = classify(
            source.disk_attributes,
            &journal.observation.state,
            report.source_filesystem.as_deref(),
            run.frozen.is_some(),
            !run.blocking_artifacts.is_empty(),
            shadow_verified,
        );
        report.state = state;
        report.can_request = ops;
        report.required_further_proofs = proofs;
        report.source = Some(source);
        report.journal = Some(journal.observation);
        Ok(())
    })();
    if let Err(e) = attempt {
        if e.chain()
            .filter_map(|v| v.downcast_ref::<std::io::Error>())
            .any(|v| matches!(v.raw_os_error(), Some(32 | 33)))
        {
            report.state = State::Busy;
            report.required_further_proofs.push("an artifact sharing conflict exists; worker identity/liveness is not established by this report".into());
        }
        report.errors.push(format!("{e:#}"));
    }
    crate::general_qualification::save(output, "state.json", &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifier_never_turns_handoff_partial_intent_or_unknown_source_into_cancel() {
        let (s, ops, proofs) = classify(3, &JournalState::PreparedClear, None, true, false, false);
        assert_eq!(s, State::FrozenBeforeActivation);
        assert_eq!(ops, ["cancel"]);
        assert!(proofs[0].contains("exclusive"));
        for journal in [
            JournalState::ApplyIntent,
            JournalState::RollbackIntent,
            JournalState::RefsHandoff,
            JournalState::NtfsRollback,
            JournalState::Unresolved,
            JournalState::Busy,
        ] {
            let (_, ops, _) = classify(3, &journal, None, true, false, true);
            assert!(!ops.iter().any(|o| o == "cancel"));
        }
        for (bound, blocking) in [(false, false), (true, true)] {
            let (s, ops, _) =
                classify(3, &JournalState::PreparedClear, None, bound, blocking, true);
            assert_eq!(s, State::Unresolved);
            assert!(ops.is_empty());
        }
    }
    #[test]
    fn activated_missing_shadow_and_native_handoff_have_distinct_conditional_operations() {
        let (s, ops, _) = classify(1, &JournalState::ApplyIntent, None, true, true, false);
        assert_eq!(s, State::ActivatedBeforeHandoff);
        assert_eq!(ops, ["rollback --without-shadow"]);
        let (_, ops, _) = classify(1, &JournalState::RollbackIntent, None, true, true, true);
        assert!(ops.iter().any(|o| o == "resume"));
        let (s, ops, _) = classify(1, &JournalState::RefsHandoff, None, true, true, false);
        assert_eq!(s, State::Unresolved);
        assert!(ops.is_empty());
        let (s, ops, _) = classify(
            0,
            &JournalState::RefsHandoff,
            Some("ReFS"),
            true,
            true,
            false,
        );
        assert_eq!(s, State::MountedRefsAfterHandoff);
        assert!(ops[0].starts_with("complete-label"));
        assert!(!ops.iter().any(|o| o.contains("rollback")));
        let (s, ops, _) = classify(1, &JournalState::NtfsRollback, None, true, true, false);
        assert_eq!(s, State::RollbackOfflineImageUnverified);
        assert_eq!(ops, ["rollback --without-shadow --after-marker"]);
    }
    #[test]
    fn pinned_artifact_handles_exclude_rewriters_and_require_exact_file_hash() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact.json");
        let bytes = br#"{"value":7}"#;
        fs::write(&path, bytes).unwrap();
        let pin = hex::encode(Sha256::digest(bytes));
        let mut files = vec![];
        let v: serde_json::Value = read_pinned(&path, &pin, 1024, &mut files).unwrap();
        assert_eq!(v["value"], 7);
        assert!(
            OpenOptions::new()
                .write(true)
                .share_mode(3)
                .open(&path)
                .is_err()
        );
        drop(files);
        assert!(
            read_pinned::<serde_json::Value>(&path, &"0".repeat(64), 1024, &mut vec![]).is_err()
        );
        assert!(read_pinned::<serde_json::Value>(&path, &pin, 2, &mut vec![]).is_err());
    }
    #[test]
    #[ignore = "requires N2R_PUBLIC_RUN_ARTIFACTS pointing to existing public conversion metadata; ordinary-file reads only"]
    fn actual_public_freeze_schema_binds_and_legacy_lab_schema_cannot_replace_it() {
        let root = PathBuf::from(std::env::var("N2R_PUBLIC_RUN_ARTIFACTS").unwrap());
        let intent: general_conversion::Request =
            serde_json::from_slice(&fs::read(root.join("conversion-intent.json")).unwrap())
                .unwrap();
        let bytes = fs::read(root.join("qualification/source-frozen.json")).unwrap();
        let frozen: FrozenSource = serde_json::from_slice(&bytes).unwrap();
        frozen.validate(&intent).unwrap();
        let mut activated = frozen.clone();
        activated.state.disk_attributes = 1;
        assert!(activated.validate(&intent).is_err());
        let mut foreign = frozen.clone();
        foreign.binding.disk_number += 1;
        assert!(foreign.validate(&intent).is_err());
        let mut legacy = serde_json::to_value(&frozen).unwrap();
        legacy["kind"] = "general-frozen-ntfs-source".into();
        legacy.as_object_mut().unwrap().remove("state");
        legacy["before"] = serde_json::to_value(&frozen.state).unwrap();
        assert!(serde_json::from_value::<FrozenSource>(legacy).is_err());
    }
}
