//! The ways back of the restart route: a run that made its source read-only,
//! and perhaps selected its recovery image for the next start, is taken back
//! as long as nothing of the conversion was written.
//!
//! One rule decides it everywhere: the run's journal. A sealed run is taken
//! back only if its journal classifies as prepared and clear with the
//! existing reader; a run that never sealed its preparation only if no
//! lifecycle byte was ever written to its journal. Everything else is
//! refused, in words that say what the way forward is. The decision is then
//! recorded in the run folder before anything is changed, and from that
//! record on no start of the runner applies the run.
use super::*;
use crate::selected_journal::{SelectedLifecycle, SelectedTicket};
use n2r_win32::{
    partition_restoration::{PreparedSourceOrigin, PreparedSourceReturn},
    recovery_boot::{
        RecoveryBootBudget, RecoveryBootCancellationReceipt, RecoveryBootSelectionState,
    },
    volume_label::VolumeLabel,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// The record of a cancellation, in the run folder.
pub const CANCELLED_RECORD: &str = "cancelled.json";
const ADMISSION_RECORD: &str = "workflow-admission.json";
const ADMISSION_KIND: &str = "shared-native-shadow-offline-workflow-admission-v1";
const REQUEST_RECORD: &str = "offline-request.json";
const BUNDLE_RECORD: &str = "prepared/control/windows-prepared-offline-apply-bundle.json";
const BUNDLE_KIND: &str = "windows-prepared-offline-apply-bundle-v1";
const INTENT_RECORD: &str = "prepared/control/partition.intent";
const UNSEALED_JOURNAL: &str = "prepared/arena/selected.journal";
const CANCELLED_KIND: &str = "ntfs2refs-restart-run-cancelled-v1";
/// The lifecycle area of this route's journal: completion and intent granule.
const LIFECYCLE_AREA_BYTES: u64 = 8192;
/// A record of a run is read whole; none of them comes near this.
const RECORD_LIMIT: u64 = 64 * 1024 * 1024;

/// What a run that can still be taken back is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnappliedState {
    /// The preparation never sealed its bundle: nothing could have applied it.
    PreparationUnfinished,
    /// Sealed, and the journal is prepared and clear.
    PreparedClear,
}

/// What the run's journal shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalEvidence {
    /// There is no journal file.
    Absent,
    /// No sealed bundle to read it with; its lifecycle area is all zero.
    LifecycleAreaClear,
    /// No sealed bundle to read it with; its lifecycle area holds bytes.
    LifecycleAreaWritten,
    /// Classified with the sealed bundle's ticket.
    Lifecycle(SelectedLifecycle),
}

/// Which runs can be cancelled, and what the others are told. The only
/// states that pass are the two in which nothing was written to the source.
pub fn admit_cancellation(
    sealed: bool,
    journal: JournalEvidence,
) -> std::result::Result<UnappliedState, String> {
    use JournalEvidence::*;
    use SelectedLifecycle::*;
    match (sealed, journal) {
        (true, Lifecycle(PreparedClear)) => Ok(UnappliedState::PreparedClear),
        (false, Absent | LifecycleAreaClear) => Ok(UnappliedState::PreparationUnfinished),
        (true, Lifecycle(ApplyIntent)) => Err(
            "the conversion had started (the journal holds its apply intent), so it cannot be cancelled from here. Restart the machine: the conversion goes on by itself, or asks whether to go on or to put NTFS back."
                .into(),
        ),
        (true, Lifecycle(RollbackIntent)) => Err(
            "the conversion had started and was being rolled back (the journal holds its rollback intent), so it cannot be cancelled from here. Restart the machine: the rollback goes on by itself."
                .into(),
        ),
        (true, Lifecycle(Handoff)) => Err(
            "the conversion was written completely (the journal is closed with its handoff), so there is nothing to cancel. Restart the machine: it finishes by itself and Windows starts with the volume as ReFS."
                .into(),
        ),
        (true, Lifecycle(Aborted)) => Err(
            "the conversion had started and was rolled back (the journal is closed as aborted). Restart the machine: it finishes by itself and Windows starts with the volume as NTFS."
                .into(),
        ),
        (true, Absent) => Err(
            "the run's sealed preparation names a journal that is not there, so it cannot be shown that the conversion never started. Nothing was changed."
                .into(),
        ),
        (true, LifecycleAreaClear | LifecycleAreaWritten) => Err(
            "the run's journal was not read with its sealed preparation. Nothing was changed."
                .into(),
        ),
        (false, LifecycleAreaWritten) => Err(
            "the run's journal holds lifecycle bytes although its preparation was never sealed, so it cannot be shown that the conversion never started. Nothing was changed."
                .into(),
        ),
        (false, Lifecycle(_)) => Err(
            "the run's journal was classified without a sealed preparation. Nothing was changed."
                .into(),
        ),
    }
}

/// Where a cancellation was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelEnvironment {
    Windows,
    RecoveryEnvironment,
}
/// What became of the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeOutcome {
    /// Writable NTFS again, verified.
    GivenBack,
    /// The run never made it read-only.
    NeverProtected,
    /// Still marked read-only: the cancellation is not complete.
    StillReadOnly,
}
/// What became of the boot selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootOutcome {
    /// Put back to what it was before the run.
    Restored,
    /// The run had not changed it.
    WasNotInstalled,
    /// Not yet looked at, or could not be put back.
    Unsettled,
}

/// The durable record of a cancellation. Written when the cancellation is
/// decided, before anything is changed, and rewritten when it ends. Its
/// presence alone forbids applying the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelledRun {
    pub schema_version: u32,
    pub kind: String,
    pub cancelled_unix_ms: u64,
    pub cancelled_utc: String,
    pub from_state: UnappliedState,
    pub environment: CancelEnvironment,
    /// The failure the cancellation followed; absent when it was asked for.
    #[serde(default)]
    pub cause: Option<String>,
    pub volume: VolumeOutcome,
    pub boot_selection: BootOutcome,
    /// What could not be done, in the words it was refused with.
    #[serde(default)]
    pub unfinished: Vec<String>,
    pub completed: bool,
}
impl CancelledRun {
    fn begin(
        from_state: UnappliedState,
        environment: CancelEnvironment,
        cause: Option<&str>,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            schema_version: 1,
            kind: CANCELLED_KIND.into(),
            cancelled_unix_ms: now_unix_ms,
            cancelled_utc: utc_text(now_unix_ms),
            from_state,
            environment,
            cause: cause.map(str::to_owned),
            volume: VolumeOutcome::StillReadOnly,
            boot_selection: BootOutcome::Unsettled,
            unfinished: Vec::new(),
            completed: false,
        }
    }
    /// What a later start is told instead of an apply.
    pub fn refusal(&self, run: &Path) -> String {
        if self.completed {
            format!(
                "this run was cancelled on {}; the volume is NTFS as it was. A conversion is started again with a new run.",
                self.cancelled_utc
            )
        } else {
            format!(
                "this run was cancelled on {}, and its cancellation is not complete. To finish it: {}",
                self.cancelled_utc,
                cancel_command(run)
            )
        }
    }
}

/// 2026-11-18 14:03:22 UTC, from milliseconds since 1970.
pub fn utc_text(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Days since 1970-01-01 to a civil date (proleptic Gregorian).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// The command that cancels a run, as it is printed everywhere.
pub fn cancel_command(run: &Path) -> String {
    format!("ntfs2refs --recover \"{}\" --rollback", run.display())
}

/// What a run says before it restarts the machine.
pub fn before_restart_lines(run: &Path) -> Vec<String> {
    vec![
        "The machine restarts now and converts the volume before Windows starts again. Keep the working disk connected until Windows is back.".to_owned(),
        format!(
            "To cancel before the conversion has started: {}",
            cancel_command(run)
        ),
        "To recover: if the machine is switched off or loses power during the conversion, start it again. It returns to the conversion by itself and asks whether to go on (R) or to put NTFS back (B). A conversion that cannot start puts the machine back by itself: Windows starts with the volume as NTFS.".to_owned(),
    ]
}

/// What a completed cancellation says. `volume` is the drive letter with
/// its colon where the volume has one.
pub fn cancelled_lines(record: &CancelledRun, volume: &str, run: &Path) -> Vec<String> {
    let first = match record.volume {
        VolumeOutcome::GivenBack => format!(
            "The conversion was cancelled before anything was written to the volume. {volume} is NTFS as it was."
        ),
        VolumeOutcome::NeverProtected => format!(
            "The conversion was cancelled before the volume was changed in any way. {volume} is NTFS as it was."
        ),
        VolumeOutcome::StillReadOnly => format!(
            "The conversion was cancelled before anything was written to the volume, but {volume} is still marked read-only. To finish the cancellation: {}",
            cancel_command(run)
        ),
    };
    let mut lines = vec![first];
    match record.boot_selection {
        BootOutcome::Restored => lines.push(
            "The machine starts Windows as before: the boot selection was put back.".to_owned(),
        ),
        BootOutcome::WasNotInstalled => {}
        BootOutcome::Unsettled => lines.push(format!(
            "The boot selection was not put back. To finish the cancellation: {}",
            cancel_command(run)
        )),
    }
    lines
}

/// What is said of the folder a cancelled run leaves.
pub fn working_files_line(run: &Path, bytes: u64) -> String {
    format!(
        "The run's working files are still in {} ({:.1} GiB); delete the folder when you no longer need its records.",
        run.display(),
        bytes as f64 / 1_073_741_824.0
    )
}

/// The error of a run that failed after it had begun, with what the way
/// back did about it.
pub fn failure_with_way_back(
    cause: anyhow::Error,
    way_back: &Result<WayBackReport>,
    run: &Path,
) -> anyhow::Error {
    match way_back {
        Ok(report) => match report.record.volume {
            VolumeOutcome::GivenBack => {
                anyhow::anyhow!("{cause:#}; the volume was given back as NTFS")
            }
            VolumeOutcome::NeverProtected => {
                anyhow::anyhow!("{cause:#}; the volume had not been changed and is NTFS as it was")
            }
            VolumeOutcome::StillReadOnly => anyhow::anyhow!(
                "{cause:#}; AND the volume could not be given back: it is still marked read-only. To try again: {}",
                cancel_command(run)
            ),
        },
        Err(why) => anyhow::anyhow!(
            "{cause:#}; AND the volume could not be given back: {why:#}. To try again: {}",
            cancel_command(run)
        ),
    }
}

/// What a way back did.
pub struct WayBackReport {
    pub run: PathBuf,
    /// The partition the run was to convert, as its admission recorded it.
    pub partition: GeneralDiskBinding,
    pub record: CancelledRun,
    /// The record was already complete: nothing was done now.
    pub already_cancelled: bool,
    pub source: Option<PreparedSourceReturn>,
    pub boot: Option<RecoveryBootCancellationReceipt>,
}

fn read_record(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new().read(true).share_mode(1).open(path) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening the run's record {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
        "the run's record {} is not an ordinary file",
        path.display()
    );
    ensure!(
        metadata.len() <= RECORD_LIMIT,
        "the run's record {} is {} bytes, more than any record of a run",
        path.display(),
        metadata.len()
    );
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(metadata.len() as usize)?;
    (&mut file)
        .take(metadata.len() + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading the run's record {}", path.display()))?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "the run's record {} changed while it was read",
        path.display()
    );
    Ok(Some(bytes))
}

#[derive(Deserialize)]
struct Admission {
    kind: String,
    preparation: PartitionAlphaRequest,
    boot_budget: RecoveryBootBudget,
}

/// The folder of a run of this route, recognised by its admission record:
/// the folder given, or the one above it when `prepared` was given.
pub fn recognise_run(given: &Path) -> Result<Option<PathBuf>> {
    let mut candidates = vec![given.to_path_buf()];
    if given
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("prepared"))
    {
        if let Some(parent) = given.parent() {
            candidates.push(parent.to_path_buf());
        }
    }
    for run in candidates {
        let Some(bytes) = read_record(&run.join(ADMISSION_RECORD))? else {
            continue;
        };
        let kind = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("kind")
                    .and_then(|k| k.as_str().map(str::to_owned))
            });
        if kind.as_deref() == Some(ADMISSION_KIND) {
            return Ok(Some(run));
        }
    }
    Ok(None)
}

fn read_admission(run: &Path) -> Result<Admission> {
    let path = run.join(ADMISSION_RECORD);
    let bytes = read_record(&path)?
        .with_context(|| format!("the run folder {} has no admission record", run.display()))?;
    let admission: Admission = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the run's admission record {}", path.display()))?;
    ensure!(
        admission.kind == ADMISSION_KIND && admission.preparation.schema_version == 1,
        "the record {} is not the admission of a restart-route run",
        path.display()
    );
    admission.preparation.expected_source.validate()?;
    admission.preparation.observation_budget.validate()?;
    Ok(admission)
}

#[derive(Deserialize)]
struct BundleFile {
    schema_version: u32,
    kind: String,
    core: BundleCore,
}
#[derive(Deserialize)]
struct BundleCore {
    source: GeneralDiskBinding,
    journal_binding: GeneralJournalStorageBinding,
    journal_path: PathBuf,
    ticket: SelectedTicket,
    publication_path: PathBuf,
    publication_sha256: String,
    #[serde(default)]
    artifacts: Vec<BundleArtifact>,
    source_preparation: serde_json::Value,
    source_payload_write_calls: u64,
    source_apply_intent_attempted: bool,
}

#[derive(Deserialize)]
struct BundleArtifact {
    role: String,
    #[serde(default)]
    snapshot: Option<serde_json::Value>,
}
impl BundleCore {
    /// Where the publication is. The sealed preparation names it twice: by
    /// the path the preparing Windows used, and, among its artifacts, by
    /// its route on the working volume, which is the same in every
    /// environment and is preferred.
    fn publication_route(&self) -> PathBuf {
        self.artifacts
            .iter()
            .find(|artifact| artifact.role == "publication")
            .and_then(|artifact| artifact.snapshot.as_ref())
            .and_then(|snapshot| snapshot.get("final_path"))
            .and_then(|path| path.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.publication_path.clone())
    }
}

/// The run's sealed preparation, if it has one. `pin` is the SHA-256 the
/// boot request carries, where there is one.
fn read_bundle(
    path: &Path,
    pin: Option<&str>,
    source: &GeneralDiskBinding,
) -> Result<Option<BundleCore>> {
    let Some(bytes) = read_record(path)? else {
        return Ok(None);
    };
    if let Some(pin) = pin {
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == pin,
            "the sealed preparation {} is not the one the run's boot request names (its SHA-256 differs)",
            path.display()
        );
    }
    let bundle: BundleFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the sealed preparation {}", path.display()))?;
    ensure!(
        bundle.schema_version == 1 && bundle.kind == BUNDLE_KIND,
        "the record {} is not a sealed preparation of this route",
        path.display()
    );
    ensure!(
        bundle.core.source == *source,
        "the sealed preparation {} names another source partition than the run's admission",
        path.display()
    );
    ensure!(
        bundle.core.source_payload_write_calls == 0 && !bundle.core.source_apply_intent_attempted,
        "the sealed preparation {} does not say that nothing was written to the source",
        path.display()
    );
    Ok(Some(bundle.core))
}

/// What the journal shows, read with the sealed preparation where there is
/// one (the existing classifier and the run's own ticket), and otherwise by
/// the one fact that needs no ticket: whether its lifecycle area was ever
/// written.
fn journal_evidence(
    bundle: Option<&BundleCore>,
    unsealed_journal: &Path,
) -> Result<JournalEvidence> {
    let path = bundle.map_or(unsealed_journal, |core| core.journal_path.as_path());
    let mut journal = match OpenOptions::new().read(true).share_mode(1).open(path) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => {
            return Ok(JournalEvidence::Absent);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening the run's journal {}", path.display()));
        }
    };
    if let Some(core) = bundle {
        ensure!(
            journal.metadata()?.len() == core.ticket.journal_length,
            "the run's journal {} is {} bytes, and its sealed preparation says {}",
            path.display(),
            journal.metadata()?.len(),
            core.ticket.journal_length
        );
        let lifecycle = crate::selected_journal::classify(&mut journal, &core.ticket)
            .with_context(|| {
                format!(
                    "reading the lifecycle of the run's journal {}",
                    path.display()
                )
            })?;
        return Ok(JournalEvidence::Lifecycle(lifecycle));
    }
    // The journal of this route keeps its lifecycle markers in its first
    // two granules and its body behind them (the sealed preparation and the
    // boot handoff prove "prepared and clear" from the same 8192 bytes). A
    // preparation writes the body and nothing there.
    let mut area = Vec::new();
    journal.seek(SeekFrom::Start(0))?;
    (&mut journal)
        .take(LIFECYCLE_AREA_BYTES)
        .read_to_end(&mut area)
        .with_context(|| format!("reading the run's journal {}", path.display()))?;
    Ok(if area.iter().all(|byte| *byte == 0) {
        JournalEvidence::LifecycleAreaClear
    } else {
        JournalEvidence::LifecycleAreaWritten
    })
}

fn read_cancelled(run: &Path) -> Result<Option<CancelledRun>> {
    let path = run.join(CANCELLED_RECORD);
    let Some(bytes) = read_record(&path)? else {
        return Ok(None);
    };
    let record: CancelledRun = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the cancellation record {}", path.display()))?;
    ensure!(
        record.schema_version == 1 && record.kind == CANCELLED_KIND,
        "the record {} is not a cancellation record this version knows",
        path.display()
    );
    Ok(Some(record))
}

/// The cancellation record of a run, if it has one. For the runner and for
/// `--recover`: a run with this record is never applied.
pub fn cancellation_of(run: &Path) -> Result<Option<CancelledRun>> {
    read_cancelled(run)
}

/// Writes the record durably: a new file, synced, then put in place of the
/// old one.
fn write_cancelled(run: &Path, record: &CancelledRun) -> Result<()> {
    let path = run.join(CANCELLED_RECORD);
    let pending = run.join("cancelled.json.new");
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pending)
        .with_context(|| format!("writing the cancellation record {}", pending.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&pending, &path).with_context(|| {
        format!(
            "putting the cancellation record {} in place",
            path.display()
        )
    })?;
    // The folder's entry for it, too.
    if let Ok(directory) = OpenOptions::new()
        .access_mode(0x4000_0000)
        .share_mode(3)
        .custom_flags(0x0200_0000)
        .open(run)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Checks the intent's own record of the source against what the sealed
/// preparation pinned of it.
fn require_pinned_origin(
    origin: &PreparedSourceOrigin,
    core: &BundleCore,
    intent: &Path,
) -> Result<()> {
    let pin = &core.source_preparation;
    let text = |name: &str| {
        pin.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    ensure!(
        text("intent_prefix_sha256") == hex::encode(origin.intent_sha256())
            && pin.get("sequence").and_then(|v| v.as_u64()) == Some(origin.records()),
        "the intent file {} is not the one the sealed preparation pinned: its SHA-256 is {} over {} record(s), and the pin is {} over {}",
        intent.display(),
        hex::encode(origin.intent_sha256()),
        origin.records(),
        text("intent_prefix_sha256"),
        pin.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0)
    );
    ensure!(
        text("ntfs_primary_sha256") == hex::encode(origin.ntfs_primary_sha256())
            && text("original_gpt_sha256") == hex::encode(origin.original_gpt_sha256()?),
        "the intent file {} records another original boot sector or partition table than the sealed preparation pinned",
        intent.display()
    );
    Ok(())
}

/// The volume's label as the sealed preparation published it.
fn published_label(core: &BundleCore) -> Result<VolumeLabel> {
    let path = core.publication_route();
    let bytes = read_record(&path)?.with_context(|| {
        format!(
            "the sealed preparation's publication {} is absent",
            path.display()
        )
    })?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == core.publication_sha256,
        "the publication {} is not the one the sealed preparation names (its SHA-256 differs)",
        path.display()
    );
    let publication: serde_json::Value = serde_json::from_slice(&bytes)?;
    let label: VolumeLabel = serde_json::from_value(publication["expected_source_label"].clone())
        .with_context(|| {
        format!(
            "the publication {} does not record the volume's label",
            path.display()
        )
    })?;
    label.validate()?;
    Ok(label)
}

/// Everything a way back reads of a run before it decides.
struct RunView {
    source: PartitionSourceBinding,
    observation: PartitionObservationBudget,
    evidence_bytes: u64,
    boot_budget: RecoveryBootBudget,
    bundle: Option<BundleCore>,
    state: UnappliedState,
}

fn view_run(run: &Path, bundle_path: &Path, bundle_pin: Option<&str>) -> Result<RunView> {
    let admission = read_admission(run)?;
    let source = admission.preparation.expected_source.clone();
    let bundle = read_bundle(bundle_path, bundle_pin, &source)?;
    let journal = journal_evidence(bundle.as_ref(), &run.join(UNSEALED_JOURNAL))?;
    let state = admit_cancellation(bundle.is_some(), journal).map_err(|refusal| {
        anyhow::anyhow!(
            "the run in {} cannot be cancelled: {refusal}",
            run.display()
        )
    })?;
    Ok(RunView {
        source: PartitionSourceBinding { storage: source },
        observation: admission.preparation.observation_budget,
        evidence_bytes: admission.preparation.maximum_evidence_bytes,
        boot_budget: admission.boot_budget,
        bundle,
        state,
    })
}

/// The SHA-256 of the sealed preparation that the run's boot request
/// carries, and the working volume it names; absent before that request
/// was written.
fn request_pins(run: &Path) -> Result<Option<(String, GeneralJournalStorageBinding)>> {
    let path = run.join(REQUEST_RECORD);
    let Some(bytes) = read_record(&path)? else {
        return Ok(None);
    };
    let request: PreparedOfflineRequest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the run's boot request {}", path.display()))?;
    Ok(Some((request.prepared_bundle_sha256, request.journal)))
}

/// The working volume a run folder lies on, bound as the preparation bound
/// it.
fn working_volume(run: &Path, source: &GeneralDiskBinding) -> Result<GeneralJournalStorageBinding> {
    let held = ordinary_directory(run)?;
    let guid = n2r_win32::file_storage::final_path_guid(
        held.first().context("the run folder could not be held")?,
    )?;
    let end = guid
        .find('}')
        .with_context(|| format!("the run folder {} has no volume route", run.display()))?
        + 1;
    let route = n2r_win32::discovery::discover(
        &format!("{}\\", &guid[..end]),
        n2r_win32::discovery::Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        route.binding.disk_number != source.disk_number
            && n2r_win32::layout::guid_bytes(&route.binding.identity.disk_guid)?
                != n2r_win32::layout::guid_bytes(&source.identity.disk_guid)?,
        "the run folder {} is on the disk of the volume it was to convert",
        run.display()
    );
    let journal = GeneralJournalStorageBinding {
        externally_enrolled_disk_unique_id: format!(
            "partition-alpha-{}",
            route.binding.identity.disk_guid
        ),
        disk: route.binding,
        allow_additional_partitions: true,
    };
    journal.validate()?;
    Ok(journal)
}

/// A folder for what one cancellation does, with its own event record.
fn cancellation_folder(run: &Path, evidence_bytes: u64) -> Result<(PathBuf, Observer)> {
    let folder = run.join(format!("cancel-{}-{}", now_unix_ms(), std::process::id()));
    fs::create_dir(&folder)
        .with_context(|| format!("creating the cancellation folder {}", folder.display()))?;
    let observer = Observer(Arc::new(Mutex::new(Ledger {
        file: OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .share_mode(1)
            .open(folder.join("native-events.jsonl"))?,
        bytes: 0,
        event_encoder: Default::default(),
        maximum: evidence_bytes,
        poisoned: false,
        meter: None,
        stage_maximum: 0,
        minimum_free: 0,
        run: folder.clone(),
    })));
    Ok((folder, observer))
}

fn before_change(observer: &Observer) -> impl FnMut(&[u8], &[u8]) -> io::Result<()> + '_ {
    move |current: &[u8], desired: &[u8]| {
        observer.lock()?.record(&serde_json::json!({
            "kind":"actual-before-cancellation-partition-change",
            "current_partition_info":current,"desired_partition_info":desired,
            "source_payload_write_authority":false}))
    }
}

/// The source part of a way back, in either environment: the intent's
/// records, checked against the sealed preparation where there is one, then
/// the native give-back.
fn give_source_back(
    view: &RunView,
    intent: &Path,
    observer: &Observer,
    events: &mut Vec<NativeEvent>,
    environment: CancelEnvironment,
) -> Result<Option<PreparedSourceReturn>> {
    let mut file = match OpenOptions::new().read(true).share_mode(1).open(intent) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening the run's intent file {}", intent.display()));
        }
    };
    if file.metadata()?.len() == 0 {
        // The preparation writes its first record before it changes the
        // partition: an empty file is a run that never did.
        return Ok(None);
    }
    let origin = PreparedSourceOrigin::read(&mut file, &view.source, view.observation.ram_bytes)
        .with_context(|| format!("reading the run's intent file {}", intent.display()))?;
    let label = match &view.bundle {
        Some(core) => {
            require_pinned_origin(&origin, core, intent)?;
            Some(published_label(core)?)
        }
        None => None,
    };
    let mut restoration = observer.clone();
    let mut record = before_change(observer);
    let returned = match environment {
        CancelEnvironment::Windows => {
            n2r_win32::partition_restoration::give_back_prepared_source_in_windows(
                &origin,
                view.observation,
                label.as_ref(),
                &mut restoration,
                &mut record,
                events,
            )
        }
        CancelEnvironment::RecoveryEnvironment => {
            n2r_win32::offline_environment::give_back_prepared_source_offline(
                &origin,
                view.observation,
                label.as_ref(),
                &mut restoration,
                &mut record,
                events,
            )
        }
    }
    .with_context(|| {
        format!(
            "giving partition {} of disk {} back as NTFS",
            view.source.storage.identity.partition_number, view.source.storage.disk_number
        )
    })?;
    Ok(Some(returned))
}

fn boot_outcome(receipt: &RecoveryBootCancellationReceipt) -> BootOutcome {
    match receipt.found {
        RecoveryBootSelectionState::NotInstalled => BootOutcome::WasNotInstalled,
        RecoveryBootSelectionState::Normal if receipt.restored_elements.is_empty() => {
            BootOutcome::WasNotInstalled
        }
        _ => BootOutcome::Restored,
    }
}

/// In Windows: take a run back whose conversion never started. For a
/// failure of the run itself (`cause`) and for `--recover --rollback`.
///
/// In this order: the run's records decide that it can be taken back; the
/// decision is recorded; the partition gets its recorded GPT attributes
/// back and is verified as the writable NTFS volume it was; the boot
/// selection is put back from the run's records; the record is completed.
/// A step that fails is recorded and ends the way back: nothing after it is
/// changed.
pub fn cancel_unapplied_run_in_windows(run: &Path, cause: Option<&str>) -> Result<WayBackReport> {
    let pins = request_pins(run)?;
    let view = view_run(
        run,
        &run.join(BUNDLE_RECORD),
        pins.as_ref().map(|(sha, _)| sha.as_str()),
    )?;
    if let Some(record) = read_cancelled(run)? {
        if record.completed {
            return Ok(WayBackReport {
                run: run.to_owned(),
                partition: view.source.storage,
                record,
                already_cancelled: true,
                source: None,
                boot: None,
            });
        }
    }
    let journal = working_volume(run, &view.source.storage)?;
    if let Some(core) = &view.bundle {
        ensure!(
            core.journal_binding == journal,
            "the run folder {} is not on the working volume its preparation was sealed on",
            run.display()
        );
    }
    if let Some((_, requested)) = &pins {
        ensure!(
            *requested == journal,
            "the run folder {} is not on the working volume its boot request names",
            run.display()
        );
    }
    let mut record =
        CancelledRun::begin(view.state, CancelEnvironment::Windows, cause, now_unix_ms());
    write_cancelled(run, &record)?;
    let (folder, observer) = cancellation_folder(run, view.evidence_bytes)?;
    let mut events = Vec::new();
    let source = give_source_back(
        &view,
        &run.join(INTENT_RECORD),
        &observer,
        &mut events,
        CancelEnvironment::Windows,
    );
    let _ = observer.checkpoint("way-back-source-closed", &mut events);
    let source = match source {
        Ok(source) => source,
        Err(error) => {
            record.unfinished.push(format!("{error:#}"));
            write_cancelled(run, &record)?;
            return Err(error);
        }
    };
    record.volume = if source.is_some() {
        VolumeOutcome::GivenBack
    } else {
        VolumeOutcome::NeverProtected
    };
    write_cancelled(run, &record)?;
    let boot = n2r_win32::recovery_boot::cancel_recovery_boot_in_windows(
        &run.join("boot").join("selection"),
        &view.source,
        &journal,
        &folder.join("boot"),
        view.boot_budget,
        &mut events,
    )
    .context("putting the boot selection back");
    let _ = observer.checkpoint("way-back-boot-selection-closed", &mut events);
    let boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            record.unfinished.push(format!("{error:#}"));
            write_cancelled(run, &record)?;
            return Err(error);
        }
    };
    record.boot_selection = boot_outcome(&boot);
    record.unfinished.clear();
    record.completed = true;
    write_cancelled(run, &record)?;
    let _ = observer.lock().and_then(|mut ledger| {
        ledger.record(
            &serde_json::json!({"kind":"restart-run-cancelled-in-windows-v1",
            "record":record,"source":source,"boot":boot}),
        )
    });
    Ok(WayBackReport {
        run: run.to_owned(),
        partition: view.source.storage,
        record,
        already_cancelled: false,
        source,
        boot: Some(boot),
    })
}

/// What `--recover` without `--rollback` says of a run of this route. It
/// changes nothing but a folder of its own query records.
pub fn describe_run_in_windows(run: &Path) -> Result<Vec<String>> {
    if let Some(record) = read_cancelled(run)? {
        return Ok(vec![upper_first(&record.refusal(run))]);
    }
    let pins = request_pins(run)?;
    let view = view_run(
        run,
        &run.join(BUNDLE_RECORD),
        pins.as_ref().map(|(sha, _)| sha.as_str()),
    )?;
    let only_cancel = |what: &str| {
        vec![
            format!("{what} It can only be cancelled, and the conversion started again."),
            format!("To cancel it: {}", cancel_command(run)),
        ]
    };
    if view.state == UnappliedState::PreparationUnfinished {
        return Ok(only_cancel(
            "The preparation of this run did not finish, and its conversion cannot start.",
        ));
    }
    let journal = working_volume(run, &view.source.storage)?;
    let folder = run.join(format!("status-{}-{}", now_unix_ms(), std::process::id()));
    fs::create_dir(&folder)?;
    let mut events = Vec::new();
    let state = n2r_win32::recovery_boot::observe_recovery_boot_in_windows(
        &run.join("boot").join("selection"),
        &view.source,
        &journal,
        &folder.join("boot"),
        view.boot_budget,
        &mut events,
    )
    .context("reading the boot selection")?;
    Ok(match state {
        RecoveryBootSelectionState::Installed => vec![
            "This run is prepared and its conversion has not started. It runs when the machine restarts.".to_owned(),
            format!(
                "To cancel before the conversion has started: {}",
                cancel_command(run)
            ),
        ],
        RecoveryBootSelectionState::PartlyInstalled => only_cancel(
            "This run is prepared, and the machine's boot selection is only partly set for it.",
        ),
        RecoveryBootSelectionState::Normal | RecoveryBootSelectionState::NotInstalled => only_cancel(
            "This run is prepared, but the machine's boot selection is not set for it: its conversion will not start.",
        ),
    })
}

fn upper_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// In Windows, after a run failed between protecting its source and
/// restarting: take it back, and say in the error what became of the volume.
/// A laboratory failure that is meant to leave the run armed is left so.
pub fn after_failure_in_windows(run: &Path, cause: anyhow::Error) -> anyhow::Error {
    let left_armed = n2r_win32::lab_fail::failure_text(n2r_win32::lab_fail::RESTART_AFTER_ARM);
    if n2r_win32::lab_fail::is_armed(n2r_win32::lab_fail::RESTART_AFTER_ARM)
        && cause.chain().any(|error| error.to_string() == left_armed)
    {
        return cause.context(format!(
            "the run is left prepared and armed, as this laboratory point asks: its conversion starts at the next restart. To cancel it: {}",
            cancel_command(run)
        ));
    }
    let text = format!("{cause:#}");
    let way_back = cancel_unapplied_run_in_windows(run, Some(&text));
    failure_with_way_back(cause, &way_back, run)
}

/// How the runner ended when it did not fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedOfflineOutcome {
    /// The conversion (or its rollback) is finished; normal boot restored.
    Finished,
    /// The conversion never started and the machine was put back: Windows
    /// starts next. The volume is NTFS; the record says whether writable.
    ReturnedToNtfs,
}

/// In the recovery environment, after the runner failed: if the run's
/// journal shows that the conversion never started, put the machine back.
/// Returns the original error unchanged where that cannot be shown, and
/// with what went wrong where the way back itself failed.
pub(super) fn after_failure_in_recovery_environment(
    request: &PreparedOfflineRequest,
    held_ram_bootstrap: &mut File,
    seen: Option<SelectedLifecycle>,
    cause: anyhow::Error,
) -> Result<PreparedOfflineOutcome> {
    if seen.is_some_and(|lifecycle| lifecycle != SelectedLifecycle::PreparedClear) {
        // The runner read a journal that is past its start: its own
        // resume, rollback and finalization are the way on.
        return Err(cause);
    }
    let text = format!("{cause:#}");
    eprintln!("The conversion could not start: {text}");
    match cold_way_back(request, held_ram_bootstrap, &text) {
        Ok(report) => {
            let run = &report.run;
            for line in cancelled_lines(&report.record, "The volume", run) {
                println!("{line}");
            }
            println!("Windows starts again now.");
            let _ = io::stdout().flush();
            Ok(PreparedOfflineOutcome::ReturnedToNtfs)
        }
        Err(ColdWayBack::NotShown(why)) => Err(cause.context(format!(
            "the machine was not put back, because it could not be shown that the conversion never started: {why:#}"
        ))),
        Err(ColdWayBack::Failed(why)) => Err(cause.context(format!(
            "the conversion never started, AND the machine could not be put back: {why:#}"
        ))),
    }
}

enum ColdWayBack {
    /// It could not be shown that the conversion never started.
    NotShown(anyhow::Error),
    /// It was shown, and putting the machine back failed.
    Failed(anyhow::Error),
}

fn cold_way_back(
    request: &PreparedOfflineRequest,
    held_ram_bootstrap: &mut File,
    cause: &str,
) -> std::result::Result<WayBackReport, ColdWayBack> {
    let mut events = Vec::new();
    // Until the working volume is reached, events are kept on the RAM disk.
    let shown = (|| -> Result<(RunView, PathBuf, Observer, File)> {
        let ram_directory = std::env::current_exe()?
            .parent()
            .context("the runner has no folder")?
            .to_path_buf();
        let ram_observer = Observer(Arc::new(Mutex::new(Ledger {
            file: OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .share_mode(1)
                .open(ram_directory.join(format!("n2r-way-back-{}.jsonl", std::process::id())))?,
            bytes: 0,
            event_encoder: Default::default(),
            maximum: request.maximum_evidence_bytes,
            poisoned: false,
            meter: None,
            stage_maximum: 0,
            minimum_free: 0,
            run: ram_directory,
        })));
        let mut enrolling = ram_observer.clone();
        let volume = n2r_win32::offline_environment::open_journal_volume_for_cancellation(
            &request.journal,
            &request.source.storage,
            held_ram_bootstrap,
            request.observation_budget,
            &mut enrolling,
            &mut events,
        )
        .context("reaching the working disk")?;
        let run = request.output_parent.clone();
        let held = ordinary_directory(&run)
            .with_context(|| format!("the run folder {} was not found", run.display()))?;
        let prefix = format!(
            "{}\\",
            request.journal.disk.volume_path()?.trim_end_matches('\\')
        );
        ensure!(
            n2r_win32::file_storage::final_path_guid(held.first().context("run folder not held")?)?
                .get(..prefix.len())
                .is_some_and(|route| route.eq_ignore_ascii_case(&prefix)),
            "the run folder {} is not on the working volume of the boot request",
            run.display()
        );
        let view = view_run(
            &run,
            &request.prepared_bundle,
            Some(&request.prepared_bundle_sha256),
        )?;
        ensure!(
            view.source == request.source
                && view
                    .bundle
                    .as_ref()
                    .is_some_and(|core| core.journal_binding == request.journal),
            "the run folder {} holds the records of another run than the boot request's",
            run.display()
        );
        let (folder, observer) = cancellation_folder(&run, view.evidence_bytes)?;
        Ok((view, folder, observer, volume))
    })();
    let (view, folder, observer, _volume) = shown.map_err(ColdWayBack::NotShown)?;
    let run = request.output_parent.clone();
    let failed = ColdWayBack::Failed;
    let mut record = match read_cancelled(&run).map_err(failed)? {
        // A cancellation that was begun, here or in Windows, is finished.
        Some(mut record) => {
            record.completed = false;
            record
        }
        None => CancelledRun::begin(
            view.state,
            CancelEnvironment::RecoveryEnvironment,
            Some(cause),
            now_unix_ms(),
        ),
    };
    write_cancelled(&run, &record).map_err(failed)?;
    let intent = view
        .bundle
        .as_ref()
        .and_then(|core| core.source_preparation["intent_file"]["final_path"].as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| run.join(INTENT_RECORD));
    // The volume first. Where it cannot be given back here (its disk or
    // partition is not as recorded), the boot selection is still put back:
    // nothing was written, Windows can start, and the cancellation is
    // finished from there.
    let source = give_source_back(
        &view,
        &intent,
        &observer,
        &mut events,
        CancelEnvironment::RecoveryEnvironment,
    );
    let _ = observer.checkpoint("cold-way-back-source-closed", &mut events);
    let source = match source {
        Ok(source) => {
            record.volume = if source.is_some() {
                VolumeOutcome::GivenBack
            } else {
                VolumeOutcome::NeverProtected
            };
            source
        }
        Err(error) => {
            eprintln!("The volume could not be given back here: {error:#}");
            record.volume = VolumeOutcome::StillReadOnly;
            record.unfinished.push(format!("{error:#}"));
            None
        }
    };
    write_cancelled(&run, &record).map_err(failed)?;
    let mut restoration = observer.clone();
    let boot = n2r_win32::recovery_boot::cancel_recovery_boot_in_recovery_environment(
        &request.boot_intent,
        &request.source,
        &request.journal,
        &folder.join("boot"),
        request.boot_budget,
        request.observation_budget,
        &mut restoration,
        &mut events,
    )
    .context("putting the boot selection back");
    let _ = observer.checkpoint("cold-way-back-boot-selection-closed", &mut events);
    let boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            record.unfinished.push(format!("{error:#}"));
            let _ = write_cancelled(&run, &record);
            return Err(ColdWayBack::Failed(error));
        }
    };
    record.boot_selection = BootOutcome::Restored;
    record.completed = record.volume != VolumeOutcome::StillReadOnly;
    if record.completed {
        record.unfinished.clear();
    }
    write_cancelled(&run, &record).map_err(failed)?;
    let _ = observer.lock().and_then(|mut ledger| {
        ledger.record(
            &serde_json::json!({"kind":"restart-run-cancelled-in-recovery-environment-v1",
            "record":record,"source":source,"boot":boot}),
        )
    });
    Ok(WayBackReport {
        run,
        partition: view.source.storage,
        record,
        already_cancelled: false,
        source,
        boot: Some(boot),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_run_that_wrote_nothing_can_be_cancelled_and_the_others_are_told_the_way_on() {
        use JournalEvidence::*;
        use SelectedLifecycle::*;
        assert_eq!(
            admit_cancellation(true, Lifecycle(PreparedClear)),
            Ok(UnappliedState::PreparedClear)
        );
        for journal in [Absent, LifecycleAreaClear] {
            assert_eq!(
                admit_cancellation(false, journal),
                Ok(UnappliedState::PreparationUnfinished)
            );
        }
        // An apply that had started is never cancelled, whatever came after.
        for (lifecycle, said) in [
            (ApplyIntent, "the conversion had started"),
            (RollbackIntent, "was being rolled back"),
            (Handoff, "nothing to cancel"),
            (Aborted, "was rolled back"),
        ] {
            let refusal = admit_cancellation(true, Lifecycle(lifecycle)).unwrap_err();
            assert!(refusal.contains(said), "{refusal}");
            assert!(refusal.contains("Restart the machine"), "{refusal}");
            // And never without a sealed preparation either.
            assert!(admit_cancellation(false, Lifecycle(lifecycle)).is_err());
        }
        // What cannot be shown is refused, not assumed.
        for (sealed, journal) in [
            (true, Absent),
            (true, LifecycleAreaClear),
            (true, LifecycleAreaWritten),
            (false, LifecycleAreaWritten),
            (false, Lifecycle(PreparedClear)),
        ] {
            let refusal = admit_cancellation(sealed, journal).unwrap_err();
            assert!(refusal.contains("Nothing was changed"), "{refusal}");
        }
    }

    #[test]
    fn the_journal_of_an_unsealed_run_is_clear_only_if_no_lifecycle_byte_was_written() {
        let work = tempfile::tempdir().unwrap();
        let journal = work.path().join("selected.journal");
        assert_eq!(
            journal_evidence(None, &journal).unwrap(),
            JournalEvidence::Absent
        );
        // A body behind the lifecycle area is what a preparation writes.
        let mut bytes = vec![0u8; LIFECYCLE_AREA_BYTES as usize];
        bytes.extend_from_slice(b"journal body");
        fs::write(&journal, &bytes).unwrap();
        assert_eq!(
            journal_evidence(None, &journal).unwrap(),
            JournalEvidence::LifecycleAreaClear
        );
        // A marker in either granule of the area.
        for at in [0usize, 4096, 8191] {
            let mut marked = bytes.clone();
            marked[at] = b'N';
            fs::write(&journal, &marked).unwrap();
            assert_eq!(
                journal_evidence(None, &journal).unwrap(),
                JournalEvidence::LifecycleAreaWritten,
                "byte {at}"
            );
        }
    }

    #[test]
    fn the_record_of_a_cancellation_is_kept_and_forbids_the_run_in_plain_words() {
        let work = tempfile::tempdir().unwrap();
        let run = work.path().join("partition-offline-conversion-0123");
        fs::create_dir(&run).unwrap();
        assert_eq!(read_cancelled(&run).unwrap(), None);
        // 2026-11-18 14:03:22 UTC.
        let now = 1_795_010_602_000;
        let mut record = CancelledRun::begin(
            UnappliedState::PreparedClear,
            CancelEnvironment::Windows,
            Some("the recovery image could not be built"),
            now,
        );
        assert_eq!(record.cancelled_utc, "2026-11-18 14:03:22 UTC");
        write_cancelled(&run, &record).unwrap();
        assert_eq!(read_cancelled(&run).unwrap().as_ref(), Some(&record));
        // Begun and not finished: a later start is sent to finish it.
        let unfinished = record.refusal(&run);
        assert!(
            unfinished.contains("cancelled on 2026-11-18 14:03:22 UTC")
                && unfinished.contains("not complete")
                && unfinished.ends_with(&format!(
                    "ntfs2refs --recover \"{}\" --rollback",
                    run.display()
                )),
            "{unfinished}"
        );
        record.volume = VolumeOutcome::GivenBack;
        record.boot_selection = BootOutcome::Restored;
        record.completed = true;
        write_cancelled(&run, &record).unwrap();
        let read = cancellation_of(&run).unwrap().unwrap();
        assert_eq!(read, record);
        assert_eq!(
            read.refusal(&run),
            "this run was cancelled on 2026-11-18 14:03:22 UTC; the volume is NTFS as it was. A conversion is started again with a new run."
        );
        assert!(!run.join("cancelled.json.new").exists());
        // A record of another kind is not taken for one.
        fs::write(run.join(CANCELLED_RECORD), b"{\"schema_version\":1}").unwrap();
        assert!(read_cancelled(&run).is_err());
    }

    #[test]
    fn dates_are_written_as_utc() {
        assert_eq!(utc_text(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc_text(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc_text(1_709_251_199_000), "2024-02-29 23:59:59 UTC");
        assert_eq!(utc_text(1_735_689_600_000), "2025-01-01 00:00:00 UTC");
    }

    fn record(volume: VolumeOutcome, boot: BootOutcome) -> CancelledRun {
        let mut record = CancelledRun::begin(
            UnappliedState::PreparedClear,
            CancelEnvironment::Windows,
            None,
            0,
        );
        record.volume = volume;
        record.boot_selection = boot;
        record.completed = volume != VolumeOutcome::StillReadOnly && boot != BootOutcome::Unsettled;
        record
    }

    #[test]
    fn a_cancellation_says_what_happened_and_what_is_left() {
        let run = Path::new("E:\\work\\partition-offline-conversion-0123");
        let command =
            "ntfs2refs --recover \"E:\\work\\partition-offline-conversion-0123\" --rollback";
        assert_eq!(cancel_command(run), command);
        assert_eq!(
            cancelled_lines(
                &record(VolumeOutcome::GivenBack, BootOutcome::Restored),
                "D:",
                run
            ),
            [
                "The conversion was cancelled before anything was written to the volume. D: is NTFS as it was.",
                "The machine starts Windows as before: the boot selection was put back.",
            ]
        );
        assert_eq!(
            cancelled_lines(
                &record(VolumeOutcome::NeverProtected, BootOutcome::WasNotInstalled),
                "D:",
                run
            ),
            [
                "The conversion was cancelled before the volume was changed in any way. D: is NTFS as it was."
            ]
        );
        let unfinished = cancelled_lines(
            &record(VolumeOutcome::StillReadOnly, BootOutcome::Restored),
            "The volume",
            run,
        );
        assert!(
            unfinished[0].contains("The volume is still marked read-only")
                && unfinished[0].ends_with(command),
            "{unfinished:?}"
        );
        assert_eq!(
            working_files_line(run, 3 << 30),
            "The run's working files are still in E:\\work\\partition-offline-conversion-0123 (3.0 GiB); delete the folder when you no longer need its records."
        );
        let said = before_restart_lines(run);
        assert_eq!(
            said[1],
            format!("To cancel before the conversion has started: {command}")
        );
        assert!(said[2].starts_with("To recover: "), "{said:?}");
    }

    #[test]
    fn a_failed_run_reports_its_cause_and_what_became_of_the_volume() {
        let run = Path::new("E:\\work\\partition-offline-conversion-0123");
        let cause =
            || anyhow::anyhow!("DISM ended with code 5").context("building the recovery image");
        let report = |volume| {
            Ok(WayBackReport {
                run: run.to_owned(),
                partition: serde_json::from_value(serde_json::json!({
                    "disk_number":0,"volume_guid":"11111111-2222-3333-4444-555555555555",
                    "identity":{"disk_guid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "partition_guid":"01234567-89ab-cdef-0123-456789abcdef",
                        "partition_number":4,"disk_bytes":136365211648u64,
                        "partition_offset":1048576u64,"partition_bytes":6442450944u64,
                        "logical_sector_bytes":512,"physical_sector_bytes":4096}}))
                .unwrap(),
                record: record(volume, BootOutcome::WasNotInstalled),
                already_cancelled: false,
                source: None,
                boot: None,
            })
        };
        assert_eq!(
            failure_with_way_back(cause(), &report(VolumeOutcome::GivenBack), run).to_string(),
            "building the recovery image: DISM ended with code 5; the volume was given back as NTFS"
        );
        assert_eq!(
            failure_with_way_back(cause(), &report(VolumeOutcome::NeverProtected), run).to_string(),
            "building the recovery image: DISM ended with code 5; the volume had not been changed and is NTFS as it was"
        );
        let failed = failure_with_way_back(
            cause(),
            &Err(anyhow::anyhow!(
                "the first sector of partition 4 of disk 0 differs"
            )),
            run,
        )
        .to_string();
        assert_eq!(
            failed,
            "building the recovery image: DISM ended with code 5; AND the volume could not be given back: the first sector of partition 4 of disk 0 differs. To try again: ntfs2refs --recover \"E:\\work\\partition-offline-conversion-0123\" --rollback"
        );
    }

    #[test]
    fn a_run_folder_is_recognised_by_its_admission_record_not_by_its_name() {
        let work = tempfile::tempdir().unwrap();
        let run = work.path().join("anything");
        fs::create_dir_all(run.join("prepared")).unwrap();
        assert_eq!(recognise_run(&run).unwrap(), None);
        fs::write(run.join(ADMISSION_RECORD), b"{\"kind\":\"something else\"}").unwrap();
        assert_eq!(recognise_run(&run).unwrap(), None);
        fs::write(
            run.join(ADMISSION_RECORD),
            format!("{{\"kind\":\"{ADMISSION_KIND}\"}}"),
        )
        .unwrap();
        assert_eq!(recognise_run(&run).unwrap(), Some(run.clone()));
        // Its `prepared` folder names the same run.
        assert_eq!(
            recognise_run(&run.join("prepared")).unwrap(),
            Some(run.clone())
        );
        assert_eq!(recognise_run(&run.join("boot")).unwrap(), None);
    }

    fn disk(number: u32, disk: &str, partition: &str, volume: &str) -> GeneralDiskBinding {
        serde_json::from_value(serde_json::json!({
            "disk_number":number,"volume_guid":volume,
            "identity":{"disk_guid":disk,"partition_guid":partition,
                "partition_number":4,"disk_bytes":136365211648u64,
                "partition_offset":1048576u64,"partition_bytes":6442450944u64,
                "logical_sector_bytes":512,"physical_sector_bytes":4096}}))
        .unwrap()
    }
    fn source() -> GeneralDiskBinding {
        disk(
            0,
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "01234567-89ab-cdef-0123-456789abcdef",
            "11111111-2222-3333-4444-555555555555",
        )
    }
    fn bundle(work: &Path, source: &GeneralDiskBinding, journal_bytes: u64) -> Vec<u8> {
        let working = disk(
            1,
            "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
            "11234567-89ab-cdef-0123-456789abcdef",
            "21111111-2222-3333-4444-555555555555",
        );
        serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"kind":BUNDLE_KIND,
            "core":{
                "source":source,
                "journal_binding":{"externally_enrolled_disk_unique_id":"partition-alpha-x",
                    "disk":working,"allow_additional_partitions":true},
                "journal_path":work.join("selected.journal"),
                "ticket":{"image_length":6442450944u64,"selected_bytes":4096,"range_count":1,
                    "journal_length":journal_bytes,"immutable_sha256":vec![1u8;32],
                    "old_selected_sha256":vec![2u8;32],"new_selected_sha256":vec![3u8;32],
                    "whole_image_verified":true},
                "publication_path":"E:\\run\\prepared\\arena\\publication.json",
                "publication_sha256":"00",
                "artifacts":[
                    {"role":"journal","path":"E:\\x","bytes":1,"sha256":"00","snapshot":null},
                    {"role":"publication","path":"E:\\run\\prepared\\arena\\publication.json",
                     "bytes":1,"sha256":"00",
                     "snapshot":{"final_path":"\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\run\\prepared\\arena\\publication.json"}}],
                "source_preparation":{"sequence":2},
                "source_payload_write_calls":0,"source_apply_intent_attempted":false,
                "something_a_later_version_adds":true
            }}))
        .unwrap()
    }

    #[test]
    fn a_sealed_preparation_is_read_only_as_the_pinned_one_of_this_source() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("bundle.json");
        assert!(read_bundle(&path, None, &source()).unwrap().is_none());
        let bytes = bundle(work.path(), &source(), 16384);
        fs::write(&path, &bytes).unwrap();
        let pin = hex::encode(Sha256::digest(&bytes));
        let core = read_bundle(&path, Some(&pin), &source()).unwrap().unwrap();
        assert_eq!(core.ticket.journal_length, 16384);
        // Its publication is found by its route on the working volume,
        // which does not depend on drive letters.
        assert_eq!(
            core.publication_route(),
            Path::new(
                "\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\run\\prepared\\arena\\publication.json"
            )
        );
        // Another bundle than the boot request names, another source, a
        // bundle that says something was written: each is refused.
        let refused = |pin: Option<&str>, source: &GeneralDiskBinding| {
            format!(
                "{:#}",
                read_bundle(&path, pin, source).err().expect("refused")
            )
        };
        assert!(refused(Some(&"0".repeat(64)), &source()).contains("SHA-256 differs"));
        let mut other = source();
        other.identity.partition_number = 5;
        assert!(refused(None, &other).contains("another source partition"));
        let mut written: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        written["core"]["source_apply_intent_attempted"] = true.into();
        fs::write(&path, serde_json::to_vec(&written).unwrap()).unwrap();
        assert!(refused(None, &source()).contains("nothing was written"));
        written["kind"] = "another".into();
        fs::write(&path, serde_json::to_vec(&written).unwrap()).unwrap();
        assert!(refused(None, &source()).contains("not a sealed preparation"));
    }

    #[test]
    fn the_journal_of_a_sealed_run_is_classified_with_its_ticket_by_the_existing_reader() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("bundle.json");
        fs::write(&path, bundle(work.path(), &source(), 16384)).unwrap();
        let core = read_bundle(&path, None, &source()).unwrap().unwrap();
        let unsealed = work.path().join("unused.journal");
        // No journal where the sealed preparation says it is.
        assert_eq!(
            journal_evidence(Some(&core), &unsealed).unwrap(),
            JournalEvidence::Absent
        );
        assert!(admit_cancellation(true, JournalEvidence::Absent).is_err());
        // Prepared and clear: both marker granules are zero.
        let mut journal = vec![0u8; 16384];
        journal[8192..8200].copy_from_slice(b"bodybody");
        fs::write(&core.journal_path, &journal).unwrap();
        let clear = journal_evidence(Some(&core), &unsealed).unwrap();
        assert_eq!(
            clear,
            JournalEvidence::Lifecycle(SelectedLifecycle::PreparedClear)
        );
        assert_eq!(
            admit_cancellation(true, clear),
            Ok(UnappliedState::PreparedClear)
        );
        // A marker that is not this ticket's, or a torn one, is not read as
        // clear: the run is refused, not cancelled.
        for at in [0usize, 4096] {
            let mut marked = journal.clone();
            marked[at..at + 8].copy_from_slice(b"N2RSAP01");
            fs::write(&core.journal_path, &marked).unwrap();
            let refusal = format!(
                "{:#}",
                journal_evidence(Some(&core), &unsealed).unwrap_err()
            );
            assert!(
                refusal.contains("foreign or torn") && refusal.contains("selected.journal"),
                "{refusal}"
            );
        }
        // Another length than the sealed one is not this run's journal.
        fs::write(&core.journal_path, &journal[..12288]).unwrap();
        let refusal = journal_evidence(Some(&core), &unsealed)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("12288 bytes"), "{refusal}");
    }
}
