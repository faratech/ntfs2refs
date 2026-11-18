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
/// How the record of a cancellation that the recovery environment could
/// not finish begins its note of the command that finishes it.
const FINISH_IN_WINDOWS: &str = "to finish the cancellation, run in Windows as administrator: ";
/// Held, unshared, by the one way back that is running for a run.
const LOCK_RECORD: &str = "cancellation-in-progress.lock";
/// The first record of a boot installation, written before the boot
/// configuration is touched.
const BOOT_FIRST_RECORD: &str = "boot/selection/recovery-boot-original-intent.json";

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
    /// No longer marked read-only, but not verified as the NTFS volume it
    /// was: the give-back failed after it changed the partition's entry.
    NotVerified,
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
    /// What the cancellation rests on beyond the ordinary, and what it
    /// could not check or keep while it went on: nothing of that is left
    /// unsaid.
    #[serde(default)]
    pub notes: Vec<String>,
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
            notes: Vec::new(),
            completed: false,
        }
    }
    /// A cancellation that was begun and not finished is taken up again
    /// under its own record: when it was decided, from which state and why
    /// stay as they were written.
    fn taken_up_again(mut self) -> Self {
        self.unfinished.clear();
        self.notes
            .retain(|note| !note.starts_with(FINISH_IN_WINDOWS));
        self.completed = false;
        self
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
            "The conversion was cancelled before anything was written to the volume, but {} is still marked read-only: nothing can be written to it. To finish the cancellation: {}",
            volume
                .strip_prefix("The ")
                .map_or(volume.to_owned(), |rest| format!("the {rest}")),
            cancel_command(run)
        ),
        VolumeOutcome::NotVerified => format!(
            "The conversion was cancelled before anything was written to the volume. {volume} is no longer marked read-only, but it could not be verified as the NTFS volume it was. To check it and finish the cancellation: {}",
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
    lines.extend(record.notes.iter().map(|note| format!("Note: {note}")));
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
///
/// `left` is the record a way back that failed left in the run folder: it
/// says how far it got, so that a volume that was given back is not
/// reported as lost because a later step failed.
pub fn failure_with_way_back(
    cause: anyhow::Error,
    way_back: &Result<WayBackReport>,
    left: Option<&CancelledRun>,
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
            VolumeOutcome::NotVerified => anyhow::anyhow!(
                "{cause:#}; AND the volume is no longer marked read-only but could not be verified as the NTFS volume it was. To check it: {}",
                cancel_command(run)
            ),
        },
        Err(why) => match left.map(|record| record.volume) {
            Some(VolumeOutcome::GivenBack | VolumeOutcome::NeverProtected) => anyhow::anyhow!(
                "{cause:#}; the volume is NTFS as it was, AND the cancellation could not be finished: {why:#}. To try again: {}",
                cancel_command(run)
            ),
            Some(VolumeOutcome::NotVerified) => anyhow::anyhow!(
                "{cause:#}; AND the volume is no longer marked read-only but could not be verified as the NTFS volume it was: {why:#}. To check it: {}",
                cancel_command(run)
            ),
            _ => anyhow::anyhow!(
                "{cause:#}; AND the volume could not be given back: {why:#}. To try again: {}",
                cancel_command(run)
            ),
        },
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

/// How large a record of a run may be where nothing of the run has been
/// read yet to say it: a sixty-fourth of the memory that is free. (The
/// runner bounds the request it is started with the same way.) Records
/// read after the admission are bounded by what the admission reserved.
fn machine_record_limit(folder: &Path) -> Result<u64> {
    Ok(
        n2r_win32::resource_native::observe_available_resources(folder)?.available_physical_bytes
            / 64,
    )
}

fn read_record(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
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
        metadata.len() <= limit,
        "the run's record {} is {} bytes, more than the {limit} bytes this run may hold of a record",
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
    let named_prepared = given
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("prepared"));
    candidates.extend(
        given
            .parent()
            .filter(|_| named_prepared)
            .map(Path::to_path_buf),
    );
    for run in candidates {
        // A folder that is not there holds no record.
        let Ok(limit) = machine_record_limit(&run) else {
            continue;
        };
        let Some(bytes) = read_record(&run.join(ADMISSION_RECORD), limit)? else {
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
    let bytes = read_record(&path, machine_record_limit(run)?)?
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

/// What is at the place of the run's sealed preparation.
enum BundleRead {
    /// No file.
    Absent,
    Sealed(Box<BundleCore>),
    /// A file that is not a whole record: what its decoding said.
    Undecodable(String),
}

/// Reads the run's sealed preparation. `pin` is the SHA-256 the boot
/// request carries, where there is one. A file that is there and is another
/// run's, another source's or says that something was written is an error;
/// one that cannot be decoded at all is reported as such, for the caller to
/// decide with what else the run left.
fn read_bundle(
    path: &Path,
    pin: Option<&str>,
    source: &GeneralDiskBinding,
    limit: u64,
) -> Result<BundleRead> {
    let Some(bytes) = read_record(path, limit)? else {
        return Ok(BundleRead::Absent);
    };
    if let Some(pin) = pin {
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == pin,
            "the sealed preparation {} is not the one the run's boot request names (its SHA-256 differs)",
            path.display()
        );
    }
    let bundle: BundleFile = match serde_json::from_slice(&bytes) {
        Ok(bundle) => bundle,
        Err(error) => return Ok(BundleRead::Undecodable(error.to_string())),
    };
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
    Ok(BundleRead::Sealed(Box::new(bundle.core)))
}

/// The record that shows a run got past its preparation, if it has one: its
/// boot request (written from the sealed preparation) or the first record of
/// its boot installation. Either exists only after the bundle was sealed.
fn past_preparation(run: &Path) -> Result<Option<PathBuf>> {
    for record in [REQUEST_RECORD, BOOT_FIRST_RECORD] {
        let path = run.join(record);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(Some(path)),
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("looking for the run's record {}", path.display()));
            }
        }
    }
    Ok(None)
}

/// Decides what the place of the sealed preparation means. A missing file
/// is never proof by itself: a run that got past its preparation must have
/// its bundle, and without it nothing shows that the conversion never
/// started. Only a run that left neither a boot request nor a boot record
/// is taken as one whose preparation did not finish, and then an
/// undecodable bundle (power lost while it was written) is that too, and
/// said so in the note returned.
fn admit_bundle(
    read: BundleRead,
    bundle: &Path,
    past_preparation: Option<&Path>,
) -> Result<(Option<BundleCore>, Option<String>)> {
    match (read, past_preparation) {
        (BundleRead::Sealed(core), _) => Ok((Some(*core), None)),
        (BundleRead::Absent, None) => Ok((None, None)),
        (BundleRead::Absent, Some(later)) => anyhow::bail!(
            "the run's sealed preparation {} is missing, although {} shows that the run sealed one: without it, it cannot be shown that the conversion never started. Nothing was changed.",
            bundle.display(),
            later.display()
        ),
        (BundleRead::Undecodable(why), Some(later)) => anyhow::bail!(
            "the run's sealed preparation {} cannot be decoded ({why}), although {} shows that the run sealed one: without it, it cannot be shown that the conversion never started. Nothing was changed.",
            bundle.display(),
            later.display()
        ),
        (BundleRead::Undecodable(why), None) => Ok((
            None,
            Some(format!(
                "the sealed preparation {} cannot be decoded ({why}), as after a power loss while it was written; the run left neither a boot request nor a boot record, so it never got further, and it was taken back as a preparation that did not finish",
                bundle.display()
            )),
        )),
    }
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
    let Some(bytes) = read_record(&path, machine_record_limit(run)?)? else {
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

/// The cancellation record of a run, if it has one.
pub fn cancellation_of(run: &Path) -> Result<Option<CancelledRun>> {
    read_cancelled(run)
}

/// Why a run must not be applied, resumed or finalized, if it must not: it
/// has a cancellation record. A record that is there and cannot be read is
/// a cancellation too: it is written only once a cancellation was decided,
/// and what it would have said can only be less than "never apply".
pub fn apply_forbidden(run: &Path) -> Option<String> {
    match read_cancelled(run) {
        Ok(None) => None,
        Ok(Some(record)) => Some(record.refusal(run)),
        Err(error) => Some(format!(
            "this run has a cancellation record that cannot be read ({error:#}); a run whose cancellation was begun is never applied. To finish the cancellation: {}",
            cancel_command(run)
        )),
    }
}

/// The record a cancellation was begun under, if one can be read. One that
/// cannot is noted and begun anew: the way back goes on from the journal.
fn begun_record(run: &Path, notes: &mut Vec<String>) -> Option<CancelledRun> {
    match read_cancelled(run) {
        Ok(record) => record,
        Err(error) => {
            notes.push(format!(
                "an earlier cancellation record could not be read and was replaced: {error:#}"
            ));
            None
        }
    }
}

/// Held for the whole of a way back: one cancellation of a run at a time.
/// The lock is a file in the run folder that its holder keeps open without
/// sharing. A file left by a process that died can be opened, and is then
/// taken over; one that cannot be opened is somebody's running way back.
struct RunLock {
    file: Option<File>,
    path: PathBuf,
}
impl RunLock {
    fn take(run: &Path) -> Result<Self> {
        let path = run.join(LOCK_RECORD);
        for _ in 0..2 {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{} {}", std::process::id(), utc_text(now_unix_ms()));
                    return Ok(Self {
                        file: Some(file),
                        path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .share_mode(0)
                        .open(&path)
                    {
                        // Nobody holds it: its holder is gone.
                        Ok(stale) => {
                            drop(stale);
                            fs::remove_file(&path).with_context(|| {
                                format!("removing the stale lock {}", path.display())
                            })?;
                        }
                        Err(held) if held.raw_os_error() == Some(32) => anyhow::bail!(
                            "a cancellation of this run is in progress (its lock {} is held): wait for it to end, then run the command again if the volume is not NTFS as it was. Nothing was changed.",
                            path.display()
                        ),
                        Err(other) if matches!(other.raw_os_error(), Some(2 | 3)) => {}
                        Err(other) => {
                            return Err(other).with_context(|| {
                                format!("opening the cancellation lock {}", path.display())
                            });
                        }
                    }
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("creating the cancellation lock {}", path.display())
                    });
                }
            }
        }
        anyhow::bail!(
            "the cancellation lock {} could not be taken: it keeps reappearing. Nothing was changed.",
            path.display()
        )
    }
}
impl Drop for RunLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

static PENDING_RECORD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Writes the record durably: a new file of its own name, synced, then put
/// in place of the old one, and the folder's entry flushed. Every step's
/// failure is an error: a record that may not be on the disk is not
/// reported as written.
fn write_cancelled(run: &Path, record: &CancelledRun) -> Result<()> {
    let path = run.join(CANCELLED_RECORD);
    let pending = run.join(format!(
        "cancelled.json.{}-{}-{}.new",
        std::process::id(),
        now_unix_ms(),
        PENDING_RECORD.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    let written = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&pending)
            .with_context(|| format!("creating {}", pending.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("writing {}", pending.display()))?;
        drop(file);
        fs::rename(&pending, &path).with_context(|| {
            format!(
                "putting {} in place of {}",
                pending.display(),
                path.display()
            )
        })?;
        let directory = OpenOptions::new()
            .access_mode(0x4000_0000)
            .share_mode(3)
            .custom_flags(0x0200_0000)
            .open(run)
            .with_context(|| format!("opening the folder {} to flush it", run.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("flushing the folder {}", run.display()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&pending);
    }
    written.with_context(|| format!("writing the cancellation record {}", path.display()))
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
fn published_label(core: &BundleCore, limit: u64) -> Result<VolumeLabel> {
    let path = core.publication_route();
    let bytes = read_record(&path, limit)?.with_context(|| {
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
    let publication: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the publication {}", path.display()))?;
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
    /// What the decision rests on beyond the ordinary, for the record.
    notes: Vec<String>,
}

/// `later` is the record that shows the run got past its preparation, if it
/// left one: with it, the sealed preparation is required.
fn view_run(
    run: &Path,
    bundle_path: &Path,
    bundle_pin: Option<&str>,
    later: Option<&Path>,
) -> Result<RunView> {
    let admission = read_admission(run)?;
    let source = admission.preparation.expected_source.clone();
    let evidence_bytes = admission.preparation.maximum_evidence_bytes;
    let read = read_bundle(bundle_path, bundle_pin, &source, evidence_bytes)?;
    let (bundle, note) = admit_bundle(read, bundle_path, later)?;
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
        evidence_bytes,
        boot_budget: admission.boot_budget,
        bundle,
        state,
        notes: note.into_iter().collect(),
    })
}

/// What the run's boot request pins: the SHA-256 of the sealed preparation,
/// the working volume, and the folder the run was made in.
struct RequestPins {
    bundle_sha256: String,
    journal: GeneralJournalStorageBinding,
    output_parent: PathBuf,
}

/// Absent before the request was written. Read before the admission, so
/// bounded by the machine.
fn request_pins(run: &Path) -> Result<Option<RequestPins>> {
    let path = run.join(REQUEST_RECORD);
    let Some(bytes) = read_record(&path, machine_record_limit(run)?)? else {
        return Ok(None);
    };
    let request: PreparedOfflineRequest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding the run's boot request {}", path.display()))?;
    Ok(Some(RequestPins {
        bundle_sha256: request.prepared_bundle_sha256,
        journal: request.journal,
        output_parent: request.output_parent,
    }))
}

/// Whether the folder at this volume route is the one a request records. A
/// copy of a run's folder holds the same records and is not the run.
fn same_folder(actual_route: &str, recorded: &Path) -> bool {
    let recorded = recorded.to_string_lossy();
    actual_route
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(recorded.trim_end_matches('\\'))
}

/// The working volume a run folder lies on, bound as the preparation bound
/// it, and the folder's own route on it.
fn working_volume(
    run: &Path,
    source: &GeneralDiskBinding,
) -> Result<(GeneralJournalStorageBinding, String)> {
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
    Ok((journal, guid))
}

/// In Windows: the run's folder is on the working volume its records name,
/// and is the folder the run was made in.
fn bind_run_folder(
    run: &Path,
    view: &RunView,
    pins: Option<&RequestPins>,
) -> Result<GeneralJournalStorageBinding> {
    let (journal, route) = working_volume(run, &view.source.storage)?;
    if let Some(core) = &view.bundle {
        ensure!(
            core.journal_binding == journal,
            "the run folder {} is not on the working volume its preparation was sealed on. Nothing was changed.",
            run.display()
        );
    }
    if let Some(pins) = pins {
        ensure!(
            pins.journal == journal,
            "the run folder {} is not on the working volume its boot request names. Nothing was changed.",
            run.display()
        );
        ensure!(
            same_folder(&route, &pins.output_parent),
            "the folder {} is not the folder this run was made in ({}): a copy of a run's folder is not the run. Nothing was changed.",
            run.display(),
            pins.output_parent.display()
        );
    }
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

/// What is at the place of the run's intent file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntentPresence {
    Missing,
    Empty,
    Records,
}

/// Whether the intent file is to be read. A sealed run made its source
/// read-only and recorded it: its intent file is required, and so it is in
/// the recovery environment, which only a sealed run reaches. Only an
/// unsealed run in Windows may be without one, and then the partition
/// itself is asked (`require_not_read_only`).
fn intent_is_read(
    sealed: bool,
    environment: CancelEnvironment,
    presence: IntentPresence,
    intent: &Path,
) -> std::result::Result<bool, String> {
    match presence {
        IntentPresence::Records => Ok(true),
        IntentPresence::Missing | IntentPresence::Empty
            if sealed || environment == CancelEnvironment::RecoveryEnvironment =>
        {
            Err(format!(
                "the run's intent file {} is {}, although its preparation was sealed after the partition was made read-only: the record of the partition's original state is gone, and the volume cannot be given back from this folder",
                intent.display(),
                if presence == IntentPresence::Missing {
                    "missing"
                } else {
                    "empty"
                }
            ))
        }
        IntentPresence::Missing | IntentPresence::Empty => Ok(false),
    }
}

/// A run without a record of having protected its partition is believed
/// only together with the partition: it is not marked read-only.
fn require_not_read_only(
    attributes: u64,
    partition: &GeneralDiskBinding,
    intent: &Path,
) -> std::result::Result<(), String> {
    if attributes & n2r_win32::partition_restoration::GPT_ATTRIBUTE_READ_ONLY == 0 {
        return Ok(());
    }
    Err(format!(
        "partition {} of disk {} is marked read-only (its GPT attributes are {attributes:#x}), but the run's record of that ({}) is missing or empty: the folder does not say what the partition was before, so nothing was changed on it",
        partition.identity.partition_number,
        partition.disk_number,
        intent.display()
    ))
}

/// The source part of a way back, in either environment: the intent's
/// records, checked against the sealed preparation where there is one, then
/// the native give-back. `None` is a run that never protected its
/// partition, which the partition itself confirmed.
fn give_source_back(
    view: &RunView,
    intent: &Path,
    observer: &Observer,
    events: &mut Vec<NativeEvent>,
    environment: CancelEnvironment,
) -> Result<Option<PreparedSourceReturn>> {
    let opened = match OpenOptions::new().read(true).share_mode(1).open(intent) {
        Ok(file) => Some(file),
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening the run's intent file {}", intent.display()));
        }
    };
    let presence = match &opened {
        None => IntentPresence::Missing,
        Some(file) if file.metadata()?.len() == 0 => IntentPresence::Empty,
        Some(_) => IntentPresence::Records,
    };
    let read = intent_is_read(view.bundle.is_some(), environment, presence, intent)
        .map_err(anyhow::Error::msg)?;
    let Some(mut file) = opened.filter(|_| read) else {
        // The preparation writes its first record before it changes the
        // partition. That the record is not there is not taken for it: the
        // partition's entry is read, and must not be read-only.
        let attributes = n2r_win32::partition_restoration::observe_partition_attributes(
            &view.source,
            view.observation,
            events,
        )?;
        require_not_read_only(attributes, &view.source.storage, intent)
            .map_err(anyhow::Error::msg)?;
        return Ok(None);
    };
    let origin = PreparedSourceOrigin::read(&mut file, &view.source, view.observation.ram_bytes)
        .with_context(|| format!("reading the run's intent file {}", intent.display()))?;
    let label = match &view.bundle {
        Some(core) => {
            require_pinned_origin(&origin, core, intent)?;
            // The publication is bounded as the runner bounds the bundle it
            // belongs to: an eighth of the observation memory.
            Some(published_label(core, view.observation.ram_bytes / 8)?)
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

/// What is true of the volume after its give-back failed: the partition's
/// entry is read again. A give-back can fail after it changed the entry
/// (the volume was not published in time, a check of it failed), and the
/// record must not say "still read-only" of a partition that no longer is.
fn volume_after_failure(
    view: &RunView,
    events: &mut Vec<NativeEvent>,
) -> (VolumeOutcome, Option<String>) {
    match n2r_win32::partition_restoration::observe_partition_attributes(
        &view.source,
        view.observation,
        events,
    ) {
        Ok(attributes) => (volume_from_attributes(attributes), None),
        Err(error) => (
            VolumeOutcome::StillReadOnly,
            Some(format!(
                "whether partition {} of disk {} is still marked read-only could not be read after its give-back failed: {error}",
                view.source.storage.identity.partition_number, view.source.storage.disk_number
            )),
        ),
    }
}
fn volume_from_attributes(attributes: u64) -> VolumeOutcome {
    if attributes & n2r_win32::partition_restoration::GPT_ATTRIBUTE_READ_ONLY == 0 {
        VolumeOutcome::NotVerified
    } else {
        VolumeOutcome::StillReadOnly
    }
}

/// A cancellation that is finished in a second pass keeps what the first
/// did: a boot selection the recovery environment put back is found normal
/// by Windows afterwards, and is still one that was restored.
fn merge_boot_outcome(before: BootOutcome, now: BootOutcome) -> BootOutcome {
    match (before, now) {
        (BootOutcome::Restored, BootOutcome::WasNotInstalled) => BootOutcome::Restored,
        _ => now,
    }
}

/// What `--recover` says of a run that has a cancellation record. One that
/// is not complete says plainly what state the volume is in and the command
/// that finishes it: after the recovery environment could only put the
/// boot selection back, this is where its user learns that the volume is
/// still read-only.
pub fn cancelled_status_lines(record: &CancelledRun, run: &Path) -> Vec<String> {
    if record.completed {
        return vec![upper_first(&record.refusal(run))];
    }
    let mut lines = vec![format!(
        "This run was cancelled on {} ({}), and its cancellation is not complete.",
        record.cancelled_utc,
        match record.environment {
            CancelEnvironment::Windows => "in Windows",
            CancelEnvironment::RecoveryEnvironment =>
                "in the recovery environment, before its conversion started",
        }
    )];
    match record.volume {
        VolumeOutcome::StillReadOnly => lines.push(format!(
            "The volume is still marked read-only: Windows shows it and its files, and nothing can be written to it. To make it the writable NTFS volume it was: {}",
            cancel_command(run)
        )),
        VolumeOutcome::NotVerified => lines.push(format!(
            "The volume is no longer marked read-only, but it was not verified as the NTFS volume it was. To check it and finish: {}",
            cancel_command(run)
        )),
        VolumeOutcome::GivenBack | VolumeOutcome::NeverProtected => lines.push(format!(
            "The volume is NTFS as it was. To finish the cancellation: {}",
            cancel_command(run)
        )),
    }
    if record.boot_selection == BootOutcome::Unsettled {
        lines.push(
            "The machine's boot selection was not put back yet; the same command does that."
                .to_owned(),
        );
    }
    lines.extend(
        record
            .unfinished
            .iter()
            .map(|why| format!("What stopped it: {why}")),
    );
    lines
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

/// A step of a way back that keeps its records failed while the way back
/// itself went on: said to the user and kept in the record, never dropped.
fn note_failure<T, E: std::fmt::Display>(
    record: &mut CancelledRun,
    what: &str,
    result: std::result::Result<T, E>,
) {
    if let Err(error) = result {
        let note = format!("{what} failed: {error}");
        eprintln!("Note: {note}");
        record.notes.push(note);
    }
}

/// In Windows: take a run back whose conversion never started. For a
/// failure of the run itself (`cause`) and for `--recover --rollback`.
///
/// In this order: one cancellation at a time (the lock); the run's records
/// decide that it can be taken back, and its folder is the run's; the
/// decision is recorded; the partition gets its recorded GPT attributes
/// back and is verified as the writable NTFS volume it was; the boot
/// selection is put back from the run's records; the record is completed.
/// A step that fails is recorded and ends the way back: nothing after it is
/// changed.
pub fn cancel_unapplied_run_in_windows(run: &Path, cause: Option<&str>) -> Result<WayBackReport> {
    let _lock = RunLock::take(run)?;
    let pins = request_pins(run)?;
    let later = past_preparation(run)?;
    let view = view_run(
        run,
        &run.join(BUNDLE_RECORD),
        pins.as_ref().map(|pins| pins.bundle_sha256.as_str()),
        later.as_deref(),
    )?;
    let journal = bind_run_folder(run, &view, pins.as_ref())?;
    let mut notes = view.notes.clone();
    let mut events = Vec::new();
    let begun = begun_record(run, &mut notes);
    if let Some(record) = begun.as_ref().filter(|record| record.completed) {
        // A completed record is believed together with the partition: it is
        // not marked read-only. One that is is taken up again.
        let attributes = n2r_win32::partition_restoration::observe_partition_attributes(
            &view.source,
            view.observation,
            &mut events,
        );
        if !matches!(attributes, Ok(attributes) if volume_from_attributes(attributes) == VolumeOutcome::StillReadOnly)
        {
            return Ok(WayBackReport {
                run: run.to_owned(),
                partition: view.source.storage,
                record: record.clone(),
                already_cancelled: true,
                source: None,
                boot: None,
            });
        }
        notes.push(format!(
            "the record said the cancellation was complete on {}, but the partition was found marked read-only, and the cancellation was taken up again",
            record.cancelled_utc
        ));
    }
    let mut record = match begun {
        Some(record) => record.taken_up_again(),
        None => CancelledRun::begin(view.state, CancelEnvironment::Windows, cause, now_unix_ms()),
    };
    record.notes.extend(notes);
    write_cancelled(run, &record)?;
    let (folder, observer) = cancellation_folder(run, view.evidence_bytes)?;
    let source = give_source_back(
        &view,
        &run.join(INTENT_RECORD),
        &observer,
        &mut events,
        CancelEnvironment::Windows,
    );
    note_failure(
        &mut record,
        "keeping the native events of the volume's give-back",
        observer.checkpoint("way-back-source-closed", &mut events),
    );
    let source = match source {
        Ok(source) => source,
        Err(error) => {
            let (volume, unread) = volume_after_failure(&view, &mut events);
            record.volume = volume;
            record.notes.extend(unread);
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
    note_failure(
        &mut record,
        "keeping the native events of the boot selection's restoration",
        observer.checkpoint("way-back-boot-selection-closed", &mut events),
    );
    let boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            record.unfinished.push(format!("{error:#}"));
            write_cancelled(run, &record)?;
            return Err(error);
        }
    };
    record.boot_selection = merge_boot_outcome(record.boot_selection, boot_outcome(&boot));
    record.notes.extend(boot.other_entries_not_compared.clone());
    record.unfinished.clear();
    record.completed = true;
    let kept = observer.lock().and_then(|mut ledger| {
        ledger.record(
            &serde_json::json!({"kind":"restart-run-cancelled-in-windows-v1",
            "record":record,"source":source,"boot":boot}),
        )
    });
    note_failure(
        &mut record,
        "keeping the cancellation's summary with its events",
        kept,
    );
    write_cancelled(run, &record)?;
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
    if let Ok(Some(record)) = read_cancelled(run) {
        return Ok(cancelled_status_lines(&record, run));
    }
    if let Some(refusal) = apply_forbidden(run) {
        return Ok(vec![upper_first(&refusal)]);
    }
    let pins = request_pins(run)?;
    let later = past_preparation(run)?;
    let view = view_run(
        run,
        &run.join(BUNDLE_RECORD),
        pins.as_ref().map(|pins| pins.bundle_sha256.as_str()),
        later.as_deref(),
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
    let journal = bind_run_folder(run, &view, pins.as_ref())?;
    let folder = run.join(format!("status-{}-{}", now_unix_ms(), std::process::id()));
    fs::create_dir(&folder)
        .with_context(|| format!("creating the folder {} for the query", folder.display()))?;
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
    let left = match &way_back {
        Ok(_) => None,
        Err(_) => read_cancelled(run).ok().flatten(),
    };
    failure_with_way_back(cause, &way_back, left.as_ref(), run)
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

/// What the cold way back records of the volume. A record that was
/// complete is never made less by a later pass that could not repeat a
/// step: it keeps what it said, and the pass's failure is noted.
fn merge_cold_volume(
    was_complete: bool,
    before: VolumeOutcome,
    now: VolumeOutcome,
) -> VolumeOutcome {
    match (was_complete, now) {
        (_, VolumeOutcome::GivenBack | VolumeOutcome::NeverProtected) => now,
        (true, _) => before,
        (false, _) => now,
    }
}

fn cold_way_back(
    request: &PreparedOfflineRequest,
    held_ram_bootstrap: &mut File,
    cause: &str,
) -> std::result::Result<WayBackReport, ColdWayBack> {
    let mut events = Vec::new();
    // Until the working volume is reached, events are kept on the RAM disk.
    let shown = (|| -> Result<(RunView, PathBuf, Observer, File, RunLock)> {
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
        let lock = RunLock::take(&run)?;
        // The request this Windows was started with was written from the
        // sealed preparation: the bundle is required, whatever else is in
        // the folder.
        let view = view_run(
            &run,
            &request.prepared_bundle,
            Some(&request.prepared_bundle_sha256),
            Some(Path::new("the boot request this Windows was started with")),
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
        Ok((view, folder, observer, volume, lock))
    })();
    let (view, folder, observer, _volume, _lock) = shown.map_err(ColdWayBack::NotShown)?;
    let run = request.output_parent.clone();
    let failed = ColdWayBack::Failed;
    let mut notes = view.notes.clone();
    // A cancellation that was begun, here or in Windows, is finished under
    // its own record; one that cannot be read is begun anew.
    let begun = begun_record(&run, &mut notes);
    let was_complete = begun.as_ref().is_some_and(|record| record.completed);
    let volume_before = begun.as_ref().map(|record| record.volume);
    let mut record = match begun {
        Some(mut record) => {
            record.unfinished.clear();
            record
        }
        None => CancelledRun::begin(
            view.state,
            CancelEnvironment::RecoveryEnvironment,
            Some(cause),
            now_unix_ms(),
        ),
    };
    record.notes.extend(notes);
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
    note_failure(
        &mut record,
        "keeping the native events of the volume's give-back",
        observer.checkpoint("cold-way-back-source-closed", &mut events),
    );
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
            // What is true of the partition now, not what was attempted.
            let (now, unread) = volume_after_failure(&view, &mut events);
            record.volume = merge_cold_volume(
                was_complete,
                volume_before.unwrap_or(VolumeOutcome::StillReadOnly),
                now,
            );
            record.notes.extend(unread);
            if was_complete {
                record.notes.push(format!(
                    "a later pass could not repeat the volume's give-back: {error:#}"
                ));
            } else {
                record.unfinished.push(format!("{error:#}"));
            }
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
    note_failure(
        &mut record,
        "keeping the native events of the boot selection's restoration",
        observer.checkpoint("cold-way-back-boot-selection-closed", &mut events),
    );
    let boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            record.unfinished.push(format!("{error:#}"));
            // The way back has failed either way; a record that could not
            // be written as well is said with it.
            return Err(ColdWayBack::Failed(match write_cancelled(&run, &record) {
                Ok(()) => error,
                Err(unwritten) => error.context(format!(
                    "its record could not be written either: {unwritten:#}"
                )),
            }));
        }
    };
    record.boot_selection = BootOutcome::Restored;
    record.notes.extend(boot.other_entries_not_compared.clone());
    record.completed = was_complete
        || matches!(
            record.volume,
            VolumeOutcome::GivenBack | VolumeOutcome::NeverProtected
        );
    record
        .notes
        .retain(|note| !note.starts_with(FINISH_IN_WINDOWS));
    if !record.completed {
        // The record and the console (which prints the notes) both carry
        // the exact command for the Windows that starts next.
        record
            .notes
            .push(format!("{FINISH_IN_WINDOWS}{}", cancel_command(&run)));
    }
    if record.completed {
        record.unfinished.clear();
    }
    let kept = observer.lock().and_then(|mut ledger| {
        ledger.record(
            &serde_json::json!({"kind":"restart-run-cancelled-in-recovery-environment-v1",
            "record":record,"source":source,"boot":boot}),
        )
    });
    note_failure(
        &mut record,
        "keeping the cancellation's summary with its events",
        kept,
    );
    write_cancelled(&run, &record).map_err(failed)?;
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
        assert!(fs::read_dir(&run).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".new")
        }));
        // A cancellation that is taken up again keeps when and why it was
        // decided, and is unfinished until it ends.
        let mut stopped = read.clone();
        stopped.unfinished.push("the volume is in use".into());
        let again = stopped.taken_up_again();
        assert!(!again.completed && again.unfinished.is_empty());
        assert_eq!(
            (again.cancelled_unix_ms, again.cause.as_deref()),
            (now, Some("the recovery image could not be built"))
        );
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
            unfinished[0].contains("but the volume is still marked read-only")
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
            failure_with_way_back(cause(), &report(VolumeOutcome::GivenBack), None, run)
                .to_string(),
            "building the recovery image: DISM ended with code 5; the volume was given back as NTFS"
        );
        assert_eq!(
            failure_with_way_back(cause(), &report(VolumeOutcome::NeverProtected), None, run)
                .to_string(),
            "building the recovery image: DISM ended with code 5; the volume had not been changed and is NTFS as it was"
        );
        let command =
            "ntfs2refs --recover \"E:\\work\\partition-offline-conversion-0123\" --rollback";
        let stopped = || {
            Err(anyhow::anyhow!(
                "the first sector of partition 4 of disk 0 differs"
            ))
        };
        assert_eq!(
            failure_with_way_back(cause(), &stopped(), None, run).to_string(),
            format!(
                "building the recovery image: DISM ended with code 5; AND the volume could not be given back: the first sector of partition 4 of disk 0 differs. To try again: {command}"
            )
        );
        // A way back that gave the volume back and stopped at the boot
        // selection does not report the volume as lost.
        let at_boot = record(VolumeOutcome::GivenBack, BootOutcome::Unsettled);
        let later = || {
            Err(anyhow::anyhow!(
                "putting the boot selection back: boot resources unavailable"
            ))
        };
        assert_eq!(
            failure_with_way_back(cause(), &later(), Some(&at_boot), run).to_string(),
            format!(
                "building the recovery image: DISM ended with code 5; the volume is NTFS as it was, AND the cancellation could not be finished: putting the boot selection back: boot resources unavailable. To try again: {command}"
            )
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
        assert!(sealed(&path, None, &source()).unwrap().is_none());
        let bytes = bundle(work.path(), &source(), 16384);
        fs::write(&path, &bytes).unwrap();
        let pin = hex::encode(Sha256::digest(&bytes));
        let core = sealed(&path, Some(&pin), &source()).unwrap().unwrap();
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
            format!("{:#}", sealed(&path, pin, source).err().expect("refused"))
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
        let core = sealed(&path, None, &source()).unwrap().unwrap();
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

    fn sealed(
        path: &Path,
        pin: Option<&str>,
        source: &GeneralDiskBinding,
    ) -> Result<Option<BundleCore>> {
        Ok(match read_bundle(path, pin, source, 1 << 20)? {
            BundleRead::Absent => None,
            BundleRead::Sealed(core) => Some(*core),
            BundleRead::Undecodable(why) => panic!("undecodable: {why}"),
        })
    }

    #[test]
    fn a_missing_or_broken_bundle_is_never_proof_for_a_run_that_got_past_its_preparation() {
        let work = tempfile::tempdir().unwrap();
        let run = work.path();
        let bundle_path = run.join("bundle.json");
        // Nothing of the run but its folder: its preparation did not finish.
        assert_eq!(past_preparation(run).unwrap(), None);
        let (core, note) = admit_bundle(BundleRead::Absent, &bundle_path, None).unwrap();
        assert!(core.is_none() && note.is_none());
        // Its boot request, or the first record of its boot installation,
        // shows that it sealed a preparation: then the bundle is required.
        for later in [REQUEST_RECORD, BOOT_FIRST_RECORD] {
            let record = run.join(later);
            fs::create_dir_all(record.parent().unwrap()).unwrap();
            fs::write(&record, b"{}").unwrap();
            let shown = past_preparation(run)
                .unwrap()
                .expect("past its preparation");
            assert_eq!(shown, record);
            let refusal = admit_bundle(BundleRead::Absent, &bundle_path, Some(&shown))
                .err()
                .expect("refused")
                .to_string();
            assert!(
                refusal.contains("bundle.json")
                    && refusal.contains("is missing")
                    && refusal.contains(&record.display().to_string())
                    && refusal.contains("Nothing was changed"),
                "{refusal}"
            );
            let refusal = admit_bundle(
                BundleRead::Undecodable("EOF while parsing".into()),
                &bundle_path,
                Some(&shown),
            )
            .err()
            .expect("refused")
            .to_string();
            assert!(
                refusal.contains("cannot be decoded (EOF while parsing)")
                    && refusal.contains("Nothing was changed"),
                "{refusal}"
            );
            fs::remove_file(&record).unwrap();
        }
        // A bundle that was cut short while it was written, in a run that
        // left nothing after it, is a preparation that did not finish, and
        // the record is told why.
        fs::write(&bundle_path, &bundle(run, &source(), 16384)[..200]).unwrap();
        let read = read_bundle(&bundle_path, None, &source(), 1 << 20).unwrap();
        assert!(matches!(read, BundleRead::Undecodable(_)));
        let (core, note) = admit_bundle(read, &bundle_path, None).unwrap();
        assert!(core.is_none());
        let note = note.expect("noted");
        assert!(
            note.contains("bundle.json") && note.contains("power loss"),
            "{note}"
        );
        // With the unsealed proof still to pass: the journal's lifecycle
        // area. A cut-short bundle beside a marked journal is refused.
        assert!(admit_cancellation(false, JournalEvidence::LifecycleAreaWritten).is_err());
        // A record larger than this run may hold is not read at all.
        let refusal = read_bundle(&bundle_path, None, &source(), 100)
            .err()
            .expect("refused")
            .to_string();
        assert!(refusal.contains("more than the 100 bytes"), "{refusal}");
    }

    #[test]
    fn a_sealed_run_needs_its_intent_file_and_an_unsealed_one_a_partition_that_is_not_read_only() {
        use CancelEnvironment::*;
        use IntentPresence::*;
        let intent = Path::new("E:\\run\\prepared\\control\\partition.intent");
        assert_eq!(intent_is_read(true, Windows, Records, intent), Ok(true));
        assert_eq!(intent_is_read(false, Windows, Records, intent), Ok(true));
        // A sealed run protected its partition: without the record of what
        // the partition was, it is refused, not taken for unprotected.
        for (presence, word) in [(Missing, "is missing"), (Empty, "is empty")] {
            for (sealed, environment) in [
                (true, Windows),
                (true, RecoveryEnvironment),
                (false, RecoveryEnvironment),
            ] {
                let refusal = intent_is_read(sealed, environment, presence, intent).unwrap_err();
                assert!(
                    refusal.contains("partition.intent") && refusal.contains(word),
                    "{refusal}"
                );
            }
            // Only an unsealed run in Windows goes on, to ask the partition.
            assert_eq!(intent_is_read(false, Windows, presence, intent), Ok(false));
        }
        let read_only = n2r_win32::partition_restoration::GPT_ATTRIBUTE_READ_ONLY;
        assert_eq!(require_not_read_only(0, &source(), intent), Ok(()));
        // Another attribute (no drive letter by default) is not this route's.
        assert_eq!(
            require_not_read_only(0x8000_0000_0000_0000, &source(), intent),
            Ok(())
        );
        let refusal = require_not_read_only(read_only, &source(), intent).unwrap_err();
        assert!(
            refusal.contains("partition 4 of disk 0 is marked read-only")
                && refusal.contains("0x1000000000000000")
                && refusal.contains("partition.intent")
                && refusal.contains("nothing was changed"),
            "{refusal}"
        );
        // After a give-back that failed, the record says what the entry is.
        assert_eq!(
            volume_from_attributes(read_only),
            VolumeOutcome::StillReadOnly
        );
        assert_eq!(volume_from_attributes(0), VolumeOutcome::NotVerified);
    }

    #[test]
    fn a_copy_of_a_run_folder_is_not_the_run() {
        let recorded = Path::new(
            "\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\work\\partition-offline-conversion-0123",
        );
        assert!(same_folder(
            "\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\work\\PARTITION-offline-conversion-0123\\",
            recorded
        ));
        for other in [
            "\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\copy\\partition-offline-conversion-0123",
            "\\\\?\\Volume{31111111-2222-3333-4444-555555555555}\\work\\partition-offline-conversion-0123",
            "\\\\?\\Volume{21111111-2222-3333-4444-555555555555}\\work",
        ] {
            assert!(!same_folder(other, recorded), "{other}");
        }
    }

    #[test]
    fn one_cancellation_of_a_run_at_a_time() {
        let work = tempfile::tempdir().unwrap();
        let run = work.path();
        let held = RunLock::take(run).unwrap();
        let refusal = RunLock::take(run).err().expect("refused").to_string();
        assert!(
            refusal.contains("a cancellation of this run is in progress")
                && refusal.contains(LOCK_RECORD)
                && refusal.contains("Nothing was changed"),
            "{refusal}"
        );
        drop(held);
        assert!(!run.join(LOCK_RECORD).exists());
        // A lock left by a process that died is not held by anybody, and
        // is taken over.
        fs::write(run.join(LOCK_RECORD), b"4242 2026-11-18 14:03:22 UTC\n").unwrap();
        let again = RunLock::take(run).unwrap();
        assert!(RunLock::take(run).is_err());
        drop(again);
        // Two writers of the record never share a temporary file.
        let mut record = CancelledRun::begin(
            UnappliedState::PreparedClear,
            CancelEnvironment::Windows,
            None,
            0,
        );
        std::thread::scope(|scope| {
            for volume in [VolumeOutcome::GivenBack, VolumeOutcome::StillReadOnly] {
                let mut record = record.clone();
                scope.spawn(move || {
                    for _ in 0..50 {
                        record.volume = volume;
                        // (Unlocked on purpose: either order may win a
                        // rename, and one may be refused while the other
                        // holds the file; what is in place always decodes.)
                        let _ = write_cancelled(run, &record);
                        if let Ok(Some(read)) = read_cancelled(run) {
                            assert_eq!(read.kind, CANCELLED_KIND);
                        }
                    }
                });
            }
        });
        record.completed = true;
        write_cancelled(run, &record).unwrap();
        assert_eq!(read_cancelled(run).unwrap(), Some(record));
        let left: Vec<_> = fs::read_dir(run)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_cancellation_record_that_cannot_be_read_still_forbids_the_run() {
        let work = tempfile::tempdir().unwrap();
        let run = work.path();
        // No record: nothing forbids the run.
        assert_eq!(apply_forbidden(run), None);
        let mut notes = Vec::new();
        assert_eq!(begun_record(run, &mut notes), None);
        assert!(notes.is_empty());
        // A record cut short, or of another kind: the runner never applies,
        // and is told how the cancellation is finished; the way back begins
        // a record anew and notes that it did.
        for broken in [
            &b"{\"schema_version\":1,\"kind\":\"ntfs2refs-restart-ru"[..],
            b"{}",
            b"",
        ] {
            fs::write(run.join(CANCELLED_RECORD), broken).unwrap();
            let refusal = apply_forbidden(run).expect("forbidden");
            assert!(
                refusal.contains("cannot be read")
                    && refusal.contains("never applied")
                    && refusal.contains("--rollback"),
                "{refusal}"
            );
            let mut notes = Vec::new();
            assert_eq!(begun_record(run, &mut notes), None);
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(notes[0].contains("could not be read and was replaced"));
        }
        // A readable one forbids it in its own words.
        let record = CancelledRun::begin(
            UnappliedState::PreparedClear,
            CancelEnvironment::Windows,
            None,
            0,
        );
        write_cancelled(run, &record).unwrap();
        assert_eq!(apply_forbidden(run), Some(record.refusal(run)));
    }

    #[test]
    fn a_record_that_was_complete_is_not_made_less_and_what_was_skipped_is_said() {
        use VolumeOutcome::*;
        // A later pass in the recovery environment that cannot repeat the
        // give-back leaves a complete record's volume as it was written.
        assert_eq!(merge_cold_volume(true, GivenBack, StillReadOnly), GivenBack);
        assert_eq!(merge_cold_volume(true, GivenBack, NotVerified), GivenBack);
        assert_eq!(merge_cold_volume(true, StillReadOnly, GivenBack), GivenBack);
        // An unfinished one takes what is true now.
        assert_eq!(
            merge_cold_volume(false, StillReadOnly, NotVerified),
            NotVerified
        );
        assert_eq!(
            merge_cold_volume(false, NotVerified, StillReadOnly),
            StillReadOnly
        );
        // What a way back could not check or keep is said with the outcome.
        let run = Path::new("E:\\work\\partition-offline-conversion-0123");
        let mut told = record(GivenBack, BootOutcome::Restored);
        told.notes.push(
            "the entries of the system's boot configuration store could not be listed whole, so it was not checked that no other entry changed: unsupported heading".into(),
        );
        let lines = cancelled_lines(&told, "D:", run);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines[2].starts_with("Note: ")
                && lines[2].contains("not checked that no other entry changed"),
            "{lines:?}"
        );
        // A partition that is no longer read-only but was not verified is
        // not called read-only, and not called NTFS as it was either.
        let unverified = cancelled_lines(&record(NotVerified, BootOutcome::Restored), "D:", run);
        assert!(
            unverified[0].contains("D: is no longer marked read-only")
                && unverified[0].contains("could not be verified")
                && unverified[0].contains("--rollback"),
            "{unverified:?}"
        );
        // A record-keeping step that failed is a note; one that did not is
        // nothing.
        note_failure::<(), _>(&mut told, "keeping the native events", Err("disk full"));
        note_failure(&mut told, "nothing", Ok::<_, String>(()));
        assert_eq!(
            told.notes.last().map(String::as_str),
            Some("keeping the native events failed: disk full")
        );
    }

    #[test]
    fn a_cancellation_the_recovery_environment_could_not_finish_is_said_and_finished_in_windows() {
        let run = Path::new("E:\\work\\partition-offline-conversion-0123");
        let command = cancel_command(run);
        // As the recovery environment leaves it when it could only put the
        // boot selection back.
        let mut left = CancelledRun::begin(
            UnappliedState::PreparedClear,
            CancelEnvironment::RecoveryEnvironment,
            Some("laboratory failure at winpe-before-apply"),
            1_795_010_602_000,
        );
        left.boot_selection = BootOutcome::Restored;
        left.unfinished
            .push("giving partition 4 of disk 0 back as NTFS: Incorrect function.".into());
        left.notes.push(format!("{FINISH_IN_WINDOWS}{command}"));
        // The status says the volume is read-only, in plain words, with
        // the command and what stopped the first attempt.
        let status = cancelled_status_lines(&left, run);
        assert_eq!(
            status[0],
            "This run was cancelled on 2026-11-18 14:03:22 UTC (in the recovery environment, before its conversion started), and its cancellation is not complete."
        );
        assert_eq!(
            status[1],
            format!(
                "The volume is still marked read-only: Windows shows it and its files, and nothing can be written to it. To make it the writable NTFS volume it was: {command}"
            )
        );
        assert_eq!(
            status[2],
            "What stopped it: giving partition 4 of disk 0 back as NTFS: Incorrect function."
        );
        assert_eq!(status.len(), 3, "{status:?}");
        // The console of the recovery environment says the same command,
        // once as the way on and once as the note for Windows.
        let console = cancelled_lines(&left, "The volume", run);
        assert!(
            console[0].contains("but the volume is still marked read-only")
                && console[0].ends_with(&command),
            "{console:?}"
        );
        assert_eq!(
            console.last().map(String::as_str),
            Some(format!("Note: {FINISH_IN_WINDOWS}{command}").as_str())
        );
        // --rollback in Windows takes it up (it is not complete), under the
        // same record, without the note that it has now followed; and the
        // boot selection it finds normal stays "restored".
        assert!(!left.completed);
        let again = left.clone().taken_up_again();
        assert!(again.notes.is_empty() && again.unfinished.is_empty() && !again.completed);
        assert_eq!(again.cancelled_unix_ms, left.cancelled_unix_ms);
        assert_eq!(again.environment, CancelEnvironment::RecoveryEnvironment);
        assert_eq!(
            merge_boot_outcome(BootOutcome::Restored, BootOutcome::WasNotInstalled),
            BootOutcome::Restored
        );
        assert_eq!(
            merge_boot_outcome(BootOutcome::Unsettled, BootOutcome::WasNotInstalled),
            BootOutcome::WasNotInstalled
        );
        assert_eq!(
            merge_boot_outcome(BootOutcome::Unsettled, BootOutcome::Restored),
            BootOutcome::Restored
        );
        // A complete one says only that.
        let mut done = left.clone();
        done.volume = VolumeOutcome::GivenBack;
        done.completed = true;
        assert_eq!(
            cancelled_status_lines(&done, run),
            [
                "This run was cancelled on 2026-11-18 14:03:22 UTC; the volume is NTFS as it was. A conversion is started again with a new run."
            ]
        );
    }
}
