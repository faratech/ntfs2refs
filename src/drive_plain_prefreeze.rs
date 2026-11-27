//! What a run changes on the source before it is frozen, to make objects
//! plain files whose bytes are not on the volume (design tier C).
//!
//! Almost every conversion to plain is made while the shadow is built, from
//! the frozen source, and changes nothing on it. A cloud provider's
//! placeholder whose data is not wholly on the volume is the exception: the
//! frozen source is read without its provider, so what it lacks has to be
//! downloaded first, through Windows, while the volume is online. That is a
//! change to the source, as the shrink of a partition and the upgrade of an
//! NTFS 1.2 or 3.0 volume are, and like them it is announced before the
//! question, needs a [`SourceChangeAuthority`] (so `--diagnose` and
//! `--check` never reach it), and is not undone: a run that is cancelled or
//! rolled back afterwards leaves the downloaded files on the volume, and
//! says so ([`note`]), from the records this step writes in the run's
//! directory before and after it changes anything ([`INTENT_FILE`],
//! [`AFTER_FILE`]).
//!
//! What is downloaded is decided before the question from what the Cloud
//! Files API reports ([`CloudFinding`]): every placeholder of the agreed list
//! that is not wholly on the volume, except those the user agreed to leave
//! out. A placeholder that cannot be downloaded
//! (its provider is not running) is named, and the run is refused before
//! anything changes unless it is left out. The download itself
//! ([`run`]) names every placeholder it could not complete.
use crate::execution_mode::{ExecutionMode, SourceChangeAuthority};
use crate::plain_projection::{PlainEntry, PlainKind, PlainList};
use anyhow::{Context, Result, bail};
use n2r_win32::cloud_native::{PlaceholderReport, Presence, SyncRoot};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, sync::Mutex};

/// The record written before anything is downloaded.
pub(crate) const INTENT_FILE: &str = "plain-prefreeze-intent.json";
/// The record written once the downloads ended, whether or not they all
/// completed.
pub(crate) const AFTER_FILE: &str = "plain-prefreeze-after.json";
const INTENT_KIND: &str = "plain-prefreeze-intent-v1";
const AFTER_KIND: &str = "plain-prefreeze-after-v1";

/// What the Cloud Files API reported of one placeholder of the volume,
/// online, before anything was asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CloudFinding {
    /// As a listing names it.
    pub path: String,
    pub directory: bool,
    /// Whose placeholder it is. A cloud one is asked of the Cloud Files
    /// API; any other is taken as the raw reading shows it, and is
    /// brought onto the volume by reading it through its provider.
    #[serde(skip)]
    pub family: crate::plain_projection::PlaceholderFamily,
    /// What is on the volume of it, or why that could not be asked.
    pub report: std::result::Result<PlaceholderReport, String>,
    /// Its provider, asked only of a placeholder that needs a download.
    pub sync_root: Option<std::result::Result<SyncRoot, String>>,
}

impl CloudFinding {
    /// The bytes a download brings onto the volume.
    pub(crate) fn missing_bytes(&self) -> u64 {
        self.report
            .as_ref()
            .map_or(0, |report| report.missing_bytes)
    }

    /// Whether anything of it is not on the volume.
    pub(crate) fn needs_download(&self) -> bool {
        self.report
            .as_ref()
            .is_ok_and(PlaceholderReport::needs_download)
    }

    fn provider(&self) -> String {
        match &self.sync_root {
            // With the status it reports (CF_SYNC_PROVIDER_STATUS): 0 is
            // disconnected, 1 idle.
            Some(Ok(root)) if !root.provider.is_empty() => {
                format!("{}, status {:#x}", root.provider, root.status)
            }
            Some(Err(error)) => format!("its provider could not be asked: {error}"),
            _ => "its provider".to_owned(),
        }
    }
}

/// Pure: what the raw reading shows of a placeholder no API reports on
/// (ProjFS's, a storage manager's): its length and the bytes below it no
/// cluster holds.
pub(crate) fn raw_report(placeholder: &crate::plain_projection::Placeholder) -> PlaceholderReport {
    if placeholder.directory {
        return n2r_win32::cloud_native::directory_report(
            n2r_win32::cloud_native::PLACEHOLDER_STATE_PLACEHOLDER,
            None,
        );
    }
    let present = placeholder.plain_bytes - placeholder.raw_missing_bytes;
    n2r_win32::cloud_native::file_report(
        placeholder.plain_bytes,
        &[n2r_win32::cloud_native::FileRange {
            offset: 0,
            length: present,
        }],
        None,
    )
}

/// Asks of each placeholder (`path` as a listing names it) of the volume
/// `root` (`\\?\Volume{...}\`) what of it is on the volume: the Cloud Files
/// API of a cloud one, the raw reading of any other. Downloads and lists
/// nothing.
pub(crate) fn find(
    root: &str,
    placeholders: &[(String, crate::plain_projection::Placeholder)],
) -> Vec<CloudFinding> {
    placeholders
        .iter()
        .map(|(path, placeholder)| {
            let (report, sync_root) =
                if placeholder.family == crate::plain_projection::PlaceholderFamily::Cloud {
                    ask_cloud(root, path)
                } else {
                    (Ok(raw_report(placeholder)), None)
                };
            CloudFinding {
                path: path.clone(),
                directory: placeholder.directory,
                family: placeholder.family,
                report,
                sync_root,
            }
        })
        .collect()
}

type Asked = (
    std::result::Result<PlaceholderReport, String>,
    Option<std::result::Result<SyncRoot, String>>,
);

#[cfg(windows)]
fn ask_cloud(root: &str, path: &str) -> Asked {
    let at = std::path::PathBuf::from(format!("{root}{}", path.trim_start_matches('\\')));
    let report = n2r_win32::cloud_native::report(&at).map_err(|error| error.to_string());
    let sync_root = report
        .as_ref()
        .is_ok_and(PlaceholderReport::needs_download)
        .then(|| n2r_win32::cloud_native::sync_root(&at).map_err(|e| e.to_string()));
    (report, sync_root)
}

#[cfg(not(windows))]
fn ask_cloud(_root: &str, _path: &str) -> Asked {
    (Err("the Cloud Files API is a Windows one".into()), None)
}

/// Sets each cloud entry's bytes to download to what the Cloud Files API
/// reported (the raw reading's holes stand where it could not be asked).
pub(crate) fn apply_downloads(entries: &mut [PlainEntry], findings: &[CloudFinding]) {
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.kind.family().is_some() && !entry.kind.is_left_out())
    {
        if let Some(finding) = findings.iter().find(|finding| finding.path == entry.path)
            && finding.report.is_ok()
        {
            entry.download_bytes = finding.missing_bytes();
        }
    }
}

fn mib(bytes: u64) -> String {
    format!("{} MiB", bytes.div_ceil(1 << 20))
}

fn named(paths: &[String]) -> String {
    let shown: Vec<&str> = paths.iter().take(5).map(String::as_str).collect();
    let more = paths.len().saturating_sub(shown.len());
    if more == 0 {
        shown.join(", ")
    } else {
        format!("{} and {more} more", shown.join(", "))
    }
}

/// The lines a check and a run print of the volume's cloud placeholders:
/// how many are on the volume in full, in part or not at all, what a run
/// downloads before the freeze, and every one it could not ask about.
pub(crate) fn summary(findings: &[CloudFinding]) -> Vec<String> {
    if findings.is_empty() {
        return Vec::new();
    }
    let count = |presence: Presence| {
        findings
            .iter()
            .filter(|finding| {
                !finding.directory
                    && finding
                        .report
                        .as_ref()
                        .is_ok_and(|report| report.presence == presence)
            })
            .count()
    };
    let directories = findings.iter().filter(|finding| finding.directory).count();
    let mut lines = vec![format!(
        "Cloud placeholders: {} file(s) and {directories} director(ies) of a cloud provider (OneDrive and others). {} file(s) are wholly on this device, {} partly and {} not at all.",
        findings.len() - directories,
        count(Presence::Full),
        count(Presence::Partial),
        count(Presence::NotPresent),
    )];
    let downloads: Vec<&CloudFinding> = findings
        .iter()
        .filter(|finding| finding.needs_download() && !finding.directory)
        .collect();
    if !downloads.is_empty() {
        let bytes = downloads.iter().fold(0u64, |sum, finding| {
            sum.saturating_add(finding.missing_bytes())
        });
        let paths: Vec<String> = downloads.iter().map(|f| f.path.clone()).collect();
        lines.push(format!(
            "{} of them are not wholly on this device: {} are downloaded from their provider before the volume is frozen, which changes the volume and is not undone (a check downloads nothing): {}.",
            downloads.len(),
            mib(bytes),
            named(&paths)
        ));
        // What each provider reports of itself, for information only: a
        // run tries every download, and names each one it cannot make.
        let reported: Vec<String> = downloads
            .iter()
            .map(|finding| format!("{} ({})", finding.path, finding.provider()))
            .collect();
        lines.push(format!(
            "Their providers, as the Cloud Files API reports them (for information: a run tries each download and names any it cannot make; a provider serves only the account that runs it): {}.",
            named(&reported)
        ));
    }
    lines
}

fn left(path: &str, left_out: &BTreeSet<String>) -> bool {
    left_out
        .iter()
        .any(|gone| crate::plain_projection::within(path, gone))
}

/// Whether a placeholder is not wholly on the volume, and so may be left
/// out: a file that needs a download, whatever its
/// provider reports of itself (the run tries the download, and names it if
/// it fails), or a folder its provider has not listed in full (what it
/// lacks cannot be named, so it can only be left out whole).
fn stranded(finding: &CloudFinding) -> bool {
    match &finding.report {
        Ok(report) if finding.directory => report.unpopulated,
        Ok(_) => finding.needs_download(),
        Err(_) => false,
    }
}

/// Why a run would stop for the volume's placeholders, before it changes
/// anything: a placeholder the Cloud Files API could not report on, and a
/// folder its provider has not listed in full, unless the user agreed to
/// leave it out (`left_out`, by path: a folder left out takes what is
/// below it). A file not wholly on the volume is not refused here: it is
/// downloaded before the freeze, and a download that fails is named then.
pub(crate) fn refusals(findings: &[CloudFinding], left_out: &BTreeSet<String>) -> Vec<String> {
    let mut refusals = Vec::new();
    let unlisted: Vec<String> = findings
        .iter()
        .filter(|finding| finding.directory && stranded(finding) && !left(&finding.path, left_out))
        .map(|finding| finding.path.clone())
        .collect();
    if !unlisted.is_empty() {
        refusals.push(format!(
            "{} cloud folder(s) have not been listed in full on this device by their provider, so what they hold cannot be named: {}. Open each with its provider running, or make it always available on this device, and run again; or agree to leave it out whole",
            unlisted.len(),
            named(&unlisted)
        ));
    }
    let unasked: Vec<String> = findings
        .iter()
        .filter(|finding| !left(&finding.path, left_out))
        .filter_map(|finding| match &finding.report {
            Err(error) => Some(format!("{} ({error})", finding.path)),
            Ok(_) => None,
        })
        .collect();
    if !unasked.is_empty() {
        refusals.push(format!(
            "the Cloud Files API could not say what of {} cloud placeholder(s) is on this device: {}",
            unasked.len(),
            named(&unasked)
        ));
    }
    refusals
}

/// What a check, and a conversion's check before its questions, refuse of
/// the volume's placeholders. Those that cannot be brought onto the volume
/// now are not among them: they may be left out (`cloud_left_out`), and
/// the conversion asks about them, and refuses them only if the user does
/// not agree.
pub(crate) fn check_refusals(findings: &[CloudFinding]) -> Result<Vec<String>> {
    if !PlainKind::CloudLeftOut.implemented() {
        return Ok(refusals(findings, &BTreeSet::new()));
    }
    Ok(refusals(findings, &paths_of(&leave_out_list(findings)?)))
}

/// The paths a list names.
pub(crate) fn paths_of(list: &PlainList) -> BTreeSet<String> {
    list.entries()
        .iter()
        .map(|entry| entry.path.clone())
        .collect()
}

/// The placeholders a user may agree to leave out: those that cannot be
/// brought onto the volume now ([`stranded`]), outermost first: what is
/// below a folder among them goes with it and is not named apart. Its
/// SHA-256 is what `--leave-out-cloud` names.
pub(crate) fn leave_out_list(findings: &[CloudFinding]) -> Result<PlainList> {
    let folders: BTreeSet<String> = findings
        .iter()
        .filter(|finding| finding.directory && stranded(finding))
        .map(|finding| finding.path.clone())
        .collect();
    PlainList::new(
        findings
            .iter()
            .filter(|finding| stranded(finding))
            .filter(|finding| {
                !folders.iter().any(|folder| {
                    folder != &finding.path
                        && crate::plain_projection::within(&finding.path, folder)
                })
            })
            .map(|finding| PlainEntry {
                kind: finding.family.left_out_kind(),
                path: finding.path.clone(),
                cleared_attributes: 0,
                bytes: finding.report.as_ref().map_or(0, |report| report.size),
                volume_extra_bytes: 0,
                working_extra_bytes: 0,
                download_bytes: 0,
            })
            .collect(),
    )
    .map_err(anyhow::Error::msg)
}

/// Reads `--leave-out-cloud`: a SHA-256 as a check prints it.
pub(crate) fn parse_leave_out(text: &str) -> std::result::Result<String, String> {
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(format!(
            "--leave-out-cloud takes the SHA-256 of a list of cloud placeholders to leave out, as `--check` prints it (64 hexadecimal digits), not {text:?}"
        ))
    }
}

/// Pure: what a run does with the list of placeholders it may leave out,
/// given `--leave-out-cloud` and whether `--yes` answers its questions.
pub(crate) fn decide_leave_out(
    list: &PlainList,
    agreed: Option<&str>,
    unattended: bool,
) -> Result<crate::plain_consent::Decision> {
    let given = agreed;
    use crate::plain_consent::Decision;
    let sha = list.sha256();
    if list.is_empty() {
        if let Some(named) = given {
            bail!(
                "--leave-out-cloud names the list {named}, and every cloud placeholder of this volume can be brought onto it: there is nothing to leave out. Nothing was changed"
            );
        }
        return Ok(Decision::Nothing);
    }
    match given {
        Some(named) if named == sha => Ok(if unattended {
            Decision::Accepted
        } else {
            Decision::Ask
        }),
        Some(named) => bail!(
            "--leave-out-cloud names the list {named}, and the cloud placeholders this run would leave out are {sha}: the volume is not as it was when that list was made. Nothing was changed. Read the list again (--check) and agree to it as it is"
        ),
        // Unattended and not left out: they are downloaded, and each one
        // that cannot be is named then.
        None if unattended => Ok(Decision::Nothing),
        None => Ok(Decision::Ask),
    }
}

/// The question a run asks about leaving placeholders out.
pub(crate) fn leave_out_question(list: &PlainList) -> String {
    format!(
        "Leave these {} {} out of the conversion? Retrieval of omitted content depends on its provider or storage manager. List SHA-256 {}. Answer no to have the converter try to retrieve them before freezing the volume. [y/N]",
        list.len(),
        crate::plain_projection::placeholders_noun(families_of(list)),
        list.sha256()
    )
}

/// Whose placeholders a list names.
fn families_of(list: &PlainList) -> Vec<crate::plain_projection::PlaceholderFamily> {
    list.entries()
        .iter()
        .filter_map(|entry| entry.kind.family())
        .collect()
}

/// Writes the list of placeholders that may be left out under
/// `directory`, and says where.
pub(crate) fn write_leave_out_list(
    directory: &Path,
    list: &PlainList,
) -> Result<std::path::PathBuf> {
    let path = directory.join(format!("cloud-left-out-{}.txt", &list.sha256()[..16]));
    std::fs::write(&path, list.text())
        .map_err(|error| anyhow::anyhow!("writing the list to {}: {error}", path.display()))?;
    Ok(path)
}

/// After the plain-conversions list was agreed: the placeholders not
/// wholly on the volume are named, and the user asked whether to leave them
/// out. Agreed (or `--leave-out-cloud` naming the
/// list), the run's list leaves them out; otherwise every file among them
/// is downloaded before the freeze, and a folder its provider has not
/// listed in full refuses the run with nothing changed.
pub(crate) fn settle(
    findings: &[CloudFinding],
    agreed: &PlainList,
    named: Option<&str>,
    directory: &Path,
) -> Result<()> {
    let list = leave_out_list(findings)?;
    let decision = decide_leave_out(&list, named, crate::confirmation::assumed())?;
    let mut left_out = BTreeSet::new();
    if !list.is_empty() {
        *LEAVE_OUT_LIST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(list.sha256());
    }
    if decision != crate::plain_consent::Decision::Nothing {
        let file = write_leave_out_list(directory, &list)?;
        println!(
            "{} {} are not wholly on this volume (or a folder their provider has not listed in full). The full list: {} (sha256 {}).",
            list.len(),
            crate::plain_projection::placeholders_noun(families_of(&list)),
            file.display(),
            list.sha256()
        );
        for entry in list.entries().iter().take(5) {
            println!("  {}", entry.path);
        }
        if list.len() > 5 {
            println!("  and {} more.", list.len() - 5);
        }
        println!("{}", leave_out_question(&list));
        let yes = if decision == crate::plain_consent::Decision::Accepted {
            println!("yes (--yes --leave-out-cloud {})", list.sha256());
            true
        } else {
            print!("> ");
            crate::confirmation::answer()?
        };
        if yes {
            crate::plain_consent::leave_out(&list)?;
            left_out = paths_of(&list);
        }
    }
    let refused = refusals(findings, &left_out);
    if let Some(first) = refused.first() {
        bail!("this volume is refused, and nothing on it was changed: {first}");
    }
    set_plan(plan_for(findings, agreed, &left_out));
    *PLACEHOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = findings
        .iter()
        .filter(|finding| !left(&finding.path, &left_out))
        .map(|finding| finding.path.clone())
        .collect();
    Ok(())
}

/// The volume's cloud placeholders this run makes plain, as a listing names
/// them: what a provider that is still connected holds, and what the lock
/// of the source names when it cannot be taken.
static PLACEHOLDERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// How long the lock of the source waits for a provider the user was asked
/// to close, on an unattended run.
pub(crate) const PROVIDER_CLOSE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(300);

/// Pure: what a run says once its downloads are done and these providers
/// are still connected, holding the volume.
pub(crate) fn close_provider_note(providers: &[String]) -> String {
    format!(
        "The downloads are done. Close {} (quit OneDrive, say) so that the volume can be taken offline: a connected cloud provider holds its sync root open. The conversion does not close it.",
        providers.join(", ")
    )
}

/// The SHA-256 of the list of placeholders this run could have left out,
/// for the words of a download that fails.
static LEAVE_OUT_LIST: Mutex<Option<String>> = Mutex::new(None);

/// One placeholder to download before the freeze.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Download {
    pub path: String,
    pub missing_bytes: u64,
    /// What it is made plain as, which says whose placeholder it is.
    #[serde(default = "cloud_kind")]
    pub kind: PlainKind,
}

fn cloud_kind() -> PlainKind {
    PlainKind::CloudPlaceholderPlain
}

impl Download {
    /// Brought onto the volume by reading it through its provider (a
    /// ProjFS placeholder, a storage manager's file), not through the Cloud
    /// Files API.
    pub(crate) fn read_through(&self) -> bool {
        self.kind != PlainKind::CloudPlaceholderPlain
    }

    fn family(&self) -> crate::plain_projection::PlaceholderFamily {
        self.kind
            .family()
            .unwrap_or(crate::plain_projection::PlaceholderFamily::Cloud)
    }
}

/// Pure: what a run downloads before the freeze, for an agreed list. Every
/// placeholder of it that is not wholly on the volume and not left out.
pub(crate) fn plan_for(
    findings: &[CloudFinding],
    agreed: &PlainList,
    left_out: &BTreeSet<String>,
) -> Vec<Download> {
    let listed: BTreeSet<&str> = agreed
        .entries()
        .iter()
        .filter(|entry| entry.kind.family().is_some() && !entry.kind.is_left_out())
        .map(|entry| entry.path.as_str())
        .collect();
    findings
        .iter()
        .filter(|finding| {
            !finding.directory
                && finding.needs_download()
                && listed.contains(finding.path.as_str())
                && !left(&finding.path, left_out)
        })
        .map(|finding| Download {
            path: finding.path.clone(),
            missing_bytes: finding.missing_bytes(),
            kind: finding.family.plain_kind(),
        })
        .collect()
}

static PLAN: Mutex<Vec<Download>> = Mutex::new(Vec::new());

/// What this run downloads before the freeze, once the user agreed.
pub(crate) fn set_plan(downloads: Vec<Download>) {
    *PLAN.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = downloads;
}

fn take_plan() -> Vec<Download> {
    std::mem::take(&mut *PLAN.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
}

/// The record of the step, before and after.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub kind: String,
    /// What is (or was) to be downloaded.
    pub planned: Vec<Download>,
    /// After: those now wholly on the volume.
    #[serde(default)]
    pub downloaded: Vec<String>,
    /// After: those that are not, and why.
    #[serde(default)]
    pub failed: Vec<(String, String)>,
}

fn write_new(path: &Path, record: &Record) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, record)?;
    file.write_all(b"\n")?;
    file.sync_all()
        .with_context(|| format!("flushing {}", path.display()))
}

/// Downloads, before the freeze, what this run planned, from each
/// placeholder's provider, through Windows; the volume `root`
/// (`\\?\Volume{...}\`) is online. Nothing when nothing was planned.
/// Each placeholder is asked again afterwards and has to be wholly on the
/// volume; every one that is not is named, and the run stops before the
/// freeze. What was downloaded stays.
pub(crate) fn run(run: &Path, root: &str, mode: ExecutionMode) -> Result<()> {
    let at =
        |path: &str| std::path::PathBuf::from(format!("{root}{}", path.trim_start_matches('\\')));
    // The lock of the source names what holds it, among the placeholders.
    let placeholders: Vec<std::path::PathBuf> = PLACEHOLDERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|path| at(path))
        .collect();
    if !placeholders.is_empty() {
        n2r_win32::lock_holders::set(n2r_win32::lock_holders::LockHints {
            paths: placeholders.clone(),
            placeholders: placeholders.clone(),
            patience: std::time::Duration::ZERO,
        });
    }
    let planned = take_plan();
    if planned.is_empty() {
        return Ok(());
    }
    let authority = mode.source_change_authority(
        "downloading cloud placeholders onto the volume before it is frozen",
    )?;
    let read_through = planned.iter().any(Download::read_through);
    download(run, root, planned, &authority, |download| {
        hydrate_within(
            at(&download.path),
            download.read_through(),
            timeout_for(download.missing_bytes),
        )
    })?;
    // A ProjFS provider that served its reads holds its virtualization root
    // open while it runs (a storage manager may hold what it recalled): no
    // API says so beforehand, so the lock of the volume waits for it a
    // while, naming what holds it, as for a connected cloud provider.
    if read_through {
        println!(
            "The program that served the reads (a ProjFS provider or a storage manager) may hold the volume open: close it now. The volume is taken offline once nothing holds it, within {} s.",
            PROVIDER_CLOSE_PATIENCE.as_secs()
        );
        n2r_win32::lock_holders::set(n2r_win32::lock_holders::LockHints {
            paths: placeholders.clone(),
            placeholders: placeholders.clone(),
            patience: PROVIDER_CLOSE_PATIENCE,
        });
    }
    // A provider that served the downloads is still connected, and holds
    // its sync root open: the volume cannot be locked until it is closed.
    // Asked to close it, interactively until it is; unattended, the lock
    // waits for it a while, naming it. Never closed by the conversion.
    let connected = connected_providers(&placeholders);
    if connected.is_empty() {
        return Ok(());
    }
    println!("{}", close_provider_note(&connected));
    if crate::confirmation::assumed() {
        println!(
            "Unattended: the volume is taken offline once it is closed, within {} s.",
            PROVIDER_CLOSE_PATIENCE.as_secs()
        );
        n2r_win32::lock_holders::set(n2r_win32::lock_holders::LockHints {
            paths: placeholders.clone(),
            placeholders,
            patience: PROVIDER_CLOSE_PATIENCE,
        });
        return Ok(());
    }
    loop {
        println!("Is it closed now? [y/N]");
        print!("> ");
        if !crate::confirmation::answer()? {
            bail!(
                "stopped before the volume was frozen, as {} was not closed: nothing was converted. The downloads stay on the volume, as announced",
                connected.join(", ")
            );
        }
        let still = connected_providers(&placeholders);
        if still.is_empty() {
            return Ok(());
        }
        println!("{} is still connected.", still.join(", "));
    }
}

/// The cloud providers of `placeholders` that the Cloud Files API reports
/// connected, each once.
fn connected_providers(placeholders: &[std::path::PathBuf]) -> Vec<String> {
    let mut providers: Vec<String> = Vec::new();
    #[cfg(windows)]
    for placeholder in placeholders {
        if let Ok(root) = n2r_win32::cloud_native::sync_root(placeholder)
            && root.running()
            && !providers.contains(&root.provider)
        {
            providers.push(root.provider);
        }
    }
    #[cfg(not(windows))]
    let _ = placeholders;
    providers
}

/// How long a download of `missing` bytes may take before the run gives up
/// on its provider: a minute, and a second for each MiB.
pub(crate) fn timeout_for(missing: u64) -> std::time::Duration {
    std::time::Duration::from_secs(60 + missing.div_ceil(1 << 20))
}

/// [`hydrate`] on a thread of its own, waited for at most `timeout`: a
/// provider that does not answer stops the run, named, instead of holding
/// it. (The thread is left to its provider; the run stops before the
/// freeze.)
fn hydrate_within(
    at: std::path::PathBuf,
    read_through: bool,
    timeout: std::time::Duration,
) -> std::result::Result<(), String> {
    let (sent, answer) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(if read_through {
            read_whole(&at)
        } else {
            hydrate(&at)
        });
    });
    match answer.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(format!(
            "its provider did not bring it onto the volume within {} s",
            timeout.as_secs()
        )),
    }
}

#[cfg(windows)]
fn hydrate(at: &Path) -> std::result::Result<(), String> {
    n2r_win32::cloud_native::hydrate(at).map_err(|error| error.to_string())?;
    let report = n2r_win32::cloud_native::report(at).map_err(|error| error.to_string())?;
    if report.missing_bytes != 0 {
        return Err(format!(
            "{} of its {} bytes are still not on this device",
            report.missing_bytes, report.size
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn hydrate(_at: &Path) -> std::result::Result<(), String> {
    Err("the Cloud Files API is a Windows one".into())
}

/// Brings a placeholder whose provider fills it in as a program reads it
/// (ProjFS, a storage manager's recall) onto the volume: opened as any
/// program opens it, through its provider, and read to its end. Whether
/// it is then wholly on the volume is held at the freeze, from the raw
/// source.
fn read_whole(at: &Path) -> std::result::Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(at).map_err(|error| error.to_string())?;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// [`run`] with the download of one placeholder (`path` as a listing names
/// it) made by `fetch`: the records, the reporting and the refusal.
fn download(
    run: &Path,
    root: &str,
    planned: Vec<Download>,
    _authority: &SourceChangeAuthority,
    mut fetch: impl FnMut(&Download) -> std::result::Result<(), String>,
) -> Result<()> {
    let bytes = planned.iter().fold(0u64, |sum, download| {
        sum.saturating_add(download.missing_bytes)
    });
    write_new(
        &run.join(INTENT_FILE),
        &Record {
            kind: INTENT_KIND.into(),
            planned: planned.clone(),
            downloaded: Vec::new(),
            failed: Vec::new(),
        },
    )?;
    let noun = crate::plain_projection::placeholders_noun(planned.iter().map(Download::family));
    println!(
        "Downloading {} {noun}, {}, onto the volume {root} before it is frozen. This is not undone.",
        planned.len(),
        mib(bytes)
    );
    let (mut downloaded, mut failed) = (Vec::new(), Vec::new());
    let mut failed_families = Vec::new();
    for download in &planned {
        match fetch(download) {
            Ok(()) => downloaded.push(download.path.clone()),
            Err(error) => {
                failed_families.push(download.family());
                failed.push((download.path.clone(), error))
            }
        }
    }
    write_new(
        &run.join(AFTER_FILE),
        &Record {
            kind: AFTER_KIND.into(),
            planned,
            downloaded: downloaded.clone(),
            failed: failed.clone(),
        },
    )?;
    if !failed.is_empty() {
        let named_failures: Vec<String> = failed
            .iter()
            .map(|(path, error)| format!("{path} ({error})"))
            .collect();
        bail!(
            "{} {} could not be downloaded before the volume was frozen: {}. The volume was not frozen and nothing was converted; the {} placeholder(s) that were downloaded stay on it. {}{}",
            failed.len(),
            crate::plain_projection::placeholders_noun(failed_families.iter().copied()),
            named(&named_failures),
            downloaded.len(),
            crate::plain_projection::remedies(failed_families),
            match LEAVE_OUT_LIST
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
            {
                Some(sha) => format!(
                    ". To leave them out, run again and agree to it, unattended with --leave-out-cloud {sha}"
                ),
                None => String::new(),
            }
        );
    }
    println!(
        "Downloaded {} {noun} before the freeze; they stay on the volume whatever happens to the conversion.",
        downloaded.len()
    );
    // A line a watcher can wait for (the lab stops its provider on it).
    println!(
        "{}",
        serde_json::json!({"kind": "cloud-downloads-done-v1", "downloaded": downloaded.len()})
    );
    Ok(())
}

/// What a cancellation, a rollback or a run that stopped says of the
/// downloads it made before the freeze, which none of them undoes. `None`
/// when the run made none.
pub(crate) fn note(run: &Path) -> Option<String> {
    let read = |name: &str| -> Option<Record> {
        serde_json::from_slice(&std::fs::read(run.join(name)).ok()?).ok()
    };
    let intent = read(INTENT_FILE)?;
    let downloaded = match read(AFTER_FILE) {
        Some(after) => after.downloaded.len().to_string(),
        None => format!("up to {}", intent.planned.len()),
    };
    Some(format!(
        "Before the volume was frozen this run downloaded {downloaded} {} onto it from their provider ({} in its records). That was a change before the freeze and is not undone: those files stay on the volume, downloaded.",
        crate::plain_projection::placeholders_noun(intent.planned.iter().map(Download::family)),
        run.join(INTENT_FILE).display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use n2r_win32::cloud_native::{FileRange, file_report};

    fn finding(path: &str, present: u64, running: Option<bool>) -> CloudFinding {
        CloudFinding {
            path: path.into(),
            directory: false,
            family: crate::plain_projection::PlaceholderFamily::Cloud,
            report: Ok(file_report(
                4096,
                &[FileRange {
                    offset: 0,
                    length: present,
                }],
                None,
            )),
            sync_root: running.map(|running| {
                Ok(SyncRoot {
                    provider: "Lab".into(),
                    status: if running { 1 } else { 0 },
                })
            }),
        }
    }

    fn agreed(paths: &[&str]) -> PlainList {
        PlainList::new(
            paths
                .iter()
                .map(|path| PlainEntry {
                    kind: PlainKind::CloudPlaceholderPlain,
                    path: (*path).into(),
                    cleared_attributes: 0,
                    bytes: 4096,
                    volume_extra_bytes: 0,
                    working_extra_bytes: 4096,
                    download_bytes: 0,
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn what_is_not_on_the_volume_is_downloaded_unless_it_is_left_out() {
        let findings = [
            finding("\\c\\full.txt", 4096, None),
            finding("\\c\\half.txt", 2048, Some(true)),
            finding("\\c\\none.txt", 0, Some(false)),
        ];
        let list = agreed(&["\\c\\full.txt", "\\c\\half.txt", "\\c\\none.txt"]);
        // Whatever a provider reports of itself, each is downloaded.
        let plan = plan_for(&findings, &list, &BTreeSet::new());
        assert_eq!(
            plan,
            [
                Download {
                    path: "\\c\\half.txt".into(),
                    missing_bytes: 2048,
                    kind: PlainKind::CloudPlaceholderPlain,
                },
                Download {
                    path: "\\c\\none.txt".into(),
                    missing_bytes: 4096,
                    kind: PlainKind::CloudPlaceholderPlain,
                }
            ]
        );
        let left_out: BTreeSet<String> = ["\\c\\none.txt".to_owned()].into();
        assert_eq!(plan_for(&findings, &list, &left_out).len(), 1);
        // Nothing outside the agreed list is downloaded.
        assert!(plan_for(&findings, &agreed(&["\\c\\full.txt"]), &BTreeSet::new()).is_empty());
        // Both not wholly here may be left out.
        assert_eq!(leave_out_list(&findings).unwrap().len(), 2);
    }

    #[test]
    fn a_providers_status_is_reported_and_refuses_nothing() {
        let findings = [
            finding("\\c\\full.txt", 4096, None),
            finding("\\c\\none.txt", 0, Some(false)),
        ];
        // Not refused: the run tries the download, and names it if it fails.
        assert!(refusals(&findings, &BTreeSet::new()).is_empty());
        let text = summary(&findings).join("\n");
        assert!(
            text.contains("1 file(s) are wholly on this device, 0 partly and 1 not at all")
                && text.contains("1 MiB are downloaded")
                && text.contains("\\c\\none.txt (Lab, status 0x0)")
                && text.contains("for information"),
            "{text}"
        );
        // A provider that does not answer within its time is named.
        assert_eq!(timeout_for(0).as_secs(), 60);
        assert_eq!(timeout_for(10 << 20).as_secs(), 70);
    }

    #[test]
    fn what_is_not_here_may_be_left_out_whole_and_bound_to_its_list() {
        use crate::plain_consent::Decision;
        let folder = |path: &str, state| CloudFinding {
            path: path.into(),
            directory: true,
            family: crate::plain_projection::PlaceholderFamily::Cloud,
            report: Ok(n2r_win32::cloud_native::directory_report(state, None)),
            sync_root: None,
        };
        let findings = [
            finding("\\c\\full.txt", 4096, None),
            finding("\\c\\up.txt", 0, Some(true)),
            finding("\\c\\down.txt", 0, Some(false)),
            folder("\\c\\unlisted", 0x11),
            finding("\\c\\unlisted\\x.txt", 0, Some(false)),
            folder("\\c\\listed", 0x1),
        ];
        // What is not wholly here; what is below a folder left out goes
        // with it and is not named apart.
        let list = leave_out_list(&findings).unwrap();
        let paths: Vec<_> = list.entries().iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["\\c\\down.txt", "\\c\\unlisted", "\\c\\up.txt"]);
        // A check refuses nothing that may be left out; a run that does not
        // leave out the folder its provider has not listed is refused.
        assert!(check_refusals(&findings).unwrap().is_empty());
        let left = paths_of(&list);
        assert!(refusals(&findings, &left).is_empty());
        assert_eq!(refusals(&findings, &BTreeSet::new()).len(), 1);
        let agreed = agreed(&[
            "\\c\\full.txt",
            "\\c\\up.txt",
            "\\c\\down.txt",
            "\\c\\unlisted\\x.txt",
        ]);
        assert!(plan_for(&findings, &agreed, &left).is_empty());
        let down: BTreeSet<String> = ["\\c\\unlisted".to_owned()].into();
        assert_eq!(plan_for(&findings, &agreed, &down).len(), 2);
        // Bound to the exact list; unattended and not named, they are
        // downloaded, not left out.
        let sha = list.sha256();
        assert_eq!(
            decide_leave_out(&list, Some(&sha), true).unwrap(),
            Decision::Accepted
        );
        assert_eq!(
            decide_leave_out(&list, Some(&sha), false).unwrap(),
            Decision::Ask
        );
        assert_eq!(decide_leave_out(&list, None, false).unwrap(), Decision::Ask);
        assert_eq!(
            decide_leave_out(&list, None, true).unwrap(),
            Decision::Nothing
        );
        let other = "0".repeat(64);
        assert!(decide_leave_out(&list, Some(&other), true).is_err());
        assert_eq!(
            decide_leave_out(&PlainList::default(), None, true).unwrap(),
            Decision::Nothing
        );
        assert!(decide_leave_out(&PlainList::default(), Some(&sha), true).is_err());
        assert!(parse_leave_out(&"AB".repeat(32)).is_ok() && parse_leave_out("ab").is_err());
        let asked = leave_out_question(&list);
        assert!(asked.contains("depends on its provider") && asked.contains("try to retrieve"));
    }

    #[test]
    fn a_provider_still_connected_is_named_and_left_to_the_user() {
        let note = close_provider_note(&["ntfs2refs lab provider".into()]);
        assert!(
            note.starts_with("The downloads are done. Close ntfs2refs lab provider")
                && note.contains("taken offline")
                && note.contains("does not close it"),
            "{note}"
        );
        assert_eq!(PROVIDER_CLOSE_PATIENCE.as_secs(), 300);
    }

    #[test]
    fn a_projfs_placeholder_is_read_through_its_provider_or_left_out_as_its_own() {
        let projected = crate::plain_projection::Placeholder {
            family: crate::plain_projection::PlaceholderFamily::Projfs,
            tag: n2r_win32::plain_ledger::PROJFS_TAG,
            directory: false,
            plain_bytes: 4096,
            raw_missing_bytes: 4096,
        };
        // As the raw reading shows it: nothing of it on the volume.
        let report = raw_report(&projected);
        assert_eq!(report.missing_bytes, 4096);
        assert!(report.needs_download());
        let findings = find("V:\\", &[("\\p\\a.txt".to_owned(), projected)]);
        assert_eq!(
            findings[0].family,
            crate::plain_projection::PlaceholderFamily::Projfs
        );
        assert!(findings[0].sync_root.is_none());
        let plan = plan_for(
            &findings,
            &agreed_as(&["\\p\\a.txt"], PlainKind::ProjfsPlaceholderPlain),
            &BTreeSet::new(),
        );
        assert_eq!(plan.len(), 1);
        assert!(plan[0].read_through());
        let list = leave_out_list(&findings).unwrap();
        assert_eq!(list.entries()[0].kind, PlainKind::ProjfsLeftOut);
        // A placeholder folder is listed in full: nothing to download.
        let folder = raw_report(&crate::plain_projection::Placeholder {
            directory: true,
            plain_bytes: 0,
            raw_missing_bytes: 0,
            ..projected
        });
        assert!(!folder.needs_download());
    }

    #[test]
    fn a_storage_managers_file_is_recalled_through_it_or_left_out_as_its_own() {
        let moved = crate::plain_projection::Placeholder {
            family: crate::plain_projection::PlaceholderFamily::Hsm,
            tag: n2r_win32::plain_ledger::HSM_TAGS[0],
            directory: false,
            plain_bytes: 8192,
            raw_missing_bytes: 8192,
        };
        let findings = find("V:\\", &[("\\h\\moved.dat".to_owned(), moved)]);
        assert!(findings[0].needs_download() && findings[0].sync_root.is_none());
        let plan = plan_for(
            &findings,
            &agreed_as(&["\\h\\moved.dat"], PlainKind::HsmRecalled),
            &BTreeSet::new(),
        );
        assert_eq!(plan[0].kind, PlainKind::HsmRecalled);
        assert!(plan[0].read_through());
        let list = leave_out_list(&findings).unwrap();
        assert_eq!(list.entries()[0].kind, PlainKind::HsmLeftOut);
        let asked = leave_out_question(&list);
        assert!(
            asked.contains("1 storage manager's file(s)")
                && asked.contains("depends on its provider or storage manager"),
            "{asked}"
        );
        // A recall that fails is named with the manager's remedy, not the
        // cloud's.
        let directory = tempfile::tempdir().unwrap();
        let authority = ExecutionMode::Convert
            .source_change_authority("test")
            .unwrap();
        let refused = download(directory.path(), "V:\\", plan, &authority, |_| {
            Err("the storage manager did not answer".into())
        })
        .unwrap_err()
        .to_string();
        assert!(
            refused.starts_with("1 storage manager's file(s) could not be downloaded")
                && refused.contains(crate::plain_projection::HSM_REMEDY)
                && !refused.contains("OneDrive"),
            "{refused}"
        );
        // A record of an older run, without the kind, reads as a cloud one.
        let old: Download =
            serde_json::from_str(r#"{"path":"\\c\\a.txt","missing_bytes":1}"#).unwrap();
        assert!(!old.read_through());
    }

    fn agreed_as(paths: &[&str], kind: PlainKind) -> PlainList {
        PlainList::new(
            paths
                .iter()
                .map(|path| PlainEntry {
                    kind,
                    path: (*path).into(),
                    cleared_attributes: 0,
                    bytes: 4096,
                    volume_extra_bytes: 0,
                    working_extra_bytes: 4096,
                    download_bytes: 0,
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn what_cannot_be_named_or_asked_is_refused() {
        let unlisted = CloudFinding {
            path: "\\c\\folder".into(),
            directory: true,
            family: crate::plain_projection::PlaceholderFamily::Cloud,
            report: Ok(n2r_win32::cloud_native::directory_report(0x11, None)),
            sync_root: None,
        };
        let unasked = CloudFinding {
            path: "\\c\\x".into(),
            directory: false,
            family: crate::plain_projection::PlaceholderFamily::Cloud,
            report: Err("access denied".into()),
            sync_root: None,
        };
        let refused = refusals(&[unlisted, unasked], &BTreeSet::new());
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused[0].contains("\\c\\folder") && refused[0].contains("listed in full"));
        assert!(refused[1].contains("\\c\\x (access denied)"));
    }

    #[test]
    fn the_check_reports_the_downloads_and_never_makes_them() {
        let mut entries = agreed(&["\\c\\half.txt"]).entries().to_vec();
        apply_downloads(&mut entries, &[finding("\\c\\half.txt", 1024, Some(true))]);
        assert_eq!(entries[0].download_bytes, 3072);
        // Diagnose has no authority to download.
        set_plan(vec![Download {
            path: "\\c\\half.txt".into(),
            missing_bytes: 3072,
            kind: PlainKind::CloudPlaceholderPlain,
        }]);
        let directory = tempfile::tempdir().unwrap();
        let refused = run(directory.path(), "V:\\", ExecutionMode::Diagnose)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("never changes the source"), "{refused}");
        assert!(!directory.path().join(INTENT_FILE).exists());
        // Nothing planned: nothing done, nothing recorded.
        assert!(run(directory.path(), "V:\\", ExecutionMode::Convert).is_ok());
        assert!(note(directory.path()).is_none());
    }

    #[test]
    fn every_download_is_recorded_and_a_failure_is_named() {
        let directory = tempfile::tempdir().unwrap();
        let authority = ExecutionMode::Convert
            .source_change_authority("test")
            .unwrap();
        let planned = vec![
            Download {
                path: "\\c\\a.txt".into(),
                missing_bytes: 10,
                kind: PlainKind::CloudPlaceholderPlain,
            },
            Download {
                path: "\\c\\b.txt".into(),
                missing_bytes: 20,
                kind: PlainKind::CloudPlaceholderPlain,
            },
        ];
        let refused = download(directory.path(), "V:\\", planned, &authority, |path| {
            if path.path.ends_with("b.txt") {
                Err("its cloud provider is not running".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err()
        .to_string();
        assert!(
            refused.contains("1 cloud placeholder(s) could not be downloaded")
                && refused.contains("\\c\\b.txt (its cloud provider is not running)")
                && refused.contains("the 1 placeholder(s) that were downloaded stay"),
            "{refused}"
        );
        let after: Record =
            serde_json::from_slice(&std::fs::read(directory.path().join(AFTER_FILE)).unwrap())
                .unwrap();
        assert_eq!(after.downloaded, ["\\c\\a.txt"]);
        assert_eq!(after.failed.len(), 1);
        let said = note(directory.path()).unwrap();
        assert!(
            said.contains("downloaded 1 cloud placeholder(s)") && said.contains("not undone"),
            "{said}"
        );
        // The records are never overwritten: a second step is refused.
        assert!(download(directory.path(), "V:\\", vec![], &authority, |_| Ok(())).is_err());
    }
}
