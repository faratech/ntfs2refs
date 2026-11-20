//! Working volumes of runs that ended before they recorded anything to
//! recover from (#201). A run attaches its `shadow.vhdx` for the lifetime of
//! the machine and prints its first `--recover` command only once its
//! preparation intent is written. A run ended before that (its process
//! killed) leaves the image attached, online and writable, with no command
//! that detaches it, and its folder cannot be deleted.
//!
//! The next conversion run (`--drive`) and `--list` look for such images
//! among every virtual disk Windows has attached, wherever they lie, and
//! detach them, or name them where they may not. An image is taken only
//! when the folder it lies in is a run's of this tool (its selection and
//! creation-admission records), holds none of the records a recovery starts
//! from (those runs have their own command), and the run's liveness token
//! (`n2r_win32::run_liveness`) is gone: a run that is still going is never
//! touched. A folder made before runs held a token is only named.
use n2r_win32::{managed_shadow, run_liveness};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

/// The record, beside `drive-selection.json`, that says the run holds a
/// liveness token until its process ends.
pub(super) const TOKEN_RECORD: &str = "run-liveness.json";
const TOKEN_KIND: &str = "run-liveness-token-v1";

/// The records that make a folder a run's of this tool, written before its
/// working volume is created.
const RUN_RECORDS: [&str; 2] = [
    "drive-selection.json",
    "native-shadow-creation-admission.json",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenRecord {
    schema_version: u32,
    kind: String,
    /// The name of the kernel mutex the run holds until its process ends.
    mutex: String,
    process_id: u32,
    held_until_the_process_ends: bool,
}

impl TokenRecord {
    /// The record of the token this process holds, by the name it was
    /// created under.
    pub(super) fn of_this_process(mutex: String) -> Self {
        Self {
            schema_version: 1,
            kind: TOKEN_KIND.to_owned(),
            mutex,
            process_id: std::process::id(),
            held_until_the_process_ends: true,
        }
    }
}

/// What may be done with what is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Settle {
    /// Detach the images of runs that have ended: an elevated run that may
    /// change disks.
    Detach,
    /// Only say where they are: not elevated, or `--check`.
    Name,
}

/// What the folder of an attached `shadow.vhdx` says of it.
#[derive(Debug, PartialEq, Eq)]
enum Folder {
    /// Not a run of this tool's: left alone, and not spoken of.
    NotARun,
    /// The run recorded something to recover from; its own `--recover`
    /// command deals with the image.
    Recorded,
    /// Its run is still going.
    Running,
    /// Its run has ended without recording anything to recover from.
    Ended,
    /// Whether its run is still going is not known, for the reason given.
    Unknown(String),
}

/// The run folder an attached image lies in, when the image is a run's
/// working volume by its name.
fn run_of(image: &Path) -> Option<PathBuf> {
    let name = image.file_name()?.to_str()?;
    if !name.eq_ignore_ascii_case("shadow.vhdx") {
        return None;
    }
    Some(image.parent()?.to_path_buf())
}

/// Whether the run in `run` has a liveness record: `Ok(true)` for one this
/// tool wrote for that folder, `Ok(false)` when there is none, and an error
/// for anything else.
fn has_token_record(run: &Path, run_id: &str) -> Result<bool, String> {
    let path = run.join(TOKEN_RECORD);
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("reading {}: {error}", path.display())),
    };
    // The record is a few hundred bytes; more than this is not one of them.
    let mut bytes = Vec::new();
    if let Err(error) = file.by_ref().take(64 * 1024).read_to_end(&mut bytes) {
        return Err(format!("reading {}: {error}", path.display()));
    }
    let expected = run_liveness::token_name(run_id).map_err(|error| error.to_string())?;
    match serde_json::from_slice::<TokenRecord>(&bytes) {
        Ok(record)
            if record.schema_version == 1
                && record.kind == TOKEN_KIND
                && record.held_until_the_process_ends
                && record.mutex == expected =>
        {
            Ok(true)
        }
        _ => Err(format!(
            "{} is not the liveness record of this run",
            path.display()
        )),
    }
}

fn classify(run: &Path) -> Folder {
    if !RUN_RECORDS.iter().all(|name| run.join(name).is_file()) {
        return Folder::NotARun;
    }
    if !super::staging::recorded_nothing(run) {
        return Folder::Recorded;
    }
    let Some(run_id) = run.file_name().and_then(|name| name.to_str()) else {
        return Folder::NotARun;
    };
    match has_token_record(run, run_id) {
        Ok(true) => {}
        Ok(false) => {
            return Folder::Unknown(
                "it was made by an earlier version of ntfs2refs, which does not record that".into(),
            );
        }
        Err(why) => return Folder::Unknown(why),
    }
    match run_liveness::is_held(run_id) {
        Ok(true) => Folder::Running,
        Ok(false) => Folder::Ended,
        Err(error) => Folder::Unknown(error.to_string()),
    }
}

/// The diskpart commands that detach an image by hand.
fn by_hand(shadow: &Path) -> String {
    format!(
        "in diskpart, `select vdisk file=\"{}\"` and `detach vdisk`",
        shadow.display()
    )
}

/// Looks for the working volumes that runs which ended before recording
/// anything to recover from left attached, and detaches or names each, with
/// its run's folder. It never fails the command it runs in: what it cannot
/// do it says.
pub(super) fn settle(how: Settle) {
    let attached = match managed_shadow::attached_image_paths() {
        Ok(attached) => attached,
        // An unelevated `--list` may not be allowed to ask: a note at every
        // such listing would tell nothing new.
        Err(error) if how == Settle::Name && error.kind() == io::ErrorKind::PermissionDenied => {
            return;
        }
        Err(error) => {
            eprintln!(
                "Note: Windows did not list its attached virtual disks ({error}), so working volumes that ended runs may have left attached were not looked for."
            );
            return;
        }
    };
    for image in attached {
        let Some(run) = run_of(&image) else {
            continue;
        };
        // The run's own name for it, which is what is detached.
        let shadow = run.join("shadow.vhdx");
        match (classify(&run), how) {
            (Folder::NotARun | Folder::Recorded | Folder::Running, _) => {}
            (Folder::Ended, Settle::Detach) => match managed_shadow::detach_left_behind(&shadow) {
                Ok(true) => eprintln!(
                    "Detached {}, the working volume of a run that ended before it recorded anything to recover from. Nothing in {} is needed any more; the folder can be deleted.",
                    shadow.display(),
                    run.display()
                ),
                Ok(false) => {}
                Err(error) => eprintln!(
                    "Note: a run that ended before it recorded anything to recover from left its working volume {} attached, and it could not be detached ({error}). Detach it by hand, {}; then {} can be deleted.",
                    shadow.display(),
                    by_hand(&shadow),
                    run.display()
                ),
            },
            (Folder::Ended, Settle::Name) => eprintln!(
                "Note: a run that ended before it recorded anything to recover from left its working volume {} attached. `ntfs2refs --list` from an elevated terminal detaches it; or detach it by hand, {}. Then {} can be deleted.",
                shadow.display(),
                by_hand(&shadow),
                run.display()
            ),
            (Folder::Unknown(why), _) => eprintln!(
                "Note: {} is attached, the working volume of a run that recorded nothing to recover from; whether that run is still going is not known ({why}), so it was left alone. Once it is not, detach it by hand, {}, and delete {}.",
                shadow.display(),
                by_hand(&shadow),
                run.display()
            ),
        }
    }
}
