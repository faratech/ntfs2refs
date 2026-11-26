//! The user's consent to converting objects to plain files.
//!
//! Nothing is made plain silently. A data-volume run (a check, a diagnose
//! run, a conversion) is *offered* plain conversions: its check before the
//! freeze counts the objects instead of refusing them, and writes the list
//! of them to a file. A check stops there and exits
//! [`crate::drive_cli::EXIT_CHECK_PLAIN`]. A run then asks its own
//! question, apart from the one that starts the conversion, naming the
//! list's SHA-256; an unattended run (`--yes`) answers it only with
//! `--accept-plain` and that same SHA-256. Once the source is frozen, the
//! objects it holds that are converted to plain must all be in the agreed
//! list ([`bind`]): a file that gained such an attribute meanwhile stops
//! the run before anything is built.
//!
//! Every other route (a Windows boot volume, the running Windows) is never
//! offered, and refuses such objects as before.
use crate::plain_projection::PlainList;
use anyhow::{Result, bail};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

enum State {
    /// Objects that would be made plain are refused.
    Refused,
    /// They are counted and listed, not refused: nothing is agreed yet.
    Offered,
    /// The user agreed to this list.
    Agreed(PlainList),
}

static STATE: Mutex<State> = Mutex::new(State::Refused);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A data-volume run: objects that would be made plain are counted and
/// listed instead of refused, until the user answers.
pub(crate) fn offer_for_this_run() {
    let mut state = state();
    if matches!(*state, State::Refused) {
        *state = State::Offered;
    }
}

/// Whether this run takes objects to plain (offered or agreed) rather than
/// refusing them.
pub(crate) fn takes_plain() -> bool {
    !matches!(*state(), State::Refused)
}

/// The user agreed to `list`.
pub(crate) fn agree(list: PlainList) {
    *state() = State::Agreed(list);
}

/// Pure: `agreed` with the placeholders of `left` left out instead: every
/// entry within a path of `left` (the path itself, or below a folder of
/// it) goes, and `left`'s own entries come in.
pub(crate) fn with_left_out(agreed: &PlainList, left: &PlainList) -> Result<PlainList> {
    let mut entries: Vec<_> = agreed
        .entries()
        .iter()
        .filter(|entry| {
            !left
                .entries()
                .iter()
                .any(|gone| crate::plain_projection::within(&entry.path, &gone.path))
        })
        .cloned()
        .collect();
    entries.extend(left.entries().iter().cloned());
    PlainList::new(entries).map_err(anyhow::Error::msg)
}

/// The user agreed, besides the list, to leave out the placeholders of
/// `left` (`cloud_left_out`): the run's agreed list is the one with them
/// left out.
pub(crate) fn leave_out(left: &PlainList) -> Result<()> {
    let mut state = state();
    let State::Agreed(agreed) = &*state else {
        bail!("placeholders are left out only of a list that was agreed");
    };
    *state = State::Agreed(with_left_out(agreed, left)?);
    Ok(())
}

/// The paths this run agreed to leave out.
pub(crate) fn left_out_paths() -> std::collections::BTreeSet<String> {
    match &*state() {
        State::Agreed(list) => list
            .entries()
            .iter()
            .filter(|entry| entry.kind == n2r_win32::plain_ledger::PlainKind::CloudLeftOut)
            .map(|entry| entry.path.clone())
            .collect(),
        _ => Default::default(),
    }
}

/// What the frozen source would make plain, held to what was agreed. The
/// SHA-256 of the agreed list, when every object of `frozen` is in it.
pub(crate) fn bind(frozen: &PlainList, agreed: Option<&PlainList>) -> Result<String> {
    let Some(agreed) = agreed else {
        if frozen.is_empty() {
            return Ok(PlainList::default().sha256());
        }
        bail!(
            "{} object(s) of the frozen source would be converted to plain files (for example {}), and no list of them was agreed before the volume was frozen. Nothing was changed: run again, and answer the question about them",
            frozen.len(),
            frozen.entries()[0].path
        );
    };
    let missing = frozen.not_in(agreed);
    if let Some(first) = missing.first() {
        bail!(
            "{} object(s) of the frozen source would be converted to plain files that are not in the list agreed before the volume was frozen (for example {}, {}). The volume changed after the question was answered. Nothing was changed: run again, and answer the question for the list as it is then",
            missing.len(),
            first.path,
            first.kind
        );
    }
    Ok(agreed.sha256())
}

/// [`bind`] against what this run agreed to.
pub(crate) fn bind_frozen(frozen: &PlainList) -> Result<String> {
    match &*state() {
        State::Agreed(list) => bind(frozen, Some(list)),
        _ => bind(frozen, None),
    }
}

static LEDGER_DIRECTORY: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Where this run keeps its ledger of plain conversions: its own directory,
/// which outlives the run. (The source admission's working files are
/// temporary files of the run's arena and are retired with it.)
pub(crate) fn keep_ledger_in(run: &Path) {
    *LEDGER_DIRECTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(run.to_owned());
}

/// The run's own directory, where one was named.
pub(crate) fn run_directory() -> Option<PathBuf> {
    LEDGER_DIRECTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Writes the ledger to the run's directory, as a file of its own that is
/// never overwritten, and flushes it. Where it went; `None` for a route
/// that names no directory.
pub(crate) fn write_ledger(
    ledger: &n2r_win32::plain_ledger::PlainLedger,
) -> Result<Option<PathBuf>> {
    let directory = LEDGER_DIRECTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    directory
        .map(|directory| write_ledger_in(&directory, ledger))
        .transpose()
}

pub(crate) fn write_ledger_in(
    directory: &Path,
    ledger: &n2r_win32::plain_ledger::PlainLedger,
) -> Result<PathBuf> {
    use std::io::Write;
    ledger.validate().map_err(anyhow::Error::msg)?;
    let path = directory.join(n2r_win32::plain_ledger::LEDGER_FILE);
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        serde_json::to_writer_pretty(&mut file, ledger)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    written.map_err(|error| {
        anyhow::anyhow!(
            "writing the ledger of plain conversions to {}: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

/// Reads `--accept-plain`: a SHA-256 as a check prints it.
pub(crate) fn parse_accept(text: &str) -> std::result::Result<String, String> {
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(format!(
            "--accept-plain takes the SHA-256 of a plain-conversions list as `--check` prints it (64 hexadecimal digits), not {text:?}"
        ))
    }
}

/// How a run reaches its answer for a list.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Nothing is made plain: there is nothing to ask.
    Nothing,
    /// The user is asked.
    Ask,
    /// Answered yes by `--yes --accept-plain` naming this list.
    Accepted,
}

/// Pure: what a run does with `list`, given `--accept-plain` and whether
/// `--yes` answers its questions.
pub(crate) fn decide(list: &PlainList, accept: Option<&str>, unattended: bool) -> Result<Decision> {
    if list.is_empty() {
        return Ok(Decision::Nothing);
    }
    let sha = list.sha256();
    match accept {
        Some(named) if named == sha => Ok(if unattended {
            Decision::Accepted
        } else {
            Decision::Ask
        }),
        Some(named) => bail!(
            "--accept-plain names the list {named}, and the list of objects this run would convert to plain files is {sha}: the volume is not as it was when that list was made. Nothing was changed. Read the list again (--check) and agree to it as it is"
        ),
        None if unattended => bail!(
            "{} object(s) would be converted to plain files (list sha256 {sha}). --yes does not agree to that by itself: add --accept-plain {sha} after reading the list. Nothing was changed",
            list.len()
        ),
        None => Ok(Decision::Ask),
    }
}

fn mib(bytes: u64) -> String {
    format!("{} MiB", bytes.div_ceil(1 << 20))
}

/// The "Converted to plain" section a check and a run print.
pub(crate) fn section(list: &PlainList, list_file: Option<&Path>) -> Vec<String> {
    let mut lines = vec![format!(
        "Converted to plain: {} object(s) have a feature ReFS does not have. A conversion makes each a plain file, and only after you agree to the list:",
        list.len()
    )];
    let (mut volume, mut working, mut download) = (0u64, 0u64, 0u64);
    for (kind, total) in list.totals() {
        lines.push(format!(
            "  {kind}: {} object(s), {} of data; {}.",
            total.objects,
            mib(total.bytes),
            kind.describe()
        ));
        volume = volume.saturating_add(total.volume_extra_bytes);
        working = working.saturating_add(total.working_extra_bytes);
        download = download.saturating_add(total.download_bytes);
    }
    lines.push(format!(
        "  Extra space: {} on the new volume, {} in the working storage; {} to download before the volume is frozen.",
        mib(volume),
        mib(working),
        mib(download)
    ));
    if list
        .entries()
        .iter()
        .any(|entry| entry.kind == n2r_win32::plain_ledger::PlainKind::EfsDecrypted)
    {
        lines.extend(
            EFS_WARNINGS
                .iter()
                .map(|warning| format!("  Warning: {warning}")),
        );
    }
    if list.entries().iter().any(|entry| {
        matches!(
            entry.kind,
            n2r_win32::plain_ledger::PlainKind::CloudPlaceholderPlain
                | n2r_win32::plain_ledger::PlainKind::CloudLeftOut
        )
    }) {
        lines.push(format!(
            "  Warning: {}.",
            crate::plain_projection::CLOUD_WARNING
        ));
    }
    for entry in list.entries().iter().take(5) {
        lines.push(format!("  {} ({})", entry.path, entry.kind));
    }
    if list.len() > 5 {
        lines.push(format!("  and {} more.", list.len() - 5));
    }
    match list_file {
        Some(file) => lines.push(format!(
            "  The full list: {} (sha256 {}).",
            file.display(),
            list.sha256()
        )),
        None => lines.push(format!("  The list's sha256: {}.", list.sha256())),
    }
    lines
}

/// What a user agrees to with EFS files made plain.
pub(crate) const EFS_WARNINGS: [&str; 3] = [
    "EFS-encrypted files are decrypted: on the new volume anyone their permissions allow can read them, with no key",
    "their plain text is also kept in the run's working storage (plain-copies in the run's folder) until the run ends and deletes it",
    "to keep them protected at rest, turn BitLocker on for the new volume and for the working storage's",
];

/// The question a run asks, apart from the one that starts it.
pub(crate) fn question(list: &PlainList) -> String {
    format!(
        "Convert these {} object(s) to plain files (list sha256 {})? [y/N]",
        list.len(),
        list.sha256()
    )
}

/// Writes the list where the user can read it, under `directory`, and says
/// where. The name carries the start of its checksum, so that two lists
/// never share a file.
pub(crate) fn write_list(directory: &Path, list: &PlainList) -> Result<PathBuf> {
    let path = directory.join(format!("plain-conversions-{}.txt", &list.sha256()[..16]));
    std::fs::write(&path, list.text())
        .map_err(|error| anyhow::anyhow!("writing the list to {}: {error}", path.display()))?;
    Ok(path)
}

/// Says what would be made plain, and asks. `Ok(true)` when the user
/// agreed (or there is nothing to agree to); the list is then this run's.
pub(crate) fn ask(
    list: &PlainList,
    accept: Option<&str>,
    list_file: Option<&Path>,
) -> Result<bool> {
    let decision = decide(list, accept, crate::confirmation::assumed())?;
    if decision == Decision::Nothing {
        agree(PlainList::default());
        return Ok(true);
    }
    for line in section(list, list_file) {
        println!("{line}");
    }
    println!("{}", question(list));
    let yes = if decision == Decision::Accepted {
        println!("yes (--yes --accept-plain {})", list.sha256());
        true
    } else {
        print!("> ");
        crate::confirmation::answer()?
    };
    if yes {
        agree(list.clone());
    }
    Ok(yes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plain_projection::{PlainEntry, PlainKind};

    fn list(paths: &[(&str, u32)]) -> PlainList {
        PlainList::new(
            paths
                .iter()
                .map(|(path, cleared)| PlainEntry {
                    kind: PlainKind::AttributesCleared,
                    path: (*path).to_owned(),
                    cleared_attributes: *cleared,
                    bytes: 3000,
                    volume_extra_bytes: 0,
                    working_extra_bytes: 0,
                    download_bytes: 0,
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn yes_alone_never_agrees_to_a_list() {
        let found = list(&[("\\t.tmp", 0x100)]);
        let sha = found.sha256();
        assert_eq!(decide(&found, None, false).unwrap(), Decision::Ask);
        let refused = decide(&found, None, true).unwrap_err().to_string();
        assert!(
            refused.contains(&format!("--accept-plain {sha}")),
            "{refused}"
        );
        assert_eq!(
            decide(&found, Some(&sha), true).unwrap(),
            Decision::Accepted
        );
        // Named without --yes, the user is still asked.
        assert_eq!(decide(&found, Some(&sha), false).unwrap(), Decision::Ask);
        // Another list is refused, asked or not.
        let other = "0".repeat(64);
        for unattended in [false, true] {
            let refused = decide(&found, Some(&other), unattended)
                .unwrap_err()
                .to_string();
            assert!(
                refused.contains(&sha) && refused.contains("Nothing was changed"),
                "{refused}"
            );
        }
        // Nothing to make plain: nothing to ask, with or without --yes.
        assert_eq!(
            decide(&PlainList::default(), None, true).unwrap(),
            Decision::Nothing
        );
    }

    #[test]
    fn the_frozen_list_must_be_a_subset_of_the_agreed_one() {
        let agreed = list(&[("\\a", 0x100), ("\\b", 0x1000)]);
        let sha = agreed.sha256();
        assert_eq!(bind(&list(&[("\\b", 0x1000)]), Some(&agreed)).unwrap(), sha);
        assert_eq!(bind(&agreed, Some(&agreed)).unwrap(), sha);
        assert_eq!(bind(&PlainList::default(), Some(&agreed)).unwrap(), sha);
        let grown = bind(&list(&[("\\a", 0x100), ("\\c", 0x100)]), Some(&agreed))
            .unwrap_err()
            .to_string();
        assert!(
            grown.contains("\\c") && grown.contains("1 object(s)"),
            "{grown}"
        );
        // A run that agreed to nothing (its check could not read the volume).
        assert!(bind(&PlainList::default(), None).is_ok());
        let unasked = bind(&agreed, None).unwrap_err().to_string();
        assert!(unasked.contains("no list of them was agreed"), "{unasked}");
    }

    #[test]
    fn a_list_with_placeholders_left_out_holds_them_and_what_is_below_them() {
        let entry = |path: &str, kind| PlainEntry {
            kind,
            path: path.into(),
            cleared_attributes: 0,
            bytes: 1,
            volume_extra_bytes: 0,
            working_extra_bytes: 0,
            download_bytes: 0,
        };
        let agreed = PlainList::new(vec![
            entry("\\c\\a.bin", PlainKind::CloudPlaceholderPlain),
            entry("\\c\\folder", PlainKind::CloudPlaceholderPlain),
            entry("\\c\\folder\\x.bin", PlainKind::CloudPlaceholderPlain),
            entry("\\c\\kept.bin", PlainKind::CloudPlaceholderPlain),
        ])
        .unwrap();
        let left = PlainList::new(vec![
            entry("\\c\\a.bin", PlainKind::CloudLeftOut),
            entry("\\c\\folder", PlainKind::CloudLeftOut),
        ])
        .unwrap();
        let both = with_left_out(&agreed, &left).unwrap();
        let shown: Vec<_> = both
            .entries()
            .iter()
            .map(|e| (e.path.as_str(), e.kind))
            .collect();
        assert_eq!(
            shown,
            [
                ("\\c\\a.bin", PlainKind::CloudLeftOut),
                ("\\c\\folder", PlainKind::CloudLeftOut),
                ("\\c\\kept.bin", PlainKind::CloudPlaceholderPlain),
            ]
        );
        // What the frozen source then finds below the folder is agreed.
        let frozen = PlainList::new(vec![
            entry("\\c\\folder\\x.bin", PlainKind::CloudLeftOut),
            entry("\\c\\kept.bin", PlainKind::CloudPlaceholderPlain),
        ])
        .unwrap();
        assert!(bind(&frozen, Some(&both)).is_ok());
        // Made plain where it was agreed left out: not agreed.
        let made =
            PlainList::new(vec![entry("\\c\\a.bin", PlainKind::CloudPlaceholderPlain)]).unwrap();
        assert!(bind(&made, Some(&both)).is_err());
    }

    #[test]
    fn the_ledger_is_kept_in_a_file_of_its_own_that_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = n2r_win32::plain_ledger::PlainLedger {
            kind: n2r_win32::plain_ledger::LEDGER_KIND.into(),
            agreed_list_sha256: "a".repeat(64),
            frozen_list_sha256: "b".repeat(64),
            source_inspection_sha256: "c".repeat(64),
            rows: Vec::new(),
        };
        let path = write_ledger_in(directory.path(), &ledger).unwrap();
        assert_eq!(path, directory.path().join("plain-conversions.json"));
        let back: n2r_win32::plain_ledger::PlainLedger =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, ledger);
        assert!(write_ledger_in(directory.path(), &ledger).is_err());
        // Nowhere named: nothing is written, and that is no error.
        assert!(write_ledger(&ledger).unwrap().is_none());
    }

    #[test]
    fn an_accepted_checksum_is_sixty_four_hex_digits() {
        let sha = "AB".repeat(32);
        assert_eq!(parse_accept(&sha), Ok("ab".repeat(32)));
        assert!(parse_accept("ab").is_err());
        assert!(parse_accept(&"g".repeat(64)).is_err());
    }

    #[test]
    fn the_section_names_each_kind_the_space_and_the_list() {
        let found = list(&[("\\a\\t.tmp", 0x100), ("\\b\\o.dat", 0x1000)]);
        let text = section(&found, Some(Path::new("S:\\runs\\plain.txt"))).join("\n");
        assert!(
            text.starts_with("Converted to plain: 2 object(s)"),
            "{text}"
        );
        assert!(
            text.contains("attributes_cleared: 2 object(s), 1 MiB of data"),
            "{text}"
        );
        assert!(
            text.contains("Extra space: 0 MiB on the new volume"),
            "{text}"
        );
        assert!(text.contains("\\a\\t.tmp (attributes_cleared)"), "{text}");
        assert!(
            text.contains(&format!("S:\\runs\\plain.txt (sha256 {})", found.sha256())),
            "{text}"
        );
        assert!(!text.contains("do not run on ReFS"), "{text}");
        // A cloud placeholder: the sync stops, and the user is told so.
        let cloud = PlainList::new(vec![PlainEntry {
            kind: PlainKind::CloudPlaceholderPlain,
            path: "\\OneDrive\\a.txt".into(),
            cleared_attributes: 0,
            bytes: 10,
            volume_extra_bytes: 0,
            working_extra_bytes: 10,
            download_bytes: 3 << 20,
        }])
        .unwrap();
        let text = section(&cloud, None).join("\n");
        assert!(
            text.contains(
                "Warning: OneDrive and other Cloud Files API providers do not run on ReFS"
            ) && text.contains("3 MiB to download before the volume is frozen"),
            "{text}"
        );
        let asked = question(&found);
        assert!(
            asked.starts_with("Convert these 2 object(s) to plain files (list sha256 ")
                && asked.ends_with("[y/N]"),
            "{asked}"
        );
    }

    #[test]
    fn the_list_file_holds_the_text_its_checksum_names() {
        let directory = tempfile::tempdir().unwrap();
        let found = list(&[("\\a", 0x100)]);
        let path = write_list(directory.path(), &found).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, found.text());
        use sha2::Digest;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(text.as_bytes())),
            found.sha256()
        );
    }
}
