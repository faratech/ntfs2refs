//! Taking the persistent recovery selection back for a conversion that never
//! started. `cold::restore_normal_boot` does this for a closed journal and
//! keeps requiring one; this is the separate case beside it, for a journal
//! the caller has proved to be clear.
//!
//! Why it needs less than the closed case and is still sound: the closed
//! case ends a conversion, so it has to prove the installed store is byte
//! for byte the one the apply was guarded by. Here nothing was applied and
//! nothing will be: the store is only read for what it selects and three
//! elements of the boot manager are put back to the values recorded before
//! the first change. What is required instead is that the records are this
//! run's (in Windows the installed loader names the SHA-256 of the intent in
//! its load options; in the recovery environment the running kernel, which
//! was started through that loader, does), that each of the three elements
//! holds either the value this run installed or the recorded original, and
//! that every other element of the boot manager is the recorded one (its
//! device aside, which each start of Windows writes in its own words and
//! which stays single). Each setter is read back, and every other object of
//! the store is compared before and after where the store can be listed
//! whole. Private entries stay in the store, as after a conversion; nothing
//! is imported, deleted or written to firmware, and the firmware's own boot
//! entries are not looked at.
use super::*;

/// What the boot manager selects, of the states an installation passes
/// through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBootSelectionState {
    /// This run has no record of having changed the boot selection.
    NotInstalled,
    /// Default, order and timeout are the recorded original ones.
    Normal,
    /// All three select this run's recovery entry.
    Installed,
    /// Some of them do: an installation or a restoration was cut short.
    PartlyInstalled,
}

/// What a cancellation of the boot selection found and did.
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryBootCancellationReceipt {
    pub kind: &'static str,
    pub found: RecoveryBootSelectionState,
    pub restored_elements: Vec<String>,
    pub default: Option<String>,
    pub display_order: Vec<String>,
    pub timeout: Option<String>,
    pub private_entries_left_in_store: Vec<String>,
    /// Whether every other entry of the store was compared before and after
    /// and found unchanged. False with nothing restored, and false with the
    /// reason below where the store could not be listed whole.
    pub other_entries_compared_unchanged: bool,
    pub other_entries_not_compared: Option<String>,
    /// The folder of this cancellation's own records; absent where the
    /// store was not touched at all.
    pub records: Option<PathBuf>,
    pub source_writer_authority: bool,
}

type Fields = BTreeMap<String, Vec<String>>;

/// The elements to put back, in the order they are set: the recovery entry
/// stays the default until order and timeout have been read back, so that a
/// cut-short restoration starts the runner again, which finishes it.
#[derive(Debug, PartialEq, Eq)]
struct SelectionPlan {
    state: RecoveryBootSelectionState,
    restore: Vec<(&'static str, Vec<String>)>,
}

fn same_guid(actual: &str, expected: &str) -> bool {
    canonical_guid(actual).is_ok_and(|actual| actual == expected)
}

fn plan_selection(
    current: &Fields,
    original: &Selection,
    loader: &str,
) -> io::Result<SelectionPlan> {
    need(
        current.get("identifier") == Some(&vec![BOOTMGR.to_owned()]),
        "the boot manager entry of the store is not the Windows Boot Manager",
    )?;
    need(
        !current.contains_key("bootsequence"),
        "the boot manager has an entry set for the next start alone (a one-time boot sequence), which this run did not set",
    )?;
    for (key, value) in &original.all_fields {
        if matches!(key.as_str(), "default" | "displayorder" | "timeout") {
            continue;
        }
        if key == "device" {
            // The same device is written differently by another start of
            // Windows or by the recovery environment (a volume number, a
            // drive letter). It is not one of the elements changed here,
            // and every setter's effect on the store is compared.
            need(
                value.len() == 1 && current.get(key).is_some_and(|v| v.len() == 1),
                "the boot manager's device element is not single",
            )?;
            continue;
        }
        need(
            current.get(key) == Some(value),
            &format!(
                "the boot manager's element {key:?} is {:?}, and before this run it was {value:?}: something else changed the boot configuration",
                current.get(key).cloned().unwrap_or_default()
            ),
        )?;
    }
    let mut restore = Vec::new();
    let mut installed = 0;
    let order: Vec<String> = current.get("displayorder").cloned().unwrap_or_default();
    let order_is = |expected: &[String]| {
        order.len() == expected.len() && order.iter().zip(expected).all(|(a, e)| same_guid(a, e))
    };
    if order_is(&original.displayorder) {
    } else if order_is(std::slice::from_ref(&loader.to_owned())) {
        installed += 1;
        restore.push(("displayorder", original.displayorder.clone()));
    } else {
        return Err(bad(&format!(
            "the boot manager's display order is {order:?}: neither this run's recovery entry {loader} alone nor the order before it {:?}",
            original.displayorder
        )));
    }
    let timeout = one(current, "timeout")?;
    if timeout == original.timeout {
    } else if timeout == "0" {
        installed += 1;
        restore.push(("timeout", vec![original.timeout.clone()]));
    } else {
        return Err(bad(&format!(
            "the boot manager's timeout is {timeout}: neither this run's 0 nor the {} before it",
            original.timeout
        )));
    }
    let default = one(current, "default")?;
    if same_guid(default, &original.default) {
    } else if same_guid(default, loader) {
        installed += 1;
        restore.push(("default", vec![original.default.clone()]));
    } else {
        return Err(bad(&format!(
            "the boot manager's default is {default}: neither this run's recovery entry {loader} nor the default before it {}",
            original.default
        )));
    }
    // A timeout that was 0 before the run cannot tell the two states apart.
    let changeable = if original.timeout == "0" { 2 } else { 3 };
    let state = match installed {
        0 => RecoveryBootSelectionState::Normal,
        n if n == changeable => RecoveryBootSelectionState::Installed,
        _ => RecoveryBootSelectionState::PartlyInstalled,
    };
    Ok(SelectionPlan { state, restore })
}

/// This run's boot records: the guard intent (written before the selection
/// was changed, with its SHA-256) or, when the installation stopped earlier,
/// only the intent written before the first private entry was made.
struct BootRecords {
    intent: BootIntent,
    guard_sha256: Option<[u8; 32]>,
    /// The record `intent` was read from.
    path: PathBuf,
}

fn read_records(
    selection: &Path,
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    budget: RecoveryBootBudget,
) -> io::Result<Option<BootRecords>> {
    let guard_path = selection.join("recovery-boot-guard-intent.json");
    let original_path = selection.join("recovery-boot-original-intent.json");
    let exists = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => Ok(false),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("looking for the boot record {}: {error}", path.display()),
        )),
    };
    if !exists(&original_path)? {
        need(
            !exists(&guard_path)?,
            &format!(
                "the run has the boot record {} without {}, which is written before it",
                guard_path.display(),
                original_path.display()
            ),
        )?;
        return Ok(None);
    }
    let original_bytes =
        metadata::read_external(&original_path, journal, budget.maximum_control_bytes).map_err(
            |error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "reading the boot record {}: {error}",
                        original_path.display()
                    ),
                )
            },
        )?;
    let decode = |bytes: &[u8], path: &Path| {
        serde_json::from_slice::<BootIntent>(bytes).map_err(|error| {
            bad(&format!(
                "the boot record {} cannot be decoded: {error}",
                path.display()
            ))
        })
    };
    let original = decode(&original_bytes, &original_path)?;
    let require_ours = |intent: &BootIntent, path: &Path| {
        need(
            intent.version == 1
                && intent.kind == "ntfs2refs-persistent-recovery-boot-intent-v1"
                && !intent.serialized_intent_is_writer_authority
                && intent.source == *source
                && intent.journal == *journal,
            &format!(
                "the boot record {} is not this run's: it names another source or working volume, or is of another kind",
                path.display()
            ),
        )
    };
    require_ours(&original, &original_path)?;
    need(
        original.guarded_store_map.is_none() && original.parent_original_intent_sha256.is_none(),
        &format!(
            "the boot record {} is not the one written before the first change of the boot configuration",
            original_path.display()
        ),
    )?;
    if !exists(&guard_path)? {
        return Ok(Some(BootRecords {
            intent: original,
            guard_sha256: None,
            path: original_path,
        }));
    }
    let guard_bytes = metadata::read_external(&guard_path, journal, budget.maximum_control_bytes)
        .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("reading the boot record {}: {error}", guard_path.display()),
        )
    })?;
    let guard = decode(&guard_bytes, &guard_path)?;
    require_ours(&guard, &guard_path)?;
    let mut reconstructed = guard.clone();
    reconstructed.guarded_store_map = None;
    reconstructed.parent_original_intent_sha256 = None;
    reconstructed.private_encoded_objects = None;
    need(
        guard.parent_original_intent_sha256 == Some(digest(&original_bytes))
            && serde_json::to_vec(&original).map_err(io::Error::other)?
                == serde_json::to_vec(&reconstructed).map_err(io::Error::other)?,
        &format!(
            "the boot record {} does not carry the selection that {} recorded before the first change",
            guard_path.display(),
            original_path.display()
        ),
    )?;
    Ok(Some(BootRecords {
        intent: guard,
        guard_sha256: Some(digest(&guard_bytes)),
        path: guard_path,
    }))
}

fn receipt(
    found: RecoveryBootSelectionState,
    restored: Vec<String>,
    current: Option<&Fields>,
    private: Vec<String>,
    not_compared: Option<String>,
    records: Option<&Path>,
) -> RecoveryBootCancellationReceipt {
    RecoveryBootCancellationReceipt {
        kind: "unstarted-conversion-recovery-boot-selection-cancelled-v1",
        found,
        other_entries_compared_unchanged: !restored.is_empty() && not_compared.is_none(),
        other_entries_not_compared: not_compared,
        restored_elements: restored,
        default: current.and_then(|f| one(f, "default").ok().map(str::to_owned)),
        display_order: current
            .and_then(|f| f.get("displayorder").cloned())
            .unwrap_or_default(),
        timeout: current.and_then(|f| one(f, "timeout").ok().map(str::to_owned)),
        private_entries_left_in_store: private,
        records: records.map(Path::to_owned),
        source_writer_authority: false,
    }
}

/// How a store is named in an error: the system's, or the file it is.
fn store_name(store: Option<&Path>) -> String {
    match store {
        Some(path) => format!("the boot configuration store {}", path.display()),
        None => "the system's boot configuration store".to_owned(),
    }
}
/// An error of a step on a store, naming both.
fn at_store(error: io::Error, step: &str, store: Option<&Path>) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{step} in {}: {error}", store_name(store)),
    )
}

#[allow(clippy::too_many_arguments)]
fn cancel_selection(
    tool: &native::Tool,
    store: Option<&Path>,
    records: &BootRecords,
    recovery_environment: bool,
    directory: &Path,
    budget: RecoveryBootBudget,
    flush: &mut dyn FnMut(&mut Vec<NativeEvent>) -> io::Result<()>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<RecoveryBootCancellationReceipt> {
    let read_bootmgr = || {
        tool.enum_object(store, BOOTMGR, directory)
            .map_err(|error| at_store(error, "reading the boot manager entry", store))
    };
    let current = read_bootmgr()?;
    let intent = &records.intent;
    let original = selection(intent.original.all_fields.clone())
        .map_err(|error| at_store(error, "decoding the recorded original selection", store))?;
    need(
        original.default == intent.original.default
            && original.displayorder == intent.original.displayorder
            && original.timeout == intent.original.timeout,
        &format!(
            "the original boot selection recorded in {} is inconsistent with itself",
            records.path.display()
        ),
    )?;
    let plan = plan_selection(&current, &original, &intent.loader)
        .map_err(|error| at_store(error, "comparing the boot manager entry", store))?;
    let private = vec![intent.loader.clone(), intent.ramdisk_options.clone()];
    if plan.restore.is_empty() {
        return Ok(receipt(
            plan.state,
            Vec::new(),
            Some(&current),
            private,
            None,
            Some(directory),
        ));
    }
    // Something selects the recovery entry: it has to be this run's, bound
    // to this very record. In the recovery environment the caller has shown
    // that from the running kernel, which was started through this entry
    // with this record's hash in its options. In Windows the entry in the
    // store is read: it is the one this run derived its identifier for, and
    // its load options name the hash of this record. (Its device elements
    // are not compared: they are written with drive letters, which another
    // start of Windows may have changed, and nothing here depends on them.)
    let guard = records.guard_sha256.ok_or_else(|| {
        bad(&format!(
            "the boot manager of {} selects a recovery entry, and this run's records in {} end before the selection was changed",
            store_name(store),
            records.path.display()
        ))
    })?;
    if !recovery_environment {
        let loader = tool
            .enum_object(store, &intent.loader, directory)
            .map_err(|error| at_store(error, "reading the run's recovery entry", store))?;
        need(
            one(&loader, "identifier")? == intent.loader
                && one(&loader, "loadoptions")? == load_options(guard, bootstrap_pin(intent)?),
            &format!(
                "the recovery entry {} of {} does not name this run's boot record {} in its load options: it is not this run's",
                intent.loader,
                store_name(store),
                records.path.display()
            ),
        )?;
    }
    let list_all = || match store {
        Some(store) => tool.enum_all(store, directory),
        None => tool.enum_system_all(directory),
    };
    let before_all = list_all();
    let intent_sha = native::persist(
        &directory.join("boot-selection-cancellation-intent.json"),
        &serde_json::json!({"kind":"unstarted-conversion-boot-selection-cancellation-intent-v1",
            "source":intent.source,"guard_intent_sha256":guard,
            "found":plan.state,"current_bootmgr":current,
            "restore":plan.restore.iter().map(|(k,v)|serde_json::json!({"element":k,"values":v})).collect::<Vec<_>>(),
            "no_backup_import":true,"private_entries_deleted":false,
            "record_grants_source_authority":false}),
        budget.maximum_control_bytes,
    )?;
    let mut restored = Vec::new();
    for (field, values) in &plan.restore {
        let mut args = vec![format!("/{field}")];
        args.extend(values.iter().cloned());
        tool.run(store, &args, directory).map_err(|error| {
            at_store(
                error,
                &format!("setting the boot manager's {field} to {values:?}"),
                store,
            )
        })?;
        flush(events).map_err(|error| at_store(error, "flushing the change", store))?;
        let after = read_bootmgr()?;
        let remaining = plan_selection(&after, &original, &intent.loader)
            .map_err(|error| at_store(error, "comparing the boot manager entry", store))?;
        need(
            !remaining.restore.iter().any(|(f, _)| f == field),
            &format!(
                "the boot manager's {field} in {} does not read back as {values:?}, which it was set to",
                store_name(store)
            ),
        )?;
        restored.push((*field).to_owned());
    }
    let after = read_bootmgr()?;
    let done = plan_selection(&after, &original, &intent.loader)
        .map_err(|error| at_store(error, "comparing the boot manager entry", store))?;
    need(
        done.state == RecoveryBootSelectionState::Normal && done.restore.is_empty(),
        &format!(
            "the boot manager of {} does not select the original recorded in {} after the restoration",
            store_name(store),
            records.path.display()
        ),
    )?;
    // Every other entry, before and after. Where the store cannot be listed
    // whole this is not checked, and the receipt says so and why: it is
    // never passed over in silence.
    let not_compared = match (before_all, list_all()) {
        (Ok(mut before), Ok(mut after)) => {
            before.remove(BOOTMGR);
            after.remove(BOOTMGR);
            need(
                before == after,
                &format!(
                    "another entry of {} changed while the boot manager's selection was restored",
                    store_name(store)
                ),
            )?;
            None
        }
        (Err(error), _) | (_, Err(error)) => Some(format!(
            "the entries of {} could not be listed whole, so it was not checked that no other entry changed: {error}",
            store_name(store)
        )),
    };
    native::persist(
        &directory.join("boot-selection-cancellation-completed.json"),
        &serde_json::json!({"kind":"unstarted-conversion-boot-selection-cancelled-v1",
            "source":intent.source,"cancellation_intent_sha256":intent_sha,
            "restored_elements":restored,"restored_bootmgr":after,
            "other_entries_compared_unchanged":not_compared.is_none(),
            "other_entries_not_compared":not_compared,
            "private_entries_left_in_store":private,"backup_imports":0,
            "firmware_writes":0,"source_payload_write_calls":0,
            "saved_record_grants_authority":false}),
        budget.maximum_control_bytes,
    )?;
    Ok(receipt(
        plan.state,
        restored,
        Some(&after),
        private,
        not_compared,
        Some(directory),
    ))
}

/// Before a run changes anything: the boot configuration can be read the
/// way the run and its ways back will have to read it. `bcdedit` prints in
/// the display language of Windows and only its English output is parsed;
/// a run that found that out when it installed its boot selection had
/// already made its source read-only. `directory` is a fresh folder for the
/// queries' own records. Reads only.
pub fn require_readable_boot_configuration(
    directory: &Path,
    budget: RecoveryBootBudget,
) -> io::Result<()> {
    budget.validate()?;
    std::fs::create_dir(directory)?;
    let tool = native::Tool::system(budget)?;
    let wrap = |what: &str, error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "the boot configuration cannot be read as this conversion needs it ({what}: {error}). `bcdedit` answers in the display language of Windows, and only its English output is understood: with another display language, switch to English (United States) for this account and start the conversion again. Nothing was changed."
            ),
        )
    };
    let bootmgr = tool
        .enum_object(None, BOOTMGR, directory)
        .map_err(|error| wrap("listing the boot manager entry", error))?;
    selection(bootmgr).map_err(|error| wrap("reading the boot manager's selection", error))?;
    let current = tool
        .enum_object(None, "{current}", directory)
        .map_err(|error| wrap("listing the entry of the running Windows", error))?;
    one(&current, "identifier")
        .map_err(|error| wrap("reading the entry of the running Windows", error))?;
    tool.enum_object(None, FWBOOTMGR, directory)
        .map_err(|error| wrap("listing the firmware boot manager entry", error))?;
    Ok(())
}

/// In the running Windows: put the boot selection back for a run whose
/// conversion never started. `selection` is the run's `boot\selection`
/// folder; `records` a fresh folder on the same working volume for what
/// this does. A run that never changed the selection is found so and
/// nothing is set.
pub fn cancel_recovery_boot_in_windows(
    selection: &Path,
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    records: &Path,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<RecoveryBootCancellationReceipt> {
    budget.validate()?;
    let Some(found) = read_records(selection, source, journal, budget)? else {
        // The installation writes its first record before it creates even a
        // private entry. A run without that record has not touched the boot
        // configuration, and the store is not read to say so: `bcdedit` may
        // not be readable here at all (another display language), and a way
        // back must not fail on a store it has nothing to do with.
        return Ok(receipt(
            RecoveryBootSelectionState::NotInstalled,
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
        ));
    };
    metadata::fresh_external(records, source, journal, budget, events)?;
    let tool = native::Tool::system(budget)?;
    cancel_selection(
        &tool,
        None,
        &found,
        false,
        records,
        budget,
        &mut |events| native::flush_system_bcd_with_events(events),
        events,
    )
}

/// What the running Windows' boot manager selects, for a run's records.
/// Reads only; `records` is a fresh folder for the two queries' own records.
pub fn observe_recovery_boot_in_windows(
    selection: &Path,
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    records: &Path,
    budget: RecoveryBootBudget,
    events: &mut Vec<NativeEvent>,
) -> io::Result<RecoveryBootSelectionState> {
    budget.validate()?;
    let Some(found) = read_records(selection, source, journal, budget)? else {
        return Ok(RecoveryBootSelectionState::NotInstalled);
    };
    metadata::fresh_external(records, source, journal, budget, events)?;
    let tool = native::Tool::system(budget)?;
    let current = tool.enum_object(None, BOOTMGR, records)?;
    let original = selection_of(&found.intent)?;
    Ok(plan_selection(&current, &original, &found.intent.loader)?.state)
}

fn selection_of(intent: &BootIntent) -> io::Result<Selection> {
    selection(intent.original.all_fields.clone())
}

/// In the recovery environment: put the boot selection back for a run whose
/// conversion never started. The intent at `intent_path` has to be the one
/// the running kernel was started with, and that kernel has to be this
/// run's loader. The disk that holds the EFI system partition is brought
/// online if a failed start left it offline; no partition of it is changed.
pub fn cancel_recovery_boot_in_recovery_environment(
    intent_path: &Path,
    source: &PartitionSourceBinding,
    journal: &GeneralJournalStorageBinding,
    records: &Path,
    budget: RecoveryBootBudget,
    observation: PartitionObservationBudget,
    observer: &mut impl crate::partition_restoration::PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> io::Result<RecoveryBootCancellationReceipt> {
    budget.validate()?;
    observation.validate()?;
    cold::restore_checkpoint(observer, "boot-cancel-opening", events)?;
    let selection_directory = intent_path
        .parent()
        .ok_or_else(|| bad("the boot intent has no folder"))?;
    let found = read_records(selection_directory, source, journal, budget)?
        .ok_or_else(|| bad("the run's boot records are absent from its folder"))?;
    let guard = found
        .guard_sha256
        .ok_or_else(|| bad("the run's boot guard record is absent from its folder"))?;
    need(
        native::current_intent_sha()? == guard,
        "the boot record in the run's folder is not the one this Windows was started with",
    )?;
    need(
        guid(&native::kernel_boot_identifier()?)? == found.intent.loader,
        "this Windows was not started through the run's recovery entry",
    )?;
    use crate::native::partition_isolation::offline;
    let efi_disk = &found.intent.efi.binding;
    offline::make_disk_available(efi_disk, events)?;
    let (ram_root, ram_backing) = offline::current_ram()?;
    metadata::fresh_external(records, source, journal, budget, events)?;
    let mut published = None;
    for attempt in 0..60 {
        let layout = offline::available_disk_layout(efi_disk, observation, events)?;
        match metadata::published_efi(
            &found.intent.efi,
            &layout,
            budget.ram_bytes,
            &ram_root,
            &ram_backing,
            events,
        ) {
            Ok(efi) => {
                published = Some(efi);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && attempt < 59 => {
                cold::restore_checkpoint(observer, "boot-cancel-EFI-not-yet-published", events)?;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => return Err(error),
        }
    }
    let efi = published.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the EFI system partition was not published after its disk came online",
        )
    })?;
    cold::restore_checkpoint(observer, "boot-cancel-EFI-published", events)?;
    let tool = native::Tool::system(budget)?;
    cancel_selection(
        &tool,
        Some(&efi.bcd_path),
        &found,
        true,
        records,
        budget,
        &mut |_| metadata::flush_explicit_store(&efi),
        events,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOADER: &str = "{11111111-2222-4333-8444-555555555555}";
    const WINDOWS: &str = "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}";
    const OTHER: &str = "{99999999-8888-4777-8666-555555555555}";

    fn fields(default: &str, order: &[&str], timeout: &str) -> Fields {
        let mut fields = Fields::new();
        fields.insert("identifier".into(), vec![BOOTMGR.into()]);
        fields.insert(
            "device".into(),
            vec!["partition=\\Device\\HarddiskVolume1".into()],
        );
        fields.insert(
            "path".into(),
            vec!["\\EFI\\Microsoft\\Boot\\bootmgfw.efi".into()],
        );
        fields.insert("description".into(), vec!["Windows Boot Manager".into()]);
        fields.insert("default".into(), vec![default.into()]);
        fields.insert(
            "displayorder".into(),
            order.iter().map(|s| (*s).to_owned()).collect(),
        );
        fields.insert("timeout".into(), vec![timeout.into()]);
        fields
    }
    fn original() -> Selection {
        selection(fields(WINDOWS, &[WINDOWS, OTHER], "30")).unwrap()
    }
    #[test]
    fn a_run_without_boot_records_is_not_installed_and_the_store_is_not_read() {
        let work = tempfile::tempdir().unwrap();
        let disk = |number: u32, tag: &str| -> crate::general_layout::GeneralDiskBinding {
            serde_json::from_value(serde_json::json!({
                "disk_number":number,"volume_guid":format!("{tag}1111111-2222-3333-4444-555555555555"),
                "identity":{"disk_guid":format!("{tag}aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                    "partition_guid":format!("{tag}1234567-89ab-cdef-0123-456789abcdef"),
                    "partition_number":4,"disk_bytes":136365211648u64,
                    "partition_offset":1048576u64,"partition_bytes":6442450944u64,
                    "logical_sector_bytes":512,"physical_sector_bytes":4096}}))
            .unwrap()
        };
        let source = PartitionSourceBinding {
            storage: disk(0, "0"),
        };
        let journal = GeneralJournalStorageBinding {
            disk: disk(1, "1"),
            externally_enrolled_disk_unique_id: "partition-alpha-x".into(),
            allow_additional_partitions: true,
        };
        let budget = RecoveryBootBudget {
            ram_bytes: 64 << 20,
            maximum_store_bytes: 1 << 20,
            maximum_control_bytes: 1 << 20,
            maximum_image_bytes: 1 << 20,
            minimum_free_bytes: 1,
            tool_timeout_milliseconds: 1000,
        };
        // No `boot\selection` folder at all, and one that is empty.
        let records = work.path().join("cancel").join("boot");
        for selection in [work.path().join("absent"), work.path().to_path_buf()] {
            let mut events = Vec::new();
            let receipt = cancel_recovery_boot_in_windows(
                &selection,
                &source,
                &journal,
                &records,
                budget,
                &mut events,
            )
            .unwrap();
            assert_eq!(receipt.found, RecoveryBootSelectionState::NotInstalled);
            assert!(receipt.restored_elements.is_empty() && receipt.records.is_none());
            // Nothing was run and nothing was written: no native event, no
            // folder of query records.
            assert!(events.is_empty() && !records.exists());
            assert_eq!(
                observe_recovery_boot_in_windows(
                    &selection,
                    &source,
                    &journal,
                    &records,
                    budget,
                    &mut events
                )
                .unwrap(),
                RecoveryBootSelectionState::NotInstalled
            );
        }
        // A guard record without the one written before it is not "none".
        std::fs::write(work.path().join("recovery-boot-guard-intent.json"), b"{}").unwrap();
        let refusal = cancel_recovery_boot_in_windows(
            work.path(),
            &source,
            &journal,
            &records,
            budget,
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("recovery-boot-guard-intent.json")
                && refusal.contains("recovery-boot-original-intent.json"),
            "{refusal}"
        );
    }

    fn elements(plan: &SelectionPlan) -> Vec<&'static str> {
        plan.restore.iter().map(|(field, _)| *field).collect()
    }

    #[test]
    fn an_installed_selection_is_put_back_in_the_order_that_keeps_the_runner_reachable() {
        let plan = plan_selection(&fields(LOADER, &[LOADER], "0"), &original(), LOADER).unwrap();
        assert_eq!(plan.state, RecoveryBootSelectionState::Installed);
        // The default goes last: until then a restart reaches the runner.
        assert_eq!(elements(&plan), ["displayorder", "timeout", "default"]);
        assert_eq!(plan.restore[0].1, [WINDOWS, OTHER]);
        assert_eq!(plan.restore[1].1, ["30"]);
        assert_eq!(plan.restore[2].1, [WINDOWS]);
    }

    #[test]
    fn a_normal_and_a_half_restored_selection_are_told_apart() {
        let normal = plan_selection(
            &fields(WINDOWS, &[WINDOWS, OTHER], "30"),
            &original(),
            LOADER,
        )
        .unwrap();
        assert_eq!(normal.state, RecoveryBootSelectionState::Normal);
        assert!(normal.restore.is_empty());
        // Order and timeout were put back, the default was not yet.
        let half = plan_selection(
            &fields(LOADER, &[WINDOWS, OTHER], "30"),
            &original(),
            LOADER,
        )
        .unwrap();
        assert_eq!(half.state, RecoveryBootSelectionState::PartlyInstalled);
        assert_eq!(elements(&half), ["default"]);
        // A timeout that was 0 before cannot be told apart and is not set.
        let zero = selection(fields(WINDOWS, &[WINDOWS], "0")).unwrap();
        let plan = plan_selection(&fields(LOADER, &[LOADER], "0"), &zero, LOADER).unwrap();
        assert_eq!(plan.state, RecoveryBootSelectionState::Installed);
        assert_eq!(elements(&plan), ["displayorder", "default"]);
    }

    #[test]
    fn a_selection_that_is_neither_this_runs_nor_the_original_is_refused_by_name() {
        let says = |current: Fields| {
            plan_selection(&current, &original(), LOADER)
                .unwrap_err()
                .to_string()
        };
        assert!(says(fields(OTHER, &[LOADER], "0")).contains("default is"));
        assert!(says(fields(LOADER, &[OTHER], "0")).contains("display order"));
        assert!(says(fields(LOADER, &[LOADER], "5")).contains("timeout is 5"));
        let mut sequence = fields(LOADER, &[LOADER], "0");
        sequence.insert("bootsequence".into(), vec![OTHER.into()]);
        assert!(says(sequence).contains("one-time boot sequence"));
        // Any other element that changed is somebody else's change.
        let mut path = fields(LOADER, &[LOADER], "0");
        path.insert("path".into(), vec!["\\EFI\\other.efi".into()]);
        assert!(says(path).contains("\"path\""));
        // The device is written differently by another start of Windows
        // and by the recovery environment; it stays single.
        let mut device = fields(LOADER, &[LOADER], "0");
        device.insert("device".into(), vec!["partition=C:".into()]);
        assert_eq!(
            plan_selection(&device, &original(), LOADER).unwrap().state,
            RecoveryBootSelectionState::Installed
        );
        device.insert(
            "device".into(),
            vec!["partition=C:".into(), "partition=D:".into()],
        );
        assert!(says(device).contains("device element is not single"));
    }
}
