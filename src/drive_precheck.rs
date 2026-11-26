//! What can be known of a data volume before it is frozen.
//!
//! The volume stays online and in use and is only read. The check finds
//! every refusal of a conversion that the NTFS structures and the
//! shadow-copy catalog decide, and estimates what a conversion would take.
//! It admits nothing: a conversion inspects the frozen source again, and
//! what only the frozen source can show is listed as still to be decided.
use crate::run_memory::memory_needed;
use crate::{
    artifact_arena::{ArtifactArena, ArtifactGroup},
    ntfs_admission,
    ntfs_inspect::{
        self, InspectionBlocker, PagedInspection, RootFileDomain, SourceMetadataBudget,
        paged_storage::SourceScratch,
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralPartitionReader,
    discovery::VolumeDiscovery,
    journal_file::GeneralJournalStorageBinding,
    resource_native::AvailableResources,
    tree_resources::{ResourceBudget, SourceResourceAdmission},
};
use std::{fs, path::Path};

/// How long the check waits before each further reading of a volume that
/// did not hold still, in seconds. A reading takes the volume's structures
/// from the disk, and what Windows has changed reaches the disk a few
/// seconds after the change: a volume that was written to a moment ago
/// reads as torn until then, and reading it again at once only finds the
/// same. The lab's volumes, read seconds after files were put on them,
/// failed three readings within a second.
const PAUSES_SECONDS: [u64; 3] = [2, 5, 10];

/// How often the volume is read before the check gives up on a consistent
/// reading: once, and once more after each pause.
const READINGS: u32 = PAUSES_SECONDS.len() as u32 + 1;

/// The pause before the `reading`th reading, counted from 1: none before
/// the first.
fn pause_before(reading: u32) -> u64 {
    (reading as usize)
        .checked_sub(2)
        .and_then(|index| PAUSES_SECONDS.get(index))
        .copied()
        .unwrap_or(0)
}

/// How many unresolved conditions a refusal spells out.
const NAMED_CONDITIONS: usize = 6;

use super::CHECK_DECIDED_WHEN_FROZEN as DECIDED_WHEN_FROZEN;

/// What a conversion would take, as far as the volume's structures say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Estimate {
    pub files: u64,
    pub directories: u64,
    pub streams: u64,
    /// The logical length of every data stream.
    pub logical_bytes: u64,
    /// Bytes a conversion leaves where they are, and bytes it writes anew.
    pub stays_bytes: u64,
    pub copied_bytes: u64,
    /// Object IDs, which are kept in the run's records and not carried over.
    pub object_ids: u64,
    /// Free memory a conversion of this many objects needs at least, and
    /// what is free now.
    pub memory_needed_bytes: u64,
    pub memory_free_bytes: u64,
    /// Free working storage a conversion needs at least, and what is free.
    pub working_needed_bytes: u64,
    pub working_free_bytes: u64,
}

impl Estimate {
    /// The time a conversion takes, as a range in seconds. From the lab's
    /// data volumes and its Windows volume, on virtual disks: about 25 s of
    /// fixed work, 5 ms for each file and directory and 45 s for each GiB
    /// of data, which overstated every measured run by a fifth to a third;
    /// the range is 0.6 to 1.2 times that figure.
    pub fn seconds(&self) -> (u64, u64) {
        let objects = self.files.saturating_add(self.directories);
        let model = 25_000u64
            .saturating_add(objects.saturating_mul(5))
            .saturating_add(self.logical_bytes / (1 << 20) * 45_000 / 1024);
        (model * 6 / 10 / 1000, model * 12 / 10 / 1000)
    }
}

/// One reading of the volume and what it found.
#[derive(Debug, Default)]
pub(super) struct Report {
    /// What a conversion would refuse, each in the words it would use.
    pub refusals: Vec<String>,
    /// What is not carried over, which a conversion announces and goes on.
    pub notes: Vec<String>,
    pub estimate: Option<Estimate>,
    /// What a conversion makes plain files of, once the list is agreed
    /// (`plain_consent`): not refused, and not converted without consent.
    pub plain: crate::plain_projection::PlainList,
    /// What the Cloud Files API reported of each cloud placeholder of the
    /// list, online; nothing was downloaded to learn it.
    pub cloud: Vec<crate::drive_plain_prefreeze::CloudFinding>,
    /// How long each part of the reading took, in order.
    pub laps: Vec<(&'static str, std::time::Duration)>,
}

/// The parts of a reading, timed one after another.
struct Laps {
    last: std::time::Instant,
    done: Vec<(&'static str, std::time::Duration)>,
}

impl Laps {
    fn start() -> Self {
        Self {
            last: std::time::Instant::now(),
            done: Vec::new(),
        }
    }
    fn end(&mut self, part: &'static str) {
        let now = std::time::Instant::now();
        self.done.push((part, now.duration_since(self.last)));
        self.last = now;
    }
}

pub(super) enum Outcome {
    /// The volume was read consistently.
    Read(Report),
    /// It was not: it changed while it was read, each time. Nothing is
    /// known, and nothing is refused.
    Changing { last: String },
}

/// The working storage a run needs at least: the 4 GiB it refuses to start
/// below, and room for what is copied twice over, once in the working
/// volume it is written to first and once as what it replaces on the
/// source, kept for the way back.
fn working_needed(copied_bytes: u64) -> u64 {
    (4u64 << 30).saturating_add(copied_bytes.saturating_mul(2))
}

fn push_unique(list: &mut Vec<String>, text: &str) {
    if !list.iter().any(|known| known == text) {
        list.push(text.to_owned());
    }
}

/// What a condition the raw inspection reports comes to before the freeze.
#[derive(Debug, PartialEq, Eq)]
enum Condition {
    /// Not a refusal, or one this check reports in another place.
    Settled,
    /// Decided by what only the frozen source shows.
    WhenFrozen,
    /// A conversion would stop for it.
    Refuses,
}

/// The codes a conversion always settles with proofs it makes of the frozen
/// source, or that a reading before the freeze adds of its own.
fn settled_without_the_file(code: &str) -> Option<Condition> {
    match code {
        "preparation_inventory_only"
        | "security_descriptors_unresolved"
        | "directory_indexes_unverified"
        | "allocation_ownership_unverified" => Some(Condition::Settled),
        "backup_boot_unverified" | "journal_state_unverified" => Some(Condition::WhenFrozen),
        // Reported once for the volume, with their number and the remedy.
        "dos_short_name" | "volume_state_flags" | "unsupported_ntfs_version" => {
            Some(Condition::Settled)
        }
        _ => None,
    }
}

fn condition(
    raw: &PagedInspection,
    blocker: &InspectionBlocker,
    indexes: &crate::ntfs_internal::PagedVerifiedIndexes,
) -> Result<Condition> {
    if let Some(known) = settled_without_the_file(&blocker.code) {
        return Ok(known);
    }
    let file = match blocker.file_record_number {
        Some(number) => raw.find_record(number, None)?,
        None => None,
    };
    Ok(match (blocker.code.as_str(), &file) {
        // An EFS object made plain, once its list is agreed.
        (code, Some(file))
            if crate::plain_projection::efs_blocker(code, &blocker.message)
                && crate::plain_projection::efs_taken(file) =>
        {
            Condition::Settled
        }
        ("object_id", _) if blocker.file_record_number == Some(3) => {
            if indexes.covers_volume_object_id_domain(raw, 3) {
                Condition::Settled
            } else {
                Condition::Refuses
            }
        }
        ("object_id", Some(file)) => match indexes.data_object_ids_owned() {
            Some(ids) if ids.accounted(raw, file)? => Condition::Settled,
            _ => Condition::Refuses,
        },
        // The storage-class mark Windows leaves on files, and the marks of
        // the transaction manager: taken over with a witness of the frozen
        // device, in exactly these forms.
        ("unsupported_attribute", Some(file))
            if blocker.message == "Attribute type 0x100 needs a preservation policy" =>
        {
            if file
                .attributes
                .iter()
                .filter(|attribute| attribute.type_code == 0x100)
                .all(|attribute| {
                    crate::ntfs_storage_class::recognized_default(attribute)
                        || ntfs_admission::recognized_root_txf(attribute)
                })
            {
                Condition::WhenFrozen
            } else {
                Condition::Refuses
            }
        }
        // NTFS's own list of bad clusters has no contents to read.
        ("logical_stream_hash_unavailable", Some(file))
            if file.record_number == 8
                && ntfs_admission::paged::internal_role(raw, file)?.as_deref()
                    == Some("$BadClus") =>
        {
            Condition::Settled
        }
        _ => Condition::Refuses,
    })
}

/// The directory NTFS moves a file into when it is deleted while a program
/// still has it open; the file goes when the last handle closes.
const DELETED_ROLE: &str = "$Extend\\$Deleted";

/// A file or directory that was deleted while a program still had it open:
/// every name it has left is in NTFS's directory for those. A volume that
/// is in use can hold some at any moment. A conversion does not meet them,
/// because the volume is taken offline first, which closes every handle;
/// the frozen source is held to that directory being empty.
fn is_deleted_while_open(
    file: &crate::ntfs_inspect::FileInventory,
    deleted_directory: Option<u64>,
) -> bool {
    deleted_directory.is_some_and(|directory| {
        !file.names.is_empty()
            && file
                .names
                .iter()
                .all(|name| name.parent_record_number == directory)
    })
}

/// What a check says of them: they are no refusal and are not counted.
fn deleted_while_open_note(count: u64) -> String {
    format!(
        "{count} file(s) or directories were deleted while a program still had them open. Windows removes each when the program closes it, and a conversion, which takes the volume offline first, does not meet them: they are not counted here."
    )
}

/// Reads the volume, up to `READINGS` times, and reports what a conversion
/// would refuse and what it would take. `parent` is the working directory
/// the check may keep its pages in while it runs, on another disk than the
/// volume; nothing is left there.
pub(super) fn examine(
    source: &VolumeDiscovery,
    journal: &GeneralJournalStorageBinding,
    parent: &Path,
    run_id: &str,
) -> Result<Outcome> {
    let mut failures: Vec<Failure> = Vec::new();
    for reading in 1..=READINGS {
        // What the inspection decided is read again at once, to see it
        // twice; a volume that did not hold still is given time.
        if let Some(failure) = failures.last().filter(|failure| !failure.decided) {
            let seconds = pause_before(reading);
            println!(
                "The volume did not read as one that is at rest ({}); reading it again in {seconds} s.",
                failure.text
            );
            std::thread::sleep(std::time::Duration::from_secs(seconds));
        }
        let directory = parent.join(format!("check-{run_id}-{reading}"));
        let result = read_in(source, journal, &directory);
        // The pages are the check's own and say nothing afterwards.
        if directory.exists() {
            if let Err(error) = fs::remove_dir_all(&directory) {
                eprintln!(
                    "The check's working files at {} could not be removed ({error}); they can be deleted.",
                    directory.display()
                );
            }
        }
        match result? {
            Ok(report) => return Ok(Outcome::Read(report)),
            Err(failure) => {
                if repeats(&failures, &failure) {
                    return Ok(Outcome::Read(Report {
                        refusals: vec![failure.text],
                        ..Report::default()
                    }));
                }
                failures.push(failure);
            }
        }
    }
    Ok(Outcome::Changing {
        last: failures
            .pop()
            .map(|failure| failure.text)
            .unwrap_or_default(),
    })
}

/// Why a reading did not end in a report.
#[derive(Debug, PartialEq, Eq)]
struct Failure {
    text: String,
    /// The inspection decided this about something it read in full: a
    /// reparse point it does not recreate, two names that differ only by
    /// case (`n2r_win32::refusal`). Otherwise a structure could not be read
    /// as expected, or the reading found the volume changed under it, and
    /// on a volume in use that says nothing: it may have been caught while
    /// it changed.
    decided: bool,
}

/// Whether `failure` is what a conversion would stop at too: a decision of
/// the inspection, made of exactly the same thing in the reading before.
/// A structure that could not be read is never that, however often the
/// same words come back: under a steady load they do.
fn repeats(earlier: &[Failure], failure: &Failure) -> bool {
    failure.decided && earlier.last() == Some(failure)
}

/// A reading that found the volume changed under it.
fn unchanged(holds: bool, otherwise: &'static str) -> Result<()> {
    ensure!(holds, "{otherwise}");
    Ok(())
}

/// One reading. The outer error is the check's own (its working directory,
/// its memory); the inner one is what the volume did not let it read.
fn read_in(
    source: &VolumeDiscovery,
    journal: &GeneralJournalStorageBinding,
    directory: &Path,
) -> Result<std::result::Result<Report, Failure>> {
    let _ancestry = crate::resource_preparation::create_external_output(directory, journal)
        .with_context(|| {
            format!(
                "creating the check's working directory {}",
                directory.display()
            )
        })?;
    let available = n2r_win32::resource_native::observe_available_resources(directory)?;
    let scratch = super::resource::aligned(
        available
            .scratch_available_bytes
            .saturating_sub(super::resource::reserve(available.scratch_available_bytes)),
    );
    let resources = super::resource::budget(available, scratch, 0)?;
    let arena = ArtifactArena::new(directory, resources, &[source.binding.clone()])?;
    ensure!(
        arena
            .volume_guid_path()?
            .eq_ignore_ascii_case(&journal.disk.volume_path()?),
        "the check's working directory is not on the working volume"
    );
    Ok(
        read(source, resources, available, directory, &arena).map_err(|error| Failure {
            decided: error.chain().any(n2r_win32::refusal::is_refusal),
            text: format!("{error:#}"),
        }),
    )
}

fn read(
    source: &VolumeDiscovery,
    resources: ResourceBudget,
    available: AvailableResources,
    directory: &Path,
    arena: &ArtifactArena,
) -> Result<Report> {
    let binding = source.binding.clone();
    let mut events = Vec::new();
    let mut report = Report::default();
    let mut laps = Laps::start();
    let _memory = arena.reserve_ram(32 * 1024 * 1024)?;
    let root = format!("{}\\", binding.volume_path()?);
    let before = n2r_win32::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    ensure!(
        before.disk_attributes == 0,
        "the volume's disk is not online and writable (disk attributes {}): a check reads a volume that is in use",
        before.disk_attributes
    );

    // Shadow copies and their providers: what a conversion asks first.
    {
        let _query = arena.reserve_ram(
            resources
                .max_row_bytes
                .checked_mul(4)
                .context("shadow-copy catalog workspace overflow")?,
        )?;
        // A provider the converter does not know and passes over is named.
        let asked = n2r_win32::vss_observation::observe_catalog(&root).and_then(|catalog| {
            catalog.require_observed_catalog_clear()?;
            Ok(catalog.provider_notes())
        });
        match asked {
            Ok(notes) => report.notes.extend(notes),
            Err(error) => report.refusals.push(error.to_string()),
        }
        // On a disk the volume shares, the volumes beside it go offline
        // with it: what a run asks of them before it locks the first.
        if let Err(error) = n2r_win32::examine_shared_disk(binding.clone(), &mut events) {
            report.refusals.push(error.to_string());
        }
    }

    laps.end("shadow copies");
    // What programs wrote a moment ago may be in Windows' cache only, and
    // the reading is of the disk: Windows is asked to write it out first.
    // A volume that cannot be written to has nothing waiting.
    if let Err(error) = n2r_win32::write_out_volume_cache(&binding) {
        if error.raw_os_error() != Some(19) {
            report.notes.push(format!(
                "Windows did not write out what it holds in memory for the volume ({error}); what was written to it in the last seconds may not have been read."
            ));
        }
    }
    laps.end("Windows writing out its cache");
    let budget = SourceMetadataBudget::from_resource_budget(resources)?;
    let group = arena.reserve_group(ArtifactGroup::Source, budget.scratch_bytes)?;
    let scratch = SourceScratch::new_in_arena(budget, group)?;
    let mut reader = GeneralPartitionReader::open(binding.clone(), &mut events)?;
    let raw = PagedInspection::inspect_preparation_with_scratch(
        &mut reader,
        binding.identity.partition_bytes,
        resources,
        &directory.join("raw"),
        &scratch,
    )?;
    unchanged(
        raw.header().inventory_complete
            && raw.header().geometry.serial_number as u32 == source.volume_serial_low32
            && raw.allocation().status
                == ntfs_inspect::AllocationReconciliationStatus::ConsistentRawModel,
        "the volume's file records and its allocation bitmap did not agree in one reading",
    )?;
    raw.revalidate()?;
    laps.end("file records");
    let indexes =
        crate::ntfs_internal::verify_domain(&mut reader, &raw, &directory.join("indexes"))?;
    let probe = reader.revalidate_route(&mut events)?;
    unchanged(
        probe.binding == binding && probe.read_only_probe && probe.source_write_requests == 0,
        "the read-only route to the volume changed while it was read",
    )?;
    let after = n2r_win32::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    unchanged(
        after == before,
        "the disk's state changed while the volume was read",
    )?;

    laps.end("NTFS's own indexes");

    // The volume as a whole.
    let header = raw.header();
    // NTFS 3.0 and 3.1 are read as they are. NTFS 1.2 is mounted read-write
    // by Windows before the freeze, with the conversion's own question, in
    // case that upgrades it; said here, not refused.
    let version = header
        .volume_version
        .as_deref()
        .and_then(crate::ntfs_version::parse);
    let upgrade = version.filter(|&version| {
        crate::ntfs_version::disposition(version)
            == crate::ntfs_version::Disposition::WindowsUpgrades
    });
    let not_dirty =
        header.dirty == Some(false) && header.volume_flags.is_some_and(|flags| flags & 1 == 0);
    let clean = not_dirty && (version.is_some_and(crate::ntfs_version::reads) || upgrade.is_some());
    if !clean {
        report
            .refusals
            .push(ntfs_admission::CLEAN_VOLUME_REQUIREMENT.to_owned());
    } else if let Some(version) = upgrade {
        report
            .notes
            .push(crate::ntfs_version::upgrade_note(version));
    }
    // 0x80 is how NTFS records that short names are not made on the volume;
    // a conversion takes it with Windows' own word for the same.
    if !matches!(header.volume_flags, Some(0) | Some(0x80)) && clean {
        report
            .refusals
            .push(ntfs_admission::VOLUME_FLAGS_REQUIREMENT.to_owned());
    }
    if crate::short_name_disposition::dropped() {
        let (count, example) = crate::general_source_admission::resource::short_name_census(&raw)?;
        if count != 0 {
            report
                .notes
                .push(crate::short_name_disposition::note(count, &example));
        }
    } else if let Err(error) = crate::general_source_admission::resource::refuse_short_names(&raw) {
        report.refusals.push(error.to_string());
    }
    for index in indexes
        .indexes
        .iter()
        .filter(|index| !index.replacement_supported)
    {
        // The quota index with nothing but the unlimited defaults is taken
        // over once Windows says that quota management is off.
        if index.role.ends_with("$Quota") && indexes.default_quotas_only {
            continue;
        }
        push_unique(
            &mut report.refusals,
            ntfs_admission::index_refusal_cause(&index.role),
        );
    }
    // Quotas are recorded and not carried over: said before the question.
    if let Some(quotas) = indexes.quotas_not_carried() {
        report.notes.push(crate::quota_disposition::note(quotas));
    }

    // What there is to convert. Each directory is also asked of Windows
    // whether it is case-sensitive, which is not in the structures read
    // above; one that does not answer is left to the frozen source.
    let case = n2r_win32::directory_case::DirectoryCaseProbe::open(&root)?;
    let (mut case_sensitive, mut case_unknown, mut case_example) = (0u64, 0u64, None);
    // Whether the root directory (FILE 5) is marked: no mark is set then.
    let mut case_mark_on_root = false;
    // Counted as a conversion counts them, a directory's named streams
    // included: the frozen source is held to these same counts.
    let mut counts = ntfs_admission::TreeCounts::default();
    // Where NTFS keeps what was deleted while a program still had it open.
    let mut deleted_directory = None;
    for ordinal in 0..raw.file_count() {
        let file = raw.file(ordinal)?;
        if ntfs_admission::paged::internal_role(&raw, &file)?.as_deref() == Some(DELETED_ROLE) {
            deleted_directory = Some(file.record_number);
            break;
        }
    }
    let mut deleted_while_open = 0u64;
    for ordinal in 0..raw.file_count() {
        let file = raw.file(ordinal)?;
        if ntfs_admission::paged::internal_role(&raw, &file)?.is_some() {
            continue;
        }
        if is_deleted_while_open(&file, deleted_directory) {
            deleted_while_open += 1;
            continue;
        }
        counts.add(&file)?;
        if file.is_directory {
            let reference = file.record_number | (u64::from(file.sequence_number) << 48);
            match case.flags(reference) {
                Ok(0) => {}
                Ok(1) => {
                    case_sensitive += 1;
                    case_mark_on_root |= file.record_number == 5;
                    if case_example.is_none() {
                        case_example = ntfs_admission::paged::refused_object_path(&raw, &file)
                            .map(|path| format!("\\{}", path.join("\\")));
                    }
                }
                Ok(_) => case_unknown += 1,
                // Left to the frozen source, which asks again.
                Err(_) => {}
            }
        }
    }
    let ntfs_admission::TreeCounts {
        files,
        directories,
        streams,
        logical_bytes,
    } = counts;
    // Two names that differ only by case would have stopped the reading.
    // Whether the mark alone is set on the new volume depends on the
    // running Windows, and a conversion says which, as this does. (A check
    // reads data volumes only.)
    if case_sensitive != 0 {
        report.notes.push(ntfs_admission::case_mark_note(
            case_sensitive,
            case_example.as_deref(),
            n2r_win32::directory_case::CaseMarkCarry::of_this_windows(false)?
                .with_source_root(case_mark_on_root),
        ));
    }
    if case_unknown != 0 {
        report
            .refusals
            .push(ntfs_admission::case_answer_requirement(
                case_unknown,
                directories,
            ));
    }
    if deleted_while_open != 0 {
        report
            .notes
            .push(deleted_while_open_note(deleted_while_open));
    }
    let object_ids = indexes.data_object_ids_owned();
    let mut estimate = Estimate {
        files,
        directories,
        streams,
        logical_bytes,
        stays_bytes: 0,
        copied_bytes: logical_bytes,
        object_ids: object_ids.as_ref().map_or(0, |ids| ids.len()),
        memory_needed_bytes: memory_needed(raw.file_count(), files, directories, streams),
        memory_free_bytes: available.available_physical_bytes,
        working_needed_bytes: working_needed(logical_bytes),
        working_free_bytes: available.scratch_available_bytes,
    };
    if files == 0 {
        report.refusals.push(
            "the volume holds no file at all (an empty volume is formatted, not converted)"
                .to_owned(),
        );
    }

    laps.end("counting, and asking each directory");

    // Each file and directory against what a conversion preserves.
    let sha: [u8; 32] = hex::decode(raw.canonical_sha256()?)?
        .try_into()
        .ok()
        .context("the inspection's checksum is not 32 bytes")?;
    // A run that fits itself to the machine is sized by this volume from
    // here on: its budget, and the admission below, are no smaller than
    // what the volume wants.
    let resources = if n2r_win32::resource_native::memory_fits_the_machine() {
        n2r_win32::resource_native::want_memory(crate::run_memory::ledger_needed(
            raw.file_count(),
            files,
            directories,
            streams,
        ));
        super::resource::budget(available, resources.scratch_bytes, 0)?
    } else {
        resources
    };
    match SourceResourceAdmission::new(
        sha,
        header.mft_record_count,
        raw.file_count(),
        files,
        directories,
        streams,
        resources,
    ) {
        Err(_) => report.refusals.push(format!(
            "the volume has {files} file(s), {directories} directories and {streams} data stream(s): a conversion needs about {} MiB of free memory for them, and {} MiB are free. Close other programs, or convert on a machine with more memory",
            estimate.memory_needed_bytes >> 20,
            estimate.memory_free_bytes >> 20
        )),
        Ok(admission) => {
            let mut refused = ntfs_admission::RefusedObjects::default();
            let mut plain = Vec::new();
            let mut wof = Vec::new();
            // EFS files this run would decrypt, whose key is asked for below.
            let mut efs_files = Vec::new();
            // Cloud placeholders, asked of the Cloud Files API below.
            let mut cloud = Vec::new();
            let (mut stays, mut copied) = (0u64, 0u64);
            for ordinal in 0..raw.file_count() {
                let file = raw.file(ordinal)?;
                if ntfs_admission::paged::internal_role(&raw, &file)?.is_some()
                    || is_deleted_while_open(&file, deleted_directory)
                {
                    continue;
                }
                if let Ok(Some(file)) = crate::plain_projection::wof_file(&file) {
                    wof.push(file);
                }
                let mut issues = ntfs_admission::paged::ordinary_user_issues_before_freeze(
                    &raw,
                    &file,
                    admission,
                    object_ids.as_deref(),
                )?;
                // Counted for the whole volume above, with one example.
                issues.retain(|issue| !issue.starts_with("it has an 8.3 short name"));
                if !issues.is_empty() {
                    let path = ntfs_admission::paged::refused_object_path(&raw, &file);
                    refused.note(file.record_number, path.as_deref(), &issues);
                } else if crate::plain_consent::takes_plain()
                    && let Some(transform) = crate::plain_projection::of_file(&file)?
                {
                    // Admitted because it is made plain: it goes on the list.
                    let path = ntfs_admission::paged::refused_object_path(&raw, &file)
                        .context("an object to be made plain has no path")?;
                    if let Some(crate::plain_projection::EfsObject::File(_)) =
                        crate::plain_projection::efs_object(&file)?
                    {
                        efs_files.push(crate::plain_projection::listing_path(&path));
                    }
                    if let Ok(Some(placeholder)) = crate::plain_projection::cloud_placeholder(&file)
                    {
                        cloud.push((
                            crate::plain_projection::listing_path(&path),
                            placeholder.directory,
                        ));
                    }
                    plain.push(crate::plain_projection::entry(
                        crate::plain_projection::listing_path(&path),
                        &file,
                        transform,
                    ));
                }
                // A directory's named streams are carried as a file's.
                for stream in &file.streams {
                    let (stay, copy) = crate::ntfs_stream_plan::estimate_stream_bytes(
                        &raw, &file, stream, admission,
                    )?;
                    stays = stays.saturating_add(stay);
                    copied = copied.saturating_add(copy);
                }
            }
            if let Some(outside) = refused.outside_policy("") {
                report.refusals.push(outside);
            }
            // What of each cloud placeholder is on the volume, as the Cloud
            // Files API says; it downloads nothing to say it.
            report.cloud = crate::drive_plain_prefreeze::find(&root, &cloud);
            crate::drive_plain_prefreeze::apply_downloads(&mut plain, &report.cloud);
            report.notes.extend(crate::drive_plain_prefreeze::summary(&report.cloud));
            report
                .refusals
                .extend(crate::drive_plain_prefreeze::check_refusals(&report.cloud)?);
            report.plain = crate::plain_projection::PlainList::new(plain)
                .map_err(anyhow::Error::msg)?;
            // Each EFS file is opened for its data as this account, which
            // proves it holds the key, without reading a byte. One it cannot
            // open is refused by name; its ciphertext is never read as plain.
            let mut keyless = Vec::new();
            for path in &efs_files {
                let opened = n2r_win32::plain_copy::probe_decryption(std::path::Path::new(
                    &format!("{}{}", root, path.trim_start_matches('\\')),
                ));
                if let Err(error) = opened {
                    keyless.push(format!("{path} ({error})"));
                }
            }
            if !keyless.is_empty() {
                report.refusals.push(format!(
                    "{} EFS-encrypted file(s) cannot be decrypted by this account, for example {}: {}",
                    keyless.len(),
                    keyless[..keyless.len().min(3)].join(", "),
                    crate::plain_projection::EFS_KEY_REMEDY
                ));
            }
            if !wof.is_empty() {
                // What making them plain takes; refused where it does not fit,
                // as the conversion refuses it once the volume is frozen.
                let free = header
                    .free_clusters
                    .unwrap_or(0)
                    .saturating_mul(u64::from(header.geometry.cluster_size));
                let cluster = n2r_win32::target_cluster::bytes();
                match crate::plain_projection::require_wof_room(&wof, cluster, free) {
                    Err(refusal)
                        if crate::plain_projection::PlainKind::WofExpanded.implemented() =>
                    {
                        report.refusals.push(refusal.to_string())
                    }
                    _ => report
                        .notes
                        .push(crate::plain_projection::wof_note(&wof, cluster, free)),
                }
            }
            estimate.stays_bytes = stays;
            estimate.copied_bytes = copied;
            // Each WOF file's plain copy is kept in the working storage.
            let copies = if crate::plain_projection::PlainKind::WofExpanded.implemented() {
                wof.iter()
                    .fold(0u64, |sum, file| sum.saturating_add(file.plain_bytes))
            } else {
                0
            };
            estimate.working_needed_bytes = working_needed(copied).saturating_add(copies);
        }
    }

    laps.end("each file and directory");

    // The conditions the inspection itself reports.
    let (mut unresolved, mut examples) = (0u64, Vec::new());
    for ordinal in 0..raw.blocker_count() {
        let blocker = raw.blocker(ordinal)?;
        if condition(&raw, &blocker, &indexes)? != Condition::Refuses {
            continue;
        }
        unresolved += 1;
        if examples.len() < NAMED_CONDITIONS {
            examples.push(match blocker.file_record_number {
                Some(number) => {
                    let path = raw
                        .find_record(number, None)?
                        .and_then(|file| ntfs_admission::paged::refused_object_path(&raw, &file))
                        .map(|path| format!(" \\{}", path.join("\\")))
                        .unwrap_or_default();
                    format!(
                        "{}: {} (MFT record {number}{path})",
                        blocker.code, blocker.message
                    )
                }
                None => format!("{}: {}", blocker.code, blocker.message),
            });
        }
    }
    if unresolved != 0 {
        report.refusals.push(format!(
            "{unresolved} condition(s) found on the volume that the converter does not take over: {}{}",
            examples.join(" | "),
            if unresolved > examples.len() as u64 {
                " | ..."
            } else {
                ""
            }
        ));
    }

    if estimate.object_ids != 0 {
        report.notes.push(format!(
            "{} file(s) and directories have an object ID (Windows gives one to the target of a shortcut). ReFS has no object IDs: a conversion keeps them in its records and does not carry them over.",
            estimate.object_ids
        ));
    }
    if estimate.memory_needed_bytes > estimate.memory_free_bytes
        && !report
            .refusals
            .iter()
            .any(|text| text.contains("free memory"))
    {
        match crate::run_memory::short_of_memory(
            estimate.memory_needed_bytes,
            estimate.memory_free_bytes,
        ) {
            crate::run_memory::Short::GoesOn(note) => report.notes.push(note),
            crate::run_memory::Short::Refused(refusal) => report.refusals.push(refusal),
        }
    }
    report.estimate = Some(estimate);
    laps.end("the volume's conditions");
    report.laps = laps.done;
    Ok(report)
}

fn mib(bytes: u64) -> String {
    if bytes >= 10 << 30 {
        format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
    } else {
        format!("{} MiB", bytes.div_ceil(1 << 20))
    }
}

fn minutes(seconds: u64) -> String {
    if seconds < 90 {
        format!("{seconds} s")
    } else {
        format!("{} min", seconds.div_ceil(60))
    }
}

/// The estimate as the lines a check prints.
pub(super) fn describe(estimate: &Estimate, target_cluster_bytes: u64) -> Vec<String> {
    let (low, high) = estimate.seconds();
    vec![
        format!(
            "{} file(s), {} directories, {} data stream(s); {} of data.",
            estimate.files,
            estimate.directories,
            estimate.streams,
            mib(estimate.logical_bytes)
        ),
        format!(
            "To {} KiB ReFS clusters: {} stay where they are, {} are copied{}.",
            target_cluster_bytes / 1024,
            mib(estimate.stays_bytes),
            mib(estimate.copied_bytes),
            // What is neither is the holes of sparse files.
            match estimate
                .logical_bytes
                .saturating_sub(estimate.stays_bytes)
                .saturating_sub(estimate.copied_bytes)
            {
                0 => String::new(),
                holes => format!(", {} are holes of sparse files and stay holes", mib(holes)),
            }
        ),
        format!(
            "Working storage: at least {} (4 GiB and what is copied, twice); {} are free there.",
            mib(estimate.working_needed_bytes),
            mib(estimate.working_free_bytes)
        ),
        format!(
            "Memory: at least {} free; {} are free now.",
            mib(estimate.memory_needed_bytes),
            mib(estimate.memory_free_bytes)
        ),
        format!(
            "Time: roughly {} to {}, from the lab's runs on virtual disks; a slower disk takes longer.",
            minutes(low),
            minutes(high)
        ),
    ]
}

/// The whole report as the lines a check prints after the volume's own.
pub(super) fn lines(outcome: &Outcome, target_cluster_bytes: u64) -> Vec<String> {
    let mut text = Vec::new();
    match outcome {
        Outcome::Changing { last } => {
            text.push(format!(
                "The volume changed while it was read, {READINGS} times running over {} s, so nothing can be said of it and nothing is refused. Run the check again when the volume is at rest; if nothing writes to it, `chkdsk <drive>:` (which only reads) says whether its structures are damaged. The last reading stopped at: {last}",
                PAUSES_SECONDS.iter().sum::<u64>()
            ));
        }
        Outcome::Read(report) => {
            if report.refusals.is_empty() {
                text.push("Nothing was found that a conversion refuses.".to_owned());
            } else {
                text.push(format!(
                    "A conversion would refuse this volume, for {} reason(s):",
                    report.refusals.len()
                ));
                for (number, refusal) in report.refusals.iter().enumerate() {
                    text.push(format!("  {}. {refusal}", number + 1));
                }
            }
            if !report.laps.is_empty() {
                let total: std::time::Duration = report.laps.iter().map(|(_, took)| *took).sum();
                text.push(format!(
                    "The reading took {:.1} s ({}).",
                    total.as_secs_f64(),
                    report
                        .laps
                        .iter()
                        .map(|(part, took)| format!("{part} {:.1} s", took.as_secs_f64()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            for note in &report.notes {
                text.push(format!("Note: {note}"));
            }
            text.push(format!(
                "Decided only when the volume is frozen for a conversion: {DECIDED_WHEN_FROZEN}."
            ));
            if let Some(estimate) = &report.estimate {
                text.push("What a conversion would take:".to_owned());
                for line in describe(estimate, target_cluster_bytes) {
                    text.push(format!("  {line}"));
                }
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate(files: u64, directories: u64, logical_bytes: u64) -> Estimate {
        Estimate {
            files,
            directories,
            streams: files,
            logical_bytes,
            stays_bytes: logical_bytes,
            copied_bytes: 0,
            object_ids: 0,
            memory_needed_bytes: memory_needed(files + directories + 30, files, directories, files),
            memory_free_bytes: 8 << 30,
            working_needed_bytes: working_needed(0),
            working_free_bytes: 100 << 30,
        }
    }

    #[test]
    fn the_time_range_holds_the_runs_the_lab_measured() {
        // (files and directories, bytes of data, seconds the conversion took)
        for (objects, bytes, measured) in [
            (23_137u64, 452_086_345u64, 133u64), // lived-in, to 4 KiB clusters
            (7_137, 451_446_345, 72),            // lived-in, to 64 KiB clusters
            (20_006, 900_088, 94),               // a directory of 20,000 entries
            (5_009, 300_088, 41),
            (21_050, 331_114_474, 128),       // lived-in on Windows Server
            (191_101, 28_514_609_218, 1_650), // the lab's Windows volume
        ] {
            let (low, high) = estimate(objects, 0, bytes).seconds();
            assert!(
                low <= measured && measured <= high,
                "{objects} objects, {bytes} bytes: {measured} s is outside {low}..{high}"
            );
        }
    }

    #[test]
    fn memory_and_working_storage_grow_with_the_volume() {
        // What the lab ran: a volume of 500,000 small files converted with
        // 13.7 GiB free and one of 100,000 with 6 GiB, each holding less
        // than the estimate allows it. The estimate is 384 MiB of free
        // memory and about 15 KiB a file: 7.5 GiB for the first, 1.8 GiB
        // for the second, and two million files still take a large machine.
        let gib = |bytes: u64| bytes as f64 / (1u64 << 30) as f64;
        let half_million = gib(memory_needed(500_511, 500_003, 508, 500_003));
        assert!((7.4..7.7).contains(&half_million), "{half_million}");
        let hundred_thousand = gib(memory_needed(100_107, 100_003, 104, 100_003));
        assert!(
            (1.75..1.85).contains(&hundred_thousand),
            "{hundred_thousand}"
        );
        let two_million = gib(memory_needed(2_000_030, 2_000_000, 100_000, 2_000_000));
        assert!((28.0..32.0).contains(&two_million), "{two_million}");
        // The ledger is the larger need: handles and indexes alone are 8.7 GiB there.
        assert!(two_million > gib(6_100_008 * 1024 * 3 / 2));
        // What the ledger was seen to hold fits the estimate: 6,194 MiB of
        // a ledger of 9,136 for the 500,000 files (with a cache of 730 MiB
        // that is given up now), 1,911 MiB of 4,045 for the 100,000.
        // And what a run of 100,000 files held to 850 MiB could not do
        // without, 737 MiB, is under the limit the estimate asks.
        let ledger = |free: f64| free * 1024.0 * 2.0 / 3.0;
        assert!(ledger(half_million) > 4669.0, "{half_million}");
        assert!(
            ledger(hundred_thousand) > 737.0 * 1.25,
            "{hundred_thousand}"
        );
        // A volume of a hundred files: what a run holds whatever it converts.
        let small = memory_needed(130, 100, 10, 100);
        assert!((384 << 20..400 << 20).contains(&small), "{small}");
        // A run never starts with less than 4 GiB, and keeps what it copies twice.
        assert_eq!(working_needed(0), 4 << 30);
        assert_eq!(working_needed(10 << 30), 24 << 30);
    }

    #[test]
    fn a_volume_refused_for_memory_is_told_whether_the_limit_or_the_machine_is_short() {
        use crate::run_memory::memory_refusal;
        const MIB: u64 = 1 << 20;
        // No limit: the machine.
        let said = memory_refusal(10_150 * MIB, 6_105 * MIB, None);
        assert!(
            said.contains("needs about 10150 MiB of free memory, and 6105 MiB are free"),
            "{said}"
        );
        // A limit of 2 GiB counts 3 GiB as free on a machine that has more:
        // the limit is what is short, and two thirds of the need is what it
        // has to be.
        let said = memory_refusal(10_150 * MIB, 3_072 * MIB, Some(2_048 * MIB));
        assert!(
            said.contains(
                "needs a memory limit of about 6767 MiB, and --memory-limit gives it 2048 MiB"
            ),
            "{said}"
        );
        // A limit above what the machine has free changes nothing: the
        // machine is what is short.
        let said = memory_refusal(10_150 * MIB, 6_105 * MIB, Some(8_192 * MIB));
        assert!(said.contains("6105 MiB are free"), "{said}");
    }

    #[test]
    fn a_condition_that_only_the_frozen_source_settles_is_not_a_refusal() {
        for code in [
            "preparation_inventory_only",
            "security_descriptors_unresolved",
            "directory_indexes_unverified",
            "allocation_ownership_unverified",
            "dos_short_name",
            "volume_state_flags",
            "unsupported_ntfs_version",
        ] {
            assert_eq!(
                settled_without_the_file(code),
                Some(Condition::Settled),
                "{code}"
            );
        }
        for code in ["backup_boot_unverified", "journal_state_unverified"] {
            assert_eq!(
                settled_without_the_file(code),
                Some(Condition::WhenFrozen),
                "{code}"
            );
        }
        // Everything else is looked at with its file.
        for code in [
            "encrypted_file_attribute",
            "object_id",
            "unsupported_attribute",
        ] {
            assert_eq!(settled_without_the_file(code), None, "{code}");
        }
    }

    #[test]
    fn a_file_deleted_while_a_program_has_it_open_is_no_refusal_and_is_said() {
        let file = |parents: &[u64]| -> crate::ntfs_inspect::FileInventory {
            serde_json::from_value(serde_json::json!({
                "record_number": 5098, "sequence_number": 1,
                "hard_link_count": parents.len(), "is_directory": false,
                "is_metadata": false, "base_file_reference": 0,
                "names": parents.iter().map(|parent| serde_json::json!({
                    "name": "00010000000013EA158BE98E", "name_utf16": [], "namespace": 1,
                    "parent_record_number": parent, "parent_sequence_number": 1
                })).collect::<Vec<_>>(),
                "standard_information": null, "streams": [], "attributes": []
            }))
            .unwrap()
        };
        // Its only name is in NTFS's directory for what was deleted while open.
        assert!(is_deleted_while_open(&file(&[40]), Some(40)));
        // A name anywhere else keeps it a file of the volume.
        assert!(!is_deleted_while_open(&file(&[40, 5]), Some(40)));
        assert!(!is_deleted_while_open(&file(&[5]), Some(40)));
        // A volume without that directory has none; a record without a name is not one.
        assert!(!is_deleted_while_open(&file(&[40]), None));
        assert!(!is_deleted_while_open(&file(&[]), Some(40)));
        let note = deleted_while_open_note(2);
        assert!(
            note.starts_with("2 file(s)") && note.contains("does not meet them"),
            "{note}"
        );
    }

    #[test]
    fn a_volume_that_did_not_hold_still_is_given_time_before_each_further_reading() {
        assert_eq!(READINGS, 4);
        assert_eq!(
            (1..=READINGS).map(pause_before).collect::<Vec<_>>(),
            [0, 2, 5, 10]
        );
        // Nothing beyond the readings there are.
        assert_eq!(pause_before(0), 0);
        assert_eq!(pause_before(READINGS + 1), 0);
    }

    #[test]
    fn only_what_the_inspection_stops_at_twice_is_a_refusal() {
        let decided = |text: &str| Failure {
            text: text.into(),
            decided: true,
        };
        let unread = |text: &str| Failure {
            text: text.into(),
            decided: false,
        };
        // The inspection decided the same thing as in the reading before.
        let wof =
            "MFT record 40: a reparse point of tag 0x80000017 is not one the converter recreates";
        assert!(repeats(&[decided(wof)], &decided(wof)));
        // Not something else, not the first time, and not when another
        // reading came between.
        assert!(!repeats(&[decided("MFT record 41: other")], &decided(wof)));
        assert!(!repeats(&[], &decided(wof)));
        assert!(!repeats(&[decided(wof), unread("other")], &decided(wof)));
        // A structure that could not be read is never a refusal, however
        // often the same words come back: the lab's volume under write load
        // gave these twice running.
        for torn in [
            "invalid INDX signature/size",
            "namespace identity absent or sequence stale",
            "the volume's file records and its allocation bitmap did not agree in one reading",
        ] {
            assert!(!repeats(&[unread(torn)], &unread(torn)), "{torn}");
            assert!(
                !repeats(&[unread(torn), unread(torn)], &unread(torn)),
                "{torn}"
            );
        }
        // The mark is read from the error as the inspection passes it up,
        // with what was added on the way.
        let marked = anyhow::Error::new(n2r_win32::refusal::io_error(wof.into()))
            .context("MFT record 40 (its path: ...)");
        assert!(marked.chain().any(n2r_win32::refusal::is_refusal));
        let named = anyhow::Error::new(n2r_win32::refusal::Refusal("two names".into()));
        assert!(named.chain().any(n2r_win32::refusal::is_refusal));
        let plain = anyhow::anyhow!("invalid INDX signature/size").context("reading an index");
        assert!(!plain.chain().any(n2r_win32::refusal::is_refusal));
        let moved = unchanged(false, "the disk's state changed while the volume was read");
        assert!(
            !moved
                .unwrap_err()
                .chain()
                .any(n2r_win32::refusal::is_refusal)
        );
        assert!(unchanged(true, "unused").is_ok());
    }

    #[test]
    fn a_report_says_what_is_refused_what_is_left_and_what_it_takes() {
        let clean = Outcome::Read(Report {
            estimate: Some(estimate(20_000, 400, 300 << 20)),
            ..Report::default()
        });
        let text = lines(&clean, 4096).join("\n");
        assert!(
            text.starts_with("Nothing was found that a conversion refuses."),
            "{text}"
        );
        assert!(
            text.contains("Decided only when the volume is frozen"),
            "{text}"
        );
        assert!(text.contains("20000 file(s), 400 directories"), "{text}");
        assert!(
            text.contains("To 4 KiB ReFS clusters: 300 MiB stay where they are, 0 MiB are copied."),
            "{text}"
        );
        assert!(
            text.contains("Working storage: at least 4096 MiB"),
            "{text}"
        );

        let refused = Outcome::Read(Report {
            refusals: vec!["first reason".into(), "second reason".into()],
            notes: vec!["3 file(s) and directories have an object ID".into()],
            estimate: None,
            cloud: Vec::new(),
            laps: vec![
                ("file records", std::time::Duration::from_millis(1500)),
                (
                    "each file and directory",
                    std::time::Duration::from_millis(700),
                ),
            ],
            plain: Default::default(),
        });
        let text = lines(&refused, 65536).join("\n");
        assert!(
            text.contains("would refuse this volume, for 2 reason(s):"),
            "{text}"
        );
        assert!(
            text.contains("  1. first reason") && text.contains("  2. second reason"),
            "{text}"
        );
        assert!(text.contains("Note: 3 file(s)"), "{text}");
        assert!(
            text.contains(
                "The reading took 2.2 s (file records 1.5 s, each file and directory 0.7 s)."
            ),
            "{text}"
        );
        assert!(!text.contains("What a conversion would take"), "{text}");

        let changing = Outcome::Changing {
            last: "the file records and the bitmap did not agree".into(),
        };
        let text = lines(&changing, 4096).join("\n");
        assert!(
            text.contains("nothing can be said of it and nothing is refused"),
            "{text}"
        );
        assert!(!text.contains("would refuse this volume"), "{text}");
    }
}
