//! Source path queries over a complete held inventory. These return semantic
//! observations only; no serialized result can grant a source certificate.
use crate::ntfs_inspect::{FileInventory, RootFileDomain};
use anyhow::{Context, Result, ensure};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

fn directory_path(files: &impl RootFileDomain, current: u64) -> Result<Vec<String>> {
    // A run that leaves short names behind walks up through directories
    // that have one; otherwise a directory with a second name ends the walk.
    directory_path_for_alias_preparation(files, current, crate::short_name_disposition::dropped())
}

/// What one directory of the chain adds to the path.
enum Step {
    Root,
    Up {
        name: String,
        units: usize,
        parent: u64,
    },
}

/// One directory's step as a walk found it, remembered while a
/// [`DirectoryPathScope`] is open: the step depends only on the directory's
/// row and on whether short names are skipped, both fixed for the held
/// domain.
#[derive(Clone)]
enum KnownStep {
    Root,
    Up {
        name: Rc<str>,
        /// The name's UTF-16 units.
        length: usize,
        parent: u64,
    },
}

/// The domain a scope is open for: its address and type. The scope borrows
/// it, so that neither changes while the scope is open.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DomainKey(usize, &'static str);
fn domain_key<D: RootFileDomain>(files: &D) -> DomainKey {
    DomainKey(
        std::ptr::from_ref(files) as usize,
        std::any::type_name::<D>(),
    )
}

struct StepScope {
    id: u64,
    domain: DomainKey,
    cache: Option<n2r_win32::evict::Evictable<StepCache>>,
    /// Steps not remembered after the ledger refused to pay, or after the
    /// cache was given up, before it is asked again.
    wait: u32,
}
struct StepCache {
    steps: HashMap<(u64, bool), KnownStep>,
    /// What the steps take, at most.
    bytes: u64,
    /// What the reservations below pay for.
    paid: u64,
    _payments: Vec<Box<dyn std::any::Any + Send>>,
}
thread_local! {
    static DIRECTORY_STEPS: RefCell<Option<StepScope>> = const { RefCell::new(None) };
    static NEXT_SCOPE: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}
const STEP_CACHE_CHUNK: u64 = 1 << 20;
const STEP_CACHE_WAIT: u32 = 4096;

/// While it lives, the walks up the directories of one held source domain on
/// this thread remember each directory's step, and every later path through
/// that directory takes it from memory instead of reading the directory's
/// row and its names again: every object's paths are derived several times
/// during the source admission (for the selector's count, the comparison,
/// the admission policy), each time through every directory above it.
///
/// The memory is a cache: paid from the run's ledger in steps of a mebibyte
/// (`n2r_win32::evict::pay_for_cache`), given up with the thread's other
/// caches when a reservation the run needs has no room, and done without
/// where it is refused or there is no ledger. Nothing depends on it: a step
/// it does not hold is read and checked as before, and one it holds was
/// checked when it was read, of the same row (the domain is immutable and
/// borrowed while the scope is open). Every check that depends on the whole
/// path (its length, the bound on its steps) is still made of the whole path.
/// Scopes nest; one closed out of order closes those above it.
pub(crate) struct DirectoryPathScope<'a> {
    id: u64,
    previous: Option<StepScope>,
    _domain: std::marker::PhantomData<&'a ()>,
}
pub(crate) fn hold_directory_paths<D: RootFileDomain>(files: &D) -> DirectoryPathScope<'_> {
    let id = NEXT_SCOPE.with(|next| {
        let id = next.get();
        next.set(id + 1);
        id
    });
    let previous = DIRECTORY_STEPS.with(|scope| {
        scope.borrow_mut().replace(StepScope {
            id,
            domain: domain_key(files),
            cache: None,
            wait: 0,
        })
    });
    DirectoryPathScope {
        id,
        previous,
        _domain: std::marker::PhantomData,
    }
}
impl Drop for DirectoryPathScope<'_> {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let closed = DIRECTORY_STEPS.with(|scope| {
            let mut scope = scope.borrow_mut();
            let ours = scope.as_ref().is_some_and(|open| open.id == self.id);
            // Closed in order, the enclosing scope is open again; out of
            // order, the scopes above it close with it (their domains may
            // no longer be borrowed), and nothing is remembered until one
            // is opened again.
            let closed = scope.take();
            if ours {
                *scope = previous;
            }
            closed
        });
        drop(closed);
    }
}
fn open_scope_for(key: DomainKey) -> bool {
    DIRECTORY_STEPS.with(|scope| {
        scope
            .try_borrow()
            .is_ok_and(|scope| scope.as_ref().is_some_and(|open| open.domain == key))
    })
}
fn known_step(key: DomainKey, current: u64, alias_preparation: bool) -> Option<KnownStep> {
    DIRECTORY_STEPS.with(|scope| {
        let scope = scope.try_borrow().ok()?;
        let open = scope.as_ref().filter(|open| open.domain == key)?;
        let cache = open.cache.as_ref()?.get()?;
        cache.steps.get(&(current, alias_preparation)).cloned()
    })
}
fn remember_step(key: DomainKey, current: u64, alias_preparation: bool, step: KnownStep) {
    let cost = 3
        * (std::mem::size_of::<(u64, bool)>() + std::mem::size_of::<KnownStep>() + 8) as u64
        + match &step {
            KnownStep::Root => 0,
            KnownStep::Up { name, .. } => name.len() as u64 + 16,
        };
    // What more to pay for, decided without holding the cache: paying may
    // give up this thread's caches, this one among them.
    let need = DIRECTORY_STEPS.with(|scope| -> Option<u64> {
        let mut scope = scope.try_borrow_mut().ok()?;
        let open = scope.as_mut().filter(|open| open.domain == key)?;
        if open.wait > 0 {
            open.wait -= 1;
            return None;
        }
        let held = match &open.cache {
            Some(cache) => cache
                .get()
                .map(|cache| (cache.bytes.saturating_add(cost), cache.paid)),
            None => Some((cost, 0)),
        };
        match held {
            Some((wanted, paid)) if wanted <= paid => Some(0),
            Some(_) => Some(STEP_CACHE_CHUNK.max(cost)),
            None => {
                // Given up: asked again after a while.
                open.cache = None;
                open.wait = STEP_CACHE_WAIT;
                None
            }
        }
    });
    let Some(need) = need else {
        return;
    };
    let payment = if need == 0 {
        None
    } else {
        match n2r_win32::evict::pay_for_cache(need) {
            n2r_win32::evict::CachePayment::Paid(payment) => Some(payment),
            _ => {
                DIRECTORY_STEPS.with(|scope| {
                    if let Ok(mut scope) = scope.try_borrow_mut()
                        && let Some(open) = scope.as_mut().filter(|open| open.domain == key)
                    {
                        open.wait = STEP_CACHE_WAIT;
                    }
                });
                return;
            }
        }
    };
    DIRECTORY_STEPS.with(|scope| {
        let Ok(mut scope) = scope.try_borrow_mut() else {
            return;
        };
        let Some(open) = scope.as_mut().filter(|open| open.domain == key) else {
            return;
        };
        if open.cache.as_ref().is_some_and(|cache| !cache.is_held()) {
            open.cache = None;
        }
        let cache = open.cache.get_or_insert_with(|| {
            n2r_win32::evict::Evictable::new(StepCache {
                steps: HashMap::new(),
                bytes: 0,
                paid: 0,
                _payments: Vec::new(),
            })
        });
        let Some(mut cache) = cache.get_mut() else {
            return;
        };
        if let Some(payment) = payment {
            cache._payments.push(payment);
            cache.paid = cache.paid.saturating_add(need);
        }
        if cache.bytes.saturating_add(cost) <= cache.paid
            && cache
                .steps
                .insert((current, alias_preparation), step)
                .is_none()
        {
            cache.bytes += cost;
        }
    });
}

fn directory_path_for_alias_preparation<D: RootFileDomain>(
    files: &D,
    current: u64,
    alias_preparation: bool,
) -> Result<Vec<String>> {
    let key = domain_key(files);
    let remembered = open_scope_for(key).then_some(key);
    walk_directory_path(
        files.file_count(),
        current,
        alias_preparation,
        remembered,
        |current, units| read_directory_step(files, current, units, alias_preparation),
    )
}

/// The walk from the directory `current` up to the root: each directory's
/// step from `read_step` (given the directory and the units of the path so
/// far), or from the open scope's memory where it holds the step.
fn walk_directory_path(
    file_count: u64,
    mut current: u64,
    alias_preparation: bool,
    remembered: Option<DomainKey>,
    mut read_step: impl FnMut(u64, usize) -> Result<Step>,
) -> Result<Vec<String>> {
    let mut components = Vec::new();
    let mut units = 0usize;
    // A canonical parent chain cannot contain more identities than the source.
    // This detects cycles without retaining an all-source visited set.
    for _ in 0..file_count {
        if let Some(key) = remembered
            && let Some(known) = known_step(key, current, alias_preparation)
        {
            match known {
                KnownStep::Root => {
                    components.reverse();
                    return Ok(components);
                }
                KnownStep::Up {
                    name,
                    length,
                    parent,
                } => {
                    // The checks of the directory itself passed when its
                    // step was read; those of the whole path are made here.
                    units = units
                        .checked_add(length)
                        .and_then(|n| n.checked_add(1))
                        .context("source native path length overflow")?;
                    ensure!(
                        units < u16::MAX as usize / 2,
                        "source path exceeds native UTF-16 representation"
                    );
                    components.push(String::from(&*name));
                    current = parent;
                    continue;
                }
            }
        }
        match read_step(current, units)? {
            Step::Root => {
                if let Some(key) = remembered {
                    remember_step(key, current, alias_preparation, KnownStep::Root);
                }
                components.reverse();
                return Ok(components);
            }
            Step::Up {
                name,
                units: longer,
                parent,
            } => {
                if let Some(key) = remembered {
                    remember_step(
                        key,
                        current,
                        alias_preparation,
                        KnownStep::Up {
                            name: Rc::from(name.as_str()),
                            length: longer - units - 1,
                            parent,
                        },
                    );
                }
                units = longer;
                components.push(name);
                current = parent;
            }
        }
    }
    anyhow::bail!("source parent chain cycles or does not reach the root")
}

/// One directory's step, read where the domain holds its row and checked.
fn read_directory_step(
    files: &impl RootFileDomain,
    current: u64,
    units: usize,
    alias_preparation: bool,
) -> Result<Step> {
    {
        let number = current & 0x0000_ffff_ffff_ffff;
        let sequence = (current >> 48) as u16;
        // The directory's row is read where the domain holds it. Every
        // object's path asks for each directory above it; a copy of the row
        // for each of them was most of what building the paths cost.
        files
            .with_record(number, Some(sequence), |directory| {
                let names: Vec<_> = directory
                    .names
                    .iter()
                    .filter(|n| !alias_preparation || n.namespace != 2)
                    .collect();
                ensure!(
                    directory.is_directory
                        && (alias_preparation || directory.hard_link_count == 1)
                        && names.len() == 1
                        && directory.base_file_reference == 0,
                    "source parent is not a canonical single-name directory"
                );
                let name = names[0];
                ensure!(
                    matches!(name.namespace, 0 | 1 | 3),
                    "source namespace is unsupported"
                );
                let parent =
                    name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
                if directory.record_number == 5 {
                    ensure!(
                        name.name_utf16 == [u16::from(b'.')] && parent == current,
                        "source root self-reference differs"
                    );
                    return Ok(Step::Root);
                }
                let units = units
                    .checked_add(name.name_utf16.len())
                    .and_then(|n| n.checked_add(1))
                    .context("source native path length overflow")?;
                ensure!(
                    units < u16::MAX as usize / 2,
                    "source path exceeds native UTF-16 representation"
                );
                Ok(Step::Up {
                    name: String::from_utf16(&name.name_utf16)?,
                    units,
                    parent,
                })
            })?
            .context("source parent identity is missing or stale")
    }
}

/// A path to name a refused object by, in a message. The admission path
/// resolver accepts only names it would transfer, so an object that also has
/// a short name falls through to the resolver that tolerates those. This
/// names an object; it admits nothing.
pub(crate) fn refused_object_path(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Option<Vec<String>> {
    user_paths(files, file)
        .or_else(|_| canonical_paths_for_alias_preparation(files, file))
        .ok()
        .and_then(|paths| paths.into_iter().next())
}

/// Canonical long paths for a separately journaled short-name preparation.
/// This does not satisfy normal source admission or permit dropping aliases.
pub(crate) fn canonical_paths_for_alias_preparation(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Vec<Vec<String>>> {
    ensure!(
        file.base_file_reference == 0,
        "canonical base required for alias preparation"
    );
    let canonical: Vec<_> = file.names.iter().filter(|n| n.namespace != 2).collect();
    // The Windows path preserves the raw FILE counter as a hint; complete
    // MFT/I30 coverage and native canonical link counts establish the names.
    ensure!(
        !canonical.is_empty()
            && canonical.iter().all(|n| matches!(n.namespace, 0 | 1 | 3))
            && (!file.is_directory || canonical.len() == 1),
        "canonical name/link coverage differs"
    );
    for alias in file.names.iter().filter(|n| n.namespace == 2) {
        ensure!(
            canonical
                .iter()
                .any(|n| n.parent_record_number == alias.parent_record_number
                    && n.parent_sequence_number == alias.parent_sequence_number),
            "DOS alias has no canonical parent identity"
        );
    }
    let mut paths = Vec::new();
    for name in canonical {
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        let mut path = directory_path_for_alias_preparation(files, parent, true)?;
        if file.record_number != 5 {
            path.push(String::from_utf16(&name.name_utf16)?);
        }
        // The default route's rule for a file and a directory alike: the
        // path has to fit Windows' extended-length form. (The second
        // argument says which route's rule applies, not what the object
        // is; `!file.is_directory` held every directory of a Windows
        // volume to the older routes' sixteen components.)
        ensure!(
            crate::shadow_tree::expected_path_fits(&path, true),
            "the path \\{} does not fit Windows' extended-length form",
            path.join("\\")
        );
        paths.push(path);
    }
    Ok(paths)
}

pub(crate) fn user_paths(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Vec<Vec<String>>> {
    // `--short-names drop`: an object's long names are what is transferred.
    // Its 8.3 names are listed in the run's records and left behind, so
    // they are not names to carry. NTFS counts a short name among the
    // file record's links, so the record's count is still that of all its
    // names.
    if crate::short_name_disposition::dropped() && file.names.iter().any(|n| n.namespace == 2) {
        ensure!(
            usize::from(file.hard_link_count) == file.names.len(),
            "the file record's link count is not the number of its names"
        );
        return canonical_paths_for_alias_preparation(files, file);
    }
    ensure!(
        !file.names.is_empty()
            && usize::from(file.hard_link_count) == file.names.len()
            && file.names.iter().all(|n| matches!(n.namespace, 0 | 1 | 3))
            && (!file.is_directory || file.names.len() == 1),
        "source name/link domain is unsupported or incomplete"
    );
    if file.is_directory {
        return Ok(vec![directory_path(
            files,
            file.record_number | (u64::from(file.sequence_number) << 48),
        )?]);
    }
    let mut paths = Vec::new();
    paths.try_reserve_exact(file.names.len())?;
    for name in &file.names {
        let parent = name.parent_record_number | (u64::from(name.parent_sequence_number) << 48);
        let mut path = directory_path(files, parent)?;
        path.push(String::from_utf16(&name.name_utf16)?);
        ensure!(
            crate::shadow_tree::expected_path_fits(&path, true),
            "source file path exceeds native UTF-16 representation"
        );
        paths.push(path);
    }
    paths.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
    ensure!(
        !paths.windows(2).any(|p| p[0] == p[1]),
        "source name is duplicated"
    );
    Ok(paths)
}

pub(crate) fn internal_role(
    files: &impl RootFileDomain,
    file: &FileInventory,
) -> Result<Option<String>> {
    // Ordinary objects cannot be replaced as NTFS internals. Their complete
    // user paths are checked by the caller's ordinary or Windows policy.
    if file.record_number >= 16
        && file.metadata_role == crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate
    {
        return Ok(None);
    }
    // Exact internal roles have a single canonical name (or that name and
    // the DOS short name Windows made beside it, which is not a path of its
    // own: super::sole_name). Reserved nameless slots are recognized before
    // the closure is called by the shared policy.
    let path = match super::sole_name(file) {
        Some(_) if file.names.len() == 1 => user_paths(files, file)
            .with_context(|| format!("NTFS internal-role path at FILE {}", file.record_number))?
            .pop(),
        Some(long) => {
            let mut named = file.clone();
            named.names = vec![long.clone()];
            named.hard_link_count = 1;
            user_paths(files, &named)
                .with_context(|| format!("NTFS internal-role path at FILE {}", file.record_number))?
                .pop()
        }
        None => None,
    };
    Ok(super::internal_role_with_path(file, || path))
}

/// Classify one raw inspection blocker using the actual retained source and
/// independent internal-state proofs. This is a diagnostic, not admission:
/// native identity, namespace, security, frozen-source and target checks are
/// still required by the enclosing live conversion.
pub(crate) fn blocker_is_unresolved(
    source: &crate::ntfs_inspect::PagedInspection,
    blocker: &crate::ntfs_inspect::InspectionBlocker,
    backups: &crate::ntfs_backup::VerifiedBackups,
    log: &crate::ntfs_log::VerifiedRestart,
    indexes: &crate::ntfs_internal::PagedVerifiedIndexes,
    transactions: &crate::ntfs_transactions::VerifiedTransactions,
    native_short_names_disabled_without_dos_aliases: bool,
) -> Result<bool> {
    use crate::ntfs_inspect::LogicalHashStatus;
    if matches!(
        blocker.code.as_str(),
        "security_descriptors_unresolved"
            | "directory_indexes_unverified"
            | "allocation_ownership_unverified"
    ) {
        return Ok(false);
    }
    if blocker.code == "backup_boot_unverified" && backups.binds_domain(source) {
        return Ok(false);
    }
    if blocker.code == "journal_state_unverified"
        && log.binds_domain(source)
        && log.restart.candidate_clean_dismount
    {
        return Ok(false);
    }
    if blocker.code == "volume_state_flags"
        && source.header().volume_flags == Some(0x80)
        && native_short_names_disabled_without_dos_aliases
    {
        return Ok(false);
    }
    if blocker.code == "object_id"
        && blocker.file_record_number == Some(3)
        && indexes.covers_volume_object_id_domain(source, 3)
    {
        return Ok(false);
    }
    if blocker.code == "object_id" && source.is_windows_conversion() {
        if let (Some(number), Some(domain)) = (
            blocker.file_record_number,
            indexes.windows_object_ids_owned(),
        ) {
            if let Some(file) = source.find_record(number, None)? {
                if domain.accounted(source, &file)? {
                    return Ok(false);
                }
            }
        }
    }
    if blocker.code == "object_id" && !source.is_windows_conversion() {
        if let (Some(number), Some(domain)) =
            (blocker.file_record_number, indexes.data_object_ids_owned())
        {
            if let Some(file) = source.find_record(number, None)? {
                if domain.accounted(source, &file)? {
                    return Ok(false);
                }
            }
        }
    }
    if blocker.code == "unsupported_attribute"
        && blocker.message == "Attribute type 0x100 needs a preservation policy"
        && transactions.binds_domain(source)
    {
        if let Some(number) = blocker.file_record_number {
            if let Some(file) = source.find_record(number, None)? {
                let role = internal_role(source, &file)?;
                let windows_user_txf = if let Some(proof) = transactions.windows_txf_markers_owned()
                {
                    crate::ntfs_transactions::windows_user_marker(source, &file, &proof)?
                } else {
                    false
                };
                if (number == 5
                    || role.as_deref() == Some("$Extend\\$RmMetadata\\$Txf")
                    || windows_user_txf)
                    && file
                        .attributes
                        .iter()
                        .filter(|a| {
                            a.type_code == 0x100
                                && a.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
                        })
                        .count()
                        == 1
                    && file.attributes.iter().any(super::recognized_root_txf)
                    && file
                        .attributes
                        .iter()
                        .filter(|a| a.type_code == 0x100)
                        .all(super::recognized_root_txf)
                {
                    return Ok(false);
                }
            }
        }
    }
    // What the raw inspection reports of an EFS object this run makes
    // plain: its encryption, its $EFS attribute and its stream without a
    // raw logical hash. The plain copy stands for all three.
    if let Some(number) = blocker.file_record_number
        && crate::plain_projection::efs_blocker(&blocker.code, &blocker.message)
        && let Some(file) = source.find_record(number, None)?
        && crate::plain_projection::efs_taken(&file)
    {
        return Ok(false);
    }
    // What the inspection reports of an object of a data volume that is
    // not carried over (below System Volume Information's folders), about
    // that object alone.
    if !source.is_windows_conversion()
        && let Some(number) = blocker.file_record_number
        && let Some(file) = source.find_record(number, None)?
        && blocker_of_object_not_carried(source, &file, &blocker.code)
    {
        return Ok(false);
    }
    if blocker.code == "logical_stream_hash_unavailable"
        && blocker.file_record_number == Some(8)
        && blocker.message
            == "DATA attribute 1 has no complete logical hash: UnsupportedBadClusterMetadata"
    {
        if let Some(file) = source.find_record(8, None)? {
            if internal_role(source, &file)?.as_deref() == Some("$BadClus")
                && file.streams.len() == 2
            {
                let unnamed = file.streams.iter().find(|s| s.name_utf16.is_empty());
                let bad = file
                    .streams
                    .iter()
                    .find(|s| s.name_utf16 == [36, 66, 97, 100]);
                if let (Some(unnamed), Some(bad)) = (unnamed, bad) {
                    let geometry = &source.header().geometry;
                    if unnamed.resident
                        && unnamed.logical_size == 0
                        && unnamed.extents.is_empty()
                        && unnamed.logical_hash_status == LogicalHashStatus::Complete
                        && !bad.resident
                        && bad.flags == 0
                        && geometry
                            .total_clusters
                            .checked_mul(u64::from(geometry.cluster_size))
                            == Some(bad.logical_size)
                        && bad.initialized_size == 0
                        && bad.allocated_size == bad.logical_size
                        && bad.logical_hash_status
                            == LogicalHashStatus::UnsupportedBadClusterMetadata
                        && bad.extents.len() == 1
                        && bad.extents[0].logical_offset == 0
                        && bad.extents[0].physical_offset.is_none()
                        && bad.extents[0].length == bad.logical_size
                    {
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

/// The same per-file preservation policy used by the legacy inspector, with
/// paths and security resolved from the actual held paged source owner.
/// Global page closure belongs to the enclosing producer, not one full-source
/// rescan per object. These diagnostics grant no admission or write authority.
pub(crate) fn ordinary_user_issues(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<Vec<String>> {
    // A volume that shares its disk is not given what a dedicated one's
    // admission leaves out of System Volume Information.
    ordinary_user_issues_scoped(source, file, resources, None, None, false, false)
}

/// The policy for a data volume whose object IDs have been matched and
/// archived: such an ID is not a reason to refuse its file.
pub(crate) fn ordinary_user_issues_data(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
) -> Result<Vec<String>> {
    ordinary_user_issues_scoped(source, file, resources, None, object_ids, false, true)
}

/// The data-volume policy applied to the inspection of a volume that is
/// still in use, for a check made before anything is frozen. Nothing has
/// been read of any stream's contents then, and that alone is not held
/// against a stream: one that the inspection found in a form the converter
/// does not read carries a status that says so, and is refused as it will
/// be. Everything else is the policy a conversion applies.
pub(crate) fn ordinary_user_issues_before_freeze(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
) -> Result<Vec<String>> {
    ensure!(
        source.is_preparation_only(),
        "the policy before the freeze applies to the inspection of a volume in use"
    );
    ordinary_user_issues_scoped(source, file, resources, None, object_ids, true, true)
}

pub(crate) fn ordinary_user_issues_windows(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    aliases: &crate::boot_alias::WindowsAliasDomain,
) -> Result<Vec<String>> {
    ordinary_user_issues_scoped(source, file, resources, Some(aliases), None, false, false)
}

fn ordinary_user_issues_scoped(
    source: &crate::ntfs_inspect::PagedInspection,
    file: &FileInventory,
    resources: n2r_win32::tree_resources::SourceResourceAdmission,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
    object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
    // The inspection was made before the freeze: no stream has been read yet.
    before_freeze: bool,
    // A data volume's System Volume Information below its immediate folders
    // is not carried over (`system_volume_information_not_carried`).
    leaves_system_out: bool,
) -> Result<Vec<String>> {
    resources.validate()?;
    let budget = source.budget();
    let expected_budget =
        crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(resources.budget)?;
    ensure!(
        source.header().inventory_complete
            && source.canonical_sha256()? == hex::encode(resources.source_inspection_sha256)
            && resources.mft_records == source.header().mft_record_count
            && resources.raw_identities == source.file_count()
            && file.record_number < resources.mft_records
            && budget.ram_bytes == resources.budget.ram_bytes
            && budget.scratch_bytes == expected_budget.scratch_bytes
            && budget.record_bytes == resources.budget.max_row_bytes
            && budget.page_bytes == resources.budget.page_bytes,
        "ordinary policy source/resource identity differs"
    );
    let paths = if let Some(aliases) = aliases {
        if let Some(proof) = aliases.storage_hint_normalization() {
            let _ = crate::ntfs_storage_class::normalize(file, proof)?;
        }
        Some(aliases.user_paths(source, file)?)
    } else {
        user_paths(source, file).ok()
    };
    // What a data volume carries of System Volume Information, decided
    // here, where the check before the freeze and the admission at it both
    // see it, and not first by the native construction after the freeze.
    // An object below its immediate folders is not carried over: what it
    // holds is not asked about, only whether Data Deduplication's files
    // still need it. (A Windows volume's system folders are the boot
    // route's own.)
    let mut split_system_names = None;
    if let Some(paths) = paths.as_deref().filter(|_| aliases.is_none()) {
        match super::system_not_carried(paths, file) {
            Ok(false) => {}
            Ok(true) if leaves_system_out => {
                return Ok(super::chunk_store_issue(paths, file, || {
                    deduplicated_files_remain(source)
                })?
                .into_iter()
                .collect());
            }
            Ok(true) => {
                return Ok(vec![format!(
                    "it is \\{} (MFT record {}), below the folders of System Volume Information, which the conversion of a volume that shares its disk carries no object of",
                    paths[0].join("\\"),
                    file.record_number
                )]);
            }
            Err(split) => split_system_names = Some(split),
        }
    }
    let names_supported = paths.is_some();
    let system_volume_information = paths.as_ref().is_some_and(|paths| {
        paths.iter().any(|path| {
            path.first()
                .is_some_and(|name| name.eq_ignore_ascii_case("System Volume Information"))
        })
    });
    let descriptor = if let Some(binding) = source.security().find_binding(file.record_number)? {
        ensure!(
            binding.sequence_number == file.sequence_number,
            "ordinary security binding has a stale file sequence"
        );
        let descriptor = if let Some(id) = binding.security_id {
            source.security().find_id(id)?
        } else {
            source.security().find_legacy(file.record_number)?
        };
        if let Some(record) = &descriptor {
            ensure!(
                record.descriptor.sha256 == binding.descriptor_sha256,
                "ordinary security descriptor differs from its complete binding"
            );
        }
        descriptor
    } else {
        None
    };
    let mut evidence = std::collections::BTreeMap::new();
    for stream in &file.streams {
        let valid = match stream.logical_hash_status {
            crate::ntfs_inspect::LogicalHashStatus::Complete => stream
                .logical_sha256
                .as_deref()
                .is_some_and(n2r_win32::content_digest::is_hex),
            crate::ntfs_inspect::LogicalHashStatus::NotReadExtentIdentityV1 => {
                // The object's paths were derived above; a run that verifies
                // once does not derive them again for each such stream.
                stream.logical_sha256.is_none()
                    && crate::ntfs_attestation::extent_identity_stream_request_observed(
                        source,
                        file,
                        stream,
                        aliases.is_some(),
                    )?
                    .is_some()
            }
            // Still to be read. (A stream the inspection could not read has
            // one of the other statuses, and stays refused.)
            crate::ntfs_inspect::LogicalHashStatus::NotComputed => {
                before_freeze && source.is_preparation_only() && stream.logical_sha256.is_none()
            }
            _ => false,
        };
        evidence.insert(&stream.name_utf16, valid);
    }
    let maximum_streams = usize::try_from(
        resources.budget.max_row_bytes
            / std::mem::size_of::<crate::ntfs_inspect::StreamInventory>() as u64,
    )?;
    let mut issues = super::user_issues_with_context_alias_scope(
        file,
        true,
        &source.header().geometry,
        names_supported,
        system_volume_information,
        descriptor.as_ref(),
        Some(resources.budget.max_row_bytes),
        maximum_streams,
        aliases.is_some(),
        aliases.is_some_and(|aliases| aliases.storage_hint_normalization().is_some()),
        if let Some(aliases) = aliases {
            aliases.windows_txf_accounted(source, file)?
        } else {
            false
        },
        if let Some(aliases) = aliases {
            aliases.windows_object_id_accounted(source, file)?
        } else if let Some(object_ids) = object_ids {
            object_ids.accounted(source, file)?
        } else {
            false
        },
        |stream| evidence.get(&stream.name_utf16).copied().unwrap_or(false),
    );
    issues.extend(split_system_names);
    Ok(issues)
}

/// Whether `code`, a condition the inspection reports of `file` alone (its
/// contents unread, its encryption or compression, an attribute the
/// converter does not carry), is settled because a data volume's
/// conversion does not carry the object over: it is below System Volume
/// Information's folders. Conditions of the volume, or of how the object's
/// record is assembled, are not.
pub(crate) fn blocker_of_object_not_carried(
    source: &impl RootFileDomain,
    file: &FileInventory,
    code: &str,
) -> bool {
    matches!(
        code,
        "logical_stream_hash_unavailable"
            | "unsupported_attribute"
            | "ntfs_encryption"
            | "encrypted_file_attribute"
            | "ntfs_compression"
            | "compressed_file_attribute"
    ) && user_paths(source, file)
        .is_ok_and(|paths| super::system_not_carried(&paths, file) == Ok(true))
}

/// Whether a file Data Deduplication has optimized, which this run does not
/// make plain, is on the volume: what its chunk store is kept for. Found
/// once for a source, and asked only where the chunk store is met.
fn deduplicated_files_remain(source: &crate::ntfs_inspect::PagedInspection) -> Result<bool> {
    static FOUND: std::sync::Mutex<Option<(String, bool, bool)>> = std::sync::Mutex::new(None);
    let source_sha256 = source.canonical_sha256()?;
    let taking = crate::plain_consent::takes_plain();
    if let Some((sha, took, remain)) = FOUND
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        && *sha == source_sha256
        && *took == taking
    {
        return Ok(*remain);
    }
    let mut remain = false;
    for ordinal in 0..source.file_count() {
        if source.with_file(ordinal, |file| {
            Ok(file.reparse.as_ref().is_some_and(|point| {
                point.tag() == n2r_win32::reparse_layout::IO_REPARSE_TAG_DEDUP
            }) && !crate::plain_projection::dedup_taken(file))
        })? {
            remain = true;
            break;
        }
    }
    *FOUND
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((source_sha256, taking, remain));
    Ok(remain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A ledger of this test's thread that pays for caches while it has room.
    struct Ledger {
        room: Cell<bool>,
        live: Cell<bool>,
    }
    impl n2r_win32::evict::CachePayer for Ledger {
        fn limit(&self) -> Option<u64> {
            self.live.get().then_some(1 << 30)
        }
        fn pay(&self, bytes: u64) -> Option<Box<dyn std::any::Any + Send>> {
            self.room
                .get()
                .then(|| Box::new(bytes) as Box<dyn std::any::Any + Send>)
        }
    }
    fn ledger(room: bool) -> Rc<Ledger> {
        let ledger = Rc::new(Ledger {
            room: Cell::new(room),
            live: Cell::new(true),
        });
        n2r_win32::evict::register_cache_payer(ledger.clone());
        ledger
    }

    const ROOT: u64 = 5 | (5 << 48);
    fn directory(record: u64) -> u64 {
        record | (1 << 48)
    }
    /// Root \ A \ B \ C, with the names given.
    fn walk(
        names: [&str; 3],
        start: u64,
        remembered: Option<DomainKey>,
        reads: &Cell<u32>,
    ) -> Result<Vec<String>> {
        walk_directory_path(1000, start, false, remembered, |current, units| {
            reads.set(reads.get() + 1);
            if current == ROOT {
                return Ok(Step::Root);
            }
            let (name, parent) = match current & 0xffff {
                30 => (names[0], ROOT),
                31 => (names[1], directory(30)),
                32 => (names[2], directory(31)),
                _ => anyhow::bail!("source parent identity is missing or stale"),
            };
            let units = units + name.len() + 1;
            ensure!(
                units < u16::MAX as usize / 2,
                "source path exceeds native UTF-16 representation"
            );
            Ok(Step::Up {
                name: name.into(),
                units,
                parent,
            })
        })
    }
    fn open(key: DomainKey) {
        DIRECTORY_STEPS.with(|scope| {
            *scope.borrow_mut() = Some(StepScope {
                id: u64::MAX,
                domain: key,
                cache: None,
                wait: 0,
            })
        });
    }
    fn close() {
        let closed = DIRECTORY_STEPS.with(|scope| scope.borrow_mut().take());
        drop(closed);
    }

    #[test]
    fn a_directory_s_step_is_read_once_while_a_scope_is_open() {
        let ledger = ledger(true);
        let key = DomainKey(1, "test domain");
        let names = ["Windows", "System32", "drivers"];
        let reads = Cell::new(0);
        let expected = vec!["Windows", "System32", "drivers"];
        // Without a scope every step is read, every time.
        assert_eq!(walk(names, directory(32), None, &reads).unwrap(), expected);
        assert_eq!(walk(names, directory(32), None, &reads).unwrap(), expected);
        assert_eq!(reads.get(), 8);
        open(key);
        reads.set(0);
        assert_eq!(
            walk(names, directory(32), Some(key), &reads).unwrap(),
            expected
        );
        assert_eq!(reads.get(), 4);
        // The same path and a path through the same directories: no read.
        assert_eq!(
            walk(names, directory(32), Some(key), &reads).unwrap(),
            expected
        );
        assert_eq!(
            walk(names, directory(31), Some(key), &reads).unwrap(),
            ["Windows", "System32"]
        );
        assert_eq!(reads.get(), 4);
        // Another domain's walks are not served from it.
        let other = DomainKey(2, "test domain");
        assert_eq!(
            walk(names, directory(31), Some(other), &reads).unwrap(),
            ["Windows", "System32"]
        );
        assert_eq!(reads.get(), 7);
        // Given up with the thread's caches, the steps are read again.
        assert!(n2r_win32::evict::evict_all());
        assert_eq!(
            walk(names, directory(32), Some(key), &reads).unwrap(),
            expected
        );
        assert_eq!(reads.get(), 11);
        close();
        ledger.live.set(false);
    }

    #[test]
    fn nothing_is_remembered_without_a_payment_and_whole_paths_are_still_checked() {
        let ledger = ledger(false);
        let key = DomainKey(3, "test domain");
        let names = ["Windows", "System32", "drivers"];
        let reads = Cell::new(0);
        open(key);
        walk(names, directory(32), Some(key), &reads).unwrap();
        walk(names, directory(32), Some(key), &reads).unwrap();
        assert_eq!(reads.get(), 8, "refused: every step is read");
        close();

        // Each name fits; two of them together are longer than a path may be.
        ledger.room.set(true);
        let long = "x".repeat(20_000);
        let names = [long.as_str(), long.as_str(), "c"];
        let key = DomainKey(4, "test domain");
        open(key);
        let reads = Cell::new(0);
        walk(names, directory(30), Some(key), &reads).unwrap();
        for remembered in [None, Some(key)] {
            let error = walk(names, directory(31), remembered, &reads).unwrap_err();
            assert_eq!(
                error.to_string(),
                "source path exceeds native UTF-16 representation"
            );
        }
        close();
        ledger.live.set(false);
    }
}
