//! Actual ordinary metadata artifacts in one scratch arena. These owning
//! capabilities are deliberately not serializable and grant no device rights.
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralDiskBinding,
    reference_file::{self, ReferenceFileSnapshot},
    tree_resources::ResourceBudget,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf, Prefix},
    sync::{Arc, Mutex, Weak},
    time::SystemTime,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactGroup {
    Source,
    Native,
    Expected,
    Map,
    LegacyExpectation,
    Auxiliary,
    RecoveryCopy,
    Capture,
    NativeJournal,
}
impl ArtifactGroup {
    fn limit(self, budget: ResourceBudget, windows_native: bool) -> u64 {
        match self {
            Self::Native if windows_native => budget.scratch_bytes / 16 * 3,
            Self::LegacyExpectation if windows_native => 0,
            Self::Source | Self::Native | Self::Expected | Self::Map | Self::Auxiliary => {
                budget.scratch_bytes / 8
            }
            Self::LegacyExpectation => budget.scratch_bytes / 16,
            Self::RecoveryCopy => budget.scratch_bytes / 16 * 5,
            // Selected literal/index/route backing uses the actual remaining
            // shared total, never a disguised enlargement of source pages.
            Self::Capture | Self::NativeJournal => budget.scratch_bytes,
        }
    }
}
struct Group {
    maximum: u64,
    held: u64,
    files: u64,
    sealed: bool,
    poisoned: bool,
    native_journal:
        Option<crate::general_reconstruct::selected_native_journal::NativeJournalAllocationOwner>,
}
struct Entry {
    group: ArtifactGroup,
    reserved: u64,
    maximum: u64,
    registry_bytes: u64,
    verified: Option<Verified>,
    lease: Weak<FilePin>,
    external_readonly: bool,
    allocation_slack: u64,
}
struct Verified {
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    // The digest the file's records name, in hex: the BLAKE3 of a record
    // store in the current format (its header says so), the SHA-256 of any
    // other file. The field keeps its historical name.
    sha256: String,
    // The BLAKE3 of the same bytes: what a later full re-read of the held
    // file is compared with. The same value as `sha256` for a store.
    reread: [u8; 32],
}
struct State {
    windows_native_allocation: bool,
    groups: BTreeMap<ArtifactGroup, Group>,
    entries: BTreeMap<PathBuf, Entry>,
    // The same immutable verified snapshots previously folded in check_free.
    // Updated only with their installation/removal under this mutex.
    verified_allocated_bytes: u64,
    verified_local_allocated_bytes: u64,
    external_roots: BTreeMap<PathBuf, Arc<ExternalOriginRoot>>,
    // A reopened file must not earn allocation credit twice through spelling
    // aliases. This is keyed by actual held file identity, never a pathname.
    verified_identities: BTreeSet<(u64, [u8; 16])>,
    allocation_poisoned: bool,
    overhead: u64,
    index_bytes: u64,
    leased_ram_bytes: u64,
    // How far what the run cannot do without may go beyond the budget: 0
    // until the budget came short in a run that fits itself to the machine.
    beyond_budget_bytes: u64,
    // The same bytes by the place in the code that holds them.
    ram_by_site: BTreeMap<RamSite, u64>,
    // The places that reserve caches, so that a ledger that runs out says
    // which of its largest holders could have been given up.
    cache_sites: BTreeSet<RamSite>,
    // The part of `leased_ram_bytes` held by optional caches.
    optional_ram_bytes: u64,
    // Of the optional total, what `reserve_cache_ram` granted: caches that
    // are held while the ledger has room and are outside the caches' quota.
    cache_ram_bytes: u64,
    // What spare reservations hold and what they have to leave room for.
    spare: SpareMemory,
    ram_poisoned: bool,
    prepared_closed: bool,
}
struct Inner {
    // Two thirds of the memory that was free when the ledger was made.
    cache_basis_bytes: u64,
    // For a run that fits itself to the machine: what the ledger may hold
    // with things it holds only to go faster, as of the last look at what
    // Windows has available (0 before the first), and when that look was,
    // in milliseconds since the ledger was made.
    made: std::time::Instant,
    fitted_ceiling: std::sync::atomic::AtomicU64,
    fitted_at_ms: std::sync::atomic::AtomicU64,
    root: PathBuf,
    root_guid: String,
    allocation_slack: u64,
    _parents: Vec<File>,
    budget: ResourceBudget,
    state: Mutex<State>,
    excluded: Vec<([u8; 16], [u8; 16])>,
    config_registry_bytes: u64,
}
/// Only live held directory/volume observations can enroll an immutable origin.
/// No path list, serialized flag, source writer or allocation credit is issued.
struct ExternalOriginRoot {
    root: PathBuf,
    root_guid: String,
    root_id: String,
    allocation_slack: u64,
    registry_bytes: u64,
    parents: Vec<File>,
}
impl ExternalOriginRoot {
    fn revalidate(&self) -> Result<()> {
        let root = self
            .parents
            .first()
            .context("external origin root handle absent")?;
        ensure!(
            root.metadata()?.is_dir()
                && root.metadata()?.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::file_id_info(root)? == self.root_id
                && n2r_win32::file_storage::final_path_guid(root)?
                    .eq_ignore_ascii_case(&self.root_guid),
            "held external readonly origin root changed"
        );
        Ok(())
    }
}
#[derive(Clone)]
pub struct ArtifactArena(Arc<Inner>);
/// This ledger as the payer of caches decided on where it is not at hand
/// ([`n2r_win32::evict::pay_for_cache`]), for as long as it lives.
struct ArenaCachePayer(std::sync::Weak<Inner>);
impl n2r_win32::evict::CachePayer for ArenaCachePayer {
    fn limit(&self) -> Option<u64> {
        self.0.upgrade().map(|inner| inner.budget.ram_bytes)
    }
    fn pay(&self, bytes: u64) -> Option<Box<dyn std::any::Any + Send>> {
        let arena = ArtifactArena(self.0.upgrade()?);
        let lease = arena.reserve_cache_ram(bytes).ok()?;
        Some(Box::new(lease))
    }
}
/// A live share of the arena's aggregate working-memory budget.
pub struct ArenaRamLease {
    arena: ArtifactArena,
    bytes: u64,
    // Taken by `reserve_optional_ram` or `reserve_cache_ram`: counted in the
    // optional total as well.
    optional: bool,
    // Taken by `reserve_cache_ram`: counted outside the caches' quota too.
    cache: bool,
    // Taken by `reserve_spare_ram` and not kept yet: counted in the spare
    // total as well.
    spare: bool,
    // Where in the code it was taken: what the ledger names when it runs out.
    site: RamSite,
}

/// The place in the code a reservation was made at: file and line.
type RamSite = (&'static str, u32);

/// What `site` holds less `bytes` (a lease returned, or shrunk).
fn release_site(held: &mut BTreeMap<RamSite, u64>, site: RamSite, bytes: u64) {
    if let Some(total) = held.get_mut(&site) {
        *total = total.saturating_sub(bytes);
        if *total == 0 {
            held.remove(&site);
        }
    }
}

/// Tells the run's timing what the ledger holds after a reservation, and
/// what holds it when what the run cannot do without has grown.
fn note_ledger(state: &State, limit: u64) {
    let held = state.leased_ram_bytes.saturating_add(state.index_bytes);
    let needed = held
        .saturating_sub(state.optional_ram_bytes)
        .saturating_sub(state.spare.held);
    if n2r_win32::perf::note_ledger(held, needed, limit) {
        n2r_win32::perf::note_ledger_holders(
            needed,
            largest_sites(&state.ram_by_site, &state.cache_sites),
        );
    }
}

/// The largest reservations, for the message of a ledger that ran out:
/// without them it says how much is held and not by what. A cache is
/// marked as one: where the ledger ran out beside one, it was in use at
/// that moment or another thread's.
fn largest_sites(held: &BTreeMap<RamSite, u64>, caches: &BTreeSet<RamSite>) -> String {
    let mut sites: Vec<(&RamSite, &u64)> = held.iter().collect();
    sites.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    sites
        .iter()
        .take(6)
        .map(|(site, bytes)| {
            let (file, line) = site;
            format!(
                "{} MiB at {}:{line}{}",
                **bytes / (1024 * 1024),
                file.rsplit(['/', '\\']).next().unwrap_or(file),
                if caches.contains(site) {
                    " (a cache)"
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}
impl ArenaRamLease {
    /// What this lease holds of the ledger.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Return unused capacity while retaining the remainder of this lease.
    pub fn shrink_to(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            bytes <= self.bytes,
            "arena RAM lease cannot grow by shrinking"
        );
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(!state.ram_poisoned, "arena RAM ledger is poisoned");
        state.leased_ram_bytes = state
            .leased_ram_bytes
            .checked_sub(self.bytes - bytes)
            .context("arena RAM lease shrink underflow")?;
        if self.optional {
            state.optional_ram_bytes = state
                .optional_ram_bytes
                .checked_sub(self.bytes - bytes)
                .context("arena optional RAM lease shrink underflow")?;
        }
        if self.cache {
            state.cache_ram_bytes = state
                .cache_ram_bytes
                .checked_sub(self.bytes - bytes)
                .context("arena cache RAM lease shrink underflow")?;
        }
        if self.spare {
            // What a pass keeps of a workspace, shrunk to what it retains,
            // is no longer memory it can do without.
            state.spare.returned(self.bytes);
            self.spare = false;
        }
        release_site(&mut state.ram_by_site, self.site, self.bytes - bytes);
        self.bytes = bytes;
        Ok(())
    }
}
#[derive(Clone)]
pub struct ArtifactGroupPermit {
    arena: ArtifactArena,
    group: ArtifactGroup,
}
pub struct ArtifactPathPermit {
    group: ArtifactGroupPermit,
    path: PathBuf,
    _parents: Vec<File>,
    complete: bool,
    external_origin: Option<Arc<ExternalOriginRoot>>,
    allocation_slack: u64,
}
struct FilePin {
    arena: ArtifactArena,
    file: Mutex<Option<File>>,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    sha256: String,
    // See `Verified::reread`.
    reread: [u8; 32],
    _parents: Vec<File>,
    external_origin: Option<Arc<ExternalOriginRoot>>,
    last_full: n2r_win32::verify_policy::LastFull,
}
struct SealedPins {
    pins: Vec<Arc<FilePin>>,
    // Drop the pin vector before returning its prepaid memory.
    _ram: ArenaRamLease,
}
#[derive(Clone)]
pub struct ArtifactLease {
    group: ArtifactGroupPermit,
    path: PathBuf,
    pin: Arc<FilePin>,
}
#[derive(Clone)]
pub struct ArtifactGroupSeal {
    permit: ArtifactGroupPermit,
    pins: Arc<SealedPins>,
    wire_bytes: u64,
    allocated_bytes: u64,
}
/// Exhaustive live ownership after every preparation artifact has closed.
/// It is neither serializable nor a source/journal activation capability.
pub(crate) struct PreparedArenaClosure {
    ordinary: Vec<ArtifactGroupSeal>,
    native_quota: ArtifactGroupPermit,
    arena: ArtifactArena,
    native_length: u64,
    native_reservation: u64,
    // All retained vectors/owners drop before returning their collection RAM.
    _ram: ArenaRamLease,
}
/// An immediate read-only validation boundary over the exact closed arena.
/// This private runtime borrow cannot be serialized or survive its callback.
/// Every covered file is fully hashed before and after the callback; nested
/// checks may reuse that work only for the identical retained file owner.
pub(crate) struct PreparedArenaRevalidation<'boundary> {
    closure: &'boundary PreparedArenaClosure,
}
impl PreparedArenaRevalidation<'_> {
    fn require_artifact(&self, artifact: &ArtifactLease) -> Result<()> {
        ensure!(
            self.closure.arena.same_arena(&artifact.group.arena)
                && self.closure.ordinary.iter().any(|seal| {
                    seal.permit.group == artifact.group.group
                        && seal
                            .pins
                            .pins
                            .iter()
                            .any(|pin| Arc::ptr_eq(pin, &artifact.pin))
                }),
            "artifact is not the exact held owner in this prepared arena boundary"
        );
        artifact.pin.revalidate_identity()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ArenaUsage {
    pub promised_bytes: u64,
    pub actual_wire_bytes: u64,
    pub actual_allocated_bytes: u64,
    pub files: u64,
    pub leased_ram_bytes: u64,
    pub registry_ram_bytes: u64,
    /// Only bytes on the active workspace volume can offset its promises.
    pub local_allocation_credit_bytes: u64,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("artifact arena accounting overflow")
}
impl State {
    /// Independently reconcile the hot-path credit against every verified
    /// registry entry before reporting usage or issuing a sealed owner.
    fn reconciled_verified_totals(&mut self) -> Result<(u64, u64)> {
        ensure!(
            !self.allocation_poisoned,
            "artifact allocation ledger is poisoned"
        );
        let mut identities = 0usize;
        let mut local_allocated = 0u64;
        let totals = self
            .entries
            .values()
            .filter_map(|entry| entry.verified.as_ref().map(|verified| (entry, verified)))
            .try_fold((0, 0), |(wire, allocated), (entry, verified)| {
                ensure!(
                    self.verified_identities.contains(&(
                        verified.snapshot.volume_serial_number,
                        verified.snapshot.file_id_128,
                    )),
                    "verified artifact identity is absent from registry"
                );
                identities = identities
                    .checked_add(1)
                    .context("artifact identity count overflow")?;
                if !entry.external_readonly {
                    local_allocated = add(local_allocated, verified.snapshot.allocation_bytes)?;
                }
                Ok::<_, anyhow::Error>((
                    add(wire, verified.snapshot.file_bytes)?,
                    add(allocated, verified.snapshot.allocation_bytes)?,
                ))
            });
        match totals {
            Ok((wire, allocated))
                if allocated == self.verified_allocated_bytes
                    && local_allocated == self.verified_local_allocated_bytes
                    && identities == self.verified_identities.len() =>
            {
                Ok((wire, allocated))
            }
            Ok(_) => {
                self.allocation_poisoned = true;
                anyhow::bail!("verified artifact allocation aggregate differs from full registry")
            }
            Err(error) => {
                self.allocation_poisoned = true;
                Err(error.context("verified artifact allocation reconciliation overflow"))
            }
        }
    }

    /// Calculate a prospective transition before changing its registry entry.
    fn next_verified_allocation(&mut self, remove: u64, credit: u64) -> Result<u64> {
        ensure!(
            !self.allocation_poisoned,
            "artifact allocation ledger is poisoned"
        );
        match self
            .verified_allocated_bytes
            .checked_sub(remove)
            .and_then(|bytes| bytes.checked_add(credit))
        {
            Some(bytes) => Ok(bytes),
            None => {
                self.allocation_poisoned = true;
                anyhow::bail!("verified artifact allocation transition overflow or underflow")
            }
        }
    }
}
const HASH_WORKSPACE: u64 = 4 * 1024 * 1024;
const ORDINARY_GROUPS: [ArtifactGroup; 8] = [
    ArtifactGroup::Source,
    ArtifactGroup::Native,
    ArtifactGroup::Expected,
    ArtifactGroup::Map,
    ArtifactGroup::LegacyExpectation,
    ArtifactGroup::Auxiliary,
    ArtifactGroup::RecoveryCopy,
    ArtifactGroup::Capture,
];
const PREPARED_REQUIRED: [ArtifactGroup; 5] = [
    ArtifactGroup::Source,
    ArtifactGroup::Native,
    ArtifactGroup::Expected,
    ArtifactGroup::Capture,
    ArtifactGroup::RecoveryCopy,
];
fn parents(path: &Path) -> Result<Vec<File>> {
    let mut result = Vec::new();
    for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let meta = fs::symlink_metadata(parent)?;
        ensure!(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "ordinary artifact directory ancestry required"
        );
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(parent)?;
        ensure!(
            file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
            "artifact parent handle differs"
        );
        result.push(file);
    }
    Ok(result)
}
/// How many working files are read and hashed at once. A file is read on
/// one thread; its BLAKE3 is computed on the pool's threads, a few
/// milliseconds for each second of reading, so the lanes are what reads at
/// the same time.
fn hash_lanes() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |cores| cores.get() / 2)
        .clamp(1, 8)
}
/// Every pin's check, each made once by one of `lanes` threads, this one
/// among them. The check is the pin's own (`revalidate_prepaid`): the lanes
/// only decide which files are read at the same time. The first failure
/// stops the lanes from starting on further files and is the one reported.
fn revalidate_pins(pins: &[&FilePin], lanes: usize) -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let lane = || -> Result<()> {
        while !failed.load(Ordering::Acquire) {
            let Some(pin) = pins.get(next.fetch_add(1, Ordering::AcqRel)) else {
                break;
            };
            if let Err(error) = pin.revalidate_prepaid() {
                failed.store(true, Ordering::Release);
                return Err(error.context(format!(
                    "re-validating working file {:?} ({} bytes)",
                    pin.snapshot.final_path, pin.snapshot.file_bytes
                )));
            }
        }
        Ok(())
    };
    if lanes <= 1 || pins.len() <= 1 {
        return lane();
    }
    std::thread::scope(|scope| {
        let others: Vec<_> = (1..lanes.min(pins.len()))
            .map(|_| {
                scope.spawn(|| {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    lane()
                })
            })
            .collect();
        let mut result = lane();
        for other in others {
            let joined = match other.join() {
                Ok(outcome) => outcome,
                Err(_) => Err(anyhow::anyhow!(
                    "a working-file re-validation lane panicked"
                )),
            };
            if result.is_ok() {
                result = joined;
            }
        }
        result
    })
}
/// How a file is held to the digest its records name.
#[derive(Clone, Copy)]
enum Hold<'a> {
    /// For the first time, by the algorithm of its format: BLAKE3 for a
    /// record store in the current format, SHA-256 for anything else
    /// (`metadata_pages::file_digest_algorithm`).
    ByFormat,
    /// For the first time, by the algorithm its writer says it hashed the
    /// bytes with: a file whose content is not the writer's to shape.
    By(n2r_win32::bulk_digest::Algorithm),
    /// Again, by the BLAKE3 taken when it was first held.
    Reread(&'a [u8; 32]),
}
/// Holds `file` to `expected`, the digest its records name, and to nothing
/// having changed while it was read.
///
/// A file's SHA-256 is one stream of a quarter of a gigabyte a second here,
/// and the gate before the first write to the source re-reads every working
/// file, 16 GB on the full Windows volume. So a file that is held for the
/// first time has its BLAKE3 taken as well, from the same read where
/// `expected` is a SHA-256, and every complete re-read after that is
/// compared with the BLAKE3: it says the same about the same bytes, at the
/// speed they can be read.
fn inspect(file: &mut File, maximum: u64, expected: &str, hold: Hold<'_>) -> Result<Verified> {
    use n2r_win32::bulk_digest::{self, Algorithm};
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical artifact SHA required"
    );
    let snapshot = reference_file::observe_reference_file_handle_with_limit(file, maximum)?;
    ensure!(
        snapshot.number_of_links == 1,
        "artifact must have exactly one link"
    );
    let modified = file.metadata()?.modified()?;
    // A record store this process has just written already has its digest,
    // computed from the bytes written; pinning it read the whole file back to
    // hash it again (every store, gigabytes in all). Under the check-once
    // policy the writer's digest stands, when it is the expected one and the
    // file is still exactly the file that writer closed. It is a BLAKE3, and
    // so also what a later re-read is compared with.
    let written = n2r_win32::metadata_pages::digest_if_written_here(file)
        .filter(|written| hex::encode(written) == expected);
    let (sha, reread) = if let Some(written) = written {
        ensure!(
            match hold {
                Hold::ByFormat | Hold::By(Algorithm::Blake3) => true,
                Hold::By(Algorithm::Sha256) => false,
                Hold::Reread(reread) => *reread == written,
            },
            "closed artifact identity/bytes changed"
        );
        (expected.to_owned(), written)
    } else {
        let position = file.stream_position()?;
        let hashed = (|| -> std::io::Result<(String, [u8; 32])> {
            let algorithm = match hold {
                Hold::Reread(reread) => {
                    let actual =
                        bulk_digest::held_file(Algorithm::Blake3, file, snapshot.file_bytes)?;
                    // The digest the records name stands only with the bytes
                    // it was taken from.
                    let named = if actual == *reread { expected } else { "" };
                    return Ok((named.to_owned(), actual));
                }
                Hold::ByFormat => n2r_win32::metadata_pages::file_digest_algorithm(file)?,
                Hold::By(algorithm) => algorithm,
            };
            match algorithm {
                Algorithm::Blake3 => {
                    let actual =
                        bulk_digest::held_file(Algorithm::Blake3, file, snapshot.file_bytes)?;
                    Ok((hex::encode(actual), actual))
                }
                Algorithm::Sha256 => {
                    let both = bulk_digest::sha256_and_blake3(file, snapshot.file_bytes)?;
                    Ok((hex::encode(both.sha256), both.blake3))
                }
            }
        })();
        file.seek(SeekFrom::Start(position))?;
        hashed?
    };
    ensure!(
        sha == expected
            && reference_file::observe_reference_file_handle_with_limit(file, maximum)? == snapshot
            && file.metadata()?.modified()? == modified,
        "closed artifact identity/bytes changed"
    );
    Ok(Verified {
        snapshot,
        modified,
        sha256: sha,
        reread,
    })
}
fn validate_prepared_state(
    arena: &ArtifactArena,
    state: &mut State,
    ordinary: &[ArtifactGroupSeal],
    native_quota: &ArtifactGroupPermit,
    native_length: u64,
    native_reservation: u64,
    closed: bool,
) -> Result<ArenaUsage> {
    state.reconciled_verified_totals()?;
    ensure!(
        state.prepared_closed == closed
            && !state.ram_poisoned
            && state.groups.len() == ordinary.len() + 1
            && native_quota.group == ArtifactGroup::NativeJournal
            && native_quota.arena.same_arena(arena),
        "prepared arena membership or runtime identity differs"
    );
    for required in PREPARED_REQUIRED {
        ensure!(
            ordinary
                .iter()
                .any(|s| s.permit.group == required && !s.pins.pins.is_empty()),
            "prepared arena required artifact group is absent or empty"
        );
    }
    let mut root_registry = arena.0.config_registry_bytes;
    for root in state.external_roots.values() {
        root.revalidate()?;
        root_registry = add(root_registry, root.registry_bytes)?;
    }
    let (mut wire, mut allocated, mut registry, mut files) = (0, 0, root_registry, 0);
    let mut local_allocated = 0u64;
    let mut previous = None;
    for seal in ordinary {
        let tag = seal.permit.group;
        ensure!(
            previous.is_none_or(|p| p < tag)
                && tag != ArtifactGroup::NativeJournal
                && seal.permit.arena.same_arena(arena),
            "prepared group owner/order differs"
        );
        previous = Some(tag);
        let group = state
            .groups
            .get(&tag)
            .context("prepared actual group is missing")?;
        ensure!(
            !group.poisoned
                && group.native_journal.is_none()
                && group.held == seal.wire_bytes
                && group.files == seal.pins.pins.len() as u64
                && group.maximum >= group.held
                && (!closed || (group.sealed && group.maximum == group.held)),
            "prepared group quota/files/closure differ"
        );
        let mut entries = state.entries.values().filter(|e| e.group == tag);
        let (mut group_wire, mut group_allocated) = (0, 0);
        for pin in &seal.pins.pins {
            let entry = entries.next().context("prepared artifact entry missing")?;
            let verified = entry
                .verified
                .as_ref()
                .context("prepared artifact is unverified")?;
            let current = entry
                .lease
                .upgrade()
                .context("prepared artifact owner expired")?;
            ensure!(
                Arc::ptr_eq(pin, &current)
                    && pin.arena.same_arena(arena)
                    && pin.snapshot == verified.snapshot
                    && pin.sha256 == verified.sha256
                    && pin.modified == verified.modified
                    && entry.reserved == verified.snapshot.file_bytes
                    && entry.maximum >= entry.reserved
                    && entry.external_readonly == pin.external_origin.is_some()
                    && verified.snapshot.allocation_bytes >= verified.snapshot.file_bytes,
                "prepared artifact lease/identity/byte accounting differs"
            );
            group_wire = add(group_wire, verified.snapshot.file_bytes)?;
            group_allocated = add(group_allocated, verified.snapshot.allocation_bytes)?;
            if !entry.external_readonly {
                local_allocated = add(local_allocated, verified.snapshot.allocation_bytes)?;
            }
            registry = add(registry, entry.registry_bytes)?;
            files = add(files, 1)?;
        }
        ensure!(
            entries.next().is_none()
                && group_wire == seal.wire_bytes
                && group_allocated == seal.allocated_bytes,
            "prepared group file set is not exhaustive"
        );
        wire = add(wire, group_wire)?;
        allocated = add(allocated, group_allocated)?;
    }
    ensure!(
        files == state.entries.len() as u64
            && state.overhead
                == allocated
                    .checked_sub(wire)
                    .context("prepared allocation underflow")?,
        "prepared artifact allocation/index set differs"
    );
    let journal = state
        .groups
        .get(&ArtifactGroup::NativeJournal)
        .context("prepared native quota missing")?;
    let witness = journal
        .native_journal
        .as_ref()
        .context("prepared native witness missing")?;
    ensure!(
        !journal.poisoned
            && journal.sealed == closed
            && journal.held == 0
            && journal.files == 0
            && journal.maximum == native_reservation
            && witness.reservation_bytes() == native_reservation,
        "prepared native journal quota/owner changed"
    );
    let (journal_allocated, journal_wire) = witness.observe()?;
    ensure!(
        journal_wire == native_length && native_length != 0,
        "prepared native fixed EOF changed"
    );
    let witness_ram = (witness.final_path().encode_utf16().count() as u64)
        .checked_mul(4)
        .and_then(|n| n.checked_add(256 * 1024))
        .context("prepared native witness RAM overflow")?;
    registry = add(registry, witness_ram)?;
    let promised = add(add(wire, state.overhead)?, native_reservation)?;
    let credit = add(local_allocated, journal_wire)?;
    ensure!(
        registry == state.index_bytes
            && registry <= arena.0.budget.retained_index_bytes
            && add(registry, state.leased_ram_bytes)? <= arena.needed_ceiling(&state)
            && promised <= arena.0.budget.scratch_bytes,
        "prepared aggregate artifact/RAM accounting differs"
    );
    let pending = promised
        .checked_sub(credit)
        .context("prepared physical credit exceeds reservation")?;
    ensure!(
        n2r_win32::resource_native::observe_available_resources(&arena.0.root)?
            .scratch_available_bytes
            >= pending,
        "prepared arena free space cannot cover retained reservation"
    );
    Ok(ArenaUsage {
        promised_bytes: promised,
        actual_wire_bytes: add(wire, journal_wire)?,
        actual_allocated_bytes: add(allocated, journal_allocated)?,
        files: add(files, 1)?,
        leased_ram_bytes: state.leased_ram_bytes,
        registry_ram_bytes: registry,
        local_allocation_credit_bytes: credit,
    })
}
impl PreparedArenaClosure {
    pub(crate) fn arena(&self) -> &ArtifactArena {
        &self.arena
    }
    /// Current bounded metadata accounting; full byte validation is separate.
    pub(crate) fn usage(&self) -> Result<ArenaUsage> {
        let _ram = self.arena.reserve_ram(256 * 1024)?;
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        validate_prepared_state(
            &self.arena,
            &mut state,
            &self.ordinary,
            &self.native_quota,
            self.native_length,
            self.native_reservation,
            true,
        )
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::ArenaRevalidation);
        let hash_bytes = add(
            self.ordinary
                .iter()
                .flat_map(|s| &s.pins.pins)
                .map(|p| p.snapshot.file_bytes.min(HASH_WORKSPACE))
                .max()
                .unwrap_or(0)
                .max(256 * 1024),
            512 * 1024,
        )?;
        let _ram = self.arena.reserve_ram(hash_bytes)?;
        let pins: Vec<&FilePin> = self
            .ordinary
            .iter()
            .flat_map(|seal| &seal.pins.pins)
            .map(|pin| &**pin)
            .collect();
        // When the files are about to be read in full (the gate before the
        // first write to the source; every time with --recheck-everything)
        // several are read and hashed at once: one file after another was
        // 16 GB on one lane for the full Windows volume. Each further lane
        // has a hashing workspace of its own, taken as spare memory before
        // the ledger is locked below: a lane that is not granted is a file
        // that waits its turn.
        let wanted = if n2r_win32::verify_policy::full_unremembered() {
            hash_lanes().min(pins.len())
        } else {
            1
        };
        let spare: Vec<ArenaRamLease> = (1..wanted)
            .map_while(|_| self.arena.reserve_spare_ram(hash_bytes).ok())
            .collect();
        let lanes = 1 + spare.len();
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        validate_prepared_state(
            &self.arena,
            &mut state,
            &self.ordinary,
            &self.native_quota,
            self.native_length,
            self.native_reservation,
            true,
        )?;
        drop(state);
        revalidate_pins(&pins, lanes)
    }

    /// Preserve exhaustive before/after content checks while allowing nested
    /// read-only checks to recognize a covered actual file object. Neither the
    /// witness nor a validation failure can authorize device access.
    pub(crate) fn with_revalidation<T>(
        &self,
        callback: impl for<'boundary> FnOnce(
            &'boundary PreparedArenaRevalidation<'boundary>,
        ) -> Result<T>,
    ) -> Result<T> {
        self.revalidate()?;
        let witness = PreparedArenaRevalidation { closure: self };
        let result = callback(&witness);
        // A raw/admin alias is possible even though ordinary writes are
        // excluded. Always run the final full check, including callback errors.
        let closing = self.revalidate();
        match (result, closing) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(closing)) => Err(error.context(format!(
                "prepared arena also failed its final complete validation: {closing:#}"
            ))),
        }
    }
}
impl ArtifactArena {
    /// Close every actual preparation owner atomically. Ordinary file quotas
    /// shrink only to verified bytes; the separately owned native journal keeps
    /// its fixed-EOF quota/witness. No disk mutation or source authority results.
    pub(crate) fn close_prepared(
        &self,
        native_quota: &ArtifactGroupPermit,
    ) -> Result<PreparedArenaClosure> {
        ensure!(
            native_quota.group == ArtifactGroup::NativeJournal
                && self.same_arena(&native_quota.arena),
            "prepared closure requires the actual same-arena native quota"
        );
        let (counts, hash_bytes) = {
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
            ensure!(
                !state.prepared_closed && !state.ram_poisoned,
                "arena is closed or poisoned"
            );
            let mut counts = [None; ORDINARY_GROUPS.len()];
            let mut hash_bytes = 256 * 1024;
            for (slot, group) in ORDINARY_GROUPS.iter().enumerate() {
                if state.groups.contains_key(group) {
                    counts[slot] =
                        Some(state.entries.values().filter(|e| e.group == *group).count());
                }
            }
            for entry in state.entries.values() {
                let verified = entry
                    .verified
                    .as_ref()
                    .context("prepared arena has an active file creation")?;
                hash_bytes = hash_bytes.max(verified.snapshot.file_bytes.min(HASH_WORKSPACE));
            }
            hash_bytes = add(hash_bytes, 512 * 1024)?;
            (counts, hash_bytes)
        };
        let group_count = counts.iter().flatten().count();
        let collection_bytes = (group_count as u64)
            .checked_mul(2 * std::mem::size_of::<ArtifactGroupSeal>() as u64)
            .and_then(|n| n.checked_add(256))
            .context("prepared closure collection RAM overflow")?;
        let collection_ram = self.reserve_ram(collection_bytes)?;
        let mut group_ram: [Option<ArenaRamLease>; ORDINARY_GROUPS.len()] =
            std::array::from_fn(|_| None);
        for (slot, count) in counts.iter().enumerate() {
            if let Some(count) = count {
                let bytes = (*count as u64)
                    .checked_mul(2 * std::mem::size_of::<Arc<FilePin>>() as u64)
                    .and_then(|n| n.checked_add(256))
                    .context("prepared group pin RAM overflow")?;
                group_ram[slot] = Some(self.reserve_ram(bytes)?);
            }
        }
        let _hash_ram = self.reserve_ram(hash_bytes)?;
        // Declare all RAM-owning collections before the state guard, so every
        // failure unlocks the mutex before their lease destructors run.
        let mut ordinary = Vec::new();
        ordinary.try_reserve_exact(group_count)?;
        ensure!(
            (ordinary.capacity() as u64)
                .checked_mul(std::mem::size_of::<ArtifactGroupSeal>() as u64)
                .is_some_and(|n| n <= collection_bytes),
            "prepared closure allocation exceeded prepaid RAM"
        );
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.prepared_closed && !state.ram_poisoned,
            "arena changed before prepared closure"
        );
        for (slot, group) in ORDINARY_GROUPS.iter().enumerate() {
            let count = state
                .groups
                .get(group)
                .map(|_| state.entries.values().filter(|e| e.group == *group).count());
            ensure!(
                count == counts[slot],
                "arena groups/files changed before prepared closure"
            );
            let Some(count) = count else { continue };
            let mut pins = Vec::new();
            pins.try_reserve_exact(count)?;
            ensure!(
                pins.capacity() <= count.saturating_mul(2).max(1),
                "prepared pin allocation exceeds prepaid RAM"
            );
            let mut wire = 0;
            let mut allocated = 0;
            for entry in state.entries.values().filter(|e| e.group == *group) {
                let verified = entry
                    .verified
                    .as_ref()
                    .context("prepared arena still has an active file creation")?;
                ensure!(
                    verified.snapshot.file_bytes.min(HASH_WORKSPACE) <= hash_bytes,
                    "arena hash workspace changed before closure"
                );
                let pin = entry
                    .lease
                    .upgrade()
                    .context("prepared artifact has no actual retained file owner")?;
                pin.revalidate_prepaid()?;
                wire = add(wire, verified.snapshot.file_bytes)?;
                allocated = add(allocated, verified.snapshot.allocation_bytes)?;
                pins.push(pin);
            }
            ensure!(
                pins.len() == count && pins.capacity() <= count.saturating_mul(2).max(1),
                "prepared pin collection differs"
            );
            // No fallible operation follows taking this lease until it has
            // entered the outer collection declared before the state guard.
            let ram = group_ram[slot].take().expect("prepaid present group");
            ordinary.push(ArtifactGroupSeal {
                permit: ArtifactGroupPermit {
                    arena: self.clone(),
                    group: *group,
                },
                pins: Arc::new(SealedPins { pins, _ram: ram }),
                wire_bytes: wire,
                allocated_bytes: allocated,
            });
        }
        let journal = state
            .groups
            .get(&ArtifactGroup::NativeJournal)
            .context("prepared native journal quota absent")?;
        let native_reservation = journal.maximum;
        let native_length = journal
            .native_journal
            .as_ref()
            .context("prepared native journal witness absent")?
            .observe()?
            .1;
        validate_prepared_state(
            self,
            &mut state,
            &ordinary,
            native_quota,
            native_length,
            native_reservation,
            false,
        )?;
        for seal in &ordinary {
            let group = state
                .groups
                .get_mut(&seal.permit.group)
                .expect("validated actual group");
            group.maximum = seal.wire_bytes;
            group.held = seal.wire_bytes;
            group.sealed = true;
        }
        state
            .groups
            .get_mut(&ArtifactGroup::NativeJournal)
            .expect("validated native group")
            .sealed = true;
        state.prepared_closed = true;
        drop(state);
        Ok(PreparedArenaClosure {
            ordinary,
            native_quota: native_quota.clone(),
            arena: self.clone(),
            native_length,
            native_reservation,
            _ram: collection_ram,
        })
    }
    pub fn new(
        root: &Path,
        budget: ResourceBudget,
        excluded: &[GeneralDiskBinding],
    ) -> Result<Self> {
        Self::new_inner(root, budget, excluded, false)
    }
    /// Reusing already allocated artifacts is not an allocation of their
    /// bytes again. This constructor admits RAM and a total-volume ceiling;
    /// every group still proves its unallocated promises against CURRENT
    /// free space. Reopen cached groups before reserving new work.
    /// No source, shadow or replay capability is issued here.
    pub fn new_resuming(
        root: &Path,
        budget: ResourceBudget,
        excluded: &[GeneralDiskBinding],
    ) -> Result<Self> {
        Self::new_inner(root, budget, excluded, true)
    }
    fn new_inner(
        root: &Path,
        budget: ResourceBudget,
        excluded: &[GeneralDiskBinding],
        resuming: bool,
    ) -> Result<Self> {
        budget.validate()?;
        ensure!(
            root.is_absolute()
                && !root
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "absolute artifact arena root required"
        );
        let handles = parents(root)?;
        let root_guid = n2r_win32::file_storage::final_path_guid(
            handles.first().context("arena root handle missing")?,
        )?;
        let allocation_slack = n2r_win32::file_storage::artifact_allocation_slack(
            handles.first().context("arena root handle missing")?,
        )?;
        for binding in excluded {
            binding.validate()?;
            ensure!(
                !root_guid
                    .to_ascii_lowercase()
                    .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
                "artifact arena is on an excluded data volume"
            );
        }
        let available = n2r_win32::resource_native::observe_available_resources(root)?;
        if resuming {
            ensure!(
                n2r_win32::resource_native::memory_is_there(
                    budget.ram_bytes,
                    available.available_physical_bytes
                ) && budget.scratch_bytes <= available.scratch_total_bytes,
                "resume arena exceeds actual RAM or total working-volume capacity"
            );
        } else {
            available.validate_budget(budget)?;
        }
        let excluded: Vec<_> = excluded
            .iter()
            .map(|binding| {
                Ok((
                    n2r_win32::layout::guid_bytes(&binding.identity.disk_guid)?,
                    n2r_win32::layout::guid_bytes(&binding.volume_guid)?,
                ))
            })
            .collect::<Result<_>>()?;
        let config_registry_bytes = add(
            4096,
            (excluded.capacity() as u64)
                .checked_mul(64)
                .context("arena exclusion registry RAM overflow")?,
        )?;
        ensure!(
            config_registry_bytes <= budget.retained_index_bytes
                && config_registry_bytes <= budget.ram_bytes,
            "arena retained configuration exceeds RAM budget"
        );
        let arena = Self(Arc::new(Inner {
            cache_basis_bytes: (available.available_physical_bytes
                - available.available_physical_bytes / 3)
                .max(budget.ram_bytes.min(64 << 20)),
            made: std::time::Instant::now(),
            fitted_ceiling: std::sync::atomic::AtomicU64::new(0),
            fitted_at_ms: std::sync::atomic::AtomicU64::new(0),
            root: fs::canonicalize(root)?,
            root_guid,
            allocation_slack,
            _parents: handles,
            budget,
            state: Mutex::new(State {
                windows_native_allocation: false,
                groups: BTreeMap::new(),
                entries: BTreeMap::new(),
                verified_allocated_bytes: 0,
                verified_local_allocated_bytes: 0,
                external_roots: BTreeMap::new(),
                verified_identities: BTreeSet::new(),
                allocation_poisoned: false,
                overhead: 0,
                index_bytes: config_registry_bytes,
                leased_ram_bytes: 0,
                beyond_budget_bytes: 0,
                ram_by_site: BTreeMap::new(),
                cache_sites: BTreeSet::new(),
                optional_ram_bytes: 0,
                cache_ram_bytes: 0,
                spare: SpareMemory::default(),
                ram_poisoned: false,
                prepared_closed: false,
            }),
            excluded,
            config_registry_bytes,
        }));
        // A page reader of this thread that decides to hold its file in
        // memory pays this ledger for it.
        n2r_win32::evict::register_cache_payer(std::rc::Rc::new(ArenaCachePayer(Arc::downgrade(
            &arena.0,
        ))));
        Ok(arena)
    }
    pub fn budget(&self) -> ResourceBudget {
        self.0.budget
    }
    /// Enroll an authenticated historical origin only after its caller has
    /// checked the independent resume pins. This retains actual directory
    /// handles and native identity; it never permits foreign output or credit.
    pub(crate) fn enroll_external_readonly_root(
        &self,
        root: &Path,
        excluded: &[GeneralDiskBinding],
    ) -> Result<()> {
        ensure!(
            root.is_absolute()
                && !root
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "ordinary absolute external origin root required"
        );
        let _working = self.reserve_ram(1024 * 1024)?;
        let handles = parents(root)?;
        let held = handles.first().context("external origin root absent")?;
        let canonical = fs::canonicalize(root)?;
        ensure!(
            !canonical.starts_with(&self.0.root) && !self.0.root.starts_with(&canonical),
            "external origin must be separate from the writable arena root"
        );
        let guid = n2r_win32::file_storage::final_path_guid(held)?;
        let end = guid
            .find("}\\")
            .context("external root volume GUID absent")?
            + 1;
        let volume = &guid[..end];
        let supplied: Vec<_> = excluded
            .iter()
            .map(|binding| {
                binding.validate()?;
                Ok((
                    n2r_win32::layout::guid_bytes(&binding.identity.disk_guid)?,
                    n2r_win32::layout::guid_bytes(&binding.volume_guid)?,
                ))
            })
            .collect::<Result<_>>()?;
        ensure!(
            supplied.len() == self.0.excluded.len()
                && supplied
                    .iter()
                    .all(|binding| self.0.excluded.contains(binding)),
            "external origin exclusions differ from actual arena enrollment"
        );
        for (_, excluded_volume) in &self.0.excluded {
            ensure!(
                n2r_win32::layout::guid_bytes(volume.trim_start_matches("\\\\?\\Volume"))?
                    != *excluded_volume,
                "external readonly origin is on a source/shadow volume"
            );
        }
        let observed = n2r_win32::discovery::discover(
            &(volume.to_owned() + "\\"),
            n2r_win32::discovery::Role::Journal {
                allow_additional_partitions: true,
            },
        )?;
        ensure!(
            observed.read_only
                && observed.observed_twice_unchanged
                && observed.source_write_requests == 0,
            "external origin storage discovery was incomplete or mutable"
        );
        let disk = n2r_win32::layout::guid_bytes(&observed.binding.identity.disk_guid)?;
        let actual_volume = n2r_win32::layout::guid_bytes(&observed.binding.volume_guid)?;
        ensure!(
            self.0
                .excluded
                .iter()
                .all(|(d, v)| *d != disk && *v != actual_volume),
            "external origin physical storage aliases source/shadow"
        );
        let slack = n2r_win32::file_storage::artifact_allocation_slack(held)?;
        let root_id = n2r_win32::file_storage::file_id_info(held)?;
        let registry = add(
            8192,
            (canonical.as_os_str().as_encoded_bytes().len() as u64)
                .checked_mul(8)
                .and_then(|n| n.checked_add((handles.len() as u64).checked_mul(1024)?))
                .context("external root registry RAM overflow")?,
        )?;
        let origin = Arc::new(ExternalOriginRoot {
            root: canonical.clone(),
            root_guid: guid,
            root_id,
            allocation_slack: slack,
            registry_bytes: registry,
            parents: handles,
        });
        origin.revalidate()?;
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.prepared_closed && !state.ram_poisoned && !state.allocation_poisoned,
            "closed or poisoned arena cannot enroll readonly origins"
        );
        if let Some(old) = state.external_roots.get(&canonical) {
            old.revalidate()?;
            ensure!(
                old.root_id == origin.root_id
                    && old.root_guid.eq_ignore_ascii_case(&origin.root_guid),
                "external origin root identity changed"
            );
            return Ok(());
        }
        ensure!(
            state
                .external_roots
                .values()
                .all(|old| !canonical.starts_with(&old.root)
                    && !old.root.starts_with(&canonical)
                    && old.root_id != origin.root_id),
            "external readonly roots overlap or alias"
        );
        let index = add(state.index_bytes, registry)?;
        ensure!(
            index <= self.0.budget.retained_index_bytes
                && add(index, state.leased_ram_bytes)? <= self.needed_ceiling(&state),
            "external root registry exceeds actual shared RAM"
        );
        state.index_bytes = index;
        state.external_roots.insert(canonical, origin);
        Ok(())
    }
    fn existing_parent_origin(
        &self,
        canonical: &Path,
        handles: &[File],
    ) -> Result<Option<Arc<ExternalOriginRoot>>> {
        let parent = handles.first().context("existing artifact parent absent")?;
        let route = n2r_win32::file_storage::final_path_guid(parent)?;
        if canonical == self.0.root || canonical.starts_with(&self.0.root) {
            self.require_directory_ancestry(handles)?;
            return Ok(None);
        }
        let origins: Vec<_> = {
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
            state.external_roots.values().cloned().collect()
        };
        for origin in origins {
            if canonical == origin.root || canonical.starts_with(&origin.root) {
                origin.revalidate()?;
                ensure!(
                    route.eq_ignore_ascii_case(&origin.root_guid)
                        || route.to_ascii_lowercase().starts_with(
                            &(origin.root_guid.trim_end_matches('\\').to_ascii_lowercase() + "\\")
                        ),
                    "existing artifact escaped held external root route"
                );
                let mut found = false;
                for handle in handles {
                    if n2r_win32::file_storage::file_id_info(handle)? == origin.root_id {
                        found = true;
                        break;
                    }
                }
                ensure!(
                    found,
                    "existing artifact ancestry lacks the enrolled root FileObject identity"
                );
                return Ok(Some(origin));
            }
        }
        anyhow::bail!("existing artifact escapes active/enrolled readonly roots")
    }
    /// Existing read-only origin routing only. No creation, growth, retirement,
    /// source write or free-space credit can be issued through this check.
    pub(crate) fn require_readonly_origin_path(&self, path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "ordinary absolute readonly origin path required"
        );
        let _working = self.reserve_ram(256 * 1024)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            (metadata.is_file() || metadata.is_dir()) && metadata.file_attributes() & 0x400 == 0,
            "readonly origin is not an existing ordinary file/directory"
        );
        let parent = if metadata.is_dir() {
            path
        } else {
            path.parent().context("readonly origin parent absent")?
        };
        let handles = parents(parent)?;
        let canonical = fs::canonicalize(parent)?;
        let _origin = self.existing_parent_origin(&canonical, &handles)?;
        Ok(())
    }
    /// Reassign only the unused legacy-expectation sixteenth to the Windows
    /// native report. Select this before any group reservation; the five
    /// primary shares plus recovery still fit the same total scratch budget.
    pub(crate) fn use_windows_native_allocation(&self, source: &GeneralDiskBinding) -> Result<()> {
        source.validate()?;
        ensure!(
            source.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows,
            "Windows native allocation requires the actual offline Windows source"
        );
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.windows_native_allocation
                && !state.prepared_closed
                && state.groups.is_empty()
                && state.entries.is_empty()
                && state.overhead == 0,
            "Windows native allocation must precede every arena reservation"
        );
        let budget = self.0.budget;
        let primary = (budget.scratch_bytes / 8)
            .checked_mul(4)
            .context("arena primary shares overflow")?;
        let native = budget.windows_native_page_budget()?.max_file_bytes;
        let recovery = budget.scratch_bytes / 16 * 5;
        ensure!(
            add(add(primary, native)?, recovery)? <= budget.scratch_bytes,
            "Windows native allocation exceeds the unchanged total scratch budget"
        );
        state.windows_native_allocation = true;
        Ok(())
    }
    pub(crate) fn native_page_budget(
        &self,
    ) -> Result<n2r_win32::tree_resources::MetadataPageBudget> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        Ok(if state.windows_native_allocation {
            self.0.budget.windows_native_page_budget()?
        } else {
            self.0.budget.page_budget()?
        })
    }
    pub(crate) fn require_native_allocation(
        &self,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        admission.validate()?;
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let expected = if state.windows_native_allocation {
            self.0.budget.windows_native_page_budget()?
        } else {
            self.0.budget.page_budget()?
        };
        ensure!(
            admission.budget == self.0.budget
                && admission.native_pages == expected
                && admission.schema_version
                    == (if state.windows_native_allocation {
                        2
                    } else {
                        1
                    })
                && (!state.windows_native_allocation
                    || !state.groups.contains_key(&ArtifactGroup::LegacyExpectation)),
            "native observation admission differs from its actual arena allocation"
        );
        Ok(())
    }
    pub fn allocation_slack_bytes(&self) -> u64 {
        self.0.allocation_slack
    }
    /// Volume identity observed from the retained arena directory handle.
    pub fn volume_guid_path(&self) -> Result<&str> {
        let end = self
            .0
            .root_guid
            .find("}\\")
            .context("arena GUID volume path is malformed")?;
        Ok(&self.0.root_guid[..=end])
    }

    /// Bind a caller's actual directory handle to the retained arena root.
    /// This is a read-only route/identity check, not a storage or write permit.
    pub(crate) fn require_root_directory(&self, file: &File) -> Result<()> {
        let root = self
            .0
            ._parents
            .first()
            .context("held arena root is absent")?;
        let actual = file.metadata()?;
        let retained = root.metadata()?;
        ensure!(
            actual.is_dir()
                && retained.is_dir()
                && actual.file_attributes() & 0x400 == 0
                && retained.file_attributes() & 0x400 == 0,
            "arena root handles must be ordinary directories"
        );
        ensure!(
            n2r_win32::file_storage::file_id_info(file)?
                == n2r_win32::file_storage::file_id_info(root)?
                && n2r_win32::file_storage::final_path_guid(file)?
                    .eq_ignore_ascii_case(&self.0.root_guid)
                && n2r_win32::file_storage::final_path_guid(root)?
                    .eq_ignore_ascii_case(&self.0.root_guid),
            "directory handle differs from the held arena root"
        );
        Ok(())
    }
    pub fn same_arena(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// A resumed preparation writes beneath the existing arena instead of
    /// replacing its root. Require the exact retained root among the ordinary
    /// held ancestors and bind the immediate parent to that same GUID route.
    pub(crate) fn require_directory_ancestry(&self, parents: &[File]) -> Result<()> {
        let first = parents.first().context("arena output ancestry is empty")?;
        let root = self
            .0
            ._parents
            .first()
            .context("held arena root is absent")?;
        let root_id = n2r_win32::file_storage::file_id_info(root)?;
        let mut matched = false;
        for file in parents {
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "held arena output ancestor is not an ordinary directory"
            );
            if n2r_win32::file_storage::file_id_info(file)? == root_id {
                self.require_root_directory(file)?;
                matched = true;
            }
        }
        let parent = n2r_win32::file_storage::final_path_guid(first)?;
        let root_path = self.0.root_guid.trim_end_matches('\\');
        ensure!(
            matched
                && (parent.eq_ignore_ascii_case(root_path)
                    || parent
                        .to_ascii_lowercase()
                        .starts_with(&(root_path.to_ascii_lowercase() + "\\"))),
            "output ancestry does not descend from the actual held arena root"
        );
        Ok(())
    }
    /// Borrow the actual still-live owner of an already charged immutable
    /// artifact. This does not adopt a pathname or repeat its byte hash.
    pub(crate) fn retained_artifact(&self, path: &Path) -> Result<ArtifactLease> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        ensure!(
            !state.allocation_poisoned && !state.ram_poisoned,
            "retained artifact arena is poisoned"
        );
        let entry = state
            .entries
            .get(path)
            .context("artifact is not accounted in this arena")?;
        let verified = entry
            .verified
            .as_ref()
            .context("artifact is not closed and verified")?;
        let pin = entry
            .lease
            .upgrade()
            .context("artifact has no surviving immutable owner")?;
        ensure!(
            pin.snapshot == verified.snapshot && pin.sha256 == verified.sha256,
            "retained artifact owner differs from accounting"
        );
        let artifact = ArtifactLease {
            group: ArtifactGroupPermit {
                arena: self.clone(),
                group: entry.group,
            },
            path: path.to_path_buf(),
            pin,
        };
        drop(state);
        artifact.pin.revalidate_identity()?;
        Ok(artifact)
    }
    /// Memory the conversion cannot do without. When the ledger has no
    /// room for it, the caches of the calling thread are given up
    /// ([`n2r_win32::evict`]), the one used longest ago first and one at a
    /// time, until it fits: a cache never makes a reservation fail that
    /// would have been granted without it.
    ///
    /// Where the caches alone would not make room, what the run can keep in
    /// working storage instead goes there, one holder at a time, until the
    /// request fits; and if it still does not but would without the
    /// caches, they go after all. (A request that fitted only with both
    /// given up found the caches held and failed, or went beyond the
    /// budget, beside them.)
    #[track_caller]
    pub fn reserve_ram(&self, bytes: u64) -> Result<ArenaRamLease> {
        let caller = std::panic::Location::caller();
        let site = (caller.file(), caller.line());
        self.follow_the_machine();
        let mut refused = match self.reserve_ram_at(bytes, site, true) {
            Ok(granted) => return Ok(granted),
            Err(refused) => refused,
        };
        if let Some(granted) = self.give_up_caches_for(bytes, site, &mut refused) {
            return Ok(granted);
        }
        // The last thing tried: what the run holds in memory and can keep
        // in working storage instead (the rows of a walk) is asked to go
        // there.
        while n2r_win32::evict::give_up_last_resort() {
            match self.reserve_ram_at(bytes, site, true) {
                Ok(granted) => return Ok(granted),
                Err(again) => refused = again,
            }
        }
        if let Some(granted) = self.give_up_caches_for(bytes, site, &mut refused) {
            return Ok(granted);
        }
        // Before spilling into the page file, give up any remaining caches on
        // this thread even if dropping them alone could not cover `bytes`: a
        // cache held in the page file makes nothing faster.
        if n2r_win32::resource_native::memory_fits_the_machine() {
            while n2r_win32::evict::evict_oldest() {
                match self.reserve_ram_at(bytes, site, true) {
                    Ok(granted) => return Ok(granted),
                    Err(again) => refused = again,
                }
            }
        }
        // Nothing is left to give up. A run that fits itself to the machine
        // goes on beyond its budget where Windows still has the memory.
        if self.go_beyond_budget(bytes) {
            return self.reserve_ram_at(bytes, site, true);
        }
        Err(refused)
    }
    /// Let what the run cannot do without go `bytes` further than the
    /// ledger has room for, if this run fits itself to the machine and
    /// Windows can still commit that much and `COMMIT_KEPT_FREE` besides.
    ///
    /// The budget is a share of the memory that was free when the run
    /// started. Other programs may have taken that memory since, or the
    /// volume may need more than the share: in both cases the run used to
    /// stop, minutes or an hour in, with the volume unchanged. It goes on
    /// now and is slower, because what is beyond the free memory comes from
    /// the page file. It still stops, with the same message, where Windows
    /// has no more to give: a process that asks for memory Windows cannot
    /// commit is ended by it.
    fn go_beyond_budget(&self, bytes: u64) -> bool {
        n2r_win32::resource_native::memory_fits_the_machine()
            && self.go_beyond_budget_with(
                bytes,
                n2r_win32::resource_native::committable_bytes().unwrap_or(0),
            )
    }
    /// As [`Self::go_beyond_budget`], given what Windows can still commit.
    fn go_beyond_budget_with(&self, bytes: u64, committable: u64) -> bool {
        /// Left to Windows and every other program of what can be committed.
        const COMMIT_KEPT_FREE: u64 = 512 << 20;
        /// The step the allowance grows by, so that it is not asked of
        /// Windows for every row.
        const STEP: u64 = 16 << 20;
        let Ok(mut state) = self.0.state.lock() else {
            return false;
        };
        if state.ram_poisoned {
            return false;
        }
        let ceiling = self.needed_ceiling(&state);
        let Some(short) = state
            .leased_ram_bytes
            .checked_add(state.index_bytes)
            .and_then(|held| held.checked_add(bytes))
            .map(|wanted| wanted.saturating_sub(ceiling))
        else {
            return false;
        };
        let more = short.div_ceil(STEP).saturating_mul(STEP);
        if committable < more.saturating_add(COMMIT_KEPT_FREE) {
            return false;
        }
        if state.beyond_budget_bytes == 0 {
            eprintln!(
                "Memory is short: the run needs more than the {} MiB it set aside when it started. It goes on with what Windows can still give it and will be slower. Closing other programs helps.",
                self.0.budget.ram_bytes >> 20
            );
        }
        let target_ceiling = ceiling.saturating_add(more);
        state.beyond_budget_bytes = target_ceiling.saturating_sub(self.0.budget.ram_bytes);
        n2r_win32::perf::note_beyond_budget(state.beyond_budget_bytes);
        true
    }
    /// Give up the thread's caches, the one used longest ago first, until
    /// `bytes` fit; none if they would not fit without any cache either.
    /// The lock is not held while one goes: it returns its own reservation
    /// to this ledger.
    fn give_up_caches_for(
        &self,
        bytes: u64,
        site: RamSite,
        refused: &mut anyhow::Error,
    ) -> Option<ArenaRamLease> {
        if !self.caches_hold_room_for(bytes, |state| self.needed_ceiling(state)) {
            return None;
        }
        while n2r_win32::evict::evict_oldest() {
            match self.reserve_ram_at(bytes, site, true) {
                Ok(granted) => return Some(granted),
                Err(again) => *refused = again,
            }
        }
        None
    }
    /// Whether `bytes` more would be within `ceiling` if no cache held
    /// anything, in a ledger that is not poisoned.
    fn caches_hold_room_for(&self, bytes: u64, ceiling: impl Fn(&State) -> u64) -> bool {
        self.0.state.lock().is_ok_and(|state| {
            !state.ram_poisoned
                && state.optional_ram_bytes != 0
                && state
                    .leased_ram_bytes
                    .checked_sub(state.optional_ram_bytes)
                    .and_then(|needed| needed.checked_add(bytes))
                    .and_then(|needed| needed.checked_add(state.index_bytes))
                    .is_some_and(|needed| needed <= ceiling(&state))
        })
    }
    /// The most the ledger may hold with what the run cannot do without:
    /// its budget and what was granted beyond it, or, for a run that fits
    /// itself to the machine, what the machine has now where that is more.
    /// [`Self::reserve_ram_at`] grants up to it, and the caches are given
    /// up for a request that fits it without them. (They were judged
    /// against the bare budget, so a request that the allowance beyond it,
    /// or the machine, had room for once the caches went was refused, or
    /// had the walk's rows written out, beside them.)
    fn needed_ceiling(&self, state: &State) -> u64 {
        self.0
            .budget
            .ram_bytes
            .saturating_add(state.beyond_budget_bytes)
            .max(self.speed_budget())
    }
    /// As [`Self::reserve_ram`], for memory the caller does without when
    /// there is no room (a row kept for the next lookup, a small table held
    /// instead of a working file): no cache is given up for it.
    #[track_caller]
    pub fn reserve_ram_if_room(&self, bytes: u64) -> Result<ArenaRamLease> {
        let caller = std::panic::Location::caller();
        self.reserve_ram_at(bytes, (caller.file(), caller.line()), false)
    }
    fn reserve_ram_at(
        &self,
        bytes: u64,
        site: RamSite,
        track_needed: bool,
    ) -> Result<ArenaRamLease> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let leased = add(state.leased_ram_bytes, bytes)?;
        if track_needed {
            state.spare.needed(bytes);
        }
        // What the run cannot do without is held to its budget and what was
        // granted beyond it, or, for a run that fits itself to the machine,
        // to what the machine has now where that is more. (Without this,
        // work done at once grew into free memory, as it may, and the next
        // thing the run needed was then "beyond its budget" and reported as
        // a shortage of memory on a machine that had 8 GB free: the full
        // Windows volume, round rc1.)
        ensure!(
            !state.ram_poisoned && add(leased, state.index_bytes)? <= self.needed_ceiling(&state),
            "aggregate artifact arena RAM exhausted or poisoned: leased={} (of which optional caches {}), registry={}, requested={} at {}:{}, limit={}, poisoned={}; the largest reservations: {}",
            state.leased_ram_bytes,
            state.optional_ram_bytes,
            state.index_bytes,
            bytes,
            site.0.rsplit(['/', '\\']).next().unwrap_or(site.0),
            site.1,
            self.0.budget.ram_bytes,
            state.ram_poisoned,
            largest_sites(&state.ram_by_site, &state.cache_sites)
        );
        state.leased_ram_bytes = leased;
        *state.ram_by_site.entry(site).or_default() += bytes;
        note_ledger(&state, self.0.budget.ram_bytes);
        Ok(ArenaRamLease {
            arena: self.clone(),
            bytes,
            optional: false,
            cache: false,
            spare: false,
            site,
        })
    }
    /// Memory for doing more at once: the workspace of one more object of a
    /// batch that helper threads work through. The pass can do without it
    /// (the object then waits its turn), so it must never be what leaves a
    /// reservation the conversion cannot do without short. See
    /// [`spare_fits`] for when it is granted. A refusal is the ordinary end
    /// of a batch, not a failure, and says no more than that.
    ///
    /// A pass may keep what it is granted for what it retains: shrunk to
    /// that, it is ordinary leased memory.
    #[track_caller]
    pub fn reserve_spare_ram(&self, bytes: u64) -> Result<ArenaRamLease> {
        let caller = std::panic::Location::caller();
        let site = (caller.file(), caller.line());
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let held = add(state.leased_ram_bytes, state.index_bytes)?;
        let caches = state.optional_ram_bytes;
        let granted = state
            .spare
            .asked_with_caches(self.speed_budget(), held, caches, bytes);
        ensure!(!state.ram_poisoned && granted, "spare memory refused");
        let leased = add(state.leased_ram_bytes, bytes)?;
        state.leased_ram_bytes = leased;
        *state.ram_by_site.entry(site).or_default() += bytes;
        note_ledger(&state, self.0.budget.ram_bytes);
        Ok(ArenaRamLease {
            arena: self.clone(),
            bytes,
            optional: false,
            cache: false,
            spare: true,
            site,
        })
    }
    /// Memory for a cache that is held whenever the ledger has room: a
    /// store the run looks things up in, the expected tree's pages, the
    /// file of a page reader that finds itself read at random. Without them
    /// a lookup re-reads or decodes megabytes: a volume of 100,000 files
    /// took 255 s longer when a reader's pages fell under the quota below,
    /// and one of 200,000 did not get through a phase in 50 minutes when
    /// its stores did. They are counted as memory the run can do without,
    /// stand outside the quota, and are given up like every cache when
    /// memory is short.
    ///
    /// One is granted while an eighth of the ledger stays free, so that the
    /// small reservations a pass makes for every object do not each find
    /// the ledger full of caches. A cache that is asked for is in use now:
    /// where the ledger has no room for it, the caches used longest ago are
    /// given up for it, one at a time.
    #[track_caller]
    pub fn reserve_cache_ram(&self, bytes: u64) -> Result<ArenaRamLease> {
        let caller = std::panic::Location::caller();
        let site = (caller.file(), caller.line());
        self.follow_the_machine();
        let mut refused = match self.reserve_cache_ram_at(bytes, site) {
            Ok(granted) => return Ok(granted),
            Err(refused) => refused,
        };
        if !self.caches_hold_room_for(bytes, |_| self.cache_ceiling()) {
            return Err(refused);
        }
        while n2r_win32::evict::evict_oldest() {
            match self.reserve_cache_ram_at(bytes, site) {
                Ok(granted) => return Ok(granted),
                Err(again) => refused = again,
            }
        }
        Err(refused)
    }
    /// Whether what the run cannot do without (not its caches, not what a
    /// batch holds from spare memory at the moment) is under half the
    /// ledger. The rows of a walk stay in memory while it is; beyond it
    /// they go to working storage, so that the stores the next steps look
    /// things up in keep room.
    pub fn needs_under_half(&self) -> bool {
        self.0.state.lock().is_ok_and(|state| {
            state
                .leased_ram_bytes
                .saturating_sub(state.optional_ram_bytes)
                .saturating_sub(state.spare.held)
                .saturating_add(state.index_bytes)
                <= self.0.budget.ram_bytes / 2
        })
    }
    /// Whether `bytes` more would fit the budget beside everything the
    /// ledger holds now, its caches among them: a reservation of that much
    /// would be granted without giving up any cache. Nothing is reserved.
    pub fn has_room_beside_caches(&self, bytes: u64) -> bool {
        self.0.state.lock().is_ok_and(|state| {
            !state.ram_poisoned
                && state
                    .leased_ram_bytes
                    .checked_add(state.index_bytes)
                    .and_then(|held| held.checked_add(bytes))
                    .is_some_and(|wanted| wanted <= self.0.budget.ram_bytes)
        })
    }
    /// Whether, once `needed` more is reserved beside everything held now
    /// (caches included), none of it a single reservation larger than
    /// `largest`, a spare reservation of `spare` would still be granted
    /// ([`spare_fits`], which no cache is given up for). Nothing is
    /// reserved and nothing counted.
    pub fn spare_would_fit_beside(&self, needed: u64, largest: u64, spare: u64) -> bool {
        self.0.state.lock().is_ok_and(|state| {
            let beside = state
                .spare
                .largest_beside
                .max(state.spare.largest_since)
                .max(largest);
            !state.ram_poisoned
                && state
                    .leased_ram_bytes
                    .checked_add(state.index_bytes)
                    .and_then(|held| held.checked_add(needed))
                    .is_some_and(|held| {
                        let budget = self.speed_budget();
                        let non_cache = held.saturating_sub(state.optional_ram_bytes);
                        held.checked_add(spare).is_some_and(|total| total <= budget)
                            && spare_fits(budget, non_cache, spare, beside)
                    })
        })
    }
    /// The most the ledger may hold with a cache in it: seven eighths of
    /// the budget, and no more than seven eighths of two thirds of the
    /// memory that was free when the ledger was made. A budget made larger
    /// than that for the volume's sake is for what the run cannot do
    /// without; a cache held in the page file would make nothing faster.
    fn cache_ceiling(&self) -> u64 {
        match self
            .0
            .fitted_ceiling
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => {
                let basis = self.0.budget.ram_bytes.min(self.0.cache_basis_bytes);
                basis - basis / 8
            }
            fitted => fitted,
        }
    }
    /// What the ledger may hold with memory for doing more at once: the
    /// budget, or for a run that fits itself to the machine what the
    /// machine has now.
    fn speed_budget(&self) -> u64 {
        match self
            .0
            .fitted_ceiling
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => self.0.budget.ram_bytes,
            fitted => fitted,
        }
    }
    /// A run that fits itself to the machine looks, a few times a second,
    /// at the memory Windows has available, and holds what it holds only to
    /// go faster by that instead of by a share of what was free when it
    /// started.
    ///
    /// More is free than at the start (another program ended): caches and
    /// work done at once may take it. Less is free than the machine should
    /// keep (`KEPT_FREE`: another program took memory): the caches used
    /// longest ago are given up until that much is free again, before
    /// Windows has to page for them. What the run cannot do without is not
    /// touched by either.
    fn follow_the_machine(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        /// How often the machine is looked at.
        const EVERY_MS: u64 = 250;
        if !n2r_win32::resource_native::memory_fits_the_machine() {
            return;
        }
        let now = self.0.made.elapsed().as_millis() as u64;
        let last = self.0.fitted_at_ms.load(Relaxed);
        if (last != 0 && now.saturating_sub(last) < EVERY_MS)
            || self
                .0
                .fitted_at_ms
                .compare_exchange(last, now.max(1), Relaxed, Relaxed)
                .is_err()
        {
            return;
        }
        let Ok((available, total)) = n2r_win32::resource_native::physical_memory_now() else {
            return;
        };
        let kept_free = kept_free(total);
        let (held, optional) = match self.0.state.lock() {
            Ok(state) => (
                state.leased_ram_bytes.saturating_add(state.index_bytes),
                state.optional_ram_bytes,
            ),
            Err(_) => return,
        };
        self.0
            .fitted_ceiling
            .store(fitted_ceiling(held, available, kept_free).max(1), Relaxed);
        // Too little is free: give back, the cache used longest ago first.
        // The lock is not held while one goes; it returns its own
        // reservation to this ledger.
        let mut owed = kept_free.saturating_sub(available).min(optional);
        while owed != 0 {
            let before = self.optional_bytes();
            if !n2r_win32::evict::evict_oldest() {
                break;
            }
            owed = owed.saturating_sub(before.saturating_sub(self.optional_bytes()).max(1));
        }
    }
    fn optional_bytes(&self) -> u64 {
        self.0
            .state
            .lock()
            .map_or(0, |state| state.optional_ram_bytes)
    }
    fn reserve_cache_ram_at(&self, bytes: u64, site: RamSite) -> Result<ArenaRamLease> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let leased = add(state.leased_ram_bytes, bytes)?;
        let optional = add(state.optional_ram_bytes, bytes)?;
        let ceiling = self.cache_ceiling();
        ensure!(
            !state.ram_poisoned && add(leased, state.index_bytes)? <= ceiling,
            "cache memory refused: leased={}, requested={}, limit={}",
            state.leased_ram_bytes,
            bytes,
            self.0.budget.ram_bytes
        );
        state.leased_ram_bytes = leased;
        state.optional_ram_bytes = optional;
        state.cache_ram_bytes = add(state.cache_ram_bytes, bytes)?;
        *state.ram_by_site.entry(site).or_default() += bytes;
        state.cache_sites.insert(site);
        note_ledger(&state, self.0.budget.ram_bytes);
        Ok(ArenaRamLease {
            arena: self.clone(),
            bytes,
            optional: true,
            cache: true,
            spare: false,
            site,
        })
    }
    /// Memory for a cache the conversion can do without (a store held in
    /// memory instead of read page by page). All such caches together may
    /// hold a third of the RAM budget, and one is granted only while the
    /// arena as a whole stays under half full, so that the reservations the
    /// conversion cannot do without find room without a cache being given
    /// up. A refusal is not a failure: the caller keeps reading from disk.
    /// (What [`Self::reserve_cache_ram`] granted counts for neither.)
    #[track_caller]
    pub fn reserve_optional_ram(&self, bytes: u64) -> Result<ArenaRamLease> {
        let caller = std::panic::Location::caller();
        let site = (caller.file(), caller.line());
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let leased = add(state.leased_ram_bytes, bytes)?;
        let optional = add(state.optional_ram_bytes, bytes)?;
        ensure!(
            !state.ram_poisoned
                && optional - state.cache_ram_bytes <= self.0.budget.ram_bytes / 3
                && add(leased, state.index_bytes)? <= self.0.budget.ram_bytes
                && add(leased, state.index_bytes)? - state.cache_ram_bytes
                    <= self.0.budget.ram_bytes / 2,
            "optional cache memory refused: leased={}, optional={}, requested={}, limit={}",
            state.leased_ram_bytes,
            state.optional_ram_bytes,
            bytes,
            self.0.budget.ram_bytes
        );
        state.leased_ram_bytes = leased;
        state.optional_ram_bytes = optional;
        *state.ram_by_site.entry(site).or_default() += bytes;
        state.cache_sites.insert(site);
        note_ledger(&state, self.0.budget.ram_bytes);
        Ok(ArenaRamLease {
            arena: self.clone(),
            bytes,
            optional: true,
            cache: false,
            spare: false,
            site,
        })
    }
    pub fn reserve_group(&self, group: ArtifactGroup, maximum: u64) -> Result<ArtifactGroupPermit> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        ensure!(
            !(state.windows_native_allocation && group == ArtifactGroup::LegacyExpectation),
            "Windows native report allocation consumes the legacy expectation slot"
        );
        ensure!(
            maximum <= group.limit(self.0.budget, state.windows_native_allocation),
            "artifact group exceeds its resource share"
        );
        ensure!(
            !state.prepared_closed && !state.groups.contains_key(&group),
            "artifact group already reserved; clone its real permit"
        );
        let held = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        ensure!(
            add(held, maximum)? <= self.0.budget.scratch_bytes,
            "aggregate artifact reservation exhausted"
        );
        self.check_free(&state, maximum)?;
        state.groups.insert(
            group,
            Group {
                maximum,
                held: 0,
                files: 0,
                sealed: false,
                poisoned: false,
                native_journal: None,
            },
        );
        Ok(ArtifactGroupPermit {
            arena: self.clone(),
            group,
        })
    }

    /// Borrow an already reserved current-epoch quota. This cannot create a
    /// reservation or recover an old epoch's permit from serialized counters.
    pub(crate) fn retained_group(
        &self,
        group: ArtifactGroup,
        maximum: u64,
    ) -> Result<ArtifactGroupPermit> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let actual = state
            .groups
            .get(&group)
            .context("actual group is not reserved")?;
        ensure!(
            !state.prepared_closed
                && !state.allocation_poisoned
                && !state.ram_poisoned
                && !actual.poisoned
                && !actual.sealed
                && actual.maximum == maximum,
            "actual retained group is closed, poisoned or has a different quota"
        );
        Ok(ArtifactGroupPermit {
            arena: self.clone(),
            group,
        })
    }

    /// Attach an actual fixed-EOF native journal file owner to its already
    /// reserved quota. The witness is non-serializable and constructed only
    /// from the prepared same-file native journal; callers cannot supply a
    /// scalar allocation credit. No group reservation is released here.
    pub(crate) fn attach_native_journal(
        &self,
        permit: &ArtifactGroupPermit,
        owner: crate::general_reconstruct::selected_native_journal::NativeJournalAllocationOwner,
    ) -> Result<()> {
        ensure!(
            permit.group == ArtifactGroup::NativeJournal && self.same_arena(&permit.arena),
            "native journal quota belongs to a different arena or group"
        );
        let volume_prefix =
            format!("{}\\", self.volume_guid_path()?.trim_end_matches('\\')).to_ascii_lowercase();
        ensure!(
            owner
                .final_path()
                .to_ascii_lowercase()
                .starts_with(&volume_prefix),
            "native journal file is not on the arena's actual volume"
        );
        // This call performs metadata-only queries on the separate readonly
        // duplicate. It holds neither the journal owner nor an arena lock.
        let _ = owner.observe()?;
        let memory = (owner.final_path().encode_utf16().count() as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add(256 * 1024))
            .context("native journal witness RAM overflow")?;
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        let group = state
            .groups
            .get(&ArtifactGroup::NativeJournal)
            .context("native journal quota missing")?;
        ensure!(
            !state.prepared_closed
                && !state.allocation_poisoned
                && !group.poisoned
                && !group.sealed
                && group.native_journal.is_none()
                && owner.reservation_bytes() == group.maximum,
            "native journal quota or owner differs"
        );
        // Re-observe under the arena lock before registering. The query does
        // not acquire an arena/journal mutex and cannot invert lock order.
        let _ = owner.observe()?;
        let registry = add(state.index_bytes, memory)?;
        ensure!(
            registry <= self.0.budget.retained_index_bytes
                && add(registry, state.leased_ram_bytes)? <= self.needed_ceiling(&state),
            "native journal witness RAM exceeds aggregate admission"
        );
        state.index_bytes = registry;
        state
            .groups
            .get_mut(&ArtifactGroup::NativeJournal)
            .unwrap()
            .native_journal = Some(owner);
        Ok(())
    }

    fn check_free(&self, state: &State, additional: u64) -> Result<()> {
        ensure!(
            !state.allocation_poisoned,
            "artifact allocation ledger is poisoned"
        );
        let held = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        let actual_files = state.verified_local_allocated_bytes;
        // The retained native witness only queries its own readonly file
        // metadata. It acquires neither a journal lock nor this arena lock,
        // so querying it while State is held cannot invert lock ordering.
        let native_credit = state
            .groups
            .values()
            .filter_map(|g| g.native_journal.as_ref())
            .try_fold(0u64, |n, owner| add(n, owner.observe()?.1))?;
        let actual = add(actual_files, native_credit)?;
        let pending = add(held, additional)?
            .checked_sub(actual)
            .context("artifact physical accounting underflow")?;
        // Only the working volume's free space is asked for, and for the
        // root as this ledger resolved it when it was made. That resolved
        // path is what every call was given to resolve again before it
        // asked, so Windows is asked the same question about the same path;
        // a root that is no longer there is now refused by that question
        // itself. The sample of the machine's memory that came with the
        // complete observation was never part of this decision.
        ensure!(
            n2r_win32::resource_native::scratch_free_bytes(&self.0.root)? >= pending,
            "actual scratch free space cannot cover live reservations"
        );
        Ok(())
    }
    pub fn usage(&self) -> Result<ArenaUsage> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        let promised = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        let (mut wire, mut allocated) = state.reconciled_verified_totals()?;
        let mut native_files = 0u64;
        for owner in state
            .groups
            .values()
            .filter_map(|g| g.native_journal.as_ref())
        {
            let (actual, credit) = owner.observe()?;
            allocated = add(allocated, actual)?;
            wire = add(wire, credit)?;
            native_files = add(native_files, 1)?;
        }
        Ok(ArenaUsage {
            promised_bytes: promised,
            actual_wire_bytes: wire,
            actual_allocated_bytes: allocated,
            files: add(state.entries.len() as u64, native_files)?,
            leased_ram_bytes: state.leased_ram_bytes,
            registry_ram_bytes: state.index_bytes,
            local_allocation_credit_bytes: add(
                state.verified_local_allocated_bytes,
                state
                    .groups
                    .values()
                    .filter_map(|g| g.native_journal.as_ref())
                    .try_fold(0u64, |n, owner| add(n, owner.observe()?.1))?,
            )?,
        })
    }
    /// Telemetry only, querying the existing retained readonly native J owner.
    /// Returns (current allocation,current EOF), never a reservation or peak.
    pub(crate) fn observe_native_journal_metadata(&self) -> Result<Option<(u64, u64)>> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        state
            .groups
            .get(&ArtifactGroup::NativeJournal)
            .and_then(|group| group.native_journal.as_ref())
            .map(|owner| owner.observe())
            .transpose()
    }
}
impl ArtifactGroupPermit {
    pub fn group(&self) -> ArtifactGroup {
        self.group
    }
    pub fn arena(&self) -> &ArtifactArena {
        &self.arena
    }
    pub fn maximum_bytes(&self) -> Result<u64> {
        Ok(self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?
            .groups
            .get(&self.group)
            .context("group missing")?
            .maximum)
    }
    /// Change a live phase promise without discarding any actual file owner.
    /// Growth still pays the same aggregate and current physical-space gates.
    pub(crate) fn resize_reservation(&self, maximum: u64) -> Result<()> {
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let group = state.groups.get(&self.group).context("group missing")?;
        ensure!(
            !state.prepared_closed
                && !state.allocation_poisoned
                && !state.ram_poisoned
                && !group.sealed
                && !group.poisoned
                && group.native_journal.is_none()
                && self.group == ArtifactGroup::RecoveryCopy
                && maximum >= group.held
                && maximum
                    <= self
                        .group
                        .limit(self.arena.0.budget, state.windows_native_allocation),
            "phase reservation cannot resize below held files or outside its share"
        );
        let prior = group.maximum;
        let promised = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        ensure!(
            add(
                promised
                    .checked_sub(prior)
                    .context("phase promise underflow")?,
                maximum
            )? <= self.arena.0.budget.scratch_bytes,
            "resized phase exceeds aggregate budget"
        );
        if maximum > prior {
            self.arena.check_free(&state, maximum - prior)?;
        }
        state.groups.get_mut(&self.group).unwrap().maximum = maximum;
        Ok(())
    }
    pub(crate) fn held_bytes(&self) -> Result<u64> {
        let state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        Ok(state.groups.get(&self.group).context("group missing")?.held)
    }
    pub fn reserve_file(&self, path: &Path, maximum: u64) -> Result<ArtifactPathPermit> {
        self.reserve_path(path, maximum, false)
    }
    /// Reopen and account an existing ordinary immutable artifact in place.
    /// The resulting lease owns a freshly hashed, deny-writer handle. It is
    /// evidence storage ownership only, never old source/admission authority.
    pub fn adopt_existing(
        &self,
        path: &Path,
        expected_sha256: &str,
        maximum: u64,
    ) -> Result<ArtifactLease> {
        let _identity_ram = self.arena.reserve_ram(256 * 1024)?;
        self.reserve_path(path, maximum, true)?
            .verify_closed(expected_sha256)
    }
    fn reserve_path(
        &self,
        path: &Path,
        maximum: u64,
        existing: bool,
    ) -> Result<ArtifactPathPermit> {
        ensure!(
            self.group != ArtifactGroup::NativeJournal,
            "native journal quota is bound only through its actual native owner"
        );
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                && matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))),
            "absolute ordinary local artifact path required"
        );
        let parent = path.parent().context("artifact parent absent")?;
        let handles = parents(parent)?;
        let canonical_parent = fs::canonicalize(parent)?;
        let external_origin = if existing {
            self.arena
                .existing_parent_origin(&canonical_parent, &handles)?
        } else {
            ensure!(
                canonical_parent == self.arena.0.root
                    || canonical_parent.starts_with(&self.arena.0.root),
                "new artifact path escapes writable arena root"
            );
            None
        };
        let allocation_slack = external_origin
            .as_ref()
            .map_or(self.arena.0.allocation_slack, |root| root.allocation_slack);
        let guid = n2r_win32::file_storage::final_path_guid(
            handles.first().context("artifact parent handle absent")?,
        )?;
        ensure!(
            external_origin.is_some()
                || guid.eq_ignore_ascii_case(&self.arena.0.root_guid)
                || guid.to_ascii_lowercase().starts_with(
                    &(self
                        .arena
                        .0
                        .root_guid
                        .trim_end_matches('\\')
                        .to_ascii_lowercase()
                        + "\\")
                ),
            "artifact parent route changed"
        );
        // Canonical paths on Windows use a verbatim prefix. Keep the validated
        // ordinary path for consumers that intentionally reject that syntax;
        // containment and the held GUID parent above remain authoritative.
        let path = path.to_path_buf();
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("Unicode artifact leaf required")?;
        let stem = leaf.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            !leaf.is_empty()
                && !leaf.ends_with([' ', '.'])
                && !leaf.chars().any(|c| c.is_control()
                    || matches!(c, ':' | '/' | '\\' | '"' | '<' | '>' | '|' | '?' | '*'))
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !((stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.len() == 4
                    && stem.as_bytes()[3].is_ascii_digit()),
            "ambiguous artifact leaf refused"
        );
        if existing {
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
                "reopened artifact must be an existing ordinary file"
            );
        } else {
            ensure!(!path.exists(), "artifact destination already exists");
        }
        let memory = add(
            // Include a conservative node for the actual identity registry.
            1280,
            (path.as_os_str().as_encoded_bytes().len() as u64)
                .checked_mul(6)
                .context("artifact path memory overflow")?,
        )?;
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.prepared_closed && !state.entries.contains_key(&path),
            "artifact path already registered"
        );
        let group = state
            .groups
            .get(&self.group)
            .context("artifact group missing")?;
        ensure!(
            !group.sealed && !group.poisoned && add(group.held, maximum)? <= group.maximum,
            "artifact group sealed/poisoned/exhausted"
        );
        let all = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        ensure!(
            add(all, allocation_slack)? <= self.arena.0.budget.scratch_bytes,
            "artifact allocation slack exceeds aggregate budget"
        );
        ensure!(
            !state.ram_poisoned
                && add(state.index_bytes, memory)? <= self.arena.0.budget.retained_index_bytes
                && add(add(state.index_bytes, memory)?, state.leased_ram_bytes)?
                    <= self.arena.needed_ceiling(&state),
            "artifact registry RAM exhausted"
        );
        // Adoption allocates no disk bytes. Its actual allocation is credited
        // only after verify_file has hashed and pinned this exact file object.
        if !existing {
            self.arena.check_free(&state, allocation_slack)?;
        }
        state.overhead = add(state.overhead, allocation_slack)?;
        state.index_bytes = add(state.index_bytes, memory)?;
        let group = state.groups.get_mut(&self.group).unwrap();
        group.held = add(group.held, maximum)?;
        state.entries.insert(
            path.clone(),
            Entry {
                group: self.group,
                reserved: maximum,
                maximum,
                registry_bytes: memory,
                verified: None,
                lease: Weak::new(),
                external_readonly: external_origin.is_some(),
                allocation_slack,
            },
        );
        Ok(ArtifactPathPermit {
            group: self.clone(),
            path,
            _parents: handles,
            complete: false,
            external_origin,
            allocation_slack,
        })
    }
    pub fn seal(&self) -> Result<ArtifactGroupSeal> {
        let (count, hash_bytes) = {
            let state = self
                .arena
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
            ensure!(
                !state.prepared_closed,
                "prepared arena disk ledger is closed"
            );
            let mut count = 0usize;
            let mut hash_bytes = 0u64;
            for entry in state.entries.values().filter(|e| e.group == self.group) {
                let verified = entry
                    .verified
                    .as_ref()
                    .context("artifact group still has an active/unverified creation")?;
                count = count
                    .checked_add(1)
                    .context("sealed artifact count overflow")?;
                hash_bytes = hash_bytes.max(verified.snapshot.file_bytes.min(HASH_WORKSPACE));
            }
            (count, hash_bytes)
        };
        let pin_bytes = (count as u64)
            .checked_mul((2 * std::mem::size_of::<Arc<FilePin>>()) as u64)
            .and_then(|n| n.checked_add(256))
            .context("sealed artifact pin RAM overflow")?;
        let pins_ram = self.arena.reserve_ram(pin_bytes)?;
        let _hash_ram = self.arena.reserve_ram(hash_bytes)?;
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.prepared_closed
                && state
                    .entries
                    .values()
                    .filter(|e| e.group == self.group)
                    .count()
                    == count,
            "artifact group changed before sealing"
        );
        let mut wire = 0;
        let mut allocated = 0;
        let mut pins = Vec::new();
        pins.try_reserve_exact(count)
            .context("sealed artifact pin allocation failed")?;
        ensure!(
            (pins.capacity() as u64)
                .checked_mul(std::mem::size_of::<Arc<FilePin>>() as u64)
                .is_some_and(|n| n <= pin_bytes),
            "sealed artifact pin allocation exceeded reservation"
        );
        for entry in state.entries.values().filter(|e| e.group == self.group) {
            let verified = entry
                .verified
                .as_ref()
                .context("artifact group still has an active/unverified creation")?;
            let pin = entry
                .lease
                .upgrade()
                .context("sealed artifact requires its actual retained immutable file owner")?;
            ensure!(
                verified.snapshot.file_bytes.min(HASH_WORKSPACE) <= hash_bytes,
                "artifact group changed before sealing"
            );
            pin.revalidate_prepaid()?;
            wire = add(wire, verified.snapshot.file_bytes)?;
            allocated = add(allocated, verified.snapshot.allocation_bytes)?;
            pins.push(pin);
        }
        ensure!(pins.len() == count, "artifact group changed before sealing");
        state.reconciled_verified_totals()?;
        let group = state
            .groups
            .get_mut(&self.group)
            .context("artifact group missing")?;
        ensure!(
            !group.poisoned
                && group.native_journal.is_none()
                && self.group != ArtifactGroup::NativeJournal,
            "artifact group is poisoned or reserved for a native journal"
        );
        group.maximum = wire;
        group.held = wire;
        group.sealed = true;
        Ok(ArtifactGroupSeal {
            permit: self.clone(),
            pins: Arc::new(SealedPins {
                pins,
                _ram: pins_ram,
            }),
            wire_bytes: wire,
            allocated_bytes: allocated,
        })
    }
}
impl Drop for ArenaRamLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.arena.0.state.lock() {
            if let Some(remaining) = state.leased_ram_bytes.checked_sub(self.bytes) {
                state.leased_ram_bytes = remaining;
            } else {
                state.ram_poisoned = true;
            }
            if self.optional {
                state.optional_ram_bytes = state.optional_ram_bytes.saturating_sub(self.bytes);
            }
            if self.cache {
                state.cache_ram_bytes = state.cache_ram_bytes.saturating_sub(self.bytes);
            }
            if self.spare {
                state.spare.returned(self.bytes);
            }
            release_site(&mut state.ram_by_site, self.site, self.bytes);
        }
    }
}
impl ArtifactPathPermit {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn verify_closed_current(self) -> Result<ArtifactLease> {
        let maximum = self
            .group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?
            .entries
            .get(&self.path)
            .context("artifact entry absent")?
            .maximum;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&self.path)?;
        let before = reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        let hash_ram = self
            .group
            .arena
            .reserve_ram(before.file_bytes.min(HASH_WORKSPACE))?;
        let hash = hex::encode(n2r_win32::metadata_pages::pinning_digest(
            &mut file,
            before.file_bytes,
        )?);
        drop(file);
        drop(hash_ram);
        self.verify_closed(&hash)
    }
    pub fn extend(&mut self, bytes: u64) -> Result<()> {
        ensure!(
            self.external_origin.is_none(),
            "external readonly artifacts cannot extend or become output"
        );
        let mut state = self
            .group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let group = state
            .groups
            .get(&self.group.group)
            .context("artifact group missing")?;
        ensure!(
            !state.prepared_closed
                && !group.sealed
                && !group.poisoned
                && add(group.held, bytes)? <= group.maximum,
            "artifact group cannot extend reservation"
        );
        self.group.arena.check_free(&state, 0)?;
        let entry = state
            .entries
            .get_mut(&self.path)
            .context("artifact entry absent")?;
        ensure!(entry.verified.is_none(), "artifact already closed");
        entry.reserved = add(entry.reserved, bytes)?;
        entry.maximum = entry.reserved;
        let group = state.groups.get_mut(&self.group.group).unwrap();
        group.held = add(group.held, bytes)?;
        Ok(())
    }
    /// Holds the closed file to `expected_sha256`, the digest its writer
    /// computed: the BLAKE3 of a record store in the current format, the
    /// SHA-256 of any other file (the parameter keeps its historical name).
    pub fn verify_closed(self, expected_sha256: &str) -> Result<ArtifactLease> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&self.path)?;
        self.verify_file(file, expected_sha256, Hold::ByFormat)
    }
    pub fn verify_closed_handle(self, file: &File, expected_sha256: &str) -> Result<ArtifactLease> {
        n2r_win32::file_storage::require_readonly_access(file)?;
        let file = n2r_win32::file_storage::duplicate_readonly(file)?;
        self.verify_file(file, expected_sha256, Hold::ByFormat)
    }
    /// As [`Self::verify_closed_handle`] for a file whose bytes are not its
    /// writer's to shape (bytes copied from a volume), so that nothing in
    /// them is read as a format: `expected` is of `algorithm`, which the
    /// writer hashed them with.
    pub fn verify_closed_handle_by(
        self,
        algorithm: n2r_win32::bulk_digest::Algorithm,
        file: &File,
        expected: &str,
    ) -> Result<ArtifactLease> {
        n2r_win32::file_storage::require_readonly_access(file)?;
        let file = n2r_win32::file_storage::duplicate_readonly(file)?;
        self.verify_file(file, expected, Hold::By(algorithm))
    }
    fn verify_file(
        mut self,
        mut file: File,
        expected_sha256: &str,
        hold: Hold<'_>,
    ) -> Result<ArtifactLease> {
        let maximum = {
            let state = self
                .group
                .arena
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
            ensure!(
                !state.prepared_closed,
                "prepared arena disk ledger is closed"
            );
            state
                .entries
                .get(&self.path)
                .context("artifact entry absent")?
                .maximum
        };
        // The handle is read-only here; reserve the maximum hash buffer before
        // inspecting its current length, so a changing file cannot outgrow it.
        let _hash_ram = self.group.arena.reserve_ram(maximum.min(HASH_WORKSPACE))?;
        let verified = inspect(&mut file, maximum, expected_sha256, hold)?;
        let parent_guid = n2r_win32::file_storage::final_path_guid(
            self._parents
                .first()
                .context("artifact parent owner absent")?,
        )?;
        let leaf = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .context("Unicode artifact leaf required")?;
        let expected_path = format!("{}\\{}", parent_guid.trim_end_matches('\\'), leaf);
        ensure!(
            verified
                .snapshot
                .final_path
                .eq_ignore_ascii_case(&expected_path),
            "held artifact final path differs from granted path"
        );
        ensure!(
            verified.snapshot.allocation_bytes
                <= add(
                    add(verified.snapshot.file_bytes, self.allocation_slack)?,
                    n2r_win32::file_storage::append_preallocation_allowance(
                        verified.snapshot.file_bytes
                    ),
                )?,
            "artifact physical allocation exceeds reserved slack: path={:?}, EOF={}, allocation={}, grant_max_EOF={}, reserved_slack={}",
            verified.snapshot.final_path,
            verified.snapshot.file_bytes,
            verified.snapshot.allocation_bytes,
            maximum,
            self.allocation_slack
        );
        let pin = Arc::new(FilePin {
            arena: self.group.arena.clone(),
            file: Mutex::new(Some(file)),
            snapshot: verified.snapshot.clone(),
            modified: verified.modified,
            sha256: verified.sha256.clone(),
            reread: verified.reread,
            _parents: std::mem::take(&mut self._parents),
            external_origin: self.external_origin.clone(),
            last_full: n2r_win32::verify_policy::LastFull::new(),
        });
        let mut state = self
            .group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        ensure!(
            !state.prepared_closed,
            "prepared arena disk ledger is closed"
        );
        let entry = state
            .entries
            .get(&self.path)
            .context("artifact entry absent")?;
        ensure!(
            entry.group == self.group.group
                && entry.verified.is_none()
                && entry.external_readonly == self.external_origin.is_some()
                && entry.allocation_slack == self.allocation_slack,
            "artifact entry is already verified or belongs to another group"
        );
        let old = entry.reserved;
        let next_allocated =
            state.next_verified_allocation(0, verified.snapshot.allocation_bytes)?;
        let next_local_allocated = if self.external_origin.is_none() {
            add(
                state.verified_local_allocated_bytes,
                verified.snapshot.allocation_bytes,
            )?
        } else {
            state.verified_local_allocated_bytes
        };
        let extra = verified
            .snapshot
            .allocation_bytes
            .saturating_sub(verified.snapshot.file_bytes);
        let next_overhead = state
            .overhead
            // Replace this file's reserved slack with its actual surplus, so the
            // ledger stays exactly "allocation minus length" over all files.
            // Filesystem append pre-allocation, admitted above, can make the
            // surplus larger than the slack that was reserved.
            .checked_sub(self.allocation_slack)
            .and_then(|overhead| overhead.checked_add(extra))
            .context("artifact slack underflow")?;
        let group = state.groups.get(&self.group.group).unwrap();
        ensure!(
            !group.sealed && !group.poisoned,
            "artifact group sealed while writing"
        );
        let next_held = group
            .held
            .checked_sub(
                old.checked_sub(verified.snapshot.file_bytes)
                    .context("verified artifact exceeds its reservation")?,
            )
            .context("artifact reservation underflow")?;
        let next_files = add(group.files, 1)?;
        let identity = (
            verified.snapshot.volume_serial_number,
            verified.snapshot.file_id_128,
        );
        ensure!(
            !state.verified_identities.contains(&identity),
            "artifact file object is already accounted through another path"
        );
        // Publish the snapshot and its allocation credit in one infallible
        // commit after all prospective accounting has passed.
        state.overhead = next_overhead;
        let group = state.groups.get_mut(&self.group.group).unwrap();
        group.held = next_held;
        group.files = next_files;
        let entry = state.entries.get_mut(&self.path).unwrap();
        entry.reserved = verified.snapshot.file_bytes;
        entry.verified = Some(verified);
        entry.lease = Arc::downgrade(&pin);
        state.verified_allocated_bytes = next_allocated;
        state.verified_local_allocated_bytes = next_local_allocated;
        state.verified_identities.insert(identity);
        self.complete = true;
        Ok(ArtifactLease {
            group: self.group.clone(),
            path: self.path.clone(),
            pin,
        })
    }
}
impl Drop for ArtifactPathPermit {
    fn drop(&mut self) {
        if !self.complete {
            if let Ok(mut state) = self.group.arena.0.state.lock() {
                if let Some(group) = state.groups.get_mut(&self.group.group) {
                    group.poisoned = true;
                }
            }
        }
    }
}
impl FilePin {
    fn revalidate_identity(&self) -> Result<()> {
        if let Some(root) = &self.external_origin {
            root.revalidate()?;
        }
        // Native GUID-path observation can grow its UTF-16 and UTF-8 buffers
        // to the Windows path bound. Prepay that transient identity workspace.
        let _ram = self.arena.reserve_ram(256 * 1024)?;
        let held = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact file lock poisoned"))?;
        let file = held.as_ref().context("artifact owner closed")?;
        ensure!(
            reference_file::observe_reference_file_handle_with_limit(
                file,
                self.snapshot.file_bytes
            )? == self.snapshot
                && file.metadata()?.modified()? == self.modified,
            "artifact held identity changed inside prepared arena boundary"
        );
        Ok(())
    }
    fn revalidate(&self) -> Result<()> {
        let _hash_ram = self
            .arena
            .reserve_ram(self.snapshot.file_bytes.min(HASH_WORKSPACE))?;
        self.revalidate_prepaid()
    }
    fn revalidate_prepaid(&self) -> Result<()> {
        if let Some(root) = &self.external_origin {
            root.revalidate()?;
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact file lock poisoned"))?;
        // The file was hashed when it was sealed and has been held open,
        // denying writers, ever since. Unless a full check is due, confirm
        // that it is still the same file with the same size and timestamp.
        if !n2r_win32::verify_policy::full(&self.last_full) {
            let held = file.as_ref().context("artifact owner closed")?;
            ensure!(
                reference_file::observe_reference_file_handle_with_limit(
                    held,
                    self.snapshot.file_bytes
                )? == self.snapshot
                    && held.metadata()?.modified()? == self.modified,
                "artifact held identity changed"
            );
            return Ok(());
        }
        let current = inspect(
            file.as_mut().context("artifact owner closed")?,
            self.snapshot.file_bytes,
            &self.sha256,
            Hold::Reread(&self.reread),
        )?;
        ensure!(
            current.snapshot == self.snapshot && current.modified == self.modified,
            "artifact held identity changed"
        );
        Ok(())
    }
}
impl ArtifactLease {
    /// Equality of the actual shared runtime owner, never a saved file pin.
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pin, &other.pin)
    }
    pub(crate) fn same_group(&self, permit: &ArtifactGroupPermit) -> bool {
        self.group.group == permit.group && self.group.arena.same_arena(&permit.arena)
    }
    /// The arena whose ledger accounts for this artifact: where a pass over
    /// it asks for memory it can do without (`reserve_spare_ram`).
    pub(crate) fn arena(&self) -> &ArtifactArena {
        &self.group.arena
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn wire_bytes(&self) -> u64 {
        self.pin.snapshot.file_bytes
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.pin.snapshot.allocation_bytes
    }
    pub fn snapshot(&self) -> &ReferenceFileSnapshot {
        &self.pin.snapshot
    }
    pub fn sha256(&self) -> &str {
        &self.pin.sha256
    }
    pub fn revalidate(&self) -> Result<()> {
        self.pin.revalidate()
    }
    /// Reuse only the complete content check from the current non-escaping
    /// closed-arena boundary; actual held-file identity is still observed now.
    pub(crate) fn revalidate_with_arena_witness(
        &self,
        witness: &PreparedArenaRevalidation<'_>,
    ) -> Result<()> {
        witness.require_artifact(self)
    }
    pub fn retire(self) -> Result<()> {
        ensure!(
            self.pin.external_origin.is_none(),
            "external readonly origin artifacts cannot be retired/deleted"
        );
        {
            let state = self
                .group
                .arena
                .0
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
            ensure!(
                !state.prepared_closed && !state.allocation_poisoned,
                "prepared arena artifacts cannot be retired"
            );
        }
        ensure!(
            Arc::strong_count(&self.pin) == 1,
            "artifact still has surviving owners"
        );
        self.revalidate()?;
        let ArtifactLease { group, path, pin } = self;
        let pin = Arc::try_unwrap(pin).map_err(|_| anyhow::anyhow!("artifact owners changed"))?;
        drop(
            pin.file
                .into_inner()
                .map_err(|_| anyhow::anyhow!("artifact file lock poisoned"))?,
        );
        let mut file = OpenOptions::new()
            .access_mode(0x80000000 | 0x10000)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(&path)?;
        let _hash_ram = group
            .arena
            .reserve_ram(pin.snapshot.file_bytes.min(HASH_WORKSPACE))?;
        // A file about to be deleted needs its identity confirmed, not its
        // contents hashed again.
        let verified = if n2r_win32::verify_policy::checks_once() {
            Verified {
                snapshot: reference_file::observe_reference_file_handle_with_limit(
                    &file,
                    pin.snapshot.file_bytes,
                )?,
                modified: file.metadata()?.modified()?,
                sha256: pin.sha256.clone(),
                reread: pin.reread,
            }
        } else {
            inspect(
                &mut file,
                pin.snapshot.file_bytes,
                &pin.sha256,
                Hold::Reread(&pin.reread),
            )?
        };
        if verified.snapshot != pin.snapshot || verified.modified != pin.modified {
            let _diagnostic_ram = group.arena.reserve_ram(8192)?;
            let route: String = verified.snapshot.final_path.chars().take(512).collect();
            anyhow::bail!(
                "artifact changed before retirement: path={route:?}, path_changed={}, volume_serial={}/{}, file_id_changed={}, EOF={}/{}, allocation={}/{}, attributes={:#x}/{:#x}, links={}/{}, modified={:?}/{:?}",
                verified.snapshot.final_path != pin.snapshot.final_path,
                verified.snapshot.volume_serial_number,
                pin.snapshot.volume_serial_number,
                verified.snapshot.file_id_128 != pin.snapshot.file_id_128,
                verified.snapshot.file_bytes,
                pin.snapshot.file_bytes,
                verified.snapshot.allocation_bytes,
                pin.snapshot.allocation_bytes,
                verified.snapshot.file_attributes,
                pin.snapshot.file_attributes,
                verified.snapshot.number_of_links,
                pin.snapshot.number_of_links,
                verified.modified,
                pin.modified,
            );
        }
        let mut state = group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        // Hashing, opening and RAM reservation are complete before this lock.
        // Keep it through deletion and the infallible registry commit so no
        // capacity query can observe freed disk space with the old credit.
        let transition = (|| -> Result<_> {
            ensure!(
                !state.prepared_closed && !state.allocation_poisoned,
                "prepared arena artifacts cannot be retired"
            );
            let entry = state
                .entries
                .get(&path)
                .context("retired artifact missing from ledger")?;
            let snapshot = &entry
                .verified
                .as_ref()
                .context("retired artifact unverified")?
                .snapshot;
            ensure!(
                entry.group == group.group && *snapshot == pin.snapshot && !entry.external_readonly,
                "retired artifact differs from its credited snapshot"
            );
            ensure!(
                state
                    .verified_identities
                    .contains(&(snapshot.volume_serial_number, snapshot.file_id_128,)),
                "retired artifact identity was absent from accounting"
            );
            let index = state
                .index_bytes
                .checked_sub(entry.registry_bytes)
                .context("artifact registry RAM credit underflow")?;
            let overhead = state
                .overhead
                .checked_sub(
                    snapshot
                        .allocation_bytes
                        .saturating_sub(snapshot.file_bytes),
                )
                .context("artifact allocation credit underflow")?;
            let current_group = state
                .groups
                .get(&group.group)
                .context("retired artifact group absent")?;
            let held = current_group
                .held
                .checked_sub(snapshot.file_bytes)
                .context("artifact wire credit underflow")?;
            let files = current_group
                .files
                .checked_sub(1)
                .context("artifact file count underflow")?;
            let remove = snapshot.allocation_bytes;
            let allocated = state.next_verified_allocation(remove, 0)?;
            let local_allocated = state
                .verified_local_allocated_bytes
                .checked_sub(remove)
                .context("local artifact allocation credit underflow")?;
            Ok((index, overhead, held, files, allocated, local_allocated))
        })();
        let (index, overhead, held, files, allocated, local_allocated) = match transition {
            Ok(values) => values,
            Err(error) => {
                state.allocation_poisoned = true;
                return Err(error);
            }
        };
        // These plain file operations acquire neither arena nor journal
        // ownership locks. Failure poisons the already-held state directly.
        if let Err(error) = n2r_win32::file_storage::mark_delete_on_close(&file) {
            state.allocation_poisoned = true;
            return Err(error.into());
        }
        drop(file);
        if !matches!(fs::symlink_metadata(&path),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound)
        {
            state.allocation_poisoned = true;
            anyhow::bail!("artifact retirement not observed complete");
        }
        state
            .entries
            .remove(&path)
            .expect("validated retired entry");
        state.index_bytes = index;
        state.overhead = overhead;
        state.verified_allocated_bytes = allocated;
        state.verified_local_allocated_bytes = local_allocated;
        state
            .verified_identities
            .remove(&(pin.snapshot.volume_serial_number, pin.snapshot.file_id_128));
        let current_group = state.groups.get_mut(&group.group).unwrap();
        current_group.held = held;
        if current_group.sealed {
            current_group.maximum = held;
        }
        current_group.files = files;
        Ok(())
    }
}
impl ArtifactGroupSeal {
    /// Equality of the actual retained seal collection, not matching JSON.
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pins, &other.pins)
    }
    /// A seal owns every file it covers until all seal clones are dropped.
    pub fn revalidate(&self) -> Result<()> {
        for pin in &self.pins.pins {
            pin.revalidate()?;
        }
        Ok(())
    }
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }
    pub fn permit(&self) -> &ArtifactGroupPermit {
        &self.permit
    }
}

/// What a ledger's spare reservations hold, and the largest single
/// reservations the conversion could not do without that the ledger was
/// asked for beside them, granted or not. See [`spare_fits`].
#[derive(Default)]
struct SpareMemory {
    held: u64,
    // The largest while spare memory was held, at any time.
    largest_beside: u64,
    // The largest since spare memory was last asked for.
    largest_since: u64,
}
impl SpareMemory {
    /// The ledger was asked for `bytes` the conversion cannot do without.
    fn needed(&mut self, bytes: u64) {
        self.largest_since = self.largest_since.max(bytes);
        if self.held != 0 {
            self.largest_beside = self.largest_beside.max(bytes);
        }
    }
    /// The ledger, of `budget` bytes and holding `held`, was asked for
    /// `bytes` of spare memory: whether it grants them, counted if it does.
    #[cfg(test)]
    fn asked(&mut self, budget: u64, held: u64, bytes: u64) -> bool {
        self.asked_with_caches(budget, held, 0, bytes)
    }
    /// Like [`Self::asked`], while `caches` bytes of `held` are evictable
    /// caches (`optional_ram_bytes`). Total leased RAM (`held + bytes`) still
    /// stays within `budget` so a `--memory-limit` is never exceeded, while
    /// headroom for needed reservations is measured against `held - caches`
    /// because `reserve_ram` evicts caches before failing.
    fn asked_with_caches(&mut self, budget: u64, held: u64, caches: u64, bytes: u64) -> bool {
        let beside = self.largest_beside.max(self.largest_since);
        self.largest_since = 0;
        let non_cache = held.saturating_sub(caches);
        let granted = held.checked_add(bytes).is_some_and(|total| total <= budget)
            && spare_fits(budget, non_cache, bytes, beside);
        if granted {
            self.held = self.held.saturating_add(bytes);
        }
        granted
    }
    /// Spare memory was returned, or kept and is spare no longer.
    fn returned(&mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
    }
}

/// Whether a spare reservation of `bytes` may be granted by a ledger of
/// `budget` bytes that holds `held`.
///
/// A pass that works through a batch on helper threads reserves a workspace
/// for every object of the batch, and with batches of 256 those workspaces
/// took all a small ledger had left. The next reservation the pass could not
/// do without (566 MB to decode an object, on a machine with 9 GB) was then
/// refused, and a volume that converts with one object at a time was refused
/// for memory. A spare reservation therefore leaves free twice the largest
/// single reservation that the conversion could not do without and that the
/// ledger was asked for beside spare memory, whether it granted it or not,
/// and never less than a sixteenth of the budget: room for what the pass
/// itself reserves while the batch is held, and for one more beside it.
///
/// "Beside spare memory" is while some was held, at any time, or since
/// spare memory was last asked for. Those are the reservations of the
/// passes that work in batches, the ones a batch can starve; what a run
/// asks for once, elsewhere, does not count against its batches. (Counting
/// every reservation of the run left the batches of a machine with 24 GB
/// nothing: a decoding there reserves 1.8 GB, an earlier step far more.)
/// What a run that fits itself to the machine leaves free for Windows and
/// every other program: a tenth of the machine's memory, and no less than
/// 1 GiB.
fn kept_free(total_physical: u64) -> u64 {
    (total_physical / 10).max(1 << 30)
}

/// What the ledger may hold with things held only to go faster, when it
/// holds `held` and Windows has `available`: what it holds, and what is
/// available beyond what is kept free.
fn fitted_ceiling(held: u64, available: u64, kept_free: u64) -> u64 {
    held.saturating_add(available.saturating_sub(kept_free))
}

fn spare_fits(budget: u64, held: u64, bytes: u64, largest_beside: u64) -> bool {
    let headroom = largest_beside.saturating_mul(2).max(budget / 16);
    held.checked_add(bytes)
        .and_then(|taken| taken.checked_add(headroom))
        .is_some_and(|needed| needed <= budget)
}

#[cfg(test)]
mod ram_site_tests {
    use super::*;

    /// The figures of the run that was refused: a ledger of 4,430,898,032
    /// bytes, object workspaces of 13.5 MB, and a decoding that reserves
    /// 566,445,160.
    #[test]
    fn a_spare_reservation_leaves_room_for_the_largest_one_asked_for() {
        const BUDGET: u64 = 4_430_898_032;
        const DECODING: u64 = 566_445_160;
        const WORKSPACE: u64 = 13_500_000;
        // Workspaces are granted one after another until twice a decoding
        // would no longer fit beside them.
        let mut held = 500_000_000;
        let mut granted = 0;
        while spare_fits(BUDGET, held, WORKSPACE, DECODING) {
            held += WORKSPACE;
            granted += 1;
        }
        assert!(granted > 100, "a batch still runs at once: {granted}");
        assert!(
            held + 2 * DECODING <= BUDGET,
            "two decodings fit beside the batch's workspaces"
        );
        assert!(
            held + 2 * DECODING + WORKSPACE > BUDGET,
            "and no more was kept free"
        );
        // Before anything large was asked for, a sixteenth of the budget
        // stays free.
        assert!(spare_fits(BUDGET, 0, BUDGET - BUDGET / 16, 0));
        assert!(!spare_fits(BUDGET, 0, BUDGET - BUDGET / 16 + 1, 0));
        // A ledger whose largest request is half of it grants nothing spare,
        // and sums that overflow are a refusal.
        assert!(!spare_fits(BUDGET, 0, 1, BUDGET / 2 + 1));
        assert!(!spare_fits(u64::MAX, u64::MAX, 1, 0));
    }

    /// A walk on a machine with 24 GB: a decoding reserves an eighth of the
    /// ledger, and an earlier step asked for far more, once.
    #[test]
    fn what_a_run_asked_for_once_does_not_count_against_its_batches() {
        const BUDGET: u64 = 14_500_000_000;
        const DECODING: u64 = BUDGET / 8;
        const WORKSPACE: u64 = 40_000_000;
        let mut spare = SpareMemory::default();
        let base = 6_000_000_000;
        // Long before the walk, a step reserved nine gigabytes at once.
        spare.needed(9_000_000_000);
        // The walk's first object is decoded and paid for as before; its
        // second is decoded, and its workspace is the first spare request.
        // That one still sees the nine gigabytes and is refused.
        spare.needed(DECODING);
        spare.needed(WORKSPACE);
        spare.needed(DECODING);
        assert!(!spare.asked(BUDGET, base, WORKSPACE));
        // From the next object on, what counts is what the walk itself
        // reserves between its spare requests: a decoding.
        let mut held = base;
        let mut at_once = 0;
        for _ in 0..255 {
            spare.needed(DECODING);
            if !spare.asked(BUDGET, held, WORKSPACE) {
                break;
            }
            held += WORKSPACE;
            at_once += 1;
        }
        assert!(at_once > 100, "{at_once} objects of a batch run at once");
        assert_eq!(spare.held, at_once * WORKSPACE);
        assert_eq!(
            spare.largest_beside, DECODING,
            "the decodings beside the batch"
        );
        assert!(held + 2 * DECODING <= BUDGET);
        // The walk keeps each workspace, shrunk, for its row: none of it is
        // spare after that, and a large reservation made then, with no
        // spare memory held, does not count.
        spare.returned(at_once * WORKSPACE);
        assert_eq!(spare.held, 0);
        spare.needed(9_000_000_000);
        assert_eq!(spare.largest_beside, DECODING);
        // The next spare request sees it once, as the walk's first did.
        assert!(!spare.asked(BUDGET, base, WORKSPACE));
        // One made while spare memory is held counts from then on.
        spare.needed(DECODING);
        assert!(spare.asked(BUDGET, base, WORKSPACE));
        spare.needed(5_000_000_000);
        assert!(!spare.asked(BUDGET, base + WORKSPACE, WORKSPACE));
        assert_eq!(spare.largest_beside, 5_000_000_000);
    }

    #[test]
    fn evictable_caches_do_not_starve_spare_batch_headroom() {
        // Under --memory-limit 1240 MiB, caches fill up to 7/8 of the budget
        // (1,085 MiB), leaving 155 MiB free. A 100 MiB needed reservation
        // seen beside a batch requires 200 MiB of headroom, which fits easily
        // against non-cache memory (385 MiB) because reserve_ram evicts caches.
        const BUDGET: u64 = 1240 << 20;
        const CACHES: u64 = 700 << 20;
        const NON_CACHE: u64 = 385 << 20;
        const HELD: u64 = NON_CACHE + CACHES;
        const WORKSPACE: u64 = 2 << 20;
        let mut spare = SpareMemory::default();
        spare.needed(100 << 20);
        assert!(
            !spare.asked(BUDGET, HELD, WORKSPACE),
            "without cache awareness, headroom against total held starves the batch"
        );
        spare.needed(100 << 20);
        assert!(
            spare.asked_with_caches(BUDGET, HELD, CACHES, WORKSPACE),
            "with cache awareness, spare fits within remaining budget and non-cache headroom"
        );
        // Total leased RAM still never exceeds BUDGET.
        assert!(
            !spare.asked_with_caches(BUDGET, BUDGET - WORKSPACE + 1, CACHES, WORKSPACE),
            "total RAM including caches must never exceed the budget"
        );
    }

    #[test]
    fn a_ledger_that_runs_out_names_what_holds_the_most() {
        let mut held: BTreeMap<RamSite, u64> = BTreeMap::new();
        held.insert(("src/first.rs", 10), 3 << 30);
        held.insert(("src/second.rs", 20), 5 << 30);
        held.insert(("src/third.rs", 30), 1 << 20);
        let none = BTreeSet::new();
        assert_eq!(
            largest_sites(&held, &none),
            "5120 MiB at second.rs:20, 3072 MiB at first.rs:10, 1 MiB at third.rs:30"
        );
        // A cache is said to be one.
        assert_eq!(
            largest_sites(&held, &BTreeSet::from([("src/first.rs", 10)])),
            "5120 MiB at second.rs:20, 3072 MiB at first.rs:10 (a cache), 1 MiB at third.rs:30"
        );
        // A lease that is returned or shrunk is no longer held there.
        release_site(&mut held, ("src/second.rs", 20), 5 << 30);
        release_site(&mut held, ("src/first.rs", 10), 1 << 30);
        assert_eq!(
            largest_sites(&held, &none),
            "2048 MiB at first.rs:10, 1 MiB at third.rs:30"
        );
        // Six at most are named, the largest first.
        for line in 1..=9u32 {
            held.insert(("src/many.rs", line), u64::from(line) << 24);
        }
        let said = largest_sites(&held, &none);
        assert_eq!(said.matches(" MiB at ").count(), 6, "{said}");
        assert!(
            said.starts_with("2048 MiB at first.rs:10, 144 MiB at many.rs:9"),
            "{said}"
        );
    }
}
#[cfg(test)]
mod cache_tests {
    use super::*;
    use n2r_win32::evict::{CachePayment, Evictable, pay_for_cache};

    const LIMIT: u64 = 64 * 1024 * 1024;

    /// A ledger of 64 MiB in a directory of its own.
    fn ledger() -> (tempfile::TempDir, ArtifactArena) {
        let directory = tempfile::tempdir().unwrap();
        let arena = ArtifactArena::new(
            directory.path(),
            ResourceBudget {
                schema_version: 1,
                ram_bytes: LIMIT,
                scratch_bytes: 256 * 1024 * 1024,
                page_bytes: 65536,
                max_row_bytes: 65536,
                retained_index_bytes: LIMIT / 16,
                handle_slots: 1024,
            },
            &[],
        )
        .unwrap();
        (directory, arena)
    }
    fn held(arena: &ArtifactArena) -> (u64, u64) {
        let state = arena.0.state.lock().unwrap();
        (state.leased_ram_bytes, state.optional_ram_bytes)
    }

    #[test]
    fn a_reservation_that_finds_no_room_gets_the_oldest_caches_back() {
        const MIB: u64 = 1024 * 1024;
        let (_directory, arena) = ledger();
        // Three stores held in memory, an eighth of the ledger each; the
        // second is the one used last.
        let store = || Evictable::new(arena.reserve_cache_ram(LIMIT / 8).unwrap());
        let (first, second, third) = (store(), store(), store());
        assert!(second.get().is_some());
        let needed = arena.reserve_ram(LIMIT / 2 - MIB).unwrap();
        assert_eq!(held(&arena), (LIMIT * 7 / 8 - MIB, LIMIT * 3 / 8));
        // What the run then needs has no room beside them: a quarter, with
        // an eighth left. The store used longest ago goes, and only that.
        let more = arena.reserve_ram(LIMIT / 4).unwrap();
        assert!(!first.is_held() && first.get().is_none());
        assert!(second.is_held() && third.is_held());
        assert_eq!(held(&arena), (LIMIT - MIB, LIMIT / 4));
        assert!(n2r_win32::evict::times_given_up() >= 1);
        // The next request takes the next; the one used last goes last.
        let still_more = arena.reserve_ram(LIMIT / 8).unwrap();
        assert!(!third.is_held() && second.is_held());
        assert_eq!(held(&arena), (LIMIT - MIB, LIMIT / 8));
        // A request that would not fit without any cache gives none up, and
        // is refused as ever.
        let refused = arena.reserve_ram(LIMIT / 4).err().unwrap().to_string();
        assert!(
            refused.contains("aggregate artifact arena RAM exhausted"),
            "{refused}"
        );
        assert!(second.is_held());
        drop((needed, more, still_more, second));
        assert_eq!(held(&arena), (0, 0));
    }

    #[test]
    fn a_run_that_fits_the_machine_goes_beyond_its_budget_while_windows_has_the_memory() {
        const MIB: u64 = 1024 * 1024;
        let (_directory, arena) = ledger();
        let site = ("test", 1);
        let held_already = arena.reserve_ram(LIMIT - MIB).unwrap();
        // The ledger is full: a process that keeps to its budget (this one
        // never asked to fit the machine) is refused, as ever.
        assert!(arena.reserve_ram(8 * MIB).is_err());
        assert!(!arena.go_beyond_budget(8 * MIB));
        // Windows has too little left to commit: refused, nothing allowed.
        assert!(!arena.go_beyond_budget_with(8 * MIB, 500 * MIB));
        assert!(arena.reserve_ram_at(8 * MIB, site, true).is_err());
        // It has enough: the allowance grows by whole steps, and what was
        // refused is granted.
        assert!(arena.go_beyond_budget_with(8 * MIB, 4096 * MIB));
        let beyond = arena.reserve_ram_at(8 * MIB, site, true).unwrap();
        assert_eq!(held(&arena), (LIMIT + 7 * MIB, 0));
        assert_eq!(arena.0.state.lock().unwrap().beyond_budget_bytes, 16 * MIB);
        // What fits the allowance asks for nothing more; what does not is
        // refused again until Windows is asked again.
        let within = arena.reserve_ram_at(8 * MIB, site, true).unwrap();
        assert!(arena.reserve_ram_at(8 * MIB, site, true).is_err());
        // A cache gets none of it: it is held only while the budget has room.
        assert!(arena.reserve_cache_ram(MIB).is_err());
        drop((held_already, beyond, within));
        assert_eq!(held(&arena), (0, 0));
    }

    #[test]
    fn caches_are_given_up_for_what_the_allowance_beyond_the_budget_has_room_for() {
        const MIB: u64 = 1024 * 1024;
        let (_directory, arena) = ledger();
        let cache = Evictable::new(arena.reserve_cache_ram(LIMIT / 8).unwrap());
        let needed = arena.reserve_ram(LIMIT - LIMIT / 8 - MIB).unwrap();
        // The budget came short and Windows allowed 16 MiB beyond it.
        assert!(arena.go_beyond_budget_with(8 * MIB, 4096 * MIB));
        assert_eq!(arena.0.state.lock().unwrap().beyond_budget_bytes, 16 * MIB);
        // 20 MiB fit beside what is needed within the allowance, but not
        // beside the cache too: the cache goes. (Judged against the bare
        // budget, it stayed and the request was refused.)
        let more = arena.reserve_ram(20 * MIB).unwrap();
        assert!(!cache.is_held());
        assert_eq!(held(&arena), (LIMIT - LIMIT / 8 - MIB + 20 * MIB, 0));
        drop((more, needed));
        assert_eq!(held(&arena), (0, 0));
    }

    #[test]
    fn what_is_held_to_go_faster_follows_what_the_machine_has() {
        const GIB: u64 = 1 << 30;
        // A machine of 4 GiB keeps 1 GiB free, one of 64 GiB a tenth.
        assert_eq!(kept_free(4 * GIB), GIB);
        assert_eq!(kept_free(64 * GIB), 64 * GIB / 10);
        // Holding 2 GiB with 10 GiB available on the large machine: caches
        // may grow until 6.4 GiB are left.
        assert_eq!(
            fitted_ceiling(2 * GIB, 10 * GIB, kept_free(64 * GIB)),
            2 * GIB + 10 * GIB - 64 * GIB / 10
        );
        // With less available than is kept free nothing more is granted:
        // the ceiling is what is held, and caches are given back.
        assert_eq!(
            fitted_ceiling(2 * GIB, 3 * GIB, kept_free(64 * GIB)),
            2 * GIB
        );
        // A ledger that never looked at the machine (this process does not
        // fit itself to it) keeps to its budget.
        let (_directory, arena) = ledger();
        arena.follow_the_machine();
        assert_eq!(arena.speed_budget(), LIMIT);
        assert!(arena.cache_ceiling() <= LIMIT - LIMIT / 8);
    }

    /// Rows a walk holds in memory and can write to working storage when
    /// asked: what [`n2r_win32::evict::register_last_resort`] is for.
    struct Rows(std::cell::RefCell<Option<ArenaRamLease>>);
    impl n2r_win32::evict::Evict for Rows {
        fn evict(&self) -> bool {
            self.0.borrow_mut().take().is_some()
        }
        fn last_used(&self) -> u64 {
            0
        }
    }

    #[test]
    fn a_request_that_needs_both_the_caches_and_the_rows_gets_both() {
        const MIB: u64 = 1024 * 1024;
        let (_directory, arena) = ledger();
        let cache = Evictable::new(arena.reserve_cache_ram(LIMIT / 8).unwrap());
        let rows = std::rc::Rc::new(Rows(std::cell::RefCell::new(Some(
            arena.reserve_ram(LIMIT / 4).unwrap(),
        ))));
        n2r_win32::evict::register_last_resort(&rows);
        let needed = arena.reserve_ram(LIMIT / 2 - MIB).unwrap();
        assert_eq!(held(&arena), (LIMIT * 7 / 8 - MIB, LIMIT / 8));
        // Half the ledger: the cache alone does not make room for it, the
        // rows alone do not either; with both gone it fits. The rows go
        // first, and then the cache, which used to stay.
        let half = arena.reserve_ram(LIMIT / 2).unwrap();
        assert!(rows.0.borrow().is_none());
        assert!(!cache.is_held());
        assert_eq!(held(&arena), (LIMIT - MIB, 0));
        drop((half, needed));
        assert_eq!(held(&arena), (0, 0));
    }

    #[test]
    fn a_ledger_that_runs_out_beside_a_cache_says_so() {
        let (_directory, arena) = ledger();
        let cache = Evictable::new(arena.reserve_cache_ram(LIMIT / 8).unwrap());
        let _needed = arena.reserve_ram(LIMIT / 2).unwrap();
        // The cache is in use: it stays, and the refusal names it as a
        // cache among the largest holders.
        let _in_use = cache.get().unwrap();
        let refused = arena.reserve_ram(LIMIT / 2).err().unwrap().to_string();
        assert!(
            refused.contains("(of which optional caches 8388608)")
                && refused.contains("the largest reservations: 32 MiB at artifact_arena.rs:")
                && refused.contains("8 MiB at artifact_arena.rs:")
                && refused.ends_with(" (a cache)"),
            "{refused}"
        );
    }

    #[test]
    fn a_cache_in_use_stays_and_the_request_is_refused() {
        let (_directory, arena) = ledger();
        let cache = Evictable::new(arena.reserve_optional_ram(LIMIT / 4).unwrap());
        let _needed = arena.reserve_ram(LIMIT / 2).unwrap();
        {
            let _in_use = cache.get().unwrap();
            assert!(arena.reserve_ram(LIMIT * 3 / 8).is_err());
        }
        assert!(cache.is_held());
        assert_eq!(held(&arena), (LIMIT * 3 / 4, LIMIT / 4));
        // Once it is no longer in use it goes for the same request.
        let _more = arena.reserve_ram(LIMIT * 3 / 8).unwrap();
        assert!(!cache.is_held());
    }

    #[test]
    fn no_cache_is_given_up_for_what_a_run_can_do_without() {
        let (_directory, arena) = ledger();
        let cache = Evictable::new(arena.reserve_optional_ram(LIMIT / 4).unwrap());
        let _needed = arena.reserve_ram(LIMIT / 2).unwrap();
        // A cache under the caches' quota, the workspace of one more object
        // of a batch, and memory the caller does without: each is refused,
        // and the cache that is there stays.
        assert!(arena.reserve_optional_ram(LIMIT / 8).is_err());
        assert!(arena.reserve_spare_ram(LIMIT * 3 / 8).is_err());
        assert!(arena.reserve_ram_if_room(LIMIT * 3 / 8).is_err());
        assert!(cache.is_held());
        // A request on another thread gives up nothing here: the caches are
        // this thread's.
        let other = arena.clone();
        std::thread::spawn(move || assert!(other.reserve_ram(LIMIT * 3 / 8).is_err()))
            .join()
            .unwrap();
        assert!(cache.is_held());
    }

    #[test]
    fn a_cache_that_is_asked_for_takes_the_place_of_the_one_used_longest_ago() {
        let (_directory, arena) = ledger();
        let old = Evictable::new(arena.reserve_optional_ram(LIMIT / 4).unwrap());
        let _needed = arena.reserve_ram(LIMIT / 2).unwrap();
        // It is granted while an eighth of the ledger stays free, above the
        // half at which the quota's caches are refused, and is counted with
        // the caches but not against their quota of a third.
        let pages = Evictable::new(arena.reserve_cache_ram(LIMIT / 16).unwrap());
        assert_eq!(held(&arena), (LIMIT * 13 / 16, LIMIT * 5 / 16));
        assert_eq!(arena.0.state.lock().unwrap().cache_ram_bytes, LIMIT / 16);
        assert!(old.is_held());
        // The next one would reach into the last eighth: the cache used
        // longest ago makes room for it.
        let hot = Evictable::new(arena.reserve_cache_ram(LIMIT / 8).unwrap());
        assert!(!old.is_held() && pages.is_held() && hot.is_held());
        assert_eq!(held(&arena), (LIMIT * 11 / 16, LIMIT * 3 / 16));
        // One that would not fit under the eighth with every cache gone is
        // refused, and none is given up for it.
        assert!(arena.reserve_cache_ram(LIMIT / 2).is_err());
        assert!(pages.is_held() && hot.is_held());
        // A cache in use is not taken for another.
        {
            let (_a, _b) = (pages.get().unwrap(), hot.get().unwrap());
            assert!(arena.reserve_cache_ram(LIMIT / 4 - 1024 * 1024).is_err());
        }
        let larger = arena.reserve_cache_ram(LIMIT / 4 - 1024 * 1024).unwrap();
        assert!(!pages.is_held() && hot.is_held());
        drop((larger, hot));
        assert_eq!(arena.0.state.lock().unwrap().cache_ram_bytes, 0);
    }

    #[test]
    fn a_reader_that_holds_its_file_by_itself_pays_the_threads_ledger() {
        assert!(matches!(pay_for_cache(4096), CachePayment::NoLedger));
        let (_directory, arena) = ledger();
        let CachePayment::Paid(paid) = pay_for_cache(LIMIT / 8) else {
            panic!("a ledger with room pays for a cache");
        };
        assert_eq!(held(&arena), (LIMIT / 8, LIMIT / 8));
        // It is paid while the ledger has room, also above half, and not
        // beyond its limit.
        let _needed = arena.reserve_ram(LIMIT / 2).unwrap();
        let CachePayment::Paid(second) = pay_for_cache(LIMIT / 8) else {
            panic!("a ledger with room pays for a cache");
        };
        assert!(matches!(pay_for_cache(LIMIT / 4), CachePayment::Refused));
        drop((paid, second));
        assert_eq!(held(&arena), (LIMIT / 2, 0));
        // A ledger that is gone pays for nothing more.
        drop(_needed);
        drop(arena);
        assert!(matches!(pay_for_cache(4096), CachePayment::NoLedger));
    }

    #[test]
    fn beyond_budget_accounts_for_fitted_ceiling_and_allows_registry_entries() {
        let (_directory, arena) = ledger();
        // Simulate a run whose fitted ceiling grew to 2x the starting budget.
        arena
            .0
            .fitted_ceiling
            .store(LIMIT * 2, std::sync::atomic::Ordering::Relaxed);
        let _held = arena.reserve_ram(LIMIT * 2 - (4 << 20)).unwrap();
        // Asking for 16 MiB more only needs 16 MiB beyond the fitted ceiling,
        // not LIMIT + 16 MiB. 600 MiB committable (> 16 MiB + 512 MiB kept free)
        // must suffice and raise needed_ceiling so the reservation succeeds.
        assert!(arena.go_beyond_budget_with(16 << 20, 600 << 20));
        let _more = arena.reserve_ram(16 << 20).unwrap();
        // Registry entries must also be judged against needed_ceiling, not bare budget.
        let permit = arena.reserve_group(ArtifactGroup::Source, 4096).unwrap();
        let path = _directory.path().join("beyond-budget-entry.bin");
        let _entry = permit.reserve_file(&path, 4096).unwrap();
    }

    #[test]
    fn reserve_ram_if_room_does_not_inflate_spare_headroom() {
        let (_directory, arena) = ledger();
        assert!(arena.reserve_ram_if_room(LIMIT * 2).is_err());
        let state = arena.0.state.lock().unwrap();
        assert_eq!(state.spare.largest_beside, 0);
        assert_eq!(state.spare.largest_since, 0);
    }

    /// Room beside the caches counts what the caches hold, reserves
    /// nothing and gives up no cache.
    #[test]
    fn room_beside_the_caches_counts_them_and_takes_nothing() {
        let (_directory, arena) = ledger();
        let free = |arena: &ArtifactArena| {
            let state = arena.0.state.lock().unwrap();
            LIMIT - state.leased_ram_bytes - state.index_bytes
        };
        let empty = free(&arena);
        assert!(arena.has_room_beside_caches(empty));
        assert!(!arena.has_room_beside_caches(empty + 1));
        let cache = Evictable::new(arena.reserve_optional_ram(LIMIT / 4).unwrap());
        let needed = arena.reserve_ram(LIMIT / 4).unwrap();
        let before = held(&arena);
        let room = empty - LIMIT / 2;
        assert!(arena.has_room_beside_caches(room));
        assert!(!arena.has_room_beside_caches(room + 1), "the cache counts");
        assert_eq!(held(&arena), before, "nothing is reserved");
        assert!(cache.is_held(), "and no cache is given up");
        drop((cache, needed));
        assert!(arena.has_room_beside_caches(empty));
    }

    /// A spare reservation is judged beside what is held, caches included,
    /// and beside the headroom its largest neighbour asks for.
    #[test]
    fn a_spare_beside_a_pass_is_judged_as_it_will_be_granted() {
        let (_directory, arena) = ledger();
        let held = {
            let state = arena.0.state.lock().unwrap();
            state.leased_ram_bytes + state.index_bytes
        };
        let headroom = LIMIT / 16;
        let spare = LIMIT - held - headroom;
        assert!(arena.spare_would_fit_beside(0, 0, spare));
        assert!(!arena.spare_would_fit_beside(0, 0, spare + 1));
        // A cache held still counts against the total budget (spare memory
        // gives no cache up), while headroom for needed reservations is
        // measured against non-cache memory because `reserve_ram` evicts caches.
        let cache = Evictable::new(arena.reserve_optional_ram(LIMIT / 8).unwrap());
        let with_cache = LIMIT - held - LIMIT / 8;
        assert!(!arena.spare_would_fit_beside(0, 0, with_cache + 1));
        assert!(arena.spare_would_fit_beside(0, 0, with_cache));
        // So do the pass's own reservations, and twice its largest.
        assert!(!arena.spare_would_fit_beside(1, 0, with_cache));
        let beside_largest = LIMIT - held - LIMIT / 2;
        assert!(arena.spare_would_fit_beside(0, LIMIT / 4, beside_largest));
        assert!(!arena.spare_would_fit_beside(0, LIMIT / 4, beside_largest + 1));
        assert!(cache.is_held());
    }
}
