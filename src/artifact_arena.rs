//! Actual ordinary metadata artifacts in one scratch arena. These owning
//! capabilities are deliberately not serializable and grant no device rights.
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralDiskBinding,
    reference_file::{self, ReferenceFileSnapshot},
    tree_resources::ResourceBudget,
};
use std::{
    collections::BTreeMap,
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
}
impl ArtifactGroup {
    fn limit(self, budget: ResourceBudget) -> u64 {
        match self {
            Self::Source | Self::Native | Self::Expected | Self::Map | Self::Auxiliary => {
                budget.scratch_bytes / 8
            }
            Self::LegacyExpectation => budget.scratch_bytes / 16,
            Self::RecoveryCopy => budget.scratch_bytes / 16 * 5,
            // Selected literal/index/route backing uses the actual remaining
            // shared total, never a disguised enlargement of source pages.
            Self::Capture => budget.scratch_bytes,
        }
    }
}
struct Group {
    maximum: u64,
    held: u64,
    files: u64,
    sealed: bool,
    poisoned: bool,
}
struct Entry {
    group: ArtifactGroup,
    reserved: u64,
    maximum: u64,
    registry_bytes: u64,
    verified: Option<Verified>,
    lease: Weak<FilePin>,
}
struct Verified {
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    sha256: String,
}
struct State {
    groups: BTreeMap<ArtifactGroup, Group>,
    entries: BTreeMap<PathBuf, Entry>,
    overhead: u64,
    index_bytes: u64,
    leased_ram_bytes: u64,
    ram_poisoned: bool,
}
struct Inner {
    root: PathBuf,
    root_guid: String,
    allocation_slack: u64,
    _parents: Vec<File>,
    budget: ResourceBudget,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct ArtifactArena(Arc<Inner>);
/// A live share of the arena's aggregate working-memory budget.
pub struct ArenaRamLease {
    arena: ArtifactArena,
    bytes: u64,
}
impl ArenaRamLease {
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
}
struct FilePin {
    file: Mutex<Option<File>>,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    sha256: String,
    _parents: Vec<File>,
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
    pins: Vec<Arc<FilePin>>,
    wire_bytes: u64,
    allocated_bytes: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct ArenaUsage {
    pub promised_bytes: u64,
    pub actual_wire_bytes: u64,
    pub actual_allocated_bytes: u64,
    pub files: u64,
    pub leased_ram_bytes: u64,
    pub registry_ram_bytes: u64,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("artifact arena accounting overflow")
}
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
fn inspect(file: &mut File, maximum: u64, expected: &str) -> Result<Verified> {
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
    let position = file.stream_position()?;
    let hash = n2r_win32::sha256_native::hash_range(file, 0, snapshot.file_bytes);
    file.seek(SeekFrom::Start(position))?;
    let sha = hex::encode(hash?);
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
    })
}
impl ArtifactArena {
    pub fn new(
        root: &Path,
        budget: ResourceBudget,
        excluded: &[GeneralDiskBinding],
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
        available.validate_budget(budget)?;
        Ok(Self(Arc::new(Inner {
            root: fs::canonicalize(root)?,
            root_guid,
            allocation_slack,
            _parents: handles,
            budget,
            state: Mutex::new(State {
                groups: BTreeMap::new(),
                entries: BTreeMap::new(),
                overhead: 0,
                index_bytes: 0,
                leased_ram_bytes: 0,
                ram_poisoned: false,
            }),
        })))
    }
    pub fn budget(&self) -> ResourceBudget {
        self.0.budget
    }
    pub fn same_arena(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn reserve_ram(&self, bytes: u64) -> Result<ArenaRamLease> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let leased = add(state.leased_ram_bytes, bytes)?;
        ensure!(
            !state.ram_poisoned && add(leased, state.index_bytes)? <= self.0.budget.ram_bytes,
            "aggregate artifact arena RAM exhausted or poisoned"
        );
        state.leased_ram_bytes = leased;
        Ok(ArenaRamLease {
            arena: self.clone(),
            bytes,
        })
    }
    pub fn reserve_group(&self, group: ArtifactGroup, maximum: u64) -> Result<ArtifactGroupPermit> {
        ensure!(
            maximum <= group.limit(self.0.budget),
            "artifact group exceeds its resource share"
        );
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        ensure!(
            !state.groups.contains_key(&group),
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
            },
        );
        Ok(ArtifactGroupPermit {
            arena: self.clone(),
            group,
        })
    }
    fn check_free(&self, state: &State, additional: u64) -> Result<()> {
        let held = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        let actual = state
            .entries
            .values()
            .filter_map(|e| e.verified.as_ref())
            .try_fold(0, |n, v| add(n, v.snapshot.allocation_bytes))?;
        let pending = add(held, additional)?
            .checked_sub(actual)
            .context("artifact physical accounting underflow")?;
        ensure!(
            n2r_win32::resource_native::observe_available_resources(&self.0.root)?
                .scratch_available_bytes
                >= pending,
            "actual scratch free space cannot cover live reservations"
        );
        Ok(())
    }
    pub fn usage(&self) -> Result<ArenaUsage> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact arena lock poisoned"))?;
        let promised = state
            .groups
            .values()
            .try_fold(state.overhead, |n, g| add(n, g.maximum))?;
        let (wire, allocated) = state
            .entries
            .values()
            .filter_map(|e| e.verified.as_ref())
            .try_fold((0, 0), |(w, a), v| {
                Ok::<_, anyhow::Error>((
                    add(w, v.snapshot.file_bytes)?,
                    add(a, v.snapshot.allocation_bytes)?,
                ))
            })?;
        Ok(ArenaUsage {
            promised_bytes: promised,
            actual_wire_bytes: wire,
            actual_allocated_bytes: allocated,
            files: state.entries.len() as u64,
            leased_ram_bytes: state.leased_ram_bytes,
            registry_ram_bytes: state.index_bytes,
        })
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
    pub fn reserve_file(&self, path: &Path, maximum: u64) -> Result<ArtifactPathPermit> {
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
        ensure!(
            canonical_parent == self.arena.0.root
                || canonical_parent.starts_with(&self.arena.0.root),
            "artifact path escapes arena"
        );
        let guid = n2r_win32::file_storage::final_path_guid(
            handles.first().context("artifact parent handle absent")?,
        )?;
        ensure!(
            guid.eq_ignore_ascii_case(&self.arena.0.root_guid)
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
        ensure!(!path.exists(), "artifact destination already exists");
        let memory = add(
            768,
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
            !state.entries.contains_key(&path),
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
            add(all, self.arena.0.allocation_slack)? <= self.arena.0.budget.scratch_bytes,
            "artifact allocation slack exceeds aggregate budget"
        );
        ensure!(
            !state.ram_poisoned
                && add(state.index_bytes, memory)? <= self.arena.0.budget.retained_index_bytes
                && add(add(state.index_bytes, memory)?, state.leased_ram_bytes)?
                    <= self.arena.0.budget.ram_bytes,
            "artifact registry RAM exhausted"
        );
        self.arena
            .check_free(&state, self.arena.0.allocation_slack)?;
        state.overhead = add(state.overhead, self.arena.0.allocation_slack)?;
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
            },
        );
        Ok(ArtifactPathPermit {
            group: self.clone(),
            path,
            _parents: handles,
            complete: false,
        })
    }
    pub fn seal(&self) -> Result<ArtifactGroupSeal> {
        let mut state = self
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let mut wire = 0;
        let mut allocated = 0;
        let mut pins = Vec::new();
        for entry in state.entries.values().filter(|e| e.group == self.group) {
            let verified = entry
                .verified
                .as_ref()
                .context("artifact group still has an active/unverified creation")?;
            let pin = entry
                .lease
                .upgrade()
                .context("sealed artifact requires its actual retained immutable file owner")?;
            pin.revalidate()?;
            wire = add(wire, verified.snapshot.file_bytes)?;
            allocated = add(allocated, verified.snapshot.allocation_bytes)?;
            pins.push(pin);
        }
        let group = state
            .groups
            .get_mut(&self.group)
            .context("artifact group missing")?;
        ensure!(!group.poisoned, "artifact group is poisoned");
        group.maximum = wire;
        group.held = wire;
        group.sealed = true;
        Ok(ArtifactGroupSeal {
            permit: self.clone(),
            pins,
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
        let hash = hex::encode(n2r_win32::sha256_native::hash_range(
            &mut file,
            0,
            before.file_bytes,
        )?);
        drop(file);
        self.verify_closed(&hash)
    }
    pub fn extend(&mut self, bytes: u64) -> Result<()> {
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
            !group.sealed && !group.poisoned && add(group.held, bytes)? <= group.maximum,
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
    pub fn verify_closed(self, expected_sha256: &str) -> Result<ArtifactLease> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&self.path)?;
        self.verify_file(file, expected_sha256)
    }
    pub fn verify_closed_handle(self, file: &File, expected_sha256: &str) -> Result<ArtifactLease> {
        n2r_win32::file_storage::require_readonly_access(file)?;
        let file = n2r_win32::file_storage::duplicate_readonly(file)?;
        self.verify_file(file, expected_sha256)
    }
    fn verify_file(mut self, mut file: File, expected_sha256: &str) -> Result<ArtifactLease> {
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
        let verified = inspect(&mut file, maximum, expected_sha256)?;
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
                    verified.snapshot.file_bytes,
                    self.group.arena.0.allocation_slack
                )?,
            "artifact physical allocation exceeds reserved slack"
        );
        let pin = Arc::new(FilePin {
            file: Mutex::new(Some(file)),
            snapshot: verified.snapshot.clone(),
            modified: verified.modified,
            sha256: verified.sha256.clone(),
            _parents: std::mem::take(&mut self._parents),
        });
        let mut state = self
            .group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let old = state
            .entries
            .get(&self.path)
            .context("artifact entry absent")?
            .reserved;
        let extra = verified
            .snapshot
            .allocation_bytes
            .saturating_sub(verified.snapshot.file_bytes);
        state.overhead = state
            .overhead
            .checked_sub(self.group.arena.0.allocation_slack - extra)
            .context("artifact slack underflow")?;
        let group = state.groups.get_mut(&self.group.group).unwrap();
        ensure!(
            !group.sealed && !group.poisoned,
            "artifact group sealed while writing"
        );
        group.held = group
            .held
            .checked_sub(old - verified.snapshot.file_bytes)
            .context("artifact reservation underflow")?;
        group.files = add(group.files, 1)?;
        let entry = state.entries.get_mut(&self.path).unwrap();
        entry.reserved = verified.snapshot.file_bytes;
        entry.verified = Some(verified);
        entry.lease = Arc::downgrade(&pin);
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
    fn revalidate(&self) -> Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact file lock poisoned"))?;
        let current = inspect(
            file.as_mut().context("artifact owner closed")?,
            self.snapshot.file_bytes,
            &self.sha256,
        )?;
        ensure!(
            current.snapshot == self.snapshot && current.modified == self.modified,
            "artifact held identity changed"
        );
        Ok(())
    }
}
impl ArtifactLease {
    pub(crate) fn same_group(&self, permit: &ArtifactGroupPermit) -> bool {
        self.group.group == permit.group && self.group.arena.same_arena(&permit.arena)
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
    pub fn retire(self) -> Result<()> {
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
        let verified = inspect(&mut file, pin.snapshot.file_bytes, &pin.sha256)?;
        ensure!(
            verified.snapshot == pin.snapshot && verified.modified == pin.modified,
            "artifact changed before retirement"
        );
        n2r_win32::file_storage::mark_delete_on_close(&file)?;
        drop(file);
        ensure!(
            matches!(fs::symlink_metadata(&path),Err(ref e) if e.kind()==std::io::ErrorKind::NotFound),
            "artifact retirement not observed complete"
        );
        let mut state = group
            .arena
            .0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("arena lock poisoned"))?;
        let entry = state
            .entries
            .remove(&path)
            .context("retired artifact missing from ledger")?;
        state.index_bytes = state
            .index_bytes
            .checked_sub(entry.registry_bytes)
            .context("artifact registry RAM credit underflow")?;
        let bytes = entry
            .verified
            .context("retired artifact unverified")?
            .snapshot;
        state.overhead = state
            .overhead
            .checked_sub(bytes.allocation_bytes.saturating_sub(bytes.file_bytes))
            .context("artifact allocation credit underflow")?;
        let group = state.groups.get_mut(&group.group).unwrap();
        group.held = group
            .held
            .checked_sub(bytes.file_bytes)
            .context("artifact wire credit underflow")?;
        if group.sealed {
            group.maximum = group.held;
        }
        group.files -= 1;
        Ok(())
    }
}
impl ArtifactGroupSeal {
    /// A seal owns every file it covers until all seal clones are dropped.
    pub fn revalidate(&self) -> Result<()> {
        for pin in &self.pins {
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
