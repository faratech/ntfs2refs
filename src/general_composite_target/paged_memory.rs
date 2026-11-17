//! Portable SDK report accounting backed by the actual shared artifact arena.
use crate::artifact_arena::{ArenaRamLease, ArtifactArena};
use crate::artifact_arena::{ArtifactGroupPermit, ArtifactLease, ArtifactPathPermit};
use n2r_win32::shadow_native::report_memory::{
    ReportMemoryAccountant, ReportMemoryLease, SpillFile, SpillSource,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) struct ArenaReportMemory(pub ArtifactArena);
struct ArenaReportLease(ArenaRamLease);
impl ReportMemoryLease for ArenaReportLease {
    fn shrink_to(&mut self, bytes: u64) -> io::Result<()> {
        self.0.shrink_to(bytes).map_err(io::Error::other)
    }
}
impl ReportMemoryAccountant for ArenaReportMemory {
    fn reserve(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        Ok(Box::new(ArenaReportLease(
            self.0.reserve_ram(bytes).map_err(io::Error::other)?,
        )))
    }
    fn reserve_optional(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        Ok(Box::new(ArenaReportLease(
            self.0
                .reserve_optional_ram(bytes)
                .map_err(io::Error::other)?,
        )))
    }
    fn reserve_spare(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        Ok(Box::new(ArenaReportLease(
            self.0.reserve_spare_ram(bytes).map_err(io::Error::other)?,
        )))
    }
    fn reserve_cache(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        Ok(Box::new(ArenaReportLease(
            self.0
                .reserve_cache_ram_while_under_half(bytes)
                .map_err(io::Error::other)?,
        )))
    }
    fn lease_heap_bytes(&self) -> u64 {
        std::mem::size_of::<ArenaReportLease>() as u64
    }
}

/// The arena as a payer that also has working storage to offer: what a walk
/// has no room for in memory it writes to files of `group`, in `directory`.
/// The files stay, closed and accounted, for as long as `files` is held:
/// whoever makes this keeps that list as long as the group's other files.
pub(crate) struct ArenaReportStorage {
    memory: ArenaReportMemory,
    group: ArtifactGroupPermit,
    directory: PathBuf,
    made: Arc<AtomicU32>,
    files: SpilledFiles,
}
/// The closed working files a payer's callers wrote.
pub(crate) type SpilledFiles = Arc<Mutex<Vec<ArtifactLease>>>;

impl ArenaReportStorage {
    /// `directory` exists, inside the arena; names in it that begin with
    /// `rows-` are this payer's.
    pub(crate) fn new(
        memory: ArenaReportMemory,
        group: ArtifactGroupPermit,
        directory: &Path,
        files: SpilledFiles,
    ) -> Self {
        Self {
            memory,
            group,
            directory: directory.to_owned(),
            made: Arc::new(AtomicU32::new(0)),
            files,
        }
    }
}
impl ReportMemoryAccountant for ArenaReportStorage {
    fn reserve(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.memory.reserve(bytes)
    }
    fn reserve_optional(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.memory.reserve_optional(bytes)
    }
    fn reserve_spare(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.memory.reserve_spare(bytes)
    }
    fn reserve_cache(&self, bytes: u64) -> io::Result<Box<dyn ReportMemoryLease>> {
        self.memory.reserve_cache(bytes)
    }
    fn spill_source(&self) -> Option<Box<dyn SpillSource>> {
        Some(Box::new(ArenaSpillSource {
            arena: self.memory.0.clone(),
            group: self.group.clone(),
            directory: self.directory.clone(),
            made: Arc::clone(&self.made),
            files: Arc::clone(&self.files),
        }))
    }
    fn lease_heap_bytes(&self) -> u64 {
        self.memory.lease_heap_bytes()
    }
}
struct ArenaSpillSource {
    arena: crate::artifact_arena::ArtifactArena,
    group: ArtifactGroupPermit,
    directory: PathBuf,
    made: Arc<AtomicU32>,
    files: SpilledFiles,
}
impl SpillSource for ArenaSpillSource {
    fn create(&self) -> io::Result<Box<dyn SpillFile>> {
        let ordinal = self.made.fetch_add(1, Ordering::SeqCst);
        let path = self.directory.join(format!("rows-{ordinal}.pages"));
        let budget = self
            .arena
            .native_page_budget()
            .map_err(io::Error::other)?
            .native()?;
        let permit = self
            .group
            .reserve_file(&path, FIRST_RESERVATION)
            .map_err(io::Error::other)?;
        Ok(Box::new(ArenaSpillFile {
            permit,
            reserved: FIRST_RESERVATION,
            written: 0,
            budget,
            files: Arc::clone(&self.files),
        }))
    }
}
/// What a spill file reserves of its group before anything is written, and
/// the least it reserves more at a time.
const FIRST_RESERVATION: u64 = 16 * 1024 * 1024;

struct ArenaSpillFile {
    permit: ArtifactPathPermit,
    reserved: u64,
    written: u64,
    budget: n2r_win32::metadata_pages::PageBudget,
    files: SpilledFiles,
}
impl SpillFile for ArenaSpillFile {
    fn path(&self) -> &Path {
        self.permit.path()
    }
    fn page_budget(&self) -> n2r_win32::metadata_pages::PageBudget {
        self.budget
    }
    fn extend(&mut self, bytes: u64) -> io::Result<()> {
        self.written = self
            .written
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("spill file size overflow"))?;
        if self.written > self.reserved {
            let more = (self.written - self.reserved).max(FIRST_RESERVATION);
            self.permit.extend(more).map_err(io::Error::other)?;
            self.reserved += more;
        }
        Ok(())
    }
    fn close(self: Box<Self>, sha256: &str) -> io::Result<()> {
        let lease = self
            .permit
            .verify_closed(sha256)
            .map_err(io::Error::other)?;
        self.files
            .lock()
            .map_err(|_| io::Error::other("spilled file list poisoned"))?
            .push(lease);
        Ok(())
    }
}
