//! Portable SDK report accounting backed by the actual shared artifact arena.
use crate::artifact_arena::{ArenaRamLease, ArtifactArena};
use n2r_win32::shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease};
use std::io;

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
    fn lease_heap_bytes(&self) -> u64 {
        std::mem::size_of::<ArenaReportLease>() as u64
    }
}
