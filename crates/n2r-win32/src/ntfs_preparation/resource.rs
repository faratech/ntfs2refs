//! Resource-accounted NTFS-owned preparation. Every device, file and mapping
//! is freshly checked; saved plans never authorize a raw source write.
use super::*;
use crate::{
    shadow_native::report_memory::{ReportMemoryAccountant, ReportMemoryLease},
    tree_resources::ResourceBudget,
};
use std::sync::Arc;

mod memory;
mod shadow;
mod source;
pub use shadow::{
    LeasedShadowHints, ShadowBitmapView, ShadowHintObservation, observe_shadow_occupancy,
};
pub use source::{
    LeasedFileObservation, LeasedMoveObservation, LeasedPreparationCompletion, OpenedFile,
    OpenedSource, PreparationCompletion,
};

type Lease = Box<dyn ReportMemoryLease>;

/// Explicit operational IO budget, separate from dataset/file-count limits.
#[derive(Clone, Copy, Debug)]
pub struct MoveBudget {
    pub maximum_moves: u64,
    pub maximum_move_bytes: u64,
    pub maximum_total_move_bytes: u64,
}
impl MoveBudget {
    fn validate(self) -> io::Result<()> {
        require(
            self.maximum_moves > 0
                && self.maximum_move_bytes > 0
                && self.maximum_total_move_bytes > 0,
            "explicit resource NTFS move budget differs",
        )
    }
}

/// Maximum request envelope shared with the actual resource mover. The caller
/// must additionally apply its explicit move-byte/total-operation budgets and
/// the live file/volume bounds. Rounded native responses must still complete
/// within the original window limits before any move can be submitted.
pub fn maximum_clusters_per_move(budget: ResourceBudget, cluster_bytes: u32) -> io::Result<u32> {
    budget.validate()?;
    require(
        cluster_bytes.is_power_of_two(),
        "resource NTFS move cluster geometry differs",
    )?;
    let maximum = memory::window_cluster_capacity(budget)?
        .min(i64::MAX as u64 / u64::from(cluster_bytes))
        .min(u64::from(u32::MAX));
    let maximum = u32::try_from(maximum).map_err(io::Error::other)?;
    require(maximum > 0, "resource NTFS move has no cluster capacity")?;
    let window = memory::window_limits(maximum, budget)?;
    require(
        memory::move_bytes(budget, window)? <= budget.ram_bytes,
        "resource NTFS move workspace exceeds the admitted total RAM",
    )?;
    Ok(maximum)
}

fn bounded_error(context: &str, error: &io::Error) -> String {
    use std::fmt::Write as _;
    struct Limited(String);
    impl std::fmt::Write for Limited {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let remaining = 4096usize.saturating_sub(self.0.len());
            let mut end = text.len().min(remaining);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            Ok(())
        }
    }
    let mut value = Limited(String::with_capacity(4096));
    let _ = write!(&mut value, "{context}: {error}");
    value.0
}
