//! Ordinary pre-publication failure cleanup using only the same live NTFS
//! owner and its original, never-consumed freeze witness.
use super::{EventLog, PreparationObserver};
use crate::general_source_admission::resource::ResourceSourceContext;
use anyhow::Result;
use n2r_win32::general_layout::GeneralDiskBinding;

pub(super) fn restore_live_source<O: PreparationObserver>(
    context: ResourceSourceContext,
    events: &mut EventLog<'_, O>,
) -> Result<GeneralDiskBinding> {
    events.phase("restore-unchanged-original-ntfs");
    events.checkpoint()?;
    let EventLog { observer, events: native_events, .. } = events;
    context.restore_original_unchanged(native_events, |batch| {
        observer.native_events("restore-unchanged-original-ntfs", batch)
    })
}
