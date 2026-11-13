//! Read-only native acquisition for explicitly scoped bitmap windows.
//! The caller retains device identity, geometry and exclusion responsibility.
//! These observations cannot authorize allocation, movement or raw writes.
use crate::{bitmap_paging, bitmap_window, stream_layout, stream_native};
use std::{fs::File, io};

pub fn capture(
    volume: &File,
    request: bitmap_window::Request,
    template: &[u8],
    limits: bitmap_window::Limits,
) -> io::Result<bitmap_window::Observation> {
    let mut collector = bitmap_window::Collector::new(request, template, limits)?;
    loop {
        let capacity = collector.page_capacity();
        if capacity < 17 || capacity > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native bitmap window exhausted its bounded response budget",
            ));
        }
        let input = bitmap_paging::page_input(template, collector.request_lcn())?;
        let query = stream_native::ioctl(volume, stream_layout::GET_BITMAP, &input, capacity);
        if let Some(error) = query.native_error.filter(|error| *error != 234) {
            return Err(io::Error::from_raw_os_error(error));
        }
        match collector.push(query)? {
            bitmap_window::PushOutcome::Complete => return collector.finish(),
            bitmap_window::PushOutcome::NeedMore
            | bitmap_window::PushOutcome::NeedLargerBuffer { .. } => (),
        }
    }
}

/// Check that the held read-only volume handle still reaches the caller's
/// independently discovered partition. No serialized success flag is accepted.
pub fn verify_route(
    volume: &File,
    binding: &crate::general_layout::GeneralDiskBinding,
) -> io::Result<()> {
    binding.validate()?;
    let response = stream_native::ioctl(volume, 0x0056_0000, &[], 32);
    if let Some(error) = response.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    binding.validate_volume_extent(&response.bytes)
}

/// Reuse the converter's existing native ReFS 3.14 geometry check, which
/// requires the chosen allocation unit.
/// Its return value is the observed cluster domain, not an ownership proof.
pub fn refs_314_clusters(
    volume: &File,
    binding: &crate::general_layout::GeneralDiskBinding,
) -> io::Result<u64> {
    verify_route(volume, binding)?;
    crate::shadow_native::query_refs_314_volume_data(volume, binding.identity.partition_bytes)
}
