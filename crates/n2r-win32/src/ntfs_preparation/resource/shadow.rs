//! Complete read-only ReFS occupancy hints. These are never allocation or
//! source-write authority; the owning target is observed again after freeze.
use super::*;
use crate::{bitmap_observation::Observation as Bitmap, preparation_shadow::ByteInterval};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ShadowBitmapView {
    Legacy,
    Metadata,
}

#[derive(Debug, Serialize)]
pub struct ShadowHintObservation {
    pub binding: GeneralDiskBinding,
    pub refs_volume_data: crate::attestation::IoctlQuery,
    pub legacy_bitmap: crate::bitmap_paging::Proof,
    pub metadata_bitmap: crate::bitmap_paging::Proof,
    pub legacy_ranges: u64,
    pub metadata_ranges: u64,
    pub bootstrap_avoidance: [ByteInterval; 2],
    pub before: native::GeneralDiskState,
    pub after: native::GeneralDiskState,
    pub final_allocation_complete: bool,
    pub reserves_target_space: bool,
    pub source_write_authority: bool,
}
#[derive(Serialize)]
#[serde(transparent)]
pub struct LeasedShadowHints {
    value: ShadowHintObservation,
    #[serde(skip)]
    _memory: Lease,
}
impl std::ops::Deref for LeasedShadowHints {
    type Target = ShadowHintObservation;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub fn observe_shadow_occupancy(
    binding: GeneralDiskBinding,
    budget: ResourceBudget,
    payer: &dyn ReportMemoryAccountant,
    mut emit: impl FnMut(ShadowBitmapView, u64, u64) -> io::Result<()>,
) -> io::Result<LeasedShadowHints> {
    budget.validate()?;
    binding.validate()?;
    let memory = payer.reserve(2 * 1024 * 1024 + payer.lease_heap_bytes())?;
    let root = format!("{}\\", binding.volume_path()?);
    let discovered = crate::discovery::discover(&root, crate::discovery::Role::Shadow)?;
    require(
        discovered.binding == binding
            && discovered.filesystem == "ReFS"
            && discovered.observed_twice_unchanged
            && discovered.read_only
            && discovered.source_write_requests == 0,
        "actual empty-shadow role/route differs",
    )?;
    let length = binding.identity.partition_bytes;
    require(
        length > 0 && length <= i64::MAX as u64 && length.is_multiple_of(4096),
        "shadow hint geometry exceeds native signed IO domain",
    )?;
    let before = native::observe_general_disk_state_readonly(binding.clone(), &mut Vec::new())?;
    require(
        before.disk_attributes == 0,
        "shadow hints require online writable target",
    )?;
    let _privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let volume = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(binding.volume_path()?)?;
    binding.validate_volume_extent(&control(&volume, GET_VOLUME_EXTENTS, &[], 32)?)?;
    let refs = stream_native::ioctl(&volume, 0x0009_02d8, &[], 256);
    if let Some(error) = refs.native_error {
        return Err(io::Error::from_raw_os_error(error));
    }
    let clusters = crate::bitmap_window_native::refs_314_clusters(&volume, &binding)?;
    require(
        clusters == length / 4096,
        "shadow complete bitmap domain differs",
    )?;
    let limits = crate::bitmap_streaming::resource_source_limits(clusters, budget.max_row_bytes)?;
    let mut proofs = Vec::with_capacity(2);
    let mut counts = [0u64; 2];
    for (index, view) in [ShadowBitmapView::Legacy, ShadowBitmapView::Metadata]
        .into_iter()
        .enumerate()
    {
        let _query = payer.reserve(
            memory::add(memory::mul(budget.max_row_bytes, 4)?, 16 * 1024 * 1024)?
                .checked_add(payer.lease_heap_bytes())
                .ok_or_else(|| invalid("shadow bitmap RAM overflow"))?,
        )?;
        let mut input = [0; 16];
        input[8] = 1;
        let template = if view == ShadowBitmapView::Legacy {
            &[0u8; 8][..]
        } else {
            &input[..]
        };
        let bitmap = Bitmap::capture_with_bounded_ranges(&volume, template, length, limits)?;
        let Bitmap::Streamed { summary, .. } = &bitmap else {
            return Err(invalid(
                "resource shadow bitmap must be complete streamed owner",
            ));
        };
        summary.validate(clusters, limits)?;
        require(
            summary.declared_clusters == clusters,
            "shadow bitmap declared domain differs",
        )?;
        for range in &summary.allocated_ranges {
            let offset = range
                .starting_lcn
                .checked_mul(4096)
                .ok_or_else(|| invalid("shadow hint offset overflow"))?;
            let bytes = range
                .clusters
                .checked_mul(4096)
                .ok_or_else(|| invalid("shadow hint length overflow"))?;
            require(
                bytes > 0 && offset.checked_add(bytes).is_some_and(|n| n <= length),
                "complete shadow hint leaves its bound partition",
            )?;
            emit(view, offset, bytes)?;
            counts[index] = counts[index]
                .checked_add(1)
                .ok_or_else(|| invalid("shadow range count overflow"))?;
        }
        proofs.push(bitmap.proof());
    }
    let again = stream_native::ioctl(&volume, 0x0009_02d8, &[], 256);
    require(
        again.native_error.is_none()
            && refs.bytes.len() >= 64
            && again.bytes.len() >= 64
            && again.bytes[..40] == refs.bytes[..40]
            && again.bytes[56..64] == refs.bytes[56..64],
        "shadow ReFS identity/geometry changed during hints",
    )?;
    binding.validate_volume_extent(&control(&volume, GET_VOLUME_EXTENTS, &[], 32)?)?;
    let after = native::observe_general_disk_state_readonly(binding.clone(), &mut Vec::new())?;
    require(
        before == after && after.disk_attributes == 0,
        "shadow physical identity/state changed during hints",
    )?;
    let final_discovery = crate::discovery::discover(&root, crate::discovery::Role::Shadow)?;
    require(
        final_discovery.binding == binding
            && final_discovery.evidence == discovered.evidence
            && final_discovery.filesystem == discovered.filesystem
            && final_discovery.volume_serial_low32 == discovered.volume_serial_low32
            && final_discovery.filesystem_flags == discovered.filesystem_flags,
        "shadow discovery route changed during hints",
    )?;
    let metadata = proofs.pop().expect("two actual bitmap proofs");
    let legacy = proofs.pop().expect("two actual bitmap proofs");
    let margin = length.min(1024 * 1024);
    Ok(LeasedShadowHints {
        value: ShadowHintObservation {
            binding,
            refs_volume_data: refs,
            legacy_bitmap: legacy,
            metadata_bitmap: metadata,
            legacy_ranges: counts[0],
            metadata_ranges: counts[1],
            bootstrap_avoidance: [
                ByteInterval {
                    offset: 0,
                    length: margin,
                },
                ByteInterval {
                    offset: length - margin,
                    length: margin,
                },
            ],
            before,
            after,
            final_allocation_complete: false,
            reserves_target_space: false,
            source_write_authority: false,
        },
        _memory: memory,
    })
}
