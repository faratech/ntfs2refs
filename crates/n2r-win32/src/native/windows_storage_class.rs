//! A narrowly scoped normalization of NTFS's default storage-placement hint.
//! This is not target construction or source-write authority. Storage Spaces,
//! removable media and unrecognized device buses cannot obtain this witness.
use super::*;

#[derive(Debug, Serialize)]
pub struct BootStorageHintNormalization {
    binding: GeneralDiskBinding,
    bus_type: u32,
    descriptor_sha256: String,
    observed_freeze_sha256: String,
    normalization: &'static str,
}
fn descriptor(
    source: &GeneralFrozenPartition,
    events: &mut Vec<NativeEvent>,
) -> io::Result<(u32, String)> {
    let bytes = control(
        &source.file,
        "boot-storage-device-descriptor",
        ALIGNMENT,
        &[0; 12],
        4096,
        events,
    )?;
    if bytes.len() < 36 {
        return Err(invalid("complete basic boot storage descriptor required"));
    }
    let size = layout::u32_at(&bytes, 4)? as usize;
    let version = layout::u32_at(&bytes, 0)?;
    let bus = layout::u32_at(&bytes, 28)?;
    // STORAGE_DEVICE_DESCRIPTOR uses an enum DWORD at +28 and a removable
    // byte at +10. Reject Spaces(16), Unknown(0), and future unknown buses.
    // This concerns the guest/owning machine's filesystem storage stack.
    if size < 36
        || size > bytes.len()
        || version < 36
        || bytes[10] != 0
        || !matches!(
            bus,
            1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 17 | 18 | 19
        )
    {
        return Err(invalid(
            "default storage-hint normalization requires a known fixed non-Storage-Spaces boot device",
        ));
    }
    Ok((bus, hex::encode(Sha256::digest(&bytes))))
}
fn freeze_pin(source: &GeneralFrozenPartition) -> io::Result<String> {
    let freeze = source
        .freeze_observation
        .as_ref()
        .ok_or_else(|| invalid("original observed Windows source freeze required"))?;
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(freeze).map_err(io::Error::other)?,
    )))
}
impl GeneralFrozenPartition {
    /// Issue only for the original frozen offline Windows source on fixed,
    /// non-Spaces storage. Only the exact ClassPerformance/flags0 $DSC value
    /// may use the enclosing application's explicit normalization policy.
    pub fn observe_boot_storage_hint_normalization(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<BootStorageHintNormalization> {
        if self.binding.layout_profile
            != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            || self.state(events)?.disk_attributes != 3
        {
            return Err(invalid(
                "excluded offline Windows source required for storage-hint normalization",
            ));
        }
        let observed_freeze_sha256 = freeze_pin(self)?;
        let (bus_type, descriptor_sha256) = descriptor(self, events)?;
        self.state(events)?;
        Ok(BootStorageHintNormalization {
            binding: self.binding.clone(),
            bus_type,
            descriptor_sha256,
            observed_freeze_sha256,
            normalization: "default-performance-placement-hint-on-fixed-non-Spaces-storage-v1",
        })
    }
}
impl BootStorageHintNormalization {
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }
    pub fn bus_type(&self) -> u32 {
        self.bus_type
    }
    pub fn revalidate(
        &self,
        source: &GeneralFrozenPartition,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        if source.binding != self.binding
            || freeze_pin(source)? != self.observed_freeze_sha256
            || source.state(events)?.disk_attributes != 3
        {
            return Err(invalid(
                "storage-hint source identity or original freeze changed",
            ));
        }
        let (bus, hash) = descriptor(source, events)?;
        if bus != self.bus_type || hash != self.descriptor_sha256 {
            return Err(invalid("storage-hint source device descriptor changed"));
        }
        source.state(events)?;
        Ok(())
    }
}
