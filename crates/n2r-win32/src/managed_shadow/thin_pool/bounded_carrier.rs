//! Fresh capacity-bounded NTFS carrier for large nominal member files only.
//! No caller-selected volume, mount letter, existing disk, quota or teardown.
use super::*;
use std::io::{Seek, SeekFrom};

const EXTERNAL_METADATA_RESERVE: u64 = 32 << 20;
const ALLOCATION_UNIT: u64 = 2 << 20;

#[derive(Clone, Debug, Serialize)]
pub struct CarrierObservation {
    pub kind: &'static str,
    pub backing_path: PathBuf,
    pub provider_virtual_disk_id: String,
    pub provider_virtual_bytes: u64,
    pub admitted_vhdx_overhead_bytes: u64,
    pub external_metadata_reserve_bytes: u64,
    pub binding: GeneralDiskBinding,
    pub member_directory: PathBuf,
    pub backing_file: reference_file::ReferenceFileSnapshot,
    pub filesystem_available: resource_native::AvailableResources,
    pub ntfs_volume_data: Vec<u8>,
    pub boot_metadata: Vec<u8>,
    pub nested_members_not_double_counted_as_host_allocation: bool,
    pub sampled_free_space_is_not_a_reservation: bool,
    pub formatted_carrier_is_not_the_conversion_target: bool,
}

pub(super) struct BoundedCarrier {
    member: Member,
    disk: File,
    binding: GeneralDiskBinding,
    volume: File,
    member_root: PathBuf,
    member_root_text: String,
    root: File,
    root_file_id: String,
    root_guid_path: String,
    ntfs_serial: u64,
}

pub(super) fn dimensions(budget: Budget) -> io::Result<(u64, u64)> {
    let disk = budget
        .scratch_bytes
        .checked_sub(EXTERNAL_METADATA_RESERVE)
        .and_then(|n| n.checked_sub(MEMBER_OVERHEAD))
        .map(|n| n / ALLOCATION_UNIT * ALLOCATION_UNIT)
        .ok_or_else(|| {
            invalid("scratch cannot cover the carrier and external metadata/header allowance")
        })?;
    let partition = disk
        .checked_sub(MARGIN)
        .ok_or_else(|| invalid("scratch cannot cover the fresh carrier GPT margin"))?;
    if disk > 64u64 << 40
        || partition
            <= budget
                .minimum_free_bytes
                .checked_add(64 << 20)
                .ok_or_else(|| invalid("carrier free reserve overflow"))?
    {
        return Err(invalid(
            "bounded carrier cannot represent the admitted scratch/reserve profile",
        ));
    }
    Ok((disk, partition))
}

fn ntfs_geometry(
    volume: &mut File,
    binding: &GeneralDiskBinding,
    serial: Option<u64>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let data = control(volume, 0x0009_0064, &[], 128)?;
    if data.len() < 96 {
        return Err(invalid("short native carrier NTFS geometry"));
    }
    let actual_serial = layout::u64_at(&data, 0)?;
    let sectors = layout::u64_at(&data, 8)?;
    let clusters = layout::u64_at(&data, 16)?;
    if actual_serial == 0
        || serial.is_some_and(|s| s != actual_serial)
        || layout::u32_at(&data, 40)? != binding.identity.logical_sector_bytes
        || layout::u32_at(&data, 44)? != 4096
        || clusters == 0
        || clusters
            .checked_mul(4096)
            .is_none_or(|n| n > binding.identity.partition_bytes)
        || sectors
            .checked_mul(u64::from(binding.identity.logical_sector_bytes))
            .is_none_or(|n| {
                n > binding.identity.partition_bytes || binding.identity.partition_bytes - n > 4096
            })
    {
        return Err(invalid(
            "actual NTFS carrier serial or cluster/volume geometry differs",
        ));
    }
    let mut boot = vec![0u8; 512];
    volume.seek(SeekFrom::Start(0))?;
    volume.read_exact(&mut boot)?;
    if boot.get(3..11) != Some(b"NTFS    ".as_slice())
        || boot[510..512] != [0x55, 0xaa]
        || u32::from(u16::from_le_bytes(boot[11..13].try_into().unwrap()))
            != binding.identity.logical_sector_bytes
        || u64::from(boot[13]) * u64::from(binding.identity.logical_sector_bytes) != 4096
        || layout::u64_at(&boot, 0x48)? != actual_serial
        || layout::u64_at(&boot, 0x28)? != sectors
    {
        return Err(invalid(
            "NTFS carrier boot metadata differs from actual native geometry",
        ));
    }
    Ok((data, boot))
}

impl BoundedCarrier {
    pub(super) fn create(directory: &Path, budget: Budget) -> io::Result<Self> {
        let (virtual_bytes, partition_bytes) = dimensions(budget)?;
        capacity(directory, budget)?;
        let path = directory.join("carrier.vhdx");
        let member = create_member(&path, virtual_bytes)?;
        let disk = native::device_file(
            &format!("\\\\.\\PhysicalDrive{}", member.attachment.number),
            true,
            false,
        )?;
        let binding = initialize_new_owned(&member.attachment, &disk, partition_bytes)?;
        let binding = rediscover_stage(binding, &path, "carrier-partition-volume")?;
        capacity(directory, budget)?;
        member.revalidate()?;
        // NTFS is used ONLY on this newly created carrier. The existing ReFS
        // formatter keeps its exact version, integrity and policy validation.
        let mut system = [0u16; 32768];
        // SAFETY: initialized system directory output and WCHAR count.
        let count =
            unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count >= system.len() {
            return Err(invalid("carrier formatter path exceeds bound"));
        }
        let formatter = PathBuf::from(
            String::from_utf16(&system[..count])
                .map_err(|_| invalid("carrier formatter path UTF16 differs"))?,
        )
        .join("format.com");
        let stdout = sidecar(&path, "ntfs-format.stdout.log")?;
        let stderr = sidecar(&path, "ntfs-format.stderr.log")?;
        let status = Command::new(formatter)
            .args([
                binding.volume_path()?,
                "/FS:NTFS".into(),
                "/Q".into(),
                "/A:4096".into(),
                "/V:n2r-bounded-carrier".into(),
                "/Y".into(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?))
            .status()?;
        stdout.sync_all()?;
        stderr.sync_all()?;
        member.revalidate()?;
        capacity(directory, budget)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "new owned carrier NTFS format refused ({status}); no fallback, all assets preserved"
            )));
        }
        let binding = rediscover_stage(binding, &path, "carrier-formatted-volume")?;
        let observed =
            discovery::discover(&(binding.volume_path()? + "\\"), discovery::Role::Shadow)?;
        if observed.binding != binding
            || observed.filesystem != "NTFS"
            || observed.label != "n2r-bounded-carrier"
            || observed.bytes_per_sector != 512
            || observed.sectors_per_cluster != 8
        {
            return Err(invalid(
                "new owned carrier is not the selected NTFS4KiB profile",
            ));
        }
        let actual = native_disk(&disk, binding.disk_number, virtual_bytes)?;
        binding.validate_layout(&actual.layout)?;
        binding.validate_alignment(&actual.alignment)?;
        let mut volume = native::device_file(&binding.volume_path()?, false, false)?;
        let (data, _) = ntfs_geometry(&mut volume, &binding, None)?;
        let ntfs_serial = layout::u64_at(&data, 0)?;
        // This is the only origin of member VolumeGUID paths. The caller's
        // ordinary-local-directory validation is not broadened to allow them.
        let member_root = PathBuf::from(binding.volume_path()? + "\\").join("members");
        fs::create_dir(&member_root)?;
        let root = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&member_root)?;
        let root_file_id = file_storage::file_id_info(&root)?;
        let root_guid_path = file_storage::final_path_guid(&root)?;
        let member_root_text = member_root
            .to_str()
            .ok_or_else(|| invalid("carrier member root is not Unicode"))?
            .to_owned();
        let carrier = Self {
            member,
            disk,
            binding,
            volume,
            member_root,
            member_root_text,
            root,
            root_file_id,
            root_guid_path,
            ntfs_serial,
        };
        let observation = carrier.observe(budget)?;
        let _receipt = save(
            &directory.join("bounded-carrier-observation.json"),
            &observation,
        )?;
        Ok(carrier)
    }

    pub(super) fn member_root_text(&self) -> &str {
        &self.member_root_text
    }

    pub(super) fn member_path(&self, index: usize, budget: Budget) -> io::Result<PathBuf> {
        if index >= 2 {
            return Err(invalid("bounded carrier has exactly two new member routes"));
        }
        self.observe(budget)?;
        Ok(self.member_root.join(format!("member-{index}.vhdx")))
    }

    fn identity(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        self.member.revalidate()?;
        let actual = native_disk(
            &self.disk,
            self.binding.disk_number,
            self.member.attachment.created.size,
        )?;
        self.binding.validate_layout(&actual.layout)?;
        self.binding.validate_alignment(&actual.alignment)?;
        if file_storage::file_id_info(&self.root)? != self.root_file_id
            || file_storage::final_path_guid(&self.root)? != self.root_guid_path
            || !self.root.metadata()?.is_dir()
            || self.root.metadata()?.file_attributes() & 0x400 != 0
        {
            return Err(invalid("held carrier members directory identity changed"));
        }
        let mut volume = self.volume.try_clone()?;
        ntfs_geometry(&mut volume, &self.binding, Some(self.ntfs_serial))
    }

    /// Identity-only cleanup gate. It does not loosen the ordinary construction
    /// or formatting admission and does not promise another full scratch budget.
    pub(super) fn verify_retirement_identity(&self) -> io::Result<()> {
        self.identity().map(|_| ())
    }

    pub(super) fn maximum_additional_host_backing_bytes(&self) -> io::Result<u64> {
        self.member.revalidate()?;
        let allocated = file_snapshot(&self.member.backing)?.allocation_bytes;
        self.member
            .attachment
            .created
            .size
            .checked_add(MEMBER_OVERHEAD)
            .and_then(|maximum| maximum.checked_sub(allocated))
            .and_then(|remaining| remaining.checked_add(EXTERNAL_METADATA_RESERVE))
            .ok_or_else(|| {
                invalid(
                    "bounded carrier remaining host backing overflow or allocation exceeds bound",
                )
            })
    }

    pub(super) fn into_retirement_member(self) -> io::Result<Member> {
        self.verify_retirement_identity()?;
        let Self {
            member,
            disk,
            volume,
            root,
            ..
        } = self;
        // Release every inner filesystem/directory/raw reference before the
        // original carrier provider is explicitly detached by its live owner.
        drop(volume);
        drop(root);
        drop(disk);
        Ok(member)
    }

    pub(super) fn observe(&self, budget: Budget) -> io::Result<CarrierObservation> {
        let (data, boot) = self.identity()?;
        // Generic resource sampling canonicalizes via a DOS final path, which
        // is absent on this deliberately letterless carrier. Sample system RAM
        // through the ordinary external backing parent, then query the actual
        // already-verified carrier VolumeGUID directly for filesystem space.
        let external_parent = self
            .member
            .path
            .parent()
            .ok_or_else(|| invalid("carrier external backing parent absent"))?;
        let external =
            resource_native::observe_available_resources(external_parent).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("carrier RAM/external-backing sample: {error}"),
                )
            })?;
        let space = discovery::observe_volume_space(&(self.binding.volume_path()? + "\\"))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("carrier verified VolumeGUID free-space sample: {error}"),
                )
            })?;
        let available = resource_native::AvailableResources {
            total_physical_bytes: external.total_physical_bytes,
            available_physical_bytes: external.available_physical_bytes,
            scratch_available_bytes: space.available_bytes_to_caller,
            scratch_total_bytes: space.total_bytes_available_to_caller,
        };
        if available.scratch_available_bytes < budget.minimum_free_bytes {
            return Err(invalid(&format!(
                "actual NTFS carrier free reserve breached: available {}, minimum {}",
                available.scratch_available_bytes, budget.minimum_free_bytes
            )));
        }
        let backing = file_snapshot(&self.member.backing)?;
        Ok(CarrierObservation {
            kind: "live-new-owned-bounded-ntfs-carrier",
            backing_path: self.member.path.clone(),
            provider_virtual_disk_id: guid_text(&self.member.attachment.created.id),
            provider_virtual_bytes: self.member.attachment.created.size,
            admitted_vhdx_overhead_bytes: MEMBER_OVERHEAD,
            external_metadata_reserve_bytes: EXTERNAL_METADATA_RESERVE,
            binding: self.binding.clone(),
            member_directory: self.member_root.clone(),
            backing_file: backing,
            filesystem_available: available,
            ntfs_volume_data: data,
            boot_metadata: boot,
            nested_members_not_double_counted_as_host_allocation: true,
            sampled_free_space_is_not_a_reservation: true,
            formatted_carrier_is_not_the_conversion_target: true,
        })
    }
}
