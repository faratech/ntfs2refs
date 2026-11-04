//! Empty-volume native format/growth experiment. Never accepts a source disk.
//! Permanent owned attachments and partial evidence survive every error.
use super::*;
use crate::{bitmap_streaming, file_storage, resource_native, volume_policy};
use serde::Serialize;
use windows_sys::Win32::System::Ioctl::{
    DISK_GROW_PARTITION, FSCTL_EXTEND_VOLUME, IOCTL_DISK_GROW_PARTITION,
};

pub const FINAL_PARTITION_BYTES: u64 = 240 * 1024 * 1024 * 1024;
pub const SEED_PARTITION_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const LOGICAL_SECTOR: u32 = 512;
const PHYSICAL_SECTOR: u32 = 4096;
const CLUSTER: u64 = 4096;
const REFS_VOLUME_DATA: u32 = 0x0009_02d8;
const VOLUME_EXTENTS: u32 = 0x0056_0000;
// winnt.h FILE_READ_ONLY_VOLUME (the generated SDK places this in an
// otherwise unused feature module).
const FILE_READ_ONLY_VOLUME_FLAG: u32 = 0x0008_0000;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Direct,
    SeedGrow,
}

impl std::str::FromStr for Mode {
    type Err = io::Error;
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "direct" => Ok(Self::Direct),
            "seed-grow" => Ok(Self::SeedGrow),
            _ => Err(invalid("growth probe mode must be direct or seed-grow")),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Budget {
    pub ram_bytes: u64,
    pub scratch_bytes: u64,
    pub minimum_free_bytes: u64,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub phase: &'static str,
    pub binding: GeneralDiskBinding,
    pub refs_volume_data: Vec<u8>,
    pub format_policy: volume_policy::Observation,
    pub legacy_bitmap: bitmap_streaming::Summary,
    pub metadata_inclusive_bitmap: bitmap_streaming::Summary,
    pub legacy_allocated_bytes: u64,
    pub metadata_inclusive_allocated_bytes: u64,
    pub observed_bitmap_union_bytes: u64,
    pub observed_bitmap_union_ranges: u64,
    pub backing_storage: file_storage::StorageUse,
    pub retained_regular_file_storage_bytes: u64,
    pub available_resources: resource_native::AvailableResources,
    pub complete_consumed_set_verified: bool,
    pub complete_allocation_ownership_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Growth {
    pub before_partition_bytes: u64,
    pub bytes_to_grow: u64,
    pub after_partition_bytes: u64,
    pub filesystem_new_sector_count: u64,
    pub grow_control_succeeded: bool,
    pub filesystem_extend_control_succeeded: bool,
    pub disk_and_volume_flushes_succeeded: bool,
    pub elapsed_milliseconds: u128,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub kind: &'static str,
    pub mode: Mode,
    pub budget: Budget,
    pub path: PathBuf,
    pub virtual_disk_id: String,
    pub virtual_disk_bytes: u64,
    pub final_binding: GeneralDiskBinding,
    pub snapshots: Vec<Snapshot>,
    pub growth: Option<Growth>,
    pub elapsed_milliseconds: u128,
    pub source_binding_supplied: bool,
    pub source_payload_bytes_read: u64,
    pub source_payload_bytes_written: u64,
    pub complete_consumed_set_verified: bool,
    pub complete_allocation_ownership_verified: bool,
    pub conversion_authorized: bool,
    pub remount_measured: bool,
    pub remount_required_before_adoption_decision: bool,
    pub speed_or_space_improvement_proven: bool,
    pub sampled_budgets_are_not_kernel_or_formatter_reservations: bool,
    pub global_directory_metadata_and_peak_io_not_measured: bool,
    pub permanent_attachment_and_backing_retained: bool,
    pub automatic_retry_or_cleanup: bool,
}

struct Evidence {
    file: File,
    bytes: u64,
    maximum: u64,
}

struct MetadataWriter<'a> {
    file: &'a mut File,
    remaining: u64,
}
impl Write for MetadataWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(invalid(
                "phase metadata exceeds its admitted file allowance",
            ));
        }
        let count = self.file.write(bytes)?;
        self.remaining -= count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn save_snapshot(path: &Path, phase: &str, snapshot: &Snapshot, budget: Budget) -> io::Result<()> {
    let mut file = sidecar(path, &format!("{phase}.json"))?;
    {
        let mut writer = MetadataWriter {
            file: &mut file,
            remaining: budget.ram_bytes,
        };
        serde_json::to_writer_pretty(&mut writer, snapshot).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
    }
    file.sync_all()
}

impl Evidence {
    fn note(&mut self, value: impl Serialize) -> io::Result<()> {
        let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
        let size = (bytes.len() as u64)
            .checked_add(1)
            .and_then(|n| self.bytes.checked_add(n))
            .ok_or_else(|| invalid("growth evidence length overflow"))?;
        if size > self.maximum {
            return Err(invalid(
                "growth evidence exceeds admitted metadata allowance",
            ));
        }
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        self.bytes = size;
        Ok(())
    }
}

fn validate_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.exists()
        || path.file_name().and_then(|s| s.to_str()) != Some("shadow.vhdx")
    {
        return Err(invalid("fresh absolute lab shadow.vhdx route required"));
    }
    for component in path.components() {
        match component {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                return Err(invalid("local drive staging route required"));
            }
            Component::CurDir | Component::ParentDir => {
                return Err(invalid("staging traversal refused"));
            }
            Component::Normal(value)
                if value
                    .to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                return Err(invalid("ambiguous staging component"));
            }
            _ => {}
        }
    }
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.file_attributes() & 0x400 != 0 {
            return Err(invalid("ordinary lab staging ancestry required"));
        }
    }
    Ok(())
}

fn capacity(
    path: &Path,
    budget: Budget,
    before_creation: bool,
) -> io::Result<(u64, resource_native::AvailableResources)> {
    let directory = path
        .parent()
        .ok_or_else(|| invalid("lab staging parent absent"))?;
    let available = resource_native::observe_available_resources(directory)?;
    if budget.ram_bytes <= 8 * 1024 * 1024
        || budget.ram_bytes > available.available_physical_bytes
        || budget.scratch_bytes < budget.ram_bytes
    {
        return Err(invalid(
            "growth probe RAM/scratch admission differs from availability",
        ));
    }
    let mut actual = 0u64;
    for item in fs::read_dir(directory)? {
        let item = item?;
        let m = fs::symlink_metadata(item.path())?;
        if !m.is_file() || m.file_attributes() & 0x400 != 0 {
            return Err(invalid(
                "lab staging must contain only ordinary owned files",
            ));
        }
        actual = actual
            .checked_add(file_storage::observe(&item.path())?.filesystem_storage_bytes)
            .ok_or_else(|| invalid("growth scratch accounting overflow"))?;
    }
    // Keep a RAM-sized final-result allowance in addition to retained backing
    // and phase evidence. These remain samples, not an OS allocation quota.
    if actual
        .checked_add(budget.ram_bytes)
        .is_none_or(|n| n > budget.scratch_bytes)
        || budget
            .minimum_free_bytes
            .checked_add(budget.ram_bytes)
            .is_none_or(|n| n > available.scratch_available_bytes)
    {
        return Err(invalid(
            "growth probe exceeded scratch budget or free-space reserve",
        ));
    }
    if before_creation
        && budget
            .scratch_bytes
            .checked_add(budget.minimum_free_bytes)
            .is_none_or(|n| n > available.scratch_available_bytes)
    {
        return Err(invalid(
            "growth probe cannot admit scratch and free-space reserve",
        ));
    }
    Ok((actual, available))
}

fn new_provider(path: &Path) -> io::Result<AttachedDisk> {
    let size = FINAL_PARTITION_BYTES
        .checked_add(MARGIN)
        .ok_or_else(|| invalid("growth provider size overflow"))?;
    let id = random_guid()?;
    let name = wide(
        path.to_str()
            .ok_or_else(|| invalid("Unicode staging route required"))?,
    )?;
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let mut params = CREATE_VIRTUAL_DISK_PARAMETERS::default();
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Anonymous = CREATE_VIRTUAL_DISK_PARAMETERS_0 {
        Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
            UniqueId: id,
            MaximumSize: size,
            BlockSizeInBytes: 2 << 20,
            SectorSizeInBytes: LOGICAL_SECTOR,
            PhysicalSectorSizeInBytes: PHYSICAL_SECTOR,
            ..Default::default()
        },
    };
    let mut handle = ptr::null_mut();
    // SAFETY: fresh ordinary path, complete version2 parameters, no parent or
    // source, zero flags for dynamic allocation, live initialized output.
    win(unsafe {
        CreateVirtualDisk(
            &storage,
            name.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            ptr::null_mut(),
            CREATE_VIRTUAL_DISK_FLAG_NONE,
            0,
            &params,
            ptr::null(),
            &mut handle,
        )
    })?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(invalid("growth provider returned no owned handle"));
    }
    CreatedDisk {
        handle: VirtualHandle(handle),
        id,
        size,
        logical: LOGICAL_SECTOR,
        physical: PHYSICAL_SECTOR,
    }
    .attach()
}

fn format_owned(binding: &GeneralDiskBinding, path: &Path, log: &mut Evidence) -> io::Result<()> {
    let mut system = [0u16; 32768];
    // SAFETY: initialized WCHAR output and exact available capacity.
    let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count >= system.len() {
        return Err(invalid("system formatter route exceeds buffer"));
    }
    let formatter = PathBuf::from(
        String::from_utf16(&system[..count])
            .map_err(|_| invalid("system directory UTF16 differs"))?,
    )
    .join("format.com");
    let args = [
        binding.volume_path()?,
        "/FS:ReFS".into(),
        "/DevDrv".into(),
        "/Q".into(),
        "/A:4096".into(),
        "/V:n2r-retained-shadow".into(),
        "/Y".into(),
    ];
    log.note(serde_json::json!({"phase":"format-start","binding":binding,"formatter":formatter,"args":args}))?;
    let stdout = sidecar(path, "format.stdout.log")?;
    let stderr = sidecar(path, "format.stderr.log")?;
    let started = Instant::now();
    let status = Command::new(formatter)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .status()?;
    stdout.sync_all()?;
    stderr.sync_all()?;
    log.note(
        serde_json::json!({"phase":"format-terminal","success":status.success(),
        "exit_code":status.code(),"elapsed_milliseconds":started.elapsed().as_millis()}),
    )?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "owned lab DevDrive format refused ({status}); backing retained"
        )));
    }
    Ok(())
}

fn geometry(volume: &File, binding: &GeneralDiskBinding) -> io::Result<Vec<u8>> {
    let extents = control(volume, VOLUME_EXTENTS, &[], 32)?;
    binding.validate_volume_extent(&extents)?;
    let data = control(volume, REFS_VOLUME_DATA, &[], 256)?;
    if data.len() < 64
        || !(64..=data.len()).contains(&(layout::u32_at(&data, 0)? as usize))
        || layout::u32_at(&data, 4)? != 3
        || layout::u32_at(&data, 8)? != 14
        || layout::u64_at(&data, 24)?
            != binding.identity.partition_bytes / u64::from(LOGICAL_SECTOR)
        || layout::u64_at(&data, 32)? != binding.identity.partition_bytes / CLUSTER
        || layout::u32_at(&data, 56)? != LOGICAL_SECTOR
        || layout::u32_at(&data, 60)? != CLUSTER as u32
    {
        return Err(invalid(
            "owned lab volume is not exact ReFS3.14/4KiB final geometry",
        ));
    }
    Ok(data)
}

fn union_totals(
    left: &bitmap_streaming::Summary,
    right: &bitmap_streaming::Summary,
) -> io::Result<(u64, u64)> {
    let mut a = left.allocated_ranges.iter().peekable();
    let mut b = right.allocated_ranges.iter().peekable();
    let mut current: Option<(u64, u64)> = None;
    let mut clusters = 0u64;
    let mut ranges = 0u64;
    while a.peek().is_some() || b.peek().is_some() {
        let row = if b.peek().is_none()
            || a.peek()
                .is_some_and(|x| x.starting_lcn <= b.peek().unwrap().starting_lcn)
        {
            a.next().unwrap()
        } else {
            b.next().unwrap()
        };
        let end = row
            .starting_lcn
            .checked_add(row.clusters)
            .ok_or_else(|| invalid("bitmap interval overflow"))?;
        match current {
            Some((start, old_end)) if row.starting_lcn <= old_end => {
                current = Some((start, old_end.max(end)))
            }
            old => {
                if let Some((start, old_end)) = old {
                    clusters = clusters
                        .checked_add(old_end - start)
                        .ok_or_else(|| invalid("bitmap union overflow"))?;
                    ranges += 1;
                }
                current = Some((row.starting_lcn, end));
            }
        }
    }
    if let Some((start, end)) = current {
        clusters = clusters
            .checked_add(end - start)
            .ok_or_else(|| invalid("bitmap union overflow"))?;
        ranges += 1;
    }
    Ok((
        clusters
            .checked_mul(CLUSTER)
            .ok_or_else(|| invalid("bitmap union byte overflow"))?,
        ranges,
    ))
}

fn snapshot(
    attached: &AttachedDisk,
    binding: &GeneralDiskBinding,
    path: &Path,
    phase: &'static str,
    budget: Budget,
    mode: Mode,
    log: &mut Evidence,
) -> io::Result<Snapshot> {
    attached.verify_provider()?;
    capacity(path, budget, false)?;
    let discovered =
        discovery::discover(&(binding.volume_path()? + "\\"), discovery::Role::Shadow)?;
    log.note(serde_json::json!({"phase":phase,"mounted_discovery":discovered}))?;
    if discovered.binding != *binding
        || discovered.filesystem != "ReFS"
        || discovered.label != "n2r-retained-shadow"
        || discovered.bytes_per_sector != LOGICAL_SECTOR
        || discovered.sectors_per_cluster != 8
        // Discovery's read_only field describes the observation operation.
        // The filesystem flag and native disk state describe the device.
        || discovered.filesystem_flags & FILE_READ_ONLY_VOLUME_FLAG != 0
    {
        return Err(invalid("owned lab mounted binding/profile differs"));
    }
    let mut events = Vec::new();
    let before = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    if before.disk_attributes != 0 {
        return Err(invalid("owned lab disk is not online/writable"));
    }
    let volume = native::device_file(&binding.volume_path()?, true, false)?;
    volume.sync_all()?;
    let refs_volume_data = geometry(&volume, binding)?;
    let format_policy = volume_policy::observe(binding, &mut events)?;
    if format_policy.developer_volume != Some(true) {
        return Err(invalid("owned lab DevDrive designation unknown or false"));
    }
    let clusters = binding.identity.partition_bytes / CLUSTER;
    let views = match mode {
        Mode::Direct => 2,
        Mode::SeedGrow => 4,
    };
    let row_bytes = budget
        .ram_bytes
        .checked_sub(8 * 1024 * 1024)
        .ok_or_else(|| invalid("bitmap working RAM absent"))?
        / views;
    let mut limits = bitmap_streaming::source_limits(clusters)?;
    limits.max_bitmap_bytes = clusters.div_ceil(8);
    limits.max_allocated_ranges =
        usize::try_from(row_bytes / (2 * mem::size_of::<bitmap_streaming::ClusterRange>() as u64))
            .map_err(io::Error::other)?;
    if limits.max_allocated_ranges == 0 {
        return Err(invalid("bitmap row allowance empty"));
    }
    let legacy_bitmap = bitmap_streaming::capture(&volume, clusters, &[0; 8], limits, |proof| {
        log.note(serde_json::json!({"phase":phase,"view":"legacy","page":proof}))
    })?;
    let mut input = [0u8; 16];
    input[8] = 1;
    let metadata_inclusive_bitmap =
        bitmap_streaming::capture(&volume, clusters, &input, limits, |proof| {
            log.note(serde_json::json!({"phase":phase,"view":"metadata-inclusive","page":proof}))
        })?;
    if geometry(&volume, binding)? != refs_volume_data {
        return Err(invalid("ReFS geometry changed across bitmap collection"));
    }
    drop(volume);
    let after = native::observe_general_disk_state_readonly(binding.clone(), &mut events)?;
    if before != after {
        return Err(invalid("owned lab route/state changed across snapshot"));
    }
    log.note(serde_json::json!({"phase":phase,"native_events":events}))?;
    let (observed_bitmap_union_bytes, observed_bitmap_union_ranges) =
        union_totals(&legacy_bitmap, &metadata_inclusive_bitmap)?;
    let legacy_allocated_bytes = legacy_bitmap
        .allocated_clusters
        .checked_mul(CLUSTER)
        .ok_or_else(|| invalid("legacy byte total overflow"))?;
    let metadata_inclusive_allocated_bytes = metadata_inclusive_bitmap
        .allocated_clusters
        .checked_mul(CLUSTER)
        .ok_or_else(|| invalid("metadata byte total overflow"))?;
    let backing_storage = file_storage::observe(path)?;
    log.note(serde_json::json!({"phase":phase,"snapshot_complete":true,
        "legacy_allocated_bytes":legacy_allocated_bytes,"metadata_inclusive_allocated_bytes":metadata_inclusive_allocated_bytes,
        "observed_bitmap_union_bytes":observed_bitmap_union_bytes,"backing_storage":backing_storage}))?;
    let (actual, available) = capacity(path, budget, false)?;
    let snapshot = Snapshot {
        phase,
        binding: binding.clone(),
        refs_volume_data,
        format_policy,
        legacy_bitmap,
        metadata_inclusive_bitmap,
        legacy_allocated_bytes,
        metadata_inclusive_allocated_bytes,
        observed_bitmap_union_bytes,
        observed_bitmap_union_ranges,
        backing_storage,
        retained_regular_file_storage_bytes: actual,
        available_resources: available,
        complete_consumed_set_verified: false,
        complete_allocation_ownership_verified: false,
    };
    // Keep the seed's maps even if a subsequent native grow/extend refuses.
    // This is bounded metadata, never a raw image or file-data export.
    save_snapshot(path, phase, &snapshot, budget)?;
    capacity(path, budget, false)?;
    Ok(snapshot)
}

fn grow(
    attached: &AttachedDisk,
    mut binding: GeneralDiskBinding,
    path: &Path,
    budget: Budget,
    log: &mut Evidence,
) -> io::Result<(GeneralDiskBinding, Growth)> {
    if binding.identity.partition_bytes != SEED_PARTITION_BYTES
        || mem::size_of::<DISK_GROW_PARTITION>() != 16
    {
        return Err(invalid("exact50GiB seed and native growth ABI required"));
    }
    attached.verify_provider()?;
    capacity(path, budget, false)?;
    let disk = native::device_file(
        &format!("\\\\.\\PhysicalDrive{}", attached.number),
        true,
        false,
    )?;
    binding.validate_layout(&control(&disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?)?;
    let increment = FINAL_PARTITION_BYTES
        .checked_sub(SEED_PARTITION_BYTES)
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .ok_or_else(|| invalid("positive partition growth increment required"))?;
    let mut input = [0u8; 16];
    input[..4].copy_from_slice(&binding.identity.partition_number.to_le_bytes());
    input[8..16].copy_from_slice(&(increment as i64).to_le_bytes());
    log.note(serde_json::json!({"phase":"grow-partition-start","binding":binding,"bytes_to_grow":increment,"control":IOCTL_DISK_GROW_PARTITION}))?;
    let started = Instant::now();
    control(&disk, IOCTL_DISK_GROW_PARTITION, &input, 0)?;
    disk.sync_all()?;
    control(&disk, IOCTL_DISK_UPDATE_PROPERTIES, &[], 0)?;
    binding.identity.partition_bytes = FINAL_PARTITION_BYTES;
    binding.validate_layout(&control(&disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 65536)?)?;
    binding = rediscover_stage(binding, path, "grown-partition-volume")?;
    log.note(serde_json::json!({"phase":"grow-partition-complete","binding":binding,"disk_flush_succeeded":true}))?;
    let volume = native::device_file(&binding.volume_path()?, true, false)?;
    binding.validate_volume_extent(&control(&volume, VOLUME_EXTENTS, &[], 32)?)?;
    let sectors = FINAL_PARTITION_BYTES / u64::from(LOGICAL_SECTOR);
    log.note(serde_json::json!({"phase":"extend-filesystem-start","control":FSCTL_EXTEND_VOLUME,"new_sector_count":sectors}))?;
    control(&volume, FSCTL_EXTEND_VOLUME, &sectors.to_le_bytes(), 0)?;
    volume.sync_all()?;
    disk.sync_all()?;
    geometry(&volume, &binding)?;
    drop(volume);
    drop(disk);
    attached.verify_provider()?;
    log.note(serde_json::json!({"phase":"extend-filesystem-complete","binding":binding,"volume_and_disk_flushes_succeeded":true}))?;
    Ok((
        binding,
        Growth {
            before_partition_bytes: SEED_PARTITION_BYTES,
            bytes_to_grow: increment,
            after_partition_bytes: FINAL_PARTITION_BYTES,
            filesystem_new_sector_count: sectors,
            grow_control_succeeded: true,
            filesystem_extend_control_succeeded: true,
            disk_and_volume_flushes_succeeded: true,
            elapsed_milliseconds: started.elapsed().as_millis(),
        },
    ))
}

/// Run one explicitly selected empty-volume case. Never detaches, deletes,
/// formats an existing disk, creates a source binding, or changes product mode.
pub fn run(path: &Path, mode: Mode, budget: Budget) -> io::Result<Report> {
    validate_path(path)?;
    capacity(path, budget, true)?;
    let mut log = Evidence {
        file: sidecar(path, "growth-events.jsonl")?,
        bytes: 0,
        maximum: (budget.ram_bytes / 4).min(budget.scratch_bytes / 4),
    };
    let started = Instant::now();
    log.note(
        serde_json::json!({"phase":"admitted","mode":mode,"budget":budget,
        "final_partition_bytes":FINAL_PARTITION_BYTES,"seed_partition_bytes":SEED_PARTITION_BYTES,
        "source_binding_supplied":false,"automatic_cleanup":false}),
    )?;
    let mut privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
    let attached = new_provider(path)?;
    log.note(serde_json::json!({"phase":"provider-created","disk_number":attached.number,
        "virtual_disk_id":guid_text(&attached.created.id),"virtual_disk_bytes":attached.created.size}))?;
    let initial = match mode {
        Mode::Direct => FINAL_PARTITION_BYTES,
        Mode::SeedGrow => SEED_PARTITION_BYTES,
    };
    let binding = attached.initialize(initial, path)?;
    format_owned(&binding, path, &mut log)?;
    attached.verify_provider()?;
    let mut binding = rediscover_stage(binding, path, "formatted-volume")?;
    let mut snapshots = Vec::with_capacity(2);
    snapshots.push(snapshot(
        &attached,
        &binding,
        path,
        match mode {
            Mode::Direct => "direct-final-formatted",
            Mode::SeedGrow => "seed-formatted",
        },
        budget,
        mode,
        &mut log,
    )?);
    let growth = if matches!(mode, Mode::SeedGrow) {
        let (grown, observation) = grow(&attached, binding, path, budget, &mut log)?;
        binding = grown;
        snapshots.push(snapshot(
            &attached,
            &binding,
            path,
            "grown-final",
            budget,
            mode,
            &mut log,
        )?);
        Some(observation)
    } else {
        None
    };
    if binding.identity.partition_bytes != FINAL_PARTITION_BYTES {
        return Err(invalid("final lab partition size differs"));
    }
    privileges.restore()?;
    capacity(path, budget, false)?;
    log.note(
        serde_json::json!({"phase":"complete","binding":binding,"remount_measured":false,
        "complete_consumed_set_verified":false,"conversion_authorized":false}),
    )?;
    Ok(Report {
        schema_version: 1,
        kind: "lab-native-empty-shadow-format-growth",
        mode,
        budget,
        path: path.to_owned(),
        virtual_disk_id: guid_text(&attached.created.id),
        virtual_disk_bytes: attached.created.size,
        final_binding: binding,
        snapshots,
        growth,
        elapsed_milliseconds: started.elapsed().as_millis(),
        source_binding_supplied: false,
        source_payload_bytes_read: 0,
        source_payload_bytes_written: 0,
        complete_consumed_set_verified: false,
        complete_allocation_ownership_verified: false,
        conversion_authorized: false,
        remount_measured: false,
        remount_required_before_adoption_decision: true,
        speed_or_space_improvement_proven: false,
        sampled_budgets_are_not_kernel_or_formatter_reservations: true,
        global_directory_metadata_and_peak_io_not_measured: true,
        permanent_attachment_and_backing_retained: true,
        automatic_retry_or_cleanup: false,
    })
}
