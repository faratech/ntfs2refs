//! Capacity enforcement for the real outer native VHDX backing volume.
//! A sampled allowance is not an OS reservation or a bound on native metadata
//! amplification. Call before each bounded allocating operation; native errors
//! still follow the ordinary preparation cancellation/recovery protocol.
use super::retirement::StagingAllocationMeter;
use super::*;

#[derive(Debug, Serialize)]
pub struct BackingResourceObservation {
    pub backing: super::StagingAllocationObservation,
    pub volume_root: String,
    pub virtual_disk_id: String,
    pub available_bytes: u64,
    pub minimum_free_bytes: u64,
    pub allocation_quantum_bytes: u64,
    pub pending_growth_bytes: u64,
    pub sampled_not_reserved: bool,
    pub native_metadata_amplification_bounded: bool,
}

pub struct BackingResourceGuard {
    meter: StagingAllocationMeter,
    provider: VirtualHandle,
    disk_number: u32,
    binding: GeneralDiskBinding,
    virtual_disk_id: [u8; 16],
    volume_root: String,
    minimum_free_bytes: u64,
    allocation_quantum_bytes: u64,
}

fn volume_root(path: &str) -> io::Result<String> {
    let end = path
        .find("}\\")
        .ok_or_else(|| invalid("backing volume GUID route absent"))?;
    if !path.starts_with("\\\\?\\Volume{") {
        return Err(invalid("backing volume GUID route required"));
    }
    Ok(path[..end + 2].to_owned())
}

fn query(provider: &VirtualHandle, version: GET_VIRTUAL_DISK_INFO_VERSION) -> io::Result<Vec<u8>> {
    let mut words = [0u64; 32];
    words[0] = version as u64;
    let mut size = mem::size_of_val(&words) as u32;
    let mut used = 0;
    // SAFETY: live query-only handle and aligned initialized bounded output.
    win(unsafe {
        GetVirtualDiskInformation(provider.0, &mut size, words.as_mut_ptr().cast(), &mut used)
    })?;
    if !(8..=256).contains(&used) || words[0] as u32 != version as u32 {
        return Err(invalid("backing provider query size/version differs"));
    }
    Ok(words
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .take(used as usize)
        .collect())
}

fn require_disk(provider: &VirtualHandle, number: u32) -> io::Result<()> {
    let mut path = [0u16; 256];
    let mut bytes = mem::size_of_val(&path) as u32;
    // SAFETY: live provider handle and initialized bounded UTF-16 output.
    win(unsafe { GetVirtualDiskPhysicalPath(provider.0, &mut bytes, path.as_mut_ptr()) })?;
    let end = path
        .iter()
        .position(|n| *n == 0)
        .ok_or_else(|| invalid("backing provider path unterminated"))?;
    if String::from_utf16(&path[..end]).map_err(|_| invalid("backing provider path UTF-16"))?
        != format!("\\\\.\\PhysicalDrive{number}")
    {
        return Err(invalid(
            "backing provider no longer names the expected shadow disk",
        ));
    }
    Ok(())
}

impl BackingResourceGuard {
    /// Bind an actual held backing file to the currently attached native VHDX.
    /// `minimum_free_bytes == 0` selects the existing quarter-free/16GiB policy
    /// independently on this volume. No entire virtual disk is preallocated.
    pub fn new(
        meter: StagingAllocationMeter,
        expected: &GeneralDiskBinding,
        minimum_free_bytes: u64,
    ) -> io::Result<Self> {
        expected.validate()?;
        let before = meter.observe()?;
        let name = wide(&before.backing_file.final_path)?;
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let mut parameters = OPEN_VIRTUAL_DISK_PARAMETERS::default();
        parameters.Version = OPEN_VIRTUAL_DISK_VERSION_2;
        parameters.Anonymous = OPEN_VIRTUAL_DISK_PARAMETERS_0 {
            Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
                GetInfoOnly: 1,
                ReadOnly: 1,
                ..Default::default()
            },
        };
        let mut handle = ptr::null_mut();
        // SAFETY: open-existing query-only parameters, no attach/create/write.
        win(unsafe {
            OpenVirtualDisk(
                &storage,
                name.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                OPEN_VIRTUAL_DISK_FLAG_NONE,
                &parameters,
                &mut handle,
            )
        })?;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(invalid("backing provider query handle absent"));
        }
        let provider = VirtualHandle(handle);
        require_disk(&provider, expected.disk_number)?;
        let size = query(&provider, GET_VIRTUAL_DISK_INFO_SIZE)?;
        let kind = query(&provider, GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE)?;
        let physical = query(&provider, GET_VIRTUAL_DISK_INFO_VHD_PHYSICAL_SECTOR_SIZE)?;
        let id = query(&provider, GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID)?;
        let quantum = u64::from(layout::u32_at(&size, 24)?);
        if layout::u64_at(&size, 8)? != expected.identity.disk_bytes
            || layout::u32_at(&size, 28)? != expected.identity.logical_sector_bytes
            || layout::u32_at(&physical, 8)? != expected.identity.physical_sector_bytes
            || layout::u32_at(&kind, 8)? != 3
            || quantum == 0
            || !quantum.is_power_of_two()
            || id
                .get(8..24)
                .is_none_or(|bytes| bytes.iter().all(|b| *b == 0))
        {
            return Err(invalid(
                "attached native VHDX geometry/type/identity differs",
            ));
        }
        let virtual_disk_id: [u8; 16] = id[8..24]
            .try_into()
            .map_err(|_| invalid("backing virtual disk ID length differs"))?;
        let root = volume_root(&before.backing_file.final_path)?;
        let available = crate::resource_native::observe_available_resources(Path::new(&root))?;
        let floor = if minimum_free_bytes == 0 {
            (available.scratch_available_bytes / 4).min(16 << 30)
        } else {
            minimum_free_bytes
        };
        let result = Self {
            meter,
            provider,
            disk_number: expected.disk_number,
            binding: expected.clone(),
            virtual_disk_id,
            volume_root: root,
            minimum_free_bytes: floor,
            allocation_quantum_bytes: quantum,
        };
        result.check_before_operation(0)?;
        Ok(result)
    }

    pub fn allocation_quantum_bytes(&self) -> u64 {
        self.allocation_quantum_bytes
    }
    pub fn require_binding(&self, expected: &GeneralDiskBinding) -> io::Result<()> {
        if &self.binding != expected {
            return Err(invalid(
                "backing capacity owner is bound to a different native shadow",
            ));
        }
        Ok(())
    }
    pub fn minimum_free_bytes(&self) -> u64 {
        self.minimum_free_bytes
    }
    pub fn volume_root(&self) -> &str {
        &self.volume_root
    }
    pub fn meter(&self) -> io::Result<StagingAllocationMeter> {
        self.meter.try_clone()
    }

    /// Compare the actual volume GUID of a held ordinary workspace directory.
    pub fn shares_volume_with(&self, directory: &Path) -> io::Result<bool> {
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(directory)?;
        let actual = crate::file_storage::final_path_guid(&file)?;
        Ok(volume_root(&actual)?.eq_ignore_ascii_case(&self.volume_root))
    }

    pub fn observe(&self, operation_bytes: u64) -> io::Result<BackingResourceObservation> {
        let _timed = crate::perf::scope(crate::perf::Point::BackingGuard);
        require_disk(&self.provider, self.disk_number)?;
        if query(&self.provider, GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID)?.get(8..24)
            != Some(self.virtual_disk_id.as_slice())
        {
            return Err(invalid("held backing virtual disk ID changed"));
        }
        let backing = self.meter.observe()?;
        if !volume_root(&backing.backing_file.final_path)?.eq_ignore_ascii_case(&self.volume_root) {
            return Err(invalid("held backing changed volume"));
        }
        let quantum = self.allocation_quantum_bytes;
        // One additional native allocation quantum is always pending. This is
        // explicit operational headroom, not an asserted metadata-growth bound.
        let pending = operation_bytes
            .checked_add(quantum - 1)
            .and_then(|n| (n / quantum).checked_add(1))
            .and_then(|n| n.checked_mul(quantum))
            .ok_or_else(|| invalid("backing operation allowance overflow"))?;
        let available =
            crate::resource_native::observe_available_resources(Path::new(&self.volume_root))?;
        Ok(BackingResourceObservation {
            backing,
            volume_root: self.volume_root.clone(),
            virtual_disk_id: hex::encode(self.virtual_disk_id),
            available_bytes: available.scratch_available_bytes,
            minimum_free_bytes: self.minimum_free_bytes,
            allocation_quantum_bytes: quantum,
            pending_growth_bytes: pending,
            sampled_not_reserved: true,
            native_metadata_amplification_bounded: false,
        })
    }

    pub fn check_before_operation(&self, operation_bytes: u64) -> io::Result<()> {
        // A free-space sample of the volume behind the shadow, against a
        // floor of gigabytes. A few samples a second cannot let that floor be
        // crossed; one before every small write cost more than the writes.
        static PACED: crate::verify_policy::Paced = crate::verify_policy::Paced::new();
        if !PACED.due(250) {
            return Ok(());
        }
        let observed = self.observe(operation_bytes)?;
        PACED.passed();
        let required = observed
            .minimum_free_bytes
            .checked_add(observed.pending_growth_bytes)
            .ok_or_else(|| invalid("backing free-space allowance overflow"))?;
        if observed.available_bytes < required {
            return Err(io::Error::other(format!(
                "native shadow backing capacity refused before operation: volume {}, available {}, required {}, floor {}, next growth {}; actual allocation {}; sampled allowance is not an OS reservation",
                observed.volume_root,
                observed.available_bytes,
                required,
                observed.minimum_free_bytes,
                observed.pending_growth_bytes,
                observed.backing.backing_file.allocation_bytes
            )));
        }
        Ok(())
    }
}

impl StagingAllocationMeter {
    /// Discover the backing of the actual already-attached shadow. Dependency
    /// strings only locate a file; native provider identity/route is verified
    /// by BackingResourceGuard::new before this can become an enforcing owner.
    pub fn discover_attached_native(expected: &GeneralDiskBinding) -> io::Result<Self> {
        expected.validate()?;
        let mut events = Vec::new();
        let before = native::observe_general_disk_state_readonly(expected.clone(), &mut events)?;
        let disk = native::device_file(
            &format!("\\\\.\\PhysicalDrive{}", expected.disk_number),
            false,
            false,
        )?;
        let mut words = [0u64; 8192];
        let base = words.as_mut_ptr().cast::<STORAGE_DEPENDENCY_INFO>();
        // SAFETY: aligned zeroed 64KiB output contains the complete header.
        unsafe {
            (*base).Version = STORAGE_DEPENDENCY_INFO_VERSION_2;
        }
        let mut used = 0;
        // SAFETY: live read-only disk handle, bounded aligned output, no writes.
        win(unsafe {
            GetStorageDependencyInformation(
                disk.as_raw_handle(),
                GET_STORAGE_DEPENDENCY_FLAG_DISK_HANDLE | GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES,
                mem::size_of_val(&words) as u32,
                base,
                &mut used,
            )
        })?;
        if used as usize > mem::size_of_val(&words)
            || (used as usize) < mem::size_of::<STORAGE_DEPENDENCY_INFO>()
        {
            return Err(invalid("shadow dependency output size differs"));
        }
        // SAFETY: bounded initialized header was validated above.
        let header = unsafe { &*base };
        if header.Version != STORAGE_DEPENDENCY_INFO_VERSION_2 || header.NumberEntries != 1 {
            return Err(invalid(
                "one direct native VHDX backing dependency required",
            ));
        }
        // SAFETY: exactly one V2 entry fits inside the validated header/output.
        let entry = unsafe { header.Anonymous.Version2Entries[0] };
        if entry.VirtualStorageType.DeviceId != VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
            || guid_bytes(&entry.VirtualStorageType.VendorId)
                != guid_bytes(&VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT)
        {
            return Err(invalid(
                "nested or non-native shadow backing is unsupported",
            ));
        }
        let string = |pointer: *mut u16| -> io::Result<String> {
            let start = pointer as usize;
            let low = words.as_ptr() as usize;
            let high = low + used as usize;
            if start < low || start >= high || !start.is_multiple_of(2) {
                return Err(invalid("shadow dependency string outside native output"));
            }
            // SAFETY: validated pointer/alignment; bound stops inside output.
            let chars = unsafe { std::slice::from_raw_parts(pointer, (high - start) / 2) };
            let end = chars
                .iter()
                .position(|n| *n == 0)
                .ok_or_else(|| invalid("shadow dependency string unterminated"))?;
            String::from_utf16(&chars[..end]).map_err(|_| invalid("shadow dependency UTF-16"))
        };
        let host = string(entry.HostVolumeName)?;
        let relative = string(entry.DependentVolumeRelativePath)?;
        let root = volume_root(&host)?;
        if !host.eq_ignore_ascii_case(&root)
            || relative.is_empty()
            || relative
                .trim_start_matches('\\')
                .split('\\')
                .any(|p| p.is_empty() || matches!(p, "." | "..") || p.contains(':'))
        {
            return Err(invalid("ordinary native shadow dependency path required"));
        }
        let path = PathBuf::from(format!("{}{}", root, relative.trim_start_matches('\\')));
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let identity = crate::reference_file::observe_reference_file_handle_with_limit(
            &file,
            i64::MAX as u64,
        )?;
        let meter = Self::from_held(&file, &identity, "native-vhdx-outer-backing")?;
        let verified = BackingResourceGuard::new(meter, expected, 0)?;
        if native::observe_general_disk_state_readonly(expected.clone(), &mut events)? != before {
            return Err(invalid("shadow disk changed during backing discovery"));
        }
        verified.meter()
    }
}
