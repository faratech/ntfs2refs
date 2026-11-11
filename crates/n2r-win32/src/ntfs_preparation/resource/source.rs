use super::*;

/// Actual mounted NTFS maintenance owner. Only filesystem-owned movement is
/// exposed; neither a raw disk writer nor conversion admission can escape.
pub struct OpenedSource {
    disk: File,
    volume: File,
    binding: GeneralDiskBinding,
    state: native::GeneralDiskState,
    geometry: VolumeGeometry,
    budget: ResourceBudget,
    moves: MoveBudget,
    attempted_moves: u64,
    attempted_bytes: u64,
    poisoned: bool,
    privileges: Privileges,
    payer: Arc<dyn ReportMemoryAccountant>,
    _memory: Lease,
}
pub struct OpenedFile<'a> {
    file: File,
    identity: FileIdentity,
    eof: u64,
    source: &'a mut OpenedSource,
    _memory: Lease,
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct LeasedFileObservation {
    value: FileObservation,
    #[serde(skip)]
    _memory: Lease,
}
impl std::ops::Deref for LeasedFileObservation {
    type Target = FileObservation;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
#[derive(Serialize)]
#[serde(transparent)]
pub struct LeasedMoveObservation {
    value: MoveObservation,
    #[serde(skip)]
    _memory: Lease,
}
impl std::ops::Deref for LeasedMoveObservation {
    type Target = MoveObservation;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[derive(Serialize)]
pub struct PreparationCompletion {
    pub privilege_states: Vec<PrivilegeState>,
    pub attempted_moves: u64,
    pub attempted_payload_bytes: u64,
    pub source_revalidated: bool,
    pub source_validation_error: Option<String>,
    pub privileges_restored: bool,
    pub privilege_restore_error: Option<String>,
    pub verified: bool,
    pub source_owner_poisoned: bool,
    pub source_admitted: bool,
}
#[derive(Serialize)]
#[serde(transparent)]
pub struct LeasedPreparationCompletion {
    value: PreparationCompletion,
    #[serde(skip)]
    _memory: Lease,
}
impl std::ops::Deref for LeasedPreparationCompletion {
    type Target = PreparationCompletion;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

fn capture(file: &File, budget: ResourceBudget) -> io::Result<retrieval_paging::Capture> {
    let bytes = usize::try_from(budget.max_row_bytes).map_err(io::Error::other)?;
    let limits = retrieval_paging::Limits::for_resource_bytes(bytes)?;
    let (first, continuation) = stream_native::retrieval_queries_resource(file, bytes)?;
    retrieval_paging::assemble_queries_with_limits(&first, &continuation, limits)
}
fn validate(
    capture: &retrieval_paging::Capture,
    info: FileInformation,
    g: VolumeGeometry,
    budget: ResourceBudget,
) -> io::Result<()> {
    let limits = retrieval_paging::Limits::for_resource_bytes(
        usize::try_from(budget.max_row_bytes).map_err(io::Error::other)?,
    )?;
    require(
        !capture.runs.is_empty() && capture.runs.len() <= limits.max_extents,
        "resident/empty or over-budget complete NTFS retrieval",
    )?;
    let mut covered = 0u64;
    for run in &capture.runs {
        let end = run
            .vcn
            .checked_add(run.clusters)
            .ok_or_else(|| invalid("NTFS preparation VCN overflow"))?;
        require(
            run.vcn == covered
                && run.clusters > 0
                && run
                    .lcn
                    .and_then(|lcn| lcn.checked_add(run.clusters))
                    .is_some_and(|n| n <= g.total_clusters),
            "NTFS preparation map is sparse, discontinuous or outside source",
        )?;
        covered = end;
    }
    let cluster = u64::from(g.cluster_bytes);
    require(
        covered == capture.proof.virtual_clusters
            && covered.checked_mul(cluster) == Some(info.allocation_bytes)
            && info
                .logical_bytes
                .checked_next_multiple_of(cluster)
                .is_some_and(|n| n <= info.allocation_bytes),
        "complete NTFS allocation/EOF mapping differs",
    )
}

impl OpenedSource {
    pub fn open(
        binding: GeneralDiskBinding,
        budget: ResourceBudget,
        expected_ntfs_serial: u64,
        expected_cluster_bytes: u32,
        moves: MoveBudget,
        payer: Arc<dyn ReportMemoryAccountant>,
    ) -> io::Result<Self> {
        budget.validate()?;
        moves.validate()?;
        binding.validate()?;
        require(
            binding.identity.partition_bytes <= i64::MAX as u64,
            "NTFS source exceeds signed native IO geometry",
        )?;
        let memory = payer.reserve(2 * 1024 * 1024 + payer.lease_heap_bytes())?;
        exclude_running_windows_disk(binding.disk_number)?;
        let privileges = Privileges::enable_for(&["SeManageVolumePrivilege"])?;
        let disk = native::device_file(
            &format!(r"\\.\PhysicalDrive{}", binding.disk_number),
            false,
            false,
        )?;
        let state = native::general_disk_state(&disk, &binding, &mut Vec::new())?;
        require(
            state.disk_attributes == 0,
            "NTFS preparation needs online writable source",
        )?;
        control(&disk, IS_DISK_WRITABLE, &[], 0)?;
        let volume = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .open(binding.volume_path()?)?;
        binding.validate_volume_extent(&control(&volume, GET_VOLUME_EXTENTS, &[], 32)?)?;
        filesystem_is_writable_ntfs(&volume)?;
        let geometry = geometry(&volume, &binding)?;
        require(
            geometry.ntfs_serial == expected_ntfs_serial
                && geometry.cluster_bytes == expected_cluster_bytes,
            "actual NTFS serial/cluster geometry differs from root inventory",
        )?;
        let value = Self {
            disk,
            volume,
            binding,
            state,
            geometry,
            budget,
            moves,
            attempted_moves: 0,
            attempted_bytes: 0,
            poisoned: false,
            privileges,
            payer,
            _memory: memory,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub fn geometry(&self) -> VolumeGeometry {
        self.geometry
    }
    pub fn binding(&self) -> &GeneralDiskBinding {
        &self.binding
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    fn revalidate(&self) -> io::Result<()> {
        exclude_running_windows_disk(self.binding.disk_number)?;
        let state = native::general_disk_state(&self.disk, &self.binding, &mut Vec::new())?;
        require(
            state == self.state && state.disk_attributes == 0,
            "NTFS source physical route/layout/state changed",
        )?;
        control(&self.disk, IS_DISK_WRITABLE, &[], 0)?;
        self.binding.validate_volume_extent(&control(
            &self.volume,
            GET_VOLUME_EXTENTS,
            &[],
            32,
        )?)?;
        filesystem_is_writable_ntfs(&self.volume)?;
        require(
            geometry(&self.volume, &self.binding)? == self.geometry,
            "NTFS source geometry/serial changed",
        )
    }
    pub fn open_file(&mut self, identity: FileIdentity, eof: u64) -> io::Result<OpenedFile<'_>> {
        require(!self.poisoned, "NTFS source owner poisoned; no retry")?;
        self.revalidate()?;
        require(
            (16..=RECORD_MASK).contains(&identity.record_number) && identity.sequence_number != 0,
            "system/invalid NTFS FILE identity",
        )?;
        let mut memory = self.payer.reserve(memory::query_bytes(self.budget)?)?;
        let descriptor = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: identity.reference() as i64,
            },
        };
        // SAFETY: same held NTFS volume and initialized FILE_ID descriptor;
        // unnamed DATA, no creation/reparse traversal, no share-write/delete.
        let handle = unsafe {
            OpenFileById(
                self.volume.as_raw_handle(),
                &descriptor,
                0xc000_0080,
                1,
                ptr::null(),
                0x0020_0000,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: newly owned native handle is transferred exactly once.
        let file = unsafe { File::from_raw_handle(handle) };
        identity_matches(
            &file_storage::file_id_info(&file)?,
            &identity,
            self.geometry.ntfs_serial,
        )?;
        ordinary(
            information(&file)?,
            eof,
            self.binding.identity.partition_bytes,
        )?;
        let mut overlapped = OVERLAPPED::default();
        // SAFETY: synchronous live file; exclusive whole-file byte lock,
        // immediate refusal. File drop releases the lock on every path.
        if unsafe {
            LockFileEx(
                file.as_raw_handle(),
                3,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let info = information(&file)?;
        ordinary(info, eof, self.binding.identity.partition_bytes)?;
        let map = capture(&file, self.budget)?;
        validate(&map, info, self.geometry, self.budget)?;
        drop(map);
        self.revalidate()?;
        memory.shrink_to(4096 + self.payer.lease_heap_bytes())?;
        Ok(OpenedFile {
            file,
            identity,
            eof,
            source: self,
            _memory: memory,
        })
    }
    pub fn finish(mut self) -> io::Result<LeasedPreparationCompletion> {
        // Preserve actual attempt counters and bounded diagnostics even when
        // the last live route/geometry/NTFS check fails. Privilege restoration
        // is attempted independently on every completion path.
        let source_validation_error = self
            .revalidate()
            .err()
            .map(|e| bounded_error("completion source validation", &e));
        let privilege_restore_error = self
            .privileges
            .restore()
            .err()
            .map(|e| bounded_error("completion privilege restoration", &e));
        self.poisoned |= source_validation_error.is_some() || privilege_restore_error.is_some();
        let value = PreparationCompletion {
            privilege_states: self.privileges.audit().to_vec(),
            attempted_moves: self.attempted_moves,
            attempted_payload_bytes: self.attempted_bytes,
            source_revalidated: source_validation_error.is_none(),
            source_validation_error,
            privileges_restored: privilege_restore_error.is_none(),
            privilege_restore_error,
            verified: !self.poisoned,
            source_owner_poisoned: self.poisoned,
            source_admitted: false,
        };
        Ok(LeasedPreparationCompletion {
            value,
            _memory: self._memory,
        })
    }
}

impl OpenedFile<'_> {
    pub fn observe(&mut self) -> io::Result<LeasedFileObservation> {
        self.observe_with_runs(|_| Ok(()))
    }
    pub fn observe_with_runs(
        &mut self,
        mut emit: impl FnMut(Run) -> io::Result<()>,
    ) -> io::Result<LeasedFileObservation> {
        require(!self.source.poisoned, "NTFS source owner poisoned")?;
        let memory = self
            .source
            .payer
            .reserve(memory::query_bytes(self.source.budget)?)?;
        self.source.revalidate()?;
        let id = file_storage::file_id_info(&self.file)?;
        identity_matches(&id, &self.identity, self.source.geometry.ntfs_serial)?;
        let info = information(&self.file)?;
        ordinary(info, self.eof, self.source.binding.identity.partition_bytes)?;
        let map = capture(&self.file, self.source.budget)?;
        validate(&map, info, self.source.geometry, self.source.budget)?;
        for run in &map.runs {
            emit(run.clone())?;
        }
        require(
            file_storage::file_id_info(&self.file)? == id && information(&self.file)? == info,
            "held NTFS file changed during current-map emission",
        )?;
        self.source.revalidate()?;
        Ok(LeasedFileObservation {
            value: FileObservation {
                file_id_info: Some(id),
                information: Some(info),
                mapping: Some(mapping_observation(map)),
                errors: Vec::new(),
            },
            _memory: memory,
        })
    }

    pub fn move_clusters_with_reservation(
        &mut self,
        request: &MoveRequest,
        mut before_submit: impl FnMut(u64) -> io::Result<()>,
    ) -> io::Result<LeasedMoveObservation> {
        let source = &mut self.source;
        require(!source.poisoned, "NTFS source poisoned; no retry")?;
        source.revalidate()?;
        let count = u64::from(request.cluster_count);
        let cluster = u64::from(source.geometry.cluster_bytes);
        let end = request
            .starting_vcn
            .checked_add(count)
            .ok_or_else(|| invalid("move VCN overflow"))?;
        let dst_end = request
            .destination_lcn
            .checked_add(count)
            .ok_or_else(|| invalid("move destination overflow"))?;
        let src_end = request
            .expected_source_lcn
            .checked_add(count)
            .ok_or_else(|| invalid("move source overflow"))?;
        let next_moves = source
            .attempted_moves
            .checked_add(1)
            .ok_or_else(|| invalid("move count overflow"))?;
        let next_bytes = source
            .attempted_bytes
            .checked_add(request.length_bytes)
            .ok_or_else(|| invalid("move bytes overflow"))?;
        require(
            request.identity == self.identity
                && request.expected_logical_bytes == self.eof
                && count > 0
                && request.cluster_count
                    <= maximum_clusters_per_move(source.budget, source.geometry.cluster_bytes)?
                && count.checked_mul(cluster) == Some(request.length_bytes)
                && request.length_bytes <= source.moves.maximum_move_bytes
                && next_moves <= source.moves.maximum_moves
                && next_bytes <= source.moves.maximum_total_move_bytes
                && end.checked_mul(cluster).is_some_and(|n| n <= self.eof)
                && src_end <= source.geometry.total_clusters
                && dst_end <= source.geometry.total_clusters
                && (src_end <= request.destination_lcn || dst_end <= request.expected_source_lcn),
            "NTFS move hint/EOF/domain/separation/operational budget differs",
        )?;
        let window = memory::window_limits(request.cluster_count, source.budget)?;
        let memory = source
            .payer
            .reserve(memory::move_bytes(source.budget, window)?)?;
        let id = file_storage::file_id_info(&self.file)?;
        identity_matches(&id, &self.identity, source.geometry.ntfs_serial)?;
        let info = information(&self.file)?;
        ordinary(info, self.eof, source.binding.identity.partition_bytes)?;
        let before_map = capture(&self.file, source.budget)?;
        validate(&before_map, info, source.geometry, source.budget)?;
        require(
            maps_to(
                &before_map.runs,
                request.starting_vcn,
                end,
                request.expected_source_lcn,
            ),
            "actual complete NTFS map differs from requested source LCN",
        )?;
        let destination = bitmap_window_native::capture(
            &source.volume,
            bitmap_window::Request {
                volume_clusters: source.geometry.total_clusters,
                starting_lcn: request.destination_lcn,
                clusters: count,
            },
            &[0; 8],
            window,
        )?;
        require(
            destination.allocated_clusters() == 0,
            "actual NTFS destination window is not entirely free",
        )?;
        let before = FileObservation {
            file_id_info: Some(id.clone()),
            information: Some(info),
            mapping: Some(MappingObservation {
                canonical: before_map.canonical.clone(),
                proof: before_map.proof.clone(),
            }),
            errors: Vec::new(),
        };
        before_submit(memory::complete_proof_bound(
            source.budget,
            request,
            &before,
            destination.proof(),
        )?)?;
        source.revalidate()?;
        let mut input = [0u8; 32];
        input[..8].copy_from_slice(&(self.file.as_raw_handle() as usize as u64).to_le_bytes());
        input[8..16].copy_from_slice(&request.starting_vcn.to_le_bytes());
        input[16..24].copy_from_slice(&request.destination_lcn.to_le_bytes());
        input[24..28].copy_from_slice(&request.cluster_count.to_le_bytes());
        source.attempted_moves = next_moves;
        source.attempted_bytes = next_bytes;
        source.poisoned = true;
        // The sole mutation is NTFS-owned FSCTL_MOVE_FILE. No raw WriteFile,
        // retry, manual undo, formatter or source-admission path exists here.
        let moved = stream_native::ioctl(&source.volume, MOVE_FILE, &input, 0);
        let flush_error = if moved.native_error.is_none() {
            self.file
                .sync_all()
                .err()
                .map(|e| bounded_error("flush", &e))
        } else {
            None
        };
        let after_id = file_storage::file_id_info(&self.file);
        let after_info = information(&self.file);
        let after_map = capture(&self.file, source.budget);
        let route = source
            .revalidate()
            .err()
            .map(|e| bounded_error("route", &e));
        let identity_ok = after_id.as_ref().is_ok_and(|v| {
            v == &id && identity_matches(v, &self.identity, source.geometry.ntfs_serial).is_ok()
        }) && after_info.as_ref().is_ok_and(|v| {
            *v == info && ordinary(*v, self.eof, source.binding.identity.partition_bytes).is_ok()
        });
        let valid = after_map
            .as_ref()
            .ok()
            .zip(after_info.as_ref().ok())
            .is_some_and(|(map, info)| {
                validate(map, *info, source.geometry, source.budget).is_ok()
            });
        let outside = valid
            && after_map.as_ref().is_ok_and(|map| {
                unchanged_outside(&before_map.runs, &map.runs, request.starting_vcn, end)
            });
        let observed = valid
            && after_map.as_ref().is_ok_and(|map| {
                maps_to(
                    &map.runs,
                    request.starting_vcn,
                    end,
                    request.destination_lcn,
                )
            });
        let verified = moved.native_error.is_none()
            && flush_error.is_none()
            && route.is_none()
            && identity_ok
            && outside
            && observed;
        if verified {
            source.poisoned = false;
        }
        let mut errors = Vec::new();
        let after_id = match after_id {
            Ok(v) => Some(v),
            Err(e) => {
                errors.push(bounded_error("identity", &e));
                None
            }
        };
        let after_info = match after_info {
            Ok(v) => Some(v),
            Err(e) => {
                errors.push(bounded_error("information", &e));
                None
            }
        };
        let after_map = match after_map {
            Ok(v) => Some(mapping_observation(v)),
            Err(e) => {
                errors.push(bounded_error("retrieval", &e));
                None
            }
        };
        Ok(LeasedMoveObservation {
            value: MoveObservation {
                schema_version: 2,
                request: request.clone(),
                submitted: true,
                native_error: moved.native_error,
                flush_error,
                before,
                after: FileObservation {
                    file_id_info: after_id,
                    information: after_info,
                    mapping: after_map,
                    errors,
                },
                destination_free_window: destination.into_proof(),
                post_route_error: route,
                identity_and_eof_unchanged: identity_ok,
                mapping_outside_requested_vcns_unchanged: outside,
                requested_destination_observed: observed,
                verified,
                source_owner_poisoned: source.poisoned,
                attempted_moves: next_moves,
                attempted_payload_bytes: next_bytes,
                source_admitted: false,
                retry_or_undo_performed: false,
            },
            _memory: memory,
        })
    }
}
