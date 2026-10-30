//! Targets are constructed from compact, initialized ordinary carriers. Sparse
//! targets clone allocated islands only; plain ADS clone a complete dense run.
//! Logical holes never receive allocation and plain stream flags stay plain.
//! Final partial clusters may move when ReFS applies EOF. Their visible bytes
//! are checked separately; padding writes outside EOF are accounted separately.
use super::*;
use crate::sparse_layout::{LogicalRange, SparseLayout};
use windows_sys::Win32::{
    Storage::FileSystem::FILE_DISPOSITION_INFO,
    System::Ioctl::{FSCTL_DUPLICATE_EXTENTS_TO_FILE, FSCTL_SET_SPARSE},
};

#[derive(Clone, Debug)]
pub(super) struct Island {
    pub logical: u64,
    pub dense: u64,
    pub length: u64,
}
pub(super) struct Target {
    pub file: File,
    pub path: String,
    pub logical_length: u64,
    pub layout: SparseLayout,
    pub islands: Vec<Island>,
    pub dense_length: u64,
    pub sparse_mode: bool,
}
pub(super) struct CarrierDirectory {
    pub path: String,
    pub component: String,
    file: File,
    id: Vec<u8>,
}
impl CarrierDirectory {
    pub fn create(root: &str) -> io::Result<Self> {
        let seed = format!(
            "{}-{}-{:?}",
            root,
            std::process::id(),
            std::time::SystemTime::now()
        );
        let component = format!(
            "n2r-sparse-carriers-{}",
            hex::encode(Sha256::digest(seed.as_bytes()))
        );
        let path = format!("{}\\{component}", root.trim_end_matches('\\'));
        let sd = private_tree::private_descriptor()?;
        let mut backing = descriptor(&sd)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: backing.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(wide(&path).as_ptr(), &attrs) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let file = File::options()
            .access_mode(0x011f01ff)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(&path)?;
        validate_open_type(&file, true)?;
        let id = info(&file, 18, 24)?;
        Ok(Self {
            path,
            component,
            file,
            id,
        })
    }
    pub fn retire(self) -> io::Result<()> {
        if info(&self.file, 18, 24)? != self.id
            || enumerate(&self.file)?
                .iter()
                .any(|e| e.name_utf16 != [46] && e.name_utf16 != [46, 46])
        {
            return Err(invalid(
                "sparse carrier directory identity or contents changed",
            ));
        }
        let d = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                4,
                (&d as *const FILE_DISPOSITION_INFO).cast(),
                mem::size_of_val(&d) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(self);
        Ok(())
    }
}

impl Target {
    pub fn create(
        root: &str,
        components: &[String],
        name: &[u16],
        length: u64,
        layout: &SparseLayout,
        base: Option<&File>,
    ) -> io::Result<Self> {
        Self::create_mode(root, components, name, length, layout, base, true)
    }

    /// ReFS may decline an ADS move without reporting an error. Place an
    /// ordinary owned carrier instead, then clone its measured allocation into
    /// the named target while preserving the target's nonsparse stream state.
    pub fn create_plain(
        root: &str,
        components: &[String],
        name: &[u16],
        length: u64,
        base: Option<&File>,
    ) -> io::Result<Self> {
        if name.is_empty() || length < 4096 || base.is_none() {
            return Err(invalid(
                "plain carrier target requires a nonempty allocated ADS",
            ));
        }
        let rounded = length
            .checked_next_multiple_of(4096)
            .ok_or_else(|| invalid("plain ADS EOF overflow"))?;
        let layout = SparseLayout::from_allocated(
            length,
            length,
            vec![LogicalRange {
                offset: 0,
                length: rounded,
            }],
        )?;
        Self::create_mode(root, components, name, length, &layout, base, false)
    }

    fn create_mode(
        root: &str,
        components: &[String],
        name: &[u16],
        length: u64,
        layout: &SparseLayout,
        base: Option<&File>,
        sparse_mode: bool,
    ) -> io::Result<Self> {
        layout.validate(length)?;
        let path = streams::path(root, components, name)?;
        let sd = private_tree::private_descriptor()?;
        let mut backing = descriptor(&sd)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: backing.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        let before = base.map(|f| info(f, 18, 24)).transpose()?;
        let handle = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                0xc0020000,
                0,
                &attrs,
                1,
                0x80200080,
                ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        if let Some(id) = before {
            if info(&file, 18, 24)? != id || info(base.unwrap(), 18, 24)? != id {
                return Err(invalid("sparse ADS differs from its base identity"));
            }
        }
        ctl(&file, 0x9c280, &[0; 8], 0)?;
        if sparse_mode {
            ctl(&file, FSCTL_SET_SPARSE, &[1], 0)?;
        }
        if (layout::u32_at(&info(&file, 9, 8)?, 0)? & 0x200 != 0) != sparse_mode {
            return Err(invalid(
                "carrier target sparse state differs from declared stream",
            ));
        }
        file.set_len(
            length
                .checked_next_multiple_of(4096)
                .ok_or_else(|| invalid("sparse EOF overflow"))?,
        )?;
        let mut dense = 0;
        let mut islands = Vec::new();
        for range in &layout.allocated {
            islands.push(Island {
                logical: range.offset,
                dense,
                length: range.length,
            });
            dense += range.length;
        }
        Ok(Self {
            file,
            path,
            logical_length: length,
            layout: layout.clone(),
            islands,
            dense_length: dense,
            sparse_mode,
        })
    }
    pub fn parts(&self, offset: u64, length: u64, from_dense: bool) -> io::Result<Vec<Island>> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("sparse translation overflow"))?;
        let mut cursor = offset;
        let mut out = Vec::new();
        while cursor < end {
            let island = self
                .islands
                .iter()
                .find(|i| {
                    let start = if from_dense { i.dense } else { i.logical };
                    start <= cursor && cursor < start + i.length
                })
                .ok_or_else(|| invalid("sparse operation overlaps a logical hole"))?;
            let start = if from_dense {
                island.dense
            } else {
                island.logical
            };
            let count = (start + island.length).min(end) - cursor;
            let within = cursor - start;
            out.push(Island {
                logical: island.logical + within,
                dense: island.dense + within,
                length: count,
            });
            cursor += count;
        }
        Ok(out)
    }
    pub fn placement_view<'a>(&self, mut item: Input<'a>) -> io::Result<Input<'a>> {
        let original = if let Some(offset) = item.source_offset {
            vec![SourceRun {
                logical_offset: 0,
                physical_offset: Some(offset),
                length: item.logical_length() / 4096 * 4096,
            }]
        } else {
            item.source_runs.clone()
        };
        let mut runs = Vec::new();
        for run in original {
            for part in self.parts(run.logical_offset, run.length, false)? {
                runs.push(SourceRun {
                    logical_offset: part.dense,
                    physical_offset: run
                        .physical_offset
                        .map(|p| p + part.logical - run.logical_offset),
                    length: part.length,
                });
            }
        }
        runs.sort_by_key(|r| r.logical_offset);
        item.expected_length = Some(self.dense_length);
        item.source_offset = None;
        item.source_runs = runs;
        item.sparse = None;
        Ok(item)
    }
    pub fn finish(
        mut self,
        carrier: Option<unwritten::PrivatePlaceholder>,
    ) -> io::Result<(File, Option<TailProof>)> {
        let mut tail: Option<(u64, u64, Vec<u8>)> = None;
        let mut padding_bytes = 0u64;
        let expected_carrier = if let Some(mut carrier) = carrier {
            if carrier.logical_length() != self.dense_length
                || carrier.valid_prefix() != self.dense_length
            {
                return Err(invalid("sparse carrier is not completely storage-valid"));
            }
            for part in &self.islands {
                if part.logical + part.length > self.logical_length {
                    let offset = part.dense + self.logical_length.saturating_sub(part.logical);
                    let count = part.logical + part.length - self.logical_length;
                    carrier.initialize_at(offset, &vec![0; count as usize])?;
                    padding_bytes = padding_bytes
                        .checked_add(count)
                        .ok_or_else(|| invalid("sparse padding accounting overflow"))?;
                }
            }
            let capture = crate::stream_native::retrieval_capture(carrier.metadata_handle())?;
            let visible = self.logical_length % 4096;
            let tail_start = self.logical_length / 4096 * 4096;
            if visible != 0 {
                if let Some(island) = self
                    .islands
                    .iter()
                    .find(|i| i.logical <= tail_start && tail_start < i.logical + i.length)
                {
                    let dense = island.dense + tail_start - island.logical;
                    let old_lcn = lcn_at(&capture.runs, dense / 4096)?;
                    let mut bytes = vec![0; visible as usize];
                    carrier.read_initialized_at(dense, &mut bytes)?;
                    tail = Some((tail_start, old_lcn, bytes));
                }
            }
            for island in &self.islands {
                let mut done = 0;
                while done < island.length {
                    let n = (island.length - done).min(512 * 1024 * 1024);
                    let mut data = [0; 32];
                    data[..8].copy_from_slice(
                        &(carrier.metadata_handle().as_raw_handle() as usize as u64).to_le_bytes(),
                    );
                    data[8..16].copy_from_slice(&(island.dense + done).to_le_bytes());
                    data[16..24].copy_from_slice(&(island.logical + done).to_le_bytes());
                    data[24..].copy_from_slice(&n.to_le_bytes());
                    ctl(&self.file, FSCTL_DUPLICATE_EXTENTS_TO_FILE, &data, 0)?;
                    done += n;
                }
            }
            self.file.sync_all()?;
            self.verify_carrier(
                &capture.runs,
                "before-carrier-retirement",
                &carrier.path,
                None,
            )?;
            let carrier_path = carrier.path.clone();
            carrier.retire()?;
            Some((capture.runs, carrier_path))
        } else {
            if self.dense_length != 0 {
                return Err(invalid("allocated sparse stream has no carrier"));
            }
            None
        };
        self.file.set_len(self.logical_length)?;
        self.file.sync_all()?;
        if let Some((runs, carrier_path)) = expected_carrier {
            self.verify_carrier(
                &runs,
                "after-final-eof",
                &carrier_path,
                tail.as_ref().map(|(at, _, _)| at / 4096),
            )?;
        }
        let tail_proof = if let Some((offset, old_lcn, expected)) = tail {
            let after = capture(&self.file, self.logical_length)?.0;
            let new_lcn = lcn_at(&after, offset / 4096)?;
            let mut actual = vec![0; expected.len()];
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.read_exact(&mut actual)?;
            if actual != expected {
                return Err(invalid(
                    "partial sparse EOF cluster contents changed after truncation",
                ));
            }
            let carrier_sha256 = hex::encode(Sha256::digest(&expected));
            let target_sha256 = hex::encode(Sha256::digest(&actual));
            Some(TailProof {
                logical_offset: offset,
                visible_bytes: expected.len() as u64,
                old_lcn,
                new_lcn,
                physical_lcn_changed: old_lcn != new_lcn,
                carrier_sha256,
                target_sha256,
                actual_bytes_equal: true,
                payload_bytes_read: 2 * expected.len() as u64,
                padding_bytes_written: padding_bytes,
                padding_bytes_readback: padding_bytes,
            })
        } else {
            None
        };
        observe_mode(
            &self.file,
            &self.layout,
            self.logical_length,
            self.sparse_mode,
        )?;
        Ok((self.file, tail_proof))
    }
    fn verify_carrier(
        &self,
        runs: &[stream_layout::Run],
        phase: &str,
        carrier_path: &str,
        permitted_partial_vcn: Option<u64>,
    ) -> io::Result<()> {
        if let Some(vcn) = permitted_partial_vcn {
            if phase != "after-final-eof"
                || self.logical_length % 4096 == 0
                || vcn != self.logical_length / 4096
                || !self
                    .layout
                    .allocated
                    .iter()
                    .any(|r| r.offset / 4096 <= vcn && vcn < (r.offset + r.length) / 4096)
            {
                return Err(invalid(
                    "invalid sparse partial-cluster verification exception",
                ));
            }
        }
        let target = capture(&self.file, self.logical_length)?.0;
        for island in &self.islands {
            for run in runs {
                let from = (run.vcn * 4096).max(island.dense);
                let end = ((run.vcn + run.clusters) * 4096).min(island.dense + island.length);
                if from >= end {
                    continue;
                }
                let lcn = run
                    .lcn
                    .ok_or_else(|| invalid("sparse carrier contains a hole"))?
                    + (from / 4096 - run.vcn);
                let original_target_vcn = (island.logical + from - island.dense) / 4096;
                let original_target_end = original_target_vcn + (end - from) / 4096;
                let segments = if let Some(vcn) = permitted_partial_vcn
                    .filter(|vcn| original_target_vcn <= *vcn && *vcn < original_target_end)
                {
                    vec![(original_target_vcn, vcn), (vcn + 1, original_target_end)]
                } else {
                    vec![(original_target_vcn, original_target_end)]
                };
                for (target_vcn, target_end) in segments {
                    if target_vcn == target_end {
                        continue;
                    }
                    let lcn = lcn + target_vcn - original_target_vcn;
                    let clusters = u32::try_from(target_end - target_vcn).map_err(|_| {
                        invalid("sparse carrier verification range exceeds native cluster count")
                    })?;
                    if !mapping_matches_run(&target, target_vcn, lcn, clusters)? {
                        let target_end = target_vcn + u64::from(clusters);
                        let overlaps = |actual: &&stream_layout::Run| {
                            actual.vcn < target_end && target_vcn < actual.vcn + actual.clusters
                        };
                        let relevant_count = target.iter().filter(overlaps).count();
                        let actual_runs: Vec<_> = target.iter().filter(overlaps).take(16).map(|actual| {
                        serde_json::json!({"vcn":actual.vcn,"clusters":actual.clusters,"lcn":actual.lcn})
                    }).collect();
                        let first = target.iter().find(|actual| {
                            actual.vcn <= target_vcn && target_vcn < actual.vcn + actual.clusters
                        });
                        let context = serde_json::json!({
                            "phase":phase,
                            "target_path":self.path.chars().take(1024).collect::<String>(),
                            "target_path_sha256":hex::encode(Sha256::digest(self.path.as_bytes())),
                            "target_logical_bytes":self.logical_length,
                            "target_standard_info_hex":info(&self.file,1,24).ok().map(hex::encode),
                            "target_file_id_info_hex":info(&self.file,18,24).ok().map(hex::encode),
                            "carrier_path":carrier_path.chars().take(1024).collect::<String>(),
                            "carrier_dense_bytes":self.dense_length,
                            "carrier_run":{"vcn":run.vcn,"clusters":run.clusters,"lcn":run.lcn},
                            "island":{"logical_offset":island.logical,"carrier_offset":island.dense,"length":island.length},
                            "target_vcn":target_vcn,"clusters":clusters,"expected_lcn":lcn,
                            "first_actual_run_present":first.is_some(),
                            "first_actual_lcn":first.and_then(|r|r.lcn.map(|base|base+target_vcn-r.vcn)),
                            "actual_relevant_runs":actual_runs,"actual_relevant_run_count":relevant_count,
                            "actual_runs_truncated":relevant_count>16,
                        });
                        return Err(invalid(&format!(
                            "sparse clone does not retain carrier physical mapping: {context}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

fn lcn_at(runs: &[stream_layout::Run], vcn: u64) -> io::Result<u64> {
    let run = runs
        .iter()
        .find(|r| r.vcn <= vcn && vcn < r.vcn + r.clusters)
        .ok_or_else(|| invalid("partial sparse EOF cluster is absent"))?;
    run.lcn
        .and_then(|l| l.checked_add(vcn - run.vcn))
        .ok_or_else(|| invalid("partial sparse EOF cluster is unallocated or overflows"))
}

#[derive(Debug, Serialize)]
pub(super) struct TailProof {
    pub logical_offset: u64,
    pub visible_bytes: u64,
    pub old_lcn: u64,
    pub new_lcn: u64,
    pub physical_lcn_changed: bool,
    pub carrier_sha256: String,
    pub target_sha256: String,
    pub actual_bytes_equal: bool,
    pub payload_bytes_read: u64,
    /// Carrier bytes outside the user-visible EOF, written and read back before cloning.
    pub padding_bytes_written: u64,
    pub padding_bytes_readback: u64,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    /// Source sparse contract. Its initialized_length is the NTFS source VDL,
    /// not a measured ReFS VDL and not a promise of numeric VDL preservation.
    pub expected: SparseLayout,
    pub source_initialized_length: u64,
    pub numeric_vdl_preservation_claimed: bool,
    /// Allocated bytes beyond the source VDL are supplied by the source's
    /// logical-zero reader and verified by the separate final stream digest.
    pub logical_zero_policy: &'static str,
    pub layout_observation_verifies_logical_zero_bytes: bool,
    pub actual_allocated: Vec<LogicalRange>,
    pub allocation_matches: bool,
    pub cached_regions: Vec<crate::attestation::IoctlQuery>,
    pub storage_regions: Vec<crate::attestation::IoctlQuery>,
    pub data_storage_valid: bool,
}
pub(super) fn capture(
    file: &File,
    length: u64,
) -> io::Result<(
    Vec<stream_layout::Run>,
    Option<crate::retrieval_paging::Capture>,
)> {
    let (first, more) = crate::stream_native::retrieval_queries(file);
    if first.native_error == Some(38)
        && first.bytes.is_empty()
        && more.is_empty()
        && layout::u64_at(&info(file, 1, 24)?, 0)? == 0
    {
        return Ok((Vec::new(), None));
    }
    if first.native_error.is_none()
        && first.bytes.len() == 16
        && layout::u32_at(&first.bytes, 0)? == 0
        && length == 0
    {
        return Ok((Vec::new(), None));
    }
    let cap = crate::retrieval_paging::assemble_queries(&first, &more)?;
    Ok((cap.runs.clone(), Some(cap)))
}
fn regions(
    file: &File,
    ranges: &[LogicalRange],
    length: u64,
    usage: u32,
) -> io::Result<Vec<crate::attestation::IoctlQuery>> {
    let mut result = Vec::new();
    for range in ranges {
        let end = (range.offset + range.length).min(length);
        if end <= range.offset {
            continue;
        }
        let mut input = [0; 24];
        input[..8].copy_from_slice(&range.offset.to_le_bytes());
        input[8..16].copy_from_slice(&(end - range.offset).to_le_bytes());
        input[16..20].copy_from_slice(&usage.to_le_bytes());
        let q = crate::stream_native::ioctl(file, 0x90284, &input, 16 + 24 * 1024);
        let b = &q.bytes;
        if q.native_error.is_some() || b.len() < 16 {
            return Err(invalid("sparse data validity query refused"));
        }
        let n = layout::u32_at(b, 8)? as usize;
        if n == 0 || n > 1024 || layout::u32_at(b, 4)? as usize != n || b.len() != 16 + 24 * n {
            return Err(invalid("sparse validity query incomplete"));
        }
        let mut cursor = range.offset;
        for row in b[16..].chunks_exact(24) {
            let at = layout::u64_at(row, 0)?;
            let stop = at
                .checked_add(layout::u64_at(row, 8)?)
                .ok_or_else(|| invalid("sparse validity range overflow"))?;
            if stop <= cursor || at >= end {
                continue;
            }
            if at > cursor || layout::u32_at(row, 16)? & usage == 0 {
                return Err(invalid("sparse allocated data is not storage-valid"));
            }
            cursor = stop.min(end);
        }
        if cursor != end {
            return Err(invalid("sparse data validity coverage incomplete"));
        }
        result.push(q);
    }
    Ok(result)
}
pub(super) fn observe(
    file: &File,
    expected: &SparseLayout,
    length: u64,
) -> io::Result<Observation> {
    observe_mode(file, expected, length, true)
}

fn observe_mode(
    file: &File,
    expected: &SparseLayout,
    length: u64,
    sparse_mode: bool,
) -> io::Result<Observation> {
    expected.validate(length)?;
    if (layout::u32_at(&info(file, 9, 8)?, 0)? & 0x200 != 0) != sparse_mode {
        return Err(invalid("observed carrier target sparse state differs"));
    }
    let (runs, _) = capture(file, length)?;
    let rounded = length
        .checked_next_multiple_of(4096)
        .ok_or_else(|| invalid("sparse EOF overflow"))?;
    let mut allocated: Vec<LogicalRange> = Vec::new();
    for run in runs.iter().filter(|r| r.lcn.is_some()) {
        let start = run
            .vcn
            .checked_mul(4096)
            .ok_or_else(|| invalid("sparse VCN overflow"))?;
        let end = (run.vcn + run.clusters)
            .checked_mul(4096)
            .ok_or_else(|| invalid("sparse run overflow"))?
            .min(rounded);
        if start >= end {
            continue;
        }
        if let Some(last) = allocated.last_mut()
            && last.offset + last.length == start
        {
            last.length = end - last.offset
        } else {
            allocated.push(LogicalRange {
                offset: start,
                length: end - start,
            });
        }
    }
    if allocated != expected.allocated {
        return Err(invalid(
            "native sparse allocation differs from source islands",
        ));
    }
    let cached_regions = regions(file, &allocated, length, 1)?;
    let storage_regions = regions(file, &allocated, length, 2)?;
    Ok(Observation {
        expected: expected.clone(),
        source_initialized_length: expected.initialized_length,
        numeric_vdl_preservation_claimed: false,
        logical_zero_policy: "source_uninitialized_allocated_bytes_are_normalized_from_logical_zero_reads; final_full_stream_digest_required",
        layout_observation_verifies_logical_zero_bytes: false,
        actual_allocated: allocated,
        allocation_matches: true,
        cached_regions,
        storage_regions,
        data_storage_valid: true,
    })
}
