//! Sparse targets are constructed from compact, initialized ordinary carriers.
//! Only allocated islands are cloned; logical holes never receive allocation.
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
        ctl(&file, FSCTL_SET_SPARSE, &[1], 0)?;
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
    pub fn finish(self, carrier: Option<unwritten::PrivatePlaceholder>) -> io::Result<File> {
        let expected_carrier = if let Some(mut carrier) = carrier {
            if carrier.logical_length() != self.dense_length
                || carrier.valid_prefix() != self.dense_length
            {
                return Err(invalid("sparse carrier is not completely storage-valid"));
            }
            for part in &self.islands {
                if part.logical + part.length > self.logical_length {
                    let offset = part.dense + self.logical_length.saturating_sub(part.logical);
                    carrier.initialize_at(
                        offset,
                        &vec![0; (part.logical + part.length - self.logical_length) as usize],
                    )?;
                }
            }
            let capture = crate::stream_native::retrieval_capture(carrier.metadata_handle())?;
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
            self.verify_carrier(&capture.runs)?;
            carrier.retire()?;
            Some(capture.runs)
        } else {
            if self.dense_length != 0 {
                return Err(invalid("allocated sparse stream has no carrier"));
            }
            None
        };
        self.file.set_len(self.logical_length)?;
        self.file.sync_all()?;
        if let Some(runs) = expected_carrier {
            self.verify_carrier(&runs)?;
        }
        observe(&self.file, &self.layout, self.logical_length)?;
        Ok(self.file)
    }
    fn verify_carrier(&self, runs: &[stream_layout::Run]) -> io::Result<()> {
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
                if !mapping_matches_run(
                    &target,
                    (island.logical + from - island.dense) / 4096,
                    lcn,
                    u32::try_from((end - from) / 4096).map_err(|_| {
                        invalid("sparse carrier verification range exceeds native cluster count")
                    })?,
                )? {
                    return Err(invalid(
                        "sparse clone does not retain carrier physical mapping",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub expected: SparseLayout,
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
    expected.validate(length)?;
    if layout::u32_at(&info(file, 9, 8)?, 0)? & 0x200 == 0 {
        return Err(invalid("declared sparse stream lacks sparse flag"));
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
        actual_allocated: allocated,
        allocation_matches: true,
        cached_regions,
        storage_regions,
        data_storage_valid: true,
    })
}
