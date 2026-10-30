//! Bounded, private sparse-carrier experiment on an empty disposable ReFS
//! volume. No converter admission or existing source file enters this module.
use super::*;
use crate::{attestation::IoctlQuery, general_layout::GeneralDiskBinding};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
    Storage::FileSystem::{FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileValidData},
    System::Ioctl::{
        FSCTL_DUPLICATE_EXTENTS_TO_FILE, FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_SPARSE,
    },
};

const CARRIER_BYTES: u64 = 16 * 1024;
const TARGET_BYTES: u64 = 256 * 1024 * 1024;
const TARGET_OFFSETS: [u64; 2] = [64 * 1024 * 1024, 128 * 1024 * 1024];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub kind: String,
    pub binding: GeneralDiskBinding,
    pub probe_id: String,
}
impl Request {
    pub fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        if self.schema_version != 1
            || self.kind != "sparse-carrier-probe-request"
            || self.binding.disk_number == 1
            || self.binding.identity.partition_bytes < TARGET_BYTES
            || self.binding.identity.logical_sector_bytes != 512
            || self.binding.identity.physical_sector_bytes != 4096
            || self.probe_id.len() != 32
            || !self
                .probe_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("bounded sparse-carrier request differs"));
        }
        Ok(())
    }
}

#[derive(Default, Serialize)]
struct Counts {
    payload_bytes_read: u64,
    carrier_payload_bytes_written: u64,
    target_payload_bytes_written: u64,
}
fn read_at(file: &mut File, offset: u64, bytes: &mut [u8], counts: &mut Counts) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    let mut done = 0;
    while done < bytes.len() {
        let n = file.read(&mut bytes[done..])?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        done += n;
        counts.payload_bytes_read += n as u64;
    }
    Ok(())
}
fn write_carrier(file: &mut File, bytes: &[u8], counts: &mut Counts) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut done = 0;
    while done < bytes.len() {
        let n = file.write(&bytes[done..])?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        done += n;
        counts.carrier_payload_bytes_written += n as u64;
    }
    Ok(())
}
fn private_descriptor() -> io::Result<Vec<u8>> {
    let text = wide("O:SYG:SYD:P(A;;FA;;;SY)");
    let mut ptr = ptr::null_mut();
    let mut size = 0;
    // SAFETY: constant SDDL and bounded allocated output returned by Windows.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut ptr, &mut size)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = if (20..=65536).contains(&size) {
        Ok(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), size as usize) }.to_vec())
    } else {
        Err(invalid("private probe descriptor size differs"))
    };
    unsafe { LocalFree(ptr) };
    result
}
fn new_file(path: &str, sd: &[u8], delete: bool) -> io::Result<File> {
    let mut sd = descriptor(sd)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    let name = wide(path);
    // SAFETY: fresh bounded path and private descriptor. CREATE_NEW and no
    // sharing prevent overwriting or replacing an existing file.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0xc0020000 | if delete { 0x10000 } else { 0 },
            0,
            &sa,
            1,
            0x80200080,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}
fn query(file: &File, code: u32, input: &[u8], capacity: usize) -> IoctlQuery {
    crate::stream_native::ioctl(file, code, input, capacity)
}
fn storage_check(file: &File, offset: u64, length: u64) -> io::Result<IoctlQuery> {
    let mut input = [0; 24];
    input[..8].copy_from_slice(&offset.to_le_bytes());
    input[8..16].copy_from_slice(&length.to_le_bytes());
    input[16..20].copy_from_slice(&2u32.to_le_bytes());
    let q = query(file, 0x90284, &input, 16 + 24 * 1024);
    let b = &q.bytes;
    if q.native_error.is_some() || b.len() < 16 {
        return Err(invalid("storage validity query refused"));
    }
    let count = layout::u32_at(b, 8)? as usize;
    if count == 0
        || count > 1024
        || layout::u32_at(b, 4)? as usize != count
        || b.len() != 16 + 24 * count
    {
        return Err(invalid("storage validity response incomplete"));
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("storage interval overflow"))?;
    let mut cursor = offset;
    for row in b[16..].chunks_exact(24) {
        let at = layout::u64_at(row, 0)?;
        let n = layout::u64_at(row, 8)?;
        let stop = at
            .checked_add(n)
            .ok_or_else(|| invalid("storage region overflow"))?;
        let usage = layout::u32_at(row, 16)?;
        if n == 0 || usage & !31 != 0 {
            return Err(invalid("storage region shape differs"));
        }
        if stop <= cursor || at >= end {
            continue;
        }
        if at > cursor || usage & 2 == 0 {
            return Err(invalid("cloned range is not storage-valid"));
        }
        cursor = stop.min(end);
    }
    if cursor != end {
        return Err(invalid("storage validity coverage is incomplete"));
    }
    Ok(q)
}
fn observation(file: &File, length: u64) -> serde_json::Value {
    let (first, continuation) = crate::stream_native::retrieval_queries(file);
    let assembled = crate::retrieval_paging::assemble_queries(&first, &continuation);
    let mut region = [0; 24];
    region[8..16].copy_from_slice(&length.to_le_bytes());
    region[16..20].copy_from_slice(&1u32.to_le_bytes());
    let cached = query(file, 0x90284, &region, 16 + 24 * 1024);
    region[16..20].copy_from_slice(&2u32.to_le_bytes());
    let storage = query(file, 0x90284, &region, 16 + 24 * 1024);
    let mut range = [0; 16];
    range[8..16].copy_from_slice(&length.to_le_bytes());
    serde_json::json!({"snapshot":snapshot(file),"retrieval_first":first,"retrieval_continuation":continuation,
        "assembled_retrieval":assembled.as_ref().ok().map(|c|&c.canonical),"retrieval_page_proof":assembled.as_ref().ok().map(|c|&c.proof),
        "retrieval_error":assembled.err().map(|e|e.to_string()),"cached_regions":cached,"storage_regions":storage,
        "allocated_ranges":query(file,FSCTL_QUERY_ALLOCATED_RANGES,&range,16*1024),"integrity":query(file,0x9027c,&[],16)})
}
fn mapped(runs: &[stream_layout::Run], vcn: u64) -> io::Result<Option<u64>> {
    let run = runs
        .iter()
        .find(|r| r.vcn <= vcn && r.vcn + r.clusters > vcn)
        .ok_or_else(|| invalid("probe map has a logical gap"))?;
    run.lcn
        .map(|l| {
            l.checked_add(vcn - run.vcn)
                .ok_or_else(|| invalid("probe physical mapping overflow"))
        })
        .transpose()
}
fn placement(
    carrier: &[stream_layout::Run],
    target: &[stream_layout::Run],
) -> io::Result<serde_json::Value> {
    // A complete sparse retrieval reply may stop at the last allocated run;
    // standard EOF and sampled zeros independently cover the unallocated tail.
    let mut allocated = 0;
    for run in target.iter().filter(|r| r.lcn.is_some()) {
        let start = run.vcn * 4096;
        let end = (run.vcn + run.clusters) * 4096;
        if !TARGET_OFFSETS
            .iter()
            .any(|o| start >= *o && end <= *o + CARRIER_BYTES)
        {
            return Err(invalid("target allocates outside cloned data ranges"));
        }
        allocated += run.clusters * 4096;
    }
    if allocated != 2 * CARRIER_BYTES {
        return Err(invalid("sparse target allocated-byte total differs"));
    }
    for offset in TARGET_OFFSETS {
        for cluster in 0..CARRIER_BYTES / 4096 {
            let source = mapped(carrier, cluster)?;
            if source.is_none() || mapped(target, offset / 4096 + cluster)? != source {
                return Err(invalid("cloned physical extent differs from carrier"));
            }
        }
    }
    Ok(
        serde_json::json!({"logical_bytes":TARGET_BYTES,"allocated_mapping_bytes":allocated,"shared_physical_bytes":CARRIER_BYTES,"same_physical_clusters":true,"hole_mapping_verified":true}),
    )
}
fn verify_data(
    target: &mut File,
    expected: &str,
    counts: &mut Counts,
) -> io::Result<serde_json::Value> {
    let mut data = vec![0; CARRIER_BYTES as usize];
    let mut copied = Vec::new();
    for offset in TARGET_OFFSETS {
        read_at(target, offset, &mut data, counts)?;
        let hash = hex::encode(Sha256::digest(&data));
        if hash != expected {
            return Err(invalid("cloned target data differs from carrier"));
        }
        copied.push(serde_json::json!({"offset":offset,"bytes":CARRIER_BYTES,"sha256":hash}));
    }
    let mut holes = Vec::new();
    let mut zeros = [0u8; 4096];
    for offset in [
        0,
        4096,
        TARGET_OFFSETS[0] - 4096,
        TARGET_OFFSETS[0] + CARRIER_BYTES,
        96 * 1024 * 1024,
        TARGET_OFFSETS[1] - 4096,
        TARGET_OFFSETS[1] + CARRIER_BYTES,
        TARGET_BYTES - 4096,
    ] {
        read_at(target, offset, &mut zeros, counts)?;
        if zeros.iter().any(|b| *b != 0) {
            return Err(invalid("sparse hole did not read as zero"));
        }
        holes.push(offset);
    }
    Ok(
        serde_json::json!({"cloned_data":copied,"zero_hole_sample_offsets":holes,"zero_hole_sample_bytes":4096}),
    )
}

/// Only newly created private files on the explicitly selected empty ReFS
/// volume are modified. The sole deletion targets the still-held carrier.
pub fn run(request: &Request) -> io::Result<serde_json::Value> {
    request.validate()?;
    if std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11") {
        return Err(invalid("disposable owning guest required"));
    }
    let mut events = Vec::new();
    let before = native::probe_general(request.binding.clone(), &mut events)?;
    if native::mounted_filesystem_general(request.binding.clone(), &mut events)? != "ReFS" {
        return Err(invalid("sparse probe target must be ReFS"));
    }
    let volume = native::device_file(&request.binding.volume_path()?, true, false)?;
    query_refs_314_volume_data(&volume, request.binding.identity.partition_bytes)?;
    let root = format!("{}\\", request.binding.volume_path()?);
    let mut privilege = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
    ])?;
    let root_handle = open(&root, true, true)?;
    if enumerate(&root_handle)?.iter().any(|e| {
        e.name_utf16 != [46]
            && e.name_utf16 != [46, 46]
            && !(e.name_utf16
                == "System Volume Information"
                    .encode_utf16()
                    .collect::<Vec<_>>()
                && e.attributes & 16 != 0
                && e.attributes & 0x400 == 0)
    }) {
        return Err(invalid("fresh empty disposable ReFS volume required"));
    }
    let directory = format!("{root}n2r-sparse-carrier-{}", request.probe_id);
    let carrier_path = format!("{directory}\\carrier.bin");
    let target_path = format!("{directory}\\sparse-target.bin");
    let private = private_descriptor()?;
    let mut sd = descriptor(&private)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    let dir = wide(&directory);
    if unsafe { CreateDirectoryW(dir.as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let directory_handle = open(&directory, true, true)?;
    let mut counts = Counts::default();
    let mut carrier: Option<File> = None;
    let mut report = serde_json::json!({"schema_version":1,"kind":"private-sparse-carrier-probe","request":request,
        "directory":directory,"carrier_path":carrier_path,"target_path":target_path,"before":before,
        "success":false,"error":null,"carrier_retired":false,"target_retained":true,
        "source_write_requests":0,"raw_device_writes":0,"conversion_qualified":false,"sparse_conversion_supported":false});
    let result = (|| -> io::Result<()> {
        carrier = Some(new_file(&carrier_path, &private, true)?);
        let c = carrier.as_mut().unwrap();
        ctl(c, 0x9c280, &[0; 8], 0)?;
        if layout::u32_at(&info(c, 9, 8)?, 0)? & 0x200 != 0 {
            return Err(invalid("carrier must remain non-sparse"));
        }
        let allocation = CARRIER_BYTES;
        if unsafe {
            SetFileInformationByHandle(c.as_raw_handle(), 5, (&allocation as *const u64).cast(), 8)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        c.set_len(CARRIER_BYTES)?;
        if unsafe { SetFileValidData(c.as_raw_handle(), CARRIER_BYTES as i64) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sentinel: [u8; 64] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(0x5a));
        write_carrier(c, &sentinel, &mut counts)?;
        c.sync_all()?;
        let carrier_identity = info(c, 18, 24)?;
        let mut carrier_data = vec![0; CARRIER_BYTES as usize];
        read_at(c, 0, &mut carrier_data, &mut counts)?;
        let carrier_hash = hex::encode(Sha256::digest(&carrier_data));
        let carrier_capture = crate::stream_native::retrieval_capture(c)?;
        report["carrier_storage_validity"] =
            serde_json::to_value(storage_check(c, 0, CARRIER_BYTES)?).map_err(io::Error::other)?;
        report["carrier_sha256"] = carrier_hash.clone().into();
        report["carrier_before"] = observation(c, CARRIER_BYTES);
        let mut target = new_file(&target_path, &private, false)?;
        ctl(&target, 0x9c280, &[0; 8], 0)?;
        let sparse = query(&target, FSCTL_SET_SPARSE, &[1], 0);
        report["set_sparse"] = serde_json::to_value(&sparse).map_err(io::Error::other)?;
        if sparse.native_error.is_some() {
            return Err(invalid("native SetSparse refused"));
        }
        if layout::u32_at(&info(&target, 9, 8)?, 0)? & 0x200 == 0 {
            return Err(invalid("target must be sparse before cloning"));
        }
        target.set_len(TARGET_BYTES)?;
        target.sync_all()?;
        report["target_before_clone"] = observation(&target, TARGET_BYTES);
        let mut clones = Vec::new();
        for offset in TARGET_OFFSETS {
            let mut data = [0; 32];
            data[..8].copy_from_slice(&(c.as_raw_handle() as usize as u64).to_le_bytes());
            data[16..24].copy_from_slice(&offset.to_le_bytes());
            data[24..32].copy_from_slice(&CARRIER_BYTES.to_le_bytes());
            let q = query(&target, FSCTL_DUPLICATE_EXTENTS_TO_FILE, &data, 0);
            let ok = q.native_error.is_none();
            clones.push(q);
            report["clone_calls"] = serde_json::to_value(&clones).map_err(io::Error::other)?;
            if !ok {
                return Err(invalid("native non-sparse to sparse clone refused"));
            }
        }
        target.sync_all()?;
        report["target_after_clone"] = observation(&target, TARGET_BYTES);
        let target_capture = crate::stream_native::retrieval_capture(&target)?;
        report["placement_before_retire"] = placement(&carrier_capture.runs, &target_capture.runs)?;
        report["data_before_retire"] = verify_data(&mut target, &carrier_hash, &mut counts)?;
        report["cloned_storage_validity_before_retire"] = serde_json::to_value(
            TARGET_OFFSETS
                .iter()
                .map(|offset| storage_check(&target, *offset, CARRIER_BYTES))
                .collect::<io::Result<Vec<_>>>()?,
        )
        .map_err(io::Error::other)?;
        if info(c, 18, 24)? != carrier_identity || layout::u32_at(&info(c, 1, 24)?, 16)? != 1 {
            return Err(invalid("owned carrier identity changed before retirement"));
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                c.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                mem::size_of_val(&disposition) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(carrier.take());
        if enumerate(&directory_handle)?
            .iter()
            .any(|e| e.name_utf16 == "carrier.bin".encode_utf16().collect::<Vec<_>>())
        {
            return Err(invalid("owned carrier remains after native deletion"));
        }
        report["carrier_retired"] = true.into();
        target.sync_all()?;
        volume.sync_all()?;
        let after_capture = crate::stream_native::retrieval_capture(&target)?;
        report["placement_after_retire"] = placement(&carrier_capture.runs, &after_capture.runs)?;
        report["data_after_retire"] = verify_data(&mut target, &carrier_hash, &mut counts)?;
        report["cloned_storage_validity_after_retire"] = serde_json::to_value(
            TARGET_OFFSETS
                .iter()
                .map(|offset| storage_check(&target, *offset, CARRIER_BYTES))
                .collect::<io::Result<Vec<_>>>()?,
        )
        .map_err(io::Error::other)?;
        report["target_after_retire"] = observation(&target, TARGET_BYTES);
        if layout::u32_at(&info(&target, 9, 8)?, 0)? & 0x200 == 0 {
            return Err(invalid("target sparse attribute absent"));
        }
        report["success"] = true.into();
        Ok(())
    })();
    if let Err(error) = result {
        report["error"] = error.to_string().into();
    }
    report["io_counts"] = serde_json::to_value(counts).map_err(io::Error::other)?;
    let after = native::probe_general(request.binding.clone(), &mut events)?;
    let after = serde_json::to_value(after).map_err(io::Error::other)?;
    if report["before"] != after {
        report["success"] = false.into();
        report["error"] = "probe storage identity or state changed".into();
    }
    report["after"] = after;
    privilege.restore()?;
    report["privileges"] = serde_json::to_value(privilege.audit()).map_err(io::Error::other)?;
    report["events"] = serde_json::to_value(events).map_err(io::Error::other)?;
    if serde_json::to_vec(&report).map_err(io::Error::other)?.len() > 1024 * 1024 {
        return Err(invalid("sparse probe report exceeds one MiB"));
    }
    Ok(report)
}
