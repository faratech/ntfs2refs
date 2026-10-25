//! Native creation on a separately bound empty ReFS volume. Never writes the
//! source disk, manufactures ReFS bytes or grants conversion authority.
use crate::{
    attestation::{PrivilegeState, Snapshot},
    attestation_native::{Privileges, snapshot},
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    layout::{self, DiskBinding, invalid},
    namespace_layout,
    native::{self, NativeEvent},
    stream_layout,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    mem,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{FILETIME, INVALID_HANDLE_VALUE},
    Security::{GetSecurityDescriptorLength, IsValidSecurityDescriptor, SECURITY_ATTRIBUTES},
    Storage::FileSystem::{
        BackupWrite, CreateDirectoryW, CreateFileW, GetDiskFreeSpaceW,
        GetFileInformationByHandleEx, GetVolumeInformationW, SetFileInformationByHandle,
        SetFileTime,
    },
    System::IO::DeviceIoControl,
};

pub struct Input<'a> {
    pub components: &'a [String],
    pub directory: bool,
    pub times: [u64; 4],
    pub attributes: u32,
    pub security: &'a [u8],
    pub payload: &'a [u8],
    /// Hash-only expectations are accepted for ordinary shadow streaming and
    /// verification. The source reader supplies bytes during construction.
    pub expected_length: Option<u64>,
    pub expected_sha256: Option<&'a str>,
    pub source_offset: Option<u64>,
    pub source_runs: Vec<SourceRun>,
}
#[derive(Clone, Debug)]
pub struct SourceRun {
    pub logical_offset: u64,
    pub physical_offset: Option<u64>,
    pub length: u64,
}
impl Input<'_> {
    fn logical_length(&self) -> u64 {
        self.expected_length.unwrap_or(self.payload.len() as u64)
    }
    fn logical_sha256(&self) -> String {
        self.expected_sha256
            .map(str::to_owned)
            .unwrap_or_else(|| hex::encode(Sha256::digest(self.payload)))
    }
}
fn valid_shadow_component(s: &str) -> bool {
    let stem = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !s.is_empty()
        && s.len() <= 100
        && !s.ends_with(['.', ' '])
        && s.bytes().all(|byte| {
            (byte == b' ' || byte.is_ascii_graphic()) && !b"<>:\"/\\|?*".contains(&byte)
        })
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(&stem.as_str())
}
fn hash_exact_stream(reader: &mut impl Read, length: u64) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0u8; 65536];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid("stream read bound"))?;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 {
        return Err(invalid("converted stream has data beyond expected EOF"));
    }
    Ok(hex::encode(hash.finalize()))
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ProbeRoot,
    RestoreRootOnly,
    Construct,
    ConstructRetaining,
    Verify,
}
#[derive(Debug, Serialize)]
pub struct CandidateReport {
    pub legacy: crate::bitmap_layout::Candidate,
    pub metadata_inclusive: crate::bitmap_layout::Candidate,
}
#[derive(Debug, Serialize)]
pub struct ObjectReport {
    pub components: Vec<String>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub logical_sha256: Option<String>,
    pub retrieval: Vec<u8>,
    pub cached_validity: Vec<u8>,
    pub storage_validity: Vec<u8>,
    pub integrity: Vec<u8>,
    pub namespace: Vec<namespace_layout::Entry>,
    pub source_candidate: Option<CandidateReport>,
    pub streams: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub binding: DiskBinding,
    pub before: crate::PartitionSnapshot,
    pub after: crate::PartitionSnapshot,
    pub objects: Vec<ObjectReport>,
    /// Complete metadata-inclusive allocation intervals observed through
    /// refs.sys on this mounted shadow. Not a stand-alone ownership proof.
    pub metadata_allocation: Option<crate::bitmap_layout::AllocationMap>,
    pub base_sectors: u64,
    pub privilege_states: Vec<PrivilegeState>,
    pub events: Vec<NativeEvent>,
    pub payload_bytes_written: u64,
    pub conversion_qualified: bool,
    pub root_security: RootSecurity,
    pub security_restorations: Vec<ObjectSecurityRestore>,
    pub security_repair_preflight_sha256: Option<String>,
    pub security_repair_privileges: Vec<PrivilegeState>,
    pub retention_attempts: Vec<RetentionAttempt>,
}

#[derive(Debug, Serialize)]
pub struct GeneralReport {
    pub pair: GeneralSourceShadowBinding,
    pub native: Report,
    pub conversion_qualified: bool,
}

#[derive(Debug, Serialize)]
pub struct GeneralConvertedReport {
    pub pair: GeneralSourceShadowBinding,
    pub native: Report,
    pub conversion_qualified: bool,
}

fn observed_shadow(
    disk: &File,
    binding: &DiskBinding,
    general: Option<&GeneralDiskBinding>,
    events: &mut Vec<NativeEvent>,
) -> io::Result<crate::PartitionSnapshot> {
    if let Some(general) = general {
        let probe = native::probe_general(general.clone(), events)?;
        Ok(crate::PartitionSnapshot {
            binding: binding.clone(),
            disk_attributes: probe.disk_attributes_after,
            device: probe.device,
            length: probe.disk_length,
            alignment: probe.alignment,
            layout: probe.gpt_layout,
        })
    } else {
        native::snapshot(disk, binding, events)
    }
}
#[derive(Debug, Serialize)]
pub struct RetentionAttempt {
    pub components: Vec<String>,
    pub starting_vcn: u64,
    pub destination_lcn: u64,
    pub clusters: u32,
    pub candidate: CandidateReport,
    pub submitted: bool,
    pub native_error: Option<i32>,
    pub mapping_before: Vec<u8>,
    pub mapping_after: Vec<u8>,
    pub all_clusters_at_source: bool,
}
fn mapping_matches_run(
    runs: &[stream_layout::Run],
    starting_vcn: u64,
    destination_lcn: u64,
    clusters: u32,
) -> io::Result<bool> {
    let mut covered = starting_vcn;
    let limit = starting_vcn
        .checked_add(u64::from(clusters))
        .ok_or_else(|| invalid("retention range overflow"))?;
    for r in runs {
        let next = r
            .vcn
            .checked_add(r.clusters)
            .ok_or_else(|| invalid("retention mapping overflow"))?;
        let begin = r.vcn.max(starting_vcn);
        let end = next.min(limit);
        if begin < end {
            if begin != covered
                || !r
                    .lcn
                    .and_then(|lcn| lcn.checked_add(begin - r.vcn))
                    .is_some_and(|lcn| {
                        destination_lcn.checked_add(begin - starting_vcn) == Some(lcn)
                    })
            {
                return Ok(false);
            }
            covered = end;
        }
    }
    Ok(covered == limit)
}
fn retain_run_on_shadow(
    volume: &File,
    root: &str,
    i: &Input<'_>,
    partition: u64,
    run: &SourceRun,
) -> io::Result<RetentionAttempt> {
    let offset = run
        .physical_offset
        .ok_or_else(|| invalid("source placement hole"))?;
    let starting_vcn = run.logical_offset / 4096;
    let h = open(&format!("{}{}", root, i.components.join("\\")), false, true)?;
    let mapping_before = ctl(
        &h,
        stream_layout::GET_RETRIEVAL,
        &[0; 8],
        stream_layout::RETRIEVAL_CAPACITY,
    )?;
    let legacy = ctl(
        volume,
        stream_layout::GET_BITMAP,
        &[0; 8],
        stream_layout::MAX_BITMAP_BYTES,
    )?;
    let mut ex = [0; 16];
    ex[8] = 1;
    let metadata = ctl(
        volume,
        stream_layout::GET_BITMAP,
        &ex,
        stream_layout::MAX_BITMAP_BYTES,
    )?;
    let candidate = CandidateReport {
        legacy: crate::bitmap_layout::candidate(&legacy, offset, run.length, partition)?,
        metadata_inclusive: crate::bitmap_layout::candidate(
            &metadata, offset, run.length, partition,
        )?,
    };
    let clusters =
        u32::try_from(run.length / 4096).map_err(|_| invalid("retention cluster budget"))?;
    let destination_lcn = offset / 4096;
    let matches = |b: &[u8]| -> io::Result<bool> {
        mapping_matches_run(
            &stream_layout::parse_retrieval(b)?,
            starting_vcn,
            destination_lcn,
            clusters,
        )
    };
    let already = matches(&mapping_before)?;
    let mut r = RetentionAttempt {
        components: i.components.to_vec(),
        starting_vcn,
        destination_lcn,
        clusters,
        candidate,
        submitted: false,
        native_error: None,
        mapping_after: mapping_before.clone(),
        mapping_before,
        all_clusters_at_source: already,
    };
    // Include the independent metadata view. Never force a move into an
    // occupied bootstrap/container range or relocate the NTFS source itself.
    if already
        || r.candidate.legacy.allocated_clusters != 0
        || r.candidate.metadata_inclusive.allocated_clusters != 0
    {
        return Ok(r);
    }
    let mut input = [0; 32];
    input[..8].copy_from_slice(&(h.as_raw_handle() as usize as u64).to_le_bytes());
    input[8..16].copy_from_slice(&starting_vcn.to_le_bytes());
    input[16..24].copy_from_slice(&destination_lcn.to_le_bytes());
    input[24..28].copy_from_slice(&clusters.to_le_bytes());
    r.submitted = true;
    if let Err(e) = ctl(volume, 0x00090074, &input, 0) {
        r.native_error = e.raw_os_error().or(Some(-1));
    }
    // A refusal can have partial completion. Do not retry; measure its actual
    // mapping and let the ordinary content/storage checks qualify the shadow.
    r.mapping_after = ctl(
        &h,
        stream_layout::GET_RETRIEVAL,
        &[0; 8],
        stream_layout::RETRIEVAL_CAPACITY,
    )?;
    r.all_clusters_at_source = matches(&r.mapping_after)?;
    Ok(r)
}
#[derive(Debug, Serialize)]
pub struct ObjectSecurityRestore {
    pub components: Vec<String>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub backup: SecurityBackup,
}
#[derive(Debug, Serialize)]
pub struct RootSecurity {
    pub before: Snapshot,
    pub after: Snapshot,
    pub matched_before: bool,
    pub matched_after: bool,
    pub backup: Option<SecurityBackup>,
}
#[derive(Debug, Serialize)]
pub struct SecurityBackup {
    pub stream_sha256: String,
    pub submitted_bytes: u32,
    pub accepted_bytes: u32,
    pub context_released: bool,
}
fn security_stream(sd: &[u8]) -> io::Result<Vec<u8>> {
    if !(20..=65536).contains(&sd.len()) {
        return Err(invalid("security backup length"));
    }
    // WIN32_STREAM_ID ends at cStreamName (offset 20), not sizeof(struct),
    // which includes WCHAR[1] and alignment padding. This stream is unnamed.
    let mut stream = vec![0; 20];
    stream[0..4].copy_from_slice(&3u32.to_le_bytes());
    stream[4..8].copy_from_slice(&2u32.to_le_bytes());
    stream[8..16].copy_from_slice(&(sd.len() as u64).to_le_bytes());
    stream.extend_from_slice(sd);
    Ok(stream)
}
fn backup_security(file: &File, sd: &[u8]) -> io::Result<SecurityBackup> {
    descriptor(sd)?;
    let stream = security_stream(sd)?;
    let mut accepted = 0;
    let mut context = ptr::null_mut();
    // SAFETY: synchronous backup-semantics handle with WRITE_DAC, WRITE_OWNER
    // and ACCESS_SYSTEM_SECURITY; bounded initialized stream; private context
    // starts NULL and is passed unchanged to the mandatory abort/cleanup call.
    let result = check(unsafe {
        BackupWrite(
            file.as_raw_handle(),
            stream.as_ptr(),
            stream.len() as u32,
            &mut accepted,
            0,
            1,
            &mut context,
        )
    });
    let mut ignored = 0;
    let cleanup = check(unsafe {
        BackupWrite(
            file.as_raw_handle(),
            ptr::null(),
            0,
            &mut ignored,
            1,
            1,
            &mut context,
        )
    });
    result?;
    cleanup?;
    if accepted as usize != stream.len() {
        return Err(invalid("partial root backup-security restoration"));
    }
    Ok(SecurityBackup {
        stream_sha256: hex::encode(Sha256::digest(&stream)),
        submitted_bytes: stream.len() as u32,
        accepted_bytes: accepted,
        context_released: true,
    })
}
fn security_matches(
    expected: &[u8],
    actual: &Snapshot,
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<bool> {
    let kernel = actual
        .kernel_security
        .as_ref()
        .ok_or_else(|| invalid("root kernel security missing"))?;
    if actual.security_error.is_some() || kernel.native_error.is_some() {
        return Err(invalid("root security query failed"));
    }
    Ok(same(expected, &actual.security)? && same(expected, &kernel.bytes)?)
}
fn query_bytes(s: &Snapshot, class: i32, length: usize) -> io::Result<&[u8]> {
    let q = s
        .queries
        .iter()
        .find(|q| q.class == class && q.native_error.is_none() && q.bytes.len() == length)
        .ok_or_else(|| invalid("missing native shadow metadata query"))?;
    Ok(&q.bytes)
}
fn basic_bytes(i: &Input<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    for t in i.times {
        b.extend_from_slice(&t.to_le_bytes());
    }
    b.extend_from_slice(&i.attributes.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    b
}
// Only a pre-restoration diagnosis. Final comparisons never normalize control
// flags: BACKUP_SECURITY_DATA must restore the exact original descriptor.
fn creation_loss_only(
    expected: &[u8],
    actual: &[u8],
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<bool> {
    if same(expected, actual)? {
        return Ok(true);
    }
    if expected.len() < 20 || actual.len() < 20 {
        return Ok(false);
    }
    let want = u16::from_le_bytes(expected[2..4].try_into().unwrap());
    let got = u16::from_le_bytes(actual[2..4].try_into().unwrap());
    if want ^ got != 0x400 || want & 0x400 == 0 {
        return Ok(false);
    }
    let mut restored = actual.to_vec();
    restored[2..4].copy_from_slice(&want.to_le_bytes());
    same(expected, &restored)
}
fn validate_existing(
    report: &Report,
    input: &[Input<'_>],
    same: &impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    before_restore: bool,
    root_basic_after_mutation: Option<&[u8; 40]>,
) -> io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    if report.objects.len() != input.len() {
        return Err(invalid("existing shadow object coverage differs"));
    }
    let mut identities = BTreeMap::new();
    let mut unique = BTreeSet::new();
    for (i, o) in input.iter().zip(&report.objects) {
        let expected_owned = basic_bytes(i);
        let expected_basic: &[u8] = if i.components.is_empty() {
            root_basic_after_mutation.map_or(&expected_owned, |bytes| bytes.as_slice())
        } else {
            &expected_owned
        };
        if i.components != o.components
            || query_bytes(&o.before, 0, 40)? != expected_basic
            || o.before != o.after
        {
            return Err(invalid(
                "existing shadow path, basic metadata or stability differs",
            ));
        }
        let id = query_bytes(&o.before, 18, 24)?[8..24].to_vec();
        if id == [0; 16]
            || !unique.insert(id.clone())
            || identities.insert(i.components.to_vec(), id).is_some()
        {
            return Err(invalid("duplicate existing shadow identity"));
        }
        let standard = query_bytes(&o.before, 1, 24)?;
        if layout::u32_at(standard, 16)? != 1
            || standard[20] != 0
            || (standard[21] != 0) != i.directory
            || (!i.directory && layout::u64_at(standard, 8)? != i.logical_length())
            || o.logical_sha256 != (!i.directory).then(|| i.logical_sha256())
        {
            return Err(invalid(
                "existing shadow links, type, EOF or contents differ",
            ));
        }
        let kernel = o
            .before
            .kernel_security
            .as_ref()
            .ok_or_else(|| invalid("existing shadow security missing"))?;
        if o.before.security_error.is_some() || kernel.native_error.is_some() {
            return Err(invalid("existing shadow security query failed"));
        }
        for actual in [&o.before.security, &kernel.bytes] {
            let matched = if before_restore {
                creation_loss_only(i.security, actual, same)?
            } else {
                same(i.security, actual)?
            };
            if !matched {
                return Err(invalid(
                    "existing shadow security differs beyond the recorded creation control-bit loss",
                ));
            }
        }
    }
    for (i, o) in input
        .iter()
        .zip(&report.objects)
        .filter(|(i, _)| i.directory)
    {
        let expected: BTreeMap<_, _> = input
            .iter()
            .filter(|c| {
                c.components.len() == i.components.len() + 1
                    && c.components.starts_with(i.components)
            })
            .map(|c| {
                (
                    c.components
                        .last()
                        .unwrap()
                        .encode_utf16()
                        .collect::<Vec<_>>(),
                    c,
                )
            })
            .collect();
        let mut seen = BTreeSet::new();
        for entry in &o.namespace {
            if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
                continue;
            }
            if i.components.is_empty()
                && !expected.contains_key(&entry.name_utf16)
                && entry.name_utf16
                    == "System Volume Information"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                && entry.attributes & 16 != 0
                && entry.attributes & 0x400 == 0
            {
                continue;
            }
            let child = expected
                .get(&entry.name_utf16)
                .ok_or_else(|| invalid("unexpected existing shadow directory entry"))?;
            if !seen.insert(entry.name_utf16.clone())
                || entry.attributes != child.attributes
                || identities
                    .get(child.components)
                    .is_none_or(|id| id.as_slice() != entry.file_id)
            {
                return Err(invalid("existing shadow namespace identity differs"));
            }
        }
        if seen.len() != expected.len() {
            return Err(invalid("missing existing shadow directory entry"));
        }
    }
    Ok(())
}
/// Repairs only the documented creation-time loss of AUTO_INHERITED, after a
/// fresh native read of every admitted shadow byte and namespace identity. The
/// preflight is a live value; no serialized `success` flag is consumed.
pub fn repair_security(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    repair_security_profile(binding, source_disk, input, same, false)
}
pub fn repair_security_ordinary(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    repair_security_profile(binding, source_disk, input, same, true)
}
fn repair_security_profile(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    same: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ordinary: bool,
) -> io::Result<Report> {
    let observed = run_role(
        binding.clone(),
        source_disk,
        input,
        Mode::Verify,
        &same,
        false,
        ordinary,
        None,
        None,
    )?;
    validate_existing(&observed, input, &same, true, None)?;
    let preflight_sha = hex::encode(Sha256::digest(
        serde_json::to_vec(&observed).map_err(io::Error::other)?,
    ));
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let root = format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid);
    let mut restorations = vec![];
    for (i, o) in input.iter().zip(&observed.objects).rev() {
        let h = open(
            &format!("{}{}", root, i.components.join("\\")),
            i.directory,
            true,
        )?;
        let before = snapshot(&h);
        if before != o.before {
            return Err(invalid("existing shadow changed after repair preflight"));
        }
        if !security_matches(i.security, &before, &same)? {
            let backup = backup_security(&h, i.security)?;
            let after = snapshot(&h);
            if !security_matches(i.security, &after, &same)? {
                return Err(invalid("restored shadow descriptor does not exactly match"));
            }
            restorations.push(ObjectSecurityRestore {
                components: i.components.to_vec(),
                before,
                after,
                backup,
            });
        }
        basic(&h, i)?;
        if !i.directory {
            h.sync_all()?;
        }
    }
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(root.trim_end_matches('\\'))?;
    volume.sync_all()?;
    privileges.restore()?;
    let mut verified = run_role(
        binding,
        source_disk,
        input,
        Mode::Verify,
        &same,
        false,
        ordinary,
        None,
        None,
    )?;
    validate_existing(&verified, input, &same, false, None)?;
    if observed
        .objects
        .iter()
        .zip(&verified.objects)
        .any(|(a, b)| a.retrieval != b.retrieval)
    {
        return Err(invalid(
            "payload allocation changed during security-only restoration",
        ));
    }
    verified.security_restorations = restorations;
    verified.security_repair_preflight_sha256 = Some(preflight_sha);
    verified.security_repair_privileges = privileges.audit().to_vec();
    Ok(verified)
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn ctl(file: &File, code: u32, input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    if size > 2 * 1024 * 1024 || input.len() > 64 {
        return Err(invalid("shadow control bound"));
    }
    let mut b = vec![0; size];
    let mut used = 0;
    // SAFETY: borrowed handle, initialized separate buffers, synchronous call.
    check(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            b.as_mut_ptr().cast(),
            size as u32,
            &mut used,
            ptr::null_mut(),
        )
    })?;
    if used as usize > size {
        return Err(invalid("oversized shadow control response"));
    }
    b.truncate(used as usize);
    Ok(b)
}
fn info(file: &File, class: i32, size: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0u64; size.div_ceil(8)];
    // SAFETY: aligned initialized storage of the exact class-specific size.
    check(unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            b.as_mut_ptr().cast(),
            size as u32,
        )
    })?;
    Ok(unsafe { std::slice::from_raw_parts(b.as_ptr().cast(), size) }.to_vec())
}
fn suppress_access(file: &File) -> io::Result<()> {
    let no_update = FILETIME {
        dwLowDateTime: u32::MAX,
        dwHighDateTime: u32::MAX,
    };
    // SAFETY: documented per-handle suppression, no stored timestamp supplied.
    check(unsafe { SetFileTime(file.as_raw_handle(), ptr::null(), &no_update, ptr::null()) })
}
fn open(path: &str, directory: bool, write: bool) -> io::Result<File> {
    let f = File::options()
        // Metadata handles need WRITE_DAC/WRITE_OWNER, never DELETE. Retaining
        // the root handle must not prevent its later finalization/observation.
        .access_mode(if write { 0x011e01ff } else { 0x01020181 })
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?;
    suppress_access(&f)?;
    let attrs = info(&f, 0, 40)?;
    let flags = u32::from_le_bytes(attrs[32..36].try_into().unwrap());
    if flags & (0x400 | 0x800 | 0x4000) != 0 || (flags & 16 != 0) != directory {
        return Err(invalid("shadow path type or encoding differs"));
    }
    Ok(f)
}
fn enumerate(file: &File) -> io::Result<Vec<namespace_layout::Entry>> {
    let mut calls = vec![];
    for i in 0..namespace_layout::MAX_CALLS {
        let class = if i == 0 {
            namespace_layout::RESTART
        } else {
            namespace_layout::CONTINUE
        };
        let result = info(file, class, namespace_layout::CAPACITY);
        let q = match result {
            Ok(b) => {
                let (_, used) = namespace_layout::parse(&b)?;
                crate::attestation::Query {
                    class,
                    bytes: b[..used].to_vec(),
                    native_error: None,
                }
            }
            Err(e) => crate::attestation::Query {
                class,
                bytes: vec![],
                native_error: Some(e.raw_os_error().ok_or(e)?),
            },
        };
        let terminal = q.native_error.is_some();
        calls.push(q);
        if terminal {
            return namespace_layout::decode_pass(&calls);
        }
    }
    Err(invalid("shadow namespace enumeration budget"))
}
fn descriptor(bytes: &[u8]) -> io::Result<Vec<u64>> {
    if !(20..=65536).contains(&bytes.len()) {
        return Err(invalid("shadow descriptor length"));
    }
    let mut aligned = vec![0u64; bytes.len().div_ceil(8)];
    // SAFETY: initialized aligned allocation covers every copied byte. Validate
    // self-relative offsets in safe code before letting Windows follow them.
    if bytes[0] != 1
        || u16::from_le_bytes(bytes[2..4].try_into().unwrap()) & 0x8004 != 0x8004
        || bytes[12..16] != [0; 4]
    {
        return Err(invalid("shadow descriptor form or SACL differs"));
    }
    for at in [4, 8, 16] {
        let p = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if p < 20 || p > bytes.len().saturating_sub(8) || !p.is_multiple_of(4) {
            return Err(invalid("shadow descriptor component bounds"));
        }
        let n = if at == 16 {
            u16::from_le_bytes(bytes[p + 2..p + 4].try_into().unwrap()) as usize
        } else {
            8 + 4 * bytes[p + 1] as usize
        };
        if n < 8 || p + n > bytes.len() {
            return Err(invalid("shadow descriptor component length"));
        }
        if at != 16 {
            if bytes[p] != 1 || bytes[p + 1] > 15 {
                return Err(invalid("shadow SID form"));
            }
        } else {
            if bytes[p] != 2 || bytes[p + 1] != 0 {
                return Err(invalid("initial shadow requires revision-two ACL"));
            }
            let count = u16::from_le_bytes(bytes[p + 4..p + 6].try_into().unwrap()) as usize;
            let mut cursor = p + 8;
            for _ in 0..count {
                if cursor + 16 > p + n || ![0, 1].contains(&bytes[cursor]) {
                    return Err(invalid("initial shadow requires bounded allow/deny ACEs"));
                }
                let size =
                    u16::from_le_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
                let sid_count = bytes[cursor + 9] as usize;
                if bytes[cursor + 8] != 1
                    || sid_count > 15
                    || size != 16 + 4 * sid_count
                    || cursor + size > p + n
                {
                    return Err(invalid("shadow ACE or SID bounds"));
                }
                cursor += size;
            }
            if cursor > p + n {
                return Err(invalid("shadow ACL overflow"));
            }
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len());
    }
    let p = aligned.as_mut_ptr().cast();
    if unsafe { IsValidSecurityDescriptor(p) } == 0
        || unsafe { GetSecurityDescriptorLength(p) } as usize > bytes.len()
    {
        return Err(invalid("invalid shadow security descriptor"));
    }
    Ok(aligned)
}
fn create(
    path: &str,
    i: &Input<'_>,
    index: usize,
    payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
) -> io::Result<()> {
    let mut sd = descriptor(i.security)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    let name = wide(path);
    if i.directory {
        // SAFETY: NUL-terminated bounded path, live validated descriptor.
        return check(unsafe { CreateDirectoryW(name.as_ptr(), &sa) });
    }
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x011f01ff,
            0,
            &sa,
            1,
            0x80200000,
            ptr::null_mut(),
        )
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: unique handle ownership is transferred to File.
    let mut f = unsafe { File::from_raw_handle(h) };
    suppress_access(&f)?;
    ctl(&f, 0x9c280, &[0; 8], 0)?;
    if let Some(writer) = payload_writer {
        writer(index, &mut f)?;
    } else {
        f.write_all(i.payload)?;
    }
    f.sync_all()?;
    Ok(())
}
fn basic(file: &File, i: &Input<'_>) -> io::Result<()> {
    let mut b = [0u64; 5];
    b[..4].copy_from_slice(&i.times);
    b[4] = i.attributes as u64;
    // SAFETY: FILE_BASIC_INFO layout, aligned initialized forty-byte buffer.
    check(unsafe { SetFileInformationByHandle(file.as_raw_handle(), 0, b.as_ptr().cast(), 40) })
}
/// Restricted lab destination: measured disk3, not the source or Windows disk.
/// Probe/verify have no creation or stored-metadata setters; handle access-time
/// suppression is still required and is never substituted for expected times.
pub fn run(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        false,
        false,
        None,
        None,
    )
}
/// Ordinary stream forms remain confined to the independent lab shadow.
pub fn run_ordinary(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        mode,
        same_security,
        false,
        true,
        None,
        None,
    )
}
/// Construct an independent native ReFS shadow with bytes supplied in bounded
/// chunks by the owning caller. The callback receives the input index and a
/// new file handle; native readback verifies the declared EOF and SHA-256.
pub fn run_ordinary_streaming(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    retain_eligible: bool,
    payload_writer: &mut impl FnMut(usize, &mut File) -> io::Result<()>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    run_role(
        binding,
        source_disk,
        input,
        if retain_eligible {
            Mode::ConstructRetaining
        } else {
            Mode::Construct
        },
        same_security,
        false,
        true,
        Some(payload_writer),
        None,
    )
}

/// Construct a Windows-created ReFS shadow on a separately bound dedicated
/// data disk. The source callback provides checked logical NTFS bytes; this
/// function never opens or writes the source disk.
pub fn run_general_ordinary_streaming(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    retain_eligible: bool,
    payload_writer: &mut impl FnMut(usize, &mut File) -> io::Result<()>,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralReport> {
    pair.validate()?;
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role(
        binding,
        pair.source.disk_number,
        input,
        if retain_eligible {
            Mode::ConstructRetaining
        } else {
            Mode::Construct
        },
        &same_security,
        false,
        true,
        Some(payload_writer),
        Some(&pair.shadow),
    )?;
    validate_existing(&native, input, &same_security, false, None)?;
    Ok(GeneralReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Re-observe an existing general shadow without creating files or changing
/// stored metadata. Security/namespace comparison remains caller-owned.
pub fn verify_general_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralReport> {
    pair.validate()?;
    let binding = DiskBinding {
        disk_number: pair.shadow.disk_number,
        volume_guid: pair.shadow.volume_guid.clone(),
        identity: pair.shadow.identity.clone(),
    };
    let native = run_role(
        binding,
        pair.source.disk_number,
        input,
        Mode::Verify,
        &same_security,
        false,
        true,
        None,
        Some(&pair.shadow),
    )?;
    validate_existing(&native, input, &same_security, false, None)?;
    Ok(GeneralReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Inspect the original data disk after the journal handoff has been made
/// durable and it has mounted as ReFS. The caller supplies the pre-cutover
/// source tree from separately pinned recovery artifacts.
pub fn verify_general_converted_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    let report = observe_general_converted_ordinary(pair, input, &same_security)?;
    validate_existing(&report.native, input, &same_security, false, None)?;
    Ok(report)
}

/// Return the bounded native observation even when a preservation comparison
/// would fail. This diagnostic does not qualify the converted tree or write to
/// the volume; callers must keep it separate from verified results.
pub fn observe_general_converted_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    pair.validate()?;
    let binding = DiskBinding {
        disk_number: pair.source.disk_number,
        volume_guid: pair.source.volume_guid.clone(),
        identity: pair.source.identity.clone(),
    };
    let native = run_role(
        binding,
        pair.source.disk_number,
        input,
        Mode::Verify,
        &same_security,
        true,
        true,
        None,
        Some(&pair.source),
    )?;
    Ok(GeneralConvertedReport {
        pair,
        native,
        conversion_qualified: false,
    })
}

/// Capture exact FileBasicInfo for the mounted volume root using the same
/// access-time-suppressed handle policy as native tree verification.
pub fn observe_general_root_basic(binding: &GeneralDiskBinding) -> io::Result<[u8; 40]> {
    binding.validate()?;
    let mut privileges = Privileges::enable_for(&[
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ])?;
    let root = format!("{}\\", binding.volume_path()?);
    let file = open(&root, true, false)?;
    let basic = info(&file, 0, 40)?;
    drop(file);
    privileges.restore()?;
    Ok(basic
        .try_into()
        .map_err(|_| invalid("root basic-info size"))?)
}

/// After a recorded namespace mutation, require the exact root basic-info
/// bytes captured by that workload. Creation time and attributes must still
/// match the NTFS source; all other objects retain exact original metadata.
pub fn verify_general_converted_after_mutation_ordinary(
    pair: GeneralSourceShadowBinding,
    input: &[Input<'_>],
    root_basic_after_mutation: [u8; 40],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<GeneralConvertedReport> {
    let root = input
        .first()
        .ok_or_else(|| invalid("missing expected root"))?;
    if !root.directory || !root.components.is_empty() {
        return Err(invalid("expected post-mutation root differs"));
    }
    let original = basic_bytes(root);
    if root_basic_after_mutation[..8] != original[..8]
        || root_basic_after_mutation[32..] != original[32..]
        || [8usize, 16, 24].into_iter().any(|at| {
            let before = u64::from_le_bytes(original[at..at + 8].try_into().unwrap());
            let after =
                u64::from_le_bytes(root_basic_after_mutation[at..at + 8].try_into().unwrap());
            after < before || after >= i64::MAX as u64
        })
    {
        return Err(invalid(
            "post-mutation root creation, attributes or time order differs",
        ));
    }
    let report = observe_general_converted_ordinary(pair, input, &same_security)?;
    validate_existing(
        &report.native,
        input,
        &same_security,
        false,
        Some(&root_basic_after_mutation),
    )?;
    Ok(report)
}
/// Observe the enrolled converted original after durable journal handoff. All
/// original shadow creation/repair entry points retain the disk3 restriction.
pub fn verify_converted(
    binding: DiskBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    if binding.disk_number != 1
        || layout::guid_bytes(&binding.identity.disk_guid)?
            != layout::guid_bytes("a01574d5-2a5c-4136-958a-dcf0d0e0f7aa")?
        || layout::guid_bytes(&binding.identity.partition_guid)?
            != layout::guid_bytes("79eaccdf-38d3-4561-97cc-9276af5d223a")?
    {
        return Err(invalid("converted natural-tree enrollment differs"));
    }
    let report = run_role(
        binding,
        1,
        input,
        Mode::Verify,
        &same_security,
        true,
        false,
        None,
        None,
    )?;
    validate_existing(&report, input, &same_security, false, None)?;
    Ok(report)
}
/// Verify an ordinary-file conversion on the owning guest after the durable
/// handoff. The caller must bind this volume to its frozen source and journal
/// ticket before bringing it online; this routine independently checks the
/// complete expected tree through the mounted ReFS driver.
pub fn verify_converted_ordinary(
    binding: DiskBinding,
    input: &[Input<'_>],
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
) -> io::Result<Report> {
    let report = run_role(
        binding,
        1,
        input,
        Mode::Verify,
        &same_security,
        true,
        true,
        None,
        None,
    )?;
    validate_existing(&report, input, &same_security, false, None)?;
    Ok(report)
}
fn run_role(
    binding: DiskBinding,
    source_disk: u32,
    input: &[Input<'_>],
    mode: Mode,
    same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    converted: bool,
    ordinary: bool,
    mut payload_writer: Option<&mut dyn FnMut(usize, &mut File) -> io::Result<()>>,
    general_shadow: Option<&GeneralDiskBinding>,
) -> io::Result<Report> {
    if let Some(general) = general_shadow {
        general.validate()?;
        let route_mode_ok = if converted {
            source_disk == binding.disk_number && mode == Mode::Verify
        } else {
            source_disk != binding.disk_number
                && matches!(
                    mode,
                    Mode::ProbeRoot | Mode::Construct | Mode::ConstructRetaining | Mode::Verify
                )
        };
        if !route_mode_ok
            || !ordinary
            || binding.disk_number != general.disk_number
            || binding.volume_guid != general.volume_guid
            || binding.identity != general.identity
            || input.is_empty()
            || input.len() > 160
        {
            return Err(invalid("general independent shadow profile differs"));
        }
    } else {
        binding.validate()?;
        if binding.disk_number != if converted { 1 } else { 3 }
            || (converted && mode != Mode::Verify)
            || source_disk != 1
            || input.is_empty()
            || input.len() > 160
            || std::env::var("COMPUTERNAME").ok().as_deref() != Some("N2R-WIN11")
        {
            return Err(invalid("restricted tree shadow lab profile differs"));
        }
    }
    if payload_writer.is_some()
        && (!ordinary || converted || !matches!(mode, Mode::Construct | Mode::ConstructRetaining))
    {
        return Err(invalid(
            "streaming payload callback is restricted to ordinary shadow construction",
        ));
    }
    let mut total = 0usize;
    let mut source_allocations = Vec::new();
    for i in input {
        if i.source_offset.is_some() && !i.source_runs.is_empty() {
            return Err(invalid("mixed single and fragmented source placement"));
        }
        if let Some(offset) = i.source_offset {
            if i.directory
                || i.logical_length() == 0
                || !i.logical_length().is_multiple_of(4096)
                || !offset.is_multiple_of(4096)
                || !offset
                    .checked_add(i.logical_length())
                    .is_some_and(|end| end <= binding.identity.partition_bytes)
            {
                return Err(invalid("single source placement differs"));
            }
            source_allocations.push((offset, i.logical_length()));
        }
        if !i.source_runs.is_empty() {
            let mut covered = 0u64;
            for run in &i.source_runs {
                let offset = run
                    .physical_offset
                    .ok_or_else(|| invalid("fragmented source hole"))?;
                if run.logical_offset != covered
                    || run.length == 0
                    || !run.length.is_multiple_of(4096)
                    || !offset.is_multiple_of(4096)
                    || !offset
                        .checked_add(run.length)
                        .is_some_and(|end| end <= binding.identity.partition_bytes)
                {
                    return Err(invalid("fragmented source placement differs"));
                }
                covered = covered
                    .checked_add(run.length)
                    .ok_or_else(|| invalid("source placement overflow"))?;
                source_allocations.push((offset, run.length));
            }
            if i.directory
                || covered == 0
                || covered > i.logical_length() / 4096 * 4096
                || i.source_runs.len() > 1024
            {
                return Err(invalid("fragmented source placement coverage differs"));
            }
        }
        let digest_only = i.expected_length.is_some() || i.expected_sha256.is_some();
        let digest_allowed = ordinary
            && !i.directory
            && ((matches!(mode, Mode::Verify | Mode::ProbeRoot) && payload_writer.is_none())
                || (!converted
                    && matches!(mode, Mode::Construct | Mode::ConstructRetaining)
                    && payload_writer.is_some()));
        if digest_only
            && (!digest_allowed
                || i.expected_length.is_none()
                || i.expected_sha256.is_none()
                || !i.payload.is_empty()
                || !i.expected_sha256.is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }))
        {
            return Err(invalid("invalid hash-only verification input"));
        }
        if payload_writer.is_some() && !i.directory && !digest_only {
            return Err(invalid("streaming source lacks a hash-only expectation"));
        }
        if i.components.len() > 16
            || i.components.iter().any(|s| !valid_shadow_component(s))
            || i.times.iter().any(|t| *t == 0 || *t >= i64::MAX as u64)
            || i.attributes & !0x2037 != 0
            || (i.attributes & 16 != 0) != i.directory
            || (i.directory && !i.payload.is_empty())
            || (!ordinary
                && !i.directory
                && (i.payload.is_empty() || !i.payload.len().is_multiple_of(65536)))
        {
            return Err(invalid("invalid bounded shadow input"));
        }
        total = total
            .checked_add(
                usize::try_from(i.logical_length())
                    .map_err(|_| invalid("payload length overflow"))?,
            )
            .ok_or_else(|| invalid("payload overflow"))?;
        if total > 256 * 1024 * 1024 {
            return Err(invalid("shadow payload budget"));
        }
        descriptor(i.security)?;
        if !ordinary
            && !i.components.is_empty()
            && u16::from_le_bytes(i.security[2..4].try_into().unwrap()) & 0x1000 == 0
        {
            return Err(invalid(
                "initial tree shadow requires protected child DACLs",
            ));
        }
    }
    source_allocations.sort_unstable();
    if source_allocations
        .windows(2)
        .any(|pair| pair[0].0 + pair[0].1 > pair[1].0)
    {
        return Err(invalid("source placement allocations overlap"));
    }
    if input.iter().filter(|i| i.components.is_empty()).count() != 1
        || !input[0].components.is_empty()
        || !input[0].directory
    {
        return Err(invalid("one first directory root required"));
    }
    let mut events = vec![];
    if native::current_windows_disk(&mut events)? == binding.disk_number {
        return Err(invalid("shadow routes to Windows disk"));
    }
    let disk = File::options()
        .read(true)
        .share_mode(3)
        .open(format!("\\\\.\\PhysicalDrive{}", binding.disk_number))?;
    let before = observed_shadow(&disk, &binding, general_shadow, &mut events)?;
    if before.disk_attributes != 0 {
        return Err(invalid("shadow must be online writable"));
    }
    let root = format!("\\\\?\\Volume{{{}}}\\", binding.volume_guid);
    let volume = File::options()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(root.trim_end_matches('\\'))?;
    let ext = ctl(&volume, 0x560000, &[], 32)?;
    if ext.len() != 32
        || layout::u32_at(&ext, 0)? != 1
        || layout::u32_at(&ext, 8)? != binding.disk_number
        || layout::u64_at(&ext, 16)? != binding.identity.partition_offset
        || layout::u64_at(&ext, 24)? != binding.identity.partition_bytes
    {
        return Err(invalid("shadow volume physical binding differs"));
    }
    let mut fs = [0u16; 32];
    let mut label = [0u16; 128];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    let root_w = wide(&root);
    let (mut spc, mut bps, mut free, mut clusters) = (0, 0, 0, 0);
    // SAFETY: initialized fixed output buffers and NUL-terminated volume path.
    unsafe {
        check(GetVolumeInformationW(
            root_w.as_ptr(),
            label.as_mut_ptr(),
            128,
            &mut serial,
            &mut component,
            &mut flags,
            fs.as_mut_ptr(),
            32,
        ))?;
        check(GetDiskFreeSpaceW(
            root_w.as_ptr(),
            &mut spc,
            &mut bps,
            &mut free,
            &mut clusters,
        ))?;
    }
    let text = |b: &[u16]| {
        String::from_utf16_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
    };
    if text(&fs) != "ReFS"
        || text(&label) != "n2r-retained-shadow"
        || spc != 8
        || bps != 512
        || flags & 0x80000 != 0
    {
        return Err(invalid(
            "shadow filesystem, label, geometry or read-only flag differs",
        ));
    }
    let base = ctl(&volume, stream_layout::GET_BASE, &[], 8)?;
    if base.len() != 8 || layout::u64_at(&base, 0)? != 0 {
        return Err(invalid("initial tree shadow requires zero retrieval base"));
    }
    let mut names = vec![
        "SeBackupPrivilege",
        "SeSecurityPrivilege",
        "SeRestorePrivilege",
    ];
    if mode == Mode::ConstructRetaining {
        names.push("SeManageVolumePrivilege");
    }
    let mut privileges = Privileges::enable_for(&names)?;
    let root_handle = open(&root, true, true)?;
    let root_state = snapshot(&root_handle);
    let matched_before = security_matches(input[0].security, &root_state, &same_security)?;
    let mut root_security = RootSecurity {
        before: root_state.clone(),
        after: root_state,
        matched_before,
        matched_after: matched_before,
        backup: None,
    };
    let mut security_restorations = vec![];
    let mut retention_attempts = vec![];
    let constructing = matches!(mode, Mode::Construct | Mode::ConstructRetaining);
    if mode == Mode::Verify && !matched_before {
        return Err(invalid("root security changed before verification"));
    }
    if mode == Mode::ProbeRoot {
        let after = observed_shadow(&disk, &binding, general_shadow, &mut events)?;
        privileges.restore()?;
        return Ok(Report {
            binding,
            before,
            after,
            objects: vec![],
            metadata_allocation: None,
            base_sectors: 0,
            privilege_states: privileges.audit().to_vec(),
            events,
            payload_bytes_written: 0,
            conversion_qualified: false,
            root_security,
            security_restorations,
            security_repair_preflight_sha256: None,
            security_repair_privileges: vec![],
            retention_attempts,
        });
    }
    if constructing || mode == Mode::RestoreRootOnly {
        let initial = enumerate(&root_handle)?;
        if initial.iter().any(|e| {
            let n = String::from_utf16_lossy(&e.name_utf16);
            n != "."
                && n != ".."
                && !(n == "System Volume Information"
                    && e.attributes & 16 != 0
                    && e.attributes & 0x400 == 0)
        }) {
            return Err(invalid("independent shadow is not empty"));
        }
        if !matched_before {
            root_security.backup = Some(backup_security(&root_handle, input[0].security)?);
            root_security.after = snapshot(&root_handle);
            root_security.matched_after =
                security_matches(input[0].security, &root_security.after, &same_security)?;
            if !root_security.matched_after {
                return Err(invalid(
                    "backup security restoration did not exactly preserve both descriptor views",
                ));
            }
        }
        if mode == Mode::RestoreRootOnly {
            volume.sync_all()?;
            let after = observed_shadow(&disk, &binding, general_shadow, &mut events)?;
            privileges.restore()?;
            return Ok(Report {
                binding,
                before,
                after,
                objects: vec![],
                metadata_allocation: None,
                base_sectors: 0,
                privilege_states: privileges.audit().to_vec(),
                events,
                payload_bytes_written: 0,
                conversion_qualified: false,
                root_security,
                security_restorations,
                security_repair_preflight_sha256: None,
                security_repair_privileges: vec![],
                retention_attempts,
            });
        }
        for (index, i) in input.iter().enumerate().skip(1) {
            let path = format!("{}{}", root, i.components.join("\\"));
            if let Some(writer) = payload_writer.as_mut() {
                create(&path, i, index, Some(&mut **writer))?;
            } else {
                create(&path, i, index, None)?;
            }
        }
        if mode == Mode::ConstructRetaining {
            for i in input.iter().filter(|i| !i.directory) {
                if let Some(offset) = i.source_offset
                    && i.logical_length() > 0
                    && i.logical_length().is_multiple_of(4096)
                {
                    retention_attempts.push(retain_run_on_shadow(
                        &volume,
                        &root,
                        i,
                        binding.identity.partition_bytes,
                        &SourceRun {
                            logical_offset: 0,
                            physical_offset: Some(offset),
                            length: i.logical_length(),
                        },
                    )?);
                }
                for run in &i.source_runs {
                    retention_attempts.push(retain_run_on_shadow(
                        &volume,
                        &root,
                        i,
                        binding.identity.partition_bytes,
                        run,
                    )?);
                }
            }
        }
        // Final metadata follows every child creation. Root security has
        // already matched the source through both independent query views.
        for i in input.iter().rev() {
            let h = open(
                &format!("{}{}", root, i.components.join("\\")),
                i.directory,
                true,
            )?;
            let before = snapshot(&h);
            if !security_matches(i.security, &before, &same_security)? {
                let backup = backup_security(&h, i.security)?;
                let after = snapshot(&h);
                if !security_matches(i.security, &after, &same_security)? {
                    return Err(invalid(
                        "object backup-security restoration differs from the source",
                    ));
                }
                security_restorations.push(ObjectSecurityRestore {
                    components: i.components.to_vec(),
                    before,
                    after,
                    backup,
                });
            }
            basic(&h, i)?;
            if !i.directory {
                h.sync_all()?;
            }
        }
        volume.sync_all()?;
    }
    // No fallback from metadata-inclusive evidence to the legacy view.
    let legacy_bitmap = ctl(
        &volume,
        stream_layout::GET_BITMAP,
        &[0; 8],
        stream_layout::MAX_BITMAP_BYTES,
    )?;
    let mut ex_input = [0; 16];
    ex_input[8] = 1;
    let metadata_bitmap = ctl(
        &volume,
        stream_layout::GET_BITMAP,
        &ex_input,
        stream_layout::MAX_BITMAP_BYTES,
    )?;
    let metadata_allocation =
        crate::bitmap_layout::allocated_ranges(&metadata_bitmap, binding.identity.partition_bytes)?;
    let mut objects = vec![];
    for i in input {
        let mut h = open(
            &format!("{}{}", root, i.components.join("\\")),
            i.directory,
            false,
        )?;
        let before = snapshot(&h);
        let expected_allocation = layout::u64_at(query_bytes(&before, 1, 24)?, 0)?;
        let (logical_sha256, retrieval, cached_validity, storage_validity, integrity, namespace) =
            if i.directory {
                (None, vec![], vec![], vec![], vec![], enumerate(&h)?)
            } else {
                let retrieval = match ctl(
                    &h,
                    stream_layout::GET_RETRIEVAL,
                    &[0; 8],
                    stream_layout::RETRIEVAL_CAPACITY,
                ) {
                    Ok(bytes)
                        if ordinary
                            && i.logical_length() == 0
                            && expected_allocation == 0
                            && bytes.len() == 16
                            && layout::u32_at(&bytes, 0)? == 0
                            && layout::u64_at(&bytes, 8)? == 0 =>
                    {
                        vec![]
                    }
                    Ok(bytes) => bytes,
                    Err(e)
                        if ordinary && expected_allocation == 0 && e.raw_os_error() == Some(38) =>
                    {
                        vec![]
                    }
                    Err(e) => return Err(e),
                };
                let runs = if retrieval.is_empty() {
                    vec![]
                } else {
                    stream_layout::parse_retrieval(&retrieval)?
                };
                let mut end = 0u64;
                for r in runs {
                    if r.vcn != end
                        || r.lcn.is_none_or(|l| {
                            l.checked_add(r.clusters)
                                .is_none_or(|e| e > clusters as u64)
                        })
                    {
                        return Err(invalid("shadow physical mapping is invalid"));
                    }
                    end += r.clusters;
                }
                if (!ordinary && end * 4096 != i.logical_length())
                    || (ordinary
                        && (end * 4096 != expected_allocation
                            || (expected_allocation == 0 && i.logical_length() > 4096)
                            || (expected_allocation != 0
                                && expected_allocation
                                    < i.logical_length().next_multiple_of(4096))
                            || expected_allocation > i.logical_length().next_multiple_of(65536)))
                {
                    return Err(invalid(
                        "shadow allocation differs from initialized payload",
                    ));
                }
                let mut regions = vec![];
                for usage in [1u32, 2] {
                    if ordinary && expected_allocation == 0 {
                        regions.push(vec![]);
                        continue;
                    }
                    let mut q = [0; 24];
                    q[8..16].copy_from_slice(&i.logical_length().to_le_bytes());
                    q[16..20].copy_from_slice(&usage.to_le_bytes());
                    let b = ctl(&h, 0x90284, &q, 16 + 24 * 1024)?;
                    if ordinary {
                        crate::region_layout::validate_logical(&b, i.logical_length(), usage)?;
                    } else {
                        crate::region_layout::validate(&b, i.logical_length(), usage)?;
                    }
                    regions.push(b);
                }
                let integrity = ctl(&h, 0x9027c, &[], 16)?;
                if integrity.len() != 16
                    || integrity[..8] != [0; 8]
                    || layout::u32_at(&integrity, 12)? != 4096
                {
                    return Err(invalid("shadow data integrity profile differs"));
                }
                let logical_hash = if let Some(expected) = i.expected_sha256 {
                    let actual = hash_exact_stream(&mut h, i.logical_length())?;
                    if actual != expected {
                        return Err(invalid("converted logical stream hash differs"));
                    }
                    actual
                } else {
                    let mut bytes = vec![];
                    (&mut h)
                        .take(i.logical_length() + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes != i.payload {
                        return Err(invalid("shadow logical bytes or EOF differ"));
                    }
                    hex::encode(Sha256::digest(&bytes))
                };
                (
                    Some(logical_hash),
                    retrieval,
                    regions.remove(0),
                    regions.remove(0),
                    integrity,
                    vec![],
                )
            };
        let after = snapshot(&h);
        if before != after {
            return Err(invalid("shadow metadata changed during observation"));
        }
        let streams = if i.directory {
            vec![]
        } else {
            let mut b = info(&h, 7, stream_layout::MAX_STREAM_BUFFER)?;
            let (entries, used) = stream_layout::parse_streams(&b)?;
            if entries.len() != 1
                || !entries[0].name.is_empty()
                || entries[0].logical_size != i.logical_length()
                || entries[0].allocated_size
                    != if ordinary {
                        expected_allocation
                    } else {
                        i.logical_length()
                    }
            {
                return Err(invalid("unexpected target data stream or allocation"));
            }
            b.truncate(used);
            b
        };
        objects.push(ObjectReport {
            components: i.components.to_vec(),
            before,
            after,
            logical_sha256,
            retrieval,
            cached_validity,
            storage_validity,
            integrity,
            namespace,
            streams,
            source_candidate: i
                .source_offset
                .map(|offset| -> io::Result<_> {
                    Ok(CandidateReport {
                        legacy: crate::bitmap_layout::candidate(
                            &legacy_bitmap,
                            offset,
                            i.logical_length().next_multiple_of(4096),
                            binding.identity.partition_bytes,
                        )?,
                        metadata_inclusive: crate::bitmap_layout::candidate(
                            &metadata_bitmap,
                            offset,
                            i.logical_length().next_multiple_of(4096),
                            binding.identity.partition_bytes,
                        )?,
                    })
                })
                .transpose()?,
        });
    }
    let after = observed_shadow(&disk, &binding, general_shadow, &mut events)?;
    if after.disk_attributes != 0 {
        return Err(invalid("shadow disk state changed"));
    }
    privileges.restore()?;
    Ok(Report {
        binding,
        before,
        after,
        objects,
        metadata_allocation: Some(metadata_allocation),
        base_sectors: 0,
        privilege_states: privileges.audit().to_vec(),
        events,
        payload_bytes_written: if constructing { total as u64 } else { 0 },
        conversion_qualified: false,
        root_security,
        security_restorations,
        security_repair_preflight_sha256: None,
        security_repair_privileges: vec![],
        retention_attempts,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_shadow_names_allow_internal_spaces_but_refuse_devices() {
        assert!(valid_shadow_component("Quarterly Report 1.txt"));
        assert!(valid_shadow_component("a  b.txt"));
        assert!(valid_shadow_component("Q4 (final) #1 & notes.txt"));
        for name in [
            "a ",
            "CON.txt",
            "CON .txt",
            "COM1 .dat",
            "a:b",
            "a\\b",
            "a?b",
            "a*b",
            "é",
        ] {
            assert!(!valid_shadow_component(name), "{name}");
        }
    }
    #[test]
    fn fragmented_retention_checks_only_the_requested_vcn_window() {
        let runs = vec![
            stream_layout::Run {
                vcn: 0,
                lcn: Some(40),
                clusters: 2,
            },
            stream_layout::Run {
                vcn: 2,
                lcn: Some(100),
                clusters: 3,
            },
            stream_layout::Run {
                vcn: 5,
                lcn: Some(70),
                clusters: 2,
            },
        ];
        assert!(mapping_matches_run(&runs, 2, 100, 3).unwrap());
        assert!(mapping_matches_run(&runs, 3, 101, 2).unwrap());
        assert!(!mapping_matches_run(&runs, 2, 101, 3).unwrap());
        assert!(!mapping_matches_run(&runs, 1, 41, 4).unwrap());
        assert!(!mapping_matches_run(&runs, 2, 100, 4).unwrap());
    }
    #[test]
    fn backup_security_stream_uses_sdk_name_offset_and_keeps_descriptor_bytes() {
        use windows_sys::Win32::Storage::FileSystem::WIN32_STREAM_ID;
        assert_eq!(mem::offset_of!(WIN32_STREAM_ID, cStreamName), 20);
        let sd = vec![42; 228];
        let b = security_stream(&sd).unwrap();
        assert_eq!(b.len(), 248);
        assert_eq!(&b[20..], sd);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 228);
        assert_eq!(&b[16..20], [0; 4]);
    }
    #[test]
    fn repair_preflight_allows_only_the_measured_creation_control_bit_loss() {
        let mut expected = vec![0; 24];
        expected[0] = 1;
        expected[2..4].copy_from_slice(&0x9404u16.to_le_bytes());
        let same = |a: &[u8], b: &[u8]| Ok(a == b);
        let mut actual = expected.clone();
        actual[2..4].copy_from_slice(&0x9004u16.to_le_bytes());
        assert!(creation_loss_only(&expected, &actual, &same).unwrap());
        actual[20] = 1;
        assert!(!creation_loss_only(&expected, &actual, &same).unwrap());
        actual[20] = 0;
        actual[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        assert!(!creation_loss_only(&expected, &actual, &same).unwrap());
        assert!(!creation_loss_only(&actual, &expected, &same).unwrap());
    }
    #[test]
    fn hash_only_verification_enforces_exact_eof() {
        let bytes = vec![0x5a; 65537];
        let expected = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64).unwrap(),
            expected
        );
        assert!(hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64 + 1).is_err());
        assert!(hash_exact_stream(&mut bytes.as_slice(), bytes.len() as u64 - 1).is_err());
        assert_eq!(
            hash_exact_stream(&mut &[][..], 0).unwrap(),
            hex::encode(Sha256::digest([]))
        );
    }
}
