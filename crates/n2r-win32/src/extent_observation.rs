//! Fresh mounted ReFS retrieval observations. This is a read-only diagnostic:
//! no payload reads, volume locks, setters, allocation or reconstruction.
use crate::{
    GeneralProbe, NativeEvent,
    general_layout::GeneralDiskBinding,
    layout, native,
    reference_file::{self, ReferenceFileSnapshot},
    retrieval_paging, shadow_names, stream_layout, stream_native,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
};

pub const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_FILES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequest {
    pub components: Vec<String>,
    pub expected_file_id: Vec<u8>,
    pub expected_volume_serial: Vec<u8>,
    pub expected_length: u64,
    pub expected_retrieval: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub kind: String,
    pub binding: GeneralDiskBinding,
    pub cluster_bytes: u32,
    pub files: Vec<FileRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Span {
    pub vcn: u64,
    pub lcn: Option<u64>,
    pub clusters: u64,
}

#[derive(Debug, Serialize)]
pub struct FileObservation {
    pub expected: FileRequest,
    pub before: Option<ReferenceFileSnapshot>,
    pub after: Option<ReferenceFileSnapshot>,
    /// Complete assembled zero-VCN map, with the actual native page transcript
    /// hashes retained separately; this is not a fabricated expected map.
    pub actual_retrieval: Vec<u8>,
    pub actual_retrieval_page_proof: Option<retrieval_paging::Proof>,
    pub expected_spans: Vec<Span>,
    pub actual_spans: Vec<Span>,
    pub identity_matches: bool,
    pub identity_stable: bool,
    pub length_matches: bool,
    pub retrieval_matches: bool,
    pub expected_matches: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub kind: &'static str,
    pub binding: GeneralDiskBinding,
    pub cluster_bytes: u32,
    pub before: GeneralProbe,
    pub after: GeneralProbe,
    pub filesystem_before: String,
    pub filesystem_after: String,
    pub geometry_before: crate::attestation::IoctlQuery,
    pub geometry_after: crate::attestation::IoctlQuery,
    pub retrieval_base_before: crate::attestation::IoctlQuery,
    pub retrieval_base_after: crate::attestation::IoctlQuery,
    pub files: Vec<FileObservation>,
    pub events: Vec<NativeEvent>,
    pub files_requested: usize,
    pub files_matching: usize,
    pub success: bool,
    pub payload_bytes_read: u64,
    pub source_write_requests: u64,
    pub raw_write_authority: bool,
    pub atomic_volume_snapshot_claimed: bool,
    pub conversion_qualified: bool,
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(bad(message)) }
}

struct Size(u64);
impl Write for Size {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| bad("JSON size overflow"))?;
        require(
            self.0 <= MAX_REPORT_BYTES,
            "extent JSON exceeds the report bound",
        )?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encoded_size(value: &impl Serialize) -> io::Result<u64> {
    let mut size = Size(0);
    serde_json::to_writer(&mut size, value).map_err(io::Error::other)?;
    Ok(size.0)
}

fn normalized(bytes: &[u8], length: u64, partition_bytes: u64) -> io::Result<Vec<Span>> {
    let runs = stream_layout::parse_complete_retrieval(bytes)?;
    let mut result: Vec<Span> = Vec::new();
    for run in runs {
        let end = run
            .vcn
            .checked_add(run.clusters)
            .ok_or_else(|| bad("retrieval VCN overflow"))?;
        require(
            end <= partition_bytes / 4096,
            "retrieval virtual range exceeds lab volume",
        )?;
        if let Some(lcn) = run.lcn {
            require(
                lcn.checked_add(run.clusters)
                    .is_some_and(|end| end <= partition_bytes / 4096),
                "retrieval physical range exceeds volume",
            )?;
        }
        let merge = result.last().is_some_and(|last| {
            last.vcn + last.clusters == run.vcn
                && match (last.lcn, run.lcn) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.checked_add(last.clusters) == Some(b),
                    _ => false,
                }
        });
        if merge {
            result.last_mut().unwrap().clusters += run.clusters;
        } else {
            result.push(Span {
                vcn: run.vcn,
                lcn: run.lcn,
                clusters: run.clusters,
            });
        }
    }
    require(
        result
            .last()
            .is_some_and(|r| r.vcn + r.clusters >= length.div_ceil(4096)),
        "retrieval does not cover the expected logical length",
    )?;
    Ok(result)
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        require(
            self.schema_version == 1
                && self.kind == "readonly-refs-extent-request"
                && self.cluster_bytes == 4096
                && (1..=MAX_FILES).contains(&self.files.len()),
            "extent request schema, cluster or file count differs",
        )?;
        require(
            encoded_size(self)? <= MAX_REQUEST_BYTES,
            "extent request exceeds four MiB",
        )?;
        let mut paths = BTreeSet::new();
        let serial = &self.files[0].expected_volume_serial;
        for file in &self.files {
            require(
                (1..=16).contains(&file.components.len())
                    && file
                        .components
                        .iter()
                        .all(|s| shadow_names::valid_unicode_component(s))
                    && paths.insert(shadow_names::conservative_path_key(&file.components)),
                "extent file path is unsupported or duplicated",
            )?;
            require(
                file.expected_file_id.len() == 16
                    && file.expected_file_id.iter().any(|b| *b != 0)
                    && file.expected_volume_serial.len() == 8
                    && file.expected_volume_serial.iter().any(|b| *b != 0)
                    && &file.expected_volume_serial == serial
                    && file.expected_length > 0
                    && file.expected_length <= self.binding.identity.partition_bytes,
                "extent file identity, serial or length differs",
            )?;
            normalized(
                &file.expected_retrieval,
                file.expected_length,
                self.binding.identity.partition_bytes,
            )?;
        }
        Ok(())
    }
}

fn open_readonly(path: &str) -> io::Result<File> {
    // READ only; existing/new writers and deleters cannot share this handle.
    // OPEN_REPARSE_POINT prevents following the final component; every ancestor
    // is separately opened, rejected if reparse, and held through the query.
    OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0220_0000)
        .open(path)
}
fn opened_file(root: &str, components: &[String]) -> io::Result<(File, Vec<File>)> {
    let mut held = Vec::new();
    let mut path = root.to_owned();
    for component in components {
        let parent = open_readonly(&path)?;
        let meta = parent.metadata()?;
        require(
            meta.is_dir() && meta.file_attributes() & 0x400 == 0,
            "extent path ancestor is not an ordinary directory",
        )?;
        held.push(parent);
        if !path.ends_with('\\') {
            path.push('\\');
        }
        path.push_str(component);
    }
    let file = open_readonly(&path)?;
    Ok((file, held))
}

fn expected_identity(file: &FileRequest, observed: &ReferenceFileSnapshot) -> bool {
    observed.file_id_128.as_slice() == file.expected_file_id.as_slice()
        && observed.volume_serial_number.to_le_bytes().as_slice()
            == file.expected_volume_serial.as_slice()
}
fn observe_file(root: &str, file: &FileRequest, partition_bytes: u64) -> FileObservation {
    let mut result = FileObservation {
        expected: file.clone(),
        before: None,
        after: None,
        actual_retrieval: Vec::new(),
        actual_retrieval_page_proof: None,
        expected_spans: Vec::new(),
        actual_spans: Vec::new(),
        identity_matches: false,
        identity_stable: false,
        length_matches: false,
        retrieval_matches: false,
        expected_matches: false,
        error: None,
    };
    let observed = (|| -> io::Result<()> {
        result.expected_spans = normalized(
            &file.expected_retrieval,
            file.expected_length,
            partition_bytes,
        )?;
        let (handle, _parents) = opened_file(root, &file.components)?;
        let before = reference_file::observe_reference_file_handle(&handle)?;
        require(
            before.final_path.eq_ignore_ascii_case(&format!(
                "{}{}",
                root,
                file.components.join("\\")
            )),
            "opened extent file resolves outside its requested volume path",
        )?;
        result.identity_matches = expected_identity(file, &before);
        result.length_matches = before.file_bytes == file.expected_length;
        result.before = Some(before.clone());
        require(
            result.identity_matches && result.length_matches,
            "opened extent file identity or length differs from the expected record",
        )?;
        let capture = stream_native::retrieval_capture(&handle)?;
        result.actual_retrieval = capture.canonical;
        result.actual_retrieval_page_proof = Some(capture.proof);
        result.actual_spans = normalized(
            &result.actual_retrieval,
            file.expected_length,
            partition_bytes,
        )?;
        result.retrieval_matches = result.actual_spans == result.expected_spans;
        let after = reference_file::observe_reference_file_handle(&handle)?;
        result.identity_stable = before.file_id_128 == after.file_id_128
            && before.volume_serial_number == after.volume_serial_number
            && before.file_bytes == after.file_bytes
            && before.final_path == after.final_path;
        result.identity_matches &= expected_identity(file, &after);
        result.length_matches &= after.file_bytes == file.expected_length;
        result.after = Some(after);
        result.expected_matches = result.identity_stable
            && result.identity_matches
            && result.length_matches
            && result.retrieval_matches;
        Ok(())
    })();
    if let Err(error) = observed {
        result.error = Some(error.to_string());
    }
    result
}

fn geometry(
    volume: &File,
    binding: &GeneralDiskBinding,
) -> io::Result<crate::attestation::IoctlQuery> {
    let query = stream_native::ioctl(volume, 0x0009_02d8, &[], 256);
    let data = &query.bytes;
    require(
        query.native_error.is_none()
            && data.len() >= 64
            && (64..=data.len()).contains(&(layout::u32_at(data, 0)? as usize))
            && layout::u32_at(data, 4)? == 3
            && layout::u32_at(data, 8)? == 14
            && layout::u64_at(data, 24)? == binding.identity.partition_bytes / 512
            && layout::u64_at(data, 32)? == binding.identity.partition_bytes / 4096
            && layout::u32_at(data, 56)? == 512
            && layout::u32_at(data, 60)? == 4096,
        "native ReFS3.14/4KiB volume geometry differs",
    )?;
    Ok(query)
}
fn base(volume: &File) -> io::Result<crate::attestation::IoctlQuery> {
    let query = stream_native::base(volume);
    require(
        query.native_error.is_none()
            && query.bytes.len() == 8
            && layout::u64_at(&query.bytes, 0)? == 0,
        "native ReFS retrieval base is not zero",
    )?;
    Ok(query)
}

/// Observe mounted ordinary files without reading payload or changing storage
/// state. Returned JSON is evidence, never a source certificate/write ticket.
pub fn query(request: &Request) -> io::Result<Report> {
    request.validate()?;
    let mut events = Vec::new();
    let before = native::probe_general(request.binding.clone(), &mut events)?;
    let filesystem_before =
        native::mounted_filesystem_general(request.binding.clone(), &mut events)?;
    require(
        filesystem_before == "ReFS",
        "extent observation requires mounted ReFS",
    )?;
    let volume = native::device_file(&request.binding.volume_path()?, false, false)?;
    let geometry_before = geometry(&volume, &request.binding)?;
    let retrieval_base_before = base(&volume)?;
    let root = request.binding.volume_path()? + "\\";
    let mut files = Vec::with_capacity(request.files.len());
    let mut bytes = 0u64;
    for file in &request.files {
        let row = observe_file(&root, file, request.binding.identity.partition_bytes);
        bytes = bytes
            .checked_add(encoded_size(&row)?)
            .ok_or_else(|| bad("extent report size overflow"))?;
        require(
            bytes <= MAX_REPORT_BYTES - 8 * 1024 * 1024,
            "extent rows exceed report budget",
        )?;
        files.push(row);
    }
    let geometry_after = geometry(&volume, &request.binding)?;
    let retrieval_base_after = base(&volume)?;
    let filesystem_after =
        native::mounted_filesystem_general(request.binding.clone(), &mut events)?;
    let after = native::probe_general(request.binding.clone(), &mut events)?;
    let stable = before.binding == after.binding
        && before.device == after.device
        && before.disk_length == after.disk_length
        && before.alignment == after.alignment
        && before.gpt_layout == after.gpt_layout
        && before.volume_extents == after.volume_extents
        && before.disk_attributes_before == after.disk_attributes_before
        && before.disk_attributes_after == after.disk_attributes_after
        && geometry_before.bytes == geometry_after.bytes
        && retrieval_base_before.bytes == retrieval_base_after.bytes
        && filesystem_after == filesystem_before;
    let files_matching = files
        .iter()
        .filter(|f| f.expected_matches && f.error.is_none())
        .count();
    let result = Report {
        schema_version: 1,
        kind: "readonly-refs-extent-observation",
        binding: request.binding.clone(),
        cluster_bytes: 4096,
        before,
        after,
        filesystem_before,
        filesystem_after,
        geometry_before,
        geometry_after,
        retrieval_base_before,
        retrieval_base_after,
        files_requested: files.len(),
        files_matching,
        success: stable && files_matching == files.len(),
        files,
        events,
        payload_bytes_read: 0,
        source_write_requests: 0,
        raw_write_authority: false,
        atomic_volume_snapshot_claimed: false,
        conversion_qualified: false,
    };
    require(
        encoded_size(&result)? <= MAX_REPORT_BYTES,
        "extent report exceeds bound",
    )?;
    Ok(result)
}
