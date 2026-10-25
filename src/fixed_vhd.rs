//! LAB ONLY: read a fixed VHD, write new ordinary corpus artifacts. This is
//! transport for native guest evidence, never an implementation of conversion.
//!
//! Footer grammar: Microsoft Virtual Hard Disk Image Format, October 2006 v1.0,
//! https://www.microsoft.com/en-us/download/details.aspx?id=23850 .
//! No GPT interpretation or guest identity authentication is performed. The
//! host orchestrator must derive selections from independently verified guest
//! exports and a powered-off owned checkpoint's fixed-VHD copy.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

const FOOTER_BYTES: u64 = 512;
const BUFFER_BYTES: usize = 1024 * 1024;
const MAX_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_SELECTION_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSelection {
    pub schema_version: u32,
    pub expected_disk_bytes: u64,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub logical_sector_size: u32,
    pub guest_disk_unique_id: String,
    pub guest_partition_guid: String,
    pub host_vhd_id: String,
    pub evidence_path: PathBuf,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixedVhdFooter {
    pub current_size: u64,
    pub original_size: u64,
    pub uuid_bytes_hex: String,
    pub footer_sha256: String,
    pub checksum: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractionRecord {
    pub schema_version: u32,
    pub status: String,
    pub method: String,
    pub source_path: PathBuf,
    pub source_length: u64,
    pub source_sha256: String,
    pub source_before_after_equal: bool,
    pub footer: FixedVhdFooter,
    pub selection_path: PathBuf,
    pub selection_sha256: String,
    pub selection: PartitionSelection,
    pub evidence_path: PathBuf,
    pub evidence_sha256: String,
    pub output_path: PathBuf,
    pub output_length: u64,
    pub output_sha256: String,
    pub output_readback_verified: bool,
    pub gpt_validated: bool,
    pub guest_identity_authenticated: bool,
    pub filesystem_validated: bool,
    pub conversion_qualified: bool,
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("footer bounds"))
}

fn be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("footer bounds"))
}

/// Accept only the modern 512-byte footer of a plain fixed VHD v1.0.
pub fn validate_footer(
    bytes: &[u8],
    file_length: u64,
    expected_disk_bytes: u64,
) -> Result<FixedVhdFooter> {
    ensure!(
        bytes.len() == FOOTER_BYTES as usize,
        "expected exactly 512 footer bytes"
    );
    ensure!(
        &bytes[..8] == b"conectix",
        "fixed VHD footer cookie missing"
    );
    ensure!(
        be_u32(bytes, 8) == 2,
        "temporary or unknown VHD features are unsupported"
    );
    ensure!(be_u32(bytes, 12) == 0x0001_0000, "unsupported VHD version");
    ensure!(
        be_u64(bytes, 16) == u64::MAX,
        "fixed VHD data offset must be the all-ones sentinel"
    );
    ensure!(be_u32(bytes, 60) == 2, "only fixed VHD type 2 is supported");
    ensure!(bytes[84] == 0, "saved-state VHD is unsupported");
    ensure!(
        bytes[85..].iter().all(|byte| *byte == 0),
        "unknown reserved VHD footer fields"
    );
    ensure!(
        bytes[68..84].iter().any(|byte| *byte != 0),
        "VHD UUID must not be empty"
    );
    let checksum = be_u32(bytes, 64);
    let sum: u32 = bytes
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .map(|(_, b)| u32::from(*b))
        .sum();
    ensure!(checksum == !sum, "VHD footer checksum mismatch");
    let current_size = be_u64(bytes, 48);
    let original_size = be_u64(bytes, 40);
    ensure!(
        (FOOTER_BYTES..=MAX_DISK_BYTES).contains(&current_size) && current_size.is_multiple_of(512),
        "unsupported VHD disk size"
    );
    ensure!(
        original_size > 0 && original_size.is_multiple_of(512),
        "invalid VHD original size"
    );
    ensure!(
        current_size == expected_disk_bytes,
        "VHD size differs from explicit selection"
    );
    ensure!(
        current_size.checked_add(FOOTER_BYTES) == Some(file_length),
        "fixed VHD length differs from payload plus footer"
    );
    Ok(FixedVhdFooter {
        current_size,
        original_size,
        uuid_bytes_hex: hex::encode(&bytes[68..84]),
        footer_sha256: hex::encode(Sha256::digest(bytes)),
        checksum,
    })
}

fn is_guid(value: &str) -> bool {
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
        && value
            .bytes()
            .any(|byte| byte.is_ascii_hexdigit() && byte != b'0')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_selection(selection: &PartitionSelection) -> Result<()> {
    ensure!(
        selection.schema_version == 1,
        "unsupported partition selection schema"
    );
    ensure!(
        selection.logical_sector_size == 512,
        "fixed VHD selection requires 512-byte logical sectors"
    );
    ensure!(
        selection.expected_disk_bytes >= 512
            && selection.expected_disk_bytes <= MAX_DISK_BYTES
            && selection.expected_disk_bytes.is_multiple_of(512),
        "selection disk size is outside bounded aligned profile"
    );
    ensure!(
        selection.length_bytes >= 512
            && selection.offset_bytes.is_multiple_of(512)
            && selection.length_bytes.is_multiple_of(512),
        "partition range must be nonempty and sector aligned"
    );
    ensure!(
        selection
            .offset_bytes
            .checked_add(selection.length_bytes)
            .is_some_and(|end| end <= selection.expected_disk_bytes),
        "partition range exceeds disk or overflows"
    );
    ensure!(
        !selection.guest_disk_unique_id.is_empty()
            && selection.guest_disk_unique_id.len() <= 256
            && selection
                .guest_disk_unique_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_{}".contains(&byte)),
        "invalid guest disk identity"
    );
    ensure!(
        is_guid(&selection.guest_partition_guid) && is_guid(&selection.host_vhd_id),
        "selection requires nonzero partition and host VHD GUIDs"
    );
    ensure!(
        is_sha256(&selection.evidence_sha256),
        "selection requires an evidence SHA-256"
    );
    Ok(())
}

fn reject_special_metadata(metadata: &Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlink paths are not accepted"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "reparse-point paths are not accepted"
        );
    }
    Ok(())
}

/// Validate each existing component without following symlinks/reparse points.
/// Reject parent traversal and Windows namespaces/alternate data streams.
pub(crate) fn checked_path(path: &Path, missing_leaf_allowed: bool) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "empty path");
    #[cfg(windows)]
    {
        use std::path::Prefix;
        ensure!(
            path.is_absolute()
                || !path
                    .components()
                    .any(|component| matches!(component, Component::Prefix(_))),
            "drive-relative Windows paths are unsupported"
        );
        for component in path.components() {
            if let Component::Prefix(prefix) = component {
                ensure!(
                    matches!(prefix.kind(), Prefix::Disk(_)),
                    "only local ordinary drive paths are accepted"
                );
            }
            if let Component::Normal(name) = component {
                let name = name.to_string_lossy();
                ensure!(
                    !name.contains(':') && !name.ends_with(['.', ' ']),
                    "alternate streams or ambiguous Windows names are unsupported"
                );
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                let numbered_device = (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.len() == 4
                    && stem.as_bytes()[3].is_ascii_digit();
                ensure!(
                    !matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) && !numbered_device,
                    "Windows device names are unsupported"
                );
            }
        }
    }
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "parent traversal is unsupported"
    );
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    #[cfg(windows)]
    ensure!(
        path.is_absolute() || !path.has_root(),
        "drive-relative/root-relative Windows paths are unsupported"
    );
    let components: Vec<_> = absolute.components().collect();
    let mut cursor = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                reject_special_metadata(&metadata)?;
                if index + 1 != components.len() {
                    ensure!(metadata.is_dir(), "path parent is not a directory");
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && missing_leaf_allowed
                    && index + 1 == components.len() => {}
            Err(error) => return Err(error).context("validate ordinary file path"),
        }
    }
    Ok(absolute)
}

pub(crate) fn open_read_only(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000); // READ sharing; OPEN_REPARSE_POINT.
    }
    let file = options
        .open(path)
        .context("open regular source read-only without writer/delete sharing")?;
    let metadata = file.metadata()?;
    reject_special_metadata(&metadata)?;
    ensure!(metadata.is_file(), "source/evidence must be a regular file");
    Ok(file)
}

pub(crate) fn create_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0).custom_flags(0x0020_0000);
    }
    options
        .open(path)
        .context("create new artifact (existing files are never overwritten)")
}

fn hash_file(file: &mut File, expected_length: u64) -> Result<String> {
    ensure!(
        file.metadata()?.len() == expected_length,
        "file length changed before hashing"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut remaining = expected_length;
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(BUFFER_BYTES as u64))?;
        file.read_exact(&mut buffer[..requested])
            .context("hash complete file")?;
        digest.update(&buffer[..requested]);
        remaining -= requested as u64;
    }
    ensure!(
        file.read(&mut [0_u8; 1])? == 0 && file.metadata()?.len() == expected_length,
        "file length changed during hashing"
    );
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

pub(crate) fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("artifact already exists: {}", path.display()),
        Err(error) => Err(error).context("check artifact absence"),
    }
}

/// A new hard link fails if the destination exists. rename() may replace a
/// concurrently created destination, so it is not used. Both names share one
/// validated parent; any failure retains artifacts and cannot complete a report.
pub(crate) fn publish_new(partial: &Path, final_path: &Path) -> Result<()> {
    fs::hard_link(partial, final_path)
        .context("publish without overwrite (destination filesystem must support hard links)")?;
    fs::remove_file(partial).context("remove only the published artifact's partial link")?;
    Ok(())
}

/// Extract every byte of a caller-selected partition. No live devices, mounting,
/// repair, filesystem conversion, or raw disk writes are implemented here.
pub fn extract(source: &Path, output: &Path, selection_path: &Path) -> Result<ExtractionRecord> {
    let source = checked_path(source, false)?;
    let selection_path = checked_path(selection_path, false)?;
    let output = checked_path(output, true)?;
    ensure!(
        output
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("raw")),
        "output must have a .raw extension"
    );
    let partial = append_suffix(&output, ".partial");
    let manifest = append_suffix(&output, ".json");
    let manifest_partial = append_suffix(&output, ".json.partial");
    for path in [&output, &partial, &manifest, &manifest_partial] {
        require_absent(path)?;
    }

    let mut selection_file = open_read_only(&selection_path)?;
    let selection_length = selection_file.metadata()?.len();
    ensure!(
        selection_length > 0 && selection_length <= MAX_SELECTION_BYTES,
        "selection JSON exceeds bound or is empty"
    );
    let selection_sha256 = hash_file(&mut selection_file, selection_length)?;
    selection_file.seek(SeekFrom::Start(0))?;
    let mut selection_bytes = vec![0_u8; selection_length as usize];
    selection_file.read_exact(&mut selection_bytes)?;
    ensure!(
        selection_file.read(&mut [0_u8; 1])? == 0,
        "selection changed during parsing"
    );
    let selection_json = selection_bytes
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&selection_bytes);
    let selection: PartitionSelection =
        serde_json::from_slice(selection_json).context("read selection JSON")?;
    validate_selection(&selection)?;
    let evidence_path = if selection.evidence_path.is_absolute() {
        selection.evidence_path.clone()
    } else {
        selection_path
            .parent()
            .context("selection parent")?
            .join(&selection.evidence_path)
    };
    let evidence_path = checked_path(&evidence_path, false)?;
    let mut evidence_file = open_read_only(&evidence_path)?;
    let evidence_length = evidence_file.metadata()?.len();
    ensure!(
        evidence_length > 0 && evidence_length <= MAX_EVIDENCE_BYTES,
        "guest evidence exceeds bound or is empty"
    );
    let evidence_sha256 = hash_file(&mut evidence_file, evidence_length)?;
    ensure!(
        evidence_sha256.eq_ignore_ascii_case(&selection.evidence_sha256),
        "guest evidence hash differs from selection"
    );

    let mut input = open_read_only(&source)?;
    let source_length = input.metadata()?.len();
    ensure!(
        (1024..=MAX_DISK_BYTES + FOOTER_BYTES).contains(&source_length),
        "source is outside bounded fixed-VHD profile"
    );
    let mut leading_magic = [0_u8; 8];
    input.read_exact(&mut leading_magic)?;
    ensure!(
        &leading_magic != b"vhdxfile" && &leading_magic != b"conectix",
        "VHDX or a mirrored dynamic/differencing VHD is unsupported"
    );
    input.seek(SeekFrom::End(-(FOOTER_BYTES as i64)))?;
    let mut footer_bytes = [0_u8; FOOTER_BYTES as usize];
    input.read_exact(&mut footer_bytes)?;
    let footer = validate_footer(&footer_bytes, source_length, selection.expected_disk_bytes)?;
    let source_sha256 = hash_file(&mut input, source_length)?;

    let mut destination = create_new(&partial)?;
    input.seek(SeekFrom::Start(selection.offset_bytes))?;
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut remaining = selection.length_bytes;
    let mut range_digest = Sha256::new();
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(BUFFER_BYTES as u64))?;
        input
            .read_exact(&mut buffer[..requested])
            .context("read complete selected partition")?;
        range_digest.update(&buffer[..requested]);
        destination
            .write_all(&buffer[..requested])
            .context("write new partition artifact")?;
        remaining -= requested as u64;
    }
    destination.sync_all()?;
    let output_sha256 = hex::encode(range_digest.finalize());
    ensure!(
        hash_file(&mut destination, selection.length_bytes)? == output_sha256,
        "output readback hash mismatch; partial retained"
    );
    ensure!(
        hash_file(&mut input, source_length)? == source_sha256,
        "source changed during extraction; partial retained"
    );
    ensure!(
        hash_file(&mut selection_file, selection_length)? == selection_sha256
            && hash_file(&mut evidence_file, evidence_length)? == evidence_sha256,
        "selection/evidence changed during extraction; partial retained"
    );
    drop(destination);

    let record = ExtractionRecord {
        schema_version: 1,
        status: "complete".into(),
        method: "lab corpus transport: full partition range from regular fixed VHD; source before/after hashes; output readback hash".into(),
        source_path: source,
        source_length,
        source_sha256,
        source_before_after_equal: true,
        footer,
        selection_path,
        selection_sha256,
        evidence_path,
        evidence_sha256,
        output_path: output.clone(),
        output_length: selection.length_bytes,
        output_sha256,
        selection,
        output_readback_verified: true,
        gpt_validated: false,
        guest_identity_authenticated: false,
        filesystem_validated: false,
        conversion_qualified: false,
    };
    let mut manifest_file = create_new(&manifest_partial)?;
    serde_json::to_writer_pretty(&mut manifest_file, &record)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    drop(manifest_file);
    publish_new(&partial, &output)?;
    publish_new(&manifest_partial, &manifest)?;
    Ok(record)
}
