//! Lab-only byte comparison. Inputs are read-only; retained file semantics and
//! write authority are outside this module's scope.
use crate::block_io::SourceIdentity;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_RETAINED_RANGES: usize = 1024;
const MAX_PATCH_RANGES: u32 = 65_536;
const BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedRangeRequest {
    pub offset: u64,
    pub length: u64,
    pub source_sha256: String,
    pub shadow_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCompareRequest {
    pub schema_version: u32,
    pub sector_size: u32,
    pub expected_length: u64,
    pub source_sha256: String,
    pub shadow_sha256: String,
    pub retained_ranges: Vec<RetainedRangeRequest>,
    /// Complete differing non-retained sectors, not merely differing bytes.
    pub max_change_bytes: u64,
    pub max_ranges: u32,
}

#[derive(Debug, Serialize)]
pub struct ComparedPatch {
    pub offset: u64,
    pub length: u64,
    pub before_sha256: String,
    pub after_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RetainedRangeObservation {
    pub offset: u64,
    pub length: u64,
    pub bytes_compared: u64,
    pub source_sha256: String,
    pub shadow_sha256: String,
    pub differing_bytes: u64,
    pub differing_sectors: u64,
    pub hashes_match_request: bool,
}

#[derive(Debug, Serialize)]
pub struct RetainedComparison {
    pub schema_version: u32,
    pub kind: String,
    pub request: RetainedCompareRequest,
    pub source: SourceIdentity,
    pub shadow: SourceIdentity,
    /// Partition positions compared, each exactly once in the first pass.
    pub compared_bytes: u64,
    pub differing_bytes: u64,
    pub differing_sectors: u64,
    pub retained_bytes: u64,
    pub retained_differing_bytes: u64,
    pub retained_differing_sectors: u64,
    pub nonretained_differing_bytes: u64,
    pub patch_bytes: u64,
    pub patches: Vec<ComparedPatch>,
    pub retained_ranges: Vec<RetainedRangeObservation>,
    pub expected_postimage_sha256: String,
    pub source_shadow_unchanged_after_comparison: bool,
    /// Two complete passes over both files; excludes the container probes.
    pub full_scan_input_bytes_read: u64,
    pub container_probe_bytes_read: u64,
    pub total_input_bytes_read: u64,
    pub executable: bool,
    pub retained_file_semantics_verified: bool,
    pub native_attestations_verified: bool,
    pub allocation_qualified: bool,
    pub conversion_qualified: bool,
    pub boot_qualified: bool,
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_request(request: &RetainedCompareRequest) -> Result<()> {
    ensure!(
        matches!(request.schema_version, 1 | 2),
        "unsupported comparison schema"
    );
    ensure!(
        matches!(request.sector_size, 512 | 4096),
        "sector size must be 512 or 4096"
    );
    let sector = u64::from(request.sector_size);
    ensure!(
        (sector..=MAX_IMAGE_BYTES).contains(&request.expected_length)
            && request.expected_length.is_multiple_of(sector),
        "expected image length is not bounded and sector aligned"
    );
    ensure!(
        valid_hash(&request.source_sha256) && valid_hash(&request.shadow_sha256),
        "whole-image SHA-256 pins must be lowercase hexadecimal"
    );
    ensure!(
        (1..=MAX_PATCH_RANGES).contains(&request.max_ranges),
        "patch range budget must be 1..=65536"
    );
    ensure!(
        request.max_change_bytes <= request.expected_length,
        "changed-sector byte budget exceeds image length"
    );
    ensure!(
        request.retained_ranges.len() <= MAX_RETAINED_RANGES
            && (request.schema_version == 2 || !request.retained_ranges.is_empty()),
        "schema 1 requires 1..=1024 retained ranges; tree schema 2 permits relocation-only reconstruction"
    );
    let mut end = 0;
    for range in &request.retained_ranges {
        ensure!(
            range.length > 0
                && range.offset.is_multiple_of(sector)
                && range.length.is_multiple_of(sector),
            "retained range must be nonempty and sector aligned"
        );
        ensure!(
            range.offset >= end,
            "retained ranges overlap or are unsorted"
        );
        end = range
            .offset
            .checked_add(range.length)
            .context("retained range overflow")?;
        ensure!(
            end <= request.expected_length,
            "retained range outside image"
        );
        ensure!(
            valid_hash(&range.source_sha256) && valid_hash(&range.shadow_sha256),
            "retained SHA-256 pins must be lowercase hexadecimal"
        );
    }
    Ok(())
}

fn reject_redirect(metadata: &Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlinks are unsupported"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "reparse points are unsupported"
        );
    }
    Ok(())
}

fn ordinary_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "empty image path");
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)),
        "parent traversal is unsupported"
    );
    #[cfg(windows)]
    {
        use std::path::Prefix;
        ensure!(
            path.is_absolute()
                || (!path.has_root()
                    && !path
                        .components()
                        .any(|part| matches!(part, Component::Prefix(_)))),
            "drive-relative/root-relative paths are unsupported"
        );
        for part in path.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(_)),
                    "only ordinary local drive paths are accepted"
                ),
                Component::Normal(name) => {
                    let name = name.to_string_lossy();
                    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                    let device_number = (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.len() == 4
                        && stem.as_bytes()[3].is_ascii_digit();
                    ensure!(
                        !name.contains(':')
                            && !name.ends_with(['.', ' '])
                            && !device_number
                            && !matches!(
                                stem.as_str(),
                                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                            ),
                        "alternate streams, device names and ambiguous paths are unsupported"
                    );
                }
                _ => {}
            }
        }
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut cursor = PathBuf::new();
    let parts: Vec<_> = absolute.components().collect();
    for (index, part) in parts.iter().enumerate() {
        cursor.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).context("check ordinary image path")?;
        reject_redirect(&metadata)?;
        if index + 1 != parts.len() {
            ensure!(metadata.is_dir(), "image ancestor is not a directory");
        } else {
            ensure!(metadata.is_file(), "image must be a regular file");
        }
    }
    Ok(absolute)
}

struct Input {
    file: File,
    path: PathBuf,
    original_path: PathBuf,
    metadata: Metadata,
}

fn open_input(path: &Path, length: u64) -> Result<Input> {
    let original_path = ordinary_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let mut file = options
        .open(&original_path)
        .context("open input read-only")?;
    let metadata = file.metadata()?;
    reject_redirect(&metadata)?;
    ensure!(
        metadata.is_file() && metadata.len() == length,
        "image length/type differs from request"
    );
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    ensure!(
        &magic != b"vhdxfile" && &magic != b"conectix",
        "container is not a raw image"
    );
    file.seek(SeekFrom::End(-512))?;
    file.read_exact(&mut magic)?;
    ensure!(&magic != b"conectix", "VHD footer is not a raw image");
    file.seek(SeekFrom::Start(0))?;
    let path = original_path.canonicalize()?;
    Ok(Input {
        file,
        path,
        original_path,
        metadata,
    })
}

pub(crate) fn hash_reader<R: Read + Seek>(reader: &mut R, length: u64) -> Result<String> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; BUFFER_BYTES];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(BUFFER_BYTES as u64))?;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(hex::encode(hash.finalize()))
}

fn verify_input_binding(input: &Input) -> Result<()> {
    let current = input.file.metadata()?;
    ensure!(
        current.len() == input.metadata.len(),
        "input length changed after comparison"
    );
    let ordinary = ordinary_path(&input.original_path)?;
    ensure!(
        ordinary.canonicalize()? == input.path,
        "input path changed after comparison"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_metadata = fs::metadata(&ordinary)?;
        ensure!(
            path_metadata.dev() == current.dev() && path_metadata.ino() == current.ino(),
            "input file identity changed"
        );
    }
    Ok(())
}

#[derive(Default)]
struct RangeHashes {
    source: Sha256,
    shadow: Sha256,
    bytes: u64,
    differing_bytes: u64,
    differing_sectors: u64,
}

struct PendingPatch {
    offset: u64,
    length: u64,
    source: Sha256,
    shadow: Sha256,
}

fn finish_patch(pending: &mut Option<PendingPatch>, patches: &mut Vec<ComparedPatch>) {
    if let Some(patch) = pending.take() {
        patches.push(ComparedPatch {
            offset: patch.offset,
            length: patch.length,
            before_sha256: hex::encode(patch.source.finalize()),
            after_sha256: hex::encode(patch.shadow.finalize()),
        });
    }
}

/// Compare every byte in two fully pinned raw files. A pin, read, stability or
/// budget failure returns no report. This emits neither patch payloads nor any
/// authorization to write, and makes no assertion about filesystem semantics.
pub fn compare_retained(
    source: &Path,
    shadow: &Path,
    request: &RetainedCompareRequest,
) -> Result<RetainedComparison> {
    validate_request(request)?;
    let mut source = open_input(source, request.expected_length)?;
    let mut shadow = open_input(shadow, request.expected_length)?;
    let mut report = compare_streams(&mut source.file, &mut shadow.file, request)?;
    verify_input_binding(&source)?;
    verify_input_binding(&shadow)?;
    report.source.path = source.path;
    report.shadow.path = shadow.path;
    report.container_probe_bytes_read = 32;
    report.total_input_bytes_read += 32;
    Ok(report)
}

/// Internal bounded stream engine. Callers establish lengths and exclusive
/// ownership; returned empty paths confer no storage identity.
pub(crate) fn compare_streams<R: Read + Seek, S: Read + Seek>(
    source: &mut R,
    shadow: &mut S,
    request: &RetainedCompareRequest,
) -> Result<RetainedComparison> {
    validate_request(request)?;
    source.seek(SeekFrom::Start(0))?;
    shadow.seek(SeekFrom::Start(0))?;
    let mut source_hash = Sha256::new();
    let mut shadow_hash = Sha256::new();
    let mut post_hash = Sha256::new();
    let mut retained: Vec<_> = request
        .retained_ranges
        .iter()
        .map(|_| RangeHashes::default())
        .collect();
    let mut patches = Vec::new();
    let mut pending: Option<PendingPatch> = None;
    let mut left = vec![0; BUFFER_BYTES];
    let mut right = vec![0; BUFFER_BYTES];
    let mut offset = 0;
    let mut retained_index = 0;
    let mut differing_bytes = 0;
    let mut differing_sectors = 0;
    let mut patch_bytes = 0_u64;
    let sector = request.sector_size as usize;
    while offset < request.expected_length {
        let count = usize::try_from((request.expected_length - offset).min(BUFFER_BYTES as u64))?;
        source.read_exact(&mut left[..count])?;
        shadow.read_exact(&mut right[..count])?;
        source_hash.update(&left[..count]);
        shadow_hash.update(&right[..count]);
        for index in (0..count).step_by(sector) {
            let position = offset + index as u64;
            let a = &left[index..index + sector];
            let b = &right[index..index + sector];
            let changed = a.iter().zip(b).filter(|(x, y)| x != y).count() as u64;
            differing_bytes += changed;
            differing_sectors += u64::from(changed != 0);
            while retained_index < request.retained_ranges.len()
                && position
                    >= request.retained_ranges[retained_index].offset
                        + request.retained_ranges[retained_index].length
            {
                retained_index += 1;
            }
            let in_retained = retained_index < request.retained_ranges.len()
                && position >= request.retained_ranges[retained_index].offset;
            if in_retained {
                finish_patch(&mut pending, &mut patches);
                let hashes = &mut retained[retained_index];
                hashes.source.update(a);
                hashes.shadow.update(b);
                hashes.bytes += sector as u64;
                hashes.differing_bytes += changed;
                hashes.differing_sectors += u64::from(changed != 0);
                post_hash.update(a);
            } else {
                post_hash.update(b);
                if changed == 0 {
                    finish_patch(&mut pending, &mut patches);
                    continue;
                }
                patch_bytes = patch_bytes
                    .checked_add(sector as u64)
                    .context("changed-sector byte overflow")?;
                ensure!(
                    patch_bytes <= request.max_change_bytes,
                    "changed-sector byte budget exceeded"
                );
                if pending.is_none() {
                    ensure!(
                        patches.len() < request.max_ranges as usize,
                        "patch range budget exceeded; no truncated result is returned"
                    );
                    pending = Some(PendingPatch {
                        offset: position,
                        length: 0,
                        source: Sha256::new(),
                        shadow: Sha256::new(),
                    });
                }
                let patch = pending.as_mut().expect("pending patch created");
                patch.length += sector as u64;
                patch.source.update(a);
                patch.shadow.update(b);
            }
        }
        offset += count as u64;
    }
    finish_patch(&mut pending, &mut patches);
    let source_sha256 = hex::encode(source_hash.finalize());
    let shadow_sha256 = hex::encode(shadow_hash.finalize());
    ensure!(
        source_sha256 == request.source_sha256,
        "full source SHA-256 pin differs"
    );
    ensure!(
        shadow_sha256 == request.shadow_sha256,
        "full shadow SHA-256 pin differs"
    );
    let mut observations = Vec::new();
    for (range, hashes) in request.retained_ranges.iter().zip(retained) {
        let source_sha256 = hex::encode(hashes.source.finalize());
        let shadow_sha256 = hex::encode(hashes.shadow.finalize());
        ensure!(
            hashes.bytes == range.length,
            "retained range was not read in full"
        );
        ensure!(
            source_sha256 == range.source_sha256 && shadow_sha256 == range.shadow_sha256,
            "retained range SHA-256 pin differs"
        );
        observations.push(RetainedRangeObservation {
            offset: range.offset,
            length: range.length,
            bytes_compared: hashes.bytes,
            source_sha256,
            shadow_sha256,
            differing_bytes: hashes.differing_bytes,
            differing_sectors: hashes.differing_sectors,
            hashes_match_request: true,
        });
    }
    ensure!(
        hash_reader(source, request.expected_length)? == source_sha256,
        "source changed after comparison"
    );
    ensure!(
        hash_reader(shadow, request.expected_length)? == shadow_sha256,
        "shadow changed after comparison"
    );
    let retained_differing_bytes = observations.iter().map(|range| range.differing_bytes).sum();
    let retained_differing_sectors = observations
        .iter()
        .map(|range| range.differing_sectors)
        .sum();
    let full_scan_input_bytes_read = request
        .expected_length
        .checked_mul(4)
        .context("read accounting overflow")?;
    Ok(RetainedComparison {
        schema_version: 1,
        kind: "lab-retained-sector-comparison".into(),
        request: request.clone(),
        source: SourceIdentity {
            path: PathBuf::new(),
            length: request.expected_length,
            sha256: source_sha256,
        },
        shadow: SourceIdentity {
            path: PathBuf::new(),
            length: request.expected_length,
            sha256: shadow_sha256,
        },
        compared_bytes: request.expected_length,
        differing_bytes,
        differing_sectors,
        retained_bytes: observations.iter().map(|range| range.length).sum(),
        retained_differing_bytes,
        retained_differing_sectors,
        nonretained_differing_bytes: differing_bytes - retained_differing_bytes,
        patch_bytes,
        patches,
        retained_ranges: observations,
        expected_postimage_sha256: hex::encode(post_hash.finalize()),
        source_shadow_unchanged_after_comparison: true,
        full_scan_input_bytes_read,
        container_probe_bytes_read: 0,
        total_input_bytes_read: full_scan_input_bytes_read,
        executable: false,
        retained_file_semantics_verified: false,
        native_attestations_verified: false,
        allocation_qualified: false,
        conversion_qualified: false,
        boot_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutation_is_denied_or_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mutable.raw");
        let before = vec![0; 1024];
        fs::write(&path, &before).unwrap();
        let mut input = open_input(&path, 1024).unwrap();
        #[cfg(windows)]
        {
            assert!(OpenOptions::new().write(true).open(&path).is_err());
            assert_eq!(
                hash_reader(&mut input.file, 1024).unwrap(),
                hex::encode(Sha256::digest(&before))
            );
            assert!(verify_input_binding(&input).is_ok());
        }
        #[cfg(not(windows))]
        {
            fs::write(&path, vec![1; 1024]).unwrap();
            assert_ne!(
                hash_reader(&mut input.file, 1024).unwrap(),
                hex::encode(Sha256::digest(&before))
            );
        }
    }
}
