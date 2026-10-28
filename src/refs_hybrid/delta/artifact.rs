//! Bounded reopening of diagnostic compact captures. Hash pins and held
//! read-only handles provide a view, never source admission or write authority.
use super::{ChangedRange, DeltaLayout, DifferenceImage};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path},
    time::SystemTime,
};

const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct DeltaArtifactPins {
    pub report_file_id_info: Option<String>,
    pub packed_file_id_info: Option<String>,
    pub report_sha256: String,
    pub report_bytes: u64,
    pub packed_sha256: String,
    pub packed_bytes: u64,
    pub partition_bytes: u64,
    pub changed_ranges: usize,
    pub selected_bytes_compared: u64,
    pub equal_selected_bytes: u64,
    pub source_selected_sha256: String,
    pub candidate_selected_sha256: String,
    pub input_plan_sha256: String,
    pub conversion_qualified: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRange {
    offset: u64,
    length: u64,
    packed_offset: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLayout {
    partition_bytes: u64,
    changed_bytes: u64,
    ranges: Vec<StoredRange>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReads {
    source_logical_bytes: u64,
    shadow_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCapture {
    layout: StoredLayout,
    selected_bytes_compared: u64,
    equal_selected_bytes: u64,
    read_counts: StoredReads,
    source_selected_sha256: String,
    candidate_selected_sha256: String,
    packed_sha256: String,
    input_plan_sha256: String,
    conversion_qualified: bool,
}

#[derive(PartialEq, Eq)]
struct Stamp {
    bytes: u64,
    modified: SystemTime,
}
impl Stamp {
    fn of(metadata: &Metadata) -> Result<Self> {
        ensure!(
            metadata.is_file(),
            "delta artifact must be an ordinary file"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "delta artifact cannot be a reparse point"
            );
        }
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified()?,
        })
    }
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn ordinary(path: &Path) -> Result<File> {
    ensure!(
        !path.as_os_str().is_empty()
            && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "ordinary artifact path without parent traversal required"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for component in path.components() {
            if let Component::Prefix(prefix) = component {
                use std::path::Prefix;
                ensure!(
                    matches!(
                        prefix.kind(),
                        Prefix::Disk(_)
                            | Prefix::VerbatimDisk(_)
                            | Prefix::UNC(_, _)
                            | Prefix::VerbatimUNC(_, _)
                    ),
                    "device-namespace artifact paths are not allowed"
                );
            }
            if let Component::Normal(name) = component {
                let name = name.to_str().context("Unicode artifact path required")?;
                ensure!(
                    !name.contains([':', '\0']),
                    "artifact alternate streams are not allowed"
                );
                let stem = name
                    .trim_end_matches([' ', '.'])
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_ascii_uppercase();
                ensure!(
                    !matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) && !(stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && matches!(stem.as_bytes()[3], b'1'..=b'9')),
                    "reserved device-name artifact paths are not allowed"
                );
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "artifact ancestry is not ordinary"
            );
        }
    }
    let before = fs::symlink_metadata(path)?;
    ensure!(
        !before.file_type().is_symlink(),
        "artifact symlink is not allowed"
    );
    Stamp::of(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Keep these exact handles. READ sharing excludes write/delete opens;
        // OPEN_REPARSE_POINT excludes final-path redirection.
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let opened = Stamp::of(&file.metadata()?)?;
    ensure!(
        opened.bytes == before.len() && opened.modified == before.modified()?,
        "opened delta artifact differs from preflight"
    );
    Ok(file)
}

fn digest_file(file: &mut File, expected_bytes: u64) -> Result<String> {
    ensure!(
        file.metadata()?.len() == expected_bytes,
        "artifact length changed before hashing"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut left = expected_bytes;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    let mut eof = [0u8; 1];
    ensure!(
        file.read(&mut eof)? == 0,
        "artifact grew beyond its pinned length"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(hex::encode(hash.finalize()))
}

/// Both handles stay open. Windows denies other writers/deleters; revalidate
/// provides a byte/metadata completion bracket. Other platforms lack that lease.
pub struct VerifiedDeltaArtifact {
    report: File,
    packed: File,
    report_bytes: Vec<u8>,
    report_stamp: Stamp,
    packed_stamp: Stamp,
    layout: DeltaLayout,
    pins: DeltaArtifactPins,
}
impl VerifiedDeltaArtifact {
    pub fn open(
        report_path: &Path,
        expected_report_sha256: &str,
        packed_path: &Path,
        expected_partition_bytes: u64,
        max_changed_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            canonical_digest(expected_report_sha256),
            "canonical capture-report SHA-256 required"
        );
        ensure!(
            expected_partition_bytes >= 64 * 4096
                && expected_partition_bytes.is_multiple_of(4096)
                && max_changed_bytes <= expected_partition_bytes,
            "capture reopening geometry/budget differs"
        );
        let mut report = ordinary(report_path)?;
        let report_stamp = Stamp::of(&report.metadata()?)?;
        ensure!(
            report_stamp.bytes <= MAX_REPORT_BYTES,
            "capture report exceeds 16-MiB limit"
        );
        let mut report_bytes = Vec::new();
        (&mut report)
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut report_bytes)?;
        ensure!(
            report_bytes.len() as u64 == report_stamp.bytes
                && report_bytes.len() as u64 <= MAX_REPORT_BYTES
                && hex::encode(Sha256::digest(&report_bytes)) == expected_report_sha256,
            "capture report length or SHA-256 differs"
        );
        ensure!(
            Stamp::of(&report.metadata()?)? == report_stamp,
            "capture report changed during reading"
        );
        let value: serde_json::Value = serde_json::from_slice(&report_bytes)?;
        ensure!(
            value["schema_version"] == 1
                && value["kind"] == "private-tree-allocation"
                && value["success"] == true
                && value["source_backed_payloads"] == true,
            "successful source-backed capture envelope required"
        );
        let capture_value = value
            .pointer("/native/compact_difference_capture")
            .context("compact difference capture absent")?;
        ensure!(
            capture_value
                .pointer("/layout/ranges")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ranges| ranges.len() <= 65536),
            "capture range budget exceeded"
        );
        let capture: StoredCapture = serde_json::from_value(capture_value.clone())?;
        drop(value);
        ensure!(
            !capture.conversion_qualified
                && capture.layout.partition_bytes == expected_partition_bytes
                && capture.layout.changed_bytes <= max_changed_bytes
                && capture.selected_bytes_compared <= expected_partition_bytes
                && capture
                    .layout
                    .changed_bytes
                    .checked_add(capture.equal_selected_bytes)
                    == Some(capture.selected_bytes_compared)
                && capture
                    .read_counts
                    .source_logical_bytes
                    .checked_add(capture.read_counts.shadow_bytes)
                    == Some(capture.selected_bytes_compared),
            "capture geometry, read totals or selected-byte accounting differs"
        );
        for digest in [
            &capture.packed_sha256,
            &capture.source_selected_sha256,
            &capture.candidate_selected_sha256,
            &capture.input_plan_sha256,
        ] {
            ensure!(canonical_digest(digest), "noncanonical capture digest");
        }
        let layout = DeltaLayout::new(
            capture.layout.partition_bytes,
            capture.layout.changed_bytes,
            capture
                .layout
                .ranges
                .into_iter()
                .map(|r| ChangedRange {
                    offset: r.offset,
                    length: r.length,
                    packed_offset: r.packed_offset,
                })
                .collect(),
        )?;
        let mut packed = ordinary(packed_path)?;
        let packed_stamp = Stamp::of(&packed.metadata()?)?;
        ensure!(
            packed_stamp.bytes == layout.changed_bytes(),
            "packed backing length differs from capture"
        );
        ensure!(
            digest_file(&mut packed, packed_stamp.bytes)? == capture.packed_sha256
                && Stamp::of(&packed.metadata()?)? == packed_stamp,
            "packed backing changed or SHA-256 differs"
        );
        let pins = DeltaArtifactPins {
            report_file_id_info: {
                #[cfg(windows)]
                {
                    Some(n2r_win32::file_storage::file_id_info(&report)?)
                }
                #[cfg(not(windows))]
                {
                    None
                }
            },
            packed_file_id_info: {
                #[cfg(windows)]
                {
                    Some(n2r_win32::file_storage::file_id_info(&packed)?)
                }
                #[cfg(not(windows))]
                {
                    None
                }
            },
            report_sha256: expected_report_sha256.to_owned(),
            report_bytes: report_stamp.bytes,
            packed_sha256: capture.packed_sha256,
            packed_bytes: packed_stamp.bytes,
            partition_bytes: layout.partition_bytes(),
            changed_ranges: layout.changed_ranges(),
            selected_bytes_compared: capture.selected_bytes_compared,
            equal_selected_bytes: capture.equal_selected_bytes,
            source_selected_sha256: capture.source_selected_sha256,
            candidate_selected_sha256: capture.candidate_selected_sha256,
            input_plan_sha256: capture.input_plan_sha256,
            conversion_qualified: false,
        };
        Ok(Self {
            report,
            packed,
            report_bytes,
            report_stamp,
            packed_stamp,
            layout,
            pins,
        })
    }
    pub fn pins(&self) -> &DeltaArtifactPins {
        &self.pins
    }
    /// One canonical encoding for journal binding in preparation, execution and
    /// handoff. Value-map ordering preserves the first prepared compact ticket.
    pub fn identity_sha256(&self) -> Result<String> {
        let value = serde_json::to_value(&self.pins)?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
    }
    pub fn layout(&self) -> &DeltaLayout {
        &self.layout
    }
    /// Exact pinned bytes; caller must still validate source/pair/tree bindings.
    pub fn report_bytes(&self) -> &[u8] {
        &self.report_bytes
    }
    pub fn image<'a, R: Read + Seek>(
        &'a mut self,
        original: &'a mut R,
    ) -> Result<DifferenceImage<'a, R, File>> {
        ensure!(
            Stamp::of(&self.report.metadata()?)? == self.report_stamp
                && Stamp::of(&self.packed.metadata()?)? == self.packed_stamp,
            "artifact metadata changed before view creation"
        );
        DifferenceImage::new(original, &mut self.packed, &self.layout)
    }
    pub fn revalidate(&mut self) -> Result<()> {
        #[cfg(windows)]
        ensure!(
            Some(n2r_win32::file_storage::file_id_info(&self.report)?)
                == self.pins.report_file_id_info
                && Some(n2r_win32::file_storage::file_id_info(&self.packed)?)
                    == self.pins.packed_file_id_info,
            "delta artifact held-file identity changed"
        );
        ensure!(
            Stamp::of(&self.report.metadata()?)? == self.report_stamp
                && Stamp::of(&self.packed.metadata()?)? == self.packed_stamp,
            "delta artifact metadata changed"
        );
        ensure!(
            digest_file(&mut self.report, self.report_stamp.bytes)? == self.pins.report_sha256
                && digest_file(&mut self.packed, self.packed_stamp.bytes)?
                    == self.pins.packed_sha256,
            "delta artifact contents changed"
        );
        ensure!(
            Stamp::of(&self.report.metadata()?)? == self.report_stamp
                && Stamp::of(&self.packed.metadata()?)? == self.packed_stamp,
            "delta artifact changed during completion bracket"
        );
        Ok(())
    }
}
