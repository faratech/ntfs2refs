//! Pinned compact-recovery routing only. A bundle cannot create source
//! admission, authorize a fresh Apply, or replace native journal/device checks.
use crate::{general_reconstruct::Request, general_recovery::ExperimentalCompactInputs};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralDiskBinding,
    reference_file::{self, ReferenceFileSnapshot},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf, Prefix},
    time::SystemTime,
};

pub const MAX_BUNDLE_BYTES: u64 = 128 * 1024;
const KIND: &str = "compact-recovery-bundle";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedShadowLocation {
    pub path: PathBuf,
    pub virtual_disk_id: String,
    pub binding: GeneralDiskBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedShadowDescriptor {
    pub receipt: PinnedFile,
    pub location: ManagedShadowLocation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema_version: u32,
    pub kind: String,
    pub experiment_id: String,
    pub request: PinnedFile,
    pub ticket: PinnedFile,
    pub journal: PathBuf,
    pub capture: PinnedFile,
    pub packed: PinnedFile,
    pub expectation: PinnedFile,
    pub source: GeneralDiskBinding,
    pub shadow: GeneralDiskBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_shadow: Option<ManagedShadowDescriptor>,
}

fn canonical_pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn canonical_guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && n2r_win32::layout::guid_bytes(value).is_ok_and(|id| id != [0; 16])
}

fn ordinary_path(path: &Path, allow_volume_guid: bool) -> Result<()> {
    let text = path
        .to_str()
        .context("Unicode recovery routing path required")?;
    ensure!(
        path.is_absolute() && text.encode_utf16().count() <= 32760,
        "bounded absolute recovery routing path required"
    );
    ensure!(
        !text.contains(['/', '\0']) && !text.ends_with('\\'),
        "canonical recovery file path required"
    );
    let mut normal = 0;
    for part in path.components() {
        match part {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
                Prefix::Verbatim(name) if allow_volume_guid => {
                    let name = name.to_str().context("Unicode recovery volume required")?;
                    let guid = name
                        .strip_prefix("Volume{")
                        .and_then(|s| s.strip_suffix('}'));
                    ensure!(
                        guid.is_some_and(canonical_guid),
                        "canonical recovery volume GUID required"
                    );
                }
                _ => anyhow::bail!("local ordinary recovery file path required"),
            },
            Component::RootDir => {}
            Component::Normal(name) => {
                normal += 1;
                let name = name
                    .to_str()
                    .context("Unicode recovery component required")?;
                ensure!(
                    !name.ends_with([' ', '.'])
                        && !name.chars().any(|c| c.is_control()
                            || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*')),
                    "ambiguous recovery path component"
                );
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                ensure!(
                    !matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) && !(stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && matches!(stem.as_bytes()[3], b'1'..=b'9')),
                    "reserved recovery path component"
                );
            }
            _ => anyhow::bail!("recovery path traversal refused"),
        }
    }
    let rebuilt: PathBuf = path.components().collect();
    ensure!(
        normal > 0 && rebuilt.as_os_str() == path.as_os_str(),
        "noncanonical recovery path separators or dot components"
    );
    Ok(())
}

fn ordinary_ancestors(path: &Path) -> Result<()> {
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
            "recovery metadata ancestry is not ordinary"
        );
    }
    Ok(())
}

impl Bundle {
    pub fn from_inputs(
        inputs: &ExperimentalCompactInputs,
        request: &Request,
        managed_shadow: Option<ManagedShadowDescriptor>,
    ) -> Result<Self> {
        let bundle = Self {
            schema_version: 1,
            kind: KIND.into(),
            experiment_id: request.experiment_id.clone(),
            request: PinnedFile {
                path: inputs.request.clone(),
                sha256: inputs.request_sha256.clone(),
            },
            ticket: PinnedFile {
                path: inputs.ticket.clone(),
                sha256: inputs.ticket_sha256.clone(),
            },
            journal: inputs.journal.clone(),
            capture: PinnedFile {
                path: inputs.capture.clone(),
                sha256: inputs.capture_sha256.clone(),
            },
            packed: PinnedFile {
                path: inputs.packed.clone(),
                sha256: inputs.packed_sha256.clone(),
            },
            expectation: PinnedFile {
                path: inputs.expectation.clone(),
                sha256: inputs.expectation_sha256.clone(),
            },
            source: request.pair.source.clone(),
            shadow: request.pair.shadow.clone(),
            managed_shadow,
        };
        bundle.validate_request(request)?;
        Ok(bundle)
    }

    pub fn inputs(&self) -> ExperimentalCompactInputs {
        ExperimentalCompactInputs {
            request: self.request.path.clone(),
            request_sha256: self.request.sha256.clone(),
            ticket: self.ticket.path.clone(),
            ticket_sha256: self.ticket.sha256.clone(),
            journal: self.journal.clone(),
            capture: self.capture.path.clone(),
            capture_sha256: self.capture.sha256.clone(),
            packed: self.packed.path.clone(),
            packed_sha256: self.packed.sha256.clone(),
            expectation: self.expectation.path.clone(),
            expectation_sha256: self.expectation.sha256.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.kind == KIND,
            "unsupported compact recovery bundle"
        );
        ensure!(
            self.experiment_id.len() == 32
                && self
                    .experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid bundle experiment ID"
        );
        self.source.validate()?;
        self.shadow.validate()?;
        let mut paths = BTreeSet::new();
        for item in [
            &self.request,
            &self.ticket,
            &self.capture,
            &self.packed,
            &self.expectation,
        ] {
            ordinary_path(&item.path, false)?;
            ensure!(
                canonical_pin(&item.sha256),
                "canonical bundle SHA-256 pin required"
            );
            ensure!(
                paths.insert(item.path.to_string_lossy().to_lowercase()),
                "bundle input routes overlap"
            );
        }
        ordinary_path(&self.journal, true)?;
        ensure!(
            paths.insert(self.journal.to_string_lossy().to_lowercase()),
            "bundle journal route overlaps an input"
        );
        if let Some(managed) = &self.managed_shadow {
            ordinary_path(&managed.receipt.path, false)?;
            ordinary_path(&managed.location.path, false)?;
            ensure!(
                canonical_pin(&managed.receipt.sha256)
                    && canonical_guid(&managed.location.virtual_disk_id),
                "pinned managed receipt/provider ID required"
            );
            ensure!(
                managed.location.binding == self.shadow,
                "managed receipt binding differs from exact shadow binding"
            );
            ensure!(
                managed
                    .location
                    .path
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("vhdx")),
                "managed existing VHDX route required"
            );
            for path in [&managed.receipt.path, &managed.location.path] {
                ensure!(
                    paths.insert(path.to_string_lossy().to_lowercase()),
                    "managed routes overlap bundle inputs"
                );
            }
        }
        Ok(())
    }

    pub fn validate_request(&self, request: &Request) -> Result<()> {
        self.validate()?;
        request.validate()?;
        ensure!(
            self.experiment_id == request.experiment_id
                && self.source == request.pair.source
                && self.shadow == request.pair.shadow
                && self.expectation.sha256 == request.expected_tree_sha256,
            "bundle differs from original typed reconstruction request"
        );
        let journal_root = request.journal.disk.volume_path()?.to_ascii_lowercase() + "\\";
        ensure!(
            self.journal
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with(&journal_root),
            "bundle journal must use its original bound volume GUID route"
        );
        Ok(())
    }
}

struct HeldJson {
    file: File,
    snapshot: ReferenceFileSnapshot,
    modified: SystemTime,
    bytes: Vec<u8>,
    sha256: String,
}
impl HeldJson {
    fn open(path: &Path, pin: Option<&str>) -> Result<Self> {
        ordinary_path(path, false)?;
        ordinary_ancestors(path)?;
        ensure!(
            pin.is_none_or(canonical_pin),
            "canonical recovery metadata pin required"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let snapshot = reference_file::observe_reference_file_handle(&file)?;
        ensure!(
            (1..=MAX_BUNDLE_BYTES).contains(&snapshot.file_bytes) && snapshot.number_of_links == 1,
            "recovery metadata exceeds128KiB or has additional links"
        );
        let modified = file.metadata()?.modified()?;
        let bytes = read_bounded(&mut file)?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        ensure!(
            bytes.len() as u64 == snapshot.file_bytes && pin.is_none_or(|p| p == sha256.as_str()),
            "held recovery metadata length or pin differs"
        );
        let mut held = Self {
            file,
            snapshot,
            modified,
            bytes,
            sha256,
        };
        held.revalidate()?;
        Ok(held)
    }
    fn revalidate(&mut self) -> Result<()> {
        ensure!(
            reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held recovery metadata identity changed"
        );
        let bytes = read_bounded(&mut self.file)?;
        ensure!(
            bytes.len() as u64 == self.snapshot.file_bytes
                && hex::encode(Sha256::digest(&bytes)) == self.sha256
                && reference_file::observe_reference_file_handle(&self.file)? == self.snapshot
                && self.file.metadata()?.modified()? == self.modified,
            "held recovery metadata changed during rehash"
        );
        Ok(())
    }
    fn require_independent(&self, bundle: &Bundle) -> Result<()> {
        for binding in [&bundle.source, &bundle.shadow] {
            ensure!(
                !self
                    .snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
                "bundle/request/managed receipt must remain outside both data volumes"
            );
        }
        Ok(())
    }
}

fn read_bounded(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_BUNDLE_BYTES,
        "recovery metadata exceeds128KiB or is empty"
    );
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedReceipt {
    schema_version: u32,
    kind: String,
    path: PathBuf,
    virtual_disk_id: String,
    binding: GeneralDiskBinding,
}
fn parse_managed(held: &HeldJson) -> Result<ManagedShadowLocation> {
    let receipt: ManagedReceipt = serde_json::from_slice(&held.bytes)?;
    ensure!(
        receipt.schema_version == 1 && receipt.kind == "managed-native-shadow-location",
        "original managed-shadow location receipt required"
    );
    Ok(ManagedShadowLocation {
        path: receipt.path,
        virtual_disk_id: receipt.virtual_disk_id,
        binding: receipt.binding,
    })
}

/// Read the already-created managed location receipt; no provider/device is opened.
pub fn managed_shadow_from_receipt(
    path: &Path,
    expected: &GeneralDiskBinding,
) -> Result<ManagedShadowDescriptor> {
    expected.validate()?;
    let held = HeldJson::open(path, None)?;
    let location = parse_managed(&held)?;
    ensure!(
        &location.binding == expected,
        "managed receipt is not the exact original shadow binding"
    );
    ordinary_path(&location.path, false)?;
    ensure!(
        canonical_guid(&location.virtual_disk_id),
        "canonical managed provider ID required"
    );
    Ok(ManagedShadowDescriptor {
        receipt: PinnedFile {
            path: path.into(),
            sha256: held.sha256,
        },
        location,
    })
}

fn checked_association(bundle: &Bundle) -> Result<(HeldJson, Request, Option<HeldJson>)> {
    bundle.validate()?;
    let request_file = HeldJson::open(&bundle.request.path, Some(&bundle.request.sha256))?;
    let request: Request = serde_json::from_slice(&request_file.bytes)?;
    bundle.validate_request(&request)?;
    request_file.require_independent(bundle)?;
    let managed = if let Some(descriptor) = &bundle.managed_shadow {
        let held = HeldJson::open(&descriptor.receipt.path, Some(&descriptor.receipt.sha256))?;
        held.require_independent(bundle)?;
        ensure!(
            parse_managed(&held)? == descriptor.location,
            "pinned managed receipt differs from bundle location"
        );
        Some(held)
    } else {
        None
    };
    Ok((request_file, request, managed))
}

/// Persist metadata before activation. Does not reopen the exclusively held
/// ticket or touch journal, capture, packed payload or either data device.
pub fn save_new(path: &Path, bundle: &Bundle) -> Result<String> {
    ordinary_path(path, false)?;
    ordinary_ancestors(path)?;
    let (mut request, _, mut managed) = checked_association(bundle)?;
    let bytes = serde_json::to_vec_pretty(bundle)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_BUNDLE_BYTES,
        "recovery bundle exceeds128KiB"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let created = reference_file::observe_reference_file_handle(&file)?;
    ensure!(
        created.number_of_links == 1,
        "new recovery bundle has additional links"
    );
    for binding in [&bundle.source, &bundle.shadow] {
        ensure!(
            !created
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(binding.volume_path()?.to_ascii_lowercase() + "\\")),
            "recovery bundle cannot be stored on either data volume"
        );
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    let saved = reference_file::observe_reference_file_handle(&file)?;
    let actual = read_bounded(&mut file)?;
    ensure!(
        actual == bytes
            && saved.file_bytes == bytes.len() as u64
            && saved.number_of_links == 1
            && reference_file::observe_reference_file_handle(&file)? == saved
            && saved.file_id_128 == created.file_id_128
            && saved.volume_serial_number == created.volume_serial_number,
        "durable recovery bundle readback/identity differs"
    );
    request.revalidate()?;
    if let Some(managed) = &mut managed {
        managed.revalidate()?;
    }
    Ok(hex::encode(Sha256::digest(&actual)))
}

/// Keep this owner alive throughout recovery. It holds only routing metadata;
/// the existing typed engine must independently open and verify all real inputs.
pub struct HeldBundle {
    bundle: Bundle,
    request: Request,
    manifest_file: HeldJson,
    request_file: HeldJson,
    managed_receipt: Option<HeldJson>,
}
impl HeldBundle {
    pub fn open(path: &Path, caller_sha256: &str) -> Result<Self> {
        let manifest_file = HeldJson::open(path, Some(caller_sha256))?;
        let bundle: Bundle = serde_json::from_slice(&manifest_file.bytes)?;
        let (request_file, request, managed_receipt) = checked_association(&bundle)?;
        manifest_file.require_independent(&bundle)?;
        let mut held = Self {
            bundle,
            request,
            manifest_file,
            request_file,
            managed_receipt,
        };
        held.revalidate()?;
        Ok(held)
    }
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn inputs(&self) -> ExperimentalCompactInputs {
        self.bundle.inputs()
    }
    pub fn revalidate(&mut self) -> Result<()> {
        self.manifest_file.revalidate()?;
        self.request_file.revalidate()?;
        if let Some(managed) = &mut self.managed_receipt {
            managed.revalidate()?;
        }
        Ok(())
    }
}
