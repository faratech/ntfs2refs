//! Private persistent recovery selection. No bootsequence, security policy,
//! SecureBoot, firmware write or source-D payload operation is available here.
use super::*;
use crate::{
    journal_file::GeneralJournalStorageBinding,
    partition_isolation::{PartitionObservationBudget, PartitionSourceBinding},
    recovery_image::OwnedRecoveryImage,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
mod bcd_device;
mod cold;
mod fat;
mod metadata;
mod native;
mod offreg;
pub use cold::{RecoveryBootGuard, RecoveryBootGuardFacts, RecoveryBootRestorationReceipt};
use metadata::{EfiIdentity, StorePin};
const BOOTMGR: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
const FWBOOTMGR: &str = "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}";
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBootBudget {
    pub ram_bytes: u64,
    pub maximum_store_bytes: u64,
    pub maximum_control_bytes: u64,
    pub maximum_image_bytes: u64,
    pub minimum_free_bytes: u64,
    pub tool_timeout_milliseconds: u32,
}
impl RecoveryBootBudget {
    fn validate(self) -> io::Result<()> {
        need(
            self.maximum_store_bytes > 0
                && self.maximum_store_bytes <= self.ram_bytes / 8
                && self.maximum_control_bytes > 0
                && self.maximum_control_bytes <= self.ram_bytes / 4
                && self.minimum_free_bytes > 0
                && self.maximum_image_bytes > 0
                && self.ram_bytes >= 2 * 1024 * 1024
                && self.tool_timeout_milliseconds > 0,
            "bounded recovery-boot resources required",
        )
    }
}
fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn need(v: bool, s: &str) -> io::Result<()> {
    if v { Ok(()) } else { Err(bad(s)) }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}
fn guid(bytes: &[u8]) -> io::Result<String> {
    need(bytes.len() == 16, "GUID width invalid")?;
    let a = u32::from_le_bytes(bytes[..4].try_into().map_err(io::Error::other)?);
    let b = u16::from_le_bytes(bytes[4..6].try_into().map_err(io::Error::other)?);
    let c = u16::from_le_bytes(bytes[6..8].try_into().map_err(io::Error::other)?);
    Ok(format!(
        "{{{a:08x}-{b:04x}-{c:04x}-{}-{}}}",
        hex::encode(&bytes[8..10]),
        hex::encode(&bytes[10..])
    ))
}
fn canonical_guid(value: &str) -> io::Result<String> {
    need(
        value.starts_with('{') && value.ends_with('}') && value.len() == 38,
        "explicit GUID required; aliases are not proof",
    )?;
    guid(&crate::layout::guid_bytes(value)?)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Selection {
    default: String,
    displayorder: Vec<String>,
    timeout: String,
    all_fields: BTreeMap<String, Vec<String>>,
}
fn selection(fields: BTreeMap<String, Vec<String>>) -> io::Result<Selection> {
    need(
        fields.get("identifier") == Some(&vec![BOOTMGR.to_owned()])
            && !fields.contains_key("bootsequence"),
        "real system bootmgr without one-shot sequence required",
    )?;
    let default = canonical_guid(one(&fields, "default")?)?;
    let displayorder = fields
        .get("displayorder")
        .ok_or_else(|| bad("original boot display order absent"))?
        .iter()
        .map(|s| canonical_guid(s))
        .collect::<io::Result<Vec<_>>>()?;
    need(
        !displayorder.is_empty() && displayorder.contains(&default),
        "default not in complete original display order",
    )?;
    let timeout = one(&fields, "timeout")?.to_owned();
    need(
        timeout.parse::<u32>().is_ok(),
        "native boot timeout unknown",
    )?;
    Ok(Selection {
        default,
        displayorder,
        timeout,
        all_fields: fields,
    })
}
fn one<'a>(fields: &'a BTreeMap<String, Vec<String>>, name: &str) -> io::Result<&'a str> {
    let values = fields
        .get(name)
        .ok_or_else(|| bad("required native BCD element absent"))?;
    need(values.len() == 1, "BCD element multiplicity invalid")?;
    Ok(&values[0])
}
// Documented BCD element types; the original native backup also verifies the
// exact raw GUID/list/integer representation before any private mutation.
const BCD_DEFAULT: u32 = 0x2300_0003;
const BCD_DISPLAY_ORDER: u32 = 0x2400_0001;
const BCD_TIMEOUT: u32 = 0x2500_0004;
const BCD_BOOT_SEQUENCE: u32 = 0x2400_0002;
const BCD_LOAD_OPTIONS: u32 = 0x1200_0030;
fn encoded_string(value: &str, terminators: u32) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(std::iter::repeat_n(0, terminators as usize))
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn decoded_guid_units(units: &[u16]) -> io::Result<String> {
    need(
        units.len() == 38 && !units.contains(&0),
        "BCD native GUID string width differs",
    )?;
    canonical_guid(&String::from_utf16(units).map_err(io::Error::other)?)
}
fn decoded_guid(value: &offreg::OfflineBcdElement) -> io::Result<String> {
    need(
        value.registry_type == 1 && value.bytes.len() == 78 && value.bytes[76..] == [0, 0],
        "BCD object reference must be native REG_SZ GUID38 plus NUL",
    )?;
    let units: Vec<_> = value.bytes[..76]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    decoded_guid_units(&units)
}
fn decoded_guid_list(value: &offreg::OfflineBcdElement) -> io::Result<Vec<String>> {
    need(
        value.registry_type == 7
            && value.bytes.len() >= 4
            && value.bytes.len() % 2 == 0
            && value.bytes[value.bytes.len() - 4..] == [0, 0, 0, 0],
        "BCD object list must be native double-NUL REG_MULTI_SZ",
    )?;
    let units: Vec<_> = value.bytes[..value.bytes.len() - 4]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    units.split(|v| *v == 0).map(decoded_guid_units).collect()
}
fn decoded_integer(value: &offreg::OfflineBcdElement) -> io::Result<u64> {
    need(
        value.registry_type == 3 && value.bytes.len() == 8,
        "BCD integer must be native REG_BINARY u64LE8",
    )?;
    Ok(u64::from_le_bytes(
        value
            .bytes
            .as_slice()
            .try_into()
            .map_err(io::Error::other)?,
    ))
}
fn element<'a>(
    object: &'a offreg::OfflineBcdObject,
    id: u32,
) -> io::Result<&'a offreg::OfflineBcdElement> {
    object
        .elements
        .get(&id)
        .ok_or_else(|| bad(&format!("required encoded BCD element 0x{id:08x} absent")))
}
fn verify_original_mutable_encoding(
    object: &offreg::OfflineBcdObject,
    original: &Selection,
) -> io::Result<()> {
    let timeout = original.timeout.parse::<u64>().map_err(io::Error::other)?;
    need(
        decoded_guid(element(object, BCD_DEFAULT)?)? == original.default
            && decoded_guid_list(element(object, BCD_DISPLAY_ORDER)?)? == original.displayorder
            && decoded_integer(element(object, BCD_TIMEOUT)?)? == timeout
            && !object.elements.contains_key(&BCD_BOOT_SEQUENCE),
        "native original BCD raw default/order/timeout/sequence encoding differs",
    )
}
fn verify_encoded_cold_objects(
    original: &offreg::OfflineBcdObject,
    current: &offreg::OfflineBcdObject,
    loader: &offreg::OfflineBcdObject,
    options: &offreg::OfflineBcdObject,
    intent: &BootIntent,
    intent_sha: [u8; 32],
) -> io::Result<()> {
    verify_original_mutable_encoding(original, &intent.original)?;
    let mut expected = original.clone();
    let mut unrelated = current.clone();
    for id in [BCD_DEFAULT, BCD_DISPLAY_ORDER, BCD_TIMEOUT] {
        expected.elements.remove(&id);
        unrelated.elements.remove(&id);
    }
    need(
        unrelated == expected
            && decoded_guid(element(current, BCD_DEFAULT)?)? == intent.loader
            && decoded_guid_list(element(current, BCD_DISPLAY_ORDER)?)?
                == std::slice::from_ref(&intent.loader)
            && decoded_integer(element(current, BCD_TIMEOUT)?)? == 0
            && !current.elements.contains_key(&BCD_BOOT_SEQUENCE),
        "actual encoded BootMgr selection or unrelated complete elements changed",
    )?;
    let private = intent
        .private_encoded_objects
        .as_ref()
        .ok_or_else(|| bad("native-boot-pinned private encoded objects absent"))?;
    let mut expected_loader = private.loader.clone();
    need(
        expected_loader.elements.get(&BCD_LOAD_OPTIONS)
            == Some(&offreg::OfflineBcdElement {
                registry_type: 1,
                bytes: encoded_string(
                    &load_options([0u8; 32], bootstrap_pin(intent)?),
                    private.loadoptions_terminators,
                ),
            }),
        "sealed native-created private loadoptions template differs",
    )?;
    expected_loader.elements.insert(
        BCD_LOAD_OPTIONS,
        offreg::OfflineBcdElement {
            registry_type: 1,
            bytes: encoded_string(
                &load_options(intent_sha, bootstrap_pin(intent)?),
                private.loadoptions_terminators,
            ),
        },
    );
    need(
        *loader == expected_loader && *options == private.options,
        "actual complete private loader/ramdisk elements differ from native-created sealed maps",
    )
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ImagePin {
    role: String,
    path: PathBuf,
    snapshot: serde_json::Value,
    sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrivateEncodedBootObjects {
    loader: offreg::OfflineBcdObject,
    options: offreg::OfflineBcdObject,
    loadoptions_terminators: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BootIntent {
    version: u32,
    kind: String,
    source: PartitionSourceBinding,
    journal: GeneralJournalStorageBinding,
    efi: EfiIdentity,
    original_store: StorePin,
    original: Selection,
    loader: String,
    ramdisk_options: String,
    image_root_guid: String,
    image_wim: PathBuf,
    image_sdi: PathBuf,
    wim_sha256: [u8; 32],
    sdi_sha256: [u8; 32],
    runner_sha256: [u8; 32],
    origin_marker_sha256: [u8; 32],
    origin_marker_ram_relative: String,
    prepared_bundle_sha256: [u8; 32],
    startup_args: Vec<String>,
    backup_path: PathBuf,
    backup_sha256: [u8; 32],
    firmware: native::FirmwareIdentity,
    planned_device: String,
    planned_sdi_device: String,
    planned_sdi_path: String,
    image_pins: Vec<ImagePin>,
    guarded_store_map: Option<StorePin>,
    parent_original_intent_sha256: Option<[u8; 32]>,
    #[serde(default)]
    private_encoded_objects: Option<PrivateEncodedBootObjects>,
    serialized_intent_is_writer_authority: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ArmedRecord {
    version: u32,
    kind: String,
    intent_path: PathBuf,
    intent_sha256: [u8; 32],
    installed_store: StorePin,
    loader: String,
    prepared_bundle_sha256: [u8; 32],
    native_persistent_selection_verified: bool,
    cold_boot_qualified: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryBootReceipt {
    pub kind: &'static str,
    pub intent_path: PathBuf,
    pub intent_sha256: [u8; 32],
    pub armed_path: PathBuf,
    pub armed_sha256: [u8; 32],
    pub loader_guid: String,
    pub prepared_bundle_sha256: [u8; 32],
    pub bcd_default_and_recovery_only_order_verified: bool,
    pub source_writer_authority: bool,
    pub cold_boot_qualified: bool,
}
/// Constructed only by actual system-store mutation/readback and immutable image.
pub struct OwnedRecoveryBoot {
    image: OwnedRecoveryImage,
    intent: BootIntent,
    record: ArmedRecord,
    receipt: RecoveryBootReceipt,
    budget: RecoveryBootBudget,
}
impl OwnedRecoveryBoot {
    pub fn install(
        image: OwnedRecoveryImage,
        directory: &Path,
        budget: RecoveryBootBudget,
        observation_budget: PartitionObservationBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        budget.validate()?;
        observation_budget.validate()?;
        image.revalidate()?;
        need(
            image.san_policy() == 3,
            "actual early-SAN3 recovery image required",
        )?;
        metadata::fresh_external(
            directory,
            image.source_binding(),
            image.journal_binding(),
            budget,
            events,
        )?;
        let tool = native::Tool::system(budget)?;
        let efi = metadata::system_efi(image.source_binding(), observation_budget, events)?;
        let firmware = native::firmware(&efi)?;
        let current = tool.enum_object(None, "{current}", directory)?;
        need(
            crate::layout::guid_bytes(one(&current, "identifier")?)?
                == native::kernel_boot_identifier()?,
            "native kernel BootIdentifier did not identify the actual current loader; no assumption permitted",
        )?;
        let original = selection(tool.enum_object(None, BOOTMGR, directory)?)?;
        let explicit = selection(tool.enum_object(Some(&efi.bcd_path), BOOTMGR, directory)?)?;
        need(
            original.all_fields == explicit.all_fields,
            "native active/system EFI BCD stores differ",
        )?;
        let fw = tool.enum_object(None, FWBOOTMGR, directory)?;
        // Nothing set for the next start alone. Which entry is first is not
        // asked here: `native::firmware` above has read the firmware's own
        // variables and holds the entry the running Windows was started
        // through to be the first of the boot order, whether that entry is
        // the Windows Boot Manager or the disk as a device.
        need(
            !fw.contains_key("bootsequence"),
            "the firmware has a boot entry set for the next start alone (a one-time boot sequence): start Windows once more, or clear it, and run the conversion again",
        )?;
        native::flush_system_bcd_with_events(events)?;
        let original_store =
            metadata::capture_active_store(&efi, budget, &tool, directory, events)?;
        let backup_path = directory.join("original-system-store.bcd");
        tool.export_owned_store(directory)?;
        let backup_sha256 = metadata::hash_external(
            &backup_path,
            image.journal_binding(),
            budget.maximum_store_bytes,
        )?;
        let backup_path = metadata::guid_external_path(
            &backup_path,
            image.journal_binding(),
            budget.maximum_store_bytes,
        )?;
        let library_pin = image
            .artifact_pins()
            .iter()
            .find(|p| p.role == "offline-registry-library")
            .ok_or_else(|| bad("owned image offline registry library absent"))?;
        let offline_registry = bcd_device::OfflineRegistryLibrary::open_sealed_journal(
            &library_pin.path,
            library_pin.sha256,
            &library_pin.snapshot,
            image.journal_binding(),
            budget,
        )?;
        let original_encoded =
            bcd_device::observe_object(&backup_path, BOOTMGR, &offline_registry, budget, events)?;
        need(
            original_encoded.file_sha256 == backup_sha256,
            "original native BCD backup differs during encoded observation",
        )?;
        verify_original_mutable_encoding(&original_encoded.object, &original)?;
        let marker =
            metadata::read_external(image.origin_marker_path(), image.journal_binding(), 65536)?;
        need(
            digest(&marker) == image.origin_marker_sha256(),
            "actual owned image origin marker differs",
        )?;
        let marker: serde_json::Value =
            serde_json::from_slice(&marker).map_err(io::Error::other)?;
        let nonce = marker["builder_nonce"]
            .as_str()
            .ok_or_else(|| bad("owned image nonce absent"))?;
        let loader = derived_guid(
            b"ntfs2refs-recovery-loader-v1",
            nonce,
            image.prepared_bundle_sha256(),
        )?;
        let ramdisk_options = derived_guid(
            b"ntfs2refs-recovery-device-v1",
            nonce,
            image.prepared_bundle_sha256(),
        )?;
        let (planned_device, planned_sdi_device, planned_sdi_path) =
            metadata::bcd_image_routes(&image, &ramdisk_options)?;
        let mut intent = BootIntent {
            version: 1,
            kind: "ntfs2refs-persistent-recovery-boot-intent-v1".into(),
            source: image.source_binding().clone(),
            journal: image.journal_binding().clone(),
            efi,
            original_store,
            original,
            loader: loader.clone(),
            ramdisk_options: ramdisk_options.clone(),
            image_root_guid: image.root_guid_path().into(),
            image_wim: image.wim_path().to_owned(),
            image_sdi: image.sdi_path().to_owned(),
            wim_sha256: image.wim_sha256(),
            sdi_sha256: image.sdi_sha256(),
            runner_sha256: image.runner_sha256(),
            origin_marker_sha256: image.origin_marker_sha256(),
            origin_marker_ram_relative: image.origin_marker_ram_relative_path().into(),
            prepared_bundle_sha256: image.prepared_bundle_sha256(),
            startup_args: image.startup_args().to_vec(),
            backup_path,
            backup_sha256,
            firmware,
            planned_device,
            planned_sdi_device,
            planned_sdi_path,
            image_pins: image
                .artifact_pins()
                .iter()
                .map(|p| {
                    Ok(ImagePin {
                        role: p.role.into(),
                        path: PathBuf::from(&p.snapshot.final_path),
                        snapshot: serde_json::to_value(&p.snapshot).map_err(io::Error::other)?,
                        sha256: p.sha256,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?,
            guarded_store_map: None,
            parent_original_intent_sha256: None,
            private_encoded_objects: None,
            serialized_intent_is_writer_authority: false,
        };
        let original_intent_path = directory.join("recovery-boot-original-intent.json");
        let original_intent_sha256 =
            native::persist(&original_intent_path, &intent, budget.maximum_control_bytes)?;
        // Every mutation is native bcdedit on the actual SYSTEM store, backed up
        // and externally intent-pinned BEFORE creating even a private object.
        tool.run(
            None,
            &[
                "/create".into(),
                ramdisk_options.clone(),
                "/d".into(),
                "ntfs2refs private recovery device".into(),
                "/device".into(),
            ],
            directory,
        )?;
        tool.set(
            &ramdisk_options,
            "ramdisksdidevice",
            &intent.planned_sdi_device,
            directory,
        )?;
        tool.set(
            &ramdisk_options,
            "ramdisksdipath",
            &intent.planned_sdi_path,
            directory,
        )?;
        tool.run(
            None,
            &[
                "/create".into(),
                loader.clone(),
                "/d".into(),
                "ntfs2refs sealed offline apply".into(),
                "/application".into(),
                "osloader".into(),
            ],
            directory,
        )?;
        for (key, value) in [
            ("device", intent.planned_device.as_str()),
            ("osdevice", intent.planned_device.as_str()),
            ("path", r"\windows\system32\boot\winload.efi"),
            ("systemroot", r"\windows"),
            ("winpe", "Yes"),
            ("detecthal", "Yes"),
        ] {
            tool.set(&loader, key, value, directory)?;
        }
        // Allocate the private load-options element before pinning the complete
        // post-creation store map. Initial BCD growth is allowed at this stage.
        tool.set(
            &loader,
            "loadoptions",
            &load_options([0u8; 32], bootstrap_pin(&intent)?),
            directory,
        )?;
        image.revalidate()?;
        // Capture exact native-created private object elements before the
        // guard-intent hash. Only LoadOptions' fixed-width self-hash changes.
        verify_loader(
            &tool.enum_object(None, &loader, directory)?,
            &intent,
            [0u8; 32],
        )?;
        let warm_options = tool.enum_object(None, &ramdisk_options, directory)?;
        cold::verify_cold_options(&warm_options, &intent)?;
        native::flush_system_bcd_with_events(events)?;
        let preselect =
            metadata::capture_active_store(&intent.efi, budget, &tool, directory, events)?;
        let encoded_path = directory.join("private-encoded-before-guard.bcd");
        let encoded_sha = metadata::raw_copy(
            &intent.efi,
            &preselect,
            &encoded_path,
            budget.maximum_store_bytes,
            budget.maximum_control_bytes,
            events,
        )?;
        need(
            encoded_sha == preselect.sha256,
            "pre-guard private object copy differs from actual store",
        )?;
        let loader_encoded =
            bcd_device::observe_object(&encoded_path, &loader, &offline_registry, budget, events)?;
        let options_encoded = bcd_device::observe_object(
            &encoded_path,
            &ramdisk_options,
            &offline_registry,
            budget,
            events,
        )?;
        need(
            loader_encoded.file_sha256 == encoded_sha && options_encoded.file_sha256 == encoded_sha,
            "pre-guard native private object copy changed",
        )?;
        let placeholder = loader_encoded
            .object
            .elements
            .get(&BCD_LOAD_OPTIONS)
            .ok_or_else(|| bad("native-created private loadoptions element absent"))?;
        let zero_options = load_options([0u8; 32], bootstrap_pin(&intent)?);
        need(
            placeholder.registry_type == 1,
            "native private loadoptions must be REG_SZ",
        )?;
        let base = encoded_string(&zero_options, 0);
        let padding = placeholder
            .bytes
            .strip_prefix(base.as_slice())
            .ok_or_else(|| {
                bad("native private loadoptions differs from exact placeholder UTF16")
            })?;
        need(
            matches!(padding.len(), 2 | 4) && padding.iter().all(|v| *v == 0),
            "native private loadoptions has unknown REG_SZ terminator format",
        )?;
        let loadoptions_terminators = (padding.len() / 2) as u32;
        intent.private_encoded_objects = Some(PrivateEncodedBootObjects {
            loader: loader_encoded.object,
            options: options_encoded.object,
            loadoptions_terminators,
        });
        intent.guarded_store_map = Some(preselect.clone());
        intent.parent_original_intent_sha256 = Some(original_intent_sha256);
        let intent_path = directory.join("recovery-boot-guard-intent.json");
        let intent_sha256 = native::persist(&intent_path, &intent, budget.maximum_control_bytes)?;
        tool.set(
            &loader,
            "loadoptions",
            &load_options(intent_sha256, bootstrap_pin(&intent)?),
            directory,
        )?;
        verify_loader(
            &tool.enum_object(None, &loader, directory)?,
            &intent,
            intent_sha256,
        )?;
        tool.run(None, &["/default".into(), loader.clone()], directory)?;
        tool.run(None, &["/displayorder".into(), loader.clone()], directory)?;
        tool.run(None, &["/timeout".into(), "0".into()], directory)?;
        native::flush_system_bcd_with_events(events)?;
        verify_selection(&tool.enum_object(None, BOOTMGR, directory)?, &intent)?;
        verify_selection(
            &tool.enum_object(Some(&intent.efi.bcd_path), BOOTMGR, directory)?,
            &intent,
        )?;
        let installed_store =
            metadata::capture_active_store(&intent.efi, budget, &tool, directory, events)?;
        need(
            installed_store.same_file_map(&preselect),
            "installed BCD physical mapping changed after immutable guard intent; no cold guard issued",
        )?;
        native::firmware(&intent.efi)?.require_same(&intent.firmware)?;
        let record = ArmedRecord {
            version: 1,
            kind: "ntfs2refs-persistent-recovery-boot-armed-v1".into(),
            intent_path: intent_path.clone(),
            intent_sha256,
            installed_store,
            loader: loader.clone(),
            prepared_bundle_sha256: image.prepared_bundle_sha256(),
            native_persistent_selection_verified: true,
            cold_boot_qualified: false,
        };
        let armed_path = directory.join("recovery-boot-armed.json");
        let armed_sha256 = native::persist(&armed_path, &record, budget.maximum_control_bytes)?;
        let receipt = RecoveryBootReceipt {
            kind: "actual-persistent-recovery-BCD-installed-v1",
            intent_path,
            intent_sha256,
            armed_path,
            armed_sha256,
            loader_guid: loader,
            prepared_bundle_sha256: image.prepared_bundle_sha256(),
            bcd_default_and_recovery_only_order_verified: true,
            source_writer_authority: false,
            cold_boot_qualified: false,
        };
        Ok(Self {
            image,
            intent,
            record,
            receipt,
            budget,
        })
    }
    pub fn receipt(&self) -> &RecoveryBootReceipt {
        &self.receipt
    }
    pub fn revalidate(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.image.revalidate()?;
        let tool = native::Tool::system(self.budget)?;
        verify_selection(
            &tool.enum_object(
                None,
                BOOTMGR,
                self.receipt
                    .intent_path
                    .parent()
                    .ok_or_else(|| bad("boot directory absent"))?,
            )?,
            &self.intent,
        )?;
        need(
            metadata::capture_active_store(
                &self.intent.efi,
                self.budget,
                &tool,
                self.receipt
                    .intent_path
                    .parent()
                    .ok_or_else(|| bad("boot directory absent"))?,
                events,
            )? == self.record.installed_store,
            "actual installed boot bytes/mapping changed",
        )?;
        native::firmware(&self.intent.efi)?.require_same(&self.intent.firmware)
    }
}
fn derived_guid(domain: &[u8], nonce: &str, bundle: [u8; 32]) -> io::Result<String> {
    let mut h = sha2::Sha256::new();
    h.update(domain);
    h.update(nonce.as_bytes());
    h.update(bundle);
    let mut b: [u8; 16] = h.finalize()[..16].try_into().map_err(io::Error::other)?;
    b[7] = (b[7] & 15) | 0x40;
    b[8] = (b[8] & 63) | 0x80;
    guid(&b)
}
// Private evidence from authenticated fresh owned copies, never a serialized
// flag or rendered device alias. It grants no source/boot write authority.
struct BootManagerDeviceProof {
    original_store_sha256: [u8; 32],
    current_store_sha256: [u8; 32],
    element_sha256: [u8; 32],
    element_bytes: u64,
}
impl BootManagerDeviceProof {
    fn require_stores(&self, original: [u8; 32], current: [u8; 32]) -> io::Result<()> {
        need(
            self.original_store_sha256 == original
                && self.current_store_sha256 == current
                && self.element_bytes > 0,
            "encoded BootMgr device proof belongs to another actual store epoch",
        )
    }
}
fn verify_selection(fields: &BTreeMap<String, Vec<String>>, intent: &BootIntent) -> io::Result<()> {
    verify_selection_inner(fields, intent, None)
}
fn verify_cold_selection(
    fields: &BTreeMap<String, Vec<String>>,
    intent: &BootIntent,
    proof: &BootManagerDeviceProof,
    current: [u8; 32],
) -> io::Result<()> {
    verify_selection_inner(fields, intent, Some((proof, current)))
}
fn verify_selection_inner(
    fields: &BTreeMap<String, Vec<String>>,
    intent: &BootIntent,
    device_proof: Option<(&BootManagerDeviceProof, [u8; 32])>,
) -> io::Result<()> {
    need(
        one(fields, "identifier")? == BOOTMGR
            && one(fields, "default")? == intent.loader
            && fields.get("displayorder") == Some(&vec![intent.loader.clone()])
            && one(fields, "timeout")? == "0"
            && !fields.contains_key("bootsequence"),
        "actual persistent default/recovery-only order differs",
    )?;
    for (key, value) in &intent.original.all_fields {
        if !matches!(key.as_str(), "default" | "displayorder" | "timeout") {
            if key == "device" {
                if let Some((proof, current)) = device_proof {
                    need(
                        value.len() == 1 && fields.get(key).is_some_and(|v| v.len() == 1),
                        "BootMgr device element multiplicity changed",
                    )?;
                    proof.require_stores(intent.backup_sha256, current)?;
                    continue;
                }
            }
            need(
                fields.get(key) == Some(value),
                "unrelated boot-manager element changed",
            )?;
        }
    }
    Ok(())
}
fn verify_original_selection(
    fields: &BTreeMap<String, Vec<String>>,
    intent: &BootIntent,
    proof: &BootManagerDeviceProof,
    current: [u8; 32],
) -> io::Result<()> {
    proof.require_stores(intent.backup_sha256, current)?;
    need(
        !fields.contains_key("bootsequence"),
        "one-shot boot sequence appeared during restoration",
    )?;
    for (key, value) in &intent.original.all_fields {
        if key == "device" {
            need(
                value.len() == 1 && fields.get(key).is_some_and(|v| v.len() == 1),
                "restored encoded BootMgr device multiplicity differs",
            )?;
        } else {
            need(
                fields.get(key) == Some(value),
                "restored original BootMgr field differs",
            )?;
        }
    }
    Ok(())
}
fn verify_loader(
    fields: &BTreeMap<String, Vec<String>>,
    intent: &BootIntent,
    sha: [u8; 32],
) -> io::Result<()> {
    need(
        one(fields, "identifier")? == intent.loader
            && one(fields, "device")?.eq_ignore_ascii_case(&intent.planned_device)
            && one(fields, "osdevice")?.eq_ignore_ascii_case(&intent.planned_device)
            && one(fields, "path")?.eq_ignore_ascii_case(r"\windows\system32\boot\winload.efi")
            && one(fields, "systemroot")?.eq_ignore_ascii_case(r"\windows")
            && one(fields, "winpe")?.eq_ignore_ascii_case("Yes")
            && one(fields, "detecthal")?.eq_ignore_ascii_case("Yes")
            && one(fields, "loadoptions")? == load_options(sha, bootstrap_pin(intent)?),
        "actual private PE loader is not the sealed image/options/intent",
    )
}

/// Actual current kernel boot-options routing pin only; never write authority.
pub fn current_recovery_intent_sha256() -> io::Result<[u8; 32]> {
    native::current_intent_sha()
}

/// Actual current kernel bootstrap routing pin only; never source authority.
pub fn current_recovery_bootstrap_sha256() -> io::Result<[u8; 32]> {
    native::current_bootstrap_sha()
}
fn bootstrap_pin(intent: &BootIntent) -> io::Result<[u8; 32]> {
    let pins: Vec<_> = intent
        .image_pins
        .iter()
        .filter(|p| p.role == "bootstrap")
        .collect();
    need(
        pins.len() == 1,
        "exact owned recovery bootstrap artifact pin required",
    )?;
    Ok(pins[0].sha256)
}
fn load_options(intent: [u8; 32], bootstrap: [u8; 32]) -> String {
    format!(
        "N2RRECOVERYINTENT={} N2RRECOVERYBOOTSTRAP={}",
        hex::encode(intent),
        hex::encode(bootstrap)
    )
}
