//! Native cold proof. Serialized records route input only: the current kernel,
//! RAM image, actual excluded owner, same J and raw installed EFI store bind it.
use super::*;
use crate::native::{HeldPagedWritePolicy, PagedRecoveryPins};
use crate::offline_environment::{
    OfflinePreparedJournalQualification, OfflinePreparedSource, OfflineSourceOwnerToken,
};
use crate::reference_file::ReferenceFileSnapshot;
use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;

struct HeldPin {
    file: File,
    snapshot: ReferenceFileSnapshot,
    sha256: [u8; 32],
}
impl HeldPin {
    fn open(
        path: &Path,
        journal: &GeneralJournalStorageBinding,
        maximum: u64,
        expected: [u8; 32],
    ) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        crate::file_storage::require_readonly_access(&file)?;
        let snapshot =
            crate::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        need(
            snapshot.file_bytes > 0
                && snapshot.number_of_links == 1
                && snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&(journal.disk.volume_path()?.to_ascii_lowercase() + "\\")),
            "cold boot artifact must be on actual enrolled J",
        )?;
        need(
            crate::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == expected,
            "actual cold boot artifact SHA differs from native-boot-pinned intent",
        )?;
        let held = Self {
            file,
            snapshot,
            sha256: expected,
        };
        held.revalidate()?;
        Ok(held)
    }
    fn revalidate(&self) -> io::Result<()> {
        // This exact readonly FILE_OBJECT excludes new write/delete handles.
        // Hash was checked once after open; later boundaries retain it and
        // require the complete same native identity/EOF/allocation snapshot.
        need(
            crate::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes,
            )? == self.snapshot,
            "same held immutable boot artifact identity changed",
        )
    }
    fn bytes(&mut self, maximum: u64) -> io::Result<Vec<u8>> {
        need(
            self.snapshot.file_bytes <= maximum,
            "cold boot control exceeds RAM quota",
        )?;
        let mut out = vec![0; usize::try_from(self.snapshot.file_bytes).map_err(io::Error::other)?];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut out)?;
        self.revalidate()?;
        need(
            digest(&out) == self.sha256,
            "same held cold control bytes changed",
        )?;
        Ok(out)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryBootGuardFacts {
    pub kind: &'static str,
    pub source: PartitionSourceBinding,
    pub prepared_bundle_sha256: [u8; 32],
    pub actual_boot_identifier: Vec<u8>,
    pub native_kernel_intent_sha256: [u8; 32],
    pub loader_guid: String,
    pub actual_early_san_policy: u32,
    pub source_already_offline_on_enrollment: bool,
    pub installed_bcd_raw_sha256: [u8; 32],
    pub persistent_recovery_default_and_order_verified: bool,
    pub ram_origin_marker_sha256: [u8; 32],
    pub raw_mapping_durable_across_boot_verified: bool,
    pub source_write_authority: bool,
    pub restoration_requires_actual_closed_terminal_owner: bool,
}
/// No Clone/Deserialize/raw File/Write. This is a separate necessary boot proof,
/// never the semantic prepared certificate or the actual J/AP writer gate.
pub struct RecoveryBootGuard {
    owner: OfflineSourceOwnerToken,
    intent: BootIntent,
    intent_sha256: [u8; 32],
    boot: Vec<u8>,
    running_image_sha256: String,
    ram_root: String,
    actual_store_sha256: [u8; 32],
    held: Vec<HeldPin>,
    facts: RecoveryBootGuardFacts,
    budget: RecoveryBootBudget,
}
impl RecoveryBootGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn observe_prepared(
        source: &mut OfflinePreparedSource,
        qualification: &OfflinePreparedJournalQualification,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        sealed_bundle: &mut File,
        intent_path: &Path,
        expected_intent_sha256: [u8; 32],
        directory: &Path,
        budget: RecoveryBootBudget,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        budget.validate()?;
        qualification.revalidate(source, policy, journal, pins, sealed_bundle, events)?;
        let requirements = qualification.boot_guard_requirements();
        need(
            requirements.source_was_already_offline_on_enrollment
                && requirements.actual_excluded_disk_attributes == 3,
            "source was not already excluded by early SAN3 before any prepared-source enrollment",
        )?;
        let actual_intent = native::current_intent_sha()?;
        need(
            actual_intent == expected_intent_sha256,
            "caller recovery intent pin is not the actual current kernel's boot options",
        )?;
        let env = source.offline_environment_facts();
        let boot = env.boot.boot_identifier.clone();
        let ram_root = env.windows_ram_root.clone();
        let running = env.running_image.sha256.clone();
        need(
            env.environment_identity_qualified
                && env.mini_nt_present
                && env.boot.firmware_type == 2
                && env.native_ram_backing.positive_native_kernel_ramdisk,
            "actual native RAM-Windows/MiniNT/UEFI environment is required",
        )?;
        let initial_bytes = metadata::read_external(
            intent_path,
            pins.journal_binding,
            budget.maximum_control_bytes,
        )?;
        need(
            digest(&initial_bytes) == actual_intent,
            "actual kernel-pinned external guard intent differs",
        )?;
        let intent: BootIntent =
            serde_json::from_slice(&initial_bytes).map_err(io::Error::other)?;
        need(
            intent.version == 1
                && intent.kind == "ntfs2refs-persistent-recovery-boot-intent-v1"
                && !intent.serialized_intent_is_writer_authority
                && intent.source == *source.binding()
                && intent.journal == *pins.journal_binding
                && intent.prepared_bundle_sha256 == requirements.sealed_publication_sha256
                && intent.parent_original_intent_sha256.is_some(),
            "native-boot-pinned intent/source/J/outer publication contract differs",
        )?;
        let guard_map = intent.guarded_store_map.as_ref().ok_or_else(|| {
            bad("actual post-creation BCD mapping not present in immutable guard intent")
        })?;
        need(
            guard_map.bytes <= budget.maximum_store_bytes,
            "guarded installed BCD exceeds admitted metadata bound",
        )?;
        need(
            guid(&boot)? == intent.loader
                && native::kernel_boot_identifier()?.as_slice() == boot.as_slice(),
            "current native kernel did not boot the actual private recovery loader",
        )?;
        native::require_san3()?;
        let state = source.state(events)?;
        metadata::require_cold_efi(&intent.efi, &state)?;
        metadata::fresh_external(directory, source.binding(), &intent.journal, budget, events)?;
        let mut held = Vec::new();
        held.push(HeldPin::open(
            intent_path,
            &intent.journal,
            budget.maximum_control_bytes,
            actual_intent,
        )?);
        let original = held[0].bytes(budget.maximum_control_bytes)?;
        need(
            original == initial_bytes,
            "held guard intent changed during enrollment",
        )?;
        // Preserve and authenticate the original BEFORE-first-mutation record.
        let original_path = intent_path
            .parent()
            .ok_or_else(|| bad("boot intent parent absent"))?
            .join("recovery-boot-original-intent.json");
        let mut parent = HeldPin::open(
            &original_path,
            &intent.journal,
            budget.maximum_control_bytes,
            intent
                .parent_original_intent_sha256
                .ok_or_else(|| bad("original intent hash absent"))?,
        )?;
        let before: BootIntent =
            serde_json::from_slice(&parent.bytes(budget.maximum_control_bytes)?)
                .map_err(io::Error::other)?;
        let mut reconstructed = intent.clone();
        reconstructed.guarded_store_map = None;
        reconstructed.parent_original_intent_sha256 = None;
        need(
            serde_json::to_vec(&before).map_err(io::Error::other)?
                == serde_json::to_vec(&reconstructed).map_err(io::Error::other)?,
            "guard intent no longer preserves original pre-mutation selection/store",
        )?;
        held.push(parent);
        held.push(HeldPin::open(
            &intent.backup_path,
            &intent.journal,
            budget.maximum_store_bytes,
            intent.backup_sha256,
        )?);
        let mut image_total = 0u64;
        let mut roles = std::collections::BTreeSet::new();
        for pin in &intent.image_pins {
            need(
                roles.insert(pin.role.clone()),
                "duplicate immutable recovery image artifact role",
            )?;
            let artifact = HeldPin::open(
                &pin.path,
                &intent.journal,
                budget.maximum_image_bytes,
                pin.sha256,
            )?;
            image_total = image_total
                .checked_add(artifact.snapshot.file_bytes)
                .ok_or_else(|| bad("recovery image byte charge overflow"))?;
            need(
                image_total <= budget.maximum_image_bytes
                    && serde_json::to_value(&artifact.snapshot).map_err(io::Error::other)?
                        == pin.snapshot,
                "image artifact identity or admitted total differs",
            )?;
            held.push(artifact);
        }
        for (role, sha) in [
            ("wim", intent.wim_sha256),
            ("sdi", intent.sdi_sha256),
            ("runner", intent.runner_sha256),
            ("origin-marker", intent.origin_marker_sha256),
        ] {
            need(
                intent
                    .image_pins
                    .iter()
                    .filter(|p| p.role == role && p.sha256 == sha)
                    .count()
                    == 1,
                "required real sealed image artifact pin absent",
            )?;
        }
        let marker_path = PathBuf::from(&ram_root).join(&intent.origin_marker_ram_relative);
        let marker = read_ram_marker(&marker_path, budget.maximum_control_bytes)?;
        need(
            digest(&marker) == intent.origin_marker_sha256,
            "actual booted RAM-WIM origin marker differs",
        )?;
        let marker: serde_json::Value =
            serde_json::from_slice(&marker).map_err(io::Error::other)?;
        require_marker(&marker, &intent, &running)?;
        native::firmware(&intent.efi)?.require_same(&intent.firmware)?;
        let actual_store_sha256 = metadata::raw_copy(
            &intent.efi,
            guard_map,
            &directory.join("actual-installed-system-store.bcd"),
            budget.maximum_store_bytes,
            budget.maximum_control_bytes,
            events,
        )?;
        let tool = native::Tool::system(budget)?;
        let store = directory.join("actual-installed-system-store.bcd");
        verify_selection(
            &tool.enum_object(Some(&store), BOOTMGR, directory)?,
            &intent,
        )?;
        verify_cold_loader(
            &tool.enum_object(Some(&store), &intent.loader, directory)?,
            &intent,
            actual_intent,
        )?;
        let options = tool.enum_object(Some(&store), &intent.ramdisk_options, directory)?;
        need(
            one(&options, "identifier")? == intent.ramdisk_options
                && one(&options, "ramdisksdipath")?.eq_ignore_ascii_case(&intent.planned_sdi_path),
            "actual installed private ramdisk options differ",
        )?;
        require_j_route(one(&options, "ramdisksdidevice")?, &intent.journal)?;
        need(
            metadata::raw_hash(&intent.efi, guard_map, budget.maximum_control_bytes, events)?
                == actual_store_sha256,
            "installed BCD changed during actual native enum",
        )?;
        qualification.revalidate(source, policy, journal, pins, sealed_bundle, events)?;
        let facts = RecoveryBootGuardFacts {
            kind: "actual-native-cold-persistent-recovery-boot-guard-v1",
            source: intent.source.clone(),
            prepared_bundle_sha256: intent.prepared_bundle_sha256,
            actual_boot_identifier: boot.clone(),
            native_kernel_intent_sha256: actual_intent,
            loader_guid: intent.loader.clone(),
            actual_early_san_policy: 3,
            source_already_offline_on_enrollment: true,
            installed_bcd_raw_sha256: actual_store_sha256,
            persistent_recovery_default_and_order_verified: true,
            ram_origin_marker_sha256: intent.origin_marker_sha256,
            raw_mapping_durable_across_boot_verified: true,
            source_write_authority: false,
            restoration_requires_actual_closed_terminal_owner: true,
        };
        native::persist(
            &directory.join("actual-cold-boot-guard.json"),
            &facts,
            budget.maximum_control_bytes,
        )?;
        Ok(Self {
            owner: source.owner_token(),
            intent,
            intent_sha256: actual_intent,
            boot,
            running_image_sha256: running,
            ram_root,
            actual_store_sha256,
            held,
            facts,
            budget,
        })
    }
    pub fn facts(&self) -> &RecoveryBootGuardFacts {
        &self.facts
    }
    pub fn require_owner(&self, owner: &OfflineSourceOwnerToken) -> io::Result<()> {
        need(
            self.owner.same_owner(owner),
            "boot guard is bound to another actual source owner",
        )
    }
    /// Boot/J artifact protection only. Caller separately revalidates actual
    /// source epoch/J lifecycle after AP; this does not recheck stale allOLD.
    /// No source writer or source I/O is returned.
    pub fn require_current_boot(
        &mut self,
        owner: &OfflineSourceOwnerToken,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.require_owner(owner)?;
        need(
            native::kernel_boot_identifier()?.as_slice() == self.boot.as_slice()
                && native::current_intent_sha()? == self.intent_sha256,
            "actual current kernel recovery boot/intent changed",
        )?;
        native::require_san3()?;
        native::firmware(&self.intent.efi)?.require_same(&self.intent.firmware)?;
        for artifact in &self.held {
            artifact.revalidate()?;
        }
        let marker = read_ram_marker(
            &PathBuf::from(&self.ram_root).join(&self.intent.origin_marker_ram_relative),
            self.budget.maximum_control_bytes,
        )?;
        need(
            digest(&marker) == self.intent.origin_marker_sha256
                && metadata::raw_hash(
                    &self.intent.efi,
                    self.intent
                        .guarded_store_map
                        .as_ref()
                        .ok_or_else(|| bad("guarded BCD map absent"))?,
                    self.budget.maximum_control_bytes,
                    events,
                )? == self.actual_store_sha256,
            "actual RAM origin or persistent installed BCD bytes changed",
        )
    }
    pub fn require_before_writer(
        &mut self,
        source: &mut OfflinePreparedSource,
        qualification: &OfflinePreparedJournalQualification,
        policy: &HeldPagedWritePolicy,
        journal: &mut File,
        pins: &PagedRecoveryPins<'_>,
        sealed_bundle: &mut File,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        qualification.revalidate(source, policy, journal, pins, sealed_bundle, events)?;
        self.require_owner(&source.owner_token())?;
        let state = source.state(events)?;
        metadata::require_cold_efi(&self.intent.efi, &state)?;
        let env = source.offline_environment_facts();
        need(
            env.boot.boot_identifier == self.boot
                && env.windows_ram_root == self.ram_root
                && env.running_image.sha256 == self.running_image_sha256
                && native::kernel_boot_identifier()?.as_slice() == self.boot.as_slice()
                && native::current_intent_sha()? == self.intent_sha256,
            "actual current RAM loader/boot/intent changed",
        )?;
        native::require_san3()?;
        native::firmware(&self.intent.efi)?.require_same(&self.intent.firmware)?;
        for artifact in &self.held {
            artifact.revalidate()?;
        }
        let marker = read_ram_marker(
            &PathBuf::from(&self.ram_root).join(&self.intent.origin_marker_ram_relative),
            self.budget.maximum_control_bytes,
        )?;
        need(
            digest(&marker) == self.intent.origin_marker_sha256
                && metadata::raw_hash(
                    &self.intent.efi,
                    self.intent
                        .guarded_store_map
                        .as_ref()
                        .ok_or_else(|| bad("guarded BCD map absent"))?,
                    self.budget.maximum_control_bytes,
                    events,
                )? == self.actual_store_sha256,
            "actual RAM origin or persistent installed BCD bytes changed",
        )?;
        qualification.revalidate(source, policy, journal, pins, sealed_bundle, events)
    }
}
fn read_ram_marker(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let before = file.metadata()?;
    need(
        before.is_file() && before.len() > 0 && before.len() <= maximum,
        "bounded actual RAM marker file required",
    )?;
    crate::native::offline_environment::kernel_ram_backing::require_file(
        path.to_str()
            .ok_or_else(|| bad("Unicode RAM origin path required"))?,
        &file,
    )?;
    let mut bytes = vec![0; usize::try_from(before.len()).map_err(io::Error::other)?];
    file.read_exact(&mut bytes)?;
    need(
        file.metadata()?.len() == before.len(),
        "RAM origin marker EOF changed",
    )?;
    Ok(bytes)
}
fn require_marker(
    marker: &serde_json::Value,
    intent: &BootIntent,
    running: &str,
) -> io::Result<()> {
    need(
        marker["kind"] == "ntfs2refs-owned-recovery-WIM-origin-v1"
            && marker["prepared_OUTER_bundle_sha256"] == hex::encode(intent.prepared_bundle_sha256)
            && marker["runner_sha256"] == hex::encode(intent.runner_sha256)
            && running.eq_ignore_ascii_case(&hex::encode(intent.runner_sha256))
            && marker["source"]
                == serde_json::to_value(&intent.source).map_err(io::Error::other)?
            && marker["journal"]
                == serde_json::to_value(&intent.journal).map_err(io::Error::other)?
            && marker["startup_args"]
                == serde_json::to_value(&intent.startup_args).map_err(io::Error::other)?
            && marker["early_SAN_policy"] == 3
            && marker["current_default_select_verified"] == true,
        "actual booted image marker/kernel runner/source/J/bundle/SAN contract differs",
    )?;
    let nonce = marker["builder_nonce"]
        .as_str()
        .ok_or_else(|| bad("actual booted WIM nonce absent"))?;
    need(
        derived_guid(
            b"ntfs2refs-recovery-loader-v1",
            nonce,
            intent.prepared_bundle_sha256,
        )? == intent.loader
            && derived_guid(
                b"ntfs2refs-recovery-device-v1",
                nonce,
                intent.prepared_bundle_sha256,
            )? == intent.ramdisk_options,
        "actual WIM marker belongs to another private boot object",
    )
}
fn require_j_route(route: &str, journal: &GeneralJournalStorageBinding) -> io::Result<()> {
    let path = route
        .strip_prefix("partition=")
        .ok_or_else(|| bad("explicit native J partition route required"))?;
    need(
        path.len() == 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':',
        "actual J route has no bounded native drive mapping",
    )?;
    let mut output = [0u16; 64];
    let root = format!("{path}\\");
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            wide(&root).as_ptr(),
            output.as_mut_ptr(),
            output.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = output
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| bad("current J volume GUID unterminated"))?;
    need(
        String::from_utf16(&output[..n])
            .map_err(io::Error::other)?
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(&journal.disk.volume_path()?),
        "native BCD image device is not actual independently enrolled J",
    )
}
fn verify_cold_loader(
    fields: &BTreeMap<String, Vec<String>>,
    intent: &BootIntent,
    sha: [u8; 32],
) -> io::Result<()> {
    let mut normalized = fields.clone();
    for key in ["device", "osdevice"] {
        let actual = one(fields, key)?;
        let prefix = "ramdisk=[";
        need(
            actual.to_ascii_lowercase().starts_with(prefix),
            "actual PE loader is not a ramdisk",
        )?;
        let end = actual
            .find(']')
            .ok_or_else(|| bad("native ramdisk device delimiter absent"))?;
        require_j_route(
            &format!("partition={}", &actual[prefix.len()..end]),
            &intent.journal,
        )?;
        let expected_end = intent
            .planned_device
            .find(']')
            .ok_or_else(|| bad("pinned ramdisk route invalid"))?;
        need(
            actual[end + 1..].eq_ignore_ascii_case(&intent.planned_device[expected_end + 1..]),
            "native ramdisk image path/private device object differs",
        )?;
        normalized.insert(key.into(), vec![intent.planned_device.clone()]);
    }
    verify_loader(&normalized, intent, sha)
}
