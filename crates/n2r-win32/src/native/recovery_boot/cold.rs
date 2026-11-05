//! Native cold proof. Serialized records route input only: the current kernel,
//! RAM image, actual excluded owner, same J and raw installed EFI store bind it.
use super::*;
use crate::native::{HeldPagedWritePolicy, PagedRecoveryPins};
use crate::offline_environment::{
    OfflinePreparedJournalQualification, OfflinePreparedReplayQualification, OfflinePreparedBootGuardRequirements, OfflinePreparedSource, OfflineSourceOwnerToken,
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
// Private common route: only actual opaque SDK qualifications implement it.
trait ActualBootQualification {
    fn revalidate_actual(&self,source:&mut OfflinePreparedSource,policy:&HeldPagedWritePolicy,
        journal:&mut File,pins:&PagedRecoveryPins<'_>,outer:&mut File,events:&mut Vec<NativeEvent>)->io::Result<()>;
    fn actual_requirements(&self)->&OfflinePreparedBootGuardRequirements;
}
impl ActualBootQualification for OfflinePreparedJournalQualification {
    fn revalidate_actual(&self,source:&mut OfflinePreparedSource,policy:&HeldPagedWritePolicy,
        journal:&mut File,pins:&PagedRecoveryPins<'_>,outer:&mut File,events:&mut Vec<NativeEvent>)->io::Result<()>{
        self.revalidate(source,policy,journal,pins,outer,events)
    }
    fn actual_requirements(&self)->&OfflinePreparedBootGuardRequirements{self.boot_guard_requirements()}
}
impl ActualBootQualification for OfflinePreparedReplayQualification {
    fn revalidate_actual(&self,source:&mut OfflinePreparedSource,policy:&HeldPagedWritePolicy,
        journal:&mut File,pins:&PagedRecoveryPins<'_>,outer:&mut File,events:&mut Vec<NativeEvent>)->io::Result<()>{
        self.revalidate(source,policy,journal,pins,outer,events)
    }
    fn actual_requirements(&self)->&OfflinePreparedBootGuardRequirements{self.boot_guard_requirements()}
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
    #[allow(clippy::too_many_arguments)]
    pub fn observe_prepared(source:&mut OfflinePreparedSource,qualification:&OfflinePreparedJournalQualification,
        policy:&HeldPagedWritePolicy,journal:&mut File,pins:&PagedRecoveryPins<'_>,sealed_bundle:&mut File,
        intent_path:&Path,expected_intent_sha256:[u8;32],directory:&Path,budget:RecoveryBootBudget,
        events:&mut Vec<NativeEvent>)->io::Result<Self>{
        Self::observe_bound(source,qualification,policy,journal,pins,sealed_bundle,
            intent_path,expected_intent_sha256,directory,budget,events)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn observe_recovery(source:&mut OfflinePreparedSource,qualification:&OfflinePreparedReplayQualification,
        policy:&HeldPagedWritePolicy,journal:&mut File,pins:&PagedRecoveryPins<'_>,sealed_bundle:&mut File,
        intent_path:&Path,expected_intent_sha256:[u8;32],directory:&Path,budget:RecoveryBootBudget,
        events:&mut Vec<NativeEvent>)->io::Result<Self>{
        Self::observe_bound(source,qualification,policy,journal,pins,sealed_bundle,
            intent_path,expected_intent_sha256,directory,budget,events)
    }
    fn observe_bound<Q:ActualBootQualification>(
        source: &mut OfflinePreparedSource,
        qualification: &Q,
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
        qualification.revalidate_actual(source, policy, journal, pins, sealed_bundle, events)?;
        let requirements = qualification.actual_requirements();
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
        let actual_bootstrap=bootstrap_pin(&intent)?;
        need(native::current_bootstrap_sha()?==actual_bootstrap,
            "actual native kernel bootstrap pin differs from installed owned image")?;
        let bootstrap=read_ram_marker(&PathBuf::from(&ram_root).join(r"Windows\System32\n2r-bootstrap.json"),budget.maximum_control_bytes)?;
        need(digest(&bootstrap)==actual_bootstrap,"actual current RAM bootstrap differs from native boot pin")?;
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
        qualification.revalidate_actual(source, policy, journal, pins, sealed_bundle, events)?;
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
    fn require_boot_identity(
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
        let bootstrap=read_ram_marker(&PathBuf::from(&self.ram_root).join(r"Windows\System32\n2r-bootstrap.json"),self.budget.maximum_control_bytes)?;
        need(native::current_bootstrap_sha()?==bootstrap_pin(&self.intent)?
            &&digest(&bootstrap)==bootstrap_pin(&self.intent)?,
            "current native/RAM bootstrap proof changed")?;
        native::require_san3()?;
        native::firmware(&self.intent.efi)?.require_same(&self.intent.firmware)?;
        for artifact in &self.held {
            artifact.revalidate()?;
        }
        let marker = read_ram_marker(
            &PathBuf::from(&self.ram_root).join(&self.intent.origin_marker_ram_relative),
            self.budget.maximum_control_bytes,
        )?;
        need(digest(&marker)==self.intent.origin_marker_sha256,
            "actual RAM origin marker changed")
    }
    pub fn require_current_boot(&mut self,owner:&OfflineSourceOwnerToken,events:&mut Vec<NativeEvent>)->io::Result<()> {
        self.require_boot_identity(owner,events)?;
        need(metadata::raw_hash(&self.intent.efi,
            self.intent.guarded_store_map.as_ref().ok_or_else(||bad("guarded BCD map absent"))?,
            self.budget.maximum_control_bytes,events)?==self.actual_store_sha256,
            "actual persistent installed BCD bytes changed")
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

#[derive(Clone,Debug,Serialize)]
pub struct RecoveryBootRestorationReceipt {
    pub kind:&'static str,
    pub source:crate::partition_isolation::PartitionSourceBinding,
    pub terminal_kind:crate::offline_environment::OfflineTerminalKind,
    pub restored_default:String,
    pub restored_display_order:Vec<String>,
    pub restored_timeout:String,
    pub restored_store_sha256:[u8;32],
    pub durable_record_path:PathBuf,
    pub durable_record_sha256:[u8;32],
    pub selected_partition_basic_readonly_preserved:bool,
    pub native_original_selection_readback_verified:bool,
    pub unrelated_bcd_objects_and_fields_preserved:bool,
    pub normal_boot_observed:bool,
    pub source_writer_authority:bool,
}
fn restore_checkpoint(observer:&mut impl crate::partition_restoration::PartitionRestorationObserver,
    phase:&'static str,events:&mut Vec<NativeEvent>)->io::Result<()> {
    observer.checkpoint_native_events(phase,events)?;
    need(events.is_empty(),"actual boot restoration observer did not durably drain events")
}
impl RecoveryBootGuard {
    /// Consume the real persistent guard and an actual closed-J metadata-only
    /// source owner. Restore ONLY original BootMgr order/timeout/default in the
    /// positively bound EFI store. No backup import, private-object delete,
    /// source-D GPT/data operation, firmware/security mutation or reboot.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_normal_boot(mut self,
        mut source:crate::offline_environment::OfflinePreparedAvailableSource,
        policy:&HeldPagedWritePolicy,journal:&mut File,pins:&PagedRecoveryPins<'_>,
        directory:&Path,observer:&mut impl crate::partition_restoration::PartitionRestorationObserver,
        events:&mut Vec<NativeEvent>)
        ->io::Result<(crate::offline_environment::OfflinePreparedAvailableSource,RecoveryBootRestorationReceipt)> {
        restore_checkpoint(observer,"recovery-boot-closed-restore-opening",events)?;
        self.require_owner(&source.owner_token())?;
        self.budget.validate()?;
        let mut last_verified_store:Option<StorePin>=None;
        let result=(||->io::Result<RecoveryBootRestorationReceipt>{
            // Full actual HND/allNEW or ABT/restoredOLD, same J/index/owner.
            // No original NTFS fingerprint/allOLD check is used after HND.
            source.revalidate_closed(policy,journal,pins,events)?;
            self.require_current_boot(&source.owner_token(),events)?;
            let before=source.state(events)?;
            need(source.binding()==&self.intent.source
                &&pins.journal_binding==&self.intent.journal
                &&before.actual.disk_attributes==0
                &&before.actual.gpt.target_attributes==0x1000_0000_0000_0000,
                "normal boot restore lacks the actual closed/available BASICRO source/J")?;
            restore_checkpoint(observer,"recovery-boot-actual-closed-owner-before-records",events)?;
            metadata::fresh_external(directory,source.binding(),&self.intent.journal,self.budget,events)?;
            let mut published=None;
            for attempt in 0..60 {
                let state=source.state(events)?;
                let observed=metadata::available_efi(&self.intent.efi,&state,self.budget.ram_bytes,events);
                restore_checkpoint(observer,"recovery-boot-terminal-EFI-publication-metadata-attempt",events)?;
                match observed {
                    Ok(efi)=>{published=Some(efi);break},
                    Err(e)if e.kind()==io::ErrorKind::NotFound&&attempt<59=>std::thread::sleep(Duration::from_millis(250)),
                    Err(e)=>return Err(e),
                }
            }
            let actual_efi=published.ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"actual terminal EFI publication wait exhausted"))?;
            native::firmware(&actual_efi)?.require_same(&self.intent.firmware)?;
            let tool=native::Tool::system(self.budget)?;
            let original=selection(self.intent.original.all_fields.clone())?;
            need(original.default==self.intent.original.default
                &&original.displayorder==self.intent.original.displayorder
                &&original.timeout==self.intent.original.timeout,
                "authenticated original BootMgr selection is internally inconsistent")?;
            let mut expected=tool.enum_all(&actual_efi.bcd_path,directory)?;
            verify_selection(expected.get(BOOTMGR).ok_or_else(||bad("current BootMgr absent"))?,&self.intent)?;
            let first_store=metadata::capture_store(&actual_efi,self.budget,events)?;
            need(first_store.sha256==self.actual_store_sha256
                &&first_store.same_file_map(self.intent.guarded_store_map.as_ref().ok_or_else(||bad("guarded store map absent"))?),
                "current published EFI BCD bytes/FAT mapping differ from actual guarded epoch")?;
            last_verified_store=Some(first_store.clone());
            restore_checkpoint(observer,"recovery-boot-original-selection-and-current-FAT-bound",events)?;
            let original_fields=&original.all_fields;
            for id in &original.displayorder {
                need(expected.contains_key(id),"original display-order object disappeared from actual guarded store")?;
            }
            // Durable immutable external record precedes the FIRST native setter.
            let intent_path=directory.join("normal-boot-restoration-intent.json");
            let restoration_intent=serde_json::json!({"kind":"actual-closed-normal-boot-restoration-intent-v1",
                "source":source.binding(),"terminal_kind":source.terminal_kind(),
                "actual_efi":actual_efi,"actual_closed_journal_identity":pins.journal_identity,
                "immutable_journal_sha256":pins.immutable_sha256,"actual_index_sha256":policy.facts()?.index_sha256,
                "original_kernel_guard_intent_sha256":self.intent_sha256,
                "prepared_outer_sha256":self.intent.prepared_bundle_sha256,
                "before_store":first_store,"before_all_native_objects":expected,
                "desired_original_bootmgr":original_fields,"no_backup_import":true,
                "selected_source_stays_BASICRO":true,"record_grants_source_authority":false});
            let intent_sha=native::persist(&intent_path,&restoration_intent,self.budget.maximum_control_bytes)?;
            restore_checkpoint(observer,"recovery-boot-before-normal-selection-intent-durable",events)?;
            // Keep the recovery default until order+timeout have been read back.
            // Closed source proof already precedes every possible selection change.
            for (ordinal,field,values) in [
                (0usize,"displayorder",original.displayorder.clone()),
                (1usize,"timeout",vec![original.timeout.clone()]),
                (2usize,"default",vec![original.default.clone()]),
            ] {
                self.require_boot_identity(&source.owner_token(),events)?;
                source.state(events)?;
                let prior=last_verified_store.as_ref().ok_or_else(||bad("current store epoch absent"))?;
                need(metadata::raw_hash(&actual_efi,prior,self.budget.maximum_control_bytes,events)?==prior.sha256,
                    "actual current FAT/BCD epoch changed before original selection setter")?;
                restore_checkpoint(observer,"recovery-boot-before-explicit-original-selection-setter",events)?;
                let mut args=vec![format!("/{field}")];args.extend(values.clone());
                tool.run(Some(&actual_efi.bcd_path),&args,directory)?;
                metadata::flush_explicit_store(&actual_efi)?;
                expected.get_mut(BOOTMGR).ok_or_else(||bad("BootMgr disappeared"))?.insert(field.into(),values);
                need(tool.enum_all(&actual_efi.bcd_path,directory)?==expected,
                    "native BCD readback changed unrelated objects/fields or failed original element restoration")?;
                let current=metadata::capture_store(&actual_efi,self.budget,events)?;
                need(current.fat_boot_sha256==first_store.fat_boot_sha256,
                    "EFI FAT boot geometry changed during BootMgr-only restoration")?;
                // This epoch is minted only from the current published EFI file,
                // actual retrieval map, both FAT chains and logical/raw readback.
                // Native BCD may legitimately reallocate its own hive pages.
                native::firmware(&actual_efi)?.require_same(&self.intent.firmware)?;
                source.state(events)?;
                native::persist(&directory.join(format!("normal-boot-step-{ordinal}.json")),
                    &serde_json::json!({"kind":"actual-original-BootMgr-element-restored-v1","element":field,
                    "current_store":current,"current_bootmgr":expected.get(BOOTMGR),
                    "unrelated_native_BCD_objects_equal":true,"original_intent_sha256":intent_sha}),
                    self.budget.maximum_control_bytes)?;
                last_verified_store=Some(current);
                restore_checkpoint(observer,"recovery-boot-original-selection-setter-readback-durable",events)?;
            }
            let restored=expected.get(BOOTMGR).ok_or_else(||bad("restored BootMgr absent"))?;
            need(one(restored,"default")?==original.default
                &&restored.get("displayorder")==Some(&original.displayorder)
                &&one(restored,"timeout")?==original.timeout&&!restored.contains_key("bootsequence"),
                "actual original native BootMgr selection was not fully restored")?;
            let final_store=last_verified_store.as_ref().ok_or_else(||bad("verified restored store absent"))?;
            need(metadata::raw_hash(&actual_efi,final_store,self.budget.maximum_control_bytes,events)?==final_store.sha256,
                "restored BCD actual FAT/raw bytes changed after native readback")?;
            self.require_boot_identity(&source.owner_token(),events)?;
            source.revalidate_closed(policy,journal,pins,events)?;
            let final_state=source.state(events)?;
            need(final_state.actual.gpt==before.actual.gpt&&final_state.actual.disk_attributes==0,
                "BootMgr restore changed source/sibling GPT or actual availability")?;
            restore_checkpoint(observer,"recovery-boot-restored-closed-J-and-source-native-verified",events)?;
            let record_path=directory.join("normal-boot-restoration-completed.json");
            let record=serde_json::json!({"kind":"actual-closed-normal-boot-selection-restored-v1",
                "source":source.binding(),"terminal_kind":source.terminal_kind(),"actual_efi":actual_efi,
                "original_selection":original,"restored_store":final_store,
                "restoration_intent_path":intent_path,"restoration_intent_sha256":intent_sha,
                "all_other_native_BCD_objects_and_fields_preserved":true,"backup_imports":0,
                "private_guard_entries_deleted":false,"source_GPT_BASICRO_preserved":true,
                "source_payload_write_calls":0,"firmware_and_security_writes":0,
                "normal_boot_observed":false,"saved_record_grants_authority":false});
            let record_sha=native::persist(&record_path,&record,self.budget.maximum_control_bytes)?;
            let record_path=metadata::guid_external_path(&record_path,&self.intent.journal,self.budget.maximum_control_bytes)?;
            Ok(RecoveryBootRestorationReceipt{kind:"actual-closed-normal-boot-selection-restored-v1",
                source:source.binding().clone(),terminal_kind:source.terminal_kind(),
                restored_default:original.default,restored_display_order:original.displayorder,
                restored_timeout:original.timeout,restored_store_sha256:final_store.sha256,
                durable_record_path:record_path,durable_record_sha256:record_sha,
                selected_partition_basic_readonly_preserved:true,native_original_selection_readback_verified:true,
                unrelated_bcd_objects_and_fields_preserved:true,normal_boot_observed:false,source_writer_authority:false})
        })();
        // Source/J closing proof and actual durable event drain run on BOTH
        // success and error, including a partial native BootMgr update.
        let closed=source.revalidate_closed(policy,journal,pins,events);
        let boot=self.require_boot_identity(&source.owner_token(),events);
        let drained=restore_checkpoint(observer,"recovery-boot-normal-restore-final-closed",events);
        let mut errors=Vec::new();
        let receipt=match result{Ok(v)=>Some(v),Err(e)=>{errors.push(format!("normal boot restoration failed:{e}"));None}};
        for (label,check) in [("closed J/source",closed),("current boot identity",boot),("durable checkpoint",drained)] {
            if let Err(e)=check{errors.push(format!("{label} also failed:{e}"));}
        }
        if !errors.is_empty(){
            if directory.is_dir(){let _=native::persist(&directory.join("normal-boot-restoration-failed-preserved.json"),
                &serde_json::json!({"errors":errors,"last_verified_store":last_verified_store,
                    "actual_current_selection_unknown_after_error":true,"no_automatic_retry_import_delete_or_reboot":true}),
                self.budget.maximum_control_bytes);}
            return Err(io::Error::other(errors.join("; ")))
        }
        Ok((source,receipt.ok_or_else(||bad("normal boot restore receipt absent"))?))
    }
}
