//! Bounded discovery of a closed, cancelled legacy preparation's facts.
//! No saved record here is source admission, native proof, or replay authority.
use crate::{
    general_source_admission::resource::{SourceCacheFilePin, SourceCacheOriginPins},
    ntfs_inspect::paged_storage::{SourceRamLease, SourceScratch},
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
    journal_file::GeneralJournalStorageBinding,
    reference_file::ReferenceFileSnapshot,
    tree_resources::{ResourceBudget, SourceResourceAdmission},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PriorAvailableResources {
    pub total_physical_bytes: u64,
    pub available_physical_bytes: u64,
    pub scratch_available_bytes: u64,
    pub scratch_total_bytes: u64,
}

/// The public envelope before the separately paid Windows repair split.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParentPublicResources {
    pub observed: PriorAvailableResources,
    pub resources: ResourceBudget,
    pub reserve_bytes: u64,
    pub provider_maximum_additional_backing_bytes: u64,
    pub provider_minimum_host_free_bytes: u64,
    pub evidence_allocation_bytes: u64,
    pub evidence_maximum_bytes: u64,
    pub evidence_ram_bytes: u64,
    pub capture_bytes: u64,
    pub maximum_journal_bytes: u64,
    pub maximum_combined_bytes: u64,
}

/// Small routing/budget facts for constructing the NEW arena. The complete
/// loader subsequently holds, hashes and cross-checks this very same plan;
/// this preliminary read grants no source, cache or shadow capability.
pub(crate) fn peek_parent_resources(directory: &Path) -> Result<ParentPublicResources> {
    ordinary(directory)?;
    let path = directory.parent().context("legacy workflow parent absent")?
        .join("resource-plan.json");
    let file = OpenOptions::new().read(true).share_mode(1)
        .custom_flags(0x0020_0000).open(&path)?;
    ensure!(file.metadata()?.is_file() && file.metadata()?.len() <= 65536,
        "bounded ordinary preparation resource plan required");
    let value: ParentPublicResources = serde_json::from_reader(file.take(65537))?;
    value.resources.validate()?;
    Ok(value)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ConservativePartialPlacementSpend {
    pub old_work_upper_bytes: u64,
    pub uncertain_operation_upper_bytes: u64,
    pub total_prior_upper_bytes: u64,
    pub old_submission_upper: u64,
    pub actual_prior_bytes_known: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ClosedLegacyLedger {
    pub file: SourceCacheFilePin,
    pub records: u64,
    pub used_bytes: u64,
    pub used_prefix_sha256: String,
    pub chain_sha256: String,
    pub placement_refusal: Value,
}

pub(crate) struct LegacyResumeOrigin {
    pub origin: SourceCacheOriginPins,
    pub origin_sha256: [u8; 32],
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    pub old_main_resources: ResourceBudget,
    pub parent_resources: ParentPublicResources,
    pub expected: SourceCacheFilePin,
    // The old observer did not persist this receipt. Only the complete typed
    // expected-page opener derives it; no guessed semantic pin is exposed.
    pub expected_semantic_sha256: Option<String>,
    pub terminal: SourceCacheFilePin,
    pub process: SourceCacheFilePin,
    pub ledger: ClosedLegacyLedger,
    pub ledger_summary: SourceCacheFilePin,
    pub parent_resource_plan: SourceCacheFilePin,
    pub conservative_spend: ConservativePartialPlacementSpend,
    pub arena_root: PathBuf,
    pub common_run_root: PathBuf,
    pub launch_root: PathBuf,
    held: Vec<HeldFile>,
    _memory: SourceRamLease,
    _ledger_memory: SourceRamLease,
}

#[derive(Deserialize)]
struct Assessment {
    kind: String,
    binding: GeneralDiskBinding,
    budget: ResourceBudget,
    resource_admission: SourceResourceAdmission,
    policy: VerificationPolicy,
}
#[derive(Deserialize)]
struct Terminal {
    native_exit: i32,
    native_launches: u64,
    owned_process_handle_observed: bool,
    birth_ms: u64,
    pid: u64,
}
#[derive(Deserialize)]
struct Process {
    native_launches: u64,
    birth_ms: u64,
    pid: u64,
    source_disk: u32,
    source_partition: u32,
    source_partition_bytes_before: u64,
    arguments: Vec<String>,
}

struct HeldFile {
    file: File,
    pin: SourceCacheFilePin,
    snapshot: ReferenceFileSnapshot,
    last_write_time: u64,
    _parents: Vec<File>,
    _memory: SourceRamLease,
    _decoded_memory: Vec<SourceRamLease>,
}
fn ordinary(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
            && !path.as_os_str().to_string_lossy().starts_with("\\\\.\\"),
        "ordinary absolute legacy metadata path required"
    );
    Ok(())
}
fn sha(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical legacy SHA-256 required"
    );
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}
fn volume(route: &str) -> Result<[u8; 16]> {
    Ok(n2r_win32::layout::guid_bytes(
        route
            .strip_prefix("\\\\?\\Volume{")
            .and_then(|s| s.split_once('}'))
            .context("GUID metadata route required")?
            .0,
    )?)
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn unique(paths: impl IntoIterator<Item = PathBuf>, description: &str) -> Result<PathBuf> {
    let mut found = None;
    for path in paths {
        if exists(&path)? {
            ensure!(found.is_none(), "ambiguous legacy {description} layout");
            found = Some(path);
        }
    }
    found.with_context(|| format!("closed legacy {description} absent"))
}
impl HeldFile {
    fn open(
        path: &Path,
        maximum: u64,
        expected: Option<&str>,
        payer: &SourceScratch,
    ) -> Result<Self> {
        ordinary(path)?;
        ensure!(
            maximum > 0 && maximum <= i64::MAX as u64,
            "legacy file bound differs"
        );
        let depth = path.ancestors().count() as u64;
        let memory = payer.lease_ram(
            depth
                .checked_mul(8192)
                .and_then(|n| n.checked_add(131072))
                .context("legacy held metadata RAM overflow")?,
        )?;
        let mut parents = Vec::new();
        for parent in path.parent().context("legacy parent absent")?.ancestors() {
            let directory = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(1)
                .custom_flags(0x0220_0000)
                .open(parent)?;
            ensure!(
                directory.metadata()?.is_dir()
                    && directory.metadata()?.file_attributes() & 0x400 == 0,
                "legacy metadata ancestry is redirected"
            );
            parents.push(directory);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(path)?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let snapshot =
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
        ensure!(
            snapshot.file_bytes > 0
                && snapshot.number_of_links == 1
                && snapshot.file_attributes & (0x400 | 0x800 | 0x200 | 0x4000) == 0,
            "legacy file is redirected, sparse, compressed, encrypted, or multiply linked"
        );
        let last_write_time = file.metadata()?.last_write_time();
        let digest = if let Some(expected) = expected {
            sha(expected)?;
            expected.to_owned()
        } else {
            hex::encode(hash_file(&mut file, snapshot.file_bytes)?)
        };
        let value = Self {
            file,
            pin: SourceCacheFilePin {
                path: path.to_path_buf(),
                sha256: digest,
                bytes: snapshot.file_bytes,
            },
            snapshot,
            last_write_time,
            _parents: parents,
            _memory: memory,
            _decoded_memory: Vec::new(),
        };
        value.revalidate_identity()?;
        Ok(value)
    }
    fn revalidate_identity(&self) -> Result<()> {
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.pin.bytes
            )? == self.snapshot
                && self.file.metadata()?.last_write_time() == self.last_write_time,
            "held legacy metadata identity/time changed"
        );
        Ok(())
    }
    fn json<T: DeserializeOwned>(&mut self, maximum: u64, payer: &SourceScratch) -> Result<T> {
        ensure!(self.pin.bytes <= maximum, "legacy JSON bound exceeded");
        let ram = payer.lease_ram(
            self.pin
                .bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .context("legacy JSON RAM overflow")?,
        )?;
        self.revalidate_identity()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::try_from(self.pin.bytes)?)?;
        (&mut self.file)
            .take(self.pin.bytes + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == self.pin.bytes
                && hex::encode(Sha256::digest(&bytes)) == self.pin.sha256,
            "legacy JSON complete hash differs"
        );
        let value = serde_json::from_slice(&bytes)?;
        self.revalidate_identity()?;
        self._decoded_memory.push(ram);
        Ok(value)
    }
}
fn hash_file(file: &mut File, bytes: u64) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut left = bytes;
    let mut buffer = [0; 65536];
    let mut hash = Sha256::new();
    while left != 0 {
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    Ok(hash.finalize().into())
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .with_context(|| format!("legacy {name} absent"))
}
fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .with_context(|| format!("legacy {name} absent"))
}

fn ledger(
    file: &mut HeldFile,
    summary: &Value,
    maximum_body: u64,
    payer: &SourceScratch,
) -> Result<(ClosedLegacyLedger, SourceRamLease)> {
    ensure!(
        text(summary, "kind")? == "bounded-native-event-ledger"
            && text(summary, "format")? == "N2REVLG1-length-hash-chain-v1"
            && summary["closed"] == true
            && summary["grants_source_or_replay_authority"] == false
            && number(summary, "reserved_file_bytes")? == file.pin.bytes,
        "legacy ledger summary is not a closed non-authority framed ledger"
    );
    file.file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 128];
    file.file.read_exact(&mut header)?;
    let maximum = u64::from_le_bytes(header[16..24].try_into()?);
    ensure!(
        &header[..8] == b"N2REVLG1"
            && header[8..12] == 1u32.to_le_bytes()
            && header[12..16] == [0; 4]
            && header[24..] == [0; 104]
            && maximum == number(summary, "maximum_budget_bytes")?
            && file.pin.bytes <= maximum,
        "legacy ledger header differs"
    );
    let mut prefix = Sha256::new();
    prefix.update(header);
    let mut chain = [0u8; 32];
    let mut used = 128u64;
    let mut records = 0u64;
    let mut refusal = None;
    let mut refusal_memory = None;
    loop {
        ensure!(
            used.checked_add(120)
                .is_some_and(|end| end <= file.pin.bytes),
            "legacy committed closing frame absent"
        );
        let mut frame = [0u8; 80];
        file.file.read_exact(&mut frame)?;
        let length = u64::from_le_bytes(frame[..8].try_into()?);
        ensure!(
            length > 0
                && length <= maximum_body
                && frame[40..72] == chain
                && frame[72..] == [0; 8]
                && used
                    .checked_add(120)
                    .and_then(|n| n.checked_add(length))
                    .is_some_and(|n| n <= file.pin.bytes),
            "legacy frame length, predecessor, or reserved bytes differ"
        );
        let _ram = payer.lease_ram(
            length
                .checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .context("legacy log body RAM overflow")?,
        )?;
        let mut body = Vec::new();
        body.try_reserve_exact(usize::try_from(length)?)?;
        body.resize(usize::try_from(length)?, 0);
        file.file.read_exact(&mut body)?;
        ensure!(
            Sha256::digest(&body).as_slice() == &frame[8..40],
            "legacy frame body SHA differs"
        );
        let mut commit = [0u8; 40];
        file.file.read_exact(&mut commit)?;
        let mut next = Sha256::new();
        next.update(chain);
        next.update(length.to_le_bytes());
        next.update(&frame[8..40]);
        let next: [u8; 32] = next.finalize().into();
        ensure!(
            &commit[..8] == b"N2REVCMT" && commit[8..] == next,
            "legacy frame commit/chain differs"
        );
        let value: Value = serde_json::from_slice(&body)?;
        let kind = text(&value, "kind")?;
        ensure!(
            !matches!(
                kind,
                "published-recovery-route"
                    | "resource-placement-summary"
                    | "pre-ap-resource-accounting-v1"
            ),
            "legacy preparation progressed beyond refused partial placement"
        );
        if kind == "resource-placement-refusal" {
            ensure!(
                refusal.is_none()
                    && value["conversion_authorized"] == false
                    && number(&value, "source_payload_writes")? == 0
                    && value["counters"].is_object()
                    && value["counters"]
                        .as_object()
                        .is_some_and(|m| m.values().all(Value::is_u64)),
                "legacy refusal lacks exact non-authority integer counters"
            );
            refusal_memory = Some(
                payer.lease_ram(
                    length
                        .checked_mul(32)
                        .and_then(|n| n.checked_add(65536))
                        .context("legacy retained refusal RAM overflow")?,
                )?,
            );
            refusal = Some(value.clone());
        }
        let closed = kind == "native-event-ledger-closed";
        if closed {
            ensure!(
                number(&value, "records_before_close")? == records
                    && text(&value, "prior_chain_sha256")? == hex::encode(chain),
                "legacy closing mark differs"
            );
        }
        prefix.update(frame);
        prefix.update(&body);
        prefix.update(commit);
        used = used
            .checked_add(120)
            .and_then(|n| n.checked_add(length))
            .context("legacy log offset overflow")?;
        records = records
            .checked_add(1)
            .context("legacy log record count overflow")?;
        chain = next;
        if closed {
            break;
        }
    }
    let used_prefix_sha256 = hex::encode(prefix.finalize());
    ensure!(
        number(summary, "used_bytes")? == used
            && number(summary, "records")? == records
            && text(summary, "used_prefix_sha256")? == used_prefix_sha256
            && text(summary, "chain_sha256")? == hex::encode(chain),
        "legacy complete ledger pins differ"
    );
    let mut tail = file.pin.bytes - used;
    let mut buffer = [0u8; 65536];
    while tail != 0 {
        let count = tail.min(buffer.len() as u64) as usize;
        file.file.read_exact(&mut buffer[..count])?;
        ensure!(
            buffer[..count].iter().all(|b| *b == 0),
            "legacy ledger contains data after closing mark"
        );
        tail -= count as u64;
    }
    file.revalidate_identity()?;
    Ok((
        ClosedLegacyLedger {
            file: file.pin.clone(),
            records,
            used_bytes: used,
            used_prefix_sha256,
            chain_sha256: hex::encode(chain),
            placement_refusal: refusal.context("legacy placement refusal absent")?,
        },
        refusal_memory.context("legacy retained refusal payment absent")?,
    ))
}

impl LegacyResumeOrigin {
    pub(crate) fn open(
        conversion_directory: &Path,
        independent_old_prep_sha: [u8; 32],
        payer: &SourceScratch,
    ) -> Result<Self> {
        ordinary(conversion_directory)?;
        let maximum = payer.budget().record_bytes.min(16 << 20);
        ensure!(maximum > 0, "legacy metadata decoder has no paid limit");
        let memory = payer.lease_ram(
            maximum
                .checked_mul(2)
                .and_then(|n| n.checked_add(1 << 20))
                .context("legacy retained metadata RAM overflow")?,
        )?;
        let run = conversion_directory
            .parent()
            .context("legacy run parent absent")?
            .to_path_buf();
        let mut held = Vec::<HeldFile>::new();
        let mut intent = HeldFile::open(
            &conversion_directory.join("preparation-intent.json"),
            maximum,
            None,
            payer,
        )?;
        ensure!(
            sha(&intent.pin.sha256)? == independent_old_prep_sha,
            "independent old preparation pin differs"
        );
        let routes = super::early_guard::inspect_routes(
            &intent.pin.path,
            independent_old_prep_sha,
            intent.pin.bytes,
        )?;
        ensure!(
            routes.phase == "Cancelled" && routes.delegated.is_none(),
            "old preparation is not native Cancelled/nondelegated"
        );
        let intent_json: Value = intent.json(maximum, payer)?;
        let saved_state_route = text(&intent_json["state_file"], "path")?;
        let state_path = conversion_directory.join("preparation-state.bin");
        ensure!(
            state_path.file_name() == Some(std::ffi::OsStr::new("preparation-state.bin")),
            "legacy native state leaf differs"
        );
        let state = HeldFile::open(
            &state_path,
            n2r_win32::source_cancel::preparation::STATE_BYTES,
            None,
            payer,
        )?;
        ensure!(
            state
                .snapshot
                .final_path
                .eq_ignore_ascii_case(saved_state_route),
            "legacy ordinary state path differs from pinned native state route"
        );
        let pair = GeneralSourceShadowBinding {
            source: routes.source,
            shadow: routes.shadow,
        };
        pair.validate()?;
        routes.journal.validate()?;
        let working_volume = n2r_win32::layout::guid_bytes(&routes.journal.disk.volume_guid)?;
        for data in [&pair.source, &pair.shadow] {
            ensure!(
                data.disk_number != routes.journal.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&routes.journal.disk.identity.disk_guid)?
                    && n2r_win32::layout::guid_bytes(&data.volume_guid)? != working_volume,
                "legacy working filesystem aliases source or shadow"
            );
        }
        let source_root = unique(
            [
                conversion_directory.join("source"),
                conversion_directory.join("source").join("source"),
            ]
            .into_iter()
            .map(|p| p.join("source-resource-assessment.json")),
            "source assessment",
        )?
        .parent()
        .context("assessment parent absent")?
        .to_path_buf();
        let mut assessment_file = HeldFile::open(
            &source_root.join("source-resource-assessment.json"),
            maximum,
            None,
            payer,
        )?;
        let assessment: Assessment = assessment_file.json(maximum, payer)?;
        assessment.budget.validate()?;
        assessment.resource_admission.validate()?;
        ensure!(
            assessment.kind == "actual-resource-source-context-v1"
                && assessment.binding == pair.source
                && pair.source.layout_profile
                    == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && assessment.resource_admission.budget == assessment.budget
                && assessment.policy == VerificationPolicy::ExtentIdentityV1,
            "legacy source assessment route/policy/wire bounds differ"
        );
        let mut parent_file =
            HeldFile::open(&run.join("resource-plan.json"), maximum, None, payer)?;
        let parent: ParentPublicResources = parent_file.json(maximum, payer)?;
        parent.resources.validate()?;
        ensure!(
            crate::refs_security_integration::TrustRepairAllocation::split(parent.resources)?.main
                == assessment.budget,
            "legacy parent envelope does not exactly reproduce the original Windows main wire bounds"
        );
        ensure!(
            parent.evidence_allocation_bytes > 0
                && parent.evidence_allocation_bytes <= parent.evidence_maximum_bytes
                && parent.evidence_ram_bytes > 0
                && parent.reserve_bytes >= parent.provider_maximum_additional_backing_bytes
                && parent.capture_bytes > 0
                && parent.maximum_journal_bytes > 0
                && parent.maximum_combined_bytes >= parent.maximum_journal_bytes,
            "legacy parent public reservations differ"
        );
        let mut witness_file = HeldFile::open(
            &source_root.join("source-native-witness.json"),
            maximum,
            None,
            payer,
        )?;
        let witness: Value = witness_file.json(maximum, payer)?;
        ensure!(
            text(&witness, "kind")? == "actual-protected-resource-source-native-witness",
            "legacy native witness kind differs"
        );
        let native_sha = text(&witness, "native_pages_sha256")?;
        sha(native_sha)?;
        let native_path = unique(
            [
                conversion_directory
                    .join("source")
                    .join("native")
                    .join("native.pages"),
                conversion_directory.join("native").join("native.pages"),
            ],
            "native pages",
        )?;
        // Only the tiny authenticated witness supplies this digest. Adoption
        // later performs the single complete multi-gigabyte native-file hash.
        let native = HeldFile::open(
            &native_path,
            assessment
                .resource_admission
                .native_page_budget()?
                .max_file_bytes,
            Some(native_sha),
            payer,
        )?;
        let source_manifest = HeldFile::open(
            &source_root.join("source-manifest.json"),
            maximum,
            None,
            payer,
        )?;
        let source_frozen = HeldFile::open(
            &source_root.join("source-frozen.json"),
            maximum,
            None,
            payer,
        )?;
        let coverage = HeldFile::open(
            &source_root.join("inspection-read-coverage.json"),
            maximum,
            None,
            payer,
        )?;
        let expected = HeldFile::open(
            &conversion_directory.join("expected.pages"),
            assessment
                .resource_admission
                .expected_page_budget()?
                .max_file_bytes,
            None,
            payer,
        )?;
        let launch_path = unique(
            run.ancestors()
                .take(8)
                .map(|p| p.join("native-terminal.json")),
            "owned native terminal",
        )?;
        let launch_root = launch_path
            .parent()
            .context("terminal parent absent")?
            .to_path_buf();
        let mut terminal_file = HeldFile::open(&launch_path, maximum, None, payer)?;
        let terminal: Terminal = terminal_file.json(maximum, payer)?;
        let mut process_file = HeldFile::open(
            &launch_root.join("native-process.json"),
            maximum,
            None,
            payer,
        )?;
        let process: Process = process_file.json(maximum, payer)?;
        ensure!(
            terminal.native_exit == 1
                && terminal.native_launches == 1
                && terminal.owned_process_handle_observed
                && terminal.pid > 0
                && terminal.birth_ms > 0
                && process.native_launches == 1
                && process.pid == terminal.pid
                && process.birth_ms == terminal.birth_ms
                && process.source_disk == pair.source.disk_number
                && process.source_partition == pair.source.identity.partition_number
                && process.source_partition_bytes_before == pair.source.identity.partition_bytes,
            "legacy terminal does not close the one owned failed source preparation"
        );
        let scratch_routes: Vec<_> = process
            .arguments
            .windows(2)
            .filter(|w| w[0] == "--scratch-directory")
            .collect();
        ensure!(
            scratch_routes.len() == 1 && run.starts_with(Path::new(&scratch_routes[0][1])),
            "legacy process scratch route differs"
        );
        let mut summary_file = HeldFile::open(
            &run.join("native-events-summary.json"),
            maximum,
            None,
            payer,
        )?;
        let summary: Value = summary_file.json(maximum, payer)?;
        let mut log = HeldFile::open(
            &run.join("native-events.log"),
            parent.evidence_maximum_bytes,
            None,
            payer,
        )?;
        let (closed_ledger, ledger_memory) = ledger(&mut log, &summary, maximum, payer)?;
        ensure!(
            number(&summary, "maximum_budget_bytes")? == parent.evidence_maximum_bytes,
            "legacy event ledger escaped original public resource envelope"
        );
        // A cancelled native guard plus complete closed log forbids selecting
        // an old AP route. An actual published envelope must use its recovery
        // protocol instead of this preparation-only origin.
        for directory in [
            conversion_directory.to_path_buf(),
            conversion_directory.join("recovery"),
        ] {
            for leaf in [
                "publication.json",
                "prepared-publication.json",
                "recovery-envelope.json",
                "recovery-locator.json",
            ] {
                ensure!(
                    !exists(&directory.join(leaf))?,
                    "legacy published recovery artifact exists"
                );
            }
        }
        let origin = SourceCacheOriginPins {
            schema_version: 1,
            source: pair.source.clone(),
            policy: assessment.policy,
            resource_admission: assessment.resource_admission,
            source_manifest: source_manifest.pin.clone(),
            source_frozen: source_frozen.pin.clone(),
            inspection_read_coverage: coverage.pin.clone(),
            source_assessment: assessment_file.pin.clone(),
            native_witness: witness_file.pin.clone(),
            native_pages: native.pin.clone(),
            cancelled_preparation_intent: intent.pin.clone(),
            cancelled_preparation_state: Some(state.pin.clone()),
            generation: None,
        };
        let origin_sha256 = origin.canonical_sha256()?;
        let old_work_upper_bytes = pair
            .source
            .identity
            .partition_bytes
            .checked_mul(4)
            .context("legacy old work upper overflow")?;
        ensure!(
            number(
                &closed_ledger.placement_refusal["counters"],
                "move_submissions_limit"
            )? == old_work_upper_bytes / 4096,
            "legacy placement counter limit differs from original partition allowance"
        );
        let uncertain_operation_upper_bytes = pair.source.identity.partition_bytes;
        let conservative_spend = ConservativePartialPlacementSpend {
            old_work_upper_bytes,
            uncertain_operation_upper_bytes,
            total_prior_upper_bytes: old_work_upper_bytes
                .checked_add(uncertain_operation_upper_bytes)
                .context("legacy prior spend overflow")?,
            old_submission_upper: old_work_upper_bytes / 4096,
            actual_prior_bytes_known: false,
        };
        let result_expected = expected.pin.clone();
        let result_terminal = terminal_file.pin.clone();
        let result_process = process_file.pin.clone();
        let result_summary = summary_file.pin.clone();
        let result_parent = parent_file.pin.clone();
        held.extend([
            intent,
            state,
            assessment_file,
            parent_file,
            witness_file,
            native,
            source_manifest,
            source_frozen,
            coverage,
            expected,
            terminal_file,
            process_file,
            summary_file,
            log,
        ]);
        for file in &held {
            ensure!(
                volume(&file.snapshot.final_path)? == working_volume,
                "legacy artifact escaped actual independent journal volume"
            );
            file.revalidate_identity()?;
        }
        let result = Self {
            origin,
            origin_sha256,
            pair,
            journal: routes.journal,
            old_main_resources: assessment.budget,
            parent_resources: parent,
            expected: result_expected,
            expected_semantic_sha256: None,
            terminal: result_terminal,
            process: result_process,
            ledger: closed_ledger,
            ledger_summary: result_summary,
            parent_resource_plan: result_parent,
            conservative_spend,
            arena_root: launch_root.clone(),
            common_run_root: run,
            launch_root,
            held,
            _memory: memory,
            _ledger_memory: ledger_memory,
        };
        result.revalidate()?;
        Ok(result)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        for file in &self.held {
            file.revalidate_identity()?;
        }
        Ok(())
    }
}
