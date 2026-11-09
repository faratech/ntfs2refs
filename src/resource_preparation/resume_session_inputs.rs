//! Reopen durable resume-session FACTS using real paid, deny-writer artifacts.
//! Nothing here cancels/reactivates a guard, freezes a source, adopts a native
//! shadow, or recreates any writer. The caller supplies those fresh issuers.
use super::resume_origin::ParentPublicResources;
use super::{ResourcePreparationRequest, ResumePreparation, early_guard};
use crate::{
    artifact_arena::{ArenaRamLease, ArtifactGroup, ArtifactGroupPermit, ArtifactLease},
    general_source_admission::resource::{SourceCacheFilePin, SourceCacheOriginPins},
    preparation_resume::{
        ArtifactPin, DurableResume, FormatProfiles, HeldArtifact, Limits, Origin, ResumeIntent,
        Stage, parse_name,
    },
    selected_capacity::SelectedCapacityPolicy,
    selected_journal::SelectedMarkerProfile,
    verification_policy::VerificationPolicy,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::{GeneralDiskLayoutProfile, GeneralSourceShadowBinding},
    journal_file::{GeneralJournalStorageBinding, MarkerStorageUse},
    shadow_native::private_tree::recovery::{PartialPlacementSpend, RecoveryLimits},
    tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const SAVED_KIND: &str = "saved-prepublication-resume-request-v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedPreparationRequest {
    pub pair: GeneralSourceShadowBinding,
    pub journal: GeneralJournalStorageBinding,
    /// UNSPLIT public parent envelope; prepare_with_mode splits it once.
    pub resources: ResourceBudget,
    pub verification_policy: VerificationPolicy,
    pub selected_capacity_policy: SelectedCapacityPolicy,
    pub maximum_placement_bytes: u64,
    pub maximum_placement_submissions: u64,
    pub maximum_materialized_bytes: u64,
    pub maximum_source_read_bytes: Option<u64>,
    pub capture_arena_bytes: u64,
    pub locator_arena_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_literal_backing_bytes: u64,
    pub max_combined_backing_and_journal_bytes: u64,
    pub minimum_free_bytes: u64,
    pub marker_profile: Option<SelectedMarkerProfile>,
    pub marker_use: String,
}
impl SavedPreparationRequest {
    fn from_actual(
        parent: &ParentPublicResources,
        request: &ResourcePreparationRequest,
    ) -> Result<Self> {
        request.validate()?;
        ensure!(
            request.marker_use == MarkerStorageUse::QualifiedProduction,
            "resume sessions do not import unqualified lab marker use"
        );
        ensure!(
            crate::refs_security_integration::TrustRepairAllocation::split(parent.resources)?.main
                == request.resources,
            "actual resume request must have exactly the original one-time trust split"
        );
        Ok(Self {
            pair: request.pair.clone(),
            journal: request.journal.clone(),
            resources: parent.resources,
            verification_policy: request.verification_policy,
            selected_capacity_policy: request.selected_capacity_policy,
            maximum_placement_bytes: request.maximum_placement_bytes,
            maximum_placement_submissions: u64::try_from(request.maximum_placement_submissions)?,
            maximum_materialized_bytes: request.maximum_materialized_bytes,
            maximum_source_read_bytes: request.maximum_source_read_bytes,
            capture_arena_bytes: request.capture_arena_bytes,
            locator_arena_bytes: request.locator_arena_bytes,
            max_journal_bytes: request.max_journal_bytes,
            max_literal_backing_bytes: request.max_literal_backing_bytes,
            max_combined_backing_and_journal_bytes: request.max_combined_backing_and_journal_bytes,
            minimum_free_bytes: request.minimum_free_bytes,
            marker_profile: request.marker_profile,
            marker_use: "qualified_production".to_owned(),
        })
    }
    pub(crate) fn into_actual(self) -> Result<ResourcePreparationRequest> {
        ensure!(
            self.marker_use == "qualified_production"
                && self.pair.source.layout_profile == GeneralDiskLayoutProfile::OfflineWindows
                && self.verification_policy == VerificationPolicy::ExtentIdentityV1,
            "unsupported resume-session source or marker profile"
        );
        let value = ResourcePreparationRequest {
            pair: self.pair,
            journal: self.journal,
            resources: self.resources,
            verification_policy: self.verification_policy,
            selected_capacity_policy: self.selected_capacity_policy,
            maximum_placement_bytes: self.maximum_placement_bytes,
            maximum_placement_submissions: usize::try_from(self.maximum_placement_submissions)?,
            maximum_materialized_bytes: self.maximum_materialized_bytes,
            maximum_source_read_bytes: self.maximum_source_read_bytes,
            capture_arena_bytes: self.capture_arena_bytes,
            locator_arena_bytes: self.locator_arena_bytes,
            max_journal_bytes: self.max_journal_bytes,
            max_literal_backing_bytes: self.max_literal_backing_bytes,
            max_combined_backing_and_journal_bytes: self.max_combined_backing_and_journal_bytes,
            minimum_free_bytes: self.minimum_free_bytes,
            marker_profile: self.marker_profile,
            marker_use: MarkerStorageUse::QualifiedProduction,
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedPlacementSpend {
    pub prior_submissions_upper: u64,
    pub prior_move_bytes_upper: u64,
    pub uncertain_tail_submissions: u64,
    pub uncertain_tail_move_bytes: u64,
}
impl SavedPlacementSpend {
    pub(crate) fn into_actual(self) -> Result<PartialPlacementSpend> {
        Ok(PartialPlacementSpend {
            prior_submissions_upper: usize::try_from(self.prior_submissions_upper)?,
            prior_move_bytes_upper: self.prior_move_bytes_upper,
            uncertain_tail_submissions: usize::try_from(self.uncertain_tail_submissions)?,
            uncertain_tail_move_bytes: self.uncertain_tail_move_bytes,
        })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedRecoveryLimits {
    pub cumulative_maximum_move_bytes: u64,
    pub cumulative_maximum_submissions: u64,
}
impl SavedRecoveryLimits {
    pub(crate) fn into_actual(self) -> Result<RecoveryLimits> {
        Ok(RecoveryLimits {
            cumulative_maximum_move_bytes: self.cumulative_maximum_move_bytes,
            cumulative_maximum_submissions: usize::try_from(self.cumulative_maximum_submissions)?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedResumeRequest {
    pub schema_version: u32,
    pub kind: String,
    pub arena_root: PathBuf,
    pub parent_resources: ParentPublicResources,
    pub request: SavedPreparationRequest,
    pub source_origin_sha256: String,
    pub expected: SourceCacheFilePin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_binding: Option<crate::shadow_tree::ExpectedBindingPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_placement: Option<ArtifactPin>,
    /// Original legacy import receipt, when present. NEVER a current-session
    /// process terminal or a requirement that a crashed process wrote one.
    pub legacy_terminal: Option<SourceCacheFilePin>,
    pub prior_spend: SavedPlacementSpend,
    pub placement_limits: SavedRecoveryLimits,
}
impl SavedResumeRequest {
    pub(crate) fn from_actual(
        parent: &ParentPublicResources,
        request: &ResourcePreparationRequest,
        saved: &ResumePreparation,
    ) -> Result<Self> {
        ensure!(
            parent.resources == saved.parent_resources.resources
                && saved.arena.budget() == request.resources
                && saved.source.canonical_sha256()? == saved.source_origin_sha256,
            "actual resume input owners/baseline differ"
        );
        let value = Self {
            schema_version: 1,
            kind: SAVED_KIND.to_owned(),
            arena_root: saved.arena_root.clone(),
            parent_resources: parent.clone(),
            request: SavedPreparationRequest::from_actual(parent, request)?,
            source_origin_sha256: hex::encode(saved.source_origin_sha256),
            expected: saved.expected.clone(),
            expected_binding: saved.expected_binding.clone(),
            completed_placement: saved
                .completed_placement
                .as_ref()
                .map(|proof| proof.pin().clone()),
            legacy_terminal: saved.legacy_terminal.clone(),
            prior_spend: SavedPlacementSpend {
                prior_submissions_upper: u64::try_from(saved.prior_spend.prior_submissions_upper)?,
                prior_move_bytes_upper: saved.prior_spend.prior_move_bytes_upper,
                uncertain_tail_submissions: u64::try_from(
                    saved.prior_spend.uncertain_tail_submissions,
                )?,
                uncertain_tail_move_bytes: saved.prior_spend.uncertain_tail_move_bytes,
            },
            placement_limits: SavedRecoveryLimits {
                cumulative_maximum_move_bytes: saved.placement_limits.cumulative_maximum_move_bytes,
                cumulative_maximum_submissions: u64::try_from(
                    saved.placement_limits.cumulative_maximum_submissions,
                )?,
            },
        };
        value.validate(request.resources)?;
        Ok(value)
    }
    fn validate(&self, main: ResourceBudget) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.kind == SAVED_KIND,
            "resume request fact schema differs"
        );
        ordinary(&self.arena_root, true)?;
        self.parent_resources.resources.validate()?;
        ensure!(
            self.request.resources == self.parent_resources.resources
                && crate::refs_security_integration::TrustRepairAllocation::split(
                    self.request.resources
                )?
                .main
                    == main,
            "resume request parent/Main envelope differs or would be split twice"
        );
        self.request.clone().into_actual()?;
        digest(&self.source_origin_sha256)?;
        file_pin(&self.expected)?;
        if let Some(pin) = &self.expected_binding {
            digest(&pin.sha256)?;
            ensure!(
                pin.bytes > 0
                    && pin.bytes <= 65536
                    && pin.path.is_absolute()
                    && pin.facts.body_file_sha256 == self.expected.sha256
                    && pin.facts.effective_admission.budget == main,
                "saved expected binding pin differs"
            );
            pin.facts.validate(
                pin.facts.effective_admission,
                &self.expected.sha256,
                &pin.facts.body_semantic_sha256,
            )?;
        }
        if let Some(terminal) = &self.legacy_terminal {
            file_pin(terminal)?;
        }
        if let Some(pin) = &self.completed_placement {
            ensure!(
                pin.key == "placement-completed"
                    && pin.bytes > 0
                    && pin
                        .path
                        .file_name()
                        .is_some_and(|name| name == "placement-completed.json"),
                "saved completed placement selector pin differs"
            );
            digest(&pin.sha256)?;
        }
        self.prior_spend.into_actual()?;
        self.placement_limits.into_actual()?;
        let spent_bytes = self
            .prior_spend
            .prior_move_bytes_upper
            .checked_add(self.prior_spend.uncertain_tail_move_bytes)
            .context("saved prior work overflow")?;
        let spent_ops = self
            .prior_spend
            .prior_submissions_upper
            .checked_add(self.prior_spend.uncertain_tail_submissions)
            .context("saved prior submissions overflow")?;
        ensure!(
            spent_bytes
                .checked_add(self.request.maximum_placement_bytes)
                .is_some_and(|n| n <= self.placement_limits.cumulative_maximum_move_bytes)
                && spent_ops
                    .checked_add(self.request.maximum_placement_submissions)
                    .is_some_and(|n| n <= self.placement_limits.cumulative_maximum_submissions),
            "saved remaining allowance exceeds its cumulative limits"
        );
        Ok(())
    }
}

fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical SHA256 required"
    );
    Ok(hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA width differs"))?)
}
fn file_pin(pin: &SourceCacheFilePin) -> Result<()> {
    digest(&pin.sha256)?;
    ensure!(pin.bytes > 0, "empty saved file pin");
    ordinary(&pin.path, false)
}
fn ordinary(path: &Path, directory: bool) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
        "ordinary absolute resume path required"
    );
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() == directory && meta.file_attributes() & 0x400 == 0,
        "resume file/directory type or reparse differs"
    );
    for parent in path
        .parent()
        .into_iter()
        .flat_map(|p| p.ancestors())
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "resume ancestry reparse refused"
        );
    }
    Ok(())
}
fn decode<T: DeserializeOwned>(
    held: &HeldArtifact,
    maximum: u64,
    group: &ArtifactGroupPermit,
) -> Result<T> {
    held.revalidate_identity()?;
    ensure!(
        held.pin().bytes <= maximum,
        "saved fact exceeds decoder bound"
    );
    let _ram = group.arena().reserve_ram(
        held.pin()
            .bytes
            .checked_mul(32)
            .and_then(|n| n.checked_add(65536))
            .context("saved fact RAM overflow")?,
    )?;
    let file = held.try_clone_readonly()?;
    let mut parser = serde_json::Deserializer::from_reader(file.take(held.pin().bytes));
    let value = T::deserialize(&mut parser)?;
    parser.end()?;
    held.revalidate_identity()?;
    Ok(value)
}
fn adopt(
    path: &Path,
    sha: &str,
    maximum: u64,
    key: &str,
    group: &ArtifactGroupPermit,
) -> Result<HeldArtifact> {
    ordinary(path, false)?;
    digest(sha)?;
    let lease = match group.arena().retained_artifact(path) {
        Ok(lease) => {
            ensure!(
                lease.same_group(group) && lease.sha256() == sha && lease.wire_bytes() <= maximum,
                "existing paid resume owner differs"
            );
            lease
        }
        Err(_) => group.adopt_existing(path, sha, maximum)?,
    };
    HeldArtifact::from_accounted_lease(lease, group, key.to_owned())
}
fn adopt_pin(pin: &ArtifactPin, maximum: u64, group: &ArtifactGroupPermit) -> Result<HeldArtifact> {
    ensure!(
        pin.bytes > 0 && pin.bytes <= maximum,
        "resume initial artifact bound differs"
    );
    let held = adopt(&pin.path, &pin.sha256, pin.bytes, &pin.key, group)?;
    held.require_pin(pin)?;
    Ok(held)
}
fn actual_checkpoint_sha(path: &Path, maximum: u64, group: &ArtifactGroupPermit) -> Result<String> {
    ordinary(path, false)?;
    let _ram = group.arena().reserve_ram(
        maximum
            .min(4 << 20)
            .checked_add(1048576)
            .context("checkpoint hash RAM overflow")?,
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    ensure!(
        before.file_bytes > 0 && before.number_of_links == 1,
        "ordinary checkpoint file required"
    );
    let sha = n2r_win32::sha256_native::hash_range(&mut file, 0, before.file_bytes)?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before,
        "checkpoint changed while hashing"
    );
    Ok(hex::encode(sha))
}

/// Routing facts only. Presence/delegation is never cancellation or replay authority.
pub(crate) struct ResumeSessionProbe {
    pub intent: ResumeIntent,
    pub actual_guard_phase: String,
    pub delegated_publication: Option<early_guard::GuardPin>,
    pub publication_file_observed: Option<PathBuf>,
}
impl ResumeSessionProbe {
    pub(crate) fn requires_publication_route(&self) -> bool {
        self.delegated_publication.is_some() || self.publication_file_observed.is_some()
    }
}
fn route(intent: ResumeIntent, directory: &Path, maximum: u64) -> Result<ResumeSessionProbe> {
    let guard = &intent.new_preparation_intent;
    digest(&guard.sha256)?;
    let actual = early_guard::inspect_routes(&guard.path, digest(&guard.sha256)?, maximum)?;
    ensure!(
        actual.source == intent.pair.source
            && actual.shadow == intent.pair.shadow
            && actual.journal == intent.working,
        "actual new guard route differs from pinned resume intent"
    );
    ensure!(
        actual.phase != "Delegated" || actual.delegated.is_some(),
        "delegated guard lacks publication route; preserve state"
    );
    let path = directory
        .parent()
        .context("resume conversion parent absent")?
        .join("recovery-envelope.json");
    let observed = match fs::symlink_metadata(&path) {
        Ok(_) => Some(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    Ok(ResumeSessionProbe {
        intent,
        actual_guard_phase: actual.phase,
        delegated_publication: actual.delegated,
        publication_file_observed: observed,
    })
}
pub(crate) fn peek_resume_intent(
    directory: &Path,
    independent_sha: [u8; 32],
    maximum: u64,
) -> Result<ResumeIntent> {
    ordinary(directory, true)?;
    ensure!(
        maximum > 0 && maximum <= (8 << 20),
        "bounded resume intent probe required"
    );
    let path = directory.join("resume-intent.json");
    ordinary(&path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    ensure!(
        before.file_bytes > 0 && before.number_of_links == 1,
        "ordinary single-link resume intent required"
    );
    ensure!(
        n2r_win32::sha256_native::hash_range(&mut file, 0, before.file_bytes)? == independent_sha,
        "independent resume intent SHA differs"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut parser = serde_json::Deserializer::from_reader((&mut file).take(before.file_bytes));
    let intent = ResumeIntent::deserialize(&mut parser)?;
    parser.end()?;
    drop(parser);
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before,
        "resume routing file changed"
    );
    intent.resources.validate()?;
    intent.pair.validate()?;
    intent.working.validate()?;
    ensure!(
        intent.schema_version == 1
            && intent.kind == ResumeIntent::kind()
            && intent.profiles == FormatProfiles::current()
            && before
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(intent.working.disk.volume_path()?.to_ascii_lowercase() + "\\")),
        "resume intent format or external file route differs"
    );
    Ok(intent)
}
pub(crate) fn probe_resume_session(
    directory: &Path,
    independent_sha: [u8; 32],
    maximum: u64,
) -> Result<ResumeSessionProbe> {
    route(
        peek_resume_intent(directory, independent_sha, maximum)?,
        directory,
        maximum,
    )
}

/// Bootstrap routing facts for creating the real new arena. This does not
/// replace open(): that path must adopt/charge and cross-check the same files.
pub(crate) fn peek_saved_resume_request(
    directory: &Path,
    independent_sha: [u8; 32],
    maximum: u64,
) -> Result<SavedResumeRequest> {
    let intent = peek_resume_intent(directory, independent_sha, maximum)?;
    let mut candidates = intent
        .initial_artifacts
        .iter()
        .filter(|pin| pin.key == "resume-request");
    let pin = candidates
        .next()
        .context("initial resume-request pin absent")?;
    ensure!(
        candidates.next().is_none()
            && pin.path == directory.join("resume-request.json")
            && pin.bytes > 0
            && pin.bytes <= maximum,
        "initial resume-request pin path/count/bound differs"
    );
    ordinary(&pin.path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&pin.path)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?;
    ensure!(
        before.file_bytes == pin.bytes
            && before.allocation_bytes == pin.allocation_bytes
            && before.final_path == pin.final_path
            && before.volume_serial_number == pin.volume_serial_number
            && before.file_id_128 == pin.file_id_128
            && before.file_attributes == pin.file_attributes
            && before.number_of_links == 1
            && pin.number_of_links == 1
            && file.metadata()?.last_write_time() == pin.last_write_time
            && before
                .final_path
                .to_ascii_lowercase()
                .starts_with(&(intent.working.disk.volume_path()?.to_ascii_lowercase() + "\\")),
        "resume-request bootstrap identity or independent working volume differs"
    );
    ensure!(
        n2r_win32::sha256_native::hash_range(&mut file, 0, pin.bytes)? == digest(&pin.sha256)?,
        "resume-request independent pin SHA differs"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut parser = serde_json::Deserializer::from_reader((&mut file).take(pin.bytes));
    let saved = SavedResumeRequest::deserialize(&mut parser)?;
    parser.end()?;
    drop(parser);
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, maximum)?
            == before
            && file.metadata()?.last_write_time() == pin.last_write_time,
        "resume-request bootstrap file changed"
    );
    saved.validate(intent.resources)?;
    ensure!(
        saved.request.pair == intent.pair
            && saved.request.journal == intent.working
            && directory.starts_with(&saved.arena_root),
        "resume-request bootstrap route differs"
    );
    Ok(saved)
}

/// Actual paid, immutable report owner. Its pin is a selector for a fresh SDK
/// placed-tree audit; neither its JSON nor this wrapper grants native authority.
#[derive(Clone)]
pub(crate) struct HeldCompletedPlacement {
    file: std::sync::Arc<HeldArtifact>,
    arena: crate::artifact_arena::ArtifactArena,
}
impl HeldCompletedPlacement {
    pub(crate) fn pin(&self) -> &ArtifactPin {
        self.file.pin()
    }
    pub(crate) fn require_arena(&self, arena: &crate::artifact_arena::ArtifactArena) -> Result<()> {
        ensure!(
            self.arena.same_arena(arena),
            "completed placement selector belongs to another actual arena"
        );
        self.file.revalidate_identity()
    }
}

pub(crate) struct ResumeSessionInputs {
    pub journal: DurableResume,
    pub saved: SavedResumeRequest,
    pub source: SourceCacheOriginPins,
    pub source_origin_sha256: [u8; 32],
    pub new_preparation_intent: ArtifactPin,
    pub actual_guard_phase: String,
    pub workspace_origin: Option<(PathBuf, GeneralJournalStorageBinding)>,
    pub completed_placement: Option<HeldCompletedPlacement>,
    _facts: Vec<HeldArtifact>,
    _metadata_owners: Vec<ArtifactLease>,
    _index_memory: Vec<ArenaRamLease>,
}
impl ResumeSessionInputs {
    pub(crate) fn open(
        directory: &Path,
        independent_sha: [u8; 32],
        group: &ArtifactGroupPermit,
    ) -> Result<Self> {
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy,
            "resume loader requires real RecoveryCopy payment"
        );
        let limits = Limits::from_budget(group.arena().budget())?;
        // Check actual delegation BEFORE interpreting a saved early stage or
        // attempting new checkpoint adoption under a possibly sealed epoch.
        let probe = probe_resume_session(directory, independent_sha, limits.max_intent_bytes)?;
        ensure!(
            !probe.requires_publication_route(),
            "resume publication observed/delegated; use authenticated postpublication recovery, never fresh isolation"
        );
        let intent = adopt(
            &directory.join("resume-intent.json"),
            &hex::encode(independent_sha),
            limits.max_intent_bytes,
            "resume-intent",
            group,
        )?;
        let mut checkpoints = Vec::new();
        let mut payments = Vec::new();
        let mut metadata_owners = vec![
            group
                .arena()
                .retained_artifact(intent.pin().path.as_path())?,
        ];
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Unicode resume leaf required")?;
            if !name.starts_with("checkpoint-") {
                continue;
            }
            ensure!(
                (checkpoints.len() as u64)
                    < limits
                        .max_checkpoints
                        .checked_mul(2)
                        .context("checkpoint count overflow")?,
                "checkpoint discovery exceeds actual index bound"
            );
            let (sequence, copy, _filename_sha) = parse_name(&path, directory)?;
            payments.push(group.arena().reserve_ram(8192)?);
            // Keep a torn replica as authenticated ACTUAL bytes. DurableResume
            // compares its filename/body SHA and retains uncertainty when only
            // the other replica is valid; this loader does not waive it.
            let sha = actual_checkpoint_sha(&path, limits.max_checkpoint_bytes, group)?;
            let held = adopt(
                &path,
                &sha,
                limits.max_checkpoint_bytes,
                &format!("checkpoint-{sequence:016x}-{copy}"),
                group,
            )?;
            metadata_owners.push(group.arena().retained_artifact(&path)?);
            checkpoints.push(held);
        }
        let journal = DurableResume::reopen(
            directory,
            group.clone(),
            intent,
            &hex::encode(independent_sha),
            checkpoints,
            limits,
        )?;
        let actual = route(journal.intent().clone(), directory, limits.max_intent_bytes)?;
        ensure!(
            !actual.requires_publication_route() && journal.publication_hint().is_none(),
            "resume epoch published/delegated; route existing publication recovery"
        );
        ensure!(
            journal.stage().is_none_or(|stage| stage <= Stage::Placing),
            "resume stage later than Placing is explicitly unsupported by the first unwritten adopter; preserve artifacts, no restart"
        );
        let initial = &journal.intent().initial_artifacts;
        let find = |key: &str| -> Result<ArtifactPin> {
            let rows: Vec<_> = initial.iter().filter(|p| p.key == key).collect();
            ensure!(
                rows.len() == 1,
                "exact initial resume artifact key absent/ambiguous: {key}"
            );
            Ok(rows[0].clone())
        };
        let request_pin = find("resume-request")?;
        let cache_pin = find("source-cache-origin")?;
        let expected_pin = find("expected")?;
        ensure!(
            request_pin.path == directory.join("resume-request.json")
                && cache_pin.path == directory.join("source-cache-origin.json"),
            "resume fact filenames escape exact session"
        );
        let request_file = adopt_pin(&request_pin, limits.max_intent_bytes, group)?;
        let cache_file = adopt_pin(&cache_pin, limits.max_intent_bytes, group)?;
        let saved: SavedResumeRequest = decode(&request_file, limits.max_intent_bytes, group)?;
        let source: SourceCacheOriginPins = decode(&cache_file, limits.max_intent_bytes, group)?;
        saved.validate(journal.intent().resources)?;
        let carried: Vec<_> = initial
            .iter()
            .filter(|pin| pin.key == "placement-completed")
            .collect();
        match (&saved.completed_placement, carried.as_slice()) {
            (None, []) => {}
            (Some(pin), [actual]) => ensure!(
                pin == *actual,
                "saved completed placement initial pin differs"
            ),
            _ => anyhow::bail!("saved completed placement initial pin is absent or ambiguous"),
        }
        let current =
            if journal.stage() == Some(Stage::Placing) && journal.pending_batch().is_none() {
                journal.completed_placement_evidence()
            } else {
                None
            };
        let completed_placement = current
            .or(saved.completed_placement.as_ref())
            .map(|pin| -> Result<HeldCompletedPlacement> {
                ensure!(
                    pin.key == "placement-completed",
                    "completed placement report key differs"
                );
                let held = adopt_pin(pin, limits.max_checkpoint_bytes, group)
                    .context("authenticate and hold completed placement selector")?;
                Ok(HeldCompletedPlacement {
                    file: std::sync::Arc::new(held),
                    arena: group.arena().clone(),
                })
            })
            .transpose()?;
        let binding_pins: Vec<_> = initial
            .iter()
            .filter(|p| p.key == "expected-binding")
            .collect();
        match (&saved.expected_binding, binding_pins.as_slice()) {
            (None, []) => {}
            (Some(binding), [pin]) => {
                ensure!(
                    pin.path == binding.path
                        && pin.sha256 == binding.sha256
                        && pin.bytes == binding.bytes,
                    "resume expected binding initial artifact differs"
                );
                let held = adopt_pin(pin, 65536, group)?;
                let facts: crate::shadow_tree::ExpectedBindingFacts = decode(&held, 65536, group)?;
                ensure!(
                    facts == binding.facts,
                    "resume expected binding actual facts differ"
                );
                let bytes = serde_json::to_vec(&facts)?;
                ensure!(
                    bytes.len() as u64 == binding.bytes
                        && hex::encode(Sha256::digest(&bytes)) == binding.sha256,
                    "resume expected binding canonical pin differs"
                );
                metadata_owners.push(group.arena().retained_artifact(&binding.path)?);
            }
            _ => anyhow::bail!("resume expected binding pin is absent or ambiguous"),
        }
        let origin_sha = digest(&saved.source_origin_sha256)?;
        ensure!(
            source.canonical_sha256()? == origin_sha
                && cache_pin.sha256 == saved.source_origin_sha256
                && source.source == journal.intent().pair.source
                && source.resource_admission.budget == journal.intent().resources
                && source.policy == saved.request.verification_policy
                && saved.request.pair == journal.intent().pair
                && saved.request.journal == journal.intent().working
                && saved.expected.path == expected_pin.path
                && saved.expected.sha256 == expected_pin.sha256
                && saved.expected.bytes == expected_pin.bytes
                && directory.starts_with(&saved.arena_root)
                && source.cancelled_preparation_intent.path
                    != journal.intent().new_preparation_intent.path,
            "saved resume source origin/request/expected or new guard differs"
        );
        match &journal.intent().origin {
            Origin::LegacyCancelledPreparation {
                preparation_intent,
                terminal,
                source_cache_manifest,
            } => {
                let old = &source.cancelled_preparation_intent;
                ensure!(
                    preparation_intent.path == old.path
                        && preparation_intent.sha256 == old.sha256
                        && source_cache_manifest == &cache_pin,
                    "legacy origin baseline differs"
                );
                let receipt = saved
                    .legacy_terminal
                    .as_ref()
                    .context("legacy import needs its ORIGINAL closed terminal pin")?;
                ensure!(
                    receipt.path == terminal.path
                        && receipt.sha256 == terminal.sha256
                        && receipt.bytes == terminal.bytes,
                    "legacy terminal fact differs"
                );
            }
            Origin::PriorEpoch {
                intent,
                source_cache_manifest,
            } => {
                ensure!(
                    source_cache_manifest == &cache_pin
                        && intent.path != journal.intent_pin().path
                        && intent.sha256 != journal.intent_pin().sha256,
                    "prior epoch link differs"
                );
            }
            Origin::WorkspaceMigration {
                intent,
                source_cache_manifest,
                prior_arena_root,
                prior_working,
            } => {
                prior_working.validate()?;
                ordinary(prior_arena_root, true)?;
                ensure!(
                    source_cache_manifest == &cache_pin
                        && intent.path != journal.intent_pin().path
                        && intent.sha256 != journal.intent_pin().sha256,
                    "migrated workspace origin link differs"
                );
                let prior = peek_resume_intent(
                    intent
                        .path
                        .parent()
                        .context("prior migration intent parent absent")?,
                    digest(&intent.sha256)?,
                    limits.max_intent_bytes,
                )?;
                ensure!(
                    prior.pair == journal.intent().pair
                        && source.source_manifest.path.starts_with(prior_arena_root),
                    "migrated origin source/shadow/cache root differs"
                );
            }
        }
        let workspace_origin = match &journal.intent().origin {
            Origin::WorkspaceMigration {
                prior_arena_root,
                prior_working,
                ..
            } => Some((prior_arena_root.clone(), prior_working.clone())),
            _ => None,
        };
        let new_guard = journal.intent().new_preparation_intent.clone();
        Ok(Self {
            journal,
            saved,
            source,
            source_origin_sha256: origin_sha,
            new_preparation_intent: new_guard,
            actual_guard_phase: actual.actual_guard_phase,
            workspace_origin,
            completed_placement,
            _facts: vec![request_file, cache_file],
            _metadata_owners: metadata_owners,
            _index_memory: payments,
        })
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        if let Some(proof) = &self.completed_placement {
            proof.require_arena(&proof.arena)?;
        }
        for file in &self._facts {
            file.revalidate_identity()?;
        }
        for lease in &self._metadata_owners {
            lease.revalidate()?;
        }
        Ok(())
    }
}
