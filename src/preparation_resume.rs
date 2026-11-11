//! Durable prepublication facts. These records never recreate a source freeze,
//! native observation, private tree, journal writer, or write admission.
use crate::artifact_arena::{
    ArenaRamLease, ArtifactArena, ArtifactGroup, ArtifactGroupPermit, ArtifactLease,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    general_layout::GeneralSourceShadowBinding, journal_file::GeneralJournalStorageBinding,
    reference_file::ReferenceFileSnapshot, tree_resources::ResourceBudget,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const INTENT_KIND: &str = "prepublication-preparation-resume-intent-v1";
const RECORD_KIND: &str = "prepublication-preparation-resume-checkpoint-v1";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    SourceCaptured,
    SourceVerified,
    ShadowAllocated,
    Placing,
    Payloads,
    Metadata,
    Captured,
    JournalPublished,
}
impl Stage {
    fn ordinal(self) -> u8 {
        match self {
            Self::SourceCaptured => 0,
            Self::SourceVerified => 1,
            Self::ShadowAllocated => 2,
            Self::Placing => 3,
            Self::Payloads => 4,
            Self::Metadata => 5,
            Self::Captured => 6,
            Self::JournalPublished => 7,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactPin {
    pub key: String,
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub allocation_bytes: u64,
    pub final_path: String,
    pub volume_serial_number: u64,
    pub file_id_128: [u8; 16],
    pub file_attributes: u32,
    pub number_of_links: u32,
    pub last_write_time: u64,
}
impl ArtifactPin {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.key.is_empty()
                && self.key.len() <= 128
                && self
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
            "resume artifact key differs"
        );
        ordinary_path(&self.path)?;
        canonical_sha(&self.sha256)?;
        ensure!(
            self.bytes > 0
                && self.bytes <= i64::MAX as u64
                && self.volume_serial_number != 0
                && self.file_id_128 != [0; 16]
                && self.number_of_links == 1,
            "resume artifact identity/length differs"
        );
        Ok(())
    }
    fn matches(&self, s: &ReferenceFileSnapshot) -> bool {
        self.bytes == s.file_bytes
            && self.allocation_bytes == s.allocation_bytes
            && self.final_path == s.final_path
            && self.volume_serial_number == s.volume_serial_number
            && self.file_id_128 == s.file_id_128
            && self.file_attributes == s.file_attributes
            && self.number_of_links == s.number_of_links
    }
}

/// Consumes real arena payment, not a saved allocation counter. Full SHA was
/// already verified when that deny-writer arena lease was issued. Its file and
/// no-reparse parent owners remain alive; reopening the same file needs no
/// second multi-gigabyte hash pass. No writable handle is exposed.
pub(crate) struct HeldArtifact {
    file: File,
    pin: ArtifactPin,
    lease: ArtifactLease,
    arena: ArtifactArena,
    _memory: ArenaRamLease,
}
impl HeldArtifact {
    pub(crate) fn from_accounted_lease(
        lease: ArtifactLease,
        group: &ArtifactGroupPermit,
        key: String,
    ) -> Result<Self> {
        ensure!(
            lease.same_group(group),
            "artifact lacks actual same-arena/group payment"
        );
        let arena = group.arena().clone();
        let mut memory = arena.reserve_ram(
            (lease.path().as_os_str().as_encoded_bytes().len() as u64)
                .checked_mul(12)
                .and_then(|n| n.checked_add(524288))
                .context("resume held-file RAM overflow")?,
        )?;
        ordinary_path(lease.path())?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(lease.path())?;
        n2r_win32::file_storage::require_readonly_access(&file)?;
        let s = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &file,
            lease.wire_bytes(),
        )?;
        ensure!(
            s == *lease.snapshot() && s.number_of_links == 1,
            "reused file differs from its verified arena owner"
        );
        let pin = ArtifactPin {
            key,
            path: lease.path().to_path_buf(),
            sha256: lease.sha256().to_owned(),
            bytes: s.file_bytes,
            allocation_bytes: s.allocation_bytes,
            final_path: s.final_path,
            volume_serial_number: s.volume_serial_number,
            file_id_128: s.file_id_128,
            file_attributes: s.file_attributes,
            number_of_links: s.number_of_links,
            last_write_time: file.metadata()?.last_write_time(),
        };
        pin.validate()?;
        let retained = (std::mem::size_of::<Self>() as u64)
            .checked_add((pin.path.as_os_str().as_encoded_bytes().len() as u64) * 4)
            .and_then(|n| {
                n.checked_add(
                    pin.key.capacity() as u64
                        + pin.sha256.capacity() as u64
                        + pin.final_path.capacity() as u64,
                )
            })
            .and_then(|n| n.checked_add(4096))
            .context("held artifact retained RAM overflow")?;
        memory.shrink_to(retained)?;
        let held = Self {
            file,
            pin,
            lease,
            arena,
            _memory: memory,
        };
        held.revalidate_identity()?;
        Ok(held)
    }
    pub(crate) fn pin(&self) -> &ArtifactPin {
        &self.pin
    }
    pub(crate) fn require_pin(&self, pin: &ArtifactPin) -> Result<()> {
        pin.validate()?;
        ensure!(
            &self.pin == pin,
            "held artifact differs from exact checkpoint expectation"
        );
        self.revalidate_identity()
    }
    pub(crate) fn try_clone_readonly(&self) -> Result<File> {
        self.revalidate_identity()?;
        Ok(n2r_win32::file_storage::duplicate_readonly(&self.file)?)
    }
    pub(crate) fn revalidate_identity(&self) -> Result<()> {
        let _ram = self.arena.reserve_ram(262144)?;
        let s = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &self.file,
            self.pin.bytes,
        )?;
        ensure!(
            self.pin.matches(&s)
                && self.file.metadata()?.last_write_time() == self.pin.last_write_time
                && self.lease.sha256() == self.pin.sha256
                && self.lease.wire_bytes() == self.pin.bytes,
            "held resume file identity/time/payment changed"
        );
        Ok(())
    }
    fn decode<T: DeserializeOwned>(&mut self, max: u64) -> Result<T> {
        self.revalidate_identity()?;
        ensure!(self.pin.bytes <= max, "resume decoder bound exceeded");
        let _ram = self.arena.reserve_ram(
            self.pin
                .bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .context("resume decoder RAM overflow")?,
        )?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut reader = (&mut self.file).take(self.pin.bytes);
        let mut parser = serde_json::Deserializer::from_reader(&mut reader);
        let value = T::deserialize(&mut parser)?;
        parser.end()?;
        self.revalidate_identity()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormatProfiles {
    pub source_cache_schema: u32,
    pub raw_source_schema: u32,
    pub native_purpose: [u8; 8],
    pub expected_purpose: [u8; 8],
    pub expected_schema: u32,
    pub refs_major: u16,
    pub refs_minor: u16,
    pub cluster_bytes: u32,
    pub placement_archive_schema: u32,
}
impl FormatProfiles {
    pub(crate) fn current() -> Self {
        Self {
            source_cache_schema: 2,
            raw_source_schema: 1,
            native_purpose: *b"N2RNAT01",
            expected_purpose: *b"N2REXP01",
            expected_schema: 3,
            refs_major: 3,
            refs_minor: 14,
            cluster_bytes: 4096,
            placement_archive_schema: 3,
        }
    }
    pub(crate) fn supported(&self) -> bool {
        let mut compatible = self.clone();
        if !matches!(compatible.source_cache_schema, 1 | 2) {
            return false;
        }
        compatible.source_cache_schema = 2;
        compatible == Self::current()
    }
}
/// An origin is evidence only. No method here opens or reactivates its guard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Origin {
    FreshPreparation {
        source_cache_manifest: ArtifactPin,
    },
    LegacyCancelledPreparation {
        preparation_intent: ArtifactPin,
        terminal: ArtifactPin,
        source_cache_manifest: ArtifactPin,
    },
    PriorEpoch {
        intent: ArtifactPin,
        source_cache_manifest: ArtifactPin,
    },
    WorkspaceMigration {
        intent: ArtifactPin,
        source_cache_manifest: ArtifactPin,
        prior_arena_root: PathBuf,
        prior_working: n2r_win32::journal_file::GeneralJournalStorageBinding,
    },
}
impl Origin {
    fn pins(&self) -> Vec<&ArtifactPin> {
        match self {
            Self::FreshPreparation {
                source_cache_manifest,
            } => vec![source_cache_manifest],
            Self::LegacyCancelledPreparation {
                preparation_intent,
                terminal,
                source_cache_manifest,
            } => vec![preparation_intent, terminal, source_cache_manifest],
            Self::PriorEpoch {
                intent,
                source_cache_manifest,
            } => vec![intent, source_cache_manifest],
            Self::WorkspaceMigration {
                intent,
                source_cache_manifest,
                ..
            } => vec![intent, source_cache_manifest],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeIntent {
    pub schema_version: u32,
    pub kind: String,
    pub epoch: String,
    pub created_unix_ms: u64,
    pub pair: GeneralSourceShadowBinding,
    pub working: GeneralJournalStorageBinding,
    pub resources: ResourceBudget,
    pub profiles: FormatProfiles,
    pub origin: Origin,
    pub new_preparation_intent: ArtifactPin,
    pub initial_artifacts: Vec<ArtifactPin>,
}
impl ResumeIntent {
    pub(crate) fn kind() -> &'static str {
        INTENT_KIND
    }
    fn validate(&self, arena: &ArtifactArena, limits: Limits) -> Result<()> {
        self.validate_with_working(arena, limits, volume(arena.volume_guid_path()?)?)
    }
    fn validate_with_working(
        &self,
        arena: &ArtifactArena,
        limits: Limits,
        actual_working: [u8; 16],
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.kind == INTENT_KIND
                && self.epoch.len() == 32
                && self
                    .epoch
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && self.created_unix_ms > 0
                && self.resources == arena.budget()
                && self.profiles.supported(),
            "resume epoch/budget/format differs"
        );
        self.pair.validate()?;
        self.working.validate()?;
        if let Origin::WorkspaceMigration {
            prior_arena_root,
            prior_working,
            ..
        } = &self.origin
        {
            prior_working.validate()?;
            ordinary_path(prior_arena_root)?;
            for data in [&self.pair.source, &self.pair.shadow] {
                ensure!(
                    prior_working.disk.disk_number != data.disk_number
                        && n2r_win32::layout::guid_bytes(&prior_working.disk.identity.disk_guid)?
                            != n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?,
                    "historical workspace aliases source or shadow storage"
                );
            }
        }
        let working = n2r_win32::layout::guid_bytes(&self.working.disk.volume_guid)?;
        ensure!(
            working == actual_working,
            "resume arena differs from working filesystem"
        );
        for data in [&self.pair.source, &self.pair.shadow] {
            ensure!(
                data.disk_number != self.working.disk.disk_number
                    && n2r_win32::layout::guid_bytes(&data.volume_guid)? != working
                    && n2r_win32::layout::guid_bytes(&data.identity.disk_guid)?
                        != n2r_win32::layout::guid_bytes(&self.working.disk.identity.disk_guid)?,
                "working storage aliases data disk"
            );
        }
        self.new_preparation_intent.validate()?;
        for old in self.origin.pins() {
            old.validate()?;
            ensure!(
                old.sha256 != self.new_preparation_intent.sha256
                    && old.path != self.new_preparation_intent.path,
                "old/cancelled guard cannot become new epoch guard"
            );
        }
        validate_pins(&self.initial_artifacts, limits.max_artifacts)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_intent_bytes: u64,
    pub max_checkpoint_bytes: u64,
    pub max_checkpoints: u64,
    pub max_artifacts: usize,
}
impl Limits {
    pub(crate) fn from_budget(b: ResourceBudget) -> Result<Self> {
        b.validate()?;
        let max = b.max_row_bytes.min(8 << 20);
        let limits = Self {
            max_intent_bytes: max,
            max_checkpoint_bytes: max,
            max_checkpoints: b.retained_index_bytes / 4096,
            max_artifacts: usize::try_from(b.retained_index_bytes / 512)?,
        };
        limits.validate(b)?;
        Ok(limits)
    }
    fn validate(self, b: ResourceBudget) -> Result<()> {
        ensure!(
            self.max_intent_bytes > 0
                && self.max_intent_bytes <= b.max_row_bytes
                && self.max_checkpoint_bytes > 0
                && self.max_checkpoint_bytes <= b.max_row_bytes
                && self.max_checkpoints > 0
                && self.max_checkpoints <= b.retained_index_bytes / 4096
                && self.max_artifacts > 0
                && self.max_artifacts as u64 <= b.retained_index_bytes / 512,
            "resume limits exceed actual contract"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchIntent {
    pub id: u64,
    pub operation: String,
    pub first_ordinal: u64,
    pub end_ordinal: u64,
    pub operation_catalog: ArtifactPin,
    pub before_state: Vec<ArtifactPin>,
}
impl BatchIntent {
    fn validate(&self, l: Limits) -> Result<()> {
        ensure!(
            !self.operation.is_empty()
                && self.operation.len() <= 64
                && self
                    .operation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && self.first_ordinal < self.end_ordinal,
            "batch operation/ordinal range differs"
        );
        self.operation_catalog.validate()?;
        validate_pins(&self.before_state, l.max_artifacts)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BatchDisposition {
    ObservedApplied,
    ObservedUnchanged,
    Refused,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchOutcome {
    pub id: u64,
    pub disposition: BatchDisposition,
    pub evidence: Vec<ArtifactPin>,
}
impl BatchOutcome {
    fn validate(&self, l: Limits) -> Result<()> {
        ensure!(
            !self.evidence.is_empty(),
            "batch outcome needs closed native evidence pins"
        );
        validate_pins(&self.evidence, l.max_artifacts)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
enum Change {
    Stage {
        artifacts: Vec<ArtifactPin>,
    },
    BatchIntent {
        batch: BatchIntent,
    },
    BatchOutcome {
        outcome: BatchOutcome,
    },
    Reconciled {
        uncertain_sequences: Vec<u64>,
        pending_outcome: Option<BatchOutcome>,
        evidence: Vec<ArtifactPin>,
    },
    JournalPublished {
        publication: ArtifactPin,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema_version: u32,
    kind: String,
    epoch: String,
    intent_sha256: String,
    sequence: u64,
    previous_sha256: String,
    stage: Stage,
    delta: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body_sha256: String,
    body: Body,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BudgetDelta {
    pub existing_wire_bytes: u64,
    pub existing_allocated_bytes: u64,
    pub local_allocation_credit_bytes: u64,
    pub incremental_reserved_bytes: u64,
    pub total_metadata_allocation_and_increment: u64,
    pub logical_metadata_ceiling: u64,
}
impl BudgetDelta {
    pub(crate) fn observe(arena: &ArtifactArena, incremental: u64) -> Result<Self> {
        let usage = arena.usage()?;
        let total = usage
            .actual_allocated_bytes
            .checked_add(incremental)
            .context("resume allocation overflow")?;
        ensure!(
            total <= arena.budget().scratch_bytes,
            "existing plus incremental metadata exceeds original envelope"
        );
        Ok(Self {
            existing_wire_bytes: usage.actual_wire_bytes,
            existing_allocated_bytes: usage.actual_allocated_bytes,
            local_allocation_credit_bytes: usage.local_allocation_credit_bytes,
            incremental_reserved_bytes: incremental,
            total_metadata_allocation_and_increment: total,
            logical_metadata_ceiling: arena.budget().scratch_bytes,
        })
    }
}
/// A durability barrier only, never storage/write authority; no Clone or Deserialize.
pub(crate) struct DurableBatchIntent {
    epoch: String,
    intent_sha256: String,
    sequence: u64,
    head: String,
    id: u64,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct UncertainCheckpoint {
    pub sequence: u64,
    pub copies_present: u8,
    pub body_sha256: String,
}
struct RecordOwners {
    _copies: Vec<HeldArtifact>,
    _memory: Vec<ArenaRamLease>,
}
struct CompletedPlacementFact {
    pin: ArtifactPin,
    _memory: ArenaRamLease,
}
pub(crate) struct DurableResume {
    group: ArtifactGroupPermit,
    directory: PathBuf,
    intent: ResumeIntent,
    intent_file: HeldArtifact,
    limits: Limits,
    sequence: u64,
    head: String,
    stage: Option<Stage>,
    pending: Option<BatchIntent>,
    completed_placement: Option<std::sync::Arc<CompletedPlacementFact>>,
    completed_payloads: Option<std::sync::Arc<CompletedPlacementFact>>,
    publication: Option<ArtifactPin>,
    uncertain: Vec<UncertainCheckpoint>,
    records: Vec<RecordOwners>,
    poisoned: bool,
    read_only_origin: bool,
    _memory: ArenaRamLease,
}
impl DurableResume {
    pub(crate) fn create(
        directory: &Path,
        group: ArtifactGroupPermit,
        intent: ResumeIntent,
        limits: Limits,
    ) -> Result<Self> {
        validate_group(&group)?;
        limits.validate(group.arena().budget())?;
        hold_directory(directory, group.arena())?;
        let encoded_bytes = canonical_metrics(&intent, limits.max_intent_bytes)?.1;
        let memory = group.arena().reserve_ram(
            encoded_bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .context("intent RAM overflow")?,
        )?;
        intent.validate(group.arena(), limits)?;
        let intent_file = write_artifact(
            &group,
            &directory.join("resume-intent.json"),
            "resume-intent",
            &intent,
            limits.max_intent_bytes,
        )?;
        Ok(Self {
            group,
            directory: directory.to_path_buf(),
            intent,
            intent_file,
            limits,
            sequence: 0,
            head: ZERO_HASH.to_owned(),
            stage: None,
            pending: None,
            completed_placement: None,
            completed_payloads: None,
            publication: None,
            uncertain: Vec::new(),
            records: Vec::new(),
            poisoned: false,
            read_only_origin: false,
            _memory: memory,
        })
    }
    /// Every discovered file must already be adopted/charged by the real arena.
    /// Hash-linked facts still need fresh source and native shadow issuers.
    pub(crate) fn reopen(
        directory: &Path,
        group: ArtifactGroupPermit,
        mut intent_file: HeldArtifact,
        independent_sha: &str,
        checkpoint_files: Vec<HeldArtifact>,
        limits: Limits,
    ) -> Result<Self> {
        validate_group(&group)?;
        limits.validate(group.arena().budget())?;
        canonical_sha(independent_sha)?;
        ensure!(
            intent_file.pin.sha256 == independent_sha
                && intent_file.arena.same_arena(group.arena())
                && intent_file.pin.path == directory.join("resume-intent.json"),
            "intent pin/arena/path differs"
        );
        let origin_directory = hold_readonly_directory(directory, group.arena())?;
        let origin_volume = volume(&n2r_win32::file_storage::final_path_guid(
            &origin_directory,
        )?)?;
        let read_only_origin = origin_volume != volume(group.arena().volume_guid_path()?)?;
        let memory = group.arena().reserve_ram(
            intent_file
                .pin
                .bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(65536))
                .context("intent RAM overflow")?,
        )?;
        let intent: ResumeIntent = intent_file.decode(limits.max_intent_bytes)?;
        intent.validate_with_working(group.arena(), limits, origin_volume)?;
        ensure!(
            checkpoint_files.len() as u64
                <= limits
                    .max_checkpoints
                    .checked_mul(2)
                    .context("checkpoint count overflow")?,
            "checkpoint index bound exceeded"
        );
        let mut groups: BTreeMap<
            u64,
            Vec<(u8, HeldArtifact, Option<(String, Body)>, ArenaRamLease)>,
        > = BTreeMap::new();
        for mut file in checkpoint_files {
            ensure!(
                file.arena.same_arena(group.arena()),
                "checkpoint payment belongs to another arena"
            );
            let (sequence, copy, file_hash) = parse_name(&file.pin.path, directory)?;
            let candidate_memory = group.arena().reserve_ram(
                file.pin
                    .bytes
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(4096))
                    .context("checkpoint candidate RAM overflow")?,
            )?;
            let body = file
                .decode::<Envelope>(limits.max_checkpoint_bytes)
                .ok()
                .and_then(|e| {
                    (file.pin.sha256 == file_hash
                        && canonical_hash(&e.body, limits.max_checkpoint_bytes)
                            .ok()
                            .as_ref()
                            == Some(&e.body_sha256))
                    .then_some((e.body_sha256, e.body))
                });
            groups
                .entry(sequence)
                .or_default()
                .push((copy, file, body, candidate_memory));
        }
        let mut value = Self {
            group,
            directory: directory.to_path_buf(),
            intent,
            intent_file,
            limits,
            sequence: 0,
            head: ZERO_HASH.to_owned(),
            stage: None,
            pending: None,
            completed_placement: None,
            completed_payloads: None,
            publication: None,
            uncertain: Vec::new(),
            records: Vec::new(),
            poisoned: false,
            read_only_origin,
            _memory: memory,
        };
        let mut replica_uncertain = Vec::new();
        for (sequence, rows) in groups {
            ensure!(
                sequence == value.sequence + 1 && rows.len() <= 2,
                "checkpoint chain gap/extra copies"
            );
            let mut copies = BTreeSet::new();
            let mut selected: Option<(String, Body)> = None;
            let mut owners = Vec::new();
            let mut payments = Vec::new();
            let mut valid = 0u8;
            for (copy, file, body, memory) in rows {
                ensure!(copies.insert(copy), "duplicate checkpoint copy");
                if let Some((hash, body)) = body {
                    if let Some((prior, _)) = &selected {
                        ensure!(prior == &hash, "checkpoint sequence forks");
                    } else {
                        selected = Some((hash, body));
                    }
                    valid += 1;
                }
                owners.push(file);
                payments.push(memory);
            }
            let (hash, body) = selected.context(
                "checkpoint has no surviving valid body; preserve for native reconciliation",
            )?;
            value.validate_body(&body)?;
            value.apply(&body, true)?;
            value.sequence = sequence;
            value.head = hash.clone();
            if valid != 2 {
                replica_uncertain.push(UncertainCheckpoint {
                    sequence,
                    copies_present: valid,
                    body_sha256: hash,
                });
            }
            value.records.push(RecordOwners {
                _copies: owners,
                _memory: payments,
            });
        }
        // Missing physical replicas are today's uncertainty, independently of
        // old reconciliation records. A NEW native reconciliation is required.
        value.uncertain = replica_uncertain;
        Ok(value)
    }
    pub(crate) fn intent(&self) -> &ResumeIntent {
        &self.intent
    }
    pub(crate) fn intent_pin(&self) -> &ArtifactPin {
        self.intent_file.pin()
    }
    pub(crate) fn stage(&self) -> Option<Stage> {
        self.stage
    }
    pub(crate) fn pending_batch(&self) -> Option<&BatchIntent> {
        self.pending.as_ref()
    }
    /// Authenticated checkpoint data only; the SDK must freshly adopt/audit
    /// the actual placed tree before this can affect any runtime owner.
    pub(crate) fn completed_placement_evidence(&self) -> Option<&ArtifactPin> {
        self.completed_placement.as_ref().map(|fact| &fact.pin)
    }
    pub(crate) fn completed_payloads_evidence(&self) -> Option<&ArtifactPin> {
        self.completed_payloads.as_ref().map(|fact| &fact.pin)
    }
    fn observe_completed_payloads(
        &mut self,
        stage: Stage,
        artifacts: &[ArtifactPin],
    ) -> Result<()> {
        if stage != Stage::Payloads {
            return Ok(());
        }
        let mut pins = artifacts.iter().filter(|pin| pin.key == "payloads-ready");
        let Some(pin) = pins.next() else {
            return Ok(());
        };
        ensure!(
            pins.next().is_none() && pin.path == self.directory.join("payloads-ready.json"),
            "completed payload report is ambiguous or outside its epoch"
        );
        let retained = (std::mem::size_of::<CompletedPlacementFact>() as u64)
            .checked_add(
                (pin.path.as_os_str().as_encoded_bytes().len() as u64)
                    .checked_mul(4)
                    .context("payload fact path RAM overflow")?,
            )
            .and_then(|n| n.checked_add((pin.final_path.len() as u64) * 4))
            .and_then(|n| n.checked_add(pin.key.len() as u64 + pin.sha256.len() as u64 + 4096))
            .context("payload fact RAM overflow")?;
        let memory = self.group.arena().reserve_ram(retained)?;
        self.completed_payloads = Some(std::sync::Arc::new(CompletedPlacementFact {
            pin: pin.clone(),
            _memory: memory,
        }));
        Ok(())
    }
    fn observe_completed_placement(&mut self, stage: Stage, outcome: &BatchOutcome) -> Result<()> {
        if stage != Stage::Placing
            || !matches!(outcome.disposition, BatchDisposition::ObservedApplied)
            || !self.pending.as_ref().is_some_and(|batch| {
                batch.operation == "native_reconcile_and_place_remaining" && batch.id == outcome.id
            })
        {
            return Ok(());
        }
        let mut pins = outcome
            .evidence
            .iter()
            .filter(|pin| pin.key == "placement-completed");
        let pin = pins
            .next()
            .context("completed placement batch lacks its closed report pin")?;
        ensure!(
            pins.next().is_none() && pin.path == self.directory.join("placement-completed.json"),
            "completed placement batch report pin is ambiguous or outside its epoch"
        );
        let retained = (std::mem::size_of::<CompletedPlacementFact>() as u64)
            .checked_add(
                (pin.path.as_os_str().as_encoded_bytes().len() as u64)
                    .checked_mul(4)
                    .context("placement fact path RAM overflow")?,
            )
            .and_then(|n| n.checked_add((pin.final_path.len() as u64) * 4))
            .and_then(|n| n.checked_add(pin.key.len() as u64 + pin.sha256.len() as u64 + 4096))
            .context("placement fact RAM overflow")?;
        let memory = self.group.arena().reserve_ram(retained)?;
        self.completed_placement = Some(std::sync::Arc::new(CompletedPlacementFact {
            pin: pin.clone(),
            _memory: memory,
        }));
        Ok(())
    }
    pub(crate) fn uncertain_checkpoints(&self) -> &[UncertainCheckpoint] {
        &self.uncertain
    }
    pub(crate) fn publication_hint(&self) -> Option<&ArtifactPin> {
        self.publication.as_ref()
    }
    pub(crate) fn record_stage(&mut self, stage: Stage, artifacts: Vec<ArtifactPin>) -> Result<()> {
        self.ready()?;
        ensure!(
            self.pending.is_none(),
            "pending native batch must reconcile first"
        );
        self.append(stage, Change::Stage { artifacts })
    }
    pub(crate) fn begin_batch(
        &mut self,
        stage: Stage,
        batch: BatchIntent,
    ) -> Result<DurableBatchIntent> {
        self.ready()?;
        ensure!(
            self.pending.is_none()
                && matches!(
                    stage,
                    Stage::ShadowAllocated | Stage::Placing | Stage::Payloads | Stage::Metadata
                ),
            "batch pending or wrong shadow stage"
        );
        let id = batch.id;
        self.append(stage, Change::BatchIntent { batch })?;
        Ok(DurableBatchIntent {
            epoch: self.intent.epoch.clone(),
            intent_sha256: self.intent_file.pin.sha256.clone(),
            sequence: self.sequence,
            head: self.head.clone(),
            id,
        })
    }
    pub(crate) fn complete_batch(
        &mut self,
        token: DurableBatchIntent,
        outcome: BatchOutcome,
    ) -> Result<()> {
        self.ready()?;
        ensure!(
            token.epoch == self.intent.epoch
                && token.intent_sha256 == self.intent_file.pin.sha256
                && token.sequence == self.sequence
                && token.head == self.head
                && token.id == outcome.id
                && self.pending.as_ref().is_some_and(|b| b.id == token.id),
            "batch completion does not consume this epoch's intent"
        );
        self.append(
            self.stage.context("batch stage absent")?,
            Change::BatchOutcome { outcome },
        )
    }
    pub(crate) fn record_reconciliation(
        &mut self,
        stage: Stage,
        pending_outcome: Option<BatchOutcome>,
        evidence: Vec<ArtifactPin>,
    ) -> Result<()> {
        ensure!(
            !self.poisoned && self.publication.is_none() && !evidence.is_empty(),
            "reconciliation owner/evidence absent"
        );
        ensure!(
            self.pending.is_some() == pending_outcome.is_some(),
            "pending reconciliation coverage differs"
        );
        self.append(
            stage,
            Change::Reconciled {
                uncertain_sequences: self.uncertain.iter().map(|v| v.sequence).collect(),
                pending_outcome,
                evidence,
            },
        )
    }
    pub(crate) fn record_journal_publication(&mut self, publication: ArtifactPin) -> Result<()> {
        self.ready()?;
        ensure!(
            self.pending.is_none() && self.stage == Some(Stage::Captured),
            "capture/batches must close before publication"
        );
        self.append(
            Stage::JournalPublished,
            Change::JournalPublished { publication },
        )
    }
    fn ready(&self) -> Result<()> {
        ensure!(
            !self.read_only_origin,
            "historical external checkpoint owner is read-only"
        );
        ensure!(
            !self.poisoned && self.publication.is_none() && self.uncertain.is_empty(),
            "incomplete copies need native reconciliation, or already published"
        );
        self.intent_file.revalidate_identity()
    }
    fn validate_body(&self, b: &Body) -> Result<()> {
        ensure!(
            b.schema_version == 1
                && b.kind == RECORD_KIND
                && b.epoch == self.intent.epoch
                && b.intent_sha256 == self.intent_file.pin.sha256
                && b.sequence == self.sequence + 1
                && b.previous_sha256 == self.head
                && b.sequence <= self.limits.max_checkpoints,
            "checkpoint is not next exact hash-linked record"
        );
        let current = self.stage.map_or(0, Stage::ordinal);
        ensure!(
            b.stage.ordinal() >= current
                && b.stage.ordinal() <= current + 1
                && (self.stage.is_some() || b.stage == Stage::SourceCaptured),
            "checkpoint stage skipped/regressed"
        );
        ensure!(
            self.publication.is_none(),
            "published preparation must use existing authenticated --recover"
        );
        ensure!(
            (b.stage == Stage::JournalPublished)
                == matches!(b.delta, Change::JournalPublished { .. }),
            "only publication record may enter final recovery stage"
        );
        Ok(())
    }
    fn apply(&mut self, b: &Body, replaying: bool) -> Result<()> {
        match &b.delta {
            Change::Stage { artifacts } => {
                ensure!(
                    self.pending.is_none() && (replaying || self.uncertain.is_empty()),
                    "stage crossed unresolved batch/copy"
                );
                validate_pins(artifacts, self.limits.max_artifacts)?;
                self.observe_completed_payloads(b.stage, artifacts)?;
            }
            Change::BatchIntent { batch } => {
                ensure!(
                    matches!(
                        b.stage,
                        Stage::ShadowAllocated | Stage::Placing | Stage::Payloads | Stage::Metadata
                    ),
                    "batch checkpoint uses a non-shadow stage"
                );
                ensure!(
                    self.pending.is_none() && (replaying || self.uncertain.is_empty()),
                    "batch crossed unresolved intent/copy"
                );
                batch.validate(self.limits)?;
                if b.stage == Stage::Placing {
                    self.completed_placement = None;
                }
                if matches!(b.stage, Stage::Placing | Stage::Payloads) {
                    self.completed_payloads = None;
                }
                self.pending = Some(batch.clone());
            }
            Change::BatchOutcome { outcome } => {
                ensure!(
                    self.stage == Some(b.stage),
                    "outcome changed its batch stage"
                );
                outcome.validate(self.limits)?;
                ensure!(
                    self.pending.as_ref().is_some_and(|v| v.id == outcome.id),
                    "outcome lacks intent"
                );
                self.observe_completed_placement(b.stage, outcome)?;
                if !matches!(outcome.disposition, BatchDisposition::Refused) {
                    self.pending = None;
                }
            }
            Change::Reconciled {
                uncertain_sequences,
                pending_outcome,
                evidence,
            } => {
                ensure!(
                    (replaying
                        || *uncertain_sequences
                            == self
                                .uncertain
                                .iter()
                                .map(|v| v.sequence)
                                .collect::<Vec<_>>())
                        && !evidence.is_empty(),
                    "reconciliation omitted uncertain copies"
                );
                validate_pins(evidence, self.limits.max_artifacts)?;
                if let Some(outcome) = pending_outcome {
                    outcome.validate(self.limits)?;
                    ensure!(
                        self.pending.as_ref().is_some_and(|v| v.id == outcome.id),
                        "reconciliation names different batch"
                    );
                    self.observe_completed_placement(b.stage, outcome)?;
                    if !matches!(outcome.disposition, BatchDisposition::Refused) {
                        self.pending = None;
                    }
                } else {
                    ensure!(self.pending.is_none(), "pending reconciliation absent");
                }
                self.uncertain.clear();
            }
            Change::JournalPublished { publication } => {
                ensure!(
                    b.stage == Stage::JournalPublished
                        && self.pending.is_none()
                        && self.uncertain.is_empty(),
                    "publication crossed unresolved state"
                );
                publication.validate()?;
                self.publication = Some(publication.clone());
            }
        }
        self.stage = Some(b.stage);
        Ok(())
    }
    fn append(&mut self, stage: Stage, delta: Change) -> Result<()> {
        let body = Body {
            schema_version: 1,
            kind: RECORD_KIND.to_owned(),
            epoch: self.intent.epoch.clone(),
            intent_sha256: self.intent_file.pin.sha256.clone(),
            sequence: self.sequence.checked_add(1).context("sequence overflow")?,
            previous_sha256: self.head.clone(),
            stage,
            delta,
        };
        self.validate_body(&body)?;
        let (hash, bytes) = canonical_metrics(&body, self.limits.max_checkpoint_bytes)?;
        let memory = self.group.arena().reserve_ram(
            bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(4096))
                .context("checkpoint RAM overflow")?,
        )?;
        // Validate the complete state transition BEFORE creating durable files.
        let old = (
            self.pending.clone(),
            self.stage,
            self.publication.clone(),
            self.uncertain.clone(),
            self.completed_placement.clone(),
            self.completed_payloads.clone(),
        );
        let validation = self.apply(&body, false);
        (
            self.pending,
            self.stage,
            self.publication,
            self.uncertain,
            self.completed_placement,
            self.completed_payloads,
        ) = old;
        validation?;
        self.poisoned = true;
        let envelope = Envelope {
            body_sha256: hash.clone(),
            body,
        };
        // Complete FILE digest in the filename lets adopt_existing authenticate
        // each replica once. The body digest remains the hash-chain identity.
        let file_hash = canonical_hash(&envelope, self.limits.max_checkpoint_bytes)?;
        let mut copies = Vec::new();
        for copy in 0..2 {
            let path = self.directory.join(format!(
                "checkpoint-{:016x}-{}-{copy}.json",
                envelope.body.sequence, file_hash
            ));
            copies.push(write_artifact(
                &self.group,
                &path,
                &format!("checkpoint-{:016x}-{copy}", envelope.body.sequence),
                &envelope,
                self.limits.max_checkpoint_bytes,
            )?);
        }
        self.apply(&envelope.body, false)?;
        self.sequence = envelope.body.sequence;
        self.head = hash;
        self.records.push(RecordOwners {
            _copies: copies,
            _memory: vec![memory],
        });
        self.poisoned = false;
        Ok(())
    }
}

fn validate_group(g: &ArtifactGroupPermit) -> Result<()> {
    ensure!(
        matches!(
            g.group(),
            ArtifactGroup::Auxiliary | ArtifactGroup::RecoveryCopy | ArtifactGroup::Capture
        ),
        "resume needs actual metadata group"
    );
    Ok(())
}
fn canonical_sha(s: &str) -> Result<()> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical lowercase SHA required"
    );
    Ok(())
}
fn ordinary_path(p: &Path) -> Result<()> {
    ensure!(
        p.is_absolute()
            && !p
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
            && !p.as_os_str().to_string_lossy().starts_with("\\\\.\\"),
        "ordinary absolute metadata path required"
    );
    Ok(())
}
fn volume(p: &str) -> Result<[u8; 16]> {
    Ok(n2r_win32::layout::guid_bytes(
        p.strip_prefix("\\\\?\\Volume{")
            .and_then(|s| s.split_once('}'))
            .context("GUID working path required")?
            .0,
    )?)
}
fn hold_directory(p: &Path, a: &ArtifactArena) -> Result<File> {
    ordinary_path(p)?;
    let f = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1)
        .custom_flags(0x0220_0000)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_dir()
            && m.file_attributes() & 0x400 == 0
            && volume(&n2r_win32::file_storage::final_path_guid(&f)?)?
                == volume(a.volume_guid_path()?)?,
        "resume directory escaped ordinary working volume"
    );
    Ok(f)
}
fn hold_readonly_directory(p: &Path, a: &ArtifactArena) -> Result<File> {
    a.require_readonly_origin_path(p)?;
    let file = OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1)
        .custom_flags(0x02200000)
        .open(p)?;
    ensure!(
        file.metadata()?.is_dir() && file.metadata()?.file_attributes() & 0x400 == 0,
        "historical resume directory is not ordinary"
    );
    Ok(file)
}
fn validate_pins(pins: &[ArtifactPin], maximum: usize) -> Result<()> {
    ensure!(pins.len() <= maximum, "artifact pin bound exceeded");
    let mut keys = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for p in pins {
        p.validate()?;
        ensure!(
            keys.insert(&p.key) && paths.insert(&p.path),
            "artifact keys/paths repeat"
        );
    }
    Ok(())
}
struct HashSink {
    hash: Sha256,
    bytes: u64,
    maximum: u64,
}
impl Write for HashSink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(b.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("canonical resume metadata exceeds bound"))?;
        self.hash.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn canonical_metrics(v: &impl Serialize, max: u64) -> Result<(String, u64)> {
    let mut sink = HashSink {
        hash: Sha256::new(),
        bytes: 0,
        maximum: max,
    };
    serde_json::to_writer(&mut sink, v)?;
    Ok((hex::encode(sink.hash.finalize()), sink.bytes))
}
fn canonical_hash(v: &impl Serialize, max: u64) -> Result<String> {
    Ok(canonical_metrics(v, max)?.0)
}

struct Output<'a> {
    file: &'a mut File,
    sink: HashSink,
}
impl Write for Output<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.sink.write_all(b)?;
        self.file.write_all(b)?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn write_artifact(
    g: &ArtifactGroupPermit,
    p: &Path,
    key: &str,
    v: &impl Serialize,
    max: u64,
) -> Result<HeldArtifact> {
    let _ram = g.arena().reserve_ram(131072)?;
    let permit = g.reserve_file(p, max)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x8020_0000)
        .open(permit.path())?;
    let mut out = Output {
        file: &mut f,
        sink: HashSink {
            hash: Sha256::new(),
            bytes: 0,
            maximum: max,
        },
    };
    serde_json::to_writer(&mut out, v)?;
    out.flush()?;
    let hash = hex::encode(out.sink.hash.finalize());
    f.sync_all()?;
    drop(f);
    HeldArtifact::from_accounted_lease(permit.verify_closed(&hash)?, g, key.to_owned())
}
pub(crate) fn parse_name(p: &Path, directory: &Path) -> Result<(u64, u8, String)> {
    ensure!(
        p.parent() == Some(directory),
        "checkpoint escapes exact epoch directory"
    );
    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .context("Unicode checkpoint leaf required")?;
    let s = name
        .strip_prefix("checkpoint-")
        .and_then(|s| s.strip_suffix(".json"))
        .context("checkpoint filename differs")?;
    let fields: Vec<_> = s.split('-').collect();
    ensure!(
        fields.len() == 3
            && fields[0].len() == 16
            && fields[0]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "checkpoint sequence filename differs"
    );
    canonical_sha(fields[1])?;
    let sequence = u64::from_str_radix(fields[0], 16)?;
    let copy = match fields[2] {
        "0" => 0,
        "1" => 1,
        _ => anyhow::bail!("checkpoint copy differs"),
    };
    ensure!(sequence > 0, "zero sequence refused");
    Ok((sequence, copy, fields[1].to_owned()))
}
