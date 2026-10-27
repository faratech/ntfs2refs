//! Recorded qualification evidence. This registry never grants device access,
//! admission, replay, cancellation, or filesystem support authority.
//!
//! Validation checks the record's structure and references. It deliberately does
//! not open historical artifacts or imply that their bytes were reverified.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};

pub const EMBEDDED: &str = include_str!("../evidence/qualification-registry.json");

/// Load a bounded registry. Historical artifact/device paths are not opened.
pub fn load_registry(path: &Path) -> Result<Registry> {
    let file = std::fs::File::open(path).context("open registry")?;
    ensure!(
        file.metadata()?.is_file(),
        "registry must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(512 * 1024 + 1).read_to_end(&mut bytes)?;
    Registry::from_json(&bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema_version: u32,
    pub scope: String,
    pub profiles: Vec<Profile>,
    pub evidence: Vec<Evidence>,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub description: String,
    pub source_filesystem: Option<String>,
    pub target_filesystem: String,
    pub logical_sector_bytes: u32,
    /// Target allocation unit. Legacy equal-geometry profiles omit the source.
    pub cluster_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cluster_bytes: Option<u32>,
    pub mft_record_bytes: Option<u32>,
    pub source_policy_windows_build: Option<u32>,
    pub observed_partition_bytes: u64,
    pub limits: Limits,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub maximum_files: u32,
    pub maximum_directories: u32,
    pub maximum_logical_bytes: u64,
    pub ascii_names_only: bool,
    pub maximum_component_bytes: u32,
    pub maximum_path_components: u32,
    pub unnamed_streams_per_file: u32,
    pub requires_absent_sacl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub role: String,
    pub path: Option<String>,
    pub location_unknown_reason: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Driver {
    pub name: String,
    pub file_version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    pub name: String,
    pub sha256: String,
    pub retained_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub windows_build_revision: Option<String>,
    pub refs_driver: Option<Driver>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub description: String,
    pub source_image_sha256: Option<String>,
    pub expected_image_sha256: Option<String>,
    pub expected_semantic_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub logical_bytes: Option<u64>,
    pub retained_payload_bytes: Option<u64>,
    pub relocated_payload_bytes: Option<u64>,
    pub materialized_payload_bytes: Option<u64>,
    pub target_bytes_written: Option<u64>,
    pub journal_bytes: Option<u64>,
    pub source_bytes_hashed: Option<u64>,
    pub metadata_write_count: Option<u64>,
    pub objects_verified: Option<u64>,
    pub actual_shadow_backing_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Implemented,
    UnitTested,
    NativeObserved,
    RebootVerified,
    ProcessFaultQualified,
    PowerLossQualified,
}

impl Stage {
    pub const ALL: [Self; 6] = [
        Self::Implemented,
        Self::UnitTested,
        Self::NativeObserved,
        Self::RebootVerified,
        Self::ProcessFaultQualified,
        Self::PowerLossQualified,
    ];
    fn needs_native(self) -> bool {
        matches!(
            self,
            Self::NativeObserved
                | Self::RebootVerified
                | Self::ProcessFaultQualified
                | Self::PowerLossQualified
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultModel {
    None,
    ProcessExitAfterSourceFreeze,
    ProcessExitAfterFirstFlushedTargetWrite,
    StoragePowerLoss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub profile_id: String,
    pub stages: Vec<Stage>,
    pub outcome: Outcome,
    pub scope: String,
    pub repository_commit: Option<String>,
    pub executable: Option<Executable>,
    pub environment: Option<Environment>,
    pub corpus: Corpus,
    pub artifacts: Vec<Artifact>,
    pub source_documents: Vec<String>,
    pub unknown_fields: BTreeMap<String, String>,
    pub fault_model: FaultModel,
    pub clean_reboot_observed: bool,
    pub metrics: Metrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: String,
    pub profile_id: String,
    pub feature: String,
    pub statement: String,
    pub evidence_ids: Vec<String>,
    pub exclusions: Vec<String>,
    pub remaining_gates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unrecorded,
    Passed,
    Failed,
    Refused,
    Mixed,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Unrecorded => "unrecorded",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MatrixRow {
    pub claim_id: String,
    pub profile_id: String,
    pub feature: String,
    pub statement: String,
    pub stages: BTreeMap<Stage, Status>,
    pub evidence_ids: Vec<String>,
    pub exclusions: Vec<String>,
    pub remaining_gates: Vec<String>,
}

fn canonical_hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':', '\n', '\r', '\0'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn artifact(pin: &Artifact) -> Result<()> {
    ensure!(!pin.role.trim().is_empty(), "artifact needs a role");
    match &pin.path {
        Some(path) => ensure!(
            relative_path(path) && pin.location_unknown_reason.is_none(),
            "artifact path must be repository-relative and unambiguous"
        ),
        None => ensure!(
            pin.location_unknown_reason
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
            "unknown artifact location requires an explanation"
        ),
    }
    ensure!(
        canonical_hex(&pin.sha256, 64),
        "artifact SHA-256 must be canonical"
    );
    Ok(())
}

impl Registry {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 512 * 1024,
            "registry exceeds bounded input size"
        );
        let registry: Self =
            serde_json::from_slice(bytes).context("invalid qualification registry")?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn embedded() -> Result<Self> {
        Self::from_json(EMBEDDED.as_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && !self.scope.trim().is_empty(),
            "unknown registry schema or missing scope"
        );
        ensure!(
            !self.profiles.is_empty() && !self.claims.is_empty(),
            "registry has no profiles or claims"
        );
        let mut profiles = BTreeSet::new();
        for p in &self.profiles {
            ensure!(
                id(&p.id) && profiles.insert(&p.id),
                "invalid or duplicate profile ID"
            );
            ensure!(
                !p.description.trim().is_empty() && !p.target_filesystem.is_empty(),
                "missing profile description or target"
            );
            ensure!(
                p.logical_sector_bytes.is_power_of_two()
                    && p.logical_sector_bytes >= 512
                    && p.cluster_bytes.is_power_of_two()
                    && p.cluster_bytes >= p.logical_sector_bytes
                    && p.observed_partition_bytes > 0
                    && p.observed_partition_bytes
                        .is_multiple_of(p.cluster_bytes as u64),
                "invalid profile geometry"
            );
            ensure!(
                p.source_cluster_bytes.is_none_or(|bytes| {
                    bytes.is_power_of_two()
                        && bytes >= p.logical_sector_bytes
                        && p.observed_partition_bytes.is_multiple_of(u64::from(bytes))
                }),
                "invalid source cluster geometry"
            );
            ensure!(
                p.mft_record_bytes
                    .is_none_or(|n| n.is_power_of_two() && n >= p.logical_sector_bytes),
                "invalid MFT record size"
            );
            ensure!(
                p.limits.maximum_files > 0
                    && p.limits.maximum_directories > 0
                    && p.limits.maximum_logical_bytes > 0
                    && p.limits.maximum_component_bytes > 0
                    && p.limits.maximum_path_components > 0
                    && p.limits.unnamed_streams_per_file == 1
                    && !p.exclusions.is_empty(),
                "missing bounded profile limits or exclusions"
            );
        }
        let mut records = BTreeMap::new();
        for e in &self.evidence {
            ensure!(
                id(&e.id) && records.insert(&e.id, e).is_none(),
                "invalid or duplicate evidence ID"
            );
            ensure!(
                profiles.contains(&e.profile_id),
                "evidence references unknown profile"
            );
            ensure!(
                !e.scope.trim().is_empty()
                    && !e.corpus.description.trim().is_empty()
                    && !e.source_documents.is_empty(),
                "incomplete evidence description"
            );
            ensure!(
                !e.stages.is_empty()
                    && e.stages.iter().collect::<BTreeSet<_>>().len() == e.stages.len(),
                "missing or duplicate evidence stages"
            );
            ensure!(
                e.source_documents.iter().all(|p| relative_path(p)),
                "invalid source document path"
            );
            ensure!(
                e.unknown_fields.values().all(|v| !v.trim().is_empty()),
                "unknown field requires an explanation"
            );
            if let Some(commit) = &e.repository_commit {
                ensure!(
                    canonical_hex(commit, 40),
                    "repository commit must be an exact lowercase SHA-1"
                );
            } else {
                ensure!(
                    e.unknown_fields.contains_key("repository_commit"),
                    "missing historical commit must be explicit"
                );
            }
            if let Some(executable) = &e.executable {
                ensure!(
                    !executable.name.is_empty() && canonical_hex(&executable.sha256, 64),
                    "invalid executable name or SHA-256"
                );
                ensure!(
                    executable
                        .retained_path
                        .as_ref()
                        .is_none_or(|p| relative_path(p)),
                    "invalid executable retained path"
                );
            } else {
                ensure!(
                    e.unknown_fields.contains_key("executable"),
                    "missing executable must be explicit"
                );
            }
            for a in &e.artifacts {
                artifact(a)?;
            }
            for digest in [
                &e.corpus.source_image_sha256,
                &e.corpus.expected_image_sha256,
                &e.corpus.expected_semantic_manifest_sha256,
            ]
            .into_iter()
            .flatten()
            {
                ensure!(canonical_hex(digest, 64), "corpus digest must be canonical");
            }
            if let Some(env) = &e.environment {
                ensure!(
                    env.windows_build_revision
                        .as_ref()
                        .is_none_or(|s| !s.is_empty()
                            && s.split('.')
                                .all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))),
                    "invalid Windows build/revision"
                );
                if let Some(driver) = &env.refs_driver {
                    ensure!(
                        driver.name == "refs.sys"
                            && !driver.file_version.is_empty()
                            && canonical_hex(&driver.sha256, 64),
                        "invalid ReFS driver identity"
                    );
                }
            }
            if e.stages.iter().any(|s| s.needs_native()) {
                ensure!(
                    !e.artifacts.is_empty(),
                    "native evidence needs a result artifact digest"
                );
                ensure!(
                    e.environment
                        .as_ref()
                        .is_some_and(|v| v.windows_build_revision.is_some())
                        || e.unknown_fields.contains_key("windows_build_revision"),
                    "native Windows identity must be recorded or explicitly unknown"
                );
                ensure!(
                    e.environment
                        .as_ref()
                        .is_some_and(|v| v.refs_driver.is_some())
                        || e.unknown_fields.contains_key("refs_driver"),
                    "native driver identity must be recorded or explicitly unknown"
                );
                ensure!(
                    e.corpus.expected_semantic_manifest_sha256.is_some()
                        || e.unknown_fields
                            .contains_key("expected_semantic_manifest_sha256"),
                    "native expected manifest must be pinned or explicitly unknown"
                );
            }
            if e.stages.contains(&Stage::RebootVerified) {
                ensure!(
                    e.clean_reboot_observed,
                    "reboot stage requires an observed clean reboot"
                );
            }
            if e.stages.contains(&Stage::ProcessFaultQualified) {
                ensure!(
                    matches!(
                        e.fault_model,
                        FaultModel::ProcessExitAfterSourceFreeze
                            | FaultModel::ProcessExitAfterFirstFlushedTargetWrite
                    ),
                    "process-fault stage needs a process fault model"
                );
            }
            if e.stages.contains(&Stage::PowerLossQualified) {
                ensure!(
                    e.fault_model == FaultModel::StoragePowerLoss,
                    "power-loss qualification cannot be inferred from process exit or clean reboot"
                );
            }
            if let (Some(logical), Some(retained), Some(relocated), Some(materialized)) = (
                e.metrics.logical_bytes,
                e.metrics.retained_payload_bytes,
                e.metrics.relocated_payload_bytes,
                e.metrics.materialized_payload_bytes,
            ) {
                ensure!(
                    retained
                        .checked_add(relocated)
                        .and_then(|n| n.checked_add(materialized))
                        == Some(logical),
                    "payload accounting does not cover logical bytes"
                );
            }
        }
        let mut claims = BTreeSet::new();
        for c in &self.claims {
            ensure!(
                id(&c.id) && claims.insert(&c.id) && profiles.contains(&c.profile_id),
                "invalid claim identity or profile"
            );
            ensure!(
                !c.feature.trim().is_empty()
                    && !c.statement.trim().is_empty()
                    && !c.exclusions.is_empty()
                    && !c.remaining_gates.is_empty(),
                "claim needs statement, exclusions and remaining gates"
            );
            let mut seen = BTreeSet::new();
            for evidence_id in &c.evidence_ids {
                let e = records
                    .get(evidence_id)
                    .context("claim references unknown evidence")?;
                ensure!(
                    seen.insert(evidence_id) && e.profile_id == c.profile_id,
                    "duplicate or cross-profile claim evidence"
                );
            }
        }
        Ok(())
    }

    pub fn matrix(&self) -> Result<Vec<MatrixRow>> {
        self.validate()?;
        Ok(self
            .claims
            .iter()
            .map(|c| {
                let stages = Stage::ALL
                    .into_iter()
                    .map(|stage| {
                        let outcomes: BTreeSet<_> = self
                            .evidence
                            .iter()
                            .filter(|e| c.evidence_ids.contains(&e.id) && e.stages.contains(&stage))
                            .map(|e| e.outcome)
                            .collect();
                        let status = match outcomes.len() {
                            0 => Status::Unrecorded,
                            1 => match outcomes.first().unwrap() {
                                Outcome::Passed => Status::Passed,
                                Outcome::Failed => Status::Failed,
                                Outcome::Refused => Status::Refused,
                            },
                            _ => Status::Mixed,
                        };
                        (stage, status)
                    })
                    .collect();
                MatrixRow {
                    claim_id: c.id.clone(),
                    profile_id: c.profile_id.clone(),
                    feature: c.feature.clone(),
                    statement: c.statement.clone(),
                    stages,
                    evidence_ids: c.evidence_ids.clone(),
                    exclusions: c.exclusions.clone(),
                    remaining_gates: c.remaining_gates.clone(),
                }
            })
            .collect())
    }
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\r', '\n'], " ")
}

pub fn render_markdown(registry: &Registry) -> Result<String> {
    registry.validate()?;
    let mut output = String::from(
        "Recorded qualification only. Artifact bytes are not reverified by this command. No entry grants execution or admission authority. Unrecorded does not mean unsupported, and passed is limited to the linked evidence.\n",
    );
    for p in &registry.profiles {
        let clusters = p.source_cluster_bytes.map_or_else(
            || format!("cluster: {} bytes", p.cluster_bytes),
            |source| {
                format!(
                    "source cluster: {source} bytes; target cluster: {} bytes",
                    p.cluster_bytes
                )
            },
        );
        output.push_str(&format!(
            "\nProfile `{}`: {} Source: {}; target: {}; logical sector: {} bytes; {}; observed partition: {} bytes. Limits: {} files, {} directories, {} logical bytes, {} unnamed stream per file, {} components of at most {} bytes, ASCII-only names: {}, absent SACL required: {}. Exclusions: {}.\n",
            p.id, cell(&p.description), p.source_filesystem.as_deref().unwrap_or("none (reference image)"),
            p.target_filesystem, p.logical_sector_bytes, clusters, p.observed_partition_bytes,
            p.limits.maximum_files, p.limits.maximum_directories, p.limits.maximum_logical_bytes,
            p.limits.unnamed_streams_per_file, p.limits.maximum_path_components, p.limits.maximum_component_bytes,
            p.limits.ascii_names_only, p.limits.requires_absent_sacl, cell(&p.exclusions.join("; "))
        ));
    }
    output.push_str("\n| Feature / profile | Implemented | Unit | Native | Reboot | Process fault | Power loss | Evidence |\n|---|---|---|---|---|---|---|---|\n");
    for row in registry.matrix()? {
        output.push_str(&format!(
            "| {} / `{}` |",
            cell(&row.feature),
            row.profile_id
        ));
        for stage in Stage::ALL {
            output.push_str(&format!(" {} |", row.stages[&stage].label()));
        }
        output.push_str(&format!(
            " {} |\n",
            row.evidence_ids
                .iter()
                .map(|id| format!("`{id}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for c in &registry.claims {
        output.push_str(&format!(
            "\n**{}** (`{}`): {}\n\nExclusions: {}\n\nRemaining gates: {}\n",
            cell(&c.feature),
            c.id,
            cell(&c.statement),
            cell(&c.exclusions.join("; ")),
            cell(&c.remaining_gates.join("; "))
        ));
    }
    output.push_str("\nRecorded evidence identities:\n");
    for e in &registry.evidence {
        output.push_str(&format!(
            "\n**{}**: {}\n\nRepository commit: `{}`. Executable: {}.\n",
            e.id,
            cell(&e.scope),
            e.repository_commit.as_deref().unwrap_or("unknown"),
            e.executable.as_ref().map_or_else(
                || "unknown".into(),
                |x| format!("`{}` SHA-256 `{}`", cell(&x.name), x.sha256)
            )
        ));
        let env = e.environment.as_ref();
        output.push_str(&format!(
            "\nWindows build/revision: `{}`. ReFS driver: {}. Semantic manifest SHA-256: `{}`.\n",
            env.and_then(|v| v.windows_build_revision.as_deref())
                .unwrap_or("unknown"),
            env.and_then(|v| v.refs_driver.as_ref()).map_or_else(
                || "unknown".into(),
                |x| format!(
                    "`{}` version `{}` SHA-256 `{}`",
                    x.name,
                    cell(&x.file_version),
                    x.sha256
                )
            ),
            e.corpus
                .expected_semantic_manifest_sha256
                .as_deref()
                .unwrap_or("unknown")
        ));
        for a in &e.artifacts {
            output.push_str(&format!(
                "\n- {}: `{}`; SHA-256 `{}`.{}\n",
                cell(&a.role),
                cell(a.path.as_deref().unwrap_or("unknown location")),
                a.sha256,
                a.location_unknown_reason
                    .as_ref()
                    .map_or_else(String::new, |s| format!(" {}", cell(s)))
            ));
        }
        if !e.unknown_fields.is_empty() {
            output.push_str("\nUnknown or scoped fields:\n");
            for (name, reason) in &e.unknown_fields {
                output.push_str(&format!("\n- `{}`: {}\n", cell(name), cell(reason)));
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_is_typed_and_does_not_inherit_unrecorded_stages() {
        let registry = Registry::embedded().unwrap();
        let rows = registry.matrix().unwrap();
        let conversion = rows
            .iter()
            .find(|r| r.claim_id == "public-existing-tree-conversion")
            .unwrap();
        assert_eq!(conversion.stages[&Stage::NativeObserved], Status::Passed);
        assert_eq!(
            conversion.stages[&Stage::PowerLossQualified],
            Status::Unrecorded
        );
        let automatic_label = rows
            .iter()
            .find(|r| r.claim_id == "automatic-source-label-path")
            .unwrap();
        assert_eq!(
            automatic_label.stages[&Stage::NativeObserved],
            Status::Passed
        );
        let writer = rows
            .iter()
            .find(|r| r.claim_id == "independent-writer-acceptance")
            .unwrap();
        assert_eq!(writer.stages[&Stage::NativeObserved], Status::Failed);
    }

    #[test]
    fn rejects_unknown_profiles_bad_pins_and_hidden_missing_identity() {
        let original = Registry::embedded().unwrap();
        let mut r = original.clone();
        r.claims[0].profile_id = "unknown".into();
        assert!(r.validate().is_err());
        let mut r = original.clone();
        r.evidence
            .iter_mut()
            .find(|e| !e.artifacts.is_empty())
            .unwrap()
            .artifacts[0]
            .sha256 = "A".repeat(64);
        assert!(r.validate().is_err());
        let mut r = original;
        let e = r
            .evidence
            .iter_mut()
            .find(|e| e.repository_commit.is_none())
            .unwrap();
        e.unknown_fields.remove("repository_commit");
        assert!(r.validate().is_err());
    }

    #[test]
    fn cannot_promote_process_interruption_to_power_loss_or_reboot() {
        let mut r = Registry::embedded().unwrap();
        let e = r
            .evidence
            .iter_mut()
            .find(|e| e.stages.contains(&Stage::ProcessFaultQualified))
            .unwrap();
        e.stages.push(Stage::PowerLossQualified);
        assert!(r.validate().is_err());
        let mut r = Registry::embedded().unwrap();
        let e = r
            .evidence
            .iter_mut()
            .find(|e| e.stages.contains(&Stage::NativeObserved) && !e.clean_reboot_observed)
            .unwrap();
        e.stages.push(Stage::RebootVerified);
        assert!(
            r.validate()
                .unwrap_err()
                .to_string()
                .contains("reboot stage")
        );
    }

    #[test]
    fn refuses_bad_accounting_cross_profile_and_duplicate_claims() {
        let original = Registry::embedded().unwrap();
        let mut r = original.clone();
        r.evidence
            .iter_mut()
            .find(|e| e.metrics.logical_bytes.is_some())
            .unwrap()
            .metrics
            .retained_payload_bytes = Some(1);
        assert!(r.validate().is_err());
        let mut r = original.clone();
        r.claims[0]
            .evidence_ids
            .push("independent-writer-native-rejection".into());
        assert!(r.validate().is_err());
        let mut r = original;
        r.claims.push(r.claims[0].clone());
        assert!(r.validate().is_err());
    }

    #[test]
    fn render_is_explicit_and_unknown_json_fields_are_refused() {
        let text = render_markdown(&Registry::embedded().unwrap()).unwrap();
        assert!(text.contains("No entry grants execution or admission authority"));
        assert!(text.contains("unrecorded"));
        assert!(text.contains("failed"));
        let mut json: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        json["execution_authorized"] = true.into();
        assert!(Registry::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    #[test]
    fn native_pins_and_unknown_locations_are_required_without_opening_artifacts() {
        let original = Registry::embedded().unwrap();
        let mut r = original.clone();
        r.evidence
            .iter_mut()
            .find(|e| e.stages.contains(&Stage::NativeObserved))
            .unwrap()
            .artifacts
            .clear();
        assert!(
            r.validate()
                .unwrap_err()
                .to_string()
                .contains("result artifact")
        );
        let mut r = original;
        r.evidence
            .iter_mut()
            .flat_map(|e| &mut e.artifacts)
            .find(|a| a.path.is_none())
            .unwrap()
            .location_unknown_reason = None;
        assert!(
            r.validate()
                .unwrap_err()
                .to_string()
                .contains("unknown artifact location")
        );
    }
}
