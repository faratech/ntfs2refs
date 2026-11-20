//! Exact-continuity source-cache origin and fresh-owner reconstruction.
//! Every saved field is evidence input. Only actual new SDK source reads issue
//! the continuity proof used to reopen the cold raw metadata owner.
use super::*;
use crate::ntfs_inspect::{SourceInspectionPin, paged_storage::SourcePagePin};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCacheFilePin {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

/// Independent explicit origin pins, not source admission or old owner state.
/// Caller pins the complete struct independently before selecting this path.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCacheOriginPins {
    pub schema_version: u32,
    pub source: GeneralDiskBinding,
    pub policy: VerificationPolicy,
    pub resource_admission: SourceResourceAdmission,
    pub source_manifest: SourceCacheFilePin,
    pub source_frozen: SourceCacheFilePin,
    pub inspection_read_coverage: SourceCacheFilePin,
    pub source_assessment: SourceCacheFilePin,
    pub native_witness: SourceCacheFilePin,
    pub native_pages: SourceCacheFilePin,
    pub cancelled_preparation_intent: SourceCacheFilePin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_preparation_state: Option<SourceCacheFilePin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<SourceCacheGeneration>,
}

/// Versioned immutable dependency facts from a closed source/Expected stage.
/// The guard may still be live when produced; cold adoption independently
/// requires its actual native cancellation before acquiring a new source owner.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCacheGeneration {
    pub schema_version: u32,
    pub prior_origin_sha256: Option<String>,
    pub prior_preparation_intent: Option<SourceCacheFilePin>,
    pub expected: SourceCacheFilePin,
    pub expected_semantic_sha256: String,
    pub windows_alias_plan: crate::ntfs_inspect::record_store::RecordStorePin,
    pub native_baseline: Option<SourceInspectionPin>,
    pub native_baseline_inspection_sha256: Option<String>,
}
impl std::fmt::Debug for SourceCacheGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCacheGeneration")
            .field("schema_version", &self.schema_version)
            .field("prior_origin_sha256", &self.prior_origin_sha256)
            .field("expected", &self.expected)
            .field("expected_semantic_sha256", &self.expected_semantic_sha256)
            .field(
                "native_baseline_inspection_sha256",
                &self.native_baseline_inspection_sha256,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct FrozenCache {
    binding: GeneralDiskBinding,
    source_sha256: String,
    inspection_sha256: String,
    fingerprint: fp::ReopenedFingerprintPins,
}
#[derive(Deserialize)]
struct AssessmentCache {
    binding: GeneralDiskBinding,
    budget: ResourceBudget,
    resource_admission: SourceResourceAdmission,
    policy: VerificationPolicy,
    source_inspection_sha256: String,
    source_sha256: String,
}
#[derive(Deserialize)]
struct NativeWitnessCache {
    kind: String,
    source_inspection_sha256: String,
    source_fingerprint_before_native: String,
    native_pages_sha256: String,
    /// What the saved Windows view did not read, where the run that took
    /// it verified once ([`super::WINDOWS_CONTENT_READS_SKIPPED`]).
    #[serde(default, rename = "windows_content_reads_skipped")]
    content_reads_skipped: Option<serde_json::Value>,
}

pub(super) struct OpenedSourceCache {
    pub(super) fingerprint: Option<PagedSourceFingerprint>,
    pub(super) continuity: Option<n2r_win32::SourceCacheContinuity>,
    pub(super) native: SourceCacheFilePin,
    pub(super) origin_sha256: [u8; 32],
    pub(super) artifacts: Vec<ArtifactLease>,
    pub(super) fresh_complete_streams_verified: u64,
    pub(super) fresh_complete_payload_bytes: u64,
    pub(super) refresh: Option<super::cache_refresh::UserSemanticRefresh>,
    /// What the saved Windows rows did not read (none for rows that read
    /// every stream), as their native witness records it.
    pub(super) windows_content_reads_skipped: Option<serde_json::Value>,
    pub(super) auxiliary_group: ArtifactGroupPermit,
    pub(super) _memory: SourceRamLease,
}

fn digest(text: &str) -> Result<[u8; 32]> {
    source_admission_digest(text)
}

impl ResourceSourceContext {
    /// Select the current immutable source artifacts from actual held owners.
    /// This issues no source owner and never rewrites an older cache generation.
    pub(crate) fn current_cache_origin(
        &self,
        expected: &crate::shadow_tree::PagedExpectedTree,
        prior: Option<&SourceCacheOriginPins>,
    ) -> Result<SourceCacheOriginPins> {
        self.require_source_evidence()?;
        self.revalidate_evidence()?;
        let arena = self
            .arena
            .as_ref()
            .context("source generation needs its actual arena")?;
        ensure!(
            self.source.freeze_observation().is_some()
                && self.source_seal.is_some()
                && self.native_seal.is_some(),
            "source generation requires the current live source freeze and sealed source/native owners"
        );
        expected.require_resource_owner(self.admission)?;
        expected.require_rebind_source(self.source_owner_identity())?;
        expected.require_shared_memory(arena)?;
        let pin = |lease: &ArtifactLease| -> Result<SourceCacheFilePin> {
            lease.revalidate()?;
            Ok(SourceCacheFilePin {
                path: lease.path().to_path_buf(),
                sha256: lease.sha256().to_owned(),
                bytes: lease.wire_bytes(),
            })
        };
        let metadata = |name: &str| -> Result<SourceCacheFilePin> {
            let mut rows = self
                ._metadata
                .iter()
                .filter(|row| row.path.file_name().is_some_and(|leaf| leaf == name));
            let row = rows
                .next()
                .with_context(|| format!("current source metadata {name} is absent"))?;
            ensure!(
                rows.next().is_none(),
                "current source metadata leaf is ambiguous"
            );
            let lease = row
                .arena_lease
                .as_ref()
                .context("source metadata lost its actual artifact owner")?;
            ensure!(
                lease.path() == row.path
                    && lease.sha256() == row.sha256
                    && lease.wire_bytes() == row.bytes,
                "source metadata artifact and held pin differ"
            );
            pin(lease)
        };
        let native = self
            .native_artifact
            .as_ref()
            .context("source generation native artifact absent")?;
        ensure!(
            native.sha256() == self.native.domain().sha256(),
            "current native generation differs from held native pages"
        );
        let guard = self
            .early_preparation_guard
            .as_ref()
            .context("source generation current guard absent")?;
        guard.revalidate()?;
        let guard_owner = guard.intent_artifact();
        let guard_pin = guard.pin();
        ensure!(
            guard_owner.sha256() == guard_pin.sha256 && guard_owner.wire_bytes() == guard_pin.bytes,
            "source generation guard differs from current native owner"
        );
        let aliases = self
            .windows_aliases
            .as_ref()
            .context("source generation alias owner absent")?;
        aliases.require_source(&self.raw)?;
        let baseline = self
            ._cache_artifacts
            .as_ref()
            .and_then(|cache| cache.refresh.as_ref());
        let generation = SourceCacheGeneration {
            schema_version: 1,
            prior_origin_sha256: prior
                .map(SourceCacheOriginPins::canonical_sha256)
                .transpose()?
                .map(hex::encode),
            prior_preparation_intent: prior
                .map(|origin| origin.cancelled_preparation_intent.clone()),
            expected: pin(expected
                .artifact_lease()
                .context("source generation Expected artifact absent")?)?,
            expected_semantic_sha256: expected.semantic_sha256().to_owned(),
            windows_alias_plan: aliases.pin().clone(),
            native_baseline: baseline.map(|refresh| refresh.old_facts().pin().clone()),
            native_baseline_inspection_sha256: baseline
                .map(|refresh| refresh.report().old_inspection_sha256.clone()),
        };
        let value = SourceCacheOriginPins {
            schema_version: 2,
            source: self.source.binding().clone(),
            policy: self.policy,
            resource_admission: self.admission,
            source_manifest: metadata("source-manifest.json")?,
            source_frozen: metadata("source-frozen.json")?,
            inspection_read_coverage: metadata("inspection-read-coverage.json")?,
            source_assessment: metadata("source-resource-assessment.json")?,
            native_witness: metadata("source-native-witness.json")?,
            native_pages: pin(native)?,
            cancelled_preparation_intent: pin(&guard_owner)?,
            cancelled_preparation_state: None,
            generation: Some(generation),
        };
        value.validate(self.source.binding(), self.admission.budget, self.policy)?;
        Ok(value)
    }
}

impl SourceCacheOriginPins {
    pub fn canonical_sha256(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self)?).into())
    }

    /// What the saved Windows view of the source did not read: the record
    /// its native witness holds where the run that took it verified once,
    /// none where it read every stream. Only the pinned witness is read,
    /// and nothing else is opened.
    pub(crate) fn windows_content_reads_skipped(&self) -> Result<Option<serde_json::Value>> {
        let pin = &self.native_witness;
        ensure!(
            pin.bytes <= 16 * 1024 * 1024,
            "the saved native witness {} is {} bytes, more than 16 MiB",
            pin.path.display(),
            pin.bytes
        );
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&pin.path)
            .with_context(|| format!("opening the saved native witness {}", pin.path.display()))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::try_from(pin.bytes)?)?;
        file.take(pin.bytes + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading the saved native witness {}", pin.path.display()))?;
        ensure!(
            bytes.len() as u64 == pin.bytes && hex::encode(Sha256::digest(&bytes)) == pin.sha256,
            "the saved native witness {} differs from its pin",
            pin.path.display()
        );
        let witness: NativeWitnessCache = serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding the saved native witness {}", pin.path.display()))?;
        Ok(witness.content_reads_skipped)
    }

    fn validate(
        &self,
        binding: &GeneralDiskBinding,
        budget: ResourceBudget,
        policy: VerificationPolicy,
    ) -> Result<()> {
        self.resource_admission.validate()?;
        ensure!(
            matches!(self.schema_version, 1 | 2)
                && (self.schema_version == 1) == self.generation.is_none()
                && (self.schema_version != 1 || self.cancelled_preparation_state.is_some())
                && self.source == *binding
                && binding.layout_profile
                    == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && self.policy == VerificationPolicy::ExtentIdentityV1
                && self.policy == policy
                && self.resource_admission.schema_version == 2
                && self.resource_admission.budget == budget,
            "exact cache requires same offline-Windows extent policy and original wire bounds"
        );
        for pin in [
            &self.source_manifest,
            &self.source_frozen,
            &self.inspection_read_coverage,
            &self.source_assessment,
            &self.native_witness,
            &self.native_pages,
            &self.cancelled_preparation_intent,
        ] {
            let _ = digest(&pin.sha256)?;
            ensure!(
                pin.bytes > 0 && pin.path.is_absolute(),
                "explicit bounded cache origin pin required"
            );
        }
        if let Some(pin) = &self.cancelled_preparation_state {
            digest(&pin.sha256)?;
            ensure!(
                pin.bytes > 0 && pin.path.is_absolute(),
                "legacy cancellation state pin differs"
            );
        }
        if let Some(generation) = &self.generation {
            ensure!(
                generation.schema_version == 1
                    && generation.expected.bytes > 0
                    && generation.expected.path.is_absolute()
                    && generation.native_baseline.is_some()
                        == generation.native_baseline_inspection_sha256.is_some(),
                "source generation dependency schema differs"
            );
            digest(&generation.expected.sha256)?;
            digest(&generation.expected_semantic_sha256)?;
            if let Some(pin) = &generation.prior_origin_sha256 {
                digest(pin)?;
            }
            if let Some(pin) = &generation.prior_preparation_intent {
                digest(&pin.sha256)?;
                ensure!(
                    pin.bytes > 0 && pin.path.is_absolute(),
                    "source generation prior guard differs"
                );
            }
            if let Some(pin) = &generation.native_baseline_inspection_sha256 {
                digest(pin)?;
            }
        }
        Ok(())
    }

    pub(super) fn open_raw(
        &self,
        source: &mut GeneralFrozenPartition,
        budget: ResourceBudget,
        scratch: &SourceScratch,
        _source_group: &ArtifactGroupPermit,
        arena: &ArtifactArena,
        output: &Path,
        expected_origin: [u8; 32],
        events: &mut Vec<NativeEvent>,
    ) -> Result<(PagedInspection, InspectionReadCoverage, OpenedSourceCache)> {
        self.validate(
            source.binding(),
            budget,
            VerificationPolicy::ExtentIdentityV1,
        )?;
        ensure!(
            self.canonical_sha256()? == expected_origin,
            "independent cache origin checksum differs"
        );
        let memory = scratch.lease_ram(
            budget
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(16 * 1024 * 1024))
                .context("cache cold-open RAM overflow")?,
        )?;
        // Keep the authenticated prior snapshot and the new raw inspector in
        // separate already-budgeted shares; importing is not a second copy.
        let auxiliary_group =
            arena.reserve_group(ArtifactGroup::Auxiliary, scratch.budget().scratch_bytes)?;
        let cached_scratch =
            SourceScratch::new_auxiliary_in_arena(scratch.budget(), auxiliary_group.clone())?;
        let mut artifacts = Vec::new();
        let mut adopted = BTreeMap::<PathBuf, (String, u64)>::new();
        let mut adopt = |pin: &SourceCacheFilePin| -> Result<()> {
            if let Some((sha, bytes)) = adopted.get(&pin.path) {
                ensure!(
                    sha == &pin.sha256 && *bytes == pin.bytes,
                    "same cache path has conflicting pins"
                );
                return Ok(());
            }
            let lease = auxiliary_group.adopt_existing(&pin.path, &pin.sha256, pin.bytes)?;
            ensure!(
                lease.wire_bytes() == pin.bytes,
                "cache origin actual byte length differs"
            );
            adopted.insert(pin.path.clone(), (pin.sha256.clone(), pin.bytes));
            artifacts.push(lease);
            Ok(())
        };
        for pin in [
            &self.source_manifest,
            &self.source_frozen,
            &self.inspection_read_coverage,
            &self.source_assessment,
            &self.native_witness,
            &self.cancelled_preparation_intent,
        ] {
            ensure!(
                pin.bytes <= 16 * 1024 * 1024,
                "cache origin JSON/state metadata exceeds16MiB"
            );
            adopt(pin)?;
        }
        if let Some(pin) = &self.cancelled_preparation_state {
            adopt(pin)?;
        }
        let load = |pin: &SourceCacheFilePin| -> Result<Vec<u8>> {
            let file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&pin.path)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(usize::try_from(pin.bytes)?)?;
            file.take(pin.bytes + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == pin.bytes
                    && hex::encode(Sha256::digest(&bytes)) == pin.sha256,
                "cache origin changed after adoption"
            );
            Ok(bytes)
        };
        let raw_pin: SourceInspectionPin = serde_json::from_slice(&load(&self.source_manifest)?)?;
        let frozen: FrozenCache = serde_json::from_slice(&load(&self.source_frozen)?)?;
        let coverage: fp::ReadCoverageReport =
            serde_json::from_slice(&load(&self.inspection_read_coverage)?)?;
        let assessment: AssessmentCache = serde_json::from_slice(&load(&self.source_assessment)?)?;
        let witness: NativeWitnessCache = serde_json::from_slice(&load(&self.native_witness)?)?;
        let inspection = hex::encode(self.resource_admission.source_inspection_sha256);
        ensure!(
            assessment.binding == self.source
                && assessment.budget == budget
                && assessment.resource_admission == self.resource_admission
                && assessment.policy == self.policy
                && assessment.source_inspection_sha256 == inspection
                && frozen.binding == self.source
                && frozen.inspection_sha256 == inspection
                && frozen.fingerprint.source_inspection_sha256 == inspection
                && frozen.fingerprint.policy == self.policy
                && frozen.source_sha256 == assessment.source_sha256
                && witness.kind == "actual-protected-resource-source-native-witness"
                && witness.source_inspection_sha256 == inspection
                && witness.source_fingerprint_before_native == frozen.source_sha256
                && witness.native_pages_sha256 == self.native_pages.sha256,
            "cache origin source/raw/fingerprint/native provenance differs"
        );
        let old = crate::resource_preparation::early_guard::inspect_routes(
            &self.cancelled_preparation_intent.path,
            digest(&self.cancelled_preparation_intent.sha256)?,
            self.cancelled_preparation_intent.bytes,
        )?;
        ensure!(
            old.phase == "Cancelled" && old.delegated.is_none() && old.source == self.source,
            "source cache requires the actual old nondelegated Cancelled epoch"
        );
        // SourcePagePin graphs are bounded by the already prepaid metadata row.
        // Every leaf is newly adopted; no old artifact seal/owner is recovered.
        let mut pages = BTreeMap::<PathBuf, SourcePagePin>::new();
        fn page_pins(
            value: serde_json::Value,
            out: &mut BTreeMap<PathBuf, SourcePagePin>,
        ) -> Result<()> {
            match value {
                serde_json::Value::Object(map) => {
                    if map.contains_key("file_sha256")
                        && map.contains_key("logical_sha256")
                        && map.contains_key("wire_bytes")
                        && map.contains_key("chunk_bytes")
                    {
                        let pin: SourcePagePin =
                            serde_json::from_value(serde_json::Value::Object(map))?;
                        if let Some(old) = out.get(&pin.path) {
                            ensure!(old == &pin, "conflicting cache page leaf");
                        } else {
                            out.insert(pin.path.clone(), pin);
                        }
                        return Ok(());
                    }
                    for (_, value) in map {
                        page_pins(value, out)?;
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        page_pins(value, out)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        page_pins(serde_json::to_value(&raw_pin)?, &mut pages)?;
        page_pins(serde_json::to_value(&frozen.fingerprint)?, &mut pages)?;
        page_pins(serde_json::to_value(&coverage)?, &mut pages)?;
        if let Some(generation) = &self.generation {
            page_pins(
                serde_json::to_value(&generation.native_baseline)?,
                &mut pages,
            )?;
        }
        for pin in pages.values() {
            adopt(&SourceCacheFilePin {
                path: pin.path.clone(),
                sha256: pin.file_sha256.clone(),
                bytes: pin.wire_bytes,
            })?;
        }
        drop(adopt);
        let previous_fingerprint = frozen.fingerprint.open(&cached_scratch)?;
        let payer = SourceNativeMemory(arena.clone());
        let exact = source.verify_cached_source_continuity(
            &previous_fingerprint,
            digest(&frozen.source_sha256)?,
            expected_origin,
            &payer,
            events,
        );
        let native_baseline = self
            .generation
            .as_ref()
            .and_then(|g| g.native_baseline.as_ref())
            .unwrap_or(&raw_pin);
        let native_inspection = self
            .generation
            .as_ref()
            .and_then(|g| g.native_baseline_inspection_sha256.as_deref())
            .unwrap_or(&inspection);
        let (raw, reads, fingerprint, continuity, mut refresh, raw_reinspected) = match exact {
            Ok(continuity) => {
                let raw = PagedInspection::open_cached_exact(
                    &raw_pin,
                    source,
                    &continuity,
                    expected_origin,
                    &cached_scratch,
                    events,
                )?;
                let reads = InspectionReadCoverage::open_cached_revalidated(
                    coverage,
                    &continuity,
                    &cached_scratch,
                    source.byte_len(),
                )?;
                (raw, reads, previous_fingerprint, continuity, None, false)
            }
            Err(error) => {
                if error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<n2r_win32::SourceCacheFingerprintMismatch>())
                    .is_none()
                {
                    return Err(error.into());
                }
                println!(
                    "Saved NTFS metadata changed; refreshing raw metadata and checking every saved user object."
                );
                std::io::stdout().flush()?;
                let old = PagedInspection::open_cached_facts(
                    native_baseline,
                    native_inspection,
                    &auxiliary_group,
                    &cached_scratch,
                )?;
                let length = source.byte_len();
                let (raw, reads) = fp::inspect_recorded_with_layout_scope(
                    source,
                    length,
                    budget,
                    self.policy,
                    &output.join("refreshed-source"),
                    scratch,
                    self.source.layout_profile,
                )?;
                let refresh = super::cache_refresh::compare_user_semantics(
                    old,
                    &raw,
                    &self.source,
                    digest(&self.native_pages.sha256)?,
                    &output.join("user-semantic-refresh"),
                    &cached_scratch,
                )?;
                let fingerprint = PagedSourceFingerprint::for_inspection(
                    &raw,
                    length,
                    self.policy,
                    &output.join("refreshed-fingerprint"),
                )?;
                fingerprint.validate_inspection_reads(&reads)?;
                let current = digest(&fingerprint.hash(source)?)?;
                let continuity = source.verify_cached_source_continuity(
                    &fingerprint,
                    current,
                    expected_origin,
                    &payer,
                    events,
                )?;
                (raw, reads, fingerprint, continuity, Some(refresh), true)
            }
        };
        // Extent policy can omit initialized payload from its fingerprint
        // while an old small/otherwise-ineligible stream still claims a
        // COMPLETE logical digest. Renew those claims from actual bytes.
        let mut fresh_complete_streams_verified = 0u64;
        let mut fresh_complete_payload_bytes = 0u64;
        let mut buffer = vec![0; 1024 * 1024];
        for ordinal in 0..if raw_reinspected { 0 } else { raw.file_count() } {
            let file = raw.file(ordinal)?;
            if file.is_directory
                || file.is_metadata
                || file.record_number < 16
                || file.metadata_role != crate::ntfs_inspect::MetadataRole::OutsideExtendCandidate
            {
                continue;
            }
            for stream in &file.streams {
                if stream.resident
                    || stream.flags != 0
                    || stream.initialized_size != stream.logical_size
                    || stream.logical_hash_status
                        != crate::ntfs_inspect::LogicalHashStatus::Complete
                {
                    continue;
                }
                let expected = stream
                    .logical_sha256
                    .as_deref()
                    .context("cached complete digest absent")?;
                if stream.logical_size == 0 {
                    ensure!(
                        n2r_win32::content_digest::of(&[]) == expected,
                        "cached empty stream digest differs"
                    );
                    fresh_complete_streams_verified = fresh_complete_streams_verified
                        .checked_add(1)
                        .context("cached empty-stream count overflow")?;
                    continue;
                }
                let mut session = crate::ntfs_inspect::PlainStreamRangeSession::open_named_domain(
                    source,
                    &raw,
                    file.record_number,
                    &stream.name_utf16,
                    stream.logical_size,
                )?;
                let mut transfer = crate::ntfs_inspect::StreamTransferBudget::new(
                    stream.logical_size,
                    stream.logical_size,
                )?;
                let mut hash = n2r_win32::content_digest::Hasher::new();
                let mut at = 0;
                while at < stream.logical_size {
                    let count = (stream.logical_size - at).min(buffer.len() as u64) as usize;
                    session.read_domain(source, &raw, at, &mut buffer[..count], &mut transfer)?;
                    hash.update(&buffer[..count]);
                    at += count as u64;
                }
                session.finish_domain(source, &raw)?;
                ensure!(
                    hash.finish() == expected,
                    "cached COMPLETE user payload digest changed at FILE {} stream {:?}; preserve shadow and require explicit refreshed source evidence",
                    file.record_number,
                    stream.name_utf16
                );
                fresh_complete_streams_verified = fresh_complete_streams_verified
                    .checked_add(1)
                    .context("cached complete-stream count overflow")?;
                fresh_complete_payload_bytes = fresh_complete_payload_bytes
                    .checked_add(stream.logical_size)
                    .context("cached complete-byte total overflow")?;
            }
        }
        drop(buffer);
        // Native page headers still describe their original raw generation.
        // Reuse the latest raw fingerprint without pretending those immutable
        // native bytes were rewritten. Renew the typed semantic join against
        // their original raw baseline after COMPLETE payload claims close.
        if refresh.is_none() && native_inspection != inspection {
            let old = PagedInspection::open_cached_facts(
                native_baseline,
                native_inspection,
                &auxiliary_group,
                &cached_scratch,
            )?;
            refresh = Some(super::cache_refresh::compare_user_semantics(
                old,
                &raw,
                &self.source,
                digest(&self.native_pages.sha256)?,
                &output.join("reopened-native-semantic-join"),
                &cached_scratch,
            )?);
        }
        fingerprint.validate_inspection_reads(&reads)?;
        // Cold decoders now carry their own actual page/cache leases. Keep
        // only registry/path ownership plus one small origin-state allowance.
        let retained = (artifacts.capacity() as u64)
            .checked_mul(std::mem::size_of::<ArtifactLease>() as u64)
            .and_then(|n| n.checked_add(1024 * 1024))
            .context("cached artifact owner RAM overflow")?;
        let mut memory = memory;
        memory.shrink_to(retained)?;
        Ok((
            raw,
            reads,
            OpenedSourceCache {
                fingerprint: Some(fingerprint),
                continuity: Some(continuity),
                native: self.native_pages.clone(),
                origin_sha256: expected_origin,
                artifacts,
                fresh_complete_streams_verified,
                fresh_complete_payload_bytes,
                refresh,
                windows_content_reads_skipped: witness.content_reads_skipped,
                auxiliary_group,
                _memory: memory,
            },
        ))
    }
}
