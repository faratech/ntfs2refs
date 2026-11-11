//! Strict old/fresh USER semantic join for a metadata-refreshed source epoch.
//! This owns historical facts and bounded proof rows, never a frozen source,
//! native observation, admission certificate, write owner or saved success flag.
use crate::{
    ntfs_admission,
    ntfs_inspect::{
        FileInventory, PagedInspection, RootFileDomain,
        paged_storage::{SourceRamLease, SourceScratch},
        record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
    },
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    SourceCacheRefreshDomain, SourceCacheRefreshRow,
    attestation::FileIdentity,
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    path::Path,
};

const PURPOSE: [u8; 8] = *b"N2RUSJ01";
const SAMPLE_LIMIT: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserSemanticRefreshRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub old_raw_row_sha256: String,
    pub new_raw_row_sha256: String,
    pub old_user_semantic_sha256: String,
    pub new_user_semantic_sha256: String,
    pub recognized_internal_disposition: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserSemanticMismatch {
    pub record_number: u64,
    pub sequence_number: u16,
    pub changed_fields: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserSemanticRefreshReport {
    pub kind: &'static str,
    pub old_inspection_sha256: String,
    pub new_inspection_sha256: String,
    pub old_native_sha256: String,
    pub records: u64,
    pub user_records: u64,
    pub unchanged_user_records: u64,
    pub recognized_internal_records: u64,
    pub changed_recognized_internal_records: u64,
    pub complete_user_streams_compared: u64,
    pub complete_user_logical_bytes: u64,
    pub extent_only_user_streams: u64,
    pub mismatched_user_records: u64,
    pub mismatch_samples: Vec<UserSemanticMismatch>,
    pub mismatch_samples_truncated: bool,
    pub all_user_fields_unchanged: bool,
    pub proof_rows: Option<RecordStorePin>,
    pub join_sha256: String,
    pub whole_user_payload_content_unchanged_claimed: bool,
    pub source_admission_issued: bool,
    pub native_rows_recollected: bool,
}

/// The actual baseline readers/leases remain owned. Fresh raw metadata stays
/// with the caller and is independently bound by the SDK's new continuity.
pub(crate) struct UserSemanticRefresh {
    old_facts: PagedInspection,
    rows: SortedRecordStore,
    report: UserSemanticRefreshReport,
    old_inspection: [u8; 32],
    new_inspection: [u8; 32],
    old_native: [u8; 32],
    projected_roles: Vec<String>,
    _role_memory: Vec<SourceRamLease>,
    _memory: SourceRamLease,
}

fn digest(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical semantic-refresh SHA256 required"
    );
    Ok(hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("semantic-refresh SHA width differs"))?)
}
fn key(number: u64) -> [u8; 16] {
    let mut value = [0; 16];
    value[..8].copy_from_slice(&number.to_be_bytes());
    value
}

struct HashWriter {
    hash: Sha256,
    bytes: u64,
    maximum: u64,
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or_else(|| io::Error::other("semantic row exceeds admitted serialization bound"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn row_hash(row: &impl Serialize, maximum: u64) -> Result<[u8; 32]> {
    let mut writer = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
        maximum,
    };
    serde_json::to_writer(&mut writer, row)?;
    Ok(writer.hash.finalize().into())
}
fn stored_security(
    source: &PagedInspection,
    file: &FileInventory,
    role: Option<&str>,
) -> Result<Option<String>> {
    let Some(binding) = source.security().find_binding(file.record_number)? else {
        ensure!(
            role == Some("reserved_mft_slot"),
            "USER/current internal record lacks its complete security binding"
        );
        return Ok(None);
    };
    ensure!(
        binding.record_number == file.record_number
            && binding.sequence_number == file.sequence_number,
        "semantic-refresh security binding identity differs"
    );
    let descriptor = if let Some(id) = binding.security_id {
        source.security().find_id(id)?
    } else {
        source.security().find_legacy(file.record_number)?
    }
    .context("semantic-refresh stored descriptor absent")?;
    let bytes = hex::decode(&descriptor.descriptor.relative_hex)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == binding.descriptor_sha256
            && descriptor.descriptor.sha256 == binding.descriptor_sha256,
        "semantic-refresh stored security bytes/digest differ"
    );
    crate::ntfs_security::parse_descriptor_with_limit(&bytes, source.budget().record_bytes)?;
    Ok(Some(descriptor.descriptor.relative_hex))
}
fn semantic_hash(row_sha: [u8; 32], security: Option<&str>) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"n2r-strict-user-file-and-full-stored-SD-v1\0");
    hash.update(row_sha);
    hash.update([u8::from(security.is_some())]);
    if let Some(hex) = security {
        let bytes = hex::decode(hex)?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}
fn changed_fields(
    old: &FileInventory,
    new: &FileInventory,
    old_sd: Option<&str>,
    new_sd: Option<&str>,
    maximum: u64,
) -> Result<Vec<&'static str>> {
    let mut fields = Vec::new();
    if old.hard_link_count != new.hard_link_count
        || old.base_file_reference != new.base_file_reference
        || old.is_directory != new.is_directory
        || old.is_metadata != new.is_metadata
        || old.metadata_role != new.metadata_role
        || old.metadata_role_issue != new.metadata_role_issue
    {
        fields.push("identity_type_links_or_role");
    }
    if row_hash(&old.names, maximum)? != row_hash(&new.names, maximum)? {
        fields.push("all_names_namespaces_and_parent_references");
    }
    if row_hash(&old.standard_information, maximum)?
        != row_hash(&new.standard_information, maximum)?
    {
        fields.push("all_STANDARD_INFORMATION_times_attributes_security_id");
    }
    if row_hash(&old.streams, maximum)? != row_hash(&new.streams, maximum)? {
        fields.push("all_stream_names_EOF_VDL_flags_runs_and_logical_digests");
    }
    if row_hash(&old.attributes, maximum)? != row_hash(&new.attributes, maximum)? {
        fields.push("complete_source_attribute_inventory_and_resident_digests");
    }
    if row_hash(&old.extended_attributes, maximum)? != row_hash(&new.extended_attributes, maximum)?
    {
        fields.push("full_raw_and_parsed_extended_attributes");
    }
    if row_hash(&old.reparse, maximum)? != row_hash(&new.reparse, maximum)? {
        fields.push("complete_reparse_bytes");
    }
    if old_sd != new_sd {
        fields.push("complete_stored_security_descriptor_bytes");
    }
    if fields.is_empty() {
        fields.push("other_serialized_user_field");
    }
    Ok(fields)
}

/// Fresh extent-policy inspection must recompute COMPLETE hashes and current
/// extent assertions. No field is cleared or normalized to make this join pass.
/// Internal changes require the SAME exact existing policy role on both sides;
/// no `is_metadata` exemption or identity/sequence replacement is allowed.
pub(crate) fn compare_user_semantics(
    mut old_facts: PagedInspection,
    fresh: &PagedInspection,
    binding: &GeneralDiskBinding,
    old_native_sha256: [u8; 32],
    output: &Path,
    scratch: &SourceScratch,
) -> Result<UserSemanticRefresh> {
    binding.validate()?;
    ensure!(
        old_facts.is_cached_facts()
            && fresh.is_windows_conversion()
            && binding.layout_profile == GeneralDiskLayoutProfile::OfflineWindows
            && old_facts.header().geometry == fresh.header().geometry
            && old_facts.header().inventory_complete
            && fresh.header().inventory_complete
            && old_facts.file_count() == fresh.file_count()
            && old_native_sha256 != [0; 32],
        "strict refresh requires complete same-geometry baseline/fresh Windows domains and native origin"
    );
    ensure!(
        fresh.header().geometry.volume_size == binding.identity.partition_bytes
            || fresh
                .header()
                .geometry
                .volume_size
                .checked_add(u64::from(fresh.header().geometry.bytes_per_sector))
                == Some(binding.identity.partition_bytes),
        "semantic-refresh fresh source does not match actual partition geometry"
    );
    old_facts.revalidate()?;
    fresh.revalidate()?;
    let maximum = old_facts
        .budget()
        .record_bytes
        .max(fresh.budget().record_bytes);
    let working = scratch.lease_ram(
        maximum
            .checked_mul(16)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .context("paired USER semantic row RAM overflow")?,
    )?;
    let memory = scratch.lease_ram(64 * 1024)?;
    let old_hash = old_facts.canonical_sha256()?;
    let new_hash = fresh.canonical_sha256()?;
    let old_inspection = digest(&old_hash)?;
    let new_inspection = digest(&new_hash)?;
    let mut writer = SortedRecordWriter::new(output, PURPOSE, scratch)?;
    let mut report = UserSemanticRefreshReport {
        kind: "strict-user-source-metadata-refresh-join-v1",
        old_inspection_sha256: old_hash,
        new_inspection_sha256: new_hash,
        old_native_sha256: hex::encode(old_native_sha256),
        records: 0,
        user_records: 0,
        unchanged_user_records: 0,
        recognized_internal_records: 0,
        changed_recognized_internal_records: 0,
        complete_user_streams_compared: 0,
        complete_user_logical_bytes: 0,
        extent_only_user_streams: 0,
        mismatched_user_records: 0,
        mismatch_samples: Vec::new(),
        mismatch_samples_truncated: false,
        all_user_fields_unchanged: false,
        // Installed only after the writer closes; never serialized as success before then.
        proof_rows: None,
        join_sha256: String::new(),
        whole_user_payload_content_unchanged_claimed: false,
        source_admission_issued: false,
        native_rows_recollected: false,
    };
    let mut join = Sha256::new();
    let mut projected_roles = Vec::new();
    let mut role_memory = Vec::new();
    join.update(b"n2r-user-refresh-ordered-join-v1\0");
    join.update(old_inspection);
    join.update(new_inspection);
    join.update(old_native_sha256);
    for ordinal in 0..old_facts.file_count() {
        let old = old_facts.file(ordinal)?;
        let new = fresh.file(ordinal)?;
        ensure!(
            old.record_number == new.record_number && old.sequence_number == new.sequence_number,
            "cached native row coverage changed at ordinal {ordinal}: old FILE {}/{} new FILE {}/{}; targeted/new identity evidence is required",
            old.record_number,
            old.sequence_number,
            new.record_number,
            new.sequence_number
        );
        let old_role = ntfs_admission::paged::internal_role(&old_facts, &old)?;
        let new_role = ntfs_admission::paged::internal_role(fresh, &new)?;
        ensure!(
            old_role == new_role,
            "USER/internal replacement role changed at FILE {}",
            old.record_number
        );
        let role = old_role.as_ref().cloned().or_else(|| {
            (old.record_number == 5
                && old
                    .attributes
                    .iter()
                    .any(ntfs_admission::recognized_root_txf))
            .then(|| "root:$TXF_DATA (not yet admitted for replacement)".to_owned())
        });
        if let Some(role) = role {
            let lease = scratch.lease_ram(
                (role.len() as u64)
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(1024))
                    .context("projection role RAM overflow")?,
            )?;
            projected_roles.push(role);
            role_memory.push(lease);
        }
        let old_raw = row_hash(&old, maximum)?;
        let new_raw = row_hash(&new, maximum)?;
        let old_sd = stored_security(&old_facts, &old, old_role.as_deref())?;
        let new_sd = stored_security(fresh, &new, new_role.as_deref())?;
        let old_sem = semantic_hash(old_raw, old_sd.as_deref())?;
        let new_sem = semantic_hash(new_raw, new_sd.as_deref())?;
        ensure!(
            old_sem != [0; 32] && new_sem != [0; 32],
            "zero USER semantic digest is invalid"
        );
        let same = old_sem == new_sem;
        if old_role.is_some() {
            report.recognized_internal_records += 1;
            if !same {
                report.changed_recognized_internal_records += 1;
            }
        } else {
            report.user_records += 1;
            if same {
                report.unchanged_user_records += 1;
            } else {
                report.mismatched_user_records += 1;
                if report.mismatch_samples.len() < SAMPLE_LIMIT {
                    report.mismatch_samples.push(UserSemanticMismatch {
                        record_number: old.record_number,
                        sequence_number: old.sequence_number,
                        changed_fields: changed_fields(
                            &old,
                            &new,
                            old_sd.as_deref(),
                            new_sd.as_deref(),
                            maximum,
                        )?,
                    });
                } else {
                    report.mismatch_samples_truncated = true;
                }
            }
            for stream in &new.streams {
                match stream.logical_hash_status {
                    crate::ntfs_inspect::LogicalHashStatus::Complete => {
                        ensure!(
                            stream
                                .logical_sha256
                                .as_deref()
                                .is_some_and(n2r_win32::content_digest::is_hex),
                            "fresh COMPLETE USER stream lacks its actual digest"
                        );
                        report.complete_user_streams_compared += 1;
                        report.complete_user_logical_bytes = report
                            .complete_user_logical_bytes
                            .checked_add(stream.logical_size)
                            .context("complete USER byte total overflow")?;
                    }
                    crate::ntfs_inspect::LogicalHashStatus::NotReadExtentIdentityV1 => {
                        ensure!(
                            stream.logical_sha256.is_none(),
                            "extent-only USER stream has a content digest"
                        );
                        report.extent_only_user_streams += 1;
                    }
                    _ => anyhow::bail!(
                        "fresh USER stream has incomplete content/extent evidence at FILE {}",
                        new.record_number
                    ),
                }
            }
        }
        let row = UserSemanticRefreshRecord {
            record_number: old.record_number,
            sequence_number: old.sequence_number,
            old_raw_row_sha256: hex::encode(old_raw),
            new_raw_row_sha256: hex::encode(new_raw),
            old_user_semantic_sha256: hex::encode(old_sem),
            new_user_semantic_sha256: hex::encode(new_sem),
            recognized_internal_disposition: old_role,
        };
        writer.push(key(row.record_number), &row)?;
        join.update(row.record_number.to_le_bytes());
        join.update(row.sequence_number.to_le_bytes());
        join.update(old_sem);
        join.update(new_sem);
        if let Some(role) = row.recognized_internal_disposition.as_deref() {
            join.update((role.len() as u64).to_le_bytes());
            join.update(role.as_bytes());
        } else {
            join.update(0u64.to_le_bytes());
        }
        report.records += 1;
    }
    let proof_rows = writer.finish()?;
    let rows = SortedRecordStore::open(&proof_rows, scratch)?;
    report.proof_rows = Some(proof_rows);
    ensure!(
        rows.len() == old_facts.file_count(),
        "strict semantic join omitted a source row"
    );
    report.join_sha256 = hex::encode(join.finalize());
    report.all_user_fields_unchanged = report.mismatched_user_records == 0;
    old_facts.revalidate()?;
    fresh.revalidate()?;
    old_facts.release_inventory_resident_cache();
    drop(working);
    Ok(UserSemanticRefresh {
        old_facts,
        rows,
        report,
        old_inspection,
        new_inspection,
        old_native: old_native_sha256,
        projected_roles,
        _role_memory: role_memory,
        _memory: memory,
    })
}

impl UserSemanticRefresh {
    pub(super) fn expected_reuse_facts(
        &self,
        current: &str,
        native: &str,
        body: &crate::shadow_tree::PagedExpectedTree,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<crate::shadow_tree::ExpectedBindingFacts> {
        n2r_win32::SourceCacheRefreshDomain::revalidate(self)?;
        ensure!(
            self.new_inspection == digest(current)?
                && self.old_native == digest(native)?
                && self.report.all_user_fields_unchanged
                && self.report.mismatched_user_records == 0
                && self.report.unchanged_user_records == self.report.user_records
                && self.report.user_records == admission.objects()?
                && self.projected_roles.as_slice() == body.internal_replacement_pending(),
            "live strict user join does not prove cached projected body eligibility"
        );
        let facts = crate::shadow_tree::ExpectedBindingFacts {
            schema_version: 1,
            verification_kind: "strict-user-refresh-and-current-projection-v1".into(),
            body_file_sha256: body.file_sha256().to_owned(),
            body_semantic_sha256: body.semantic_sha256().to_owned(),
            original_admission: body
                .header()
                .resource_admission
                .context("cached expected original admission absent")?,
            effective_admission: admission,
            profile: body.profile().to_owned(),
            logical_bytes: body.logical_bytes(),
            objects: body.len() as u64,
            pending_roles: self.projected_roles.clone(),
            native_file_sha256: native.to_owned(),
            user_join_sha256: self.report.join_sha256.clone(),
        };
        facts.validate(admission, body.file_sha256(), body.semantic_sha256())?;
        Ok(facts)
    }
    pub(crate) fn report(&self) -> &UserSemanticRefreshReport {
        &self.report
    }
    pub(crate) fn pin(&self) -> &RecordStorePin {
        self.rows.pin()
    }
    pub(crate) fn old_facts(&self) -> &PagedInspection {
        &self.old_facts
    }
    pub(crate) fn record(&self, index: u64) -> Result<UserSemanticRefreshRecord> {
        self.rows.get(index)
    }
}
impl SourceCacheRefreshDomain for UserSemanticRefresh {
    fn old_inspection_sha256(&self) -> [u8; 32] {
        self.old_inspection
    }
    fn new_inspection_sha256(&self) -> [u8; 32] {
        self.new_inspection
    }
    fn old_native_sha256(&self) -> [u8; 32] {
        self.old_native
    }
    fn len(&self) -> usize {
        self.rows.len() as usize
    }
    fn row(&self, index: usize) -> io::Result<SourceCacheRefreshRow> {
        (|| -> Result<_> {
            let row = self.record(index as u64)?;
            ensure!(
                self.rows.key(index as u64)? == key(row.record_number),
                "semantic proof row key differs"
            );
            Ok(SourceCacheRefreshRow {
                identity: FileIdentity {
                    record_number: row.record_number,
                    sequence_number: row.sequence_number,
                },
                old_user_semantic_sha256: digest(&row.old_user_semantic_sha256)?,
                new_user_semantic_sha256: digest(&row.new_user_semantic_sha256)?,
                recognized_internal_disposition: row.recognized_internal_disposition,
            })
        })()
        .map_err(io::Error::other)
    }
    fn revalidate(&self) -> io::Result<()> {
        (|| -> Result<()> {
            self.old_facts.revalidate()?;
            self.rows.revalidate()?;
            ensure!(
                self.old_facts.canonical_sha256()? == hex::encode(self.old_inspection)
                    && self.rows.len() == self.report.records,
                "strict USER join origin/count changed"
            );
            Ok(())
        })()
        .map_err(io::Error::other)
    }
}
