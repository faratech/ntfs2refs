//! Source/native projection into immutable expected-object pages. This owns
//! construction metadata only, never a source certificate or write authority.
use super::*;
use crate::ntfs_inspect::{
    external_sort::ExternalSort,
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use crate::{
    ntfs_inspect::{PagedInspection, RootFileDomain},
    ntfs_stream_plan::{self, Disposition},
};
use n2r_win32::{attestation::NativeObservationDomain, tree_resources::SourceResourceAdmission};
use serde::ser::{Error as _, SerializeSeq, SerializeStruct};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, cell::Cell, path::Path, sync::Arc};

mod in_order;

#[derive(Serialize, Deserialize)]
struct NameRow {
    folded: String,
}
#[derive(Serialize, Deserialize)]
struct PhysicalRow {
    offset: u64,
    length: u64,
}
#[derive(Serialize, Deserialize)]
struct WindowsTxfDisposition {
    record_number: u64,
    sequence_number: u16,
    source_attribute: ntfs::AttributeInventory,
}

pub struct SourceExpectedDomain {
    objects: SortedRecordStore,
    windows_ea_normalizations: Option<SortedRecordStore>,
    windows_txf_dispositions: Option<SortedRecordStore>,
    windows_object_id_dispositions: Option<SortedRecordStore>,
    windows_object_id_owner: Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>>,
    windows_ea_normalized_entries: u64,
    object_count: usize,
    admission: SourceResourceAdmission,
    profile: String,
    logical_bytes: u64,
    internal_replacement_pending: Vec<String>,
    source_inspection_sha256: String,
    files: u64,
    directories: u64,
    streams: u64,
    scratch: SourceScratch,
    _role_ram: Vec<SourceRamLease>,
    _row_ram: SourceRamLease,
}

/// Retains the real immutable projection files after their complete semantic
/// comparison. This owner deliberately cannot decode objects or serialize a
/// new projection, and grants no source-admission or conversion authority.
pub(crate) struct ProjectionRevalidationOwner {
    objects: SortedRecordStore,
    windows_ea_normalizations: Option<SortedRecordStore>,
    windows_txf_dispositions: Option<SortedRecordStore>,
    windows_object_id_dispositions: Option<SortedRecordStore>,
    windows_object_id_owner: Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>>,
    _scratch: SourceScratch,
}

impl ProjectionRevalidationOwner {
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.objects.revalidate()?;
        if let Some(records) = &self.windows_ea_normalizations {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_txf_dispositions {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_object_id_dispositions {
            records.revalidate()?;
        }
        if let Some(owner) = &self.windows_object_id_owner {
            owner.revalidate()?;
        }
        Ok(())
    }
}
fn ordered_key(first: u64, second: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&first.to_be_bytes());
    key[8..].copy_from_slice(&second.to_be_bytes());
    key
}
/// What a projected object's key and the root's place are made of, read
/// from its row under [`Object`]'s own field names. Every other field is
/// passed over, and the path's components are counted, not kept.
#[derive(serde::Deserialize)]
struct ObjectHead {
    record_number: u64,
    path: PathDepth,
    directory: bool,
}
/// How many components a path has: a sequence of strings, none of them
/// kept.
struct PathDepth(u64);
impl<'de> serde::Deserialize<'de> for PathDepth {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Component;
        impl<'de> serde::Deserialize<'de> for Component {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                struct Text;
                impl serde::de::Visitor<'_> for Text {
                    type Value = Component;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a path component")
                    }
                    fn visit_str<E: serde::de::Error>(
                        self,
                        _: &str,
                    ) -> std::result::Result<Component, E> {
                        Ok(Component)
                    }
                }
                deserializer.deserialize_str(Text)
            }
        }
        struct Components;
        impl<'de> serde::de::Visitor<'de> for Components {
            type Value = PathDepth;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("the components of a path")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<PathDepth, A::Error> {
                let mut depth = 0u64;
                while sequence.next_element::<Component>()?.is_some() {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| serde::de::Error::custom("path depth overflow"))?;
                }
                Ok(PathDepth(depth))
            }
        }
        deserializer.deserialize_seq(Components)
    }
}
fn add_role(
    roles: &mut Vec<String>,
    leases: &mut Vec<SourceRamLease>,
    role: String,
    scratch: &SourceScratch,
) -> Result<()> {
    // The caller is exclusively the exact finite NTFS internal-role policy
    // (plus root TXF). No arbitrary source object can append a pending role.
    let bytes = (role.capacity() as u64)
        .checked_add(2 * std::mem::size_of::<String>() as u64)
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<SourceRamLease>() as u64))
        .context("replacement-role RAM overflow")?;
    let lease = scratch.lease_ram(bytes)?;
    roles.try_reserve(1)?;
    leases.try_reserve(1)?;
    roles.push(role);
    leases.push(lease);
    Ok(())
}
/// The stored security descriptor of `file`: its bytes, held to the
/// descriptor rules within `maximum_bytes`, and their SHA-256 in hex.
///
/// With `cache` (a run that verifies once), a descriptor that the volume's
/// security stream names by an ID is decoded, checked and hashed once for
/// all the objects bound to that ID. Each object's own binding is still
/// read and held to its sequence and to the digest of the descriptor its ID
/// names, with the same refusals in the same order; what is left out for a
/// second object of the same ID is the same row decoded, the same bytes
/// checked and the same digest computed again. Without it, every object's
/// descriptor is read, checked and hashed by itself, as it always was.
fn stored_descriptor(
    source: &PagedInspection,
    file: &ntfs::FileInventory,
    maximum_bytes: u64,
    cache: Option<&DescriptorCache>,
) -> Result<(Vec<u8>, String)> {
    let binding = source
        .security()
        .find_binding(file.record_number)?
        .context("source descriptor binding absent")?;
    ensure!(
        binding.sequence_number == file.sequence_number,
        "source descriptor sequence differs"
    );
    if let (Some(id), Some(held)) = (binding.security_id, cache.and_then(|cache| cache.0.get()))
        && let Some(held) = held.by_id.get(&id)
    {
        ensure!(
            held.descriptor_sha256 == binding.descriptor_sha256,
            "source descriptor binding hash differs"
        );
        let mut stored = Vec::new();
        stored.try_reserve_exact(held.stored.len()).with_context(|| {
            format!(
                "copying the stored security descriptor {id} of FILE {} from the projection's cache",
                file.record_number
            )
        })?;
        stored.extend_from_slice(&held.stored);
        return Ok((stored, held.stored_sha256.clone()));
    }
    let value = if let Some(id) = binding.security_id {
        source.security().find_id(id)?
    } else {
        source.security().find_legacy(file.record_number)?
    }
    .context("source descriptor bytes absent")?;
    ensure!(
        value.descriptor.sha256 == binding.descriptor_sha256,
        "source descriptor binding hash differs"
    );
    let stored = hex::decode(&value.descriptor.relative_hex)?;
    n2r_win32::security_descriptor::validate_with_limit(&stored, maximum_bytes)?;
    let stored_sha256 = hex::encode(Sha256::digest(&stored));
    if let (Some(id), Some(mut held)) = (
        binding.security_id,
        cache.and_then(|cache| cache.0.get_mut()),
    ) {
        held.keep(id, value.descriptor.sha256, &stored, &stored_sha256);
    }
    Ok((stored, stored_sha256))
}

/// What a projection made in a run that verifies once
/// ([`n2r_win32::verify_policy::verifies_once`]) leaves out of
/// [`build_object`]: a stored descriptor decoded, checked and hashed again
/// for another object of the same security ID (while the cache of them is
/// held, [`DescriptorCache`]); a file's paths taken again for each of its
/// streams, and the canonical paths an extent-identity stream's selector
/// walks again for its classification (the object's own paths, just
/// derived from the same held source, stand for both); and that selector
/// made again for the stream's evidence, which its classification has just
/// established. Only `derive_scoped` makes one, and only in such a run; a
/// thorough run, a diagnosis and the comparison of a cached body with the
/// current projection pass none.
struct VerifiedOnce {
    descriptors: Option<DescriptorCache>,
    stream_facts: ntfs_stream_plan::StreamSourceFacts,
}

/// The descriptors [`stored_descriptor`] has decoded, checked and hashed,
/// by security ID: a cache of the run ([`n2r_win32::evict::Evictable`]),
/// paid for by a fixed lease of cache memory
/// (`SourceScratch::lease_cache_ram`) and given up with it when memory is
/// short. Nothing depends on it: a descriptor it does not hold, because it
/// was given up or the lease is full, is read, checked and hashed again as
/// without it. The lease is fixed, so it does not grow with the number of
/// objects.
struct DescriptorCache(n2r_win32::evict::Evictable<HeldDescriptors>);
struct HeldDescriptors {
    by_id: std::collections::HashMap<u32, HeldDescriptor>,
    bytes: u64,
    // Returned after the descriptors it pays for, when this is given up.
    _lease: SourceRamLease,
}
struct HeldDescriptor {
    // The digest of the descriptor record, which each binding names.
    descriptor_sha256: String,
    stored: Vec<u8>,
    stored_sha256: String,
}
impl DescriptorCache {
    const LEASE_BYTES: u64 = 8 * 1024 * 1024;
    /// The cache, where the run's memory has room for it now.
    fn leased(scratch: &SourceScratch) -> Option<Self> {
        let lease = scratch.lease_cache_ram(Self::LEASE_BYTES).ok()?;
        Some(Self(n2r_win32::evict::Evictable::new(HeldDescriptors {
            by_id: std::collections::HashMap::new(),
            bytes: 0,
            _lease: lease,
        })))
    }
}
impl HeldDescriptors {
    fn keep(&mut self, id: u32, descriptor_sha256: String, stored: &[u8], stored_sha256: &str) {
        // The strings and bytes, and the entry with the table's room for
        // it (a table holds at most twice its entries' room as it grows).
        let entry = std::mem::size_of::<(u32, HeldDescriptor)>() as u64 * 4;
        let bytes =
            (descriptor_sha256.capacity() + stored.len() + stored_sha256.len()) as u64 + entry;
        let Some(total) = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= DescriptorCache::LEASE_BYTES)
        else {
            return;
        };
        if self.by_id.try_reserve(1).is_err() {
            return;
        }
        self.by_id.insert(
            id,
            HeldDescriptor {
                descriptor_sha256,
                stored: stored.to_vec(),
                stored_sha256: stored_sha256.to_owned(),
            },
        );
        self.bytes = total;
    }
}
fn stream_evidence(
    source: &PagedInspection,
    file: &ntfs::FileInventory,
    stream: &ntfs::StreamInventory,
    aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
) -> Result<Option<SourceStreamEvidence>> {
    match stream.logical_hash_status {
        ntfs::LogicalHashStatus::Complete => {
            ensure!(
                stream
                    .logical_sha256
                    .as_deref()
                    .is_some_and(n2r_win32::content_digest::is_hex),
                "complete source stream digest absent"
            );
            Ok(None)
        }
        ntfs::LogicalHashStatus::NotReadExtentIdentityV1 => {
            ensure!(
                stream.logical_sha256.is_none()
                    && (if aliases.is_some() {
                        crate::ntfs_attestation::extent_identity_stream_request_windows_domain(
                            source, file, stream,
                        )?
                    } else {
                        crate::ntfs_attestation::extent_identity_stream_request_domain(
                            source, file, stream, true, true,
                        )?
                    })
                    .is_some(),
                "source extent-only stream is not eligible"
            );
            Ok(Some(
                if n2r_win32::target_cluster::aligned(stream.logical_size) {
                    SourceStreamEvidence::ExtentIdentityV1
                } else {
                    SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1
                },
            ))
        }
        _ => anyhow::bail!("source stream evidence is incomplete"),
    }
}
/// [`stream_evidence`] of a stream that `decision`, its classification in
/// this projection, has just admitted. A stream left unread under the
/// extent-identity policy is admitted (any disposition but `Reject`) only
/// where its classification found its digest absent and its selector
/// eligible, on the same held source and paths: that selector is not made
/// again here. A projection that verifies once calls this; every other
/// calls `stream_evidence`.
fn stream_evidence_classified(
    stream: &ntfs::StreamInventory,
    decision: &ntfs_stream_plan::StreamDecision,
) -> Result<Option<SourceStreamEvidence>> {
    match stream.logical_hash_status {
        ntfs::LogicalHashStatus::Complete => {
            ensure!(
                stream
                    .logical_sha256
                    .as_deref()
                    .is_some_and(n2r_win32::content_digest::is_hex),
                "complete source stream digest absent"
            );
            Ok(None)
        }
        ntfs::LogicalHashStatus::NotReadExtentIdentityV1 => {
            ensure!(
                stream.logical_sha256.is_none() && decision.disposition != Disposition::Reject,
                "source extent-only stream is not eligible"
            );
            Ok(Some(
                if n2r_win32::target_cluster::aligned(stream.logical_size) {
                    SourceStreamEvidence::ExtentIdentityV1
                } else {
                    SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1
                },
            ))
        }
        _ => anyhow::bail!("source stream evidence is incomplete"),
    }
}
/// What the comparison of the raw and Windows views wrote of one object
/// (`source-comparison`, the admission's `ObjectRow` of a
/// `PagedFileComparison`), read under its own field names: the results a
/// run that verifies once takes from there instead of evaluating them again.
#[derive(Deserialize)]
struct ComparedObject {
    native: ComparedViews,
    user_issues: Vec<String>,
}
#[derive(Deserialize)]
struct ComparedViews {
    record_number: u64,
    sequence_number: u16,
    internal_replacement_role: Option<String>,
    metadata: ComparedCheck,
    directory_case: Option<ComparedCheck>,
    case_sensitive_mark: bool,
    timestamps: Option<ComparedTimestamps>,
    security: Option<SecurityFacts>,
}
#[derive(Deserialize)]
struct ComparedCheck {
    matched: bool,
    detail: String,
}
#[derive(Deserialize)]
struct ComparedTimestamps {
    stored: [u64; 4],
}
/// The parts of a [`crate::ntfs_source_view::SecurityView`] the projection
/// uses, evaluated here or taken from the comparison.
#[derive(Deserialize)]
struct SecurityFacts {
    stored_sha256: String,
    api_descriptor_hex: String,
    api_matches_stored: bool,
    api_stable: bool,
    target_must_reproduce_both_views: bool,
}
impl From<crate::ntfs_source_view::SecurityView> for SecurityFacts {
    fn from(view: crate::ntfs_source_view::SecurityView) -> Self {
        Self {
            stored_sha256: view.stored_sha256,
            api_descriptor_hex: view.api_descriptor_hex,
            api_matches_stored: view.api_matches_stored,
            api_stable: view.api_stable,
            target_must_reproduce_both_views: view.target_must_reproduce_both_views,
        }
    }
}
fn compared_key(record_number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&record_number.to_be_bytes());
    key
}

/// What [`build_object`] reads of the held source and of its stores, each
/// asked for where the object's construction uses it, in that order.
///
/// [`LiveReads`] reads each when it is asked, as the construction always
/// did. [`GatheredReads`] answers with what the thread that holds the
/// source read for the object beforehand, by the very same calls (or, for
/// the comparison's row, the row's bytes, decoded when asked), errors
/// included: so the construction refuses an object with the same first
/// refusal either way, and may run on a thread that holds no reader.
trait ObjectReads {
    /// The comparison's row of the object, as `SortedRecordStore::find`
    /// gives it; `None` where there is no comparison store.
    fn compared(&self, record_number: u64) -> Option<Result<Option<ComparedObject>>>;
    /// The object's paths: its canonical paths on a Windows volume (with
    /// its aliases held to the alias domain), its user paths otherwise.
    fn user_paths(&self, file: &ntfs::FileInventory) -> Result<Vec<Vec<String>>>;
    /// The user issues of the object, evaluated here: only where there is
    /// no comparison store.
    fn ordinary_user_issues(
        &self,
        file: &ntfs::FileInventory,
        admission: SourceResourceAdmission,
    ) -> Result<Vec<String>>;
    /// [`stored_descriptor`] of the object.
    fn stored_descriptor(
        &self,
        file: &ntfs::FileInventory,
        maximum_bytes: u64,
    ) -> Result<(Vec<u8>, String)>;
    /// A path to name the object by in a refusal of its case mark.
    fn refused_object_path(&self, file: &ntfs::FileInventory) -> Option<Vec<String>>;
    /// Whether this is a Windows volume's projection (an alias domain).
    fn windows(&self) -> bool;
    /// Whether the alias domain holds a storage-hint normalization.
    fn storage_hint_normalized(&self) -> bool;
    /// Whether the source was inspected for a Windows conversion.
    fn is_windows_conversion(&self) -> bool;
    /// The case mark, stored times and security views of the object from
    /// its native row: only where there is no comparison store.
    fn native_views(
        &self,
        ordinal: u64,
        file: &ntfs::FileInventory,
        stored: &[u8],
        admission: SourceResourceAdmission,
        carry_case_marks: bool,
        case_mark_context: &dyn Fn() -> String,
    ) -> Result<(Option<bool>, [u64; 4], SecurityFacts)>;
    /// The classification of one of the object's streams;
    /// `paths_eligible` as in [`ntfs_stream_plan::classify_stream_known_paths`],
    /// of the paths [`Self::user_paths`] gave.
    fn classify(
        &self,
        file: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        admission: SourceResourceAdmission,
        paths_eligible: bool,
    ) -> Result<ntfs_stream_plan::StreamDecision>;
    /// The evidence of a stream that `decision` has admitted.
    fn stream_evidence(
        &self,
        file: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        decision: &ntfs_stream_plan::StreamDecision,
    ) -> Result<Option<SourceStreamEvidence>>;
}

/// The reads of [`build_object`] made when they are asked for. `compared`
/// as in [`build_object`]; `once` as in [`VerifiedOnce`].
struct LiveReads<'a, N> {
    source: &'a PagedInspection,
    native: &'a N,
    compared: Option<&'a SortedRecordStore>,
    aliases: Option<&'a crate::boot_alias::WindowsAliasDomain>,
    object_ids: Option<&'a crate::object_id_disposition::DataObjectIds>,
    once: Option<&'a VerifiedOnce>,
}
impl<N: NativeObservationDomain> ObjectReads for LiveReads<'_, N> {
    fn compared(&self, record_number: u64) -> Option<Result<Option<ComparedObject>>> {
        self.compared
            .map(|rows| rows.find(compared_key(record_number)))
    }
    fn user_paths(&self, file: &ntfs::FileInventory) -> Result<Vec<Vec<String>>> {
        if let Some(aliases) = self.aliases {
            aliases.user_paths(self.source, file)
        } else {
            ntfs_admission::paged::user_paths(self.source, file)
        }
    }
    fn ordinary_user_issues(
        &self,
        file: &ntfs::FileInventory,
        admission: SourceResourceAdmission,
    ) -> Result<Vec<String>> {
        if let Some(aliases) = self.aliases {
            ntfs_admission::paged::ordinary_user_issues_windows(
                self.source,
                file,
                admission,
                aliases,
            )
        } else {
            ntfs_admission::paged::ordinary_user_issues_data(
                self.source,
                file,
                admission,
                self.object_ids,
            )
        }
    }
    fn stored_descriptor(
        &self,
        file: &ntfs::FileInventory,
        maximum_bytes: u64,
    ) -> Result<(Vec<u8>, String)> {
        stored_descriptor(
            self.source,
            file,
            maximum_bytes,
            self.once.and_then(|once| once.descriptors.as_ref()),
        )
    }
    fn refused_object_path(&self, file: &ntfs::FileInventory) -> Option<Vec<String>> {
        ntfs_admission::paged::refused_object_path(self.source, file)
    }
    fn windows(&self) -> bool {
        self.aliases.is_some()
    }
    fn storage_hint_normalized(&self) -> bool {
        self.aliases
            .is_some_and(|aliases| aliases.storage_hint_normalization().is_some())
    }
    fn is_windows_conversion(&self) -> bool {
        self.source.is_windows_conversion()
    }
    fn native_views(
        &self,
        ordinal: u64,
        file: &ntfs::FileInventory,
        stored: &[u8],
        admission: SourceResourceAdmission,
        carry_case_marks: bool,
        case_mark_context: &dyn Fn() -> String,
    ) -> Result<(Option<bool>, [u64; 4], SecurityFacts)> {
        let native_row = self.native.row_view(usize::try_from(ordinal)?)?;
        let observed = native_row.observation();
        ensure!(
            observed.identity.record_number == file.record_number
                && observed.identity.sequence_number == file.sequence_number
                && observed.open_error.is_none(),
            "actual native row identity/open differs from canonical source"
        );
        let before = observed
            .before
            .as_ref()
            .context("source native before snapshot absent")?;
        let after = observed
            .after
            .as_ref()
            .context("source native after snapshot absent")?;
        // Where the mark is carried over, every directory states the source's:
        // the new directory is made with it, set or not, and held to it. The
        // flags are those the admission read, asked of Windows twice.
        let case_sensitive = if carry_case_marks && file.is_directory {
            Some(
                crate::ntfs_attestation::check_directory_case_observation(
                    file,
                    self.source.header().geometry.serial_number,
                    observed,
                )
                .with_context(case_mark_context)?,
            )
        } else {
            None
        };
        let check_metadata = if self.aliases.is_some() {
            crate::ntfs_source_view::check_metadata_windows_with_limit
        } else {
            crate::ntfs_source_view::check_metadata_with_limit
        };
        let timestamps = check_metadata(
            file,
            self.source.header().geometry.serial_number,
            stored,
            before,
            after,
            admission.budget.max_row_bytes,
        )?;
        let views = crate::ntfs_source_view::check_security_views_with_limit(
            stored,
            before,
            after,
            admission.budget.max_row_bytes,
        )?;
        Ok((
            case_sensitive,
            timestamps.stored,
            SecurityFacts::from(views),
        ))
    }
    fn classify(
        &self,
        file: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        admission: SourceResourceAdmission,
        paths_eligible: bool,
    ) -> Result<ntfs_stream_plan::StreamDecision> {
        // This file's paths were taken just before (from `aliases` on a
        // Windows volume). A projection that verifies once does not take
        // them again for each of its streams, nor the canonical paths an
        // extent-identity stream's selector walks: the same derivation of
        // the same held rows, which has just succeeded.
        match (self.once, self.aliases) {
            (Some(once), _) => ntfs_stream_plan::classify_stream_known_paths(
                &once.stream_facts,
                file,
                stream,
                admission,
                self.aliases.is_some(),
                paths_eligible,
            ),
            (None, Some(aliases)) => ntfs_stream_plan::classify_stream_windows_domain(
                self.source,
                file,
                stream,
                admission,
                aliases,
            ),
            (None, None) => {
                ntfs_stream_plan::classify_stream_domain(self.source, file, stream, admission)
            }
        }
    }
    fn stream_evidence(
        &self,
        file: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        decision: &ntfs_stream_plan::StreamDecision,
    ) -> Result<Option<SourceStreamEvidence>> {
        // Nor does it make that selector again for the stream's evidence:
        // its classification has just made it.
        if self.once.is_some() {
            stream_evidence_classified(stream, decision)
        } else {
            stream_evidence(self.source, file, stream, self.aliases)
        }
    }
}

/// A stored security descriptor and its SHA-256 in hex ([`stored_descriptor`]).
type StoredDescriptor = (Vec<u8>, String);
/// The reads of [`build_object`] for one object of a projection that
/// verifies once and has the comparison's rows, made beforehand by the
/// thread that holds the source ([`GatheredReads::gather`]): each answer is
/// taken once, where the construction asks for it, so that it may run on
/// another thread. The comparison's row is decoded there.
struct GatheredReads<'a> {
    compared: Cell<Option<Result<Option<Vec<u8>>>>>,
    user_paths: Cell<Option<Result<Vec<Vec<String>>>>>,
    descriptor: Cell<Option<Result<StoredDescriptor>>>,
    // Whether the construction asked for a path to name the object by in
    // a refusal (of its case mark): that path is not read beforehand, and
    // such a refusal is made again in turn, where it is read.
    wanted_refused_path: Cell<bool>,
    windows: bool,
    storage_hint_normalized: bool,
    is_windows_conversion: bool,
    stream_facts: &'a ntfs_stream_plan::StreamSourceFacts,
}
impl<'a> GatheredReads<'a> {
    /// Makes, through `live` (which verifies once and has the comparison's
    /// rows), every read the construction of `file` will ask for, and what
    /// holding the answers and constructing the object take, at the most.
    fn gather<N: NativeObservationDomain>(
        live: &LiveReads<'_, N>,
        once: &'a VerifiedOnce,
        rows: &SortedRecordStore,
        file: &ntfs::FileInventory,
        admission: SourceResourceAdmission,
    ) -> (Self, u64) {
        // `SortedRecordStore::find`, with the row's bytes taken and not
        // decoded: the same reads and lookups, counted as a decoding.
        let compared = (|| -> Result<Option<Vec<u8>>> {
            let Some(ordinal) = rows.find_ordinal(compared_key(file.record_number))? else {
                return Ok(None);
            };
            n2r_win32::perf::add_call(n2r_win32::perf::Point::SourceRowDecode);
            rows.get_json(ordinal).map(Some)
        })();
        let user_paths = live.user_paths(file);
        let descriptor = live.stored_descriptor(file, admission.budget.max_row_bytes);
        // The row and what is read for it, the object made of them and its
        // text: each about as large as what it is made of, four times over.
        let read = |bytes: usize| bytes as u64;
        let paths = user_paths.as_ref().map_or(0, |paths| {
            paths
                .iter()
                .flatten()
                .map(|part| read(part.len()) + 32)
                .sum::<u64>()
                + read(paths.len()) * 32
        });
        let workspace = crate::ntfs_inspect::file_heap_bytes(file)
            .ok()
            .and_then(|row| {
                row.checked_add(std::mem::size_of::<ntfs::FileInventory>() as u64)?
                    .checked_add(
                        compared
                            .as_ref()
                            .map_or(0, |row| row.as_ref().map_or(0, |bytes| read(bytes.len()))),
                    )?
                    .checked_add(
                        descriptor
                            .as_ref()
                            .map_or(0, |(stored, hash)| read(stored.len()) + read(hash.len())),
                    )?
                    .checked_add(paths)?
                    .checked_mul(4)?
                    .checked_add(4096)
            })
            .unwrap_or(u64::MAX);
        (
            Self {
                compared: Cell::new(Some(compared)),
                user_paths: Cell::new(Some(user_paths)),
                descriptor: Cell::new(Some(descriptor)),
                wanted_refused_path: Cell::new(false),
                windows: live.windows(),
                storage_hint_normalized: live.storage_hint_normalized(),
                is_windows_conversion: live.is_windows_conversion(),
                stream_facts: &once.stream_facts,
            },
            workspace,
        )
    }
}
/// The answer a construction asks for a second time: it never does.
fn asked_again(what: &str) -> anyhow::Error {
    anyhow::anyhow!("the projection asked for an object's {what} twice")
}
impl ObjectReads for GatheredReads<'_> {
    fn compared(&self, _: u64) -> Option<Result<Option<ComparedObject>>> {
        // `SortedRecordStore::get`'s decoding of the row's bytes.
        Some(
            self.compared
                .take()
                .unwrap_or_else(|| Err(asked_again("comparison row")))
                .and_then(|row| {
                    row.map(|bytes| -> Result<ComparedObject> {
                        Ok(serde_json::from_str(std::str::from_utf8(&bytes)?)?)
                    })
                    .transpose()
                }),
        )
    }
    fn user_paths(&self, _: &ntfs::FileInventory) -> Result<Vec<Vec<String>>> {
        self.user_paths
            .take()
            .unwrap_or_else(|| Err(asked_again("paths")))
    }
    fn ordinary_user_issues(
        &self,
        file: &ntfs::FileInventory,
        _: SourceResourceAdmission,
    ) -> Result<Vec<String>> {
        // A projection with the comparison's rows takes the issues from
        // them and never asks.
        anyhow::bail!(
            "the projection of FILE {} has no comparison row to take its user issues from",
            file.record_number
        )
    }
    fn stored_descriptor(&self, _: &ntfs::FileInventory, _: u64) -> Result<(Vec<u8>, String)> {
        self.descriptor
            .take()
            .unwrap_or_else(|| Err(asked_again("security descriptor")))
    }
    fn refused_object_path(&self, _: &ntfs::FileInventory) -> Option<Vec<String>> {
        // Asked only for the text of a refusal: the object is then built
        // again in turn, where the path is read (`wanted_refused_path`).
        self.wanted_refused_path.set(true);
        None
    }
    fn windows(&self) -> bool {
        self.windows
    }
    fn storage_hint_normalized(&self) -> bool {
        self.storage_hint_normalized
    }
    fn is_windows_conversion(&self) -> bool {
        self.is_windows_conversion
    }
    fn native_views(
        &self,
        _: u64,
        file: &ntfs::FileInventory,
        _: &[u8],
        _: SourceResourceAdmission,
        _: bool,
        _: &dyn Fn() -> String,
    ) -> Result<(Option<bool>, [u64; 4], SecurityFacts)> {
        // As for the user issues: the comparison's row holds these.
        anyhow::bail!(
            "the projection of FILE {} has no comparison row to take its views from",
            file.record_number
        )
    }
    fn classify(
        &self,
        file: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        admission: SourceResourceAdmission,
        paths_eligible: bool,
    ) -> Result<ntfs_stream_plan::StreamDecision> {
        // `LiveReads::classify` of a projection that verifies once.
        ntfs_stream_plan::classify_stream_known_paths(
            self.stream_facts,
            file,
            stream,
            admission,
            self.windows,
            paths_eligible,
        )
    }
    fn stream_evidence(
        &self,
        _: &ntfs::FileInventory,
        stream: &ntfs::StreamInventory,
        decision: &ntfs_stream_plan::StreamDecision,
    ) -> Result<Option<SourceStreamEvidence>> {
        // `LiveReads::stream_evidence` of a projection that verifies once.
        stream_evidence_classified(stream, decision)
    }
}

/// The object a source row projects to, and the EA normalization of a
/// Windows file, from what `reads` reads of the held source.
///
/// Where `reads` has the comparison's store of rows (the run verifies once,
/// `--verify fast`, owner's decision D2, #250), the object's user issues,
/// its metadata and security views and its directory's case mark are those
/// the comparison evaluated for it from the same held source and Windows
/// rows, and the Windows row is not decoded again. Without it they are
/// evaluated here, as every thorough run does.
fn build_object(
    reads: &impl ObjectReads,
    ordinal: u64,
    file: &ntfs::FileInventory,
    admission: SourceResourceAdmission,
    carry_case_marks: bool,
) -> Result<(
    Object,
    Option<crate::ntfs_extended_attributes::WindowsKernelPurgeEaNormalization>,
)> {
    let compared = reads
        .compared(file.record_number)
        .map(|found| -> Result<ComparedObject> {
            let row: ComparedObject = found?
                .with_context(|| {
                    format!(
                        "the comparison of FILE {} with its Windows view is absent from source-comparison",
                        file.record_number
                    )
                })?;
            ensure!(
                row.native.record_number == file.record_number
                    && row.native.sequence_number == file.sequence_number
                    && row.native.internal_replacement_role.is_none(),
                "the comparison row of FILE {} differs from the canonical source object",
                file.record_number
            );
            Ok(row)
        })
        .transpose()?;
    let resources = ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission));
    let mut names = reads.user_paths(file)?;
    ensure!(
        !names.is_empty() && (!file.is_directory || names.len() == 1),
        "missing names or unsupported directory links"
    );
    // Whether these paths keep extent evidence, as an extent-identity
    // stream's selector would find of the same paths derived again.
    let extent_paths_eligible = crate::ntfs_attestation::extent_identity_paths_eligible(&names);
    for name in &names {
        if let Some(part) = name
            .iter()
            .find(|part| !n2r_win32::shadow_names::valid_unicode_component(part))
        {
            anyhow::bail!(
                "\\{} has {}, which the converter does not carry over: rename it",
                name.join("\\"),
                n2r_win32::shadow_names::component_refusal(part)
            );
        }
        ensure!(
            expected_path_fits(name, true),
            "\\{} is a path too long or too deep for the converter to carry over",
            name.join("\\")
        );
    }
    ensure!(
        !file.streams.iter().any(|s| !s.name_utf16.is_empty())
            || names.iter().all(|path| path
                .first()
                .is_none_or(|p| !p.eq_ignore_ascii_case("System Volume Information"))),
        "named System Volume Information payload requires its separate system implementation"
    );
    let path = names.remove(0);
    if file.record_number == 5 {
        ensure!(
            path.is_empty() && file.is_directory && file.streams.is_empty(),
            "invalid source root"
        );
        ensure!(
            file.attributes.iter().all(|a| a.flags == 0
                && a.lowest_vcn == 0
                && ((matches!(a.type_code, 0x10 | 0x30 | 0x50)
                    && a.resident
                    && a.name_utf16.is_empty())
                    || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                        && crate::ntfs_namespace::is_i30(&a.name_utf16))
                    || ntfs_admission::recognized_root_txf(a)
                    || (reads.storage_hint_normalized()
                        && crate::ntfs_storage_class::recognized_default(a)))),
            "unknown root attributes"
        );
    } else {
        let evaluated;
        let issues: &[String] = if let Some(row) = &compared {
            &row.user_issues
        } else {
            evaluated = reads.ordinary_user_issues(file, admission)?;
            &evaluated
        };
        ensure!(
            issues.is_empty(),
            "record {} exceeds shadow profile: {issues:?}",
            file.record_number
        );
    }
    let (stored, stored_sha256) = reads.stored_descriptor(file, admission.budget.max_row_bytes)?;
    let case_mark_context = || {
        format!(
            "the case-sensitive mark of the directory at FILE {} ({})",
            file.record_number,
            reads
                .refused_object_path(file)
                .map(|path| format!("\\{}", path.join("\\")))
                .unwrap_or_else(|| "its path was not read".to_owned())
        )
    };
    if reads.windows() {
        ensure!(
            reads.is_windows_conversion(),
            "Windows projection requires its actual inspection purpose"
        );
    }
    let (case_sensitive, timestamps, views) = if let Some(row) = compared {
        // The comparison opened the object (its metadata check refuses an
        // object Windows did not open) and evaluated these on the same
        // decoding of its Windows row; an evaluation that failed there is
        // this projection's failure, with what the comparison found.
        let row = row.native;
        let case_sensitive = if carry_case_marks && file.is_directory {
            let check = row
                .directory_case
                .context("the comparison of a directory holds no case-sensitivity check")?;
            if !check.matched {
                return Err(anyhow::anyhow!("{}", check.detail)).with_context(case_mark_context);
            }
            Some(row.case_sensitive_mark)
        } else {
            None
        };
        ensure!(row.metadata.matched, "{}", row.metadata.detail);
        (
            case_sensitive,
            row.timestamps
                .context("the comparison holds no timestamp view")?
                .stored,
            row.security
                .context("the comparison holds no security view")?,
        )
    } else {
        reads.native_views(
            ordinal,
            file,
            &stored,
            admission,
            carry_case_marks,
            &case_mark_context,
        )?
    };
    ensure!(
        views.api_stable
            && views.target_must_reproduce_both_views
            && views.stored_sha256 == stored_sha256,
        "source security view differs"
    );
    let si = file
        .standard_information
        .as_ref()
        .context("stored timestamps absent")?;
    let times = [
        si.creation_time,
        si.access_time,
        si.modification_time,
        si.mft_change_time,
    ];
    ensure!(
        timestamps == times,
        "source persisted timestamp projection differs"
    );
    let eas = crate::ntfs_attestation::has_verified_nonempty_eas(file);
    let reparse = crate::ntfs_reparse::file_point(file)?;
    let normalized = si.file_attributes & 0x800 != 0 || file.streams.iter().any(|s| s.flags == 1);
    let projected = crate::ntfs_file_attributes::project_user(file)?;
    ensure!(
        times.iter().all(|t| *t > 0 && *t < i64::MAX as u64)
            && projected.source_attributes
                & !(0x2027
                    | if reparse.is_some() { 0x400 } else { 0 }
                    | if file.streams.iter().any(|s| s.flags == 0x8000) {
                        0x200
                    } else {
                        0
                    }
                    | if eas { 0x40000 } else { 0 }
                    | if normalized { 0x800 } else { 0 })
                == 0,
        "unsupported basic metadata"
    );
    let classify = |stream: &ntfs::StreamInventory| {
        reads.classify(file, stream, admission, extent_paths_eligible)
    };
    let evidence = |stream: &ntfs::StreamInventory, decision: &ntfs_stream_plan::StreamDecision| {
        reads.stream_evidence(file, stream, decision)
    };
    let (source_offset, source_extents, length, sha256, source_evidence, sparse) =
        if let Some(stream) = file.streams.iter().find(|s| s.name_utf16.is_empty()) {
            let decision = classify(stream)?;
            let (offset, extents) = planned_stream_source(Some(&decision), resources)?;
            (
                offset,
                extents,
                stream.logical_size,
                stream.logical_sha256.clone(),
                evidence(stream, &decision)?,
                decision.sparse,
            )
        } else {
            (None, Vec::new(), 0, None, None, None)
        };
    let mut named_streams = Vec::new();
    for stream in file.streams.iter().filter(|s| !s.name_utf16.is_empty()) {
        ensure!(!file.is_directory, "named directory streams unsupported");
        let decision = classify(stream)?;
        ensure!(
            decision.disposition != Disposition::Reject,
            "named source stream candidate refused"
        );
        let (offset, extents) = planned_stream_source(Some(&decision), resources)?;
        named_streams.try_reserve(1)?;
        named_streams.push(NamedStream {
            name_utf16: stream.name_utf16.clone(),
            source_offset: offset,
            source_extents: extents,
            length: stream.logical_size,
            sha256: stream.logical_sha256.clone(),
            source_evidence: evidence(stream, &decision)?,
            sparse: decision.sparse,
        });
    }
    named_streams.sort_by(|a, b| a.name_utf16.cmp(&b.name_utf16));
    let (extended_attributes, ea_normalization) = if reads.windows() {
        ensure!(
            reads.is_windows_conversion(),
            "Windows EA projection requires its actual inspection purpose"
        );
        crate::ntfs_extended_attributes::windows_target_projection(file)?
    } else {
        (crate::ntfs_extended_attributes::file_set(file)?, None)
    };
    Ok((
        Object {
            record_number: file.record_number,
            sequence_number: file.sequence_number,
            path,
            additional_names: names,
            directory: file.is_directory,
            stored_times: times,
            attributes: crate::ntfs_attestation::default_stream_attributes(
                file,
                projected.win32_attributes,
            )? & !if normalized { 0x800 } else { 0 },
            ntfs_compression_normalized: normalized,
            security: stored,
            api_security: if views.api_matches_stored {
                None
            } else {
                Some(hex::decode(views.api_descriptor_hex)?)
            },
            extended_attributes: Some(extended_attributes),
            reparse,
            case_sensitive,
            source_offset,
            source_extents,
            length,
            sha256,
            source_evidence,
            named_streams,
            sparse,
        },
        ea_normalization,
    ))
}

/// The text of an object and of the case-folded keys of its names, made on
/// whichever thread.
struct EncodedRow {
    object_json: Vec<u8>,
    names: Vec<(u64, Vec<u8>)>,
}
/// The text of `object`, held to the admitted working record bytes, and
/// the rows of its names' keys.
fn encode_row(object: &Object, record_limit: u64) -> Result<EncodedRow> {
    let object_json = serde_json::to_vec(object)?;
    ensure!(
        !object_json.is_empty() && (object_json.len() as u64) <= record_limit,
        "projected source object exceeds admitted working record bytes"
    );
    let mut folded_names = Vec::with_capacity(1 + object.additional_names.len());
    for path in std::iter::once(&object.path).chain(object.additional_names.iter()) {
        let folded = n2r_win32::shadow_names::conservative_path_key(path);
        let bucket = xxhash_rust::xxh3::xxh3_64(folded.as_bytes());
        let name_json = serde_json::to_vec(&NameRow { folded })?;
        folded_names.push((bucket, name_json));
    }
    Ok(EncodedRow {
        object_json,
        names: folded_names,
    })
}
/// An object on its way into the sorts, under its key: as it was built, or
/// already encoded by the helper thread that built it. (At most a batch
/// of them is held, and an object is far larger than its text's handle.)
#[allow(clippy::large_enum_variant)]
enum PendingObject {
    Built([u8; 16], Object),
    Encoded([u8; 16], Result<EncodedRow>),
}

/// What `derive_scoped` has made of the source so far, and where each
/// object goes once it is built: the counts, the archives, the roles, the
/// physical ranges and the objects and names on their way into the sorts.
/// Every object is added to it in the source's order, on the thread that
/// holds the source.
struct Projecting<'a> {
    source: &'a PagedInspection,
    aliases: Option<&'a crate::boot_alias::WindowsAliasDomain>,
    windows_object_id_owner: Option<&'a crate::boot_alias::WindowsObjectIdDomain>,
    scratch: &'a SourceScratch,
    output: &'a Path,
    objects: ExternalSort,
    names: ExternalSort,
    physical_mem: Option<(Vec<(u64, u64)>, SourceRamLease)>,
    physical: Option<ExternalSort>,
    roles: Vec<String>,
    role_ram: Vec<SourceRamLease>,
    windows_ea_writer: Option<SortedRecordWriter>,
    windows_ea_normalized_entries: u64,
    windows_txf_writer: Option<SortedRecordWriter>,
    windows_object_id_writer: Option<SortedRecordWriter>,
    files: u64,
    directories: u64,
    streams: u64,
    logical_bytes: u64,
    name_ordinal: u64,
    physical_ordinal: u64,
    pushed_roots: u64,
    pending: Vec<PendingObject>,
    serialize_batch_limit: usize,
    serialize_workers: usize,
    record_limit: u64,
}
impl Projecting<'_> {
    fn role(&mut self, role: String) -> Result<()> {
        add_role(&mut self.roles, &mut self.role_ram, role, self.scratch)
    }
    /// Adds `object`, built from `file` at `ordinal`, with what follows
    /// its construction: its archives (TxF marker, object ID, EA
    /// normalization), its counts and physical ranges, the root's roles and
    /// place, and the object itself on its way into the sorts (`encoded`
    /// where it is already encoded).
    fn record(
        &mut self,
        ordinal: u64,
        file: &ntfs::FileInventory,
        object: Object,
        ea_normalization: Option<
            crate::ntfs_extended_attributes::WindowsKernelPurgeEaNormalization,
        >,
        encoded: Option<Result<EncodedRow>>,
    ) -> Result<()> {
        let source = self.source;
        if self
            .aliases
            .map(|owner| owner.windows_txf_accounted(source, file))
            .transpose()?
            .unwrap_or(false)
        {
            let attribute = file
                .attributes
                .iter()
                .find(|attribute| {
                    attribute.type_code == 0x100
                        && attribute.name_utf16 == [36, 84, 88, 70, 95, 68, 65, 84, 65]
                })
                .context("verified Windows TxF source attribute disappeared")?;
            self.windows_txf_writer
                .as_mut()
                .context("Windows TxF disposition archive absent")?
                .push(
                    ordered_key(ordinal, file.record_number),
                    &WindowsTxfDisposition {
                        record_number: file.record_number,
                        sequence_number: file.sequence_number,
                        source_attribute: attribute.clone(),
                    },
                )?;
        }
        if let Some(owner) = self.windows_object_id_owner
            && let Some(disposition) = owner.disposition(source, file)?
        {
            self.windows_object_id_writer
                .as_mut()
                .context("Windows object-ID disposition archive absent")?
                .push(ordered_key(ordinal, file.record_number), &disposition)?;
        }
        if let Some(normalization) = ea_normalization {
            self.windows_ea_normalized_entries = self
                .windows_ea_normalized_entries
                .checked_add(u64::try_from(normalization.omitted.entries.len())?)
                .context("Windows kernel EA normalization count overflow")?;
            self.windows_ea_writer
                .as_mut()
                .context("Windows EA normalization archive absent")?
                .push(ordered_key(ordinal, file.record_number), &normalization)?;
        }
        if object.directory {
            self.directories = self
                .directories
                .checked_add(1)
                .context("directory count overflow")?;
        } else {
            self.files = self.files.checked_add(1).context("file count overflow")?;
        }
        let mut ranges = Vec::new();
        for stream in object.data_streams() {
            self.streams = self
                .streams
                .checked_add(1)
                .context("DATA-stream count overflow")?;
            self.logical_bytes = self
                .logical_bytes
                .checked_add(stream.length)
                .context("logical byte total overflow")?;
            validate_stream_source(stream, &mut ranges)?;
        }
        for (offset, length) in ranges {
            ensure!(
                offset
                    .checked_add(length)
                    .is_some_and(|end| end <= source.header().geometry.volume_size),
                "retained source payload escapes the source"
            );
            if let Some((vec, _)) = self.physical_mem.as_mut() {
                if vec.len() < vec.capacity() {
                    vec.push((offset, length));
                    continue;
                }
                let (spilled, lease) = self.physical_mem.take().unwrap();
                drop(lease);
                let mut sorter = ExternalSort::with_shared_projection_hint(
                    &self.output.join("retained-source-ranges"),
                    *b"N2RPHYS1",
                    self.scratch,
                    source.allocation().physical_intervals,
                )?;
                for (prev_offset, prev_length) in spilled {
                    sorter.push(
                        ordered_key(prev_offset, self.physical_ordinal),
                        &PhysicalRow {
                            offset: prev_offset,
                            length: prev_length,
                        },
                    )?;
                    self.physical_ordinal = self
                        .physical_ordinal
                        .checked_add(1)
                        .context("physical source interval count overflow")?;
                }
                self.physical = Some(sorter);
            }
            self.physical
                .as_mut()
                .context("physical range sorter absent")?
                .push(
                    ordered_key(offset, self.physical_ordinal),
                    &PhysicalRow { offset, length },
                )?;
            self.physical_ordinal = self
                .physical_ordinal
                .checked_add(1)
                .context("physical source interval count overflow")?;
        }
        if file.record_number == 5
            && file
                .attributes
                .iter()
                .any(ntfs_admission::recognized_root_txf)
        {
            self.role("root:$TXF_DATA (not yet admitted for replacement)".into())?;
        }
        if object.path.is_empty() {
            ensure!(
                object.directory && object.record_number == 5,
                "invalid projected root"
            );
            self.pushed_roots += 1;
        }
        let object_key = ordered_key(u64::try_from(object.path.len())?, object.record_number);
        self.pending.push(match encoded {
            None => PendingObject::Built(object_key, object),
            Some(encoded) => PendingObject::Encoded(object_key, encoded),
        });
        if self.pending.len() >= self.serialize_batch_limit {
            self.flush()?;
        }
        Ok(())
    }
    /// Puts the objects waiting into the sorts, in order: those not yet
    /// encoded are encoded first, on helper threads where there are enough
    /// of them. The first that cannot be encoded or put ends it.
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let items = std::mem::take(&mut self.pending);
        let record_limit = self.record_limit;
        let encode = |item: PendingObject| -> Result<([u8; 16], EncodedRow)> {
            match item {
                PendingObject::Built(key, object) => {
                    let record_number = object.record_number;
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        encode_row(&object, record_limit)
                    }))
                    .unwrap_or_else(|panic| {
                        Err(anyhow::anyhow!(
                            "the encoding of the projected FILE {record_number} panicked: {}",
                            in_order::panic_text(panic.as_ref())
                        ))
                    })
                    .map(|row| (key, row))
                }
                PendingObject::Encoded(key, row) => row.map(|row| (key, row)),
            }
        };
        let built = items
            .iter()
            .filter(|item| matches!(item, PendingObject::Built(..)))
            .count();
        let workers = self.serialize_workers;
        let encoded: Vec<Result<([u8; 16], EncodedRow)>> = if built >= 16 && workers > 1 {
            let chunk_size = items.len().div_ceil(workers);
            let mut iter = items.into_iter();
            let mut chunks: Vec<Vec<PendingObject>> = Vec::with_capacity(workers);
            loop {
                let chunk: Vec<_> = iter.by_ref().take(chunk_size).collect();
                if chunk.is_empty() {
                    break;
                }
                chunks.push(chunk);
            }
            std::thread::scope(|scope| -> Result<Vec<_>> {
                let handles: Vec<_> = chunks
                    .into_iter()
                    .map(|chunk| scope.spawn(|| chunk.into_iter().map(&encode).collect::<Vec<_>>()))
                    .collect();
                let mut out = Vec::with_capacity(built);
                for handle in handles {
                    out.extend(handle.join().map_err(|panic| {
                        anyhow::anyhow!(
                            "a thread encoding projected objects panicked: {}",
                            in_order::panic_text(panic.as_ref())
                        )
                    })?);
                }
                Ok(out)
            })?
        } else {
            items.into_iter().map(&encode).collect()
        };
        for row in encoded {
            let (object_key, row) = row?;
            for (bucket, name_json) in row.names {
                self.names
                    .push_json(ordered_key(bucket, self.name_ordinal), name_json)?;
                self.name_ordinal = self
                    .name_ordinal
                    .checked_add(1)
                    .context("namespace name count overflow")?;
            }
            self.objects.push_json(object_key, row.object_json)?;
        }
        Ok(())
    }
}

/// The most physical source ranges checked in spare memory (16 bytes each).
const PHYSICAL_MEM_CAP: usize = 512 * 1024;
/// Objects encoded at once by the serial loop's flush, and their spare memory.
const SERIALIZE_BATCH: usize = 256;
const SERIALIZE_BATCH_SPARE_BYTES: u64 = 16 * 1024 * 1024;
/// A batch of objects built on helper threads: at most this many, and
/// about this much workspace.
const AT_ONCE_OBJECTS: usize = 512;
const AT_ONCE_BATCH_BYTES: u64 = 16 << 20;
/// An object whose reads and construction may take more is built in
/// turn, under the projection's own row allowance.
const AT_ONCE_OBJECT_BYTES: u64 = 4 << 20;
/// The batch being built and the one being read beside it.
const AT_ONCE_SPARE_BYTES: u64 = 2 * (AT_ONCE_BATCH_BYTES + AT_ONCE_OBJECT_BYTES);
/// A batch of alias rows decoded on helper threads.
const ALIAS_BATCH: usize = 4096;
const ALIAS_BATCH_BYTES: u64 = 8 << 20;
/// Two batches, each of which may end with a row past its share (an
/// alias's paths: far less than a third more).
const ALIAS_SPARE_BYTES: u64 = 3 * ALIAS_BATCH_BYTES;
/// A source row a helper thread builds the object of, with what the
/// thread that holds the source read for it.
struct AtOnceJob<'a> {
    ordinal: u64,
    file: Arc<ntfs::FileInventory>,
    reads: GatheredReads<'a>,
}
/// A source row of a projection that builds its objects at once, as it is
/// added to the projection in the source's order. (At most a batch of
/// them is held.)
#[allow(clippy::large_enum_variant)]
enum AtOnce {
    /// An NTFS internal role.
    Role(String),
    /// The row could not be read, or its role derived: the projection
    /// stops there.
    Refused(anyhow::Error),
    /// An object too large for a helper's share of the workspace: built in
    /// turn, on the thread that holds the source.
    InTurn {
        ordinal: u64,
        file: Arc<ntfs::FileInventory>,
    },
    /// An object a helper built and encoded, or its first refusal.
    Built {
        ordinal: u64,
        file: Arc<ntfs::FileInventory>,
        built: Result<(
            Object,
            Option<crate::ntfs_extended_attributes::WindowsKernelPurgeEaNormalization>,
            Result<EncodedRow>,
        )>,
    },
}

impl SourceExpectedDomain {
    /// Linear current-code equality proof for an authenticated saved body.
    /// Native rows are visited in source ordinal order; no projection stores,
    /// sort runs or replacement expected file are produced.
    pub(crate) fn verify_cached_body(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        aliases: &crate::boot_alias::WindowsAliasDomain,
        expected: &crate::shadow_tree::PagedExpectedTree,
        scratch: &SourceScratch,
    ) -> Result<()> {
        aliases.require_source(source)?;
        source.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        ensure!(
            native.header().request.source_inspection_sha256 == source.canonical_sha256()?
                && native.header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission)
                    ))
                && native.len() as u64 == source.file_count()
                && expected.len() as u64 == admission.objects()?
                && expected.profile()
                    == crate::ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                        .ordinary_shadow_profile(),
            "cached expected current projection profile/source coverage differs"
        );
        let index_bytes = (expected.len() as u64)
            .checked_mul(256)
            .and_then(|n| n.checked_add(65536))
            .context("cached expected equality index RAM overflow")?;
        let _index = scratch.lease_ram(index_bytes)?;
        let _row = scratch.lease_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(16)
                .and_then(|n| n.checked_add(8 * 1024 * 1024))
                .context("cached expected equality row RAM overflow")?,
        )?;
        let mut hashes = std::collections::BTreeMap::new();
        for index in 0..expected.len() {
            let object = expected.object_leased(index)?;
            let hash: [u8; 32] = Sha256::digest(serde_json::to_vec(&*object)?).into();
            ensure!(
                hashes.insert(object.record_number, hash).is_none(),
                "cached expected repeats a source identity"
            );
        }
        let mut logical = 0u64;
        let mut roles = Vec::new();
        let reads = LiveReads {
            source,
            native,
            compared: None,
            aliases: Some(aliases),
            object_ids: None,
            once: None,
        };
        for ordinal in 0..source.file_count() {
            let file = source.file_shared(ordinal)?;
            if let Some(role) = ntfs_admission::paged::internal_role(source, &file)? {
                roles.push(role);
                continue;
            }
            let (object, _) = build_object(
                &reads, ordinal, &file, admission,
                // A volume that holds a Windows carries no mark over.
                false,
            )?;
            let hash: [u8; 32] = Sha256::digest(serde_json::to_vec(&object)?).into();
            ensure!(
                hashes.remove(&object.record_number) == Some(hash),
                "cached expected differs from current typed projection at FILE {}",
                object.record_number
            );
            for stream in object.data_streams() {
                logical = logical
                    .checked_add(stream.length)
                    .context("cached expected logical total overflow")?;
            }
            if file.record_number == 5
                && file
                    .attributes
                    .iter()
                    .any(ntfs_admission::recognized_root_txf)
            {
                roles.push("root:$TXF_DATA (not yet admitted for replacement)".to_owned());
            }
        }
        ensure!(
            hashes.is_empty()
                && logical == expected.logical_bytes()
                && roles.as_slice() == expected.internal_replacement_pending(),
            "cached expected user coverage/logical total/roles differ"
        );
        source.revalidate()?;
        native.revalidate()?;
        expected.revalidate()?;
        Ok(())
    }
    /// What a projection reserves at the most in one reservation it cannot
    /// do without: its row working allowance.
    pub(crate) fn largest_working_reservation(admission: SourceResourceAdmission) -> u64 {
        admission.budget.max_row_bytes.saturating_mul(8)
    }
    /// The spare memory a projection asks for beside its working memory,
    /// at the most: the physical ranges, the encoding batch, the
    /// helper batches of its objects and of its
    /// aliases. Without it the projection does that work in turn.
    pub(crate) fn spare_ram_bound() -> u64 {
        (PHYSICAL_MEM_CAP as u64 * 16)
            + SERIALIZE_BATCH_SPARE_BYTES
            + AT_ONCE_SPARE_BYTES
            + ALIAS_SPARE_BYTES
    }
    /// What a projection of `file_count` source rows under `admission`
    /// reserves in `scratch`, at the most, of memory it cannot do without:
    /// its row working allowance, the batches of its three sorts as they
    /// grow and what writing their runs out takes, and the page windows of
    /// its other writers. A bound for deciding whether caches may stay
    /// beside it; nothing depends on it being exact.
    pub(crate) fn working_ram_bound(
        file_count: u64,
        admission: SourceResourceAdmission,
        scratch: &SourceScratch,
    ) -> u64 {
        let rows = admission.budget.max_row_bytes.saturating_mul(8);
        let sort = ExternalSort::shared_projection_batch_bytes(scratch, file_count)
            .saturating_add(ExternalSort::shared_projection_spill_bytes(scratch));
        let windows = u64::from(scratch.budget().page_bytes).saturating_mul(16);
        rows.saturating_add(sort.saturating_mul(3))
            .saturating_add(windows)
    }
    pub fn derive(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
    ) -> Result<Self> {
        Self::derive_scoped(
            source, native, None, admission, output, scratch, None, None, false,
        )
    }
    /// The tree of a data volume whose object IDs, if it has any, have been
    /// matched and archived and are not carried over. With
    /// `carry_case_marks`, every directory of the tree states its
    /// case-sensitive mark, set or not: the run's decision, taken where the
    /// source has a marked directory and the running Windows is one the
    /// mark is carried on (`n2r_win32::directory_case::CaseMarkCarry`).
    /// `compared` as in [`build_object`].
    #[allow(clippy::too_many_arguments)]
    pub fn derive_data(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
        carry_case_marks: bool,
    ) -> Result<Self> {
        Self::derive_scoped(
            source,
            native,
            compared,
            admission,
            output,
            scratch,
            None,
            object_ids,
            carry_case_marks,
        )
    }
    /// `compared` as in [`build_object`].
    pub fn derive_windows(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: &crate::boot_alias::WindowsAliasDomain,
    ) -> Result<Self> {
        aliases.require_source(source)?;
        Self::derive_scoped(
            source,
            native,
            compared,
            admission,
            output,
            scratch,
            Some(aliases),
            None,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn derive_scoped(
        source: &PagedInspection,
        native: &impl NativeObservationDomain,
        compared: Option<&SortedRecordStore>,
        admission: SourceResourceAdmission,
        output: &Path,
        scratch: &SourceScratch,
        aliases: Option<&crate::boot_alias::WindowsAliasDomain>,
        object_ids: Option<&crate::object_id_disposition::DataObjectIds>,
        carry_case_marks: bool,
    ) -> Result<Self> {
        admission.validate()?;
        ensure!(
            !carry_case_marks || aliases.is_none(),
            "a volume that holds a Windows carries no case-sensitive mark over"
        );
        ensure!(
            aliases.is_none() || source.is_windows_conversion(),
            "Windows projection requires its actual inspection purpose"
        );
        source.require_paged_source(admission.source_pages, admission.semantic_byte_budget())?;
        native.revalidate()?;
        n2r_win32::attestation::validate_domain_resources(native)?;
        let source_pin = source.canonical_sha256()?;
        let source_hash: [u8; 32] = hex::decode(&source_pin)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("source inspection pin length differs"))?;
        let expected_budget =
            crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(admission.budget)?;
        let actual_budget = scratch.budget();
        ensure!(
            native.is_paged()
                && native.len() as u64 == source.file_count()
                && native.header().request.source_inspection_sha256 == source_pin
                && !native.header().conversion_qualified
                && native.header().request.resource_profile
                    == Some(n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(
                        Some(admission)
                    ))
                && admission.source_inspection_sha256 == source_hash
                && scratch.budget().page_budget()? == admission.expected_page_budget()?
                && actual_budget.ram_bytes == expected_budget.ram_bytes
                && actual_budget.record_bytes == expected_budget.record_bytes
                && actual_budget.merge_fan_in == expected_budget.merge_fan_in,
            "actual source/native/resource projection ownership differs"
        );
        let row_working_bytes = admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .context("source object working RAM overflow")?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        // The complete source counts size batches only; extra names or large
        // rows still spill and merge without dropping any source evidence.
        let objects = ExternalSort::with_shared_projection_hint(
            &output.join("source-objects"),
            *b"N2RSOBJ1",
            scratch,
            source.file_count(),
        )?;
        let names = ExternalSort::with_shared_projection_hint(
            &output.join("destination-names"),
            *b"N2RDNAM1",
            scratch,
            source.file_count(),
        )?;
        // Check physical source range non-overlap in spare RAM when available
        // (16 bytes per range; e.g. 200k ranges = 3.2 MiB), falling back to
        // on-disk ExternalSort if spare RAM is unavailable or capacity is exceeded.
        let physical_hint = usize::try_from(source.allocation().physical_intervals)
            .unwrap_or(PHYSICAL_MEM_CAP)
            .clamp(64, PHYSICAL_MEM_CAP);
        let physical_mem_bytes = (physical_hint as u64) * 16;
        let physical_mem: Option<(Vec<(u64, u64)>, SourceRamLease)> = scratch
            .lease_spare_ram(physical_mem_bytes)
            .ok()
            .map(|lease| (Vec::with_capacity(physical_hint), lease));
        let physical: Option<ExternalSort> = if physical_mem.is_none() {
            Some(ExternalSort::with_shared_projection_hint(
                &output.join("retained-source-ranges"),
                *b"N2RPHYS1",
                scratch,
                source.allocation().physical_intervals,
            )?)
        } else {
            None
        };
        let windows_ea_writer = aliases
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-kernel-purge-ea-normalizations"),
                    *b"WINEAN01",
                    scratch,
                )
            })
            .transpose()?;
        let windows_txf_writer = aliases
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-nontransacted-txf-dispositions"),
                    *b"WINTXF01",
                    scratch,
                )
            })
            .transpose()?;
        let windows_object_id_owner = aliases.and_then(|owner| owner.windows_object_ids_owned());
        let windows_object_id_writer = windows_object_id_owner
            .as_ref()
            .map(|_| {
                SortedRecordWriter::new(
                    &output.join("windows-object-ID-dispositions"),
                    *b"WINOIDP1",
                    scratch,
                )
            })
            .transpose()?;
        // Parallelize JSON serialization and case-folded NameRow generation in
        // spare-RAM batches of up to 256 objects, falling back to single-object
        // inline encoding if spare RAM is unavailable.
        let _serialize_spare = scratch.lease_spare_ram(SERIALIZE_BATCH_SPARE_BYTES).ok();
        let serialize_batch_limit = if _serialize_spare.is_some() {
            SERIALIZE_BATCH
        } else {
            1
        };
        let serialize_workers = std::thread::available_parallelism()
            .map_or(2, |n| n.get())
            .clamp(2, 4);
        let record_limit = scratch.budget().record_bytes;
        // What this projection leaves out of each object's construction in
        // a run that verifies once (see `VerifiedOnce`).
        let once = n2r_win32::verify_policy::verifies_once().then(|| VerifiedOnce {
            descriptors: DescriptorCache::leased(scratch),
            stream_facts: ntfs_stream_plan::StreamSourceFacts::of(source),
        });
        let mut projecting = Projecting {
            source,
            aliases,
            windows_object_id_owner: windows_object_id_owner.as_deref(),
            scratch,
            output,
            objects,
            names,
            physical_mem,
            physical,
            roles: Vec::new(),
            role_ram: Vec::new(),
            windows_ea_writer,
            windows_ea_normalized_entries: 0,
            windows_txf_writer,
            windows_object_id_writer,
            files: 0,
            directories: 0,
            streams: 0,
            logical_bytes: 0,
            name_ordinal: 0,
            physical_ordinal: 0,
            pushed_roots: 0,
            pending: Vec::with_capacity(serialize_batch_limit),
            serialize_batch_limit,
            serialize_workers,
            record_limit,
        };
        let live = LiveReads {
            source,
            native,
            compared,
            aliases,
            object_ids,
            once: once.as_ref(),
        };
        // A run that verifies once and has the comparison's rows builds its
        // objects on helper threads, in batches whose workspace it pays from
        // spare memory: this thread reads, for one batch after another,
        // what the construction of each object reads of the held source
        // (`GatheredReads`), the helpers build and encode the objects of
        // the batch before (`build_object` itself, from those reads), and
        // this thread adds them to the projection in the source's order. An
        // object's first refusal is the one building it in turn gives, and
        // the first refusal in the source's order ends the projection, as
        // in turn. Without the spare memory, a second core or that run, the
        // objects are built in turn, as they always were.
        let helpers = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .saturating_sub(1)
            .min(8);
        let at_once = match (compared, once.as_ref()) {
            (Some(rows), Some(once)) if helpers >= 1 => scratch
                // The batch being built and the one being read beside it.
                .lease_spare_ram(AT_ONCE_SPARE_BYTES)
                .ok()
                .map(|workspace| (rows, once, workspace)),
            _ => None,
        };
        if let Some((rows, once, _workspace)) = at_once {
            let end = source.file_count();
            let mut next = 0u64;
            let mut stopped = false;
            in_order::in_order(
                helpers,
                || {
                    let mut batch = Vec::new();
                    let mut bytes = 0u64;
                    while !stopped
                        && next < end
                        && batch.len() < AT_ONCE_OBJECTS
                        && bytes < AT_ONCE_BATCH_BYTES
                    {
                        let ordinal = next;
                        next += 1;
                        let file = match source.file_shared(ordinal) {
                            Ok(file) => file,
                            Err(error) => {
                                stopped = true;
                                batch.push(in_order::Slot::Ready(AtOnce::Refused(error)));
                                break;
                            }
                        };
                        match ntfs_admission::paged::internal_role(source, &file) {
                            Ok(Some(role)) => {
                                batch.push(in_order::Slot::Ready(AtOnce::Role(role)));
                                continue;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                stopped = true;
                                batch.push(in_order::Slot::Ready(AtOnce::Refused(error)));
                                break;
                            }
                        }
                        let (reads, workspace) =
                            GatheredReads::gather(&live, once, rows, &file, admission);
                        if workspace > AT_ONCE_OBJECT_BYTES {
                            // Its row is held until it is built, outside
                            // the batch's share: the batch ends with it, so
                            // that at most one such row is held for each of
                            // the two batches (as the serial loop holds one
                            // under the row allowance).
                            batch.push(in_order::Slot::Ready(AtOnce::InTurn { ordinal, file }));
                            break;
                        }
                        bytes += workspace;
                        batch.push(in_order::Slot::Work(AtOnceJob {
                            ordinal,
                            file,
                            reads,
                        }));
                    }
                    batch
                },
                move |AtOnceJob {
                          ordinal,
                          file,
                          reads,
                      }| {
                    let record_number = file.record_number;
                    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::AtOnce);
                        let (object, ea_normalization) =
                            build_object(&reads, ordinal, &file, admission, carry_case_marks)?;
                        let encoded = encode_row(&object, record_limit);
                        Ok((object, ea_normalization, encoded))
                    }))
                    .unwrap_or_else(|panic| {
                        Err(anyhow::anyhow!(
                            "the projection of FILE {record_number} panicked on a helper thread: {}",
                            in_order::panic_text(panic.as_ref())
                        ))
                    });
                    // A refusal whose text names the object by a path that
                    // was not read beforehand is made again in turn, where
                    // it is read: the same refusal, with its path.
                    if built.is_err() && reads.wanted_refused_path.get() {
                        return AtOnce::InTurn { ordinal, file };
                    }
                    AtOnce::Built {
                        ordinal,
                        file,
                        built,
                    }
                },
                |made| match made {
                    AtOnce::Role(role) => projecting.role(role),
                    AtOnce::Refused(error) => Err(error),
                    AtOnce::InTurn { ordinal, file } => {
                        let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::InTurn);
                        let (object, ea_normalization) =
                            build_object(&live, ordinal, &file, admission, carry_case_marks)?;
                        projecting.record(ordinal, &file, object, ea_normalization, None)
                    }
                    AtOnce::Built {
                        ordinal,
                        file,
                        built,
                    } => {
                        let (object, ea_normalization, encoded) = built?;
                        projecting.record(ordinal, &file, object, ea_normalization, Some(encoded))
                    }
                },
            )?;
        } else {
            for ordinal in 0..source.file_count() {
                let file = source.file_shared(ordinal)?;
                if let Some(role) = ntfs_admission::paged::internal_role(source, &file)? {
                    projecting.role(role)?;
                    continue;
                }
                let (object, ea_normalization) =
                    build_object(&live, ordinal, &file, admission, carry_case_marks)?;
                projecting.record(ordinal, &file, object, ea_normalization, None)?;
            }
        }
        projecting.flush()?;
        let Projecting {
            objects,
            mut names,
            physical_mem,
            physical,
            roles,
            role_ram,
            windows_ea_writer,
            windows_ea_normalized_entries,
            windows_txf_writer,
            windows_object_id_writer,
            files,
            directories,
            streams,
            logical_bytes,
            mut name_ordinal,
            pushed_roots,
            ..
        } = projecting;
        let (mut physical_mem, mut physical) = (physical_mem, physical);
        drop(_serialize_spare);
        drop(once);
        if let Some(aliases) = aliases {
            // Alias entries participate in the real destination collision
            // proof without becoming source objects or changing source counts.
            //
            // A run that verifies once, with spare memory for two batches
            // (each may end with a row past its share, an alias's paths:
            // far less than a third more), reads the alias rows here and
            // has helper threads decode them
            // and make their name rows (`ExternalSort::encode`, as `push`
            // makes them), which go into the sort here in the domain's
            // order; the first refusal in that order ends it. Otherwise
            // each is decoded and pushed in turn, as before.
            let record_limit = scratch.budget().record_bytes;
            let at_once = (n2r_win32::verify_policy::verifies_once() && helpers >= 1)
                .then(|| scratch.lease_spare_ram(ALIAS_SPARE_BYTES).ok())
                .flatten();
            if let Some(_workspace) = at_once {
                let end = aliases.len();
                let mut next = 0u64;
                let mut stopped = false;
                in_order::in_order(
                    helpers,
                    || {
                        let mut batch = Vec::new();
                        let mut bytes = 0u64;
                        while !stopped
                            && next < end
                            && batch.len() < ALIAS_BATCH
                            && bytes < ALIAS_BATCH_BYTES
                        {
                            let ordinal = next;
                            next += 1;
                            match aliases.alias_bytes(ordinal) {
                                Ok(row) => {
                                    // The row, the alias and its key's row.
                                    bytes += 4 * row.len() as u64 + 256;
                                    batch.push(in_order::Slot::Work((ordinal, row)));
                                }
                                Err(error) => {
                                    stopped = true;
                                    batch.push(in_order::Slot::Ready(Err(error)));
                                }
                            }
                        }
                        batch
                    },
                    move |(ordinal, row): (u64, Vec<u8>)| -> Result<(u64, Vec<u8>)> {
                        std::panic::catch_unwind(|| {
                            let alias = crate::boot_alias::WindowsPathAlias::decode(&row)?;
                            let folded =
                                n2r_win32::shadow_names::conservative_path_key(&alias.path);
                            let bucket = xxhash_rust::xxh3::xxh3_64(folded.as_bytes());
                            Ok((
                                bucket,
                                ExternalSort::encode(&NameRow { folded }, record_limit)?,
                            ))
                        })
                        .unwrap_or_else(|panic| {
                            Err(anyhow::anyhow!(
                                "the name row of Windows alias {ordinal} panicked on a helper thread: {}",
                                in_order::panic_text(panic.as_ref())
                            ))
                        })
                    },
                    |made| {
                        let (bucket, row) = made?;
                        names.push_json(ordered_key(bucket, name_ordinal), row)?;
                        name_ordinal = name_ordinal
                            .checked_add(1)
                            .context("Windows alias namespace count overflow")?;
                        Ok(())
                    },
                )?;
            } else {
                for ordinal in 0..aliases.len() {
                    let alias = aliases.alias(ordinal)?;
                    let folded = n2r_win32::shadow_names::conservative_path_key(&alias.path);
                    let bucket = xxhash_rust::xxh3::xxh3_64(folded.as_bytes());
                    names.push(ordered_key(bucket, name_ordinal), &NameRow { folded })?;
                    name_ordinal = name_ordinal
                        .checked_add(1)
                        .context("Windows alias namespace count overflow")?;
                }
            }
            aliases.require_source(source)?;
        }
        admission.validate_tree(files, directories, streams)?;
        // Object construction is complete. Return its transient parse/clone
        // allowance before opening merge heads and output verification rows.
        drop(row_ram);
        let name_pin = names.finish()?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        let name_store = SortedRecordStore::open(&name_pin, scratch)?;
        // Hashes only select bounded on-disk comparison buckets. Equality is
        // ALWAYS the full folded string; distinct hash-colliding names remain
        // valid, and no bucket-size cap or resident whole-name set exists.
        //
        // The last name of a bucket (nearly every name is alone in its
        // bucket) is compared with no other. A run that verifies once does
        // not decode its row only to drop it: the rows are those this pass
        // has just serialized into the store, which its writer framed and
        // which is held. Every other run decodes every row, as before.
        let decode_every_row = !n2r_win32::verify_policy::verifies_once();
        let mut start = 0u64;
        while start < name_store.len() {
            let prefix: [u8; 8] = name_store.key(start)?[..8].try_into()?;
            let mut end = start + 1;
            while end < name_store.len() && name_store.key(end)?[..8] == prefix {
                end += 1;
            }
            for a in start..end {
                if a + 1 == end && !decode_every_row {
                    break;
                }
                let left: NameRow = name_store.get(a)?;
                for b in a + 1..end {
                    let right: NameRow = name_store.get(b)?;
                    ensure!(left.folded != right.folded, "colliding destination name");
                }
            }
            start = end;
        }
        drop(name_store);
        scratch.retire_created(&name_pin.data)?;
        scratch.retire_created(&name_pin.directory)?;
        drop(row_ram);
        if let Some((mut ranges, lease)) = physical_mem.take() {
            ranges.sort_unstable();
            let mut prior_end = 0u64;
            for (offset, length) in ranges {
                ensure!(
                    offset >= prior_end && length > 0,
                    "overlapping default or named source payloads"
                );
                prior_end = offset
                    .checked_add(length)
                    .context("physical source interval overflow")?;
            }
            drop(lease);
        } else if let Some(physical) = physical.take() {
            let physical_pin = physical.finish()?;
            let row_ram = scratch.lease_ram(row_working_bytes)?;
            let physical_store = SortedRecordStore::open(&physical_pin, scratch)?;
            let mut prior_end = 0u64;
            for ordinal in 0..physical_store.len() {
                let range: PhysicalRow = physical_store.get(ordinal)?;
                ensure!(
                    range.offset >= prior_end && range.length > 0,
                    "overlapping default or named source payloads"
                );
                prior_end = range
                    .offset
                    .checked_add(range.length)
                    .context("physical source interval overflow")?;
            }
            drop(physical_store);
            scratch.retire_created(&physical_pin.data)?;
            scratch.retire_created(&physical_pin.directory)?;
            drop(row_ram);
        }
        let object_pin = objects.finish()?;
        let row_ram = scratch.lease_ram(row_working_bytes)?;
        let objects = SortedRecordStore::open(&object_pin, scratch)?;
        ensure!(
            objects.len() == admission.objects()? && directories > 0,
            "complete projected object domain differs"
        );
        let object_count = usize::try_from(objects.len())?;
        let windows_ea_normalizations = windows_ea_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        let windows_txf_dispositions = windows_txf_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        let windows_object_id_dispositions = windows_object_id_writer
            .map(|writer| SortedRecordStore::open(&writer.finish()?, scratch))
            .transpose()?;
        if let Some(owner) = &windows_object_id_owner {
            owner.require_source(source)?;
            ensure!(
                windows_object_id_dispositions
                    .as_ref()
                    .is_some_and(|records| records.len() == owner.len()),
                "Windows object-ID projected disposition coverage differs"
            );
        }
        // Each row is held to its key and the root to its place. Under the
        // check-once policy, outside its gate, this pass just wrote every row
        // from a typed `Object` into `objects` with key `(path.len(), record_number)`
        // and verified the single root while pushing, and `SortedRecordStore::open`
        // verified the store's integrity and strictly ascending keys. Otherwise
        // the whole object is decoded here, as it always was.
        if !n2r_win32::verify_policy::full_unremembered() {
            ensure!(
                pushed_roots == 1,
                "exactly one projected source root required"
            );
        } else {
            let mut roots = 0u64;
            for ordinal in 0..objects.len() {
                let object: Object = objects.get(ordinal)?;
                let head = ObjectHead {
                    record_number: object.record_number,
                    path: PathDepth(u64::try_from(object.path.len())?),
                    directory: object.directory,
                };
                ensure!(
                    objects.key(ordinal)? == ordered_key(head.path.0, head.record_number),
                    "projected object key or ordering differs"
                );
                if head.path.0 == 0 {
                    ensure!(
                        head.directory && head.record_number == 5,
                        "invalid projected root"
                    );
                    roots += 1;
                }
            }
            ensure!(roots == 1, "exactly one projected source root required");
        }
        source.revalidate()?;
        native.revalidate()?;
        let value = Self {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            windows_ea_normalized_entries,
            object_count,
            admission,
            profile: ntfs_admission::ResourceProfile::ResourceBoundedV4(Some(admission))
                .ordinary_shadow_profile()
                .into(),
            logical_bytes,
            internal_replacement_pending: roles,
            source_inspection_sha256: source_pin,
            files,
            directories,
            streams,
            scratch: scratch.clone(),
            _role_ram: role_ram,
            _row_ram: row_ram,
        };
        value.revalidate_stores()?;
        Ok(value)
    }
    pub fn object_pin(&self) -> &RecordStorePin {
        self.objects.pin()
    }
    pub fn source_inspection_sha256(&self) -> &str {
        &self.source_inspection_sha256
    }

    fn revalidate_stores(&self) -> Result<()> {
        self.objects.revalidate()?;
        if let Some(records) = &self.windows_ea_normalizations {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_txf_dispositions {
            records.revalidate()?;
        }
        if let Some(records) = &self.windows_object_id_dispositions {
            records.revalidate()?;
        }
        if let Some(owner) = &self.windows_object_id_owner {
            owner.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn windows_ea_normalization_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_ea_normalizations.as_ref().map(|records| serde_json::json!({
            "kind":"Windows-target-kernel-purge-EA-normalization-v1",
            "source_inspection_sha256":self.source_inspection_sha256,
            "records":records.pin(), "normalized_objects":records.len(),
            "omitted_kernel_purge_entries":self.windows_ea_normalized_entries,
            "policy":"target only: omit flags0 $Kernel.Purge.<nonempty> caches and the flags0 $Kernel.CFDoNotConvert hive mark; archive exact source EAs; preserve ordinary EAs",
            "ea_set_digest_format":"ntfs2refs-exact-EA-set-v1",
            "raw_source_evidence_changed":false,"source_native_comparison_changed":false,
            "grants_source_or_replay_authority":false,
        })))
    }
    pub(crate) fn windows_txf_disposition_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_txf_dispositions.as_ref().map(|records| serde_json::json!({
            "kind":"Windows-source-nontransacted-TxF-disposition-v1",
            "source_inspection_sha256":self.source_inspection_sha256,
            "records":records.pin(), "source_marker_objects":records.len(),
            "policy":"archive exact NTFS-only TxF marker bytes after live protected per-file nontransacted proof; target files preserve ordinary content and metadata",
            "target_transactional_continuity_preserved":false,
            "grants_source_or_replay_authority":false,
        })))
    }
    pub(crate) fn windows_object_id_disposition_report(&self) -> Result<Option<serde_json::Value>> {
        self.revalidate_stores()?;
        Ok(self.windows_object_id_dispositions.as_ref().map(|records|serde_json::json!({
            "kind":"Windows-target-object-ID-epoch-disposition-v1",
            "source_inspection_sha256":self.source_inspection_sha256,"records":records.pin(),
            "source_object_id_objects":records.len(),"source_owner":self.windows_object_id_owner.as_ref().map(|owner|owner.audit()),
            "policy":"retain exact source raw/index/native object-ID bytes in paid metadata; target starts a new object-ID epoch",
            "target_object_id_continuity_preserved":false,"raw_source_evidence_changed":false,
            "source_native_comparison_changed":false,"grants_source_or_replay_authority":false,
        })))
    }

    /// Drop decode-only workspace once the caller has completed its semantic
    /// comparison, without replacing the held file owners with serialized pins.
    pub(crate) fn into_revalidation_owner(self) -> Result<ProjectionRevalidationOwner> {
        self.revalidate_stores()?;
        let Self {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            scratch,
            ..
        } = self;
        Ok(ProjectionRevalidationOwner {
            objects,
            windows_ea_normalizations,
            windows_txf_dispositions,
            windows_object_id_dispositions,
            windows_object_id_owner,
            _scratch: scratch,
        })
    }
}
impl ExpectedObjectDomain for SourceExpectedDomain {
    fn object_count(&self) -> usize {
        self.object_count
    }
    fn object(&self, index: usize) -> Result<Cow<'_, Object>> {
        self.objects.get(index as u64).map(Cow::Owned)
    }
    fn profile(&self) -> &str {
        &self.profile
    }
    fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    fn internal_replacement_pending(&self) -> &[String] {
        &self.internal_replacement_pending
    }
    fn revalidate_domain(&self) -> Result<()> {
        self.revalidate_stores()
    }
    fn require_paged_metadata(
        &self,
        budget: n2r_win32::metadata_pages::PageBudget,
        semantic: u64,
    ) -> Result<()> {
        ensure!(
            budget == self.admission.expected_page_budget()?
                && semantic == self.admission.semantic_byte_budget(),
            "actual projected page resources differ"
        );
        self.revalidate_stores()
    }
    fn require_resource_metadata(&self, admission: SourceResourceAdmission) -> Result<()> {
        ensure!(
            admission == self.admission && !self.scratch.is_poisoned(),
            "projected source admission differs"
        );
        admission.validate_tree(self.files, self.directories, self.streams)?;
        self.require_paged_metadata(
            admission.expected_page_budget()?,
            admission.semantic_byte_budget(),
        )
    }
}
struct Objects<'a>(&'a SourceExpectedDomain);
impl Serialize for Objects<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let count = usize::try_from(self.0.objects.len()).map_err(S::Error::custom)?;
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for ordinal in 0..self.0.objects.len() {
            let object: Object = self.0.objects.get(ordinal).map_err(S::Error::custom)?;
            sequence.serialize_element(&object)?;
        }
        sequence.end()
    }
}
impl Serialize for SourceExpectedDomain {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("ExpectedTree", 4)?;
        value.serialize_field("profile", &self.profile)?;
        value.serialize_field("objects", &Objects(self))?;
        value.serialize_field("logical_bytes", &self.logical_bytes)?;
        value.serialize_field(
            "internal_replacement_pending",
            &self.internal_replacement_pending,
        )?;
        value.end()
    }
}

#[cfg(test)]
mod descriptor_cache_tests {
    use super::*;

    /// The cache keeps descriptors only as far as its fixed lease holds them,
    /// and hands back what it kept, byte for byte.
    #[test]
    fn the_descriptor_cache_keeps_what_its_lease_holds_and_no_more() {
        let directory = tempfile::tempdir().unwrap();
        let arena = crate::artifact_arena::ArtifactArena::new(
            directory.path(),
            n2r_win32::tree_resources::ResourceBudget {
                schema_version: 1,
                ram_bytes: 256 * 1024 * 1024,
                scratch_bytes: 256 * 1024 * 1024,
                page_bytes: 65536,
                max_row_bytes: 65536,
                retained_index_bytes: 16 * 1024 * 1024,
                handle_slots: 1024,
            },
            &[],
        )
        .unwrap();
        let budget =
            crate::ntfs_inspect::SourceMetadataBudget::from_resource_budget(arena.budget())
                .unwrap();
        let group = arena
            .reserve_group(
                crate::artifact_arena::ArtifactGroup::Source,
                budget.scratch_bytes,
            )
            .unwrap();
        let scratch = SourceScratch::new_in_arena(budget, group).unwrap();
        let cache = DescriptorCache::leased(&scratch).expect("memory for the cache");
        let stored: Vec<u8> = (0..4096u32).map(|n| n as u8).collect();
        {
            let mut held = cache.0.get_mut().unwrap();
            for id in 0..4096u32 {
                held.keep(id, "ab".repeat(32), &stored, &"cd".repeat(32));
            }
            assert!(held.bytes <= DescriptorCache::LEASE_BYTES);
            let kept = held.by_id.len();
            assert!((1024..2048).contains(&kept), "{kept}");
            let first = &held.by_id[&0];
            assert_eq!(first.stored, stored);
            assert_eq!(first.descriptor_sha256, "ab".repeat(32));
            assert_eq!(first.stored_sha256, "cd".repeat(32));
            assert!(!held.by_id.contains_key(&(kept as u32)));
        }
        // A cache of the run: given up when memory is short, and done
        // without from then on.
        cache.0.clear();
        assert!(cache.0.get().is_none() && cache.0.get_mut().is_none());
    }
}
