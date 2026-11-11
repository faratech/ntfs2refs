//! Semantic input for an independent, native-created ReFS shadow. This is not
//! source admission, a conversion plan or authority to modify the NTFS source.
#[cfg(windows)]
pub mod pages;
#[cfg(windows)]
pub mod source_pages;
use crate::{ntfs_admission, ntfs_inspect as ntfs, ntfs_security, ntfs_stream_plan};
use anyhow::{Context, Result, ensure};
pub use n2r_win32::sparse_layout::{LogicalRange, SparseLayout};
#[cfg(windows)]
pub(crate) use pages::ExpectedTreeView;
#[cfg(windows)]
pub(crate) use pages::{ExpectedBindingFacts, ExpectedBindingPin};
#[cfg(windows)]
pub use pages::{
    ExpectedTreePageCounts, ExpectedTreePageHeader, ExpectedTreePageReceipt, PagedExpectedTree,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

/// Actual source evidence, never a fabricated content digest. Native mapping
/// reconciliation and the original live freeze are still required for admission.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStreamEvidence {
    ExtentIdentityV1,
    /// The complete source stream is byte-mapped and initialized. Only its
    /// full-cluster prefix may be retained; construction must materialize and
    /// verify the final partial cluster through the checked range reader.
    ExtentIdentityWithMaterializedTailV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedStream {
    pub name_utf16: Vec<u16>,
    pub source_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_extents: Vec<ntfs::Extent>,
    pub length: u64,
    /// The inspected content digest, not a native target-verification claim.
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<SourceStreamEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse: Option<SparseLayout>,
}

#[derive(Clone, Copy, Debug)]
pub struct StreamRef<'a> {
    pub name_utf16: &'a [u16],
    pub source_offset: Option<u64>,
    pub source_extents: &'a [ntfs::Extent],
    pub length: u64,
    pub sha256: Option<&'a str>,
    pub source_evidence: Option<SourceStreamEvidence>,
    pub sparse: Option<&'a SparseLayout>,
}
impl StreamRef<'_> {
    pub fn tail_requires_materialization(&self) -> bool {
        if self.length.is_multiple_of(4096) {
            return false;
        }
        let tail = self.length / 4096 * 4096;
        self.sparse.is_none_or(|sparse| {
            sparse.allocated.iter().any(|range| {
                range.offset <= tail
                    && range
                        .offset
                        .checked_add(range.length)
                        .is_some_and(|end| tail < end)
            })
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub record_number: u64,
    pub sequence_number: u16,
    pub path: Vec<String>,
    /// Other full volume-relative paths for this same file identity. Payload,
    /// metadata and allocation are owned once by the canonical object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_names: Vec<Vec<String>>,
    pub directory: bool,
    /// FILE_BASIC_INFO order: creation, access, write, change.
    pub stored_times: [u64; 4],
    pub attributes: u32,
    /// Source compression policy/encoding is intentionally normalized. Source
    /// views retain their original flags; target DATA is ordinary ReFS data.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ntfs_compression_normalized: bool,
    pub security: Vec<u8>,
    /// Measured GetSecurityInfo projection, when it differs from the stored
    /// descriptor. Never written over the stored/kernel descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_security: Option<Vec<u8>>,
    /// Complete file-level EAs, independently bound to native source queries.
    /// Missing in historical requests; never confused with an observed empty set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<n2r_win32::extended_attributes::Set>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse: Option<n2r_win32::reparse_layout::Point>,
    pub source_offset: Option<u64>,
    /// Fragmented, aligned NTFS payload runs. Mutually exclusive with the
    /// single-run source_offset; absent in older frozen tree requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_extents: Vec<ntfs::Extent>,
    pub length: u64,
    /// The stream's [`n2r_win32::content_digest`] (XXH3-128; historical name).
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<SourceStreamEvidence>,
    /// File streams share the canonical file identity and all hard-link names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_streams: Vec<NamedStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse: Option<SparseLayout>,
}
impl Object {
    /// Read-only flattened view of a validated object's DATA streams. The
    /// default stream remains first; directory streams are unsupported.
    pub fn data_streams(&self) -> impl Iterator<Item = StreamRef<'_>> {
        (!self.directory)
            .then(|| StreamRef {
                name_utf16: &[],
                source_offset: self.source_offset,
                source_extents: &self.source_extents,
                length: self.length,
                sha256: self.sha256.as_deref(),
                source_evidence: self.source_evidence,
                sparse: self.sparse.as_ref(),
            })
            .into_iter()
            .chain(self.named_streams.iter().map(|stream| StreamRef {
                name_utf16: &stream.name_utf16,
                source_offset: stream.source_offset,
                source_extents: &stream.source_extents,
                length: stream.length,
                sha256: stream.sha256.as_deref(),
                source_evidence: stream.source_evidence,
                sparse: stream.sparse.as_ref(),
            }))
    }
    pub fn stream(&self, name_utf16: &[u16]) -> Option<StreamRef<'_>> {
        self.data_streams()
            .find(|stream| stream.name_utf16 == name_utf16)
    }
}
#[derive(Debug, Serialize)]
pub struct Tree {
    pub profile: &'static str,
    pub objects: Vec<Object>,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
}
impl Tree {
    pub fn bind_security_views(&mut self, views: &crate::ntfs_source_view::Analysis) -> Result<()> {
        for object in &mut self.objects {
            let matches: Vec<_> = views
                .objects
                .iter()
                .filter(|view| {
                    view.record_number == object.record_number
                        && view.sequence_number == object.sequence_number
                })
                .collect();
            ensure!(
                matches.len() == 1 && matches[0].metadata.matched,
                "source metadata view missing/refused"
            );
            let security = matches[0]
                .security
                .as_ref()
                .context("source security views absent")?;
            ensure!(
                security.api_stable
                    && security.target_must_reproduce_both_views
                    && security.stored_sha256
                        == hex::encode(sha2::Sha256::digest(&object.security)),
                "source descriptor view differs from canonical tree"
            );
            object.api_security = if security.api_matches_stored {
                None
            } else {
                Some(hex::decode(&security.api_descriptor_hex)?)
            };
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTree {
    pub profile: String,
    pub objects: Vec<Object>,
    pub logical_bytes: u64,
    pub internal_replacement_pending: Vec<String>,
}
impl From<&Tree> for ExpectedTree {
    fn from(tree: &Tree) -> Self {
        Self {
            profile: tree.profile.into(),
            objects: tree.objects.clone(),
            logical_bytes: tree.logical_bytes,
            internal_replacement_pending: tree.internal_replacement_pending.clone(),
        }
    }
}
impl ExpectedTree {
    pub fn has_extent_only_streams(&self) -> bool {
        self.objects.iter().any(|object| {
            object
                .data_streams()
                .any(|stream| stream.source_evidence.is_some())
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_with_resource_profile(ntfs_admission::ResourceProfile::AlphaV1)
    }
    /// Explicit semantic validation only. Large-tree validation does not
    /// attest native construction support or create source-write authority.
    pub fn validate_with_resource_profile(
        &self,
        resources: ntfs_admission::ResourceProfile,
    ) -> Result<()> {
        validate_expected_domain(self, resources)
    }
}

/// Complete object access, never a deserializable admission capability. Paged
/// implementations return one owned object; inline trees borrow their objects.
mod expected_domain_sealed {
    pub trait Sealed {}
    impl Sealed for super::ExpectedTree {}
    #[cfg(windows)]
    impl Sealed for super::PagedExpectedTree {}
    #[cfg(windows)]
    impl Sealed for super::ExpectedTreeView<'_> {}
    #[cfg(windows)]
    impl Sealed for super::source_pages::SourceExpectedDomain {}
}
pub trait ExpectedObjectDomain: Serialize + expected_domain_sealed::Sealed {
    fn object_count(&self) -> usize;
    fn object(&self, index: usize) -> Result<std::borrow::Cow<'_, Object>>;
    fn profile(&self) -> &str;
    fn logical_bytes(&self) -> u64;
    fn internal_replacement_pending(&self) -> &[String];
    fn has_extent_only_streams(&self) -> Result<bool> {
        for index in 0..self.object_count() {
            if self
                .object(index)?
                .data_streams()
                .any(|stream| stream.source_evidence.is_some())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn revalidate_domain(&self) -> Result<()> {
        Ok(())
    }
    #[cfg(windows)]
    fn require_paged_metadata(
        &self,
        _budget: n2r_win32::metadata_pages::PageBudget,
        _semantic_bytes: u64,
    ) -> Result<()> {
        anyhow::bail!("source admission requires authenticated paged metadata ownership")
    }
    #[cfg(windows)]
    fn require_resource_metadata(
        &self,
        _admission: n2r_win32::tree_resources::SourceResourceAdmission,
    ) -> Result<()> {
        anyhow::bail!("resource source admission requires bounded typed page ownership")
    }
}

impl ExpectedObjectDomain for ExpectedTree {
    fn object_count(&self) -> usize {
        self.objects.len()
    }
    fn object(&self, index: usize) -> Result<std::borrow::Cow<'_, Object>> {
        self.objects
            .get(index)
            .map(std::borrow::Cow::Borrowed)
            .context("expected object index is outside the complete domain")
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
}

pub(crate) fn validate_expected_domain<T: ExpectedObjectDomain>(
    domain: &T,
    resources: ntfs_admission::ResourceProfile,
) -> Result<()> {
    let limits = resources.limits();
    let object_limit = resources.maximum_objects();
    let count = domain.object_count();
    ensure!(
        domain.profile() == resources.ordinary_shadow_profile()
            && count != 0
            && count <= object_limit,
        "expected general tree profile or root differs"
    );
    let resource_admission = resources.resource_admission()?;
    let resource_ranges = if let Some(admission) = resource_admission {
        domain.require_resource_metadata(admission)?;
        Some(preflight_resource_indexes(domain, admission)?)
    } else {
        None
    };
    let first = domain.object(0)?;
    ensure!(
        first.directory && first.path.is_empty(),
        "expected root is absent or invalid"
    );
    drop(first);
    // Only scalar path indexes survive an object/page boundary. This first
    // complete pass retains the old global reparse-ancestor check without
    // loading every object's streams or descriptors into memory.
    let mut reparse_paths = BTreeSet::new();
    for index in 0..count {
        let object = domain.object(index)?;
        if object.reparse.is_some() {
            reparse_paths.insert(destination_key(&object.path, resources));
        }
    }
    let mut directories = 0usize;
    let mut roots = 0usize;
    let mut paths = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut bytes = 0u64;
    let mut name_count = 0usize;
    let mut stream_count = 0usize;
    let mut source_ranges = Vec::new();
    if let Some(ranges) = resource_ranges {
        source_ranges.try_reserve_exact(ranges)?;
    }
    for index in 0..count {
        let owned = domain.object(index)?;
        let object = owned.as_ref();
        directories += usize::from(object.directory);
        roots += usize::from(object.path.is_empty());
        if object.source_evidence.is_some()
            || object
                .named_streams
                .iter()
                .any(|s| s.source_evidence.is_some())
        {
            ensure!(
                resources.is_streaming() && !object.directory && object.reparse.is_none(),
                "extent-only evidence requires the ordinary streaming source profile (record {})",
                object.record_number
            );
            // Compression normalization is recorded per file when any
            // sibling stream is compressed. Each extent-only stream has
            // its own plain-DATA proof; encoded siblings retain digests
            // and are materialized through their existing decoder path.
        }
        name_count = name_count
            .checked_add(1)
            .and_then(|n| n.checked_add(object.additional_names.len()))
            .context("expected name count overflow")?;
        ensure!(
            resource_admission.is_some() || name_count <= crate::ntfs_namespace::MAX_ENTRIES,
            "expected namespace name count exceeds the raw namespace bound"
        );
        if let Some(api) = &object.api_security {
            if let Some(admission) = resource_admission {
                ntfs_security::parse_descriptor_with_limit(api, admission.budget.max_row_bytes)?;
            } else {
                ensure!(api.len() <= 65536, "API descriptor exceeds bound");
                ntfs_security::parse_descriptor(api)?;
            }
        }
        if let Some(eas) = &object.extended_attributes {
            eas.validate()?;
        }
        if let Some(point) = &object.reparse {
            point.validate()?;
            ensure!(
                !object.path.is_empty(),
                "volume root reparse point is unsupported"
            );
            ensure!(
                object
                    .extended_attributes
                    .as_ref()
                    .is_none_or(|ea| ea.is_empty()),
                "reparse points and EAs are mutually exclusive"
            );
            ensure!(
                object.directory
                    || (object.length == 0
                        && object.named_streams.is_empty()
                        && object.sparse.is_none()),
                "file-link DATA streams exceed the initial reparse profile"
            );
            ensure!(
                point.tag() != 0xa0000003 || object.directory,
                "junction must be a directory"
            );
        }
        if let Some(admission) = resource_admission {
            ntfs_security::parse_descriptor_with_limit(
                &object.security,
                admission.budget.max_row_bytes,
            )?;
        } else {
            ntfs_security::parse_descriptor(&object.security)?;
        }
        if let Some(admission) = resource_admission {
            n2r_win32::security_descriptor::validate_with_limit(
                &object.security,
                admission.budget.max_row_bytes,
            )?;
        } else {
            n2r_win32::security_descriptor::validate(&object.security)?;
        }
        let path_key = destination_key(&object.path, resources);
        ensure!(
            expected_path_fits(&object.path, resource_admission.is_some())
                && object
                    .path
                    .iter()
                    .all(|part| valid_component_with_resources(part, resources))
                && object
                    .stored_times
                    .iter()
                    .all(|time| *time > 0 && *time < i64::MAX as u64)
                && object.attributes
                    & !(0x2037
                        | if object.reparse.is_some() { 0x400 } else { 0 }
                        | if object.sparse.is_some()
                            || object.named_streams.iter().any(|s| s.sparse.is_some())
                        {
                            0x200
                        } else {
                            0
                        })
                    == 0
                && (object.attributes & 16 != 0) == object.directory
                && (object.attributes & 0x400 != 0) == object.reparse.is_some()
                && identities.insert((object.record_number, object.sequence_number))
                && !paths.contains_key(&path_key),
            "expected general tree object is invalid or duplicated"
        );
        if !object.path.is_empty() {
            ensure!(
                (1..object.path.len()).all(|depth| !reparse_paths
                    .contains(&destination_key(&object.path[..depth], resources))),
                "namespace descends through a reparse object"
            );
            let parent = destination_key(&object.path[..object.path.len() - 1], resources);
            ensure!(
                paths.get(&parent) == Some(&true),
                "expected tree parent is missing, is not a directory, or follows its child"
            );
        }
        paths.insert(path_key, object.directory);
        ensure!(
            !object.directory || object.additional_names.is_empty(),
            "directory hard links are unsupported"
        );
        if object.sparse.is_some()
            || object
                .named_streams
                .iter()
                .any(|stream| stream.sparse.is_some())
        {
            ensure!(
                !object.directory
                    && std::iter::once(&object.path)
                        .chain(object.additional_names.iter())
                        .all(|path| {
                            path.first().is_none_or(|name| {
                                !name.eq_ignore_ascii_case("System Volume Information")
                            })
                        }),
                "sparse system-managed or directory streams are unsupported"
            );
        }
        for alias in &object.additional_names {
            // Reject an oversized path before allocating/checking prefixes.
            ensure!(
                !alias.is_empty()
                    && expected_path_fits(alias, resource_admission.is_some())
                    && alias
                        .iter()
                        .all(|part| valid_component_with_resources(part, resources)),
                "expected additional file name is invalid or collides"
            );
            ensure!(
                (1..alias.len())
                    .all(|depth| !reparse_paths
                        .contains(&destination_key(&alias[..depth], resources))),
                "additional name descends through a reparse object"
            );
            ensure!(
                !alias.is_empty()
                    && expected_path_fits(alias, resource_admission.is_some())
                    && alias
                        .iter()
                        .all(|part| valid_component_with_resources(part, resources))
                    && !paths.contains_key(&destination_key(alias, resources)),
                "expected additional file name is invalid or collides"
            );
            paths.insert(destination_key(alias, resources), false);
        }
        if !object.directory {
            stream_count = stream_count
                .checked_add(1)
                .and_then(|count| count.checked_add(object.named_streams.len()))
                .context("expected DATA stream count overflow")?;
            ensure!(
                resource_admission.is_some() || stream_count <= ntfs_admission::MAX_DATA_STREAMS,
                "expected total DATA stream count exceeds 16,384"
            );
            ensure!(
                object.named_streams.is_empty()
                    || std::iter::once(&object.path)
                        .chain(object.additional_names.iter())
                        .all(|path| {
                            path.first().is_none_or(|part| {
                                !part.eq_ignore_ascii_case("System Volume Information")
                            })
                        }),
                "named streams on System Volume Information objects are unsupported"
            );
            ensure!(
                object.length <= limits.maximum_stream_bytes,
                "expected stream exceeds selected resource profile"
            );
            validate_stream_evidence(object.stream(&[]).context("default stream absent")?)?;
            bytes = bytes
                .checked_add(object.length)
                .context("expected byte overflow")?;
            ensure!(
                resource_admission.is_some()
                    || object.named_streams.len() < n2r_win32::stream_layout::MAX_STREAMS,
                "expected named stream count exceeds the native stream-list bound"
            );
            let mut exact_names = BTreeSet::new();
            let mut folded_names = BTreeSet::new();
            for stream in &object.named_streams {
                ensure!(
                    ntfs_admission::valid_named_stream_name(&stream.name_utf16)
                        && exact_names.insert(stream.name_utf16.as_slice())
                        && folded_names
                            .insert(String::from_utf16(&stream.name_utf16)?.to_uppercase())
                        && stream.length <= limits.maximum_stream_bytes,
                    "expected named stream identity, size or digest differs"
                );
                validate_stream_evidence(
                    object
                        .stream(&stream.name_utf16)
                        .context("named stream absent")?,
                )?;
                bytes = bytes
                    .checked_add(stream.length)
                    .context("named stream byte overflow")?;
            }
        } else {
            ensure!(
                object.length == 0
                    && object.sha256.is_none()
                    && object.source_evidence.is_none()
                    && object.source_offset.is_none()
                    && object.source_extents.is_empty()
                    && object.named_streams.is_empty()
                    && object.sparse.is_none(),
                "expected directory carries stream data"
            );
        }
        for stream in object.data_streams() {
            validate_stream_source(stream, &mut source_ranges)?;
        }
    }
    // Additional names are created after all canonical objects. Their
    // directory parents may therefore occur later than the file's primary
    // path, but must still be real canonical directories, never aliases.
    for index in 0..count {
        let owned = domain.object(index)?;
        let object = owned.as_ref();
        for alias in &object.additional_names {
            let parent = destination_key(&alias[..alias.len() - 1], resources);
            ensure!(
                paths.get(&parent) == Some(&true),
                "expected additional name has no directory parent"
            );
        }
    }
    ensure!(
        roots == 1,
        "expected tree must contain exactly one canonical root"
    );
    validate_source_overlap(&mut source_ranges)?;
    if let Some(ranges) = resource_ranges {
        ensure!(
            source_ranges.len() == ranges,
            "expected source-range count changed"
        );
    }
    ensure!(
        bytes == domain.logical_bytes() && bytes <= limits.maximum_logical_bytes,
        "expected logical byte total differs"
    );
    if resources != ntfs_admission::ResourceProfile::AlphaV1 {
        ensure!(
            directories <= limits.maximum_directories
                && count - directories <= limits.maximum_files,
            "expected file/directory counts exceed selected resource profile"
        );
        if let Some(admission) = resources.count_admission()? {
            admission.validate_tree(count - directories, directories, stream_count)?;
            admission.validate_expected_bytes(domain)?;
        }
        if let Some(admission) = resource_admission {
            admission.validate_tree(
                u64::try_from(count - directories)?,
                u64::try_from(directories)?,
                u64::try_from(stream_count)?,
            )?;
            admission.validate_constructor_metadata(domain)?;
            domain.require_resource_metadata(admission)?;
        }
    }
    domain.revalidate_domain()?;
    Ok(())
}

/// The resource profile uses the native extended-path representation rather
/// than an arbitrary directory-depth ceiling. Native creation still checks the
/// complete path including its actual owned root prefix before any source write.
pub(crate) fn expected_path_fits(path: &[String], resource_based: bool) -> bool {
    if !resource_based {
        return path.len() <= 16;
    }
    path.iter()
        .try_fold(0usize, |n, part| {
            n.checked_add(part.encode_utf16().count())?.checked_add(1)
        })
        .is_some_and(|units| units < u16::MAX as usize / 2)
}

/// Charge the complete retained scalar indexes before constructing any of
/// them. Variable object data remains under the authenticated row owner's
/// budget. This pass reads pages, not payload data, and never materializes the
/// whole tree. B-tree node/allocator overhead and UTF-8 case expansion are
/// conservatively included in addition to the physical-range vector capacity.
fn preflight_resource_indexes(
    domain: &impl ExpectedObjectDomain,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
) -> Result<usize> {
    admission.validate()?;
    let mut bytes = 4096u64;
    let mut ranges = 0usize;
    for index in 0..domain.object_count() {
        let object = domain.object(index)?;
        bytes = bytes
            .checked_add(256)
            .context("expected identity index overflow")?;
        for path in std::iter::once(&object.path).chain(object.additional_names.iter()) {
            ensure!(
                expected_path_fits(path, true),
                "expected native path is too long"
            );
            let key_bytes = path
                .iter()
                .try_fold(0u64, |n, part| {
                    n.checked_add(part.len() as u64)?.checked_add(1)
                })
                .context("expected path-index length overflow")?;
            let entry = key_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(256))
                .context("expected path-index allocation overflow")?;
            bytes = bytes
                .checked_add(entry)
                .context("expected path index overflow")?;
            if object.reparse.is_some() && std::ptr::eq(path, &object.path) {
                bytes = bytes
                    .checked_add(entry)
                    .context("reparse path index overflow")?;
            }
        }
        for stream in object.data_streams() {
            ranges = ranges
                .checked_add(usize::from(stream.source_offset.is_some()))
                .and_then(|n| n.checked_add(stream.source_extents.len()))
                .context("expected physical-range count overflow")?;
        }
        let range_bytes = u64::try_from(ranges)?
            .checked_mul(32)
            .context("expected physical-range index overflow")?;
        ensure!(
            bytes
                .checked_add(range_bytes)
                .is_some_and(|n| n <= admission.budget.retained_index_bytes),
            "expected path/identity/physical-range indexes exceed admitted RAM"
        );
    }
    domain.revalidate_domain()?;
    Ok(ranges)
}

pub fn derive(raw: &ntfs::NtfsInspection) -> Result<Tree> {
    derive_profile(raw, false, ntfs_admission::ResourceProfile::AlphaV1)
}
/// Additional ordinary stream forms are materialized from logical bytes. This
/// constructs an independent shadow; it does not admit source-device writes.
pub fn derive_ordinary(raw: &ntfs::NtfsInspection) -> Result<Tree> {
    derive_ordinary_with_resource_profile(raw, ntfs_admission::ResourceProfile::AlphaV1)
}
pub fn derive_ordinary_with_resource_profile(
    raw: &ntfs::NtfsInspection,
    resources: ntfs_admission::ResourceProfile,
) -> Result<Tree> {
    derive_profile(raw, true, resources)
}
fn derive_profile(
    raw: &ntfs::NtfsInspection,
    ordinary: bool,
    resources: ntfs_admission::ResourceProfile,
) -> Result<Tree> {
    let limits = resources.limits();
    ntfs::validate_record_coverage(raw)?;
    ensure!(
        ntfs_admission::has_unique_sorted_records(raw),
        "source path lookup requires uniquely ordered canonical records"
    );
    ensure!(
        raw.schema_version == 1 && resources.supports_source_geometry(&raw.geometry),
        "incomplete record scan or unsupported source geometry"
    );
    ensure!(
        matches!(
            raw.allocation_reconciliation.as_ref().map(|a| &a.status),
            Some(ntfs::AllocationReconciliationStatus::ConsistentRawModel)
        ) && matches!(
            raw.namespace_reconciliation.as_ref().map(|n| &n.status),
            Some(crate::ntfs_namespace::Status::ConsistentRawModel)
        ),
        "raw ownership or namespace is unresolved"
    );
    let sd = raw
        .security_reconciliation
        .as_ref()
        .context("no raw security model")?;
    ensure!(
        sd.status == ntfs_security::Status::ConsistentRawModel,
        "raw security unresolved"
    );
    let mut tree = Tree {
        profile: if ordinary {
            resources.ordinary_shadow_profile()
        } else {
            "native-existing-tree-shadow-v1"
        },
        objects: vec![],
        logical_bytes: 0,
        internal_replacement_pending: vec![],
    };
    let mut paths = BTreeSet::new();
    let mut source_ranges = vec![];
    let mut stream_count = 0usize;
    let source_plan = ntfs_stream_plan::classify_with_resource_profile(raw, resources);
    let source_decisions: BTreeMap<_, _> = source_plan
        .streams
        .iter()
        .map(|decision| {
            (
                (
                    decision.record_number,
                    decision.sequence_number,
                    decision.name_utf16.as_slice(),
                ),
                decision,
            )
        })
        .collect();
    ensure!(
        source_decisions.len() == source_plan.streams.len(),
        "ambiguous source stream decision"
    );
    for f in &raw.files {
        if let Some(role) = ntfs_admission::internal_role(raw, f) {
            tree.internal_replacement_pending.push(role);
            continue;
        }
        let mut names = if ordinary {
            ntfs_admission::user_paths(raw, f).context("unresolved source names")?
        } else {
            vec![ntfs_admission::path(raw, f).context("unresolved source path")?]
        };
        ensure!(
            !names.is_empty() && (!f.is_directory || names.len() == 1),
            "missing source name or unsupported directory links"
        );
        for name in &names {
            ensure!(
                name.len() <= 16
                    && name
                        .iter()
                        .all(|c| valid_component_with_resources(c, resources)),
                "unsupported Windows path"
            );
            ensure!(
                paths.len() < crate::ntfs_namespace::MAX_ENTRIES
                    && paths.insert(destination_key(name, resources)),
                "colliding destination name or namespace name budget exceeded"
            );
        }
        if !f.is_directory {
            stream_count = stream_count
                .checked_add(f.streams.len())
                .context("source DATA stream count overflow")?;
            ensure!(
                stream_count <= ntfs_admission::MAX_DATA_STREAMS,
                "source total DATA stream count exceeds 16,384"
            );
        }
        ensure!(
            !f.streams.iter().any(|stream| !stream.name_utf16.is_empty())
                || names.iter().all(|path| path
                    .first()
                    .is_none_or(|part| !part.eq_ignore_ascii_case("System Volume Information"))),
            "named streams on System Volume Information objects require a separate system-payload implementation"
        );
        let p = names.remove(0);
        if f.record_number == 5 {
            // Root is reconstructed only as a shadow experiment. Its NTFS
            // transactional attribute is explicitly unresolved for admission.
            ensure!(
                p.is_empty() && f.is_directory && f.streams.is_empty(),
                "invalid root"
            );
            ensure!(
                f.attributes.iter().all(|a| a.flags == 0
                    && a.lowest_vcn == 0
                    && ((matches!(a.type_code, 0x10 | 0x30 | 0x50)
                        && a.resident
                        && a.name_utf16.is_empty())
                        || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                            && crate::ntfs_namespace::is_i30(&a.name_utf16))
                        || ntfs_admission::recognized_root_txf(a))),
                "unknown root attributes"
            );
            if f.attributes.iter().any(|a| a.type_code == 0x100) {
                tree.internal_replacement_pending
                    .push("root:$TXF_DATA (not yet admitted for replacement)".into());
            }
        } else {
            let issues = if ordinary {
                ntfs_admission::ordinary_user_issues(raw, f)
            } else {
                ntfs_admission::user_issues(raw, f)
            };
            ensure!(
                issues.is_empty(),
                "record {} exceeds shadow profile: {issues:?}",
                f.record_number
            );
        }
        let binding = sd
            .bindings
            .iter()
            .find(|b| b.record_number == f.record_number && b.sequence_number == f.sequence_number)
            .context("missing descriptor binding")?;
        let descriptor = &sd
            .descriptors
            .iter()
            .find(|d| d.descriptor.sha256 == binding.descriptor_sha256)
            .context("missing descriptor bytes")?
            .descriptor;
        if ordinary {
            n2r_win32::security_descriptor::validate(&hex::decode(&descriptor.relative_hex)?)?;
        } else {
            ensure!(
                descriptor.sacl.state == ntfs_security::AclState::Absent
                    && descriptor.dacl.state == ntfs_security::AclState::Present,
                "initial shadow requires present DACL and absent SACL"
            );
        }
        ensure!(
            ordinary || f.record_number == 5 || descriptor.control & 0x1000 != 0,
            "initial shadow profile requires protected child DACLs"
        );
        let si = f
            .standard_information
            .as_ref()
            .context("missing stored timestamps")?;
        let times = [
            si.creation_time,
            si.access_time,
            si.modification_time,
            si.mft_change_time,
        ];
        let has_verified_eas = crate::ntfs_attestation::has_verified_nonempty_eas(f);
        let reparse = crate::ntfs_reparse::file_point(f)?;
        let ntfs_compression_normalized =
            ordinary && (si.file_attributes & 0x800 != 0 || f.streams.iter().any(|s| s.flags == 1));
        let projected_attributes = crate::ntfs_file_attributes::project_user(f)?;
        ensure!(
            times.iter().all(|t| *t > 0 && *t < i64::MAX as u64)
                && projected_attributes.source_attributes
                    & !(0x2027
                        | if reparse.is_some() { 0x400 } else { 0 }
                        | if f.streams.iter().any(|s| s.flags == 0x8000) {
                            0x200
                        } else {
                            0
                        }
                        | if has_verified_eas { 0x40000 } else { 0 }
                        | if ntfs_compression_normalized {
                            0x800
                        } else {
                            0
                        })
                    == 0,
            "unsupported basic metadata"
        );
        let (source_offset, source_extents, length, sha256, source_evidence, sparse) =
            match f.streams.iter().find(|s| s.name_utf16.is_empty()) {
                Some(s) => {
                    let candidate = source_decisions
                        .get(&(f.record_number, f.sequence_number, s.name_utf16.as_slice()))
                        .copied();
                    let (offset, extents) = planned_stream_source(candidate, resources)?;
                    (
                        offset,
                        extents,
                        s.logical_size,
                        s.logical_sha256.clone(),
                        source_stream_evidence(raw, f, s)?,
                        candidate.and_then(|decision| decision.sparse.clone()),
                    )
                }
                None => (None, Vec::new(), 0, None, None, None),
            };
        let mut named_streams = Vec::new();
        for stream in f
            .streams
            .iter()
            .filter(|stream| !stream.name_utf16.is_empty())
        {
            ensure!(
                !f.is_directory && ordinary,
                "named directory or legacy stream unsupported"
            );
            let candidate = source_decisions
                .get(&(
                    f.record_number,
                    f.sequence_number,
                    stream.name_utf16.as_slice(),
                ))
                .copied();
            let (source_offset, source_extents) = planned_stream_source(candidate, resources)?;
            named_streams.push(NamedStream {
                name_utf16: stream.name_utf16.clone(),
                source_offset,
                source_extents,
                length: stream.logical_size,
                sha256: stream.logical_sha256.clone(),
                source_evidence: source_stream_evidence(raw, f, stream)?,
                sparse: candidate.and_then(|decision| decision.sparse.clone()),
            });
        }
        named_streams.sort_by(|a, b| a.name_utf16.cmp(&b.name_utf16));
        tree.logical_bytes = tree
            .logical_bytes
            .checked_add(length)
            .context("logical size overflow")?;
        for stream in &named_streams {
            tree.logical_bytes = tree
                .logical_bytes
                .checked_add(stream.length)
                .context("named logical size overflow")?;
        }
        let object = Object {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            path: p,
            additional_names: names,
            directory: f.is_directory,
            stored_times: times,
            attributes: crate::ntfs_attestation::default_stream_attributes(
                f,
                projected_attributes.win32_attributes,
            )? & !if ntfs_compression_normalized {
                0x800
            } else {
                0
            },
            ntfs_compression_normalized,
            security: hex::decode(&descriptor.relative_hex)?,
            api_security: None,
            extended_attributes: Some(crate::ntfs_extended_attributes::file_set(f)?),
            reparse,
            source_offset,
            source_extents,
            length,
            sha256,
            source_evidence,
            named_streams,
            sparse,
        };
        for stream in object.data_streams() {
            validate_stream_source(stream, &mut source_ranges)?;
        }
        tree.objects.push(object);
    }
    validate_source_overlap(&mut source_ranges)?;
    let directories = tree.objects.iter().filter(|o| o.directory).count();
    ensure!(
        directories > 0
            && tree.objects.len() <= resources.maximum_objects()
            && directories <= limits.maximum_directories
            && tree.objects.len() - directories <= limits.maximum_files
            && tree.logical_bytes <= limits.maximum_logical_bytes
            && tree.objects.iter().filter(|o| o.path.is_empty()).count() == 1,
        "tree budget or root differs"
    );
    tree.objects.sort_by_key(|o| (o.path.len(), o.path.clone()));
    if resources != ntfs_admission::ResourceProfile::AlphaV1 {
        ExpectedTree::from(&tree).validate_with_resource_profile(resources)?;
    }
    Ok(tree)
}

fn planned_stream_source(
    candidate: Option<&ntfs_stream_plan::StreamDecision>,
    resources: ntfs_admission::ResourceProfile,
) -> Result<(Option<u64>, Vec<ntfs::Extent>)> {
    if resources != ntfs_admission::ResourceProfile::AlphaV1
        || candidate.is_some_and(|c| c.sparse.is_some())
    {
        ensure!(
            candidate.is_some_and(
                |decision| decision.disposition != ntfs_stream_plan::Disposition::Reject
            ),
            "source stream is not a candidate under the selected resource profile"
        );
    }
    let source_offset = candidate
        .filter(|decision| decision.disposition == ntfs_stream_plan::Disposition::RetainCandidate)
        .and_then(|decision| decision.source_offset);
    let source_extents = candidate
        .filter(|decision| {
            matches!(
                decision.disposition,
                ntfs_stream_plan::Disposition::RetainCandidate
                    | ntfs_stream_plan::Disposition::MixedCandidate
            )
        })
        .map(|decision| decision.source_extents.clone())
        .unwrap_or_default();
    Ok((source_offset, source_extents))
}

fn validate_stream_source(stream: StreamRef<'_>, physical: &mut Vec<(u64, u64)>) -> Result<()> {
    validate_stream_evidence(stream)?;
    if let Some(sparse) = stream.sparse {
        sparse.validate(stream.length)?;
        ensure!(
            stream.source_offset.is_none(),
            "sparse stream requires explicit physical islands"
        );
        let initialized_end = sparse.initialized_length / 4096 * 4096;
        let mut expected = Vec::new();
        for allocated in &sparse.allocated {
            let end = allocated
                .offset
                .checked_add(allocated.length)
                .context("sparse allocation overflow")?
                .min(initialized_end);
            if allocated.offset < end {
                append_logical(&mut expected, allocated.offset, end - allocated.offset)?;
            }
        }
        let mut actual = Vec::new();
        let mut previous_end = 0u64;
        for extent in stream.source_extents {
            let offset = extent
                .physical_offset
                .context("sparse retained island has no physical source")?;
            let logical_end = extent
                .logical_offset
                .checked_add(extent.length)
                .context("sparse island overflow")?;
            ensure!(
                extent.length > 0
                    && extent.length.is_multiple_of(4096)
                    && extent.logical_offset.is_multiple_of(4096)
                    && extent.logical_offset >= previous_end
                    && logical_end <= initialized_end
                    && offset.is_multiple_of(4096)
                    && offset.checked_add(extent.length).is_some(),
                "invalid sparse initialized physical island"
            );
            append_logical(&mut actual, extent.logical_offset, extent.length)?;
            physical.push((offset, extent.length));
            previous_end = logical_end;
        }
        ensure!(
            actual == expected,
            "sparse initialized islands do not cover the allocated VDL prefix"
        );
        return Ok(());
    }
    ensure!(
        stream.source_offset.is_none() || stream.source_extents.is_empty(),
        "expected stream mixes single and fragmented source runs"
    );
    if let Some(offset) = stream.source_offset {
        ensure!(
            stream.length > 0
                && stream.length.is_multiple_of(4096)
                && offset.is_multiple_of(4096)
                && offset.checked_add(stream.length).is_some(),
            "expected single source run differs"
        );
        physical.push((offset, stream.length));
    }
    if !stream.source_extents.is_empty() {
        let mut covered = 0u64;
        for extent in stream.source_extents {
            let offset = extent
                .physical_offset
                .context("expected source run has a hole")?;
            ensure!(
                extent.logical_offset == covered
                    && extent.length > 0
                    && extent.length.is_multiple_of(4096)
                    && offset.is_multiple_of(4096)
                    && offset.checked_add(extent.length).is_some(),
                "expected fragmented source run differs"
            );
            covered = covered
                .checked_add(extent.length)
                .context("source run overflow")?;
            physical.push((offset, extent.length));
        }
        ensure!(
            covered <= stream.length / 4096 * 4096,
            "source initialized-cluster prefix differs"
        );
    }
    Ok(())
}

fn source_stream_evidence(
    raw: &ntfs::NtfsInspection,
    file: &ntfs::FileInventory,
    stream: &ntfs::StreamInventory,
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
                    && crate::ntfs_attestation::extent_identity_stream_request(raw, file, stream)?
                        .is_some(),
                "source extent-only stream is not eligible"
            );
            Ok(Some(if stream.logical_size.is_multiple_of(4096) {
                SourceStreamEvidence::ExtentIdentityV1
            } else {
                SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1
            }))
        }
        _ => anyhow::bail!("source stream evidence is incomplete"),
    }
}

fn validate_stream_evidence(stream: StreamRef<'_>) -> Result<()> {
    match (stream.sha256, stream.source_evidence) {
        (Some(digest), None) => ensure!(
            n2r_win32::content_digest::is_hex(digest),
            "invalid content digest"
        ),
        (None, Some(evidence)) => {
            let prefix = stream.length / 4096 * 4096;
            let partial_tail =
                evidence == SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1;
            let shape_matches = match evidence {
                SourceStreamEvidence::ExtentIdentityV1 => stream.length.is_multiple_of(4096),
                SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1 => {
                    !stream.length.is_multiple_of(4096) && stream.tail_requires_materialization()
                }
            };
            ensure!(
                prefix != 0 && stream.sparse.is_none() && shape_matches,
                "extent-only stream prefix or explicit tail evidence differs"
            );
            let mut covered = 0u64;
            if let Some(offset) = stream.source_offset {
                ensure!(
                    !partial_tail
                        && stream.source_extents.is_empty()
                        && offset.is_multiple_of(4096)
                        && offset.checked_add(stream.length).is_some(),
                    "invalid extent-only single mapping"
                );
                covered = stream.length;
            } else {
                for extent in stream.source_extents {
                    ensure!(
                        extent.logical_offset == covered
                            && extent.length > 0
                            && extent.length.is_multiple_of(4096)
                            && extent
                                .physical_offset
                                .is_some_and(|p| p.is_multiple_of(4096)
                                    && p.checked_add(extent.length).is_some()),
                        "invalid extent-only mapping"
                    );
                    covered = covered
                        .checked_add(extent.length)
                        .context("extent-only coverage overflow")?;
                }
            }
            ensure!(
                covered == prefix,
                "extent-only mapping does not cover the complete initialized cluster prefix"
            );
        }
        _ => anyhow::bail!("missing or ambiguous source stream evidence"),
    }
    Ok(())
}

fn append_logical(ranges: &mut Vec<LogicalRange>, offset: u64, length: u64) -> Result<()> {
    if let Some(last) = ranges.last_mut()
        && last.offset.checked_add(last.length) == Some(offset)
    {
        last.length = last
            .length
            .checked_add(length)
            .context("logical coalescing overflow")?;
    } else {
        ranges.push(LogicalRange { offset, length });
    }
    Ok(())
}

fn validate_source_overlap(physical: &mut [(u64, u64)]) -> Result<()> {
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|pair| pair[0]
            .0
            .checked_add(pair[0].1)
            .is_some_and(|end| end <= pair[1].0)),
        "overlapping default or named stream source payloads"
    );
    Ok(())
}

pub(crate) fn valid_component(s: &str) -> bool {
    let upper = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !s.is_empty()
        && s.len() <= 100
        && !s.ends_with([' ', '.'])
        && s.bytes()
            .all(|c| (c == b' ' || c.is_ascii_graphic()) && !b"<>:\"/\\|?*".contains(&c))
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(&upper.as_str())
}

fn valid_component_with_resources(s: &str, resources: ntfs_admission::ResourceProfile) -> bool {
    if resources.is_streaming() {
        n2r_win32::shadow_names::valid_unicode_component(s)
    } else {
        valid_component(s)
    }
}

fn destination_key(path: &[String], resources: ntfs_admission::ResourceProfile) -> String {
    if resources.is_streaming() {
        n2r_win32::shadow_names::conservative_path_key(path)
    } else {
        path.join("\\").to_ascii_uppercase()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_alias_traversal_devices_and_ambiguous_components() {
        for s in [
            "", ".", "..", "a.", "a ", "CON.txt", "CON .txt", "lpt9.bin", "a:b", "a\\b", "a/b",
            "a?b", "a*b", "a\0b", "é",
        ] {
            assert!(!valid_component(s), "{s:?}");
        }
        assert!(valid_component("doc1.bin"));
        assert!(valid_component("Quarterly Report 1.txt"));
        assert!(valid_component("Q4 (final) #1 & notes.txt"));
    }
}
