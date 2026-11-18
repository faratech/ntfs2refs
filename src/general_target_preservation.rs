//! Freeze the ReFS target, verify its native semantics while read-only, and
//! bracket that observation with unchanged raw-image hashes. Serialized reports cannot create
//! this witness or supply an unfrozen target to journal activation.
use crate::{
    general_shadow, lab_reconstruct, ntfs_attestation, ntfs_inspect, refs_inspect, shadow_tree,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralDiskState, GeneralFrozenPartition, GeneralLiveRefsLayoutObservation, NativeEvent,
    general_layout::GeneralSourceShadowBinding,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

mod allocation;
pub use allocation::{CapturedDeltaAllocationDiagnostic, ProtectedAllocationCoverage};

fn validate_expected_owner(
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<()> {
    expected.revalidate_domain()?;
    shadow_tree::validate_expected_domain(expected, resources)?;
    if let Some(admission) = resources
        .count_admission()?
        .filter(|a| a.requires_paged_metadata())
    {
        expected.require_paged_metadata(
            admission.expected_page_budget()?,
            u64::from(admission.maximum_expected_tree_bytes),
        )?;
    }
    Ok(())
}

fn bracket_image_with_resource_profile<R: Read + Seek, T>(
    image: &mut R,
    length: u64,
    resources: crate::ntfs_admission::ResourceProfile,
    observe: impl FnOnce(&mut R) -> Result<T>,
) -> Result<(T, String)> {
    let before = lab_reconstruct::hash_range_with_resource_profile(image, 0, length, resources)?;
    let observation = observe(image)?;
    let after = lab_reconstruct::hash_range_with_resource_profile(image, 0, length, resources)?;
    ensure!(
        before == after,
        "protected semantic observation changed frozen image bytes"
    );
    Ok((observation, hex::encode(after)))
}

/// Protected native metadata/layout of one byte-identical frozen shadow.
/// Placeholder contents remain unverified. Neither this opaque witness nor
/// its serialized diagnostic report constitutes source or write admission.
#[derive(Debug, Serialize)]
pub struct ProtectedTargetLayout {
    native: GeneralLiveRefsLayoutObservation,
    raw_sha256: String,
    expected_tree_sha256: String,
    frozen_state: GeneralDiskState,
    resources: crate::ntfs_admission::ResourceProfile,
    routes: n2r_win32::shadow_native::private_tree::SourceBackedRoutes,
    allocation_coverage: ProtectedAllocationCoverage,
    raw_image_unchanged: bool,
    /// Present only when the closing bracket covered the protected allocation
    /// rather than the complete image (allocation-bounded mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    bracket_closure: Option<AllocationBracketClosure>,
    logical_payload_verified: bool,
    complete_allocation_graph_verified: bool,
    source_admitted: bool,
    conversion_qualified: bool,
}

impl ProtectedTargetLayout {
    pub fn native(&self) -> &GeneralLiveRefsLayoutObservation {
        &self.native
    }
    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }
    pub fn expected_tree_sha256(&self) -> &str {
        &self.expected_tree_sha256
    }
    pub fn routes(&self) -> &n2r_win32::shadow_native::private_tree::SourceBackedRoutes {
        &self.routes
    }
    pub fn frozen_state(&self) -> &GeneralDiskState {
        &self.frozen_state
    }
    pub fn resource_profile(&self) -> crate::ntfs_admission::ResourceProfile {
        self.resources
    }
    pub fn allocation_coverage(&self) -> &ProtectedAllocationCoverage {
        &self.allocation_coverage
    }
}

/// Verify native metadata and stream layout after final freeze, with complete
/// raw-image equality around the physically read-only native observation.
/// File contents are deliberately not read from allocation-only placeholders;
/// the caller must separately prove the complete source-backed target image.
pub fn verify_frozen_layout_with_resource_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    verify_frozen_layout_profile(target, pair, expected, resources, None, events)
}

/// Opt-in initialized-suffix verification for a source-backed composite. The
/// caller freshly obtains each expectation through the frozen NTFS reader.
pub fn verify_frozen_layout_residuals_with_resource_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    verify_frozen_layout_profile(target, pair, expected, resources, Some(residuals), events)
}

fn verify_frozen_layout_profile(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: Option<&[n2r_win32::shadow_native::LayoutResidualExpectation]>,
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    validate_expected_owner(expected, resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected layout target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "layout observation requires a frozen target"
    );
    let expected_tree_sha256 = crate::general_qualification::pretty_json_sha256(expected)?;
    let input = general_shadow::ExpectedInputs(expected);
    let length = target.byte_len();
    let ((native, anchors), raw_sha256) =
        bracket_image_with_resource_profile(target, length, resources, |target| {
            let same_security = |a: &[u8], b: &[u8]| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            };
            let native = match residuals {
                Some(residuals) => target.observe_refs_layout_residuals_domain(
                    pair.clone(),
                    &input,
                    residuals,
                    same_security,
                    resources.native_profile(),
                    events,
                )?,
                None => target.observe_refs_layout_domain(
                    pair.clone(),
                    &input,
                    same_security,
                    resources.native_profile(),
                    events,
                )?,
            };
            // This bounded raw inspection shares the same unchanged-image
            // bracket. Unknown/rejected anchor forms remain explicit diagnostics;
            // they must not silently establish required-byte completeness.
            let anchors = refs_inspect::inspect_with_resource_profile(target, length, resources)
                .and_then(|refs| crate::refs_write_set::observed_anchors(&refs))
                .map_err(|error| format!("{error:#}"));
            Ok((native, anchors))
        })?;
    ensure!(
        native.before() == &before
            && native.after() == &before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair
            && target.state(events)? == before,
        "protected layout observation changed its identity or persistent exclusion"
    );
    let routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(&native)?;
    let allocation_coverage = allocation::reconcile(&native, anchors, &raw_sha256, length)?;
    expected.revalidate_domain()?;
    Ok(ProtectedTargetLayout {
        native,
        raw_sha256,
        expected_tree_sha256,
        frozen_state: before,
        resources,
        routes,
        allocation_coverage,
        raw_image_unchanged: true,
        bracket_closure: None,
        logical_payload_verified: false,
        complete_allocation_graph_verified: false,
        source_admitted: false,
        conversion_qualified: false,
    })
}

#[derive(Debug, Serialize)]
pub struct AllocationBracketClosure {
    opening: &'static str,
    raw_sha256_meaning: &'static str,
    opening_chunks: usize,
    opening_bytes: u64,
    closing_ranges: usize,
    closing_chunks: usize,
    closing_bytes_reread: u64,
    free_space_rechecked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_consumption: Option<RoutedPayloadBracketScope>,
}

#[derive(Debug, Serialize)]
struct RoutedPayloadBracketScope {
    scope: &'static str,
    framed_hash_domain: &'static str,
    raw_metadata_hash_algorithm: &'static str,
    opening_hash_counts: RawBracketHashCounts,
    closing_hash_counts: RawBracketHashCounts,
    protected_routes_sha256: String,
    excluded_payload_map_sha256: String,
    excluded_payload_ranges: Vec<crate::refs_write_set::ByteRange>,
    excluded_payload_bytes: u64,
    consumed_ranges_sha256: String,
    preliminary_and_bracketed_native_routes_identical: bool,
    preliminary_and_bracketed_allocation_maps_identical: bool,
    raw_inspection_reads_covered: bool,
}

#[derive(Debug, Default, Serialize)]
struct RawBracketHashCounts {
    raw_bytes_read: u64,
    chunks_read: usize,
    zero_chunks_observed: usize,
    zero_bytes_observed: u64,
    zero_digest_cache_hits: usize,
    zero_lengths_hashed: usize,
    bytes_processed_by_inner_sha256: u64,
}

const BRACKET_CHUNK: u64 = 1024 * 1024;

/// Sorted distinct 1 MiB chunk indices overlapping the sorted `ranges`.
fn chunk_indices(ranges: &[crate::refs_write_set::ByteRange], length: u64) -> Result<Vec<u64>> {
    let mut indices: Vec<u64> = Vec::new();
    for range in ranges {
        let end = range
            .offset
            .checked_add(range.length)
            .context("bracket range overflow")?;
        ensure!(
            range.length != 0 && end <= length,
            "bracket range escapes the image"
        );
        for index in range.offset / BRACKET_CHUNK..=(end - 1) / BRACKET_CHUNK {
            if indices.last() != Some(&index) {
                indices.push(index);
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// The bracket chunks at `indices`, each clipped to the image end.
fn bracket_chunks(indices: &[u64], length: u64) -> Result<Vec<crate::parallel_digest::Chunk>> {
    indices
        .iter()
        .map(|&index| {
            let offset = index * BRACKET_CHUNK;
            Ok(crate::parallel_digest::Chunk {
                offset,
                length: usize::try_from((length - offset).min(BRACKET_CHUNK))?,
            })
        })
        .collect()
}

/// Opening pass over only the chunks overlapping `ranges`: their XXH3-128
/// change-detection digests, plus one SHA-256 over every (index, digest) pair.
/// The image is read on this thread while the spare cores hash.
fn open_allocated_bracket(
    image: &mut GeneralFrozenPartition,
    length: u64,
    ranges: &[crate::refs_write_set::ByteRange],
) -> Result<(String, Vec<(u64, [u8; 16])>, u64)> {
    let indices = chunk_indices(ranges, length)?;
    let chunks = bracket_chunks(&indices, length)?;
    let hashed = crate::parallel_digest::digest_frozen_chunks(image, &chunks)?;
    let bytes = chunks.iter().map(|chunk| chunk.length as u64).sum();
    let digests: Vec<_> = indices.into_iter().zip(hashed).collect();
    let mut summary = n2r_win32::sha256_native::Sha256::new()?;
    for (index, digest) in &digests {
        summary.update(&index.to_le_bytes())?;
        summary.update(digest)?;
    }
    Ok((hex::encode(summary.finish()?), digests, bytes))
}

/// Recheck every chunk overlapping the sorted `ranges` against the opening
/// pass. A chunk the opening pass did not hash refuses before any read.
fn close_allocated_bracket(
    image: &mut GeneralFrozenPartition,
    length: u64,
    opened: &[(u64, [u8; 16])],
    ranges: &[crate::refs_write_set::ByteRange],
) -> Result<(usize, u64)> {
    let indices = chunk_indices(ranges, length)?;
    let expected = indices
        .iter()
        .map(|&index| {
            opened
                .binary_search_by_key(&index, |(opened, _)| *opened)
                .map(|position| opened[position].1)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "closing allocation includes a chunk the opening pass did not hash"
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let chunks = bracket_chunks(&indices, length)?;
    let hashed = crate::parallel_digest::digest_frozen_chunks(image, &chunks)?;
    ensure!(
        hashed == expected,
        "protected observation changed allocated frozen image bytes"
    );
    let reread = chunks.iter().map(|chunk| chunk.length as u64).sum();
    Ok((indices.len(), reread))
}

/// Allocation-bounded counterpart of
/// [`verify_frozen_layout_residuals_with_resource_profile`] under the user's
/// allocation guarantee. A first protected read-only mount supplies the native
/// allocation map; the bracket opens over its chunks, the full observation runs,
/// both mounts must report the identical map, and the bracket closes over the
/// observed allocation. No pass reads the complete image.
pub fn verify_frozen_layout_residuals_allocation_closed(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    validate_expected_owner(expected, resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected layout target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "layout observation requires a frozen target"
    );
    let expected_tree_sha256 = crate::general_qualification::pretty_json_sha256(expected)?;
    let input = general_shadow::ExpectedInputs(expected);
    let length = target.byte_len();
    let witness = target.observe_refs_allocation_readonly(resources.native_profile(), events)?;
    target.validate_readonly_allocation_witness(&witness, events)?;
    let premap = witness.snapshot().metadata_inclusive();
    let opening: Vec<_> = premap
        .ranges
        .iter()
        .map(|range| crate::refs_write_set::ByteRange {
            offset: range.offset,
            length: range.length,
        })
        .collect();
    let (raw_sha256, chunks, opening_bytes) = open_allocated_bracket(target, length, &opening)?;
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let native = target.observe_refs_layout_residuals_domain(
        pair.clone(),
        &input,
        residuals,
        same_security,
        resources.native_profile(),
        events,
    )?;
    let anchors = refs_inspect::inspect_with_resource_profile(target, length, resources)
        .and_then(|refs| crate::refs_write_set::observed_anchors(&refs))
        .map_err(|error| format!("{error:#}"));
    ensure!(
        native.before() == &before
            && native.after() == &before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair
            && target.state(events)? == before,
        "protected layout observation changed its identity or persistent exclusion"
    );
    let observed_map = native
        .report()
        .native()
        .metadata_allocation
        .as_ref()
        .context("protected allocation bitmap absent")?;
    ensure!(
        observed_map.bitmap_sha256 == premap.bitmap_sha256
            && observed_map.cluster_count == premap.cluster_count,
        "the two protected read-only mounts reported different allocation maps"
    );
    let routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(&native)?;
    let allocation_coverage = allocation::reconcile(&native, anchors, &raw_sha256, length)?;
    let selection = allocation_coverage.observed_ranges(&native)?;
    let (closing_chunks, closing_bytes_reread) =
        close_allocated_bracket(target, length, &chunks, &selection)?;
    ensure!(
        target.state(events)? == before,
        "protected allocation bracket changed persistent exclusion"
    );
    expected.revalidate_domain()?;
    Ok(ProtectedTargetLayout {
        native,
        raw_sha256,
        expected_tree_sha256,
        frozen_state: before,
        resources,
        routes,
        allocation_coverage,
        raw_image_unchanged: false,
        bracket_closure: Some(AllocationBracketClosure {
            opening: "1 MiB chunk XXH3-128 digests over the allocation map of a prior protected read-only mount",
            raw_sha256_meaning: "SHA-256 over the opening (chunk index, XXH3-128 chunk digest) pairs; detects change between the two passes, not a cryptographic content hash or a whole-image hash",
            opening_chunks: chunks.len(),
            opening_bytes,
            closing_ranges: selection.len(),
            closing_chunks,
            closing_bytes_reread,
            free_space_rechecked: false,
            raw_consumption: None,
        }),
        logical_payload_verified: false,
        complete_allocation_graph_verified: false,
        source_admitted: false,
        conversion_qualified: false,
    })
}

/// The full-content path retains its historical bracket and serialized scope.
/// Fast verification may exclude only exact physical prefixes that the opaque
/// native route witness says the composite replaces with logical source bytes.
pub fn verify_frozen_layout_residuals_allocation_closed_with_policy(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
    policy: crate::verification_policy::VerificationPolicy,
) -> Result<ProtectedTargetLayout> {
    if policy.is_full_content() {
        return verify_frozen_layout_residuals_allocation_closed(
            target, pair, expected, resources, residuals, events,
        );
    }
    verify_nonrouted_allocation_closed(target, pair, expected, resources, residuals, events)
}

fn recorded_anchors(
    target: &mut GeneralFrozenPartition,
    length: u64,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<(
    std::result::Result<Vec<crate::refs_write_set::ByteRange>, String>,
    Vec<crate::refs_write_set::ByteRange>,
)> {
    let mut recorded = ntfs_inspect::ReadRecorder::new(target)?;
    let anchors = refs_inspect::inspect_with_resource_profile(&mut recorded, length, resources)
        .and_then(|refs| crate::refs_write_set::observed_anchors(&refs))
        .map_err(|error| format!("{error:#}"));
    // Hash the containing 4 KiB granules, never a 1 MiB envelope crossing an
    // excluded prefix. Actual reads remain recorded even if inspection fails.
    let reads = recorded
        .ranges()
        .into_iter()
        .map(|(offset, bytes)| {
            let end = offset
                .checked_add(bytes)
                .context("raw inspection read overflow")?;
            ensure!(end <= length, "raw inspection read escapes partition");
            let start = offset / 4096 * 4096;
            let end = end
                .checked_next_multiple_of(4096)
                .context("raw inspection alignment overflow")?;
            ensure!(end <= length, "raw inspection granule escapes partition");
            Ok(crate::refs_write_set::ByteRange {
                offset: start,
                length: end - start,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((anchors, allocation::union(reads, length)?))
}

fn consumed_chunks(
    ranges: &[crate::refs_write_set::ByteRange],
) -> Result<Vec<crate::parallel_digest::Chunk>> {
    let mut chunks = Vec::new();
    for range in ranges {
        let mut done = 0;
        while done < range.length {
            let count = (range.length - done).min(BRACKET_CHUNK);
            chunks
                .try_reserve(1)
                .context("raw consumption bracket allocation failed")?;
            chunks.push(crate::parallel_digest::Chunk {
                offset: range.offset + done,
                length: count as usize,
            });
            done += count;
        }
    }
    Ok(chunks)
}

/// A chunk can only be minted here after the complete actual read, every
/// zero-byte assertion and the exact v2 hash frame have consumed its bytes.
/// Its borrow prevents recycling the closing buffer while a consumer uses it.
struct ConsumedShadowChunk<'buf> {
    offset: u64,
    bytes: &'buf [u8],
}

struct RawConsumptionHash {
    hash: n2r_win32::sha256_native::Sha256,
    zero_digests: Vec<Option<[u8; 32]>>,
    counts: RawBracketHashCounts,
}
impl RawConsumptionHash {
    fn new(length: u64, exclusions_sha256: &str, chunk_count: usize) -> Result<Self> {
        let mut hash = n2r_win32::sha256_native::Sha256::new()?;
        hash.update(b"n2r-refs-source-backed-raw-consumption-v2\0")?;
        hash.update(&length.to_le_bytes())?;
        hash.update(exclusions_sha256.as_bytes())?;
        hash.update(&(chunk_count as u64).to_le_bytes())?;
        // Exact-length SHA-256 values, never inferred bitmap contents. Chunk
        // lengths are 4 KiB multiples, so this cache has at most 256 live entries
        // with the current 1 MiB bound and never grows with the volume's size.
        let cache_slots = BRACKET_CHUNK as usize / 4096 + 1;
        let mut zero_digests: Vec<Option<[u8; 32]>> = Vec::new();
        zero_digests
            .try_reserve_exact(cache_slots)
            .context("raw metadata zero-digest cache allocation failed")?;
        zero_digests.resize(cache_slots, None);
        let counts = RawBracketHashCounts::default();
        Ok(Self {
            hash,
            zero_digests,
            counts,
        })
    }

    fn consume(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= BRACKET_CHUNK as usize
                && bytes.len().is_multiple_of(4096)
                && offset.is_multiple_of(4096),
            "raw metadata bracket chunk exceeds its read bound"
        );
        self.hash.update(&offset.to_le_bytes())?;
        self.hash.update(&(bytes.len() as u64).to_le_bytes())?;
        self.counts.raw_bytes_read = self
            .counts
            .raw_bytes_read
            .checked_add(bytes.len() as u64)
            .context("raw metadata read accounting overflow")?;
        self.counts.chunks_read += 1;
        let zero = bytes.iter().all(|&byte| byte == 0);
        let cached = if zero {
            self.zero_digests[bytes.len() / 4096]
        } else {
            None
        };
        let digest = if let Some(digest) = cached {
            self.counts.zero_digest_cache_hits += 1;
            digest
        } else {
            // Every nonzero chunk, and the first actually observed zero chunk
            // of each exact length, is hashed over all of its actual bytes.
            let mut chunk_hash = n2r_win32::sha256_native::Sha256::new()?;
            chunk_hash.update(bytes)?;
            let digest = chunk_hash.finish()?;
            self.counts.bytes_processed_by_inner_sha256 = self
                .counts
                .bytes_processed_by_inner_sha256
                .checked_add(bytes.len() as u64)
                .context("raw metadata hash accounting overflow")?;
            if zero {
                self.zero_digests[bytes.len() / 4096] = Some(digest);
                self.counts.zero_lengths_hashed += 1;
            }
            digest
        };
        if zero {
            self.counts.zero_chunks_observed += 1;
            self.counts.zero_bytes_observed = self
                .counts
                .zero_bytes_observed
                .checked_add(bytes.len() as u64)
                .context("raw metadata zero-byte accounting overflow")?;
        }
        // Frame boundaries and the exact length are authenticated outside the
        // inner SHA-256. Reuse is allowed only after reading and checking every
        // actual byte for zero, never from allocation or sparsity assumptions.
        self.hash.update(&digest)?;
        Ok(())
    }

    fn finish(self) -> Result<(String, RawBracketHashCounts)> {
        Ok((hex::encode(self.hash.finish()?), self.counts))
    }
}

fn hash_consumed_chunks(
    target: &mut GeneralFrozenPartition,
    length: u64,
    exclusions_sha256: &str,
    chunks: &[crate::parallel_digest::Chunk],
) -> Result<(String, RawBracketHashCounts)> {
    let mut hash = RawConsumptionHash::new(length, exclusions_sha256, chunks.len())?;
    let mut buffer = vec![0u8; BRACKET_CHUNK as usize];
    for chunk in chunks {
        ensure!(
            chunk.length <= buffer.len(),
            "raw metadata bracket chunk exceeds its read bound"
        );
        target.seek(std::io::SeekFrom::Start(chunk.offset))?;
        target.read_exact(&mut buffer[..chunk.length])?;
        hash.consume(chunk.offset, &buffer[..chunk.length])?;
    }
    hash.finish()
}

/// One bounded actual closing buffer, pulled in increasing physical order by
/// capture. All skipped chunks are still read/authenticated before completion.
/// No hash, bitmap or serialized value can supply bytes through this object.
struct ClosingShadowConsumption<'chunks> {
    chunks: &'chunks [crate::parallel_digest::Chunk],
    hash: RawConsumptionHash,
    buffer: Vec<u8>,
    next: usize,
    loaded: Option<usize>,
}
impl<'chunks> ClosingShadowConsumption<'chunks> {
    fn new(
        length: u64,
        exclusions_sha256: &str,
        chunks: &'chunks [crate::parallel_digest::Chunk],
    ) -> Result<Self> {
        Ok(Self {
            chunks,
            hash: RawConsumptionHash::new(length, exclusions_sha256, chunks.len())?,
            buffer: vec![0u8; BRACKET_CHUNK as usize],
            next: 0,
            loaded: None,
        })
    }

    fn consume_next(&mut self, target: &mut GeneralFrozenPartition) -> Result<()> {
        let chunk = self.chunks.get(self.next).context("closing chunk absent")?;
        ensure!(
            chunk.length <= self.buffer.len(),
            "closing chunk exceeds its buffer"
        );
        target.seek(std::io::SeekFrom::Start(chunk.offset))?;
        target.read_exact(&mut self.buffer[..chunk.length])?;
        self.hash
            .consume(chunk.offset, &self.buffer[..chunk.length])?;
        self.loaded = Some(self.next);
        self.next += 1;
        Ok(())
    }

    fn loaded_chunk(&self) -> Result<ConsumedShadowChunk<'_>> {
        let chunk = &self.chunks[self
            .loaded
            .context("closing buffer has no consumed chunk")?];
        Ok(ConsumedShadowChunk {
            offset: chunk.offset,
            bytes: &self.buffer[..chunk.length],
        })
    }

    fn finish(
        mut self,
        target: &mut GeneralFrozenPartition,
    ) -> Result<(String, RawBracketHashCounts)> {
        while self.next < self.chunks.len() {
            self.consume_next(target)?;
        }
        self.hash.finish()
    }
}
impl crate::general_shadow::source_backed::ClosingShadowBytes for ClosingShadowConsumption<'_> {
    fn read_shadow_exact(
        &mut self,
        target: &mut GeneralFrozenPartition,
        offset: u64,
        output: &mut [u8],
    ) -> Result<u64> {
        let end = offset
            .checked_add(output.len() as u64)
            .context("closing supply end overflow")?;
        let first = self
            .chunks
            .partition_point(|chunk| chunk.offset + chunk.length as u64 <= offset);
        let mut cursor = offset;
        for chunk in &self.chunks[first..] {
            if cursor == end {
                break;
            }
            if chunk.offset > cursor {
                break;
            }
            cursor = end.min(chunk.offset + chunk.length as u64);
        }
        // Preserve ordinary reader behavior for an unsupported/nonmonotone
        // request. The complete closing pass and its final equality still run.
        if cursor != end
            || self
                .loaded
                .is_some_and(|loaded| offset < self.chunks[loaded].offset)
        {
            target.seek(std::io::SeekFrom::Start(offset))?;
            target.read_exact(output)?;
            return Ok(0);
        }
        let mut done = 0;
        while done < output.len() {
            let position = offset + done as u64;
            while self.loaded.is_none_or(|loaded| {
                let chunk = &self.chunks[loaded];
                position >= chunk.offset + chunk.length as u64
            }) {
                self.consume_next(target)?;
            }
            let consumed = self.loaded_chunk()?;
            let start = usize::try_from(
                position
                    .checked_sub(consumed.offset)
                    .context("closing supply precedes consumed buffer")?,
            )?;
            let count = (output.len() - done).min(consumed.bytes.len() - start);
            output[done..done + count].copy_from_slice(&consumed.bytes[start..start + count]);
            done += count;
        }
        Ok(output.len() as u64)
    }
}

/// Raw bytes inside a route cannot affect this composite: SourceBackedShadow
/// supplies that entire physical interval from the admitted logical NTFS
/// stream. This is a read-consumption proof, never a claim that the complement
/// of file data is a complete ReFS metadata graph. Every other allocated byte,
/// including reservations, zero regions and unknown owners, stays bracketed.
fn verify_nonrouted_allocation_closed(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
) -> Result<ProtectedTargetLayout> {
    verify_nonrouted_allocation_closed_with_consumption(
        target,
        pair,
        expected,
        resources,
        residuals,
        events,
        |_, _, _, _| Ok(()),
    )
    .map(|(protected, ())| protected)
}

pub(crate) fn verify_nonrouted_allocation_closed_with_consumption<T>(
    target: &mut GeneralFrozenPartition,
    pair: GeneralSourceShadowBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    resources: crate::ntfs_admission::ResourceProfile,
    residuals: &[n2r_win32::shadow_native::LayoutResidualExpectation],
    events: &mut Vec<NativeEvent>,
    consume: impl FnOnce(
        &mut GeneralFrozenPartition,
        &n2r_win32::shadow_native::private_tree::SourceBackedRoutes,
        &[crate::refs_write_set::ByteRange],
        &mut dyn crate::general_shadow::source_backed::ClosingShadowBytes,
    ) -> Result<T>,
) -> Result<(ProtectedTargetLayout, T)> {
    pair.validate_with_resource_profile(resources.native_profile())?;
    validate_expected_owner(expected, resources)?;
    ensure!(
        target.binding() == &pair.shadow,
        "protected layout target binding differs"
    );
    let before = target.state(events)?;
    ensure!(
        before.disk_attributes == 3,
        "layout observation requires a frozen target"
    );
    let length = target.byte_len();
    let expected_tree_sha256 = crate::general_qualification::pretty_json_sha256(expected)?;
    let input = general_shadow::ExpectedInputs(expected);
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    // Routes must exist before exclusions are chosen. A preliminary full
    // native metadata observation replaces no bracket; the second complete
    // observation below is still enclosed by both raw consumed-byte passes.
    let preliminary = target.observe_refs_layout_residuals_domain(
        pair.clone(),
        &input,
        residuals,
        same_security,
        resources.native_profile(),
        events,
    )?;
    ensure!(
        preliminary.before() == &before
            && preliminary.after() == &before
            && preliminary.observed_readonly().disk_attributes == 2
            && preliminary.report().pair() == &pair
            && target.state(events)? == before,
        "preliminary protected layout changed identity or exclusion"
    );
    let preliminary_routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(
            &preliminary,
        )?;
    let routes_encoding = serde_json::to_vec(&preliminary_routes)?;
    let protected_routes_sha256 = hex::encode(Sha256::digest(&routes_encoding));
    let exclusions = allocation::union(
        preliminary_routes
            .entries()
            .iter()
            .map(|route| crate::refs_write_set::ByteRange {
                offset: route.target_physical_offset,
                length: route.length,
            })
            .collect(),
        length,
    )?;
    let excluded_payload_bytes = allocation::total(&exclusions)?;
    ensure!(
        excluded_payload_bytes == preliminary_routes.payload_bytes(),
        "protected route exclusions lose ownership coverage"
    );
    let excluded_payload_map_sha256 =
        hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "scope":"source-backed-route-exclusions-v1","partition_bytes":length,
            "protected_routes_sha256":protected_routes_sha256,"ranges":exclusions,
        }))?));
    let premap = preliminary
        .report()
        .native()
        .metadata_allocation
        .as_ref()
        .context("preliminary complete allocation missing")?;
    let prepages = preliminary
        .report()
        .native()
        .metadata_allocation_page_proof
        .as_ref()
        .context("preliminary complete allocation page proof missing")?;
    let premap_encoding = serde_json::to_vec(premap)?;
    ensure!(
        premap.cluster_count.checked_mul(4096) == Some(length)
            && prepages.cluster_count == premap.cluster_count
            && prepages.canonical_bitmap_sha256 == premap.bitmap_sha256,
        "preliminary allocation domain or page proof differs"
    );
    let allocated = allocation::union(
        premap
            .ranges
            .iter()
            .map(|range| crate::refs_write_set::ByteRange {
                offset: range.offset,
                length: range.length,
            })
            .collect(),
        length,
    )?;
    ensure!(
        premap.allocated_clusters.checked_mul(4096) == Some(allocation::total(&allocated)?),
        "preliminary allocation interval totals differ"
    );
    ensure!(
        allocation::subtract(&exclusions, &allocated)?.is_empty(),
        "route ownership is not covered by the complete native allocation"
    );
    let (opening_anchors, opening_reads) = recorded_anchors(target, length, resources)?;
    if let Ok(anchors) = &opening_anchors {
        let anchors = allocation::union(anchors.clone(), length)?;
        ensure!(
            allocation::total(&allocation::subtract(&anchors, &exclusions)?)?
                == allocation::total(&anchors)?,
            "known metadata anchors overlap an excluded payload route"
        );
    }
    ensure!(
        allocation::total(&allocation::subtract(&opening_reads, &exclusions)?)?
            == allocation::total(&opening_reads)?,
        "raw metadata inspection overlaps an excluded payload route"
    );
    let opening_all = allocation::union(
        allocated
            .into_iter()
            .chain(opening_anchors.as_ref().ok().into_iter().flatten().copied())
            .chain(opening_reads.iter().copied())
            .collect(),
        length,
    )?;
    let consumed = allocation::subtract(&opening_all, &exclusions)?;
    let consumed_ranges_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&consumed)?));
    let chunks = consumed_chunks(&consumed)?;
    let opening_bytes = chunks.iter().try_fold(0u64, |sum, chunk| {
        sum.checked_add(chunk.length as u64)
            .context("consumed byte total overflow")
    })?;
    let (raw_sha256, opening_hash_counts) =
        hash_consumed_chunks(target, length, &excluded_payload_map_sha256, &chunks)?;
    let native = target.observe_refs_layout_residuals_domain(
        pair.clone(),
        &input,
        residuals,
        same_security,
        resources.native_profile(),
        events,
    )?;
    let routes =
        n2r_win32::shadow_native::private_tree::SourceBackedRoutes::from_protected_layout(&native)?;
    ensure!(
        serde_json::to_vec(&routes)? == routes_encoding,
        "protected payload identities or mappings changed inside raw consumption bracket"
    );
    let map = native
        .report()
        .native()
        .metadata_allocation
        .as_ref()
        .context("protected allocation missing")?;
    ensure!(
        serde_json::to_vec(map)? == premap_encoding,
        "protected complete allocation changed inside raw consumption bracket"
    );
    let (anchors, closing_reads) = recorded_anchors(target, length, resources)?;
    if let Ok(anchors) = &anchors {
        let anchors = allocation::union(anchors.clone(), length)?;
        ensure!(
            allocation::total(&allocation::subtract(&anchors, &exclusions)?)?
                == allocation::total(&anchors)?,
            "closing metadata anchors overlap an excluded payload route"
        );
    }
    ensure!(
        allocation::total(&allocation::subtract(&closing_reads, &exclusions)?)?
            == allocation::total(&closing_reads)?,
        "closing raw metadata inspection overlaps an excluded payload route"
    );
    let mut allocation_coverage = allocation::reconcile(&native, anchors, &raw_sha256, length)?;
    let selection = allocation_coverage.observed_ranges(&native)?;
    let closing_all = allocation::union(
        selection.iter().copied().chain(closing_reads).collect(),
        length,
    )?;
    let closing_consumed = allocation::subtract(&closing_all, &exclusions)?;
    ensure!(
        allocation::subtract(&closing_consumed, &consumed)?.is_empty(),
        "closing raw consumer requires bytes absent from the opening bracket"
    );
    let mut closing = ClosingShadowConsumption::new(length, &excluded_payload_map_sha256, &chunks)?;
    let captured = consume(target, &routes, &selection, &mut closing)?;
    let (closing_sha256, closing_hash_counts) = closing.finish(target)?;
    ensure!(
        closing_sha256 == raw_sha256,
        "protected observation changed consumed raw shadow bytes"
    );
    ensure!(
        native.before() == &before
            && native.after() == &before
            && native.observed_readonly().disk_attributes == 2
            && native.report().pair() == &pair
            && target.state(events)? == before,
        "protected layout observation changed identity or exclusion"
    );
    allocation_coverage.bind_routed_payload_bracket(&raw_sha256, &excluded_payload_map_sha256);
    expected.revalidate_domain()?;
    Ok((
        ProtectedTargetLayout {
            native,
            raw_sha256,
            expected_tree_sha256,
            frozen_state: before,
            resources,
            routes,
            allocation_coverage,
            raw_image_unchanged: false,
            bracket_closure: Some(AllocationBracketClosure {
                opening: "exact 4 KiB-aligned native allocation plus observed raw metadata reads, excluding only opaque source-backed payload routes",
                raw_sha256_meaning: "SHA-256 over the v2 raw-consumption domain, partition length, pinned exclusion-map digest and every consumed (offset,length,SHA-256(actual chunk bytes)) frame; exact-length zero digests may be reused only after reading and checking every actual byte for zero; not a direct allocation-wide or whole-image digest",
                opening_chunks: chunks.len(),
                opening_bytes,
                closing_ranges: closing_consumed.len(),
                closing_chunks: chunks.len(),
                closing_bytes_reread: opening_bytes,
                free_space_rechecked: false,
                raw_consumption: Some(RoutedPayloadBracketScope {
                    scope: "source-backed-raw-consumption-v2",
                    framed_hash_domain: "n2r-refs-source-backed-raw-consumption-v2",
                    raw_metadata_hash_algorithm: "sha256-framed-chunks-v1",
                    opening_hash_counts,
                    closing_hash_counts,
                    protected_routes_sha256,
                    excluded_payload_map_sha256,
                    excluded_payload_ranges: exclusions,
                    excluded_payload_bytes,
                    consumed_ranges_sha256,
                    preliminary_and_bracketed_native_routes_identical: true,
                    preliminary_and_bracketed_allocation_maps_identical: true,
                    raw_inspection_reads_covered: true,
                }),
            }),
            logical_payload_verified: false,
            complete_allocation_graph_verified: false,
            source_admitted: false,
            conversion_qualified: false,
        },
        captured,
    ))
}
