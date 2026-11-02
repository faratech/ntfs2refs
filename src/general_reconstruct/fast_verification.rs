//! Fresh conversion evidence and separately authenticated, read-only recovery
//! map facts. Deserializing facts never recreates source or write admission.
use super::*;
use crate::{
    general_composite_target::FrozenAllocationTargetPreservation,
    general_qualification::{canonical_json_sha256, pretty_json_sha256},
    general_source_admission::AllocationCertificate,
    selected_journal,
};
use anyhow::{Context, ensure};
use n2r_win32::{attestation::Snapshot, metadata_pages, shadow_native::Report};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

type StreamKey = (Vec<String>, Vec<u16>);
type StreamMaps = BTreeMap<StreamKey, StreamMap>;

pub(crate) struct FreshPayloadProof {
    expected_tree_sha256: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    native: Arc<Report>,
    maps: Vec<StreamLocation>,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    plan_sha256: String,
    ticket_sha256: String,
    tail_extent_streams: usize,
    tail_payload_bytes_verified: u64,
    map_page_budget: metadata_pages::PageBudget,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Vec<u8>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<n2r_win32::sparse_layout::SparseLayout>,
    integrity: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StreamStandard {
    Data([u8; 22]),
    // Directory tree storage may grow for the separately verified post-mount
    // indexer cache. It is not retained file payload; namespace stays checked.
    DirectoryLinksAndType([u8; 6]),
}

/// A scalar snapshot and borrowed variable-sized buffers. Comparing an already
/// collected native report must not duplicate its retrieval and integrity data.
#[derive(PartialEq, Eq, Serialize)]
struct StreamMapRef<'a> {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: &'a [u8],
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<&'a n2r_win32::sparse_layout::SparseLayout>,
    integrity: &'a [u8],
}

impl StreamMap {
    fn as_ref(&self) -> StreamMapRef<'_> {
        StreamMapRef {
            file_id: self.file_id,
            standard: self.standard,
            retrieval: &self.retrieval,
            complete_page_proof: self.complete_page_proof,
            resident: self.resident,
            sparse: self.sparse.as_ref(),
            integrity: &self.integrity,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapEntry {
    components: Vec<String>,
    name_utf16: Vec<u16>,
    map: StreamMap,
}

/// Immutable observation facts pinned by the recovery bundle. No lifecycle,
/// device exclusion, native observation or write capability can be serialized.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPayloadManifest {
    schema_version: u32,
    kind: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    bindings: Vec<MapEntry>,
    grants_write_authority: bool,
    initial_retained_content_digests_available: bool,
}

const MAP_PAGE_PURPOSE: [u8; 8] = *b"MAPREF01";
pub(crate) const PAGED_MAP_FILENAME: &str = "recovery-payload-manifest.pages";

fn map_page_budget(
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<metadata_pages::PageBudget> {
    if let Some(admission) = resources
        .count_admission()?
        .filter(|a| a.requires_paged_metadata())
    {
        return Ok(admission.map_page_budget()?);
    }
    Ok(metadata_pages::PageBudget {
        max_page_bytes: 4 * 1024 * 1024,
        max_records_per_page: 128,
        max_records: (n2r_win32::tree_resources::OBJECT_SLOTS
            + n2r_win32::tree_resources::DATA_STREAMS
            + 1) as u64,
        max_pages: (n2r_win32::tree_resources::OBJECT_SLOTS
            + n2r_win32::tree_resources::DATA_STREAMS
            + 1) as u64,
        max_file_bytes: super::selected_artifacts::Artifact::PayloadMap.maximum_bytes() as u64,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapManifestHeader {
    schema_version: u32,
    kind: String,
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
    bindings_count: u64,
    grants_write_authority: bool,
    initial_retained_content_digests_available: bool,
}

#[derive(Serialize)]
struct MapEntryRef<'a> {
    components: &'a [String],
    name_utf16: &'a [u16],
    map: PagedStreamMapRef<'a>,
}

// The legacy byte-array JSON expands complete fragmented maps beyond one page.
// This wire form preserves every byte and sparse range in less than 3MiB at
// the existing native bounds; it is not an alternate mapping or admission.
struct Base64Bytes<'a>(&'a [u8]);
struct Base64Ranges<'a>(&'a [n2r_win32::sparse_layout::LogicalRange]);
struct Base64Display<I>(I);
impl<I: Iterator<Item = u8> + Clone> std::fmt::Display for Base64Display<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bytes = self.0.clone();
        while let Some(a) = bytes.next() {
            let b = bytes.next();
            let c = bytes.next();
            let encoded = [
                ABC[(a >> 2) as usize],
                ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
                b.map_or(b'=', |b| {
                    ABC[(((b & 15) << 2) | (c.unwrap_or(0) >> 6)) as usize]
                }),
                c.map_or(b'=', |c| ABC[(c & 63) as usize]),
            ];
            f.write_str(std::str::from_utf8(&encoded).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for Base64Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&Base64Display(self.0.iter().copied()))
    }
}
impl Serialize for Base64Ranges<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&Base64Display(self.0.iter().flat_map(|r| {
            r.offset
                .to_le_bytes()
                .into_iter()
                .chain(r.length.to_le_bytes())
        })))
    }
}
fn decode_base64(value: &str, maximum: usize) -> Result<Vec<u8>> {
    let input = value.as_bytes();
    ensure!(input.len().is_multiple_of(4), "map base64 length differs");
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    ensure!(padding <= 2, "map base64 padding differs");
    let length = input
        .len()
        .checked_div(4)
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_sub(padding))
        .context("map base64 length overflow")?;
    ensure!(length <= maximum, "decoded map field exceeds native bound");
    let digit = |b: u8| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical map base64 alphabet"),
        })
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("decoded map storage unavailable")?;
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let last = index + 1 == input.len() / 4;
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        bytes.push((a << 2) | (b >> 4));
        if chunk[2] == b'=' {
            ensure!(
                last && chunk[3] == b'=' && b & 15 == 0,
                "noncanonical map base64 padding bits"
            );
        } else {
            let c = digit(chunk[2])?;
            bytes.push((b << 4) | (c >> 2));
            if chunk[3] == b'=' {
                ensure!(last && c & 3 == 0, "noncanonical map base64 padding bits");
            } else {
                bytes.push((c << 6) | digit(chunk[3])?);
            }
        }
    }
    ensure!(bytes.len() == length, "decoded map length differs");
    Ok(bytes)
}

#[derive(Serialize)]
struct PagedSparseRef<'a> {
    initialized_length: u64,
    allocated: Base64Ranges<'a>,
    holes: Base64Ranges<'a>,
}
#[derive(Serialize)]
struct PagedStreamMapRef<'a> {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: Base64Bytes<'a>,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<PagedSparseRef<'a>>,
    integrity: Base64Bytes<'a>,
}
impl<'a> PagedStreamMapRef<'a> {
    fn new(map: StreamMapRef<'a>) -> Result<Self> {
        ensure!(
            map.retrieval.len() <= n2r_win32::stream_layout::COMPLETE_RETRIEVAL_CAPACITY
                && map.integrity.len() <= 16,
            "native map wire field exceeds complete bound"
        );
        if let Some(sparse) = map.sparse {
            ensure!(
                sparse
                    .allocated
                    .len()
                    .checked_add(sparse.holes.len())
                    .is_some_and(|n| n <= n2r_win32::sparse_layout::MAX_LAYOUT_RANGES),
                "native sparse map wire exceeds complete bound"
            );
        }
        Ok(Self {
            file_id: map.file_id,
            standard: map.standard,
            retrieval: Base64Bytes(map.retrieval),
            complete_page_proof: map.complete_page_proof,
            resident: map.resident,
            integrity: Base64Bytes(map.integrity),
            sparse: map.sparse.map(|s| PagedSparseRef {
                initialized_length: s.initialized_length,
                allocated: Base64Ranges(&s.allocated),
                holes: Base64Ranges(&s.holes),
            }),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedSparse {
    initialized_length: u64,
    allocated: String,
    holes: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedStreamMap {
    file_id: [u8; 16],
    standard: StreamStandard,
    retrieval: String,
    complete_page_proof: bool,
    resident: bool,
    sparse: Option<PagedSparse>,
    integrity: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedMapEntry {
    components: Vec<String>,
    name_utf16: Vec<u16>,
    map: PagedStreamMap,
}
fn decode_ranges(value: &str) -> Result<Vec<n2r_win32::sparse_layout::LogicalRange>> {
    let bytes = decode_base64(value, n2r_win32::sparse_layout::MAX_LAYOUT_RANGES * 16)?;
    ensure!(
        bytes.len().is_multiple_of(16),
        "packed sparse map length differs"
    );
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(bytes.len() / 16)
        .context("sparse map storage unavailable")?;
    for pair in bytes.chunks_exact(16) {
        ranges.push(n2r_win32::sparse_layout::LogicalRange {
            offset: u64::from_le_bytes(pair[..8].try_into()?),
            length: u64::from_le_bytes(pair[8..].try_into()?),
        });
    }
    Ok(ranges)
}
impl PagedMapEntry {
    fn decode(bytes: &[u8]) -> Result<MapEntry> {
        let entry: Self = serde_json::from_slice(bytes)?;
        let map = entry.map;
        let sparse = map
            .sparse
            .map(|s| -> Result<_> {
                let allocated = decode_ranges(&s.allocated)?;
                let holes = decode_ranges(&s.holes)?;
                ensure!(
                    allocated
                        .len()
                        .checked_add(holes.len())
                        .is_some_and(|n| n <= n2r_win32::sparse_layout::MAX_LAYOUT_RANGES),
                    "decoded sparse map exceeds combined native bound"
                );
                Ok(n2r_win32::sparse_layout::SparseLayout {
                    initialized_length: s.initialized_length,
                    allocated,
                    holes,
                })
            })
            .transpose()?;
        Ok(MapEntry {
            components: entry.components,
            name_utf16: entry.name_utf16,
            map: StreamMap {
                file_id: map.file_id,
                standard: map.standard,
                retrieval: decode_base64(
                    &map.retrieval,
                    n2r_win32::stream_layout::COMPLETE_RETRIEVAL_CAPACITY,
                )?,
                complete_page_proof: map.complete_page_proof,
                resident: map.resident,
                sparse,
                integrity: decode_base64(&map.integrity, 16)?,
            },
        })
    }
}

/// Prefix-free keys preserve the existing (component strings, UTF16 name)
/// tuple order. Header key is empty; every stream key starts with tag1.
fn encoded_stream_key(components: &[String], name: &[u16]) -> Result<Vec<u8>> {
    let mut key = vec![1];
    for component in components {
        ensure!(
            !component.is_empty() && !component.as_bytes().contains(&0),
            "invalid recovery map component key"
        );
        key.extend_from_slice(component.as_bytes());
        key.push(0);
    }
    key.push(0);
    for unit in name {
        ensure!(*unit != 0, "invalid recovery map stream key");
        key.extend_from_slice(&unit.to_be_bytes());
    }
    key.extend_from_slice(&[0, 0]);
    Ok(key)
}

fn record_json(value: &impl Serialize) -> Result<Vec<u8>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= 4 * 1024 * 1024)
                .ok_or_else(|| std::io::Error::other("recovery map record exceeds page budget"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count.0)
        .context("recovery map record storage unavailable")?;
    serde_json::to_writer(&mut bytes, value)?;
    ensure!(
        bytes.len() == count.0,
        "borrowed recovery map record changed during serialization"
    );
    Ok(bytes)
}

/// Only scalar facts are needed after parsing and checking the complete pinned
/// manifest. Its binding buffers move into the proof's sole canonical map.
struct RecoveryPayloadHeader {
    source: n2r_win32::general_layout::GeneralDiskBinding,
    expected_tree_sha256: String,
    plan_sha256: String,
    ticket_sha256: String,
    base_sectors: u64,
    new_selected_sha256: [u8; 32],
    selected_bytes: u64,
    range_count: u32,
}

enum RecoveryMaps {
    Legacy(StreamMaps),
    Paged {
        reader: RefCell<metadata_pages::Reader>,
        index: Vec<(StreamKey, u64)>,
    },
}

impl RecoveryMaps {
    fn len(&self) -> usize {
        match self {
            Self::Legacy(maps) => maps.len(),
            Self::Paged { index, .. } => index.len(),
        }
    }
}

pub(crate) struct RecoveryPayloadProof {
    facts: RecoveryPayloadHeader,
    maps: RecoveryMaps,
}

fn query(snapshot: &Snapshot, class: i32) -> Result<&[u8]> {
    let mut found = snapshot.queries.iter().filter(|query| query.class == class);
    let value = found.next().context("fast stream binding query absent")?;
    ensure!(
        found.next().is_none() && value.native_error.is_none() && value.bytes.len() == 24,
        "fast stream binding query refused or ambiguous"
    );
    Ok(&value.bytes)
}

fn stream_map_ref<'a>(
    snapshot: &Snapshot,
    retrieval: &'a [u8],
    paged: bool,
    resident: bool,
    sparse: Option<&'a n2r_win32::sparse_layout::SparseLayout>,
    integrity: &'a [u8],
) -> Result<StreamMapRef<'a>> {
    let identity = query(snapshot, 18)?;
    let standard = query(snapshot, 1)?;
    ensure!(standard[20] == 0, "fast stream is delete pending");
    // File identities live in the copied ReFS metadata graph. Volume paths and
    // disk numbers change at cutover; neither substitutes for the 128-bit ID.
    Ok(StreamMapRef {
        file_id: identity[8..].try_into()?,
        standard: if standard[21] == 0 {
            StreamStandard::Data(standard[..22].try_into()?)
        } else {
            StreamStandard::DirectoryLinksAndType(standard[16..22].try_into()?)
        },
        retrieval,
        complete_page_proof: paged,
        resident,
        sparse,
        integrity,
    })
}

type StreamKeyRef<'a> = (&'a [String], &'a [u16]);
type StreamBindingRef<'a> = (StreamKeyRef<'a>, StreamMapRef<'a>);

/// Numeric indexes into the shared immutable observation; paths and variable
/// map buffers remain owned only by that original native report.
#[derive(Clone, Copy)]
struct StreamLocation {
    object: usize,
    named: Option<usize>,
}

impl StreamLocation {
    fn key(self, report: &Report) -> StreamKeyRef<'_> {
        let object = &report.objects[self.object];
        let name = self.named.map_or(&[] as &[u16], |index| {
            object.named_streams[index].name_utf16.as_slice()
        });
        (object.components.as_slice(), name)
    }

    fn view(self, report: &Report) -> Result<StreamBindingRef<'_>> {
        let object = &report.objects[self.object];
        let (name, snapshot, retrieval, paged, resident, sparse, integrity) =
            if let Some(index) = self.named {
                let stream = &object.named_streams[index];
                (
                    stream.name_utf16.as_slice(),
                    &stream.before,
                    stream.retrieval.as_slice(),
                    stream.retrieval_page_proof.is_some(),
                    stream.resident_data,
                    stream.sparse.as_ref().map(|sparse| &sparse.expected),
                    stream.integrity.as_slice(),
                )
            } else {
                (
                    &[] as &[u16],
                    &object.before,
                    object.retrieval.as_slice(),
                    object.retrieval_page_proof.is_some(),
                    object.resident_data,
                    object.sparse.as_ref().map(|sparse| &sparse.expected),
                    object.integrity.as_slice(),
                )
            };
        Ok((
            (object.components.as_slice(), name),
            stream_map_ref(snapshot, retrieval, paged, resident, sparse, integrity)?,
        ))
    }
}

fn maps(report: &Report) -> Result<Vec<StreamLocation>> {
    // Borrowed slice tuples have the same lexicographic ordering as the old
    // owned Vec tuples, preserving the exact manifest binding sequence.
    let mut maps = BTreeMap::new();
    for (object_index, object) in report.objects.iter().enumerate() {
        ensure!(
            object.before == object.after,
            "fast object metadata changed during observation"
        );
        let location = StreamLocation {
            object: object_index,
            named: None,
        };
        let (key, _) = location.view(report)?;
        ensure!(
            maps.insert(key, location).is_none(),
            "duplicate fast canonical object"
        );
        for (stream_index, stream) in object.named_streams.iter().enumerate() {
            ensure!(
                stream.before == stream.after,
                "fast named stream metadata changed"
            );
            let location = StreamLocation {
                object: object_index,
                named: Some(stream_index),
            };
            let (key, _) = location.view(report)?;
            ensure!(
                !stream.name_utf16.is_empty() && maps.insert(key, location).is_none(),
                "duplicate fast named stream"
            );
        }
    }
    Ok(maps.into_values().collect())
}

/// Compare every reported binding without constructing another owning map.
/// The sorted index borrows keys and buffers from the proof; one seen flag per
/// binding preserves duplicate detection and complete-set equality.
fn maps_match<'a, T>(
    report: &Report,
    expected: impl IntoIterator<Item = T>,
    key: impl Fn(&T) -> StreamKeyRef<'a>,
    map: impl Fn(&T) -> Result<StreamMapRef<'a>>,
) -> Result<bool> {
    let mut bindings: Vec<_> = expected.into_iter().map(|value| (value, false)).collect();
    let mut match_stream = |components: &[String], name: &[u16], value: StreamMapRef<'_>| {
        let found = bindings.binary_search_by(|(binding, _)| {
            let key = key(binding);
            key.0.cmp(components).then_with(|| key.1.cmp(name))
        });
        let Ok(index) = found else {
            return Ok(false);
        };
        let (expected, seen) = &mut bindings[index];
        ensure!(!*seen, "duplicate fast canonical stream");
        *seen = true;
        Ok(map(expected)? == value)
    };
    for object in &report.objects {
        ensure!(
            object.before == object.after,
            "fast object metadata changed during observation"
        );
        if !match_stream(
            &object.components,
            &[],
            stream_map_ref(
                &object.before,
                &object.retrieval,
                object.retrieval_page_proof.is_some(),
                object.resident_data,
                object.sparse.as_ref().map(|sparse| &sparse.expected),
                &object.integrity,
            )?,
        )? {
            return Ok(false);
        }
        for stream in &object.named_streams {
            ensure!(
                stream.before == stream.after,
                "fast named stream metadata changed"
            );
            ensure!(!stream.name_utf16.is_empty(), "duplicate fast named stream");
            if !match_stream(
                &object.components,
                &stream.name_utf16,
                stream_map_ref(
                    &stream.before,
                    &stream.retrieval,
                    stream.retrieval_page_proof.is_some(),
                    stream.resident_data,
                    stream.sparse.as_ref().map(|sparse| &sparse.expected),
                    &stream.integrity,
                )?,
            )? {
                return Ok(false);
            }
        }
    }
    Ok(bindings.iter().all(|(_, seen)| *seen))
}

impl FreshPayloadProof {
    pub(crate) fn new(
        proof: &FrozenAllocationTargetPreservation,
        certificate: &AllocationCertificate,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        expected.revalidate_domain()?;
        let expected_tree_sha256 = pretty_json_sha256(expected)?;
        ensure!(
            certificate.binds(proof)
                && proof.data_ties_verified()
                && proof.expected_tree_sha256() == expected_tree_sha256
                && certificate.expected_tree_sha256() == expected_tree_sha256
                && serde_json::to_vec(plan)?
                    == serde_json::to_vec(&proof.plan(plan.max_journal_bytes)?)?,
            "fresh payload proof differs from the original live certificate or exact selected plan"
        );
        // The explicit ticket profile chooses the exact marker-body length.
        let (selected_bytes, journal_bytes) =
            plan.validate_marker_profile(ticket.marker_profile)?;
        ensure!(
            ticket.image_length == proof.pair().source.identity.partition_bytes
                && ticket.selected_bytes == selected_bytes
                && ticket.journal_length == journal_bytes
                && ticket.range_count as usize == plan.ranges.len()
                && !ticket.whole_image_verified
                && ticket.new_selected_sha256 != ticket.old_selected_sha256,
            "fresh payload ticket differs from its prepared plan"
        );
        let native = proof
            .protected_layout()
            .native()
            .report()
            .native_observation();
        let protected = proof.protected_layout().native().report();
        let mut tail_extent_streams = 0usize;
        let mut tail_payload_bytes_verified = 0u64;
        for object_index in 0..expected.object_count() {
            let object = expected.object(object_index)?;
            for stream in object.data_streams().filter(|s| {
                s.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
            }) {
                let matches: Vec<_> = protected
                    .residuals()
                    .iter()
                    .filter(|r| {
                        r.object_index == object_index && r.stream_name_utf16 == stream.name_utf16
                    })
                    .collect();
                ensure!(
                    protected.residual_contents_verified()
                        && matches.len() == 1
                        && matches[0].logical_offset == stream.length / 4096 * 4096
                        && matches[0].length == stream.length % 4096
                        && matches[0].sha256.len() == 64,
                    "extent-only partial tail lacks exact protected source-to-target residual verification"
                );
                tail_extent_streams += 1;
                tail_payload_bytes_verified = tail_payload_bytes_verified
                    .checked_add(matches[0].length)
                    .context("verified extent-tail byte count overflow")?;
            }
        }
        Ok(Self {
            expected_tree_sha256,
            source: proof.pair().source.clone(),
            maps: maps(&native)?,
            base_sectors: native.base_sectors,
            native,
            new_selected_sha256: ticket.new_selected_sha256,
            selected_bytes,
            range_count: ticket.range_count,
            plan_sha256: canonical_json_sha256(plan)?,
            ticket_sha256: canonical_json_sha256(ticket)?,
            tail_extent_streams,
            tail_payload_bytes_verified,
            map_page_budget: map_page_budget(resources)?,
        })
    }

    /// Stream one borrowed native binding at a time. The bundle pins the
    /// finished immutable page file, never a serialized capability.
    pub(crate) fn write_recovery_manifest(&self, path: &Path) -> Result<String> {
        let header = MapManifestHeader {
            schema_version: 2,
            kind: "protected-target-stream-map-pages-v2".into(),
            source: self.source.clone(),
            expected_tree_sha256: self.expected_tree_sha256.clone(),
            plan_sha256: self.plan_sha256.clone(),
            ticket_sha256: self.ticket_sha256.clone(),
            base_sectors: self.base_sectors,
            new_selected_sha256: self.new_selected_sha256,
            selected_bytes: self.selected_bytes,
            range_count: self.range_count,
            bindings_count: self.maps.len() as u64,
            grants_write_authority: false,
            initial_retained_content_digests_available: false,
        };
        let mut writer = metadata_pages::Writer::new(path, MAP_PAGE_PURPOSE, self.map_page_budget)?;
        writer.push(&[], &record_json(&header)?)?;
        for location in &self.maps {
            let ((components, name_utf16), map) = location.view(&self.native)?;
            let key = encoded_stream_key(components, name_utf16)?;
            let entry = MapEntryRef {
                components,
                name_utf16,
                map: PagedStreamMapRef::new(map)?,
            };
            writer.push(&key, &record_json(&entry)?)?;
        }
        Ok(writer.finish()?.sha256)
    }

    fn verify(
        &self,
        scope: &NativeVerificationScope<'_>,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        applied: &selected_journal::SelectedResult,
        handoff: &selected_journal::SelectedResult,
        native: &shadow_native::GeneralConvertedReport,
    ) -> Result<Value> {
        ensure!(
            scope.pair.source == self.source
                && native.pair.source.identity == self.source.identity
                && pretty_json_sha256(expected)? == self.expected_tree_sha256,
            "fresh payload source or expected tree changed at handoff"
        );
        for result in [applied, handoff] {
            ensure!(
                result.selected_sha256 == self.new_selected_sha256
                    && result.selected_bytes == self.selected_bytes
                    && result.range_count == self.range_count
                    && !result.whole_image_verified,
                "fresh payload apply/handoff checksum differs"
            );
        }
        ensure!(
            handoff.replay_closed,
            "extent verification requires a durable closed handoff"
        );
        let observation = native
            .content_observation
            .as_ref()
            .context("metadata observation scope absent")?;
        ensure!(
            !observation.full_file_hashes
                && observation.admitted_payload_bytes_read == 0
                && observation.metadata_and_namespace_verified
                && observation.complete_stream_mappings_observed
                && observation.data_storage_validity_checked
                && native.native.base_sectors == self.base_sectors
                && maps_match(
                    &native.native,
                    &self.maps,
                    |location| location.key(&self.native),
                    |location| Ok(location.view(&self.native)?.1),
                )?,
            "mounted file identities, complete physical maps or storage validity differ from the protected candidate"
        );
        Ok(
            serde_json::json!({"schema_version":1,"scope":"fresh-conversion-extent-identity-v1",
            "expected_tree_sha256":self.expected_tree_sha256,"stream_and_directory_bindings":self.maps.len(),
            "selected_bytes_checksummed":self.selected_bytes,"selected_sha256":hex::encode(self.new_selected_sha256),
            "retained_bytes_proven_by_same_physical_mapping":true,
            "resident_and_residual_bytes_bound_by_selected_image":true,
            "all_complete_maps_identical":true,"handoff_replay_closed":true,
            "extent_only_partial_streams":self.tail_extent_streams,
            "materialized_extent_tail_bytes_verified":self.tail_payload_bytes_verified,
            "target_full_file_hashes":false,"target_admitted_payload_bytes_read":0,
            "saved_receipt_grants_execution_authority":false}),
        )
    }
}

fn expected_map_keys(
    expected: &impl shadow_tree::ExpectedObjectDomain,
) -> Result<BTreeSet<Vec<u8>>> {
    let mut keys = BTreeSet::new();
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        ensure!(
            keys.insert(encoded_stream_key(&object.path, &[])?),
            "duplicate expected map object"
        );
        for stream in &object.named_streams {
            ensure!(
                keys.insert(encoded_stream_key(&object.path, &stream.name_utf16)?),
                "duplicate expected map stream"
            );
        }
    }
    Ok(keys)
}

pub(crate) fn extent_stream_counts(
    expected: &impl shadow_tree::ExpectedObjectDomain,
) -> Result<(usize, usize)> {
    let (mut extents, mut partials) = (0usize, 0usize);
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        for stream in object.data_streams() {
            if stream.source_evidence.is_some() {
                extents = extents
                    .checked_add(1)
                    .context("extent stream count overflow")?;
            }
            if stream.source_evidence
                == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
            {
                partials = partials
                    .checked_add(1)
                    .context("partial extent stream count overflow")?;
            }
        }
    }
    Ok((extents, partials))
}

fn validate_map_entry(entry: &MapEntry, expected_keys: &BTreeSet<Vec<u8>>) -> Result<()> {
    ensure!(
        expected_keys
            .contains(encoded_stream_key(&entry.components, &entry.name_utf16)?.as_slice())
            && entry.map.file_id != [0; 16],
        "unexpected recovery map binding"
    );
    ensure!(
        entry.map.retrieval.len() <= n2r_win32::retrieval_paging::MAX_RETURNED_BYTES,
        "recovery stream map exceeds retrieval bound"
    );
    Ok(())
}

fn validate_map_header(
    facts: &MapManifestHeader,
    schema_version: u32,
    kind: &str,
    source: &n2r_win32::general_layout::GeneralDiskBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    plan: &selected_journal::SelectedPlan,
    ticket: &selected_journal::SelectedTicket,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<()> {
    resources.count_admission()?;
    ensure!(
        resources.is_streaming(),
        "recovery map facts require the pinned streaming resource profile"
    );
    expected.revalidate_domain()?;
    shadow_tree::validate_expected_domain(expected, resources)?;
    let (selected_bytes, journal_bytes) = plan.validate_marker_profile(ticket.marker_profile)?;
    ensure!(
        expected.has_extent_only_streams()?
            && facts.schema_version == schema_version
            && facts.kind == kind
            && !facts.grants_write_authority
            && !facts.initial_retained_content_digests_available
            && &facts.source == source
            && facts.expected_tree_sha256 == pretty_json_sha256(expected)?
            && facts.plan_sha256 == canonical_json_sha256(plan)?
            && facts.ticket_sha256 == canonical_json_sha256(ticket)?
            && ticket.image_length == source.identity.partition_bytes
            && !ticket.whole_image_verified
            && ticket.selected_bytes == selected_bytes
            && ticket.journal_length == journal_bytes
            && ticket.range_count as usize == plan.ranges.len()
            && facts.new_selected_sha256 == ticket.new_selected_sha256
            && facts.selected_bytes == selected_bytes
            && facts.range_count == ticket.range_count
            && facts.bindings_count == expected_map_keys(expected)?.len() as u64,
        "pinned recovery map facts differ from tree, source, selected plan or trusted ticket"
    );
    Ok(())
}

fn proof_header(facts: MapManifestHeader) -> RecoveryPayloadHeader {
    RecoveryPayloadHeader {
        source: facts.source,
        expected_tree_sha256: facts.expected_tree_sha256,
        plan_sha256: facts.plan_sha256,
        ticket_sha256: facts.ticket_sha256,
        base_sectors: facts.base_sectors,
        new_selected_sha256: facts.new_selected_sha256,
        selected_bytes: facts.selected_bytes,
        range_count: facts.range_count,
    }
}

impl RecoveryPayloadProof {
    /// Legacy JSON1 remains readable with its original pinned-input protocol.
    pub(crate) fn from_pinned_manifest(
        bytes: &[u8],
        source: &n2r_win32::general_layout::GeneralDiskBinding,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= super::selected_artifacts::Artifact::PayloadMap.maximum_bytes(),
            "recovery map artifact exceeds bound"
        );
        let old: RecoveryPayloadManifest = serde_json::from_slice(bytes)?;
        let header = MapManifestHeader {
            schema_version: old.schema_version,
            kind: old.kind,
            source: old.source,
            expected_tree_sha256: old.expected_tree_sha256,
            plan_sha256: old.plan_sha256,
            ticket_sha256: old.ticket_sha256,
            base_sectors: old.base_sectors,
            new_selected_sha256: old.new_selected_sha256,
            selected_bytes: old.selected_bytes,
            range_count: old.range_count,
            bindings_count: old.bindings.len() as u64,
            grants_write_authority: old.grants_write_authority,
            initial_retained_content_digests_available: old
                .initial_retained_content_digests_available,
        };
        validate_map_header(
            &header,
            1,
            "protected-target-stream-map-facts-v1",
            source,
            expected,
            plan,
            ticket,
            resources,
        )?;
        let keys = expected_map_keys(expected)?;
        let mut maps = BTreeMap::new();
        for entry in old.bindings {
            validate_map_entry(&entry, &keys)?;
            ensure!(
                maps.insert((entry.components, entry.name_utf16), entry.map)
                    .is_none(),
                "duplicate recovery map binding"
            );
        }
        Ok(Self {
            facts: proof_header(header),
            maps: RecoveryMaps::Legacy(maps),
        })
    }

    /// Full file/page/header/map-set closure precedes journal or target opening.
    /// Only keys/ordinals survive; retrieval/sparse/integrity buffers are decoded
    /// one record at a time from the exact held immutable page owner.
    pub(crate) fn from_pinned_pages(
        path: &Path,
        expected_sha256: &str,
        source: &n2r_win32::general_layout::GeneralDiskBinding,
        expected: &impl shadow_tree::ExpectedObjectDomain,
        plan: &selected_journal::SelectedPlan,
        ticket: &selected_journal::SelectedTicket,
        resources: crate::ntfs_admission::ResourceProfile,
    ) -> Result<Self> {
        let mut reader = metadata_pages::Reader::open(
            path,
            expected_sha256,
            MAP_PAGE_PURPOSE,
            map_page_budget(resources)?,
        )?;
        let record = reader.get(0)?;
        ensure!(
            record.key.is_empty(),
            "paged recovery map header key differs"
        );
        let header: MapManifestHeader = serde_json::from_slice(&record.payload)?;
        validate_map_header(
            &header,
            2,
            "protected-target-stream-map-pages-v2",
            source,
            expected,
            plan,
            ticket,
            resources,
        )?;
        ensure!(
            header.bindings_count.checked_add(1) == Some(reader.len()),
            "paged recovery map record count differs"
        );
        let keys = expected_map_keys(expected)?;
        let mut index: Vec<(StreamKey, u64)> = Vec::new();
        index
            .try_reserve_exact(usize::try_from(header.bindings_count)?)
            .context("recovery map index storage unavailable")?;
        for ordinal in 1..reader.len() {
            let record = reader.get(ordinal)?;
            let entry = PagedMapEntry::decode(&record.payload)?;
            validate_map_entry(&entry, &keys)?;
            ensure!(
                record.key == encoded_stream_key(&entry.components, &entry.name_utf16)?,
                "paged recovery map key differs from its payload"
            );
            let key = (entry.components, entry.name_utf16);
            ensure!(
                index.last().is_none_or(|(previous, _)| previous < &key),
                "paged recovery maps are duplicated or out of order"
            );
            index.push((key, ordinal));
        }
        ensure!(
            index.len() == keys.len(),
            "complete paged recovery map set differs"
        );
        reader.revalidate()?;
        Ok(Self {
            facts: proof_header(header),
            maps: RecoveryMaps::Paged {
                reader: RefCell::new(reader),
                index,
            },
        })
    }

    pub(crate) fn paged_final_path(&self) -> Option<String> {
        match &self.maps {
            RecoveryMaps::Paged { reader, .. } => Some(reader.borrow().final_path().to_owned()),
            RecoveryMaps::Legacy(_) => None,
        }
    }

    pub(crate) fn revalidate_paged_manifest(&self) -> Result<()> {
        if let RecoveryMaps::Paged { reader, .. } = &self.maps {
            reader.borrow_mut().revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn copy_paged_manifest(&self, output: &Path) -> Result<()> {
        if let RecoveryMaps::Paged { reader, .. } = &self.maps {
            reader
                .borrow_mut()
                .copy_to(&output.join(PAGED_MAP_FILENAME))?;
        }
        Ok(())
    }

    fn maps_match(&self, report: &Report) -> Result<bool> {
        match &self.maps {
            RecoveryMaps::Legacy(expected) => maps_match(
                report,
                expected,
                |(key, _)| (key.0.as_slice(), key.1.as_slice()),
                |(_, map)| Ok(map.as_ref()),
            ),
            RecoveryMaps::Paged { reader, index } => {
                let actual = maps(report)?;
                if actual.len() != index.len() {
                    return Ok(false);
                }
                let mut reader = reader.borrow_mut();
                for (location, (expected_key, ordinal)) in actual.iter().zip(index) {
                    let ((components, name), value) = location.view(report)?;
                    if components != expected_key.0.as_slice() || name != expected_key.1.as_slice()
                    {
                        return Ok(false);
                    }
                    let record = reader.get(*ordinal)?;
                    let entry = PagedMapEntry::decode(&record.payload)?;
                    ensure!(
                        record.key == encoded_stream_key(&entry.components, &entry.name_utf16)?
                            && entry.components == expected_key.0
                            && entry.name_utf16 == expected_key.1,
                        "held paged recovery map key changed"
                    );
                    if value != entry.map.as_ref() {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }
}

/// Lab metadata inspection only. Full page and semantic closure is required;
/// this opens no journal or source device and returns no execution capability.
pub(crate) fn inspect_pinned_recovery_pages(
    path: &Path,
    sha256: &str,
    source: &n2r_win32::general_layout::GeneralDiskBinding,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    plan: &selected_journal::SelectedPlan,
    ticket: &selected_journal::SelectedTicket,
    resources: crate::ntfs_admission::ResourceProfile,
) -> Result<Value> {
    expected.revalidate_domain()?;
    let proof = RecoveryPayloadProof::from_pinned_pages(
        path, sha256, source, expected, plan, ticket, resources,
    )?;
    proof.revalidate_paged_manifest()?;
    expected.revalidate_domain()?;
    let RecoveryMaps::Paged { reader, index } = &proof.maps else {
        anyhow::bail!("paged metadata inspection requires a page owner");
    };
    let reader = reader.borrow();
    Ok(serde_json::json!({
        "schema_version":1,"kind":"read-only-pinned-recovery-map-pages-inspection",
        "file_sha256":sha256,"actual_final_path":reader.final_path(),
        "bytes":reader.byte_len(),"pages":reader.page_count(),"records":reader.len(),
        "bindings":index.len(),"complete_paged_and_expected_map_set_validated":true,
        "source":proof.facts.source,
        "expected_tree_sha256":proof.facts.expected_tree_sha256,
        "plan_sha256":proof.facts.plan_sha256,"ticket_sha256":proof.facts.ticket_sha256,
        "base_sectors":proof.facts.base_sectors,
        "new_selected_sha256":proof.facts.new_selected_sha256,
        "selected_bytes":proof.facts.selected_bytes,"range_count":proof.facts.range_count,
        "grants_source_admission":false,"grants_write_authority":false,
        "initial_retained_content_digests_available":false,
        "journal_opened":false,"source_device_opened":false,
    }))
}

/// Recovery never reissues a fresh source certificate. Its existing journal
/// protocol first proves a closed target against the complete immutable body;
/// this routine then compares all mounted maps against independently pinned facts.
pub(crate) fn verify_native_recovery_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    proof: &RecoveryPayloadProof,
    closed: &selected_journal::SelectedResult,
    restored_label: bool,
) -> Result<Value> {
    let facts = &proof.facts;
    ensure!(
        scope.pair.source == facts.source
            && closed.replay_closed
            && !closed.whole_image_verified
            && closed.selected_sha256 == facts.new_selected_sha256
            && closed.selected_bytes == facts.selected_bytes
            && closed.range_count == facts.range_count
            && facts.expected_tree_sha256 == pretty_json_sha256(expected)?,
        "recovery requires the actual closed selected-target result for its pinned maps"
    );
    let native = observe_native_metadata(scope, expected, report, restored_label)?;
    let observation = native
        .content_observation
        .as_ref()
        .context("recovery metadata observation absent")?;
    let known = observation
        .known_content
        .as_ref()
        .context("recovery known-content checks absent")?;
    let mut known_streams = 0usize;
    let mut unknown_streams = 0usize;
    let mut known_bytes = 0u64;
    let mut unknown_partial_streams = 0usize;
    let mut unknown_partial_tail_bytes = 0u64;
    for index in 0..expected.object_count() {
        let object = expected.object(index)?;
        for stream in object.data_streams() {
            if stream.sha256.is_some() {
                known_streams += 1;
                known_bytes = known_bytes
                    .checked_add(stream.length)
                    .context("recovery known stream total overflow")?;
            } else {
                unknown_streams += 1;
                if stream.source_evidence
                    == Some(shadow_tree::SourceStreamEvidence::ExtentIdentityWithMaterializedTailV1)
                {
                    unknown_partial_streams += 1;
                    unknown_partial_tail_bytes = unknown_partial_tail_bytes
                        .checked_add(stream.length % 4096)
                        .context("recovery extent-tail byte total overflow")?;
                }
            }
        }
    }
    ensure!(
        observation.metadata_and_namespace_verified
            && observation.complete_stream_mappings_observed
            && observation.data_storage_validity_checked
            && !observation.full_file_hashes
            && observation.admitted_payload_bytes_read == known_bytes
            && known.payload_bytes_read == known_bytes
            && known.streams_hashed == known_streams
            && known.streams_without_content_baseline == unknown_streams
            && native.pair.source.identity == facts.source.identity
            && native.native.base_sectors == facts.base_sectors
            && proof.maps_match(&native.native)?,
        "recovery mounted metadata, storage validity or complete maps differ from pinned target facts"
    );
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() && !restored_label {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(
        serde_json::json!({"schema_version":1,"scope":"recovery-selected-checksums-and-pinned-stream-maps-v1",
        "all_complete_maps_identical":true,"stream_and_directory_bindings":proof.maps.len(),
        "selected_bytes_checksummed":closed.selected_bytes,"selected_sha256":hex::encode(closed.selected_sha256),
        "handoff_replay_closed":true,"full_file_hashes":false,"initial_retained_content_digests_available":false,
        "known_content_streams_hashed":known_streams,"known_content_payload_bytes_read":known_bytes,
        "extent_only_streams":unknown_streams,
        "extent_only_partial_streams":unknown_partial_streams,
        "extent_only_partial_tail_bytes":unknown_partial_tail_bytes,
        "post_operational_source_equality_claimed":false,"grants_fresh_source_or_write_authority":false}),
    )
}

fn observe_native_metadata(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    restored_label: bool,
) -> Result<shadow_native::GeneralConvertedReport> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    expected.revalidate_domain()?;
    let input = crate::general_shadow::ExpectedInputs(expected);
    Ok(
        shadow_native::verify_general_converted_known_contents_domain(
            pair,
            &input,
            if restored_label {
                scope.expected_source_label
            } else {
                None
            },
            |a, b| {
                ntfs_attestation::same_security(a, b)
                    .map_err(|error| io::Error::other(error.to_string()))
            },
            scope
                .source_resource_profile
                .unwrap_or_default()
                .native_profile(),
        )?,
    )
}

/// Only the fresh allocation route can supply this in-memory proof and its
/// actual Apply/HND results. Recovery uses its distinct pinned-fact protocol.
pub(crate) fn verify_native_extents_scoped(
    scope: &NativeVerificationScope<'_>,
    expected: &impl shadow_tree::ExpectedObjectDomain,
    report: &mut Finalization,
    proof: &FreshPayloadProof,
    applied: &selected_journal::SelectedResult,
    handoff: &selected_journal::SelectedResult,
) -> Result<Value> {
    let mut pair = scope.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut report.events)?;
    expected.revalidate_domain()?;
    let input = crate::general_shadow::ExpectedInputs(expected);
    let native = shadow_native::observe_general_converted_metadata_domain(
        pair,
        &input,
        None,
        |a, b| {
            ntfs_attestation::same_security(a, b)
                .map_err(|error| io::Error::other(error.to_string()))
        },
        scope
            .source_resource_profile
            .unwrap_or_default()
            .native_profile(),
    )?;
    let receipt = proof.verify(scope, expected, applied, handoff, &native)?;
    record_mount_paths_scoped(scope, &native, report);
    report.native = Some(native);
    if report.error.is_none() {
        restore_source_label_scoped(scope, report);
    }
    report.success = report.error.is_none();
    Ok(receipt)
}
