//! Native adoption of a metadata transition AFTER carrier transfer has closed.
//! No PrivateTree flags, saved handles, namespace identities or success reports
//! are deserialized. Partial carrier transfer is outside this first adopter.
use super::*;
use crate::progress::{Phase, Unit, Update};
use crate::shadow_native::windows_aliases::{
    VerifiedWindowsAliases, WindowsAliasInput, WindowsAliasInputDomain,
};

#[derive(Clone)]
struct Name {
    object: usize,
    directory: bool,
    optional: bool,
    alias: bool,
    parent: usize,
    canonical_path: Option<Vec<String>>,
}
#[derive(Clone)]
struct StreamState {
    object: usize,
    name: Vec<u16>,
    identity: [u8; 24],
    length: u64,
    allocation: u64,
    mapping: [u8; 32],
}

/// Native handles and complete namespace observations, with payload freshness
/// still pending. Only verify_payloads can issue the metadata-writing wrapper.
pub struct PendingMetadataRecovery {
    pair: GeneralSourceShadowBinding,
    before: source_scope::ConstructionSourceState,
    source: source_scope::DedicatedShadowConstructionLease,
    volume: File,
    handles: BTreeMap<usize, File>,
    alias_handles: BTreeMap<Vec<String>, File>,
    identities: BTreeMap<usize, [u8; 24]>,
    names: BTreeMap<Vec<String>, Name>,
    child_counts: BTreeMap<Vec<String>, usize>,
    canonical_ids: BTreeSet<[u8; 16]>,
    streams: Vec<StreamState>,
    verified_complete_bytes: u64,
    verified_tail_bytes: u64,
    verified_reference_bytes: u64,
    has_installed_points: bool,
    input_digest: [u8; 32],
    alias_digest: [u8; 32],
    admission: crate::tree_resources::SourceResourceAdmission,
    privileges: Privileges,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    _memory: Box<dyn report_memory::ReportMemoryLease>,
}
/// Not constructible from saved facts. The native namespace, storage validity,
/// complete-digest streams and source-compared tails have all closed freshly.
pub struct VerifiedMetadataRecovery {
    inner: PendingMetadataRecovery,
}

/// A selector from a fresh native observation, never allocation/metadata
/// authority. The selected adopter must still prove its complete namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadsShape {
    PrivatePayloads,
    FinalTargets,
}
pub fn classify_payloads_domain(
    enrollment: &mut ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    payer: &dyn report_memory::ReportMemoryAccountant,
) -> io::Result<PayloadsShape> {
    let _memory = payer.reserve(
        (namespace_layout::CAPACITY as u64)
            .checked_mul(namespace_layout::MAX_CALLS as u64)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add((stream_layout::MAX_STREAM_BUFFER as u64) * 4 + 65536))
            .ok_or_else(|| invalid("payload native classification workspace overflow"))?,
    )?;
    enrollment.revalidate()?;
    let cluster = crate::target_cluster::bytes();
    let expected = input.any(|item| {
        item.sparse
            .is_some_and(|layout| !layout.allocated.is_empty())
            || item.named_streams.iter().any(|stream| {
                stream.expected_length >= cluster
                    || stream
                        .sparse
                        .is_some_and(|layout| !layout.allocated.is_empty())
            })
    })?;
    let entries = enumerate(&enrollment.root)?;
    let mut carriers = 0;
    for entry in entries {
        let name = String::from_utf16(&entry.name_utf16)
            .map_err(|_| invalid("payload recovery root UTF16 differs"))?;
        if name.starts_with("n2r-sparse-carriers-") {
            if !expected || entry.attributes & 16 == 0 || entry.attributes & 0x400 != 0 {
                return Err(invalid("payload recovery has an unexpected carrier root"));
            }
            carriers += 1;
        }
    }
    if carriers > 1 {
        return Err(invalid("payload recovery carrier root is ambiguous"));
    }
    let mut private = carriers == 1;
    let mut final_targets = false;
    if carriers == 0 {
        let root = format!("{}\\", enrollment.pair.shadow.volume_path()?);
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let object = owner.input();
            input.progress(
                Update::new(
                    Phase::MetadataRestoration,
                    Unit::Objects,
                    index as u64,
                    Some(input.len() as u64),
                )
                .with_pass(20),
            );
            if object.directory {
                continue;
            }
            if object.logical_length() % cluster == 0
                && object
                    .named_streams
                    .iter()
                    .all(|stream| stream.expected_length % cluster == 0)
            {
                continue;
            }
            let path = super::super::streams::path(&root, object.components, &[])?;
            let file = File::options()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(&path)?;
            if !crate::file_storage::held_at_guid_path(&file, &path)? {
                return Err(invalid("payload EOF probe escaped its exact shadow path"));
            }
            let before = identity(&file)?;
            let raw = info(&file, 7, stream_layout::MAX_STREAM_BUFFER)?;
            let (actual, _) = stream_layout::parse_streams(&raw)?;
            for position in 0..=object.named_streams.len() {
                let name = if position == 0 {
                    &[][..]
                } else {
                    object.named_streams[position - 1].name_utf16
                };
                let item = super::super::streams::view_object(&object, name)?;
                let length = item.logical_length();
                if length % cluster == 0 {
                    continue;
                }
                let found = actual
                    .iter()
                    .find(|stream| stream.name == name)
                    .ok_or_else(|| invalid("payload EOF probe stream absent"))?;
                let rounded = length
                    .checked_next_multiple_of(cluster)
                    .ok_or_else(|| invalid("payload EOF probe overflow"))?;
                if found.logical_size == rounded {
                    private = true;
                } else if found.logical_size == length {
                    // Ordinary private files already use logical EOF. Only
                    // rounded carrier targets distinguish a completed transfer.
                    if item.sparse.is_some() || (!name.is_empty() && length >= cluster) {
                        final_targets = true;
                    }
                } else {
                    return Err(invalid(
                        "payload EOF probe found neither private nor final stream shape",
                    ));
                }
            }
            if identity(&file)? != before
                || info(&file, 7, stream_layout::MAX_STREAM_BUFFER)? != raw
            {
                return Err(invalid("payload EOF probe changed"));
            }
        }
    }
    if private && final_targets {
        return Err(invalid(
            "payload EOF probe found partial carrier transfer; preserve without fallback",
        ));
    }
    enrollment.revalidate()?;
    Ok(if private {
        PayloadsShape::PrivatePayloads
    } else {
        PayloadsShape::FinalTargets
    })
}

fn identity(file: &File) -> io::Result<[u8; 24]> {
    info(file, 18, 24)?
        .try_into()
        .map_err(|_| invalid("metadata recovery identity width differs"))
}
fn open_transition(
    path: &str,
    directory: bool,
    point: Option<&crate::reparse_layout::Point>,
) -> io::Result<File> {
    // Restored READONLY data files reject WRITE_DATA/APPEND even under backup
    // semantics. Security, EA and basic metadata use their narrower rights.
    let mut file = File::options()
        .access_mode(if directory {
            crate::shadow_native::METADATA_WRITE_ACCESS
        } else {
            crate::shadow_native::METADATA_WRITE_ACCESS & !0x6
        })
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?;
    suppress_access(&file)?;
    let flags = layout::u32_at(&info(&file, 9, 8)?, 0)?;
    if flags & (0x800 | 0x4000) != 0 || (flags & 16 != 0) != directory {
        return Err(invalid(
            "metadata transition object type or encoding differs",
        ));
    }
    let actual = crate::reparse_native::capture(&file)?;
    if actual.as_ref().is_some_and(|actual| Some(actual) != point) {
        return Err(invalid(
            "metadata transition contains an unexpected reparse target",
        ));
    }
    if (flags & 0x400 != 0) != actual.is_some() {
        return Err(invalid("metadata transition reparse attributes disagree"));
    }
    if !directory && actual.is_none() && point.is_some() {
        // SET requires writable fresh-object access. Keep the first identity
        // held while obtaining it; never clear READONLY merely to gain access.
        if flags & 1 != 0 || layout::u64_at(&info(&file, 1, 24)?, 8)? != 0 {
            return Err(invalid(
                "uninstalled recovered reparse file is readonly or nonempty",
            ));
        }
        let before = identity(&file)?;
        let setter = File::options()
            .access_mode(crate::shadow_native::METADATA_WRITE_ACCESS)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(path)?;
        suppress_access(&setter)?;
        if identity(&setter)? != before
            || layout::u32_at(&info(&setter, 9, 8)?, 0)? != flags
            || crate::reparse_native::capture(&setter)?.is_some()
        {
            return Err(invalid("recovered reparse setter identity changed"));
        }
        file = setter;
    }
    Ok(file)
}
fn stream_state(
    file: &File,
    object: usize,
    name: &[u16],
    item: &Input<'_>,
    partition: u64,
    query_bytes: usize,
    mut mapping_out: Option<&mut Vec<SourceRun>>,
) -> io::Result<StreamState> {
    let before = identity(file)?;
    let standard = info(file, 1, 24)?;
    let length = item.logical_length();
    let cluster = crate::target_cluster::bytes();
    let prefix = length / cluster * cluster;
    let allocation = layout::u64_at(&standard, 0)?;
    if layout::u64_at(&standard, 8)? != length || standard[20] != 0 || standard[21] != 0 {
        return Err(invalid(
            "metadata recovery requires final stream EOF; partial carrier transfer is unsupported",
        ));
    }
    let (first, continuation) =
        crate::stream_native::retrieval_queries_resource(file, query_bytes)?;
    let resident = resident_allocation(length, allocation);
    let empty = (allocation == 0 || resident)
        && continuation.is_empty()
        && ((first.native_error == Some(38) && first.bytes.is_empty())
            || (length == 0
                && first.native_error.is_none()
                && first.bytes.len() == 16
                && layout::u32_at(&first.bytes, 0)? == 0));
    let mut digest = Sha256::new();
    digest.update(b"n2r-metadata-recovery-stream-map-v1\0");
    digest.update(before);
    digest.update(length.to_le_bytes());
    digest.update(allocation.to_le_bytes());
    if !empty {
        let capture = crate::retrieval_paging::assemble_queries_with_limits(
            &first,
            &continuation,
            crate::retrieval_paging::Limits::for_resource_bytes(query_bytes)?,
        )?;
        let mut end = 0u64;
        let mut allocated = 0u64;
        if let Some(output) = mapping_out.as_mut() {
            output
                .try_reserve_exact(capture.runs.len())
                .map_err(io::Error::other)?;
        }
        for run in &capture.runs {
            if run.vcn != end
                || run.clusters == 0
                || match run.lcn {
                    Some(lcn) => lcn
                        .checked_add(run.clusters)
                        .is_none_or(|n| n > partition / cluster),
                    None => item.sparse.is_none() && run.vcn < prefix / cluster,
                }
            {
                return Err(invalid(
                    "metadata recovery native stream map is incomplete or escapes shadow",
                ));
            }
            end = end
                .checked_add(run.clusters)
                .ok_or_else(|| invalid("metadata recovery VCN overflow"))?;
            if run.lcn.is_some() {
                allocated = allocated
                    .checked_add(run.clusters)
                    .ok_or_else(|| invalid("recovery allocated cluster overflow"))?;
            }
            if let Some(output) = mapping_out.as_mut() {
                output.push(SourceRun {
                    logical_offset: run
                        .vcn
                        .checked_mul(cluster)
                        .ok_or_else(|| invalid("recovery mapping offset overflow"))?,
                    physical_offset: run
                        .lcn
                        .map(|lcn| {
                            lcn.checked_mul(cluster)
                                .ok_or_else(|| invalid("recovery mapping physical overflow"))
                        })
                        .transpose()?,
                    length: run
                        .clusters
                        .checked_mul(cluster)
                        .ok_or_else(|| invalid("recovery mapping length overflow"))?,
                });
            }
        }
        if let Some(expected) = item.sparse {
            let allocated = capture
                .runs
                .iter()
                .filter(|run| run.lcn.is_some())
                .map(|run| {
                    Ok(crate::sparse_layout::LogicalRange {
                        offset: run
                            .vcn
                            .checked_mul(cluster)
                            .ok_or_else(|| invalid("sparse offset overflow"))?,
                        length: run
                            .clusters
                            .checked_mul(cluster)
                            .ok_or_else(|| invalid("sparse length overflow"))?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let observed = crate::sparse_layout::SparseLayout::from_allocated(
                length,
                expected.initialized_length,
                allocated,
            )?;
            if observed.allocated != expected.allocated || observed.holes != expected.holes {
                return Err(invalid(
                    "metadata recovery sparse allocation/hole map differs",
                ));
            }
        }
        if item.sparse.is_none()
            && (allocated.checked_mul(cluster) != Some(allocation)
                || end.checked_mul(cluster).is_none_or(|end| end < prefix)
                || allocation < prefix
                || allocation
                    > length
                        .checked_next_multiple_of(65536)
                        .ok_or_else(|| invalid("recovery allocation overflow"))?)
        {
            return Err(invalid("metadata recovery dense allocation differs"));
        }
        digest.update(&capture.canonical);
    } else if item
        .sparse
        .is_some_and(|layout| !layout.allocated.is_empty())
    {
        return Err(invalid(
            "metadata recovery sparse native allocations are absent",
        ));
    } else if length > 0 && item.sparse.is_none() && !resident {
        return Err(invalid(
            "metadata recovery nonempty dense stream has no native allocation",
        ));
    }
    // Sparse complete-digest streams are read in full below; the existing
    // protected target observer retains the exact sparse layout obligation.
    if prefix > 0 && item.sparse.is_none() && !resident && allocation > 0 {
        for usage in [1, 2] {
            initialized_regions::capture_initialized(file, prefix, usage, query_bytes)?
                .validate(prefix, usage)?;
        }
    }
    if identity(file)? != before || info(file, 1, 24)? != standard {
        return Err(invalid(
            "metadata recovery stream changed during native map/VDL audit",
        ));
    }
    Ok(StreamState {
        object,
        name: name.to_vec(),
        identity: before,
        length,
        allocation,
        mapping: digest.finalize().into(),
    })
}

/// The same-coordinate intersection used by placed recovery, expressed in
/// final logical stream coordinates (including sparse islands). Relocated
/// COMPLETE ranges must be read from shadow, never substituted from source.
fn hash_hybrid_complete(
    file: &mut File,
    index: usize,
    name: &[u16],
    item: &Input<'_>,
    mapping: &[SourceRun],
    partition: u64,
    source_read: &mut impl FnMut(usize, &[u16], u64, Option<u64>, &mut [u8]) -> io::Result<()>,
) -> io::Result<(String, u64)> {
    let length = item.logical_length();
    let cluster = crate::target_cluster::bytes();
    let prefix = length / cluster * cluster;
    let sources = if prefix == 0 {
        Vec::new()
    } else if item.sparse.is_none() {
        super::super::placement::source_runs(item, partition)?
    } else if let Some(offset) = item.source_offset {
        if !item.source_runs.is_empty() {
            return Err(invalid("hybrid sparse source forms conflict"));
        }
        vec![SourceRun {
            logical_offset: 0,
            physical_offset: Some(offset),
            length: prefix,
        }]
    } else {
        item.source_runs.clone()
    };
    let mut previous_end = 0u64;
    for source in &sources {
        if source.length == 0
            || source.logical_offset < previous_end
            || !source.logical_offset.is_multiple_of(cluster)
            || !source.length.is_multiple_of(cluster)
            || source.physical_offset.is_some_and(|physical| {
                !physical.is_multiple_of(cluster)
                    || physical
                        .checked_add(source.length)
                        .is_none_or(|end| end > partition)
            })
        {
            return Err(invalid(
                "hybrid source intervals are not ordered admitted physical ranges",
            ));
        }
        previous_end = source
            .logical_offset
            .checked_add(source.length)
            .ok_or_else(|| invalid("hybrid source interval overflow"))?;
    }
    let mut references = Vec::new();
    for source in &sources {
        let Some(physical) = source.physical_offset else {
            continue;
        };
        let source_end = (source.logical_offset + source.length).min(prefix);
        if source.logical_offset >= source_end {
            continue;
        }
        let first = mapping.partition_point(|target| {
            target.logical_offset + target.length <= source.logical_offset
        });
        for target in &mapping[first..] {
            if target.logical_offset >= source_end {
                break;
            }
            let Some(target_physical) = target.physical_offset else {
                continue;
            };
            let start = target.logical_offset.max(source.logical_offset);
            let end = (target.logical_offset + target.length).min(source_end);
            if start < end
                && target_physical + start - target.logical_offset
                    == physical + start - source.logical_offset
            {
                references.push((start, physical + start - source.logical_offset, end - start));
            }
        }
    }
    let mut hash = crate::content_digest::Hasher::new();
    let mut buffer = [0u8; 65536];
    let (mut at, mut source_bytes, mut reference_index, mut map_index) =
        (0u64, 0u64, 0usize, 0usize);
    while at < length {
        while references
            .get(reference_index)
            .is_some_and(|&(start, _, count)| start + count <= at)
        {
            reference_index += 1;
        }
        while mapping
            .get(map_index)
            .is_some_and(|run| run.logical_offset + run.length <= at)
        {
            map_index += 1;
        }
        let mut end = at
            .checked_add(buffer.len() as u64)
            .unwrap_or(u64::MAX)
            .min(length);
        let reference = references
            .get(reference_index)
            .copied()
            .filter(|&(start, _, count)| start <= at && at < start + count);
        if let Some((start, physical, count)) = reference {
            end = end.min(start + count);
            let count = (end - at) as usize;
            source_read(
                index,
                name,
                at,
                Some(physical + at - start),
                &mut buffer[..count],
            )?;
            source_bytes = source_bytes
                .checked_add(count as u64)
                .ok_or_else(|| invalid("hybrid source byte count overflow"))?;
        } else {
            if let Some(&(start, _, _)) = references.get(reference_index) {
                end = end.min(start);
            }
            let mut hole = false;
            if item.sparse.is_some() {
                match mapping.get(map_index) {
                    Some(run) if run.logical_offset <= at => {
                        end = end.min(run.logical_offset + run.length);
                        hole = run.physical_offset.is_none();
                    }
                    Some(run) => {
                        end = end.min(run.logical_offset);
                        hole = true;
                    }
                    None => hole = true,
                }
            }
            let count = (end - at) as usize;
            if hole {
                buffer[..count].fill(0);
            } else {
                file.seek(SeekFrom::Start(at))?;
                file.read_exact(&mut buffer[..count])?;
            }
        }
        if end <= at {
            return Err(invalid("hybrid payload verification made no progress"));
        }
        hash.update(&buffer[..(end - at) as usize]);
        at = end;
    }
    Ok((hash.finish(), source_bytes))
}

/// Enroll an existing final-target namespace. Missing declared hard links and
/// derived aliases are permitted; missing canonical objects, unknown names,
/// wrong identities and remaining carrier directories are refused before writes.
pub fn adopt_domain(
    mut enrollment: ConstructionEnrollment<'_>,
    input: &impl InputDomain,
    aliases: &impl WindowsAliasInputDomain,
    profile: crate::attestation::ResourceProfile,
    payer: Arc<dyn report_memory::ReportMemoryAccountant>,
    pins: ExternalOriginPins,
) -> io::Result<PendingMetadataRecovery> {
    let admission = profile
        .resource_admission()?
        .ok_or_else(|| invalid("metadata recovery requires V4 admission"))?;
    if enrollment.pair.source.layout_profile
        != crate::general_layout::GeneralDiskLayoutProfile::OfflineWindows
        || pins.prior_preparation_sha256 == [0; 32]
        || pins.expected_pages_sha256 == [0; 32]
        || pins.authenticated_checkpoint_sha256 == [0; 32]
        || pins.new_epoch == [0; 16]
    {
        return Err(invalid(
            "metadata recovery requires exact Windows origin pins",
        ));
    }
    input.require_resource_metadata(admission)?;
    aliases.require_resource_metadata(admission)?;
    aliases.revalidate()?;
    let root = format!("{}\\", enrollment.pair.shadow.volume_path()?);
    super::super::hard_links::validate_resource_domain(
        input,
        admission.maximum_namespace_names()?,
        &root,
        crate::shadow_names::valid_unicode_component,
    )?;
    let mut bytes = 1024 * 1024u64;
    let mut names_count = 0u64;
    input.for_each(|_, item| {
        for path in super::super::hard_links::paths(item) {
            names_count = names_count
                .checked_add(1)
                .ok_or_else(|| invalid("recovery namespace count overflow"))?;
            bytes = bytes
                .checked_add(path.iter().try_fold(1024u64, |sum, p| {
                    sum.checked_add((p.len() as u64) * 16)
                        .ok_or_else(|| invalid("recovery path RAM overflow"))
                })?)
                .ok_or_else(|| invalid("recovery index RAM overflow"))?;
        }
        for stream in &item.named_streams {
            bytes = bytes
                .checked_add(
                    (stream.name_utf16.len() as u64)
                        .checked_mul(8)
                        .and_then(|n| n.checked_add(256))
                        .ok_or_else(|| invalid("recovery stream-name RAM overflow"))?,
                )
                .ok_or_else(|| invalid("recovery stream-name total overflow"))?;
        }
        Ok(())
    })?;
    for index in 0..aliases.len() {
        let row = aliases.alias(index)?;
        let row = row.input();
        bytes = bytes
            .checked_add(
                row.components
                    .iter()
                    .chain(row.canonical_components.iter())
                    .try_fold(1024u64, |sum, p| {
                        sum.checked_add((p.len() as u64) * 16)
                            .ok_or_else(|| invalid("recovery alias RAM overflow"))
                    })?,
            )
            .ok_or_else(|| invalid("recovery alias index overflow"))?;
    }
    bytes = bytes
        .checked_add(
            admission
                .data_streams
                .checked_mul(1024)
                .ok_or_else(|| invalid("recovery stream index overflow"))?,
        )
        .ok_or_else(|| invalid("recovery owner RAM overflow"))?;
    if (input.len() as u64)
        .checked_add(aliases.len() as u64)
        .and_then(|n| n.checked_add(12))
        .is_none_or(|n| n > admission.budget.handle_slots)
    {
        return Err(invalid("metadata recovery native handles exceed budget"));
    }
    let memory = payer.reserve(bytes)?;
    let _work = payer.reserve(
        admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(2 * 1024 * 1024))
            .ok_or_else(|| invalid("recovery working RAM overflow"))?,
    )?;
    enrollment.revalidate()?;
    let source = match &enrollment.source {
        source_scope::ConstructionSource::Dedicated(source) => *source,
        _ => {
            return Err(invalid(
                "metadata recovery requires actual whole-disk source exclusion",
            ));
        }
    };
    let dedicated = source_scope::DedicatedShadowConstructionLease::begin(
        source,
        &enrollment.pair,
        &enrollment.source_before,
        payer.as_ref(),
        &mut Vec::new(),
    )?;
    let mut names = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut order = Vec::new();
    input.for_each(|index, item| {
        order.push((item.components.len(), index));
        for (position, path) in super::super::hard_links::paths(item).enumerate() {
            if !folded.insert(crate::shadow_names::conservative_path_key(path))
                || names
                    .insert(
                        path.to_vec(),
                        Name {
                            object: index,
                            directory: item.directory,
                            optional: position != 0,
                            alias: false,
                            parent: 0,
                            canonical_path: None,
                        },
                    )
                    .is_some()
            {
                return Err(invalid("metadata recovery namespace paths collide"));
            }
        }
        Ok(())
    })?;
    for index in 0..aliases.len() {
        let owner = aliases.alias(index)?;
        let row = owner.input();
        let directory = super::super::windows_aliases::validate_row(input, &row, &root)?;
        if !folded.insert(crate::shadow_names::conservative_path_key(row.components))
            || names
                .insert(
                    row.components.to_vec(),
                    Name {
                        object: row.canonical_object_index,
                        directory,
                        optional: true,
                        alias: true,
                        parent: row.parent_object_index,
                        canonical_path: Some(row.canonical_components.to_vec()),
                    },
                )
                .is_some()
        {
            return Err(invalid(
                "metadata recovery alias collides with canonical namespace",
            ));
        }
    }
    order.sort_unstable();
    let mut handles = BTreeMap::new();
    let mut identities = BTreeMap::new();
    let mut unique = BTreeSet::new();
    let mut has_installed_points = false;
    handles.insert(0, enrollment.root);
    for (ordinal, (_, index)) in order.into_iter().enumerate() {
        let owner = input.object(index)?;
        let item = owner.input();
        if !item.components.is_empty() {
            let parent = &item.components[..item.components.len() - 1];
            let parent_index = names
                .get(parent)
                .filter(|name| !name.alias && name.directory)
                .ok_or_else(|| invalid("metadata recovery canonical parent absent"))?
                .object;
            let parent_handle = handles
                .get(&parent_index)
                .ok_or_else(|| invalid("metadata recovery parent was not opened first"))?;
            if crate::reparse_native::capture(parent_handle)?.is_some() {
                return Err(invalid(
                    "metadata recovery refuses traversal through reparse parent",
                ));
            }
            let path = format!("{root}{}", item.components.join("\\"));
            let file = open_transition(&path, item.directory, item.reparse)?;
            if !crate::file_storage::held_at_guid_path(&file, &path)? {
                return Err(invalid("metadata recovery final native path differs"));
            }
            handles.insert(index, file);
        } else if index != 0 || !item.directory {
            return Err(invalid("metadata recovery canonical root differs"));
        }
        let file = handles
            .get(&index)
            .ok_or_else(|| invalid("metadata recovery canonical handle absent"))?;
        crate::extended_attributes_native::validate_recovery_subset(file, item.extended_attributes)
            .map_err(io::Error::other)?;
        has_installed_points |= crate::reparse_native::capture(file)?.is_some();
        let id = identity(file)?;
        if !unique.insert(id)
            || identities
                .get(&0)
                .is_some_and(|root: &[u8; 24]| root[..8] != id[..8])
        {
            return Err(invalid(
                "metadata recovery canonical identities collide or escape volume",
            ));
        }
        identities.insert(index, id);
        if !item.directory {
            super::super::streams::exact_list(
                &info(file, 7, stream_layout::MAX_STREAM_BUFFER)?,
                &item,
            )?;
        }
        input.progress(
            Update::new(
                Phase::MetadataRestoration,
                Unit::Objects,
                ordinal as u64 + 1,
                Some(input.len() as u64),
            )
            .with_pass(21),
        );
    }
    let canonical_ids = identities
        .values()
        .map(|id| id[8..24].try_into().unwrap())
        .collect();
    let mut child_counts = BTreeMap::new();
    for path in names.keys().filter(|path| !path.is_empty()) {
        *child_counts
            .entry(path[..path.len() - 1].to_vec())
            .or_insert(0usize) += 1;
    }
    let mut result = PendingMetadataRecovery {
        pair: enrollment.pair,
        before: enrollment.source_before,
        source: dedicated,
        volume: enrollment.volume,
        handles,
        alias_handles: BTreeMap::new(),
        identities,
        names,
        child_counts,
        canonical_ids,
        streams: Vec::new(),
        verified_complete_bytes: 0,
        verified_tail_bytes: 0,
        verified_reference_bytes: 0,
        has_installed_points,
        input_digest: metadata::input_digest_domain(input)?,
        alias_digest: aliases.semantic_sha256()?,
        admission,
        privileges: enrollment.privileges,
        payer,
        _memory: memory,
    };
    result.audit_namespace(input, true)?;
    result.boundary()?;
    Ok(result)
}

impl PendingMetadataRecovery {
    fn boundary(&self) -> io::Result<()> {
        self.source
            .revalidate_boundary(&self.pair, &self.before, &mut Vec::new())?;
        self.pair
            .shadow
            .validate_volume_extent(&ctl(&self.volume, 0x00560000, &[], 1024)?)?;
        super::super::enrollment::check_mounted_profile(
            &self.volume,
            self.pair.shadow.identity.partition_bytes,
        )
    }
    fn audit_namespace(
        &mut self,
        input: &impl InputDomain,
        retain_aliases: bool,
    ) -> io::Result<()> {
        let root = format!("{}\\", self.pair.shadow.volume_path()?);
        let mut observed = BTreeSet::new();
        let mut alias_ids = BTreeSet::new();
        let mut observed_links = BTreeMap::new();
        observed.insert(Vec::new());
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            let file = &self.handles[&index];
            if identity(file)? != self.identities[&index] {
                return Err(invalid("metadata recovery canonical identity changed"));
            }
            if !item.directory {
                continue;
            }
            if crate::reparse_native::capture(file)?.is_some() {
                self.has_installed_points = true;
                if self.child_counts.get(item.components).copied().unwrap_or(0) != 0 {
                    return Err(invalid(
                        "recovered reparse directory has declared descendants",
                    ));
                }
                continue;
            }
            let count = self.child_counts.get(item.components).copied().unwrap_or(0);
            let bound = count
                .checked_add(2)
                .and_then(|n| n.checked_mul(4096))
                .and_then(|n| n.checked_add(namespace_layout::CAPACITY * 4))
                .ok_or_else(|| invalid("metadata recovery enumeration bound overflow"))?;
            let _work = self.payer.reserve(
                (bound as u64)
                    .checked_mul(2)
                    .ok_or_else(|| invalid("metadata recovery enumeration RAM overflow"))?,
            )?;
            for entry in enumerate_with_resource_budget(file, Some(bound))? {
                if entry.name_utf16 == [46] || entry.name_utf16 == [46, 46] {
                    continue;
                }
                let mut path = item.components.to_vec();
                path.push(
                    String::from_utf16(&entry.name_utf16)
                        .map_err(|_| invalid("metadata recovery child UTF16 differs"))?,
                );
                let name = self.names.get(&path).ok_or_else(|| {
                    invalid(
                        "metadata recovery found unknown or partial-carrier namespace; preserve it",
                    )
                })?;
                if !observed.insert(path.clone()) || (entry.attributes & 16 != 0) != name.directory
                {
                    return Err(invalid("metadata recovery namespace type/count differs"));
                }
                if name.alias {
                    if !alias_ids.insert(entry.file_id)
                        || self.canonical_ids.contains(&entry.file_id)
                    {
                        return Err(invalid("recovered alias identity is not independent"));
                    }
                    let canonical = input.object(name.object)?;
                    let canonical = canonical.input();
                    let canonical_path = name
                        .canonical_path
                        .as_ref()
                        .ok_or_else(|| invalid("recovered alias canonical path absent"))?;
                    let relative: Vec<u16> = canonical_path
                        .last()
                        .ok_or_else(|| invalid("alias canonical leaf absent"))?
                        .encode_utf16()
                        .collect();
                    let point = crate::reparse_layout::Point::relative_component_alias(&relative)?;
                    let alias = open_transition(
                        &format!("{root}{}", path.join("\\")),
                        name.directory,
                        Some(&point),
                    )?;
                    crate::extended_attributes_native::validate_recovery_subset(&alias, None)
                        .map_err(io::Error::other)?;
                    if identity(&alias)?[8..24] != entry.file_id {
                        return Err(invalid("alias changed during recovery enumeration"));
                    }
                    let standard = info(&alias, 1, 24)?;
                    if layout::u32_at(&standard, 16)? != 1 || standard[20] != 0 {
                        return Err(invalid("recovered alias link/delete state differs"));
                    }
                    if !name.directory {
                        let raw = info(&alias, 7, stream_layout::MAX_STREAM_BUFFER)?;
                        let (streams, _) = stream_layout::parse_streams(&raw)?;
                        if streams.len() != 1
                            || !streams[0].name.is_empty()
                            || streams[0].logical_size != 0
                        {
                            return Err(invalid("recovered alias has payload or named streams"));
                        }
                    }
                    if crate::reparse_native::capture(&alias)?.is_some() {
                        self.has_installed_points = true;
                        let target = open_transition(
                            &format!("{root}{}", canonical_path.join("\\")),
                            canonical.directory,
                            canonical.reparse,
                        )?;
                        if identity(&target)? != self.identities[&name.object] {
                            return Err(invalid("recovered alias canonical path changed identity"));
                        }
                        crate::windows_alias_native::verify_owned(
                            &self.handles[&name.parent],
                            &target,
                            &alias,
                            name.directory,
                            &relative,
                        )?;
                    } else if name.directory
                        && enumerate_with_resource_budget(&alias, Some(bound))?
                            .iter()
                            .any(|child| child.name_utf16 != [46] && child.name_utf16 != [46, 46])
                    {
                        return Err(invalid("uninstalled alias directory is not empty"));
                    }
                    if let Some(held) = self.alias_handles.get(&path) {
                        if identity(held)? != identity(&alias)? {
                            return Err(invalid("held recovery alias identity changed"));
                        }
                    } else if retain_aliases {
                        self.alias_handles.insert(path.clone(), alias);
                    } else {
                        return Err(invalid(
                            "metadata recovery gained an alias outside its retained native handles",
                        ));
                    }
                } else {
                    if self.identities[&name.object][8..24] != entry.file_id {
                        return Err(invalid(
                            "recovered hard link names another canonical identity",
                        ));
                    }
                    *observed_links.entry(name.object).or_insert(0usize) += 1;
                }
            }
            input.progress(
                Update::new(
                    Phase::MetadataRestoration,
                    Unit::Objects,
                    index as u64 + 1,
                    Some(input.len() as u64),
                )
                .with_pass(22),
            );
        }
        for (path, name) in &self.names {
            if !name.optional && !observed.contains(path) {
                return Err(invalid(
                    "metadata recovery canonical namespace coverage incomplete",
                ));
            }
        }
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let item = owner.input();
            if item.directory {
                continue;
            }
            let links = observed_links.get(&index).copied().unwrap_or(0);
            if layout::u32_at(&info(&self.handles[&index], 1, 24)?, 16)? as usize != links {
                return Err(invalid(
                    "metadata recovery has undeclared native hard links",
                ));
            }
        }
        Ok(())
    }
    pub fn verify_payloads(
        mut self,
        input: &impl InputDomain,
        aliases: &impl WindowsAliasInputDomain,
        mut source_read: impl FnMut(usize, &[u16], u64, Option<u64>, &mut [u8]) -> io::Result<()>,
    ) -> io::Result<VerifiedMetadataRecovery> {
        self.boundary()?;
        if metadata::input_digest_domain(input)? != self.input_digest
            || aliases.semantic_sha256()? != self.alias_digest
        {
            return Err(invalid("metadata recovery input generation changed"));
        }
        let query =
            usize::try_from(self.admission.budget.max_row_bytes).map_err(io::Error::other)?;
        let _work = self.payer.reserve(
            self.admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(2 * 1024 * 1024))
                .ok_or_else(|| invalid("metadata payload audit RAM overflow"))?,
        )?;
        let root = format!("{}\\", self.pair.shadow.volume_path()?);
        for index in 0..input.len() {
            let owner = input.object(index)?;
            let object = owner.input();
            if object.directory {
                continue;
            }
            for position in 0..=object.named_streams.len() {
                let name = if position == 0 {
                    &[][..]
                } else {
                    object.named_streams[position - 1].name_utf16
                };
                let item = super::super::streams::view_object(&object, name)?;
                let path = super::super::streams::path(&root, object.components, name)?;
                let mut file = File::options()
                    .access_mode(0x01020089)
                    .share_mode(3)
                    .custom_flags(0x02200000)
                    .open(path)?;
                let mut mapping = Vec::new();
                let state = stream_state(
                    &file,
                    index,
                    name,
                    &item,
                    self.pair.shadow.identity.partition_bytes,
                    query,
                    Some(&mut mapping),
                )?;
                if state.identity != self.identities[&index] {
                    return Err(invalid("metadata recovery ADS native identity differs"));
                }
                if let Some(expected) = item.logical_sha256() {
                    let (actual, references) = hash_hybrid_complete(
                        &mut file,
                        index,
                        name,
                        &item,
                        &mapping,
                        self.pair.source.identity.partition_bytes,
                        &mut source_read,
                    )?;
                    if actual != expected {
                        return Err(invalid("metadata recovery hybrid payload digest differs"));
                    }
                    self.verified_reference_bytes = self
                        .verified_reference_bytes
                        .checked_add(references)
                        .ok_or_else(|| invalid("recovery source reference byte overflow"))?;
                    self.verified_complete_bytes = self
                        .verified_complete_bytes
                        .checked_add(item.logical_length())
                        .ok_or_else(|| invalid("recovery complete-byte count overflow"))?;
                } else {
                    let length = item.logical_length();
                    let prefix = crate::target_cluster::floor(length);
                    if prefix == 0 || item.sparse.is_some() {
                        return Err(invalid(
                            "metadata recovery digest-free stream lacks ordinary source prefix",
                        ));
                    }
                    let mut covered = 0;
                    if let Some(offset) = item.source_offset {
                        if offset
                            .checked_add(prefix)
                            .is_none_or(|end| end > self.pair.source.identity.partition_bytes)
                        {
                            return Err(invalid("recovered source prefix escapes source"));
                        }
                        covered = prefix;
                    } else {
                        for run in &item.source_runs {
                            if run.logical_offset != covered
                                || run.physical_offset.is_none_or(|at| {
                                    at.checked_add(run.length).is_none_or(|end| {
                                        end > self.pair.source.identity.partition_bytes
                                    })
                                })
                            {
                                return Err(invalid(
                                    "recovered source extent prefix is incomplete",
                                ));
                            }
                            covered = covered
                                .checked_add(run.length)
                                .ok_or_else(|| invalid("recovered source extent overflow"))?;
                        }
                    }
                    if covered != prefix {
                        return Err(invalid(
                            "recovered source extent prefix does not cover logical clusters",
                        ));
                    }
                    if prefix < length {
                        // A tail is shorter than one target cluster.
                        let count = (length - prefix) as usize;
                        let mut wanted = vec![0u8; count];
                        let mut actual = vec![0u8; count];
                        source_read(index, name, prefix, None, &mut wanted[..count])?;
                        file.seek(SeekFrom::Start(prefix))?;
                        file.read_exact(&mut actual[..count])?;
                        if actual[..count] != wanted[..count] {
                            return Err(invalid(
                                "recovered materialized tail differs from actual frozen source",
                            ));
                        }
                        self.verified_tail_bytes = self
                            .verified_tail_bytes
                            .checked_add(count as u64)
                            .ok_or_else(|| invalid("recovery tail-byte count overflow"))?;
                    }
                }
                let after = stream_state(
                    &file,
                    index,
                    name,
                    &item,
                    self.pair.shadow.identity.partition_bytes,
                    query,
                    None,
                )?;
                if state.identity != after.identity || state.mapping != after.mapping {
                    return Err(invalid(
                        "metadata recovery payload map changed across readback",
                    ));
                }
                self.streams.push(state);
            }
            input.progress(
                Update::new(
                    Phase::PayloadVerification,
                    Unit::Objects,
                    index as u64 + 1,
                    Some(input.len() as u64),
                )
                .with_pass(23),
            );
        }
        self.audit_namespace(input, false)?;
        self.boundary()?;
        aliases.revalidate()?;
        Ok(VerifiedMetadataRecovery { inner: self })
    }
}

impl VerifiedMetadataRecovery {
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"kind":"fresh-native-metadata-recovery-verified-v1","pair":self.inner.pair,
            "input_sha256":hex::encode(self.inner.input_digest),"alias_plan_sha256":hex::encode(self.inner.alias_digest),
            "canonical_objects":self.inner.handles.len(),"verified_streams":self.inner.streams.len(),
            "existing_aliases":self.inner.alias_handles.len(),"complete_logical_bytes_verified":self.inner.verified_complete_bytes,
            "same_coordinate_source_reference_bytes_read":self.inner.verified_reference_bytes,
            "materialized_tail_bytes_compared":self.inner.verified_tail_bytes,"payload_bytes_written":0,"source_payload_writes":0,
            "metadata_reconciliation_pending":true,"original_security_verification_pending":true,
            "protected_target_capture_required":true,"conversion_qualified":false})
    }
    /// Reconcile the already audited namespace. Existing correct aliases,
    /// hard links, EAs and reparse points are read-only successes. Conflicting
    /// points or names refuse; no replacement/deletion repair is attempted.
    pub fn complete(
        self,
        input: &impl InputDomain,
        aliases: &impl WindowsAliasInputDomain,
        security_placeholders: bool,
        same_security: impl Fn(&[u8], &[u8]) -> io::Result<bool>,
    ) -> io::Result<(serde_json::Value, VerifiedWindowsAliases)> {
        let mut state = self.inner;
        state.boundary()?;
        input.require_resource_metadata(state.admission)?;
        aliases.require_resource_metadata(state.admission)?;
        if metadata::input_digest_domain(input)? != state.input_digest
            || aliases.semantic_sha256()? != state.alias_digest
        {
            return Err(invalid(
                "verified metadata recovery inputs changed before mutation",
            ));
        }
        state.audit_namespace(input, false)?;
        // Original construction installs points only AFTER all directory ACL
        // propagation closes. Never replay propagation over an installed
        // junction/symlink: require that completed directory security phase
        // still matches exactly, otherwise refuse before any metadata write.
        if state.has_installed_points {
            for index in 0..input.len() {
                let owner = input.object(index)?;
                let mut item = owner.input();
                if !item.directory {
                    continue;
                }
                let temporary = if security_placeholders {
                    crate::refs_security_descriptor::ConstructorSecurityViews::prepare(
                        item.security,
                        item.expected_api_security,
                        state.admission.budget.max_row_bytes,
                    )?
                } else {
                    None
                };
                if let Some(view) = temporary.as_ref() {
                    item.security = &view.stored;
                    item.expected_api_security = view.api.as_deref();
                }
                if !security_matches(
                    &item,
                    &security_snapshot_with_limit(
                        &state.handles[&index],
                        Some(state.admission.budget.max_row_bytes),
                    ),
                    &same_security,
                )? {
                    return Err(invalid(
                        "recovered directory security differs after reparse installation; unsafe inheritance replay refused",
                    ));
                }
            }
        }
        let root = format!("{}\\", state.pair.shadow.volume_path()?);
        let links = super::super::hard_links::reconcile_owned_resource_domain(
            input,
            &state.handles,
            state.admission.maximum_namespace_names()?,
            &root,
            state.payer.as_ref(),
        )?;
        state.boundary()?;
        let mut reparse = Privileges::enable_for(&["SeCreateSymbolicLinkPrivilege"])?;
        let mut staged = super::super::windows_aliases::StagedWindowsAliases::reconcile(
            input,
            aliases,
            &state.pair,
            &state.handles,
            state.admission,
            state.payer.as_ref(),
            std::mem::take(&mut state.alias_handles),
        )?;
        let mut report =
            super::super::cache_refresh::complete_recovered_metadata_scoped_windows_aliases_domain(
                &state.pair,
                &state.before,
                &state.volume,
                input,
                &state.handles,
                input.len(),
                state.admission,
                &mut staged,
                state.payer.as_ref(),
                security_placeholders,
                same_security,
            )?;
        // Metadata may change security/times/link counts, never stream identity,
        // EOF, allocation or the complete map observed before those mutations.
        let query =
            usize::try_from(state.admission.budget.max_row_bytes).map_err(io::Error::other)?;
        let _work = state.payer.reserve(
            state
                .admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .and_then(|n| n.checked_add(1024 * 1024))
                .ok_or_else(|| invalid("recovery closing RAM overflow"))?,
        )?;
        for (ordinal, before) in state.streams.iter().enumerate() {
            let owner = input.object(before.object)?;
            let object = owner.input();
            let item = super::super::streams::view_object(&object, &before.name)?;
            let path = super::super::streams::path(&root, object.components, &before.name)?;
            let file = File::options()
                .access_mode(0x01020089)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(path)?;
            let after = stream_state(
                &file,
                before.object,
                &before.name,
                &item,
                state.pair.shadow.identity.partition_bytes,
                query,
                None,
            )?;
            if after.identity != before.identity
                || after.length != before.length
                || after.allocation != before.allocation
                || after.mapping != before.mapping
            {
                return Err(invalid(
                    "metadata recovery altered a verified payload mapping",
                ));
            }
            input.progress(
                Update::new(
                    Phase::PayloadVerification,
                    Unit::Streams,
                    ordinal as u64 + 1,
                    Some(state.streams.len() as u64),
                )
                .with_pass(24),
            );
        }
        state.boundary()?;
        aliases.revalidate()?;
        report["recovery"] = serde_json::json!({"kind":"fresh-native-mixed-metadata-reconciliation-v1",
            "canonical_objects":state.handles.len(),"verified_streams":state.streams.len(),
            "hard_links":links,"source_payload_writes":0,"payload_rematerialization_bytes":0,
            "saved_flags_used_as_authority":false,"partial_carrier_transfer_supported":false,
            "protected_target_capture_required":true,"conversion_qualified":false});
        reparse.restore()?;
        state.privileges.restore()?;
        let verified = staged.finish()?;
        state
            .source
            .finish(&state.pair, &state.before, &mut Vec::new())?;
        Ok((report, verified))
    }
}
