//! Compare pinned saved metadata only. Never opens a device or queries a VM.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use n2r_win32::{attestation::Snapshot, retrieval_paging, stream_layout};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

const CLUSTER: u64 = 4096;
const MAX_INPUT: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputPin {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    source_basis: InputPin,
    expectation: InputPin,
    target_preservation: InputPin,
    native_report: InputPin,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    kind: String,
    source_commit: String,
    executable_sha256: String,
    files: Inputs,
}

#[derive(Serialize)]
struct ObservedInput {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    file_id_info: Option<String>,
}
struct Loaded<T> {
    value: T,
    observed: ObservedInput,
    file: File,
    modified: SystemTime,
}

fn canonical_hex(text: &str, count: usize) -> bool {
    text.len() == count
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ordinary_path(path: &Path, file_must_exist: bool) -> Result<()> {
    ensure!(
        path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "absolute ordinary path without traversal required"
    );
    #[cfg(windows)]
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => ensure!(
                matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ),
                "device and network namespaces are not allowed"
            ),
            Component::Normal(name) => ensure!(
                !name.to_string_lossy().contains(':'),
                "alternate streams are not allowed"
            ),
            _ => {}
        }
    }
    for ancestor in path
        .ancestors()
        .skip(if file_must_exist { 0 } else { 1 })
        .filter(|p| !p.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "symlink evidence ancestry is not allowed"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "reparse evidence ancestry is not allowed"
            );
        }
        if ancestor != path {
            ensure!(metadata.is_dir(), "evidence ancestry must be directories");
        }
    }
    Ok(())
}
fn held_id(file: &File) -> Result<Option<String>> {
    #[cfg(windows)]
    {
        Ok(Some(n2r_win32::file_storage::file_id_info(file)?))
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(None)
    }
}
fn load<T: DeserializeOwned>(path: &Path, expected: Option<&str>, limit: u64) -> Result<Loaded<T>> {
    ordinary_path(path, true)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= limit,
        "bounded nonempty ordinary JSON required: {}",
        path.display()
    );
    let modified = before.modified()?;
    let file_id_info = held_id(&file)?;
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() && bytes.len() as u64 <= limit,
        "input length changed during reading"
    );
    let sha256 = hex::encode(Sha256::digest(&bytes));
    ensure!(
        expected.is_none_or(|pin| canonical_hex(pin, 64) && pin == sha256),
        "saved metadata SHA-256 differs: {}",
        path.display()
    );
    ensure!(
        file.metadata()?.len() == before.len()
            && file.metadata()?.modified()? == modified
            && held_id(&file)? == file_id_info,
        "input identity changed during reading"
    );
    let value =
        serde_json::from_slice(&bytes).with_context(|| format!("decoding {}", path.display()))?;
    Ok(Loaded {
        value,
        observed: ObservedInput {
            path: path.to_owned(),
            sha256,
            bytes: before.len(),
            file_id_info,
        },
        file,
        modified,
    })
}
impl<T> Loaded<T> {
    fn revalidate(&self) -> Result<()> {
        ensure!(
            self.file.metadata()?.len() == self.observed.bytes
                && self.file.metadata()?.modified()? == self.modified
                && held_id(&self.file)? == self.observed.file_id_info,
            "held metadata input identity changed"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
struct SourceBasis {
    source_sha256: String,
    canonical_inspection_sha256: String,
    ntfs: Ntfs,
}
#[derive(Deserialize)]
struct Ntfs {
    geometry: Geometry,
    inventory_complete: bool,
    files: Vec<SourceFile>,
}
#[derive(Deserialize)]
struct Geometry {
    cluster_size: u64,
    bytes_per_sector: u64,
    volume_size: u64,
}
#[derive(Deserialize)]
struct SourceFile {
    record_number: u64,
    sequence_number: u16,
    is_directory: bool,
    is_metadata: bool,
    attributes: Vec<Attribute>,
}
#[derive(Deserialize)]
struct Attribute {
    type_code: u32,
    name_utf16: Vec<u16>,
    flags: u16,
    resident: bool,
    logical_size: u64,
    initialized_size: u64,
    lowest_vcn: u64,
    #[serde(default)]
    compression_unit: u16,
    extents: Vec<Extent>,
}
#[derive(Deserialize)]
struct Extent {
    logical_offset: u64,
    physical_offset: Option<u64>,
    length: u64,
}
#[derive(Deserialize)]
struct Expectation {
    objects: Vec<ExpectedObject>,
}
#[derive(Deserialize)]
struct ExpectedObject {
    record_number: u64,
    sequence_number: u16,
    path: Vec<String>,
    directory: bool,
    length: u64,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Partition {
    disk_guid: String,
    partition_guid: String,
    partition_number: u32,
    disk_bytes: u64,
    partition_offset: u64,
    partition_bytes: u64,
    logical_sector_bytes: u32,
    physical_sector_bytes: u32,
}
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Binding {
    disk_number: u32,
    identity: Partition,
}
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Pair {
    source: Binding,
    shadow: Binding,
}
#[derive(Deserialize)]
struct Preservation {
    pair: Pair,
    source_sha256: String,
    inspection_sha256: String,
    expected_tree_sha256: String,
    in_place_payload_bytes_not_compared: u64,
    protected: Protected,
}
#[derive(Deserialize)]
struct Protected {
    routes: Routes,
    native: ProtectedWitness,
    expected_tree_sha256: String,
}
#[derive(Deserialize)]
struct Routes {
    pair: Pair,
    entries: Vec<Route>,
    payload_bytes: u64,
}
#[derive(Deserialize)]
struct Route {
    object_index: usize,
    logical_offset: u64,
    target_physical_offset: u64,
    length: u64,
    stream_length: u64,
    components: Vec<String>,
    expected_sha256: String,
    native_file_id: Vec<u8>,
}
#[derive(Deserialize)]
struct ProtectedWitness {
    before: serde_json::Value,
    after: serde_json::Value,
    observed_readonly: serde_json::Value,
    report: ProtectedReport,
}
#[derive(Deserialize)]
struct ProtectedReport {
    pair: Pair,
    native: NativeSnapshot,
    expected_stream_sha256: Vec<Option<String>>,
    metadata_and_namespace_verified: bool,
    complete_stream_mappings_verified: bool,
    storage_validity_verified: bool,
    data_integrity_disabled: bool,
}
#[derive(Deserialize)]
struct Completion {
    success: bool,
    rollback_closed: bool,
    error: Option<serde_json::Value>,
    native: Converted,
}
#[derive(Deserialize)]
struct Converted {
    pair: Pair,
    native: NativeSnapshot,
}
#[derive(Deserialize)]
struct NativeSnapshot {
    binding: Binding,
    base_sectors: u64,
    objects: Vec<NativeObject>,
}
#[derive(Deserialize)]
struct NativeObject {
    components: Vec<String>,
    before: Snapshot,
    after: Snapshot,
    logical_sha256: Option<String>,
    retrieval: Vec<u8>,
    retrieval_page_proof: Option<retrieval_paging::Proof>,
    resident_data: bool,
    storage_validity: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Mapping {
    logical: u64,
    physical: u64,
    length: u64,
}
#[derive(Default, Serialize)]
struct Summary {
    expected_objects: usize,
    native_objects: usize,
    files: usize,
    user_files: usize,
    saved_logical_hashes_matched: usize,
    nonempty_native_maps: usize,
    independently_matched_single_page_responses: usize,
    structurally_checked_multi_page_maps: usize,
    eligible_files: usize,
    eligible_bytes: u64,
    retained_bytes: u64,
    relocated_bytes: u64,
    user_eligible_files: usize,
    user_eligible_bytes: u64,
    user_retained_bytes: u64,
    user_relocated_bytes: u64,
    files_with_retained: usize,
    files_with_relocated: usize,
    files_with_both: usize,
    excluded_files_by_reason: BTreeMap<String, usize>,
    protected_routes: usize,
    protected_route_bytes: u64,
    protected_routes_matched: usize,
    live_proof_retained_bytes: u64,
}
#[derive(Serialize)]
struct FileRow {
    object_index: usize,
    record_number: u64,
    sequence_number: u16,
    components: Vec<String>,
    user_file: bool,
    logical_bytes: u64,
    initialized_bytes: u64,
    disposition: String,
    eligible_bytes: u64,
    retained_bytes: u64,
    relocated_bytes: u64,
}
#[derive(Serialize)]
struct Segment {
    object_index: usize,
    logical_offset: u64,
    length: u64,
    original_physical_offset: u64,
    final_physical_offset: u64,
    retained: bool,
}
#[derive(Serialize)]
struct QueryFile {
    components: Vec<String>,
    expected_file_id: [u8; 16],
    expected_volume_serial: [u8; 8],
    expected_length: u64,
    expected_retrieval: Vec<u8>,
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("extent arithmetic overflow")
}
fn query(snapshot: &Snapshot, class: i32, minimum: usize) -> Result<&[u8]> {
    let mut found = snapshot.queries.iter().filter(|q| q.class == class);
    let value = found
        .next()
        .context("required native snapshot query absent")?;
    ensure!(
        found.next().is_none() && value.native_error.is_none() && value.bytes.len() >= minimum,
        "native snapshot query is ambiguous, failed or truncated"
    );
    Ok(&value.bytes)
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .context("truncated native u64")?
            .try_into()?,
    ))
}
fn identity(object: &NativeObject) -> Result<([u8; 8], [u8; 16])> {
    let data = query(&object.before, 18, 24)?;
    Ok((data[..8].try_into()?, data[8..24].try_into()?))
}
fn path_valid(path: &[String]) -> bool {
    path.iter().all(|part| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', '/', '\0'])
    })
}
fn decode_map(
    object: &NativeObject,
    expected: &ExpectedObject,
    partition: u64,
    summary: &mut Summary,
) -> Result<Vec<Mapping>> {
    ensure!(
        object.before == object.after,
        "saved native object snapshot changed: {:?}",
        object.components
    );
    let standard = query(&object.before, 1, 24)?;
    ensure!(
        (standard[21] != 0) == expected.directory,
        "native directory type differs"
    );
    let _ = identity(object)?;
    if !expected.directory {
        ensure!(
            u64_at(standard, 8)? == expected.length,
            "native stream EOF differs"
        );
    }
    if object.retrieval.is_empty() {
        let allocation = u64_at(standard, 0)?;
        ensure!(
            object.retrieval_page_proof.is_none()
                && (expected.directory
                    || (expected.length == 0 && allocation == 0)
                    || (object.resident_data
                        && expected.length <= CLUSTER
                        && allocation < CLUSTER
                        && allocation >= expected.length)),
            "allocated stream lacks its saved native map"
        );
        return Ok(Vec::new());
    }
    ensure!(
        !expected.directory && !object.resident_data,
        "directory or resident object has an allocated stream map"
    );
    let runs = stream_layout::parse_complete_retrieval(&object.retrieval)?;
    let proof = object
        .retrieval_page_proof
        .as_ref()
        .context("assembled map proof absent")?;
    let canonical = hex::encode(Sha256::digest(&object.retrieval));
    ensure!(
        proof.encoding == retrieval_paging::ENCODING
            && proof.canonical_sha256 == canonical
            && proof.extent_count == runs.len(),
        "native canonical retrieval proof differs"
    );
    ensure!(
        !proof.pages.is_empty() && proof.pages.len() <= retrieval_paging::MAX_PAGES,
        "native retrieval transcript is empty or over budget"
    );
    let mut previous_input = None;
    for (index, page) in proof.pages.iter().enumerate() {
        let input = u64_at(&page.input, 0)?;
        let count = u32::from_le_bytes(page.response_header[..4].try_into()?) as usize;
        let start = i64::from_le_bytes(page.response_header[8..16].try_into()?);
        ensure!(
            page.input.len() == 8
                && count > 0
                && count <= stream_layout::MAX_EXTENTS
                && page.response_bytes == 16 + count * 16
                && start >= 0
                && start as u64 <= input
                && canonical_hex(&page.response_sha256, 64),
            "malformed saved native retrieval page proof"
        );
        ensure!(
            input < proof.virtual_clusters
                && if index == 0 {
                    input == 0
                } else {
                    previous_input.is_some_and(|old| input > old)
                },
            "nonprogressing native retrieval transcript"
        );
        ensure!(
            if index + 1 == proof.pages.len() {
                page.native_error.is_none()
            } else {
                page.native_error == Some(retrieval_paging::MORE_DATA)
            },
            "native retrieval transcript did not complete"
        );
        previous_input = Some(input);
    }
    if proof.pages.len() == 1 {
        let page = &proof.pages[0];
        ensure!(
            page.response_bytes == object.retrieval.len()
                && page.response_header.as_slice() == &object.retrieval[..16]
                && page.response_sha256 == canonical,
            "single-page response cannot be reconstructed from the saved canonical map"
        );
        summary.independently_matched_single_page_responses += 1;
    } else {
        // Original per-page bodies are not serialized. Their structural
        // transcript and canonical map are checked; no fresh native claim.
        summary.structurally_checked_multi_page_maps += 1;
    }
    let mut maps = Vec::with_capacity(runs.len());
    let mut virtual_end = 0;
    for run in runs {
        ensure!(run.vcn == virtual_end, "gapped native logical mapping");
        virtual_end = add(run.vcn, run.clusters)?;
        let logical = run
            .vcn
            .checked_mul(CLUSTER)
            .context("native VCN overflow")?;
        let physical = run
            .lcn
            .context("ordinary native payload contains a hole")?
            .checked_mul(CLUSTER)
            .context("native LCN overflow")?;
        let length = run
            .clusters
            .checked_mul(CLUSTER)
            .context("native run length overflow")?;
        ensure!(
            add(physical, length)? <= partition,
            "native physical extent escapes partition"
        );
        maps.push(Mapping {
            logical,
            physical,
            length,
        });
    }
    let allocation = virtual_end
        .checked_mul(CLUSTER)
        .context("native allocation overflow")?;
    ensure!(
        virtual_end == proof.virtual_clusters
            && allocation == u64_at(standard, 0)?
            && allocation >= expected.length,
        "native allocation or proof length differs"
    );
    if expected.length != 0 {
        n2r_win32::region_layout::validate_logical(&object.storage_validity, expected.length, 2)?;
    }
    summary.nonempty_native_maps += 1;
    Ok(maps)
}
fn source_maps(attribute: &Attribute, partition: u64) -> Result<Vec<Mapping>> {
    let mut result = Vec::with_capacity(attribute.extents.len());
    let mut previous = 0;
    for extent in &attribute.extents {
        let physical = extent
            .physical_offset
            .context("ordinary initialized source has a sparse extent")?;
        ensure!(
            extent.length > 0
                && extent.length.is_multiple_of(CLUSTER)
                && extent.logical_offset.is_multiple_of(CLUSTER)
                && physical.is_multiple_of(CLUSTER)
                && extent.logical_offset >= previous
                && add(physical, extent.length)? <= partition,
            "invalid original source extent"
        );
        previous = add(extent.logical_offset, extent.length)?;
        result.push(Mapping {
            logical: extent.logical_offset,
            physical,
            length: extent.length,
        });
    }
    Ok(result)
}
fn compare(
    left: &[Mapping],
    right: &[Mapping],
    start: u64,
    length: u64,
    mut visit: impl FnMut(u64, u64, u64, u64) -> Result<()>,
) -> Result<()> {
    let stop = add(start, length)?;
    let mut cursor = start;
    let mut a = left.partition_point(|m| m.logical + m.length <= cursor);
    let mut b = right.partition_point(|m| m.logical + m.length <= cursor);
    while cursor < stop {
        let old = left
            .get(a)
            .context("original logical mapping is incomplete")?;
        let new = right
            .get(b)
            .context("final logical mapping is incomplete")?;
        let old_end = add(old.logical, old.length)?;
        let new_end = add(new.logical, new.length)?;
        ensure!(
            old.logical <= cursor && cursor < old_end && new.logical <= cursor && cursor < new_end,
            "logical extent coverage has a gap"
        );
        let end = stop.min(old_end).min(new_end);
        visit(
            cursor,
            end - cursor,
            add(old.physical, cursor - old.logical)?,
            add(new.physical, cursor - new.logical)?,
        )?;
        cursor = end;
        if cursor == old_end {
            a += 1;
        }
        if cursor == new_end {
            b += 1;
        }
    }
    Ok(())
}
fn push_segment(rows: &mut Vec<Segment>, row: Segment) -> Result<()> {
    if let Some(last) = rows.last_mut()
        && last.object_index == row.object_index
        && last.retained == row.retained
        && add(last.logical_offset, last.length)? == row.logical_offset
        && add(last.original_physical_offset, last.length)? == row.original_physical_offset
        && add(last.final_physical_offset, last.length)? == row.final_physical_offset
    {
        last.length = add(last.length, row.length)?;
    } else {
        rows.push(row);
    }
    Ok(())
}

fn checked_native<'a>(
    native: &'a NativeSnapshot,
    expected: &[ExpectedObject],
    partition: u64,
    content: bool,
    summary: &mut Summary,
) -> Result<(
    BTreeMap<Vec<String>, &'a NativeObject>,
    BTreeMap<Vec<String>, Vec<Mapping>>,
)> {
    ensure!(
        native.base_sectors == 0 && native.objects.len() == expected.len(),
        "native base or object count differs"
    );
    let mut objects = BTreeMap::new();
    for object in &native.objects {
        ensure!(
            path_valid(&object.components)
                && objects.insert(object.components.clone(), object).is_none(),
            "native namespace path duplicated or invalid"
        );
    }
    let mut maps = BTreeMap::new();
    for object in expected {
        let observed = objects
            .get(&object.path)
            .context("expected native path absent")?;
        if content {
            ensure!(
                observed.logical_sha256 == object.sha256
                    && (object.directory || object.sha256.as_ref().is_some_and(|s| !s.is_empty())),
                "saved native logical content digest differs"
            );
            if !object.directory {
                summary.saved_logical_hashes_matched += 1;
            }
        }
        maps.insert(
            object.path.clone(),
            decode_map(observed, object, partition, summary)?,
        );
    }
    Ok((objects, maps))
}

fn run(args: Args) -> Result<()> {
    let manifest: Loaded<Manifest> = load(&args.manifest, None, 64 * 1024)?;
    let m = &manifest.value;
    ensure!(
        m.schema_version == 1
            && m.kind == "saved-native-extent-inputs"
            && canonical_hex(&m.source_commit, 40)
            && canonical_hex(&m.executable_sha256, 64),
        "unsupported saved-extent manifest provenance"
    );
    let basis: Loaded<SourceBasis> = load(
        &m.files.source_basis.path,
        Some(&m.files.source_basis.sha256),
        MAX_INPUT,
    )?;
    let expected: Loaded<Expectation> = load(
        &m.files.expectation.path,
        Some(&m.files.expectation.sha256),
        MAX_INPUT,
    )?;
    let target: Loaded<Preservation> = load(
        &m.files.target_preservation.path,
        Some(&m.files.target_preservation.sha256),
        MAX_INPUT,
    )?;
    let completed: Loaded<Completion> = load(
        &m.files.native_report.path,
        Some(&m.files.native_report.sha256),
        MAX_INPUT,
    )?;
    let proof = &target.value;
    let source = &basis.value.ntfs;
    let objects = &expected.value.objects;
    let partition = proof.pair.source.identity.partition_bytes;
    ensure!(
        partition != 0
            && partition.is_multiple_of(CLUSTER)
            && source.geometry.cluster_size >= CLUSTER
            && source.geometry.cluster_size.is_multiple_of(CLUSTER)
            && source.geometry.bytes_per_sector != 0
            && source.geometry.volume_size <= partition,
        "unsupported saved source geometry"
    );
    ensure!(
        completed.value.success
            && completed.value.rollback_closed
            && completed.value.error.is_none(),
        "native completion was not successful and handed off"
    );
    ensure!(
        proof.pair == proof.protected.routes.pair
            && proof.pair == proof.protected.native.report.pair
            && proof.pair == completed.value.native.pair
            && completed.value.native.native.binding == proof.pair.source
            && proof.protected.native.report.native.binding == proof.pair.shadow,
        "source/shadow/native physical bindings differ"
    );
    ensure!(
        proof.expected_tree_sha256 == m.files.expectation.sha256
            && proof.protected.expected_tree_sha256 == m.files.expectation.sha256
            && proof.inspection_sha256 == basis.value.canonical_inspection_sha256
            && proof.source_sha256 == basis.value.source_sha256,
        "source inspection or expected-tree associations differ"
    );
    let protected = &proof.protected.native;
    ensure!(
        protected.before == protected.after
            && protected.before["disk_attributes"] == 3
            && protected.observed_readonly["disk_attributes"] == 2
            && protected.report.metadata_and_namespace_verified
            && protected.report.complete_stream_mappings_verified
            && protected.report.storage_validity_verified
            && protected.report.data_integrity_disabled,
        "protected native layout evidence did not preserve exclusion and semantics"
    );
    let mut identities = BTreeMap::new();
    for file in &source.files {
        ensure!(
            identities
                .insert((file.record_number, file.sequence_number), file)
                .is_none(),
            "source file identity duplicated"
        );
    }
    let mut expected_paths = BTreeMap::new();
    for (index, object) in objects.iter().enumerate() {
        ensure!(
            path_valid(&object.path) && expected_paths.insert(object.path.clone(), index).is_none(),
            "expected path duplicated or invalid"
        );
    }
    ensure!(
        !objects.is_empty() && protected.report.expected_stream_sha256.len() == objects.len(),
        "protected expectations are incomplete"
    );
    for (index, object) in objects.iter().enumerate() {
        ensure!(
            protected
                .report
                .native
                .objects
                .get(index)
                .is_some_and(|o| o.components == object.path)
                && protected.report.expected_stream_sha256[index] == object.sha256,
            "protected object order or expected digest differs"
        );
    }
    let mut summary = Summary {
        expected_objects: objects.len(),
        native_objects: completed.value.native.native.objects.len(),
        live_proof_retained_bytes: proof.in_place_payload_bytes_not_compared,
        ..Summary::default()
    };
    let (native_objects, native_maps) = checked_native(
        &completed.value.native.native,
        objects,
        partition,
        true,
        &mut summary,
    )?;
    let mut protected_summary = Summary::default();
    let (protected_objects, protected_maps) = checked_native(
        &protected.report.native,
        objects,
        partition,
        false,
        &mut protected_summary,
    )?;
    let mut files = Vec::new();
    let mut segments = Vec::new();
    let mut query_files = Vec::new();
    for (object_index, object) in objects.iter().enumerate() {
        let file = identities
            .get(&(object.record_number, object.sequence_number))
            .context("expected source identity absent")?;
        ensure!(
            file.is_directory == object.directory,
            "source expected object type differs"
        );
        if object.directory {
            continue;
        }
        summary.files += 1;
        let user_file = !file.is_metadata
            && object
                .path
                .first()
                .is_none_or(|p| p != "System Volume Information");
        if user_file {
            summary.user_files += 1;
        }
        let mut attrs = file
            .attributes
            .iter()
            .filter(|a| a.type_code == 0x80 && a.name_utf16.is_empty());
        let attribute = attrs.next().context("default data attribute absent")?;
        ensure!(
            attrs.next().is_none()
                && attribute.logical_size == object.length
                && attribute.initialized_size <= attribute.logical_size,
            "default stream is ambiguous or has invalid sizes"
        );
        let eligible = attribute.initialized_size.min(attribute.logical_size) / CLUSTER * CLUSTER;
        let exclusion = if attribute.resident {
            Some("source_resident")
        } else if attribute.flags != 0
            || attribute.lowest_vcn != 0
            || attribute.compression_unit != 0
        {
            Some("unsupported_source_encoding")
        } else if eligible == 0 {
            Some("no_initialized_whole_cluster")
        } else {
            None
        };
        let mut row = FileRow {
            object_index,
            record_number: object.record_number,
            sequence_number: object.sequence_number,
            components: object.path.clone(),
            user_file,
            logical_bytes: object.length,
            initialized_bytes: attribute.initialized_size,
            disposition: exclusion.unwrap_or("eligible").into(),
            eligible_bytes: 0,
            retained_bytes: 0,
            relocated_bytes: 0,
        };
        if let Some(reason) = exclusion {
            *summary
                .excluded_files_by_reason
                .entry(reason.into())
                .or_default() += 1;
            files.push(row);
            continue;
        }
        let source_maps = source_maps(attribute, partition)?;
        let final_maps = &native_maps[&object.path];
        compare(
            &source_maps,
            final_maps,
            0,
            eligible,
            |logical, length, original, final_offset| {
                let retained = original == final_offset;
                if retained {
                    row.retained_bytes = add(row.retained_bytes, length)?;
                } else {
                    row.relocated_bytes = add(row.relocated_bytes, length)?;
                }
                push_segment(
                    &mut segments,
                    Segment {
                        object_index,
                        logical_offset: logical,
                        length,
                        original_physical_offset: original,
                        final_physical_offset: final_offset,
                        retained,
                    },
                )
            },
        )?;
        row.eligible_bytes = eligible;
        ensure!(
            add(row.retained_bytes, row.relocated_bytes)? == eligible,
            "physical payload accounting differs"
        );
        summary.eligible_files += 1;
        summary.eligible_bytes = add(summary.eligible_bytes, eligible)?;
        summary.retained_bytes = add(summary.retained_bytes, row.retained_bytes)?;
        summary.relocated_bytes = add(summary.relocated_bytes, row.relocated_bytes)?;
        summary.files_with_retained += usize::from(row.retained_bytes != 0);
        summary.files_with_relocated += usize::from(row.relocated_bytes != 0);
        summary.files_with_both += usize::from(row.retained_bytes != 0 && row.relocated_bytes != 0);
        if user_file {
            summary.user_eligible_files += 1;
            summary.user_eligible_bytes = add(summary.user_eligible_bytes, eligible)?;
            summary.user_retained_bytes = add(summary.user_retained_bytes, row.retained_bytes)?;
            summary.user_relocated_bytes = add(summary.user_relocated_bytes, row.relocated_bytes)?;
            let native = native_objects[&object.path];
            let (serial, id) = identity(native)?;
            query_files.push(QueryFile {
                components: object.path.clone(),
                expected_file_id: id,
                expected_volume_serial: serial,
                expected_length: object.length,
                expected_retrieval: native.retrieval.clone(),
            });
        }
        files.push(row);
    }
    ensure!(
        summary.retained_bytes == proof.in_place_payload_bytes_not_compared,
        "actual retained bytes differ from the live frozen proof"
    );
    let mut route_end = 0;
    let mut route_domains: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
    for route in &proof.protected.routes.entries {
        let expected = objects
            .get(route.object_index)
            .context("protected route object index escapes expectation")?;
        ensure!(
            !expected.directory
                && route.length != 0
                && route.length.is_multiple_of(CLUSTER)
                && route.logical_offset.is_multiple_of(CLUSTER)
                && route.target_physical_offset.is_multiple_of(CLUSTER)
                && route.target_physical_offset >= route_end
                && add(route.target_physical_offset, route.length)? <= partition
                && add(route.logical_offset, route.length)? <= expected.length / CLUSTER * CLUSTER
                && route.stream_length == expected.length
                && route.components == expected.path
                && expected.sha256.as_deref() == Some(route.expected_sha256.as_str()),
            "protected route identity, geometry or ordering differs"
        );
        route_end = add(route.target_physical_offset, route.length)?;
        let (_, before_id) = identity(protected_objects[&route.components])?;
        let (_, final_id) = identity(native_objects[&route.components])?;
        ensure!(
            route.native_file_id.as_slice() == before_id.as_slice() && before_id == final_id,
            "protected route native file identity changed"
        );
        let route_map = [Mapping {
            logical: route.logical_offset,
            physical: route.target_physical_offset,
            length: route.length,
        }];
        for mappings in [
            &protected_maps[&route.components],
            &native_maps[&route.components],
        ] {
            compare(
                &route_map,
                mappings,
                route.logical_offset,
                route.length,
                |_, _, old, new| {
                    ensure!(
                        old == new,
                        "protected target route moved in the saved native mapping"
                    );
                    Ok(())
                },
            )?;
        }
        summary.protected_routes += 1;
        summary.protected_routes_matched += 1;
        summary.protected_route_bytes = add(summary.protected_route_bytes, route.length)?;
        route_domains
            .entry(route.object_index)
            .or_default()
            .push((route.logical_offset, route.length));
    }
    for (index, object) in objects
        .iter()
        .enumerate()
        .filter(|(_, object)| !object.directory)
    {
        let domain = route_domains.entry(index).or_default();
        domain.sort_unstable();
        let mut end = 0;
        for &(logical, length) in domain.iter() {
            ensure!(
                logical == end,
                "protected routes overlap or leave a logical gap"
            );
            end = add(end, length)?;
        }
        ensure!(
            end == object.length / CLUSTER * CLUSTER,
            "protected routes do not cover the whole-cluster stream prefix"
        );
    }
    ensure!(
        summary.protected_route_bytes == proof.protected.routes.payload_bytes,
        "protected payload coverage differs"
    );
    manifest.revalidate()?;
    basis.revalidate()?;
    expected.revalidate()?;
    target.revalidate()?;
    completed.revalidate()?;
    let report = serde_json::json!({
        "schema_version":1,"kind":"saved-native-extent-preservation-analysis","success":true,
        "source_commit":m.source_commit,"executable_sha256":m.executable_sha256,
        "manifest":manifest.observed,"inputs":{"source_basis":basis.observed,"expectation":expected.observed,"target_preservation":target.observed,"native_report":completed.observed},
        "analysis_of_saved_native_metadata":true,"fresh_native_queries":false,
        "raw_inspector_inventory_complete":source.inventory_complete,
        "source_admission_reassessed":false,
        "payload_bytes_read":0,"allocator_reconciliation_performed":false,
        "conversion_authorized":false,"recovery_authorized":false,
        "physical_offsets_are_partition_relative":true,"source_cluster_bytes":source.geometry.cluster_size,"target_cluster_bytes":CLUSTER,
        "content_hashes_are_saved_xxh3_128":true,"file_pins_are_sha256":true,
        "windows_input_write_delete_sharing_excluded":cfg!(windows),
        "summary":summary,"protected_map_checks":protected_summary,
        "files":files,"segments":segments,"query_files":query_files,
        "scope":"Historical saved mappings only. Full initialized 4 KiB ordinary default-data payload is classified; resident bytes and EOF/VDL tails are excluded from physical retention. Multi-page proof bodies are not stored and receive structural transcript checks only. No native result is inherited by this analyzer."
    });
    ordinary_path(&args.output, false)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0).custom_flags(0x0020_0000);
    }
    let mut output = options.open(&args.output)?;
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"success":true,"output":args.output,"summary":report["summary"],"query_files":report["query_files"].as_array().map_or(0,Vec::len),"analysis_of_saved_native_metadata":true,"fresh_native_queries":false,"conversion_authorized":false})
    );
    Ok(())
}
fn main() -> Result<()> {
    run(Args::parse())
}
