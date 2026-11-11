//! Read-only replay of closed placement artifacts, never a live-volume witness.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{bitmap_paging, bitmap_window, bitmap_window_transport};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };

    const INPUT_LIMIT: u64 = 64 * 1024 * 1024;
    const OUTPUT_LIMIT: usize = 1024 * 1024;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        input_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }

    #[derive(Deserialize)]
    struct Artifact {
        schema_version: u32,
        kind: String,
        occupancy_evidence_scope: String,
        per_move_retrieval_scope: String,
        phase_bitmap_scope: String,
        moves: Vec<MoveRow>,
        original_coordinate_ranges: Vec<Coordinate>,
        original_coordinate_bytes: u64,
        counters: Counters,
        source_payload_writes: u64,
    }
    #[derive(Deserialize)]
    struct Counters {
        phase_bitmap_snapshots: u64,
    }
    #[derive(Deserialize)]
    struct MoveRow {
        object_index: u64,
        phase: String,
        proof: MoveProof,
    }
    #[derive(Deserialize)]
    struct MoveProof {
        destination_lcn: u64,
        starting_vcn: u64,
        clusters: u32,
        submitted_once: bool,
        before_valid_data_advance: bool,
        native_error: Value,
        mapping_matches: bool,
        all_placements_match: bool,
        destination_bitmap: Destination,
    }
    #[derive(Deserialize)]
    struct Destination {
        schema_version: u32,
        scope: String,
        legacy: bitmap_window_transport::Proof,
        metadata: bitmap_window_transport::Proof,
    }
    #[derive(Deserialize)]
    struct Coordinate {
        object_index: u64,
        logical_offset: u64,
        source_physical_offset: u64,
        target_physical_offset: u64,
        length: u64,
    }

    fn ordinary_path(path: &Path, fresh: bool) -> Result<()> {
        ensure!(path.is_absolute(), "absolute ordinary file path required");
        for part in path.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(drive) if drive.is_ascii_alphabetic()),
                    "device, UNC and verbatim paths are refused"
                ),
                Component::RootDir => (),
                Component::Normal(value) => {
                    let value = value.to_str().context("Unicode file path required")?;
                    ensure!(
                        !value.contains(':') && !value.ends_with('.') && !value.ends_with(' '),
                        "alternate streams and ambiguous path components are refused"
                    );
                }
                _ => anyhow::bail!("path traversal is refused"),
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary non-reparse file ancestry required"
            );
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                !fresh && metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
                "input must be ordinary; output must be fresh"
            ),
            Err(error) if fresh && error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    // Independently derive the native mover's destination-window limits. No
    // serialized limit or success flag grants additional allocation capacity.
    fn destination_limits(clusters: u32) -> Result<bitmap_window::Limits> {
        ensure!(clusters > 0, "empty destination window");
        let window_bytes = usize::try_from(u64::from(clusters).div_ceil(8))?;
        let max_pages = window_bytes
            .div_ceil(4096 - 16)
            .checked_mul(2)
            .and_then(|n| n.checked_add(16))
            .context("window page-budget overflow")?;
        let rounding_bytes = bitmap_paging::PAGE_BYTES
            .checked_mul(2)
            .context("window rounding-budget overflow")?;
        let max_returned_bytes = window_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(rounding_bytes))
            .and_then(|n| {
                max_pages
                    .checked_mul(16)
                    .and_then(|headers| n.checked_add(headers))
            })
            .context("window transcript-budget overflow")?;
        Ok(bitmap_window::Limits {
            max_window_bytes: window_bytes,
            max_pages,
            max_returned_bytes,
            page_bytes: bitmap_paging::PAGE_BYTES,
        })
    }

    fn add(total: &mut u64, amount: u64) -> Result<()> {
        *total = total
            .checked_add(amount)
            .context("replay summary count overflow")?;
        Ok(())
    }

    let args = Args::parse();
    ensure!(
        args.input_sha256.len() == 64
            && args
                .input_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase 64-character input SHA-256 required"
    );
    ordinary_path(&args.input, false)?;
    ordinary_path(&args.output, true)?;
    ensure!(
        args.output
            .extension()
            .is_some_and(|extension| extension == "json"),
        "fresh JSON output required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(&args.input)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file() && before.file_attributes() & 0x400 == 0 && before.len() <= INPUT_LIMIT,
        "input is not an ordinary bounded file"
    );
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(before.len())?)?;
    Read::by_ref(&mut input)
        .take(INPUT_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let after = input.metadata()?;
    ensure!(
        bytes.len() as u64 == before.len()
            && after.len() == before.len()
            && after.len() <= INPUT_LIMIT
            && after.file_attributes() & 0x400 == 0
            && before.creation_time() == after.creation_time()
            && before.last_write_time() == after.last_write_time(),
        "input changed around bounded read"
    );
    let actual_sha = hex::encode(Sha256::digest(&bytes));
    ensure!(
        actual_sha == args.input_sha256,
        "closed placement input SHA-256 differs"
    );
    let artifact: Artifact =
        serde_json::from_slice(&bytes).context("invalid placement artifact")?;
    ensure!(
        artifact.schema_version == 2
            && artifact.kind == "private-unwritten-tree-placement"
            && artifact.occupancy_evidence_scope == "destination-window-v1"
            && artifact.per_move_retrieval_scope == "complete-file-mapping"
            && artifact.phase_bitmap_scope == "full-volume"
            && artifact.source_payload_writes == 0
            && artifact.counters.phase_bitmap_snapshots > 0
            && !artifact.moves.is_empty(),
        "unsupported placement schema, scope or empty evidence"
    );

    let mut domain = None;
    let mut declared_domain = None;
    let mut windows = 0u64;
    let mut queries = 0u64;
    let mut returned = 0u64;
    let mut moved_clusters = 0u64;
    let mut phases = BTreeMap::<String, u64>::new();
    for (index, row) in artifact.moves.iter().enumerate() {
        let movement = &row.proof;
        ensure!(
            movement.submitted_once
                && movement.before_valid_data_advance
                && movement.mapping_matches
                && movement.all_placements_match
                && movement.native_error.is_null(),
            "move {index} did not complete successfully"
        );
        ensure!(
            !row.phase.is_empty() && row.phase.len() <= 128,
            "move {index} has an invalid phase"
        );
        ensure!(
            movement.destination_bitmap.schema_version == 1
                && movement.destination_bitmap.scope == "destination-window-v1",
            "move {index} has unsupported destination proof"
        );
        let limits = destination_limits(movement.clusters)?;
        for (metadata, compact) in [
            (false, &movement.destination_bitmap.legacy),
            (true, &movement.destination_bitmap.metadata),
        ] {
            let observation = bitmap_window_transport::replay(compact, limits)
                .with_context(|| format!("move {index} selector {metadata} replay refused"))?;
            let proof = observation.proof();
            let mut template = vec![0; if metadata { 16 } else { 8 }];
            if metadata {
                template[8] = 1;
            }
            ensure!(
                proof.template == template
                    && proof.schema_version == 1
                    && proof.request.starting_lcn == movement.destination_lcn
                    && proof.request.clusters == u64::from(movement.clusters)
                    && !proof.whole_volume_complete
                    && proof.allocated_clusters == 0
                    && proof.window_bits.iter().all(|&byte| byte == 0),
                "move {index} selector, destination or free-window evidence differs"
            );
            ensure!(
                domain.is_none_or(|prior| prior == proof.request.volume_clusters)
                    && declared_domain.is_none_or(|prior| prior == proof.declared_volume_clusters),
                "move {index} volume domain differs between observations"
            );
            domain = Some(proof.request.volume_clusters);
            declared_domain = Some(proof.declared_volume_clusters);
            ensure!(
                movement
                    .starting_vcn
                    .checked_add(u64::from(movement.clusters))
                    .is_some(),
                "move {index} VCN bounds overflow"
            );
            let actual_returned = proof.queries.iter().try_fold(0u64, |sum, query| {
                sum.checked_add(query.bytes.len() as u64)
                    .context("query byte count overflow")
            })?;
            ensure!(
                actual_returned == proof.returned_bytes as u64,
                "move {index} native query byte count differs"
            );
            add(&mut windows, 1)?;
            add(&mut queries, proof.queries.len() as u64)?;
            add(&mut returned, actual_returned)?;
        }
        add(&mut moved_clusters, u64::from(movement.clusters))?;
        add(phases.entry(row.phase.clone()).or_default(), 1)?;
        let _ = row.object_index; // Identity labels are reported, never authority.
    }
    let volume_bytes = domain
        .context("missing window volume domain")?
        .checked_mul(4096)
        .context("window volume byte size overflow")?;
    let mut original_bytes = 0u64;
    for (index, range) in artifact.original_coordinate_ranges.iter().enumerate() {
        ensure!(
            range.length > 0
                && range.length.is_multiple_of(4096)
                && range.logical_offset.is_multiple_of(4096)
                && range.source_physical_offset.is_multiple_of(4096)
                && range.source_physical_offset == range.target_physical_offset
                && range.logical_offset.checked_add(range.length).is_some()
                && range
                    .source_physical_offset
                    .checked_add(range.length)
                    .is_some_and(|end| end <= volume_bytes),
            "original-coordinate range {index} differs or escapes volume"
        );
        add(&mut original_bytes, range.length)?;
        let _ = range.object_index;
    }
    ensure!(
        original_bytes == artifact.original_coordinate_bytes,
        "original-coordinate range bytes differ from artifact total"
    );
    let summary = json!({
        "schema_version":1,"kind":"closed-placement-window-replay","success":true,
        "input":args.input,"input_sha256":actual_sha,"input_bytes":bytes.len(),
        "placement_schema_version":artifact.schema_version,
        "occupancy_evidence_scope":artifact.occupancy_evidence_scope,
        "phase_bitmap_scope":artifact.phase_bitmap_scope,
        "phase_bitmap_snapshots":artifact.counters.phase_bitmap_snapshots,
        "per_move_retrieval_scope":artifact.per_move_retrieval_scope,
        "full_retrieval_evidence_replayed":false,
        "move_count":artifact.moves.len(),"window_count":windows,
        "native_query_count":queries,"native_returned_bytes":returned,
        "moved_clusters":moved_clusters,"volume_clusters":domain,
        "declared_volume_clusters":declared_domain,"moves_by_phase":phases,
        "original_coordinate_range_count":artifact.original_coordinate_ranges.len(),
        "original_coordinate_bytes":original_bytes,
        "all_window_transcripts_replayed":true,"all_destination_bits_free":true,
        "native_volume_queries":0,"native_moves_submitted":0,"source_write_requests":0,
        "new_volume_verification":false,"source_admission_authorized":false,
        "conversion_authorized":false,"conversion_qualified":false
    });
    let output_bytes = serde_json::to_vec_pretty(&summary)?;
    ensure!(
        output_bytes.len() <= OUTPUT_LIMIT,
        "replay summary exceeds output bound"
    );
    ordinary_path(&args.output, true)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(&args.output)?;
    ensure!(
        output.metadata()?.is_file() && output.metadata()?.file_attributes() & 0x400 == 0,
        "output is not an ordinary file"
    );
    output.write_all(&output_bytes)?;
    output.sync_all()?;
    println!(
        "Replayed {} moves / {windows} windows / {queries} native queries into {}",
        artifact.moves.len(),
        args.output.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Closed placement replay requires Windows ordinary-file handle checks")
}
