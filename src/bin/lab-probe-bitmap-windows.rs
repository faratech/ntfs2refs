//! Read-only D1 research. Compares scoped bitmap windows with complete native
//! maps; never changes production placement, exclusion, or recovery policy.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{bitmap_streaming, bitmap_window, bitmap_window_native, discovery, layout};
    use serde::Serialize;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const PARTITION_BYTES: u64 = 52 * 1024 * 1024 * 1024;
    const REPORT_LIMIT: usize = 16 * 1024 * 1024;
    const METADATA_RESERVE: usize = 1024 * 1024;
    const PAYLOAD_LCN: u64 = 3_145_728;

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        probe_id: String,
        #[arg(long)]
        acknowledge_readonly_data_volume: bool,
    }

    fn output_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute() && path.extension().is_some_and(|v| v == "json"),
            "fresh absolute C: JSON output required"
        );
        for part in path.components() {
            match part {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    "report must stay on C: metadata storage"
                ),
                Component::RootDir => (),
                Component::Normal(value) => ensure!(
                    n2r_win32::shadow_names::valid_unicode_component(
                        value.to_str().context("Unicode metadata path required")?
                    ),
                    "invalid metadata path component"
                ),
                _ => anyhow::bail!("report path traversal refused"),
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
                "ordinary metadata ancestry required"
            );
        }
        ensure!(!path.try_exists()?, "report already exists");
        Ok(())
    }

    fn enrolled() -> Result<discovery::VolumeDiscovery> {
        let source = discovery::discover(r"H:\", discovery::Role::Shadow)?;
        let identity = &source.binding.identity;
        ensure!(
            source.binding.disk_number == 6
                && layout::guid_bytes(&identity.disk_guid)?
                    == layout::guid_bytes("f95141cb-fe7e-439a-a82b-c2b3f55965d2")?
                && layout::guid_bytes(&identity.partition_guid)?
                    == layout::guid_bytes("f77d3d8f-9a87-464d-a7de-e1b77604da7b")?
                && identity.partition_number == 2
                && identity.partition_offset == 32 * 1024 * 1024
                && identity.partition_bytes == PARTITION_BYTES
                && identity.disk_bytes == 56 * 1024 * 1024 * 1024
                && identity.logical_sector_bytes == 512
                && identity.physical_sector_bytes == 4096
                && !source.disk_is_windows_disk
                && source.read_only
                && source.source_write_requests == 0
                && source.observed_twice_unchanged
                && source.filesystem == "ReFS"
                && source.label == "n2r-links-source"
                && source.bytes_per_sector == 512
                && source.sectors_per_cluster == 8,
            "exact enrolled disk-6 ReFS H: data volume required"
        );
        Ok(source)
    }

    fn retain<T: Serialize>(value: &T, retained: &mut usize) -> Result<Value> {
        let bytes = serde_json::to_vec(value)?;
        let total = retained
            .checked_add(bytes.len())
            .context("report budget overflow")?;
        ensure!(
            total <= REPORT_LIMIT - METADATA_RESERVE,
            "bounded bitmap probe evidence exhausted before retaining another observation"
        );
        *retained = total;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn full_bits(
        summary: &bitmap_streaming::Summary,
        request: bitmap_window::Request,
    ) -> Result<Vec<u8>> {
        ensure!(
            summary.cluster_count == request.volume_clusters,
            "full/window volume domains differ"
        );
        let end = request
            .starting_lcn
            .checked_add(request.clusters)
            .filter(|end| *end <= request.volume_clusters)
            .context("comparison window escapes domain")?;
        let mut bits = vec![0; usize::try_from(request.clusters.div_ceil(8))?];
        // Sweep only overlapping occupied intervals. Each canonical requested
        // bit is represented, including free bits and final-byte padding.
        let first = summary
            .allocated_ranges
            .partition_point(|range| range.starting_lcn + range.clusters <= request.starting_lcn);
        for range in summary.allocated_ranges[first..]
            .iter()
            .take_while(|range| range.starting_lcn < end)
        {
            let stop = range
                .starting_lcn
                .checked_add(range.clusters)
                .context("full map range overflow")?
                .min(end);
            for cluster in range.starting_lcn.max(request.starting_lcn)..stop {
                let relative = cluster - request.starting_lcn;
                bits[(relative / 8) as usize] |= 1u8 << (relative % 8);
            }
        }
        Ok(bits)
    }

    fn free_cluster_from(summary: &bitmap_streaming::Summary, start: u64) -> Result<u64> {
        ensure!(
            start < summary.cluster_count,
            "free-cluster search starts outside volume"
        );
        let first = summary
            .allocated_ranges
            .partition_point(|range| range.starting_lcn + range.clusters <= start);
        let mut candidate = start;
        for range in &summary.allocated_ranges[first..] {
            if range.starting_lcn > candidate {
                break;
            }
            candidate = range
                .starting_lcn
                .checked_add(range.clusters)
                .context("free-cluster search range overflow")?;
        }
        ensure!(
            candidate < summary.cluster_count,
            "no free cluster after search anchor"
        );
        Ok(candidate)
    }

    fn full_capture(
        volume: &File,
        clusters: u64,
        template: &[u8],
    ) -> Result<(bitmap_streaming::Summary, u64)> {
        let limits = bitmap_streaming::source_limits(clusters)?;
        let start = Instant::now();
        let summary = bitmap_streaming::capture(volume, clusters, template, limits, |_| Ok(()))?;
        let elapsed = u64::try_from(start.elapsed().as_micros())?;
        summary.validate(clusters, limits)?;
        ensure!(
            summary.declared_clusters == clusters,
            "full map declared domain differs"
        );
        Ok((summary, elapsed))
    }

    let args = Args::parse();
    ensure!(
        args.acknowledge_readonly_data_volume
            && std::env::var("COMPUTERNAME").as_deref() == Ok("N2R-WIN11")
            && args.probe_id.len() == 32
            && args
                .probe_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "explicit enrolled-guest acknowledgement and lowercase 32-character probe ID required"
    );
    output_path(&args.output)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    let limits = bitmap_window::Limits {
        max_window_bytes: 1024 * 1024,
        max_pages: 32,
        max_returned_bytes: 256 * 1024,
        page_bytes: 16 + 64 * 1024,
    };
    let mut report = json!({"schema_version":1,"kind":"native-bitmap-window-probe",
        "probe_id":args.probe_id,"success":false,"source_write_requests":0,
        "read_only_volume_handles":true,"volume_frozen":false,"source_frozen":false,
        "locks_or_disk_attribute_changes":0,"conversion_authorized":false,
        "production_d1_enabled":false,"conversion_qualified":false,
        "started_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        "window_limits":{"max_window_bytes":limits.max_window_bytes,"max_pages":limits.max_pages,
        "max_returned_bytes":limits.max_returned_bytes,"page_bytes":limits.page_bytes,
        "initial_page_bytes":4096},"selectors":[]});
    let mut phase = "discovery";
    let mut retained = 0usize;
    let attempted = (|| -> Result<()> {
        let before = enrolled()?;
        let volume = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(before.volume_guid_path.trim_end_matches('\\'))?;
        bitmap_window_native::verify_route(&volume, &before.binding)?;
        let clusters = bitmap_window_native::refs_314_clusters(&volume, &before.binding)?;
        ensure!(
            clusters == PARTITION_BYTES / 4096,
            "held ReFS 3.14 cluster domain differs"
        );
        report["discovery_before"] = retain(&before, &mut retained)?;
        report["volume_clusters"] = clusters.into();
        report["refs_profile"] =
            json!({"major":3,"minor":14,"sector_bytes":512,"cluster_bytes":4096});
        let cases = [
            ("allocated_payload", PAYLOAD_LCN, 1, Some(1u64)),
            ("adjacent_free", PAYLOAD_LCN + 1, 1, Some(0)),
            ("unaligned_start", PAYLOAD_LCN + 3, 37, None),
            ("mixed_range", PAYLOAD_LCN, 2050, None),
            ("near_zero", 0, 65, None),
            (
                "volume_tail",
                clusters.checked_sub(19).context("short volume")?,
                19,
                None,
            ),
            ("paginated", PAYLOAD_LCN, 65_537, None),
        ];
        for metadata in [false, true] {
            let mut template = vec![0; if metadata { 16 } else { 8 }];
            if metadata {
                template[8] = 1;
            }
            let name = if metadata {
                "metadata_inclusive"
            } else {
                "legacy"
            };
            let selectors = report["selectors"].as_array_mut().unwrap();
            let index = selectors.len();
            selectors
                .push(json!({"selector":name,"template":template,"windows":[],"success":false}));
            bitmap_window_native::verify_route(&volume, &before.binding)?;
            phase = "full-bitmap-before";
            let (full_before, micros) = full_capture(&volume, clusters, &template)?;
            report["selectors"][index]["full_before"] = retain(
                &json!({"elapsed_microseconds":micros,"summary":full_before}),
                &mut retained,
            )?;
            let mut windows = Vec::new();
            for (case, starting_lcn, count, expected_allocated) in cases {
                let starting_lcn = if case == "adjacent_free" {
                    free_cluster_from(&full_before, starting_lcn)?
                } else {
                    starting_lcn
                };
                phase = "native-window";
                let request = bitmap_window::Request {
                    volume_clusters: clusters,
                    starting_lcn,
                    clusters: count,
                };
                let start = Instant::now();
                let observation =
                    bitmap_window_native::capture(&volume, request, &template, limits)?;
                let elapsed = u64::try_from(start.elapsed().as_micros())?;
                let proof = observation.into_proof();
                phase = "window-proof-replay";
                let start = Instant::now();
                let replayed = bitmap_window::replay(&proof, limits)?;
                let replay_micros = u64::try_from(start.elapsed().as_micros())?;
                ensure!(
                    replayed.proof() == &proof && !proof.whole_volume_complete,
                    "window replay differs or claims full-volume coverage"
                );
                let expected = full_bits(&full_before, request)?;
                let matches_before = expected == proof.window_bits;
                let expected_case_matches =
                    expected_allocated.is_none_or(|value| proof.allocated_clusters == value);
                let paginated = case != "paginated" || proof.queries.len() >= 2;
                let row = json!({"case":case,"request":request,"elapsed_microseconds":elapsed,
                    "replay_microseconds":replay_micros,"returned_bytes":proof.returned_bytes,
                    "pages":proof.queries.len(),"allocated_clusters":proof.allocated_clusters,
                    "expected_case_allocated_clusters":expected_allocated,"case_matches":expected_case_matches,
                    "pagination_exercised":proof.queries.len()>=2,"proof_replay_exact":true,
                    "all_requested_bits_match_full_before":matches_before,
                    "all_requested_bits_match_full_after":false,"full_after_comparison_pending":true,
                    "proof":proof});
                let row = retain(&row, &mut retained)?;
                report["selectors"][index]["windows"]
                    .as_array_mut()
                    .unwrap()
                    .push(row);
                ensure!(
                    matches_before,
                    "native window differs from full before map at {case}"
                );
                ensure!(
                    expected_case_matches,
                    "named allocated/free probe case differs at {case}"
                );
                ensure!(
                    paginated,
                    "large requested window did not exercise pagination"
                );
                windows.push((request, proof.window_bits));
            }
            phase = "full-bitmap-after";
            let (full_after, micros) = full_capture(&volume, clusters, &template)?;
            report["selectors"][index]["full_after"] = retain(
                &json!({"elapsed_microseconds":micros,"summary":full_after}),
                &mut retained,
            )?;
            phase = "compare-every-requested-bit";
            for (window_index, (request, bits)) in windows.iter().enumerate() {
                let matches = full_bits(&full_after, *request)? == *bits;
                report["selectors"][index]["windows"][window_index]["all_requested_bits_match_full_after"] =
                    matches.into();
                report["selectors"][index]["windows"][window_index]["full_after_comparison_pending"] =
                    false.into();
                ensure!(
                    matches,
                    "requested bitmap bits changed or differ after window {window_index}"
                );
            }
            bitmap_window_native::verify_route(&volume, &before.binding)?;
            report["selectors"][index]["full_maps_identical"] = (full_before == full_after).into();
            report["selectors"][index]["success"] = true.into();
        }
        phase = "final-route-and-discovery";
        bitmap_window_native::verify_route(&volume, &before.binding)?;
        ensure!(
            bitmap_window_native::refs_314_clusters(&volume, &before.binding)? == clusters,
            "held ReFS geometry changed during probe"
        );
        let after = enrolled()?;
        report["discovery_after"] = retain(&after, &mut retained)?;
        ensure!(
            before.binding == after.binding
                && before.volume_guid_path == after.volume_guid_path
                && before.evidence == after.evidence
                && before.windows_disk_number == after.windows_disk_number
                && before.volume_serial_low32 == after.volume_serial_low32,
            "enrolled volume or Windows disk route changed during probe"
        );
        bitmap_window_native::verify_route(&volume, &before.binding)?;
        report["all_requested_bits_compared_before_and_after"] = true.into();
        report["route_revalidated"] = true.into();
        Ok(())
    })();
    report["retained_evidence_bytes"] = retained.into();
    if let Err(error) = &attempted {
        report["error"] = format!("{error:#}").into();
        report["failed_phase"] = phase.into();
        report["partial_observations_retained"] = true.into();
    } else {
        report["success"] = true.into();
    }
    let bytes = serde_json::to_vec(&report)?;
    ensure!(
        bytes.len() <= REPORT_LIMIT,
        "bitmap probe report exceeds sixteen MiB"
    );
    let digest = hex::encode(Sha256::digest(&bytes));
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        json!({"success":attempted.is_ok(),"report":args.output,
        "report_bytes":bytes.len(),"report_sha256":digest,"conversion_authorized":false})
    );
    attempted
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Read-only bitmap-window probe requires the enrolled Windows guest");
    std::process::exit(2);
}
