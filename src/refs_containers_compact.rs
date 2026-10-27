//! Compact, actual-image container traversal for the experimental profile.
//! Only ID/address pairs survive leaf decoding. Digests cover all raw values
//! and every visited page; serialized receipts omit live address lookup data.
use super::*;

pub fn inspect_container_tables_compact<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    roots: &[ContainerRootTarget],
    protected_lcns: &BTreeSet<u64>,
) -> Result<ContainerTablesProbe> {
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_cluster == CLUSTER as u32
            && geometry.volume_bytes.is_multiple_of(CLUSTER),
        "unsupported compact container geometry"
    );
    ensure!(
        roots.len() <= 4 && protected_lcns.len() <= 128,
        "compact root or anchor budget exceeded"
    );
    let row_limit = (geometry.volume_bytes / (CPC * CLUSTER)).min(33_554_432);
    ensure!(row_limit > 0, "empty compact container domain");
    let limits = ContainerLimits {
        max_pages_per_tree: 1_048_576,
        max_total_pages: 4_194_304,
        max_rows_per_tree: row_limit as u32,
        max_depth: 8,
    };
    let mut identities = BTreeSet::new();
    let mut checkpoints = BTreeSet::new();
    for root in roots {
        ensure!(
            matches!(root.root_index, 7 | 8)
                && matches!(root.table_id, 11 | 12)
                && identities.insert((root.checkpoint_lcn, root.root_index)),
            "invalid compact container root identity"
        );
        ensure!(
            root.expected_sha256.len() == 64
                && root.expected_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid compact container root hash"
        );
        validate_slots(&root.lcn_slots, geometry.volume_bytes)?;
        checkpoints.insert(root.checkpoint_lcn);
    }
    ensure!(checkpoints.len() <= 2, "too many compact checkpoint pairs");
    let mut result = ContainerTablesProbe {
        profile: "candidate ReFS 3.14 compact container traversal v1".into(),
        limits,
        pages_read: 0,
        bytes_read: 0,
        trees: Vec::new(),
        failover_comparisons: Vec::new(),
        authoritative_checkpoint_selected: false,
        metadata_verified: false,
        allocation_verified: false,
        conversion_profile_qualified: false,
    };
    for root in roots {
        let mut tree = ContainerTreeObservation {
            checkpoint_lcn: root.checkpoint_lcn,
            root_index: root.root_index,
            table_id: root.table_id,
            root_lcn_slots: root.lcn_slots,
            expected_root_rows: None,
            root_count_matches: None,
            walk_finished: false,
            pages: Vec::new(),
            mappings: Vec::new(),
            compact: None,
            rejection: None,
        };
        match walk(
            reader,
            geometry,
            root,
            roots,
            protected_lcns,
            &mut tree,
            &mut result.pages_read,
            &mut result.bytes_read,
            limits,
        ) {
            Ok(index) => {
                tree.root_count_matches = Some(tree.expected_root_rows == Some(index.mapping_rows));
                tree.walk_finished = tree.root_count_matches == Some(true);
                if !tree.walk_finished {
                    tree.rejection = Some("compact container root count differs".into());
                }
                tree.compact = Some(index);
            }
            Err(error) if error.downcast_ref::<std::io::Error>().is_some() => return Err(error),
            Err(error) => tree.rejection = Some(error.to_string()),
        }
        result.trees.push(tree);
    }
    for checkpoint in checkpoints {
        let a = result
            .trees
            .iter()
            .find(|t| t.checkpoint_lcn == checkpoint && t.root_index == 7);
        let b = result
            .trees
            .iter()
            .find(|t| t.checkpoint_lcn == checkpoint && t.root_index == 8);
        let mut comparison = ContainerPairComparison {
            checkpoint_lcn: checkpoint,
            root_indices: [7, 8],
            both_walks_finished: false,
            both_root_counts_match: false,
            mapping_entries_equal: None,
            raw_values_equal: None,
            rejection: None,
        };
        if let (Some(a), Some(b)) = (a, b) {
            comparison.both_walks_finished = a.walk_finished && b.walk_finished;
            comparison.both_root_counts_match =
                a.root_count_matches == Some(true) && b.root_count_matches == Some(true);
            if a.table_id == b.table_id {
                comparison.rejection = Some("failover pair repeats table identity".into());
            } else if let (Some(x), Some(y)) = (&a.compact, &b.compact)
                && comparison.both_walks_finished
                && comparison.both_root_counts_match
            {
                comparison.mapping_entries_equal = Some(x.addresses == y.addresses);
                comparison.raw_values_equal = Some(x.mapping_sha256 == y.mapping_sha256);
            } else {
                comparison.rejection = Some("compact failover walk is incomplete".into());
            }
        } else {
            comparison.rejection = Some("compact failover root absent".into());
        }
        result.failover_comparisons.push(comparison);
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn walk<R: Read + Seek>(
    reader: &mut R,
    geometry: &RefsGeometry,
    root: &ContainerRootTarget,
    roots: &[ContainerRootTarget],
    protected: &BTreeSet<u64>,
    tree: &mut ContainerTreeObservation,
    total_pages: &mut u32,
    total_bytes: &mut u64,
    limits: ContainerLimits,
) -> Result<CompactTreeIndex> {
    let mut pending = vec![PendingPage {
        slots: root.lcn_slots,
        crc: root.expected_crc64,
        depth: 0,
        parent: None,
        row: None,
        expected_level: None,
    }];
    let mut visited = BTreeSet::new();
    let mut addresses: Vec<CompactAddress> = Vec::new();
    let mut pages = 0u32;
    let mut mapping_hash = Sha256::new();
    let mut transcript = Sha256::new();
    transcript.update(b"refs-container-compact-page-transcript-v1");
    while let Some(next) = pending.pop() {
        ensure!(
            pages < limits.max_pages_per_tree
                && *total_pages < limits.max_total_pages
                && next.depth <= limits.max_depth,
            "compact container traversal budget exhausted"
        );
        validate_slots(&next.slots, geometry.volume_bytes)?;
        for &lcn in &next.slots {
            ensure!(
                visited.insert(lcn),
                "compact container cycle or shared physical page"
            );
            if next.depth != 0 {
                ensure!(
                    !protected.contains(&lcn) && !roots.iter().any(|r| r.lcn_slots.contains(&lcn)),
                    "compact container child overlaps bootstrap or another root"
                );
            }
        }
        let bytes = read_page(reader, &next.slots)?;
        let page_index = pages as usize;
        pages += 1;
        *total_pages += 1;
        *total_bytes += PAGE as u64;
        let actual_crc = crc64_nvme(&bytes);
        let actual_hash = hex::encode(Sha256::digest(bytes));
        let header_matches = &bytes[..4] == b"MSB+"
            && u32le(&bytes, 4) == 2
            && u32le(&bytes, 8) == 0
            && u32le(&bytes, 0xc) == root.volume_signature
            && slots(&bytes[0x20..]) == next.slots
            && u64le(&bytes, 0x40) == 0
            && u64le(&bytes, 0x48) == root.table_id;
        for lcn in next.slots {
            transcript.update(lcn.to_le_bytes());
        }
        transcript.update([next.depth]);
        transcript.update(bytes);
        // Preserve completed-read receipts on structural refusal, including
        // a bad-CRC page. This rejected prefix has no live lookup binding.
        tree.compact = Some(CompactTreeIndex {
            encoding: "refs-container-compact-partial-v1".into(),
            mapping_rows: addresses.len() as u64,
            pages_read: pages,
            bytes_read: u64::from(pages) * PAGE as u64,
            mapping_sha256: hex::encode(mapping_hash.clone().finalize()),
            page_transcript_sha256: hex::encode(transcript.clone().finalize()),
            addresses: Vec::new(),
            binding: None,
        });
        if next.depth == 0 {
            tree.pages.push(ContainerPageObservation {
                lcn_slots: next.slots,
                depth: 0,
                parent_page_index: None,
                parent_row_index: None,
                sha256: actual_hash.clone(),
                stored_crc64: format!("{:016x}", next.crc),
                computed_crc64: format!("{actual_crc:016x}"),
                checksum_matches: actual_crc == next.crc,
                header_matches,
                node_level: None,
                row_count: None,
                rejection: None,
            });
            ensure!(
                actual_hash == root.expected_sha256,
                "compact container root hash changed"
            );
        }
        ensure!(
            actual_crc == next.crc && header_matches,
            "compact container page CRC or header differs at {:?}; expected {:016x}, observed {:016x}",
            next.slots,
            next.crc,
            actual_crc
        );
        let (level, rows) = if next.depth == 0 {
            let node = refs_node::inspect_root_node(&bytes)?;
            ensure!(
                node.table_id_low == root.table_id
                    && node.node_level <= limits.max_depth
                    && node.whole_table_row_count <= u64::from(limits.max_rows_per_tree),
                "compact container root row budget or identity differs"
            );
            tree.expected_root_rows = Some(node.whole_table_row_count);
            addresses
                .try_reserve_exact(node.whole_table_row_count as usize)
                .context("compact container index storage unavailable")?;
            tree.pages[0].node_level = Some(node.node_level);
            tree.pages[0].row_count = Some(node.rows.len() as u32);
            (node.node_level, node.rows)
        } else {
            let node = refs_node::inspect_container_child_node(&bytes)?;
            ensure!(
                Some(node.node_level) == next.expected_level,
                "compact container child level differs from parent"
            );
            (node.node_level, node.rows)
        };
        if level != 0 {
            ensure!(
                next.depth < limits.max_depth
                    && !rows.is_empty()
                    && pages as usize + pending.len() + rows.len()
                        <= limits.max_pages_per_tree as usize,
                "compact container pending-page or depth budget exhausted"
            );
            for row in rows.iter().rev() {
                pending.push(child_reference(row, page_index, level, next.depth)?);
            }
        } else {
            ensure!(
                addresses.len() + rows.len() <= limits.max_rows_per_tree as usize
                    && addresses.len() as u64 + rows.len() as u64
                        <= tree.expected_root_rows.unwrap(),
                "compact container leaf count exceeds root or resource budget"
            );
            for row in rows {
                let mapping = leaf_mapping(&row, page_index, geometry.volume_bytes / CLUSTER)?;
                ensure!(
                    addresses
                        .last()
                        .is_none_or(|p| p.container_id < mapping.container_id),
                    "duplicate or unsorted compact container key"
                );
                mapping_hash.update(mapping.container_id.to_le_bytes());
                mapping_hash.update(mapping.physical_start_lcn.to_le_bytes());
                mapping_hash.update(mapping.clusters_per_container.to_le_bytes());
                mapping_hash.update(mapping.value_bytes_hex.bytes()?);
                addresses.push(CompactAddress {
                    container_id: mapping.container_id,
                    physical_start_lcn: mapping.physical_start_lcn,
                });
            }
        }
        if let Some(partial) = tree.compact.as_mut() {
            partial.mapping_rows = addresses.len() as u64;
            partial.mapping_sha256 = hex::encode(mapping_hash.clone().finalize());
        }
    }
    ensure!(
        Some(addresses.len() as u64) == tree.expected_root_rows,
        "compact container root count is incomplete"
    );
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(addresses.len())
        .context("compact container overlap storage unavailable")?;
    physical.extend(addresses.iter().map(|r| r.physical_start_lcn));
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|p| p[0] + CPC <= p[1]),
        "compact container physical extents overlap"
    );
    Ok(CompactTreeIndex {
        encoding: "refs-container-compact-index-v1".into(),
        mapping_rows: addresses.len() as u64,
        pages_read: pages,
        bytes_read: u64::from(pages) * PAGE as u64,
        mapping_sha256: hex::encode(mapping_hash.finalize()),
        page_transcript_sha256: hex::encode(transcript.finalize()),
        addresses,
        binding: Some(CompactBinding {
            checkpoint_lcn: root.checkpoint_lcn,
            root_index: root.root_index,
            table_id: root.table_id,
            root_slots: root.lcn_slots,
            root_sha256: root.expected_sha256.clone(),
            volume_clusters: geometry.volume_bytes / CLUSTER,
        }),
    })
}
