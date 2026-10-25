use ntfs2refs::{refs_allocator, refs_cow_overlay::RefsCowOverlay};

#[test]
#[ignore = "requires N2R_NATIVE_REFS_CORPUS and N2R_REFSNT_OVERLAY; read-only 52 GiB image views"]
fn native_medium_allocator_tracks_adopted_cluster_without_payload_copy() {
    let corpus = std::path::PathBuf::from(
        std::env::var_os("N2R_NATIVE_REFS_CORPUS").expect("explicit native corpus directory"),
    );
    let overlay = std::path::PathBuf::from(
        std::env::var_os("N2R_REFSNT_OVERLAY").expect("explicit isolated overlay"),
    );
    let base = corpus.join("devdrive.raw");
    let mut source = std::fs::File::open(&base).unwrap();
    assert_eq!(source.metadata().unwrap().len(), 55834574848);
    let before = refs_allocator::inspect_medium(&mut source, 55834574848).unwrap();
    assert_eq!(before.checkpoint_clock, 45);
    assert_eq!(before.rows.len(), 23);
    assert_eq!(before.free_clusters, 13384480);
    assert!(!before.medium_allocated(10243));
    let small_before = refs_allocator::inspect_small(&mut source, 55834574848).unwrap();
    assert_eq!(small_before.rows.len(), 2);
    assert_eq!(small_before.free_clusters, 16304);
    assert_eq!(small_before.allocated_clusters, 92);
    assert!(!small_before.allocated_ranges.iter().any(|range| {
        range.offset <= 10243 * 4096 && 10243 * 4096 < range.offset + range.length
    }));
    let mut changed = RefsCowOverlay::open(&base, &overlay).unwrap();
    assert!(!changed.writes_overlap(10243 * 4096, 4096).unwrap());
    let after = refs_allocator::inspect_medium(&mut changed, 55834574848).unwrap();
    assert_eq!(after.checkpoint_clock, 46);
    assert_eq!(after.rows.len(), 23);
    assert_eq!(after.free_clusters, before.free_clusters - 1);
    assert!(after.medium_allocated(10243));
    assert!(!after.whole_volume_ownership_verified);
    let small_after = refs_allocator::inspect_small(&mut changed, 55834574848).unwrap();
    assert_eq!(small_after.free_clusters, small_before.free_clusters);
    assert_eq!(
        small_after.allocated_clusters,
        small_before.allocated_clusters
    );
}
