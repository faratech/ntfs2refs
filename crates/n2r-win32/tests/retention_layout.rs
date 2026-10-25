use n2r_win32::retention_layout::{self, SourceRun, plan_free_subruns};

const C: u64 = 4096;
fn bitmap(clusters: u64, occupied: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0; 16 + clusters.div_ceil(8) as usize];
    bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
    for cluster in occupied {
        bytes[16 + (*cluster / 8) as usize] |= 1 << (*cluster % 8);
    }
    bytes
}
fn source() -> SourceRun {
    SourceRun {
        logical_offset: 16 * C,
        physical_offset: 8 * C,
        length: 16 * C,
    }
}

#[test]
fn splits_natural_run_at_union_of_metadata_and_legacy_collisions() {
    let legacy = bitmap(64, &[10, 20]);
    let metadata = bitmap(64, &[12, 13, 20]);
    let plan = plan_free_subruns(&legacy, &metadata, source(), 64 * C, 16).unwrap();
    assert_eq!(plan.free_bytes, 12 * C);
    assert_eq!(plan.blocked_bytes, 4 * C);
    assert_eq!(
        plan.subruns
            .iter()
            .map(|r| (r.starting_vcn, r.destination_lcn, r.clusters))
            .collect::<Vec<_>>(),
        [(16, 8, 2), (19, 11, 1), (22, 14, 6), (29, 21, 3)]
    );
    assert_ne!(plan.legacy_bitmap_sha256, plan.metadata_bitmap_sha256);
    for run in &plan.subruns {
        assert_eq!(run.logical_offset / C, run.starting_vcn);
        assert_eq!(run.physical_offset / C, run.destination_lcn);
        assert_eq!(run.length / C, u64::from(run.clusters));
    }
}

#[test]
fn preserves_maximal_full_run_and_empty_result_without_dummy_candidates() {
    let clear = bitmap(64, &[]);
    let full = plan_free_subruns(&clear, &clear, source(), 64 * C, 1).unwrap();
    assert_eq!(full.subruns.len(), 1);
    assert_eq!(full.subruns[0].length, 16 * C);
    let occupied = bitmap(64, &(8..24).collect::<Vec<_>>());
    let none = plan_free_subruns(&clear, &occupied, source(), 64 * C, 1).unwrap();
    assert!(none.subruns.is_empty());
    assert_eq!(none.free_bytes, 0);
    assert_eq!(none.blocked_bytes, 16 * C);
}

#[test]
fn incomplete_or_conflicting_domains_never_supply_partial_retention() {
    let clear = bitmap(64, &[]);
    for bad in [
        bitmap(63, &[]),
        bitmap(65, &[]),
        clear[..clear.len() - 1].to_vec(),
        {
            let mut b = clear.clone();
            b[0] = 1;
            b
        },
        {
            let mut b = clear.clone();
            b[8..16].copy_from_slice(&(-1i64).to_le_bytes());
            b
        },
    ] {
        assert!(plan_free_subruns(&clear, &bad, source(), 64 * C, 16).is_err());
        assert!(plan_free_subruns(&bad, &clear, source(), 64 * C, 16).is_err());
    }
}

#[test]
fn rejects_overflow_unaligned_ranges_u32_counts_and_exhausted_budget() {
    let clear = bitmap(64, &[]);
    let occupied = bitmap(64, &[10, 12, 13, 20]);
    assert!(plan_free_subruns(&clear, &occupied, source(), 64 * C, 3).is_err());
    for budget in [0, retention_layout::MAX_SUBRUNS + 1] {
        assert!(plan_free_subruns(&clear, &clear, source(), 64 * C, budget).is_err());
    }
    for run in [
        SourceRun {
            logical_offset: 1,
            ..source()
        },
        SourceRun {
            physical_offset: 1,
            ..source()
        },
        SourceRun {
            length: 0,
            ..source()
        },
        SourceRun {
            length: C + 1,
            ..source()
        },
        SourceRun {
            logical_offset: u64::MAX - (C - 1),
            length: C,
            ..source()
        },
        SourceRun {
            physical_offset: u64::MAX - (C - 1),
            length: C,
            ..source()
        },
        SourceRun {
            physical_offset: 63 * C,
            length: 2 * C,
            ..source()
        },
    ] {
        assert!(plan_free_subruns(&clear, &clear, run, 64 * C, 16).is_err());
    }
    let huge = SourceRun {
        logical_offset: 0,
        physical_offset: 0,
        length: (u64::from(u32::MAX) + 1) * C,
    };
    assert!(
        plan_free_subruns(&clear, &clear, huge, 64 * C, 16)
            .unwrap_err()
            .to_string()
            .contains("u32")
    );
}
