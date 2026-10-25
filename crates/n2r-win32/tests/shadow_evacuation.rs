use n2r_win32::bitmap_layout;
#[path = "../src/shadow_evacuation.rs"]
mod shadow_evacuation;
use shadow_evacuation::{Extent, Limits, plan};
const C: u64 = 4096;
fn bitmap(clusters: u64, occupied: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0; 16 + clusters.div_ceil(8) as usize];
    bytes[8..16].copy_from_slice(&clusters.to_le_bytes());
    for cluster in occupied {
        bytes[16 + (*cluster / 8) as usize] |= 1 << (*cluster % 8);
    }
    bytes
}
fn extent(file: u32, logical: u64, physical: u64, count: u64) -> Extent {
    Extent {
        file_index: file,
        logical_offset: logical * C,
        physical_offset: physical * C,
        length: count * C,
    }
}

#[test]
fn moves_only_obstructing_shadow_data_and_excludes_every_source_destination() {
    let source = [extent(0, 0, 10, 4), extent(1, 0, 2, 2)];
    let owned = [extent(7, 8, 8, 8)];
    let legacy = bitmap(32, &[0, 8, 9, 10, 11, 12, 13, 14, 15]);
    let metadata = bitmap(32, &[1, 8, 9, 10, 11, 12, 13, 14, 15]);
    let result = plan(
        &legacy,
        &metadata,
        &source,
        &owned,
        32 * C,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(result.evacuated_bytes, 4 * C);
    assert_eq!(result.moves.len(), 1);
    let moved = result.moves[0];
    assert_eq!(
        (
            moved.file_index,
            moved.starting_vcn,
            moved.source_offset / C,
            moved.destination_lcn,
            moved.clusters
        ),
        (7, 10, 10, 4, 4)
    );
    assert_eq!(moved.logical_offset, 10 * C);
    assert_eq!(moved.length, 4 * C);
}

#[test]
fn fragmented_free_space_is_reserved_once_and_logical_offsets_advance() {
    let source = [extent(0, 0, 10, 4)];
    let owned = [extent(7, 20, 10, 4)];
    let legacy = bitmap(
        24,
        &[
            1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23,
        ],
    );
    let result = plan(&legacy, &legacy, &source, &owned, 24 * C, Limits::default()).unwrap();
    assert_eq!(
        result
            .moves
            .iter()
            .map(|m| (
                m.starting_vcn,
                m.source_offset / C,
                m.destination_lcn,
                m.clusters
            ))
            .collect::<Vec<_>>(),
        [(20, 10, 0, 1), (21, 11, 2, 2), (23, 13, 14, 1)]
    );
}

#[test]
fn already_correct_file_and_vcn_placement_stays_in_place() {
    let source = [extent(0, 10, 10, 4)];
    let owned = [extent(0, 10, 10, 2), extent(0, 30, 12, 2)];
    let bits = bitmap(32, &[10, 11, 12, 13]);
    let result = plan(&bits, &bits, &source, &owned, 32 * C, Limits::default()).unwrap();
    assert_eq!(result.already_in_place_bytes, 2 * C);
    assert_eq!(result.evacuated_bytes, 2 * C);
    assert_eq!(result.moves.len(), 1);
    assert_eq!(result.moves[0].starting_vcn, 30);
}

#[test]
fn metadata_only_blockage_never_becomes_a_user_move() {
    let source = [extent(0, 0, 10, 4)];
    let owned = [extent(0, 0, 20, 4)];
    let legacy = bitmap(32, &[20, 21, 22, 23]);
    let metadata = bitmap(32, &[10, 11, 12, 13, 20, 21, 22, 23]);
    let result = plan(
        &legacy,
        &metadata,
        &source,
        &owned,
        32 * C,
        Limits::default(),
    )
    .unwrap();
    assert!(result.moves.is_empty());
    assert_eq!(result.evacuated_bytes, 0);
    assert_eq!(result.scanned_clusters, 0);
}

#[test]
fn incomplete_domains_unallocated_ownership_aliases_and_overflows_fail() {
    let source = [extent(0, 0, 10, 4)];
    let owned = [extent(7, 0, 10, 4)];
    let bits = bitmap(32, &[10, 11, 12, 13]);
    for bad in [
        bitmap(31, &[10, 11, 12, 13]),
        bits[..bits.len() - 1].to_vec(),
        {
            let mut b = bits.clone();
            b[0] = 1;
            b
        },
    ] {
        assert!(plan(&bits, &bad, &source, &owned, 32 * C, Limits::default()).is_err());
    }
    assert!(
        plan(
            &bits,
            &bitmap(32, &[]),
            &source,
            &owned,
            32 * C,
            Limits::default()
        )
        .is_err()
    );
    for bad in [
        vec![source[0], source[0]],
        vec![extent(0, 0, 10, 2), extent(0, 1, 20, 2)],
        vec![Extent {
            length: C + 1,
            ..source[0]
        }],
        vec![Extent {
            logical_offset: u64::MAX - (C - 1),
            ..source[0]
        }],
        vec![Extent {
            physical_offset: u64::MAX - (C - 1),
            ..source[0]
        }],
        vec![extent(0, 0, 31, 2)],
    ] {
        assert!(plan(&bits, &bits, &bad, &owned, 32 * C, Limits::default()).is_err());
    }
}

#[test]
fn resource_and_space_exhaustion_return_no_partial_plan() {
    let source = [extent(0, 0, 10, 4)];
    let owned = [extent(7, 0, 10, 4)];
    let bits = bitmap(
        24,
        &[
            1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23,
        ],
    );
    for limits in [
        Limits {
            max_moves: 1,
            ..Limits::default()
        },
        Limits {
            max_scan_clusters: 1,
            ..Limits::default()
        },
        Limits {
            max_evacuation_bytes: C,
            ..Limits::default()
        },
        Limits {
            max_moves: 0,
            ..Limits::default()
        },
    ] {
        assert!(plan(&bits, &bits, &source, &owned, 24 * C, limits).is_err());
    }
    let full = bitmap(24, &(0..24).collect::<Vec<_>>());
    assert!(plan(&full, &full, &source, &owned, 24 * C, Limits::default()).is_err());
}
