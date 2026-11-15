use ntfs2refs::ntfs_allocation::*;

fn interval(record: u64, lcn: u64, clusters: u64) -> PhysicalInterval {
    PhysicalInterval {
        owner: AttributeKey {
            record_number: record,
            sequence_number: 1,
            type_code: 0x80,
            name_utf16: vec![],
            instance: 0,
        },
        vcn_start: 0,
        lcn_start: lcn,
        clusters,
    }
}
fn bitmap(domain: u64, claims: &[PhysicalInterval]) -> Vec<u8> {
    let mut bytes = vec![0; domain.div_ceil(8) as usize];
    for span in claims {
        for c in span.lcn_start..span.lcn_start + span.clusters {
            bytes[(c / 8) as usize] |= 1 << (c % 8);
        }
    }
    bytes
}
fn consistent(result: Assessment) -> Consistency {
    assert!(!result.grants_write_authority());
    match result {
        Assessment::Consistent(s) => s,
        other => panic!("{other:?}"),
    }
}
fn rejected(result: Assessment) -> Refusal {
    assert!(!result.grants_write_authority());
    match result {
        Assessment::Rejected(r) => r,
        other => panic!("{other:?}"),
    }
}

#[test]
fn accounts_system_and_user_attributes_without_mutating_inputs() {
    let claims = vec![
        interval(16, 22, 2),
        interval(0, 4, 5),
        interval(7, 0, 4),
        interval(6, 10, 1),
    ];
    let bits = bitmap(24, &claims);
    let old_claims = claims.clone();
    let old_bits = bits.clone();
    let s = consistent(assess(24, &bits, &claims, Limits::default()));
    assert_eq!(
        (s.allocated_clusters, s.free_clusters, s.distinct_attributes),
        (12, 12, 4)
    );
    assert_eq!((s.cluster_checks, s.bitmap_bytes_checked), (24, 3));
    assert_eq!(claims, old_claims);
    assert_eq!(bits, old_bits);
}
#[test]
fn fragments_may_run_backwards_physically_and_have_vcn_holes() {
    let mut a = interval(20, 10, 2);
    a.vcn_start = 0;
    let mut b = interval(20, 2, 2);
    b.vcn_start = 4;
    let claims = vec![a, b];
    let s = consistent(assess(16, &bitmap(16, &claims), &claims, Limits::default()));
    assert_eq!(s.distinct_attributes, 1); // Physical ownership does not establish logical completeness.
}
#[test]
fn adjacent_intervals_and_end_of_domain_are_allowed() {
    let claims = vec![interval(20, 0, 4), interval(21, 4, 4)];
    assert_eq!(
        consistent(assess(8, &[255], &claims, Limits::default())).free_clusters,
        0
    );
}
#[test]
fn cross_file_overlap_is_rejected_before_bitmap_scan() {
    let claims = vec![interval(20, 2, 4), interval(21, 4, 1)];
    assert_eq!(
        rejected(assess(8, &[0], &claims, Limits::default())),
        Refusal::PhysicalOverlap {
            first: 0,
            second: 1,
            lcn: 4
        }
    );
}
#[test]
fn metadata_user_overlap_is_not_exempt() {
    let claims = vec![interval(0, 2, 4), interval(20, 2, 4)];
    assert!(matches!(
        rejected(assess(8, &[255], &claims, Limits::default())),
        Refusal::PhysicalOverlap { .. }
    ));
}
#[test]
fn same_owner_duplicate_or_aliased_physical_ranges_are_rejected() {
    let a = interval(20, 2, 2);
    let mut b = a.clone();
    b.vcn_start = 2;
    assert!(matches!(
        rejected(assess(8, &[12], &[a.clone(), b], Limits::default())),
        Refusal::PhysicalOverlap { .. }
    ));
    assert!(matches!(
        rejected(assess(8, &[12], &[a.clone(), a], Limits::default())),
        Refusal::VcnOverlap { .. }
    ));
}
#[test]
fn overlapping_vcns_are_rejected_even_on_distinct_physical_storage() {
    let a = interval(20, 0, 2);
    let mut b = interval(20, 4, 2);
    b.vcn_start = 1;
    assert!(matches!(
        rejected(assess(8, &[51], &[a, b], Limits::default())),
        Refusal::VcnOverlap { .. }
    ));
}
#[test]
fn distinct_attribute_names_types_instances_and_records_keep_separate_vcns() {
    for dimension in 0..5 {
        let a = interval(20, 0, 1);
        let mut b = interval(20, 1, 1);
        match dimension {
            0 => b.owner.record_number += 1,
            1 => b.owner.sequence_number += 1,
            2 => b.owner.type_code = 0xa0,
            3 => b.owner.name_utf16 = vec![0xd800],
            _ => b.owner.instance = 1,
        }
        assert_eq!(
            consistent(assess(8, &[3], &[a, b], Limits::default())).distinct_attributes,
            2
        );
    } // Name/sequence authenticity and Unicode semantics are upstream obligations.
}
#[test]
fn claimed_free_and_unowned_allocated_clusters_are_precise() {
    assert_eq!(
        rejected(assess(8, &[0], &[interval(20, 3, 1)], Limits::default())),
        Refusal::ClaimedFree { input: 0, lcn: 3 }
    );
    assert_eq!(
        rejected(assess(8, &[128], &[], Limits::default())),
        Refusal::AllocatedUnowned { lcn: 7 }
    );
}
#[test]
fn a_missing_metadata_owner_is_not_a_reservation() {
    assert_eq!(
        rejected(assess(8, &[1], &[], Limits::default())),
        Refusal::AllocatedUnowned { lcn: 0 }
    );
}
#[test]
fn tail_bits_are_outside_the_explicit_cluster_domain() {
    let a = interval(20, 0, 1);
    let s = consistent(assess(9, &[1, 254], &[a], Limits::default()));
    assert_eq!(
        (s.allocated_clusters, s.free_clusters, s.padding_bits_set),
        (1, 8, 7)
    );
    assert!(matches!(
        rejected(assess(
            9,
            &[0, 254],
            &[interval(20, 9, 1)],
            Limits::default()
        )),
        Refusal::OutsideDomain { .. }
    ));
}
#[test]
fn exact_bitmap_byte_domain_is_required() {
    assert_eq!(
        rejected(assess(9, &[0], &[], Limits::default())),
        Refusal::BitmapLength {
            expected: 2,
            actual: 1
        }
    );
    assert_eq!(
        rejected(assess(8, &[0, 0], &[], Limits::default())),
        Refusal::BitmapLength {
            expected: 1,
            actual: 2
        }
    );
    assert_eq!(
        rejected(assess(0, &[], &[], Limits::default())),
        Refusal::EmptyDomain
    );
}
#[test]
fn invalid_interval_sizes_boundaries_and_overflow_are_refused() {
    assert_eq!(
        rejected(assess(8, &[0], &[interval(20, 0, 0)], Limits::default())),
        Refusal::EmptyInterval { input: 0 }
    );
    assert_eq!(
        rejected(assess(8, &[0], &[interval(20, 7, 2)], Limits::default())),
        Refusal::OutsideDomain { input: 0 }
    );
    assert_eq!(
        rejected(assess(
            8,
            &[0],
            &[interval(20, u64::MAX, 1)],
            Limits::default()
        )),
        Refusal::Overflow {
            input: 0,
            coordinate: "LCN"
        }
    );
    let mut a = interval(20, 0, 1);
    a.vcn_start = u64::MAX;
    assert_eq!(
        rejected(assess(8, &[0], &[a], Limits::default())),
        Refusal::Overflow {
            input: 0,
            coordinate: "VCN"
        }
    );
}
#[test]
fn malformed_attribute_key_is_refused() {
    for dimension in 0..5 {
        let mut a = interval(20, 0, 1);
        match dimension {
            0 => a.owner.record_number = 1 << 48,
            1 => a.owner.sequence_number = 0,
            2 => a.owner.type_code = 0,
            3 => a.owner.type_code = 0x81,
            _ => a.owner.name_utf16 = vec![1; 256],
        }
        assert_eq!(
            rejected(assess(8, &[1], &[a], Limits::default())),
            Refusal::InvalidOwner { input: 0 }
        );
    }
}
#[test]
fn every_budget_is_enforced_and_no_partial_summary_is_returned() {
    let mut a = interval(20, 0, 1);
    a.owner.name_utf16 = vec![1, 2];
    for dimension in 0..5 {
        let mut limits = Limits::default();
        let expected = match dimension {
            0 => {
                limits.max_intervals = 0;
                "interval count"
            }
            1 => {
                limits.max_bitmap_bytes = 0;
                "bitmap bytes"
            }
            2 => {
                limits.max_cluster_checks = 7;
                "cluster checks"
            }
            3 => {
                limits.max_total_name_units = 1;
                "attribute name units"
            }
            _ => {
                limits.max_sort_bytes = 0;
                "sorting storage"
            }
        };
        assert_eq!(
            rejected(assess(8, &[1], std::slice::from_ref(&a), limits)),
            Refusal::BudgetExceeded(expected)
        );
    }
}
#[test]
fn repeated_names_are_charged_per_input_interval() {
    let mut a = interval(20, 0, 1);
    a.owner.name_utf16 = vec![1; 2];
    let mut b = a.clone();
    b.vcn_start = 1;
    b.lcn_start = 1;
    let limits = Limits {
        max_total_name_units: 3,
        ..Limits::default()
    };
    assert_eq!(
        rejected(assess(8, &[3], &[a, b], limits)),
        Refusal::BudgetExceeded("attribute name units")
    );
}
#[test]
fn huge_domain_refuses_before_sort_or_bitmap_work() {
    assert_eq!(
        rejected(assess(u64::MAX, &[], &[], Limits::default())),
        Refusal::BudgetExceeded("cluster checks")
    );
}
#[test]
fn free_domain_with_no_claims_is_a_consistency_result_only() {
    let s = consistent(assess(8, &[0], &[], Limits::default()));
    assert_eq!(
        (
            s.allocated_clusters,
            s.distinct_attributes,
            s.sorting_storage_bytes
        ),
        (0, 0, 0)
    );
}
#[test]
fn exhaustive_small_bitmaps_match_independent_per_cluster_oracle() {
    // Enumerate every eight-cluster bitmap and every one-cluster claim set.
    for bits in 0u16..256 {
        for claims_bits in 0u16..256 {
            let claims: Vec<_> = (0..8)
                .filter(|c| claims_bits & (1 << c) != 0)
                .map(|c| interval(20 + c, c, 1))
                .collect();
            let result = assess(8, &[bits as u8], &claims, Limits::default());
            assert!(!result.grants_write_authority());
            assert_eq!(
                matches!(result, Assessment::Consistent(_)),
                bits == claims_bits
            );
            if bits == claims_bits {
                assert_eq!(
                    consistent(result).allocated_clusters,
                    u64::from(bits.count_ones())
                );
            }
        }
    }
}
