//! Pure retrieval transcript replay. No native calls, files or devices.
use n2r_win32::{
    attestation::IoctlQuery,
    retrieval_paging::{
        Assembler, ENCODING, MAX_COMPLETE_EXTENTS, MAX_PAGES, MAX_RETURNED_BYTES, MORE_DATA,
        PAGE_CAPACITY, assemble_queries,
    },
    stream_layout::{
        COMPLETE_RETRIEVAL_CAPACITY, GET_RETRIEVAL, MAX_EXTENTS, Run, parse_complete_retrieval,
        parse_retrieval,
    },
};
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn response(start: i64, extents: &[(i64, i64)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + extents.len() * 16);
    bytes.extend_from_slice(&(extents.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&start.to_le_bytes());
    for (next_vcn, lcn) in extents {
        bytes.extend_from_slice(&next_vcn.to_le_bytes());
        bytes.extend_from_slice(&lcn.to_le_bytes());
    }
    bytes
}

fn page(
    requested_vcn: u64,
    response_vcn: i64,
    extents: &[(i64, i64)],
    native_error: Option<i32>,
) -> IoctlQuery {
    IoctlQuery {
        code: GET_RETRIEVAL,
        input: requested_vcn.to_le_bytes().to_vec(),
        bytes: response(response_vcn, extents),
        native_error,
    }
}

fn fragmented(first_vcn: usize, count: usize) -> Vec<(i64, i64)> {
    (first_vcn..first_vcn + count)
        .map(|vcn| ((vcn + 1) as i64, (100_000 + vcn * 3) as i64))
        .collect()
}

fn refuses_and_poisons(prefix: &[IoctlQuery], bad: &IoctlQuery) {
    let mut assembler = Assembler::default();
    for query in prefix {
        assert!(!assembler.push(query).unwrap());
    }
    assert!(assembler.push(bad).is_err());
    assert_eq!(assembler.response_capacity(), 0);
    let otherwise_valid = page(assembler.next_vcn(), 0, &[(100, 500)], None);
    assert!(assembler.push(&otherwise_valid).is_err());
    assert!(assembler.finish().is_err());
}

#[test]
fn more_than_one_native_page_preserves_fragmented_runs_and_raw_page_proofs() {
    let first = page(0, 0, &fragmented(0, MAX_EXTENTS), Some(MORE_DATA));
    let second = page(
        MAX_EXTENTS as u64,
        MAX_EXTENTS as i64,
        &fragmented(MAX_EXTENTS, 3),
        None,
    );
    let capture = assemble_queries(&first, std::slice::from_ref(&second)).unwrap();
    assert_eq!(capture.runs.len(), MAX_EXTENTS + 3);
    assert_eq!(capture.proof.extent_count, MAX_EXTENTS + 3);
    assert_eq!(capture.proof.virtual_clusters, (MAX_EXTENTS + 3) as u64);
    assert_eq!(capture.proof.encoding, ENCODING);
    assert_eq!(capture.proof.canonical_sha256, sha(&capture.canonical));
    assert!(parse_retrieval(&capture.canonical).is_err());
    assert_eq!(
        parse_complete_retrieval(&capture.canonical).unwrap(),
        capture.runs
    );
    for (index, run) in capture.runs.iter().enumerate() {
        assert_eq!(run.vcn, index as u64);
        assert_eq!(run.clusters, 1);
        assert_eq!(run.lcn, Some((100_000 + index * 3) as u64));
    }
    for (proof, query) in capture.proof.pages.iter().zip([&first, &second]) {
        assert_eq!(proof.input, query.input);
        assert_eq!(proof.response_header.as_slice(), &query.bytes[..16]);
        assert_eq!(proof.response_bytes, query.bytes.len());
        assert_eq!(proof.native_error, query.native_error);
        assert_eq!(proof.response_sha256, sha(&query.bytes));
        assert_ne!(proof.response_sha256, capture.proof.canonical_sha256);
    }
}

#[test]
fn exactly_65536_fragmented_extents_finish_at_the_64_page_boundary() {
    assert_eq!(MAX_EXTENTS, 1024);
    assert_eq!(MAX_COMPLETE_EXTENTS, 65_536);
    let pages = MAX_COMPLETE_EXTENTS / MAX_EXTENTS;
    assert_eq!(pages, 64);
    let mut assembler = Assembler::default();
    for index in 0..pages {
        let first_vcn = index * MAX_EXTENTS;
        assert_eq!(assembler.next_vcn(), first_vcn as u64);
        assert_eq!(assembler.response_capacity(), PAGE_CAPACITY);
        let query = page(
            first_vcn as u64,
            first_vcn as i64,
            &fragmented(first_vcn, MAX_EXTENTS),
            (index + 1 < pages).then_some(MORE_DATA),
        );
        assert_eq!(assembler.push(&query).unwrap(), index + 1 == pages);
    }
    assert_eq!(assembler.next_vcn(), MAX_COMPLETE_EXTENTS as u64);
    assert_eq!(assembler.response_capacity(), 0);
    let capture = assembler.finish().unwrap();
    assert_eq!(capture.canonical.len(), COMPLETE_RETRIEVAL_CAPACITY);
    assert_eq!(capture.runs.len(), MAX_COMPLETE_EXTENTS);
    assert_eq!(capture.proof.pages.len(), pages);
    assert_eq!(
        parse_complete_retrieval(&capture.canonical).unwrap(),
        capture.runs
    );
    assert!(parse_retrieval(&capture.canonical).is_err());
    assert_eq!(
        capture.runs.last().unwrap().vcn,
        MAX_COMPLETE_EXTENTS as u64 - 1
    );
    assert_eq!(capture.proof.canonical_sha256, sha(&capture.canonical));
}

#[test]
fn rounded_overlap_can_change_segmentation_only_when_adjusted_mapping_is_identical() {
    let first = page(0, 0, &[(4, 100), (8, 104)], Some(MORE_DATA));
    let second = page(8, 2, &[(5, 102), (10, 105), (12, 500)], None);
    let capture = assemble_queries(&first, std::slice::from_ref(&second)).unwrap();
    assert_eq!(
        capture.runs,
        [
            Run {
                vcn: 0,
                lcn: Some(100),
                clusters: 10
            },
            Run {
                vcn: 10,
                lcn: Some(500),
                clusters: 2
            },
        ]
    );
    assert_eq!(capture.canonical, response(0, &[(10, 100), (12, 500)]));
    assert_eq!(capture.proof.pages[1].input, 8u64.to_le_bytes());
    assert_eq!(
        &capture.proof.pages[1].response_header[8..],
        &2i64.to_le_bytes()
    );
    for bad_extents in [
        vec![(5, 103), (10, 105), (12, 500)],
        vec![(5, 102), (10, 106), (12, 500)],
        vec![(5, -1), (10, 105), (12, 500)],
    ] {
        refuses_and_poisons(
            std::slice::from_ref(&first),
            &page(8, 2, &bad_extents, None),
        );
    }
}

#[test]
fn sparse_holes_survive_paging_and_cannot_change_to_allocated_overlap() {
    let first = page(0, 0, &[(4, -1), (8, 100)], Some(MORE_DATA));
    let second = page(8, 2, &[(4, -1), (6, 100), (10, 102)], None);
    let capture = assemble_queries(&first, std::slice::from_ref(&second)).unwrap();
    assert_eq!(capture.canonical, response(0, &[(4, -1), (10, 100)]));
    assert_eq!(
        capture.runs[0],
        Run {
            vcn: 0,
            lcn: None,
            clusters: 4
        }
    );
    assert_eq!(
        capture.runs[1],
        Run {
            vcn: 4,
            lcn: Some(100),
            clusters: 6
        }
    );
    let allocated_hole = page(8, 2, &[(4, 98), (6, 100), (10, 102)], None);
    refuses_and_poisons(std::slice::from_ref(&first), &allocated_hole);
    let hole_over_allocation = page(8, 4, &[(10, -1)], None);
    refuses_and_poisons(std::slice::from_ref(&first), &hole_over_allocation);
    refuses_and_poisons(&[], &page(0, 0, &[(1, -2)], None));
}

#[test]
fn malformed_counts_headers_extent_order_and_query_identity_are_refused() {
    let good = page(0, 0, &[(4, 100), (8, 500)], None);
    for count in [0u32, 1, 3, u32::MAX] {
        let mut bad = good.clone();
        bad.bytes[..4].copy_from_slice(&count.to_le_bytes());
        refuses_and_poisons(&[], &bad);
    }
    for length in [0, 15, 16, 31, 33, good.bytes.len() - 1] {
        let mut bad = good.clone();
        bad.bytes.truncate(length);
        refuses_and_poisons(&[], &bad);
    }
    for bad in [
        page(0, -1, &[(4, 100)], None),
        page(0, 1, &[(4, 100)], None),
        page(0, 0, &[(0, 100)], None),
        page(0, 0, &[(-1, 100)], None),
        page(0, 0, &[(4, 100), (3, 500)], None),
        page(0, 0, &[(4, 100), (4, 500)], None),
    ] {
        refuses_and_poisons(&[], &bad);
    }
    for change in 0..4 {
        let mut bad = good.clone();
        match change {
            0 => bad.code ^= 1,
            1 => bad.input.truncate(7),
            2 => bad.input.push(0),
            _ => bad.input = 100u64.to_le_bytes().to_vec(),
        }
        refuses_and_poisons(&[], &bad);
    }
}

#[test]
fn gaps_nonprogress_and_eof_do_not_complete_a_partial_mapping() {
    let first = page(0, 0, &[(8, 100)], Some(MORE_DATA));
    for bad in [
        page(8, 9, &[(10, 500)], None),
        page(8, 0, &[(8, 100)], None),
        page(8, 0, &[(4, 100)], Some(MORE_DATA)),
        page(8, 8, &[], None),
        page(8, 8, &[], Some(MORE_DATA)),
        page(8, 8, &[], Some(38)),
        page(8, 8, &[(9, 500)], Some(38)),
        page(8, 8, &[(9, 500)], Some(5)),
        page(8, 8, &[(9, 500)], Some(0)),
    ] {
        refuses_and_poisons(std::slice::from_ref(&first), &bad);
    }
    let mut eof = page(0, 0, &[], Some(38));
    eof.bytes.clear();
    refuses_and_poisons(&[], &eof);
    assert!(Assembler::default().finish().is_err());
    assert!(assemble_queries(&first, &[]).is_err());
    let mut truncated = Assembler::default();
    assert!(!truncated.push(&first).unwrap());
    assert!(truncated.finish().is_err());
}

#[test]
fn continuation_uses_next_vcn_not_the_last_or_next_physical_lcn() {
    let first = page(0, 0, &[(4, 90_000), (12, 500)], Some(MORE_DATA));
    let mut assembler = Assembler::default();
    assert!(!assembler.push(&first).unwrap());
    assert_eq!(assembler.next_vcn(), 12);
    let continuation = page(12, 12, &[(16, 4_000_000)], None);
    assert!(assembler.push(&continuation).unwrap());
    assert_eq!(assembler.finish().unwrap().proof.virtual_clusters, 16);
    for wrong_start in [500, 508, 90_000, 90_004] {
        let wrong = page(wrong_start, 12, &[(16, 4_000_000)], None);
        refuses_and_poisons(std::slice::from_ref(&first), &wrong);
    }
}

#[test]
fn a_terminal_page_closes_the_chain_and_any_additional_push_poisons_it() {
    let terminal = page(0, 0, &[(1, 100)], None);
    let mut assembler = Assembler::default();
    assert!(assembler.push(&terminal).unwrap());
    assert_eq!(assembler.response_capacity(), 0);
    let extra = page(1, 1, &[(2, 500)], None);
    assert!(assembler.push(&extra).is_err());
    assert!(assembler.finish().is_err());
    assert!(assemble_queries(&terminal, &[extra]).is_err());
}

#[test]
fn page_and_complete_extent_budgets_are_distinct_and_fail_closed() {
    let oversized_page = page(0, 0, &fragmented(0, MAX_EXTENTS + 1), None);
    refuses_and_poisons(&[], &oversized_page);
    let mut full = Assembler::default();
    for index in 0..MAX_COMPLETE_EXTENTS / MAX_EXTENTS {
        let start = index * MAX_EXTENTS;
        let query = page(
            start as u64,
            start as i64,
            &fragmented(start, MAX_EXTENTS),
            Some(MORE_DATA),
        );
        assert!(!full.push(&query).unwrap());
    }
    let extra = page(
        MAX_COMPLETE_EXTENTS as u64,
        MAX_COMPLETE_EXTENTS as i64,
        &fragmented(MAX_COMPLETE_EXTENTS, 1),
        None,
    );
    assert!(full.push(&extra).is_err());
    assert_eq!(full.response_capacity(), 0);
    assert!(full.finish().is_err());
    let oversized_complete = response(0, &fragmented(0, MAX_COMPLETE_EXTENTS + 1));
    assert!(parse_complete_retrieval(&oversized_complete).is_err());
    let offset_complete = response(1, &[(2, 100)]);
    assert!(parse_complete_retrieval(&offset_complete).is_err());
}

#[test]
fn page_count_budget_stops_even_when_contiguous_extents_coalesce() {
    let mut assembler = Assembler::default();
    for index in 0..MAX_PAGES {
        let query = page(
            index as u64,
            index as i64,
            &[((index + 1) as i64, (100 + index) as i64)],
            Some(MORE_DATA),
        );
        assert!(!assembler.push(&query).unwrap());
    }
    assert_eq!(assembler.next_vcn(), MAX_PAGES as u64);
    assert_eq!(assembler.response_capacity(), 0);
    let terminal = page(
        MAX_PAGES as u64,
        MAX_PAGES as i64,
        &[((MAX_PAGES + 1) as i64, (100 + MAX_PAGES) as i64)],
        None,
    );
    assert!(assembler.push(&terminal).is_err());
    assert!(assembler.finish().is_err());
}

#[test]
fn maximum_wire_pages_remain_bounded_when_the_canonical_map_is_small() {
    // With these constants the page-count/per-page caps are tighter than the
    // aggregate returned-byte cap. Exercise the largest legal wire transcript.
    let mut assembler = Assembler::default();
    let mut returned = 0;
    for index in 0..MAX_PAGES {
        let start = index * MAX_EXTENTS;
        let entries: Vec<_> = (start..start + MAX_EXTENTS)
            .map(|vcn| ((vcn + 1) as i64, (100 + vcn) as i64))
            .collect();
        let query = page(
            start as u64,
            start as i64,
            &entries,
            (index + 1 < MAX_PAGES).then_some(MORE_DATA),
        );
        assert_eq!(query.bytes.len(), PAGE_CAPACITY);
        returned += query.bytes.len();
        assert_eq!(assembler.push(&query).unwrap(), index + 1 == MAX_PAGES);
    }
    let capture = assembler.finish().unwrap();
    assert_eq!(capture.runs.len(), 1);
    assert_eq!(capture.proof.pages.len(), MAX_PAGES);
    assert_eq!(
        capture.proof.virtual_clusters,
        (MAX_PAGES * MAX_EXTENTS) as u64
    );
    assert_eq!(capture.runs[0].lcn, Some(100));
    assert_eq!(
        capture
            .proof
            .pages
            .iter()
            .map(|p| p.response_bytes)
            .sum::<usize>(),
        returned
    );
    assert!(returned <= MAX_RETURNED_BYTES);
}

#[test]
fn preallocated_mapping_is_not_trimmed_to_a_guessed_logical_eof() {
    // Logical EOF/VDL are intentionally not inputs to the page assembler.
    let query = page(0, 0, &[(16, 100)], None);
    let capture = assemble_queries(&query, &[]).unwrap();
    assert_eq!(
        capture.runs,
        [Run {
            vcn: 0,
            lcn: Some(100),
            clusters: 16
        }]
    );
    assert_eq!(capture.proof.virtual_clusters, 16);
    assert_eq!(capture.canonical, response(0, &[(16, 100)]));
}

#[test]
fn equivalent_maps_keep_distinct_raw_pages_and_preserve_header_padding_in_proofs() {
    let mut direct = page(0, 0, &[(10, 100), (12, 500)], None);
    direct.bytes[4..8].copy_from_slice(&[0x41, 0x42, 0x43, 0x44]);
    let one = assemble_queries(&direct, &[]).unwrap();
    let first = page(0, 0, &[(4, 100), (8, 104)], Some(MORE_DATA));
    let second = page(8, 2, &[(5, 102), (10, 105), (12, 500)], None);
    let paged = assemble_queries(&first, &[second]).unwrap();
    assert_eq!(one.runs, paged.runs);
    assert_eq!(one.canonical, paged.canonical);
    assert_eq!(one.proof.canonical_sha256, paged.proof.canonical_sha256);
    assert_eq!(&one.canonical[4..8], &[0; 4]);
    assert_eq!(
        &one.proof.pages[0].response_header[4..8],
        &[0x41, 0x42, 0x43, 0x44]
    );
    assert_eq!(one.proof.pages[0].response_sha256, sha(&direct.bytes));
    assert_ne!(
        one.proof.pages[0].response_sha256,
        one.proof.canonical_sha256
    );
    assert_ne!(one.proof.pages, paged.proof.pages);
}
