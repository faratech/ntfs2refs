//! Pure replay/assembly checks. No native calls, files, images or devices.
use n2r_win32::{
    attestation::IoctlQuery,
    bitmap_paging::{
        Assembler, ENCODING, MAX_COMPLETE_BYTES, MAX_DATA_BYTES, MAX_PAGES, MAX_RETURNED_BYTES,
        MORE_DATA, PAGE_BYTES, assemble_queries, page_input,
    },
    stream_layout::GET_BITMAP,
};
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn metadata_template() -> Vec<u8> {
    let mut template = vec![0; 16];
    template[8] = 1;
    template
}

fn page(
    template: &[u8],
    requested_lcn: u64,
    response_lcn: i64,
    remaining_clusters: i64,
    data: &[u8],
    native_error: Option<i32>,
) -> IoctlQuery {
    let mut bytes = Vec::with_capacity(16 + data.len());
    bytes.extend_from_slice(&response_lcn.to_le_bytes());
    bytes.extend_from_slice(&remaining_clusters.to_le_bytes());
    bytes.extend_from_slice(data);
    IoctlQuery {
        code: GET_BITMAP,
        input: page_input(template, requested_lcn).unwrap(),
        bytes,
        native_error,
    }
}

fn canonical(cluster_count: u64, data: &[u8]) -> Vec<u8> {
    let mut bitmap = vec![0; 8];
    bitmap.extend_from_slice(&cluster_count.to_le_bytes());
    bitmap.extend_from_slice(data);
    bitmap
}

fn rejects_and_poisons(first: Option<&IoctlQuery>, bad: &IoctlQuery, template: &[u8]) {
    let mut assembler = Assembler::default();
    if let Some(first) = first {
        assert!(!assembler.push(first, template).unwrap());
    }
    assert!(assembler.push(bad, template).is_err());
    assert!(assembler.finish().is_err());
}

#[test]
fn full_128_gib_cluster_domain_requires_two_real_pages_and_complete_provenance() {
    // 128 GiB / 4 KiB = 2^25 clusters = exactly 4 MiB of bitmap data.
    let template = metadata_template();
    let clusters = 128u64 * 1024 * 1024 * 1024 / 4096;
    let data: Vec<_> = (0..MAX_DATA_BYTES)
        .map(|index| (index.wrapping_mul(73).wrapping_add(19) & 255) as u8)
        .collect();
    let split = PAGE_BYTES - 16;
    let next = (split as u64) * 8;
    let first = page(
        &template,
        0,
        0,
        clusters as i64,
        &data[..split],
        Some(MORE_DATA),
    );
    let second = page(
        &template,
        next,
        next as i64,
        (clusters - next) as i64,
        &data[split..],
        None,
    );
    let mut assembler = Assembler::default();
    assert_eq!(assembler.next_lcn(), 0);
    assert!(!assembler.push(&first, &template).unwrap());
    assert_eq!(assembler.next_lcn(), next);
    assert!(assembler.push(&second, &template).unwrap());
    assert_eq!(assembler.next_lcn(), clusters);
    let capture = assembler.finish().unwrap();
    assert_eq!(capture.bitmap, canonical(clusters, &data));
    assert_eq!(capture.bitmap.len(), MAX_COMPLETE_BYTES);
    assert_eq!(capture.proof.encoding, ENCODING);
    assert_eq!(capture.proof.cluster_count, clusters);
    assert_eq!(capture.proof.canonical_bitmap_sha256, sha(&capture.bitmap));
    assert_eq!(capture.proof.pages.len(), 2);
    for (proof, query) in capture.proof.pages.iter().zip([&first, &second]) {
        assert_eq!(proof.input, query.input);
        assert_eq!(proof.response_header.as_slice(), &query.bytes[..16]);
        assert_eq!(proof.response_bytes, query.bytes.len());
        assert_eq!(proof.native_error, query.native_error);
        assert_eq!(proof.response_sha256, sha(&query.bytes));
        assert_ne!(proof.response_sha256, capture.proof.canonical_bitmap_sha256);
        assert_eq!(&proof.input[8..], &template[8..]);
    }
    let replay = assemble_queries(&first, &[second], &template).unwrap();
    assert_eq!(replay.bitmap, capture.bitmap);
    assert_eq!(replay.proof, capture.proof);
}

#[test]
fn exact_64_gib_domain_fits_only_when_response_capacity_includes_the_header() {
    let template = [0; 8];
    let clusters = 64u64 * 1024 * 1024 * 1024 / 4096;
    let data = vec![0xa5; 2 * 1024 * 1024];
    let complete = page(&template, 0, 0, clusters as i64, &data, None);
    assert_eq!(complete.bytes.len(), PAGE_BYTES);
    let capture = assemble_queries(&complete, &[], &template).unwrap();
    assert_eq!(capture.bitmap, canonical(clusters, &data));
    let mut insufficient = complete.clone();
    insufficient.bytes.truncate(2 * 1024 * 1024);
    rejects_and_poisons(None, &insufficient, &template);
    let mut false_more = complete;
    false_more.native_error = Some(MORE_DATA);
    rejects_and_poisons(None, &false_more, &template);
}

#[test]
fn rounded_down_identical_overlap_is_accepted_and_conflicting_overlap_is_refused() {
    let template = metadata_template();
    let data: Vec<u8> = (0..16).collect();
    let first = page(&template, 0, 0, 128, &data[..9], Some(MORE_DATA));
    let rounded = page(&template, 72, 64, 64, &data[8..], None);
    let capture = assemble_queries(&first, std::slice::from_ref(&rounded), &template).unwrap();
    assert_eq!(capture.bitmap, canonical(128, &data));
    assert_eq!(capture.proof.pages[1].input[..8], 72u64.to_le_bytes());
    assert_eq!(
        capture.proof.pages[1].response_header[..8],
        64i64.to_le_bytes()
    );
    let mut conflict = rounded;
    conflict.bytes[16] ^= 1;
    rejects_and_poisons(Some(&first), &conflict, &template);
}

#[test]
fn gaps_changing_domains_invalid_headers_and_native_failures_poison_assembly() {
    let template = [0; 8];
    let first = page(&template, 0, 0, 32, &[0x11], Some(MORE_DATA));
    for bad in [
        page(&template, 8, 16, 16, &[0x22, 0x33], None), // gap
        page(&template, 8, 8, 16, &[0x22, 0x33], None),  // domain changed 32 -> 24
        page(&template, 8, -8, 40, &[0x11, 0x22, 0x33, 0x44, 0x55], None),
        page(&template, 8, 8, -1, &[0x22], None),
        page(&template, 8, 8, 0, &[0x22], None),
        page(&template, 8, 1, 31, &[0x11, 0x22, 0x33, 0x44], None),
        page(&template, 8, 8, 24, &[0x22], None), // successful but incomplete
        page(&template, 8, 0, 32, &[0x11], Some(MORE_DATA)), // no progress
        page(&template, 8, 8, 24, &[0x22, 0x33, 0x44], Some(MORE_DATA)),
        page(&template, 8, 8, 24, &[0x22, 0x33, 0x44], Some(5)),
        page(&template, 8, 8, 24, &[0x22, 0x33, 0x44], Some(0)),
    ] {
        rejects_and_poisons(Some(&first), &bad, &template);
    }
    for length in [0, 8, 15, 16] {
        let mut bad = first.clone();
        bad.bytes.truncate(length);
        rejects_and_poisons(None, &bad, &template);
    }
}

#[test]
fn continuation_queries_must_preserve_exact_lcn_code_and_metadata_flag() {
    let template = metadata_template();
    let first = page(&template, 0, 0, 16, &[0x11], Some(MORE_DATA));
    let correct = page(&template, 8, 8, 8, &[0x22], None);
    for change in 0..5 {
        let mut bad = correct.clone();
        match change {
            0 => bad.input = page_input(&template, 0).unwrap(),
            1 => bad.input[8] = 0,
            2 => bad.input.truncate(8),
            3 => bad.input[12] = 1,
            _ => bad.code ^= 1,
        }
        rejects_and_poisons(Some(&first), &bad, &template);
    }
    let mut poisoned = Assembler::default();
    assert!(!poisoned.push(&first, &template).unwrap());
    let mut bad = correct.clone();
    bad.input[8] = 0;
    assert!(poisoned.push(&bad, &template).is_err());
    assert!(poisoned.push(&correct, &template).is_err());
    assert!(poisoned.finish().is_err());
}

#[test]
fn incomplete_chains_and_additional_terminal_pages_are_refused() {
    let template = [0; 8];
    assert!(Assembler::default().finish().is_err());
    let first = page(&template, 0, 0, 16, &[0x11], Some(MORE_DATA));
    assert!(assemble_queries(&first, &[], &template).is_err());
    let mut incomplete = Assembler::default();
    assert!(!incomplete.push(&first, &template).unwrap());
    assert!(incomplete.finish().is_err());
    let complete = page(&template, 0, 0, 8, &[0x11], None);
    let mut assembler = Assembler::default();
    assert!(assembler.push(&complete, &template).unwrap());
    assert!(assembler.push(&complete, &template).is_err());
    assert!(assembler.finish().is_err());
    assert!(assemble_queries(&complete, std::slice::from_ref(&complete), &template).is_err());
}

#[test]
fn input_templates_and_continuation_addresses_are_strictly_bounded() {
    for template in [vec![0; 8], vec![0; 16], metadata_template()] {
        assert_eq!(page_input(&template, 0).unwrap(), template);
        let continued = page_input(&template, 4096).unwrap();
        assert_eq!(&continued[..8], &4096u64.to_le_bytes());
        assert_eq!(&continued[8..], &template[8..]);
        for lcn in [1, 7, 9, i64::MAX as u64 + 1] {
            assert!(page_input(&template, lcn).is_err());
        }
    }
    for length in [0, 7, 9, 15, 17] {
        assert!(page_input(&vec![0; length], 0).is_err());
    }
    for change in 0..3 {
        let mut bad = metadata_template();
        match change {
            0 => bad[0] = 8,
            1 => bad[8] = 2,
            _ => bad[15] = 1,
        }
        assert!(page_input(&bad, 0).is_err());
    }
    let mut bad_template = metadata_template();
    bad_template[8] = 2;
    let otherwise_valid = page(&[0; 8], 0, 0, 8, &[0], None);
    rejects_and_poisons(None, &otherwise_valid, &bad_template);
}

#[test]
fn domain_response_page_count_and_total_returned_byte_budgets_are_enforced() {
    let template = [0; 8];
    assert_eq!(MAX_COMPLETE_BYTES, 16 + MAX_DATA_BYTES);
    let excessive_domain = page(
        &template,
        0,
        0,
        (MAX_DATA_BYTES as i64) * 8 + 8,
        &[0],
        Some(MORE_DATA),
    );
    rejects_and_poisons(None, &excessive_domain, &template);
    let excessive_response = page(
        &template,
        0,
        0,
        (MAX_DATA_BYTES as i64) * 8,
        &vec![0; PAGE_BYTES - 16 + 1],
        Some(MORE_DATA),
    );
    rejects_and_poisons(None, &excessive_response, &template);

    let mut limited_pages = Assembler::default();
    let clusters = (MAX_PAGES as u64 + 1) * 8;
    for index in 0..MAX_PAGES {
        let next = (index as u64) * 8;
        let query = page(
            &template,
            next,
            next as i64,
            (clusters - next) as i64,
            &[0],
            Some(MORE_DATA),
        );
        assert!(!limited_pages.push(&query, &template).unwrap());
    }
    let next = limited_pages.next_lcn();
    let final_page = page(&template, next, next as i64, 8, &[0], None);
    assert!(limited_pages.push(&final_page, &template).is_err());
    assert!(limited_pages.finish().is_err());

    // Large rounded-down pages make a little progress while repeatedly
    // returning the same bytes. The aggregate cap is independent of MAX_PAGES.
    let clusters = (MAX_DATA_BYTES as u64) * 8;
    let data = vec![0; PAGE_BYTES - 16];
    let accepted_pages = MAX_RETURNED_BYTES / PAGE_BYTES;
    assert!(accepted_pages < MAX_PAGES);
    let mut repeated = Assembler::default();
    for index in 0..=accepted_pages {
        let response_start = index as u64 * 8;
        let query = page(
            &template,
            repeated.next_lcn(),
            response_start as i64,
            (clusters - response_start) as i64,
            &data,
            Some(MORE_DATA),
        );
        if index < accepted_pages {
            assert!(!repeated.push(&query, &template).unwrap());
        } else {
            assert!(repeated.push(&query, &template).is_err());
        }
    }
    assert!(repeated.finish().is_err());
}

#[test]
fn unused_final_bits_are_preserved_without_relabeling_page_hashes_as_canonical() {
    let template = [0; 8];
    let first = page(&template, 0, 0, 11, &[0xaa], Some(MORE_DATA));
    let second = page(&template, 8, 8, 3, &[0xed], None);
    let capture = assemble_queries(&first, std::slice::from_ref(&second), &template).unwrap();
    assert_eq!(capture.bitmap, canonical(11, &[0xaa, 0xed]));
    assert_eq!(capture.bitmap[17] & 0xf8, 0xe8);
    assert_eq!(capture.proof.canonical_bitmap_sha256, sha(&capture.bitmap));
    assert_eq!(capture.proof.pages[1].response_sha256, sha(&second.bytes));
    assert_ne!(
        capture.proof.pages[1].response_sha256,
        capture.proof.canonical_bitmap_sha256
    );
}

#[test]
fn equivalent_canonical_bitmaps_keep_distinct_native_page_proofs() {
    let template = metadata_template();
    let data: Vec<u8> = (0..16).collect();
    let direct_first = page(&template, 0, 0, 128, &data[..8], Some(MORE_DATA));
    let direct_second = page(&template, 64, 64, 64, &data[8..], None);
    let direct = assemble_queries(&direct_first, &[direct_second], &template).unwrap();
    let rounded_first = page(&template, 0, 0, 128, &data[..9], Some(MORE_DATA));
    let rounded_second = page(&template, 72, 64, 64, &data[8..], None);
    let rounded = assemble_queries(&rounded_first, &[rounded_second], &template).unwrap();
    assert_eq!(direct.bitmap, rounded.bitmap);
    assert_eq!(
        direct.proof.canonical_bitmap_sha256,
        rounded.proof.canonical_bitmap_sha256
    );
    assert_ne!(direct.proof.pages, rounded.proof.pages);
    assert_ne!(
        direct.proof.pages[0].response_sha256,
        rounded.proof.pages[0].response_sha256
    );
    assert_ne!(direct.proof.pages[1].input, rounded.proof.pages[1].input);
}
