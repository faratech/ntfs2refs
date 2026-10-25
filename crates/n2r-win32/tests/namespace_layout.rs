use n2r_win32::{attestation::Query, namespace_layout as n};
fn row(name: &[u16]) -> Vec<u8> {
    let mut b = vec![0; 88 + name.len() * 2];
    b[60..64].copy_from_slice(&(name.len() as u32 * 2).to_le_bytes());
    b[72..80].copy_from_slice(&0x1000000000010u64.to_le_bytes());
    for (i, c) in name.iter().enumerate() {
        b[88 + 2 * i..90 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    b
}
fn query(bytes: Vec<u8>, class: i32, error: Option<i32>) -> Query {
    Query {
        class,
        bytes,
        native_error: error,
    }
}
#[test]
fn preserves_exact_utf16_and_128_bit_identity() {
    let b = row(&[0x41, 0xd800]);
    let (e, used) = n::parse(&b).unwrap();
    assert_eq!(used, b.len());
    assert_eq!(e[0].name_utf16, [0x41, 0xd800]);
    assert_eq!(&e[0].file_id[..8], &0x1000000000010u64.to_le_bytes());
}
#[test]
fn malformed_offsets_and_lengths_are_rejected() {
    let good = row(&[65]);
    let mut cases = vec![vec![], vec![0; 88], good[..89].to_vec()];
    for (offset, value) in [
        (0, 1u32),
        (0, 88),
        (0, 96),
        (60, 1),
        (60, 512),
        (60, u32::MAX),
    ] {
        let mut b = good.clone();
        b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        cases.push(b);
    }
    for b in cases {
        assert!(n::parse(&b).is_err());
    }
    for c in [0, 47, 58, 92] {
        assert!(n::parse(&row(&[c])).is_err());
    }
}
#[test]
fn linked_rows_use_aligned_offsets_and_ignore_output_padding() {
    let mut b = row(&[65]);
    b.resize(96, 0);
    b[..4].copy_from_slice(&96u32.to_le_bytes());
    b.extend(row(&[66]));
    let end = b.len();
    b.resize(n::CAPACITY, 0);
    let (e, used) = n::parse(&b).unwrap();
    assert_eq!(used, end);
    assert_eq!(e.len(), 2);
}
#[test]
fn empty_directory_requires_native_end_of_enumeration() {
    assert!(
        n::decode_pass(&[query(vec![], n::RESTART, Some(n::END))])
            .unwrap()
            .is_empty()
    );
    for error in [Some(5), Some(2), None] {
        assert!(n::decode_pass(&[query(vec![], n::RESTART, error)]).is_err());
    }
}

#[test]
fn initial_empty_refs_query_requires_a_separate_exact_continuation_eof() {
    let first = query(vec![], n::RESTART, Some(n::FIRST_EMPTY));
    let end = query(vec![], n::CONTINUE, Some(n::END));
    assert!(
        n::decode_pass(&[first.clone(), end.clone()])
            .unwrap()
            .is_empty()
    );
    for calls in [
        vec![first.clone()],
        vec![first.clone(), query(vec![], n::CONTINUE, Some(5))],
        vec![first.clone(), query(row(&[65]), n::CONTINUE, None)],
        vec![first.clone(), end.clone(), end.clone()],
        vec![first.clone(), query(vec![0], n::CONTINUE, Some(n::END))],
        vec![
            query(vec![0], n::RESTART, Some(n::FIRST_EMPTY)),
            end.clone(),
        ],
        vec![first, query(vec![], n::RESTART, Some(n::END))],
        vec![
            query(row(&[65]), n::RESTART, None),
            query(vec![], n::CONTINUE, Some(n::FIRST_EMPTY)),
        ],
    ] {
        assert!(n::decode_pass(&calls).is_err());
    }
}
#[test]
fn partial_enumeration_and_failure_after_some_entries_are_refused() {
    let first = query(row(&[65]), n::RESTART, None);
    assert!(n::decode_pass(std::slice::from_ref(&first)).is_err());
    assert!(n::decode_pass(&[first.clone(), query(vec![], n::CONTINUE, Some(5))]).is_err());
    assert_eq!(
        n::decode_pass(&[first, query(vec![], n::CONTINUE, Some(n::END))])
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn restart_and_terminal_sequence_are_checked() {
    assert!(n::decode_pass(&[]).is_err());
    assert!(n::decode_pass(&[query(vec![], n::CONTINUE, Some(n::END))]).is_err());
    assert!(
        n::decode_pass(&[
            query(vec![], n::RESTART, Some(n::END)),
            query(row(&[65]), n::CONTINUE, None)
        ])
        .is_err()
    );
    let mut padded = row(&[65]);
    padded.push(0);
    assert!(
        n::decode_pass(&[
            query(padded, n::RESTART, None),
            query(vec![], n::CONTINUE, Some(n::END))
        ])
        .is_err()
    );
}
