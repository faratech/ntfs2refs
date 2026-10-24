use n2r_win32::stream_layout::{parse_retrieval, parse_streams};
fn p32(b: &mut [u8], o: usize, n: u32) {
    b[o..o + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], o: usize, n: i64) {
    b[o..o + 8].copy_from_slice(&n.to_le_bytes());
}
fn entry(name: &[u16], next: bool) -> Vec<u8> {
    let n = 24 + name.len() * 2;
    let mut b = vec![0; if next { n.next_multiple_of(8) } else { n }];
    if next {
        let len = b.len() as u32;
        p32(&mut b, 0, len);
    }
    p32(&mut b, 4, (name.len() * 2) as u32);
    p64(&mut b, 8, 19);
    p64(&mut b, 16, 24);
    for (i, c) in name.iter().enumerate() {
        b[24 + 2 * i..26 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    b
}
fn named(name: &str, next: bool) -> Vec<u8> {
    entry(&name.encode_utf16().collect::<Vec<_>>(), next)
}
fn retrieval() -> Vec<u8> {
    let mut b = vec![0; 48];
    p32(&mut b, 0, 2);
    p64(&mut b, 16, 2);
    p64(&mut b, 24, 100);
    p64(&mut b, 32, 7);
    p64(&mut b, 40, -1);
    b
}
#[test]
fn parses_unnamed_and_ads() {
    let mut b = named("::$DATA", true);
    b.extend(named(":note:$DATA", false));
    let (s, end) = parse_streams(&b).unwrap();
    assert_eq!(end, b.len());
    assert!(s[0].name.is_empty());
    assert_eq!(s[1].name, "note".encode_utf16().collect::<Vec<_>>());
}
#[test]
fn preserves_unpaired_utf16() {
    let mut name = vec![58, 0xd800];
    name.extend(":$DATA".encode_utf16());
    assert_eq!(
        parse_streams(&entry(&name, false)).unwrap().0[0].name,
        vec![0xd800]
    );
}
#[test]
fn excludes_initialized_unused_output() {
    let mut b = named("::$DATA", false);
    let end = b.len();
    b.resize(4096, 0);
    assert_eq!(parse_streams(&b).unwrap().1, end);
}
#[test]
fn rejects_negative_sizes_and_bad_names() {
    for at in [8, 16] {
        let mut b = named("::$DATA", false);
        p64(&mut b, at, -1);
        assert!(parse_streams(&b).is_err());
    }
    for name in [
        ":bad/name:$DATA",
        ":bad\\name:$DATA",
        ":bad:name:$DATA",
        ":bad\0name:$DATA",
        ":$I30:$INDEX_ALLOCATION",
    ] {
        assert!(parse_streams(&named(name, false)).is_err());
    }
}
#[test]
fn rejects_misaligned_overlapping_and_outside_links() {
    for offset in [24, 39, 4096] {
        let mut b = named("::$DATA", false);
        p32(&mut b, 0, offset);
        assert!(parse_streams(&b).is_err());
    }
}
#[test]
fn rejects_odd_or_truncated_names() {
    let mut b = named("::$DATA", false);
    p32(&mut b, 4, 13);
    assert!(parse_streams(&b).is_err());
    let b = named("::$DATA", false);
    assert!(parse_streams(&b[..b.len() - 1]).is_err());
}
#[test]
fn rejects_duplicate_names_and_count_exhaustion() {
    let mut b = named("::$DATA", true);
    b.extend(named("::$DATA", false));
    assert!(parse_streams(&b).is_err());
    let mut b = vec![];
    for i in 0..65 {
        b.extend(named(&format!(":s{i}:$DATA"), i < 64));
    }
    assert!(parse_streams(&b).is_err());
}
#[test]
fn parses_sparse_retrieval() {
    let r = parse_retrieval(&retrieval()).unwrap();
    assert_eq!(r[0].vcn, 0);
    assert_eq!(r[0].lcn, Some(100));
    assert_eq!(r[1].vcn, 2);
    assert_eq!(r[1].lcn, None);
    assert_eq!(r[1].clusters, 5);
}
#[test]
fn rejects_incomplete_or_offset_retrieval() {
    let b = retrieval();
    assert!(parse_retrieval(&b[..32]).is_err());
    let mut b = retrieval();
    p64(&mut b, 8, 1);
    assert!(parse_retrieval(&b).is_err());
    let mut b = retrieval();
    p32(&mut b, 0, 0);
    assert!(parse_retrieval(&b).is_err());
}
#[test]
fn rejects_reversed_vcns_and_invalid_lcns() {
    let mut b = retrieval();
    p64(&mut b, 32, 1);
    assert!(parse_retrieval(&b).is_err());
    let mut b = retrieval();
    p64(&mut b, 24, -2);
    assert!(parse_retrieval(&b).is_err());
}
