use ntfs2refs::{
    ntfs_inspect::{FileInventory, MetadataRole, NameInventory},
    ntfs_namespace::{self as ns, Link},
};

const ROOT: u64 = (1 << 48) | 5;
fn reference(number: u64) -> u64 {
    (1 << 48) | number
}
fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn link(name: &str, number: u64) -> Link {
    Link {
        child: reference(number),
        parent: ROOT,
        namespace: 1,
        name: name.encode_utf16().collect(),
    }
}
fn encoded(key: Option<&Link>, child: Option<u64>) -> Vec<u8> {
    let key_length = key.map_or(0, |k| 66 + 2 * k.name.len());
    let size = ((16 + key_length + 7) & !7) + if child.is_some() { 8 } else { 0 };
    let mut b = vec![0; size];
    put16(&mut b, 8, size as u16);
    put16(&mut b, 10, key_length as u16);
    put16(
        &mut b,
        12,
        u16::from(child.is_some()) | if key.is_none() { 2 } else { 0 },
    );
    if let Some(k) = key {
        put64(&mut b, 0, k.child);
        put64(&mut b, 16, k.parent);
        b[80] = k.name.len() as u8;
        b[81] = k.namespace;
        for (i, c) in k.name.iter().enumerate() {
            put16(&mut b, 82 + 2 * i, *c);
        }
    }
    if let Some(vcn) = child {
        put64(&mut b, size - 8, vcn);
    }
    b
}
fn node(entries: &[(&Link, Option<u64>)], last: Option<u64>) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, c) in entries {
        b.extend(encoded(Some(k), *c));
    }
    b.extend(encoded(None, last));
    b
}
pub fn root(entries: &[(&Link, Option<u64>)], last: Option<u64>) -> Vec<u8> {
    let entries = node(entries, last);
    let mut b = vec![0; 32 + entries.len()];
    put32(&mut b, 0, 0x30);
    put32(&mut b, 4, 1);
    put32(&mut b, 8, 4096);
    b[12] = 1;
    put32(&mut b, 16, 16);
    put32(&mut b, 20, (16 + entries.len()) as u32);
    put32(&mut b, 24, (16 + entries.len()) as u32);
    b[28] = u8::from(last.is_some());
    b[32..].copy_from_slice(&entries);
    b
}
fn block(slot: u64, entries: &[(&Link, Option<u64>)], last: Option<u64>) -> Vec<u8> {
    let entries = node(entries, last);
    let mut b = vec![0; 4096];
    b[..4].copy_from_slice(b"INDX");
    put16(&mut b, 4, 40);
    put16(&mut b, 6, 9);
    put64(&mut b, 16, slot);
    put32(&mut b, 24, 40);
    put32(&mut b, 28, (40 + entries.len()) as u32);
    put32(&mut b, 32, 4096 - 24);
    b[36] = u8::from(last.is_some());
    b[64..64 + entries.len()].copy_from_slice(&entries);
    put16(&mut b, 40, 0xabcd);
    for i in 1..9 {
        let old = [b[i * 512 - 2], b[i * 512 - 1]];
        b[40 + 2 * i..42 + 2 * i].copy_from_slice(&old);
        put16(&mut b, i * 512 - 2, 0xabcd);
    }
    b
}
fn object(number: u64, directory: bool, names: Vec<Link>) -> FileInventory {
    FileInventory {
        extended_attributes: None,
        reparse: None,
        record_number: number,
        sequence_number: 1,
        hard_link_count: names.iter().filter(|n| n.namespace != 2).count() as u16,
        is_directory: directory,
        is_metadata: number < 16,
        metadata_role: MetadataRole::NotClassified,
        metadata_role_issue: None,
        base_file_reference: 0,
        names: names
            .into_iter()
            .map(|n| NameInventory {
                name: String::from_utf16_lossy(&n.name),
                name_utf16: n.name,
                namespace: n.namespace,
                parent_record_number: n.parent & 0xffff_ffff_ffff,
                parent_sequence_number: (n.parent >> 48) as u16,
            })
            .collect(),
        standard_information: None,
        streams: Vec::new(),
        attributes: Vec::new(),
    }
}
fn root_object() -> FileInventory {
    object(
        5,
        true,
        vec![Link {
            child: ROOT,
            parent: ROOT,
            namespace: 1,
            name: vec![46],
        }],
    )
}
fn upcase() -> Vec<u16> {
    (0..=u16::MAX)
        .map(|n| if (97..=122).contains(&n) { n - 32 } else { n })
        .collect()
}
fn directory(entries: &[Link]) -> ns::Directory {
    ns::parse_directory(
        ROOT,
        &root(&entries.iter().map(|k| (k, None)).collect::<Vec<_>>(), None),
        &[],
        0,
        &[],
    )
    .unwrap()
}

#[test]
fn matches_leaf_names_and_reachability() {
    let name = link("hello", 16);
    let files = vec![root_object(), object(16, false, vec![name.clone()])];
    let d = directory(&[name]);
    assert_eq!(ns::reconcile(&files, &[d], &upcase()).unwrap(), 2);
}
#[test]
fn walks_internal_keys_in_order_and_all_allocated_blocks() {
    let a = link("Alpha", 16);
    let m = link("Middle", 17);
    let z = link("Omega", 18);
    let allocation = [block(0, &[(&a, None)], None), block(1, &[(&z, None)], None)].concat();
    let d = ns::parse_directory(
        ROOT,
        &root(&[(&m, Some(0))], Some(1)),
        &allocation,
        8192,
        &[3],
    )
    .unwrap();
    assert_eq!(d.entries, vec![a, m, z]);
    assert_eq!(d.index_blocks, 2);
}
#[test]
fn rejects_allocated_unreachable_nodes() {
    let a = link("A", 16);
    assert!(
        ns::parse_directory(
            ROOT,
            &root(&[], None),
            &block(0, &[(&a, None)], None),
            4096,
            &[1]
        )
        .is_err()
    );
}
#[test]
fn rejects_child_into_a_free_index_slot() {
    assert!(
        ns::parse_directory(ROOT, &root(&[], Some(0)), &block(0, &[], None), 4096, &[0]).is_err()
    );
}
#[test]
fn rejects_cycles_and_shared_child_pages() {
    let page = block(0, &[], Some(0));
    assert!(ns::parse_directory(ROOT, &root(&[], Some(0)), &page, 4096, &[1]).is_err());
    let a = link("A", 16);
    let page = block(0, &[], None);
    assert!(
        ns::parse_directory(ROOT, &root(&[(&a, Some(0))], Some(0)), &page, 4096, &[1]).is_err()
    );
}
#[test]
fn rejects_torn_index_pages() {
    for sector in 1..=8 {
        let mut page = block(0, &[], None);
        page[sector * 512 - 2] ^= 1;
        assert!(ns::parse_directory(ROOT, &root(&[], Some(0)), &page, 4096, &[1]).is_err());
    }
}
#[test]
fn rejects_wrong_vcn_or_uninitialized_live_node() {
    let page = block(1, &[], None);
    assert!(ns::parse_directory(ROOT, &root(&[], Some(0)), &page, 4096, &[1]).is_err());
    assert!(
        ns::parse_directory(ROOT, &root(&[], Some(0)), &block(0, &[], None), 4095, &[1]).is_err()
    );
}
#[test]
fn ignores_free_old_pages_but_rejects_bitmap_outside_eof() {
    assert!(ns::parse_directory(ROOT, &root(&[], None), &vec![0xff; 4096], 0, &[0]).is_ok());
    assert!(ns::parse_directory(ROOT, &root(&[], None), &[], 0, &[1]).is_err());
    assert!(ns::parse_directory(ROOT, &root(&[], None), &vec![0; 4096], 0, &[]).is_err());
}
#[test]
fn bounds_tree_depth() {
    let mut allocation = Vec::new();
    for i in 0..65 {
        allocation.extend(block(i, &[], if i == 64 { None } else { Some(i + 1) }));
    }
    let mut bitmap = vec![255; 9];
    bitmap[8] = 1;
    assert!(
        ns::parse_directory(
            ROOT,
            &root(&[], Some(0)),
            &allocation,
            allocation.len() as u64,
            &bitmap
        )
        .is_err()
    );
}
#[test]
fn validates_node_and_entry_lengths_terminators_and_flags() {
    let a = link("A", 16);
    let good = root(&[(&a, None)], None);
    for (at, value) in [(16, 0), (20, 0xff), (28, 2), (44, 4), (42, 1), (40, 0)] {
        let mut b = good.clone();
        b[at] = value;
        assert!(
            ns::parse_directory(ROOT, &b, &[], 0, &[]).is_err(),
            "offset{at}"
        );
    }
    let mut b = good;
    let end = b.len();
    b[end - 4] = 0;
    assert!(ns::parse_directory(ROOT, &b, &[], 0, &[]).is_err());
}
#[test]
fn rejects_misrouted_parent_or_unknown_namespace() {
    for parent in [reference(6), 5] {
        let mut name = link("name", 16);
        name.parent = parent;
        assert!(ns::parse_directory(ROOT, &root(&[(&name, None)], None), &[], 0, &[]).is_err());
    }
    let mut name = link("name", 16);
    name.namespace = 4;
    assert!(ns::parse_directory(ROOT, &root(&[(&name, None)], None), &[], 0, &[]).is_err());
}
#[test]
fn preserves_raw_utf16_without_lossy_identity() {
    let name = Link {
        child: reference(16),
        parent: ROOT,
        namespace: 1,
        name: vec![0xd800, 0x03c9],
    };
    let d = directory(std::slice::from_ref(&name));
    assert_eq!(d.entries[0].name, name.name);
    let files = vec![root_object(), object(16, false, vec![name])];
    assert!(ns::reconcile(&files, &[d], &upcase()).is_ok());
}
#[test]
fn accepts_hardlinks_and_dos_alias_as_distinct_index_links() {
    let a = link("Alpha", 16);
    let b = link("Beta", 16);
    let files = vec![root_object(), object(16, false, vec![a.clone(), b.clone()])];
    assert!(ns::reconcile(&files, &[directory(&[a, b])], &upcase()).is_ok());
    let mut a = link("ALT", 16);
    a.namespace = 2;
    let b = link("longfilename", 16);
    let files = vec![root_object(), object(16, false, vec![a.clone(), b.clone()])];
    assert!(ns::reconcile(&files, &[directory(&[a, b])], &upcase()).is_ok());
}
#[test]
fn rejects_missing_or_fabricated_index_entries() {
    let a = link("A", 16);
    let files = vec![root_object(), object(16, false, vec![a.clone()])];
    assert!(ns::reconcile(&files, &[directory(&[])], &upcase()).is_err());
    let mut b = a.clone();
    b.name = vec![66];
    assert!(ns::reconcile(&files, &[directory(&[b])], &upcase()).is_err());
    assert!(ns::reconcile(&[root_object()], &[directory(&[a])], &upcase()).is_err());
}
#[test]
fn rejects_stale_file_or_parent_sequences() {
    let a = link("A", 16);
    let mut files = vec![root_object(), object(16, false, vec![a.clone()])];
    files[1].sequence_number = 2;
    assert!(ns::reconcile(&files, &[directory(std::slice::from_ref(&a))], &upcase()).is_err());
    files[1].sequence_number = 1;
    files[1].names[0].parent_sequence_number = 2;
    assert!(ns::reconcile(&files, &[directory(&[a])], &upcase()).is_err());
}
#[test]
fn checks_order_and_case_collisions_with_volume_upcase() {
    let a = link("a", 16);
    let z = link("Z", 17);
    let files = vec![
        root_object(),
        object(16, false, vec![a.clone()]),
        object(17, false, vec![z.clone()]),
    ];
    assert!(ns::reconcile(&files, &[directory(&[z, a])], &upcase()).is_err());
    let a = link("Name", 16);
    let b = link("NAME", 17);
    let files = vec![
        root_object(),
        object(16, false, vec![a.clone()]),
        object(17, false, vec![b.clone()]),
    ];
    assert!(ns::reconcile(&files, &[directory(&[a, b])], &upcase()).is_err());
}
#[test]
fn rejects_link_count_and_nonindexed_objects() {
    let a = link("A", 16);
    let mut files = vec![root_object(), object(16, false, vec![a.clone()])];
    files[1].hard_link_count = 2;
    assert!(ns::reconcile(&files, &[directory(&[a])], &upcase()).is_err());
    assert!(
        ns::reconcile(
            &[root_object(), object(16, false, vec![])],
            &[directory(&[])],
            &upcase()
        )
        .is_err()
    );
}
#[test]
fn requires_each_directory_exactly_once() {
    let files = vec![root_object()];
    assert!(ns::reconcile(&files, &[], &upcase()).is_err());
    assert!(ns::reconcile(&files, &[directory(&[]), directory(&[])], &upcase()).is_err());
}
#[test]
fn rejects_disconnected_cycle_even_if_all_names_match() {
    let a = Link {
        child: reference(16),
        parent: reference(17),
        namespace: 1,
        name: vec![65],
    };
    let b = Link {
        child: reference(17),
        parent: reference(16),
        namespace: 1,
        name: vec![66],
    };
    let files = vec![
        root_object(),
        object(16, true, vec![a.clone()]),
        object(17, true, vec![b.clone()]),
    ];
    let mut d16 = directory(&[]);
    d16.reference = reference(16);
    d16.entries = vec![b];
    let mut d17 = directory(&[]);
    d17.reference = reference(17);
    d17.entries = vec![a];
    assert!(ns::reconcile(&files, &[directory(&[]), d16, d17], &upcase()).is_err());
}
#[test]
fn rejects_partial_or_invalid_upcase_tables() {
    let files = vec![root_object()];
    assert!(ns::reconcile(&files, &[directory(&[])], &[]).is_err());
    let mut table = upcase();
    table[97] = 97;
    assert!(ns::reconcile(&files, &[directory(&[])], &table).is_err());
    let mut table = upcase();
    table[200] = 201;
    table[201] = 202;
    assert!(ns::reconcile(&files, &[directory(&[])], &table).is_err());
}
#[test]
fn rejects_unassembled_or_extension_records() {
    let a = link("A", 16);
    let mut files = vec![root_object(), object(16, false, vec![a.clone()])];
    files[1].base_file_reference = reference(17);
    assert!(ns::reconcile(&files, &[directory(&[a])], &upcase()).is_err());
}

#[test]
fn rejects_unbalanced_leaf_depths() {
    let a = link("Alpha", 16);
    let m = link("Middle", 17);
    let z = link("Omega", 18);
    let allocation = [
        block(0, &[(&a, None)], None),
        block(1, &[(&z, None)], None),
        block(2, &[], Some(1)),
    ]
    .concat();
    assert!(
        ns::parse_directory(
            ROOT,
            &root(&[(&m, Some(0))], Some(2)),
            &allocation,
            12288,
            &[7]
        )
        .is_err()
    );
}

#[test]
fn refuses_index_input_beyond_its_global_byte_bound() {
    let allocation = vec![0; ns::MAX_INDEX_BYTES + 4096];
    assert!(ns::parse_directory(ROOT, &root(&[], None), &allocation, 0, &vec![0; 1024]).is_err());
}

#[test]
fn rejects_update_sequence_metadata_overlapping_entries_or_sector_tail() {
    for (offset, value) in [(4, 500), (6, 8), (24, 16)] {
        let mut page = block(0, &[], None);
        put16(&mut page, offset, value);
        assert!(ns::parse_directory(ROOT, &root(&[], Some(0)), &page, 4096, &[1]).is_err());
    }
}

#[test]
fn validates_root_self_entry_namespace_when_present() {
    let files = vec![root_object()];
    let mut dot = Link {
        child: ROOT,
        parent: ROOT,
        namespace: 1,
        name: vec![46],
    };
    assert!(ns::reconcile(&files, &[directory(std::slice::from_ref(&dot))], &upcase()).is_ok());
    dot.namespace = 3;
    assert!(ns::reconcile(&files, &[directory(&[dot])], &upcase()).is_err());
}
