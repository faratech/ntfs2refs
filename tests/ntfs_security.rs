use ntfs2refs::{
    ntfs_index::Input,
    ntfs_inspect::{
        AttributeInventory, FileInventory, MetadataRole, NameInventory, StandardInformation,
    },
    ntfs_security::{self as sec, AclState, Header, IndexKind, SecurityIndex},
};
fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn empty() -> Vec<u8> {
    let mut b = vec![0; 20];
    b[0] = 1;
    p16(&mut b, 2, 0x8000);
    b
}
fn sid() -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}
fn ace(ty: u8, extra: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 8];
    b[0] = ty;
    b[1] = 0x10;
    p32(&mut b, 4, 0x00120089);
    b.extend(sid());
    b.extend(extra);
    let len = b.len() as u16;
    p16(&mut b, 2, len);
    b
}
fn descriptor(aces: &[Vec<u8>], sacl: bool, revision: u8) -> Vec<u8> {
    let mut b = empty();
    p16(&mut b, 2, 0x8000 | if sacl { 16 } else { 4 });
    p32(&mut b, if sacl { 12 } else { 16 }, 20);
    let mut acl = vec![0; 8];
    acl[0] = revision;
    for a in aces {
        acl.extend(a);
    }
    let n = acl.len() as u16;
    p16(&mut acl, 2, n);
    p16(&mut acl, 4, aces.len() as u16);
    b.extend(acl);
    b
}
fn encode_header(h: &Header) -> Vec<u8> {
    let mut b = vec![0; 20];
    p32(&mut b, 0, h.hash);
    p32(&mut b, 4, h.id);
    p64(&mut b, 8, h.offset);
    p32(&mut b, 16, h.length);
    b
}
fn corpus(data: &[Vec<u8>]) -> (Vec<u8>, Vec<Header>) {
    let mut primary = Vec::new();
    let mut headers = Vec::new();
    let mut last_end = 0;
    for (i, d) in data.iter().enumerate() {
        let h = Header {
            hash: sec::ntfs_hash(d).unwrap(),
            id: 256 + i as u32,
            offset: primary.len() as u64,
            length: (d.len() + 20) as u32,
        };
        primary.extend(encode_header(&h));
        primary.extend(d);
        last_end = primary.len();
        primary.resize((primary.len() + 15) & !15, 0);
        headers.push(h);
    }
    assert!(primary.len() < 0x40000);
    let mut bytes = vec![0; 0x40000 + last_end];
    bytes[..primary.len()].copy_from_slice(&primary);
    bytes[0x40000..].copy_from_slice(&primary[..last_end]);
    (bytes, headers)
}
fn indexes(headers: &[Header]) -> (SecurityIndex, SecurityIndex) {
    let mut hash = headers.to_vec();
    hash.sort_by_key(|h| (h.hash, h.id));
    (
        SecurityIndex {
            entries: headers.to_vec(),
            index_blocks: 0,
        },
        SecurityIndex {
            entries: hash,
            index_blocks: 0,
        },
    )
}
fn root(headers: &[Header], kind: IndexKind) -> Vec<u8> {
    let mut entries = Vec::new();
    for h in headers {
        let key = match kind {
            IndexKind::Id => h.id.to_le_bytes().to_vec(),
            IndexKind::Hash => [h.hash.to_le_bytes(), h.id.to_le_bytes()].concat(),
        };
        let offset = 16 + key.len();
        let size = (offset + 20 + 7) & !7;
        let mut b = vec![0; size];
        p16(&mut b, 0, offset as u16);
        p16(&mut b, 2, 20);
        p16(&mut b, 8, size as u16);
        p16(&mut b, 10, key.len() as u16);
        b[16..offset].copy_from_slice(&key);
        b[offset..offset + 20].copy_from_slice(&encode_header(h));
        entries.extend(b);
    }
    let mut end = vec![0; 16];
    p16(&mut end, 8, 16);
    p16(&mut end, 12, 2);
    entries.extend(end);
    let mut b = vec![0; 32 + entries.len()];
    p32(
        &mut b,
        4,
        match kind {
            IndexKind::Id => 0x10,
            IndexKind::Hash => 0x12,
        },
    );
    p32(&mut b, 8, 4096);
    b[12] = 1;
    p32(&mut b, 16, 16);
    p32(&mut b, 20, (16 + entries.len()) as u32);
    p32(&mut b, 24, (16 + entries.len()) as u32);
    b[32..].copy_from_slice(&entries);
    b
}
fn parse_index(root: &[u8], kind: IndexKind) -> anyhow::Result<SecurityIndex> {
    sec::parse_index(
        Input {
            root,
            allocation: &[],
            initialized: 0,
            bitmap: &[],
        },
        kind,
    )
}
fn file(id: Option<u32>) -> FileInventory {
    FileInventory {
        extended_attributes: None,
        reparse: None,
        record_number: 16,
        sequence_number: 1,
        hard_link_count: 1,
        is_directory: false,
        is_metadata: false,
        metadata_role: MetadataRole::NotClassified,
        metadata_role_issue: None,
        base_file_reference: 0,
        names: vec![NameInventory {
            name: "data".into(),
            name_utf16: vec![100, 97, 116, 97],
            namespace: 1,
            parent_record_number: 5,
            parent_sequence_number: 1,
        }],
        standard_information: Some(StandardInformation {
            creation_time: 0,
            modification_time: 0,
            mft_change_time: 0,
            access_time: 0,
            file_attributes: 32,
            security_id: id,
        }),
        streams: Vec::new(),
        attributes: Vec::new(),
    }
}
fn legacy_attr(data: &[u8]) -> AttributeInventory {
    AttributeInventory {
        type_code: 0x50,
        instance: 1,
        name_utf16: Vec::new(),
        flags: 0,
        resident: true,
        logical_size: data.len() as u64,
        initialized_size: data.len() as u64,
        allocated_size: data.len() as u64,
        lowest_vcn: 0,
        compression_unit: 0,
        total_allocated_size: None,
        extents: Vec::new(),
        // A resident attribute carries the content digest; a descriptor's own
        // evidence hash stays SHA-256.
        resident_sha256: Some(n2r_win32::content_digest::of(data)),
        resident_metadata_hex: Some(hex::encode(data)),
    }
}

#[test]
fn distinguishes_absent_null_and_empty_dacl() {
    let absent = sec::parse_descriptor(&empty()).unwrap();
    assert_eq!(absent.dacl.state, AclState::Absent);
    let mut bytes = empty();
    p16(&mut bytes, 2, 0x8004);
    assert_eq!(
        sec::parse_descriptor(&bytes).unwrap().dacl.state,
        AclState::Null
    );
    let present = sec::parse_descriptor(&descriptor(&[], false, 2)).unwrap();
    assert_eq!(present.dacl.state, AclState::Present);
    assert!(present.dacl.aces.is_empty());
}
#[test]
fn distinguishes_absent_null_and_empty_sacl() {
    let mut b = empty();
    assert_eq!(
        sec::parse_descriptor(&b).unwrap().sacl.state,
        AclState::Absent
    );
    p16(&mut b, 2, 0x8010);
    assert_eq!(
        sec::parse_descriptor(&b).unwrap().sacl.state,
        AclState::Null
    );
    assert_eq!(
        sec::parse_descriptor(&descriptor(&[], true, 2))
            .unwrap()
            .sacl
            .state,
        AclState::Present
    );
}
#[test]
fn preserves_ordered_allow_deny_aces_and_exact_bytes() {
    let b = descriptor(&[ace(1, &[]), ace(0, &[])], false, 2);
    let d = sec::parse_descriptor(&b).unwrap();
    assert_eq!(
        d.dacl.aces.iter().map(|a| a.ace_type).collect::<Vec<_>>(),
        [1, 0]
    );
    assert_eq!(d.dacl.aces[0].trustee_sid, "S-1-5-18");
    assert_eq!(d.relative_hex, hex::encode(&b));
    assert_eq!(d.sha256, sec::hash(&b));
}
#[test]
fn reads_owner_group_in_arbitrary_order_and_shared_sid_storage() {
    let mut b = empty();
    b.extend(sid());
    p32(&mut b, 4, 20);
    p32(&mut b, 8, 20);
    let d = sec::parse_descriptor(&b).unwrap();
    assert_eq!(d.owner_sid.as_deref(), Some("S-1-5-18"));
    assert_eq!(d.owner_sid, d.group_sid);
    assert_eq!(d.minimum_length, b.len());
}
#[test]
fn reads_audit_sacl_without_treating_it_as_absent() {
    let mut audit = ace(2, &[]);
    audit[1] = 0xc0;
    let d = sec::parse_descriptor(&descriptor(&[audit], true, 2)).unwrap();
    assert_eq!(d.sacl.aces.len(), 1);
    assert_eq!(d.sacl.aces[0].flags, 0xc0);
    assert_eq!(d.dacl.state, AclState::Absent);
}
#[test]
fn preserves_object_guids_and_requires_ds_acl_revision() {
    let mut a = vec![0; 12];
    a[0] = 5;
    p32(&mut a, 4, 1);
    p32(&mut a, 8, 3);
    a.extend(0..16);
    a.extend([0xff; 16]);
    a.extend(sid());
    let n = a.len() as u16;
    p16(&mut a, 2, n);
    let d = sec::parse_descriptor(&descriptor(&[a.clone()], false, 4)).unwrap();
    assert_eq!(
        d.dacl.aces[0].object_type.as_deref(),
        Some("03020100-0504-0706-0809-0a0b0c0d0e0f")
    );
    assert_eq!(
        d.dacl.aces[0].inherited_object_type.as_deref(),
        Some("ffffffff-ffff-ffff-ffff-ffffffffffff")
    );
    assert!(sec::parse_descriptor(&descriptor(&[a], false, 2)).is_err());
}
#[test]
fn preserves_conditional_application_bytes_without_evaluating_them() {
    let b = descriptor(&[ace(9, &[1, 2, 3, 4])], false, 2);
    let d = sec::parse_descriptor(&b).unwrap();
    let a = &d.dacl.aces[0];
    assert_eq!(a.application_data_length, 4);
    let at = a.application_data_offset.unwrap();
    assert_eq!(&b[at..at + 4], &[1, 2, 3, 4]);
    assert!(sec::parse_descriptor(&descriptor(&[ace(0, &[1, 2, 3, 4])], false, 2)).is_err());
}
#[test]
fn rejects_invalid_revision_relative_form_and_rm_byte() {
    for (offset, value) in [(0, 2), (1, 1)] {
        let mut b = empty();
        b[offset] = value;
        assert!(sec::parse_descriptor(&b).is_err());
    }
    let mut b = empty();
    p16(&mut b, 2, 0);
    assert!(sec::parse_descriptor(&b).is_err());
    let mut b = empty();
    p16(&mut b, 2, 0xc000);
    b[1] = 42;
    assert_eq!(sec::parse_descriptor(&b).unwrap().rm_control, 42);
}
#[test]
fn rejects_sid_offsets_counts_and_truncation() {
    for offset in [1, 16, 21, u32::MAX] {
        let mut b = empty();
        b.extend(sid());
        p32(&mut b, 4, offset);
        assert!(sec::parse_descriptor(&b).is_err());
    }
    let mut b = empty();
    b.extend(sid());
    p32(&mut b, 4, 20);
    b[21] = 16;
    assert!(sec::parse_descriptor(&b).is_err());
    let mut b = empty();
    b.extend(&sid()[..8]);
    p32(&mut b, 4, 20);
    assert!(sec::parse_descriptor(&b).is_err());
}
#[test]
fn rejects_acl_pointer_without_present_flag() {
    let mut b = empty();
    b.resize(28, 0);
    p32(&mut b, 16, 20);
    assert!(sec::parse_descriptor(&b).is_err());
}
#[test]
fn rejects_bad_acl_bounds_revision_and_reserved_bytes() {
    let good = descriptor(&[], false, 2);
    for (at, value) in [(20, 3), (21, 1), (22, 4), (24, 1), (26, 1)] {
        let mut b = good.clone();
        b[at] = value;
        assert!(sec::parse_descriptor(&b).is_err(), "offset{at}");
    }
}
#[test]
fn rejects_ace_count_size_sid_and_unknown_type() {
    let good = descriptor(&[ace(0, &[])], false, 2);
    for (at, value) in [(24, 2), (28, 4), (30, 15), (37, 16)] {
        let mut b = good.clone();
        b[at] = value;
        assert!(sec::parse_descriptor(&b).is_err(), "offset{at}");
    }
}
#[test]
fn bounds_descriptor_and_index_metadata_inputs() {
    assert!(sec::parse_descriptor(&vec![0; sec::MAX_DESCRIPTOR_BYTES + 4]).is_err());
    assert!(sec::parse_descriptor(&[1; 19]).is_err());
    let (sii, sdh) = indexes(&[]);
    assert!(sec::reconcile_table(&vec![0; sec::MAX_METADATA_BYTES + 1], &sii, &sdh).is_err());
}
#[test]
fn verifies_rotate_add_hash_and_wrapping() {
    assert_eq!(sec::ntfs_hash(&1u32.to_le_bytes()).unwrap(), 1);
    assert_eq!(
        sec::ntfs_hash(&[1u32.to_le_bytes(), 2u32.to_le_bytes()].concat()).unwrap(),
        10
    );
    assert_eq!(
        sec::ntfs_hash(&[u32::MAX.to_le_bytes(), 1u32.to_le_bytes()].concat()).unwrap(),
        0
    );
    assert!(sec::ntfs_hash(&[1, 2, 3]).is_err());
}
#[test]
fn reproduces_native_windows_descriptor_vector() {
    let b=hex::decode("01000480480000005400000000000000140000000200340002000000000014008900120001010000000000051200000000001800890012000102000000000005200000002002000001010000000000051400000001020000000000052000000020020000").unwrap();
    assert_eq!(sec::ntfs_hash(&b).unwrap(), 0x32fee6cb);
    let d = sec::parse_descriptor(&b).unwrap();
    assert_eq!(d.owner_sid.as_deref(), Some("S-1-5-20"));
    assert_eq!(d.group_sid.as_deref(), Some("S-1-5-32-544"));
    assert_eq!(d.dacl.aces.len(), 2);
}
#[test]
fn reconciles_mirrored_sds_and_both_indexes() {
    let (sds, h) = corpus(&[empty(), descriptor(&[], false, 2)]);
    let (sii, sdh) = indexes(&h);
    let table = sec::reconcile_table(&sds, &sii, &sdh).unwrap();
    assert_eq!(table.records.len(), 2);
    assert_eq!(table.records[0].security_id, Some(256));
    assert_eq!(table.records[0].sds_offset, Some(0));
}
#[test]
fn allows_hash_collisions_and_identical_descriptors_with_distinct_ids() {
    let (sds, h) = corpus(&[empty(), empty()]);
    assert_eq!(h[0].hash, h[1].hash);
    let (sii, sdh) = indexes(&h);
    assert_eq!(
        sec::reconcile_table(&sds, &sii, &sdh)
            .unwrap()
            .records
            .len(),
        2
    );
}
#[test]
fn refuses_missing_or_different_sds_mirror() {
    let (sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    assert!(sec::reconcile_table(&sds[..0x40000], &sii, &sdh).is_err());
    let mut b = sds;
    b[0x40000 + 20] ^= 1;
    assert!(sec::reconcile_table(&b, &sii, &sdh).is_err());
}
#[test]
fn refuses_corrupt_descriptor_hash_even_when_mirrors_agree() {
    let (mut sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    sds[21] = 1;
    sds[0x40000 + 21] = 1;
    assert!(
        sec::reconcile_table(&sds, &sii, &sdh)
            .err()
            .unwrap()
            .to_string()
            .contains("hash mismatch")
    );
}
#[test]
fn refuses_wrong_sds_offsets_and_unparsed_nonzero_tail() {
    let (sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    let mut b = sds.clone();
    p64(&mut b, 8, 16);
    p64(&mut b, 0x40000 + 8, 16);
    assert!(sec::reconcile_table(&b, &sii, &sdh).is_err());
    let mut b = sds;
    b[100] = 1;
    assert!(sec::reconcile_table(&b, &sii, &sdh).is_err());
}
#[test]
fn requires_exact_sds_sii_sdh_membership() {
    let (sds, h) = corpus(&[empty()]);
    let (mut sii, mut sdh) = indexes(&h);
    sii.entries.clear();
    assert!(sec::reconcile_table(&sds, &sii, &sdh).is_err());
    sii.entries = h.clone();
    sdh.entries[0].offset = 16;
    assert!(sec::reconcile_table(&sds, &sii, &sdh).is_err());
}
#[test]
fn parses_distinct_sii_and_sdh_key_contracts() {
    let (_, h) = corpus(&[empty()]);
    for kind in [IndexKind::Id, IndexKind::Hash] {
        let r = root(&h, kind);
        let index = parse_index(&r, kind).unwrap();
        assert_eq!(index.entries, h);
    }
}
#[test]
fn rejects_security_index_data_overlaps_and_reserved_fields() {
    let (_, h) = corpus(&[empty()]);
    let good = root(&h, IndexKind::Id);
    for (at, value) in [(32, 16), (34, 21), (36, 1), (42, 0)] {
        let mut b = good.clone();
        b[at] = value;
        assert!(parse_index(&b, IndexKind::Id).is_err(), "offset{at}");
    }
}
#[test]
fn rejects_security_index_key_value_disagreement() {
    let (_, h) = corpus(&[empty()]);
    let mut r = root(&h, IndexKind::Id);
    p32(&mut r, 48, 257);
    assert!(parse_index(&r, IndexKind::Id).is_err());
    let mut r = root(&h, IndexKind::Hash);
    r[48] ^= 1;
    assert!(parse_index(&r, IndexKind::Hash).is_err());
}
#[test]
fn rejects_unsorted_and_duplicated_security_index_keys() {
    let (_, mut h) = corpus(&[empty(), empty()]);
    h.reverse();
    assert!(parse_index(&root(&h, IndexKind::Id), IndexKind::Id).is_err());
    h[1] = h[0].clone();
    assert!(parse_index(&root(&h, IndexKind::Hash), IndexKind::Hash).is_err());
}
#[test]
fn binds_files_by_central_id_and_refuses_unknown_ids() {
    let (sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    let table = sec::reconcile_table(&sds, &sii, &sdh).unwrap();
    let bindings = sec::bind_files(&[file(Some(256))], &table.records).unwrap();
    assert_eq!(bindings[0].security_id, Some(256));
    assert!(sec::bind_files(&[file(Some(257))], &table.records).is_err());
}
#[test]
fn binds_legacy_bytes_only_with_matching_source_attribute() {
    let b = empty();
    let record = sec::DescriptorRecord {
        security_id: None,
        legacy_record: Some(16),
        sds_offset: None,
        ntfs_hash: None,
        descriptor: sec::parse_descriptor(&b).unwrap(),
    };
    let mut f = file(None);
    assert!(sec::bind_files(std::slice::from_ref(&f), std::slice::from_ref(&record)).is_err());
    f.attributes.push(legacy_attr(&b));
    assert!(sec::bind_files(std::slice::from_ref(&f), std::slice::from_ref(&record)).is_ok());
    f.attributes[0].resident_sha256 = Some("bad".into());
    assert!(sec::bind_files(&[f], &[record]).is_err());
}
#[test]
fn refuses_ambiguous_central_and_legacy_file_security() {
    let (sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    let table = sec::reconcile_table(&sds, &sii, &sdh).unwrap();
    let mut f = file(Some(256));
    f.attributes.push(legacy_attr(&empty()));
    assert!(sec::bind_files(&[f], &table.records).is_err());
}
#[test]
fn refuses_unassembled_and_duplicate_file_identities() {
    let (sds, h) = corpus(&[empty()]);
    let (sii, sdh) = indexes(&h);
    let table = sec::reconcile_table(&sds, &sii, &sdh).unwrap();
    let mut f = file(Some(256));
    f.base_file_reference = 17;
    assert!(sec::bind_files(&[f], &table.records).is_err());
    assert!(sec::bind_files(&[file(Some(256)), file(Some(256))], &table.records).is_err());
}

#[test]
fn reconciles_multiple_sds_primary_mirror_pairs_with_absolute_offsets() {
    let (first, mut headers) = corpus(&[empty()]);
    let (mut second, mut second_headers) = corpus(&[empty()]);
    for at in [0, 0x40000] {
        p32(&mut second, at + 4, 257);
        p64(&mut second, at + 8, 0x80000);
    }
    second_headers[0].id = 257;
    second_headers[0].offset = 0x80000;
    headers.extend(second_headers);
    let mut bytes = vec![0; 0x80000 + second.len()];
    bytes[..first.len()].copy_from_slice(&first);
    bytes[0x80000..].copy_from_slice(&second);
    let (sii, sdh) = indexes(&headers);
    let table = sec::reconcile_table(&bytes, &sii, &sdh).unwrap();
    assert_eq!(table.records[1].sds_offset, Some(0x80000));
}

#[test]
fn reads_internal_security_keys_and_leaf_values_in_order() {
    let (_, headers) = corpus(&[empty(), empty(), empty()]);
    for kind in [IndexKind::Id, IndexKind::Hash] {
        let mut allocation = Vec::new();
        for (slot, h) in [headers[0].clone(), headers[2].clone()].iter().enumerate() {
            let leaf = root(std::slice::from_ref(h), kind);
            let mut b = vec![0; 4096];
            b[..4].copy_from_slice(b"INDX");
            p16(&mut b, 4, 40);
            p16(&mut b, 6, 9);
            p64(&mut b, 16, slot as u64);
            p32(&mut b, 24, 40);
            p32(&mut b, 28, (40 + leaf.len() - 32) as u32);
            p32(&mut b, 32, 4096 - 24);
            b[64..64 + leaf.len() - 32].copy_from_slice(&leaf[32..]);
            p16(&mut b, 40, 0xabcd);
            for sector in 1..9 {
                let prior = [b[512 * sector - 2], b[512 * sector - 1]];
                b[40 + 2 * sector..42 + 2 * sector].copy_from_slice(&prior);
                p16(&mut b, 512 * sector - 2, 0xabcd);
            }
            allocation.extend(b);
        }
        let leaf = root(&headers[1..2], kind);
        let old_size = usize::from(u16::from_le_bytes(leaf[40..42].try_into().unwrap()));
        let mut node = vec![0; leaf.len() + 16];
        node[..32 + old_size].copy_from_slice(&leaf[..32 + old_size]);
        p16(&mut node, 40, (old_size + 8) as u16);
        p16(&mut node, 44, 1);
        let terminal = 32 + old_size + 8;
        p16(&mut node, terminal + 8, 24);
        p16(&mut node, terminal + 12, 3);
        p64(&mut node, terminal + 16, 1);
        node[28] = 1;
        let size = node.len() - 16;
        p32(&mut node, 20, size as u32);
        p32(&mut node, 24, size as u32);
        let index = sec::parse_index(
            Input {
                root: &node,
                allocation: &allocation,
                initialized: 8192,
                bitmap: &[3],
            },
            kind,
        )
        .unwrap();
        assert_eq!(index.entries, headers);
        assert_eq!(index.index_blocks, 2);
    }
}
