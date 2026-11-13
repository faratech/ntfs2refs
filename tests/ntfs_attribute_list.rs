//! Original synthetic report evidence; no disk image, native handle or device.
use ntfs2refs::{
    ntfs_attribute_list::{self as list, Assembly, Entry, RecordEvidence},
    ntfs_inspect::{AttributeInventory, Extent, NtfsGeometry},
};
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// A resident value is checked against whichever digest was recorded for
/// it: the 32-digit content digest an inspection records today, or the
/// 64-digit SHA-256 that evidence retained from before that change holds.
#[test]
fn a_resident_value_is_checked_against_the_digest_that_was_recorded() {
    let bytes = b"a resident attribute list";
    let current = n2r_win32::content_digest::of(bytes);
    let retained = hash(bytes);
    assert_eq!((current.len(), retained.len()), (32, 64));
    assert!(list::resident_digest_matches(&current, bytes));
    assert!(list::resident_digest_matches(&retained, bytes));
    for expected in [&current, &retained] {
        assert!(!list::resident_digest_matches(expected, b"other bytes"));
    }
    // A well-formed digest of the wrong content, and malformed ones.
    assert!(!list::resident_digest_matches(&"0".repeat(32), bytes));
    assert!(!list::resident_digest_matches(&"0".repeat(64), bytes));
    assert!(!list::resident_digest_matches(&current[..31], bytes));
    assert!(!list::resident_digest_matches(
        &current.to_uppercase(),
        bytes
    ));
    assert!(!list::resident_digest_matches("", bytes));
}
fn geometry() -> NtfsGeometry {
    NtfsGeometry {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_size: 4096,
        total_sectors: 32768,
        volume_size: 16 * 1024 * 1024,
        total_clusters: 4096,
        mft_lcn: 4,
        mftmirr_lcn: 30,
        file_record_size: 1024,
        index_record_size: 4096,
        serial_number: 123,
    }
}
fn resident(type_code: u32, instance: u16) -> AttributeInventory {
    AttributeInventory {
        type_code,
        instance,
        name_utf16: vec![],
        flags: 0,
        resident: true,
        logical_size: 48,
        initialized_size: 48,
        allocated_size: 48,
        lowest_vcn: 0,
        compression_unit: 0,
        total_allocated_size: None,
        extents: vec![],
        resident_sha256: Some(hash(&[0; 48])),
        resident_metadata_hex: None,
    }
}
fn data(instance: u16, lowest: u64, physical: u64) -> AttributeInventory {
    AttributeInventory {
        type_code: 0x80,
        instance,
        name_utf16: vec![],
        flags: 0,
        resident: false,
        logical_size: 8193,
        initialized_size: 8193,
        allocated_size: 12288,
        lowest_vcn: lowest,
        compression_unit: 0,
        total_allocated_size: None,
        extents: vec![Extent {
            logical_offset: lowest * 4096,
            physical_offset: Some(physical * 4096),
            length: 4096,
        }],
        resident_sha256: None,
        resident_metadata_hex: None,
    }
}
fn entry(
    type_code: u32,
    lowest_vcn: u64,
    record_number: u64,
    sequence_number: u16,
    instance: u16,
) -> Entry {
    Entry {
        type_code,
        lowest_vcn,
        record_number,
        sequence_number,
        instance,
    }
}
fn encode(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for e in entries {
        let mut row = [0u8; 32];
        row[..4].copy_from_slice(&e.type_code.to_le_bytes());
        row[4..6].copy_from_slice(&32u16.to_le_bytes());
        row[8..16].copy_from_slice(&e.lowest_vcn.to_le_bytes());
        row[16..24].copy_from_slice(
            &(e.record_number | (u64::from(e.sequence_number) << 48)).to_le_bytes(),
        );
        row[24..26].copy_from_slice(&e.instance.to_le_bytes());
        row[26..].fill(0xa5); // Padding is preserved, not promoted to semantics.
        bytes.extend(row);
    }
    bytes
}
fn bind_list(base: &mut RecordEvidence, bytes: &[u8]) {
    let a = base
        .attributes
        .iter_mut()
        .find(|a| a.type_code == 0x20)
        .unwrap();
    a.logical_size = bytes.len() as u64;
    a.initialized_size = a.logical_size;
    a.allocated_size = a.logical_size;
    a.resident_sha256 = Some(hash(bytes));
    a.resident_metadata_hex = None;
}
fn fixture(self_entry: bool) -> (RecordEvidence, Vec<RecordEvidence>, Vec<u8>, NtfsGeometry) {
    let mut base = RecordEvidence {
        record_number: 16,
        sequence_number: 1,
        hard_link_count: 1,
        is_directory: false,
        base_file_reference: 0,
        raw_record_sha256: "1".repeat(64),
        attributes: vec![
            resident(0x10, 0),
            resident(0x30, 1),
            resident(0x20, 2),
            data(3, 0, 100),
        ],
    };
    let mut extensions: Vec<_> = [(17, 2, 1, 200), (18, 3, 2, 300)]
        .into_iter()
        .map(|(number, sequence, low, physical)| RecordEvidence {
            record_number: number,
            sequence_number: sequence,
            hard_link_count: 0,
            is_directory: false,
            base_file_reference: 16 | (1u64 << 48),
            raw_record_sha256: format!("{number:064x}"),
            attributes: vec![data(0, low, physical)],
        })
        .collect();
    // Undefined continuation size fields must never override the base sizes.
    for record in &mut extensions {
        let a = &mut record.attributes[0];
        a.logical_size = 0;
        a.initialized_size = u64::MAX;
        a.allocated_size = u64::MAX;
    }
    let mut entries = vec![entry(0x10, 0, 16, 1, 0)];
    if self_entry {
        entries.push(entry(0x20, 0, 16, 1, 2));
    }
    entries.extend([
        entry(0x30, 0, 16, 1, 1),
        entry(0x80, 0, 16, 1, 3),
        entry(0x80, 1, 17, 2, 0),
        entry(0x80, 2, 18, 3, 0),
    ]);
    let bytes = encode(&entries);
    bind_list(&mut base, &bytes);
    (base, extensions, bytes, geometry())
}
fn rejected(base: RecordEvidence, extensions: Vec<RecordEvidence>, bytes: &[u8], g: &NtfsGeometry) {
    assert!(list::assemble(base, extensions, bytes, g).is_err());
}

#[test]
fn assembles_optional_self_entry_and_keeps_original_segment_evidence() {
    for self_entry in [false, true] {
        let (base, mut extensions, bytes, g) = fixture(self_entry);
        let original_base = serde_json::to_vec(&base).unwrap();
        extensions.reverse(); // Canonical VCN order is independent of discovery order.
        let original_extensions = serde_json::to_vec(&extensions).unwrap();
        let (canonical, proof) = list::assemble(base, extensions, &bytes, &g).unwrap();
        assert_eq!(
            canonical.iter().map(|a| a.type_code).collect::<Vec<_>>(),
            [0x10, 0x30, 0x80]
        );
        let data = canonical.last().unwrap();
        assert_eq!(
            (
                data.logical_size,
                data.initialized_size,
                data.allocated_size
            ),
            (8193, 8193, 12288)
        );
        assert_eq!(data.instance, 3);
        assert_eq!(
            data.extents
                .iter()
                .map(|e| e.logical_offset)
                .collect::<Vec<_>>(),
            [0, 4096, 8192]
        );
        assert_eq!(
            data.extents
                .iter()
                .map(|e| e.physical_offset)
                .collect::<Vec<_>>(),
            [Some(409600), Some(819200), Some(1228800)]
        );
        assert_eq!(proof.schema_version, 1);
        assert_eq!(serde_json::to_vec(&proof.base).unwrap(), original_base);
        assert_eq!(
            serde_json::to_vec(&proof.extensions).unwrap(),
            original_extensions
        );
        assert_eq!(hex::decode(&proof.list_value_hex).unwrap(), bytes);
        let replay: Assembly =
            serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
        let (replayed, _) = list::assemble(
            replay.base,
            replay.extensions,
            &hex::decode(replay.list_value_hex).unwrap(),
            &g,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&canonical).unwrap(),
            serde_json::to_vec(&replayed).unwrap()
        );
    }
}

#[test]
fn optional_resident_legacy_security_descriptor_is_listed_and_preserved() {
    let (mut base, extensions, _, g) = fixture(false);
    base.attributes.insert(2, resident(0x50, 4));
    let bytes = encode(&[
        entry(0x10, 0, 16, 1, 0),
        entry(0x30, 0, 16, 1, 1),
        entry(0x50, 0, 16, 1, 4),
        entry(0x80, 0, 16, 1, 3),
        entry(0x80, 1, 17, 2, 0),
        entry(0x80, 2, 18, 3, 0),
    ]);
    bind_list(&mut base, &bytes);
    let (canonical, _) = list::assemble(base, extensions, &bytes, &g).unwrap();
    assert_eq!(canonical.iter().filter(|a| a.type_code == 0x50).count(), 1);
}

#[test]
fn parser_preserves_48_bit_references_and_record_local_instance_at_24() {
    let expected = entry(0x80, 9, 0x0000_abcd_1234_5678, 0xbeef, 0x4321);
    assert_eq!(
        list::parse(&encode(std::slice::from_ref(&expected))).unwrap(),
        [expected]
    );
}

#[test]
fn parser_refuses_truncation_lengths_names_order_duplicates_and_zero_sequences() {
    let (_, _, bytes, _) = fixture(false);
    for length in [0, 1, 25, 26, 31, bytes.len() - 1] {
        assert!(list::parse(&bytes[..length]).is_err());
    }
    for length in [0u16, 24, 26, 31, 40, u16::MAX] {
        let mut bad = bytes.clone();
        bad[4..6].copy_from_slice(&length.to_le_bytes());
        assert!(list::parse(&bad).is_err());
    }
    let mut named = bytes.clone();
    named[6] = 1;
    assert!(list::parse(&named).is_err());
    let mut zero_sequence = bytes.clone();
    zero_sequence[22..24].fill(0);
    assert!(list::parse(&zero_sequence).is_err());
    let first = entry(0x80, 0, 16, 1, 0);
    assert!(list::parse(&encode(&[first.clone(), first.clone()])).is_err());
    assert!(list::parse(&encode(&[entry(0x80, 1, 16, 1, 0), first.clone()])).is_err());
    assert!(list::parse(&encode(&[first, entry(0x80, 1, 16, 2, 0)])).is_err()); // Same physical origin, stale sequence.
    let mut trailing = bytes;
    trailing.push(0);
    assert!(list::parse(&trailing).is_err());
}

#[test]
fn exact_list_byte_bound_and_oversized_lists_are_distinct() {
    let entries: Vec<_> = (0..list::MAX_LIST_BYTES / 32)
        .map(|i| entry(0x80, i as u64, i as u64, 1, 0))
        .collect();
    let mut bytes = encode(&entries);
    assert_eq!(bytes.len(), list::MAX_LIST_BYTES);
    assert_eq!(list::parse(&bytes).unwrap().len(), entries.len());
    bytes.push(0);
    assert!(list::parse(&bytes).is_err());
}

#[test]
fn base_extension_identity_and_record_form_must_match_exactly() {
    for case in 0..16 {
        let (mut base, mut extensions, bytes, g) = fixture(false);
        match case {
            0 => base.record_number = 15,
            1 => base.sequence_number = 0,
            2 => base.hard_link_count = 2,
            3 => base.is_directory = true,
            4 => base.base_file_reference = 17,
            5 => base.raw_record_sha256 = "x".repeat(64),
            6 => extensions.clear(),
            7 => extensions[0].record_number = 16,
            8 => extensions[0].record_number = 15,
            9 => extensions[0].sequence_number = 0,
            10 => extensions[0].hard_link_count = 1,
            11 => extensions[0].is_directory = true,
            12 => extensions[0].base_file_reference = 18 | (1u64 << 48),
            13 => extensions[0].base_file_reference = 16 | (2u64 << 48),
            14 => extensions.push(extensions[0].clone()),
            15 => extensions[0].raw_record_sha256 = "0".repeat(63),
            _ => unreachable!(),
        }
        rejected(base, extensions, &bytes, &g);
    }
}

#[test]
fn every_attribute_requires_an_exact_nonforeign_list_entry() {
    for case in 0..8 {
        let (mut base, extensions, bytes, g) = fixture(false);
        let mut entries = list::parse(&bytes).unwrap();
        match case {
            0 => {
                entries.remove(0);
            }
            1 => {
                entries.pop();
            }
            2 => entries[3].sequence_number += 1,
            3 => entries[3].record_number = 999,
            4 => entries[3].instance = 9,
            5 => entries[3].lowest_vcn = 3,
            6 => entries.push(entry(0x90, 0, 16, 1, 9)),
            7 => entries.insert(1, entry(0x20, 0, 17, 2, 0)),
            _ => unreachable!(),
        }
        let bytes = encode(&entries);
        bind_list(&mut base, &bytes);
        rejected(base, extensions, &bytes, &g);
    }
}

#[test]
fn extra_duplicate_named_encoded_and_resident_data_forms_are_refused() {
    for case in 0..13 {
        let (mut base, mut extensions, bytes, g) = fixture(false);
        match case {
            0 => base.attributes.push(resident(0x40, 9)),
            1 => base.attributes[0].type_code = 0x30,
            2 => base.attributes[0].instance = 1,
            3 => base.attributes[3].resident = true,
            4 => base.attributes[2].resident = false,
            5 => base.attributes[3].flags = 0x8000,
            6 => base.attributes[3].compression_unit = 4,
            7 => base.attributes[3].name_utf16 = vec![65],
            8 => extensions[0].attributes.push(resident(0x10, 9)),
            9 => extensions[0].attributes[0].type_code = 0x30,
            10 => extensions[0].attributes[0].resident = true,
            11 => extensions[0].attributes[0].lowest_vcn = 0,
            12 => base.attributes[0].lowest_vcn = 1,
            _ => unreachable!(),
        }
        rejected(base, extensions, &bytes, &g);
    }
}

#[test]
fn list_bytes_hash_lengths_and_optional_retained_value_must_agree() {
    for case in 0..5 {
        let (mut base, extensions, bytes, g) = fixture(false);
        let a = &mut base.attributes[2];
        match case {
            0 => a.logical_size += 1,
            1 => a.initialized_size -= 1,
            2 => a.allocated_size += 1,
            3 => a.resident_sha256 = Some("0".repeat(64)),
            4 => a.resident_metadata_hex = Some("00".into()),
            _ => unreachable!(),
        }
        rejected(base, extensions, &bytes, &g);
    }
    let (mut base, extensions, bytes, g) = fixture(false);
    base.attributes[2].resident_metadata_hex = Some(hex::encode(&bytes));
    list::assemble(base, extensions, &bytes, &g).unwrap();
}

#[test]
fn vcn_allocation_vdl_physical_alignment_and_exclusive_ownership_are_enforced() {
    for case in 0..13 {
        let (mut base, mut extensions, bytes, mut g) = fixture(false);
        match case {
            0 => base.attributes[3].initialized_size = 8194, // still valid until logical comparison below
            1 => base.attributes[3].logical_size = 12289,
            2 => base.attributes[3].allocated_size = 8192,
            3 => base.attributes[3].allocated_size = 12289,
            4 => base.attributes[3].extents[0].logical_offset = 4096,
            5 => extensions[0].attributes[0].extents[0].logical_offset = 8192,
            6 => extensions[0].attributes[0].extents[0].physical_offset = None,
            7 => extensions[0].attributes[0].extents[0].physical_offset = Some(409601),
            8 => extensions[0].attributes[0].extents[0].physical_offset = Some(100 * 4096),
            9 => extensions[0].attributes[0].extents[0].physical_offset = Some(g.volume_size),
            10 => extensions[0].attributes[0].extents[0].length = 0,
            11 => extensions[0].attributes[0].extents[0].length = 4097,
            12 => g.cluster_size = 0,
            _ => unreachable!(),
        }
        rejected(base, extensions, &bytes, &g);
    }
}

#[test]
fn exact_run_budget_succeeds_and_extra_run_or_extension_exhaustion_refuses() {
    for count in [list::MAX_RUNS, list::MAX_RUNS + 1] {
        let (mut base, mut extensions, _, g) = fixture(false);
        extensions.truncate(1);
        base.attributes[3].logical_size = count as u64 * 4096;
        base.attributes[3].initialized_size = base.attributes[3].logical_size;
        base.attributes[3].allocated_size = base.attributes[3].logical_size;
        base.attributes[3].extents = (0..512)
            .map(|i| Extent {
                logical_offset: i * 4096,
                physical_offset: Some((100 + i * 2) * 4096),
                length: 4096,
            })
            .collect();
        extensions[0].attributes[0].lowest_vcn = 512;
        extensions[0].attributes[0].extents = (512..count as u64)
            .map(|i| Extent {
                logical_offset: i * 4096,
                physical_offset: Some((100 + i * 2) * 4096),
                length: 4096,
            })
            .collect();
        let bytes = encode(&[
            entry(0x10, 0, 16, 1, 0),
            entry(0x30, 0, 16, 1, 1),
            entry(0x80, 0, 16, 1, 3),
            entry(0x80, 512, 17, 2, 0),
        ]);
        bind_list(&mut base, &bytes);
        let result = list::assemble(base, extensions, &bytes, &g);
        if count == list::MAX_RUNS {
            assert_eq!(result.unwrap().0.last().unwrap().extents.len(), count);
        } else {
            assert!(result.unwrap_err().to_string().contains("run budget"));
        }
    }
    let (base, extensions, bytes, g) = fixture(false);
    let too_many = vec![extensions[0].clone(); list::MAX_EXTENSION_RECORDS + 1];
    assert!(
        list::assemble(base, too_many, &bytes, &g)
            .unwrap_err()
            .to_string()
            .contains("extension record count")
    );
}

fn nonresident_fixture() -> (RecordEvidence, Vec<RecordEvidence>, Vec<u8>, NtfsGeometry) {
    let (mut base, extensions, small, geometry) = fixture(false);
    let mut bytes = Vec::new();
    for row in small.as_chunks::<32>().0 {
        let mut padded = vec![0x5a; 1024];
        padded[..32].copy_from_slice(row);
        padded[4..6].copy_from_slice(&1024u16.to_le_bytes());
        bytes.extend(padded);
    }
    bind_list(&mut base, &bytes);
    let list = &mut base.attributes[2];
    list.resident = false;
    list.allocated_size = 8192;
    list.resident_sha256 = None;
    list.extents = vec![
        Extent {
            logical_offset: 0,
            physical_offset: Some(500 * 4096),
            length: 4096,
        },
        Extent {
            logical_offset: 4096,
            physical_offset: Some(503 * 4096),
            length: 4096,
        },
    ];
    (base, extensions, bytes, geometry)
}

#[test]
fn complete_fragmented_nonresident_list_uses_a_separate_storage_version() {
    let (base, extensions, bytes, geometry) = nonresident_fixture();
    list::validate_list_storage(&base.attributes[2], &geometry).unwrap();
    let (canonical, ledger) = list::assemble(base, extensions, &bytes, &geometry).unwrap();
    assert_eq!(ledger.schema_version, 2);
    assert!(!ledger.base.attributes[2].resident);
    assert_eq!(ledger.base.attributes[2].extents.len(), 2);
    assert_eq!(hex::decode(ledger.list_value_hex).unwrap(), bytes);
    assert!(canonical.iter().all(|a| a.type_code != 0x20));
    assert_eq!(canonical.last().unwrap().extents.len(), 3);
    let (base, extensions, bytes, geometry) = fixture(false);
    assert_eq!(
        list::assemble(base, extensions, &bytes, &geometry)
            .unwrap()
            .1
            .schema_version,
        1
    );
}

/// A sparse stream whose mapping needs more than one file record (a large
/// sparse file with many islands) is assembled like a plain one: the segment
/// that starts the stream carries the allocation granule as its compression
/// unit, a continuation carries none, and a run may be a hole.
#[test]
fn a_sparse_stream_that_spans_file_records_is_assembled_with_its_holes() {
    let limits = || list::AssemblyLimits::from_working_bytes(16 << 20, 1024).unwrap();
    let sparse = || {
        let (mut base, mut extensions, bytes, g) = fixture(false);
        // A complete file's resident metadata comes with its bytes.
        base.attributes[0].resident_metadata_hex = Some(hex::encode([0u8; 48]));
        // A file name of one character: 66 bytes and the name.
        let mut name = [0u8; 68];
        name[64] = 1;
        name[66] = b'f';
        let file_name = &mut base.attributes[1];
        file_name.logical_size = 68;
        file_name.initialized_size = 68;
        file_name.allocated_size = 68;
        file_name.resident_sha256 = Some(hash(&name));
        file_name.resident_metadata_hex = Some(hex::encode(name));
        base.attributes[3].flags = 0x8000;
        base.attributes[3].compression_unit = 4;
        for record in &mut extensions {
            record.attributes[0].flags = 0x8000;
        }
        // The middle cluster is a hole.
        extensions[0].attributes[0].extents[0].physical_offset = None;
        (base, extensions, bytes, g)
    };
    let (base, extensions, bytes, g) = sparse();
    let (canonical, _) =
        list::assemble_attributes_resource(base, extensions, &bytes, &g, limits()).unwrap();
    let stream = canonical.iter().find(|a| a.type_code == 0x80).unwrap();
    assert_eq!((stream.flags, stream.compression_unit), (0x8000, 4));
    assert_eq!(
        stream
            .extents
            .iter()
            .map(|e| (e.logical_offset, e.physical_offset, e.length))
            .collect::<Vec<_>>(),
        [
            (0, Some(100 * 4096), 4096),
            (4096, None, 4096),
            (8192, Some(300 * 4096), 4096)
        ]
    );

    // A unit that 4 KiB clusters do not have, and a hole in a stream that is
    // neither sparse nor compressed, are refused.
    let (mut base, extensions, bytes, g) = sparse();
    base.attributes[3].compression_unit = 3;
    let error =
        list::assemble_attributes_resource(base, extensions, &bytes, &g, limits()).unwrap_err();
    assert!(
        error.to_string().contains("compression unit 3"),
        "{error:#}"
    );
    let (mut base, mut extensions, bytes, g) = sparse();
    base.attributes[3].flags = 0;
    base.attributes[3].compression_unit = 0;
    for record in &mut extensions {
        record.attributes[0].flags = 0;
    }
    let error =
        list::assemble_attributes_resource(base, extensions, &bytes, &g, limits()).unwrap_err();
    assert!(
        error.to_string().contains("neither sparse nor compressed"),
        "{error:#}"
    );
}

/// NTFS may hold more clusters for a nonresident value than the value needs:
/// it grows such an attribute several clusters at a time, most visibly on
/// small clusters. What the header says is allocated must be what is mapped.
#[test]
fn a_nonresident_list_may_hold_more_clusters_than_its_value_needs() {
    let (mut base, _, _, geometry) = nonresident_fixture();
    let a = &mut base.attributes[2];
    a.allocated_size = 12288;
    a.extents.push(Extent {
        logical_offset: 8192,
        physical_offset: Some(510 * 4096),
        length: 4096,
    });
    list::validate_list_storage(a, &geometry).unwrap();
    a.allocated_size = 16384;
    assert!(list::validate_list_storage(a, &geometry).is_err());
    a.allocated_size = 12288 + 512;
    assert!(list::validate_list_storage(a, &geometry).is_err());
}

#[test]
fn nonresident_list_refuses_synthetic_zeroes_incomplete_storage_and_payload_overlap() {
    for case in 0..17 {
        let (mut base, extensions, bytes, geometry) = nonresident_fixture();
        let a = &mut base.attributes[2];
        match case {
            0 => a.initialized_size -= 1,
            1 => a.allocated_size = 4096,
            2 => a.allocated_size = 12288,
            3 => a.extents[1].logical_offset = 8192,
            4 => a.extents[0].physical_offset = None,
            5 => a.extents[1].physical_offset = a.extents[0].physical_offset,
            6 => a.extents[1].physical_offset = Some(geometry.volume_size),
            7 => a.extents[0].physical_offset = Some(500 * 4096 + 1),
            8 => a.extents[0].length = 0,
            9 => a.extents[0].length = 4097,
            10 => a.logical_size = list::MAX_LIST_BYTES as u64 + 1,
            11 => a.resident_sha256 = Some(hash(&bytes)),
            12 => a.resident_metadata_hex = Some(hex::encode(&bytes)),
            13 => a.lowest_vcn = 1,
            14 => a.flags = 0x8000,
            15 => a.extents.clear(),
            16 => a.extents[0].physical_offset = Some(100 * 4096),
            _ => unreachable!(),
        }
        if case == 16 {
            // Its own storage is valid; the combined DATA/list ownership is not.
            list::validate_list_storage(a, &geometry).unwrap();
        } else {
            assert!(
                list::validate_list_storage(a, &geometry).is_err(),
                "storage case {case}"
            );
        }
        assert!(
            list::assemble(base, extensions, &bytes, &geometry).is_err(),
            "assembly case {case}"
        );
    }
}

fn mft_fixture() -> (
    RecordEvidence,
    Vec<RecordEvidence>,
    Vec<u8>,
    Vec<u8>,
    NtfsGeometry,
) {
    let (mut base, mut extensions, _, geometry) = fixture(false);
    base.record_number = 0;
    let data = &mut base.attributes[3];
    data.logical_size = 7 * 4096;
    data.initialized_size = data.logical_size;
    data.allocated_size = data.logical_size;
    data.extents[0].physical_offset = Some(4 * 4096);
    data.extents[0].length = 5 * 4096;
    for (index, extension) in extensions.iter_mut().enumerate() {
        extension.base_file_reference = 1 << 48;
        let data = &mut extension.attributes[0];
        data.lowest_vcn = 5 + index as u64;
        data.extents[0].logical_offset = data.lowest_vcn * 4096;
    }
    let bitmap = vec![1, 0, 6, 0];
    let mut attribute = resident(0xb0, 4);
    attribute.logical_size = bitmap.len() as u64;
    attribute.initialized_size = attribute.logical_size;
    attribute.allocated_size = attribute.logical_size;
    attribute.resident_sha256 = Some(hash(&bitmap));
    base.attributes.push(attribute);
    let bytes = encode(&[
        entry(0x10, 0, 0, 1, 0),
        entry(0x30, 0, 0, 1, 1),
        entry(0x80, 0, 0, 1, 3),
        entry(0x80, 5, 17, 2, 0),
        entry(0x80, 6, 18, 3, 0),
        entry(0xb0, 0, 0, 1, 4),
    ]);
    bind_list(&mut base, &bytes);
    (base, extensions, bytes, bitmap, geometry)
}

#[test]
fn mft_profile_keeps_its_bitmap_and_never_relaxes_ordinary_record_identity() {
    let (base, extensions, bytes, bitmap, geometry) = mft_fixture();
    let (canonical, ledger) =
        list::assemble_mft(base.clone(), extensions.clone(), &bytes, &bitmap, &geometry).unwrap();
    assert_eq!(ledger.schema_version, 3);
    assert_eq!(
        ledger.mft_bitmap_hex.as_deref(),
        Some(hex::encode(&bitmap).as_str())
    );
    assert_eq!(
        canonical
            .iter()
            .find(|a| a.type_code == 0x80)
            .unwrap()
            .extents
            .len(),
        3
    );
    assert!(list::assemble(base, extensions, &bytes, &geometry).is_err());
}

#[test]
fn mft_profile_refuses_stale_bitmap_auxiliary_layout_and_foreign_boot_locations() {
    for case in 0..10 {
        let (mut base, mut extensions, bytes, mut bitmap, geometry) = mft_fixture();
        match case {
            0 => bitmap[0] = 0,
            1 => bitmap[2] &= !2,
            2 => bitmap.push(0),
            3 => bitmap[3] |= 0x80,
            4 => base.attributes[3].logical_size -= 1,
            5 => base.attributes[4].initialized_size = 0,
            6 => base.attributes[3].extents[0].physical_offset = Some(5 * 4096),
            7 => extensions[0].base_file_reference = 16 | (1 << 48),
            8 => base.attributes[4].type_code = 0x50,
            9 => base.record_number = 16,
            _ => unreachable!(),
        }
        assert!(
            list::assemble_mft(base, extensions, &bytes, &bitmap, &geometry).is_err(),
            "MFT case {case}"
        );
    }
}
