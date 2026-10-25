// Unit-test fixture module; included by journal_file.rs so parsing internals do
// not need to become an API that accepts untrusted evidence as native authority.
use super::*;

fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

fn binding() -> JournalStorageBinding {
    JournalStorageBinding {
        disk_number: 2,
        externally_enrolled_disk_unique_id: "600224806AAC261F021F249596F332FC".into(),
        volume_guid: "12345678-1234-1234-abcd-123456789abc".into(),
        identity: PartitionIdentity {
            disk_guid: "22345678-1234-1234-abcd-123456789abc".into(),
            partition_guid: "32345678-1234-1234-abcd-123456789abc".into(),
            partition_number: 2,
            disk_bytes: JOURNAL_DISK_BYTES,
            partition_offset: JOURNAL_PARTITION_OFFSET,
            partition_bytes: JOURNAL_PARTITION_BYTES,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    }
}
fn path(b: &JournalStorageBinding) -> String {
    format!(
        "\\\\?\\Volume{{{}}}\\ntfs2refs-shadow\\case\\journal.bin",
        b.volume_guid
    )
}
fn fixture(b: &JournalStorageBinding) -> JournalFileEvidence {
    let mut e = JournalFileEvidence {
        file_id_info: [0; 24],
        file_standard_info: [0; 24],
        file_attribute_tag_info: [0; 8],
        volume_extents: vec![0; 32],
        disk_device_number: vec![0; 12],
        disk_length: vec![0; 8],
        disk_alignment: vec![0; 28],
        disk_layout: vec![0; 48 + 2 * 144],
    };
    put64(&mut e.file_id_info, 0, 0x8765432112345678);
    e.file_id_info[8] = 0x27;
    e.file_id_info[23] = 0xa5;
    put32(&mut e.file_standard_info, 16, 1);
    put32(&mut e.file_attribute_tag_info, 0, 0x20);
    put32(&mut e.volume_extents, 0, 1);
    put32(&mut e.volume_extents, 8, 2);
    put64(&mut e.volume_extents, 16, JOURNAL_PARTITION_OFFSET);
    put64(&mut e.volume_extents, 24, JOURNAL_PARTITION_BYTES);
    put32(&mut e.disk_device_number, 0, 7);
    put32(&mut e.disk_device_number, 4, 2);
    put64(&mut e.disk_length, 0, JOURNAL_DISK_BYTES);
    for (at, n) in [(0, 28), (4, 28), (16, 512), (20, 4096)] {
        put32(&mut e.disk_alignment, at, n);
    }
    let raw = &mut e.disk_layout;
    put32(raw, 0, 1);
    put32(raw, 4, 2);
    raw[8..24].copy_from_slice(&guid_bytes(&b.identity.disk_guid).unwrap());
    put64(raw, 24, 17408);
    put64(raw, 32, JOURNAL_DISK_BYTES - 17408 - 16896);
    for (index, number, offset, length, kind, id) in [
        (
            0,
            1,
            17408,
            JOURNAL_PARTITION_OFFSET - 17408,
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "42345678-1234-1234-abcd-123456789abc",
        ),
        (
            1,
            2,
            JOURNAL_PARTITION_OFFSET,
            JOURNAL_PARTITION_BYTES,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            b.identity.partition_guid.as_str(),
        ),
    ] {
        let at = 48 + index * 144;
        put32(raw, at, 1);
        put64(raw, at + 8, offset);
        put64(raw, at + 16, length);
        put32(raw, at + 24, number);
        raw[at + 32..at + 48].copy_from_slice(&guid_bytes(kind).unwrap());
        raw[at + 48..at + 64].copy_from_slice(&guid_bytes(id).unwrap());
    }
    e
}

#[test]
fn general_journal_binding_accepts_distinct_dedicated_disk_geometry() {
    let fixed = binding();
    let mut evidence = fixture(&fixed);
    let mut disk = GeneralDiskBinding {
        disk_number: fixed.disk_number,
        volume_guid: fixed.volume_guid.clone(),
        identity: fixed.identity.clone(),
    };
    disk.identity.disk_bytes = 12 * 1024 * 1024 * 1024;
    put64(&mut evidence.disk_length, 0, disk.identity.disk_bytes);
    let general = GeneralJournalStorageBinding {
        disk,
        externally_enrolled_disk_unique_id: fixed.externally_enrolled_disk_unique_id.clone(),
    };
    let observed = validate_general_evidence(&general, &path(&fixed), evidence).unwrap();
    assert_eq!(observed.identity.disk_bytes, 12 * 1024 * 1024 * 1024);
    assert_eq!(observed.identity.partition_bytes, JOURNAL_PARTITION_BYTES);
}

#[test]
fn empty_and_prepared_files_have_the_same_stable_identity() {
    let b = binding();
    let e = fixture(&b);
    let empty = validate_evidence(&b, &path(&b), e.clone()).unwrap();
    assert_eq!(empty.file_bytes, 0);
    assert_eq!(empty.identity.file_id_128[15], 0xa5);
    assert_eq!(empty.identity.volume_serial_number, 0x8765432112345678);
    let mut prepared = e;
    put64(&mut prepared.file_standard_info, 0, MAX_JOURNAL_BYTES);
    put64(&mut prepared.file_standard_info, 8, MAX_JOURNAL_BYTES);
    let full = validate_evidence(
        &b,
        &path(&b).replace("journal.bin", "renamed.bin"),
        prepared,
    )
    .unwrap();
    assert_eq!(empty.identity, full.identity);
    assert_eq!(full.file_bytes, MAX_JOURNAL_BYTES);
    assert!(
        !full.external_unique_id_verified
            && !full.sharing_mode_verified
            && !full.conversion_qualified
    );
    assert!(!full.observations_match_before_after); // A pure parse is not a native double observation.
    let mut external = b.clone();
    external.externally_enrolled_disk_unique_id = "other-enrollment".into();
    assert_eq!(
        validate_evidence(&external, &path(&external), fixture(&external))
            .unwrap()
            .identity,
        empty.identity
    );
}

#[test]
fn bindings_refuse_routes_geometry_and_bad_enrollment_before_observation() {
    let original = binding();
    for n in [0, 1, 3, u32::MAX] {
        let mut b = original.clone();
        b.disk_number = n;
        assert!(b.validate().is_err());
    }
    for n in [0, 1, 3] {
        let mut b = original.clone();
        b.identity.partition_number = n;
        assert!(b.validate().is_err());
    }
    for unique in ["", "../disk", "x:y", "a b", "a\0b"] {
        let mut b = original.clone();
        b.externally_enrolled_disk_unique_id = unique.into();
        assert!(b.validate().is_err());
    }
    let mut b = original.clone();
    b.externally_enrolled_disk_unique_id = "a".repeat(129);
    assert!(b.validate().is_err());
    for field in 0..5 {
        let mut b = original.clone();
        match field {
            0 => b.identity.disk_bytes += 512,
            1 => b.identity.partition_offset += 512,
            2 => b.identity.partition_bytes += 512,
            3 => b.identity.logical_sector_bytes = 4096,
            _ => b.identity.physical_sector_bytes = 512,
        }
        assert!(b.validate().is_err());
    }
}

#[test]
fn path_is_a_measured_volume_guid_and_single_ordinary_stream() {
    let b = binding();
    let e = fixture(&b);
    let good = path(&b);
    for suffix in [
        "",
        "a:alternate",
        "a::$DATA",
        "a\\..\\b",
        ".\\b",
        "a\\\\b",
        "a.",
        "a ",
        "a/child",
        "a\0b",
        "a\\",
        "a?b",
    ] {
        let bad = format!("\\\\?\\Volume{{{}}}\\{suffix}", b.volume_guid);
        assert!(validate_evidence(&b, &bad, e.clone()).is_err(), "{bad:?}");
    }
    for bad in [
        "J:\\journal.bin".to_string(),
        "\\\\server\\share\\journal.bin".into(),
        good.replace(&b.volume_guid, &b.identity.disk_guid),
        format!("{good}{}", "a".repeat(MAX_PATH_UNITS)),
    ] {
        assert!(validate_evidence(&b, &bad, e.clone()).is_err());
    }
    let mut upper = b.clone();
    upper.volume_guid = format!("{{{}}}", b.volume_guid.to_uppercase());
    assert_eq!(
        validate_evidence(&upper, &good, e.clone())
            .unwrap()
            .identity,
        validate_evidence(&b, &good, e).unwrap().identity
    );
}

#[test]
fn nonordinary_linked_deleting_and_oversized_files_are_rejected() {
    let b = binding();
    let e = fixture(&b);
    for flag in [0x10, 0x40, 0x200, 0x400, 0x800, 0x4000] {
        let mut bad = e.clone();
        put32(&mut bad.file_attribute_tag_info, 0, flag);
        assert!(validate_evidence(&b, &path(&b), bad).is_err());
    }
    for links in [0, 2, u32::MAX] {
        let mut bad = e.clone();
        put32(&mut bad.file_standard_info, 16, links);
        assert!(validate_evidence(&b, &path(&b), bad).is_err());
    }
    for at in [20, 21] {
        for value in [1, 2, 255] {
            let mut bad = e.clone();
            bad.file_standard_info[at] = value;
            assert!(validate_evidence(&b, &path(&b), bad).is_err());
        }
    }
    for (at, n) in [
        (0, u64::MAX),
        (8, u64::MAX),
        (8, MAX_JOURNAL_BYTES + 1),
        (0, MAX_JOURNAL_BYTES + 4096),
    ] {
        let mut bad = e.clone();
        put64(&mut bad.file_standard_info, at, n);
        assert!(validate_evidence(&b, &path(&b), bad).is_err());
    }
    for region in [0..8, 8..24] {
        let mut bad = e.clone();
        bad.file_id_info[region].fill(0);
        assert!(validate_evidence(&b, &path(&b), bad).is_err());
    }
    let mut bad = e.clone();
    put32(&mut bad.file_attribute_tag_info, 4, 1);
    assert!(validate_evidence(&b, &path(&b), bad).is_err());
    // Resident allocation observations need not have cluster-aligned sizes.
    let mut resident = e;
    put64(&mut resident.file_standard_info, 0, 1024);
    validate_evidence(&b, &path(&b), resident).unwrap();
}

#[test]
fn native_buffers_are_complete_and_geometry_is_exact() {
    let b = binding();
    let original = fixture(&b);
    for which in 0..5 {
        let length = match which {
            0 => 32,
            1 => 12,
            2 => 8,
            3 => 28,
            _ => 336,
        };
        for cut in 0..length {
            let mut e = original.clone();
            match which {
                0 => e.volume_extents.truncate(cut),
                1 => e.disk_device_number.truncate(cut),
                2 => e.disk_length.truncate(cut),
                3 => e.disk_alignment.truncate(cut),
                _ => e.disk_layout.truncate(cut),
            }
            assert!(
                validate_evidence(&b, &path(&b), e).is_err(),
                "buffer {which} cut {cut}"
            );
        }
    }
    for (which, at) in [
        (0, 0),
        (0, 8),
        (0, 16),
        (0, 24),
        (1, 0),
        (1, 4),
        (1, 8),
        (2, 0),
        (3, 0),
        (3, 4),
        (3, 16),
        (3, 20),
        (3, 24),
        (4, 0),
        (4, 4),
        (4, 8),
        (4, 192 + 8),
        (4, 192 + 16),
        (4, 192 + 24),
        (4, 192 + 32),
        (4, 192 + 48),
        (4, 192 + 64),
    ] {
        let mut e = original.clone();
        match which {
            0 => e.volume_extents[at] ^= 0xff,
            1 => e.disk_device_number[at] ^= 0xff,
            2 => e.disk_length[at] ^= 0xff,
            3 => e.disk_alignment[at] ^= 0xff,
            _ => e.disk_layout[at] ^= 0xff,
        }
        assert!(
            validate_evidence(&b, &path(&b), e).is_err(),
            "buffer {which} at {at}"
        );
    }
}

#[test]
fn gpt_refuses_overflow_overlap_duplicates_and_system_partitions() {
    let b = binding();
    let original = fixture(&b);
    for (at, n) in [
        (24, u64::MAX),
        (32, u64::MAX),
        (48 + 8, JOURNAL_PARTITION_OFFSET),
        (48 + 16, JOURNAL_PARTITION_BYTES),
        (192 + 8, u64::MAX - 511),
        (192 + 16, u64::MAX),
    ] {
        let mut e = original.clone();
        put64(&mut e.disk_layout, at, n);
        assert!(validate_evidence(&b, &path(&b), e).is_err());
    }
    let mut e = original.clone();
    let id = e.disk_layout[240..256].to_vec();
    e.disk_layout[96..112].copy_from_slice(&id);
    assert!(validate_evidence(&b, &path(&b), e).is_err());
    let mut e = original.clone();
    e.disk_layout[80..96]
        .copy_from_slice(&guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap());
    assert!(validate_evidence(&b, &path(&b), e).is_err());
    let mut e = original;
    put32(&mut e.disk_layout, 48 + 24, 2);
    assert!(validate_evidence(&b, &path(&b), e).is_err());
}

#[cfg(windows)]
#[test]
fn sdk_file_information_abi_matches_raw_parser_offsets() {
    use std::mem::{offset_of, size_of};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FILE_STANDARD_INFO,
    };
    assert_eq!(size_of::<FILE_ID_INFO>(), 24);
    assert_eq!(offset_of!(FILE_ID_INFO, VolumeSerialNumber), 0);
    assert_eq!(offset_of!(FILE_ID_INFO, FileId), 8);
    assert_eq!(size_of::<FILE_STANDARD_INFO>(), 24);
    assert_eq!(offset_of!(FILE_STANDARD_INFO, AllocationSize), 0);
    assert_eq!(offset_of!(FILE_STANDARD_INFO, EndOfFile), 8);
    assert_eq!(offset_of!(FILE_STANDARD_INFO, NumberOfLinks), 16);
    assert_eq!(offset_of!(FILE_STANDARD_INFO, DeletePending), 20);
    assert_eq!(offset_of!(FILE_STANDARD_INFO, Directory), 21);
    assert_eq!(size_of::<FILE_ATTRIBUTE_TAG_INFO>(), 8);
    assert_eq!(offset_of!(FILE_ATTRIBUTE_TAG_INFO, FileAttributes), 0);
    assert_eq!(offset_of!(FILE_ATTRIBUTE_TAG_INFO, ReparseTag), 4);
}

#[test]
fn changed_file_or_storage_observations_are_not_certified_stable() {
    let b = binding();
    let raw = fixture(&b);
    let p = path(&b);
    let before = validate_evidence(&b, &p, raw.clone()).unwrap();
    assert!(
        finish_observation(before.clone(), &p, &raw)
            .unwrap()
            .observations_match_before_after
    );
    assert!(
        finish_observation(before.clone(), &p.replace("journal.bin", "other.bin"), &raw).is_err()
    );
    for field in 0..8 {
        let mut after = raw.clone();
        match field {
            0 => after.file_id_info[8] ^= 1,
            1 => after.file_standard_info[8] ^= 1,
            2 => after.file_attribute_tag_info[0] ^= 1,
            3 => after.volume_extents[8] ^= 1,
            4 => after.disk_device_number[4] ^= 1,
            5 => after.disk_length[0] ^= 1,
            6 => after.disk_alignment[16] ^= 1,
            _ => after.disk_layout[8] ^= 1,
        }
        assert!(finish_observation(before.clone(), &p, &after).is_err());
    }
}

#[test]
fn ordinary_handle_parser_keeps_file_identity_without_storage_claims() {
    let b = binding();
    let evidence = fixture(&b);
    let file = ordinary_snapshot(&path(&b), &evidence).unwrap();
    assert_eq!(file.file_bytes, 0);
    assert_eq!(file.file_id_128, evidence.file_id_info[8..24]);
    assert_eq!(file.volume_serial_number, 0x8765432112345678);
    assert_eq!(file.number_of_links, 1);
    assert!(ordinary_snapshot("C:\\ntfs2refs\\ticket.json", &evidence).is_err());
    assert!(ordinary_snapshot(&format!("{}:stream", path(&b)), &evidence).is_err());
    let mut linked = evidence;
    put32(&mut linked.file_standard_info, 16, 2);
    assert!(ordinary_snapshot(&path(&b), &linked).is_err());
}
