use n2r_win32::layout::*;

fn binding() -> DiskBinding {
    DiskBinding {
        disk_number: 1,
        volume_guid: "5f2d3e41-5555-4444-aabb-123456789abc".into(),
        identity: PartitionIdentity {
            disk_guid: "12345678-1111-2222-aaaa-123456789abc".into(),
            partition_guid: "23456789-2222-3333-bbbb-123456789abc".into(),
            partition_number: 2,
            disk_bytes: DISK_BYTES,
            partition_offset: PARTITION_OFFSET,
            partition_bytes: PARTITION_BYTES,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    }
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn fixture(b: &DiskBinding) -> Vec<u8> {
    let mut raw = vec![0; 48 + 2 * 144];
    put32(&mut raw, 0, 1);
    put32(&mut raw, 4, 2);
    raw[8..24].copy_from_slice(&guid_bytes(&b.identity.disk_guid).unwrap());
    put64(&mut raw, 24, 17408);
    put64(&mut raw, 32, DISK_BYTES - 17408 - 16896);
    for (index, number, offset, length, kind, id) in [
        (
            0,
            1,
            17408,
            16 * 1024 * 1024 - 17408,
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "34567890-3333-4444-cccc-123456789abc",
        ),
        (
            1,
            2,
            PARTITION_OFFSET,
            PARTITION_BYTES,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            b.identity.partition_guid.as_str(),
        ),
    ] {
        let at = 48 + index * 144;
        put32(&mut raw, at, 1);
        put64(&mut raw, at + 8, offset);
        put64(&mut raw, at + 16, length);
        put32(&mut raw, at + 24, number);
        raw[at + 32..at + 48].copy_from_slice(&guid_bytes(kind).unwrap());
        raw[at + 48..at + 64].copy_from_slice(&guid_bytes(id).unwrap());
    }
    raw
}

#[test]
fn gpt_identity_geometry_and_complete_buffer_are_required() {
    let b = binding();
    let raw = fixture(&b);
    validate_layout(&raw, &b).unwrap();
    for length in 0..raw.len() {
        assert!(
            validate_layout(&raw[..length], &b).is_err(),
            "truncation {length}"
        );
    }
    for at in [
        0,
        4,
        8,
        24,
        32,
        48,
        48 + 24,
        48 + 32,
        192,
        192 + 8,
        192 + 16,
        192 + 24,
        192 + 32,
        192 + 48,
        192 + 64,
    ] {
        let mut changed = raw.clone();
        changed[at] ^= 0xff;
        assert!(validate_layout(&changed, &b).is_err(), "field {at}");
    }
    let mut wrong = b.clone();
    wrong.identity.disk_guid = wrong.identity.partition_guid.clone();
    assert!(validate_layout(&raw, &wrong).is_err());
    let mut system = raw.clone();
    system[80..96].copy_from_slice(&guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap());
    assert!(validate_layout(&system, &b).is_err());
}

#[test]
fn guids_are_data_and_volume_identity_is_distinct() {
    assert_eq!(
        guid_bytes("12345678-1111-2222-aabb-123456789abc").unwrap(),
        [
            0x78, 0x56, 0x34, 0x12, 0x11, 0x11, 0x22, 0x22, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc
        ]
    );
    for bad in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "12345678-1111-2222-aabb-123456789abx",
        "../PhysicalDrive0",
    ] {
        assert!(guid_bytes(bad).is_err());
    }
    let b = binding();
    assert_ne!(b.volume_guid, b.identity.partition_guid);
    assert_eq!(
        b.volume_path().unwrap(),
        "\\\\?\\Volume{5f2d3e41-5555-4444-aabb-123456789abc}"
    );
}

#[test]
fn native_routes_and_ranges_reject_escapes() {
    let b = binding();
    let mut extent = vec![0; 32];
    put32(&mut extent, 0, 1);
    put32(&mut extent, 8, 1);
    put64(&mut extent, 16, PARTITION_OFFSET);
    put64(&mut extent, 24, PARTITION_BYTES);
    validate_volume_extent(&extent, &b).unwrap();
    put32(&mut extent, 8, 0);
    assert!(validate_volume_extent(&extent, &b).is_err());
    let mut device = vec![0; 12];
    put32(&mut device, 0, 7);
    put32(&mut device, 4, 1);
    validate_device(&device, 1).unwrap();
    assert!(validate_device(&device, 0).is_err());
    validate_ranges(&[(0, 4096), (8192, 4096)], PARTITION_BYTES).unwrap();
    for ranges in [
        vec![],
        vec![(1, 4096)],
        vec![(0, 1)],
        vec![(0, 8192), (4096, 4096)],
        vec![(u64::MAX - 4095, 8192)],
        vec![(PARTITION_BYTES, 4096)],
    ] {
        assert!(validate_ranges(&ranges, PARTITION_BYTES).is_err());
    }
}
