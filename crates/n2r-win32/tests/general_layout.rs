use n2r_win32::{
    general_layout::GeneralDiskBinding,
    layout::{PartitionIdentity, guid_bytes},
};

const DISK: u64 = 8 * 1024 * 1024 * 1024;
const OFFSET: u64 = 16 * 1024 * 1024;
const PARTITION: u64 = 6 * 1024 * 1024 * 1024;

fn binding() -> GeneralDiskBinding {
    GeneralDiskBinding {
        disk_number: 7,
        volume_guid: "5f2d3e41-5555-4444-aabb-123456789abc".into(),
        identity: PartitionIdentity {
            disk_guid: "12345678-1111-2222-aaaa-123456789abc".into(),
            partition_guid: "23456789-2222-3333-bbbb-123456789abc".into(),
            partition_number: 2,
            disk_bytes: DISK,
            partition_offset: OFFSET,
            partition_bytes: PARTITION,
            logical_sector_bytes: 512,
            physical_sector_bytes: 4096,
        },
    }
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn layout(binding: &GeneralDiskBinding) -> Vec<u8> {
    let mut bytes = vec![0u8; 48 + 2 * 144];
    put32(&mut bytes, 0, 1);
    put32(&mut bytes, 4, 2);
    bytes[8..24].copy_from_slice(&guid_bytes(&binding.identity.disk_guid).unwrap());
    put64(&mut bytes, 24, 1 << 20);
    put64(&mut bytes, 32, DISK - 2 * (1 << 20));
    for (index, number, offset, length, kind, id) in [
        (
            0,
            1,
            1 << 20,
            15 << 20,
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "34567890-3333-4444-cccc-123456789abc",
        ),
        (
            1,
            2,
            OFFSET,
            PARTITION,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            binding.identity.partition_guid.as_str(),
        ),
    ] {
        let at = 48 + index * 144;
        put32(&mut bytes, at, 1);
        put64(&mut bytes, at + 8, offset);
        put64(&mut bytes, at + 16, length);
        put32(&mut bytes, at + 24, number);
        bytes[at + 32..at + 48].copy_from_slice(&guid_bytes(kind).unwrap());
        bytes[at + 48..at + 64].copy_from_slice(&guid_bytes(id).unwrap());
    }
    bytes
}

#[test]
fn dedicated_data_disk_accepts_new_geometry_but_refuses_other_volume_classes() {
    let binding = binding();
    binding.validate().unwrap();
    let bytes = layout(&binding);
    binding.validate_layout(&bytes).unwrap();
    let mut efi = bytes.clone();
    efi[80..96].copy_from_slice(&guid_bytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap());
    assert!(binding.validate_layout(&efi).is_err());
    let mut second_data = bytes.clone();
    second_data[80..96]
        .copy_from_slice(&guid_bytes("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").unwrap());
    assert!(binding.validate_layout(&second_data).is_err());
    let mut overlap = bytes.clone();
    put64(&mut overlap, 48 + 144 + 8, 8 << 20);
    assert!(binding.validate_layout(&overlap).is_err());
}

#[test]
fn native_alignment_and_single_partition_extent_bind_to_request() {
    let mut binding = binding();
    let mut alignment = vec![0u8; 28];
    put32(&mut alignment, 0, 28);
    put32(&mut alignment, 4, 28);
    put32(&mut alignment, 16, 512);
    put32(&mut alignment, 20, 4096);
    binding.validate_alignment(&alignment).unwrap();
    binding.identity.logical_sector_bytes = 4096;
    assert!(binding.validate_alignment(&alignment).is_err());
    put32(&mut alignment, 16, 4096);
    binding.validate_alignment(&alignment).unwrap();
    let mut extent = vec![0u8; 32];
    put32(&mut extent, 0, 1);
    put32(&mut extent, 8, binding.disk_number);
    put64(&mut extent, 16, OFFSET);
    put64(&mut extent, 24, PARTITION);
    binding.validate_volume_extent(&extent).unwrap();
    put32(&mut extent, 8, binding.disk_number + 1);
    assert!(binding.validate_volume_extent(&extent).is_err());
}
