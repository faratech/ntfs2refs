use ntfs2refs::refs_inspect::{BackupHeaderStatus, inspect, inspect_boot_sector};
use std::io::Cursor;

// These are hand-constructed header fixtures, not native-formatted filesystems.
// They test parser bounds and reporting and cannot qualify a ReFS writer.
fn header(sector_bytes: u32, cluster_sectors: u32, sectors: u64) -> [u8; 512] {
    let mut bytes = [0_u8; 512];
    bytes[3..11].copy_from_slice(b"ReFS\0\0\0\0");
    bytes[16..20].copy_from_slice(b"FSRS");
    bytes[20..22].copy_from_slice(&512_u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&sectors.to_le_bytes());
    bytes[32..36].copy_from_slice(&sector_bytes.to_le_bytes());
    bytes[36..40].copy_from_slice(&cluster_sectors.to_le_bytes());
    bytes[40] = 3;
    bytes[41] = 14;
    bytes[56..64].copy_from_slice(&0x1234_5678_9abc_def0_u64.to_le_bytes());
    bytes
}

#[test]
fn decodes_512e_and_4kn_without_constant_sector_assumption() {
    for (sector, cluster) in [(512, 8), (4096, 1), (512, 128), (4096, 16)] {
        let bytes = header(sector, cluster, 1024);
        let report = inspect_boot_sector(&bytes, 1024 * u64::from(sector)).unwrap();
        assert_eq!(report.bytes_per_cluster, sector * cluster);
        assert_eq!(report.volume_bytes, 1024 * u64::from(sector));
        assert_eq!(report.major_version, 3);
        assert_eq!(report.minor_version, 14);
        assert_eq!(report.volume_serial, 0x1234_5678_9abc_def0);
    }
}

#[test]
fn matching_backup_does_not_claim_format_or_health_qualification() {
    let primary = header(4096, 1, 16);
    let mut image = vec![0_u8; 16 * 4096];
    image[..512].copy_from_slice(&primary);
    image[15 * 4096..15 * 4096 + 512].copy_from_slice(&primary);
    let length = image.len() as u64;
    let report = inspect(&mut Cursor::new(image), length).unwrap();
    assert_eq!(report.backup_probe_offset, 15 * 4096);
    assert_eq!(report.backup_header_status, BackupHeaderStatus::Matching);
    assert!(!report.metadata_verified);
    assert!(!report.checksum_verified);
    assert!(!report.conversion_profile_qualified);
    assert_eq!(report.native_format_provenance, "unknown");
}

#[test]
fn reports_absent_or_different_backup_without_repairing() {
    let primary = header(512, 8, 16);
    let mut image = vec![0_u8; 16 * 512];
    image[..512].copy_from_slice(&primary);
    let original = image.clone();
    let report = inspect(&mut Cursor::new(&mut image), 8192).unwrap();
    assert_eq!(
        report.backup_header_status,
        BackupHeaderStatus::NotRecognized
    );
    assert_eq!(image, original);

    image[15 * 512..16 * 512].copy_from_slice(&primary);
    image[15 * 512 + 56] ^= 1;
    let report = inspect(&mut Cursor::new(image), 8192).unwrap();
    assert_eq!(report.backup_header_status, BackupHeaderStatus::Different);
}

#[test]
fn permits_partition_padding_without_moving_backup_probe() {
    let primary = header(512, 8, 16);
    let report = inspect_boot_sector(&primary, 16384).unwrap();
    assert_eq!(report.volume_bytes, 8192);
    assert_eq!(report.trailing_bytes, 8192);
}

#[test]
fn rejects_truncation_and_declared_size_overflow() {
    let bytes = header(512, 8, 16);
    for size in 0..512 {
        assert!(inspect_boot_sector(&bytes[..size], 8192).is_err());
    }
    assert!(inspect_boot_sector(&bytes, 8191).is_err());
    assert!(inspect_boot_sector(&header(4096, 1, u64::MAX), u64::MAX).is_err());
    assert!(inspect(&mut Cursor::new(bytes), 8192).is_err());
}

#[test]
fn rejects_short_declared_view_before_accessing_larger_backing_reader() {
    let mut reader = Cursor::new(header(512, 8, 16));
    for length in 0..512 {
        reader.set_position(17);
        assert!(inspect(&mut reader, length).is_err());
        assert_eq!(reader.position(), 17);
    }
}

#[test]
fn rejects_invalid_geometry_without_panicking() {
    for sector in [0, 1, 256, 513, 8192, u32::MAX] {
        assert!(inspect_boot_sector(&header(sector, 8, 1024), u64::MAX).is_err());
    }
    for cluster in [0, 3, 7, 256, 1 << 31] {
        assert!(inspect_boot_sector(&header(512, cluster, 1024), u64::MAX).is_err());
    }
    for sectors in [0, 1, 2] {
        assert!(inspect_boot_sector(&header(512, 8, sectors), 8192).is_err());
    }
}

#[test]
fn rejects_wrong_recognition_structure_and_unknown_major() {
    for offset in [3, 10, 16, 19, 20] {
        let mut bytes = header(512, 8, 16);
        bytes[offset] ^= 0xff;
        assert!(inspect_boot_sector(&bytes, 8192).is_err());
    }
    let mut bytes = header(512, 8, 16);
    bytes[40] = 4;
    assert!(inspect_boot_sector(&bytes, 8192).is_err());
    bytes[3..11].copy_from_slice(b"-FVE-FS-");
    let message = inspect_boot_sector(&bytes, 8192).unwrap_err().to_string();
    assert!(message.contains("BitLocker"));
}

#[test]
fn does_not_require_legacy_jump_or_boot_signature() {
    let mut bytes = header(512, 8, 16);
    bytes[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    assert!(inspect_boot_sector(&bytes, 8192).is_ok());
}
